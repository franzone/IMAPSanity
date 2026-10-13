import json
import os
import unittest
from unittest import mock

from imapsanity import ai, apply, guards, journal, maildir, plan, rules, shadow, sync, typesafe
from imapsanity.backends.imap import ImapBackend
from imapsanity.config import ConfigError, load
from imapsanity.index import Index

from .helpers import Env, FakeIMAP


def quiet(*a, **k):
    pass


class Base(unittest.TestCase):
    maildir_folders = ()
    push = ()

    def setUp(self):
        self.env = Env(self.maildir_folders, self.push)
        self.cfg = self.env.cfg()
        self.idx = Index(self.cfg)

    def tearDown(self):
        self.idx.close()
        self.env.cleanup()

    def plan_rules(self):
        self.idx.update(verbose=False)
        actions, notes = rules.build_actions(self.cfg, self.idx)
        return actions, notes


class TestMaildirHelpers(unittest.TestCase):
    def test_names(self):
        self.assertEqual(maildir.split_name("1.2.h,U=7:2,FS"), ("1.2.h,U=7", "FS"))
        self.assertEqual(maildir.split_name("1.2.h,U=7"), ("1.2.h,U=7", ""))
        self.assertEqual(maildir.strip_uid("1.2.h,U=7:2,S"), "1.2.h:2,S")
        self.assertEqual(maildir.to_imap("INBOX", "INBOX.", "."), "INBOX")
        self.assertEqual(maildir.to_imap("Filtered/Cron Jobs", "INBOX.", "."), "INBOX.Filtered.Cron Jobs")
        self.assertEqual(maildir.imap_quote('a "b"'), '"a \\"b\\""')


class TestConfig(Base):
    def test_rule_without_criteria_rejected(self):
        self.env.cfg_path.write_text(self.env.cfg_path.read_text() + '\n[[match]]\nfiler = "One"\n')
        with self.assertRaises(ConfigError):
            self.env.cfg()

    def test_ai_destination_must_be_allowed(self):
        text = self.env.cfg_path.read_text().replace('"Quarantine" = "junk"', '"Elsewhere" = "x"')
        self.env.cfg_path.write_text(text)
        with self.assertRaises(ConfigError):
            self.env.cfg()

    def test_protected_patterns_include_vip_filer(self):
        self.assertIn("mom@family.com", self.cfg.protected_patterns)
        self.assertTrue(self.cfg.is_protected_sender("Boss <BOSS@work.com>"))


class TestIndexAndRules(Base):
    def test_trashed_messages_are_ignored(self):
        self.env.add("INBOX", "a@deals.com", "gone", flags="ST")
        self.env.add("INBOX", "a@deals.com", "live")
        self.idx.update(verbose=False)
        self.assertEqual([r["subject"] for r in self.idx.live("INBOX")], ["live"])

    def test_index_is_incremental(self):
        _, path = self.env.add("INBOX", "x@y.com", "one")
        self.idx.update(verbose=False)
        os.rename(path, str(path).replace(":2,S", ":2,FS"))
        self.assertEqual(self.idx.update(verbose=False), (0, 1, 0))
        self.assertEqual(self.idx.live("INBOX")[0]["flags"], "FS")

    def test_filing_and_keep_last_n(self):
        self.env.add("INBOX", "Mom <mom@family.com>", "hi")
        self.env.add("INBOX", "Shop <sale@deals.com>", "newest", days_ago=0)
        self.env.add("INBOX", "Shop <sale@deals.com>", "older", days_ago=2)
        self.env.add("IMAPSanity/One", "Shop <sale@deals.com>", "resident", days_ago=5)
        self.env.add("INBOX", "someone@else.com", "untouched")
        actions, _ = self.plan_rules()
        by_subject = {a["subject"]: a for a in actions}
        self.assertEqual(by_subject["hi"]["dest"], "IMAPSanity/VIP")
        self.assertEqual(by_subject["newest"]["dest"], "IMAPSanity/One")
        self.assertEqual(by_subject["older"]["dest"], "Quarantine")       # trimmed on arrival
        self.assertEqual(by_subject["resident"]["dest"], "Quarantine")    # trimmed in place
        self.assertNotIn("untouched", by_subject)
        self.assertTrue(all(a["approved"] for a in actions))

    def test_flagged_and_protected_are_not_trimmed(self):
        self.env.add("IMAPSanity/One", "sale@deals.com", "new", days_ago=0)
        self.env.add("IMAPSanity/One", "sale@deals.com", "flagged", days_ago=3, flags="FS")
        self.env.add("IMAPSanity/One", "Boss <boss@work.com> weekly digest", "weekly digest", days_ago=1)
        self.env.add("IMAPSanity/One", "news@x.com", "Weekly Digest #1", days_ago=0)
        actions, notes = self.plan_rules()
        self.assertEqual([a["subject"] for a in actions], [])
        self.assertTrue(any("protected" in n for n in notes))


class TestGuards(Base):
    def action(self, **kw):
        a = {"folder": "INBOX", "dest": "Filtered/News", "msgid": "<x>", "from": "a@b.com",
             "source": "rule", "approved": True, "subject": ""}
        a.update(kw)
        return a

    def test_rejections(self):
        cases = {
            "not in allow": self.action(dest="Spam"),
            "protected": self.action(folder="Sent"),
            "not allowed for AI": self.action(source="ai", dest="Local/Done"),
            "cannot be quarantined": self.action(dest="Quarantine", **{"from": "Mom <mom@family.com>"}),
            "no Message-ID": self.action(msgid=""),
            "different backends": self.action(dest="Local/Done"),
        }
        self.cfg.maildir_folders = ["Local/Done"]
        for expected, a in cases.items():
            v = guards.check_plan(self.cfg, [a], {})
            self.assertEqual(len(v.rejected), 1, expected)
            self.assertIn(expected, v.rejected[0][1])

    def test_unapproved_are_ignored(self):
        v = guards.check_plan(self.cfg, [self.action(approved=False)], {})
        self.assertEqual((v.ok, v.rejected), ([], []))

    def test_caps_abort(self):
        many = [self.action(msgid=f"<{i}>") for i in range(60)]
        self.assertTrue(guards.check_plan(self.cfg, many, {}).aborts)
        self.assertFalse(guards.check_plan(self.cfg, many, {}, max_moves=100).aborts)
        frac = [self.action(msgid=f"<{i}>") for i in range(8)]
        self.assertTrue(guards.check_plan(self.cfg, frac, {"INBOX": 12}).aborts)
        self.assertFalse(guards.check_plan(self.cfg, frac, {"INBOX": 9}).aborts)  # below min size


class TestImapBackend(Base):
    def fake(self):
        return FakeIMAP({
            "INBOX": {1: ("<a@x>", "\\Seen"), 2: ("<dup@x>", ""), 3: ("<dup@x>", ""), 4: ("<f@x>", "\\Flagged")},
            "INBOX.Filtered.News": {}, "INBOX.Quarantine": {},
        })

    def test_move_by_message_id(self):
        conn = self.fake()
        acts = [{"msgid": m, "folder": "INBOX", "dest": d} for m, d in
                [("<a@x>", "Filtered/News"), ("<dup@x>", "Filtered/News"), ("<f@x>", "Filtered/News"),
                 ("<none@x>", "Filtered/News")]]
        acts.append({"msgid": "<a@x>", "folder": "INBOX", "dest": "Nope"})
        with ImapBackend(self.cfg, conn=conn) as b:
            res = {(a["msgid"], a["dest"]): s for a, s, _ in b.move("INBOX", acts)}
        self.assertEqual(res[("<a@x>", "Filtered/News")], "moved")
        self.assertEqual(res[("<dup@x>", "Filtered/News")], "ambiguous")
        self.assertEqual(res[("<f@x>", "Filtered/News")], "flagged")
        self.assertEqual(res[("<none@x>", "Filtered/News")], "not_found")
        self.assertEqual(res[("<a@x>", "Nope")], "failed")
        self.assertEqual(list(conn.boxes["INBOX.Filtered.News"].values()), [("<a@x>", "\\Seen")])
        self.assertFalse(any(c == "EXPUNGE" for c, _ in conn.log))

    def test_refuses_without_move(self):
        with self.assertRaises(Exception):
            ImapBackend(self.cfg, conn=FakeIMAP({}, caps="IMAP4rev1")).__enter__()


class TestApplyUndoPurge(Base):
    def setUp(self):
        super().setUp()
        self.conn = FakeIMAP({"INBOX": {}, "INBOX.IMAPSanity.One": {}, "INBOX.IMAPSanity.VIP": {},
                              "INBOX.Quarantine": {}, "INBOX.Filtered.News": {}})
        patcher = mock.patch("imapsanity.apply.ImapBackend", lambda cfg: ImapBackend(cfg, conn=self.conn))
        patcher.start()
        self.addCleanup(patcher.stop)

    def seed(self, folder, *args, **kw):
        msgid, path = self.env.add(folder, *args, **kw)
        box = self.conn.boxes["INBOX" if folder == "INBOX" else "INBOX." + folder.replace("/", ".")]
        box[len(box) + 1] = (msgid, "")
        return msgid

    def make_plan(self):
        actions, _ = self.plan_rules()
        return plan.save(self.cfg, plan.new_plan(actions))

    def test_dry_run_changes_nothing(self):
        self.seed("INBOX", "sale@deals.com", "x")
        path = self.make_plan()
        self.assertEqual(apply.apply_plan(self.cfg, self.idx, path, execute=False, out=quiet), 0)
        self.assertEqual(len(self.conn.boxes["INBOX"]), 1)
        self.assertEqual(journal.all_runs(self.cfg), [])

    def test_execute_undo_and_no_reapply(self):
        self.seed("INBOX", "sale@deals.com", "new", days_ago=0)
        self.seed("INBOX", "sale@deals.com", "old", days_ago=3)
        path = self.make_plan()
        self.assertEqual(apply.apply_plan(self.cfg, self.idx, path, execute=True, out=quiet), 0)
        self.assertEqual(len(self.conn.boxes["INBOX"]), 0)
        self.assertEqual(len(self.conn.boxes["INBOX.IMAPSanity.One"]), 1)
        self.assertEqual(len(self.conn.boxes["INBOX.Quarantine"]), 1)
        self.assertEqual(apply.apply_plan(self.cfg, self.idx, path, execute=True, out=quiet), 2)

        run = journal.all_runs(self.cfg)[0]
        entries = journal.read(self.cfg, run)
        self.assertEqual([e["status"] for e in entries], ["intent", "intent", "moved", "moved"])
        self.assertEqual(apply.undo(self.cfg, run, execute=True, out=quiet), 0)
        self.assertEqual(len(self.conn.boxes["INBOX"]), 2)
        self.assertEqual(apply.undo(self.cfg, run, execute=True, out=quiet), 2)  # already undone

    def test_cycle_does_not_shadow_manual_plan(self):
        from imapsanity import cli
        manual = plan.save(self.cfg, plan.new_plan([]))
        self.seed("INBOX", "sale@deals.com", "x")
        with mock.patch("builtins.print"):
            cli.cmd_cycle(self.cfg, self.idx, None)
        self.assertEqual(len(self.conn.boxes["INBOX.IMAPSanity.One"]), 1)
        self.assertEqual(plan.resolve(self.cfg), manual)
        self.assertEqual(len(list(plan.plans_dir(self.cfg).glob("cycle-*.json"))), 1)

    def test_unapproved_ai_actions_not_applied(self):
        self.seed("INBOX", "news@letters.com", "issue 5")
        self.idx.update(verbose=False)
        row = self.idx.live("INBOX")[0]
        path = plan.save(self.cfg, plan.new_plan([plan.make_action(row, "Filtered/News", "ai", "news", False, 0.9)]))
        apply.apply_plan(self.cfg, self.idx, path, execute=True, out=quiet)
        self.assertEqual(len(self.conn.boxes["INBOX"]), 1)

    def test_purge_requires_age_and_confirmation(self):
        self.seed("INBOX", "sale@deals.com", "new", days_ago=0)
        self.seed("INBOX", "sale@deals.com", "old", days_ago=3)
        apply.apply_plan(self.cfg, self.idx, self.make_plan(), execute=True, out=quiet)
        apply.purge(self.cfg, 30, execute=True, inp=lambda _: "PURGE 1", out=quiet)
        self.assertEqual(len(self.conn.boxes["INBOX.Quarantine"]), 1)   # too young
        apply.purge(self.cfg, 0, execute=True, inp=lambda _: "yes", out=quiet)
        self.assertEqual(len(self.conn.boxes["INBOX.Quarantine"]), 1)   # not confirmed
        apply.purge(self.cfg, 0, execute=True, inp=lambda _: "PURGE 1", out=quiet)
        self.assertEqual(len(self.conn.boxes["INBOX.Quarantine"]), 0)
        self.assertEqual(len(self.conn.boxes["INBOX.IMAPSanity.One"]), 1)  # filed mail untouched


class TestMaildirBackendAndBreaker(Base):
    maildir_folders = ("Local/Inbox", "Local/Done")
    push = ("true",)

    def test_move_breaker_and_undo(self):
        msgid, path = self.env.add("Local/Inbox", "x@y.com", "move me", uid=42)
        _, stray = self.env.add("Local/Inbox", "x@y.com", "keep me", uid=43)
        self.cfg.pull_commands = []
        sync.pull(self.cfg, self.idx, execute=True, out=quiet)  # sets the baseline

        row = next(r for r in self.idx.live("Local/Inbox") if r["msgid"] == msgid)
        action = plan.make_action(row, "Local/Done", "rule", "test", True)
        action["id"] = "a0001"
        jnl = journal.Journal(self.cfg, "run-1")
        tally = apply.execute_moves(self.cfg, [action], jnl, out=quiet)
        self.assertEqual(tally["moved"], 1)
        moved = os.listdir(self.env.mail / "Local/Done/cur")
        self.assertEqual(len(moved), 1)
        self.assertNotIn(",U=", moved[0])  # fresh UID on push

        self.assertEqual(sync.breaker(self.cfg)[0], [])  # explained by the journal
        os.remove(stray)                                  # unexplained loss
        problems, _ = sync.breaker(self.cfg)
        self.assertTrue(problems and "vanished" in problems[0])
        self.assertEqual(sync.push(self.cfg, execute=True, out=quiet), 2)

        self.assertEqual(apply.undo(self.cfg, "run-1", execute=True, out=quiet), 0)
        self.assertEqual(len(os.listdir(self.env.mail / "Local/Inbox/cur")), 1)

    def test_push_snapshots_and_rebaselines(self):
        self.env.add("Local/Inbox", "x@y.com", "a")
        self.cfg.pull_commands = []
        sync.pull(self.cfg, self.idx, execute=True, out=quiet)
        self.assertEqual(sync.push(self.cfg, execute=True, out=quiet), 0)
        self.assertEqual(len(list((self.cfg.state_dir / "snapshots").iterdir())), 1)
        self.assertEqual(sync.load_state(self.cfg)["delta"], {})


class TestAI(Base):
    def test_proposals_are_unapproved_validated_and_rejections_stick(self):
        self.env.add("INBOX", "news@letters.com", "Issue 1")
        self.env.add("INBOX", "Mom <mom@family.com>", "dinner")       # rule match: not sent to AI
        self.env.add("INBOX", "Boss <boss@work.com>", "report")       # protected: not sent to AI
        self.env.add("INBOX", "friend@x.com", "lunch?")
        self.idx.update(verbose=False)
        sent = []

        def fake_claude(cfg, system, prompt, schema):
            items = json.loads(prompt.split("\n", 1)[1])
            sent.extend(i["subject"] for i in items)
            self.assertIn("UNTRUSTED", system)
            out = []
            for i in items:
                if i["subject"] == "Issue 1":
                    out.append({"id": i["id"], "dest": "Filtered/News", "confidence": 0.95, "reason": "newsletter"})
                else:
                    out.append({"id": i["id"], "dest": "Sent", "confidence": 1, "reason": "invalid dest"})
            return {"items": out}, 0.01

        with mock.patch("imapsanity.ai.run_claude", fake_claude):
            actions = ai.build_actions(self.cfg, self.idx, exclude=set(), out=quiet)
            self.assertEqual(sorted(sent), ["Issue 1", "lunch?"])
            self.assertEqual([(a["subject"], a["dest"], a["approved"]) for a in actions],
                             [("Issue 1", "Filtered/News", False)])

            path = plan.save(self.cfg, plan.new_plan(actions))
            plan.review(self.cfg, self.idx, path, inp=lambda _: "r", out=quiet)
            self.assertEqual(ai.build_actions(self.cfg, self.idx, exclude=set(), out=quiet), [])
            self.assertEqual(len(sent), 2)  # cached, not re-classified


SHADOW_CONFIG = """
[auto]
mode = "shadow"
destinations = ["Filtered/News"]

[typesafe]
enabled = true
"""


def ts_response(choice, conf, personal=0.0, important=0.0):
    return {"model": "jev-1.13.0", "usage": {"input_tokens": 300}, "answers": {
        "destination": {"type": "choice", "choice": choice, "confidence": conf,
                        "probabilities": {choice: conf}},
        "personal": {"type": "noul", "noul": personal},
        "important": {"type": "noul", "noul": important}}}


class TestShadow(Base):
    def setUp(self):
        super().setUp()
        self.env.cfg_path.write_text(self.env.cfg_path.read_text() + SHADOW_CONFIG)
        self.cfg = load(self.env.cfg_path)
        self.claude = {}      # subject -> (dest, confidence)
        self.ts = {}          # subject -> response
        self.ts_sent = []
        os.environ["TYPESAFE_API_KEY"] = "test-key"
        self.addCleanup(os.environ.pop, "TYPESAFE_API_KEY", None)

    def fake_claude(self, cfg, system, prompt, schema):
        items = json.loads(prompt.split("\n", 1)[1])
        out = [{"id": i["id"], "dest": self.claude[i["subject"]][0], "confidence": self.claude[i["subject"]][1],
                "reason": "test"} for i in items]
        return {"items": out}, 0.0

    def fake_post(self, cfg, key, payload):
        self.assertEqual(key, "test-key")
        subject = payload["state"]["email"]["subject"]
        self.ts_sent.append(payload)
        return self.ts[subject]

    def patched(self):
        stack = mock.patch("imapsanity.ai.run_claude", self.fake_claude), \
            mock.patch("imapsanity.typesafe._post", self.fake_post)
        for m in stack:
            m.start()
            self.addCleanup(m.stop)

    def test_config_validation(self):
        text = self.env.cfg_path.read_text()
        for bad in ('destinations = ["Quarantine"]', 'destinations = ["Local/Done"]'):
            self.env.cfg_path.write_text(text.replace('destinations = ["Filtered/News"]', bad))
            with self.assertRaises(ConfigError):
                load(self.env.cfg_path)
        self.env.cfg_path.write_text(text.replace('mode = "shadow"', 'mode = "on"'))
        with self.assertRaises(ConfigError):
            load(self.env.cfg_path)

    def test_typesafe_request_shape_and_cache(self):
        self.patched()
        self.env.add("INBOX", "news@letters.com", "Issue 1")
        self.idx.update(verbose=False)
        self.ts["Issue 1"] = ts_response("Filtered/News", 0.9)
        rows = ai.candidates(self.cfg, self.idx)
        self.assertEqual(typesafe.classify(self.cfg, self.idx, rows, 10, out=quiet), 1)
        self.assertEqual(typesafe.classify(self.cfg, self.idx, rows, 10, out=quiet), 0)  # cached
        p = self.ts_sent[0]
        self.assertEqual(set(p["questions"]), {"destination", "personal", "important"})
        self.assertEqual(list(p["questions"]["destination"]["criteria"]), ["KEEP", "Filtered/News", "Quarantine"])
        self.assertNotIn("date", p["state"]["email"])
        self.assertEqual(self.idx.ts_cached(rows[0]["msgid"])["dest"], "Filtered/News")

    def test_typesafe_rejects_unknown_choice(self):
        self.patched()
        self.env.add("INBOX", "news@letters.com", "Issue 1")
        self.idx.update(verbose=False)
        self.ts["Issue 1"] = ts_response("Sent", 0.9)
        with self.assertRaises(typesafe.TypeSafeError):
            typesafe.classify(self.cfg, self.idx, ai.candidates(self.cfg, self.idx), 10, out=quiet)

    def test_cycle_shadow_moves_nothing_and_applies_vetoes(self):
        self.patched()
        self.env.add("INBOX", "news@letters.com", "Issue 1")
        self.env.add("INBOX", "friend@x.com", "lunch?")
        self.env.add("INBOX", "bank@bank.com", "statement")
        self.idx.update(verbose=False)
        self.claude = {"Issue 1": ("Filtered/News", 0.9), "lunch?": ("KEEP", 0.9),
                       "statement": ("Filtered/News", 0.7)}
        self.ts = {"Issue 1": ts_response("Filtered/News", 0.95),
                   "lunch?": ts_response("Filtered/News", 0.95, personal=0.9),     # personal veto
                   "statement": ts_response("Filtered/News", 0.95, important=0.8)}  # important veto
        lines = []
        shadow.run(self.cfg, self.idx, out=lines.append)
        summary = lines[-1]
        self.assertIn("claude 1 (Filtered/News 1)", summary)
        self.assertIn("typesafe 1 (Filtered/News 1)", summary)
        self.assertIn("both agree 1", summary)
        self.assertEqual(sorted(p.name for p in (self.env.mail / "INBOX" / "cur").iterdir()).__len__(), 3)
        self.assertFalse((self.cfg.state_dir / "journal").exists())

    def test_classifier_failure_is_logged_not_raised(self):
        self.env.add("INBOX", "news@letters.com", "Issue 1")
        self.idx.update(verbose=False)

        def boom(*a, **k):
            raise typesafe.TypeSafeError("HTTP 401")
        with mock.patch("imapsanity.ai.run_claude", side_effect=ai.AIError("no claude")), \
                mock.patch("imapsanity.typesafe._post", boom):
            lines = []
            shadow.run(self.cfg, self.idx, out=lines.append)
        self.assertTrue(any("claude skipped" in l for l in lines))
        self.assertTrue(any("typesafe skipped" in l for l in lines))

    def test_report_outcomes(self):
        self.patched()
        filed, _ = self.env.add("Filtered/News", "news@letters.com", "Issue 1", days_ago=5)
        kept, _ = self.env.add("INBOX", "shop@store.com", "Sale", days_ago=5, flags="S")
        self.idx.update(verbose=False)
        for msgid in (filed, kept):
            self.idx.ai_store(msgid, "Filtered/News", 0.9, "test", "sonnet")
            self.idx.ts_store(msgid, "Filtered/News", 0.9, "{}", 0.0, 0.0, "jev-1.13.0")
        lines = []
        shadow.report(self.cfg, self.idx, 30, out=lines.append)
        text = "\n".join(lines)
        self.assertIn("2 message(s)", text)
        self.assertRegex(text, r"now in that folder\s+1\s+1")
        self.assertRegex(text, r"still in inbox, read\s+1\s+1")


if __name__ == "__main__":
    unittest.main()
