import argparse
import contextlib
import fcntl
import io
import json
import os
import time
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest import mock

from imapsanity import ai, apply, cli, guards, journal, maildir, plan, quarantine, rules, shadow, sync, typesafe
from imapsanity.backends.imap import ImapBackend
from imapsanity.config import ConfigError, load, load_all
from imapsanity.index import Index

from .helpers import FOLDERS, Env, FakeIMAP


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

    def test_single_account_table_unchanged(self):
        self.assertEqual(self.cfg.name, "")
        self.assertEqual(self.cfg.state_dir, self.env.root / "state")
        self.assertEqual(self.cfg.matches[0].label(), "match#1 sender~mom@family.com -> VIP")


MULTI_ACCOUNTS = """
[[account]]
name = "personal"
email = "me@example.com"
imap_host = "imap.example.com"
keychain_service = "test"
maildir = "{root}/Mail"
pull = [["mbsync", "personal"]]

  [account.safety]
  max_moves_per_run = 7

  [account.destinations]
  allow = ["Clients"]

  [account.filers.One]
  folder = "IMAPSanity/Uno"
  keep = 2

  [account.filers.Clients]
  folder = "Clients"
  keep = "all"

  [[account.match]]
  sender = "@client.com"
  filer = "Clients"

[[account]]
name = "work"
email = "me@work.com"
imap_host = "imap.work.com"
keychain_service = "test"
maildir = "{root}/Mail2"
state = "{root}/oldstate"

  [account.ai]
  enabled = false
"""


class TestMultiAccount(Base):
    def setUp(self):
        super().setUp()
        text = self.env.cfg_path.read_text()
        shared = text[text.index("[paths]"):].replace(f'maildir = "{self.env.root}/Mail"\n', "")
        self.env.cfg_path.write_text(shared + MULTI_ACCOUNTS.format(root=self.env.root))
        self.personal, self.work = load_all(self.env.cfg_path)

    def args(self, *argv):
        return cli.build_parser().parse_args(argv)

    def test_merge(self):
        p, w = self.personal, self.work
        self.assertEqual((p.name, p.account.email, w.account.imap_host), ("personal", "me@example.com", "imap.work.com"))
        self.assertEqual(p.state_dir, self.env.root / "state" / "personal")
        self.assertEqual(w.state_dir, self.env.root / "oldstate")
        self.assertEqual(p.pull_commands, [["mbsync", "personal"]])
        self.assertEqual(w.pull_commands, [])
        # Key-by-key section overrides; untouched keys come from the shared section.
        self.assertEqual((p.safety.max_moves_per_run, w.safety.max_moves_per_run), (7, 50))
        self.assertEqual(p.safety.protected_senders, ["boss@work.com"])
        self.assertEqual((p.ai.enabled, w.ai.enabled), (True, False))
        # Filers: same name replaces, new ones are added; destinations are a union.
        self.assertEqual(p.filers["One"].folder, "IMAPSanity/Uno")
        self.assertEqual(w.filers["One"].folder, "IMAPSanity/One")
        self.assertIn("Clients", p.allow_destinations)
        self.assertNotIn("Clients", w.allow_destinations)
        self.assertIn("Filtered/News", p.allow_destinations)
        # Account rules first, with their own labels; shared labels don't shift.
        self.assertEqual([m.label() for m in p.matches[:2]],
                         ["personal:match#1 sender~@client.com -> Clients", "match#1 sender~mom@family.com -> VIP"])
        self.assertEqual(len(w.matches), 3)
        self.assertIn("mom@family.com", w.protected_patterns)

    def test_load_needs_account_when_several(self):
        with self.assertRaises(ConfigError):
            load(self.env.cfg_path)
        self.assertEqual(load(self.env.cfg_path, "work").name, "work")
        with self.assertRaises(ConfigError):
            load(self.env.cfg_path, "nope")

    def test_bad_account_entries(self):
        text = self.env.cfg_path.read_text()
        root = self.env.root
        cases = {
            "used twice": text.replace('name = "work"', 'name = "personal"'),
            "letters, digits": text.replace('name = "work"', 'name = "../x"'),
            "work: unknown keys: stat": text.replace('state = ', 'stat = '),
            "work: maildir is required": text.replace(f'maildir = "{root}/Mail2"', ''),
            # A missing required key is a config error, not a TypeError.
            "work: [account] missing keys: imap_host": text.replace('imap_host = "imap.work.com"', ''),
            # Errors inside a per-account section say which account they're in.
            "work: [ai] unknown keys: enabeld": text.replace("enabled = false", "enabeld = false"),
            "personal: [account.destinations] unknown keys: alow": text.replace('allow = ["Clients"]',
                                                                                'alow = ["Clients"]'),
            # Settings naming one account's mail can't be shared.
            "[mbsync].pull can't be shared": text.replace("[mbsync]", '[mbsync]\npull = [["mbsync", "x"]]'),
            "[backends].maildir_folders can't be shared": text.replace("maildir_folders = []",
                                                                       'maildir_folders = ["Local/Inbox"]'),
            "[paths].maildir can't be shared": text.replace("[paths]", f'[paths]\nmaildir = "{root}/Mail"'),
            # Accounts can't share or nest state dirs or maildirs, or pull each other's mail.
            "state_dir": text.replace(f'state = "{root}/oldstate"', f'state = "{root}/state/personal"'),
            "maildir": text.replace(f'maildir = "{root}/Mail2"', f'maildir = "{root}/Mail/sub"'),
            "same mbsync command": text.replace(f'state = "{root}/oldstate"',
                                               f'state = "{root}/oldstate"\npull = [["mbsync", "personal"]]'),
            "syncs every channel": text.replace('["mbsync", "personal"]', '["mbsync", "-a"]'),
        }
        for message, bad in cases.items():
            self.env.cfg_path.write_text(bad)
            with self.assertRaises(ConfigError, msg=message) as cm:
                load_all(self.env.cfg_path)
            self.assertIn(message, str(cm.exception))

    def test_select_accounts(self):
        cfgs = [self.personal, self.work]
        with mock.patch.dict(os.environ, {"IMAPSANITY_ACCOUNT": ""}):
            self.assertEqual(len(cli.select_accounts(cfgs, self.args("plan"))), 2)
            self.assertEqual(len(cli.select_accounts(cfgs, self.args("sync", "pull"))), 2)
            for argv in (("apply",), ("sync", "push"), ("review",), ("undo", "20260101-000000-apply")):
                with self.assertRaises(ConfigError):
                    cli.select_accounts(cfgs, self.args(*argv))
            # purge names its account even when only one is configured as [[account]].
            with self.assertRaises(ConfigError):
                cli.select_accounts(cfgs[:1], self.args("purge", "--older-than", "30"))
            self.assertEqual(cli.select_accounts(cfgs, self.args("--account", "work", "apply")), [self.work])
            args = self.args("undo", "work/20260101-000000-apply")
            self.assertEqual(cli.select_accounts(cfgs, args), [self.work])
            self.assertEqual(args.run, "20260101-000000-apply")
            with self.assertRaises(ConfigError):
                cli.select_accounts(cfgs, self.args("--account", "personal", "undo", "work/x"))
        with mock.patch.dict(os.environ, {"IMAPSANITY_ACCOUNT": "personal"}):
            self.assertEqual(cli.select_accounts(cfgs, self.args("apply")), [self.personal])
            # A single [account] table has no names, so the variable doesn't apply to it.
            legacy = self.cfg   # loaded from the single-[account] file before setUp rewrote it
            self.assertEqual(cli.select_accounts([legacy], self.args("apply")), [legacy])
            with self.assertRaises(ConfigError):
                cli.select_accounts([legacy], self.args("--account", "personal", "apply"))

    def test_one_account_failing_doesnt_stop_the_others(self):
        self.work.state_dir.mkdir(parents=True)
        out, err = io.StringIO(), io.StringIO()
        with open(self.work.state_dir / "lock", "w") as held, \
                mock.patch.dict(os.environ, {"IMAPSANITY_ACCOUNT": ""}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            rc = cli.main(["--config", str(self.env.cfg_path), "runs"])
        self.assertEqual(rc, 1)
        self.assertIn("== personal ==", out.getvalue())
        self.assertIn("work: skipped: another imapsanity run is in progress", err.getvalue())

        boom = mock.Mock(side_effect=[RuntimeError("down"), 0])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(cli.COMMANDS, {"runs": boom}), mock.patch.dict(os.environ, {"IMAPSANITY_ACCOUNT": ""}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["--config", str(self.env.cfg_path), "runs"])
        self.assertEqual((rc, boom.call_count), (1, 2))
        self.assertIn("personal: error:", err.getvalue())
        self.assertIn("Traceback", err.getvalue())
        self.assertIn("RuntimeError: down", err.getvalue())

        clean = mock.Mock(side_effect=[SystemExit(None), SystemExit(0)])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(cli.COMMANDS, {"runs": clean}), mock.patch.dict(os.environ, {"IMAPSANITY_ACCOUNT": ""}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["--config", str(self.env.cfg_path), "runs"])
        self.assertEqual((rc, err.getvalue()), (0, ""))

    def test_password_env_is_per_account(self):
        from imapsanity.backends.imap import get_password
        env = {"IMAPSANITY_PASSWORD": "shared", "IMAPSANITY_PASSWORD_WORK": "w"}
        with mock.patch.dict(os.environ, env), mock.patch("subprocess.run") as run:
            self.assertEqual(get_password(self.work.account, "work"), "w")
            self.assertEqual(get_password(self.cfg.account, ""), "shared")
            run.return_value = mock.Mock(returncode=0, stdout="kc\n")
            # The shared variable is never used for a named account.
            self.assertEqual(get_password(self.personal.account, "personal"), "kc")

    def test_suggest_rules_writes_account_rules(self):
        self.idx.close()
        self.idx = Index(self.personal)
        for i in range(3):
            self.env.add("INBOX", "promo@vendor.com", f"Sale {i}")
        result = {"suggestions": [{"sender": "promo@vendor.com", "filer": "One", "reason": "bulk"}]}
        with mock.patch.object(ai, "run_claude", return_value=(result, 0.01)):
            self.idx.update(verbose=False)
            text = ai.suggest_rules(self.personal, self.idx, min_count=3, out=quiet)
        self.assertIn("[[account.match]]", text)
        self.assertIn("under the [[account]] named 'personal'", text)
        self.assertNotIn("\n[[match]]", text)

    def test_runs_prefixes_account(self):
        j = journal.Journal(self.work, "20260101-000000-apply")
        j.write({"folder": "INBOX", "dest": "Quarantine"}, "done", "imap")
        j.close()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.cmd_runs(self.work, None, argparse.Namespace(last=5))
        self.assertTrue(out.getvalue().startswith("work/20260101-000000-apply"))


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

    def test_duplicate_copies_count_once_and_are_not_trimmed(self):
        self.env.add("IMAPSanity/One", "sale@deals.com", "new", days_ago=0)
        dup, _ = self.env.add("IMAPSanity/One", "sale@deals.com", "old copy", days_ago=3)
        self.env.add("IMAPSanity/One", "sale@deals.com", "old copy", days_ago=3, msgid=dup)
        self.env.add("IMAPSanity/One", "sale@deals.com", "oldest", days_ago=5)
        actions, notes = self.plan_rules()
        self.assertEqual([a["subject"] for a in actions], ["oldest"])
        self.assertTrue(any("duplicate Message-ID in IMAPSanity/One" in n for n in notes))

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


class TestBacklogLimits(Base):
    def test_scale_from_gap_capped(self):
        s = self.cfg.safety
        s.max_moves_per_run, s.max_quarantine_per_run, s.max_fraction_per_folder = 200, 100, 0.25
        s.cycle_interval_minutes, s.max_backlog_scale, s.max_backlog_fraction = 15, 5, 0.5
        self.assertEqual(guards.backlog_limits(self.cfg, 0), (1.0, 200, 0.25, 100))        # first run
        self.assertEqual(guards.backlog_limits(self.cfg, 15 * 60), (1.0, 200, 0.25, 100))  # on schedule
        self.assertEqual(guards.backlog_limits(self.cfg, 30 * 60), (2.0, 400, 0.5, 200))
        self.assertEqual(guards.backlog_limits(self.cfg, 62 * 3600), (5.0, 1000, 0.5, 500))  # weekend asleep
        self.assertEqual(guards.backlog_limits(self.cfg, 60, carried=3), (3.0, 600, 0.5, 300))


class TestImapBackend(Base):
    def test_tls_verifies_the_server(self):
        import ssl
        conn = FakeIMAP({"INBOX": {}})
        conn.login = mock.Mock(return_value=("OK", [b""]))
        with mock.patch("imaplib.IMAP4_SSL", return_value=conn) as ctor, \
                mock.patch.dict(os.environ, {"IMAPSANITY_PASSWORD": "pw"}):
            with ImapBackend(self.cfg):
                pass
        (host, port), kw = ctor.call_args
        self.assertEqual((host, port), ("imap.example.com", 993))
        self.assertEqual(kw["ssl_context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(kw["ssl_context"].check_hostname)
        conn.login.assert_called_once_with("me@example.com", "pw")

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


class ImapFixture:
    """A fake IMAP server behind the apply backend."""

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


class TestApplyUndoPurge(ImapFixture, Base):
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

    def test_cycle_limits_scale_after_gap_not_after_abort(self):
        from imapsanity import cli
        self.cfg.safety.max_moves_per_run = 1
        self.cfg.safety.min_folder_size_for_fraction = 1000
        for days in (0, 1, 2):
            self.seed("INBOX", "sale@deals.com", f"x{days}", days_ago=days)
        with mock.patch("builtins.print"):
            self.assertEqual(cli.cmd_cycle(self.cfg, self.idx, None), 2)   # first run: 1x, 3 moves > 1
            self.assertEqual(cli.cmd_cycle(self.cfg, self.idx, None), 2)   # an abort doesn't raise the scale
            self.assertEqual(len(self.conn.boxes["INBOX"]), 3)
            self.idx.set_meta("cycle_last_run", str(time.time() - 30 * 60))  # one cycle missed: 2x
            self.assertEqual(cli.cmd_cycle(self.cfg, self.idx, None), 2)
            self.assertAlmostEqual(float(self.idx.get_meta("cycle_backlog_scale")), 2.0, places=3)  # carried
            self.cfg.safety.max_moves_per_run = 2                             # 2 x 2 = 4 >= 3
            self.assertEqual(cli.cmd_cycle(self.cfg, self.idx, None), 0)
        self.assertEqual(len(self.conn.boxes["INBOX"]), 0)
        self.assertEqual(self.idx.get_meta("cycle_backlog_scale"), "1")

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


class QuarantineHelpers:
    """Messages with arbitrary headers, and mirroring the fake server into the local maildir."""

    def put(self, folder, sender, subject, extra="", days_ago=0):
        """A message with arbitrary extra headers, locally and on the fake server."""
        self.env.counter += 1
        n = self.env.counter
        msgid = f"<q{n}@test>"
        date = format_datetime(datetime.now(timezone.utc) - timedelta(days=days_ago))
        path = self.env.mail / folder / "cur" / f"17100000{n:02d}.1_{n}.host,U={n}:2,S"
        path.write_text(f"From: {sender}\nSubject: {subject}\nDate: {date}\nMessage-ID: {msgid}\n{extra}\nbody {n}\n")
        box = self.conn.boxes["INBOX" if folder == "INBOX" else "INBOX." + folder.replace("/", ".")]
        box[len(box) + 1] = (msgid, "")
        return msgid

    def mirror(self):
        """Make the local maildir match the fake server, as an mbsync pull would."""
        where = {m: name for name, box in self.conn.boxes.items() for m, _ in box.values()}
        for folder in FOLDERS:
            for f in (self.env.mail / folder / "cur").iterdir():
                m = next((line.split(": ", 1)[1] for line in f.read_text().splitlines()
                          if line.startswith("Message-ID: ")), None)
                target = where.get(m)
                if target is None:
                    continue   # local-only (e.g. a Sent message the test wrote), or purged: leave it
                local = "INBOX" if target == "INBOX" else target[6:].replace(".", "/")
                if local != folder:
                    f.rename(self.env.mail / local / "cur" / f.name)
        self.idx.update(verbose=False)

    def quarantine(self, *msgids, source="rule"):
        self.idx.update(verbose=False)
        rows = [r for r in self.idx.live("INBOX") if r["msgid"] in msgids]
        actions = [plan.make_action(r, "Quarantine", source, f"test {source}", True) for r in rows]
        path = plan.save(self.cfg, plan.new_plan(actions))
        self.assertEqual(apply.apply_plan(self.cfg, self.idx, path, execute=True, out=quiet), 0)
        self.mirror()


class TestQuarantineReview(QuarantineHelpers, ImapFixture, Base):
    """Quarantine tiers, rescue + exceptions, and purge only deleting confirmed junk."""

    def test_tiers(self):
        (self.env.mail / "Sent" / "cur" / "1.s,U=1:2,S").write_text(
            "From: me@example.com\nTo: Friend <Friend@pal.com>\nCc: other@x.com\nMessage-ID: <s1@test>\n\nhi\n")
        friend = self.put("INBOX", "Friend <friend@pal.com>", "lunch?")
        trimmed = self.put("INBOX", "news@list.com", "issue 9", extra="List-Id: <news.list.com>\n")
        self.quarantine(friend, trimmed)
        pitch = self.put("INBOX", "rep@cold.com", "quick question")
        self.quarantine(pitch, source="ai")
        items = {i["msgid"]: i for i in quarantine.items(self.cfg, self.idx)}
        self.assertEqual({m: quarantine.tier(i) for m, i in items.items()},
                         {friend: "careful", pitch: "glance", trimmed: "rules"})
        self.assertIn("you've written to this sender", items[friend]["reasons"])
        self.assertEqual((items[pitch]["origin"], items[pitch]["why"], items[pitch]["ours"]), ("INBOX", "test ai", True))
        groups = quarantine.groups(items.values())
        self.assertEqual([(g["sender"], g["tier"]) for g in groups],
                         [("friend@pal.com", "careful"), ("rep@cold.com", "glance"), ("news@list.com", "rules")])

    def test_purge_only_deletes_confirmed_junk(self):
        a, b = self.put("INBOX", "x@a.com", "a"), self.put("INBOX", "y@b.com", "b")
        self.quarantine(a, b)
        lines = []
        apply.purge(self.cfg, 0, execute=True, inp=lambda _: "PURGE 0", out=lines.append, confirmed=set())
        self.assertEqual(len(self.conn.boxes["INBOX.Quarantine"]), 2)
        self.assertIn("2 old enough but not confirmed as junk", lines[0])
        self.idx.confirm_junk([a])
        apply.purge(self.cfg, 0, execute=True, inp=lambda _: "PURGE 1", out=quiet, confirmed=self.idx.confirmed_junk())
        self.assertEqual([m for m, _ in self.conn.boxes["INBOX.Quarantine"].values()], [b])
        self.idx.confirm_junk([b])
        self.idx.confirm_junk([b], confirmed=False)
        self.assertEqual(self.idx.confirmed_junk(), {a})

    def test_rescue_keeps_message_out_of_quarantine(self):
        old = self.put("INBOX", "sale@deals.com", "old", days_ago=3)
        self.put("INBOX", "sale@deals.com", "new")
        apply.apply_plan(self.cfg, self.idx, self.make_plan(), execute=True, out=quiet)   # keep-last-1
        self.mirror()
        self.assertEqual([i["msgid"] for i in quarantine.items(self.cfg, self.idx)], [old])
        self.idx.confirm_junk([old])

        tally = quarantine.rescue(self.cfg, self.idx, [old], out=quiet)
        self.assertEqual(tally, {"moved": 1})
        self.assertIn(old, [m for m, _ in self.conn.boxes["INBOX"].values()])
        self.mirror()
        cfg = self.env.cfg()   # a fresh load sees the saved exception
        self.assertIn(old, cfg.kept_msgids)
        self.assertNotIn(old, self.idx.confirmed_junk())
        self.assertEqual(self.idx.ai_decision(old, "Quarantine"), "rejected")
        actions, _ = rules.build_actions(cfg, self.idx)
        self.assertEqual({a["msgid"]: a["dest"] for a in actions}, {old: "IMAPSanity/One"})   # filed, not trimmed
        self.assertEqual(quarantine.items(cfg, self.idx), [])
        row = self.idx.live("INBOX")[0]
        self.assertEqual(guards.action_problem(cfg, plan.make_action(row, "Quarantine", "rule", "x", True)),
                         "kept message cannot be quarantined")

    def test_rescue_and_keep_sender(self):
        m = self.put("INBOX", "Pat <pat@co.com>", "invoice")
        self.quarantine(m, source="ai")
        quarantine.rescue(self.cfg, self.idx, [m], keep_sender=True, out=quiet)
        cfg = self.env.cfg()
        self.assertTrue(cfg.is_protected_sender("Pat <PAT@co.com>"))
        self.assertEqual(cfg.kept_msgids, set())
        self.assertIn("pat@co.com", cfg.protected_patterns)
        self.assertEqual(quarantine.rescue(cfg, self.idx, ["<gone@test>"], out=quiet), {})


class TestDashboard(QuarantineHelpers, ImapFixture, Base):
    def setUp(self):
        super().setUp()
        import socket
        from imapsanity import dashboard
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.app = dashboard.App(self.env.cfg_path, port, token="t0ken")
        handler = dashboard.make_handler(self.app)
        handler.log_message = lambda *a: None
        self.server = dashboard.ThreadingHTTPServer(("127.0.0.1", port), handler)
        self.server.daemon_threads = True
        import threading
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{port}"
        self.cookie = f"imapsanity{port}=t0ken"

    def http(self, method, path, form=None, headers=None, cookie=True):
        import http.client
        from urllib.parse import urlencode
        conn = http.client.HTTPConnection("127.0.0.1", self.app.port, timeout=10)
        hdrs = dict(headers or {})
        if cookie:
            hdrs.setdefault("Cookie", self.cookie)
        body = urlencode(form or {}, doseq=True) if form is not None else None
        if body is not None:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body, headers=hdrs)
        r = conn.getresponse()
        out = (r.status, dict(r.getheaders()), r.read().decode())
        conn.close()
        return out

    def test_access_control(self):
        self.assertEqual(self.http("GET", "/", cookie=False)[0], 403)
        self.assertEqual(self.http("GET", "/login?token=nope", cookie=False)[0], 403)
        status, headers, _ = self.http("GET", "/login?token=t0ken", cookie=False)
        self.assertEqual(status, 303)
        self.assertIn("HttpOnly; SameSite=Strict", headers["Set-Cookie"])
        self.assertEqual(self.http("GET", "/", headers={"Host": "evil.example:80"})[0], 400)
        status, headers, page = self.http("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        # the one script is the fixed Check all / Clear all helper, allowed only by its hash
        from imapsanity import dashboard
        import base64, hashlib, re
        scripts = re.findall(r"<script>(.*?)</script>", page, re.S)
        self.assertEqual(scripts, [dashboard.SELECT_JS])
        digest = base64.b64encode(hashlib.sha256(scripts[0].encode()).digest()).decode()
        self.assertIn(f"script-src 'sha256-{digest}';", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline';", headers["Content-Security-Policy"].split("style-src")[0])
        q = "/a/_/quarantine"
        self.assertEqual(self.http("POST", q, {"action": "junk", "msgid": "x"},
                                   headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.http("POST", q, {"action": "junk", "msgid": "x"},
                                   headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.http("POST", q, {"action": "junk", "msgid": "x"},
                                   headers={"Origin": "null"})[0], 403)
        # what a browser sends for a form on the dashboard's own page
        self.assertEqual(self.http("POST", q, {"action": "junk"},
                                   headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"})[0], 303)
        self.assertEqual(self.http("POST", q, {"action": "junk"},
                                   headers={"Origin": self.base, "Sec-Fetch-Site": "same-origin"})[0], 303)
        self.assertEqual(self.http("POST", q, {"action": "junk", "msgid": "x"},
                                   headers={"Origin": self.base, "Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.http("GET", "/a/nobody/quarantine")[0], 404)

    def test_quarantine_page_escapes_and_confirms(self):
        m = self.put("INBOX", "x@a.com", '<script>alert(1)</script> & "quotes"')
        self.quarantine(m)
        status, _, page = self.http("GET", "/a/_/quarantine")
        self.assertEqual(status, 200)
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quotes&quot;", page)
        self.assertIn("Trimmed by your keep-last-N rules", page)
        self.assertIn("Confirm all 1 as junk", page)
        self.assertIn('data-check="1">Check all</button>', page)
        self.assertIn('data-check="0">Clear all</button>', page)
        status, headers, _ = self.http("POST", "/a/_/quarantine", {"action": "junk", "msgid": [m]})
        self.assertEqual(status, 303)
        self.assertIn("Confirmed+as+junk", headers["Location"])
        self.assertEqual(self.idx.confirmed_junk(), {m})
        self.assertIn("Confirmed junk · 1", self.http("GET", "/a/_/quarantine")[2])
        self.assertIn("Nothing+selected", self.http("POST", "/a/_/quarantine", {"action": "junk"})[1]["Location"])

    def test_busy_while_cycle_holds_the_lock(self):
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        with open(self.cfg.state_dir / "lock", "w") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            status, headers, _ = self.http("POST", "/a/_/quarantine", {"action": "junk", "msgid": "x"})
        self.assertEqual(status, 303)
        self.assertIn("Busy", headers["Location"])
        self.assertEqual(self.idx.confirmed_junk(), set())

    def test_ai_review_and_apply_preview(self):
        m = self.put("INBOX", "news@letters.com", "issue 1")
        q = self.put("INBOX", "rep@cold.com", "pitch")
        self.idx.update(verbose=False)
        rows = {r["msgid"]: r for r in self.idx.live("INBOX")}
        p = plan.new_plan([plan.make_action(rows[m], "Filtered/News", "ai", "newsletter", False, 0.9),
                           plan.make_action(rows[q], "Quarantine", "ai", "cold pitch", False, 0.8)])
        path = plan.save(self.cfg, p)
        page = self.http("GET", "/a/_/review")[2]
        self.assertLess(page.index("rep@cold.com"), page.index("news@letters.com"))   # least confident first
        self.assertIn('value="a0001" checked', page)
        self.assertNotIn('value="a0002" checked', page)   # quarantine proposals start unticked
        self.http("POST", "/a/_/review", {"plan": path.name, "action": "approve", "id": "a0001"})
        self.http("POST", "/a/_/review", {"plan": path.name, "action": "reject", "id": "a0002"})
        self.assertEqual(self.idx.ai_decision(q, "Quarantine"), "rejected")
        self.assertEqual([a["approved"] for a in plan.load(path)["actions"]], [True, False])
        self.assertEqual(self.http("POST", "/a/_/review", {"plan": "../x.json", "action": "approve", "id": "a1"})[0], 303)

        status, _, page = self.http("POST", "/a/_/actions", {"op": "apply"})
        self.assertIn("dry run", page)
        self.assertIn("Apply for real", page)
        self.assertEqual(len(self.conn.boxes["INBOX"]), 2)
        self.http("POST", "/a/_/actions", {"op": "apply-execute", "plan": path.name})
        self.assertEqual([mm for mm, _ in self.conn.boxes["INBOX.Filtered.News"].values()], [m])

    def test_exceptions_page(self):
        self.http("POST", "/a/_/exceptions", {"action": "add", "sender": "@Friends.org"})
        self.assertIn("@friends.org", self.env.cfg().protected_patterns)
        self.assertIn("@friends.org", self.http("GET", "/a/_/exceptions")[2])
        self.http("POST", "/a/_/exceptions", {"action": "remove", "kind": "senders", "key": "@friends.org"})
        self.assertNotIn("@friends.org", self.env.cfg().protected_patterns)
        self.assertIn("Enter+an+address", self.http("POST", "/a/_/exceptions", {"action": "add", "sender": "a b"})[1]["Location"])


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
        live = text.replace('mode = "shadow"', 'mode = "live"')
        self.env.cfg_path.write_text(live)
        self.assertEqual(load(self.env.cfg_path).auto.mode, "live")
        self.env.cfg_path.write_text(live.replace("enabled = true", "enabled = false"))
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

    def test_live_actions_follow_jev_bar_oldest_first_capped(self):
        self.patched()
        self.cfg.auto.mode = "live"
        self.cfg.auto.max_moves_per_run = 2
        self.env.add("INBOX", "news@letters.com", "Issue 1", days_ago=3)
        self.env.add("INBOX", "news@letters.com", "Issue 2", days_ago=2)
        self.env.add("INBOX", "news@letters.com", "Issue 3", days_ago=1)
        self.env.add("INBOX", "news@letters.com", "Issue 4", days_ago=4)
        self.env.add("INBOX", "friend@x.com", "lunch?")
        self.env.add("INBOX", "shop@store.com", "Sale")
        self.idx.update(verbose=False)
        self.claude = {s: ("KEEP", 0.9) for s in ("Issue 1", "Issue 2", "Issue 3", "Issue 4", "lunch?", "Sale")}
        self.ts = {"Issue 1": ts_response("Filtered/News", 0.95),
                   "Issue 2": ts_response("Filtered/News", 0.95),
                   "Issue 3": ts_response("Filtered/News", 0.95),
                   "Issue 4": ts_response("Filtered/News", 0.95),
                   "lunch?": ts_response("Filtered/News", 0.95, personal=0.9),
                   "Sale": ts_response("Filtered/News", 0.5)}                    # below the bar
        rows = shadow.run(self.cfg, self.idx, out=quiet)
        issue4 = next(r for r in rows if r["subject"] == "Issue 4")
        self.idx.record_decision(issue4["msgid"], "Filtered/News", "rejected")
        actions = shadow.live_actions(self.cfg, self.idx, rows)
        self.assertEqual([a["subject"] for a in actions], ["Issue 1", "Issue 2"])
        self.assertTrue(all(a["approved"] and a["source"] == "ai" and a["dest"] == "Filtered/News"
                            for a in actions))
        self.assertFalse(guards.check_plan(self.cfg, actions, self.idx.folder_sizes()).rejected)

    def test_live_actions_skip_duplicate_copies(self):
        self.patched()
        self.cfg.auto.mode = "live"
        msgid, _ = self.env.add("INBOX", "news@letters.com", "Issue 1")
        self.env.add("INBOX", "news@letters.com", "Issue 1", msgid=msgid)   # second copy, same Message-ID
        self.env.add("INBOX", "news@letters.com", "Issue 2")
        self.idx.update(verbose=False)
        self.claude = {"Issue 1": ("KEEP", 0.9), "Issue 2": ("KEEP", 0.9)}
        self.ts = {"Issue 1": ts_response("Filtered/News", 0.95), "Issue 2": ts_response("Filtered/News", 0.95)}
        rows = shadow.run(self.cfg, self.idx, out=quiet)
        self.assertEqual([a["subject"] for a in shadow.live_actions(self.cfg, self.idx, rows)], ["Issue 2"])

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
