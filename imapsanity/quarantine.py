"""The quarantine, for review: why each message is there, how likely it is to be a mistake, and the
ways out: rescue (move it back, or to another folder, and keep it) or confirm it as junk (only
confirmed junk is purged).

Risk is a few cheap signals, not a model. With why a message was quarantined, they sort the
quarantine into three tiers so the handful worth a careful look aren't buried in bulk mail:
  careful  a strong signal: you've written to the sender, or TypeSafe thinks it's personal/important
  glance   the AI's judgment, nothing strong (weak signals, e.g. not a mailing list, sort these)
  rules    extras trimmed by your own keep-last-N rules, nothing strong
With [safety].purge_rule_trims_days set, cycle deletes confirmed junk that many days after
quarantining it, and the "rules" tier needs no review: it counts as confirmed, as keep-last-N always
meant. So do trims from senders you trust (exceptions "trust_trims"), whatever their signals.
"""

import email.parser
import email.policy
import email.utils
from collections import Counter, defaultdict

from . import apply, exceptions, journal, sync
from .message import read_header_bytes

CAREFUL = 3   # one strong signal; the weak ones add up to at most 2
PERSONAL = 0.5   # TypeSafe probabilities at or above this count as a signal

_correspondents = {}   # state_dir -> (cache key, addresses)


def sent_folders(cfg):
    return [f for f in cfg.safety.protected_folders if "sent" in f.lower()]


def correspondents(cfg, idx):
    """Addresses you've written to (To/Cc/Bcc in the Sent folders), cached until those folders change."""
    rows = [r for f in sent_folders(cfg) for r in idx.live(f)]
    key = (len(rows), max((r["key"] for r in rows), default=""))
    hit = _correspondents.get(cfg.state_dir)
    if hit and hit[0] == key:
        return hit[1]
    parser = email.parser.BytesHeaderParser(policy=email.policy.compat32)
    addrs = set()
    for r in rows:
        try:
            msg = parser.parsebytes(read_header_bytes(idx.path_of(r)))
        except OSError:
            continue
        values = [str(v) for h in ("To", "Cc", "Bcc") for v in msg.get_all(h, [])]
        addrs.update(a.lower() for _, a in email.utils.getaddresses(values) if a)
    _correspondents[cfg.state_dir] = (key, addrs)
    return addrs


def _score(item, known, typesafe_row, times_quarantined):
    reasons = []
    if item["addr"] and item["addr"] in known:
        reasons.append((3, "you've written to this sender"))
    if typesafe_row is not None:
        if typesafe_row["personal"] >= PERSONAL:
            reasons.append((3, f"TypeSafe: likely written to you personally ({typesafe_row['personal']:.0%})"))
        if typesafe_row["important"] >= PERSONAL:
            reasons.append((3, f"TypeSafe: likely a bill, alert or official notice ({typesafe_row['important']:.0%})"))
    if not item["list_id"]:
        reasons.append((1, "not from a mailing list"))
        if times_quarantined <= 1:
            reasons.append((1, "first message from this sender to be quarantined"))
    return sum(n for n, _ in reasons), [r for _, r in reasons]


def items(cfg, idx):
    """Every message in the quarantine folder, with why it's there and its risk signals."""
    q = cfg.safety.quarantine
    last, history = {}, defaultdict(set)
    for e in journal.entries(cfg):
        if e["status"] not in ("moved", "purged") or not e.get("msgid"):
            continue
        last[e["msgid"]] = e
        if e["status"] == "moved" and e["to_folder"] == q:
            history[(e.get("addr") or "").lower()].add(e["msgid"])
    confirmed = idx.confirmed_junk()
    known = correspondents(cfg, idx)
    out = []
    for row in idx.live(q):
        e = last.get(row["msgid"])
        ours = e is not None and e["status"] == "moved" and e["to_folder"] == q
        item = {
            "msgid": row["msgid"], "key": row["key"], "path": idx.path_of(row), "from": row["from_raw"] or "",
            "addr": row["from_addr"] or "", "subject": row["subject"] or "", "date_ts": row["date_ts"],
            "list_id": row["list_id"] or "",
            "ours": ours,   # False: someone put it here by hand, and purge never touches it
            "origin": e["from_folder"] if ours else None,
            "why": (e.get("why") or "") if ours else "",
            "source": (e.get("source") or "") if ours else "",
            "quarantined_ts": e["ts"] if ours else None,
            "confirmed": row["msgid"] in confirmed,
        }
        item["score"], item["reasons"] = _score(item, known, idx.ts_cached(row["msgid"]) if row["msgid"] else None,
                                                len(history[item["addr"]]))
        item["auto"] = auto_junk(cfg, item)
        item["confirmed"] = item["confirmed"] or item["auto"]
        out.append(item)
    return out


def auto_junk(cfg, item):
    """A keep-last-N trim with no strong signal, or from a sender whose trims you trust, while
    [safety].purge_rule_trims_days is on."""
    return bool(cfg.safety.purge_rule_trims_days) and item["ours"] and item["source"] == "rule" \
        and (tier(item) == "rules" or item["addr"].lower() in cfg.exceptions["trust_trims"])


def purgeable(cfg, idx):
    """Message-IDs `purge` may delete: the ones you confirmed, plus keep-last-N trims (auto_junk)."""
    return idx.confirmed_junk() | {i["msgid"] for i in items(cfg, idx) if i["auto"]}


def auto_purge(cfg, idx, out=print):
    """cycle: permanently delete confirmed junk (yours, and keep-last-N trims) quarantined more than
    purge_rule_trims_days ago. Returns how many were deleted."""
    days = cfg.safety.purge_rule_trims_days
    if not days:
        return 0
    junk = {i["msgid"] for i in items(cfg, idx) if i["confirmed"]}
    cands = [e for e in apply.purge_candidates(cfg, days) if e["msgid"] in junk]
    if not cands:
        return 0
    tally = apply.delete_quarantined(cfg, cands, kind="autopurge")
    out(f"purge: confirmed junk quarantined over {days:g} day(s) ago: "
        + ", ".join(f"{k} {n}" for k, n in tally.items()))
    return tally.get("purged", 0)


def tier(items):
    """Tier for a message or a sender's group of messages."""
    items = [items] if isinstance(items, dict) else items
    if max(i["score"] for i in items) >= CAREFUL:
        return "careful"
    return "rules" if all(i["source"] == "rule" for i in items) else "glance"


def groups(entries):
    """One group per tier and sender (a sender's AI-judged mail isn't lumped in with its rule trims),
    riskiest first; within a score, smaller groups first."""
    by = defaultdict(list)
    for it in entries:
        by[(tier(it), it["addr"] or it["from"])].append(it)
    out = []
    for (t, sender), its in by.items():
        reasons = list(dict.fromkeys(r for it in its for r in it["reasons"]))
        out.append({"sender": sender, "items": sorted(its, key=lambda i: -(i["date_ts"] or 0)),
                    "score": max(it["score"] for it in its), "reasons": reasons, "tier": t})
    return sorted(out, key=lambda g: (-g["score"], len(g["items"]), g["sender"]))


def move_targets(cfg):
    """Folders the dashboard offers for "Move to": every allowed destination except the quarantine."""
    return sorted(f for f in cfg.allow_destinations if f != cfg.safety.quarantine)


def rescue(cfg, idx, msgids, keep_sender=False, dest=None, out=print):
    """Move messages back where imapsanity took them from (or to `dest`, an allowed destination), and
    keep them (or their senders) from now on, so keep-last-N never trims them back into the quarantine.

    The exception is saved before the move, so even a half-failed move is never re-quarantined.
    Returns a Counter of move statuses.
    """
    q = cfg.safety.quarantine
    if dest is not None and dest not in move_targets(cfg):
        out(f"can't move to {dest}: not an allowed destination")
        return Counter()
    why = f"moved to {dest} in the dashboard" if dest else "rescued in the dashboard"
    by_msgid = {it["msgid"]: it for it in items(cfg, idx)}
    actions = []
    for m in msgids:
        it = by_msgid.get(m)
        if it is None:
            out(f"no longer in {q}: {m}")
            continue
        to = dest or it["origin"] or cfg.rules_source_folders[0]
        if cfg.backend_for(q) != cfg.backend_for(to):
            out(f"can't rescue to {to}: it and {q} use different backends; move it by hand")
            continue
        actions.append({"id": f"r{len(actions) + 1:04d}", "msgid": m, "folder": q, "dest": to,
                        "key": it["key"], "source": "rescue", "why": why,
                        "from": it["from"], "addr": it["addr"], "subject": it["subject"]})
    if not actions:
        return Counter()

    exc = exceptions.load(cfg.state_dir)
    for a in actions:
        if keep_sender and a["addr"]:
            exceptions.add_sender(exc, a["addr"], note=f"rescued from {q}: {a['subject'][:80]}")
        else:
            exceptions.add_message(exc, a["msgid"], a["addr"], a["subject"])
        idx.record_decision(a["msgid"], q, "rejected")   # the AI never proposes quarantining it again
    exceptions.save(cfg.state_dir, exc)
    cfg.exceptions = exc
    idx.confirm_junk([a["msgid"] for a in actions], confirmed=False)

    tally = apply.execute_moves(cfg, actions, journal.Journal(cfg, journal.new_run_id("rescue", cfg)),
                                check_flagged=False, out=out)
    sync.pull(cfg, idx, True, out=out)
    return tally
