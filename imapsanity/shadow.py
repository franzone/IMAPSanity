"""Shadow mode: during `cycle`, Claude and TypeSafe both judge new unmatched mail and the cycle
logs what each *would* auto-move. Nothing is moved. `shadow-report` compares the two against
your review decisions and against where each message ended up.

The auto bar for each classifier lives here (claude_pick / typesafe_pick), applied to cached
answers, so changing a threshold in config.toml re-scores history without re-asking anyone.
"""

import time
from collections import Counter
from datetime import datetime

from . import ai, typesafe
from .ai import KEEP


def claude_pick(cfg, c):
    if c and c["dest"] in cfg.auto.destinations and (c["confidence"] or 0) >= cfg.auto.min_confidence:
        return c["dest"]
    return None


def typesafe_pick(cfg, t):
    ts = cfg.typesafe
    if (t and t["dest"] in cfg.auto.destinations and t["confidence"] >= ts.min_confidence
            and t["personal"] <= ts.max_personal and t["important"] <= ts.max_important):
        return t["dest"]
    return None


def run(cfg, idx, out=print):
    """The shadow step of `cycle`. Classifier failures are logged, never raised."""
    rows = ai.candidates(cfg, idx)
    n = cfg.auto.max_classify_per_run
    todo = [r for r in rows if idx.ai_cached(r["msgid"]) is None][:n]
    if todo:
        try:
            ai.classify(cfg, idx, todo, out=out)
        except ai.AIError as e:
            out(f"shadow: claude skipped ({e})")
    if cfg.typesafe.enabled:
        try:
            typesafe.classify(cfg, idx, rows, n, out=out)
        except typesafe.TypeSafeError as e:
            out(f"shadow: typesafe skipped ({e})")

    c_moves, t_moves, agree = Counter(), Counter(), 0
    for r in {r["msgid"]: r for r in rows}.values():
        cp = claude_pick(cfg, idx.ai_cached(r["msgid"]))
        tp = typesafe_pick(cfg, idx.ts_cached(r["msgid"])) if cfg.typesafe.enabled else None
        if cp:
            c_moves[cp] += 1
        if tp:
            t_moves[tp] += 1
        agree += bool(cp and cp == tp)
    fmt = lambda c: f"{sum(c.values())}" + (f" ({', '.join(f'{d} {k}' for d, k in sorted(c.items()))})" if c else "")
    line = f"shadow: of {len(rows)} unmatched in {', '.join(cfg.ai.folders)}, would auto-move: claude {fmt(c_moves)}"
    if cfg.typesafe.enabled:
        line += f"; typesafe {fmt(t_moves)}; both agree {agree}"
    out(line + ". Nothing moved.")


# --- report -------------------------------------------------------------------------

OUTCOMES = [
    ("same", "now in that folder"),
    ("other", "now in a different folder"),
    ("read", "still in inbox, read"),
    ("unread", "still in inbox, unread"),
    ("gone", "deleted or purged"),
    ("new", "too new to judge"),
    ("rejected", "you rejected this in review"),
]


def outcome(cfg, idx, msgid, dest, date_ts, now):
    """Where a message the classifier would have moved to `dest` actually is today."""
    if idx.ai_decision(msgid, dest) == "rejected":
        return "rejected"
    rows = idx.live_by_msgid(msgid)
    folders = {r["folder"] for r in rows}
    if dest in folders:
        return "same"
    inbox = [r for r in rows if r["folder"] in cfg.ai.folders]
    if inbox and (date_ts or now) > now - cfg.auto.settle_days * 86400:
        return "new"
    if inbox:
        return "read" if any("S" in r["flags"] for r in inbox) else "unread"
    return "other" if rows else "gone"


def report(cfg, idx, days, out=print, show=15):
    now = time.time()
    cutoff = now - days * 86400
    rows = idx.db.execute(
        "SELECT c.msgid, c.dest AS c_dest, c.confidence AS c_conf, "
        "t.dest AS t_dest, t.confidence AS t_conf, t.personal, t.important, "
        "MAX(m.date_ts) AS date_ts, MAX(m.from_addr) AS addr, MAX(m.subject) AS subject "
        "FROM ai_cache c JOIN ts_cache t ON t.msgid = c.msgid "
        "LEFT JOIN messages m ON m.msgid = c.msgid "
        "GROUP BY c.msgid HAVING date_ts IS NULL OR date_ts >= ?", (cutoff,)).fetchall()
    if not rows:
        out(f"no messages from the last {days} days were classified by both claude and typesafe yet")
        return 0

    ts = cfg.typesafe
    out(f"shadow report: {len(rows)} message(s) since {datetime.fromtimestamp(cutoff):%Y-%m-%d} "
        f"classified by both; auto destinations: {', '.join(cfg.auto.destinations) or '(none)'}\n")
    out(f"  claude bar:   confidence >= {cfg.auto.min_confidence}")
    out(f"  typesafe bar: confidence >= {ts.min_confidence}, personal <= {ts.max_personal}, "
        f"important <= {ts.max_important}\n")

    tallies = {"claude": Counter(), "typesafe": Counter()}
    picks = []
    for r in rows:
        cp = claude_pick(cfg, {"dest": r["c_dest"], "confidence": r["c_conf"]})
        tp = typesafe_pick(cfg, {"dest": r["t_dest"], "confidence": r["t_conf"],
                                 "personal": r["personal"], "important": r["important"]})
        for name, p in (("claude", cp), ("typesafe", tp)):
            if p:
                tallies[name][outcome(cfg, idx, r["msgid"], p, r["date_ts"], now)] += 1
        picks.append((r, cp, tp))

    out(f"  {'would auto-move':28} {'claude':>8} {'typesafe':>9}")
    out(f"  {'total':28} {sum(tallies['claude'].values()):>8} {sum(tallies['typesafe'].values()):>9}")
    for key, label in OUTCOMES:
        out(f"    {label:26} {tallies['claude'][key]:>8} {tallies['typesafe'][key]:>9}")

    approved = [p for p in picks if idx.ai_decision(p[0]["msgid"], p[0]["c_dest"]) == "approved"
                and p[0]["c_dest"] in cfg.auto.destinations]
    if approved:
        out(f"\n  of {len(approved)} you approved in review (auto destinations only), would auto-move to the "
            f"same folder: claude {sum(1 for r, cp, tp in approved if cp == r['c_dest'])}, "
            f"typesafe {sum(1 for r, cp, tp in approved if tp == r['c_dest'])}")

    same = sum(1 for r, *_ in picks if r["c_dest"] == r["t_dest"])
    out(f"\n  raw destination agreement (incl. {KEEP} and below-bar answers): {same}/{len(picks)} "
        f"({same / len(picks):.0%})")
    matrix = Counter((r["c_dest"], r["t_dest"]) for r, *_ in picks)
    dests = [KEEP, *cfg.ai.destinations]
    short = {d: d.rsplit("/", 1)[-1][:10] for d in dests}
    out("  claude \\ typesafe " + "".join(f"{short[d]:>11}" for d in dests))
    for cd in dests:
        out(f"  {short[cd]:18}" + "".join(f"{matrix[(cd, td)]:>11}" for td in dests))

    split = [(r, cp, tp) for r, cp, tp in picks if cp != tp]
    if split:
        out(f"\n  auto picks that differ ({len(split)}; showing {min(show, len(split))}):")
        for r, cp, tp in split[:show]:
            out(f"    {(r['addr'] or '?')[:30]:30} {(r['subject'] or '')[:40]:40} "
                f"claude {cp or '-'} ({r['c_dest']} {r['c_conf'] or 0:.2f}) | typesafe {tp or '-'} "
                f"({r['t_dest']} {r['t_conf']:.2f}, personal {r['personal']:.2f}, important {r['important']:.2f})")
    return 0
