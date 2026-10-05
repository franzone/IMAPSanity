"""Plans: the only thing rules and AI produce. A plan is a JSON list of proposed moves.

Rule actions are pre-approved; AI actions start unapproved and need `review`.
"""

import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PLAN_VERSION = 1


def make_action(row, dest, source, why, approved, confidence=None):
    return {
        "folder": row["folder"],
        "key": row["key"],
        "msgid": row["msgid"] or "",
        "from": row["from_raw"] or "",
        "addr": row["from_addr"] or "",
        "subject": row["subject"] or "",
        "date": _iso(row["date_ts"]),
        "dest": dest,
        "source": source,
        "why": why,
        "confidence": confidence,
        "approved": approved,
    }


def _iso(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else ""


def new_plan(actions):
    now = datetime.now(timezone.utc)
    for i, a in enumerate(actions, start=1):
        a["id"] = f"a{i:04d}"
    return {
        "version": PLAN_VERSION,
        "id": now.astimezone().strftime("%Y%m%d-%H%M%S"),
        "created": now.isoformat(),
        "actions": actions,
    }


def plans_dir(cfg):
    d = cfg.state_dir / "plans"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save(cfg, plan, path=None, prefix="plan"):
    """Manual plans are plan-*.json (what `resolve` picks up); unattended ones use another prefix."""
    path = Path(path) if path else plans_dir(cfg) / f"{prefix}-{plan['id']}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(plan, indent=2, ensure_ascii=False))
    tmp.replace(path)
    return path


def resolve(cfg, path=None):
    if path:
        return Path(path)
    plans = sorted(plans_dir(cfg).glob("plan-*.json"))
    if not plans:
        raise SystemExit("no plans yet; run `imapsanity plan` first")
    return plans[-1]


def load(path):
    plan = json.loads(Path(path).read_text())
    if plan.get("version") != PLAN_VERSION:
        raise SystemExit(f"{path}: unsupported plan version {plan.get('version')}")
    return plan


def age_hours(plan):
    created = datetime.fromisoformat(plan["created"])
    return (datetime.now(timezone.utc) - created).total_seconds() / 3600


def summarize(plan, out=print):
    groups = defaultdict(lambda: [0, 0])
    for a in plan["actions"]:
        g = groups[(a["source"], a["folder"], a["dest"])]
        g[0] += 1
        g[1] += bool(a["approved"])
    if not groups:
        out("plan is empty: nothing to do")
        return
    out(f"{'source':6} {'approved':>9}  move")
    for (source, folder, dest), (n, ok) in sorted(groups.items()):
        out(f"{source:6} {ok:>4}/{n:<4}  {folder} -> {dest}")
    pending = sum(1 for a in plan["actions"] if a["source"] == "ai" and not a["approved"]
                  and a.get("decision") != "rejected")
    if pending:
        out(f"\n{pending} AI proposal(s) await review: imapsanity review")


def review(cfg, idx, path, inp=input, out=print):
    """Interactively approve/reject AI proposals, grouped by (dest, sender)."""
    plan = load(path)
    pending = [a for a in plan["actions"]
               if a["source"] == "ai" and not a["approved"] and a.get("decision") != "rejected"]
    groups = defaultdict(list)
    for a in pending:
        groups[(a["dest"], a["addr"] or a["from"])].append(a)
    if not groups:
        out("no AI proposals awaiting review")
        return

    def decide(actions, decision):
        for a in actions:
            a["approved"] = decision == "approved"
            a["decision"] = decision
            idx.record_decision(a["msgid"], a["dest"], decision)

    items = sorted(groups.items(), key=lambda kv: (kv[0][0], -len(kv[1])))
    try:
        for n, ((dest, sender), actions) in enumerate(items, start=1):
            confs = [a["confidence"] or 0 for a in actions]
            out(f"\n[{n}/{len(items)}] {dest}  <-  {sender}  ({len(actions)} msg, conf {min(confs):.2f}-{max(confs):.2f})")
            for a in actions[:5]:
                out(f"    {a['date']}  {a['subject'][:80]}")
            if len(actions) > 5:
                out(f"    ... and {len(actions) - 5} more")
            out(f"    why: {actions[0]['why']}")
            while True:
                choice = inp("  [a]pprove  [r]eject  [s]kip  [i]ndividually  [q]uit > ").strip().lower()
                if choice in ("a", "r", "s", "i", "q"):
                    break
            if choice == "q":
                break
            if choice == "a":
                decide(actions, "approved")
            elif choice == "r":
                decide(actions, "rejected")
            elif choice == "i":
                for a in actions:
                    c = inp(f"    {a['date']} {a['subject'][:70]}  [y/n/s] > ").strip().lower()
                    if c in ("y", "n"):
                        decide([a], "approved" if c == "y" else "rejected")
    finally:
        save(cfg, plan, path)
        approved = sum(1 for a in plan["actions"] if a["approved"])
        out(f"\nsaved {path} ({approved} approved). Next: imapsanity apply   (dry run), then --execute")
