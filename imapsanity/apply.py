"""The executor: apply a plan, undo a run, purge the quarantine. Dry run unless execute=True."""

import time
from collections import Counter, defaultdict

from . import guards, journal, sync
from .backends.imap import ImapBackend
from .backends.maildir import MaildirBackend
from .plan import age_hours, load, save


def execute_moves(cfg, actions, jnl, check_flagged=True, out=print):
    groups = defaultdict(list)
    for a in actions:
        groups[(cfg.backend_for(a["folder"]), a["folder"])].append(a)

    tally = Counter()
    backends = {}
    try:
        for (bname, folder), acts in sorted(groups.items()):
            if bname not in backends:
                b = ImapBackend(cfg) if bname == "imap" else MaildirBackend(cfg)
                backends[bname] = b.__enter__()
            backend = backends[bname]
            for a in acts:
                jnl.write(a, "intent", bname)
            try:
                results = backend.move(folder, acts, check_flagged=check_flagged)
            except Exception as e:
                results = [(a, "failed", f"{type(e).__name__}: {e}") for a in acts]
            maildir_moves = []
            for a, status, detail in results:
                extra = detail if isinstance(detail, dict) else {}
                jnl.write(a, status, bname, None if extra else detail, **extra)
                tally[status] += 1
                if status == "moved" and bname == "maildir":
                    maildir_moves.append((a["folder"], a["dest"]))
                if status != "moved":
                    out(f"  {status}: {a['folder']} -> {a['dest']}  {a.get('subject', '')[:60]}  ({detail})")
            sync.record_moves(cfg, maildir_moves)
            out(f"  {folder}: " + ", ".join(f"{k} {v}" for k, v in Counter(r[1] for r in results).items()))
    finally:
        for b in backends.values():
            b.__exit__(None, None, None)
        jnl.close()
    return tally


def _print_moves(actions, out):
    for (folder, dest), n in sorted(Counter((a["folder"], a["dest"]) for a in actions).items()):
        out(f"  {n:5}  {folder} -> {dest}")


def apply_plan(cfg, idx, path, execute, max_moves=None, max_fraction=None, max_quarantine=None, out=print):
    plan = load(path)
    if plan.get("applied_run"):
        out(f"{path} was already applied (run {plan['applied_run']}); make a new plan")
        return 2
    age = age_hours(plan)
    if age > cfg.safety.max_plan_age_hours:
        out(f"plan is {age:.1f}h old (max {cfg.safety.max_plan_age_hours}h); make a new plan")
        return 2

    v = guards.check_plan(cfg, plan["actions"], idx.folder_sizes(), max_moves, max_fraction, max_quarantine)
    for a, reason in v.rejected:
        out(f"  rejected: {a['folder']} -> {a['dest']}  {a['subject'][:60]}  ({reason})")
    if v.aborts:
        out("ABORT: nothing was moved:")
        for r in v.aborts:
            out("  - " + r)
        return 2
    if not v.ok:
        out("nothing approved to apply")
        return 0
    out(f"{len(v.ok)} move(s) from {path.name}:")
    _print_moves(v.ok, out)
    if not execute:
        out("dry run; add --execute to apply")
        return 0

    run_id = journal.new_run_id("apply")
    tally = execute_moves(cfg, v.ok, journal.Journal(cfg, run_id), out=out)
    plan["applied_run"] = run_id
    save(cfg, plan, path)
    out(f"run {run_id}: " + ", ".join(f"{k} {n}" for k, n in tally.items()) + f"   (undo: imapsanity undo {run_id})")
    return 0 if set(tally) <= {"moved", "not_found", "flagged"} else 1


def undo(cfg, run_id, execute, force=False, out=print):
    if any(r.endswith(f"-undo-{run_id}") for r in journal.all_runs(cfg)) and not force:
        out(f"{run_id} was already undone; use --force to undo again")
        return 2
    moved = [e for e in journal.final_states(journal.read(cfg, run_id)) if e["status"] == "moved"]
    if not moved:
        out("nothing to undo")
        return 0
    actions = [{
        "id": e["action"], "msgid": e["msgid"],
        "folder": e["to_folder"], "dest": e["from_folder"],
        "key": e.get("new_key") or e.get("key"),
        "source": "undo", "why": f"undo {run_id}",
        "addr": e.get("addr"), "subject": e.get("subject") or "",
    } for e in moved]
    out(f"undo {run_id}: {len(actions)} move(s)")
    _print_moves(actions, out)
    if not execute:
        out("dry run; add --execute to undo")
        return 0
    jnl = journal.Journal(cfg, journal.new_run_id(f"undo-{run_id}"))
    tally = execute_moves(cfg, actions, jnl, check_flagged=False, out=out)
    out("undo: " + ", ".join(f"{k} {n}" for k, n in tally.items()))
    return 0 if set(tally) <= {"moved"} else 1


def purge(cfg, days, execute, inp=input, out=print):
    """Permanently delete messages *we* quarantined at least `days` ago. Human-only."""
    q = cfg.safety.quarantine
    last = {}
    for run in journal.all_runs(cfg):
        for e in journal.read(cfg, run):
            if e["status"] in ("moved", "purged") and e.get("msgid"):
                if e["msgid"] not in last or e["ts"] >= last[e["msgid"]]["ts"]:
                    last[e["msgid"]] = e
    cutoff = time.time() - days * 86400
    cands = [e for e in last.values() if e["status"] == "moved" and e["to_folder"] == q and e["ts"] <= cutoff]
    out(f"{len(cands)} message(s) quarantined by imapsanity more than {days} day(s) ago")
    for e in cands[:15]:
        out(f"  {e.get('addr') or ''}  {(e.get('subject') or '')[:70]}")
    if len(cands) > 15:
        out(f"  ... and {len(cands) - 15} more")
    if not cands:
        return 0
    if not execute:
        out("dry run; add --execute to permanently delete these from the server")
        return 0
    if inp(f"Type 'PURGE {len(cands)}' to permanently delete: ").strip() != f"PURGE {len(cands)}":
        out("not confirmed; nothing deleted")
        return 2
    jnl = journal.Journal(cfg, journal.new_run_id("purge"))
    try:
        with ImapBackend(cfg) as b:
            results = b.purge(q, [e["msgid"] for e in cands])
        by_msgid = {e["msgid"]: e for e in cands}
        for i, (msgid, status) in enumerate(results, start=1):
            e = by_msgid[msgid]
            jnl.write({"id": f"p{i:04d}", "msgid": msgid, "folder": q, "dest": "(deleted)",
                       "addr": e.get("addr"), "subject": e.get("subject")}, status, "imap")
    finally:
        jnl.close()
    out("purge: " + ", ".join(f"{k} {n}" for k, n in Counter(s for _, s in results).items()))
    return 0
