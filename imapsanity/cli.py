"""Command line. Everything that changes mail is a dry run unless --execute is given."""

import argparse
import fcntl
import sys
from collections import Counter
from contextlib import contextmanager
from datetime import datetime

from . import ai, apply, journal, plan, rules, shadow, sync, typesafe
from .backends import BackendError
from .backends.imap import ImapBackend
from .config import ConfigError, load
from .index import Index


@contextmanager
def run_lock(cfg):
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    with open(cfg.state_dir / "lock", "w") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("another imapsanity run is in progress")
        yield


def cmd_index(cfg, idx, args):
    idx.update()
    return 0


def cmd_plan(cfg, idx, args):
    idx.update()
    actions, notes = rules.build_actions(cfg, idx)
    for n in notes[:20]:
        print("  note: " + n)
    if len(notes) > 20:
        print(f"  ... {len(notes) - 20} more notes")
    if cfg.ai.enabled and not args.no_ai:
        try:
            actions += ai.build_actions(cfg, idx, exclude={(a["folder"], a["msgid"]) for a in actions})
        except ai.AIError as e:
            print(f"ai: skipped ({e})")
    p = plan.new_plan(actions)
    path = plan.save(cfg, p)
    plan.summarize(p)
    print(f"\nplan: {path}\nnext: imapsanity show | review | apply")
    return 0


def cmd_show(cfg, idx, args):
    path = plan.resolve(cfg, args.plan)
    p = plan.load(path)
    print(f"{path}  (created {p['created']}{', applied ' + p['applied_run'] if p.get('applied_run') else ''})")
    for a in p["actions"]:
        if args.pending and (a["approved"] or a["source"] != "ai"):
            continue
        mark = "✓" if a["approved"] else ("✗" if a.get("decision") == "rejected" else "?")
        conf = f" {a['confidence']:.2f}" if a.get("confidence") is not None else ""
        print(f"{mark} {a['id']} [{a['source']}{conf}] {a['folder']} -> {a['dest']} | {a['addr'] or a['from']} | "
              f"{a['subject'][:60]} | {a['why']}")
    print()
    plan.summarize(p)
    return 0


def cmd_review(cfg, idx, args):
    plan.review(cfg, idx, plan.resolve(cfg, args.plan))
    return 0


def cmd_apply(cfg, idx, args):
    return apply.apply_plan(cfg, idx, plan.resolve(cfg, args.plan), args.execute,
                            args.max_moves, args.max_fraction, args.max_quarantine)


def cmd_undo(cfg, idx, args):
    return apply.undo(cfg, args.run, args.execute, force=args.force)


def cmd_runs(cfg, idx, args):
    for run in journal.all_runs(cfg)[-args.last:]:
        states = Counter(e["status"] for e in journal.final_states(journal.read(cfg, run)))
        print(f"{run:40} " + ", ".join(f"{k} {n}" for k, n in sorted(states.items())))
    return 0


def cmd_purge(cfg, idx, args):
    return apply.purge(cfg, args.older_than, args.execute)


def cmd_sync(cfg, idx, args):
    if args.direction == "pull":
        return sync.pull(cfg, idx, args.execute)
    return sync.push(cfg, args.execute)


def cmd_cycle(cfg, idx, args):
    """Unattended run (launchd): pull, rules-only plan, apply, push, pull.

    Its plans are saved as cycle-*.json so they never shadow the manual plan that
    `review` / `apply` pick by default, and empty plans aren't saved at all.
    With [auto].mode = "shadow" it then classifies new unmatched mail with Claude (and
    TypeSafe) and logs what would have moved; AI never moves mail here.
    """
    print(f"=== cycle {datetime.now():%Y-%m-%d %H:%M:%S}")
    rc = sync.pull(cfg, idx, True)
    if rc:
        return rc
    actions, _ = rules.build_actions(cfg, idx)
    if not actions:
        print("cycle: no rule matches")
    else:
        path = plan.save(cfg, plan.new_plan(actions), prefix="cycle")
        rc = apply.apply_plan(cfg, idx, path, True)
        if rc == 2:
            return rc
    if cfg.maildir_folders:
        rc = sync.push(cfg, True) or rc
    if actions or cfg.maildir_folders:
        rc = sync.pull(cfg, idx, True) or rc
    if cfg.auto.mode == "shadow":
        shadow.run(cfg, idx)
    return rc


def cmd_shadow_report(cfg, idx, args):
    return shadow.report(cfg, idx, args.days, show=args.show)


def cmd_typesafe_backfill(cfg, idx, args):
    """Ask TypeSafe about messages Claude already classified, so shadow-report has history now."""
    if not cfg.typesafe.enabled:
        print("[typesafe].enabled is false")
        return 2
    rows = idx.ts_backfill_rows()
    if not args.execute:
        n = min(len(rows), args.limit)
        print(f"would send {n} message(s) to TypeSafe (sender, subject, List-Id, first 500 chars). "
              f"Re-run with --execute.")
        return 0
    try:
        typesafe.classify(cfg, idx, rows, args.limit)
    except typesafe.TypeSafeError as e:
        print(f"typesafe: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_suggest_rules(cfg, idx, args):
    idx.update(verbose=False)
    text = ai.suggest_rules(cfg, idx, min_count=args.min_count)
    if text:
        path = cfg.state_dir / f"suggested-rules-{datetime.now():%Y%m%d-%H%M%S}.toml"
        path.write_text(text)
        print(text)
        print(f"saved to {path} (config.toml was not changed)")
    return 0


def cmd_mkfolder(cfg, idx, args):
    if args.folder not in cfg.allow_destinations:
        print(f"{args.folder!r} is not in [destinations].allow; add it there first")
        return 2
    with ImapBackend(cfg) as b:
        if b.exists(args.folder):
            print(f"{args.folder} already exists")
            return 0
        b.create(args.folder)
    print(f"created {args.folder} on the server; run `imapsanity sync pull --execute` to mirror it")
    return 0


def cmd_check(cfg, idx, args):
    ok = True
    print(f"config: {cfg.path}\nmaildir: {cfg.maildir}\nstate: {cfg.state_dir}")
    print(f"{len(cfg.filers)} filers, {len(cfg.matches)} match rules, "
          f"{len(cfg.protected_patterns)} protected sender patterns")
    for f in cfg.maildir_folders:
        if not (cfg.maildir / f / "cur").is_dir():
            print(f"  ✗ maildir folder missing locally: {f}")
            ok = False
    try:
        with ImapBackend(cfg) as b:
            print("  ✓ IMAP login, MOVE + UIDPLUS supported")
            for folder in sorted(set(cfg.allow_destinations) | set(cfg.rules_source_folders) | set(cfg.ai.folders)):
                if not b.exists(folder):
                    ok = False
                    print(f"  ✗ missing on server: {folder}   (imapsanity mkfolder {folder!r})")
    except (BackendError, OSError) as e:
        ok = False
        print(f"  ✗ IMAP: {e}")
    if cfg.ai.enabled:
        try:
            print(f"  ✓ claude: {ai.claude_path(cfg)} (model {cfg.ai.model})")
        except ai.AIError as e:
            ok = False
            print(f"  ✗ {e}")
    if cfg.typesafe.enabled:
        try:
            models = typesafe.list_models(cfg)
            print(f"  ✓ typesafe: key works (model {cfg.typesafe.model}; account has {', '.join(models)})")
        except typesafe.TypeSafeError as e:
            ok = False
            print(f"  ✗ typesafe: {e}")
    print("all good" if ok else "problems found")
    return 0 if ok else 1


def build_parser():
    p = argparse.ArgumentParser(prog="imapsanity", description=__doc__)
    p.add_argument("--config", help="path to config.toml")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check", help="validate config, server folders, claude")
    sub.add_parser("index", help="update the local index")

    sp = sub.add_parser("plan", help="index, then propose moves from rules (+ AI)")
    sp.add_argument("--no-ai", action="store_true")

    sp = sub.add_parser("show", help="list a plan's actions")
    sp.add_argument("plan", nargs="?")
    sp.add_argument("--pending", action="store_true", help="only AI proposals awaiting review")

    sp = sub.add_parser("review", help="approve/reject AI proposals")
    sp.add_argument("plan", nargs="?")

    sp = sub.add_parser("apply", help="apply approved moves (dry run without --execute)")
    sp.add_argument("plan", nargs="?")
    sp.add_argument("--execute", action="store_true")
    sp.add_argument("--max-moves", type=int)
    sp.add_argument("--max-fraction", type=float)
    sp.add_argument("--max-quarantine", type=int)

    sp = sub.add_parser("undo", help="reverse a run's moves")
    sp.add_argument("run")
    sp.add_argument("--execute", action="store_true")
    sp.add_argument("--force", action="store_true")

    sp = sub.add_parser("runs", help="list journaled runs")
    sp.add_argument("--last", type=int, default=20)

    sp = sub.add_parser("purge", help="permanently delete old quarantined messages")
    sp.add_argument("--older-than", type=int, required=True, metavar="DAYS")
    sp.add_argument("--execute", action="store_true")

    sp = sub.add_parser("sync", help="mbsync pull, or breaker-guarded push")
    sp.add_argument("direction", choices=["pull", "push"])
    sp.add_argument("--execute", action="store_true")

    sub.add_parser("cycle", help="unattended rules-only run for launchd (+ shadow AI if enabled)")

    sp = sub.add_parser("shadow-report", help="compare what Claude and TypeSafe would have auto-moved")
    sp.add_argument("--days", type=int, default=30)
    sp.add_argument("--show", type=int, default=15, help="how many disagreements to list")

    sp = sub.add_parser("typesafe-backfill", help="ask TypeSafe about messages Claude already classified")
    sp.add_argument("--limit", type=int, default=1000)
    sp.add_argument("--execute", action="store_true")

    sp = sub.add_parser("suggest-rules", help="ask Claude to propose [[match]] rules")
    sp.add_argument("--min-count", type=int, default=3)

    sp = sub.add_parser("mkfolder", help="create an allowed destination folder on the server")
    sp.add_argument("folder")
    return p


COMMANDS = {
    "check": cmd_check, "index": cmd_index, "plan": cmd_plan, "show": cmd_show,
    "review": cmd_review, "apply": cmd_apply, "undo": cmd_undo, "runs": cmd_runs,
    "purge": cmd_purge, "sync": cmd_sync, "cycle": cmd_cycle,
    "suggest-rules": cmd_suggest_rules, "mkfolder": cmd_mkfolder,
    "shadow-report": cmd_shadow_report, "typesafe-backfill": cmd_typesafe_backfill,
}


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        cfg = load(args.config)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    with run_lock(cfg):
        idx = Index(cfg)
        try:
            return COMMANDS[args.cmd](cfg, idx, args)
        except BackendError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        finally:
            idx.close()
