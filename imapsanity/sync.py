"""mbsync wrapper with a circuit breaker for the maildir backend.

The breaker only matters for [backends].maildir_folders (two-way synced). Before a push it
checks that every message that left those folders since the last pull/push is explained
by a journaled move. Anything else (a stray `rm`, a bad script, a corrupted folder) aborts
the push so it never reaches the server. A hardlink snapshot is taken before every push.
"""

import json
import os
import shlex
import shutil
import subprocess
from datetime import datetime

from . import maildir

SNAPSHOTS_KEPT = 5


def _state_path(cfg):
    return cfg.state_dir / "maildir-sync.json"


def load_state(cfg):
    p = _state_path(cfg)
    return json.loads(p.read_text()) if p.exists() else {"baseline": None, "delta": {}}


def save_state(cfg, st):
    p = _state_path(cfg)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=2))
    tmp.replace(p)


def record_moves(cfg, moves):
    """moves: [(from_folder, to_folder)] that the maildir backend actually performed."""
    if not moves:
        return
    st = load_state(cfg)
    for src, dst in moves:
        st["delta"][src] = st["delta"].get(src, 0) - 1
        st["delta"][dst] = st["delta"].get(dst, 0) + 1
    save_state(cfg, st)


def current_counts(cfg):
    return {f: maildir.live_count(cfg.maildir, f) for f in cfg.maildir_folders}


def _run(cmd, out):
    out("$ " + shlex.join(cmd))
    return subprocess.run(cmd).returncode


def pull(cfg, idx, execute, out=print):
    if not cfg.pull_commands:
        out("no [mbsync].pull commands configured")
    for cmd in cfg.pull_commands:
        if not execute:
            out("would run: " + shlex.join(cmd))
            continue
        rc = _run(cmd, out)
        if rc != 0:
            out(f"mbsync exited {rc}; stopping")
            return rc
    if execute and cfg.maildir_folders:
        st = load_state(cfg)
        counts = current_counts(cfg)
        # Pulled changes are the server's truth; unpushed local moves stay pending.
        st["baseline"] = {f: n - st["delta"].get(f, 0) for f, n in counts.items()}
        save_state(cfg, st)
    idx.update()
    return 0


def breaker(cfg):
    st = load_state(cfg)
    problems, report = [], []
    if st.get("baseline") is None:
        return ["no baseline yet; run `imapsanity sync pull --execute` first"], report
    counts = current_counts(cfg)
    for f in cfg.maildir_folders:
        if f not in st["baseline"]:
            problems.append(f"{f}: no baseline (newly added folder?); pull first")
            continue
        expected = st["baseline"][f] + st["delta"].get(f, 0)
        actual = counts[f]
        report.append(f"  {f}: baseline {st['baseline'][f]}, journaled {st['delta'].get(f, 0):+d}, now {actual}")
        if actual < expected:
            problems.append(f"{f}: {expected - actual} message(s) vanished without a journal entry "
                            f"(expected {expected}, found {actual})")
    return problems, report


def snapshot(cfg):
    root = cfg.state_dir / "snapshots"
    dest = root / datetime.now().strftime("%Y%m%d-%H%M%S")
    for folder in cfg.maildir_folders:
        for sub in maildir.SUBDIRS:
            src_dir = os.path.join(cfg.maildir, folder, sub)
            if not os.path.isdir(src_dir):
                continue
            dst_dir = dest / folder / sub
            dst_dir.mkdir(parents=True, exist_ok=True)
            for name in os.listdir(src_dir):
                os.link(os.path.join(src_dir, name), dst_dir / name)  # maildir files are immutable
    for old in sorted(p for p in root.iterdir() if p.is_dir())[:-SNAPSHOTS_KEPT]:
        shutil.rmtree(old)
    return dest


def push(cfg, execute, out=print):
    if not cfg.maildir_folders or not cfg.push_command:
        out("nothing to push: [backends].maildir_folders / [mbsync].push not configured")
        return 0
    problems, report = breaker(cfg)
    for line in report:
        out(line)
    if problems:
        out("ABORT: circuit breaker tripped, nothing pushed:")
        for p in problems:
            out("  - " + p)
        return 2
    if not execute:
        out("dry run (mbsync --dry-run); add --execute to push")
        return _run([cfg.push_command[0], "--dry-run", *cfg.push_command[1:]], out)
    out(f"snapshot: {snapshot(cfg)}")
    rc = _run(cfg.push_command, out)
    if rc == 0:
        save_state(cfg, {"baseline": current_counts(cfg), "delta": {}})
    else:
        out(f"mbsync exited {rc}; pending moves kept, breaker state unchanged")
    return rc
