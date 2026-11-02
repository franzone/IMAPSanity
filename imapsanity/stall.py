"""Alerts when unattended cycles keep failing to sort mail.

A cycle stalls when mbsync fails, the rules step aborts on a guard, or the push fails. One stall is
routine (a timeout, a backlog the next cycle drains). A run of them means mail has stopped moving and
needs a person: guards never raise their own limits, so an aborted backlog only grows. After
[safety].stall_alert_after stalls in a row this logs a STALLED line and posts a macOS notification,
then repeats every stall_alert_every stalls, and posts once more when a cycle runs clean again.
"""

import subprocess
import sys
import time


def _notify(title, message):
    if sys.platform != "darwin":
        return
    script = ["-e", "on run argv", "-e", "display notification (item 1 of argv) with title (item 2 of argv)",
              "-e", "end run"]
    try:
        subprocess.run(["osascript", *script, message, title], capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        pass


def _label(cfg):
    return f"IMAPSanity: {cfg.name}" if cfg.name else "IMAPSanity"


def record(cfg, idx, reason=None, hint=None, out=None, notify=None):
    """Record this cycle's outcome. `reason` is None for a clean cycle, else why it stalled;
    `hint` is what to run about it, for the log."""
    out = out or print
    notify = notify or _notify
    s = cfg.safety
    count = int(idx.get_meta("cycle_stall_count") or 0)
    if reason is None:
        if s.stall_alert_after and count >= s.stall_alert_after:
            out(f"cycle: recovered after {count} stalled cycle(s)")
            notify(_label(cfg), f"Sorting again after {count} stalled cycles.")
        if count:
            idx.set_meta("cycle_stall_count", "0")
            idx.set_meta("cycle_stall_since", "")
            idx.set_meta("cycle_stall_alerted", "0")
        return

    count += 1
    since = float(idx.get_meta("cycle_stall_since") or 0) or time.time()
    idx.set_meta("cycle_stall_count", str(count))
    idx.set_meta("cycle_stall_since", str(since))
    if not s.stall_alert_after or count < s.stall_alert_after:
        return
    alerted = int(idx.get_meta("cycle_stall_alerted") or 0)
    if alerted and count - alerted < max(1, s.stall_alert_every):
        return
    hours = (time.time() - since) / 3600
    msg = f"No mail sorted for {hours:.1f}h ({count} cycles): {reason}"
    out(f"STALLED: {msg}")
    if hint:
        out(f"  fix: {hint}")
    notify(_label(cfg), msg)
    idx.set_meta("cycle_stall_alerted", str(count))
