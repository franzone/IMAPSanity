"""Invariants checked before anything moves, no matter who wrote the plan."""

from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Verdict:
    ok: list = field(default_factory=list)
    rejected: list = field(default_factory=list)  # (action, reason)
    aborts: list = field(default_factory=list)    # reasons the whole run must stop


def action_problem(cfg, a):
    s = cfg.safety
    if not a.get("msgid"):
        return "no Message-ID"
    if a["dest"] == a["folder"]:
        return "destination equals source"
    if a["folder"] in s.protected_folders:
        return f"source folder {a['folder']!r} is protected"
    if a["dest"] not in cfg.allow_destinations:
        return f"destination {a['dest']!r} not in allow list"
    if a["source"] == "ai":
        if a["dest"] not in cfg.ai.destinations:
            return f"destination {a['dest']!r} not allowed for AI"
        if cfg.is_protected_sender(a["from"]):
            return "AI may not act on protected senders"
    if a["dest"] == s.quarantine and cfg.is_protected_sender(a["from"]):
        return "protected sender cannot be quarantined"
    if cfg.backend_for(a["folder"]) != cfg.backend_for(a["dest"]):
        return "source and destination use different backends (both must be maildir_folders, or neither)"
    return None


def check_plan(cfg, actions, folder_sizes, max_moves=None, max_fraction=None, max_quarantine=None):
    s = cfg.safety
    max_moves = s.max_moves_per_run if max_moves is None else max_moves
    max_fraction = s.max_fraction_per_folder if max_fraction is None else max_fraction
    max_quarantine = s.max_quarantine_per_run if max_quarantine is None else max_quarantine

    v = Verdict()
    seen = set()
    for a in actions:
        if not a.get("approved"):
            continue
        ident = (a["folder"], a.get("msgid"))
        problem = "duplicate action for the same message" if ident in seen else action_problem(cfg, a)
        seen.add(ident)
        if problem:
            v.rejected.append((a, problem))
        else:
            v.ok.append(a)

    if len(v.ok) > max_moves:
        v.aborts.append(f"{len(v.ok)} moves exceeds max_moves_per_run={max_moves} (override: --max-moves)")
    nq = sum(1 for a in v.ok if a["dest"] == s.quarantine)
    if nq > max_quarantine:
        v.aborts.append(f"{nq} quarantines exceeds max_quarantine_per_run={max_quarantine} (override: --max-quarantine)")
    for folder, n in Counter(a["folder"] for a in v.ok).items():
        size = folder_sizes.get(folder, 0)
        if size >= s.min_folder_size_for_fraction and n > size * max_fraction:
            v.aborts.append(f"{n} of {size} messages leaving {folder} exceeds "
                            f"max_fraction_per_folder={max_fraction} (override: --max-fraction)")
    return v
