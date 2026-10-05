"""Deterministic rules (ported from v1 mailboxes.yml): file by sender/subject, keep last N.

Matching keeps v1's IMAP SEARCH semantics: case-insensitive substring of From / Subject.
Keep-last-N no longer deletes: extras are proposed for the quarantine folder.
"""

from .plan import make_action


def rule_matches(rule, row):
    if rule.sender and rule.sender.lower() not in (row["from_raw"] or "").lower():
        return False
    if rule.subject and rule.subject.lower() not in (row["subject"] or "").lower():
        return False
    return True


def first_match(cfg, row):
    for rule in cfg.matches:
        if rule_matches(rule, row):
            return rule
    return None


def build_actions(cfg, idx):
    """Return (actions, notes). Every action is approved: rules are config you wrote."""
    notes = []
    q = cfg.safety.quarantine
    incoming = {}  # (folder, msgid) -> [row, rule, dest, why]
    seen = set()

    # 1. File messages out of the source folders (first matching rule wins).
    for folder in cfg.rules_source_folders:
        for row in idx.live(folder):
            rule = first_match(cfg, row)
            if rule is None:
                continue
            ident = (folder, row["msgid"])
            if not row["msgid"]:
                notes.append(f"skip (no Message-ID): {row['from_raw']} / {row['subject']}")
                continue
            if ident in seen:
                notes.append(f"skip (duplicate Message-ID in {folder}): {row['subject']}")
                incoming.pop(ident, None)
                continue
            seen.add(ident)
            if "F" in row["flags"] and cfg.safety.skip_flagged:
                continue
            filer = cfg.filers[rule.filer]
            incoming[ident] = [row, rule, filer.folder, rule.label()]

    # 2. Keep last N per rule, across what's already in the filer folder plus what's arriving.
    trims = []
    for filer in cfg.filers.values():
        if filer.keep is None:
            continue
        resident = [r for r in idx.live(filer.folder) if r["msgid"]]
        arriving = [v for v in incoming.values() if v[2] == filer.folder]
        kept, beyond = set(), {}
        for rule in (m for m in cfg.matches if m.filer == filer.name):
            pool = [(r, False) for r in resident if rule_matches(rule, r)]
            pool += [(v[0], True) for v in arriving if rule_matches(rule, v[0])]
            pool.sort(key=lambda p: p[0]["date_ts"] or 0, reverse=True)
            for i, (r, is_incoming) in enumerate(pool):
                ident = (r["folder"], r["msgid"])
                if i < filer.keep:
                    kept.add(ident)
                else:
                    beyond.setdefault(ident, (r, is_incoming, rule))
        for ident, (r, is_incoming, rule) in beyond.items():
            if ident in kept or ("F" in r["flags"] and cfg.safety.skip_flagged):
                continue
            if cfg.is_protected_sender(r["from_raw"]):
                notes.append(f"not quarantining protected sender: {r['from_raw']}")
                continue
            why = f"keep-last-{filer.keep} ({filer.name}, {rule.label()})"
            if is_incoming:
                incoming[ident][2:] = [q, why]
            else:
                trims.append(make_action(r, q, "rule", why, approved=True))

    actions = [make_action(row, dest, "rule", why, approved=True) for row, _, dest, why in incoming.values()]
    return actions + trims, notes


def unmatched(cfg, idx, folders):
    """Live messages in `folders` that no rule claims (input for AI + rule suggestions)."""
    return [r for f in folders for r in idx.live(f) if r["msgid"] and first_match(cfg, r) is None]
