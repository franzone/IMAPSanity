"""IMAPSanity v2: rules + AI proposals for a local mbsync maildir, applied safely.

Pipeline: index -> plan (rules, optional AI) -> review -> apply (guards, journal) -> undo/purge.
Only apply/undo/purge ever change mail, and only through the backends.
"""

__version__ = "2.0.0"
