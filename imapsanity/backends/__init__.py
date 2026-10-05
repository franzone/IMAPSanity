"""Backends are the only code that changes mail. Both return per-action results:

    [(action, status, detail)]  with status in
    moved | not_found | ambiguous | flagged | failed

A backend never creates folders (except ImapBackend.create, used only by `mkfolder`)
and never deletes (except ImapBackend.purge, used only by `purge` on the quarantine).
"""


class BackendError(Exception):
    pass
