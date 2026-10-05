"""Maildir layout helpers shared by the index, the maildir backend and the sync breaker.

mbsync filenames look like `1789659503.22454_1.host,U=1:2,ST`: `,U=<n>` is mbsync's UID
and everything after `:2,` is the flag set. `T` (trashed) means the message is gone on
the server; with `Expunge None` the file stays around locally, so it must be ignored.
"""

import os
import re

INFO_SEP = ":2,"
_UID_RE = re.compile(r",U=\d+")
SUBDIRS = ("cur", "new")


def split_name(name):
    """Return (key, flags). The key is stable across flag changes."""
    base, sep, flags = name.partition(INFO_SEP)
    return base, (flags if sep else "")


def strip_uid(name):
    """Remove mbsync's `,U=<n>` so a moved file gets a fresh UID instead of a duplicate."""
    return _UID_RE.sub("", name)


def is_trashed(flags):
    return "T" in flags


def list_folders(root):
    out = []
    for dirpath, dirnames, _ in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in ("cur", "new", "tmp") and not d.startswith("."))
        if dirpath != str(root) and os.path.isdir(os.path.join(dirpath, "cur")):
            out.append(os.path.relpath(dirpath, root).replace(os.sep, "/"))
    return sorted(out)


def iter_messages(root, folder):
    """Yield (subdir, filename) for every message file in a folder, trashed ones included."""
    for sub in SUBDIRS:
        try:
            names = os.listdir(os.path.join(root, folder, sub))
        except FileNotFoundError:
            continue
        for n in names:
            if not n.startswith("."):
                yield sub, n


def live_count(root, folder):
    return sum(1 for _, n in iter_messages(root, folder) if not is_trashed(split_name(n)[1]))


def to_imap(folder, prefix, delimiter):
    if folder == "INBOX":
        return "INBOX"
    return prefix + folder.replace("/", delimiter)


def imap_quote(name):
    if not name.isascii():
        raise ValueError(f"non-ASCII mailbox name not supported: {name!r}")
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
