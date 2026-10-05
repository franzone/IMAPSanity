"""Local maildir moves for folders synced two-way by mbsync (pushed later by `sync push`).

A move is a rename within the same filesystem. mbsync's `,U=<n>` is stripped so the
file gets a fresh UID in the destination instead of colliding with an existing one.
"""

import os

from .. import maildir
from ..message import read_headers
from . import BackendError


class MaildirBackend:
    name = "maildir"

    def __init__(self, cfg):
        self.cfg = cfg
        self.root = str(cfg.maildir)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def _files(self, folder):
        """uid-less key -> [(subdir, filename)]"""
        out = {}
        for sub, name in maildir.iter_messages(self.root, folder):
            out.setdefault(maildir.strip_uid(maildir.split_name(name)[0]), []).append((sub, name))
        return out

    def exists(self, folder):
        return os.path.isdir(os.path.join(self.root, folder, "cur"))

    def move(self, folder, actions, check_flagged=True):
        results = []
        files = self._files(folder)
        for a in actions:
            hits = files.get(maildir.strip_uid(a.get("key") or ""), [])
            hits = [h for h in hits if not maildir.is_trashed(maildir.split_name(h[1])[1])]
            if not hits:
                results.append((a, "not_found", f"not in local {folder}"))
                continue
            if len(hits) > 1:
                results.append((a, "ambiguous", f"{len(hits)} files match key"))
                continue
            sub, name = hits[0]
            src = os.path.join(self.root, folder, sub, name)
            if check_flagged and "F" in maildir.split_name(name)[1]:
                results.append((a, "flagged", "flagged locally"))
                continue
            try:
                if read_headers(src)["msgid"] != a["msgid"]:
                    results.append((a, "failed", "Message-ID mismatch; refusing"))
                    continue
            except OSError as e:
                results.append((a, "failed", str(e)))
                continue
            if not self.exists(a["dest"]):
                results.append((a, "failed", f"destination {a['dest']!r} does not exist locally"))
                continue
            new_name = maildir.strip_uid(name)
            dst = os.path.join(self.root, a["dest"], sub, new_name)
            if os.path.exists(dst):
                results.append((a, "failed", "target file already exists"))
                continue
            os.rename(src, dst)
            results.append((a, "moved", {"new_key": maildir.split_name(new_name)[0]}))
        return results

    def create(self, folder):
        raise BackendError("maildir backend never creates folders; create it on the server and pull")
