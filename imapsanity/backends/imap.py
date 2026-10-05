"""Server-side moves over IMAP (TLS). Messages are located by Message-ID, never by position.

Requires MOVE and UIDPLUS so every operation targets exact UIDs; a plain EXPUNGE
(which v1 used) would also remove anything another client had flagged \\Deleted.
"""

import email.parser
import imaplib
import os
import re
import subprocess
from collections import defaultdict

from ..maildir import imap_quote, to_imap
from ..message import norm_msgid
from . import BackendError

CHUNK = 100
_UID_RE = re.compile(rb"\bUID (\d+)")
_FLAGS_RE = re.compile(rb"\bFLAGS \(([^)]*)\)")
_LIST_RE = re.compile(r'^\((?P<flags>[^)]*)\) (?P<delim>"(?:[^"\\]|\\.)*"|NIL) (?P<name>.+)$')


def get_password(account):
    if os.environ.get("IMAPSANITY_PASSWORD"):
        return os.environ["IMAPSANITY_PASSWORD"]
    if not account.keychain_service:
        raise BackendError("set [account].keychain_service or IMAPSANITY_PASSWORD")
    r = subprocess.run(["/usr/bin/security", "find-generic-password", "-a", account.email,
                        "-s", account.keychain_service, "-w"], capture_output=True, text=True)
    if r.returncode != 0:
        raise BackendError(f"keychain lookup failed for service {account.keychain_service!r}")
    return r.stdout.rstrip("\n")


def _unquote(name):
    if name.startswith('"') and name.endswith('"'):
        return re.sub(r'\\(.)', r'\1', name[1:-1])
    return name


class ImapBackend:
    name = "imap"

    def __init__(self, cfg, conn=None):
        self.cfg = cfg
        self.conn = conn
        self.folders = set()

    def __enter__(self):
        if self.conn is None:
            a = self.cfg.account
            self.conn = imaplib.IMAP4_SSL(a.imap_host, a.imap_port)
            self.conn.login(a.email, get_password(a))
        typ, data = self.conn.capability()
        caps = set(b" ".join(data).decode().upper().split())
        missing = {"MOVE", "UIDPLUS"} - caps
        if missing:
            raise BackendError(f"server lacks {', '.join(sorted(missing))}; refusing to run")
        self.folders = self._list()
        return self

    def __exit__(self, *exc):
        try:
            self.conn.logout()
        except Exception:
            pass

    def _imap(self, folder):
        return to_imap(folder, self.cfg.account.imap_prefix, self.cfg.account.imap_delimiter)

    def _list(self):
        typ, data = self.conn.list()
        if typ != "OK":
            raise BackendError("LIST failed")
        names = set()
        for item in data:
            if isinstance(item, tuple):  # name sent as a literal
                names.add(item[1].decode())
                continue
            if not item:
                continue
            m = _LIST_RE.match(item.decode())
            if m:
                names.add(_unquote(m["name"]))
        return names

    def exists(self, folder):
        return self._imap(folder) in self.folders

    def _select(self, folder):
        typ, data = self.conn.select(imap_quote(self._imap(folder)))
        if typ != "OK":
            raise BackendError(f"cannot select {folder}: {data}")
        return int(data[0] or 0)

    def _message_map(self, folder):
        """msgid -> [(uid, flags)] for the selected folder, from the live server state."""
        if self._select(folder) == 0:
            return {}
        typ, data = self.conn.uid("FETCH", "1:*", "(FLAGS BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
        if typ != "OK":
            raise BackendError(f"FETCH failed in {folder}")
        records, meta, literal = [], None, None
        for item in data:
            if isinstance(item, tuple):
                if meta is not None:
                    records.append((meta, literal))
                meta, literal = item[0], item[1]
            elif isinstance(item, bytes) and meta is not None:
                meta += item  # e.g. b' FLAGS (\\Seen))' when FLAGS follows the literal
        if meta is not None:
            records.append((meta, literal))

        parser = email.parser.BytesHeaderParser()
        out = defaultdict(list)
        for meta, literal in records:
            uid, flags = _UID_RE.search(meta), _FLAGS_RE.search(meta)
            if not uid:
                continue
            msgid = norm_msgid(parser.parsebytes(literal or b"").get("Message-ID"))
            if msgid:
                out[msgid].append((uid.group(1).decode(), (flags.group(1).decode() if flags else "")))
        return out

    def move(self, folder, actions, check_flagged=True):
        """Move actions whose source is `folder`. Returns [(action, status, detail)]."""
        results = []
        by_msgid = self._message_map(folder)
        by_dest = defaultdict(list)
        for a in actions:
            hits = by_msgid.get(a["msgid"], [])
            if not hits:
                results.append((a, "not_found", f"not in {folder} on server"))
            elif len(hits) > 1:
                results.append((a, "ambiguous", f"{len(hits)} copies in {folder}"))
            elif check_flagged and "\\Flagged" in hits[0][1]:
                results.append((a, "flagged", "flagged on server"))
            elif not self.exists(a["dest"]):
                results.append((a, "failed", f"destination {a['dest']!r} does not exist on server"))
            else:
                by_dest[a["dest"]].append((a, hits[0][0]))

        for dest, items in by_dest.items():
            for i in range(0, len(items), CHUNK):
                chunk = items[i:i + CHUNK]
                uidset = ",".join(uid for _, uid in chunk)
                typ, data = self.conn.uid("MOVE", uidset, imap_quote(self._imap(dest)))
                status = "moved" if typ == "OK" else "failed"
                detail = None if typ == "OK" else str(data)[:200]
                results.extend((a, status, detail) for a, _ in chunk)
        return results

    def create(self, folder):
        typ, data = self.conn.create(imap_quote(self._imap(folder)))
        if typ != "OK":
            raise BackendError(f"CREATE {folder} failed: {data}")
        self.conn.subscribe(imap_quote(self._imap(folder)))

    def purge(self, folder, msgids):
        """Permanently delete exact messages from `folder`. Only called by `purge` on the quarantine."""
        by_msgid = self._message_map(folder)
        uids, results = [], []
        for m in msgids:
            hits = by_msgid.get(m, [])
            if len(hits) == 1:
                uids.append(hits[0][0])
                results.append((m, "purged"))
            else:
                results.append((m, "not_found" if not hits else "ambiguous"))
        for i in range(0, len(uids), CHUNK):
            uidset = ",".join(uids[i:i + CHUNK])
            typ, data = self.conn.uid("STORE", uidset, "+FLAGS.SILENT", "(\\Deleted)")
            if typ != "OK":
                raise BackendError(f"STORE failed: {data}")
            typ, data = self.conn.uid("EXPUNGE", uidset)
            if typ != "OK":
                raise BackendError(f"UID EXPUNGE failed: {data}")
        return results
