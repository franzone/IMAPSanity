import os
import tempfile
import textwrap
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone
from pathlib import Path

from imapsanity.config import load

BASE_CONFIG = """
[account]
email = "me@example.com"
imap_host = "imap.example.com"
keychain_service = "test"

[paths]
maildir = "{root}/Mail"
state = "{root}/state"

[backends]
maildir_folders = {maildir_folders}

[mbsync]
push = {push}

[safety]
max_moves_per_run = 50
max_fraction_per_folder = 0.5
min_folder_size_for_fraction = 10
protected_senders = ["boss@work.com"]

[destinations]
allow = ["Filtered/News", "Local/Done"]

[ai]
enabled = true
[ai.destinations]
"Filtered/News" = "newsletters"
"Quarantine" = "junk"

[filers.VIP]
folder = "IMAPSanity/VIP"
keep = "all"

[filers.One]
folder = "IMAPSanity/One"
keep = 1

[[match]]
sender = "mom@family.com"
filer = "VIP"

[[match]]
sender = "@deals.com"
filer = "One"

[[match]]
subject = "weekly digest"
filer = "One"
"""

FOLDERS = ["INBOX", "IMAPSanity/VIP", "IMAPSanity/One", "Filtered/News", "Quarantine",
           "Sent", "Local/Inbox", "Local/Done"]


class Env:
    """A temp maildir + state dir + config."""

    def __init__(self, maildir_folders=(), push=()):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.mail = self.root / "Mail"
        for f in FOLDERS:
            for sub in ("cur", "new", "tmp"):
                (self.mail / f / sub).mkdir(parents=True, exist_ok=True)
        cfg_text = BASE_CONFIG.format(root=self.root, maildir_folders=list(maildir_folders), push=list(push))
        cfg_text = cfg_text.replace("'", '"')
        self.cfg_path = self.root / "config.toml"
        self.cfg_path.write_text(textwrap.dedent(cfg_text))
        self.counter = 0

    def cfg(self):
        return load(self.cfg_path)

    def add(self, folder, sender, subject, days_ago=0, flags="S", msgid=None, uid=None, sub="cur"):
        self.counter += 1
        n = self.counter
        msgid = msgid or f"<m{n}@test>"
        date = datetime.now(timezone.utc) - timedelta(days=days_ago)
        body = (f"From: {sender}\nSubject: {subject}\nDate: {format_datetime(date)}\n"
                f"Message-ID: {msgid}\n\nhello {n}\n")
        uid = uid if uid is not None else n
        name = f"17000000{n:02d}.1_{n}.host,U={uid}" + (f":2,{flags}" if sub == "cur" else "")
        path = self.mail / folder / sub / name
        path.write_text(body)
        return msgid, path

    def cleanup(self):
        self._tmp.cleanup()


class FakeIMAP:
    """Just enough of imaplib.IMAP4 for ImapBackend. Mailboxes: {imap_name: {uid: (msgid, flags)}}"""

    def __init__(self, boxes, caps="IMAP4rev1 MOVE UIDPLUS"):
        self.boxes = boxes
        self.caps = caps
        self.selected = None
        self.next_uid = 1000
        self.log = []

    def capability(self):
        return "OK", [self.caps.encode()]

    def list(self):
        return "OK", [f'(\\HasNoChildren) "." "{n}"'.encode() for n in self.boxes]

    def select(self, name, readonly=False):
        name = name.strip('"')
        if name not in self.boxes:
            return "NO", [b"no such mailbox"]
        self.selected = name
        return "OK", [str(len(self.boxes[name])).encode()]

    def uid(self, cmd, *args):
        self.log.append((cmd, args))
        box = self.boxes[self.selected]
        if cmd == "FETCH":
            data = []
            for i, (uid, (msgid, flags)) in enumerate(sorted(box.items()), start=1):
                lit = f"Message-ID: {msgid}\r\n\r\n".encode()
                data.append((f"{i} (UID {uid} FLAGS ({flags}) BODY[HEADER.FIELDS (MESSAGE-ID)] {{{len(lit)}}}".encode(), lit))
                data.append(b")")
            return "OK", data
        if cmd == "MOVE":
            uids, dest = args[0].split(","), args[1].strip('"')
            for u in uids:
                self.next_uid += 1
                self.boxes[dest][self.next_uid] = box.pop(int(u))
            return "OK", [None]
        if cmd == "STORE":
            for u in args[0].split(","):
                m, f = box[int(u)]
                box[int(u)] = (m, f + " \\Deleted")
            return "OK", [None]
        if cmd == "EXPUNGE":
            for u in args[0].split(","):
                box.pop(int(u))
            return "OK", [None]
        raise AssertionError(cmd)

    def create(self, name):
        self.boxes[name.strip('"')] = {}
        return "OK", [None]

    def subscribe(self, name):
        return "OK", [None]

    def logout(self):
        pass
