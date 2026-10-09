"""Incremental SQLite index of the local maildir (headers only). Replaces notmuch.

Read-only with respect to mail: it never modifies the maildir.
"""

import fnmatch
import os
import sqlite3
import time

from . import maildir
from .message import read_headers

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    folder   TEXT NOT NULL,
    key      TEXT NOT NULL,
    subdir   TEXT NOT NULL,
    filename TEXT NOT NULL,
    flags    TEXT NOT NULL,
    trashed  INTEGER NOT NULL,
    msgid    TEXT,
    from_raw TEXT,
    from_addr TEXT,
    subject  TEXT,
    date_ts  INTEGER,
    list_id  TEXT,
    PRIMARY KEY (folder, key)
);
CREATE INDEX IF NOT EXISTS messages_msgid ON messages (msgid);
CREATE TABLE IF NOT EXISTS ai_cache (
    msgid TEXT PRIMARY KEY,
    dest TEXT NOT NULL,
    confidence REAL,
    reason TEXT,
    model TEXT,
    ts INTEGER
);
CREATE TABLE IF NOT EXISTS ai_decisions (
    msgid TEXT NOT NULL,
    dest TEXT NOT NULL,
    decision TEXT NOT NULL,
    ts INTEGER,
    PRIMARY KEY (msgid, dest)
);
CREATE TABLE IF NOT EXISTS ts_cache (
    msgid TEXT PRIMARY KEY,
    dest TEXT NOT NULL,
    confidence REAL NOT NULL,
    probabilities TEXT NOT NULL,
    personal REAL NOT NULL,
    important REAL NOT NULL,
    model TEXT,
    ts INTEGER
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


class Index:
    def __init__(self, cfg):
        self.cfg = cfg
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(cfg.state_dir / "index.sqlite3")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    # --- indexing -----------------------------------------------------------------

    def _excluded(self, folder):
        return any(fnmatch.fnmatch(folder, pat) for pat in self.cfg.index_exclude)

    def update(self, verbose=True):
        root = self.cfg.maildir
        folders = [f for f in maildir.list_folders(root) if not self._excluded(f)]
        added = changed = removed = 0
        started = time.time()
        for folder in folders:
            known = {r["key"]: (r["subdir"], r["filename"])
                     for r in self.db.execute("SELECT key, subdir, filename FROM messages WHERE folder=?", (folder,))}
            seen = set()
            f_added = 0
            for sub, name in maildir.iter_messages(root, folder):
                key, flags = maildir.split_name(name)
                seen.add(key)
                old = known.get(key)
                if old == (sub, name):
                    continue
                trashed = int(maildir.is_trashed(flags))
                if old is None:
                    try:
                        h = read_headers(os.path.join(root, folder, sub, name))
                    except OSError:
                        continue  # vanished mid-scan; next run picks it up
                    self.db.execute(
                        "INSERT OR REPLACE INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (folder, key, sub, name, flags, trashed, h["msgid"], h["from_raw"],
                         h["from_addr"], h["subject"], h["date_ts"], h["list_id"]))
                    f_added += 1
                else:
                    self.db.execute(
                        "UPDATE messages SET subdir=?, filename=?, flags=?, trashed=? WHERE folder=? AND key=?",
                        (sub, name, flags, trashed, folder, key))
                    changed += 1
            gone = set(known) - seen
            self.db.executemany("DELETE FROM messages WHERE folder=? AND key=?", [(folder, k) for k in gone])
            removed += len(gone)
            added += f_added
            self.db.commit()
            if verbose and f_added > 200:
                print(f"  indexed {f_added} new in {folder}")
        placeholders = ",".join("?" * len(folders)) or "''"
        cur = self.db.execute(f"DELETE FROM messages WHERE folder NOT IN ({placeholders})", folders)
        removed += cur.rowcount
        self.db.commit()
        if verbose:
            print(f"index: {len(folders)} folders, +{added} new, {changed} changed, -{removed} removed "
                  f"({time.time() - started:.1f}s)")
        return added, changed, removed

    # --- queries ------------------------------------------------------------------

    def live(self, folder):
        """Messages still present on the server side (not T-flagged), newest first."""
        return self.db.execute(
            "SELECT * FROM messages WHERE folder=? AND trashed=0 ORDER BY date_ts DESC", (folder,)).fetchall()

    def folder_sizes(self):
        return {r["folder"]: r["n"] for r in self.db.execute(
            "SELECT folder, COUNT(*) AS n FROM messages WHERE trashed=0 GROUP BY folder")}

    def path_of(self, row):
        return os.path.join(self.cfg.maildir, row["folder"], row["subdir"], row["filename"])

    # --- AI cache / decisions -------------------------------------------------------

    def ai_cached(self, msgid):
        return self.db.execute("SELECT * FROM ai_cache WHERE msgid=?", (msgid,)).fetchone()

    def ai_store(self, msgid, dest, confidence, reason, model):
        self.db.execute("INSERT OR REPLACE INTO ai_cache VALUES (?,?,?,?,?,?)",
                        (msgid, dest, confidence, reason, model, int(time.time())))
        self.db.commit()

    def ai_decision(self, msgid, dest):
        r = self.db.execute("SELECT decision FROM ai_decisions WHERE msgid=? AND dest=?", (msgid, dest)).fetchone()
        return r["decision"] if r else None

    def record_decision(self, msgid, dest, decision):
        self.db.execute("INSERT OR REPLACE INTO ai_decisions VALUES (?,?,?,?)",
                        (msgid, dest, decision, int(time.time())))
        self.db.commit()

    # --- TypeSafe cache (shadow mode) ----------------------------------------------

    def ts_cached(self, msgid):
        return self.db.execute("SELECT * FROM ts_cache WHERE msgid=?", (msgid,)).fetchone()

    def ts_store(self, msgid, dest, confidence, probabilities, personal, important, model):
        self.db.execute("INSERT OR REPLACE INTO ts_cache VALUES (?,?,?,?,?,?,?,?)",
                        (msgid, dest, confidence, probabilities, personal, important, model, int(time.time())))
        self.db.commit()

    def ts_backfill_rows(self):
        """One live row per message Claude classified but TypeSafe hasn't (for typesafe-backfill)."""
        return self.db.execute(
            "SELECT m.* FROM messages m JOIN ai_cache c ON c.msgid = m.msgid "
            "LEFT JOIN ts_cache t ON t.msgid = m.msgid "
            "WHERE m.trashed = 0 AND t.msgid IS NULL GROUP BY m.msgid ORDER BY m.date_ts DESC").fetchall()

    def live_by_msgid(self, msgid):
        return self.db.execute("SELECT * FROM messages WHERE msgid=? AND trashed=0", (msgid,)).fetchall()

    # --- meta ---------------------------------------------------------------------

    def get_meta(self, k, default=None):
        r = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r["v"] if r else default

    def set_meta(self, k, v):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))
        self.db.commit()
