"""Edit config.toml from the dashboard without losing what you wrote by hand.

The file is changed line by line: only the lines of the filer, rule or key being edited are
touched, so comments, ordering and blank lines everywhere else stay as they are. Before anything
is written the new text is loaded with the normal config loader (an invalid config is refused, so
the dashboard and launchd keep working), the old file is copied to <state>/config-backups, and the
file is replaced atomically. Every edit carries the revision of the text it was made against, so a
change made meanwhile (in an editor, or another tab) is never overwritten.

Structured editing covers the shared filers, [[match]] rules and [destinations].allow. Filers and
rules inside [[account]] entries, and everything else, are edited as raw text.
"""

import bisect
import hashlib
import json
import os
import re
import shutil
import threading
import time
import tomllib
from pathlib import Path

from .config import load_all

BACKUPS = "config-backups"
KEEP_BACKUPS = 30
NAME = re.compile(r"^[A-Za-z0-9_-]+$")
_HEADER = re.compile(r"^\s*(\[\[?)\s*(.+?)\s*\]\]?\s*(#.*)?$")
_KEY_PART = re.compile(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'|[A-Za-z0-9_-]+')
_write_lock = threading.Lock()


class EditError(Exception):
    pass


def revision(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)   # JSON string escapes are valid TOML basic-string escapes
    if isinstance(v, list):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    raise TypeError(v)


def _key_path(spec):
    parts = []
    for m in _KEY_PART.finditer(spec):
        p = m.group(0)
        parts.append(tomllib.loads(f"k = {p}")["k"] if p[0] in "\"'" else p)
    return tuple(parts)


def _parses(text):
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None


def _blank_or_comment(line):
    s = line.strip()
    return not s or s.startswith("#")


class Doc:
    """config.toml as lines, with the table headers located."""

    def __init__(self, text):
        self.lines = text.splitlines(keepends=True)
        if self.lines and not self.lines[-1].endswith("\n"):
            self.lines[-1] += "\n"
        self._headers = None
        self.raw   # refuse a file that isn't valid TOML up front

    def changed(self):
        self._headers = None

    @property
    def text(self):
        return "".join(self.lines)

    @property
    def raw(self):
        return tomllib.loads(self.text)

    def headers(self):
        """[(line, is_array, key path)] for every table header. A line inside a multi-line string
        could look like a header; rules() and filers() catch that by re-parsing every block."""
        if self._headers is None:
            self._headers = []
            for i, line in enumerate(self.lines):
                m = _HEADER.match(line)
                if m and not line.lstrip().startswith("#"):
                    self._headers.append((i, m.group(1) == "[[", _key_path(m.group(2))))
            self._starts = [i for i, _, _ in self._headers]
        return self._headers

    def _span(self, start):
        """(lead, end): a block's header line `start`, with the comment lines directly above it
        (lead), to the end of its keys (end), leaving trailing comments/blanks to the next block."""
        self.headers()
        k = bisect.bisect_right(self._starts, start)
        end = self._starts[k] if k < len(self._starts) else len(self.lines)
        while end > start + 1 and _blank_or_comment(self.lines[end - 1]):
            end -= 1
        lead = start
        while lead > 0 and self.lines[lead - 1].strip().startswith("#"):
            lead -= 1
        return lead, end

    def _body(self, start):
        return "".join(self.lines[start + 1:self._span(start)[1]])

    # --- the blocks the editor knows -----------------------------------------------------------

    def rules(self):
        """Header line of each shared [[match]], in order (rule n is rules()[n-1])."""
        found = [i for i, arr, path in self.headers() if arr and path == ("match",)]
        want = self.raw.get("match", [])
        if len(found) != len(want) or any(_parses(self._body(i)) != w for i, w in zip(found, want)):
            raise EditError("can't map the [[match]] rules in config.toml to their lines; use the raw editor")
        return found

    def filers(self):
        """{name: header line} of each shared [filers.NAME]."""
        found = {path[1]: i for i, arr, path in self.headers() if not arr and len(path) == 2 and path[0] == "filers"}
        want = self.raw.get("filers", {})
        if set(found) != set(want) or any(_parses(self._body(found[n])) != want[n] for n in want):
            raise EditError("can't map the [filers.*] tables in config.toml to their lines; use the raw editor")
        return found

    def table(self, name):
        for i, arr, path in self.headers():
            if not arr and path == (name,):
                return i
        return None

    # --- primitive edits ----------------------------------------------------------------------------

    def _key_lines(self, start, key):
        """(first, end) lines of `key = ...` in the block at `start`, or None."""
        end = self._span(start)[1]
        pat = re.compile(rf"^\s*{re.escape(key)}\s*=")
        for i in range(start + 1, end):
            if pat.match(self.lines[i]):
                for j in range(i + 1, end + 1):   # a value can span lines (arrays)
                    if _parses("".join(self.lines[i:j])) is not None:
                        return i, j
                raise EditError(f"can't parse {key} at line {i + 1}")
        return None

    def set_key(self, start, key, value, before=()):
        """Set (or with value None, remove) `key` in the block whose header is at `start`. A new
        key goes just above the first of `before` that the block has, else at the end."""
        span = self._key_lines(start, key)
        if value is None:
            if span:
                del self.lines[span[0]:span[1]]
                self.changed()
            return
        new = f"{key} = {toml_value(value)}"
        if span:
            comment = ""
            if span[1] - span[0] == 1:
                line = self.lines[span[0]].rstrip("\n")
                indent = line[:len(line) - len(line.lstrip())]
                new = indent + new
                full = _parses(line)
                for pos in (p for p, c in enumerate(line) if c == "#"):
                    if _parses(line[:pos]) == full:
                        comment = "   " + line[pos:].strip()
                        break
            self.lines[span[0]:span[1]] = [new + comment + "\n"]
        else:
            at = self._span(start)[1]
            for b in before:
                other = self._key_lines(start, b)
                if other:
                    at = other[0]
                    break
            self.lines.insert(at, new + "\n")
        self.changed()

    def remove_block(self, start):
        lead, end = self._span(start)
        del self.lines[lead:end]
        while lead < len(self.lines) and not self.lines[lead].strip() and (lead == 0 or not self.lines[lead - 1].strip()):
            del self.lines[lead]
        if lead == len(self.lines):   # it was the last block: no blank lines left dangling at the end
            while self.lines and not self.lines[-1].strip():
                self.lines.pop()
        self.changed()

    def insert_block(self, at, block_lines):
        """Insert a block (header + keys) before line `at`, separated by one blank line."""
        chunk = list(block_lines)
        if at > 0 and self.lines[at - 1].strip():
            chunk.insert(0, "\n")
        if at < len(self.lines) and self.lines[at].strip():
            chunk.append("\n")
        self.lines[at:at] = chunk
        self.changed()

    def end_of(self, start):
        return self._span(start)[1]

    def lead_of(self, start):
        return self._span(start)[0]


# --- operations: text in, text out ------------------------------------------------------------------

def _rule_block(sender, subject, filer):
    out = ["[[match]]\n"]
    if sender:
        out.append(f"sender = {toml_value(sender)}\n")
    if subject:
        out.append(f"subject = {toml_value(subject)}\n")
    out.append(f"filer = {toml_value(filer)}\n")
    return out


def _clean(s):
    s = (s or "").strip()
    if "\n" in s or "\r" in s:
        raise EditError("one line only")
    return s


def add_rule(text, sender, subject, filer, position=None):
    """Insert a rule so it becomes rule `position` (1-based; None = last)."""
    doc = Doc(text)
    sender, subject = _clean(sender), _clean(subject)
    rules = doc.rules()
    block = _rule_block(sender, subject, filer)
    if position is not None and 1 <= position <= len(rules):
        doc.insert_block(doc.lead_of(rules[position - 1]), block)
    elif rules:
        doc.insert_block(doc.end_of(rules[-1]), block)
    else:
        doc.insert_block(len(doc.lines), block)
    return doc.text


def update_rule(text, n, sender, subject, filer):
    doc = Doc(text)
    rules = doc.rules()
    if not 1 <= n <= len(rules):
        raise EditError(f"no rule #{n}")
    start = rules[n - 1]
    doc.set_key(start, "sender", _clean(sender) or None, before=("subject", "filer"))
    doc.set_key(doc.rules()[n - 1], "subject", _clean(subject) or None, before=("filer",))
    doc.set_key(doc.rules()[n - 1], "filer", filer)
    return doc.text


def delete_rule(text, n):
    doc = Doc(text)
    rules = doc.rules()
    if not 1 <= n <= len(rules):
        raise EditError(f"no rule #{n}")
    doc.remove_block(rules[n - 1])
    return doc.text


def move_rule(text, n, to):
    """Move rule n (with the comments directly above it) so it becomes rule `to`."""
    doc = Doc(text)
    rules = doc.rules()
    if not (1 <= n <= len(rules) and 1 <= to <= len(rules)):
        raise EditError(f"no rule #{n if not 1 <= n <= len(rules) else to}")
    if n == to:
        return text
    lead, end = doc.lead_of(rules[n - 1]), doc.end_of(rules[n - 1])
    block = doc.lines[lead:end]
    doc.remove_block(rules[n - 1])
    rules = doc.rules()   # now without it; the one at `to` moves down one
    if to <= len(rules):
        doc.insert_block(doc.lead_of(rules[to - 1]), block)
    else:
        doc.insert_block(doc.end_of(rules[-1]), block)
    return doc.text


def _keep_value(keep):
    keep = str(keep).strip().lower()
    if keep == "all":
        return "all"
    if keep.isdigit():
        return int(keep)
    raise EditError('keep must be "all" or a whole number')


def add_filer(text, name, folder, keep):
    doc = Doc(text)
    name, folder = _clean(name), _clean(folder)
    if not NAME.match(name):
        raise EditError("a filer name is letters, digits, '-' or '_'")
    filers = doc.filers()
    if name in filers:
        raise EditError(f"there's already a filer called {name}")
    block = [f"[filers.{name}]\n", f"folder = {toml_value(folder)}\n", f"keep = {toml_value(_keep_value(keep))}\n"]
    if filers:
        doc.insert_block(doc.end_of(max(filers.values())), block)
    else:
        rules = doc.rules()
        doc.insert_block(doc.lead_of(rules[0]) if rules else len(doc.lines), block)
    return doc.text


def update_filer(text, name, folder, keep):
    doc = Doc(text)
    filers = doc.filers()
    if name not in filers:
        raise EditError(f"no filer {name}")
    doc.set_key(filers[name], "folder", _clean(folder))
    doc.set_key(doc.filers()[name], "keep", _keep_value(keep))
    return doc.text


def filer_users(raw, name):
    """Where a filer is referenced: rule labels and settings."""
    out = [f"match #{i}" for i, m in enumerate(raw.get("match", []), 1) if m.get("filer") == name]
    for a in raw["account"] if isinstance(raw.get("account"), list) else []:
        out += [f"{a.get('name')}: match #{i}" for i, m in enumerate(a.get("match", []), 1) if m.get("filer") == name]
        if name in a.get("safety", {}).get("protect_filers", []):
            out.append(f"{a.get('name')}: [safety].protect_filers")
    if name in raw.get("safety", {}).get("protect_filers", []):
        out.append("[safety].protect_filers")
    return out


def delete_filer(text, name):
    doc = Doc(text)
    filers = doc.filers()
    if name not in filers:
        raise EditError(f"no filer {name}")
    used = filer_users(doc.raw, name)
    if used:
        raise EditError(f"{name} is still used by {', '.join(used[:5])}{' …' if len(used) > 5 else ''}")
    doc.remove_block(filers[name])
    return doc.text


def set_allow(text, folders):
    doc = Doc(text)
    folders = list(dict.fromkeys(_clean(f) for f in folders if f.strip()))
    start = doc.table("destinations")
    if start is None:
        filers = doc.filers()
        at = doc.lead_of(min(filers.values())) if filers else len(doc.lines)
        doc.insert_block(at, ["[destinations]\n", f"allow = {toml_value(folders)}\n"])
    else:
        doc.set_key(start, "allow", folders)
    return doc.text


# --- reading and saving ----------------------------------------------------------------------------

def read(path):
    text = Path(path).read_text()
    return text, revision(text)


def backups_dir(path):
    return load_all(path)[0].state_dir / BACKUPS


def backups(path):
    """Newest first."""
    d = backups_dir(path)
    if not d.exists():
        return []
    return sorted(d.glob("config-*.toml"), key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)


def save(path, new_text, rev):
    """Validate new_text with the real loader, back up the current file, and replace it.

    Raises EditError if the file changed since `rev`, and ConfigError (or TOMLDecodeError) if
    new_text isn't a valid config.
    """
    path = Path(path)
    with _write_lock:
        current = path.read_text()
        if revision(current) != rev:
            raise EditError("config.toml changed since this page was loaded; reload and try again")
        if new_text == current:
            return
        tmp = path.with_name(f".{path.name}.edit-{os.getpid()}")
        try:
            tmp.write_text(new_text)
            shutil.copymode(path, tmp)
            load_all(tmp)
            bdir = backups_dir(path)
            bdir.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            n = 0
            while (bdir / f"config-{stamp}{f'.{n}' if n else ''}.toml").exists():
                n += 1
            shutil.copyfile(path, bdir / f"config-{stamp}{f'.{n}' if n else ''}.toml")
            for old in backups(path)[KEEP_BACKUPS:]:
                old.unlink()
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)

