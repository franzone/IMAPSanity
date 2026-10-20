"""Senders and messages you told the dashboard to keep: never quarantined, never touched by AI.
Plus "trusted trims": senders whose keep-last-N extras are deleted without review even though they
look personal (say, a store you once replied to).

Kept per account in <state>/exceptions.json, so config.toml (hand-written, with comments) is never
rewritten. Kept senders join [safety].protected_senders; kept messages are matched by Message-ID.
"""

import json
import time

FILE = "exceptions.json"


def empty():
    return {"senders": {}, "messages": {}, "trust_trims": {}}


def load(state_dir):
    path = state_dir / FILE
    if not path.exists():
        return empty()
    data = json.loads(path.read_text())
    return {"senders": data.get("senders", {}), "messages": data.get("messages", {}),
            "trust_trims": data.get("trust_trims", {})}


def save(state_dir, data):
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / FILE
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    tmp.replace(path)


def add_sender(data, addr, note=""):
    data["senders"][addr.lower()] = {"added": int(time.time()), "note": note}


def trust_trims(data, addr, note=""):
    data["trust_trims"][addr.lower()] = {"added": int(time.time()), "note": note}


def add_message(data, msgid, addr="", subject=""):
    data["messages"][msgid] = {"added": int(time.time()), "addr": addr, "subject": subject}


def remove(data, kind, key):
    return data[kind].pop(key, None) is not None
