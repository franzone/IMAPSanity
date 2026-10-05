"""Append-only JSONL journal: one file per run. Intent is written before each move."""

import json
import time
from datetime import datetime
from pathlib import Path


def journal_dir(cfg):
    d = cfg.state_dir / "journal"
    d.mkdir(parents=True, exist_ok=True)
    return d


def new_run_id(kind):
    return f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{kind}"


class Journal:
    def __init__(self, cfg, run_id):
        self.run_id = run_id
        self.path = journal_dir(cfg) / f"{run_id}.jsonl"
        if self.path.exists():
            raise SystemExit(f"journal {self.path} already exists")
        self._f = open(self.path, "a", encoding="utf-8")

    def write(self, action, status, backend, detail=None, **extra):
        entry = {
            "ts": int(time.time()),
            "run": self.run_id,
            "action": action.get("id"),
            "msgid": action.get("msgid"),
            "from_folder": action["folder"],
            "to_folder": action["dest"],
            "key": action.get("key"),
            "backend": backend,
            "status": status,
            "source": action.get("source"),
            "why": action.get("why"),
            "addr": action.get("addr"),
            "subject": action.get("subject"),
        }
        if detail:
            entry["detail"] = detail
        entry.update(extra)
        self._f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._f.flush()

    def close(self):
        self._f.close()


def read(cfg, run_id):
    path = journal_dir(cfg) / f"{run_id}.jsonl"
    if not path.exists():
        raise SystemExit(f"no journal for run {run_id!r} (see `imapsanity runs`)")
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def all_runs(cfg):
    return sorted(p.stem for p in journal_dir(cfg).glob("*.jsonl"))


def final_states(entries):
    """Last entry per action id, i.e. what actually happened."""
    last = {}
    for e in entries:
        last[e["action"]] = e
    return list(last.values())
