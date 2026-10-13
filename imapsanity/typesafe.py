"""Second opinion from TypeSafe's Jev (a System One model) for shadow mode. Never touches mail.

One request per message, three questions over the same state:
- `destination`: a Choice over KEEP + [ai.destinations], with calibrated probabilities.
- `personal`: a Noul, "did a real person write this to the recipient?" (used as a veto).
- `important`: a Noul, "is this a bill, security alert or official notice?" (used as a veto).

Raw probabilities are cached in ts_cache, so the auto bar can be retuned without re-asking.
Sender, subject, List-Id and the first 500 characters of the body are sent to api.typesafe.ai.
"""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .ai import KEEP
from .message import read_snippet

RETRIES = 3


class TypeSafeError(Exception):
    pass


def api_key(cfg):
    if os.environ.get("TYPESAFE_API_KEY"):
        return os.environ["TYPESAFE_API_KEY"]
    if not cfg.typesafe.keychain_service:
        raise TypeSafeError("set [typesafe].keychain_service or TYPESAFE_API_KEY")
    r = subprocess.run(["/usr/bin/security", "find-generic-password", "-a", cfg.account.email,
                        "-s", cfg.typesafe.keychain_service, "-w"], capture_output=True, text=True)
    if r.returncode != 0:
        raise TypeSafeError(f"keychain lookup failed for service {cfg.typesafe.keychain_service!r}")
    return r.stdout.rstrip("\n")


def questions(cfg):
    criteria = {KEEP: {
        "what": "Leave it in the inbox for the owner to read.",
        "use_for": ["anything written personally by a real person", "time-sensitive mail",
                    "financial, legal, medical or government mail", "mail the owner's preferences say to keep",
                    "anything that does not clearly fit another folder"],
    }}
    criteria.update(cfg.ai.destinations)
    return {
        "destination": {
            "type": "choice",
            "instructions": {
                "question": "Which folder should `email` be filed in? Choose KEEP unless `email` "
                            "clearly belongs in one of the other folders.",
                "owner_preferences": cfg.ai.instructions.strip() or "(none given)",
            },
            "criteria": criteria,
        },
        "personal": {
            "type": "noul",
            "instructions": "Was `email` written by a real person specifically to the recipient, "
                            "rather than sent automatically or as a bulk mailing to many people?",
            "criteria": {"true": "A person wrote it to the recipient (family, friend, client, colleague, church)",
                         "false": "Automated, a newsletter, marketing, or a mass mailing"},
        },
        "important": {
            "type": "noul",
            "instructions": "Is `email` a bill, payment notice, security alert, appointment, or official "
                            "notice from a bank, government, school or doctor?",
            "criteria": {"true": "The recipient may need to see or act on it",
                         "false": "Marketing, a newsletter, a social notification, or other optional reading"},
        },
    }


def state_for(cfg, idx, row):
    # No date: Jev reads dates as text, and it doesn't help the filing decision.
    return {
        "recipient": cfg.account.email,
        "email": {
            "from": row["from_raw"],
            "subject": row["subject"],
            "list_id": row["list_id"] or None,
            "body_start": read_snippet(idx.path_of(row)),
        },
    }


def _post(cfg, key, payload):
    data = json.dumps(payload, ensure_ascii=False).encode()
    for attempt in range(RETRIES + 1):
        req = urllib.request.Request(cfg.typesafe.url, data=data, method="POST", headers={
            "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=cfg.typesafe.timeout_seconds) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 529) and attempt < RETRIES:
                time.sleep(float(e.headers.get("retry-after") or 2 ** attempt))
                continue
            raise TypeSafeError(f"HTTP {e.code}: {e.read()[:300].decode(errors='replace')}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt < RETRIES:
                time.sleep(2 ** attempt)
                continue
            raise TypeSafeError(f"cannot reach {cfg.typesafe.url}: {e}")


def _parse(cfg, resp):
    try:
        a = resp["answers"]
        d = a["destination"]
        if d["choice"] not in {KEEP, *cfg.ai.destinations}:
            raise TypeSafeError(f"unexpected choice {d['choice']!r}")
        return (d["choice"], float(d["confidence"]), json.dumps(d["probabilities"]),
                float(a["personal"]["noul"]), float(a["important"]["noul"]), resp.get("model"))
    except (KeyError, TypeError, ValueError) as e:
        raise TypeSafeError(f"malformed response ({e}): {str(resp)[:300]}")


def classify(cfg, idx, rows, limit, out=print):
    """Ask about up to `limit` rows not already in ts_cache. Results already stored survive an error."""
    todo, seen = [], set()
    for r in rows:
        if r["msgid"] and r["msgid"] not in seen and idx.ts_cached(r["msgid"]) is None:
            seen.add(r["msgid"])
            todo.append(r)
    todo = todo[:limit]
    if not todo:
        return 0
    key = api_key(cfg)
    qs = questions(cfg)
    payloads = [{"state": state_for(cfg, idx, r), "model": cfg.typesafe.model, "questions": qs} for r in todo]
    out(f"typesafe: classifying {len(todo)} message(s)")
    tokens = 0
    # Results come back in order; sqlite writes stay on this thread.
    with ThreadPoolExecutor(max_workers=cfg.typesafe.workers) as pool:
        for r, resp in zip(todo, pool.map(lambda p: _post(cfg, key, p), payloads)):
            idx.ts_store(r["msgid"], *_parse(cfg, resp))
            tokens += (resp.get("usage") or {}).get("input_tokens", 0)
    out(f"typesafe: done ({tokens} input tokens)")
    return len(todo)


def list_models(cfg):
    """For `check`: proves the key works without spending tokens."""
    url = cfg.typesafe.url.rsplit("/", 1)[0] + "/models"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_key(cfg)}"})
    try:
        with urllib.request.urlopen(req, timeout=cfg.typesafe.timeout_seconds) as r:
            return [m["name"] for m in json.load(r).get("models", [])]
    except urllib.error.HTTPError as e:
        raise TypeSafeError(f"HTTP {e.code} from {url}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise TypeSafeError(f"cannot reach {url}: {e}")
