"""`imapsanity serve`: a local web dashboard for reviewing the quarantine and AI proposals, and for
running the everyday commands.

Local only, by construction:
  * binds 127.0.0.1 and refuses any other Host header (DNS rebinding);
  * every request needs a cookie set from the one-time link printed at startup, and POSTs must come
    from the dashboard's own pages (SameSite=Strict cookie, Origin / Sec-Fetch-Site checks);
  * the only JavaScript is the fixed SELECT_JS below (Check all / Clear all), allowed by its hash in
    the Content-Security-Policy, which forbids every other script; every value taken from mail
    (subjects, senders, snippets) is HTML-escaped.
Every change goes through the same code the CLI uses (guards, journal, undo), under the account's
run lock, so a launchd `cycle` and the dashboard never move mail at the same time. Config edits go
through configedit: validated, backed up, and written without disturbing the rest of the file.
"""

import argparse
import base64
import contextlib
import difflib
import hashlib
import hmac
import html
import io
import re
import secrets
import sys
import time
import tomllib
import traceback
import webbrowser
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from . import apply, cli, configedit, exceptions, journal, plan, quarantine
from .config import ConfigError, Match, load_all
from .config import config_path as resolve_config_path
from .index import Index
from .message import read_snippet
from .rules import rule_matches

MAX_BODY = 1 << 20
PLAN_NAME = re.compile(r"^plan-[0-9-]+\.json$")
CONFIG_BACK = re.compile(r"^/config(/rules|/raw)?(\?[^\r\n]*)?$")
RULES_PER_PAGE = 100
UNNAMED = "_"   # URL segment for a single [account] config, whose account has no name
TIER_TITLES = {
    "careful": ("Look carefully", "Strong signs these might not be junk. Nothing is pre-selected: "
                                  "tick what you've checked."),
    "glance": ("Worth a glance", "Quarantined on the AI's judgment. Pre-selected; untick anything that isn't junk."),
    "rules": ("Trimmed by your keep-last-N rules", "Older extras from senders you wrote rules for, with no sign "
                                                   "they're personal. Pre-selected."),
}

CSS = """
:root { --bg:#f7f7f5; --panel:#fff; --text:#1d1d1b; --muted:#6b6b66; --line:#e3e2dd; --accent:#2f5d8a;
  --warn:#9a5b00; --warn-bg:#fff4e0; --bad:#a3302a; --ok:#2e6b3a; --chip:#eef1f5; }
@media (prefers-color-scheme: dark) { :root { --bg:#161615; --panel:#1f1f1d; --text:#e8e6e1; --muted:#9a988f;
  --line:#33322f; --accent:#8db4dc; --warn:#e0a54a; --warn-bg:#2d2416; --bad:#e07a72; --ok:#7cc48b; --chip:#272a2f; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.45 -apple-system, system-ui, sans-serif; }
header.top { display:flex; flex-wrap:wrap; gap:4px 18px; align-items:center; padding:12px 20px;
  border-bottom:1px solid var(--line); background:var(--panel); }
header.top strong { font-size:16px; margin-right:8px; }
nav a { margin-right:14px; color:var(--muted); text-decoration:none; }
nav a.on { color:var(--text); font-weight:600; }
main { max-width:1100px; margin:0 auto; padding:20px 16px 60px; }
h1 { font-size:22px; margin:4px 0 16px; } h2 { font-size:17px; margin:28px 0 6px; }
p.hint, .muted { color:var(--muted); } p.hint { margin:0 0 12px; }
a { color:var(--accent); }
.flash { padding:10px 14px; border-radius:8px; background:var(--chip); margin-bottom:16px; }
.flash.bad { background:var(--warn-bg); color:var(--warn); }
.cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:16px; }
.card, .group { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
.group { margin:10px 0; } .group.careful { border-left:4px solid var(--warn); }
.group h3 { margin:0; font-size:15px; overflow-wrap:anywhere; }
.chips { margin:6px 0 8px; } .chip { display:inline-block; background:var(--chip); border-radius:999px;
  padding:1px 9px; margin:2px 4px 2px 0; font-size:12.5px; }
.chip.warn { background:var(--warn-bg); color:var(--warn); }
table { width:100%; border-collapse:collapse; } td, th { text-align:left; padding:5px 6px; vertical-align:top;
  border-top:1px solid var(--line); font-size:14px; overflow-wrap:anywhere; } th { color:var(--muted); font-weight:500; }
td.nowrap { white-space:nowrap; } .snippet { color:var(--muted); font-size:13px; margin-top:2px; }
.stat { font-size:26px; font-weight:600; } .stat small { font-size:13px; color:var(--muted); font-weight:400; }
.row { display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; align-items:center; }
button { font:inherit; padding:6px 12px; border-radius:7px; border:1px solid var(--line); background:var(--panel);
  color:var(--text); cursor:pointer; } button.primary { background:var(--accent); border-color:var(--accent); color:var(--bg); }
button.danger { color:var(--bad); border-color:var(--bad); }
button.small { padding:2px 8px; font-size:12px; }
select { font:inherit; padding:5px 8px; border-radius:7px; border:1px solid var(--line);
  background:var(--panel); color:var(--text); }
input[type=text], input[type=number], textarea { font:inherit; padding:6px 8px; border-radius:7px;
  border:1px solid var(--line); background:var(--panel); color:var(--text); }
input[type=text] { min-width:260px; }
input.cell { min-width:0; width:100%; } input[type=number] { width:5.5em; }
textarea { width:100%; font:13px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }
td.tight { white-space:nowrap; width:1%; }
details > summary { cursor:pointer; margin:8px 0; color:var(--accent); }
pre { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px; overflow:auto;
  white-space:pre-wrap; font-size:13px; }
.ok { color:var(--ok); } .bad { color:var(--bad); }
@media (max-width:640px) { td.hide-sm, th.hide-sm { display:none; } }
"""

# Check all / Clear all for a quarantine group: ticks or clears every message box in the button's form.
SELECT_JS = ("document.addEventListener('click',function(e){var b=e.target.closest('button[data-check]');"
             "if(!b)return;b.form.querySelectorAll('input[name=msgid][type=checkbox]').forEach("
             "function(c){c.checked=b.dataset.check==='1';});});")
SELECT_JS_HASH = base64.b64encode(hashlib.sha256(SELECT_JS.encode()).digest()).decode()

CSP = (f"default-src 'none'; script-src 'sha256-{SELECT_JS_HASH}'; style-src 'unsafe-inline'; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


def h(value):
    return html.escape("" if value is None else str(value), quote=True)


def ago(ts):
    if not ts:
        return "never"
    s = max(0, time.time() - float(ts))
    for unit, n in (("d", 86400), ("h", 3600), ("min", 60)):
        if s >= n:
            return f"{int(s // n)} {unit} ago"
    return "just now"


def day(ts):
    return datetime.fromtimestamp(ts).strftime("%b %d") if ts else ""


class Busy(Exception):
    pass


class Response:
    def __init__(self, body="", status=200, location=None):
        self.body, self.status, self.location = body, status, location


def redirect(path, msg=None, bad=False):
    if msg:
        path += ("&" if "?" in path else "?") + urlencode({"msg": msg, **({"bad": "1"} if bad else {})})
    return Response(status=303, location=path)


class App:
    def __init__(self, config_path, port, token=None):
        self.config_path = resolve_config_path(config_path)   # None (no --config) means the default file
        self.port = port
        self.token = token or secrets.token_urlsafe(24)
        self.cookie = f"imapsanity{port}"
        self.op_lock = Lock()   # one mail-changing operation at a time (and stdout capture is global)

    # --- accounts -------------------------------------------------------------------

    def accounts(self):
        return load_all(self.config_path)

    def account(self, slug):
        name = "" if slug == UNNAMED else slug
        for cfg in self.accounts():
            if cfg.name == name:
                return cfg
        return None

    @staticmethod
    def slug(cfg):
        return cfg.name or UNNAMED

    @contextlib.contextmanager
    def open(self, cfg, lock=False):
        """Index for one account; with lock=True also its run lock (Busy if cycle holds it)."""
        with contextlib.ExitStack() as stack:
            if lock:
                stack.enter_context(self.op_lock)
                try:
                    stack.enter_context(cli.run_lock(cfg))
                except SystemExit as e:
                    raise Busy(str(e.code)) from None
            idx = Index(cfg)
            stack.callback(idx.close)
            yield idx

    @staticmethod
    def capture(fn):
        """Run fn() with stdout captured (the CLI code reports with print). Returns (rc, text)."""
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = fn()
        except SystemExit as e:   # e.g. "no plans yet"
            rc = e.code if isinstance(e.code, int) else 1
            if isinstance(e.code, str):
                buf.write(e.code + "\n")
        return rc, buf.getvalue()

    # --- layout -----------------------------------------------------------------------

    def page(self, title, body, cfg=None, tab=None, query=None):
        accounts = self.accounts()
        nav = [f'<a href="/" class="{"on" if tab == "home" else ""}">Overview</a>']
        if cfg is None and tab == "config" and len(accounts) == 1:
            cfg = accounts[0]   # keep the account tabs on the config pages
        if cfg is not None:
            base = f"/a/{quote(self.slug(cfg))}"
            for key, label in (("quarantine", "Quarantine"), ("review", "AI review"), ("runs", "Runs"),
                               ("exceptions", "Exceptions"), ("actions", "Actions")):
                nav.append(f'<a href="{base}/{key}" class="{"on" if tab == key else ""}">{label}</a>')
        nav.append(f'<a href="/config" class="{"on" if tab == "config" else ""}">Config</a>')
        switch = ""
        if cfg is not None and len(accounts) > 1:
            switch = " ".join(
                f'<a href="/a/{quote(self.slug(c))}/{tab or "quarantine"}" class="{"on" if c.name == cfg.name else ""}">'
                f"{h(c.name)}</a>" for c in accounts)
            switch = f'<nav class="muted">account: {switch}</nav>'
        flash = ""
        if query and query.get("msg"):
            cls = "flash bad" if query.get("bad") else "flash"
            flash = f'<div class="{cls}">{h(query["msg"][0])}</div>'
        return Response(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{h(title)} · IMAPSanity</title>
<style>{CSS}</style></head><body>
<header class="top"><strong>IMAPSanity</strong><nav>{"".join(nav)}</nav>{switch}</header>
<main>{flash}<h1>{h(title)}</h1>{body}</main><script>{SELECT_JS}</script></body></html>""")

    # --- routing ----------------------------------------------------------------------

    def route(self, method, path, query, form):
        if path == "/" and method == "GET":
            return self.overview(query)
        if path in ("/config", "/config/rules", "/config/raw"):
            if method == "GET":
                return {"/config": self.get_config, "/config/rules": self.get_config_rules,
                        "/config/raw": self.get_config_raw}[path](query)
            if method == "POST" and path == "/config":
                return self.post_config(form)
            return Response("method not allowed", 405)
        m = re.fullmatch(r"/a/([^/]+)/(quarantine|review|runs|exceptions|actions|undo)", path)
        if not m:
            return Response("not found", 404)
        cfg = self.account(m.group(1))
        if cfg is None:
            return Response("no such account", 404)
        view = m.group(2)
        try:
            if method == "GET" and view != "undo":
                return getattr(self, f"get_{view}")(cfg, query)
            if method == "POST":
                return getattr(self, f"post_{view}")(cfg, form)
        except Busy as e:
            back = f"/a/{quote(self.slug(cfg))}/{'runs' if view == 'undo' else view}"
            return redirect(back, f"Busy: {e} (probably the scheduled cycle). Try again in a moment.", bad=True)
        return Response("method not allowed", 405)

    # --- overview -----------------------------------------------------------------------

    def overview(self, query):
        cards = []
        for cfg in self.accounts():
            base = f"/a/{quote(self.slug(cfg))}"
            with self.open(cfg) as idx:
                its = [i for i in quarantine.items(cfg, idx) if i["ours"]]
                todo = [i for i in its if not i["confirmed"]]
                careful = sum(1 for i in todo if quarantine.tier(i) == "careful")
                pending, plan_note = self._pending(cfg, idx)
                last_cycle = idx.get_meta("cycle_last_run")
            runs = journal.all_runs(cfg)[-4:]
            run_list = "".join(f"<li>{h(r)}</li>" for r in reversed(runs)) or "<li class='muted'>none yet</li>"
            careful_chip = f' <span class="chip warn">{careful} need a careful look</span>' if careful else ""
            cards.append(f"""<div class="card">
<h2 style="margin-top:0">{h(cfg.name or cfg.account.email)}</h2>
<div class="muted">{h(cfg.account.email)} · last cycle {h(ago(last_cycle))}</div>
<div class="row"><div class="stat">{len(todo)} <small>quarantined, not reviewed</small></div>{careful_chip}</div>
<div class="muted">{len(its) - len(todo)} confirmed as junk (purge-able)</div>
<div class="row"><div class="stat">{pending} <small>AI proposals waiting</small></div></div>
<div class="muted">{h(plan_note)}</div>
<div class="row"><a href="{base}/quarantine">Review quarantine</a> <a href="{base}/review">Review AI proposals</a>
<a href="{base}/actions">Actions</a></div>
<h2>Recent runs</h2><ul>{run_list}</ul></div>""")
        return self.page("Overview", f'<div class="cards">{"".join(cards)}</div>', tab="home", query=query)

    def _pending(self, cfg, idx):
        try:
            path = plan.resolve(cfg)
        except SystemExit:
            return 0, "no plan yet"
        p = plan.load(path)
        if p.get("applied_run"):
            return 0, f"latest plan already applied ({p['applied_run']})"
        age = plan.age_hours(p)
        if age > cfg.safety.max_plan_age_hours:
            return 0, f"latest plan expired ({age:.0f}h old); make a new one"
        return len(plan.pending(p)), f"plan {path.name}, {age:.1f}h old"

    # --- quarantine -----------------------------------------------------------------------

    def get_quarantine(self, cfg, query):
        base = f"/a/{quote(self.slug(cfg))}/quarantine"
        with self.open(cfg) as idx:
            its = quarantine.items(cfg, idx)
        ours = [i for i in its if i["ours"]]
        todo = quarantine.groups([i for i in ours if not i["confirmed"]])
        done = quarantine.groups([i for i in ours if i["confirmed"]])
        manual = [i for i in its if not i["ours"]]
        targets = quarantine.move_targets(cfg)

        days = cfg.safety.purge_rule_trims_days
        trims = (f'Extras trimmed by your keep-last-N rules are confirmed automatically and deleted {days:g} day(s) '
                 f'after they were quarantined; rescue any you want before then. ') if days else ""
        parts = [f'<p class="hint">{len(ours)} message(s) imapsanity quarantined. Purge only deletes the ones you '
                 f'confirm as junk here. {trims}<b>Rescue</b> moves a message back where it came from and keeps it from '
                 f'being quarantined again; <b>Rescue + keep sender</b> does that for everything from the sender; '
                 f'<b>Move to folder</b> rescues it into a folder you pick (say, when a rule filed it in the wrong '
                 f'one: fix the rule in config.toml too).</p>']
        if not todo:
            parts.append('<p class="ok">Nothing waiting for review.</p>')
        for tier in ("careful", "glance", "rules"):
            gs = [g for g in todo if g["tier"] == tier]
            if not gs:
                continue
            title, hint = TIER_TITLES[tier]
            n = sum(len(g["items"]) for g in gs)
            blocks = "".join(self._qgroup(base, g, tier, targets, days) for g in gs)
            head = f"<h2>{title} · {len(gs)} sender(s), {n} message(s)</h2><p class='hint'>{hint}</p>"
            if tier == "rules":
                # Your own rules put these here and anything with a strong signal is listed above,
                # so this is the one section that can be confirmed in one go.
                ids = "".join(f'<input type="hidden" name="msgid" value="{h(i["msgid"])}">' for g in gs for i in g["items"])
                confirm_all = (f'<form method="post" action="{base}">{ids}<div class="row"><button name="action" '
                               f'value="junk" class="primary">Confirm all {n} as junk</button></div></form>')
                parts.append(f"{head}{confirm_all}<details><summary>Show {len(gs)} sender(s)</summary>{blocks}</details>")
            else:
                parts.append(head + blocks)
        if done:
            n = sum(len(g["items"]) for g in done)
            blocks = "".join(self._qgroup(base, g, "done", targets, days) for g in done)
            auto = sum(1 for g in done for i in g["items"] if i["auto"])
            how = (f" {auto} of them are keep-last-N trims, deleted automatically {days:g} day(s) after they were "
                   f"quarantined.") if auto else ""
            parts.append(f"<h2>Confirmed junk · {n}</h2><p class='hint'>These are what <code>purge</code> deletes once "
                         f"they're old enough.{how}</p><details><summary>Show</summary>{blocks}</details>")
        if manual:
            rows = "".join(f"<tr><td class='nowrap'>{h(day(i['date_ts']))}</td><td>{h(i['from'])}</td>"
                           f"<td>{h(i['subject'])}</td></tr>" for i in manual)
            parts.append(f"<h2>Put here by hand · {len(manual)}</h2><p class='hint'>Not moved by imapsanity, so never "
                         f"purged. Move them out with your mail client.</p><details><summary>Show</summary>"
                         f"<table>{rows}</table></details>")
        return self.page("Quarantine", "".join(parts), cfg, "quarantine", query)

    def _qgroup(self, base, g, tier, targets, days=0):
        checked = "" if tier == "careful" else " checked"
        rows = []
        for i in g["items"]:
            when = ""
            if i.get("auto") and i["quarantined_ts"]:
                due = i["quarantined_ts"] + days * 86400
                when = f" · deleted {'at the next cycle' if due <= time.time() else day(due)}"
            snippet = ""
            if tier == "careful":
                snippet = f'<div class="snippet">{h(read_snippet(i["path"], 240))}</div>'
            rows.append(f"""<tr><td><input type="checkbox" name="msgid" value="{h(i['msgid'])}"{checked}
 aria-label="select"></td><td class="nowrap">{h(day(i['date_ts']))}</td>
<td>{h(i['subject']) or '<span class="muted">(no subject)</span>'}{snippet}</td>
<td class="hide-sm">{h(i['why'])}<div class="muted">from {h(i['origin'])} · {h(ago(i['quarantined_ts']))}{h(when)}</div></td></tr>""")
        chips = "".join(f'<span class="chip{" warn" if tier == "careful" else ""}">{h(r)}</span>' for r in g["reasons"])
        move = ('<span class="muted">or</span><select name="dest" aria-label="folder">'
                + "".join(f'<option value="{h(t)}">{h(t)}</option>' for t in targets)
                + '</select><button name="action" value="move">Move to folder</button>')
        if tier == "done":
            # Automatic trims can't go back to review (they'd be confirmed again), only out of the quarantine.
            buttons = ("" if all(i.get("auto") for i in g["items"]) else
                       '<button name="action" value="unjunk">Not sure any more: back to review</button>')
            buttons += ('<button name="action" value="rescue">Rescue</button>'
                        '<button name="action" value="keep-sender">Rescue + keep sender</button>' + move)
        else:
            buttons = ('<button name="action" value="junk" class="primary">Confirm junk</button>'
                       '<button name="action" value="rescue">Rescue</button>'
                       '<button name="action" value="keep-sender">Rescue + keep sender</button>' + move)
        return f"""<div class="group {tier}"><form method="post" action="{base}">
<h3>{h(g['sender'])} <span class="muted">· {len(g['items'])}</span></h3><div class="chips">{chips}</div>
<div class="row"><button type="button" class="small" data-check="1">Check all</button>
<button type="button" class="small" data-check="0">Clear all</button></div>
<table><tr><th></th><th>Date</th><th>Subject</th><th class="hide-sm">Why it's here</th></tr>{"".join(rows)}</table>
<div class="row">{buttons}</div></form></div>"""

    def post_quarantine(self, cfg, form):
        base = f"/a/{quote(self.slug(cfg))}/quarantine"
        msgids = form.get("msgid", [])
        action = (form.get("action") or [""])[0]
        if not msgids:
            return redirect(base, "Nothing selected: tick the messages first.", bad=True)
        with self.open(cfg, lock=True) as idx:
            if action in ("junk", "unjunk"):
                idx.confirm_junk(msgids, confirmed=action == "junk")
                verb = "Confirmed as junk" if action == "junk" else "Back in review"
                return redirect(base, f"{verb}: {len(msgids)} message(s).")
            if action in ("rescue", "keep-sender", "move"):
                dest = (form.get("dest") or [""])[0] if action == "move" else None
                if action == "move" and dest not in quarantine.move_targets(cfg):
                    return redirect(base, "Pick a folder to move to.", bad=True)
                tally = Counter()
                self.capture(lambda: tally.update(
                    quarantine.rescue(cfg, idx, msgids, keep_sender=action == "keep-sender", dest=dest)))
                moved = tally.get("moved", 0)
                problems = {k: v for k, v in tally.items() if k != "moved"}
                if action == "move":
                    msg = f"Moved {moved} message(s) to {dest}."
                else:
                    msg = f"Rescued {moved} message(s)" + (" and kept their sender(s)." if action == "keep-sender" else ".")
                if problems:
                    msg += " Not moved: " + ", ".join(f"{k} {v}" for k, v in problems.items()) + " (see Runs)."
                return redirect(base, msg, bad=bool(problems))
        return redirect(base, "Unknown action.", bad=True)

    # --- AI review ----------------------------------------------------------------------

    def get_review(self, cfg, query):
        base = f"/a/{quote(self.slug(cfg))}"
        try:
            path = plan.resolve(cfg)
        except SystemExit:
            return self.page("AI review", self._make_plan_form(base, "There's no plan yet."), cfg, "review", query)
        p = plan.load(path)
        age = plan.age_hours(p)
        if p.get("applied_run") or age > cfg.safety.max_plan_age_hours:
            why = "was already applied" if p.get("applied_run") else f"is {age:.0f}h old, past the {cfg.safety.max_plan_age_hours:g}h limit"
            return self.page("AI review", self._make_plan_form(base, f"The latest plan {why}."), cfg, "review", query)
        waiting = plan.pending(p)
        groups = {}
        for a in waiting:
            groups.setdefault((a["dest"], a["addr"] or a["from"]), []).append(a)
        ordered = sorted(groups.items(), key=lambda kv: min(a["confidence"] or 0 for a in kv[1]))
        approved = sum(1 for a in p["actions"] if a["approved"])
        parts = [f'<p class="hint">Plan <code>{h(path.name)}</code>, {age:.1f}h old · {approved} move(s) approved '
                 f'(rules are pre-approved) · {len(waiting)} AI proposal(s) waiting. Least confident first. '
                 f'Proposals to the quarantine start unticked.</p>']
        if not waiting:
            parts.append('<p class="ok">Nothing waiting.</p>')
        for (dest, sender), acts in ordered:
            checked = "" if dest == cfg.safety.quarantine else " checked"
            confs = [a["confidence"] or 0 for a in acts]
            rows = "".join(
                f"""<tr><td><input type="checkbox" name="id" value="{h(a['id'])}"{checked} aria-label="select"></td>
<td class="nowrap">{h(a['date'][:10])}</td><td>{h(a['subject']) or '(no subject)'}</td>
<td class="nowrap">{(a['confidence'] or 0):.2f}</td></tr>""" for a in acts)
            cls = "group careful" if dest == cfg.safety.quarantine else "group"
            parts.append(f"""<div class="{cls}"><form method="post" action="{base}/review">
<input type="hidden" name="plan" value="{h(path.name)}">
<h3>{h(sender)} → {h(dest)} <span class="muted">· {len(acts)} · confidence {min(confs):.2f}–{max(confs):.2f}</span></h3>
<div class="chips"><span class="chip">{h(acts[0]['why'])}</span></div>
<table><tr><th></th><th>Date</th><th>Subject</th><th>Conf.</th></tr>{rows}</table>
<div class="row"><button name="action" value="approve" class="primary">Approve</button>
<button name="action" value="reject">Reject (never propose again)</button></div></form></div>""")
        parts.append(f"""<h2>Apply</h2><form method="post" action="{base}/actions"><input type="hidden" name="op" value="apply">
<p class="hint">Shows exactly what would move first; nothing moves until you confirm.</p>
<button class="primary">Preview apply</button></form>""")
        return self.page("AI review", "".join(parts), cfg, "review", query)

    @staticmethod
    def _make_plan_form(base, why):
        return f"""<p>{h(why)}</p><form method="post" action="{base}/actions"><div class="row">
<button name="op" value="plan" class="primary">Make a new plan (rules + AI)</button>
<button name="op" value="plan-rules">Rules only</button></div></form>"""

    def post_review(self, cfg, form):
        base = f"/a/{quote(self.slug(cfg))}/review"
        name = (form.get("plan") or [""])[0]
        ids = set(form.get("id", []))
        action = (form.get("action") or [""])[0]
        if not PLAN_NAME.match(name) or action not in ("approve", "reject"):
            return redirect(base, "Bad request.", bad=True)
        if not ids:
            return redirect(base, "Nothing selected: tick the messages first.", bad=True)
        with self.open(cfg, lock=True) as idx:
            path = plan.plans_dir(cfg) / name
            p = plan.load(path)
            acts = [a for a in plan.pending(p) if a["id"] in ids]
            plan.decide(idx, acts, "approved" if action == "approve" else "rejected")
            plan.save(cfg, p, path)
        verb = "Approved" if action == "approve" else "Rejected"
        return redirect(base, f"{verb} {len(acts)} proposal(s).")

    # --- runs / undo ----------------------------------------------------------------------

    def get_runs(self, cfg, query):
        base = f"/a/{quote(self.slug(cfg))}"
        rows = []
        for run in reversed(journal.all_runs(cfg)[-60:]):
            states = Counter(e["status"] for e in journal.final_states(journal.read(cfg, run)))
            summary = ", ".join(f"{k} {n}" for k, n in sorted(states.items()))
            undo = ""
            if states.get("moved") and "-purge" not in run:
                undo = (f'<form method="post" action="{base}/undo"><input type="hidden" name="run" value="{h(run)}">'
                        f'<button>Undo…</button></form>')
            rows.append(f"<tr><td class='nowrap'>{h(run)}</td><td>{h(summary)}</td><td>{undo}</td></tr>")
        body = ("<p class='hint'>Undo shows what it would move back before doing anything.</p>"
                f"<table><tr><th>Run</th><th>Result</th><th></th></tr>{''.join(rows)}</table>" if rows
                else "<p class='muted'>No runs yet.</p>")
        return self.page("Runs", body, cfg, "runs", query)

    def post_undo(self, cfg, form):
        base = f"/a/{quote(self.slug(cfg))}"
        run = (form.get("run") or [""])[0]
        if run not in journal.all_runs(cfg):
            return redirect(f"{base}/runs", "No such run.", bad=True)
        execute = (form.get("execute") or [""])[0] == "1"
        with self.open(cfg, lock=True):
            rc, text = self.capture(lambda: apply.undo(cfg, run, execute))
        confirm = ""
        if not execute and rc == 0 and "nothing to undo" not in text:
            confirm = f"""<form method="post" action="{base}/undo"><input type="hidden" name="run" value="{h(run)}">
<input type="hidden" name="execute" value="1"><button class="primary">Undo for real</button></form>"""
        return self._output(cfg, f"Undo {run}" + ("" if execute else " (preview)"), rc, text, confirm, "runs")

    # --- exceptions ------------------------------------------------------------------------

    def get_exceptions(self, cfg, query):
        base = f"/a/{quote(self.slug(cfg))}/exceptions"
        exc = exceptions.load(cfg.state_dir)

        def remove(kind, key):
            return (f'<form method="post" action="{base}"><input type="hidden" name="kind" value="{kind}">'
                    f'<input type="hidden" name="key" value="{h(key)}"><button name="action" value="remove">Remove</button></form>')

        senders = "".join(f"<tr><td>{h(k)}</td><td class='nowrap'>{h(day(v.get('added')))}</td><td>{h(v.get('note'))}</td>"
                          f"<td>{remove('senders', k)}</td></tr>" for k, v in sorted(exc["senders"].items()))
        messages = "".join(f"<tr><td>{h(v.get('addr'))}</td><td>{h(v.get('subject'))}</td>"
                           f"<td class='nowrap'>{h(day(v.get('added')))}</td><td>{remove('messages', k)}</td></tr>"
                           for k, v in sorted(exc["messages"].items(), key=lambda kv: -kv[1].get("added", 0)))
        body = f"""<p class="hint">Kept senders and messages are never quarantined and never touched by the AI, like
<code>[safety].protected_senders</code>. A sender matches anywhere in the From header. These live in
<code>{h(cfg.state_dir / exceptions.FILE)}</code>, not in config.toml.</p>
<h2>Kept senders · {len(exc['senders'])}</h2>
<form method="post" action="{base}" class="row"><input type="text" name="sender" placeholder="someone@example.com or @example.com"
 aria-label="sender"><button name="action" value="add" class="primary">Keep sender</button></form>
{f"<table><tr><th>Sender</th><th>Added</th><th>Note</th><th></th></tr>{senders}</table>" if senders else "<p class='muted'>None.</p>"}
<h2>Kept messages · {len(exc['messages'])}</h2>
{f"<table><tr><th>From</th><th>Subject</th><th>Added</th><th></th></tr>{messages}</table>" if messages else "<p class='muted'>None.</p>"}"""
        return self.page("Exceptions", body, cfg, "exceptions", query)

    def post_exceptions(self, cfg, form):
        base = f"/a/{quote(self.slug(cfg))}/exceptions"
        action = (form.get("action") or [""])[0]
        with self.open(cfg, lock=True):
            exc = exceptions.load(cfg.state_dir)
            if action == "add":
                sender = (form.get("sender") or [""])[0].strip().lower()
                if len(sender) < 3 or " " in sender:
                    return redirect(base, "Enter an address or a domain like @example.com.", bad=True)
                exceptions.add_sender(exc, sender, note="added in the dashboard")
                msg = f"Keeping {sender}."
            elif action == "remove":
                kind, key = (form.get("kind") or [""])[0], (form.get("key") or [""])[0]
                if kind not in ("senders", "messages") or not exceptions.remove(exc, kind, key):
                    return redirect(base, "Not found.", bad=True)
                msg = "Removed."
            else:
                return redirect(base, "Unknown action.", bad=True)
            exceptions.save(cfg.state_dir, exc)
        return redirect(base, msg)

    # --- config editor ----------------------------------------------------------------------

    def _config_hint(self):
        try:
            bdir = configedit.backups_dir(self.config_path)
        except ConfigError:
            bdir = "<state>/config-backups"
        return (f'<p class="hint">Edits are written to <code>{h(self.config_path)}</code>. Each save is checked '
                f'with the same loader <code>cycle</code> uses (an invalid config is refused), the previous file is '
                f'kept in <code>{h(bdir)}</code>, and only the lines you change are touched, so your comments stay. '
                f'The next cycle uses the new config. Rules only file new mail out of '
                f'{h(", ".join(self.accounts()[0].rules_source_folders))}; changing one doesn\'t move mail it already filed.</p>')

    @staticmethod
    def _hidden(**kw):
        return "".join(f'<input type="hidden" name="{k}" value="{h(v)}">' for k, v in kw.items())

    def get_config(self, query):
        text, rev = configedit.read(self.config_path)
        raw = tomllib.loads(text)
        filers = raw.get("filers", {})
        counts = {n: len(configedit.filer_users(raw, n)) for n in filers}
        rows = []
        for n, f in filers.items():
            fid = f"f-{n}"
            keep = f.get("keep", "all")
            rows.append(f"""<tr><td class="tight"><b>{h(n)}</b></td>
<td><input class="cell" type="text" name="folder" value="{h(f.get('folder'))}" form="{fid}" aria-label="folder"></td>
<td class="tight"><input type="text" name="keep" value="{h(keep)}" form="{fid}" aria-label="keep" style="min-width:0;width:4.5em"></td>
<td class="tight"><a href="/config/rules?filer={quote(n)}">{counts[n]} use(s)</a></td>
<td class="tight"><form id="{fid}" method="post" action="/config">{self._hidden(rev=rev, name=n, back="/config")}
<button name="op" value="update-filer">Save</button> <button name="op" value="delete-filer" class="danger"
{' disabled title="still used"' if counts[n] else ''}>Delete</button></form></td></tr>""")
        allow = raw.get("destinations", {}).get("allow", [])
        accounts = raw["account"] if isinstance(raw.get("account"), list) else []
        scoped = [(a.get("name"), "filer", fn, f.get("folder")) for a in accounts for fn, f in a.get("filers", {}).items()]
        scoped += [(a.get("name"), "rule", f"#{i}", f"{m.get('sender', '')} {m.get('subject', '')} → {m.get('filer')}")
                   for a in accounts for i, m in enumerate(a.get("match", []), 1)]
        scoped_html = ""
        if scoped:
            items = "".join(f"<tr><td>{h(a)}</td><td>{h(k)}</td><td>{h(n)}</td><td>{h(v)}</td></tr>" for a, k, n, v in scoped)
            scoped_html = (f"<h2>Inside [[account]] entries · {len(scoped)}</h2><p class='hint'>Edit these in the "
                           f"<a href='/config/raw'>raw editor</a>.</p><table>{items}</table>")
        body = f"""{self._config_hint()}
<p><a href="/config/rules"><b>Rules · {len(raw.get('match', []))}</b></a> &nbsp; <a href="/config/raw">Raw config.toml and backups</a></p>
<h2>Filers · {len(filers)}</h2>
<p class="hint">A filer is a folder plus how many messages to keep per rule: <code>all</code>, or a number (older
extras go to the quarantine for review). A filer can only be deleted once no rule uses it.</p>
<table><tr><th>Name</th><th>Folder</th><th>Keep</th><th>Rules</th><th></th></tr>{"".join(rows)}</table>
<form method="post" action="/config" class="row">{self._hidden(rev=rev, back="/config")}
<input type="text" name="name" placeholder="new filer name, e.g. TwentyOfThese" aria-label="name" style="min-width:200px">
<input type="text" name="folder" placeholder="folder, e.g. IMAPSanity/TwentyOfThese" aria-label="folder">
<input type="text" name="keep" placeholder="keep: all or 20" aria-label="keep" style="min-width:0;width:9em">
<button name="op" value="add-filer" class="primary">Add filer</button></form>
<p class="hint">A new folder has to exist on the server: <code>imapsanity mkfolder FOLDER --execute</code>.</p>
<h2>Allowed destinations</h2>
<p class="hint">Folders anything may be moved to, one per line. Filer folders and the quarantine are always allowed.
Folders in <code>[ai.destinations]</code> must be listed here.</p>
<form method="post" action="/config">{self._hidden(rev=rev, back="/config")}
<textarea name="allow" rows="{max(3, len(allow) + 1)}" aria-label="allowed destinations">{h(chr(10).join(allow))}</textarea>
<div class="row"><button name="op" value="set-allow" class="primary">Save destinations</button></div></form>
{scoped_html}"""
        return self.page("Config", body, tab="config", query=query)

    def _filer_select(self, filers, current, form_id=None):
        attr = f' form="{form_id}"' if form_id else ""
        opts = "".join(f'<option value="{h(n)}"{" selected" if n == current else ""}>{h(n)}</option>' for n in filers)
        return f'<select name="filer" aria-label="filer"{attr}>{opts}</select>'

    def get_config_rules(self, query):
        text, rev = configedit.read(self.config_path)
        raw = tomllib.loads(text)
        filers = list(raw.get("filers", {}))
        rules = list(enumerate(raw.get("match", []), 1))
        q = (query.get("q") or [""])[0].strip()
        want = (query.get("filer") or [""])[0]
        shown = [(n, m) for n, m in rules
                 if (not q or q.lower() in f"{m.get('sender', '')}\n{m.get('subject', '')}".lower())
                 and (not want or m.get("filer") == want)]
        pages = max(1, -(-len(shown) // RULES_PER_PAGE))
        try:
            pg = min(max(1, int((query.get("page") or ["1"])[0])), pages)
        except ValueError:
            pg = 1
        back = "/config/rules?" + urlencode({k: v for k, v in (("q", q), ("filer", want), ("page", pg)) if v})
        rows = []
        for n, m in shown[(pg - 1) * RULES_PER_PAGE:pg * RULES_PER_PAGE]:
            fid = f"r{n}"
            rows.append(f"""<tr><td class="tight"><input type="number" name="position" value="{n}" min="1" max="{len(rules)}"
 form="{fid}" aria-label="position"></td>
<td><input class="cell" type="text" name="sender" value="{h(m.get('sender', ''))}" form="{fid}" aria-label="sender"></td>
<td><input class="cell" type="text" name="subject" value="{h(m.get('subject', ''))}" form="{fid}" aria-label="subject"></td>
<td class="tight">{self._filer_select(filers, m.get('filer'), fid)}</td>
<td class="tight"><form id="{fid}" method="post" action="/config">{self._hidden(rev=rev, n=n, back=back)}
<button name="op" value="update-rule">Save</button> <button name="op" value="preview-rule">Preview</button>
<button name="op" value="delete-rule" class="danger">Delete</button></form></td></tr>""")
        nav = ""
        if pages > 1:
            links = " ".join(
                f"<b>{p}</b>" if p == pg else
                f'<a href="/config/rules?{h(urlencode({k: v for k, v in (("q", q), ("filer", want), ("page", p)) if v}))}">{p}</a>'
                for p in range(1, pages + 1))
            nav = f'<p class="row">Page {links}</p>'
        prefill = {k: (query.get(k) or [""])[0] for k in ("sender", "subject")}
        filter_opts = "".join(f'<option value="{h(n)}"{" selected" if n == want else ""}>{h(n)}</option>' for n in filers)
        body = f"""{self._config_hint()}
<p class="hint">Rules are checked in order and the first match wins. Sender and subject match anywhere in the From
header / Subject, ignoring case; a rule with both needs both. Change the number to move a rule.
<b>Preview</b> shows what a rule would file right now, without saving.</p>
<h2>Add a rule</h2>
<form method="post" action="/config" class="row">{self._hidden(rev=rev, back=back)}
<input type="text" name="sender" value="{h(prefill['sender'])}" placeholder="sender, e.g. news@shop.com or @shop.com" aria-label="sender">
<input type="text" name="subject" value="{h(prefill['subject'])}" placeholder="subject (optional)" aria-label="subject" style="min-width:180px">
{self._filer_select(filers, None)}
<input type="number" name="position" min="1" max="{len(rules) + 1}" placeholder="last" aria-label="position">
<button name="op" value="preview-rule">Preview</button>
<button name="op" value="add-rule" class="primary">Add rule</button></form>
<h2>Rules · {len(shown)}{f" of {len(rules)}" if len(shown) != len(rules) else ""}</h2>
<form method="get" action="/config/rules" class="row"><input type="text" name="q" value="{h(q)}" placeholder="search sender or subject"
 aria-label="search"><select name="filer" aria-label="filer"><option value="">any filer</option>{filter_opts}</select>
<button>Filter</button>{' <a href="/config/rules">clear</a>' if q or want else ''}</form>
{nav}<table><tr><th>#</th><th>Sender</th><th>Subject</th><th>Filer</th><th></th></tr>{"".join(rows)}</table>{nav}"""
        return self.page("Rules", body, tab="config", query=query)

    def get_config_raw(self, query, text=None, error=None):
        current, rev = configedit.read(self.config_path)
        if text is None:
            text = current
        err = f'<div class="flash bad">{h(error)}</div>' if error else ""
        rows = []
        for b in configedit.backups(self.config_path)[:10]:
            rows.append(f"""<tr><td>{h(b.name)}</td><td class="nowrap">{h(ago(b.stat().st_mtime))}</td><td class="tight">
<form method="post" action="/config">{self._hidden(rev=rev, backup=b.name, back="/config/raw")}
<button name="op" value="restore-preview">Compare and restore…</button></form></td></tr>""")
        backups = f"<table>{''.join(rows)}</table>" if rows else "<p class='muted'>None yet.</p>"
        body = f"""{self._config_hint()}{err}
<form method="post" action="/config">{self._hidden(rev=rev, back="/config/raw")}
<textarea name="text" rows="32" spellcheck="false" aria-label="config.toml">{h(text)}</textarea>
<div class="row"><button name="op" value="raw-save" class="primary">Check and save</button>
<a href="/config/raw">Discard changes</a></div></form>
<h2>Backups</h2><p class="hint">The {configedit.KEEP_BACKUPS} most recent versions before a dashboard save, newest first.</p>{backups}"""
        return self.page("Raw config.toml", body, tab="config", query=query)

    def _rule_preview(self, raw, sender, subject, position):
        """What a rule at `position` among the shared rules would file now, per account."""
        rule = Match(0, "", sender.strip(), subject.strip())
        parts = []
        for cfg in self.accounts():
            earlier = [m for m in cfg.matches if m.scope] + [m for m in cfg.matches if not m.scope][:position - 1]
            with self.open(cfg) as idx:
                rows = [r for f in cfg.rules_source_folders for r in idx.live(f) if rule_matches(rule, r)]
            taken = [(r, next((m for m in earlier if rule_matches(m, r)), None)) for r in rows]
            free = [r for r, m in taken if m is None]
            claimed = Counter(m.label() for _, m in taken if m is not None)
            sample = "".join(f"<tr><td class='nowrap'>{h(day(r['date_ts']))}</td><td>{h(r['from_raw'])}</td>"
                             f"<td>{h(r['subject'])}</td></tr>" for r in free[:15])
            more = f"<p class='muted'>…and {len(free) - 15} more.</p>" if len(free) > 15 else ""
            claimed_html = "".join(f"<li>{n} by {h(label)}</li>" for label, n in claimed.most_common(10))
            parts.append(f"""<div class="card"><h3>{h(cfg.name or cfg.account.email)}</h3>
<p><b>{len(free)}</b> message(s) in {h(", ".join(cfg.rules_source_folders))} would be filed by this rule.</p>
{f"<p class='hint'>{len(taken) - len(free)} more match but an earlier rule files them first:</p><ul>{claimed_html}</ul>" if claimed else ""}
{f"<table>{sample}</table>{more}" if sample else ""}</div>""")
        return "".join(parts)

    def post_config(self, form):
        def val(k):
            return (form.get(k) or [""])[0]

        op, rev, back = val("op"), val("rev"), val("back")
        if not CONFIG_BACK.match(back):
            back = "/config"
        path = self.config_path
        try:
            text, _ = configedit.read(path)
            raw = tomllib.loads(text)
            n_rules = len(raw.get("match", []))

            def number(k, default=None):
                v = val(k).strip()
                if not v:
                    return default
                if not v.isdigit():
                    raise configedit.EditError(f"{k} must be a number")
                return int(v)

            if op == "preview-rule":
                n = number("n")
                pos = n or number("position", n_rules + 1)
                if not (val("sender").strip() or val("subject").strip()):
                    raise configedit.EditError("a rule needs a sender or a subject")
                again = (self._hidden(rev=rev, back=back, sender=val("sender"), subject=val("subject"),
                                      filer=val("filer"), position=val("position"), **({"n": n} if n else {})))
                what = f"rule #{n}" if n else "the new rule"
                button = "update-rule" if n else "add-rule"
                body = f"""<p>{h(what)}: sender <code>{h(val('sender')) or '–'}</code>, subject <code>{h(val('subject')) or '–'}</code>
→ <b>{h(val('filer'))}</b>{f" at position {pos}" if not n else ""}. Nothing is saved yet.</p>
<div class="cards">{self._rule_preview(raw, val("sender"), val("subject"), pos)}</div>
<form method="post" action="/config" class="row">{again}<button name="op" value="{button}" class="primary">Save {h(what)}</button>
<a href="{h(back)}">Back</a></form>"""
                return self.page("Rule preview", body, tab="config")
            if op == "restore-preview":
                name = val("backup")
                match = [b for b in configedit.backups(path) if b.name == name]
                if not match:
                    raise configedit.EditError("no such backup")
                old = match[0].read_text()
                diff = "".join(difflib.unified_diff(text.splitlines(True), old.splitlines(True), "current", name, n=2))
                body = f"""<p>Changes restoring <code>{h(name)}</code> would make (the current file is backed up first):</p>
<pre>{h(diff) or "(identical)"}</pre><form method="post" action="/config" class="row">
{self._hidden(rev=rev, backup=name, back="/config/raw")}<button name="op" value="restore" class="primary">Restore it</button>
<a href="/config/raw">Back</a></form>"""
                return self.page("Restore backup", body, tab="config")

            if op == "add-rule":
                new = configedit.add_rule(text, val("sender"), val("subject"), val("filer"), number("position"))
                msg = f"Added rule #{number('position') or n_rules + 1}."
            elif op == "update-rule":
                n = number("n")
                new = configedit.update_rule(text, n, val("sender"), val("subject"), val("filer"))
                to = number("position", n)
                if to != n:
                    new = configedit.move_rule(new, n, min(max(1, to), n_rules))
                msg = f"Saved rule #{n}" + (f", now #{min(max(1, to), n_rules)}." if to != n else ".")
            elif op == "delete-rule":
                n = number("n")
                new = configedit.delete_rule(text, n)
                m = raw["match"][n - 1] if n and 0 < n <= n_rules else {}
                msg = f"Deleted rule #{n} ({m.get('sender') or m.get('subject')} → {m.get('filer')}); later rules moved up one."
            elif op == "add-filer":
                new = configedit.add_filer(text, val("name"), val("folder"), val("keep") or "all")
                msg = f"Added filer {val('name').strip()}."
            elif op == "update-filer":
                new = configedit.update_filer(text, val("name"), val("folder"), val("keep"))
                msg = f"Saved filer {val('name')}."
            elif op == "delete-filer":
                new = configedit.delete_filer(text, val("name"))
                msg = f"Deleted filer {val('name')}."
            elif op == "set-allow":
                new = configedit.set_allow(text, val("allow").splitlines())
                msg = "Saved allowed destinations."
            elif op == "raw-save":
                new = val("text").replace("\r\n", "\n")
                try:
                    configedit.save(path, new, rev)
                except (ConfigError, tomllib.TOMLDecodeError, configedit.EditError) as e:
                    return self.get_config_raw({}, text=new, error=f"Not saved: {e}")
                return redirect("/config/raw", "Saved." if new != text else "No changes.")
            elif op == "restore":
                match = [b for b in configedit.backups(path) if b.name == val("backup")]
                if not match:
                    raise configedit.EditError("no such backup")
                new = match[0].read_text()
                msg = f"Restored {val('backup')}."
            else:
                return redirect(back, "Unknown action.", bad=True)
            configedit.save(path, new, rev)
        except (configedit.EditError, ConfigError, tomllib.TOMLDecodeError) as e:
            return redirect(back, f"Not saved: {e}", bad=True)
        return redirect(back, msg)

    # --- actions ----------------------------------------------------------------------------

    OPS = {
        "pull": ("Pull mail", "Run mbsync and update the index."),
        "plan": ("Make a plan (rules + AI)", "Rules file what they can; Claude proposes moves for the rest. Moves nothing."),
        "plan-rules": ("Make a plan (rules only)", "No AI, no cost. Moves nothing."),
        "apply": ("Preview apply", "Shows what the latest plan would move, then asks."),
        "suggest": ("Suggest rules", "Claude proposes [[match]] rules for frequent unmatched senders. Changes nothing."),
    }

    def get_actions(self, cfg, query):
        base = f"/a/{quote(self.slug(cfg))}/actions"
        rows = "".join(f"""<tr><td><form method="post" action="{base}"><button name="op" value="{op}"
{' class="primary"' if op == "pull" else ""}>{h(label)}</button></form></td><td>{h(desc)}</td></tr>"""
                       for op, (label, desc) in self.OPS.items())
        body = (f"<table>{rows}</table><p class='hint'>Purge stays on the command line: "
                f"<code>imapsanity{' --account ' + h(cfg.name) if cfg.name else ''} purge --older-than 30</code>. "
                f"It only deletes messages you confirmed as junk in Quarantine"
                + (f" (keep-last-N trims count as confirmed; cycle already deletes them after "
                   f"{cfg.safety.purge_rule_trims_days:g} day(s))" if cfg.safety.purge_rule_trims_days else "")
                + ".</p>")
        return self.page("Actions", body, cfg, "actions", query)

    def post_actions(self, cfg, form):
        base = f"/a/{quote(self.slug(cfg))}"
        op = (form.get("op") or [""])[0]
        confirm = ""
        with self.open(cfg, lock=True) as idx:
            if op == "pull":
                rc, text = self.capture(lambda: cli.cmd_sync(cfg, idx, argparse.Namespace(direction="pull", execute=True)))
            elif op in ("plan", "plan-rules"):
                rc, text = self.capture(lambda: cli.cmd_plan(cfg, idx, argparse.Namespace(no_ai=op == "plan-rules")))
                confirm = f'<p><a href="{base}/review">Review AI proposals →</a></p>'
            elif op == "suggest":
                rc, text = self.capture(lambda: cli.cmd_suggest_rules(cfg, idx, argparse.Namespace(min_count=3)))
            elif op in ("apply", "apply-execute"):
                name = (form.get("plan") or [""])[0]
                if op == "apply":
                    rc, text = self.capture(lambda: apply.apply_plan(cfg, idx, plan.resolve(cfg), False))
                    if rc == 0 and "dry run" in text:
                        name = plan.resolve(cfg).name
                        confirm = f"""<form method="post" action="{base}/actions"><input type="hidden" name="op" value="apply-execute">
<input type="hidden" name="plan" value="{h(name)}"><button class="primary">Apply for real</button></form>"""
                elif not PLAN_NAME.match(name):
                    return redirect(f"{base}/actions", "Bad request.", bad=True)
                else:
                    rc, text = self.capture(lambda: apply.apply_plan(cfg, idx, plan.plans_dir(cfg) / name, True))
            else:
                return redirect(f"{base}/actions", "Unknown action.", bad=True)
        title = {"apply-execute": "Apply"}.get(op) or self.OPS[op][0]
        return self._output(cfg, title, rc, text, confirm, "actions")

    def _output(self, cfg, title, rc, text, extra, tab):
        status = '<p class="ok">Done.</p>' if not rc else f'<p class="bad">Finished with exit code {h(rc)}.</p>'
        body = f"{status}<pre>{h(text.strip()) or '(no output)'}</pre>{extra}"
        return self.page(title, body, cfg, tab)


def make_handler(app):
    allowed_hosts = {f"127.0.0.1:{app.port}", f"localhost:{app.port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "imapsanity"
        sys_version = ""

        def log_message(self, fmt, *args):
            sys.stderr.write(f"{self.log_date_time_string()} {fmt % args}\n")

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def _send(self, resp, extra_headers=()):
            body = resp.body.encode()
            self.send_response(resp.status)
            if resp.location:
                self.send_header("Location", resp.location)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "same-origin")   # no-referrer makes form POSTs send "Origin: null"
            self.send_header("Cache-Control", "no-store")
            for k, v in extra_headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _authed(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == app.cookie and hmac.compare_digest(v, app.token):
                    return True
            return False

        def _same_origin(self):
            # Sec-Fetch-Site is set by the browser and can't be forged by a page, so it decides when
            # present. Origin is the fallback for browsers without it; a "null" Origin (sent for
            # privacy, e.g. under some referrer policies) proves nothing, so it's refused there.
            site = self.headers.get("Sec-Fetch-Site")
            if site is not None:
                return site in ("same-origin", "none")
            origin = self.headers.get("Origin")
            return origin is None or origin == f"http://{self.headers.get('Host')}"

        def _handle(self, method):
            if self.headers.get("Host") not in allowed_hosts:
                return self._send(Response("bad host", 400))
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            if url.path == "/login" and method == "GET":
                if not hmac.compare_digest((query.get("token") or [""])[0], app.token):
                    return self._send(Response("bad token", 403))
                cookie = f"{app.cookie}={app.token}; HttpOnly; SameSite=Strict; Path=/"
                return self._send(Response(status=303, location="/"), [("Set-Cookie", cookie)])
            if not self._authed():
                return self._send(Response("Not signed in: open the link that <code>imapsanity serve</code> printed.", 403))
            form = {}
            if method == "POST":
                if not self._same_origin():
                    return self._send(Response("cross-site request refused", 403))
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY:
                    return self._send(Response("too large", 413))
                form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
            try:
                resp = app.route(method, url.path, query, form)
            except ConfigError as e:
                resp = Response(f"<p>config error: {h(e)}</p>", 500)
            except Exception:
                traceback.print_exc()
                resp = Response(f"<pre>{h(traceback.format_exc())}</pre>", 500)
            self._send(resp)

    return Handler


def serve(config_path, port=8765, open_browser=True):
    try:
        load_all(config_path)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    app = App(config_path, port)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    server.daemon_threads = True
    url = f"http://127.0.0.1:{port}/login?token={app.token}"
    print(f"IMAPSanity dashboard: {url}\n(local only; this link is the password. Ctrl-C to stop.)", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
    return 0
