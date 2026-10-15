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
run lock, so a launchd `cycle` and the dashboard never move mail at the same time.
"""

import argparse
import base64
import contextlib
import hashlib
import hmac
import html
import io
import re
import secrets
import sys
import time
import traceback
import webbrowser
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from . import apply, cli, exceptions, journal, plan, quarantine
from .config import ConfigError, load_all
from .index import Index
from .message import read_snippet

MAX_BODY = 1 << 20
PLAN_NAME = re.compile(r"^plan-[0-9-]+\.json$")
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
input[type=text] { font:inherit; padding:6px 8px; border-radius:7px; border:1px solid var(--line);
  background:var(--panel); color:var(--text); min-width:260px; }
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
        path += "?" + urlencode({"msg": msg, **({"bad": "1"} if bad else {})})
    return Response(status=303, location=path)


class App:
    def __init__(self, config_path, port, token=None):
        self.config_path = config_path
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
        if cfg is not None:
            base = f"/a/{quote(self.slug(cfg))}"
            for key, label in (("quarantine", "Quarantine"), ("review", "AI review"), ("runs", "Runs"),
                               ("exceptions", "Exceptions"), ("actions", "Actions")):
                nav.append(f'<a href="{base}/{key}" class="{"on" if tab == key else ""}">{label}</a>')
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

        parts = [f'<p class="hint">{len(ours)} message(s) imapsanity quarantined. Purge only deletes the ones you '
                 f'confirm as junk here. <b>Rescue</b> moves a message back where it came from and keeps it from '
                 f'being quarantined again; <b>Rescue + keep sender</b> does that for everything from the sender.</p>']
        if not todo:
            parts.append('<p class="ok">Nothing waiting for review.</p>')
        for tier in ("careful", "glance", "rules"):
            gs = [g for g in todo if g["tier"] == tier]
            if not gs:
                continue
            title, hint = TIER_TITLES[tier]
            n = sum(len(g["items"]) for g in gs)
            blocks = "".join(self._qgroup(base, g, tier) for g in gs)
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
            blocks = "".join(self._qgroup(base, g, "done") for g in done)
            parts.append(f"<h2>Confirmed junk · {n}</h2><p class='hint'>These are what <code>purge</code> deletes once "
                         f"they're old enough.</p><details><summary>Show</summary>{blocks}</details>")
        if manual:
            rows = "".join(f"<tr><td class='nowrap'>{h(day(i['date_ts']))}</td><td>{h(i['from'])}</td>"
                           f"<td>{h(i['subject'])}</td></tr>" for i in manual)
            parts.append(f"<h2>Put here by hand · {len(manual)}</h2><p class='hint'>Not moved by imapsanity, so never "
                         f"purged. Move them out with your mail client.</p><details><summary>Show</summary>"
                         f"<table>{rows}</table></details>")
        return self.page("Quarantine", "".join(parts), cfg, "quarantine", query)

    def _qgroup(self, base, g, tier):
        checked = "" if tier == "careful" else " checked"
        rows = []
        for i in g["items"]:
            snippet = ""
            if tier == "careful":
                snippet = f'<div class="snippet">{h(read_snippet(i["path"], 240))}</div>'
            rows.append(f"""<tr><td><input type="checkbox" name="msgid" value="{h(i['msgid'])}"{checked}
 aria-label="select"></td><td class="nowrap">{h(day(i['date_ts']))}</td>
<td>{h(i['subject']) or '<span class="muted">(no subject)</span>'}{snippet}</td>
<td class="hide-sm">{h(i['why'])}<div class="muted">from {h(i['origin'])} · {h(ago(i['quarantined_ts']))}</div></td></tr>""")
        chips = "".join(f'<span class="chip{" warn" if tier == "careful" else ""}">{h(r)}</span>' for r in g["reasons"])
        if tier == "done":
            buttons = '<button name="action" value="unjunk">Not sure any more: back to review</button>'
        else:
            buttons = ('<button name="action" value="junk" class="primary">Confirm junk</button>'
                       '<button name="action" value="rescue">Rescue</button>'
                       '<button name="action" value="keep-sender">Rescue + keep sender</button>')
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
            if action in ("rescue", "keep-sender"):
                tally = Counter()
                self.capture(lambda: tally.update(
                    quarantine.rescue(cfg, idx, msgids, keep_sender=action == "keep-sender")))
                moved = tally.get("moved", 0)
                problems = {k: v for k, v in tally.items() if k != "moved"}
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
                f"It only deletes messages you confirmed as junk in Quarantine.</p>")
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
