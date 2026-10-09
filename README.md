# IMAPSanity
Rules-based (and optionally AI-assisted) cleanup for an IMAP mailbox that is mirrored locally with
[mbsync](https://isync.sourceforge.io/). Built so that no rule, script or LLM can quietly delete mail.

Pure Python standard library (3.11+): no notmuch, no afew, no virtualenv, no pip packages.

## How it works

```
mbsync pull ─▶ index ─▶ rules ─┐
                               ├─▶ plan.json ─▶ review ─▶ apply ─▶ journal ─▶ (push)
                 ai (optional) ┘                          guards     undo
```

| Step | What it does |
|---|---|
| `index` | Incremental SQLite index of the local maildir (headers only). Ignores messages mbsync marked trashed (`T`). |
| `plan` | Runs your rules, then (optionally) asks Claude about whatever the rules didn't match. Writes a JSON plan. Changes nothing. |
| `review` | Approve or reject AI proposals, grouped by sender. Rejections are remembered. |
| `apply` | The only command that moves mail. Dry run unless `--execute`. |
| `undo` | Reverses a run from its journal. |
| `purge` | The only command that deletes mail: old quarantined messages, after you type a confirmation. |

### Safety guarantees
* **No deletes.** Keep-last-N moves extras to `Quarantine`. Only `purge --execute` deletes, only messages
  imapsanity itself quarantined, only after N days, only after typing `PURGE <count>`.
* **AI proposes only.** Claude runs headless (`claude -p`) with every tool disabled, no MCP servers and no
  settings, in an empty temp dir. Its answer must match a JSON schema whose destinations are your allow
  list. Every AI proposal starts unapproved. Email content is treated as untrusted (prompt injection can at
  worst produce a proposal you reject).
* **Guards on every apply**, whoever wrote the plan: destination allow list, protected source folders
  (Sent, Drafts…), protected senders (and everyone in the `VIP` filer) can't be quarantined or touched by AI,
  flagged messages are skipped, per-run caps on moves/quarantines/fraction of a folder (exceeding any
  aborts the whole run), plans older than 24h are refused, a plan can be applied once.
* **Exact targeting.** Messages are located on the server by Message-ID; zero or multiple matches are
  skipped. Requires IMAP `MOVE` + `UIDPLUS`; never issues a bare `EXPUNGE`.
* **Journal + undo.** Intent is journaled before every move; `imapsanity undo <run>` reverses a run.

### Two backends
* **IMAP (default):** moves happen on the server with `UID MOVE`; the next mbsync pull mirrors them.
  mbsync stays pull-only for these folders, so a damaged local maildir can never push a deletion.
* **Maildir (`[backends].maildir_folders`):** moves are local file renames (mbsync's `,U=` stripped),
  pushed by `imapsanity sync push`. Before pushing, a circuit breaker verifies that every message that
  left those folders is explained by the journal, and a hardlink snapshot is taken. Source and destination
  must both be maildir folders, and they must be in a two-way mbsync channel that is *not* part of the
  pull group (pull them with `mbsync --pull <channel>`).

## Setup
1. Config: `cp config.sample.toml config.toml` and edit, or migrate v1 rules:
   `/usr/bin/python3 tools/migrate_yaml.py mailboxes.yml jonathan > config.toml` (needs PyYAML, once).
2. Password lives in the macOS Keychain (`[account].keychain_service`, the same item mbsync's `PassCmd`
   uses), or `IMAPSANITY_PASSWORD`.
3. `bin/imapsanity check` and create anything missing, e.g. `bin/imapsanity mkfolder Quarantine`.

## Day-to-day use

### The daily triage (a few minutes)
```
bin/imapsanity sync pull --execute     # 1. fetch new mail (mbsync) and update the index
bin/imapsanity plan                    # 2. rules file what they can; Claude proposes moves for the rest
bin/imapsanity review                  # 3. approve / reject the AI proposals, grouped by sender
bin/imapsanity apply                   # 4. dry run: shows exactly what would move, and anything a guard rejected
bin/imapsanity apply --execute         # 5. do it (prints the run id to use with undo)
```
In `review`, each group shows the destination, sender, up to five subjects and the model's reason:
`a` approves the whole group, `r` rejects it (remembered, never proposed again), `s` skips it for now,
`i` decides message by message, `q` saves and quits. Rule-based moves are pre-approved; `bin/imapsanity show`
lists every action in the latest plan (`--pending` for just the AI proposals awaiting review).

Plans expire after 24 hours and can only be applied once, so if you come back to it later, just re-run `plan`.
AI classifications are cached by Message-ID, so re-planning doesn't re-bill messages already classified
(about $0.20 per 100 new ones with Sonnet).

### Undoing something
```
bin/imapsanity runs                    # recent runs with what happened in each
bin/imapsanity undo <run>              # dry run
bin/imapsanity undo <run> --execute    # moves everything from that run back where it came from
```

### Weekly-ish maintenance
```
bin/imapsanity suggest-rules           # Claude proposes [[match]] rules for frequent unmatched senders
```
Suggestions are written to `~/.local/state/imapsanity/suggested-rules-*.toml` and printed; `config.toml` is never
changed. Paste the ones you agree with. Every rule you add is one less thing for the AI to guess about
(and the unattended `cycle` below only uses rules).

Look through `Quarantine` in any mail client. To rescue something, just move it out yourself. When you're happy:
```
bin/imapsanity purge --older-than 30             # list what would be deleted
bin/imapsanity purge --older-than 30 --execute   # asks you to type "PURGE <count>"
```
Purge only deletes messages imapsanity itself quarantined. Anything you put there by hand is left alone.

### Unattended (launchd)
`cycle` = pull, rules-only plan, apply, pull. AI never moves mail here (see shadow mode below), and it is subject
to the same guards and caps.
Its plans are saved as `cycle-*.json`, so they never replace the manual plan `review`/`apply` pick up.

Use a LaunchAgent, not cron: cron jobs on macOS can't read the login Keychain, so the IMAP password lookup
(and mbsync's `PassCmd`) fails. `~/Library/LaunchAgents/com.franzone.imapsanity.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.franzone.imapsanity</string>
    <key>ProgramArguments</key>
    <array><string>/Users/YOU/DEV/IMAPSanity/bin/imapsanity</string><string>cycle</string></array>
    <key>StartInterval</key><integer>900</integer>
    <key>ProcessType</key><string>Background</string>
    <key>EnvironmentVariables</key>
    <dict><key>PYTHONUNBUFFERED</key><string>1</string></dict>  <!-- keep log lines in order -->
    <key>StandardOutPath</key><string>/Users/YOU/.local/state/imapsanity/cron.log</string>
    <key>StandardErrorPath</key><string>/Users/YOU/.local/state/imapsanity/cron.log</string>
</dict>
</plist>
```
```
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.franzone.imapsanity.plist   # enable
launchctl kickstart gui/$(id -u)/com.franzone.imapsanity                                # run now
launchctl bootout gui/$(id -u)/com.franzone.imapsanity                                  # disable
tail -f ~/.local/state/imapsanity/cron.log                                              # watch
```
(`./go` runs one cycle by hand.)

### Shadow mode (trying out unattended AI)
With `[auto] mode = "shadow"`, every `cycle` also classifies up to `max_classify_per_run` new unmatched
messages with Claude and, if `[typesafe] enabled = true`, with TypeSafe's Jev, then logs what each would
auto-move. **Nothing moves.** Claude's answers land in the same cache `plan` uses, so they aren't billed twice.

TypeSafe asks three questions per message: which folder (a Choice over KEEP + `[ai.destinations]`), whether
a real person wrote it personally, and whether it's a bill/security/official notice. Its bar is confidence
plus both vetoes. Raw probabilities are cached, so changing a threshold re-scores history without new calls.
```
security add-generic-password -a you@example.com -s typesafe-api -w     # store the key (prompts for it)
bin/imapsanity check                                                    # verifies the key
bin/imapsanity typesafe-backfill --execute     # one-off: TypeSafe on everything Claude already classified
bin/imapsanity shadow-report                   # compare both against where your mail actually ended up
```
The report shows, for each classifier, what it would have moved and where those messages are now: in that
folder (you or `review` agreed), elsewhere, still in the inbox (read or unread), deleted, or rejected in
`review`. Then a destination agreement matrix and the messages they disagree on.

### When something stops
* **`ABORT: ... exceeds max_moves_per_run` (or a fraction/quarantine cap):** nothing was moved. Check the dry run;
  if it's legitimate (e.g. the first run after adding many rules), re-run with `--max-moves N`,
  `--max-fraction F` or `--max-quarantine N`.
* **`rejected: ...` lines:** a guard refused that one action (protected sender, folder not in the allow list…);
  the rest still apply. Fix `config.toml` if the rejection is wrong.
* **`not_found` / `ambiguous` after apply:** the message was already moved elsewhere or exists twice on the
  server; it was skipped. Pull and re-plan.
* **mbsync: `Unable to recover from UIDVALIDITY change`:** the provider rebuilt that mailbox and mbsync
  refuses to guess. For a pull-only folder, move the local copy out of the synced tree (e.g.
  `mv ~/Mail/account/INBOX ~/Mail/account-INBOX-stale-$(date +%Y%m%d)`) and pull again; it re-downloads.
* **`circuit breaker tripped` (maildir backend only):** messages vanished locally without a journal entry.
  Nothing was pushed. Find out why before pushing; the last snapshots are in
  `~/.local/state/imapsanity/snapshots/`.
* **`another imapsanity run is in progress`:** a scheduled `cycle` is running; wait a minute.

### Where things live
| Path | What |
|---|---|
| `config.toml` | Your account, rules, safety limits and AI settings (gitignored) |
| `~/.local/state/imapsanity/index.sqlite3` | Index, AI and TypeSafe caches and your review decisions (safe to delete; rebuilt on next run, but AI results are re-billed) |
| `~/.local/state/imapsanity/plans/` | Every plan, as JSON |
| `~/.local/state/imapsanity/journal/` | One JSONL file per apply/undo/purge run |

## Rules
```toml
[filers.OneOfThese]
folder = "IMAPSanity/OneOfThese"   # local maildir name; "INBOX." prefix and "." delimiter on the server
keep = 1                           # or "all"

[[match]]
sender = "@deals.example.com"      # case-insensitive substring of From
subject = ""                       # case-insensitive substring of Subject
filer = "OneOfThese"
```
Messages in `[rules].source_folders` (default `INBOX`) are filed by the first matching rule. For filers with
a numeric `keep`, only the newest N messages per rule are kept and the rest go to the quarantine.

## AI settings
```toml
[ai]
enabled = true
model = "sonnet"
max_messages = 100        # per plan; the newest unclassified messages first
min_confidence = 0.7      # lower-confidence proposals are dropped
instructions = """
Plain-English preferences, e.g. anything from church, family or my bank stays in the inbox.
"""

[ai.destinations]         # the only folders the model may propose (each must also be in [destinations].allow)
"Filtered/Newsletters" = "newsletters, digests and content subscriptions"
"Quarantine" = "obvious junk worth deleting later"
```
The descriptions are shown to the model, so write them the way you'd explain your folders to an assistant.
Set `enabled = false` (or use `plan --no-ai`) to run rules only.

## Tests
```
/opt/homebrew/bin/python3 -m unittest discover -s tests -t .
```

The v1 script is kept in `legacy/`.

## Terms and Conditions
Download and use of any content (files, scripts, images, etc.) from the repository located at https://github.com/franzone/IMAPSanity construes your consent to these **Terms and Conditions**. Use of this script or any related files is at your own risk. The author, Jonathan Franzone, his family, friends or associates, may not be held liable for any damages, imagined or real, caused by your use of this script or related files.

## Author
The author of this script is Jonathan Franzone (that's me!). You can find more information about him at:
* https://franzone.blog
* https://about.franzone.com
* https://www.linkedin.com/in/jonathanfranzone/

## License
[MIT License](LICENSE)
