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

## Everyday use
```
bin/imapsanity sync pull --execute     # mbsync + index
bin/imapsanity plan                    # rules + AI proposals
bin/imapsanity review                  # approve / reject AI proposals
bin/imapsanity apply                   # dry run
bin/imapsanity apply --execute
bin/imapsanity runs                    # journaled runs
bin/imapsanity undo <run> --execute
bin/imapsanity suggest-rules           # Claude proposes new [[match]] rules; you paste the ones you like
bin/imapsanity purge --older-than 30 --execute
```

Unattended (cron), rules only, never AI:
```
*/15 * * * * $HOME/DEV/IMAPSanity/bin/imapsanity cycle >> $HOME/.local/state/imapsanity/cron.log 2>&1
```

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
