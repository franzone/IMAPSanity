"""One-time migration: v1 mailboxes.yml -> v2 config.toml.

Needs PyYAML (the only place it is used), e.g. with macOS's system Python:
    /usr/bin/python3 tools/migrate_yaml.py mailboxes.yml jonathan > config.toml
The password is NOT migrated; v2 reads it from the macOS Keychain.
"""

import json
import sys

import yaml

q = json.dumps  # JSON strings are valid TOML basic strings


def imap_to_local(name, prefix="INBOX.", delim="."):
    if name == "INBOX":
        return name
    if name.startswith(prefix):
        name = name[len(prefix):]
    return name.replace(delim, "/")


def main():
    src, account = sys.argv[1], sys.argv[2]
    acct = yaml.safe_load(open(src))[account]
    filers = acct["filers"]
    out = []
    w = out.append

    w(f"""# IMAPSanity v2 config (migrated from {src}). Folder names use the local maildir form
# (e.g. "IMAPSanity/VIP"), mapped to the server as imap_prefix + name with "/" -> delimiter.

[account]
email = {q(acct['email'])}
imap_host = {q(acct['imapHost'])}
imap_port = 993
keychain_service = "imap-password"   # security find-generic-password -a <email> -s <service> -w
imap_prefix = "INBOX."
imap_delimiter = "."

[paths]
maildir = "~/Mail/account"
state = "~/.local/state/imapsanity"

[mbsync]
pull = [["/opt/homebrew/bin/mbsync", "account"]]   # your mbsync channel/group name
push = []   # only for maildir_folders, e.g. ["/opt/homebrew/bin/mbsync", "--push", "account-managed"]

[backends]
# Folders moved by local file renames + `sync push` (must be in a two-way mbsync channel
# that is NOT part of the pull group). Everything else is moved server-side over IMAP.
maildir_folders = []

[rules]
source_folders = ["INBOX"]

[index]
exclude = []

[safety]
quarantine = "Quarantine"
max_moves_per_run = 200
max_quarantine_per_run = 100
max_fraction_per_folder = 0.25
min_folder_size_for_fraction = 40
max_plan_age_hours = 24
skip_flagged = true
protected_folders = ["Sent", "Sent Messages", "Drafts", "Templates", "Trash", "Deleted Messages"]
protected_senders = []
protect_filers = ["VIP"]   # senders matched to these filers are never quarantined or touched by AI

[destinations]
# Filer folders and the quarantine are added automatically.
allow = ["Filtered/Newsletters", "Filtered/Social", "Archive/Coupons"]

[ai]
enabled = true
command = "claude"
model = "sonnet"
folders = ["INBOX"]
batch_size = 25
max_messages = 100
min_confidence = 0.7
max_budget_usd = 1.0
instructions = \"\"\"
Newsletters and marketing I subscribed to can be filed. Anything from church, family,
clients, banks, or government stays in the inbox.
\"\"\"

[ai.destinations]
"Filtered/Newsletters" = "newsletters, digests and content subscriptions"
"Filtered/Social" = "social network notifications"
"Archive/Coupons" = "coupons, sales and promotional offers"
"Quarantine" = "obvious junk worth deleting later (cold sales pitches, spam that got through)"
""")

    for name, f in filers.items():
        keep = '"all"' if f.get("keepAll") else int(f.get("keep") or 0)
        w(f"[filers.{name}]\nfolder = {q(imap_to_local(f['folder']))}\nkeep = {keep}\n")

    skipped = 0
    for m in acct["matches"]:
        sender, subject = (m.get("sender") or "").strip(), (m.get("subject") or "").strip()
        if not sender and not subject:
            skipped += 1
            continue
        w("[[match]]")
        if sender:
            w(f"sender = {q(sender)}")
        if subject:
            w(f"subject = {q(subject)}")
        w(f"filer = {q(m['filer'])}\n")

    print("\n".join(out))
    if skipped:
        print(f"skipped {skipped} match(es) with neither sender nor subject", file=sys.stderr)


if __name__ == "__main__":
    main()
