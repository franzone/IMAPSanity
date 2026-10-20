"""Load and validate config.toml (stdlib tomllib, no third-party dependencies)."""

import copy
import os
import re
import tomllib
from dataclasses import MISSING, dataclass, field, fields
from pathlib import Path

from . import exceptions

REPO_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = REPO_DIR / "config.toml"


class ConfigError(Exception):
    pass


@dataclass
class Account:
    email: str
    imap_host: str
    imap_port: int = 993
    keychain_service: str = ""
    imap_prefix: str = "INBOX."
    imap_delimiter: str = "."


@dataclass
class Safety:
    quarantine: str = "Quarantine"
    max_moves_per_run: int = 200
    max_quarantine_per_run: int = 100
    max_fraction_per_folder: float = 0.25
    min_folder_size_for_fraction: int = 40
    max_plan_age_hours: float = 24
    cycle_interval_minutes: float = 15   # launchd StartInterval; a longer gap scales cycle's limits
    max_backlog_scale: float = 5         # cap on that scale
    max_backlog_fraction: float = 0.5    # cap on max_fraction_per_folder after scaling
    skip_flagged: bool = True
    protected_folders: list = field(default_factory=lambda: [
        "Sent", "Sent Messages", "Drafts", "Templates", "Trash", "Deleted Messages"])
    protected_senders: list = field(default_factory=list)
    protect_filers: list = field(default_factory=lambda: ["VIP"])
    # >0: extras trimmed by keep-last-N rules (with no sign they're personal) count as confirmed
    # junk, and cycle permanently deletes them this many days after quarantining them. 0: you review them.
    purge_rule_trims_days: float = 0


@dataclass
class AI:
    enabled: bool = False
    command: str = "claude"
    model: str = "sonnet"
    folders: list = field(default_factory=lambda: ["INBOX"])
    destinations: dict = field(default_factory=dict)  # folder -> description shown to the model
    instructions: str = ""
    batch_size: int = 25
    max_messages: int = 100
    min_confidence: float = 0.7
    max_budget_usd: float = 1.0
    timeout_seconds: int = 300


@dataclass
class Auto:
    """Unattended AI filing in `cycle`. "shadow": classify and log, move nothing.
    "live": the same, then move what TypeSafe's Jev picks (Claude stays a shadow for comparison)."""
    mode: str = "off"                 # "off" | "shadow" | "live"
    destinations: list = field(default_factory=list)  # subset of [ai.destinations]; never the quarantine
    min_confidence: float = 0.85      # bar for Claude's self-reported confidence
    max_classify_per_run: int = 30    # per classifier, per cycle (cost and time)
    max_moves_per_run: int = 50       # live: Jev moves at most this many per cycle, oldest first
    settle_days: float = 2            # shadow-report: younger messages count as "too new to judge"


@dataclass
class TypeSafe:
    """Second classifier (TypeSafe Jev): shadow mode and its report, and the mover in live mode."""
    enabled: bool = False
    model: str = "jev-latest"
    url: str = "https://api.typesafe.ai/v1/systemone"
    keychain_service: str = ""        # security find-generic-password -a <email> -s <service> -w
    keychain_account: str = ""        # Keychain account for the key; default [account].email
    min_confidence: float = 0.8
    max_personal: float = 0.2         # veto: probability a real person wrote it personally
    max_important: float = 0.2        # veto: probability it's a bill/security/official notice
    workers: int = 8
    timeout_seconds: int = 30


@dataclass
class Filer:
    name: str
    folder: str
    keep: int | None  # None = keep all


@dataclass
class Match:
    index: int
    filer: str
    sender: str = ""
    subject: str = ""
    scope: str = ""   # account name for an [[account.match]] rule; "" for a shared one

    def label(self):
        parts = [f"{self.scope}:match#{self.index}" if self.scope else f"match#{self.index}"]
        if self.sender:
            parts.append(f"sender~{self.sender}")
        if self.subject:
            parts.append(f"subject~{self.subject}")
        return " ".join(parts) + f" -> {self.filer}"


@dataclass
class Config:
    path: Path
    name: str   # [[account]] name; "" for a single [account] table
    account: Account
    maildir: Path
    state_dir: Path
    pull_commands: list
    push_command: list
    maildir_folders: list
    allow_destinations: list
    rules_source_folders: list
    index_exclude: list
    safety: Safety
    ai: AI
    auto: Auto
    typesafe: TypeSafe
    filers: dict
    matches: list
    exceptions: dict = field(default_factory=exceptions.empty)   # dashboard keeps, from <state>/exceptions.json

    def backend_for(self, folder):
        return "maildir" if folder in self.maildir_folders else "imap"

    def is_protected_sender(self, from_header):
        """Substring match, same semantics as rule senders (and IMAP SEARCH FROM)."""
        text = (from_header or "").lower()
        return any(p and p.lower() in text for p in self.protected_patterns)

    @property
    def protected_patterns(self):
        pats = list(self.safety.protected_senders)
        protect = set(self.safety.protect_filers)
        pats += [m.sender for m in self.matches if m.filer in protect and m.sender]
        pats += list(self.exceptions["senders"])
        return pats

    @property
    def kept_msgids(self):
        return set(self.exceptions["messages"])


def _section(raw, name, cls):
    data = raw.get(name, {})
    known = set(cls.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"[{name}] unknown keys: {', '.join(sorted(unknown))}")
    missing = [f.name for f in fields(cls)
               if f.default is MISSING and f.default_factory is MISSING and f.name not in data]
    if missing:
        raise ConfigError(f"[{name}] missing keys: {', '.join(missing)}")
    return cls(**data)


# Keys an [[account]] entry may have besides the Account fields and the per-account sections.
ACCOUNT_PATH_KEYS = {"name", "maildir", "state", "pull", "push", "maildir_folders"}
# Shared sections an [[account]] entry may override key by key.
ACCOUNT_SECTIONS = {"safety", "ai", "auto", "typesafe", "rules", "index"}
ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
# With [[account]] entries these name one account's mail, so they belong in each entry.
PER_ACCOUNT_ONLY = [("paths", "maildir"), ("mbsync", "pull"), ("mbsync", "push"), ("backends", "maildir_folders")]


def config_path(path=None):
    """The config file: `path`, else $IMAPSANITY_CONFIG, else config.toml in the checkout."""
    return Path(path or os.environ.get("IMAPSANITY_CONFIG") or DEFAULT_CONFIG)


def load_all(path=None):
    """One Config per account. A single [account] table gives one Config named "" that
    behaves exactly as before; [[account]] entries are each merged over the shared sections."""
    path = config_path(path)
    if not path.exists():
        raise ConfigError(f"config not found: {path} (copy config.sample.toml or run tools/migrate_yaml.py)")
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    accounts = raw.get("account")
    if isinstance(accounts, dict):
        return [_build(path, raw, "")]
    if not accounts:
        raise ConfigError("an [account] section or [[account]] entries are required")
    for section, key in PER_ACCOUNT_ONLY:
        if raw.get(section, {}).get(key):
            raise ConfigError(f"[{section}].{key} can't be shared between [[account]] entries; "
                              f"set {key} in each entry instead")
    cfgs, seen = [], set()
    for entry in accounts:
        name = entry.get("name", "")
        if not ACCOUNT_NAME.match(name):
            raise ConfigError(f"[[account]] name {name!r} must be letters, digits, '-' or '_'")
        if name in seen:
            raise ConfigError(f"[[account]] name {name!r} is used twice")
        seen.add(name)
        try:
            cfgs.append(_build(path, _merge_account(raw, entry), name))
        except ConfigError as e:
            raise ConfigError(f"[[account]] {name}: {e}") from None
    _check_separate(cfgs)
    return cfgs


def _check_separate(cfgs):
    """Accounts must not share (or nest) state or maildir directories, nor pull each other's mail."""
    def overlap(a, b):
        return a == b or a in b.parents or b in a.parents

    for i, a in enumerate(cfgs):
        for cmd in a.pull_commands + [a.push_command]:
            if len(cfgs) > 1 and ("-a" in cmd or "--all" in cmd):
                raise ConfigError(f"[[account]] {a.name}: mbsync {' '.join(cmd[1:])!r} syncs every channel, "
                                  f"including other accounts'; name this account's channel or group")
        for b in cfgs[i + 1:]:
            for what in ("state_dir", "maildir"):
                pa, pb = getattr(a, what).absolute(), getattr(b, what).absolute()
                if overlap(pa, pb):
                    raise ConfigError(f"[[account]] {a.name} and {b.name}: {what} {pa} and {pb} overlap")
            shared = [c for c in a.pull_commands if c in b.pull_commands]
            if shared or (a.push_command and a.push_command == b.push_command):
                raise ConfigError(f"[[account]] {a.name} and {b.name} run the same mbsync command; "
                                  f"give each account its own channel or group")


def pick(cfgs, name):
    for cfg in cfgs:
        if cfg.name == name:
            return cfg
    raise ConfigError(f"no account {name!r} (have: {', '.join(c.name or '(unnamed)' for c in cfgs)})")


def load(path=None, account=None):
    """The Config for one account: the named one, or the only one."""
    cfgs = load_all(path)
    if account:
        return pick(cfgs, account)
    if len(cfgs) > 1:
        raise ConfigError(f"several accounts configured; pick one with --account "
                          f"({', '.join(c.name for c in cfgs)})")
    return cfgs[0]


def _merge_account(raw, entry):
    """Rewrite one [[account]] entry plus the shared sections into the single-account shape."""
    name = entry["name"]
    known = set(Account.__dataclass_fields__) | ACCOUNT_PATH_KEYS | ACCOUNT_SECTIONS | {
        "destinations", "filers", "match"}
    unknown = set(entry) - known
    if unknown:
        raise ConfigError(f"unknown keys: {', '.join(sorted(unknown))}")
    if not entry.get("maildir"):
        raise ConfigError("maildir is required")
    unknown = set(entry.get("destinations", {})) - {"allow"}
    if unknown:
        raise ConfigError(f"[account.destinations] unknown keys: {', '.join(sorted(unknown))}")

    merged = {k: copy.deepcopy(v) for k, v in raw.items() if k not in ("account", "paths", "mbsync", "backends")}
    merged["account"] = {k: v for k, v in entry.items() if k in Account.__dataclass_fields__}
    shared_state = raw.get("paths", {}).get("state", "~/.local/state/imapsanity")
    merged["paths"] = {"maildir": entry["maildir"], "state": entry.get("state") or f"{shared_state}/{name}"}
    merged["mbsync"] = {"pull": entry.get("pull", []), "push": entry.get("push", [])}
    merged["backends"] = {"maildir_folders": entry.get("maildir_folders", [])}
    for section in ACCOUNT_SECTIONS:
        merged[section] = {**merged.get(section, {}), **entry.get(section, {})}
    allow = merged.get("destinations", {}).get("allow", [])
    extra = [d for d in entry.get("destinations", {}).get("allow", []) if d not in allow]
    merged["destinations"] = {"allow": allow + extra}
    merged["filers"] = {**merged.get("filers", {}), **entry.get("filers", {})}
    # Account rules first: first match wins, so they beat the shared ones.
    merged["match"] = ([dict(m, _scope=name) for m in entry.get("match", [])]
                       + merged.get("match", []))
    return merged


def _build(path, raw, name):
    if "account" not in raw:
        raise ConfigError("[account] section is required")
    account = _section(raw, "account", Account)
    safety = _section(raw, "safety", Safety)
    ai = _section(raw, "ai", AI)
    auto = _section(raw, "auto", Auto)
    typesafe = _section(raw, "typesafe", TypeSafe)

    paths = raw.get("paths", {})
    mbsync = raw.get("mbsync", {})

    filers = {}
    for fname, f in raw.get("filers", {}).items():
        keep = f.get("keep", "all")
        if keep == "all":
            keep = None
        elif not isinstance(keep, int) or keep < 0:
            raise ConfigError(f"[filers.{fname}] keep must be \"all\" or a non-negative integer")
        if not f.get("folder"):
            raise ConfigError(f"[filers.{fname}] folder is required")
        filers[fname] = Filer(fname, f["folder"], keep)

    matches = []
    counters = {}
    for m in raw.get("match", []):
        scope = m.get("_scope", "")
        counters[scope] = i = counters.get(scope, 0) + 1
        mm = Match(i, m.get("filer", ""), (m.get("sender") or "").strip(), (m.get("subject") or "").strip(), scope)
        where = f"{scope}: match #{i}" if scope else f"match #{i}"
        if mm.filer not in filers:
            raise ConfigError(f"{where}: unknown filer {mm.filer!r}")
        if not mm.sender and not mm.subject:
            # v1 fell back to matching ALL messages here; v2 refuses.
            raise ConfigError(f"{where}: needs a sender or a subject")
        matches.append(mm)

    cfg = Config(
        path=path,
        name=name,
        account=account,
        maildir=Path(os.path.expanduser(paths.get("maildir", "~/Mail"))),
        state_dir=Path(os.path.expanduser(paths.get("state", "~/.local/state/imapsanity"))),
        pull_commands=mbsync.get("pull", []),
        push_command=mbsync.get("push", []),
        maildir_folders=raw.get("backends", {}).get("maildir_folders", []),
        allow_destinations=list(raw.get("destinations", {}).get("allow", [])),
        rules_source_folders=raw.get("rules", {}).get("source_folders", ["INBOX"]),
        index_exclude=raw.get("index", {}).get("exclude", []),
        safety=safety,
        ai=ai,
        auto=auto,
        typesafe=typesafe,
        filers=filers,
        matches=matches,
    )
    cfg.exceptions = exceptions.load(cfg.state_dir)
    _validate(cfg)
    return cfg


def _validate(cfg):
    # Filer folders and the quarantine are always valid destinations.
    for f in cfg.filers.values():
        if f.folder not in cfg.allow_destinations:
            cfg.allow_destinations.append(f.folder)
    if cfg.safety.quarantine not in cfg.allow_destinations:
        cfg.allow_destinations.append(cfg.safety.quarantine)

    for dest in cfg.ai.destinations:
        if dest not in cfg.allow_destinations:
            raise ConfigError(f"[ai.destinations] {dest!r} is not in [destinations].allow")
    for dest in cfg.allow_destinations:
        if dest in cfg.safety.protected_folders:
            raise ConfigError(f"{dest!r} is both a protected folder and an allowed destination")
        if not dest.isascii():
            raise ConfigError(f"{dest!r}: non-ASCII folder names are not supported")
    if cfg.auto.mode not in ("off", "shadow", "live"):
        raise ConfigError(f"[auto].mode must be \"off\", \"shadow\" or \"live\", not {cfg.auto.mode!r}")
    if cfg.auto.mode in ("shadow", "live") and not cfg.ai.enabled:
        raise ConfigError(f"[auto].mode = \"{cfg.auto.mode}\" needs [ai].enabled = true")
    if cfg.auto.mode == "live" and not cfg.typesafe.enabled:
        raise ConfigError("[auto].mode = \"live\" needs [typesafe].enabled = true")
    for dest in cfg.auto.destinations:
        if dest == cfg.safety.quarantine:
            raise ConfigError("[auto].destinations may not include the quarantine")
        if dest not in cfg.ai.destinations:
            raise ConfigError(f"[auto].destinations: {dest!r} is not in [ai.destinations]")
    if cfg.push_command and not cfg.maildir_folders:
        raise ConfigError("[mbsync].push is set but [backends].maildir_folders is empty")
    if not 0 < cfg.safety.max_fraction_per_folder <= 1:
        raise ConfigError("[safety].max_fraction_per_folder must be in (0, 1]")
