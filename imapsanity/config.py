"""Load and validate config.toml (stdlib tomllib, no third-party dependencies)."""

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

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
    skip_flagged: bool = True
    protected_folders: list = field(default_factory=lambda: [
        "Sent", "Sent Messages", "Drafts", "Templates", "Trash", "Deleted Messages"])
    protected_senders: list = field(default_factory=list)
    protect_filers: list = field(default_factory=lambda: ["VIP"])


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
    """Unattended AI filing in `cycle`. Only "shadow" exists so far: classify and log, move nothing."""
    mode: str = "off"                 # "off" | "shadow"
    destinations: list = field(default_factory=list)  # subset of [ai.destinations]; never the quarantine
    min_confidence: float = 0.85      # bar for Claude's self-reported confidence
    max_classify_per_run: int = 30    # per classifier, per cycle (cost and time)
    settle_days: float = 2            # shadow-report: younger messages count as "too new to judge"


@dataclass
class TypeSafe:
    """Second classifier (TypeSafe Jev), used only by shadow mode and its report."""
    enabled: bool = False
    model: str = "jev-latest"
    url: str = "https://api.typesafe.ai/v1/systemone"
    keychain_service: str = ""        # security find-generic-password -a <email> -s <service> -w
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

    def label(self):
        parts = [f"match#{self.index}"]
        if self.sender:
            parts.append(f"sender~{self.sender}")
        if self.subject:
            parts.append(f"subject~{self.subject}")
        return " ".join(parts) + f" -> {self.filer}"


@dataclass
class Config:
    path: Path
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
        return pats


def _section(raw, name, cls):
    data = raw.get(name, {})
    known = set(cls.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"[{name}] unknown keys: {', '.join(sorted(unknown))}")
    return cls(**data)


def load(path=None):
    path = Path(path or os.environ.get("IMAPSANITY_CONFIG") or DEFAULT_CONFIG)
    if not path.exists():
        raise ConfigError(f"config not found: {path} (copy config.sample.toml or run tools/migrate_yaml.py)")
    with open(path, "rb") as f:
        raw = tomllib.load(f)

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
    for name, f in raw.get("filers", {}).items():
        keep = f.get("keep", "all")
        if keep == "all":
            keep = None
        elif not isinstance(keep, int) or keep < 0:
            raise ConfigError(f"[filers.{name}] keep must be \"all\" or a non-negative integer")
        if not f.get("folder"):
            raise ConfigError(f"[filers.{name}] folder is required")
        filers[name] = Filer(name, f["folder"], keep)

    matches = []
    for i, m in enumerate(raw.get("match", []), start=1):
        mm = Match(i, m.get("filer", ""), (m.get("sender") or "").strip(), (m.get("subject") or "").strip())
        if mm.filer not in filers:
            raise ConfigError(f"match #{i}: unknown filer {mm.filer!r}")
        if not mm.sender and not mm.subject:
            # v1 fell back to matching ALL messages here; v2 refuses.
            raise ConfigError(f"match #{i}: needs a sender or a subject")
        matches.append(mm)

    cfg = Config(
        path=path,
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
    if cfg.auto.mode not in ("off", "shadow"):
        raise ConfigError(f"[auto].mode must be \"off\" or \"shadow\", not {cfg.auto.mode!r}")
    if cfg.auto.mode == "shadow" and not cfg.ai.enabled:
        raise ConfigError("[auto].mode = \"shadow\" needs [ai].enabled = true")
    for dest in cfg.auto.destinations:
        if dest == cfg.safety.quarantine:
            raise ConfigError("[auto].destinations may not include the quarantine")
        if dest not in cfg.ai.destinations:
            raise ConfigError(f"[auto].destinations: {dest!r} is not in [ai.destinations]")
    if cfg.push_command and not cfg.maildir_folders:
        raise ConfigError("[mbsync].push is set but [backends].maildir_folders is empty")
    if not 0 < cfg.safety.max_fraction_per_folder <= 1:
        raise ConfigError("[safety].max_fraction_per_folder must be in (0, 1]")
