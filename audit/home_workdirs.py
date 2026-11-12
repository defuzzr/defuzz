"""Bounded, read-only measurement of work output stored inside the Hermes home.

Walks the home in one iterative pass using ``os.scandir(follow_symlinks=False)`` and
``os.lstat`` metadata only; never reads file contents except a capped 4-byte magic check
with ``O_NOFOLLOW`` on non-credential regular files to identify compiled executables.
Opens no database. The section and findings hold no clock-derived value (deterministic for an
unchanged home); elapsed time is returned only in the sibling `run_metrics`.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Callable

from .contract import (
    CLASSIFICATION_INFO,
    CLASSIFICATION_REVIEW,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
    make_component_envelope,
    make_finding,
)
from .fingerprint import CredentialStoreNotOpened, open_checked
from .policy import credential_path

# Bounded walk caps (audit hygiene rules).
MAX_ENTRIES = 400_000
MAX_DEPTH = 40
MAX_SECONDS = 20.0
# Cap on 4-byte O_NOFOLLOW magic header reads across the home walk.
# A typical home has tens of thousands of files but only a few dozen executables, so the cap is
# far above normal use and still bounds the cost on a pathological tree.
MAX_MAGIC_READS = 10_000

# Not-Hermes top-level folders (temporary folders, projects, notes, vendored copies) are common in
# small amounts; the finding needs both an absolute size well above ordinary skill and config files
# and a large share of the home, so a small home with one scratch folder is not flagged by share
# alone. plans/, tools/, venvs/ are Hermes-named and measured by HERMES_FOLDER_EXPECTATIONS.
WORK_FOLDERS_BYTES_THRESHOLD = 100 * 1024 * 1024  # 100 MiB
WORK_FOLDERS_SHARE_THRESHOLD = 0.20  # 20% of total home bytes
# Single huge files threshold: 50 MiB (52,428,800 B). Set to flag stray multi-hundred-MB output,
# log, browser and archive files while keeping skills hub index caches and single tool binaries
# (tens of MB) below it; state.db is listed under hermes_databases instead.
HUGE_FILE_THRESHOLD_BYTES = 50 * 1024 * 1024  # 50 MiB
MAX_PATH_COMPONENT_CHARS = 40

# Hermes-owned top-level directory and file names, cited from Hermes source (`src/hermes-agent`):
# - hermes_cli/config.py:435,475,564-566,3274,3773 (`config.yaml`, `.env`, `cron`, `sessions`,
#   `logs`, `memories`, `pairing`, `hooks`, `image_cache`, `audio_cache`, `skills`, `skins`, `plugins`)
# - hermes_constants.py:174,288-295,318-320,399,708,864,978 (`active_profile`, `models`, `runtimes`,
#   `node`, `downloads`, `.deleted`, `SOUL.md`, `profile.yaml`, `auth.json`, `state.db`, `home`,
#   `.managed`, `cache`)
# - hermes_cli/profiles.py:40,50-61,72-99,159-197,227-272 (`workspace`, `hermes-agent`, `.worktrees`,
#   `profiles`, `bin`, `node_modules`, `.hermes-runtime`, `state.db-wal`, `state.db-shm`, `backups`,
#   `state-snapshots`, `checkpoints`, `webapp`, `.no-bundled-skills`, `auth`, `.op.env`, `npmrc`,
#   `.anthropic_oauth.json`, `google_token.json`, `google_oauth_pending.json`,
#   `google_client_secret.json`, `google_chat_user_tokens`, `google_chat_user_client_secret.json`,
#   `google_chat_user_oauth_pending.json`, `google_chat_user_token.json`,
#   `google_chat_user_oauth_pending`, `slack_tokens.json`, `honcho.json`, `mem0.json`,
#   `webhook_subscriptions.json`, `teams_pipeline_store.json`, `mcp-tokens`, `vault`,
#   `browser-profile`, `browser_auth`, `bot-desktop`, `browser-profiles`, `browser_profiles`,
#   `platforms`, `feishu_comment_pairing.json`, `whatsapp`, `matrix`, `weixin`, `.copilot_jwt.json`,
#   `proxy`, `chrome-debug`, `hermes_state.db`, `response_store.db`, `response_store.db-shm`,
#   `response_store.db-wal`, `gateway.pid`, `gateway_state.json`, `processes.json`, `auth.lock`,
#   `.update_check`, `source-checks`, `errors.log`, `.hermes_history`, `document_cache`,
#   `browser_screenshots`, `sandboxes`, `MEMORY.md`, `USER.md`, `todo.json`, `system_prompt.md`,
#   `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `desktop.json`, `scripts`, `knowledge`, `preferences`,
#   `distribution.yaml`, `gateway.parked`, `import-sync.json`)
# - hermes_cli/backup.py:132,152,1106-1122 (`.backup.lock`, `cron.pid`, `gateway.lock`,
#   `channel_directory.json`, `channel_aliases.json`, `gateway`, `projects.db`, `memory_store.db`,
#   `verification_evidence.db`, `kanban.db`, `kanban`)
# - hermes_cli/home_data_layout.py:6,11-18 (`installs`, `bws_cache.json`, `bws_cache.enc.json`,
#   `op_cache.json`, `photon-sidecar.json`, `runtime`)
# - plugins/plugin_storage.py:27-33 (`plugin-data`)
# - hermes_cli/desktop_plugin_install.py:26 (`desktop-plugins`)
# - hermes_cli/plugins_cadence.py:20 (`plugin-update-checks`)
# - hermes_cli/install_identity.py:16,25 (`install_id`, `.install_id.lock`)
# - hermes_cli/terminal_breadcrumbs.py:29 (`terminal-sessions`)
# - hermes_cli/update_serve_obligations.py:56 (`serve_restart_pending`)
# - hermes_cli/update_cmd_windows.py:1229 (`bootstrap-cache`)
# - tools/credential_files.py:248-275 (`video_cache`, `web_cache`, `delegation_cache`,
#   `images`, `attachments`, `composer-pastes`)
# - gateway/hosted_rooms.py:426 (`shared-state.db`)
# - gateway/sticker_cache.py:17 (`sticker_cache.json`)
# - agent/pet/store.py:65 (`pets`)
# - agent/skill_bundles.py:30 (`skill-bundles`)
# - agent/model_metadata.py:1100 (`context_length_cache.yaml`)
# - hermes_cli/models_local.py:631 (`ollama_cloud_models_cache.json`)
# - hermes_cli/models_cache_lock.py:1 (`provider_models_cache.json`)
# - ui-tui/src/lib/themeBoot.ts:40 (`tui-theme-boot.json`)
# - tests-js/scripts/desktop-smoke.test.ts:176 (`spawn-ledger.json`)
# - hermes_cli/subcommands/hooks.py:14 (`shell-hooks-allowlist.json`)
# - tools/bot_relay.py / tui_gateway/change_watcher.py:358 (`bot_relay`)
HERMES_OWNED_TOP_LEVEL: frozenset[str] = frozenset({
    # Core directories
    "skills", "memories", "sessions", "logs", "cron", "plugins", "profiles", "hooks",
    "cache", "checkpoints", "kanban", "pending", "pending_messages", "backups", "bin",
    "skins", "workspace", "home", "scripts", "knowledge", "preferences",
    "pairing", "platforms", "mcp-tokens", "vault", "proxy", "auth",
    "models", "runtimes", "node", "installs", "downloads", "hermes-agent",
    ".worktrees", "node_modules", ".hermes-runtime", "state-snapshots",
    "image_cache", "audio_cache", "document_cache", "video_cache", "web_cache",
    "delegation_cache", "browser_screenshots", "sandboxes",
    "browser-profile", "browser_auth", "bot-desktop", "webapp",
    "browser-profiles", "browser_profiles", "chrome-debug",
    "whatsapp", "matrix", "weixin", "gateway",
    "plugin-data", "desktop-plugins", "plugin-update-checks",
    "terminal-sessions", "serve_restart_pending", "bootstrap-cache",
    "images", "attachments", "composer-pastes", "pets", "skill-bundles",
    "source-checks", "bot_relay", "runtime",
    # Core files
    "config.yaml", "SOUL.md", "MEMORY.md", "USER.md", "AGENTS.md", "CLAUDE.md",
    ".cursorrules", "system_prompt.md", "profile.yaml", "distribution.yaml",
    "desktop.json", "todo.json", "import-sync.json", "active_profile",
    ".managed", ".no-bundled-skills", ".update_check", ".update_exit_code",
    ".hermes_history", ".scratch_tip_shown", ".codex_gpt55_autoraise_notice",
    "install_id", ".install_id.lock",
    "state.db", "state.db-wal", "state.db-shm", "state.db-journal",
    "hermes_state.db", "projects.db", "projects.db-wal", "projects.db-shm",
    "response_store.db", "response_store.db-wal", "response_store.db-shm",
    "memory_store.db", "memory_store.db-wal", "memory_store.db-shm",
    "verification_evidence.db", "verification_evidence.db-wal", "verification_evidence.db-shm",
    "kanban.db", "kanban.db-wal", "kanban.db-shm",
    "shared-state.db", "shared-state.db-wal", "shared-state.db-shm",
    "auth.json", "auth.lock", ".env", ".op.env", "npmrc", ".npmrc",
    ".anthropic_oauth.json", "google_token.json", "google_oauth_pending.json",
    "google_client_secret.json", "google_chat_user_tokens",
    "google_chat_user_client_secret.json", "google_chat_user_oauth_pending.json",
    "google_chat_user_token.json", "google_chat_user_oauth_pending",
    "slack_tokens.json", "honcho.json", "mem0.json",
    "webhook_subscriptions.json", "teams_pipeline_store.json",
    "feishu_comment_pairing.json", ".copilot_jwt.json",
    "bws_cache.json", "bws_cache.enc.json", "op_cache.json", "photon-sidecar.json",
    "gateway.pid", "cron.pid", "gateway.lock", "gateway.parked",
    "gateway_state.json", "gateway_voice_mode.json", "gateway-starts.log",
    "processes.json", "errors.log", ".backup.lock",
    "channel_directory.json", "channel_aliases.json", "sticker_cache.json",
    "context_length_cache.yaml", "ollama_cloud_models_cache.json",
    "provider_models_cache.json", "models_dev_cache.json", "models_dev_cache.etag",
    "tui-theme-boot.json", "spawn-ledger.json", "shell-hooks-allowlist.json",
    "desktop-build-stamp.json", "web-ui-build-stamp.json",
    "profile-exports",
    # Folders Hermes itself names (correction (a)); measured separately by
    # HERMES_FOLDER_EXPECTATIONS below instead of being called "not Hermes".
    "plans",   # hermes_cli/profiles.py:40 (bootstrapped in every profile)
    "tools",   # hermes_cli/home_data_layout.py:6; pm/paths.py:71 (`<home>/tools` pm store)
    "venvs",   # hermes_constants.py:1373-1374 (`$HERMES_HOME/venvs/<name>` installer venvs)
})

# Short documented allowlist of well-known plugin/runtime names at the profile root:
# - `.curator_backups`: skill curator backup store (`tools/skill_ledger.py:89`)
# - `a2a_conversations`, `a2a_audit.jsonl`: A2A platform plugin state (`plugins/platforms/a2a/protocol.py:450`)
# - `disk-cleanup`: disk-cleanup plugin state (`plugins/disk-cleanup/disk_cleanup.py:29`)
# - `byterover`: ByteRover memory provider store (`plugins/memory/byterover/__init__.py:57`)
# - KNOWN_THIRD_PARTY_PLUGIN_TOP_LEVEL (below): state folders of community plugins listed in the
#   Hermes plugin catalog
# - `state`, `shared`, `desktop`, `assets`, `agent-images`, `locks`: desktop/gateway/plugin runtime state
# - `tasks.json`, `webui.ctl.env`, `webui.log`,
#   `.skills_prompt_snapshot.json`, `profile-config-sync-status.json`,
#   `workspace-sessions.json`, `workspace-rules`: CLI/WebUI/Desktop runtime files
# Data, not a private name: community plugins from the upstream Hermes plugin catalog whose state
# folder sits at the profile root, so their state is not reported as work output.
# - `memlock`: a third-party memory plugin (`plugin-catalog/memlock.yaml:1`)
KNOWN_THIRD_PARTY_PLUGIN_TOP_LEVEL: frozenset[str] = frozenset({"memlock"})
WELL_KNOWN_PLUGIN_RUNTIME_TOP_LEVEL: frozenset[str] = KNOWN_THIRD_PARTY_PLUGIN_TOP_LEVEL | frozenset({
    ".curator_backups",
    "a2a_conversations",
    "a2a_audit.jsonl",
    "disk-cleanup",
    "byterover",
    "state",
    "shared",
    "desktop",
    "assets",
    "agent-images",
    "locks",
    "tasks.json",
    "webui.ctl.env",
    "webui.log",
    ".skills_prompt_snapshot.json",
    "profile-config-sync-status.json",
    "workspace-sessions.json",
    "workspace-rules",
})

# Prefix/pattern matches for Hermes-created backup/lock/sidecar files at the root
# (`hermes_cli/profiles.py:194-197`, `hermes_cli/backup.py:141-144`).
_HERMES_OWNED_ROOT_PATTERNS = re.compile(
    r"^(?:"
    r"auth\.json\..+"
    r"|\.env\.(?:bak|codex-backup).*"
    r"|config\.yaml\.(?:bak|corrupt|pre-).*"
    r"|(?:state|kanban|memory_store|projects|response_store|verification_evidence|shared-state)\.db[-.].+"
    r"|\.npm_lock_hash_.+"
    r"|\.provider_models_cache_.+"
    r"|\.[a-z0-9_-]+\.lock"
    r")$",
    re.I,
)


def is_hermes_owned_top_level(name: str) -> bool:
    """Return True if top-level entry `name` is Hermes-owned or in the documented runtime allowlist."""
    if name in HERMES_OWNED_TOP_LEVEL or name in WELL_KNOWN_PLUGIN_RUNTIME_TOP_LEVEL:
        return True
    return bool(_HERMES_OWNED_ROOT_PATTERNS.match(name))


# Extension classes for huge files.
TEXT_LIKE_EXTENSIONS: frozenset[str] = frozenset({
    ".json", ".log", ".stdout", ".stderr", ".txt", ".jsonl", ".md", ".csv",
    ".tsv", ".yaml", ".yml", ".xml", ".html", ".htm", ".py", ".js", ".ts", ".sh",
})
ARCHIVE_EXTENSIONS: tuple[str, ...] = (
    ".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst",
    ".tgz", ".txz", ".zip", ".tar", ".7z", ".rar", ".gz", ".xz", ".bz2", ".zst",
)
# Archive extensions specifically counted under (c) working trees:
# `.zip .tar .tar.gz .tgz .tar.xz .7z`
WORKING_TREE_ARCHIVE_SUFFIXES: tuple[str, ...] = (
    ".tar.gz", ".tar.xz", ".tgz", ".zip", ".tar", ".7z",
)
MEDIA_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".ico",
    ".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac",
    ".mp4", ".webm", ".mkv", ".mov", ".avi",
})
DATABASE_EXTENSIONS: frozenset[str] = frozenset({
    ".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".db-journal",
})

# Non-executable extensions skipped before spending a magic-read slot (lstat name check only).
NON_EXECUTABLE_MAGIC_SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".json", ".jsonl", ".yaml", ".yml", ".toml", ".md", ".txt", ".rst", ".csv", ".tsv",
    ".log", ".stdout", ".stderr", ".xml", ".html", ".htm", ".css", ".scss", ".less",
    ".py", ".pyi", ".pyc", ".pyo", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".d.ts",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".sql", ".db", ".sqlite", ".sqlite3",
    ".db-wal", ".db-shm", ".db-journal", ".lock", ".etag", ".asc", ".sha256", ".cfg",
    ".ini", ".conf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".mp3", ".wav", ".ogg", ".flac", ".m4a", ".mp4", ".webm", ".mkv", ".mov", ".pdf",
    ".rtf", ".pak", ".dat",
})


def _should_probe_magic(filename: str, st_mode: int, file_size: int, huge_threshold: int) -> bool:
    """Return True when `filename` is a candidate for a 4-byte executable magic probe."""
    low = filename.lower()
    if low.endswith((".exe", ".dll", ".so", ".dylib", ".bin")) or ".so." in low:
        return True
    ext = os.path.splitext(low)[1]
    if ext in NON_EXECUTABLE_MAGIC_SKIP_EXTENSIONS:
        return False
    if not ext or (st_mode & 0o111) or file_size >= huge_threshold:
        return True
    return False
ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS: frozenset[bytes] = frozenset({
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
})

# Nested Hermes homes, one definition (correction (d)): a directory below the root, other than a
# named profile `profiles/<name>` and other than a plugin package (`plugins/...` holding
# `plugin.yaml`), that holds a regular file `config.yaml`. It is `config_with_marker` when it also
# holds one of the names below (seen by name via lstat only), else `config_only`. Basis: Hermes's own
# home/profile markers `_HERMES_HOME_MARKERS` (`hermes_constants.py:320`: config.yaml, .env,
# state.db) and `_PROFILE_IDENTITY_MARKERS` (`hermes_constants.py:399`: + SOUL.md, profile.yaml,
# auth.json), plus the `skills/` and `profiles/` folders every home has (`hermes_cli/profiles.py:40`).
# Folders where Hermes keeps its own copies (HERMES_COPY_FOLDERS) are not counted.
# Only `config_with_marker` raises the finding: a lone config.yaml is common in project and plugin
# folders, so `config_only` is reported for information and a looser any-config.yaml rule is not used.
NESTED_HOME_COMPANION_MARKERS: frozenset[str] = frozenset({
    "skills", "state.db", "auth.json", ".env", "SOUL.md", "profile.yaml", "profiles",
})


# Hermes-named folders and what Hermes puts in them (correction (a)). Bytes of files that are not
# that kind are "other kind"; a folder whose other-kind bytes exceed
# HERMES_FOLDER_OTHER_BYTES_THRESHOLD is listed in `hermes_folders_holding_work_output`.
# - plans/: created empty at profile bootstrap (hermes_cli/profiles.py:40); the only Hermes writer
#   found is `/plan`, which saves one markdown file `YYYY-MM-DD_HHMMSS-<slug>.md`
#   (agent/plan_prompt.py:21, hermes_cli/commands.py:166). Expected kind: `*.md` directly in plans/.
# - tools/: the pm byte store of downloaded tool generations (hermes_cli/home_data_layout.py:5-6,
#   pm/paths.py:71), whose root holds `facts.json` (pm/paths.py:63, hermes_cli/gateway.py:3108).
#   Expected kind: everything, but only when `tools/facts.json` exists (this check cannot tell pm
#   generations apart from other content in a real store); without it nothing is expected kind.
# - venvs/: installer interpreter venvs `$HERMES_HOME/venvs/<name>` (hermes_constants.py:1373-1374).
#   Expected kind: files inside `venvs/<name>/` when `venvs/<name>/pyvenv.cfg` exists.
HERMES_FOLDER_EXPECTATIONS: dict[str, str] = {
    "plans": "markdown_plans_at_folder_root",
    "tools": "pm_tool_store_with_facts_json",
    "venvs": "virtualenvs_with_pyvenv_cfg",
}
# 100 MiB of other-kind bytes. These folders can legitimately be large with their expected kind
# (plan files, a bundled tool, virtualenvs), so only a sizeable amount of unexpected content counts.
# Same size as WORK_FOLDERS_BYTES_THRESHOLD.
HERMES_FOLDER_OTHER_BYTES_THRESHOLD = 100 * 1024 * 1024

# Hermes-managed dependency/checkout areas where virtualenv, node_modules, .git and source-tree
# markers are Hermes's own layout and are not counted as working trees (false-positive guard; the
# homes often have these trees): installs/cache (hermes_cli/home_data_layout.py:6),
# hermes-agent/.worktrees/bin/node_modules/.hermes-runtime/node (hermes_cli/profiles.py:229-235),
# plugins (plugin venvs, hermes_cli/backup.py:91), skills, desktop-plugins
# (hermes_cli/desktop_plugin_install.py:26), runtimes (hermes_constants.py:288-295), venvs (above).
# `tools` joins them only when `tools/facts.json` exists.
HERMES_DEPENDENCY_TOP_LEVEL: frozenset[str] = frozenset({
    "installs", "cache", "hermes-agent", ".worktrees", "bin", "node_modules", ".hermes-runtime",
    "node", "runtimes", "plugins", "skills", "desktop-plugins", "venvs",
})

# Databases Hermes owns (correction (b)), as paths relative to a home root (the profile itself or
# `profiles/<name>/`). Listed apart in `hermes_databases` (size only), never in `huge_files`.
# state.db (tools/session_search_tool.py:640), hermes_state.db and response_store.db
# (hermes_cli/profiles.py:237-239), projects.db (hermes_cli/projects_db.py:25), memory_store.db,
# verification_evidence.db, kanban.db, gateway/discord_message_recovery.db (hermes_cli/backup.py:1107-1116),
# shared-state.db (gateway/hosted_rooms.py:426), runs_idempotency.db
# (gateway/platforms/api_server_run_idempotency.py:69), cron/executions.db (cron/executions.py:57),
# cron/deliveries.db (cron/delivery_queue.py:82), cron/notepad.db (cron/notepad.py:33),
# kanban/boards/<slug>/kanban.db (hermes_cli/kanban_db.py:4,566) and archived boards
# kanban/boards/_archived/<slug>/kanban.db (hermes_cli/kanban_db_boards.py:169).
HERMES_DATABASE_RELPATHS: frozenset[str] = frozenset({
    "state.db", "hermes_state.db", "projects.db", "response_store.db", "memory_store.db",
    "verification_evidence.db", "kanban.db", "shared-state.db", "runs_idempotency.db",
    "cron/executions.db", "cron/deliveries.db", "cron/notepad.db",
    "gateway/discord_message_recovery.db",
})
# SQLite sidecars (hermes_cli/profiles.py:237-239 lists `-wal`/`-shm`).
HERMES_DATABASE_SIDECARS: tuple[str, ...] = ("-wal", "-shm", "-journal")
MAX_DATABASE_LISTED = 50

# Folders where Hermes itself stores copies of a home's config and stores; a config.yaml there is
# not counted as a nested home: `state-snapshots` (hermes_cli/backup.py:62,1259), `backups`
# (hermes_cli/backup.py:1157), `checkpoints` (hermes_cli/backup.py:84), and the profile tombstone
# folder `profiles/.deleted` (hermes_constants.py:317).
# A home with snapshots can hold dozens of such copies.
HERMES_COPY_FOLDERS: frozenset[str] = frozenset({"state-snapshots", "backups", "checkpoints"})


def _inside_hermes_copy_folder(parts: tuple[str, ...]) -> bool:
    if len(parts) >= 2 and parts[0] == "profiles" and parts[1] == ".deleted":
        return True
    if len(parts) >= 3 and parts[0] == "profiles":
        parts = parts[2:]
    return bool(parts) and parts[0] in HERMES_COPY_FOLDERS

# Extra name-only guard before the 4-byte magic read: the read policy also never opens `*token*`,
# `*secret*`, `*credential*`, `*password*` names (audit hygiene rules), which `credential_path` does not
# cover for extensionless files.
_CREDENTIAL_NAME_FRAGMENTS: tuple[str, ...] = ("token", "secret", "credential", "password", "passwd")


def _credential_like(path: str, name: str) -> bool:
    from .outward_analyzers import credential_candidate
    from .secret_file_copies import (
        _SECRETARY_WORD_RE,
        _is_excluded_example_or_public,
        _is_excluded_token_name,
    )

    if credential_path(path) or credential_candidate(name):
        return True
    low = name.casefold()
    if _is_excluded_example_or_public(low) or _is_excluded_token_name(low):
        return False
    cleaned = _SECRETARY_WORD_RE.sub("", low)
    return any(frag in cleaned for frag in _CREDENTIAL_NAME_FRAGMENTS)


def _hermes_database_relpath(parts: tuple[str, ...]) -> str | None:
    """Return the profile-relative path when `parts` names a Hermes database or sidecar."""
    if len(parts) >= 3 and parts[0] == "profiles" and not parts[1].startswith("."):
        inner = parts[2:]
    else:
        inner = parts
    rel = "/".join(inner)
    base = rel
    for suffix in HERMES_DATABASE_SIDECARS:
        if rel.endswith(suffix):
            base = rel[: -len(suffix)]
            break
    board_db = (
        len(inner) in (4, 5) and inner[0] == "kanban" and inner[1] == "boards"
        and (len(inner) == 4 or inner[2] == "_archived") and base.endswith("/kanban.db")
    )
    if base in HERMES_DATABASE_RELPATHS or board_db:
        return "/".join(parts)
    return None


# Enumerated string values and finding consequences.
RULE_WORK_FOLDERS = "home_workdirs.work_folders_in_home"
RULE_OVERSIZED_HERMES_FOLDERS = "home_workdirs.oversized_hermes_folders"
RULE_HUGE_FILES = "home_workdirs.huge_files"
RULE_WORKING_TREES = "home_workdirs.working_trees_in_home"
RULE_NESTED_HOMES = "home_workdirs.nested_hermes_homes"
RULE_COULD_NOT_VERIFY = "home_workdirs.could_not_verify"

CONSEQUENCE_WORK_FOLDERS = (
    "Top-level folders whose names the Hermes source never creates hold more than the size or share "
    "threshold of this home's bytes; this is a measurement of names, sizes and file counts and does not "
    "show who created them or whether they are still needed."
)
CONSEQUENCE_OVERSIZED_HERMES_FOLDERS = (
    "Folders that Hermes creates (plans, tools, venvs) hold more than the threshold in files that are not "
    "the kind Hermes writes there; this measures file names and sizes only and does not show who wrote "
    "them or whether they are still needed."
)
CONSEQUENCE_HUGE_FILES = (
    "Files other than Hermes's own databases are at or above the single-file size threshold; this records "
    "size and file type only and does not show who wrote them or whether they are still needed."
)
CONSEQUENCE_WORKING_TREES = (
    "Virtual environments, copied source trees, dependency folders, repositories or archives beside an "
    "extracted copy were found by marker names outside Hermes's own dependency folders; this counts them "
    "and their bytes and does not show whether anything still uses them."
)
CONSEQUENCE_NESTED_HOMES = (
    "Directories below the home root, outside named profiles, hold config.yaml together with a Hermes home "
    "marker name; this counts them by file name only and does not show how they were made or whether "
    "Hermes uses them."
)
CONSEQUENCE_COULD_NOT_VERIFY = (
    "Home workdir inspection hit a safety cap or could not read part of the home; incomplete traversal "
    "is reported as could_not_verify rather than clean."
)


def _year_month(mtime: float | None) -> int | None:
    """UTC year-month of a file time as the integer YYYYMM (e.g. 202608), or None."""
    if mtime is None or mtime <= 0:
        return None
    try:
        dt = datetime.fromtimestamp(mtime, timezone.utc)
        return dt.year * 100 + dt.month
    except (OSError, OverflowError, ValueError):
        return None


def _display(text: str) -> str:
    """Make a file-system name valid UTF-8 for output: undecodable bytes become U+FFFD."""
    return os.fsencode(text).decode("utf-8", "replace")


# Why a path is not shown (`path_withheld`); `path` is then null. The report serializer keeps only
# vocabulary labels and absolute paths of items that exist, so every other name would become a
# per-run token: names are therefore shown only as absolute paths of the existing item, or not at all.
WITHHELD_UNDECODABLE = "undecodable_name"  # bytes that are not UTF-8: no stable text form
WITHHELD_CREDENTIAL = "credential_named"  # credential-looking name: never shown
WITHHELD_LONG = "long_name"  # a component over MAX_PATH_COMPONENT_CHARS (privacy cap)
WITHHELD_SYMLINK = "symlink"  # a link: its resolved target could lie outside the home


def _shown_path(base: str, parts: tuple[str, ...], *, is_symlink: bool = False) -> tuple[str | None, str | None]:
    """Absolute path of an existing item below `base` (the resolved home), or a vocabulary reason."""
    if any(_display(part) != part for part in parts) or _display(base) != base:
        return None, WITHHELD_UNDECODABLE
    full = os.path.join(base, *parts)
    if credential_path(full) or any(
        _credential_like(os.path.join(base, *parts[: i + 1]), part) for i, part in enumerate(parts)
    ):
        return None, WITHHELD_CREDENTIAL
    if any(len(part) > MAX_PATH_COMPONENT_CHARS for part in parts):
        return None, WITHHELD_LONG
    if is_symlink:
        return None, WITHHELD_SYMLINK
    return full, None


def _archive_stem(filename: str) -> str | None:
    """Return the stem of an archive filename if it matches WORKING_TREE_ARCHIVE_SUFFIXES, else None."""
    low = filename.lower()
    for ext in WORKING_TREE_ARCHIVE_SUFFIXES:
        if low.endswith(ext) and len(filename) > len(ext):
            return filename[: -len(ext)]
    return None


def _classify_extension(filename: str, *, is_executable_magic: bool) -> str:
    """Classify a file into: executable_file, database, archive, media, text_like, or other."""
    if is_executable_magic:
        return "executable_file"
    low = filename.lower()
    for ext in ARCHIVE_EXTENSIONS:
        if low.endswith(ext):
            return "archive"
    for ext in DATABASE_EXTENSIONS:
        if low.endswith(ext):
            return "database"
    ext = os.path.splitext(low)[1]
    if ext in MEDIA_EXTENSIONS:
        return "media"
    if ext in TEXT_LIKE_EXTENSIONS:
        return "text_like"
    return "other"


def _is_magic_executable(
    file_path: str,
    file_size: int,
    *,
    is_credential: bool,
) -> tuple[bool, bool]:
    """Check 4-byte magic header with O_NOFOLLOW.

    Returns `(is_executable, did_read)`. Never opens credential paths or files < 4 bytes.
    """
    if is_credential or file_size < 4:
        return False, False
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = open_checked(file_path, flags)
    except CredentialStoreNotOpened:
        return False, False  # the opened file is a declared credential: as if never probed
    except OSError:
        return False, True
    try:
        st_fd = os.fstat(fd)
        if not stat.S_ISREG(st_fd.st_mode):
            return False, True
        header = os.read(fd, 4)
    except OSError:
        return False, True
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if len(header) < 2:
        return False, True
    if header == ELF_MAGIC or header in MACHO_MAGICS or header[:2] == b"MZ":
        return True, True
    return False, True


_WORKING_TREE_KEYS = (
    "virtualenv_count", "virtualenv_bytes", "source_tree_count", "source_tree_bytes",
    "node_modules_count", "node_modules_bytes", "git_dir_count", "git_dir_bytes",
    "archive_count", "archive_bytes", "archives_beside_extracted_count",
    "archives_beside_extracted_bytes", "executable_count", "executable_bytes",
)


def _totals(
    total: int, hermes_named: int, not_hermes: int, other_kind: int, db_bytes: int, huge: int,
) -> dict[str, Any]:
    def share(n: int) -> float:
        return round(n / total, 4) if total > 0 else 0.0

    return {
        "total_home_bytes": total,
        "hermes_named_bytes": hermes_named,
        "not_hermes_bytes": not_hermes,
        "hermes_folders_other_kind_bytes": other_kind,
        "hermes_database_bytes": db_bytes,
        "huge_files_bytes": huge,
        "hermes_named_share": share(hermes_named),
        "not_hermes_share": share(not_hermes),
        "huge_files_share": share(huge),
    }


def _section(
    *, status: str, coverage: str, reason: str | None, truncated_by: str | None,
    not_hermes: list, hermes_folders: list, huge: list, databases: dict, working_trees: dict,
    nested: dict, totals: dict, symlinks: int, limits: dict, thresholds: dict,
) -> dict[str, Any]:
    return {
        "status": status,
        "coverage": coverage,
        "reason": reason,
        "truncated_by": truncated_by,
        "not_hermes_folders": not_hermes,
        "hermes_folders_holding_work_output": hermes_folders,
        "huge_files": huge,
        "hermes_databases": databases,
        "working_trees": working_trees,
        "nested_hermes_homes": nested,
        "totals": totals,
        "symlinks_skipped": symlinks,
        "limits": limits,
        "thresholds": thresholds,
    }


def _not_measured(root: Path | None, reason: str, limits: dict, thresholds: dict) -> dict[str, Any]:
    # No identity or path: the root does not exist or cannot be shown, and a path that does not
    # exist would become a per-run token in the sealed report.
    shown: list[str] = []
    finding = make_finding(
        rule_id=RULE_COULD_NOT_VERIFY,
        classification=CLASSIFICATION_INFO,
        coverage=COVERAGE_COULD_NOT_VERIFY,
        affected_identities=shown,
        source_paths=shown,
        evidence={"reason": reason, "cuts": 1},
        consequence=CONSEQUENCE_COULD_NOT_VERIFY,
    )
    limits["cuts"] = 1
    section = _section(
        status="not_measured", coverage=COVERAGE_COULD_NOT_VERIFY, reason=reason, truncated_by=None,
        not_hermes=[], hermes_folders=[], huge=[], databases={"count": 0, "bytes": 0, "files": []},
        working_trees={k: 0 for k in _WORKING_TREE_KEYS},
        nested={"count": 0, "config_with_marker": 0, "config_only": 0},
        totals=_totals(0, 0, 0, 0, 0, 0), symlinks=0, limits=limits, thresholds=thresholds,
    )
    return _envelope([finding], COVERAGE_COULD_NOT_VERIFY, section, elapsed_ms=0)


def _envelope(findings: list, coverage: str, section: dict, *, elapsed_ms: int) -> dict[str, Any]:
    """Wiring envelope: exactly the section, findings, status, coverage and `run_metrics`.

    `run_metrics` holds the only run-dependent value (elapsed time from the injected clock); the
    caller stores it outside the fingerprinted report, so the section stays digest-stable.
    """
    env = make_component_envelope(findings=findings, coverage=coverage)
    return {
        "home_workdirs": section,
        "findings": env["findings"],
        "status": env["status"],
        "coverage": env["coverage"],
        "run_metrics": {"elapsed_ms": max(0, int(elapsed_ms))},
    }


def _directory_entry_records(
    raw_entries: list[os.DirEntry[str]], note_cut: Callable[[str], None],
) -> tuple[list[tuple[os.DirEntry[str], os.stat_result, str]], set[str], set[str], set[str]]:
    """Collect no-follow metadata and marker names for one sorted directory."""
    dir_names: set[str] = set()
    file_names: set[str] = set()
    all_names: set[str] = set()
    entry_records: list[tuple[os.DirEntry[str], os.stat_result, str]] = []
    for entry in raw_entries:
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            note_cut("lstat_error")
            continue
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            kind = "symlink"
        elif stat.S_ISDIR(mode):
            kind = "directory"
            dir_names.add(entry.name)
        elif stat.S_ISREG(mode):
            kind = "regular"
            file_names.add(entry.name)
        else:
            kind = "special"
        all_names.add(entry.name)
        entry_records.append((entry, st, kind))
    return entry_records, dir_names, file_names, all_names


def audit_home_workdirs(
    profile_path: str | Path,
    *,
    huge_file_threshold_bytes: int = HUGE_FILE_THRESHOLD_BYTES,
    work_folders_bytes_threshold: int = WORK_FOLDERS_BYTES_THRESHOLD,
    work_folders_share_threshold: float = WORK_FOLDERS_SHARE_THRESHOLD,
    hermes_folder_other_bytes_threshold: int = HERMES_FOLDER_OTHER_BYTES_THRESHOLD,
    max_entries: int = MAX_ENTRIES,
    max_depth: int = MAX_DEPTH,
    max_magic_reads: int = MAX_MAGIC_READS,
    max_seconds: float = MAX_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Measure agent work output stored inside the Hermes home in a single bounded pass.

    The section and findings depend only on the home's contents: the injected clock bounds the walk
    and gives `run_metrics.elapsed_ms` (outside the section); modification times appear only as UTC
    year-month integers (YYYYMM).
    """
    limits: dict[str, Any] = {
        "max_entries": int(max_entries),
        "max_depth": int(max_depth),
        "max_magic_reads": int(max_magic_reads),
        "max_seconds": float(max_seconds),
        "entries_walked": 0,
        "magic_reads": 0,
        "cuts": 0,
    }
    thresholds: dict[str, Any] = {
        "huge_file_bytes": int(huge_file_threshold_bytes),
        "work_folders_bytes": int(work_folders_bytes_threshold),
        "work_folders_share": float(work_folders_share_threshold),
        "hermes_folder_other_kind_bytes": int(hermes_folder_other_bytes_threshold),
    }

    try:
        root = Path(profile_path)
    except TypeError:
        return _not_measured(None, "invalid_home_root", limits, thresholds)
    try:
        root_st = os.lstat(root)
    except ValueError:  # embedded NUL
        return _not_measured(None, "invalid_home_root", limits, thresholds)
    except FileNotFoundError:
        return _not_measured(root, "missing_home", limits, thresholds)
    except OSError:
        return _not_measured(root, "unreadable_home", limits, thresholds)
    if stat.S_ISLNK(root_st.st_mode) or not stat.S_ISDIR(root_st.st_mode):
        return _not_measured(root, "invalid_home_root", limits, thresholds)

    started = clock()
    deadline = started + float(max_seconds)
    # Paths are shown under the resolved home so the serializer keeps them unchanged.
    base_shown = os.path.realpath(root)
    truncated_by: str | None = None

    def _note_cut(reason: str) -> None:
        nonlocal truncated_by
        limits["cuts"] += 1
        if truncated_by is None:
            truncated_by = reason

    def _expired() -> bool:
        if clock() >= deadline:
            _note_cut("max_seconds")
            return True
        return False

    top_level_stats: dict[str, dict[str, Any]] = {}
    huge_files: list[dict[str, Any]] = []
    databases: list[dict[str, Any]] = []
    wt = {k: 0 for k in _WORKING_TREE_KEYS}
    nested_with_marker = 0
    nested_config_only = 0
    symlinks_skipped = 0
    tools_has_pm_marker = False
    venvs_with_cfg: set[str] = set()
    # Per Hermes-named folder: expected-kind / other-kind byte and file counts.
    hermes_folder_kind: dict[str, dict[str, int]] = {
        name: {"expected_kind_bytes": 0, "other_kind_bytes": 0, "other_kind_files": 0}
        for name in HERMES_FOLDER_EXPECTATIONS
    }

    def _markers_in_scope(top_name: str) -> bool:
        if top_name in HERMES_DEPENDENCY_TOP_LEVEL:
            return False
        if top_name == "tools" and tools_has_pm_marker:
            return False
        return True

    stack: list[tuple[str, tuple[str, ...], int, frozenset[str]]] = [
        (str(root), (), 0, frozenset())
    ]

    while stack:
        if _expired():
            break
        cur_dir, rel_parts, depth, active_buckets = stack.pop()

        try:
            with os.scandir(cur_dir) as it:
                raw_entries = []
                for entry in it:
                    # Skip macOS AppleDouble resource fork stubs (`._*`, audit hygiene rules).
                    if entry.name.startswith("._"):
                        continue
                    limits["entries_walked"] += 1
                    if limits["entries_walked"] > max_entries:
                        _note_cut("max_entries")
                        raw_entries = None
                        break
                    raw_entries.append(entry)
        except OSError:
            _note_cut("scandir_error")
            continue

        if raw_entries is None:
            break

        raw_entries.sort(key=lambda e: e.name)

        entry_records, dir_names, file_names, all_names = _directory_entry_records(raw_entries, _note_cut)

        cur_buckets = set(active_buckets)

        if depth > 0 and rel_parts:
            top_name = rel_parts[0]
            top_owned = top_level_stats[top_name]["owned"]
            leaf_name = rel_parts[-1]
            if rel_parts == ("tools",):
                tools_has_pm_marker = "facts.json" in file_names
            if len(rel_parts) == 2 and top_name == "venvs" and "pyvenv.cfg" in file_names:
                venvs_with_cfg.add(rel_parts[1])
            in_marker_scope = _markers_in_scope(top_name)

            # (d) Nested Hermes homes (definition at NESTED_HOME_COMPANION_MARKERS).
            is_real_named_profile = (
                len(rel_parts) == 2
                and rel_parts[0] == "profiles"
                and not rel_parts[1].startswith(".")
            )
            is_plugin_package = rel_parts[0] == "plugins" and "plugin.yaml" in file_names
            if (
                not is_real_named_profile
                and not is_plugin_package
                and not _inside_hermes_copy_folder(rel_parts)
                and "config.yaml" in file_names
            ):
                if all_names & NESTED_HOME_COMPANION_MARKERS:
                    nested_with_marker += 1
                else:
                    nested_config_only += 1

            # (c) Virtualenvs: directory containing `pyvenv.cfg`
            if in_marker_scope and "pyvenv.cfg" in file_names and "venv" not in cur_buckets:
                wt["virtualenv_count"] += 1
                cur_buckets.add("venv")

            # (c) Copied source trees: `pyproject.toml` or `package.json` at a folder root under a
            # not-Hermes top-level folder or under `tmp/` / `plans/`, outermost only.
            in_work_tree_scope = in_marker_scope and ((not top_owned) or top_name in {"tmp", "plans"})
            if (
                in_work_tree_scope
                and "src" not in cur_buckets
                and "venv" not in cur_buckets
                and "node_modules" not in cur_buckets
                and ("pyproject.toml" in file_names or "package.json" in file_names)
                and ("pyproject.toml" in file_names or len(rel_parts) >= 2)
            ):
                wt["source_tree_count"] += 1
                cur_buckets.add("src")

            # (c) `node_modules` dirs (outermost only)
            if in_marker_scope and leaf_name == "node_modules" and "node_modules" not in cur_buckets:
                wt["node_modules_count"] += 1
                cur_buckets.add("node_modules")

            # (c) `.git` dirs outside Hermes's own dependency/checkout folders
            if in_marker_scope and leaf_name == ".git" and "git" not in cur_buckets:
                wt["git_dir_count"] += 1
                cur_buckets.add("git")

        frozen_buckets = frozenset(cur_buckets)
        subdirs_to_push: list[tuple[str, tuple[str, ...], int, frozenset[str]]] = []

        for entry, st, kind in entry_records:
            if _expired():
                break
            ename = entry.name
            child_parts = (*rel_parts, ename)
            top_name = child_parts[0]

            if depth == 0:
                owned = is_hermes_owned_top_level(ename)
                top_level_stats[ename] = {
                    "name": ename,
                    "kind": kind,
                    "owned": owned,
                    "size_bytes": 0,
                    "file_count": 0,
                    "min_mtime": None,
                    "max_mtime": None,
                }

            top_rec = top_level_stats[top_name]

            if kind == "symlink":
                symlinks_skipped += 1
                continue

            if kind == "directory":
                if depth + 1 > max_depth:
                    _note_cut("max_depth")
                    continue
                subdirs_to_push.append((entry.path, child_parts, depth + 1, frozen_buckets))
                continue

            if kind != "regular":
                continue

            fsize = int(st.st_size)
            fmtime = float(st.st_mtime)

            top_rec["size_bytes"] += fsize
            top_rec["file_count"] += 1
            if top_rec["min_mtime"] is None or fmtime < top_rec["min_mtime"]:
                top_rec["min_mtime"] = fmtime
            if top_rec["max_mtime"] is None or fmtime > top_rec["max_mtime"]:
                top_rec["max_mtime"] = fmtime

            # Expected-kind accounting for Hermes-named folders (HERMES_FOLDER_EXPECTATIONS).
            if len(child_parts) >= 2 and top_name in hermes_folder_kind and top_rec["kind"] == "directory":
                if top_name == "plans":
                    expected = len(child_parts) == 2 and ename.lower().endswith(".md")
                elif top_name == "tools":
                    expected = tools_has_pm_marker
                else:
                    expected = len(child_parts) >= 3 and child_parts[1] in venvs_with_cfg
                rec = hermes_folder_kind[top_name]
                if expected:
                    rec["expected_kind_bytes"] += fsize
                else:
                    rec["other_kind_bytes"] += fsize
                    rec["other_kind_files"] += 1

            if "venv" in frozen_buckets:
                wt["virtualenv_bytes"] += fsize
            if "src" in frozen_buckets:
                wt["source_tree_bytes"] += fsize
            if "node_modules" in frozen_buckets:
                wt["node_modules_bytes"] += fsize
            if "git" in frozen_buckets:
                wt["git_dir_bytes"] += fsize

            # (c) Archives and archives beside an extracted folder
            stem = _archive_stem(ename)
            if stem is not None:
                wt["archive_count"] += 1
                wt["archive_bytes"] += fsize
                has_extracted_sibling = stem in dir_names
                if not has_extracted_sibling and len(rel_parts) >= 2 and rel_parts[-1] in {"dl", "downloads"}:
                    # e.g. tools/<name>/dl/<name>-<version>.tar.xz beside tools/<name>/cache/
                    parent_prefix = stem.split("-")[0].lower()
                    if parent_prefix and rel_parts[-2].lower() == parent_prefix:
                        has_extracted_sibling = True
                if has_extracted_sibling and _markers_in_scope(top_name):
                    wt["archives_beside_extracted_count"] += 1
                    wt["archives_beside_extracted_bytes"] += fsize

            # (c) Executables by 4-byte magic header (ELF, Mach-O, PE 'MZ').
            # Never open credential-looking files (House Rule #3).
            is_cred = _credential_like(entry.path, ename)
            is_exe = False
            if (
                not is_cred
                and fsize >= 4
                and stem is None
                and _should_probe_magic(ename, st.st_mode, fsize, huge_file_threshold_bytes)
            ):
                if limits["magic_reads"] >= max_magic_reads:
                    _note_cut("max_magic_reads")
                else:
                    is_exe, did_read = _is_magic_executable(entry.path, fsize, is_credential=is_cred)
                    if did_read:
                        limits["magic_reads"] += 1
                    if is_exe:
                        wt["executable_count"] += 1
                        wt["executable_bytes"] += fsize

            # (b) Hermes databases (size only) are listed apart; other files at or above the
            # huge-file threshold are huge files.
            db_rel = _hermes_database_relpath(child_parts)
            if db_rel is not None:
                db_path, db_withheld = _shown_path(base_shown, child_parts)
                databases.append({
                    "path": db_path, "path_withheld": db_withheld, "size_bytes": fsize, "_sort": db_rel,
                })
            elif fsize >= huge_file_threshold_bytes:
                ext_class = _classify_extension(ename, is_executable_magic=is_exe)
                huge_path, huge_withheld = _shown_path(base_shown, child_parts[:2])
                huge_files.append({
                    "path": huge_path,
                    "path_withheld": huge_withheld,
                    "_sort": "/".join(child_parts[:2]),
                    "size_bytes": fsize,
                    "extension_class": ext_class,
                    "hermes_named_top_level": bool(top_rec["owned"]),
                })

        for item in reversed(subdirs_to_push):
            stack.append(item)

    not_hermes_list: list[dict[str, Any]] = []
    hermes_folders_list: list[dict[str, Any]] = []
    hermes_named_bytes = 0
    not_hermes_bytes = 0
    other_kind_total = 0

    for name, rec in sorted(top_level_stats.items()):
        if rec["owned"]:
            hermes_named_bytes += rec["size_bytes"]
            if name in HERMES_FOLDER_EXPECTATIONS and rec["kind"] == "directory":
                kinds = hermes_folder_kind[name]
                other_kind_total += kinds["other_kind_bytes"]
                if kinds["other_kind_bytes"] > hermes_folder_other_bytes_threshold:
                    if name == "tools":
                        marker = tools_has_pm_marker
                    elif name == "venvs":
                        marker = bool(venvs_with_cfg)
                    else:
                        marker = kinds["expected_kind_bytes"] > 0
                    hermes_folders_list.append({
                        "name": name,
                        "expectation": HERMES_FOLDER_EXPECTATIONS[name],
                        "layout_marker_present": marker,
                        "size_bytes": rec["size_bytes"],
                        "file_count": rec["file_count"],
                        "expected_kind_bytes": kinds["expected_kind_bytes"],
                        "other_kind_bytes": kinds["other_kind_bytes"],
                        "other_kind_files": kinds["other_kind_files"],
                        "oldest_year_month": _year_month(rec["min_mtime"]),
                        "newest_year_month": _year_month(rec["max_mtime"]),
                    })
        else:
            # Ignore empty unknown folders so they are not flagged
            if rec["kind"] == "directory" and rec["file_count"] == 0 and rec["size_bytes"] == 0:
                continue
            not_hermes_bytes += rec["size_bytes"]
            shown, withheld = _shown_path(base_shown, (name,), is_symlink=rec["kind"] == "symlink")
            not_hermes_list.append({
                "path": shown,
                "path_withheld": withheld,
                "_sort": name,
                "kind": rec["kind"],
                "size_bytes": rec["size_bytes"],
                "file_count": rec["file_count"],
                "oldest_year_month": _year_month(rec["min_mtime"]),
                "newest_year_month": _year_month(rec["max_mtime"]),
            })

    not_hermes_list.sort(key=lambda r: (-r["size_bytes"], r.pop("_sort")))
    hermes_folders_list.sort(key=lambda r: (-r["other_kind_bytes"], r["name"]))
    huge_files.sort(key=lambda r: (-r["size_bytes"], r.pop("_sort")))
    databases.sort(key=lambda r: (-r["size_bytes"], r.pop("_sort")))

    total_home_bytes = hermes_named_bytes + not_hermes_bytes
    huge_files_bytes = sum(r["size_bytes"] for r in huge_files)
    database_bytes = sum(r["size_bytes"] for r in databases)
    hermes_databases = {
        "count": len(databases),
        "bytes": database_bytes,
        "files": databases[:MAX_DATABASE_LISTED],
    }
    totals = _totals(
        total_home_bytes, hermes_named_bytes, not_hermes_bytes, other_kind_total, database_bytes,
        huge_files_bytes,
    )

    coverage = COVERAGE_COULD_NOT_VERIFY if limits["cuts"] > 0 else COVERAGE_VERIFIED
    findings: list[dict[str, Any]] = []
    root_shown = [base_shown] if _display(base_shown) == base_shown else []

    if not_hermes_list and (
        not_hermes_bytes > work_folders_bytes_threshold
        or (total_home_bytes > 0 and (not_hermes_bytes / total_home_bytes) > work_folders_share_threshold)
    ):
        findings.append(make_finding(
            rule_id=RULE_WORK_FOLDERS,
            classification=CLASSIFICATION_REVIEW,
            coverage=coverage,
            affected_identities=root_shown,
            source_paths=[r["path"] for r in not_hermes_list[:10] if r["path"] is not None] or root_shown,
            evidence={
                "not_hermes_count": len(not_hermes_list),
                "not_hermes_bytes": not_hermes_bytes,
                "total_home_bytes": total_home_bytes,
                "not_hermes_share": totals["not_hermes_share"],
                "threshold_bytes": int(work_folders_bytes_threshold),
                "threshold_share": float(work_folders_share_threshold),
            },
            consequence=CONSEQUENCE_WORK_FOLDERS,
        ))

    if hermes_folders_list:
        findings.append(make_finding(
            rule_id=RULE_OVERSIZED_HERMES_FOLDERS,
            classification=CLASSIFICATION_REVIEW,
            coverage=coverage,
            affected_identities=root_shown,
            source_paths=[os.path.join(base_shown, r["name"]) for r in hermes_folders_list],
            evidence={
                "folder_count": len(hermes_folders_list),
                "other_kind_bytes": sum(r["other_kind_bytes"] for r in hermes_folders_list),
                "other_kind_files": sum(r["other_kind_files"] for r in hermes_folders_list),
                "threshold_bytes": int(hermes_folder_other_bytes_threshold),
            },
            consequence=CONSEQUENCE_OVERSIZED_HERMES_FOLDERS,
        ))

    if huge_files:
        findings.append(make_finding(
            rule_id=RULE_HUGE_FILES,
            classification=CLASSIFICATION_REVIEW,
            coverage=coverage,
            affected_identities=root_shown,
            source_paths=root_shown,
            evidence={
                "huge_file_count": len(huge_files),
                "huge_files_bytes": huge_files_bytes,
                "largest_file_bytes": huge_files[0]["size_bytes"],
                "threshold_bytes": int(huge_file_threshold_bytes),
            },
            consequence=CONSEQUENCE_HUGE_FILES,
        ))

    if (
        wt["virtualenv_count"] > 0
        or wt["source_tree_count"] > 0
        or wt["node_modules_count"] > 0
        or wt["git_dir_count"] > 0
        or wt["archives_beside_extracted_count"] > 0
    ):
        findings.append(make_finding(
            rule_id=RULE_WORKING_TREES,
            classification=CLASSIFICATION_INFO,
            coverage=coverage,
            affected_identities=root_shown,
            source_paths=root_shown,
            evidence=dict(wt),
            consequence=CONSEQUENCE_WORKING_TREES,
        ))

    if nested_with_marker > 0:
        findings.append(make_finding(
            rule_id=RULE_NESTED_HOMES,
            classification=CLASSIFICATION_REVIEW,
            coverage=coverage,
            affected_identities=root_shown,
            source_paths=root_shown,
            evidence={
                "nested_hermes_home_count": nested_with_marker,
                "config_with_marker": nested_with_marker,
                "config_only": nested_config_only,
            },
            consequence=CONSEQUENCE_NESTED_HOMES,
        ))

    if coverage == COVERAGE_COULD_NOT_VERIFY:
        findings.append(make_finding(
            rule_id=RULE_COULD_NOT_VERIFY,
            classification=CLASSIFICATION_INFO,
            coverage=COVERAGE_COULD_NOT_VERIFY,
            affected_identities=root_shown,
            source_paths=root_shown,
            evidence={"cuts": limits["cuts"], "truncated_by": truncated_by or "io_error"},
            consequence=CONSEQUENCE_COULD_NOT_VERIFY,
        ))

    section = _section(
        status="completed", coverage=coverage, reason=None, truncated_by=truncated_by,
        not_hermes=not_hermes_list, hermes_folders=hermes_folders_list, huge=huge_files,
        databases=hermes_databases, working_trees=dict(wt),
        nested={
            "count": nested_with_marker,
            "config_with_marker": nested_with_marker,
            "config_only": nested_config_only,
        },
        totals=totals, symlinks=symlinks_skipped, limits=limits, thresholds=thresholds,
    )
    return _envelope(findings, coverage, section, elapsed_ms=round((clock() - started) * 1000))
