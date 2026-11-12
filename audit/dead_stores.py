"""Deterministic, read-only dead-store and regenerable-cache measurement.

Hermes source citations for on-disk layout and retention rules:
- Profile exports: ``hermes_cli/profiles.py:2022-2027,2050-2069,2158-2165`` and
  ``hermes_cli/subcommands/profile.py:119`` write ``<home>/profile-exports/<name>-<ts>.tar.gz``.
- Full/quick backups & exclusions: ``hermes_cli/backup.py:60-145`` and
  ``hermes_cli/home_data_layout.py:5-18``.
- Point-in-time config backups: ``hermes_cli/config_backups.py:21-27,44-71`` write
  ``<home>/backups/config/config.yaml.<reason>.<YYYYMMDD-HHMMSS>`` and sweep legacy
  ``config.yaml.bak.*`` / ``config.yaml.corrupt.*.bak`` / ``config.yaml.bak-pre-migrate-*``.
- User plugins & manifests: ``hermes_cli/plugins.py:3-9,69-75``,
  ``hermes_cli/plugins_discovery.py:112-132,141-219,269-334``,
  ``hermes_cli/plugins_manifest.py:59-63,551-583``, ``pm/plugins_state.py:83-110,198-219``,
  ``pm/plugin_eviction.py:15,97-117``, and ``pm/publication.py:143,173,185``
  (``.install-metadata.json`` and ``.previous-<uuid>``).
- Desktop plugin halves: ``hermes_cli/desktop_plugin_halves.py:1-15,34-38,120-127``
  (``<home>/desktop-plugins/<name>/plugin.js`` and ``.hermes-package.json``).
- Per-plugin persistent data: ``plugins/plugin_storage.py:1,27-33``
  (``<home>/plugin-data/<name>/``).
- Request error dumps: ``agent/agent_init.py:1102-1104``,
  ``agent/agent_runtime_helpers.py:1553-1560``, ``hermes_state_sessions.py:1632,1642``,
  and ``gateway/run.py:4385`` (``<home>/sessions/request_dump_<sid>_<ts>.json``;
  counted only directly in ``sessions/`` or ``profiles/<name>/sessions/``).
- Skills Hub index cache: ``tools/skills_hub.py:61-67`` and ``tools/skills_hub_search.py:31-33``
  (``<home>/skills/.hub/index-cache/hermes-index.json``).
- Model & tool discovery caches: ``agent/models_dev.py:4,241-245`` (``models_dev_cache.json``,
  ``models_dev_cache.etag``), ``hermes_cli/models.py:1772,1857-1859``
  (``provider_models_cache.json``), and ``tools/registry.py:183``
  (``cache/tool_discovery_cache.json``).
- Media & screenshot caches: ``gateway/platforms/base.py:485,560-561,681-683,728-731,757``,
  ``tools/credential_files.py:249-251``, and ``tools/image_source.py:189``
  (``cache/images``, ``image_cache``, ``cache/audio``, ``audio_cache``,
  ``cache/documents``, ``document_cache``, ``video_cache``, ``browser_screenshots``).
- Bootstrap installer binary at root: ``apps/bootstrap-installer/src-tauri/src/paths.rs:110-116``
  and ``apps/bootstrap-installer/src-tauri/src/bootstrap.rs:901`` (``hermes-setup``,
  ``hermes-setup.exe``).
- Hermes log locations (the only places the unrotated-log sub-check looks):
  ``<home>/logs/`` (``hermes_logging.py:369``; per-profile homes the same,
  ``hermes_logging.py:710``), ``<home>/disk-cleanup/cleanup.log``
  (``plugins/disk-cleanup/disk_cleanup.py:27-29,59-66``, append-only), ``<home>/skills/.hub/audit.log``
  (``tools/skills_hub.py:65``), and plugin folders (``plugins/``, ``desktop-plugins/``,
  ``plugin-data/``). Rotation-managed names inside ``logs/`` are skipped: ``agent.log``,
  ``errors.log``, ``gateway.log``, ``gui.log`` (``hermes_logging.py:396-401``), ``tool_calls.log``
  (``gateway/run_turn.py:70-71``), ``desktop.log`` (``apps/desktop/electron/main.ts:1355,2037`` with
  ``apps/desktop/electron/log-rotation.ts:15-16,52``). Append-only logs in ``logs/`` with no rotation in
  the source include ``mcp-stderr.log`` (``tools/mcp_tool_config.py:39``) and ``update.log``
  (``hermes_cli/main_dashboard.py:546``).
- Attachments & composer pastes: ``tui_gateway/prompt_attachments.py:110-124``,
  ``apps/desktop/electron/hardening.ts:446-462`` (``<home>/attachments/``), and
  ``apps/desktop/electron/composer-paste.ts:5,18-24`` (``<home>/composer-pastes/``).
- Lockfile conventions: ``hermes_state_repair.py:181,210`` (``.repair.lock``,
  ``.auto-maintenance.lock``), ``hermes_state_dbfile.py:659`` (``.quarantine.lock``),
  ``hermes_cli/backup.py:132,152`` (``.backup.lock``, ``gateway.lock``),
  ``pm/publication.py:173`` (``.install-metadata.json.lock``),
  ``plugins/disk-cleanup/disk_cleanup.py:153`` (``cron/.tick.lock``).
- Cron output cap (DO NOT FLAG): ``cron/jobs.py:3318-3364`` caps ``cron/output/<job>/*.md``
  at ``_CRON_OUTPUT_DEFAULT_KEEP = 50`` per job.
- External skill directories: ``agent/skill_utils.py:402-424`` and
  ``cli-config.yaml.example:1219`` (``skills.external_dirs``).
- Petdex sprite assets: ``hermes_cli/config_defaults.py:970-982`` and
  ``hermes_cli/pets.py:16-112`` (``display.pet.enabled`` defaults to ``False``;
  sprites live under ``<home>/pets/<slug>/``).
- Plugin sources other than folders: pip entry points (``hermes_cli/plugins_discovery.py:72-95``) and
  project plugins (``hermes_cli/plugins_discovery.py:212-216``) are invisible to a home walk, so an
  enabled name with no folder is ``review_suggested``, never ``warning``. Plugins that left core and
  became catalog plugins: ``hermes_cli/left_core_migration.py:454-520`` (``LEFT_CORE``).
- PM tool store root ``<home>/tools`` (``hermes_cli/home_data_layout.py:6``, ``pm/paths.py:71``); the
  ``tools/<name>/cache`` and ``tools/<name>/dl`` layout is NOT in the Hermes source, so those bytes are
  labelled ``cache_in_work_folder``.
- Naming conventions NOT in the Hermes source: top-level ``vendor-skills/`` style clone roots
  (``_VENDOR_SKILL_ROOT_NAMES``) and ``*.parked-*`` plugin folder names; absent means nothing found.
- Profile tombstones & live checks: ``hermes_constants.py:318,327`` and
  ``hermes_cli/profiles.py:2320`` (``profiles/.deleted/<name>``).
"""
from __future__ import annotations

from datetime import datetime, timezone
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Callable, Sequence

from .contract import (
    CLASSIFICATION_INFO,
    CLASSIFICATION_REVIEW,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
    make_component_envelope,
    make_finding,
)
from .facts import DuplicateConfigKeyError, _parse_simple_yaml_mapping
from .fingerprint import CredentialStoreNotOpened, open_checked
from .policy import credential_path
from .write_settings import _has_managed_overlay

# Bounded traversal and metadata-read budgets.
MAX_ENTRIES = 400_000
MAX_SECONDS = 20.0
MAX_METADATA_FILE_BYTES = 256 * 1024  # 256 KiB per metadata file read
MAX_METADATA_READS = 500
MAX_DEPTH = 64
MAX_CONFIG_BYTES = 1024 * 1024  # <profile>/config.yaml read cap (same bound as write_settings)

# Marker default: "read this value from <profile>/config.yaml". Passing ``None`` explicitly still
# means "not supplied" (the dependent check reports could_not_verify).
_FROM_CONFIG: Any = object()

# Thresholds sit above what an ordinary, tidy home accumulates and well below the piles that
# long-running homes collect; they are review prompts, not safety limits.
PROFILE_EXPORTS_THRESHOLD_BYTES = 50 * 1024 * 1024  # 50 MiB: well above one or two small profile exports
LARGE_ARCHIVE_BYTES = 10 * 1024 * 1024  # 10 MiB archive threshold at top-level or backups/
EXPORT_BURST_COUNT = 3  # >= 3 archives/backups written within 60 s window
EXPORT_BURST_WINDOW_SECONDS = 60.0  # a scripted export or backup loop writes several files within seconds
DISABLED_PLUGIN_THRESHOLD_BYTES = 5 * 1024 * 1024  # 5 MiB: above a plain-Python plugin, below one carrying bundled dependencies
REGENERABLE_CACHES_THRESHOLD_BYTES = 20 * 1024 * 1024  # 20 MiB: several times the normal model-catalogue cache size
REQUEST_DUMPS_THRESHOLD_COUNT = 10  # > 10 files: a few dumps from debugging are normal, dozens are leftovers
UNROTATED_LOG_THRESHOLD_BYTES = 500 * 1024  # 500 KiB: far above a log that is rotated or rewritten
BACKUP_PILE_THRESHOLD_COUNT = 20  # > 20 backup-style files: more than any keep-N-backups habit leaves
STALE_LOCK_AGE_SECONDS = 24 * 3600  # 24 hours before the NEWEST regular-file mtime in the home
STALE_LOCKS_THRESHOLD_COUNT = 10  # > 10 stale zero-byte locks: a few can survive crashes, many mean none are cleaned

# Bundled plugin directory keys and manifest names shipped in the Hermes source tree
# (hermes-agent/plugins/**/plugin.yaml and plugins/**/dashboard/manifest.json;
# discovery in hermes_cli/plugins_discovery.py:206-209,269-278).
BUNDLED_PLUGIN_NAMES: frozenset[str] = frozenset({
    "a2a-platform", "actual-provider", "ai-gateway-provider", "alibaba-coding-plan-provider",
    "alibaba-provider", "anthropic-provider", "arcee-provider", "azure-foundry-provider",
    "basic", "bedrock-provider", "bluebubbles-platform", "browser-browser-use",
    "browser-browserbase", "browser-firecrawl", "browser/browser_use", "browser/browserbase",
    "browser/firecrawl", "buzz-platform", "byterover", "chronos", "commandcode-provider",
    "computer_use/cua", "config_backends/remote", "cron_providers/chronos", "cua",
    "custom-provider", "dashboard_auth/basic", "dashboard_auth/drain", "dashboard_auth/nous",
    "dashboard_auth/self_hosted", "dashboard_auth/session_token", "deepinfra",
    "deepinfra-provider", "deepseek-provider", "default", "delegation/default",
    "dingtalk-platform", "discord-platform", "disk-cleanup", "drain", "email-platform",
    "fal", "feishu-platform", "fireworks-provider", "gemini-provider", "gmi-provider",
    "google_chat-platform", "google_meet", "hermes-achievements", "huggingface-provider",
    "image_gen/deepinfra", "image_gen/fal", "image_gen/krea", "image_gen/meta-ai",
    "image_gen/openai", "image_gen/openai-codex", "image_gen/openrouter", "image_gen/xai",
    "irc-platform", "kanban", "kilocode-provider", "kimi-coding-provider", "krea",
    "line-platform", "lmstudio-provider", "matrix-platform", "mattermost-platform",
    "memory/byterover", "memory/retaindb", "meta-ai-image-gen", "meta-ai-provider",
    "minimax-provider", "model-providers/actual", "model-providers/ai-gateway",
    "model-providers/alibaba", "model-providers/alibaba-coding-plan",
    "model-providers/anthropic", "model-providers/arcee", "model-providers/azure-foundry",
    "model-providers/bedrock", "model-providers/commandcode", "model-providers/custom",
    "model-providers/deepinfra", "model-providers/deepseek", "model-providers/fireworks",
    "model-providers/gemini", "model-providers/gmi", "model-providers/huggingface",
    "model-providers/kilocode", "model-providers/kimi-coding", "model-providers/lmstudio",
    "model-providers/meta-ai", "model-providers/minimax",
    "model-providers/nebius-token-factory", "model-providers/nous", "model-providers/novita",
    "model-providers/nvidia", "model-providers/ollama-cloud", "model-providers/openai-codex",
    "model-providers/opencode-zen", "model-providers/openrouter", "model-providers/qwen-oauth",
    "model-providers/router", "model-providers/solstice", "model-providers/stepfun",
    "model-providers/tencent-tokenhub", "model-providers/upstage", "model-providers/vertex",
    "model-providers/xai", "model-providers/xiaomi", "model-providers/zai",
    "nebius-token-factory-provider", "nous", "nous-provider", "novita-provider",
    "ntfy-platform", "nvidia-provider", "ollama-cloud-provider", "openai", "openai-codex",
    "openai-codex-provider", "opencode-zen-provider", "openrouter", "openrouter-provider",
    "photon-platform", "platforms/a2a", "platforms/bluebubbles", "platforms/buzz",
    "platforms/dingtalk", "platforms/discord", "platforms/email", "platforms/feishu",
    "platforms/google_chat", "platforms/irc", "platforms/line", "platforms/matrix",
    "platforms/mattermost", "platforms/ntfy", "platforms/photon", "platforms/qqbot",
    "platforms/raft", "platforms/signal", "platforms/simplex", "platforms/slack",
    "platforms/sms", "platforms/teams", "platforms/telegram", "platforms/wecom",
    "platforms/weixin", "platforms/whatsapp", "platforms/whatsapp_cloud", "platforms/yuanbao",
    "qqbot-platform", "qwen-oauth-provider", "raft-platform", "remote", "retaindb",
    "router-provider", "security-guidance", "self-hosted", "session-token", "signal-platform",
    "simplex-platform", "slack-platform", "sms-platform", "solstice-provider",
    "stepfun-provider", "teams-platform", "teams_pipeline", "telegram-platform",
    "tencent-tokenhub-provider", "upstage-provider", "vertex-provider", "video_gen/deepinfra",
    "video_gen/fal", "video_gen/openrouter", "video_gen/xai", "web-brave-free", "web-ddgs",
    "web-exa", "web-firecrawl", "web-keenable", "web-openai-native", "web-parallel",
    "web-perplexity", "web-searxng", "web-tavily", "web-xai", "web/brave_free", "web/ddgs",
    "web/exa", "web/firecrawl", "web/keenable", "web/openai_native", "web/parallel",
    "web/perplexity", "web/searxng", "web/tavily", "web/xai", "wecom-platform",
    "weixin-platform", "whatsapp-platform", "whatsapp_cloud-platform", "xai", "xai-provider",
    "xiaomi-provider", "yuanbao-platform", "zai-provider",
})

# Plugins that left core for the catalog (hermes_cli/left_core_migration.py:454-520: ``plugin=`` and
# ``plugin_key=`` values). A home from before the move can list them in plugins.enabled with no folder;
# they are reported separately and never counted as missing.
LEFT_CORE_PLUGIN_NAMES: frozenset[str] = frozenset({
    "homeassistant", "spotify", "langfuse", "observability/langfuse", "mcp-serve", "camofox",
    "singularity", "agent-importers", "github-copilot",
})

# Rotation-managed log file names directly inside a Hermes ``logs/`` directory: hermes_logging.py:396-401
# (agent/errors/gateway/gui), gateway/run_turn.py:70-71 (tool_calls), apps/desktop/electron/main.ts:1355,2037
# with log-rotation.ts:15-16,52 (desktop). Below their size cap no rotated sibling exists yet, so a missing
# ``.1`` proves nothing for them; they are skipped, not counted.
ROTATION_MANAGED_LOG_NAMES: frozenset[str] = frozenset({
    "agent.log", "errors.log", "gateway.log", "gui.log", "tool_calls.log", "desktop.log",
})

# Label for tools/<name>/cache and tools/<name>/dl bytes: tools/ is the PM store root
# (hermes_cli/home_data_layout.py:6, pm/paths.py:71) but the <name>/cache layout is not in the source.
TOOL_CACHE_LABEL = "cache_in_work_folder"

# Label for counts that rest on file or folder NAME patterns the Hermes source does not define:
# parked-style plugin folder names (``*.parked-*``, ``*.bak``, ``*.old``, ``*-backup`` ...; only
# ``.previous-<uuid>`` comes from pm/publication.py:185) and backup-style file names (``*.bak``,
# ``*.orig``, ``*~`` ...; only ``backups/config/`` comes from hermes_cli/config_backups.py:21-27).
NAME_PATTERN_LABEL = "name_pattern_not_in_hermes_source"

# Stale-lock age reference (deterministic, data-relative).
STALE_LOCK_REFERENCE = "newest_mtime_in_home"

_PLUGIN_ROOT_DIRS: frozenset[str] = frozenset({"plugins", "desktop-plugins", "plugin-data"})


# Fixed labels for the Hermes log location of an unrotated log (reported instead of its path).
LOG_LOCATION_LABELS: tuple[str, ...] = ("logs_folder", "disk_cleanup_log", "skills_hub_audit_log", "plugin_folder")


def _log_location_label(prof_rel: Sequence[str]) -> str:
    if prof_rel[0] == "logs":
        return "logs_folder"
    if prof_rel[0] in _PLUGIN_ROOT_DIRS:
        return "plugin_folder"
    if prof_rel[0] == "disk-cleanup":
        return "disk_cleanup_log"
    return "skills_hub_audit_log"


def _in_hermes_log_location(prof_rel: Sequence[str]) -> bool:
    """True for Hermes's own log locations (see module docstring); work folders are excluded."""
    if not prof_rel:
        return False
    if prof_rel[0] == "logs" or prof_rel[0] in _PLUGIN_ROOT_DIRS:
        return True
    return tuple(prof_rel) in (("disk-cleanup", "cleanup.log"), ("skills", ".hub", "audit.log"))

# Category subdirectories under plugins/ (hermes_cli/plugins_discovery.py:144-187,208-209).
_PLUGIN_CATEGORY_DIRS: frozenset[str] = frozenset({
    "browser", "computer_use", "config_backends", "context_engine", "cron_providers",
    "dashboard_auth", "delegation", "image_gen", "memory", "model-providers",
    "platforms", "video_gen", "web",
})

# Foreign harness directories skipped by plugin discovery (hermes_cli/plugins_discovery.py:35-37).
_SKIPPED_PLUGIN_DIRS: frozenset[str] = frozenset({
    ".claude-plugin", ".codex-plugin", ".cursor-plugin", ".devin-plugin", ".kimi-plugin",
    ".git", ".github", ".pytest_cache", "__pycache__",
})

# Candidate top-level directories holding external/vendor skill clones.
_VENDOR_SKILL_ROOT_NAMES: frozenset[str] = frozenset({
    "vendor-skills", "vendor_skills", "external-skills", "third-party-skills",
})

# Dead-weight classes in deterministic report order.
DEAD_WEIGHT_CLASSES: tuple[str, ...] = (
    "exports_and_archives",
    "parked_and_disabled_plugins",
    "plugin_dev_residue",
    "orphan_plugin_data",
    "regenerable_caches",
    "request_dumps",
    "unrotated_logs",
    "backup_files",
    "unreferenced_skill_clones",
    "feature_off_assets",
)

FINDING_CONSEQUENCES: dict[str, str] = {
    "dead_stores.profile_exports": (
        "Profile export and backup archive files total more than 50 MiB; byte counts and write-time"
        " bursts measure archive files on disk and do not show whether another copy exists or whether the files"
        " are still needed."
    ),
    "dead_stores.parked_or_disabled_plugins": (
        "Plugin folders with parked-style names, or not enabled in plugins.enabled, are on disk; parked-style"
        " folder names other than .previous- are not defined by the Hermes source, and byte and declared-hook"
        " counts measure files and manifest entries and do not show whether these plugins were ever loaded."
    ),
    "dead_stores.enabled_plugin_missing": (
        "Names in plugins.enabled matched no bundled plugin and no plugin folder with a manifest in this"
        " home; this compares configuration with disk and does not prove the plugin is unavailable, because"
        " entry-point plugins and plugins outside the home are not visible to this check."
    ),
    "dead_stores.orphan_plugin_data": (
        "Folders under plugin-data match no plugin folder, enabled name, or bundled plugin in this home;"
        " byte counts measure stored plugin state and do not show whether it will be used again."
    ),
    "dead_stores.regenerable_caches": (
        "Index, model-catalog, media, tool and installer cache files total more than 20 MiB; sizes measure"
        " files on disk and do not show whether they will be needed again or what a rebuild would cost."
    ),
    "dead_stores.request_dumps": (
        "More than 10 request_dump files from failed API requests are in sessions folders; counts and"
        " sizes measure files on disk and do not show the cause of those failures or any current fault."
    ),
    "dead_stores.unrotated_logs": (
        "Log files over 500 KiB in Hermes log locations, excluding logs Hermes rotates and files with a"
        " rotated sibling, were found; sizes measure those files on disk and do not show errors or a current fault."
    ),
    "dead_stores.backup_file_pile": (
        "More than 20 backup-style files were found across the home; backup-style name patterns outside"
        " backups/config are not defined by the Hermes source, counts and sizes come from file names and sizes"
        " only, credential-named files are counted and never opened, and this does not show whether any copy is"
        " still needed."
    ),
    "dead_stores.stale_locks": (
        "More than 10 zero-byte .lock files have a modification time over 24 hours before the newest file"
        " in the home; this measures file timestamps and does not show whether any process holds or waits on a lock."
    ),
    "dead_stores.unreferenced_skill_clones": (
        "Folders under a top-level vendor-skills style directory are not listed in skills.external_dirs;"
        " byte counts measure files on disk and do not show whether anything outside Hermes uses them."
    ),
    "dead_stores.feature_off_assets": (
        "Pet sprite files are on disk under pets while display.pet.enabled is false; byte counts measure"
        " those files and do not show a configuration error."
    ),
    "dead_stores.summary": (
        "Dead-store classes were measured across the home; class totals and home share are file sizes on"
        " disk that overlap bytes counted by other sections, must not be added to other sections' totals, and do"
        " not by themselves make any file safe to delete."
    ),
    "dead_stores.could_not_verify": (
        "One or more dead-store sub-checks could not be verified because a configuration value was not"
        " supplied, the home could not be read, or a traversal budget was reached; unverified checks are not"
        " reported as clean."
    ),
}

_CRED_NAME_RE = re.compile(
    r"(?i)(?:^\.env(?:\.|$|-|_)|^auth\.json(?:\.|$|-|_)|"
    r"(?:^|[_.-])(?:token|secret|credential|password|passwd|api[_-]?key|private[_-]?key)s?(?:$|[_.-])|"
    r"\.(?:pem|key|p12|pfx)(?:\.|$|-|_)|^id_(?:rsa|ed25519|ecdsa|dsa)(?:\.|$|-|_))"
)
_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.xz", ".zip")
_EXECUTABLE_MAGICS = (
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
    b"MZ",
)


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _is_archive_name(name: str) -> bool:
    low = name.lower()
    return any(low.endswith(sfx) for sfx in _ARCHIVE_SUFFIXES)


def _is_parked_plugin_dir_name(name: str) -> bool:
    low = name.lower()
    return (
        ".parked-" in low
        or low.endswith(".parked")
        or low.endswith(".bak")
        or ".bak-" in low
        or ".bak." in low
        or low.endswith(".old")
        or ".old-" in low
        or "-backup" in low
        or ".backup" in low
        or low.startswith(".previous-")
    )


def _is_backup_filename(name: str) -> bool:
    low = name.lower()
    return (
        low.endswith(".bak")
        or ".bak-" in low
        or ".bak." in low
        or ".pre-" in low
        or low.endswith(".before")
        or low.endswith(".orig")
        or low.endswith("~")
        or (low.startswith(".env.") and "backup" in low)
    )


def _is_credential_filename(name: str) -> bool:
    if _CRED_NAME_RE.search(name):
        return True
    return bool(credential_path(Path(name)))


def _abs_item_path(real_root: str, parts: Sequence[str]) -> str | None:
    """Absolute path of an existing item in the home, for the report's path rule.

    The evidence serializer keeps a string only if it is vocabulary or an absolute path that resolves
    to an existing item; anything else becomes a per-run token. ``real_root`` is the resolved home, so
    the value is already in the serializer's resolved form. Credential-named components get no path.
    """
    if any(_is_credential_filename(p) for p in parts):
        return None
    candidate = os.path.join(real_root, *parts)
    if credential_path(Path(candidate)):
        return None
    return candidate


def _burst_stats(mtimes: Sequence[float], window: float = EXPORT_BURST_WINDOW_SECONDS) -> tuple[int, float | None]:
    """Return (max_count_in_window, span_seconds) if >= EXPORT_BURST_COUNT files fall within `window` seconds."""
    if len(mtimes) < EXPORT_BURST_COUNT:
        return 0, None
    sorted_t = sorted(mtimes)
    best_count = 0
    best_span: float | None = None
    j = 0
    for i, start_t in enumerate(sorted_t):
        while j < len(sorted_t) and sorted_t[j] - start_t <= window:
            j += 1
        count = j - i
        if count >= EXPORT_BURST_COUNT:
            span = round(max(0.0, sorted_t[j - 1] - start_t), 3)
            if count > best_count or (count == best_count and (best_span is None or span < best_span)):
                best_count = count
                best_span = span
    return best_count, best_span


def _year_month_utc(mtime: float | None) -> tuple[int | None, int | None]:
    """UTC (year, month) of an mtime as integers; (None, None) when unknown."""
    if mtime is None or not math.isfinite(mtime) or mtime <= 0:
        return None, None
    try:
        dt = datetime.fromtimestamp(mtime, timezone.utc)
        return dt.year, dt.month
    except (ValueError, OSError, OverflowError):
        return None, None


def _oldest_fields(mtime: float | None) -> dict[str, int | None]:
    year, month = _year_month_utc(mtime)
    return {"oldest_year": year, "oldest_month": month}


def _validate_str_list(val: Any) -> list[str] | None:
    if val is None or isinstance(val, (str, bytes)):
        return None
    if not isinstance(val, (list, tuple, set, frozenset)):
        return None
    out: list[str] = []
    for item in val:
        if not isinstance(item, str):
            return None
        s = item.strip()
        if s:
            out.append(s)
    return out


def _read_bounded_regular_bytes(
    root: Path,
    rel_parts: Sequence[str],
    max_bytes: int,
) -> tuple[bytes | None, str | None]:
    """Safely read up to `max_bytes` from a non-credential regular file below `root` without following symlinks."""
    candidate = root.joinpath(*rel_parts)
    if credential_path(candidate) or _is_credential_filename(candidate.name):
        return None, "credential_excluded"
    o_nofollow = getattr(os, "O_NOFOLLOW", 0)
    o_nonblock = getattr(os, "O_NONBLOCK", 0)
    o_directory = getattr(os, "O_DIRECTORY", 0)
    fd_stack: list[int] = []
    try:
        cur_fd = os.open(str(root), os.O_RDONLY | o_nofollow | o_nonblock | o_directory)
        fd_stack.append(cur_fd)
        for part in rel_parts[:-1]:
            st_dir = os.stat(part, dir_fd=cur_fd, follow_symlinks=False)
            if stat.S_ISLNK(st_dir.st_mode) or not stat.S_ISDIR(st_dir.st_mode):
                return None, "unsafe_path"
            next_fd = os.open(part, os.O_RDONLY | o_nofollow | o_nonblock | o_directory, dir_fd=cur_fd)
            fd_stack.append(next_fd)
            cur_fd = next_fd
        leaf = rel_parts[-1]
        st_leaf = os.stat(leaf, dir_fd=cur_fd, follow_symlinks=False)
        if stat.S_ISLNK(st_leaf.st_mode) or not stat.S_ISREG(st_leaf.st_mode):
            return None, "not_regular"
        try:
            file_fd = open_checked(leaf, os.O_RDONLY | o_nofollow | o_nonblock, dir_fd=cur_fd,
                                   full_path=os.path.abspath(candidate))
        except CredentialStoreNotOpened:
            return None, "credential_excluded"
        try:
            st_open = os.fstat(file_fd)
            if not stat.S_ISREG(st_open.st_mode) or (st_open.st_dev, st_open.st_ino) != (st_leaf.st_dev, st_leaf.st_ino):
                return None, "changed_on_open"
            chunks: list[bytes] = []
            remaining = max_bytes
            while remaining > 0:
                chunk = os.read(file_fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks), None
        finally:
            os.close(file_fd)
    except OSError:
        return None, "read_error"
    finally:
        for fd in reversed(fd_stack):
            try:
                os.close(fd)
            except OSError:
                pass


def _config_inputs(root: Path, managed_dir: Path | str | None) -> tuple[dict[str, Any], set[str]]:
    """Read the four configuration inputs from ``<root>/config.yaml`` (bounded, no symlinks).

    Keys: ``plugins.enabled``, ``plugins.disabled``, ``skills.external_dirs``, ``display.pet.enabled``.
    A missing file means Hermes defaults (``hermes_cli/config_defaults.py``: ``display.pet.enabled``
    False, ``skills.external_dirs`` []; ``plugins.enabled``/``disabled`` are omitted from the defaults so
    an absent list is empty). An unreadable or unparsable file, or an active managed scope
    (``hermes_cli/managed_scope.py``, which overrides user config), makes every value unverified
    (``None``). Values are returned raw; the caller's validation rejects wrong types.
    """
    unverified: set[str] = set()
    none_values: dict[str, Any] = {
        "enabled_plugins": None, "disabled_plugins": None, "external_skill_dirs": None, "pet_enabled": None,
    }
    if _has_managed_overlay(managed_dir):
        unverified.add("managed_config_overlay")
        return none_values, unverified
    config: Any = {}
    try:
        st_cfg = os.lstat(root / "config.yaml")
    except FileNotFoundError:
        st_cfg = None
    except OSError:
        unverified.add("config_unreadable")
        return none_values, unverified
    if st_cfg is not None:
        raw, err = (
            _read_bounded_regular_bytes(root, ("config.yaml",), MAX_CONFIG_BYTES + 1)
            if stat.S_ISREG(st_cfg.st_mode) else (None, "not_regular")
        )
        if err is not None or raw is None or len(raw) > MAX_CONFIG_BYTES:
            unverified.add("config_unreadable")
            return none_values, unverified
        try:
            config = _parse_simple_yaml_mapping(raw.decode("utf-8-sig"), reject_duplicate_keys=True)
        except (DuplicateConfigKeyError, UnicodeError, ValueError, RecursionError):
            unverified.add("config_unreadable")
            return none_values, unverified
        if config is None:
            config = {}
        if not isinstance(config, dict):
            unverified.add("config_unreadable")
            return none_values, unverified

    def section(mapping: Any, key: str) -> Any:
        value = mapping.get(key) if isinstance(mapping, dict) else _FROM_CONFIG
        if value is None:
            return {}
        return value if isinstance(value, dict) else _FROM_CONFIG  # _FROM_CONFIG = malformed here

    plugins = section(config, "plugins")
    skills = section(config, "skills")
    pet = section(section(config, "display"), "pet")
    out: dict[str, Any] = {}
    out["enabled_plugins"] = plugins.get("enabled", []) if isinstance(plugins, dict) else None
    out["disabled_plugins"] = plugins.get("disabled", []) if isinstance(plugins, dict) else 0
    ext = skills.get("external_dirs", []) if isinstance(skills, dict) else None
    if isinstance(ext, list) and any(isinstance(e, str) and "${" in e for e in ext):
        ext = None  # Hermes expands ${VAR} in its own environment; not resolvable here
    out["external_skill_dirs"] = ext
    out["pet_enabled"] = pet.get("enabled", False) if isinstance(pet, dict) else None
    return out, unverified


def _normalize_inputs(
    enabled_plugins: Any, disabled_plugins: Any, external_skill_dirs: Any, pet_enabled: Any,
) -> tuple[list[str] | None, list[str] | None, list[str] | None, bool | None, set[str]]:
    enabled_norm = _validate_str_list(enabled_plugins)
    disabled_norm = _validate_str_list(disabled_plugins) if disabled_plugins is not None else []
    ext_skills_norm = _validate_str_list(external_skill_dirs)
    pet_norm = pet_enabled if type(pet_enabled) is bool else None
    unverified: set[str] = set()
    if enabled_norm is None:
        unverified.add("enabled_plugins")
    if disabled_plugins is not None and disabled_norm is None:
        unverified.add("enabled_plugins")
    if ext_skills_norm is None:
        unverified.add("external_skill_dirs")
    if pet_norm is None:
        unverified.add("pet_enabled")
    return enabled_norm, disabled_norm, ext_skills_norm, pet_norm, unverified


def _finding(
    rule_id: str,
    rel_source: str,
    evidence: dict[str, Any],
    *,
    classification: str = CLASSIFICATION_REVIEW,
    coverage: str = COVERAGE_VERIFIED,
) -> dict[str, Any]:
    return make_finding(
        rule_id=rule_id,
        classification=classification,
        coverage=coverage,
        affected_identities=[rel_source],
        source_paths=[rel_source],
        evidence=evidence,
        consequence=FINDING_CONSEQUENCES[rule_id],
    )


def _envelope(
    findings: Sequence[dict[str, Any]],
    coverage: str,
    section: dict[str, Any],
    run_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return exactly ``dead_stores``, ``findings``, ``run_metrics``, ``status`` and ``coverage``.

    ``run_metrics`` holds values that depend on the wall clock (``now``); it is a sibling of the
    section so the fingerprinted report never contains it. ``adapt_component_result`` copies it through.
    """
    env = make_component_envelope(findings=findings, coverage=coverage)
    return {
        "dead_stores": section,
        "findings": env["findings"],
        "run_metrics": run_metrics if run_metrics is not None else {"stale_locks_vs_now_count": None},
        "status": env["status"],
        "coverage": env["coverage"],
    }


def _empty_section(
    *,
    status: str,
    coverage: str,
    reason: str | None,
    truncated_by: str | None,
    pet_enabled_norm: bool | None,
    unverified_checks: Sequence[str],
    entries_walked: int = 0,
    metadata_reads: int = 0,
    metadata_bytes_read: int = 0,
    symlinks_skipped: int = 0,
    cuts: int = 0,
) -> dict[str, Any]:
    return {
        "status": status,
        "coverage": coverage,
        "reason": reason,
        "truncated_by": truncated_by,
        "overlaps_other_sections": True,
        "total_home_bytes": 0,
        "total_home_files": 0,
        "total_dead_weight_bytes": 0,
        "dead_weight_share_of_home": 0.0,
        "dead_weight_by_class": {k: 0 for k in DEAD_WEIGHT_CLASSES},
        "exports_and_archives": {
            "profile_exports_count": 0,
            "profile_exports_bytes": 0,
            "large_archives_count": 0,
            "large_archives_bytes": 0,
            "total_bytes": 0,
            "burst_count": 0,
            "burst_span_seconds": None,
        },
        "plugins": {
            "coverage": COVERAGE_VERIFIED if "enabled_plugins" not in unverified_checks else COVERAGE_COULD_NOT_VERIFY,
            "parked_copies": [],
            "parked_count": 0,
            "parked_name_label": NAME_PATTERN_LABEL,
            "parked_bytes": 0,
            "disabled_on_disk": [],
            "disabled_count": 0,
            "disabled_bytes": 0,
            "disabled_hooks_declared": 0,
            "enabled_missing": [],
            "enabled_missing_count": 0,
            "enabled_symlinked_count": 0,
            "enabled_moved_out_of_core": [],
            "enabled_moved_out_of_core_count": 0,
            "dev_residue": {
                "git_bytes": 0,
                "pycache_bytes": 0,
                "tests_bytes": 0,
                "node_modules_bytes": 0,
                "total_bytes": 0,
                "active_plugin_residue_bytes": 0,
                "by_plugin": [],
            },
        },
        "orphan_plugin_data": {
            "orphans": [],
            "count": 0,
            "total_bytes": 0,
        },
        "regenerable_caches": {
            "hub_index_cache_bytes": 0,
            "hub_index_cache_count": 0,
            "models_dev_cache_bytes": 0,
            "provider_models_cache_bytes": 0,
            "image_cache_bytes": 0,
            "audio_cache_bytes": 0,
            "document_cache_bytes": 0,
            "other_media_cache_bytes": 0,
            "tool_cache_bytes": 0,
            "tool_cache_label": TOOL_CACHE_LABEL,
            "installer_binaries_bytes": 0,
            "installer_binaries_count": 0,
            "total_bytes": 0,
        },
        "growing_piles": {
            "request_dumps": {"count": 0, "bytes": 0},
            "unrotated_logs": {
                "count": 0,
                "bytes": 0,
                "files": [],
                "rotation_managed_skipped_count": 0,
                "outside_hermes_log_locations_count": 0,
                "outside_hermes_log_locations_bytes": 0,
            },
            "attachments": {"count": 0, "bytes": 0, "oldest_year": None, "oldest_month": None},
            "composer_pastes": {"count": 0, "bytes": 0, "oldest_year": None, "oldest_month": None},
            "backup_files": {
                "count": 0,
                "bytes": 0,
                "cred_named_count": 0,
                "cred_named_bytes": 0,
                "config_backup_count": 0,
                "config_backup_bytes": 0,
                "config_backup_burst_count": 0,
                "name_pattern_label": NAME_PATTERN_LABEL,
            },
            "empty_profile_dirs_count": 0,
            "deleted_profile_tombstones_count": 0,
        },
        "stale_locks": {
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "reference": STALE_LOCK_REFERENCE,
            "count": 0,
            "young_or_nonempty_ignored_count": 0,
        },
        "unreferenced_skill_clones": {
            "coverage": COVERAGE_VERIFIED if "external_skill_dirs" not in unverified_checks else COVERAGE_COULD_NOT_VERIFY,
            "clones": [],
            "count": 0,
            "total_bytes": 0,
        },
        "feature_off_assets": {
            "coverage": COVERAGE_VERIFIED if "pet_enabled" not in unverified_checks else COVERAGE_COULD_NOT_VERIFY,
            "pet_enabled": pet_enabled_norm,
            "pets_bytes": 0,
            "pets_file_count": 0,
            "total_bytes": 0,
        },
        "unverified_checks": sorted(set(unverified_checks)),
        "limits": {
            "max_entries": MAX_ENTRIES,
            "max_seconds": MAX_SECONDS,
            "max_metadata_file_bytes": MAX_METADATA_FILE_BYTES,
            "max_metadata_reads": MAX_METADATA_READS,
            "max_depth": MAX_DEPTH,
            "entries_walked": entries_walked,
            "metadata_reads": metadata_reads,
            "metadata_bytes_read": metadata_bytes_read,
            "symlinks_skipped": symlinks_skipped,
            "cuts": cuts,
        },
        "thresholds": {
            "profile_exports_bytes": PROFILE_EXPORTS_THRESHOLD_BYTES,
            "large_archive_bytes": LARGE_ARCHIVE_BYTES,
            "burst_count": EXPORT_BURST_COUNT,
            "burst_window_seconds": EXPORT_BURST_WINDOW_SECONDS,
            "disabled_plugin_bytes": DISABLED_PLUGIN_THRESHOLD_BYTES,
            "regenerable_caches_bytes": REGENERABLE_CACHES_THRESHOLD_BYTES,
            "request_dumps_count": REQUEST_DUMPS_THRESHOLD_COUNT,
            "unrotated_log_bytes": UNROTATED_LOG_THRESHOLD_BYTES,
            "backup_pile_count": BACKUP_PILE_THRESHOLD_COUNT,
            "stale_lock_age_seconds": STALE_LOCK_AGE_SECONDS,
            "stale_locks_count": STALE_LOCKS_THRESHOLD_COUNT,
        },
    }


def _unmeasured_root(
    reason: str,
    pet_norm: bool | None,
    unverified_checks: set[str],
    *,
    symlinks_skipped: int = 0,
) -> dict[str, Any]:
    """Build the common not-measured result for an unusable home root."""
    sec = _empty_section(
        status="not_measured",
        coverage=COVERAGE_COULD_NOT_VERIFY,
        reason=reason,
        truncated_by=None,
        pet_enabled_norm=pet_norm,
        unverified_checks=sorted(unverified_checks),
        symlinks_skipped=symlinks_skipped,
        cuts=1,
    )
    f = _finding(
        "dead_stores.could_not_verify",
        ".",
        {"cuts": 1, "unverified_count": len(sec["unverified_checks"])},
        classification=CLASSIFICATION_INFO,
        coverage=COVERAGE_COULD_NOT_VERIFY,
    )
    return _envelope([f], COVERAGE_COULD_NOT_VERIFY, sec)


def audit_dead_stores(
    profile_path: Path | str,
    *,
    enabled_plugins: Sequence[str] | None = _FROM_CONFIG,
    disabled_plugins: Sequence[str] | None = _FROM_CONFIG,
    external_skill_dirs: Sequence[str] | None = _FROM_CONFIG,
    pet_enabled: bool | None = _FROM_CONFIG,
    now: float | int | None = None,
    clock: Callable[[], float] = time.monotonic,
    managed_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Measure dead stores and regenerable caches in a Hermes home in a single lstat walk.

    Configuration inputs left at their default are read from ``<profile_path>/config.yaml``
    (see ``_config_inputs``); an explicit argument, including ``None``, wins over the file.
    """
    supplied: dict[str, Any] = {
        "enabled_plugins": enabled_plugins,
        "disabled_plugins": disabled_plugins,
        "external_skill_dirs": external_skill_dirs,
        "pet_enabled": pet_enabled,
    }
    pre = {k: (None if v is _FROM_CONFIG else v) for k, v in supplied.items()}
    enabled_norm, disabled_norm, ext_skills_norm, pet_norm, unverified_checks = _normalize_inputs(
        pre["enabled_plugins"], pre["disabled_plugins"], pre["external_skill_dirs"], pre["pet_enabled"],
    )

    # ``now`` never changes the section: stale-lock age is measured against the newest regular-file
    # mtime in the home (deterministic; a backup is judged as of when it was taken). A supplied ``now``
    # only feeds the envelope's top-level ``run_metrics.stale_locks_vs_now_count``.
    now_val: float | None = (
        float(now) if type(now) in (int, float) and math.isfinite(float(now)) else None
    )


    try:
        root = Path(os.path.abspath(os.path.expanduser(os.fspath(profile_path))))
        st_root = os.lstat(root)
    except FileNotFoundError:
        unverified_checks.add("root_missing")
        return _unmeasured_root("missing", pet_norm, unverified_checks)
    except (OSError, TypeError, ValueError):
        unverified_checks.add("root_unreadable")
        return _unmeasured_root("unreadable", pet_norm, unverified_checks)

    if stat.S_ISLNK(st_root.st_mode):
        unverified_checks.add("root_symlink")
        return _unmeasured_root("symlink_root", pet_norm, unverified_checks, symlinks_skipped=1)

    if not stat.S_ISDIR(st_root.st_mode):
        unverified_checks.add("root_not_directory")
        return _unmeasured_root("not_directory", pet_norm, unverified_checks)

    real_root = os.path.realpath(root)

    if any(v is _FROM_CONFIG for v in supplied.values()):
        from_config, config_unverified = _config_inputs(root, managed_dir)
        resolved = {k: (from_config[k] if v is _FROM_CONFIG else v) for k, v in supplied.items()}
        enabled_norm, disabled_norm, ext_skills_norm, pet_norm, unverified_checks = _normalize_inputs(
            resolved["enabled_plugins"], resolved["disabled_plugins"],
            resolved["external_skill_dirs"], resolved["pet_enabled"],
        )
        unverified_checks |= config_unverified

    deadline = clock() + MAX_SECONDS
    entries_walked = 0
    metadata_reads = 0
    metadata_bytes_read = 0
    symlinks_skipped = 0
    cuts = 0
    truncated_by: str | None = None

    def note_truncation(kind: str) -> None:
        nonlocal cuts, truncated_by
        cuts += 1
        if truncated_by is None:
            truncated_by = kind
        unverified_checks.add("walk_truncated")

    def is_expired() -> bool:
        if clock() >= deadline:
            note_truncation("time_budget")
            return True
        return False

    # Accumulators across the single walk
    total_home_bytes = 0
    total_home_files = 0
    dead_weight_by_class: dict[str, int] = {k: 0 for k in DEAD_WEIGHT_CLASSES}

    # (a) Exports and archives
    profile_exports_count = 0
    profile_exports_bytes = 0
    large_archives_count = 0
    large_archives_bytes = 0
    export_mtimes: list[float] = []

    # (b) Plugins on disk
    # Keyed by (source_dir, plugin_key) where source_dir in {"plugins", "desktop-plugins"}
    plugin_dirs_seen: dict[tuple[str, str], dict[str, Any]] = {}
    enabled_set = (set(enabled_norm) - set(disabled_norm or ())) if enabled_norm is not None else set()

    # (c) Orphan plugin data
    plugin_data_dirs: dict[str, dict[str, int]] = {}

    # (d) Regenerable caches
    hub_index_cache_bytes = 0
    hub_index_dirs_seen: set[str] = set()
    models_dev_cache_bytes = 0
    provider_models_cache_bytes = 0
    image_cache_bytes = 0
    audio_cache_bytes = 0
    document_cache_bytes = 0
    other_media_cache_bytes = 0
    tool_cache_bytes = 0
    installer_binaries_count = 0
    installer_binaries_bytes = 0
    installer_candidates: list[tuple[str, int]] = []

    # (e) Growing piles
    request_dumps_count = 0
    request_dumps_bytes = 0
    unrotated_logs: list[dict[str, Any]] = []
    unrotated_logs_bytes = 0
    rotation_managed_skipped_count = 0
    outside_log_locations_count = 0
    outside_log_locations_bytes = 0
    attachments_count = 0
    attachments_bytes = 0
    attachments_min_mtime: float | None = None
    composer_pastes_count = 0
    composer_pastes_bytes = 0
    composer_pastes_min_mtime: float | None = None
    backup_files_count = 0
    backup_files_bytes = 0
    cred_named_count = 0
    cred_named_bytes = 0
    config_backup_count = 0
    config_backup_bytes = 0
    config_backup_mtimes: list[float] = []
    named_profile_file_counts: dict[str, int] = {}
    deleted_profile_tombstones_count = 0

    # (f) Stale locks
    stale_locks_count = 0
    young_or_nonempty_locks_count = 0
    nonempty_locks_count = 0
    zero_lock_mtimes: list[float] = []
    newest_mtime: float | None = None
    plugin_symlink_names: set[str] = set()

    # (g) Unreferenced skill clones
    skill_clone_dirs: dict[str, dict[str, int]] = {}

    # (h) Feature-off assets
    pets_bytes = 0
    pets_file_count = 0

    def ensure_plugin_record(source_dir: str, pkey: str) -> dict[str, Any]:
        rec = plugin_dirs_seen.get((source_dir, pkey))
        if rec is None:
            rec = {
                "name": pkey,
                "source_dir": source_dir,
                "bytes": 0,
                "file_count": 0,
                "is_parked": _is_parked_plugin_dir_name(pkey.rsplit("/", 1)[-1]),
                "has_yaml": False,
                "yaml_rel_parts": None,
                "yaml_size": 0,
                "yaml_is_symlink": False,
                "has_other_manifest": False,
                "has_package_marker": False,
                "git_bytes": 0,
                "pycache_bytes": 0,
                "tests_bytes": 0,
                "node_modules_bytes": 0,
            }
            plugin_dirs_seen[(source_dir, pkey)] = rec
        return rec

    # Stack of (directory_path, rel_parts_tuple)
    stack: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    while stack:
        if is_expired():
            break
        cur_dir, rel_parts = stack.pop()
        try:
            with os.scandir(cur_dir) as it:
                batch: list[os.DirEntry[str]] = []
                for entry in it:
                    if is_expired():
                        batch = []
                        break
                    entries_walked += 1
                    if entries_walked > MAX_ENTRIES:
                        note_truncation("entry_budget")
                        batch = []
                        break
                    batch.append(entry)
        except OSError:
            if not rel_parts:
                unverified_checks.add("root_unreadable")
                return _unmeasured_root("unreadable", pet_norm, unverified_checks)
            cuts += 1
            unverified_checks.add("unreadable_subdir")
            continue

        if truncated_by is not None:
            break

        batch.sort(key=lambda e: e.name)
        dir_entry_names = {e.name for e in batch if not e.name.startswith("._")}

        for entry in batch:
            name = entry.name
            if _has_surrogate(name):
                cuts += 1
                unverified_checks.add("surrogate_name")
                continue
            if name.startswith("._"):
                continue

            entry_parts = (*rel_parts, name)
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                cuts += 1
                unverified_checks.add("stat_error")
                continue

            mode = st.st_mode
            if stat.S_ISLNK(mode):
                symlinks_skipped += 1
                # A symlinked plugin folder is counted, never followed (reported as ``symlinked``).
                if len(entry_parts) == 2 and entry_parts[0] in ("plugins", "desktop-plugins"):
                    plugin_symlink_names.add(name)
                elif len(entry_parts) == 3 and entry_parts[0] == "plugins" and entry_parts[1] in _PLUGIN_CATEGORY_DIRS:
                    plugin_symlink_names.add(f"{entry_parts[1]}/{name}")
                if len(entry_parts) == 3 and entry_parts[0] == "plugins" and name in ("plugin.yaml", "plugin.yml"):
                    rec = ensure_plugin_record("plugins", entry_parts[1])
                    rec["yaml_is_symlink"] = True
                continue

            if stat.S_ISDIR(mode):
                # Record structural directories even if they turn out to be empty.
                if len(entry_parts) == 2 and entry_parts[0] in ("plugins", "desktop-plugins"):
                    src_d = entry_parts[0]
                    if name not in _SKIPPED_PLUGIN_DIRS and not (name.startswith("__") and name.endswith("__")):
                        if not (src_d == "plugins" and name in _PLUGIN_CATEGORY_DIRS and name not in enabled_set):
                            if not name.startswith(".") or _is_parked_plugin_dir_name(name):
                                ensure_plugin_record(src_d, name)
                elif (
                    len(entry_parts) == 3
                    and entry_parts[0] == "plugins"
                    and entry_parts[1] in _PLUGIN_CATEGORY_DIRS
                    and entry_parts[1] not in enabled_set
                ):
                    if name not in _SKIPPED_PLUGIN_DIRS and not name.startswith("."):
                        ensure_plugin_record("plugins", f"{entry_parts[1]}/{name}")
                elif len(entry_parts) == 2 and entry_parts[0] == "plugin-data" and not name.startswith("."):
                    plugin_data_dirs.setdefault(name, {"bytes": 0, "file_count": 0})
                elif len(entry_parts) == 2 and entry_parts[0] == "profiles":
                    if name != ".deleted" and not name.startswith("."):
                        named_profile_file_counts.setdefault(name, 0)
                elif len(entry_parts) == 3 and entry_parts[:2] == ("profiles", ".deleted"):
                    deleted_profile_tombstones_count += 1
                elif len(entry_parts) == 2 and entry_parts[0] in _VENDOR_SKILL_ROOT_NAMES and not name.startswith("."):
                    skill_clone_dirs.setdefault(f"{entry_parts[0]}/{name}", {"bytes": 0, "file_count": 0})

                if len(entry_parts) > MAX_DEPTH:
                    note_truncation("depth_budget")
                    continue
                stack.append((Path(entry.path), entry_parts))
                continue

            if not stat.S_ISREG(mode):
                continue

            fsize = int(st.st_size)
            fmtime = float(st.st_mtime)
            total_home_bytes += fsize
            total_home_files += 1
            if math.isfinite(fmtime) and (newest_mtime is None or fmtime > newest_mtime):
                newest_mtime = fmtime

            top = entry_parts[0]
            if len(entry_parts) >= 3 and top == "profiles":
                if entry_parts[1] == ".deleted":
                    if len(entry_parts) == 3:
                        deleted_profile_tombstones_count += 1
                elif not entry_parts[1].startswith("."):
                    named_profile_file_counts[entry_parts[1]] = named_profile_file_counts.get(entry_parts[1], 0) + 1

            # Profile-relative parts for caches/attachments/pastes that may also live in profiles/<name>/
            prof_rel = (
                entry_parts[2:]
                if (len(entry_parts) >= 3 and top == "profiles" and entry_parts[1] != ".deleted")
                else entry_parts
            )

            # Track primary dead-weight class for this file so class totals never double-count.
            file_dead_class: str | None = None

            # (a) Exports and archives
            if top == "profile-exports":
                profile_exports_count += 1
                profile_exports_bytes += fsize
                export_mtimes.append(fmtime)
                file_dead_class = "exports_and_archives"
            elif (len(entry_parts) == 1 or top == "backups") and _is_archive_name(name) and fsize > LARGE_ARCHIVE_BYTES:
                large_archives_count += 1
                large_archives_bytes += fsize
                export_mtimes.append(fmtime)
                file_dead_class = "exports_and_archives"

            # (b) Plugins on disk (plugins/ and desktop-plugins/)
            if top in ("plugins", "desktop-plugins") and len(entry_parts) >= 3:
                second = entry_parts[1]
                if (
                    top == "plugins"
                    and second in _PLUGIN_CATEGORY_DIRS
                    and second not in enabled_set
                    and len(entry_parts) >= 4
                ):
                    pkey = f"{second}/{entry_parts[2]}"
                    subparts = entry_parts[3:]
                else:
                    pkey = second
                    subparts = entry_parts[2:]

                if (
                    subparts
                    and pkey not in _SKIPPED_PLUGIN_DIRS
                    and not (pkey.startswith("__") and pkey.endswith("__"))
                    and (not pkey.startswith(".") or _is_parked_plugin_dir_name(pkey))
                ):
                    rec = ensure_plugin_record(top, pkey)
                    rec["bytes"] += fsize
                    rec["file_count"] += 1
                    if subparts in (("plugin.yaml",), ("plugin.yml",)) and not rec["has_yaml"]:
                        rec["has_yaml"] = True
                        rec["yaml_rel_parts"] = entry_parts
                        rec["yaml_size"] = fsize
                    elif subparts in (("plugin.json",), ("dashboard", "manifest.json")) or (
                        top == "desktop-plugins" and subparts == ("plugin.js",)
                    ):
                        rec["has_other_manifest"] = True
                    elif top == "desktop-plugins" and subparts == (".hermes-package.json",):
                        rec["has_package_marker"] = True

                    parent_dirs = set(subparts[:-1])
                    if ".git" in parent_dirs:
                        rec["git_bytes"] += fsize
                    elif "__pycache__" in parent_dirs:
                        rec["pycache_bytes"] += fsize
                    elif "tests" in parent_dirs:
                        rec["tests_bytes"] += fsize
                    elif "node_modules" in parent_dirs:
                        rec["node_modules_bytes"] += fsize

            # (c) Orphan plugin data (plugin-data/<name>/...)
            if top == "plugin-data" and len(entry_parts) >= 3 and not entry_parts[1].startswith("."):
                pdata_rec = plugin_data_dirs.setdefault(entry_parts[1], {"bytes": 0, "file_count": 0})
                pdata_rec["bytes"] += fsize
                pdata_rec["file_count"] += 1

            # (d) Regenerable caches
            is_cache_file = False
            if len(prof_rel) >= 4 and prof_rel[:3] == ("skills", ".hub", "index-cache"):
                hub_index_cache_bytes += fsize
                prefix_len = len(entry_parts) - len(prof_rel) + 3
                hub_index_dirs_seen.add("/".join(entry_parts[:prefix_len]))
                is_cache_file = True
            elif len(prof_rel) == 1 and prof_rel[0] in ("models_dev_cache.json", "models_dev_cache.etag"):
                models_dev_cache_bytes += fsize
                is_cache_file = True
            elif len(prof_rel) == 1 and (
                prof_rel[0] == "provider_models_cache.json"
                or prof_rel[0].endswith("_models_cache.json")
                or (prof_rel[0].startswith(".provider_models_cache") and prof_rel[0].endswith(".tmp"))
            ):
                provider_models_cache_bytes += fsize
                is_cache_file = True
            elif prof_rel[0] == "image_cache" or (len(prof_rel) >= 2 and prof_rel[:2] == ("cache", "images")):
                image_cache_bytes += fsize
                is_cache_file = True
            elif prof_rel[0] == "audio_cache" or (len(prof_rel) >= 2 and prof_rel[:2] == ("cache", "audio")):
                audio_cache_bytes += fsize
                is_cache_file = True
            elif prof_rel[0] == "document_cache" or (len(prof_rel) >= 2 and prof_rel[:2] == ("cache", "documents")):
                document_cache_bytes += fsize
                is_cache_file = True
            elif prof_rel[0] in ("cache", "video_cache", "browser_screenshots", "bootstrap-cache"):
                other_media_cache_bytes += fsize
                is_cache_file = True
            elif len(entry_parts) >= 4 and top == "tools" and (
                entry_parts[2] == "cache" or (entry_parts[2] == "dl" and _is_archive_name(name))
            ):
                tool_cache_bytes += fsize
                is_cache_file = True
            elif len(entry_parts) == 1 and name.startswith("hermes-setup"):
                installer_candidates.append((name, fsize))

            if is_cache_file and file_dead_class is None:
                file_dead_class = "regenerable_caches"

            # (e) Piles that only grow
            # e.1 Request dumps
            if len(prof_rel) == 2 and prof_rel[0] == "sessions" and name.startswith("request_dump_") and name.endswith(".json"):
                request_dumps_count += 1
                request_dumps_bytes += fsize
                if file_dead_class is None:
                    file_dead_class = "request_dumps"

            # e.2 Unrotated logs: > 500 KiB, in a Hermes log location, not rotation-managed, and no
            # name.1 / name.0 / name.1.gz sibling. Work output elsewhere is only tallied as out of scope.
            if name.endswith(".log") and fsize > UNROTATED_LOG_THRESHOLD_BYTES and not _in_hermes_log_location(prof_rel):
                outside_log_locations_count += 1
                outside_log_locations_bytes += fsize
            elif (
                name.endswith(".log")
                and fsize > UNROTATED_LOG_THRESHOLD_BYTES
                and len(prof_rel) == 2
                and prof_rel[0] == "logs"
                and name in ROTATION_MANAGED_LOG_NAMES
            ):
                rotation_managed_skipped_count += 1
            elif name.endswith(".log") and fsize > UNROTATED_LOG_THRESHOLD_BYTES:
                has_rotated_sibling = (
                    f"{name}.1" in dir_entry_names
                    or f"{name}.0" in dir_entry_names
                    or f"{name}.1.gz" in dir_entry_names
                )
                if not has_rotated_sibling:
                    unrotated_logs_bytes += fsize
                    unrotated_logs.append({
                        "log_location": _log_location_label(prof_rel),
                        "in_named_profile": len(prof_rel) != len(entry_parts),
                        "bytes": fsize,
                    })
                    if file_dead_class is None:
                        file_dead_class = "unrotated_logs"

            # e.3 Attachments & composer-pastes
            if prof_rel[0] == "attachments":
                attachments_count += 1
                attachments_bytes += fsize
                if attachments_min_mtime is None or fmtime < attachments_min_mtime:
                    attachments_min_mtime = fmtime
            elif prof_rel[0] == "composer-pastes":
                composer_pastes_count += 1
                composer_pastes_bytes += fsize
                if composer_pastes_min_mtime is None or fmtime < composer_pastes_min_mtime:
                    composer_pastes_min_mtime = fmtime

            # e.4 Backup-style files
            in_config_backups_dir = len(entry_parts) >= 3 and entry_parts[:2] == ("backups", "config")
            is_bak_name = _is_backup_filename(name)
            if in_config_backups_dir or is_bak_name:
                backup_files_count += 1
                backup_files_bytes += fsize
                if _is_credential_filename(name):
                    cred_named_count += 1
                    cred_named_bytes += fsize
                if in_config_backups_dir or (name.startswith("config.yaml.") and is_bak_name):
                    config_backup_count += 1
                    config_backup_bytes += fsize
                    config_backup_mtimes.append(fmtime)
                if file_dead_class is None and top not in ("plugins", "desktop-plugins", "plugin-data"):
                    file_dead_class = "backup_files"

            # (f) Stale locks: zero-byte *.lock; age judged after the walk against newest_mtime.
            if name.endswith(".lock"):
                if fsize == 0 and math.isfinite(fmtime):
                    zero_lock_mtimes.append(fmtime)
                else:
                    nonempty_locks_count += 1

            # (g) Unreferenced skill clones (top-level vendor-skills/ etc.)
            if top in _VENDOR_SKILL_ROOT_NAMES:
                ckey = f"{top}/{entry_parts[1]}" if len(entry_parts) >= 3 else top
                crec = skill_clone_dirs.setdefault(ckey, {"bytes": 0, "file_count": 0})
                crec["bytes"] += fsize
                crec["file_count"] += 1

            # (h) Feature-off assets (pets/)
            if top == "pets":
                pets_bytes += fsize
                pets_file_count += 1

            if file_dead_class is not None:
                dead_weight_by_class[file_dead_class] += fsize

    # Empty home check (audit hygiene rule 10: a missing/empty home returns a not-measured section)
    if entries_walked == 0 and truncated_by is None:
        cov = COVERAGE_COULD_NOT_VERIFY if unverified_checks else COVERAGE_VERIFIED
        sec = _empty_section(
            status="not_measured",
            coverage=cov,
            reason="empty_home",
            truncated_by=None,
            pet_enabled_norm=pet_norm,
            unverified_checks=sorted(unverified_checks),
        )
        findings_empty: list[dict[str, Any]] = []
        if cov == COVERAGE_COULD_NOT_VERIFY:
            findings_empty.append(
                _finding(
                    "dead_stores.could_not_verify",
                    ".",
                    {"cuts": 0, "unverified_count": len(sec["unverified_checks"])},
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                )
            )
        return _envelope(findings_empty, cov, sec)

    # Verify top-level hermes-setup* installer binaries by magic (8-byte header read)
    for cand_name, cand_size in installer_candidates:
        if is_expired():
            break
        cand_path = root / cand_name
        if credential_path(cand_path) or _is_credential_filename(cand_name):
            continue
        if metadata_reads >= MAX_METADATA_READS:
            note_truncation("metadata_read_budget")
            break
        metadata_reads += 1
        head, err = _read_bounded_regular_bytes(root, (cand_name,), 8)
        if err is not None or head is None:
            if err not in ("credential_excluded", None):
                cuts += 1
                unverified_checks.add("installer_magic_read")
            continue
        metadata_bytes_read += len(head)
        if any(head.startswith(magic) for magic in _EXECUTABLE_MAGICS):
            installer_binaries_count += 1
            installer_binaries_bytes += cand_size
            dead_weight_by_class["regenerable_caches"] += cand_size

    # Post-process (b) Plugins on disk vs enabled
    parked_copies: list[dict[str, Any]] = []
    disabled_on_disk: list[dict[str, Any]] = []
    enabled_missing: list[dict[str, Any]] = []
    dev_residue_by_plugin: list[dict[str, Any]] = []
    git_bytes_total = 0
    pycache_bytes_total = 0
    tests_bytes_total = 0
    node_modules_bytes_total = 0
    active_plugin_residue_bytes = 0
    matched_enabled_names: set[str] = set()
    installed_plugin_names: set[str] = set()
    missing_names: set[str] = set()

    for (source_dir, pkey), rec in sorted(plugin_dirs_seen.items()):
        p_bytes = int(rec["bytes"])
        r_git = int(rec["git_bytes"])
        r_pyc = int(rec["pycache_bytes"])
        r_tst = int(rec["tests_bytes"])
        r_nm = int(rec["node_modules_bytes"])
        r_sum = r_git + r_pyc + r_tst + r_nm
        git_bytes_total += r_git
        pycache_bytes_total += r_pyc
        tests_bytes_total += r_tst
        node_modules_bytes_total += r_nm
        if r_sum > 0:
            dev_residue_by_plugin.append({
                "path": _abs_item_path(real_root, (source_dir, *pkey.split("/"))),
                "source_dir": source_dir,
                "git_bytes": r_git,
                "pycache_bytes": r_pyc,
                "tests_bytes": r_tst,
                "node_modules_bytes": r_nm,
            })

        if rec["is_parked"]:
            parked_copies.append({
                "path": _abs_item_path(real_root, (source_dir, *pkey.split("/"))),
                "source_dir": source_dir,
                "bytes": p_bytes,
            })
            dead_weight_by_class["parked_and_disabled_plugins"] += p_bytes
            continue

        leaf_name = pkey.rsplit("/", 1)[-1]
        has_any_manifest = bool(rec["has_yaml"] or rec["has_other_manifest"])
        if rec["file_count"] > 0 and has_any_manifest:
            installed_plugin_names.add(pkey)
            installed_plugin_names.add(leaf_name)

        if source_dir == "desktop-plugins":
            # Standalone desktop plugins in desktop-plugins/ are toggled in Electron UI, not plugins.enabled.
            if pkey in enabled_set or leaf_name in enabled_set:
                if rec["file_count"] > 0 and has_any_manifest:
                    matched_enabled_names.add(pkey)
                    matched_enabled_names.add(leaf_name)
            active_plugin_residue_bytes += r_sum
            dead_weight_by_class["plugin_dev_residue"] += r_sum
            continue

        # Agent plugin under plugins/
        if enabled_norm is None:
            active_plugin_residue_bytes += r_sum
            dead_weight_by_class["plugin_dev_residue"] += r_sum
            continue

        is_enabled = pkey in enabled_set or leaf_name in enabled_set
        if is_enabled:
            if rec["file_count"] == 0:
                enabled_missing.append({"reason": "empty_folder",
                                        "path": _abs_item_path(real_root, ("plugins", *pkey.split("/")))})
                missing_names.add(pkey)
            elif not has_any_manifest:
                enabled_missing.append({"reason": "no_manifest",
                                        "path": _abs_item_path(real_root, ("plugins", *pkey.split("/")))})
                missing_names.add(pkey)
            else:
                matched_enabled_names.add(pkey)
                matched_enabled_names.add(leaf_name)
            active_plugin_residue_bytes += r_sum
            dead_weight_by_class["plugin_dev_residue"] += r_sum
        else:
            # Disabled plugin present on disk: read its plugin.yaml (bounded) and count declared hooks.
            hooks_declared = 0
            manifest_cov = COVERAGE_VERIFIED
            if rec["yaml_is_symlink"]:
                cuts += 1
                manifest_cov = COVERAGE_COULD_NOT_VERIFY
                unverified_checks.add("plugin_manifest")
            elif rec["has_yaml"] and rec["yaml_rel_parts"] is not None:
                if int(rec["yaml_size"]) > MAX_METADATA_FILE_BYTES:
                    note_truncation("metadata_byte_budget")
                    manifest_cov = COVERAGE_COULD_NOT_VERIFY
                    unverified_checks.add("plugin_manifest")
                elif metadata_reads >= MAX_METADATA_READS:
                    note_truncation("metadata_read_budget")
                    manifest_cov = COVERAGE_COULD_NOT_VERIFY
                    unverified_checks.add("plugin_manifest")
                elif not is_expired():
                    metadata_reads += 1
                    raw_yaml, err = _read_bounded_regular_bytes(
                        root, rec["yaml_rel_parts"], MAX_METADATA_FILE_BYTES
                    )
                    if err is not None or raw_yaml is None:
                        cuts += 1
                        manifest_cov = COVERAGE_COULD_NOT_VERIFY
                        unverified_checks.add("plugin_manifest")
                    else:
                        metadata_bytes_read += len(raw_yaml)
                        try:
                            text_yaml = raw_yaml.decode("utf-8-sig")
                            if "\x00" in text_yaml:
                                raise ValueError("nul byte in yaml")
                            parsed = _parse_simple_yaml_mapping(text_yaml)
                            m_name = parsed.get("name")
                            if isinstance(m_name, str) and m_name.strip():
                                installed_plugin_names.add(m_name.strip())
                                if m_name.strip() in enabled_set:
                                    # Enabled via manifest name alias
                                    matched_enabled_names.add(m_name.strip())
                                    active_plugin_residue_bytes += r_sum
                                    dead_weight_by_class["plugin_dev_residue"] += r_sum
                                    continue
                            raw_hooks = parsed.get("provides_hooks", parsed.get("hooks", []))
                            if raw_hooks is None:
                                raw_hooks = []
                            if not isinstance(raw_hooks, list) or any(not isinstance(h, str) for h in raw_hooks):
                                raise ValueError("invalid provides_hooks")
                            hook_names = {h.strip() for h in raw_hooks if h.strip()}
                            hooks_declared = len(hook_names)
                        except (UnicodeError, ValueError, RecursionError):
                            cuts += 1
                            manifest_cov = COVERAGE_COULD_NOT_VERIFY
                            unverified_checks.add("plugin_manifest")

            disabled_on_disk.append({
                "path": _abs_item_path(real_root, ("plugins", *pkey.split("/"))),
                "bytes": p_bytes,
                "hooks_declared": hooks_declared,
                "manifest_coverage": manifest_cov,
            })
            dead_weight_by_class["parked_and_disabled_plugins"] += p_bytes

    # Symlinked plugin folders are counted only: the serializer would resolve a symlink path to its
    # target outside the home, and a name from config is not an existing item.
    enabled_symlinked: list[str] = []
    enabled_moved_out_of_core: list[str] = []
    if enabled_norm is not None:
        already_missing = set(missing_names)
        for ename in sorted(set(enabled_norm) - set(disabled_norm or ())):
            if ename in BUNDLED_PLUGIN_NAMES:
                continue
            if ename in matched_enabled_names or ename in already_missing:
                continue
            leaf = ename.rsplit("/", 1)[-1]
            if leaf in matched_enabled_names or leaf in already_missing:
                continue
            if ename in plugin_symlink_names or leaf in plugin_symlink_names:
                enabled_symlinked.append(ename)
                continue
            if ename in LEFT_CORE_PLUGIN_NAMES:
                enabled_moved_out_of_core.append(ename)
                continue
            enabled_missing.append({"reason": "no_folder", "path": None})

    # Post-process (c) Orphan plugin data
    active_bundled = set(enabled_norm or ()) & BUNDLED_PLUGIN_NAMES
    orphans: list[dict[str, Any]] = []
    for pdata_name, pdata_info in sorted(plugin_data_dirs.items()):
        if (
            pdata_name in installed_plugin_names
            or pdata_name in active_bundled
            or pdata_name in enabled_set
            or pdata_name in {n.rsplit("/", 1)[-1] for n in plugin_symlink_names}
        ):
            continue
        if pdata_info["bytes"] > 0 or pdata_info["file_count"] > 0:
            orphans.append({
                "path": _abs_item_path(real_root, ("plugin-data", pdata_name)),
                "bytes": pdata_info["bytes"],
                "file_count": pdata_info["file_count"],
            })
            dead_weight_by_class["orphan_plugin_data"] += pdata_info["bytes"]

    # Post-process (g) Unreferenced skill clones
    unreferenced_clones: list[dict[str, Any]] = []
    if ext_skills_norm is not None:
        resolved_ext_paths: list[Path] = []
        for raw_ext in ext_skills_norm:
            expanded = Path(os.path.expanduser(raw_ext))
            abs_ext = Path(os.path.abspath(expanded if expanded.is_absolute() else (root / expanded)))
            resolved_ext_paths.append(abs_ext)
        for ckey, cinfo in sorted(skill_clone_dirs.items()):
            if cinfo["bytes"] <= 0:
                continue
            cpath = root.joinpath(*ckey.split("/"))
            is_referenced = any(
                ext_p == cpath or ext_p.is_relative_to(cpath) or cpath.is_relative_to(ext_p)
                for ext_p in resolved_ext_paths
            )
            if not is_referenced:
                unreferenced_clones.append({
                    "path": _abs_item_path(real_root, ckey.split("/")),
                    "bytes": cinfo["bytes"],
                    "file_count": cinfo["file_count"],
                })
                dead_weight_by_class["unreferenced_skill_clones"] += cinfo["bytes"]
    else:
        for ckey, cinfo in sorted(skill_clone_dirs.items()):
            if cinfo["bytes"] > 0:
                unreferenced_clones.append({
                    "path": _abs_item_path(real_root, ckey.split("/")),
                    "bytes": cinfo["bytes"],
                    "file_count": cinfo["file_count"],
                })

    # Post-process (h) Feature-off leftovers
    feature_off_bytes = pets_bytes if pet_norm is False else 0
    dead_weight_by_class["feature_off_assets"] += feature_off_bytes

    # Post-process (f) Stale locks relative to the newest regular-file mtime in the home.
    if newest_mtime is not None:
        stale_locks_count = sum(1 for m in zero_lock_mtimes if newest_mtime - m > STALE_LOCK_AGE_SECONDS)
    else:
        unverified_checks.add("stale_locks")
    young_or_nonempty_locks_count = len(zero_lock_mtimes) - stale_locks_count + nonempty_locks_count
    stale_locks_vs_now_count = (
        sum(1 for m in zero_lock_mtimes if now_val - m > STALE_LOCK_AGE_SECONDS) if now_val is not None else None
    )

    # Totals and bursts
    export_burst_count, export_burst_span = _burst_stats(export_mtimes)
    cfg_burst_count, _ = _burst_stats(config_backup_mtimes)

    exports_total_bytes = profile_exports_bytes + large_archives_bytes
    parked_bytes_total = sum(x["bytes"] for x in parked_copies)
    disabled_bytes_total = sum(x["bytes"] for x in disabled_on_disk)
    disabled_hooks_total = sum(x["hooks_declared"] for x in disabled_on_disk)
    dev_residue_total = git_bytes_total + pycache_bytes_total + tests_bytes_total + node_modules_bytes_total
    orphan_total_bytes = sum(x["bytes"] for x in orphans)
    regenerable_total_bytes = (
        hub_index_cache_bytes
        + models_dev_cache_bytes
        + provider_models_cache_bytes
        + image_cache_bytes
        + audio_cache_bytes
        + document_cache_bytes
        + other_media_cache_bytes
        + tool_cache_bytes
        + installer_binaries_bytes
    )
    unreferenced_clones_bytes = sum(x["bytes"] for x in unreferenced_clones) if ext_skills_norm is not None else 0
    empty_profile_dirs_count = sum(1 for c in named_profile_file_counts.values() if c == 0)

    total_dead_weight_bytes = sum(dead_weight_by_class.values())
    dead_weight_share = (
        round(min(1.0, total_dead_weight_bytes / total_home_bytes), 6) if total_home_bytes > 0 else 0.0
    )

    # Emit findings
    findings: list[dict[str, Any]] = []

    if exports_total_bytes > PROFILE_EXPORTS_THRESHOLD_BYTES:
        findings.append(
            _finding(
                "dead_stores.profile_exports",
                "profile-exports",
                {
                    "profile_exports_count": profile_exports_count,
                    "profile_exports_bytes": profile_exports_bytes,
                    "large_archives_count": large_archives_count,
                    "large_archives_bytes": large_archives_bytes,
                    "total_bytes": exports_total_bytes,
                    "burst_count": export_burst_count,
                    "threshold_bytes": PROFILE_EXPORTS_THRESHOLD_BYTES,
                },
                classification=CLASSIFICATION_REVIEW,
            )
        )

    if parked_copies or disabled_bytes_total > DISABLED_PLUGIN_THRESHOLD_BYTES or disabled_hooks_total > 0:
        p_ev: dict[str, Any] = {
            "parked_count": len(parked_copies),
            "parked_bytes": parked_bytes_total,
            "disabled_count": len(disabled_on_disk),
            "disabled_bytes": disabled_bytes_total,
            "threshold_bytes": DISABLED_PLUGIN_THRESHOLD_BYTES,
            "name_pattern_label": NAME_PATTERN_LABEL,
        }
        if disabled_hooks_total > 0:
            p_ev["hooks_declared"] = disabled_hooks_total
        findings.append(
            _finding(
                "dead_stores.parked_or_disabled_plugins",
                "plugins",
                p_ev,
                classification=CLASSIFICATION_REVIEW,
            )
        )

    if enabled_norm is not None and enabled_missing:
        findings.append(
            _finding(
                "dead_stores.enabled_plugin_missing",
                "plugins",
                {
                    "missing_count": len(enabled_missing),
                    "no_folder_count": sum(1 for m in enabled_missing if m["reason"] == "no_folder"),
                    "empty_folder_count": sum(1 for m in enabled_missing if m["reason"] == "empty_folder"),
                    "no_manifest_count": sum(1 for m in enabled_missing if m["reason"] == "no_manifest"),
                    "symlinked_count": len(enabled_symlinked),
                    "moved_out_of_core_count": len(enabled_moved_out_of_core),
                },
                classification=CLASSIFICATION_REVIEW,
            )
        )

    if orphans:
        findings.append(
            _finding(
                "dead_stores.orphan_plugin_data",
                "plugin-data",
                {
                    "orphan_count": len(orphans),
                    "total_bytes": orphan_total_bytes,
                },
                classification=CLASSIFICATION_INFO,
            )
        )

    if regenerable_total_bytes > REGENERABLE_CACHES_THRESHOLD_BYTES:
        findings.append(
            _finding(
                "dead_stores.regenerable_caches",
                "cache",
                {
                    "total_bytes": regenerable_total_bytes,
                    "hub_index_cache_bytes": hub_index_cache_bytes,
                    "hub_index_cache_count": len(hub_index_dirs_seen),
                    "models_dev_cache_bytes": models_dev_cache_bytes,
                    "provider_models_cache_bytes": provider_models_cache_bytes,
                    "tool_cache_bytes": tool_cache_bytes,
                    "installer_binaries_bytes": installer_binaries_bytes,
                    "threshold_bytes": REGENERABLE_CACHES_THRESHOLD_BYTES,
                },
                classification=CLASSIFICATION_INFO,
            )
        )

    if request_dumps_count > REQUEST_DUMPS_THRESHOLD_COUNT:
        findings.append(
            _finding(
                "dead_stores.request_dumps",
                "sessions",
                {
                    "count": request_dumps_count,
                    "bytes": request_dumps_bytes,
                    "threshold_count": REQUEST_DUMPS_THRESHOLD_COUNT,
                },
                classification=CLASSIFICATION_REVIEW,
            )
        )

    if unrotated_logs:
        findings.append(
            _finding(
                "dead_stores.unrotated_logs",
                "logs",
                {
                    "count": len(unrotated_logs),
                    "bytes": unrotated_logs_bytes,
                    "threshold_bytes": UNROTATED_LOG_THRESHOLD_BYTES,
                },
                classification=CLASSIFICATION_INFO,
            )
        )

    if backup_files_count > BACKUP_PILE_THRESHOLD_COUNT:
        findings.append(
            _finding(
                "dead_stores.backup_file_pile",
                "backups",
                {
                    "count": backup_files_count,
                    "bytes": backup_files_bytes,
                    "cred_named_count": cred_named_count,
                    "cred_named_bytes": cred_named_bytes,
                    "config_backup_count": config_backup_count,
                    "config_backup_burst_count": cfg_burst_count,
                    "threshold_count": BACKUP_PILE_THRESHOLD_COUNT,
                    "name_pattern_label": NAME_PATTERN_LABEL,
                },
                classification=CLASSIFICATION_INFO,
            )
        )

    if newest_mtime is not None and stale_locks_count > STALE_LOCKS_THRESHOLD_COUNT:
        findings.append(
            _finding(
                "dead_stores.stale_locks",
                "locks",
                {
                    "count": stale_locks_count,
                    "age_threshold_seconds": STALE_LOCK_AGE_SECONDS,
                    "threshold_count": STALE_LOCKS_THRESHOLD_COUNT,
                },
                classification=CLASSIFICATION_INFO,
            )
        )

    if ext_skills_norm is not None and unreferenced_clones:
        findings.append(
            _finding(
                "dead_stores.unreferenced_skill_clones",
                "vendor-skills",
                {
                    "count": len(unreferenced_clones),
                    "total_bytes": unreferenced_clones_bytes,
                },
                classification=CLASSIFICATION_REVIEW,
            )
        )

    if pet_norm is False and pets_bytes > 0:
        findings.append(
            _finding(
                "dead_stores.feature_off_assets",
                "pets",
                {
                    "pets_bytes": pets_bytes,
                    "pets_file_count": pets_file_count,
                    "pet_enabled": False,
                },
                classification=CLASSIFICATION_INFO,
            )
        )

    if total_dead_weight_bytes > 0:
        findings.append(
            _finding(
                "dead_stores.summary",
                ".",
                {
                    "total_home_bytes": total_home_bytes,
                    "total_dead_weight_bytes": total_dead_weight_bytes,
                    "dead_weight_share_of_home": dead_weight_share,
                },
                classification=CLASSIFICATION_INFO,
            )
        )

    overall_coverage = (
        COVERAGE_COULD_NOT_VERIFY if (unverified_checks or cuts > 0 or truncated_by is not None) else COVERAGE_VERIFIED
    )
    if overall_coverage == COVERAGE_COULD_NOT_VERIFY:
        findings.append(
            _finding(
                "dead_stores.could_not_verify",
                ".",
                {
                    "cuts": cuts,
                    "unverified_count": len(unverified_checks),
                },
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
            )
        )

    plugins_cov = (
        COVERAGE_COULD_NOT_VERIFY
        if ("enabled_plugins" in unverified_checks or "plugin_manifest" in unverified_checks or truncated_by is not None)
        else COVERAGE_VERIFIED
    )
    clones_cov = (
        COVERAGE_COULD_NOT_VERIFY
        if ("external_skill_dirs" in unverified_checks or truncated_by is not None)
        else COVERAGE_VERIFIED
    )
    feature_cov = (
        COVERAGE_COULD_NOT_VERIFY
        if ("pet_enabled" in unverified_checks or truncated_by is not None)
        else COVERAGE_VERIFIED
    )
    locks_cov = (
        COVERAGE_COULD_NOT_VERIFY
        if ("stale_locks" in unverified_checks or truncated_by is not None)
        else COVERAGE_VERIFIED
    )

    section: dict[str, Any] = {
        "status": "completed",
        "coverage": overall_coverage,
        "reason": None,
        "truncated_by": truncated_by,
        "overlaps_other_sections": True,
        "total_home_bytes": total_home_bytes,
        "total_home_files": total_home_files,
        "total_dead_weight_bytes": total_dead_weight_bytes,
        "dead_weight_share_of_home": dead_weight_share,
        "dead_weight_by_class": dead_weight_by_class,
        "exports_and_archives": {
            "profile_exports_count": profile_exports_count,
            "profile_exports_bytes": profile_exports_bytes,
            "large_archives_count": large_archives_count,
            "large_archives_bytes": large_archives_bytes,
            "total_bytes": exports_total_bytes,
            "burst_count": export_burst_count,
            "burst_span_seconds": export_burst_span,
        },
        "plugins": {
            "coverage": plugins_cov,
            "parked_copies": parked_copies,
            "parked_count": len(parked_copies),
            "parked_name_label": NAME_PATTERN_LABEL,
            "parked_bytes": parked_bytes_total,
            "disabled_on_disk": disabled_on_disk,
            "disabled_count": len(disabled_on_disk),
            "disabled_bytes": disabled_bytes_total,
            "disabled_hooks_declared": disabled_hooks_total,
            "enabled_missing": enabled_missing,
            "enabled_missing_count": len(enabled_missing),
            "enabled_symlinked_count": len(enabled_symlinked),
            "enabled_moved_out_of_core": enabled_moved_out_of_core,
            "enabled_moved_out_of_core_count": len(enabled_moved_out_of_core),
            "dev_residue": {
                "git_bytes": git_bytes_total,
                "pycache_bytes": pycache_bytes_total,
                "tests_bytes": tests_bytes_total,
                "node_modules_bytes": node_modules_bytes_total,
                "total_bytes": dev_residue_total,
                "active_plugin_residue_bytes": active_plugin_residue_bytes,
                "by_plugin": dev_residue_by_plugin,
            },
        },
        "orphan_plugin_data": {
            "orphans": orphans,
            "count": len(orphans),
            "total_bytes": orphan_total_bytes,
        },
        "regenerable_caches": {
            "hub_index_cache_bytes": hub_index_cache_bytes,
            "hub_index_cache_count": len(hub_index_dirs_seen),
            "models_dev_cache_bytes": models_dev_cache_bytes,
            "provider_models_cache_bytes": provider_models_cache_bytes,
            "image_cache_bytes": image_cache_bytes,
            "audio_cache_bytes": audio_cache_bytes,
            "document_cache_bytes": document_cache_bytes,
            "other_media_cache_bytes": other_media_cache_bytes,
            "tool_cache_bytes": tool_cache_bytes,
            "tool_cache_label": TOOL_CACHE_LABEL,
            "installer_binaries_bytes": installer_binaries_bytes,
            "installer_binaries_count": installer_binaries_count,
            "total_bytes": regenerable_total_bytes,
        },
        "growing_piles": {
            "request_dumps": {
                "count": request_dumps_count,
                "bytes": request_dumps_bytes,
            },
            "unrotated_logs": {
                "count": len(unrotated_logs),
                "bytes": unrotated_logs_bytes,
                "files": unrotated_logs,
                "rotation_managed_skipped_count": rotation_managed_skipped_count,
                "outside_hermes_log_locations_count": outside_log_locations_count,
                "outside_hermes_log_locations_bytes": outside_log_locations_bytes,
            },
            "attachments": {
                "count": attachments_count,
                "bytes": attachments_bytes,
                **_oldest_fields(attachments_min_mtime),
            },
            "composer_pastes": {
                "count": composer_pastes_count,
                "bytes": composer_pastes_bytes,
                **_oldest_fields(composer_pastes_min_mtime),
            },
            "backup_files": {
                "count": backup_files_count,
                "bytes": backup_files_bytes,
                "cred_named_count": cred_named_count,
                "cred_named_bytes": cred_named_bytes,
                "config_backup_count": config_backup_count,
                "config_backup_bytes": config_backup_bytes,
                "config_backup_burst_count": cfg_burst_count,
                "name_pattern_label": NAME_PATTERN_LABEL,
            },
            "empty_profile_dirs_count": empty_profile_dirs_count,
            "deleted_profile_tombstones_count": deleted_profile_tombstones_count,
        },
        "stale_locks": {
            "coverage": locks_cov,
            "reference": STALE_LOCK_REFERENCE,
            "count": stale_locks_count,
            "young_or_nonempty_ignored_count": young_or_nonempty_locks_count,
        },
        "unreferenced_skill_clones": {
            "coverage": clones_cov,
            "clones": unreferenced_clones,
            "count": len(unreferenced_clones) if ext_skills_norm is not None else 0,
            "total_bytes": unreferenced_clones_bytes,
        },
        "feature_off_assets": {
            "coverage": feature_cov,
            "pet_enabled": pet_norm,
            "pets_bytes": pets_bytes,
            "pets_file_count": pets_file_count,
            "total_bytes": feature_off_bytes,
        },
        "unverified_checks": sorted(unverified_checks),
        "limits": {
            "max_entries": MAX_ENTRIES,
            "max_seconds": MAX_SECONDS,
            "max_metadata_file_bytes": MAX_METADATA_FILE_BYTES,
            "max_metadata_reads": MAX_METADATA_READS,
            "max_depth": MAX_DEPTH,
            "entries_walked": entries_walked,
            "metadata_reads": metadata_reads,
            "metadata_bytes_read": metadata_bytes_read,
            "symlinks_skipped": symlinks_skipped,
            "cuts": cuts,
        },
        "thresholds": {
            "profile_exports_bytes": PROFILE_EXPORTS_THRESHOLD_BYTES,
            "large_archive_bytes": LARGE_ARCHIVE_BYTES,
            "burst_count": EXPORT_BURST_COUNT,
            "burst_window_seconds": EXPORT_BURST_WINDOW_SECONDS,
            "disabled_plugin_bytes": DISABLED_PLUGIN_THRESHOLD_BYTES,
            "regenerable_caches_bytes": REGENERABLE_CACHES_THRESHOLD_BYTES,
            "request_dumps_count": REQUEST_DUMPS_THRESHOLD_COUNT,
            "unrotated_log_bytes": UNROTATED_LOG_THRESHOLD_BYTES,
            "backup_pile_count": BACKUP_PILE_THRESHOLD_COUNT,
            "stale_lock_age_seconds": STALE_LOCK_AGE_SECONDS,
            "stale_locks_count": STALE_LOCKS_THRESHOLD_COUNT,
        },
    }
    return _envelope(findings, overall_coverage, section, {"stale_locks_vs_now_count": stale_locks_vs_now_count})
