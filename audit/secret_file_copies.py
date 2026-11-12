"""Detect secret file copies and misplaced secret-named files by name and lstat only.

Never opens, reads, hashes, resolves or stats-with-follow any file or symlink. The only
filesystem calls are os.scandir (directory listings) and os.lstat (size, mode bits, mtime).
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import fnmatch
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Callable

from .contract import make_component_envelope, make_finding

# This module opens no file at all, so audit.policy.credential_path (which gates content
# reads elsewhere in the audit) has nothing to gate here. It is deliberately not used as a
# name classifier either: its filename hints (any name starting with "id_" or ".env", any
# "*.key") flagged locale packs such as id_FEMININE.pak and Keynote decks, and in an audit
# run it consults per-run state through os.path.abspath, which makes a bare-name check
# depend on the working directory.

# Bounds: a home of tens of thousands of entries is walked in seconds; the caps leave a wide margin.
MAX_ENTRIES = 400_000
MAX_DEPTH = 40
MAX_SECONDS = 15.0
MAX_EXAMPLE_LOCATIONS = 20

# Thresholds: a single copy of a credential file is already worth a warning, because editors,
# backup tools and quick manual copies routinely leave .env, auth and config backups behind.
BACKUP_COPIES_WARNING_THRESHOLD = 1
WORK_FOLDER_SECRET_FILES_WARNING_THRESHOLD = 1
FIXTURE_HOME_SECRET_FILES_THRESHOLD = 1
PLUGIN_SECRET_FILE_THRESHOLD = 1
READABLE_BY_OTHERS_WARNING_THRESHOLD = 1
CONFIG_BACKUP_INFO_THRESHOLD = 1
CONFIG_BACKUP_REVIEW_THRESHOLD = 5
CONFIG_BACKUP_BURST_MIN_FILES = 3
CONFIG_BACKUP_BURST_WINDOW_SECONDS = 60.0

# Secret-name pattern classes (fnmatch on the lower-cased basename) and their output label.
# Precision/recall are measured in tests/test_audit_secret_file_copies.py on 52 innocent and
# 49 secret-like names.
SECRET_PATTERN_CLASSES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("dotenv", (".env", ".env.*", "*.env", ".envrc")),
    ("oauth-json", ("*oauth*.json",)),
    ("service-account-json", ("*service-account*.json", "*service_account*.json")),
    ("auth-json", ("auth.json", "*auth*.json")),
    ("token-json", ("*token*.json",)),
    ("tokens", ("*tokens*",)),
    ("credential", ("*credential*",)),
    ("secret_word", ("*secret*",)),  # not "secret": a sealed plain value in the report
    ("api-key", ("*api_key*", "*apikey*", "*api-key*")),
    ("pem", ("*.pem",)),
    ("key", ("*.key",)),  # only with a key-like stem, see _key_extension_is_key_like
    ("ssh-key", ("id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*", "*.ppk")),
    ("pkcs12", ("*.p12", "*.pfx")),
    ("keystore", ("*.keystore", "*.jks")),
    ("netrc", (".netrc", ".pgpass")),
    ("npmrc", (".npmrc", "npmrc", "pip.conf")),
    ("pypirc", (".pypirc",)),
)
SECRET_NAME_PATTERNS: tuple[str, ...] = tuple(
    pat for _cls, pats in SECRET_PATTERN_CLASSES for pat in pats
)

# "*.key" is shared with Keynote presentations (turkey.key, "Q3 Review.key"). A .key file is
# matched only when a word of its stem is key vocabulary or the stem is dotted like a host
# name (www.example.org.key). Recall cost: a private key named e.g. mysite.key is missed.
KEY_STEM_WORDS: frozenset[str] = frozenset({
    "private", "priv", "privkey", "privatekey", "server", "client", "tls", "ssl", "cert",
    "ca", "signing", "sign", "master", "secret", "api", "apikey", "ssh", "rsa", "dsa",
    "ecdsa", "ed25519", "pgp", "gpg", "fernet", "vault", "jwt", "hmac", "encryption", "enc",
    "key", "localhost", "deploy", "admin", "root", "service", "account", "token", "auth",
    "oauth", "login", "access", "wildcard", "host", "domain", "prod", "production",
})

# Explicit do-not-flag exclusions for non-secret token filenames.
TOKEN_NAME_EXCLUSIONS: tuple[str, ...] = (
    "tokenizer.json",
    "tokenizer_config.json",
    "*tokeniz*",
    "special_tokens_map.json",
    "added_tokens.json",
    "tokens.css",
    "tokens.txt",  # model vocabulary files (tools/wake_word_engines.py:161)
    "design-tokens*",
    "design_tokens*",
    "*token_count*",
    "*token-count*",
    "*token_usage*",
    "*token-usage*",
    "*token_cost*",
    "*token-cost*",
    "*.tokens.json",
    "trust tokens*",
)

# A name with one of these dot/dash/underscore/space-separated words is a placeholder or
# template by convention (.env.example, credentials.example.json, secrets.template.yaml).
EXAMPLE_NAME_WORDS: frozenset[str] = frozenset({
    "example", "examples", "sample", "samples", "template", "templates", "tmpl", "tpl",
    "dist", "defaults",
})

# Public material: certificates, certificate requests, public keys, CA bundles.
EXAMPLE_AND_PUBLIC_EXCLUSIONS: tuple[str, ...] = (
    "*.crt",
    "*.cer",
    "*.csr",
    "*.pub",
    "cacert.pem",
    "*ca-bundle*",
    "ca-certificates*",
    "chain.pem",
    "fullchain.pem",
    "debug.keystore",  # Android SDK's generated debug signing store with a published password
)

# Source code, documentation, lockfiles, logs, and media assets are not secret stores
# when matching broad substring patterns (*tokens*, *credential*, *secret*).
NON_STORE_SUFFIXES: tuple[str, ...] = (
    ".py", ".pyc", ".pyo", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".rs", ".go", ".c", ".h", ".cpp", ".hpp", ".java", ".kt", ".swift", ".cs", ".rb", ".php",
    ".vue", ".svelte", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd",
    ".md", ".mdx", ".rst", ".adoc", ".css", ".scss", ".sass", ".less",
    ".html", ".htm", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".map",
    ".lock", ".log", ".patch", ".diff",
)

# Third-party package trees: secret-named files there ship with a library (test fixtures,
# CA bundles) and are not counted.
VENDORED_PACKAGE_DIRS: frozenset[str] = frozenset({
    "site-packages", "dist-packages", "node_modules", "bower_components", "_vendor", "certifi",
})
VENDORED_CERT_DIRS = VENDORED_PACKAGE_DIRS  # backward-compatible alias

# Where the Hermes source keeps secrets, per home root and per profiles/<name> root
# (hermes-agent at the pinned checkout; every path below is cited):
# - .env: hermes_constants.py:1279-1281; .op.env: hermes_cli/env_loader.py:221,496;
#   .envrc: hermes_cli/profiles.py:153-154 (_OS_CREDENTIAL_STORES), agent/file_safety.py:339
# - auth.json: hermes_cli/auth.py:479-501; credentials.json / credentials/:
#   hermes_cli/models.py:1945-1948, gateway/platforms/base.py:784-785,
#   hermes_cli/web_routers/files.py:85
# - shared/nous_auth.json at the default root only (one store for every profile):
#   hermes_cli/auth_nous.py:346-365, hermes_cli/auth_commands.py:330-332,
#   hermes_cli/install_state.py:356-359
# - mcp-tokens/: tools/mcp_oauth.py:229-233,412-434
# - pairing/, platforms/pairing/, feishu_comment_pairing.json: gateway/pairing.py:58-59,
#   hermes_cli/profiles.py:176
# - vault/: agent/vault_store.py:208-220, agent/file_safety.py:364-366, hermes_cli/profiles.py:173
# - platform token stores: plugins/platforms/slack/adapter.py:6529-6534,
#   gateway/webapp_listener.py:32, hermes_cli/webapp_sign_in.py:52,
#   hermes_cli/home_data_layout.py:11-18, hermes_cli/profiles.py:167-171,174,177-182
# - OAuth stores: agent/credential_sources.py:160-165, hermes_cli/profiles.py:160-166,181
# - browser and subprocess-HOME trees (browser-profile, browser_auth, bot-desktop,
#   browser-profiles, browser_profiles, chrome-debug, home): hermes_cli/profiles.py:174-175,183-184,
#   hermes_constants.py:703-709, hermes_cli/browser_connect.py:837
# - OS credential dirs (.ssh .aws .gnupg .kube .docker .azure .config/gh .config/gcloud):
#   agent/file_safety.py:211, hermes_cli/profiles.py:153-154,186
EXPECTED_SECRET_KINDS: tuple[str, ...] = (
    "dotenv",
    "auth_json",
    "shared_auth",
    "credentials_store",
    "mcp_tokens",
    "pairing",
    "vault",
    "platform_token_stores",
    "oauth_stores",
    "browser_and_home_stores",
    "os_credential_dirs",
)

NOUS_SHARED_STORE = ("shared", "nous_auth.json")  # hermes_cli/auth_nous.py:346,361-364

EXPECTED_ROOT_PLATFORM_FILES: frozenset[str] = frozenset({
    "slack_tokens.json",
    "webhook_subscriptions.json",
    "teams_pipeline_store.json",
    "honcho.json",
    "mem0.json",
    "npmrc",
    ".npmrc",
    ".netrc",
    "bws_cache.json",
    "bws_cache.enc.json",
    "op_cache.json",
    "photon-sidecar.json",
})

EXPECTED_SUBPATH_PLATFORM_FILES: frozenset[tuple[str, ...]] = frozenset({
    ("cache", "bws_cache.json"),
    ("cache", "bws_cache.enc.json"),
    ("cache", "op_cache.json"),
    ("runtime", "photon-sidecar.json"),
    ("workspace", "meetings", "node_token.json"),
    ("workspace", "meetings", "auth.json"),
})

EXPECTED_ROOT_OAUTH_FILES: frozenset[str] = frozenset({
    ".anthropic_oauth.json",
    "google_token.json",
    "google_oauth_pending.json",
    "google_client_secret.json",
    "google_chat_user_token.json",
    "google_chat_user_client_secret.json",
    "google_chat_user_oauth_pending.json",
    ".copilot_jwt.json",
})

# Whole trees that hold browser logins or a subprocess HOME (hermes_cli/profiles.py:174-175,183-184).
# Only their secret-named files are counted (as expected); everything else there is ignored.
BROWSER_AND_HOME_TREES: frozenset[str] = frozenset({
    "browser-profile", "browser_auth", "bot-desktop", "browser-profiles", "browser_profiles",
    "chrome-debug", "home",
})

# OS credential directories (agent/file_safety.py:211); every file inside counts as expected.
OS_CREDENTIAL_DIRS: tuple[tuple[str, ...], ...] = (
    (".ssh",), (".aws",), (".gnupg",), (".kube",), (".docker",), (".azure",),
    (".config", "gh"), (".config", "gcloud"),
)

# Files Hermes writes whose names only look secret; never counted.
HERMES_NON_SECRET_FILES: frozenset[tuple[str, ...]] = frozenset({
    ("cache", "oauth_heal_clean.json"),   # hermes_cli/auth_oauth_grants.py:305,319
    ("cache", "image_token_costs.json"),  # agent/image_token_cost.py:39, agent/model_metadata.py:154-156
    ("cache", "platform-ca-bundle.pem"),  # agent/ssl_verify.py:278
})

EXPECTED_SECRET_FILENAMES: dict[str, str] = {
    ".env": "dotenv",
    ".op.env": "dotenv",
    ".envrc": "dotenv",
    "auth.json": "auth_json",
    "credentials.json": "credentials_store",
    **{name: "platform_token_stores" for name in EXPECTED_ROOT_PLATFORM_FILES},
    **{name: "oauth_stores" for name in EXPECTED_ROOT_OAUTH_FILES},
    "vault.key": "vault",
    "vault.json.enc": "vault",
}

# Hermes home/profile identity markers (hermes_constants.py:320,399).
HERMES_HOME_MARKERS: frozenset[str] = frozenset({
    "config.yaml", ".env", "SOUL.md", "profile.yaml", "auth.json", "state.db",
})
HERMES_HOME_SIGNALS: frozenset[str] = HERMES_HOME_MARKERS | frozenset({
    "profiles", "memories", "sessions", "mcp-tokens", "pairing", "vault",
})

BACKUP_FOLDERS: frozenset[str] = frozenset({
    "backups", ".curator_backups", "state-snapshots", "checkpoints",
})

PLUGIN_FOLDERS: frozenset[str] = frozenset({
    "plugins", "desktop-plugins",
})

_BACKUP_SUFFIX_RE = re.compile(
    r"^(?:"
    r"\.bak(?:$|[-._].*|\d+.*)"
    r"|\.orig(?:$|[-._].*)"
    r"|\.old(?:$|[-._].*)"
    r"|\.pre-[^/]*"
    r"|\.before(?:$|[-._].*)"
    r"|\.save(?:$|[-._].*)"
    r"|~$"
    r"|[-.]backup(?:$|[-._].*|\d+.*)"
    r"|[-.]codex-backup(?:$|[-._].*)"
    r"|[._-]\d{6,8}(?:[t_-]\d{4,6}z?)?(?:$|[._-].*)"
    r"|[._-]\d{4}-\d{2}-\d{2}(?:$|[._-].*)"
    r")$",
    re.I,
)

_STEM_BACKUP_INFIX_RE = re.compile(
    r"^(?:[-.]before[-.]|[-.]bak(?:[-.]|$)|[-.]backup(?:[-.]|$)|[-.]old(?:[-.]|$)|"
    r"[-.]orig(?:[-.]|$)|[-.]pre-|[-.]save(?:[-.]|$)|[-.]codex-backup[-.]).*",
    re.I,
)

# config.yaml copies: hermes_cli/config_backups.py:21-27 (backups/config/, legacy siblings).
_CONFIG_BACKUP_NAME_RE = re.compile(
    r"^(?:"
    r"config\.yaml\.(?:bak.*|pre-.*|before.*|old.*|orig.*|save.*|corrupt.*|\d{6,8}.*)"
    r"|config\.yaml~"
    r"|config\.(?:bak|pre-|before|old|orig)[^/]*\.yaml"
    r")$",
    re.I,
)

_AUTHOR_WORD_RE = re.compile(r"author[a-z]*", re.I)
_SECRETARY_WORD_RE = re.compile(r"secretar[a-z]*", re.I)
_NAME_WORD_SPLIT_RE = re.compile(r"[._\- ]+")

FINDING_CONSEQUENCES: dict[str, str] = {
    "secret_file_copies.backup_copies_of_secret_files": (
        "Files named as copies of a Hermes secret store (such as .env.bak-*, auth.json.old, or a "
        "store's name inside a backups folder) were counted next to the live stores or in backup "
        "folders. The audit matched file names and lstat metadata only and did not open any file, "
        "so it cannot tell whether a copy holds a working secret, an expired one, or none."
    ),
    "secret_file_copies.secret_named_files_in_work_folders": (
        "Files whose names match secret-store patterns were counted outside the places the Hermes "
        "source keeps secrets. The audit matched file names only and did not open any file, so it "
        "cannot tell whether any of them holds a real secret; a copy, sync or share of those "
        "folders includes them. Files that third-party plugins write are not known to the audit "
        "as expected stores and are counted here."
    ),
    "secret_file_copies.secret_named_files_in_fixture_homes": (
        "Secret-named files were counted inside nested directories shaped like a Hermes home below "
        "the profile root. The audit matched file names only and did not open any file, so it "
        "cannot tell real secrets from test values."
    ),
    "secret_file_copies.plugin_holds_secret_file": (
        "A .env-style file was counted inside one or more plugin folders, outside the profile's "
        "secret stores. The audit matched file names only and did not open any file, so it cannot "
        "tell whether the file holds a real secret."
    ),
    "secret_file_copies.readable_by_others": (
        "Secret-named files carry group or world permission bits (mode & 0o077) in a home whose "
        "file modes vary. The audit matched file names and lstat mode bits only and did not open "
        "any file, so it cannot tell whether a file holds a real secret or who else can log in to "
        "this machine."
    ),
    "secret_file_copies.config_backup_copies": (
        "Copies of config.yaml were counted at the home or profile root and in backup folders; a "
        "config.yaml can contain keys typed into it. The audit matched file names and lstat "
        "metadata only and did not open any file, so it cannot tell whether any copy holds a key."
    ),
    "secret_file_copies.could_not_verify": (
        "Part of the home could not be listed (a safety cap, an unreadable folder, an undecodable "
        "name, or a missing or invalid home path), so the counts are partial. The audit matched "
        "file names only and did not open any file; what was not listed is neither clean nor a "
        "problem."
    ),
}

FIXTURE_HOMES_NOTE = (
    "Counted apart from work folders because names alone cannot tell test values from real "
    "secrets; the audit opened no file."
)

def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _is_macos_stub(name: str) -> bool:
    return name.startswith("._")


def _name_words(low_name: str) -> list[str]:
    return [w for w in _NAME_WORD_SPLIT_RE.split(low_name) if w]


def _is_excluded_example_or_public(low_name: str) -> bool:
    if any(fnmatch.fnmatchcase(low_name, pat) for pat in EXAMPLE_AND_PUBLIC_EXCLUSIONS):
        return True
    return any(word in EXAMPLE_NAME_WORDS for word in _name_words(low_name))


def _is_excluded_token_name(low_name: str) -> bool:
    return any(fnmatch.fnmatchcase(low_name, pat) for pat in TOKEN_NAME_EXCLUSIONS)


def _is_vendored(rel_parts: tuple[str, ...]) -> bool:
    return any(part.lower() in VENDORED_PACKAGE_DIRS for part in rel_parts[:-1])


def _is_vendored_cacert(rel_parts: tuple[str, ...]) -> bool:
    """Kept for callers of the earlier name: any file inside a vendored package tree."""
    return bool(rel_parts) and _is_vendored(rel_parts)


def _key_extension_is_key_like(low_name: str) -> bool:
    stem = low_name[: -len(".key")]
    if "." in stem:
        return True
    return any(word in KEY_STEM_WORDS for word in _name_words(stem))


def _is_config_backup(rel_parts: tuple[str, ...]) -> bool:
    """True for config.yaml.bak*, config.yaml.pre-*, or files under backups/config/."""
    if not rel_parts:
        return False
    name_low = rel_parts[-1].lower()
    if _is_macos_stub(rel_parts[-1]) or _is_excluded_example_or_public(name_low):
        return False
    if len(rel_parts) == 3 and rel_parts[:2] == ("profiles", ".deleted") and _CONFIG_BACKUP_NAME_RE.match(name_low):
        return True
    sub = _profile_subpath(rel_parts)
    if sub is None:
        return False
    if len(sub) >= 3 and sub[0].lower() == "backups" and sub[1].lower() == "config":
        return True
    if len(sub) == 1 and _CONFIG_BACKUP_NAME_RE.match(name_low):
        return True
    if len(sub) >= 2 and sub[0].lower() in BACKUP_FOLDERS and _CONFIG_BACKUP_NAME_RE.match(name_low):
        return True
    return False


def _profile_subpath(rel_parts: tuple[str, ...]) -> tuple[str, ...] | None:
    """If rel_parts is under a named profile profiles/<name>/..., return subpath inside that profile;
    otherwise return rel_parts relative to the home root."""
    if len(rel_parts) >= 2 and rel_parts[0] == "profiles":
        if rel_parts[1].startswith("."):
            return None
        return rel_parts[2:]
    return rel_parts


def _owning_root_parts(rel_parts: tuple[str, ...]) -> tuple[str, ...]:
    if len(rel_parts) >= 2 and rel_parts[0] == "profiles" and not rel_parts[1].startswith("."):
        return rel_parts[:2]
    return ()


def _is_hermes_non_secret(rel_parts: tuple[str, ...]) -> bool:
    sub = _profile_subpath(rel_parts)
    return bool(sub) and tuple(p.lower() for p in sub) in HERMES_NON_SECRET_FILES


def _under_os_credential_dir(sub_low: tuple[str, ...]) -> bool:
    return any(len(sub_low) > len(d) and sub_low[: len(d)] == d for d in OS_CREDENTIAL_DIRS)


# Sentinel: the file sits inside a Hermes store tree but is neither a secret store nor counted.
_IGNORED = "__ignored__"


def _expected_secret_kind(
    rel_parts: tuple[str, ...], name_cache: dict[str, str | None] | None = None
) -> str | None:
    """Return the expected secret kind if rel_parts is at a place the Hermes source keeps secrets.

    Returns _IGNORED for files inside browser/subprocess-HOME trees whose names are not
    secret-like (never counted, never mode-checked).
    """
    if not rel_parts:
        return None
    if _is_macos_stub(rel_parts[-1]):
        return None
    name_low = rel_parts[-1].lower()
    if name_low.endswith(".lock") or _is_excluded_example_or_public(name_low):
        return None
    if tuple(p.lower() for p in rel_parts) == NOUS_SHARED_STORE:
        return "shared_auth"
    sub = _profile_subpath(rel_parts)
    if not sub:
        return None
    if len(sub) == 1:
        if name_low in {".env", ".op.env", ".envrc"}:
            return "dotenv"
        if name_low == "auth.json":
            return "auth_json"
        if name_low == "credentials.json":
            return "credentials_store"
        if name_low == "feishu_comment_pairing.json":
            return "pairing"
        if name_low in EXPECTED_ROOT_PLATFORM_FILES:
            return "platform_token_stores"
        if name_low in EXPECTED_ROOT_OAUTH_FILES:
            return "oauth_stores"
        return None
    first_low = sub[0].lower()
    sub_low = tuple(p.lower() for p in sub)
    if first_low == "credentials":
        return "credentials_store"
    if first_low == "mcp-tokens":
        return "mcp_tokens"
    if first_low == "pairing" or sub_low[:2] == ("platforms", "pairing"):
        return "pairing"
    if first_low == "vault":
        return "vault"
    if sub_low in EXPECTED_SUBPATH_PLATFORM_FILES:
        return "platform_token_stores"
    if (
        sub_low[:2] in {("weixin", "accounts"), ("whatsapp", "session"), ("matrix", "store")}
        or sub_low[:3] in {("platforms", "whatsapp", "session"), ("platforms", "matrix", "store")}
        or first_low in {"webapp", "proxy"}
    ):
        return "platform_token_stores"
    if sub_low == ("auth", "google_oauth.json") or first_low in {
        "google_chat_user_tokens", "google_chat_user_oauth_pending",
    }:
        return "oauth_stores"
    if _under_os_credential_dir(sub_low):
        return "os_credential_dirs"
    if first_low in BROWSER_AND_HOME_TREES:
        if first_low == "home" and _under_os_credential_dir(sub_low[1:]):
            return "browser_and_home_stores"
        if classify_secret_filename(sub[-1], sub, name_cache) is not None:
            return "browser_and_home_stores"
        return _IGNORED
    return None


def _match_backup_of_expected_secret(rel_parts: tuple[str, ...]) -> tuple[str, str, str] | None:
    """If rel_parts is a backup copy of an expected secret file, return (secret_kind, live_filename, scope).

    Checks files next to the original (home/profile root, shared/) or under backup folders.
    """
    if not rel_parts:
        return None
    name = rel_parts[-1]
    low = name.lower()
    if _is_macos_stub(name) or _is_excluded_example_or_public(low) or low.endswith(".lock"):
        return None
    if _is_config_backup(rel_parts):
        return None

    if len(rel_parts) == 2 and rel_parts[0].lower() == NOUS_SHARED_STORE[0]:
        live = NOUS_SHARED_STORE[1]
        if low.startswith(live) and len(low) > len(live) and _BACKUP_SUFFIX_RE.match(low[len(live):]):
            return "shared_auth", live, "home"
        return None

    sub = _profile_subpath(rel_parts)
    if sub is None:
        if len(rel_parts) >= 3 and rel_parts[:2] == ("profiles", ".deleted"):
            sub = rel_parts[2:]
            scope = "profile"
        else:
            return None
    else:
        scope = "profile" if len(rel_parts) >= 2 and rel_parts[0] == "profiles" else "home"

    if not sub:
        return None
    in_backup_dir = len(sub) >= 2 and sub[0].lower() in BACKUP_FOLDERS
    if in_backup_dir:
        scope = "backups"
    elif len(sub) != 1:
        return None

    # 1. Exact expected secret name + backup suffix (e.g. .env.bak-*, auth.json.bak, .env~)
    for expected_name, kind in EXPECTED_SECRET_FILENAMES.items():
        if low.startswith(expected_name) and len(low) > len(expected_name):
            suffix = low[len(expected_name):]
            if _BACKUP_SUFFIX_RE.match(suffix):
                return kind, expected_name, scope
        if in_backup_dir and low == expected_name:
            return kind, expected_name, scope

    # 2. Stem-inserted backup suffix before extension (e.g. backups/auth-before-copilot-*.json)
    for expected_name, kind in EXPECTED_SECRET_FILENAMES.items():
        if "." not in expected_name or expected_name.startswith("."):
            continue
        stem, ext = expected_name.rsplit(".", 1)
        dot_ext = "." + ext
        if low.startswith(stem) and low.endswith(dot_ext) and len(low) > len(stem) + len(dot_ext):
            infix = low[len(stem):-len(dot_ext)]
            if _STEM_BACKUP_INFIX_RE.match(infix):
                return kind, expected_name, scope

    return None


def classify_secret_filename(
    name: str,
    rel_parts: tuple[str, ...] = (),
    _name_cache: dict[str, str | None] | None = None,
) -> str | None:
    """Classify a filename into a secret pattern class, or None if excluded / not matching.

    Pure string work on the name (and on rel_parts for the vendored/config-backup checks);
    never touches the filesystem. `_name_cache` is a per-call memo owned by the caller.
    """
    if not name or _is_macos_stub(name):
        return None
    if rel_parts and (_is_vendored(rel_parts) or _is_config_backup(rel_parts)):
        return None
    low = name.lower()
    if _name_cache is not None:
        if low not in _name_cache:
            _name_cache[low] = _classify_lower_name(low)
        return _name_cache[low]
    return _classify_lower_name(low)


def _classify_lower_name(low: str) -> str | None:
    if _is_excluded_example_or_public(low):
        return None
    if _is_excluded_token_name(low):
        return None
    if low.endswith(NON_STORE_SUFFIXES):
        return None

    for cls_label, patterns in SECRET_PATTERN_CLASSES:
        for pat in patterns:
            if not fnmatch.fnmatchcase(low, pat):
                continue
            if cls_label == "auth-json" and pat == "*auth*.json":
                # Exclude plain 'author' / 'authority' / 'authorship' / 'authored' words
                if "auth" not in _AUTHOR_WORD_RE.sub("", low):
                    continue
            if cls_label == "secret_word" and "secret" not in _SECRETARY_WORD_RE.sub("", low):
                continue
            if cls_label == "key" and not _key_extension_is_key_like(low):
                continue
            return cls_label
    return None


def _is_plugin_dotenv(rel_parts: tuple[str, ...]) -> tuple[str, ...] | None:
    """If rel_parts is a .env-style file inside a plugin folder, return the plugin folder's parts.

    The parts end at the plugin folder itself (``plugins/<name>`` or
    ``profiles/<p>/plugins/<name>``), never at the file.
    """
    sub = _profile_subpath(rel_parts)
    if sub is None or len(sub) < 3:
        return None
    if sub[0].lower() not in PLUGIN_FOLDERS:
        return None
    plugin_parts = rel_parts[: len(rel_parts) - len(sub) + 2]
    name = sub[-1]
    low = name.lower()
    if _is_macos_stub(name) or _is_excluded_example_or_public(low):
        return None
    if low == ".env" or low.startswith(".env.") or low.endswith(".env") or low == ".envrc":
        return plugin_parts
    return None


def _top_folder_path(root_abs: str, rel_parts: tuple[str, ...]) -> str:
    """Absolute path of the top-level folder holding rel_parts; the home root for root files.

    Never deeper than the top-level folder and never the file itself: the report keeps an
    absolute path to an existing item as is, while any other string (a relative name, a
    masked placeholder) becomes a per-run token. Pure string work, no filesystem call.
    """
    if len(rel_parts) <= 1:
        return root_abs
    return os.path.join(root_abs, rel_parts[0])


def _mtime_year_month(mtime: float) -> tuple[int | None, int | None]:
    """UTC (year, month) of a file mtime, from data only (never from the wall clock).

    Numbers, not a "YYYY-MM" string: the report's evidence serializer keeps numbers as they
    are but replaces any string outside its closed vocabulary with a per-run token.
    """
    if not isinstance(mtime, (int, float)) or mtime <= 0:
        return None, None
    try:
        dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None, None
    return dt.year, dt.month


def _compute_bursts(mtimes: list[float]) -> tuple[int, int]:
    """Return (burst_count, max_burst_files) for clusters of >=3 files within 60 seconds."""
    valid = sorted(t for t in mtimes if isinstance(t, (int, float)) and t > 0)
    if len(valid) < CONFIG_BACKUP_BURST_MIN_FILES:
        return 0, 0
    burst_count = 0
    max_burst = 0
    i = 0
    n = len(valid)
    while i < n:
        j = i
        while j < n and (valid[j] - valid[i]) <= CONFIG_BACKUP_BURST_WINDOW_SECONDS:
            j += 1
        window_size = j - i
        if window_size >= CONFIG_BACKUP_BURST_MIN_FILES:
            burst_count += 1
            if window_size > max_burst:
                max_burst = window_size
            i = j
        else:
            i += 1
    return burst_count, max_burst


def _mode_check(all_file_modes: list[int]) -> tuple[str, str | None]:
    """Decide whether permission bits in this home carry information.

    A home copied through a filesystem or archive tool that sets one policy for every file
    (FAT/NTFS 0777/0666, an extraction to owner-only, a uniform 0644) cannot show which
    files were private, so the check reports could_not_verify instead of a count.
    """
    if not all_file_modes:
        return "verified", None
    if all((m & 0o077) == 0 for m in all_file_modes):
        return "could_not_verify", "no_group_or_other_bits_anywhere"
    if all(m in (0o777, 0o666) for m in all_file_modes):
        return "could_not_verify", "all_files_permissive"
    if len(set(all_file_modes)) == 1:
        return "could_not_verify", "uniform_mode"
    return "verified", None


def _is_fixture_home_dir(rel_parts: tuple[str, ...], child_names: set[str]) -> bool:
    """True when rel_parts below profile_path looks like a nested Hermes home (excluding profiles/<name>)."""
    if not rel_parts:
        return False
    if rel_parts[0] == "profiles" and len(rel_parts) <= 2:
        return False
    if rel_parts[0].lower() in PLUGIN_FOLDERS | BACKUP_FOLDERS | {"skills", "vendor-skills", "shared"}:
        if rel_parts[-1] != ".hermes":
            return False
    if rel_parts[-1] == ".hermes":
        return True
    if len(rel_parts) >= 2 and rel_parts[-2] == "profiles" and bool(child_names & HERMES_HOME_MARKERS):
        return True
    if bool(child_names & {"SOUL.md", "profile.yaml"}):
        return True
    if "config.yaml" in child_names and len(child_names & HERMES_HOME_SIGNALS) >= 2:
        return True
    return False


def _finding(
    rule_id: str,
    evidence: dict[str, Any],
    *,
    classification: str = "review_suggested",
    coverage: str = "verified",
) -> dict[str, Any]:
    return make_finding(
        rule_id=rule_id,
        classification=classification,
        coverage=coverage,
        evidence=evidence,
        consequence=FINDING_CONSEQUENCES[rule_id],
    )


def _thresholds() -> dict[str, Any]:
    return {
        "backup_copies_warning": BACKUP_COPIES_WARNING_THRESHOLD,
        "work_folder_secret_files_warning": WORK_FOLDER_SECRET_FILES_WARNING_THRESHOLD,
        "fixture_home_secret_files_review": FIXTURE_HOME_SECRET_FILES_THRESHOLD,
        "plugin_secret_file_review": PLUGIN_SECRET_FILE_THRESHOLD,
        "readable_by_others_warning": READABLE_BY_OTHERS_WARNING_THRESHOLD,
        "config_backup_info": CONFIG_BACKUP_INFO_THRESHOLD,
        "config_backup_review": CONFIG_BACKUP_REVIEW_THRESHOLD,
        "config_backup_burst_min_files": CONFIG_BACKUP_BURST_MIN_FILES,
        "config_backup_burst_window_seconds": CONFIG_BACKUP_BURST_WINDOW_SECONDS,
    }


def _empty_section(
    *,
    status: str,
    reason: str | None,
    coverage: str,
    truncated_by: str | None,
    max_entries: int,
    max_depth: int,
    max_seconds: float,
    entries_walked: int = 0,
    max_depth_reached: int = 0,
    cuts: int = 0,
) -> dict[str, Any]:
    return {
        "coverage": coverage,
        "status": status,
        "reason": reason,
        "truncated_by": truncated_by,
        "expected_secret_files": {
            "total": 0,
            "by_kind": {k: 0 for k in EXPECTED_SECRET_KINDS},
        },
        "backup_copies": {
            "count": 0,
            "same_size_as_live_count": 0,
            "copies": [],
        },
        "secret_named_files": {
            "count": 0,
            "by_top_level_folder": [],
            "by_pattern_class": {},
            "example_locations": [],
            "plugin_dotenv_count": 0,
            "plugin_folders_with_dotenv": [],
            "top_level_folder_count": 0,
            "plugin_folder_count": 0,
        },
        "fixture_homes": {
            "fixture_home_count": 0,
            "fixture_profile_dir_count": 0,
            "secret_named_file_count": 0,
            "by_pattern_class": {},
            "note": FIXTURE_HOMES_NOTE,
        },
        "mode_bits": {
            "mode_check": "could_not_verify",
            "mode_check_reason": "not_measured",
            "readable_by_others_count": None,
            "checked_count": 0,
        },
        "config_backups": {
            "count": 0,
            "root_count": 0,
            "profile_count": 0,
            "backups_config_dir_count": 0,
            "burst_count": 0,
            "max_burst_files": 0,
            "reason": "configs_may_embed_keys_not_read",
        },
        "symlinks": {
            "symlinks_skipped": 0,
            "secret_named_symlinks": 0,
        },
        "limits": {
            "max_entries": max_entries,
            "max_depth": max_depth,
            "max_seconds": max_seconds,
            "entries_walked": entries_walked,
            "max_depth_reached": max_depth_reached,
            "cuts": cuts,
        },
        "thresholds": _thresholds(),
    }


def _not_measured(reason: str, *, max_entries: int, max_depth: int, max_seconds: float) -> dict[str, Any]:
    sec = _empty_section(
        status="not_measured",
        reason=reason,
        coverage="could_not_verify",
        truncated_by=None,
        max_entries=max_entries,
        max_depth=max_depth,
        max_seconds=max_seconds,
        cuts=1,
    )
    finding = _finding(
        "secret_file_copies.could_not_verify",
        {"cuts": 1, "reason": reason},
        classification="info",
        coverage="could_not_verify",
    )
    return _envelope([finding], "could_not_verify", sec, elapsed_seconds=0.0)


_ENVELOPE_KEYS = ("secret_file_copies", "findings", "status", "coverage")


def _envelope(
    findings: list[dict[str, Any]],
    coverage: str,
    section: dict[str, Any],
    *,
    elapsed_seconds: float,
) -> dict[str, Any]:
    """The component result: the section, its findings, status/coverage and run_metrics.

    run_metrics holds what changes between two runs on an unchanged home (elapsed time);
    it is a sibling of the section so the caller can keep it out of the report digest.
    """
    env = make_component_envelope(
        findings=findings, coverage=coverage, extra={"secret_file_copies": section}
    )
    out = {k: env[k] for k in _ENVELOPE_KEYS}
    out["run_metrics"] = {"elapsed_seconds": elapsed_seconds}
    return out


def _has_ancestor_in(parts: tuple[str, ...], ancestors: set[tuple[str, ...]]) -> bool:
    """Pure prefix membership check; no I/O, and the path itself is excluded."""
    return any(parts[:k] in ancestors for k in range(1, len(parts)))


def _fixture_home_dirs(
    dir_child_names: dict[tuple[str, ...], set[str]],
) -> tuple[list[tuple[str, ...]], list[tuple[str, ...]]]:
    """Pure metadata classification, no I/O; retain outermost homes for membership checks."""
    all_fixture_dirs: list[tuple[str, ...]] = []
    for d_parts, c_names in sorted(dir_child_names.items()):
        if _is_fixture_home_dir(d_parts, c_names):
            all_fixture_dirs.append(d_parts)

    top_fixture_homes: list[tuple[str, ...]] = []
    top_fixture_homes_set: set[tuple[str, ...]] = set()
    for d_parts in all_fixture_dirs:
        if not _has_ancestor_in(d_parts, top_fixture_homes_set):
            top_fixture_homes.append(d_parts)
            top_fixture_homes_set.add(d_parts)
    return all_fixture_dirs, top_fixture_homes


_PendingBackup = tuple[tuple[str, ...], str, str, str, int, float]


def _resolve_backup_copies(
    pending_backups: list[_PendingBackup],
    live_secret_sizes: dict[tuple[tuple[str, ...], str], int],
) -> tuple[list[dict[str, Any]], int]:
    """Pure metadata comparison, no I/O; resolve copies without reporting raw sizes."""
    backup_copies_list: list[dict[str, Any]] = []
    same_size_count = 0
    for owner, secret_kind, live_name, scope, bak_size, mtime in pending_backups:
        live_size = live_secret_sizes.get((owner, live_name))
        if live_size is None and owner:
            live_size = live_secret_sizes.get(((), live_name))
        same_size = bool(live_size is not None and bak_size == live_size)
        if same_size:
            same_size_count += 1
        year, month = _mtime_year_month(mtime)
        backup_copies_list.append({
            "secret_kind": secret_kind,
            "scope": scope,
            "same_size_as_live": same_size,
            "year": year,
            "month": month,
        })
    return backup_copies_list, same_size_count


def _walk_secret_metadata(
    root_str: str,
    *,
    clock: Callable[[], float],
    start_time: float,
    max_entries: int,
    max_depth: int,
    max_seconds: float,
) -> tuple[
    list[tuple[tuple[str, ...], int, int, float]],
    dict[tuple[str, ...], set[str]],
    int, int, int, int, int, str | None,
]:
    """Collect listing/lstat metadata only; performs I/O but never opens files."""
    entries_walked = 0
    max_depth_reached = 0
    cuts = 0
    truncated_by: str | None = None

    regular_files: list[tuple[tuple[str, ...], int, int, float]] = []
    dir_child_names: dict[tuple[str, ...], set[str]] = {}
    symlinks_skipped = 0
    secret_named_symlinks = 0

    # Deterministic depth-first stack (pop from end; push sorted in reverse).
    stack: list[tuple[str, tuple[str, ...]]] = [(root_str, ())]
    while stack:
        if (clock() - start_time) > max_seconds:
            cuts += 1
            if truncated_by is None:
                truncated_by = "time_budget"
            break

        cur_path, rel_parts = stack.pop()
        depth = len(rel_parts)
        if depth > max_depth_reached:
            max_depth_reached = depth

        try:
            with os.scandir(cur_path) as it:
                raw_entries = list(it)
        except OSError:
            cuts += 1
            if truncated_by is None:
                truncated_by = "subpath_unreadable"
            continue

        raw_entries.sort(key=lambda e: e.name)
        child_names: set[str] = set()
        subdirs_to_push: list[tuple[str, tuple[str, ...]]] = []

        cap_hit = False
        for entry in raw_entries:
            if (clock() - start_time) > max_seconds:
                cuts += 1
                if truncated_by is None:
                    truncated_by = "time_budget"
                cap_hit = True
                break

            entries_walked += 1
            if entries_walked > max_entries:
                entries_walked = max_entries
                cuts += 1
                if truncated_by is None:
                    truncated_by = "max_entries"
                cap_hit = True
                break

            name = entry.name
            if _has_surrogate(name):
                cuts += 1
                if truncated_by is None:
                    truncated_by = "subpath_unreadable"
                continue

            if not _is_macos_stub(name):
                child_names.add(name)

            child_parts = rel_parts + (name,)
            try:
                st = os.lstat(entry.path)
            except OSError:
                cuts += 1
                if truncated_by is None:
                    truncated_by = "subpath_unreadable"
                continue

            mode = st.st_mode
            if stat.S_ISLNK(mode):
                # Counted by its own name only; the target is never read (no os.readlink).
                symlinks_skipped += 1
                if (
                    classify_secret_filename(name, child_parts) is not None
                    or _match_backup_of_expected_secret(child_parts) is not None
                ):
                    secret_named_symlinks += 1
                continue

            if stat.S_ISDIR(mode):
                next_depth = len(child_parts)
                if next_depth > max_depth:
                    cuts += 1
                    if truncated_by is None:
                        truncated_by = "max_depth"
                    continue
                subdirs_to_push.append((entry.path, child_parts))
            elif stat.S_ISREG(mode):
                if _is_macos_stub(name):
                    continue
                regular_files.append((child_parts, st.st_size, stat.S_IMODE(mode), st.st_mtime))

        dir_child_names[rel_parts] = child_names
        if cap_hit:
            break

        for item in reversed(subdirs_to_push):
            stack.append(item)

    return (
        regular_files, dir_child_names, symlinks_skipped, secret_named_symlinks,
        entries_walked, max_depth_reached, cuts, truncated_by,
    )


def audit_secret_file_copies(
    profile_path: str | Path,
    *,
    clock: Callable[[], float] = time.monotonic,
    max_entries: int = MAX_ENTRIES,
    max_depth: int = MAX_DEPTH,
    max_seconds: float = MAX_SECONDS,
) -> dict[str, Any]:
    """Audit secret file copies and secret-named files using directory listings and lstat only."""
    limits_kw = dict(max_entries=max_entries, max_depth=max_depth, max_seconds=max_seconds)
    try:
        raw_root = os.fsdecode(os.fspath(profile_path))
        if not raw_root or "\x00" in raw_root:
            raise ValueError("empty or NUL-containing profile path")
    except (TypeError, ValueError):
        return _not_measured("invalid_path", **limits_kw)
    root_str = raw_root
    # String normalisation only (os.getcwd for a relative path; no file is touched).
    root_abs = os.path.abspath(root_str)
    start_time = clock()

    try:
        root_st = os.lstat(root_str)
    except FileNotFoundError:
        return _not_measured("missing", **limits_kw)
    except (OSError, ValueError):
        return _not_measured("unreadable", **limits_kw)

    if stat.S_ISLNK(root_st.st_mode):
        return _not_measured("symlink_root", **limits_kw)

    if not stat.S_ISDIR(root_st.st_mode):
        return _not_measured("not_directory", **limits_kw)

    (
        regular_files, dir_child_names, symlinks_skipped, secret_named_symlinks,
        entries_walked, max_depth_reached, cuts, truncated_by,
    ) = _walk_secret_metadata(
        root_str, clock=clock, start_time=start_time,
        max_entries=max_entries, max_depth=max_depth, max_seconds=max_seconds,
    )

    # Identify nested fixture home directories (excluding the real home and profiles/<name>).
    all_fixture_dirs, top_fixture_homes = _fixture_home_dirs(dir_child_names)
    top_fixture_homes_set = set(top_fixture_homes)

    live_secret_sizes: dict[tuple[tuple[str, ...], str], int] = {}
    expected_by_kind: Counter[str] = Counter({k: 0 for k in EXPECTED_SECRET_KINDS})

    regular_files.sort(key=lambda row: row[0])
    all_file_modes: list[int] = []
    secret_file_modes: list[int] = []

    config_backup_total = 0
    config_backup_root = 0
    config_backup_profile = 0
    config_backup_dir_count = 0
    config_backup_mtimes_by_owner: dict[tuple[str, ...], list[float]] = defaultdict(list)

    pending_backups: list[_PendingBackup] = []
    fixture_secret_by_class: Counter[str] = Counter()
    work_secret_by_top: Counter[str] = Counter()
    work_classes_by_top: dict[str, Counter[str]] = defaultdict(Counter)
    work_secret_by_class: Counter[str] = Counter()
    example_locations: list[dict[str, str]] = []
    example_seen: set[tuple[str, str]] = set()
    plugin_dotenv_count = 0
    plugin_folders_with_dotenv: set[str] = set()
    name_cache: dict[str, str | None] = {}

    for rel_parts, size, imode, mtime in regular_files:
        all_file_modes.append(imode)

        if _has_ancestor_in(rel_parts, top_fixture_homes_set):
            cls = classify_secret_filename(rel_parts[-1], rel_parts, name_cache)
            if cls is not None:
                fixture_secret_by_class[cls] += 1
                secret_file_modes.append(imode)
            continue

        if _is_hermes_non_secret(rel_parts):
            continue

        if _is_config_backup(rel_parts):
            config_backup_total += 1
            # profiles/<name>/ and profiles/.deleted/ copies both belong to a profile.
            owner = rel_parts[:2] if len(rel_parts) >= 3 and rel_parts[0] == "profiles" else ()
            if owner:
                config_backup_profile += 1
            else:
                config_backup_root += 1
            sub = _profile_subpath(rel_parts)
            if sub and len(sub) >= 3 and sub[0].lower() == "backups" and sub[1].lower() == "config":
                config_backup_dir_count += 1
            config_backup_mtimes_by_owner[owner].append(mtime)
            continue

        exp_kind = _expected_secret_kind(rel_parts, name_cache)
        if exp_kind == _IGNORED:
            continue
        if exp_kind is not None:
            expected_by_kind[exp_kind] += 1
            owner = _owning_root_parts(rel_parts)
            live_secret_sizes[(owner, rel_parts[-1].lower())] = size
            secret_file_modes.append(imode)
            continue

        bak_match = _match_backup_of_expected_secret(rel_parts)
        if bak_match is not None:
            secret_kind, live_name, scope = bak_match
            owner = _owning_root_parts(rel_parts)
            pending_backups.append((owner, secret_kind, live_name, scope, size, mtime))
            secret_file_modes.append(imode)
            continue

        cls = classify_secret_filename(rel_parts[-1], rel_parts, name_cache)
        if cls is not None:
            top_path = _top_folder_path(root_abs, rel_parts)
            work_secret_by_top[top_path] += 1
            work_classes_by_top[top_path][cls] += 1
            work_secret_by_class[cls] += 1
            loc = (top_path, cls)
            if loc not in example_seen and len(example_locations) < MAX_EXAMPLE_LOCATIONS:
                example_seen.add(loc)
                example_locations.append({"path": top_path, "class": cls})
            secret_file_modes.append(imode)

            plugin_parts = _is_plugin_dotenv(rel_parts)
            if plugin_parts is not None:
                plugin_dotenv_count += 1
                plugin_folders_with_dotenv.add(os.path.join(root_abs, *plugin_parts))

    backup_copies_list, same_size_count = _resolve_backup_copies(pending_backups, live_secret_sizes)

    mode_check, mode_check_reason = _mode_check(all_file_modes)
    readable_by_others_count: int | None = None
    if mode_check == "verified":
        readable_by_others_count = sum(1 for m in secret_file_modes if (m & 0o077) != 0)

    total_bursts = 0
    max_burst_files = 0
    for owner_mtimes in config_backup_mtimes_by_owner.values():
        b_cnt, b_max = _compute_bursts(owner_mtimes)
        total_bursts += b_cnt
        if b_max > max_burst_files:
            max_burst_files = b_max

    work_secret_total = sum(work_secret_by_class.values())
    fixture_secret_total = sum(fixture_secret_by_class.values())
    expected_total = sum(expected_by_kind.values())

    coverage = "could_not_verify" if cuts > 0 else "verified"

    findings: list[dict[str, Any]] = []
    if len(backup_copies_list) >= BACKUP_COPIES_WARNING_THRESHOLD:
        findings.append(
            _finding(
                "secret_file_copies.backup_copies_of_secret_files",
                {
                    "count": len(backup_copies_list),
                    "same_size_as_live_count": same_size_count,
                },
                classification="warning",
            )
        )

    if work_secret_total >= WORK_FOLDER_SECRET_FILES_WARNING_THRESHOLD:
        findings.append(
            _finding(
                "secret_file_copies.secret_named_files_in_work_folders",
                {
                    "count": work_secret_total,
                    "folder_count": len(work_secret_by_top),
                    "class_count": len(work_secret_by_class),
                },
                classification="warning",
            )
        )

    if fixture_secret_total >= FIXTURE_HOME_SECRET_FILES_THRESHOLD:
        findings.append(
            _finding(
                "secret_file_copies.secret_named_files_in_fixture_homes",
                {
                    "count": fixture_secret_total,
                    "fixture_home_count": len(top_fixture_homes),
                },
                classification="review_suggested",
            )
        )

    if plugin_dotenv_count >= PLUGIN_SECRET_FILE_THRESHOLD:
        findings.append(
            _finding(
                "secret_file_copies.plugin_holds_secret_file",
                {
                    "count": plugin_dotenv_count,
                    "plugin_count": len(plugin_folders_with_dotenv),
                },
                classification="review_suggested",
            )
        )

    if (
        readable_by_others_count is not None
        and readable_by_others_count >= READABLE_BY_OTHERS_WARNING_THRESHOLD
    ):
        findings.append(
            _finding(
                "secret_file_copies.readable_by_others",
                {
                    "count": readable_by_others_count,
                    "checked_count": len(secret_file_modes),
                },
                classification="warning",
            )
        )

    if config_backup_total >= CONFIG_BACKUP_INFO_THRESHOLD:
        cfg_cls = (
            "review_suggested"
            if config_backup_total > CONFIG_BACKUP_REVIEW_THRESHOLD
            else "info"
        )
        findings.append(
            _finding(
                "secret_file_copies.config_backup_copies",
                {
                    "count": config_backup_total,
                    "burst_count": total_bursts,
                    "max_burst_files": max_burst_files,
                    "review_threshold": CONFIG_BACKUP_REVIEW_THRESHOLD,
                },
                classification=cfg_cls,
            )
        )

    if cuts > 0:
        findings.append(
            _finding(
                "secret_file_copies.could_not_verify",
                {
                    "cuts": cuts,
                    "entries_walked": entries_walked,
                    "truncated_by": truncated_by or "limit_exceeded",
                },
                classification="info",
                coverage="could_not_verify",
            )
        )

    section: dict[str, Any] = {
        "coverage": coverage,
        "status": "completed",
        "reason": None,
        "truncated_by": truncated_by,
        "expected_secret_files": {
            "total": expected_total,
            "by_kind": {k: expected_by_kind[k] for k in EXPECTED_SECRET_KINDS},
        },
        "backup_copies": {
            "count": len(backup_copies_list),
            "same_size_as_live_count": same_size_count,
            "copies": backup_copies_list,
        },
        "secret_named_files": {
            "count": work_secret_total,
            "by_top_level_folder": [
                {
                    "path": top_path,
                    "count": work_secret_by_top[top_path],
                    "classes": dict(sorted(work_classes_by_top[top_path].items())),
                }
                for top_path in sorted(work_secret_by_top)
            ],
            "by_pattern_class": dict(sorted(work_secret_by_class.items())),
            "example_locations": example_locations,
            "plugin_dotenv_count": plugin_dotenv_count,
            "plugin_folders_with_dotenv": sorted(plugin_folders_with_dotenv),
            "top_level_folder_count": len(work_secret_by_top),
            "plugin_folder_count": len(plugin_folders_with_dotenv),
        },
        "fixture_homes": {
            "fixture_home_count": len(top_fixture_homes),
            "fixture_profile_dir_count": len(all_fixture_dirs),
            "secret_named_file_count": fixture_secret_total,
            "by_pattern_class": dict(sorted(fixture_secret_by_class.items())),
            "note": FIXTURE_HOMES_NOTE,
        },
        "mode_bits": {
            "mode_check": mode_check,
            "mode_check_reason": mode_check_reason,
            "readable_by_others_count": readable_by_others_count,
            "checked_count": len(secret_file_modes),
        },
        "config_backups": {
            "count": config_backup_total,
            "root_count": config_backup_root,
            "profile_count": config_backup_profile,
            "backups_config_dir_count": config_backup_dir_count,
            "burst_count": total_bursts,
            "max_burst_files": max_burst_files,
            "reason": "configs_may_embed_keys_not_read",
        },
        "symlinks": {
            "symlinks_skipped": symlinks_skipped,
            "secret_named_symlinks": secret_named_symlinks,
        },
        "limits": {
            "max_entries": max_entries,
            "max_depth": max_depth,
            "max_seconds": max_seconds,
            "entries_walked": entries_walked,
            "max_depth_reached": max_depth_reached,
            "cuts": cuts,
        },
        "thresholds": _thresholds(),
    }
    elapsed = clock() - start_time
    elapsed_seconds = round(elapsed, 3) if isinstance(elapsed, (int, float)) and elapsed >= 0 else 0.0
    return _envelope(findings, coverage, section, elapsed_seconds=float(elapsed_seconds))
