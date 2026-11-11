# vendored module (origin: hermes_audit/executable_inventory.py, from the author's audit toolkit; not published separately). Do not edit: change the origin and re-vendor.
"""Executable inventory audit component (pinned audit YAML parser, plain-data inputs).

Implements the 'Executable inventory' check from `hermes-adopt-audit-redesign.md` §5
(with §1, §2, §3, §6, §11, §12, §13 constraints):
- Statically lists plugin manifests (`plugin.yaml` / `plugin.json` / `dashboard/manifest.json`),
  shell hook and outbound webhook declarations (`config.yaml` `hooks:`), and MCP server
  declarations (`config.yaml` `mcp_servers:` and portable `mcp.json`) with full provenance
  (`profile`, `source_path`, `source_kind`).
- Redacts secrets everywhere before emitting inventory records or findings:
  - Environment mappings (`env`) keep KEYS ONLY (`env_keys`); values are never retained.
  - HTTP headers keep HEADER NAMES ONLY (`header_names`); header values are never retained.
  - Webhook `secret` values are replaced with `<redacted>` (`has_inline_secret=True`).
  - Command arguments and URLs are scrubbed for URL userinfo (`user:pass@`), secret flags
    (`--api-key=...`, `--token ...`, `-H "Authorization: ..."`), token prefixes (`sk-`, `ghp_`,
    `github_pat_`, `AKIA`, `xoxb-`, JWTs, PEM blocks), and secret assignments.
- Declarations that require execution or dynamic runtime registration to discover (e.g.
  `register(ctx)` hook/tool/skill callbacks, entry-point plugins not inspectable from static
  files, live MCP tool schemas) are explicitly reported with `coverage="could_not_verify"`.
- Emits `info` findings for the static declaration inventory and escalates to `warning` when:
  - A declaration executes from a world-writable or project-relative/unanchored relative path.
  - An MCP server or hook command matches a known indicators-of-compromise / shell-egress /
    persistence backdoor shape or embeds raw inline credentials in arguments/URLs.
- The IOC / shell-egress / persistence shape check is NOT owned here: the caller injects
  `entry_security_check` (in Hermes, `hermes_cli.mcp_security.validate_mcp_server_entry`, the
  same check Hermes enforces at MCP save and spawn time). Without it the shape check does not
  run and declaration findings carry `coverage="could_not_verify"`, never a clean verdict.
-Note on `evidence` keys: `evidence` dicts never use forbidden executable
  fix keys (`cmd`, `command`, `commands`, `script`, `argv`, etc.), using descriptive declaration
  keys (`declared_executable`, `declared_args`, `hook_executable`, etc.) instead.

Input TypedDicts (plain data produced by the caller):
```python
class PluginManifestInput(TypedDict, total=False):
    profile: str
    plugin_id: str
    source_path: str          # Path to plugin.yaml / plugin.json
    plugin_dir: str           # Directory containing the plugin
    manifest_text: str        # Raw YAML or JSON text of the manifest
    manifest_data: dict[str, Any]
    mcp_json_text: str        # Optional portable mcp.json text
    has_init_py: bool         # True if __init__.py exists (dynamic register(ctx))
    world_writable: bool      # True if plugin_dir or manifest is world-writable
    coverage: str

class ProfileExecutableConfigInput(TypedDict, total=False):
    profile: str
    profile_dir: str
    config_path: str
    config_text: str
    config_data: dict[str, Any]
    plugin_manifests: list[PluginManifestInput]
    world_writable_paths: list[str]
    coverage: str

class ExecutableInventoryInput(TypedDict, total=False):
    profiles: list[ProfileExecutableConfigInput]
    plugin_manifests: list[PluginManifestInput]
```
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
import urllib.parse
from typing import Any, Callable, Iterable, Mapping, Sequence, TypedDict

__all__ = [
    "COMPONENT_VERSION",
    "EMPTY_INPUT",
    "ExecutableInventoryInput",
    "PluginManifestInput",
    "ProfileExecutableConfigInput",
    "audit_executable_inventory",
    "redact_arg_or_url",
    "run",
]

COMPONENT_VERSION = "1.1.0+defuzz.credential-redaction-v2"

CLASSIFICATION_WARNING = "warning"
CLASSIFICATION_REVIEW = "review_suggested"
CLASSIFICATION_INFO = "info"

COVERAGE_VERIFIED = "verified"
COVERAGE_COULD_NOT_VERIFY = "could_not_verify"

# `(name, {"command", "args", "env"}) -> issues`: the shape of
# `hermes_cli.mcp_security.validate_mcp_server_entry`, injected by the plugin runner.
EntrySecurityCheck = Callable[[str, dict[str, Any]], Sequence[str]]
COVERAGE_NOT_INCLUDED = "not_included"

REDACTED_PLACEHOLDER = "<redacted>"

_CLASSIFICATION_RANK: dict[str, int] = {
    CLASSIFICATION_WARNING: 3,
    CLASSIFICATION_REVIEW: 2,
    CLASSIFICATION_INFO: 1,
}

_CLASSIFICATION_TO_LEGACY_SEVERITY: dict[str, str] = {
    CLASSIFICATION_WARNING: "warn",
    CLASSIFICATION_REVIEW: "warn",
    CLASSIFICATION_INFO: "info",
}

_FORBIDDEN_EVIDENCE_KEYS: frozenset[str] = frozenset({
    "cmd",
    "command",
    "commands",
    "script",
    "shell_cmd",
    "executable_fix",
    "fix_cmd",
    "fix_command",
    "fix_script",
    "argv",
})

_SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|_|-)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|client[_-]?secret|auth[_-]?token|credential|bearer)s?(?:$|_|-)"
)

# Copied secret content patterns (never importing secret_sniffer per standalone stdlib rule)
_TOKEN_PREFIX_RE = re.compile(
    r"\b(?:"
    r"sk-[A-Za-z0-9_-]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|gho_[A-Za-z0-9]{20,}"
    r"|ghu_[A-Za-z0-9]{20,}"
    r"|ghs_[A-Za-z0-9]{20,}"
    r"|ghr_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{16,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")\b"
)

_PEM_HEADER_RE = re.compile(r"BEGIN\s+(?:[A-Z0-9]+\s+)?PRIVATE\s+KEY")

# LOCAL PATCH linear-redaction-regex-v1: bounded negative lookbehind, not an
# unbounded `[A-Z0-9_]*_` prefix (upstream f4cd65c). Value minimum stays {1,},
# not upstream {6,}: short assignment secrets must still be redacted.
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<prefix>(?<![A-Za-z0-9])(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|password|token|secret|bearer)[\"']?\s*[=:]\s*[\"']?)"
    r"(?!(?:YOUR_|CHANGE_ME|REPLACE_|EXAMPLE|NONE|NULL|TRUE|FALSE|<redacted>|\$\{))"
    r"(?P<val>[^\s\"']{1,})"
)

_SECRET_FLAG_NAME_RE = re.compile(
    r"(?i)^-{1,2}(?:api[-_]?key|token|access[-_]?token|auth[-_]?token|secret|client[-_]?secret|password|passwd|bearer)$"
)

# LOCAL PATCH linear-redaction-regex-v1: one whitespace/auth-scheme split so
# optional scheme and whitespace cannot overlap (upstream 6cc2d03).
_AUTH_HEADER_INLINE_RE = re.compile(
    r"(?i)(authorization\s*:\s*(?:(?:bearer|basic|token)\s+)?)([^\s\"',;]+)"
)

class PluginManifestInput(TypedDict, total=False):
    profile: str
    plugin_id: str
    source_path: str
    plugin_dir: str
    manifest_text: str
    manifest_data: Mapping[str, Any]
    mcp_json_text: str
    has_init_py: bool
    world_writable: bool
    coverage: str


class ProfileExecutableConfigInput(TypedDict, total=False):
    profile: str
    profile_dir: str
    config_path: str
    config_text: str
    config_data: Mapping[str, Any]
    plugin_manifests: Sequence[PluginManifestInput]
    world_writable_paths: Sequence[str]
    coverage: str


class ExecutableInventoryInput(TypedDict, total=False):
    profiles: Sequence[ProfileExecutableConfigInput]
    plugin_manifests: Sequence[PluginManifestInput]


EMPTY_INPUT: dict[str, Any] = {
    "profiles": [],
    "plugin_manifests": [],
}


def _as_seq(val: Any) -> Sequence[Any]:
    if isinstance(val, Sequence) and not isinstance(val, (str, bytes, bytearray)):
        return val
    return ()


def _sanitize_evidence(value: Any, *, _key_hint: str = "") -> Any:
    if callable(value):
        raise ValueError("Callable objects are forbidden in audit finding evidence")
    if _key_hint and _key_hint.lower() in _FORBIDDEN_EVIDENCE_KEYS:
        raise ValueError(f"Executable fix field {_key_hint!r} is forbidden inside finding evidence")
    if _key_hint and _SECRET_KEY_RE.search(_key_hint):
        return REDACTED_PLACEHOLDER
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in sorted(value.items(), key=lambda item: str(item[0])):
            k_str = str(k)
            if k_str.lower() in _FORBIDDEN_EVIDENCE_KEYS:
                raise ValueError(f"Executable fix field {k_str!r} is forbidden inside finding evidence")
            out[k_str] = _sanitize_evidence(v, _key_hint=k_str)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        seq = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        return [_sanitize_evidence(item) for item in seq]
    return str(value)


def _normalize_source_paths(source_paths: Sequence[Mapping[str, Any] | str] | None) -> list[dict[str, Any]]:
    if not source_paths:
        return []
    out: list[dict[str, Any]] = []
    for entry in source_paths:
        if isinstance(entry, str):
            out.append({"path": entry, "start_line": None, "end_line": None})
        elif isinstance(entry, Mapping):
            p = str(entry.get("path") or "").strip()
            s_line = entry.get("start_line", entry.get("line"))
            e_line = entry.get("end_line", s_line)
            out.append({
                "path": p,
                "start_line": int(s_line) if isinstance(s_line, int) and s_line > 0 else None,
                "end_line": int(e_line) if isinstance(e_line, int) and e_line > 0 else None,
            })
        else:
            out.append({"path": str(entry), "start_line": None, "end_line": None})
    out.sort(
        key=lambda item: (
            item["path"],
            item["start_line"] if item["start_line"] is not None else -1,
            item["end_line"] if item["end_line"] is not None else -1,
        )
    )
    return out


def _make_finding(
    *,
    rule_id: str,
    classification: str,
    coverage: str = COVERAGE_VERIFIED,
    affected_identities: Sequence[str] = (),
    source_paths: Sequence[Mapping[str, Any] | str] = (),
    evidence: Mapping[str, Any] | None = None,
    consequence: str,
    limitations: str = "",
    proposed_cleanup_id: str | None = None,
    fix: str | None = None,
) -> dict[str, Any]:
    identities = sorted({str(x).strip() for x in affected_identities if str(x).strip()})
    paths = _normalize_source_paths(source_paths)
    clean_ev = _sanitize_evidence(dict(evidence) if evidence is not None else {})
    consequence_str = str(consequence).strip()
    limitations_str = str(limitations).strip()
    sev = _CLASSIFICATION_TO_LEGACY_SEVERITY.get(classification, "info")

    return {
        "id": str(rule_id).strip(),
        "classification": classification,
        "coverage": coverage,
        "affected_identities": identities,
        "source_paths": paths,
        "evidence": clean_ev,
        "consequence": consequence_str,
        "limitations": limitations_str,
        "proposed_cleanup_id": proposed_cleanup_id,
        "severity": sev,
        "detail": consequence_str,
        "fix": str(fix) if fix is not None else None,
    }


def _finding_sort_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    cls_name = str(finding.get("classification") or CLASSIFICATION_INFO)
    rank = _CLASSIFICATION_RANK.get(cls_name, 0)
    identities = tuple(finding.get("affected_identities") or ())
    paths = tuple(
        (
            str(p.get("path") or ""),
            int(p["start_line"]) if isinstance(p.get("start_line"), int) else -1,
        )
        for p in (finding.get("source_paths") or ())
        if isinstance(p, Mapping)
    )
    return (
        -rank,
        str(finding.get("id") or ""),
        identities,
        paths,
        str(finding.get("consequence") or ""),
        str(finding.get("proposed_cleanup_id") or ""),
    )


def _redact_url(raw_url: str) -> tuple[str, bool]:
    """Redact userinfo (`user:pass@`) and secret query parameters from a URL."""
    s = str(raw_url or "").strip()
    if "://" not in s:
        return s, False
    try:
        parts = urllib.parse.urlsplit(s)
    except ValueError:
        return REDACTED_PLACEHOLDER, True

    redacted = False
    netloc = parts.netloc
    if "@" in netloc:
        _, hostpart = netloc.rsplit("@", 1)
        netloc = f"{REDACTED_PLACEHOLDER}@{hostpart}"
        redacted = True

    query = parts.query
    if query:
        q_pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        new_pairs: list[tuple[str, str]] = []
        for k, v in q_pairs:
            if v:  # Local policy: opaque custom parameters can carry credentials.
                new_pairs.append((k, REDACTED_PLACEHOLDER))
                redacted = True
            else:
                new_pairs.append((k, v))
        if redacted:
            query = urllib.parse.urlencode(new_pairs)

    fragment = REDACTED_PLACEHOLDER if parts.fragment else ""
    redacted = redacted or bool(parts.fragment)
    rebuilt = urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, query, fragment))
    return rebuilt, redacted


def redact_arg_or_url(text: str) -> tuple[str, bool]:
    """Redact credentials, tokens, PEM headers, URL userinfo, and secret assignments in a single string.

    Returns `(redacted_text, was_redacted)`.
    """
    raw = str(text or "")
    if not raw:
        return "", False

    changed = False
    out = raw

    if "://" in out:
        out_url, url_red = _redact_url(out)
        if url_red:
            out = out_url
            changed = True

    if _PEM_HEADER_RE.search(out):
        return REDACTED_PLACEHOLDER, True

    if _AUTH_HEADER_INLINE_RE.search(out):
        out = _AUTH_HEADER_INLINE_RE.sub(rf"\1{REDACTED_PLACEHOLDER}", out)
        changed = True

    if _SECRET_ASSIGNMENT_RE.search(out):
        out = _SECRET_ASSIGNMENT_RE.sub(rf"\g<prefix>{REDACTED_PLACEHOLDER}", out)
        changed = True

    if _TOKEN_PREFIX_RE.search(out):
        out = _TOKEN_PREFIX_RE.sub(REDACTED_PLACEHOLDER, out)
        changed = True

    return out, changed


def _redact_args_list(args: Sequence[Any]) -> tuple[list[str], bool]:
    """Redact a sequence of CLI arguments, handling both `--token=val` and two-token `['--token', 'val']`."""
    redacted_list: list[str] = []
    any_redacted = False
    skip_next = False

    for idx, raw_arg in enumerate(args):
        if skip_next:
            skip_next = False
            redacted_list.append(REDACTED_PLACEHOLDER)
            any_redacted = True
            continue
        arg_str = str(raw_arg)
        if _SECRET_FLAG_NAME_RE.match(arg_str.strip()) and idx + 1 < len(args):
            redacted_list.append(arg_str)
            skip_next = True
            continue
        # Handle `-H` / `--header` followed by `Authorization: ...`
        if arg_str.strip() in ("-H", "--header") and idx + 1 < len(args):
            next_str = str(args[idx + 1])
            if _SECRET_KEY_RE.search(next_str) or "authorization" in next_str.lower():
                redacted_list.append(arg_str)
                skip_next = True
                continue
        red_item, was_red = redact_arg_or_url(arg_str)
        if was_red:
            any_redacted = True
        redacted_list.append(red_item)

    return redacted_list, any_redacted


def _redact_command_string(cmd_str: str) -> tuple[str, list[str], bool]:
    """Split a shell command string into tokens, redact secrets, and return `(executable, redacted_args, was_redacted)`."""
    s = str(cmd_str or "").strip()
    if not s:
        return "", [], False
    try:
        tokens = shlex.split(s, posix=True)
    except ValueError:
        tokens = s.split()
    if not tokens:
        return "", [], False
    exe_red, exe_was_red = redact_arg_or_url(tokens[0])
    args_red, args_was_red = _redact_args_list(tokens[1:])
    return exe_red, args_red, (exe_was_red or args_was_red)


def _is_project_relative_executable(executable: str, cwd: str | None = None) -> bool:
    """Return True if `executable` runs from a relative path (e.g. `./...`, `../...`, or `subdir/bin`)."""
    exe = str(executable or "").strip()
    if not exe:
        return False
    if exe.startswith(("./", "../", ".\\", "..\\")):
        return True
    # A path with slashes that does not start with `/`, `~`, `$`, or Windows drive letter is project/cwd-relative
    if ("/" in exe or "\\" in exe) and not (
        exe.startswith(("/", "~", "$"))
        or re.match(r"^[A-Za-z]:[/\\]", exe)
    ):
        return True
    if cwd and str(cwd).strip().startswith(("./", "../")):
        return True
    return False


def _parse_yaml_or_json(text: str) -> tuple[dict[str, Any] | None, str | None]:
    """Parse JSON or use the audit's pinned, fail-closed YAML parser.

    LOCAL PATCH: share parser approval and normalization with audit.facts;
    never substitute heuristic YAML parsing when the dependency is unavailable.
    """
    s = str(text or "").strip()
    if s.startswith("{"):
        try:
            loaded = json.loads(s)
            if isinstance(loaded, dict):
                return loaded, None
            return None, "Top-level JSON value must be an object"
        except (ValueError, TypeError) as exc:
            return None, f"Invalid JSON: {exc}"

    try:
        from ..facts import _parse_simple_yaml_mapping

        return _parse_simple_yaml_mapping(s), None
    except Exception:
        # Do not expose parser exception text, which may include source secrets.
        return None, "YAML could not be verified with the approved audit parser"


def _normalize_str_list(raw: Any) -> list[str]:
    if isinstance(raw, str):
        return [raw.strip()] if raw.strip() else []
    if isinstance(raw, Sequence):
        return [str(x).strip() for x in raw if str(x).strip()]
    return []


def _extract_requires_env_keys(raw: Any) -> list[str]:
    if not isinstance(raw, Sequence) or isinstance(raw, str):
        return []
    keys: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            keys.append(item.strip())
        elif isinstance(item, Mapping) and item.get("name"):
            keys.append(str(item["name"]).strip())
        elif isinstance(item, Mapping) and item.get("key"):
            keys.append(str(item["key"]).strip())
    return sorted(set(keys))


def _check_mcp_ioc_or_shell_risk(
    name: str,
    executable: str,
    args: Sequence[str],
    env: Mapping[str, Any] | None,
    check: EntrySecurityCheck | None,
) -> tuple[list[str], str]:
    """``(issues, coverage)`` from the injected IOC / shell egress / persistence check.

    No checker (or one that rejects the entry) means the shape check did not run: coverage is
    ``could_not_verify`` and the declaration must not be reported as clean.
    """
    if check is None:
        return [], COVERAGE_COULD_NOT_VERIFY
    entry: dict[str, Any] = {"command": executable, "args": list(args)}
    if isinstance(env, Mapping):
        entry["env"] = dict(env)
    try:
        return [str(issue) for issue in check(name, entry)], COVERAGE_VERIFIED
    except (TypeError, ValueError):
        return [], COVERAGE_COULD_NOT_VERIFY


def _process_plugin_manifest(
    raw_plugin: Mapping[str, Any],
    *,
    default_profile: str = "default",
    world_writable_set: set[str],
    entry_security_check: EntrySecurityCheck | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], str]:
    """Parse and inventory one static plugin manifest (`plugin.yaml` or `plugin.json`)."""
    findings: list[dict[str, Any]] = []
    portable_mcp_records: list[dict[str, Any]] = []
    profile = str(raw_plugin.get("profile") or default_profile).strip() or "default"
    src_path = str(raw_plugin.get("source_path") or raw_plugin.get("path") or "").strip()
    plugin_dir = str(raw_plugin.get("plugin_dir") or (posixpath.dirname(src_path) if src_path else "")).strip()
    cov = str(raw_plugin.get("coverage") or COVERAGE_VERIFIED).strip()
    is_ww = bool(raw_plugin.get("world_writable")) or (src_path in world_writable_set) or (plugin_dir in world_writable_set)
    has_init_py = bool(raw_plugin.get("has_init_py", False))

    data: Mapping[str, Any] | None = None
    parse_err: str | None = None
    raw_data = raw_plugin.get("manifest_data")
    raw_text = raw_plugin.get("manifest_text")
    if isinstance(raw_data, Mapping):
        data = raw_data
    elif isinstance(raw_text, str):
        data, parse_err = _parse_yaml_or_json(raw_text)
    else:
        # LOCAL PATCH uncaptured-manifest-v1: directory metadata is not a
        # parsed empty manifest and cannot substantiate verified inventory.
        parse_err = "Plugin manifest not captured or unreadable"

    if parse_err is not None or data is None or cov == COVERAGE_COULD_NOT_VERIFY:
        cov = COVERAGE_COULD_NOT_VERIFY
        pid = str(raw_plugin.get("plugin_id") or raw_plugin.get("name") or (posixpath.basename(plugin_dir) if plugin_dir else "unknown"))
        findings.append(
            _make_finding(
                rule_id="executable_inventory.plugin_manifest_unverified",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[profile],
                source_paths=[src_path] if src_path else (),
                evidence={
                    "error": parse_err or "unreadable manifest",
                    "plugin_id": pid,
                    "profile": profile,
                    "source_path": src_path,
                },
                consequence=f"Plugin manifest for {pid!r} in profile {profile!r} could not be statically parsed.",
                limitations=parse_err or "Manifest unreadable.",
            )
        )
        return (
            {
                "profile": profile,
                "plugin_id": pid,
                "version": "",
                "kind": "unknown",
                "provides_hooks": [],
                "provides_tools": [],
                "requires_env_keys": [],
                "source_dir": plugin_dir,
                "source_path": src_path,
                "coverage": COVERAGE_COULD_NOT_VERIFY,
            },
            portable_mcp_records,
            findings,
            COVERAGE_COULD_NOT_VERIFY,
        )

    plugin_id = str(data.get("name") or raw_plugin.get("plugin_id") or (posixpath.basename(plugin_dir) if plugin_dir else "unknown")).strip()
    version = str(data.get("version") or "").strip()
    kind = str(data.get("kind") or ("portable" if src_path.endswith("plugin.json") else "standalone")).strip()
    provides_hooks = sorted(set(_normalize_str_list(data.get("provides_hooks") or data.get("hooks"))))
    provides_tools = sorted(set(_normalize_str_list(data.get("provides_tools"))))
    requires_env_keys = _extract_requires_env_keys(data.get("requires_env"))
    capabilities = sorted(set(_normalize_str_list(data.get("capabilities"))))

    # Dynamic registration check: if the plugin has `__init__.py` (`register(ctx)`), dynamic hooks/tools/skills
    # that aren't statically verifiable without executing Python are noted as `could_not_verify` when undeclared.
    dynamic_cov = COVERAGE_VERIFIED
    if has_init_py and not provides_hooks and not provides_tools:
        dynamic_cov = COVERAGE_COULD_NOT_VERIFY
        findings.append(
            _make_finding(
                rule_id="executable_inventory.plugin_dynamic_registrations_unverified",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[profile],
                source_paths=[src_path] if src_path else (),
                evidence={
                    "has_init_py": True,
                    "plugin_id": plugin_id,
                    "profile": profile,
                    "source_dir": plugin_dir,
                    "source_path": src_path,
                },
                consequence=(
                    f"Plugin {plugin_id!r} in profile {profile!r} contains executable Python code (__init__.py) "
                    "with no static provides_hooks/provides_tools declarations; runtime registrations cannot be verified without execution."
                ),
                limitations="Static sweep never imports or executes plugin __init__.py (§1, §5).",
            )
        )

    record = {
        "profile": profile,
        "plugin_id": plugin_id,
        "version": version,
        "kind": kind,
        "provides_hooks": provides_hooks,
        "provides_tools": provides_tools,
        "capabilities": capabilities,
        "requires_env_keys": requires_env_keys,
        "source_dir": plugin_dir,
        "source_path": src_path,
        "world_writable": is_ww,
        "coverage": dynamic_cov,
    }

    if is_ww:
        findings.append(
            _make_finding(
                rule_id="executable_inventory.plugin_world_writable",
                classification=CLASSIFICATION_WARNING,
                coverage=COVERAGE_VERIFIED,
                affected_identities=[profile],
                source_paths=[src_path or plugin_dir],
                evidence={
                    "plugin_id": plugin_id,
                    "profile": profile,
                    "source_dir": plugin_dir,
                    "source_path": src_path,
                },
                consequence=(
                    f"Plugin {plugin_id!r} in profile {profile!r} resides in a world-writable path ({plugin_dir or src_path}); "
                    "other local users could tamper with plugin code executed by Hermes."
                ),
                limitations="Static permission metadata check.",
            )
        )
    else:
        findings.append(
            _make_finding(
                rule_id="executable_inventory.plugin_manifest",
                classification=CLASSIFICATION_INFO,
                coverage=dynamic_cov,
                affected_identities=[profile],
                source_paths=[src_path] if src_path else (),
                evidence={
                    "capabilities": capabilities,
                    "kind": kind,
                    "plugin_id": plugin_id,
                    "profile": profile,
                    "provides_hooks": provides_hooks,
                    "provides_tools": provides_tools,
                    "requires_env_keys": requires_env_keys,
                    "source_dir": plugin_dir,
                    "version": version,
                },
                consequence=(
                    f"Plugin {plugin_id!r} (v{version or 'unspecified'}) declared in {profile!r} "
                    f"(hooks: {len(provides_hooks)}, tools: {len(provides_tools)})."
                ),
                limitations="Static manifest read only; plugin code is not executed.",
            )
        )

    # Check optional portable `mcp.json` inside the plugin
    mcp_json_text = raw_plugin.get("mcp_json_text")
    if isinstance(mcp_json_text, str) and mcp_json_text.strip():
        mcp_data, mcp_err = _parse_yaml_or_json(mcp_json_text)
        mcp_src = f"{plugin_dir}/mcp.json" if plugin_dir else src_path
        if mcp_err or not isinstance(mcp_data, Mapping):
            dynamic_cov = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="executable_inventory.mcp_declaration_unverified",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[profile],
                    source_paths=[mcp_src] if mcp_src else (),
                    evidence={"error": mcp_err or "invalid mcp.json", "plugin_id": plugin_id, "profile": profile},
                    consequence=f"Portable mcp.json for plugin {plugin_id!r} could not be parsed.",
                    limitations=mcp_err or "Malformed mcp.json.",
                )
            )
        else:
            servers_map = mcp_data.get("mcpServers")
            if isinstance(servers_map, Mapping):
                for sname, scfg in sorted(servers_map.items(), key=lambda x: str(x[0])):
                    if isinstance(scfg, Mapping):
                        mcp_rec, mcp_f = _process_mcp_server_entry(
                            profile=profile,
                            server_name=str(sname),
                            raw_cfg=scfg,
                            source_path=mcp_src,
                            provenance=f"plugin:{plugin_id}",
                            world_writable_set=world_writable_set,
                            entry_security_check=entry_security_check,
                        )
                        portable_mcp_records.append(mcp_rec)
                        findings.extend(mcp_f)

    return record, portable_mcp_records, findings, dynamic_cov


def _process_hook_declarations(
    *,
    profile: str,
    hooks_cfg: Any,
    source_path: str,
    world_writable_set: set[str],
    entry_security_check: EntrySecurityCheck | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    """Extract and redact shell hook and outbound webhook declarations from `config.yaml` `hooks:`."""
    records: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    coverage = COVERAGE_VERIFIED

    if hooks_cfg is None:
        return records, findings, coverage
    if not isinstance(hooks_cfg, Mapping):
        findings.append(
            _make_finding(
                rule_id="executable_inventory.hook_declaration_unverified",
                classification=CLASSIFICATION_INFO,
                coverage=COVERAGE_COULD_NOT_VERIFY,
                affected_identities=[profile],
                source_paths=[source_path] if source_path else (),
                evidence={"profile": profile, "source_path": source_path},
                consequence=f"hooks section in {source_path or profile} is malformed (expected mapping).",
                limitations="Malformed hooks configuration.",
            )
        )
        return records, findings, COVERAGE_COULD_NOT_VERIFY

    for event_name, raw_entries in sorted(hooks_cfg.items(), key=lambda x: str(x[0])):
        ev_str = str(event_name).strip()
        if ev_str == "output_spill":
            continue

        if ev_str == "outbound":
            if not isinstance(raw_entries, Sequence) or isinstance(raw_entries, str):
                coverage = COVERAGE_COULD_NOT_VERIFY
                continue
            for idx, item in enumerate(raw_entries):
                if not isinstance(item, Mapping):
                    coverage = COVERAGE_COULD_NOT_VERIFY
                    continue
                raw_url = str(item.get("url") or "").strip()
                red_url, url_was_red = redact_arg_or_url(raw_url)
                events = sorted(set(_normalize_str_list(item.get("events"))))
                has_secret = bool(item.get("secret"))
                secret_env = str(item.get("secret_env") or "").strip() or None
                name = str(item.get("name") or f"outbound_{idx}").strip()
                matcher = str(item.get("matcher") or "").strip() or None

                rec = {
                    "profile": profile,
                    "hook_kind": "outbound_webhook",
                    "name": name,
                    "events": events,
                    "url": red_url,
                    "matcher": matcher,
                    "has_inline_secret": has_secret,
                    "secret_value": REDACTED_PLACEHOLDER if has_secret else None,
                    "secret_env_key": secret_env,
                    "redacted": url_was_red or has_secret,
                    "source_path": source_path,
                }
                records.append(rec)

                cls = CLASSIFICATION_WARNING if (url_was_red or raw_url.lower().startswith("http://")) else CLASSIFICATION_INFO
                conseq = (
                    f"Outbound webhook {name!r} in profile {profile!r} posts events ({', '.join(events)}) to {red_url}"
                    + (" over unencrypted HTTP or with inline URL credentials." if cls == CLASSIFICATION_WARNING else ".")
                )
                findings.append(
                    _make_finding(
                        rule_id="executable_inventory.outbound_webhook_declaration",
                        classification=cls,
                        coverage=COVERAGE_VERIFIED,
                        affected_identities=[profile],
                        source_paths=[source_path] if source_path else (),
                        evidence={
                            "events": events,
                            "has_inline_secret": has_secret,
                            "hook_kind": "outbound_webhook",
                            "matcher": matcher,
                            "name": name,
                            "profile": profile,
                            "redacted": url_was_red or has_secret,
                            "secret_env_key": secret_env,
                            "url": red_url,
                        },
                        consequence=conseq,
                        limitations="Static config declaration; webhook secrets redacted.",
                    )
                )
            continue

        # Shell event hooks (`pre_tool_call`, `post_tool_call`, `on_session_start`, etc.)
        if not isinstance(raw_entries, Sequence) or isinstance(raw_entries, str):
            coverage = COVERAGE_COULD_NOT_VERIFY
            continue

        for idx, item in enumerate(raw_entries):
            if not isinstance(item, Mapping):
                coverage = COVERAGE_COULD_NOT_VERIFY
                continue
            raw_cmd = str(item.get("command") or "").strip()
            if not raw_cmd:
                coverage = COVERAGE_COULD_NOT_VERIFY
                continue
            exe, red_args, was_red = _redact_command_string(raw_cmd)
            matcher = str(item.get("matcher") or "").strip() or None
            timeout = int(item.get("timeout", 60)) if isinstance(item.get("timeout"), (int, float)) else 60
            fail_closed = bool(item.get("fail_closed", item.get("failClosed", False)))
            is_rel = _is_project_relative_executable(exe)
            is_ww = exe in world_writable_set or any(exe.startswith(w.rstrip("/") + "/") for w in world_writable_set if w)
            ioc_issues, check_cov = _check_mcp_ioc_or_shell_risk(
                f"hook:{ev_str}[{idx}]", exe, red_args, None, entry_security_check
            )

            rec = {
                "profile": profile,
                "hook_kind": "shell_hook",
                "event": ev_str,
                "index": idx,
                "declared_executable": exe,
                "declared_args": red_args,
                "matcher": matcher,
                "timeout": timeout,
                "fail_closed": fail_closed,
                "redacted": was_red,
                "project_relative_path": is_rel,
                "world_writable": is_ww,
                "security_issues": ioc_issues,
                "security_check_coverage": check_cov,
                "source_path": source_path,
            }
            records.append(rec)

            if is_ww or is_rel or ioc_issues:
                reasons: list[str] = []
                if is_ww:
                    reasons.append("world-writable path")
                if is_rel:
                    reasons.append("project-relative executable path")
                if ioc_issues:
                    reasons.extend(ioc_issues)
                findings.append(
                    _make_finding(
                        rule_id="executable_inventory.hook_unsafe_path_or_command",
                        classification=CLASSIFICATION_WARNING,
                        coverage=COVERAGE_VERIFIED,
                        affected_identities=[profile],
                        source_paths=[source_path] if source_path else (),
                        evidence={
                            "declared_args": red_args,
                            "declared_executable": exe,
                            "event": ev_str,
                            "fail_closed": fail_closed,
                            "matcher": matcher,
                            "profile": profile,
                            "project_relative_path": is_rel,
                            "reasons": reasons,
                            "redacted": was_red,
                            "world_writable": is_ww,
                        },
                        consequence=(
                            f"Shell hook for event {ev_str!r} in profile {profile!r} ({exe}) uses an unsafe "
                            f"execution declaration: {'; '.join(reasons)}."
                        ),
                        limitations="Static hook declaration check; hook scripts are never executed during audit.",
                    )
                )
            else:
                findings.append(
                    _make_finding(
                        rule_id="executable_inventory.shell_hook_declaration",
                        classification=CLASSIFICATION_INFO,
                        coverage=check_cov,
                        affected_identities=[profile],
                        source_paths=[source_path] if source_path else (),
                        evidence={
                            "declared_args": red_args,
                            "declared_executable": exe,
                            "event": ev_str,
                            "fail_closed": fail_closed,
                            "matcher": matcher,
                            "profile": profile,
                            "redacted": was_red,
                            "timeout": timeout,
                        },
                        consequence=(
                            f"Shell hook declared for event {ev_str!r} in profile {profile!r}: {exe}."
                        ),
                        limitations="Static hook declaration listing with argument redaction.",
                    )
                )

    return records, findings, coverage


def _process_mcp_server_entry(
    *,
    profile: str,
    server_name: str,
    raw_cfg: Mapping[str, Any],
    source_path: str,
    provenance: str,
    world_writable_set: set[str],
    entry_security_check: EntrySecurityCheck | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Extract and redact one MCP server declaration from `config.yaml` or `mcp.json`."""
    findings: list[dict[str, Any]] = []
    raw_cmd = str(raw_cfg.get("command") or "").strip()
    raw_args = raw_cfg.get("args")
    args_seq = raw_args if isinstance(raw_args, Sequence) and not isinstance(raw_args, str) else (
        [raw_args] if isinstance(raw_args, str) and raw_args.strip() else []
    )

    exe_red, exe_was_red = redact_arg_or_url(raw_cmd) if raw_cmd else ("", False)
    args_red, args_was_red = _redact_args_list(args_seq)

    raw_url = str(raw_cfg.get("url") or "").strip()
    url_red, url_was_red = redact_arg_or_url(raw_url) if raw_url else ("", False)

    # Env keys ONLY — never store env values (§5)
    raw_env = raw_cfg.get("env")
    env_keys = sorted(str(k) for k in raw_env.keys()) if isinstance(raw_env, Mapping) else []

    # Header names ONLY — never store header values
    raw_headers = raw_cfg.get("headers")
    header_names = sorted(str(k) for k in raw_headers.keys()) if isinstance(raw_headers, Mapping) else []

    cwd_val = str(raw_cfg.get("cwd") or "").strip() or None
    enabled = bool(raw_cfg.get("enabled", True))
    transport = "remote" if (url_red and not exe_red) else "stdio"

    # Also check raw unredacted command/args for IOC substrings before discarding unredacted text
    raw_args_strs = [str(a) for a in args_seq]
    ioc_issues, check_cov = _check_mcp_ioc_or_shell_risk(
        server_name, raw_cmd, raw_args_strs, raw_env if isinstance(raw_env, Mapping) else None,
        entry_security_check,
    )

    # Portable plugins allow `./` relative to `${PLUGIN_ROOT}` after translation, whereas config.yaml project-relative paths are unsafe
    is_rel = _is_project_relative_executable(exe_red, cwd_val) and not provenance.startswith("plugin:")
    is_ww = (
        (exe_red in world_writable_set)
        or (cwd_val is not None and cwd_val in world_writable_set)
        or any(exe_red.startswith(w.rstrip("/") + "/") for w in world_writable_set if w)
    )
    was_redacted = exe_was_red or args_was_red or url_was_red or bool(env_keys) or bool(header_names)

    rec = {
        "profile": profile,
        "server_name": server_name,
        "transport": transport,
        "enabled": enabled,
        "declared_executable": exe_red or None,
        "declared_args": args_red,
        "url": url_red or None,
        "cwd": cwd_val,
        "env_keys": env_keys,
        "header_names": header_names,
        "provenance": provenance,
        "source_path": source_path,
        "redacted": was_redacted,
        "project_relative_path": is_rel,
        "world_writable": is_ww,
        "security_issues": ioc_issues,
        "security_check_coverage": check_cov,
    }

    evidence_payload = {
        "cwd": cwd_val,
        "declared_args": args_red,
        "declared_executable": exe_red or None,
        "enabled": enabled,
        "env_keys": env_keys,
        "header_names": header_names,
        "profile": profile,
        "project_relative_path": is_rel,
        "provenance": provenance,
        "redacted": was_redacted,
        "security_issues": ioc_issues,
        "server_name": server_name,
        "transport": transport,
        "url": url_red or None,
        "world_writable": is_ww,
    }

    if is_ww or is_rel or ioc_issues:
        reasons: list[str] = []
        if is_ww:
            reasons.append("world-writable executable or cwd")
        if is_rel:
            reasons.append("project-relative executable or cwd path")
        if ioc_issues:
            reasons.extend(ioc_issues)
        findings.append(
            _make_finding(
                rule_id="executable_inventory.mcp_unsafe_declaration",
                classification=CLASSIFICATION_WARNING,
                coverage=COVERAGE_VERIFIED,
                affected_identities=[profile],
                source_paths=[source_path] if source_path else (),
                evidence={**evidence_payload, "reasons": reasons},
                consequence=(
                    f"MCP server {server_name!r} in profile {profile!r} has an unsafe declaration: "
                    f"{'; '.join(reasons)}."
                ),
                limitations="Static MCP declaration check; MCP servers are never started during audit.",
            )
        )
    else:
        findings.append(
            _make_finding(
                rule_id="executable_inventory.mcp_server_declaration",
                classification=CLASSIFICATION_INFO,
                coverage=check_cov,
                affected_identities=[profile],
                source_paths=[source_path] if source_path else (),
                evidence=evidence_payload,
                consequence=(
                    f"MCP server {server_name!r} ({transport}) declared in profile {profile!r} "
                    f"(provenance: {provenance}, env keys: {len(env_keys)})."
                ),
                limitations="Static MCP declaration listing; env values and secret arguments are redacted; live tool schemas are not queried.",
            )
        )

    return rec, findings


def audit_executable_inventory(
    inputs: ExecutableInventoryInput | Mapping[str, Any],
    *,
    entry_security_check: EntrySecurityCheck | None = None,
) -> dict[str, Any]:
    """Statically inventory plugin manifests, hook declarations, and MCP server declarations with secret redaction (§5).

    *entry_security_check* runs the IOC / shell egress / persistence shape check on each hook and MCP
    declaration; omitted, those declarations report ``coverage="could_not_verify"``.
    """
    if not isinstance(inputs, Mapping):
        return {
            "ok": False,
            "status": "error",
            "error": f"inputs must be a Mapping, got {type(inputs).__name__}",
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "classification": CLASSIFICATION_INFO,
            "findings": [],
            "inventory": {"plugins": [], "hooks": [], "mcp_servers": []},
        }

    findings: list[dict[str, Any]] = []
    plugin_records: list[dict[str, Any]] = []
    hook_records: list[dict[str, Any]] = []
    mcp_records: list[dict[str, Any]] = []
    overall_coverage = COVERAGE_VERIFIED

    profiles_in = _as_seq(inputs.get("profiles"))
    top_manifests_in = _as_seq(inputs.get("plugin_manifests"))

    for raw_prof in profiles_in:
        if not isinstance(raw_prof, Mapping):
            continue
        pname = str(raw_prof.get("profile") or raw_prof.get("name") or "default").strip() or "default"
        cfg_path = str(raw_prof.get("config_path") or "").strip()
        prof_cov = str(raw_prof.get("coverage") or COVERAGE_VERIFIED).strip()
        ww_list = _as_seq(raw_prof.get("world_writable_paths"))
        ww_set = {str(p).strip() for p in ww_list if str(p).strip()}

        if prof_cov == COVERAGE_COULD_NOT_VERIFY:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY

        cfg_data: Mapping[str, Any] | None = None
        cfg_err: str | None = None
        raw_cfg_data = raw_prof.get("config_data")
        raw_cfg_text = raw_prof.get("config_text")
        if isinstance(raw_cfg_data, Mapping):
            cfg_data = raw_cfg_data
        elif isinstance(raw_cfg_text, str):
            cfg_data, cfg_err = _parse_yaml_or_json(raw_cfg_text)
        elif prof_cov == COVERAGE_COULD_NOT_VERIFY:
            cfg_err = "Profile config.yaml unreadable"
        else:
            cfg_data = {}

        if cfg_err is not None or cfg_data is None:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY
            findings.append(
                _make_finding(
                    rule_id="executable_inventory.config_unverified",
                    classification=CLASSIFICATION_INFO,
                    coverage=COVERAGE_COULD_NOT_VERIFY,
                    affected_identities=[pname],
                    source_paths=[cfg_path] if cfg_path else (),
                    evidence={"error": cfg_err or "unreadable config", "profile": pname, "source_path": cfg_path},
                    consequence=f"Configuration for profile {pname!r} could not be statically parsed for hooks/MCP declarations.",
                    limitations=cfg_err or "Unreadable config.yaml.",
                )
            )
            cfg_data = {}

        # 1. Profile plugin manifests
        prof_manifests = _as_seq(raw_prof.get("plugin_manifests"))
        for pm in prof_manifests:
            if not isinstance(pm, Mapping):
                continue
            p_rec, port_mcp, p_findings, p_cov = _process_plugin_manifest(
                pm, default_profile=pname, world_writable_set=ww_set,
            entry_security_check=entry_security_check,
            )
            plugin_records.append(p_rec)
            mcp_records.extend(port_mcp)
            findings.extend(p_findings)
            if p_cov == COVERAGE_COULD_NOT_VERIFY:
                overall_coverage = COVERAGE_COULD_NOT_VERIFY

        # 2. Hooks (`config.yaml` `hooks:`)
        hooks_cfg = cfg_data.get("hooks")
        h_recs, h_findings, h_cov = _process_hook_declarations(
            profile=pname,
            hooks_cfg=hooks_cfg,
            source_path=cfg_path,
            world_writable_set=ww_set,
            entry_security_check=entry_security_check,
        )
        hook_records.extend(h_recs)
        findings.extend(h_findings)
        if h_cov == COVERAGE_COULD_NOT_VERIFY:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY

        # 3. MCP servers (`config.yaml` `mcp_servers:`)
        mcp_cfg = cfg_data.get("mcp_servers")
        if mcp_cfg is not None:
            if not isinstance(mcp_cfg, Mapping):
                overall_coverage = COVERAGE_COULD_NOT_VERIFY
                findings.append(
                    _make_finding(
                        rule_id="executable_inventory.mcp_declaration_unverified",
                        classification=CLASSIFICATION_INFO,
                        coverage=COVERAGE_COULD_NOT_VERIFY,
                        affected_identities=[pname],
                        source_paths=[cfg_path] if cfg_path else (),
                        evidence={"profile": pname, "source_path": cfg_path},
                        consequence=f"mcp_servers section in {cfg_path or pname} is malformed (expected mapping).",
                        limitations="Malformed mcp_servers block.",
                    )
                )
            else:
                for sname, scfg in sorted(mcp_cfg.items(), key=lambda x: str(x[0])):
                    if not isinstance(scfg, Mapping):
                        overall_coverage = COVERAGE_COULD_NOT_VERIFY
                        continue
                    m_rec, m_findings = _process_mcp_server_entry(
                        profile=pname,
                        server_name=str(sname),
                        raw_cfg=scfg,
                        source_path=cfg_path,
                        provenance="config.yaml",
                        world_writable_set=ww_set,
                        entry_security_check=entry_security_check,
                    )
                    mcp_records.append(m_rec)
                    findings.extend(m_findings)

    # Also process any top-level `plugin_manifests` passed outside `profiles`
    for pm in top_manifests_in:
        if not isinstance(pm, Mapping):
            continue
        p_rec, port_mcp, p_findings, p_cov = _process_plugin_manifest(
            pm, default_profile="default", world_writable_set=set(),
            entry_security_check=entry_security_check,
        )
        plugin_records.append(p_rec)
        mcp_records.extend(port_mcp)
        findings.extend(p_findings)
        if p_cov == COVERAGE_COULD_NOT_VERIFY:
            overall_coverage = COVERAGE_COULD_NOT_VERIFY

    plugin_records.sort(key=lambda r: (r["profile"], r["plugin_id"], r["source_path"]))
    hook_records.sort(key=lambda r: (r["profile"], r["hook_kind"], r.get("event") or r.get("name") or "", r["source_path"]))
    mcp_records.sort(key=lambda r: (r["profile"], r["server_name"], r["provenance"], r["source_path"]))
    findings.sort(key=_finding_sort_key)

    if any(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in findings):
        overall_coverage = COVERAGE_COULD_NOT_VERIFY

    headline_cls = CLASSIFICATION_INFO
    best_rank = _CLASSIFICATION_RANK[headline_cls]
    for f in findings:
        r = _CLASSIFICATION_RANK.get(f["classification"], 1)
        if r > best_rank:
            headline_cls = f["classification"]
            best_rank = r

    has_legacy_error = any(f.get("severity") == "error" for f in findings)
    legacy_status = "fail" if has_legacy_error else "pass"

    return {
        "ok": legacy_status == "pass",
        "status": legacy_status,
        "error": None,
        "component_version": COMPONENT_VERSION,
        "coverage": overall_coverage,
        "classification": headline_cls,
        "findings": findings,
        "inventory": {
            "plugins": plugin_records,
            "hooks": hook_records,
            "mcp_servers": mcp_records,
        },
    }


def run(
    inputs: ExecutableInventoryInput | Mapping[str, Any],
    *,
    entry_security_check: EntrySecurityCheck | None = None,
) -> dict[str, Any]:
    """Standard component entry point (`run(inputs) -> dict`)."""
    return audit_executable_inventory(inputs, entry_security_check=entry_security_check)
