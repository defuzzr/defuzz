"""Whole-project lint runner and per-tool output parsers for the Defuzz plugin."""

from __future__ import annotations

import json
import os
import posixpath
import re
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import lint_env, lint_tools, safety, safe_state_store, state_store
from .lint_tools import ToolSpec

MAX_FILES_PER_TOOL: int = 2000
REPO_CODE_WARNING: str = (
    "POST tools that execute repo code (clippy, dotnet) ran on the host without a sandbox"
)
VALID_TOOL_STATUSES: frozenset[str] = frozenset(
    {
        "clean",
        "disabled",
        "findings",
        "not_installed",
        "not_configured",
        "no_files",
        "timed_out",
        "crashed",
        "unparseable",
    }
)
_FORMAT_TOOLS: frozenset[str] = frozenset(
    {
        "ruff-format",
        "rustfmt",
        "gofmt",
        "clang-format",
        "csharpier",
        "gdformat",
        "stylua",
        "shfmt",
        "taplo",
    }
)


class LintError(RuntimeError):
    """Raised when a lint configuration or programmer contract is violated."""


@dataclass(frozen=True)
class ParseInput:
    """Bundled subprocess output and context passed to a tool parser."""

    stdout: str
    stderr: str = ""
    returncode: int = 0
    root: Path = Path(".")
    files: Sequence[str] = ()
    tool: str = ""


def _to_posix(raw: str) -> str:
    """Convert path separators to forward slashes and strip redundant ./ prefixes."""
    if not raw or not raw.strip():
        return ""
    s = raw.replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    return "" if s.strip() == "." else s


def _norm_posix(raw: str) -> str:
    """Normalize a posix path string while collapsing leading double slashes and preserving filename spaces."""
    s = _to_posix(raw)
    if not s:
        return ""
    normed = posixpath.normpath(s)
    if normed.startswith("//"):
        normed = "/" + normed.lstrip("/")
    return "" if normed == "." else normed


def _is_windows_drive_path(path_str: str) -> bool:
    """Return True if path_str starts with a Windows drive prefix like 'C:/' or 'c:'."""
    return bool(re.match(r"^[A-Za-z]:(?:/|$)", path_str))


def _is_valid_int(val: Any, *, min_value: int = 0) -> bool:
    """Return True if val is a non-boolean integer >= min_value."""
    return isinstance(val, int) and not isinstance(val, bool) and val >= min_value


def _is_nonempty_str(*vals: Any) -> bool:
    """Return True if every argument is a non-empty, non-whitespace string."""
    return all(isinstance(v, str) and bool(v.strip()) for v in vals)


def _is_crash_exit(rc: int) -> bool:
    """Return True if subprocess exit code rc indicates a POSIX signal or Windows NTSTATUS exception crash."""
    if rc < 0:
        return True
    if rc >= 0xFFFFFFFF:
        return False
    return (rc & 0xC0000000) == 0xC0000000


def _root_candidates(root_str: str) -> list[str]:
    """Build normalized lexical and resolved path candidates for a project root string."""
    candidates: list[str] = []
    c0 = _norm_posix(root_str)
    if c0:
        candidates.append(c0)
    if not _is_windows_drive_path(c0):
        try:
            lex_str = _norm_posix(str(safety._lexical_abs(root_str)))
            if lex_str and lex_str not in candidates:
                candidates.append(lex_str)
            real_str = _norm_posix(os.path.realpath(os.path.expanduser(root_str)))
            if real_str and real_str not in candidates:
                candidates.append(real_str)
        except Exception:
            pass
    return candidates


def relpath(root: Path | str | None, p: Path | str | None) -> str:
    """Return a posix path relative to root when inside root, else keep as given."""
    if p is None:
        return ""
    raw = str(p)
    if not raw or not raw.strip() or raw.strip() == ".":
        return ""
    norm_p = _norm_posix(raw)
    if not norm_p or root is None:
        return norm_p

    root_str = str(root).strip()
    if not root_str:
        return norm_p

    p_variants: list[str] = [norm_p]
    if not _is_windows_drive_path(norm_p) and norm_p.startswith("/"):
        try:
            real_p = _norm_posix(os.path.realpath(raw))
            if real_p and real_p not in p_variants:
                p_variants.append(real_p)
        except Exception:
            pass

    for cand in _root_candidates(root_str):
        if cand == "/":
            if norm_p == "/":
                return ""
            if norm_p.startswith("/"):
                return norm_p.lstrip("/")
            continue
        cand_clean = cand.rstrip("/")
        if not cand_clean:
            continue
        is_win = _is_windows_drive_path(cand_clean)
        for pv in p_variants:
            win_pair = is_win and _is_windows_drive_path(pv)
            pv_cmp = pv.lower() if win_pair else pv
            cand_cmp = cand_clean.lower() if win_pair else cand_clean
            if pv_cmp == cand_cmp:
                return ""
            prefix = cand_cmp + "/"
            if pv_cmp.startswith(prefix):
                sub = pv[len(prefix) :]
                while sub.startswith("./"):
                    sub = sub[2:]
                return "" if sub in ("", ".") else sub
    return norm_p


def _split_location(line: str) -> tuple[str, int, int | None, str] | None:
    """Split a 'file:line[:col][: rest]' diagnostic line into (file, line, col, rest)."""
    m = re.match(r"^(.+?):(\d+)(?::(\d+))?(?::\s*(.*)|\s*)$", line.strip())
    if not m:
        return None
    col_num = int(m.group(3)) if m.group(3) is not None else None
    return m.group(1), int(m.group(2)), col_num, (m.group(4) or "").strip()


def _normalize_severity(raw: Any, default: str = "warning") -> str:
    """Normalize arbitrary tool severity strings or numeric codes to error|warning|info."""
    if isinstance(raw, int):
        return "error" if raw >= 2 else ("warning" if raw == 1 else "info")
    text = str(raw or "").strip().lower()
    if text in ("error", "err", "fatal", "high", "parseerror"):
        return "error"
    if text in ("warning", "warn", "medium"):
        return "warning"
    if text in ("info", "information", "note", "style", "hint", "help", "low"):
        return "info"
    return default


def make_finding(
    file: str | Path | None = "",
    line: int | str | None = 0,
    rule: str | None = "",
    message: str | None = "",
    tool: str | None = "",
    severity: str | int | None = "warning",
    *,
    root: Path | str | None = None,
) -> dict[str, Any]:
    """Construct a normalized finding dictionary conforming to the common finding schema."""
    try:
        line_num = max(0, int(line)) if line is not None else 0
    except (ValueError, TypeError):
        line_num = 0
    return {
        "file": relpath(root, file),
        "line": line_num,
        "rule": str(rule or "").strip(),
        "message": str(message or "").strip(),
        "tool": str(tool or "").strip(),
        "severity": _normalize_severity(severity),
    }


def _finding_from(
    inp: ParseInput,
    default_tool: str,
    file: str | Path | None,
    line: int | str | None = 0,
    rule: str | None = "",
    message: str | None = "",
    severity: str | int | None = "warning",
) -> dict[str, Any]:
    """Construct a finding bound to inp.tool (or default_tool) and inp.root."""
    return make_finding(
        file=file,
        line=line,
        rule=rule,
        message=message,
        tool=inp.tool or default_tool,
        severity=severity,
        root=inp.root,
    )


def _combined_text(inp: ParseInput) -> str:
    """Concatenate stdout and stderr with a newline separator when both are non-empty."""
    out, err = inp.stdout or "", inp.stderr or ""
    return f"{out}\n{err}" if (out and err) else (out or err)


def _output_snippet(inp: ParseInput, empty_suffix: str = "") -> str:
    """Return a ': <snippet>' suffix truncated at 200 chars, or empty_suffix when output is blank."""
    snippet = _combined_text(inp).strip()
    if not snippet:
        return empty_suffix
    if len(snippet) > 200:
        snippet = snippet[:200] + "..."
    return f": {snippet}"


def _format_unparseable_message(inp: ParseInput) -> str:
    """Format a concise diagnostic message describing unparseable tool output."""
    detail = _output_snippet(inp, empty_suffix=" (empty output)")
    return f"tool output not parseable (rc={inp.returncode}){detail}"


def _make_parse_error_marker(inp: ParseInput) -> list[dict[str, Any]]:
    """Return a single parse-error marker dict for parser-level unparseable output."""
    return [_finding_from(inp, "", "", 0, "parse-error", _format_unparseable_message(inp), "error")]


def _unparseable_fallback(inp: ParseInput, *, force: bool = False) -> list[dict[str, Any]]:
    """Return an error finding when output is unparseable (forced for structured parsers or when rc != 0)."""
    return _make_parse_error_marker(inp) if (force or inp.returncode != 0) else []


def _load_json_payload(
    inp: ParseInput, *, empty_ok_on_zero: bool = True, sgr_envelope: bool = False
) -> tuple[Any, bool]:
    """Parse JSON from stdout (or stderr fallback), returning (payload, ok)."""
    raw = (inp.stdout or "").strip() or (inp.stderr or "").strip()
    if not raw:
        return None, (empty_ok_on_zero and inp.returncode == 0)
    if sgr_envelope:
        raw = re.sub(r"\A(?:\s|\x1b\[[0-9;]*m)+", "", raw)
        raw = re.sub(r"(?:\s|\x1b\[[0-9;]*m)+\Z", "", raw)
    try:
        parsed = json.loads(raw)
    except Exception:
        return None, False
    return (parsed, True) if parsed is not None else (None, False)


def _parse_json_items(
    inp: ParseInput,
    extract_items: Callable[[Any], Any],
    build_item: Callable[[dict[str, Any]], dict[str, Any] | None],
    *,
    sgr_envelope: bool = False,
) -> list[dict[str, Any]]:
    """Load a JSON document, extract its diagnostic list, and map each dict item to a finding."""
    data, ok = _load_json_payload(inp, sgr_envelope=sgr_envelope)
    if not ok:
        return _unparseable_fallback(inp, force=True)
    if data is None:
        return []
    items = extract_items(data)
    if not isinstance(items, list):
        return _unparseable_fallback(inp, force=True)
    findings: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            return _unparseable_fallback(inp, force=True)
        finding = build_item(item)
        if finding is None:
            return _unparseable_fallback(inp, force=True)
        findings.append(finding)
    return findings if findings else _unparseable_fallback(inp)


def _load_ndjson_objects(inp: ParseInput) -> tuple[list[dict[str, Any]], bool]:
    """Parse NDJSON lines starting with '{' or '[' into dict objects, returning (objs, ok)."""
    raw = _combined_text(inp).strip()
    if not raw:
        return [], inp.returncode == 0
    objs: list[dict[str, Any]] = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or not (s.startswith("{") or s.startswith("[")):
            continue
        try:
            obj = json.loads(s)
        except Exception:
            return [], False
        if not isinstance(obj, dict):
            return [], False
        objs.append(obj)
    return (objs, True) if objs else ([], False)


def _object_or_array_items(data: Any) -> list[Any] | None:
    """Treat a single JSON object as a one-item list; pass lists through; else None."""
    return [data] if isinstance(data, dict) else (data if isinstance(data, list) else None)


def _parse_regex_lines(
    inp: ParseInput,
    pattern: str,
    build: Callable[[re.Match[str]], dict[str, Any]],
    *,
    flags: int = 0,
    strip: bool = False,
) -> list[dict[str, Any]]:
    """Apply a regex to each line of combined output and build findings from matches."""
    rx = re.compile(pattern, flags)
    findings = [
        build(m)
        for raw in _combined_text(inp).splitlines()
        if (m := rx.match(raw.strip() if strip else raw))
    ]
    return findings if findings else _unparseable_fallback(inp)


def _parse_ruff(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `ruff check --output-format json` array output into findings."""
    def _build(item: dict[str, Any]) -> dict[str, Any] | None:
        fname, msg, loc, raw_code = (
            item.get("filename"),
            item.get("message"),
            item.get("location"),
            item.get("code"),
        )
        if (
            not _is_nonempty_str(fname, msg)
            or not isinstance(loc, dict)
            or not _is_valid_int(loc.get("row"), min_value=1)
            or (raw_code is not None and not isinstance(raw_code, str))
        ):
            return None
        code = str(raw_code or "syntax-error").strip()
        raw_sev = item.get("severity")
        if raw_sev is not None:
            sev = _normalize_severity(raw_sev, default="warning")
        elif code.startswith(("E9", "F")) or code in ("syntax-error", "invalid-syntax"):
            sev = "error"
        else:
            sev = "warning"
        return _finding_from(inp, "ruff", fname, loc["row"], code, msg, sev)

    return _parse_json_items(inp, lambda d: d if isinstance(d, list) else None, _build)


def _parse_ruff_format(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse legacy filenames and Ruff 0.16+ full formatter diagnostics."""
    findings: list[dict[str, Any]] = []
    text = _combined_text(inp)
    for m in re.finditer(
        r"^unformatted: File would be reformatted\r?\n[ \t]*-->[ \t]+(.+):(\d+):(\d+)[ \t]*$",
        text,
        re.MULTILINE,
    ):
        findings.append(
            _finding_from(inp, "ruff-format", m.group(1), int(m.group(2)), "format", "Would reformat", "warning")
        )
    for line in text.splitlines():
        if m := re.match(r"^\s*Would reformat:\s+(.+?)\s*$", line):
            findings.append(
                _finding_from(inp, "ruff-format", m.group(1), 0, "format", "Would reformat", "warning")
            )
    return findings if findings else _unparseable_fallback(inp)


def _parse_rustfmt(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `rustfmt --check` 'Diff in <path>:<line>:' or 'Diff in <path> at line <line>:' headers."""
    return _parse_regex_lines(
        inp,
        r"^Diff in (.+?)(?::(\d+)| at line (\d+)):\s*$",
        lambda m: _finding_from(
            inp, "rustfmt", m.group(1), m.group(2) or m.group(3) or 0,
            "rustfmt", "File is not formatted with rustfmt", "warning",
        ),
        strip=True,
    )


def _parse_cargo_json(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `cargo clippy --message-format json` NDJSON compiler-message lines."""
    objs, ok = _load_ndjson_objects(inp)
    if not ok:
        return _unparseable_fallback(inp, force=True)
    if not objs:
        return []
    findings: list[dict[str, Any]] = []
    for obj in objs:
        reason = obj.get("reason")
        if not isinstance(reason, str):
            return _unparseable_fallback(inp, force=True)
        if reason != "compiler-message":
            continue
        msg = obj.get("message")
        if not isinstance(msg, dict):
            return _unparseable_fallback(inp, force=True)
        msg_text, spans = msg.get("message"), msg.get("spans")
        if not _is_nonempty_str(msg_text) or not isinstance(spans, list):
            return _unparseable_fallback(inp, force=True)
        fname, line_no = "", 0
        if spans:
            if not all(
                isinstance(sp, dict)
                and _is_nonempty_str(sp.get("file_name"))
                and _is_valid_int(sp.get("line_start"), min_value=1)
                for sp in spans
            ):
                return _unparseable_fallback(inp, force=True)
            primary = next((sp for sp in spans if sp.get("is_primary")), spans[0])
            fname = str(primary["file_name"])
            if ".cargo/registry" in fname.replace("\\", "/"):
                continue
            line_no = int(primary["line_start"])
        code_obj = msg.get("code")
        if code_obj is not None and not isinstance(code_obj, dict):
            return _unparseable_fallback(inp, force=True)
        rule = (
            str(code_obj["code"]).strip()
            if isinstance(code_obj, dict) and code_obj.get("code")
            else (inp.tool or "clippy")
        )
        findings.append(
            _finding_from(inp, "clippy", fname, line_no, rule, msg_text, msg.get("level"))
        )
    return findings if findings else _unparseable_fallback(inp)


def _extract_biome_location_and_desc(diag: dict[str, Any]) -> tuple[str, int, Any]:
    """Extract (file_str, line_no, desc) from a single Biome diagnostic object."""
    loc = diag["location"]
    path_field = loc.get("path")
    file_str = (
        str(path_field.get("file") or "")
        if isinstance(path_field, dict)
        else (path_field if isinstance(path_field, str) else "")
    )
    line_no = 0
    loc_line, loc_start, loc_src, loc_span = (
        loc.get("line"),
        loc.get("start"),
        loc.get("sourceCode"),
        loc.get("span"),
    )
    if _is_valid_int(loc_line, min_value=1):
        line_no = loc_line
    elif isinstance(loc_start, dict) and _is_valid_int(loc_start.get("line"), min_value=1):
        line_no = loc_start["line"]
    elif isinstance(loc_src, str) and isinstance(loc_span, list) and loc_span:
        if _is_valid_int(loc_span[0], min_value=0):
            line_no = 1 + loc_src.encode("utf-8")[: loc_span[0]].count(b"\n")

    desc = diag.get("description")
    if not desc:
        msg_val = diag.get("message")
        if isinstance(msg_val, list):
            desc = "".join(str(p.get("content", "")) for p in msg_val if isinstance(p, dict))
        elif isinstance(msg_val, str):
            desc = msg_val
        else:
            desc = ""
    return file_str, line_no, desc


def _parse_biome_json(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `biome --reporter json` diagnostics using location.start.line or UTF-8 byte offsets."""
    def _build(diag: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(diag.get("location"), dict):
            return None
        file_str, line_no, desc = _extract_biome_location_and_desc(diag)
        cat = diag.get("category")
        if not _is_nonempty_str(file_str, desc, cat):
            return None
        return _finding_from(inp, "biome", file_str, line_no, cat, desc, diag.get("severity"))

    return _parse_json_items(
        inp,
        lambda d: d.get("diagnostics") if isinstance(d, dict) else None,
        _build,
        sgr_envelope=True,
    )


def _parse_oxlint_json(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `oxlint --format json` diagnostics object or array into findings."""
    def _build(diag: dict[str, Any]) -> dict[str, Any] | None:
        fname = diag.get("filename") or diag.get("file")
        msg = diag.get("message")
        rule = diag.get("code") or diag.get("rule_id")
        if not _is_nonempty_str(fname, msg, rule):
            return None
        line_no = diag.get("line", 0)
        labels = diag.get("labels")
        if isinstance(labels, list) and labels and isinstance(labels[0], dict):
            span = labels[0].get("span")
            if isinstance(span, dict):
                line_no = span.get("line", line_no)
        return _finding_from(inp, "oxlint", fname, line_no, str(rule), msg, diag.get("severity"))

    return _parse_json_items(
        inp,
        lambda d: d.get("diagnostics") if isinstance(d, dict) else (d if isinstance(d, list) else None),
        _build,
    )


def _parse_gofmt(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `gofmt -e -l` unformatted filenames and `file:line:col: msg` syntax errors."""
    findings: list[dict[str, Any]] = []
    for line in _combined_text(inp).splitlines():
        s = line.strip()
        if not s:
            continue
        if m_err := re.match(r"^(.+?):(\d+):(?:\d+:)?\s+(.+)$", s):
            findings.append(
                _finding_from(inp, "gofmt", m_err.group(1), m_err.group(2), "syntax", m_err.group(3), "error")
            )
        elif s.endswith(".go"):
            findings.append(
                _finding_from(inp, "gofmt", s, 0, "gofmt", "File is not gofmt-formatted", "warning")
            )
    return findings if findings else _unparseable_fallback(inp)


def _parse_go_vet(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `go vet` stderr lines (`path:line:col: message`), skipping `# pkg` headers."""
    findings: list[dict[str, Any]] = []
    for line in _combined_text(inp).splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = s[5:].strip() if s.startswith("vet: ") else s
        if m := re.match(r"^(.+?\.go):(\d+):(?:\d+:)?\s+(.+)$", s):
            findings.append(
                _finding_from(inp, "go-vet", m.group(1), m.group(2), "vet", m.group(3), "error")
            )
    return findings if findings else _unparseable_fallback(inp)


def _parse_golangci_json(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `golangci-lint` JSON `{Issues: [...]}` output into findings."""
    def _extract(data: Any) -> Any:
        if not isinstance(data, dict):
            return None
        issues = data.get("Issues")
        if issues is None and "Issues" in data and inp.returncode == 0:
            return []
        return issues

    def _build(issue: dict[str, Any]) -> dict[str, Any] | None:
        pos, from_linter, text = issue.get("Pos"), issue.get("FromLinter"), issue.get("Text")
        if (
            not isinstance(pos, dict)
            or not _is_nonempty_str(pos.get("Filename"), from_linter, text)
            or not _is_valid_int(pos.get("Line"), min_value=0)
        ):
            return None
        return _finding_from(
            inp, "golangci-lint", pos["Filename"], pos["Line"], from_linter, text, issue.get("Severity")
        )

    return _parse_json_items(inp, _extract, _build)


def _parse_clang_format(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `clang-format --dry-run -Werror` diagnostics into warning findings."""
    return _parse_regex_lines(
        inp,
        r"^(.+?):(\d+):(\d+):\s+(?:error|warning):\s+(.+?)(?:\s+\[([^\]]+)\])?\s*$",
        lambda m: _finding_from(inp, "clang-format", m.group(1), m.group(2), "clang-format", m.group(4), "warning"),
        strip=True,
    )


def _parse_clang_tidy(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `clang-tidy` `file:line:col: warning|error: message [check-name]` lines."""
    return _parse_regex_lines(
        inp,
        r"^(.+?):(\d+):(\d+):\s+(warning|error):\s+(.+?)(?:\s+\[([^\]]+)\])?\s*$",
        lambda m: _finding_from(
            inp, "clang-tidy", m.group(1), m.group(2), m.group(6) or "clang-tidy", m.group(5), m.group(4)
        ),
        strip=True,
    )


def _parse_csharpier(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `csharpier check` 'Warning|Error <path> - <msg>' output lines."""
    return _parse_regex_lines(
        inp,
        r"^\s*(Warning|Error)\s+(.+?)\s+-\s+(.+?)\s*$",
        lambda m: _finding_from(inp, "csharpier", m.group(2), 0, "csharpier", m.group(3), m.group(1)),
    )


def _parse_dotnet_format(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `dotnet format --verify-no-changes` `path(line,col): error|warning CODE: msg [proj]` lines."""
    return _parse_regex_lines(
        inp,
        r"^\s*(.+?)\((\d+),\d+\):\s+(error|warning|info)\s+([A-Za-z0-9_]+):\s+(.+?)(?:\s+\[[^\]]+\])?\s*$",
        lambda m: _finding_from(inp, "dotnet-format", m.group(1), m.group(2), m.group(4), m.group(5), m.group(3)),
        flags=re.IGNORECASE,
    )


def _parse_gdformat(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `gdformat --check` 'would reformat <path>' lines."""
    return _parse_regex_lines(
        inp,
        r"^\s*would reformat\s+(.+?)\s*$",
        lambda m: _finding_from(inp, "gdformat", m.group(1), 0, "gdformat", "would reformat", "warning"),
        flags=re.IGNORECASE,
    )


def _parse_gdlint(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `gdlint` `path:line: Error|Warning: message (rule-name)` lines."""
    return _parse_regex_lines(
        inp,
        r"^\s*(.+?):(\d+):\s*(Error|Warning):\s+(.+?)\s+\(([^)]+)\)\s*$",
        lambda m: _finding_from(inp, "gdlint", m.group(1), m.group(2), m.group(5), m.group(4), m.group(3)),
        flags=re.IGNORECASE,
    )


def _parse_stylua(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `stylua --check` 'Diff in <path>:' headers."""
    return _parse_regex_lines(
        inp,
        r"^Diff in (.+?):\s*$",
        lambda m: _finding_from(inp, "stylua", m.group(1), 0, "stylua", "Diff in file", "warning"),
        strip=True,
    )


def _parse_selene_json(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `selene --display-style json` NDJSON lines (converting 0-based start_line to 1-based)."""
    objs, ok = _load_ndjson_objects(inp)
    if not ok:
        return _unparseable_fallback(inp, force=True)
    if not objs:
        return []
    findings: list[dict[str, Any]] = []
    for obj in objs:
        obj_type = obj.get("type")
        if obj_type not in ("Summary", "Diagnostic"):
            return _unparseable_fallback(inp, force=True)
        if obj_type == "Summary":
            continue
        primary, msg, code = obj.get("primary_label"), obj.get("message"), obj.get("code")
        if (
            not isinstance(primary, dict)
            or not _is_nonempty_str(primary.get("filename"), msg, code)
            or not isinstance(primary.get("span"), dict)
            or not _is_valid_int(primary["span"].get("start_line"), min_value=0)
        ):
            return _unparseable_fallback(inp, force=True)
        line_1based = int(primary["span"]["start_line"]) + 1
        findings.append(
            _finding_from(inp, "selene", primary["filename"], line_1based, code, msg, obj.get("severity"))
        )
    return findings if findings else _unparseable_fallback(inp)


def _parse_glslang(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `glslangValidator` `ERROR|WARNING: path:line: message` output lines."""
    def _build(m: re.Match[str]) -> dict[str, Any]:
        sev = "error" if m.group(1) == "ERROR" else "warning"
        path_tok = str(inp.files[0]) if (m.group(2) == "0" and len(inp.files) == 1) else m.group(2)
        return _finding_from(inp, "glslangValidator", path_tok, m.group(3), "shader", m.group(4), sev)

    return _parse_regex_lines(inp, r"^\s*(ERROR|WARNING):\s+(.+?):(\d+):\s*(.+?)\s*$", _build)


def _parse_dxc(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `dxc` `path:line:col: error|warning: message` output lines."""
    return _parse_regex_lines(
        inp,
        r"^\s*(.+?):(\d+):(\d+):\s+(error|warning):\s+(.+?)\s*$",
        lambda m: _finding_from(inp, "dxc", m.group(1), m.group(2), "shader", m.group(5), m.group(4)),
        flags=re.IGNORECASE,
    )


def _parse_shfmt(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `shfmt -d` unified diff headers (`--- path.orig` / `+++ path`) and syntax errors."""
    findings: list[dict[str, Any]] = []
    seen_diff_files: set[str] = set()
    for line in _combined_text(inp).splitlines():
        s = line.strip()
        if s.startswith("+++ "):
            target = s[4:].strip().split("\t")[0].removesuffix(".orig")
            rel = relpath(inp.root, target)
            if rel and rel not in seen_diff_files:
                seen_diff_files.add(rel)
                findings.append(
                    _finding_from(inp, "shfmt", rel, 0, "shfmt", "File differs from shfmt formatting", "warning")
                )
        elif not s.startswith(("--- ", "@@ ", "diff ")):
            if m_err := re.match(r"^(.+?\.(:?sh|bash)):(\d+):(\d+):\s+(.+)$", s):
                findings.append(
                    _finding_from(inp, "shfmt", m_err.group(1), m_err.group(3), "shfmt", m_err.group(5), "error")
                )
    return findings if findings else _unparseable_fallback(inp)


def _parse_shellcheck_json(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `shellcheck -f json` array or `{comments: [...]}` object into findings."""
    def _build(item: dict[str, Any]) -> dict[str, Any] | None:
        fname, line_no, code, msg = (
            item.get("file"),
            item.get("line"),
            item.get("code"),
            item.get("message"),
        )
        if (
            not _is_nonempty_str(fname, msg)
            or not _is_valid_int(line_no, min_value=0)
            or isinstance(code, bool)
            or not isinstance(code, (int, str))
        ):
            return None
        rule = str(code) if str(code).startswith("SC") else f"SC{code}"
        return _finding_from(inp, "shellcheck", fname, line_no, rule, msg, item.get("level"))

    return _parse_json_items(
        inp,
        lambda d: d.get("comments") if isinstance(d, dict) else (d if isinstance(d, list) else None),
        _build,
    )


def _parse_pwsh_parse_json(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse PowerShell `Parser::ParseFile` `ConvertTo-Json` ParseError object or array."""
    def _build(item: dict[str, Any]) -> dict[str, Any] | None:
        raw_extent = item.get("Extent")
        extent = raw_extent if isinstance(raw_extent, dict) else {}
        fname = extent.get("File") or item.get("File")
        line_no = extent.get("StartLineNumber") if "StartLineNumber" in extent else item.get("Line")
        err_id, msg = item.get("ErrorId"), item.get("Message")
        if not _is_nonempty_str(fname, err_id, msg) or not _is_valid_int(line_no, min_value=0):
            return None
        return _finding_from(inp, "pwsh-parse", fname, line_no, err_id, msg, "error")

    return _parse_json_items(
        inp,
        _object_or_array_items,
        _build,
    )


def _parse_psscriptanalyzer_json(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `Invoke-ScriptAnalyzer | ConvertTo-Json` object or array into findings."""
    def _build(item: dict[str, Any]) -> dict[str, Any] | None:
        fname = item.get("ScriptPath") or item.get("ScriptName")
        line_no = item.get("Line", 0)
        rule_name, msg = item.get("RuleName"), item.get("Message")
        if not _is_nonempty_str(fname, rule_name, msg) or not _is_valid_int(line_no, min_value=0):
            return None
        return _finding_from(inp, "psscriptanalyzer", fname, line_no, rule_name, msg, item.get("Severity"))

    return _parse_json_items(
        inp,
        _object_or_array_items,
        _build,
    )


def _parse_yamllint_parsable(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `yamllint -f parsable` `path:line:col: [error|warning] message (rule)` lines."""
    return _parse_regex_lines(
        inp,
        r"^(.+?):(\d+):(\d+):\s+\[(error|warning|info)\]\s+(.+?)(?:\s+\(([^)]+)\))?\s*$",
        lambda m: _finding_from(
            inp, "yamllint", m.group(1), m.group(2), m.group(6) or "syntax", m.group(5), m.group(4)
        ),
        flags=re.IGNORECASE,
        strip=True,
    )


def _parse_taplo(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse both `taplo format --check` and `taplo lint` output blocks leniently."""
    findings: list[dict[str, Any]] = []
    pending_msg, pending_sev = "", "error"
    for raw_line in _combined_text(inp).splitlines():
        s = raw_line.strip()
        if not s:
            continue
        if m_fmt := re.search(r'not properly formatted.*?\bpath="([^"]+)"', s):
            findings.append(
                _finding_from(inp, "taplo", m_fmt.group(1), 0, "taplo", "TOML file is not properly formatted", "warning")
            )
        elif m_hdr := re.match(r"^(error|warning)(?:\[[^\]]*\])?:\s+(.+)$", s, re.IGNORECASE):
            pending_sev, pending_msg = m_hdr.group(1).lower(), m_hdr.group(2).strip()
        elif m_loc := re.match(r"^(?:┌─|-->)\s+(.+?):(\d+):(\d+)\s*$", s):
            findings.append(
                _finding_from(
                    inp, "taplo", m_loc.group(1), m_loc.group(2), "taplo",
                    pending_msg or "TOML lint error", pending_sev,
                )
            )
            pending_msg = ""
        elif s.endswith(".toml") and " " not in s:
            findings.append(
                _finding_from(inp, "taplo", s, 0, "taplo", "TOML file needs formatting", "warning")
            )
    return findings if findings else _unparseable_fallback(inp)


def _parse_rumdl_json(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `rumdl check --output-format json` array or object into warning findings."""
    def _extract(data: Any) -> Any:
        if isinstance(data, dict):
            for key in ("warnings", "findings", "diagnostics"):
                if key in data:
                    return data.get(key)
            return [data]
        return data if isinstance(data, list) else None

    def _build(item: dict[str, Any]) -> dict[str, Any] | None:
        fname = item.get("file") or item.get("filename")
        line_no = item.get("line", 0)
        rule = item.get("rule") or item.get("code")
        msg = item.get("message")
        if not _is_nonempty_str(fname, rule, msg) or not _is_valid_int(line_no, min_value=0):
            return None
        return _finding_from(inp, "rumdl", fname, line_no, rule, msg, item.get("severity"))

    return _parse_json_items(inp, _extract, _build)


def _parse_hadolint_json(inp: ParseInput) -> list[dict[str, Any]]:
    """Parse `hadolint -f json` array of `{file, line, code, level, message}` into findings."""
    def _build(item: dict[str, Any]) -> dict[str, Any] | None:
        fname, line_no, code, msg = (
            item.get("file"),
            item.get("line"),
            item.get("code"),
            item.get("message"),
        )
        if not _is_nonempty_str(fname, code, msg) or not _is_valid_int(line_no, min_value=0):
            return None
        return _finding_from(inp, "hadolint", fname, line_no, code, msg, item.get("level"))

    return _parse_json_items(inp, lambda d: d if isinstance(d, list) else None, _build)


PARSERS: dict[str, Callable[[ParseInput], list[dict[str, Any]]]] = {
    "ruff": _parse_ruff,
    "ruff-format": _parse_ruff_format,
    "rustfmt": _parse_rustfmt,
    "cargo-json": _parse_cargo_json,
    "biome-json": _parse_biome_json,
    "oxlint-json": _parse_oxlint_json,
    "gofmt": _parse_gofmt,
    "go-vet": _parse_go_vet,
    "golangci-json": _parse_golangci_json,
    "clang-format": _parse_clang_format,
    "clang-tidy": _parse_clang_tidy,
    "csharpier": _parse_csharpier,
    "dotnet-format": _parse_dotnet_format,
    "gdformat": _parse_gdformat,
    "gdlint": _parse_gdlint,
    "stylua": _parse_stylua,
    "selene-json": _parse_selene_json,
    "glslang": _parse_glslang,
    "dxc": _parse_dxc,
    "shfmt": _parse_shfmt,
    "shellcheck-json": _parse_shellcheck_json,
    "pwsh-parse-json": _parse_pwsh_parse_json,
    "psscriptanalyzer-json": _parse_psscriptanalyzer_json,
    "yamllint-parsable": _parse_yamllint_parsable,
    "taplo": _parse_taplo,
    "rumdl-json": _parse_rumdl_json,
    "hadolint-json": _parse_hadolint_json,
}


def detect_for_project(
    root: Path | str,
    db_path: Path | str | None = None,
    *,
    scan_result: lint_tools.ScanResult | None = None,
    include_unsatisfied: bool = False,
) -> tuple[list[ToolSpec], list[str]]:
    """Detect applicable ToolSpecs for root (consulting state_store languages) and return (specs, warnings)."""
    base = Path(root).expanduser()
    warnings: list[str] = []
    languages: list[str] = []
    try:
        proj = state_store.get_project(base, db_path=db_path)
        if isinstance(proj, dict) and isinstance(proj.get("languages"), list):
            languages = [str(x) for x in proj["languages"]]
    except Exception as exc:
        warnings.append(f"state_store lookup failed: {exc}")

    scan_res = lint_tools.scan(base) if scan_result is None else scan_result
    if scan_res.truncated:
        warnings.append(
            f"Project file scan truncated at {lint_tools.MAX_DETECT_WALK_ENTRIES} entries"
        )
    specs = lint_tools.detect(
        base,
        languages,
        scan_result=scan_res,
        include_unsatisfied=include_unsatisfied,
    )
    return specs, warnings


def _matching_files_for_spec(spec: ToolSpec, all_files: Sequence[str]) -> list[str]:
    """Filter scanned project files matching spec.input_globs (or [] for whole-project tools)."""
    if not spec.input_globs:
        return []
    matched: list[str] = []
    for rel in all_files:
        if lint_tools.is_generated_lockfile(rel):
            continue
        if any(lint_tools._glob_matches_path(pat, rel) for pat in spec.input_globs):
            if spec.name == "glslangValidator" and lint_tools.derive_glsl_stage(rel) is None:
                continue
            if spec.name == "dxc" and Path(rel).suffix.lower() in lint_tools._SHADER_HEADER_EXTENSIONS:
                continue
            matched.append(rel)
    return matched


def _dedupe_and_sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate identical findings and sort by (file, line, tool, rule, message)."""
    seen: set[tuple[str, int, str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = (
            str(f.get("file", "")),
            int(f.get("line", 0)),
            str(f.get("tool", "")),
            str(f.get("rule", "")),
            str(f.get("message", "")),
            str(f.get("severity", "")),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(
        key=lambda x: (
            str(x.get("file", "")),
            int(x.get("line", 0)),
            str(x.get("tool", "")),
            str(x.get("rule", "")),
            str(x.get("message", "")),
        )
    )
    return unique


def _error_response(project_str: str, mode: str, err: str) -> dict[str, Any]:
    """Return a structured error response dict when run_lint cannot start."""
    return {
        "ok": False,
        "status": "error",
        "project": project_str,
        "mode": str(mode),
        "findings": [],
        "tools_run": [],
        "tools_missing": [],
        "tool_statuses": [],
        "tool_errors": [],
        "warnings": [],
        "error": err,
    }


def _load_rule_settings(db_path: Path | str | None) -> list[dict[str, Any]]:
    """Read and validate saved workspace-ui/settings rules before executing any tool."""
    entry = safe_state_store.get_entry(
        db_path if db_path is not None else state_store.state_db_path(),
        "workspace-ui",
        "settings",
    )
    settings = entry["value"] if entry else {}
    if not isinstance(settings, dict):
        raise LintError("settings must be an object")
    rules = settings.get("rules", [])
    if not isinstance(rules, list):
        raise LintError("rules must be a list")
    seen: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise LintError("each rule must be an object")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id or rule_id != rule_id.strip():
            raise LintError("rule id must be a non-empty string without surrounding whitespace")
        if rule_id in seen:
            raise LintError(f"duplicate rule id: {rule_id}")
        seen.add(rule_id)
        if not isinstance(rule.get("enabled", True), bool):
            raise LintError(f"{rule_id}: enabled must be boolean")
        if rule.get("mode", "both") not in ("pre", "post", "both"):
            raise LintError(f"{rule_id}: mode must be pre, post, or both")
        if "severity" in rule and rule["severity"] not in ("error", "warning", "info"):
            raise LintError(f"{rule_id}: severity must be error, warning, or info")
    return rules


def _settings_group(spec: ToolSpec) -> str:
    """Classify a tool invocation for the saved format/analysis/repo groups."""
    if spec.executes_repo_code:
        return "repo"
    return "format" if spec.tool in _FORMAT_TOOLS else "analysis"


def _make_tool_status(
    tool: str,
    mode: str,
    status: str,
    message: str = "",
    *,
    findings: int = 0,
    exit_code: int | None = None,
) -> dict[str, Any]:
    """Construct a per-tool, per-mode status entry."""
    return {
        "tool": tool,
        "mode": mode,
        "status": status,
        "findings": findings,
        "exit_code": exit_code,
        "message": message,
    }


def _make_tool_error(tool: str, mode: str, status: str, message: str) -> dict[str, Any]:
    """Construct a per-tool error entry for incomplete runs."""
    return {"tool": tool, "mode": mode, "status": status, "message": message}


def _make_tool_run(
    tool: str,
    mode: str,
    argv: list[str],
    exit_code: int,
    duration_ms: int,
    findings: int,
    status: str,
) -> dict[str, Any]:
    """Construct a per-tool execution record for tools_run."""
    return {
        "tool": tool,
        "mode": mode,
        "argv": argv,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "findings": findings,
        "status": status,
    }


def _filter_enabled_modes(
    spec: ToolSpec,
    requested_modes: Sequence[str],
    rule_settings: Sequence[dict[str, Any]],
    tool_statuses: list[dict[str, Any]],
) -> list[str]:
    """Filter spec.modes against requested_modes and saved rule settings, recording disabled statuses."""
    active_modes = [m for m in spec.modes if m in requested_modes]
    if not active_modes:
        return []
    group_name = _settings_group(spec)
    enabled_modes: list[str] = []
    for m in active_modes:
        applicable = {
            s["id"]: s for s in rule_settings if s.get("mode", "both") in ("both", m)
        }
        group_cfg = applicable.get(group_name, {})
        tool_cfg = applicable.get(spec.tool, {})
        if tool_cfg.get("enabled", group_cfg.get("enabled", True)) is False:
            tool_statuses.append(
                _make_tool_status(
                    spec.tool, m, "disabled", f"Skipped {spec.tool}: disabled by saved lint settings"
                )
            )
        else:
            enabled_modes.append(m)
    return enabled_modes


def _record_mode_statuses(
    tool_statuses: list[dict[str, Any]],
    spec: ToolSpec,
    modes: Sequence[str],
    status: str,
    message: str,
) -> None:
    """Append one skipped-run status entry per mode for spec."""
    for m in modes:
        tool_statuses.append(_make_tool_status(spec.tool, m, status, message))


def _not_configured_message(spec: ToolSpec) -> str:
    """Build a human-readable configuration error message for an unsatisfied ToolSpec."""
    if "compile_commands.json" in spec.requires:
        return (
            f"{spec.tool} requires compile_commands.json (searched in <root>/, build/, out/). "
            "To enable: generate a compilation database (e.g. `cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` or `bear -- make`)."
        )
    return f"{spec.tool} is not configured: missing required {', '.join(spec.requires)}"


def _execute_tool_mode(
    spec: ToolSpec,
    mode: str,
    root_path: Path,
    matched_files: list[str],
    resolved_bins: Mapping[str, str | None],
    run_env: Mapping[str, str],
    timeout_s: int,
    runner: Callable[..., Any] | None,
) -> tuple[list[str], Any, int, Exception | None]:
    """Build argv, manage temporary SPIR-V output if needed, and run the tool subprocess."""
    cmd = list(lint_tools.argv(spec, mode, root_path, matched_files))
    resolved_first = resolved_bins.get(cmd[0]) or lint_env.which(cmd[0], run_env)
    if resolved_first:
        cmd[0] = resolved_first

    tmp_spv_path: Path | None = None
    if spec.name == "glslangValidator" and "-o" in cmd:
        o_idx = cmd.index("-o")
        if o_idx + 1 < len(cmd) and cmd[o_idx + 1] == os.devnull:
            fd, raw_tmp = tempfile.mkstemp(prefix=".adopt-glslang-", suffix=".spv")
            os.close(fd)
            tmp_spv_path = Path(raw_tmp)
            cmd[o_idx + 1] = str(tmp_spv_path)

    t0 = time.monotonic()
    cp: Any = None
    exec_exc: Exception | None = None
    try:
        cp = lint_env.run(cmd, cwd=root_path, env=run_env, timeout_s=timeout_s, runner=runner)
    except Exception as exc:
        exec_exc = exc
    if tmp_spv_path is not None:
        tmp_spv_path.unlink(missing_ok=True)
    return cmd, cp, int((time.monotonic() - t0) * 1000), exec_exc


def _is_parse_error_marker(finding: dict[str, Any]) -> bool:
    """Return True for the file-less parse-error marker emitted by _make_parse_error_marker."""
    return finding.get("rule") == "parse-error" and finding.get("file", "") == ""


def _classify_tool_output(
    spec: ToolSpec,
    cp: Any,
    root_path: Path,
    matched_files: Sequence[str],
    timeout_s: int,
    warnings: list[str],
) -> tuple[str, str, list[dict[str, Any]]]:
    """Parse subprocess output and classify the run into (status, message, findings)."""
    if cp.returncode == lint_env.TIMEOUT_RC:
        msg = f"tool {spec.tool} timed out after {timeout_s}s"
        warnings.append(msg)
        return "timed_out", msg, []

    if cp.returncode != 0:
        start_msg = lint_env.tool_start_failure_message(spec.tool, cp.stdout or "", cp.stderr or "")
        if start_msg:
            warnings.append(start_msg)
            return "crashed", start_msg, []

    parser_fn = PARSERS.get(spec.parser)
    if parser_fn is None:
        msg = f"No parser registered for {spec.parser!r} (tool {spec.tool})"
        warnings.append(msg)
        return "crashed", msg, []

    parse_inp = ParseInput(
        stdout=cp.stdout or "",
        stderr=cp.stderr or "",
        returncode=cp.returncode,
        root=root_path,
        files=matched_files,
        tool=spec.tool,
    )
    try:
        raw_parsed = parser_fn(parse_inp)
    except Exception as exc:
        msg = f"Parser {spec.parser} failed for {spec.tool}: {exc}"
        warnings.append(msg)
        return "crashed", msg, []

    parse_errors = [f for f in raw_parsed if _is_parse_error_marker(f)]
    tool_findings = [f for f in raw_parsed if not _is_parse_error_marker(f)]

    if _is_crash_exit(cp.returncode):
        msg = f"tool {spec.tool} crashed (rc={cp.returncode}){_output_snippet(parse_inp)}"
        warnings.append(msg)
        return "crashed", msg, tool_findings

    if parse_errors or (cp.returncode != 0 and not tool_findings):
        has_output = bool(_combined_text(parse_inp).strip())
        status = "unparseable" if has_output else "crashed"
        msg = (
            str(parse_errors[0].get("message", ""))
            if parse_errors
            else _format_unparseable_message(parse_inp)
        )
        warnings.append(msg)
        return status, msg, tool_findings

    return ("findings" if tool_findings else "clean"), "", tool_findings


def _apply_rule_settings(
    spec: ToolSpec,
    mode: str,
    rule_settings: Sequence[dict[str, Any]],
    tool_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Apply saved group, tool, and tool:rule enable/severity overrides to parsed findings."""
    group_name = _settings_group(spec)
    ordered_settings = sorted(
        rule_settings,
        key=lambda s: 0 if s.get("id") == group_name else (1 if s.get("id") == spec.tool else 2),
    )
    for setting in ordered_settings:
        if setting.get("mode", "both") not in ("both", mode):
            continue
        rule_id = setting.get("id")
        adjusted: list[dict[str, Any]] = []
        for finding in tool_findings:
            if rule_id in (group_name, spec.tool, f"{spec.tool}:{finding['rule']}"):
                if setting.get("enabled", True) is False:
                    continue
                if "severity" in setting:
                    finding = {**finding, "severity": setting["severity"]}
            adjusted.append(finding)
        tool_findings = adjusted
    return tool_findings


def _run_spec_mode(
    spec: ToolSpec,
    mode: str,
    root_path: Path,
    matched_files: list[str],
    resolved_bins: Mapping[str, str | None],
    run_env: Mapping[str, str],
    timeout_s: int,
    runner: Callable[..., Any] | None,
    rule_settings: Sequence[dict[str, Any]],
    warnings: list[str],
    tools_run: list[dict[str, Any]],
    tool_statuses: list[dict[str, Any]],
    tool_errors: list[dict[str, Any]],
    all_findings: list[dict[str, Any]],
) -> None:
    """Execute one (spec, mode) invocation, classify its output, and append status/finding records."""
    cmd, cp, duration_ms, exec_exc = _execute_tool_mode(
        spec, mode, root_path, matched_files, resolved_bins, run_env, timeout_s, runner
    )
    if exec_exc is not None:
        msg = f"tool {spec.tool} failed to execute: {exec_exc}"
        warnings.append(msg)
        tools_run.append(_make_tool_run(spec.tool, mode, cmd, -1, duration_ms, 0, "crashed"))
        tool_statuses.append(_make_tool_status(spec.tool, mode, "crashed", msg, exit_code=-1))
        tool_errors.append(_make_tool_error(spec.tool, mode, "crashed", msg))
        return

    tool_status, status_msg, tool_findings = _classify_tool_output(
        spec, cp, root_path, matched_files, timeout_s, warnings
    )
    tool_findings = _apply_rule_settings(spec, mode, rule_settings, tool_findings)
    if tool_status in ("clean", "findings"):
        tool_status = "findings" if tool_findings else "clean"
    deduped = _dedupe_and_sort_findings(tool_findings)
    all_findings.extend(deduped)

    tools_run.append(
        _make_tool_run(spec.tool, mode, cmd, cp.returncode, duration_ms, len(deduped), tool_status)
    )
    tool_statuses.append(
        _make_tool_status(
            spec.tool, mode, tool_status, status_msg, findings=len(deduped), exit_code=cp.returncode
        )
    )
    if tool_status in ("timed_out", "crashed", "unparseable"):
        tool_errors.append(_make_tool_error(spec.tool, mode, tool_status, status_msg))


def run_lint(
    root: Path | str,
    mode: str = "both",
    *,
    env: Mapping[str, str] | None = None,
    runner: Callable[..., Any] | None = None,
    db_path: Path | str | None = None,
    timeout_scale: float = 1.0,
    max_findings: int = 5000,
) -> dict[str, Any]:
    """Run detected lint tools for root in mode ('pre'|'post'|'both') and return structured findings."""
    project_str = str(root)
    if mode not in ("pre", "post", "both"):
        return _error_response(
            project_str, str(mode), f"Invalid mode {mode!r}; expected 'pre', 'post', or 'both'"
        )

    try:
        safety.assert_not_live_hermes(root, "project")
        root_path = safety._lexical_abs(root)
    except Exception as exc:
        return _error_response(project_str, mode, str(exc))

    project_str = str(root_path)
    if not root_path.exists() or not root_path.is_dir():
        return _error_response(
            project_str, mode, f"Project root does not exist or is not a directory: {root_path}"
        )

    try:
        run_env = lint_env.build_env() if env is None else dict(env)
    except Exception as exc:
        return _error_response(project_str, mode, f"environment build failed: {exc}")

    try:
        rule_settings = _load_rule_settings(db_path)
    except Exception as exc:
        return _error_response(project_str, mode, f"lint settings could not be loaded: {exc}")

    scan_res = lint_tools.scan(root_path)
    specs, warnings = detect_for_project(
        root_path, db_path=db_path, scan_result=scan_res, include_unsatisfied=True
    )
    all_files = scan_res.files

    requested_modes: tuple[str, ...] = ("pre", "post") if mode == "both" else (mode,)
    tools_run: list[dict[str, Any]] = []
    tools_missing: list[str] = []
    missing_seen: set[str] = set()
    tool_statuses: list[dict[str, Any]] = []
    tool_errors: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    warned_repo_code = False

    for spec in specs:
        active_modes = _filter_enabled_modes(spec, requested_modes, rule_settings, tool_statuses)
        if not active_modes:
            continue

        matched_files = _matching_files_for_spec(spec, all_files)
        if spec.input_globs and not matched_files:
            _record_mode_statuses(
                tool_statuses, spec, active_modes, "no_files", f"Skipped {spec.tool}: no matching input files"
            )
            continue

        if not spec.is_satisfied(root_path):
            not_cfg_msg = _not_configured_message(spec)
            warnings.append(not_cfg_msg)
            tool_errors.append(_make_tool_error(spec.tool, active_modes[0], "not_configured", not_cfg_msg))
            _record_mode_statuses(tool_statuses, spec, active_modes, "not_configured", not_cfg_msg)
            continue

        resolved_bins = {b: lint_env.which(b, run_env) for b in spec.binaries}
        missing_bins = [b for b, v in resolved_bins.items() if v is None]
        if missing_bins:
            msg = f"tool {spec.tool} is not installed (missing binary: {', '.join(missing_bins)})"
            if spec.tool not in missing_seen:
                missing_seen.add(spec.tool)
                tools_missing.append(spec.tool)
                warnings.append(msg)
                tool_errors.append(_make_tool_error(spec.tool, active_modes[0], "not_installed", msg))
            _record_mode_statuses(tool_statuses, spec, active_modes, "not_installed", msg)
            continue

        if len(matched_files) > MAX_FILES_PER_TOOL:
            warnings.append(
                f"Tool {spec.tool} file list capped at {MAX_FILES_PER_TOOL} files (of {len(matched_files)})"
            )
            matched_files = matched_files[:MAX_FILES_PER_TOOL]

        timeout_s = max(1, int(spec.timeout_s * timeout_scale))
        for m in active_modes:
            if spec.executes_repo_code and not warned_repo_code:
                warnings.append(REPO_CODE_WARNING)
                warned_repo_code = True
            _run_spec_mode(
                spec,
                m,
                root_path,
                matched_files,
                resolved_bins,
                run_env,
                timeout_s,
                runner,
                rule_settings,
                warnings,
                tools_run,
                tool_statuses,
                tool_errors,
                all_findings,
            )

    return _lint_result(
        project_str,
        mode,
        all_findings,
        all_files,
        max_findings,
        tools_run,
        tools_missing,
        tool_statuses,
        tool_errors,
        warnings,
    )


def _lint_result(
    project_str: str,
    mode: str,
    all_findings: list[dict[str, Any]],
    all_files: Sequence[str],
    max_findings: int,
    tools_run: list[dict[str, Any]],
    tools_missing: list[str],
    tool_statuses: list[dict[str, Any]],
    tool_errors: list[dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    """Dedupe/cap findings and assemble the final run_lint response dict."""
    sorted_findings = _dedupe_and_sort_findings(all_findings)
    if len(sorted_findings) > max_findings:
        warnings.append(
            f"Findings truncated at {max_findings} (of {len(sorted_findings)} total findings)"
        )
        sorted_findings = sorted_findings[:max_findings]

    ok = len(tool_errors) == 0
    overall_status = "incomplete" if not ok else ("findings" if sorted_findings else "clean")
    overall_error = (
        None
        if ok
        else "Tool(s) failed or could not run: "
        + ", ".join(f"{e['tool']} ({e['status']})" for e in tool_errors)
    )

    return {
        "ok": ok,
        "status": overall_status,
        "project": project_str,
        "mode": mode,
        "findings": sorted_findings,
        "tools_run": tools_run,
        "tools_missing": tools_missing,
        "skipped_generated": sorted(
            path for path in all_files if lint_tools.is_generated_lockfile(path)
        ),
        "tool_statuses": tool_statuses,
        "tool_errors": tool_errors,
        "warnings": warnings,
        "error": overall_error,
    }
