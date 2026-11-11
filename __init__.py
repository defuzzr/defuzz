"""Project Defuzz Hermes Plugin (__init__.py).

Registers:
- Tools: defuzz_project, defuzz_place
- Hooks: pre_tool_call (write_file placement), transform_tool_result (placed_at note)
- CLI subcommand: hermes defuzz {scan,copy,rules,apply,run,place}
- Slash command: /defuzz
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import re
from contextlib import redirect_stdout, redirect_stderr
import shlex
import sys
from typing import Any, Dict

from . import schemas
from .cli import execute_defuzz_place, execute_defuzz_project, handle_defuzz_cli, setup_defuzz_cli
from .placer import on_pre_tool_call, on_transform_tool_result
from .safety import SafetyError


CLI_ONLY_ARGS = {"include_secret_files": "--include-secret-files"}


def _declared_args(schema: Dict[str, Any], args: Any) -> Dict[str, Any]:
    """Agent-tool boundary: only schema-declared properties reach the engine (rules 11/12)."""
    payload = args if isinstance(args, dict) else {}
    for key, flag in CLI_ONLY_ARGS.items():
        if key in payload:
            raise SafetyError(
                f"{key!r} is not available to agent tools; a user must pass {flag} to the "
                "`hermes defuzz` CLI to copy secret-named files"
            )
    declared = set(schema.get("parameters", {}).get("properties", {}))
    unknown = sorted(set(payload) - declared)
    if unknown:
        raise SafetyError(f"Undeclared argument(s) {unknown} rejected (allowed: {sorted(declared)})")
    return dict(payload)


def _handle_defuzz_project_tool(args: Dict[str, Any], ctx: Any = None, **kwargs: Any) -> str:
    from .catalog_list import coming_soon_message

    # Refuse unavailable choices even before the schema rejects unsupported creation args.
    if isinstance(args, dict):
        for kind in ("kit", "template"):
            refusal = coming_soon_message(kind, args.get(f"{kind}_id"))
            if refusal:
                return json.dumps({"ok": False, "error": refusal})
    try:
        res = execute_defuzz_project(_declared_args(schemas.DEFUZZ_PROJECT, args), ctx=ctx)
        return json.dumps(res)
    except SafetyError as exc:
        return json.dumps({"ok": False, "error": str(exc)})
    except Exception as exc:
        return json.dumps({"ok": False, "error": f"defuzz_project failed: {exc}"})


def _handle_defuzz_place_tool(args: Dict[str, Any], **kwargs: Any) -> str:
    try:
        payload = _declared_args(schemas.DEFUZZ_PLACE, args)
        action = str(payload.get("action") or "").strip().lower()
        allowed_actions = set(
            schemas.DEFUZZ_PLACE.get("parameters", {})
            .get("properties", {})
            .get("action", {})
            .get("enum", ())
        )
        if action not in allowed_actions:
            raise SafetyError(
                f"Action {action!r} is not allowed in defuzz_place tool (allowed: {sorted(allowed_actions)})"
            )
        res = execute_defuzz_place(payload)
        return json.dumps(res)
    except SafetyError as exc:
        return json.dumps({"ok": False, "error": str(exc)})
    except Exception as exc:
        return json.dumps({"ok": False, "error": f"defuzz_place failed: {exc}"})


# Third-party packages the audit needs at import time, by import name -> PyPI name.
_AUDIT_PACKAGES = {"yaml": "PyYAML"}


def _missing_package(exc: ImportError) -> str | None:
    """PyPI name of the missing third-party package behind *exc*, or None for any other error."""
    root = (getattr(exc, "name", None) or "").split(".")[0]
    return _AUDIT_PACKAGES.get(root) if isinstance(exc, ModuleNotFoundError) else None


def _missing_package_message(package: str) -> str:
    return f"defuzz audit needs the Python package {package}, which is not installed."


def _audit_schema() -> Dict[str, Any]:
    """The audit tool schema; a minimal stand-in when an audit dependency is missing, so the
    plugin still loads and the tool answers with one plain line instead of breaking discovery."""
    try:
        from .audit_surface import SCHEMA
        return SCHEMA
    except ImportError as exc:
        package = _missing_package(exc)
        if package is None:
            raise
        return {"name": "defuzz_audit", "description": _missing_package_message(package),
                "parameters": {"type": "object", "properties": {
                    "action": {"type": "string", "enum": ["run", "status", "report", "cancel", "resume"]}},
                    "required": ["action"]}}


def _handle_defuzz_audit_tool(args: Dict[str, Any], **kwargs: Any) -> str:
    try:
        from .audit_surface import execute_audit
    except ImportError as exc:
        package = _missing_package(exc)
        if package is None:
            raise
        return json.dumps({"ok": False, "error": _missing_package_message(package)})
    try:
        return json.dumps(execute_audit(_declared_args(_audit_schema(), args)))
    except (ValueError, KeyError, SafetyError) as exc:
        return json.dumps({"ok": False, "error": str(exc)})


APP_LINE = "Open the plugin page to create a project."
USAGE_LINE = (
    "Usage: /defuzz list | /defuzz new --template ID|--kit ID --name NAME | "
    "/defuzz scan|run <copy_dir> [--source <src_dir>] | /defuzz report <copy_dir> | "
    "/defuzz lint <project> [--mode pre|post|both] "
    "(also: new [--yes], scan [--out <inventory.json>], run [--staging <staging_dir>], "
    "lint [--json]; run /defuzz list first, show the user the list, wait for their choice, "
    "pass its id)"
)
SLASH_MAX_CHARS = 8192
"""Longest /defuzz text read at all: room for an idea at the parser's cap plus paths and flags."""
SLASH_REPLY_MAX = 4000
"""Longest argparse error text put in a reply (it can echo what was typed)."""
UNREADABLE_LINE = (
    "Could not read that command: a quote or a backslash is not closed. "
    "Put the idea in double quotes, or remove the stray quote."
)
TOO_LONG_LINE = (
    f"That /defuzz command is too long (at most {SLASH_MAX_CHARS} characters); "
    "keep the idea short and try again."
)
_LIST_SUBS = ("new", "list")


def _first_word(raw: str) -> str:
    head = raw.lstrip()[:32].split(None, 1)
    return head[0].lower() if head else ""


def _refusal(line: str, sub: str) -> str:
    """One plain line plus the usage line; `new` and `list` also point to the plugin page."""
    tail = f"\n{APP_LINE}" if sub in _LIST_SUBS else ""
    return f"{line}\n{USAGE_LINE}{tail}"


def _handle_slash_command(ctx: Any, raw_args: str) -> str:
    from .catalog_list import escape_text

    raw = raw_args if isinstance(raw_args, str) else ""
    if len(raw) > SLASH_MAX_CHARS:  # refuse before any parsing work (shlex is slow on huge text)
        return _refusal(TOO_LONG_LINE, _first_word(raw))
    try:
        tokens = shlex.split(raw)
    except ValueError:  # unmatched quote, or a backslash at the very end
        return _refusal(UNREADABLE_LINE, _first_word(raw))
    app_line = APP_LINE
    if not tokens:
        return f"{app_line} In chat: {USAGE_LINE}"
    sub = tokens[0].lower()
    if sub in ("lint", "audit", "new", "templates", "list"):
        parser = argparse.ArgumentParser(prog="/defuzz")
        setup_defuzz_cli(parser, ctx=ctx)
        output = io.StringIO()
        as_json = False
        parse_failed = False
        with redirect_stdout(output), redirect_stderr(output):
            try:
                ns = parser.parse_args(tokens)
            except SystemExit as exc:
                code = exc.code
                parse_failed = True
            else:
                as_json = bool(getattr(ns, "as_json", False))
                try:
                    code = handle_defuzz_cli(ns, ctx=ctx)
                except SystemExit as exc:
                    code = exc.code
        label = 'Lint' if sub == 'lint' else sub.capitalize()
        text = escape_text(output.getvalue().strip())
        if parse_failed and code and len(text) > SLASH_REPLY_MAX:  # an argparse error echoes the input
            text = text[:SLASH_REPLY_MAX].rstrip() + " ..."
        if sub in _LIST_SUBS and not as_json:
            if text:  # kit names come from another plugin: a code block keeps links and mentions inert
                fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", text)), default=0))
                text = f"{fence}\n{text}\n{fence}"
            text = f"{text}\n{app_line}".strip()
        return f"{text}\n{label} exit code: {code}".strip()
    if sub == "report" and len(tokens) >= 2:
        return _handle_defuzz_project_tool({"action": "report", "copy_path": tokens[1]}, ctx=ctx)
    if sub in ("scan", "run", "apply") and len(tokens) >= 2:
        payload: Dict[str, Any] = {"action": sub, "copy_path": tokens[1]}
        idx = 2
        while idx < len(tokens):
            flag = tokens[idx]
            if flag == "--source" and idx + 1 < len(tokens):
                payload["source_path"] = tokens[idx + 1]
                idx += 2
            elif flag == "--staging" and idx + 1 < len(tokens):
                payload["staging_path"] = tokens[idx + 1]
                idx += 2
            elif flag == "--out" and idx + 1 < len(tokens):
                payload["inventory_path"] = tokens[idx + 1]
                idx += 2
            elif flag == "--deterministic":
                payload["use_fallback_rules"] = True
                idx += 1
            else:
                idx += 1
        return _handle_defuzz_project_tool(payload, ctx=ctx)
    return f"Unknown /defuzz subcommand: {sub!r}"


def register(ctx: Any) -> None:
    """Register tools, hooks, CLI command, and slash command with Hermes PluginContext."""
    if not sys.platform.startswith("linux"):
        logging.getLogger(__name__).warning("Defuzz supports Linux only.")
        return
    if tuple(sys.version_info[:2]) < (3, 13):
        logging.getLogger(__name__).warning("Defuzz needs Python 3.13 or newer.")
        return
    auto_place = bool(ctx.get_config("auto_place_writes", True))
    from .desktop_registration import bind_context
    bind_context(ctx)

    ctx.register_tool(name="defuzz_audit", toolset="defuzz", schema=_audit_schema(),
                      handler=_handle_defuzz_audit_tool)
    ctx.register_tool(
        name="defuzz_project",
        toolset="defuzz",
        schema=schemas.DEFUZZ_PROJECT,
        handler=lambda args, **kw: _handle_defuzz_project_tool(args, ctx=ctx, **kw),
    )
    ctx.register_tool(
        name="defuzz_place",
        toolset="defuzz",
        schema=schemas.DEFUZZ_PLACE,
        handler=_handle_defuzz_place_tool,
    )

    ctx.register_hook(
        "pre_tool_call",
        lambda **kw: on_pre_tool_call(auto_place_enabled=auto_place, **kw),
    )
    ctx.register_hook(
        "transform_tool_result",
        on_transform_tool_result,
    )
    ctx.register_cli_command(
        name="defuzz",
        help="Adopt messy folders on a safe copy and place new files automatically",
        setup_fn=lambda parser: setup_defuzz_cli(parser, ctx=ctx),
        handler_fn=lambda ns: handle_defuzz_cli(ns, ctx=ctx),
        description="Copy-only workspace organizer and mechanical file placement engine.",
    )

    ctx.register_command(
        name="defuzz",
        handler=lambda raw: _handle_slash_command(ctx, raw),
        description="Adopt a project copy, inspect its report, or run manual lint",
        args_hint="<list|new|scan|run|report|lint>",
    )
