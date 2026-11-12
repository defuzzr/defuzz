"""CLI and tool handlers for Project Defuzz."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import json
import os
import sys
import time
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

if not __package__:
    import importlib.util as _ilu
    import types as _types

    _pkg_dir = Path(__file__).resolve().parent
    _ns_name = "hermes_plugins"
    _pkg_name = f"{_ns_name}.defuzz"
    if _ns_name not in sys.modules:
        _ns_mod = _types.ModuleType(_ns_name)
        _ns_mod.__path__ = []  # type: ignore[attr-defined]
        _ns_mod.__package__ = _ns_name
        sys.modules[_ns_name] = _ns_mod
    if _pkg_name not in sys.modules:
        _init_path = _pkg_dir / "__init__.py"
        _pkg_spec = _ilu.spec_from_file_location(
            _pkg_name,
            _init_path,
            submodule_search_locations=[str(_pkg_dir)],
        )
        if _pkg_spec is None or _pkg_spec.loader is None:
            raise ImportError(f"Cannot create package spec for {_init_path}")
        _pkg_mod = _ilu.module_from_spec(_pkg_spec)
        _pkg_mod.__package__ = _pkg_name
        _pkg_mod.__path__ = [str(_pkg_dir)]  # type: ignore[attr-defined]
        sys.modules[_pkg_name] = _pkg_mod
    __package__ = _pkg_name

from . import catalog_list, componentize_bridge, lint_setup, linter, matcher, setup_manifest, tool_seed, toolchk, workspace_root
from .agents_md import DEFAULT_MAX_LINES
from .applier import ReportDestination, apply_rules_to_copy
from .lint_setup import describe_plan, headless_message, run_setup, status
from .linter import run_lint
from .matcher import parse_kit_list, parse_kit_list_detailed
from .network_failure import NETWORK_REQUIRED_REASON
from .new_project import run_new_project_flow
from .output_file import adopt_copy_guard, reuse_finished_copy, write_output_text
from .prompt_parse import MAX_PROMPT_CHARS
from .placer import (
    _is_valid_adopted_rules,
    _load_place_log,
    _parse_rules_bytes,
    _read_rules_bytes_nofollow,
    add_placement_rule,
    compute_rules_hash,
    inspect_project_trust,
    load_project_rules,
    place_existing_files,
    sweep_inbox,
    trust_project,
    undo_placements,
)
from .questionnaire import QUESTIONS, QuestionnaireTimeout, run_questionnaire, validate_answer
from .rules import (
    build_deterministic_fallback_rules,
    propose_rules_via_llm,
    validate_rules_spec,
)
from .safety import (
    GitUnavailableError,
    SafetyError,
    _is_same_or_subpath,
    _lexical_abs,
    assert_disjoint_roots,
    assert_not_live_hermes,
    assert_safe_root,
    copy_tree_nofollow,
)
from .scaffolder import (
    Proposal,
    ScaffoldError,
    ScaffoldTimeout,
    accept,
    default_project_create,
    discard,
    propose,
)
from .scanner import scan_folder
from .state_store import StateDirNotWritable, save_answers, state_db_path
from .templates import (
    TemplateError,
    load_templates,
    load_templates_lenient,
    templates_root as default_templates_root,
)

REGISTER_PROJECT: Callable[[str, str], str] = default_project_create
LEFT_BEHIND_DISPLAY_CAP = 50


def format_secret_files_left_behind(
    left_behind: Sequence[str],
    source: Optional[os.PathLike | str],
) -> str:
    """Render a plain-language terminal notice for secret-named files not copied."""
    if not left_behind:
        return ""
    from .audit_summary import safe_text

    src_display = safe_text(str(source), path=True) if source is not None else "the source folder"
    lines = [
        f"These files look like they hold secrets, so they were not copied; the originals are untouched in {src_display}. "
        "If the copy needs one, copy it yourself or run again with --include-secret-files:"
    ]
    shown = list(left_behind[:LEFT_BEHIND_DISPLAY_CAP])
    for rel in shown:
        lines.append(f"  - {safe_text(rel, path=True)}")
    remaining = len(left_behind) - len(shown)
    if remaining > 0:
        lines.append(f"  and {remaining} more")
    return "\n".join(lines)

_TOOLS_EXIT_CODES_EPILOG = (
    "Exit codes:\n"
    "  0  ok\n"
    "  2  blocked (version drift or unlisted tool)\n"
    "  3  probe failed (tool missing or version unreadable)\n"
    "  4  TOOLS.lock broken or missing"
)


def _default_inventory_out(copy_root: Path, explicit_out: Optional[str]) -> Path:
    if explicit_out:
        return _lexical_abs(explicit_out)
    candidate = _lexical_abs(os.getcwd()) / "inventory.json"
    if _is_same_or_subpath(candidate, copy_root):
        raise SafetyError(
            "Default './inventory.json' falls inside the scanned folder; pass --out <path> outside the copy."
        )
    return candidate


def _staging_default(
    args: Dict[str, Any],
    key: str,
    staging_path: Optional[Path],
    filename: str,
) -> Optional[str]:
    return args.get(key) or (str(staging_path / filename) if staging_path else None)


def _load_or_scan_inventory(
    copy_path: Path,
    source_path: Optional[Path],
    inv_path: Optional[str],
) -> Dict[str, Any]:
    if inv_path and Path(inv_path).is_file():
        return json.loads(Path(inv_path).read_text(encoding="utf-8"))
    return scan_folder(copy_path, source_root=source_path)


def _write_rules_file(
    rules_out: Optional[str],
    rules_spec: Dict[str, Any],
    forbidden_roots: Sequence[Optional[Path]] = (),
) -> Optional[str]:
    if not rules_out:
        return None
    r_lex = _lexical_abs(rules_out)
    assert_not_live_hermes(r_lex, role="rules_out")
    write_output_text(r_lex, json.dumps(rules_spec, indent=2) + "\n", role="rules_out", forbidden_roots=forbidden_roots)
    return str(r_lex)


def _resolve_agents_md_max_lines(ctx: Any) -> int:
    if ctx is not None and hasattr(ctx, "get_config"):
        try:
            cfg_lines = ctx.get_config("agents_md_max_lines", DEFAULT_MAX_LINES)
            if isinstance(cfg_lines, int) and 6 <= cfg_lines <= 100:
                return cfg_lines
        except Exception:
            pass
    return DEFAULT_MAX_LINES


def execute_defuzz_project(
    args: Dict[str, Any],
    *,
    ctx: Any = None,
) -> Dict[str, Any]:
    """Core dispatcher for defuzz_project tool and CLI commands."""
    for kind in ("kit", "template"):
        refusal = catalog_list.coming_soon_message(kind, args.get(f"{kind}_id"))
        if refusal:
            return {"ok": False, "error": refusal}
    action = str(args.get("action") or "").strip().lower()
    copy_raw = args.get("copy_path")
    if not copy_raw:
        raise SafetyError("copy_path is required")
    copy_path = _lexical_abs(copy_raw)
    source_path = _lexical_abs(args["source_path"]) if args.get("source_path") else None
    staging_path = _lexical_abs(args["staging_path"]) if args.get("staging_path") else None

    assert_disjoint_roots(source=source_path, staging=staging_path, output=copy_path)
    for key in ("report_path", "rules_path"):
        if args.get(key) and (key == "report_path" or action in ("propose_rules", "run")):
            assert_disjoint_roots(source=source_path, staging=args[key], output=copy_path)

    max_lines = _resolve_agents_md_max_lines(ctx)
    inv_arg = _staging_default(args, "inventory_path", staging_path, "inventory.json")
    rules_arg = _staging_default(args, "rules_path", staging_path, "rules.json")
    report_arg = _staging_default(args, "report_path", staging_path, "report.json")

    if action == "scan":
        scan_left_behind: Optional[List[str]] = None
        if source_path is not None and not copy_path.exists():
            scan_left_behind = []
            copy_tree_nofollow(
                source_path,
                copy_path,
                staging_root=staging_path,
                include_secret_files=bool(args.get("include_secret_files", False)),
                left_behind=scan_left_behind,
                base=copy_path,  # the folder the person chose (links above it are theirs)
            )
        inv_out = _default_inventory_out(copy_path, inv_arg)
        inv = scan_folder(
            copy_path,
            source_root=source_path,
            out_path=inv_out,
            secret_files_left_behind=scan_left_behind,
        )
        return {
            "ok": True,
            "action": "scan",
            "copy_root": str(copy_path),
            "inventory_path": str(inv_out),
            "total_regular_files": len(inv["files"]),
            "junk_dirs": inv["junk_dirs"],
            "mixed_cache_dirs": inv["mixed_cache_dirs"],
            "links_count": len(inv["links"]),
            "secrets_flagged_count": len(inv["secrets_flagged"]),
            "local_only_branches": inv["git"]["local_only_branches"],
        }

    if action == "propose_rules":
        inventory = _load_or_scan_inventory(copy_path, source_path, inv_arg)
        use_fallback = bool(args.get("use_fallback_rules", False))
        llm = getattr(ctx, "llm", None) if ctx is not None else None
        if not use_fallback and llm is not None:
            rules_spec = propose_rules_via_llm(inventory, llm)
        elif not use_fallback and llm is None:
            raise SafetyError("No ctx.llm available; pass use_fallback_rules=True or run inside Hermes")
        else:
            rules_spec = build_deterministic_fallback_rules(inventory)
        written_rules = _write_rules_file(rules_arg, rules_spec, (copy_path, source_path))
        return {"ok": True, "action": "propose_rules", "rules_path": written_rules, "rules": rules_spec}

    if action == "apply":
        inventory = _load_or_scan_inventory(copy_path, source_path, inv_arg)
        if rules_arg and Path(rules_arg).is_file():
            rules_spec = json.loads(Path(rules_arg).read_text(encoding="utf-8"))
        else:
            rules_spec = build_deterministic_fallback_rules(inventory)
        report = apply_rules_to_copy(
            copy_path,
            inventory,
            rules_spec,
            source_root=source_path,
            staging_root=staging_path,
            report_out_path=report_arg,
            agents_md_max_lines=max_lines,
        )
        return {"ok": True, "action": "apply", "report": report}

    if action == "run":
        include_secret_files = bool(args.get("include_secret_files", False))
        copied_left_behind: Optional[List[str]] = None
        # The report folder is checked and opened before anything is copied or committed.
        report_dest = ReportDestination(report_arg) if report_arg else contextlib.nullcontext()
        with report_dest, adopt_copy_guard(copy_path, source_path):
            if source_path is not None and not reuse_finished_copy(copy_path, source_path):
                copied_left_behind = []
                copy_tree_nofollow(
                    source_path,
                    copy_path,
                    staging_root=staging_path,
                    include_secret_files=include_secret_files,
                    left_behind=copied_left_behind,
                    base=copy_path,  # the folder the person chose (links above it are theirs)
                )
            inventory = scan_folder(
                copy_path,
                source_root=source_path,
                out_path=inv_arg,
                secret_files_left_behind=copied_left_behind,
            )
            left_behind = list(inventory.get("secret_files_left_behind") or [])
            use_fallback = bool(args.get("use_fallback_rules", False))
            llm = getattr(ctx, "llm", None) if ctx is not None else None
            rules_spec = (
                propose_rules_via_llm(inventory, llm)
                if not use_fallback and llm is not None
                else build_deterministic_fallback_rules(inventory)
            )
            written_rules = _write_rules_file(rules_arg, rules_spec, (copy_path, source_path))
            report = apply_rules_to_copy(
                copy_path,
                inventory,
                rules_spec,
                source_root=source_path,
                staging_root=staging_path,
                report_out_path=report_dest if report_arg else None,
                agents_md_max_lines=max_lines,
            )
        notice = format_secret_files_left_behind(left_behind, args.get("source_path") or source_path)
        return {
            "ok": True,
            "action": "run",
            "inventory_path": str(_lexical_abs(inv_arg)) if inv_arg else None,
            "rules_path": written_rules or str(copy_path / ".adopt" / "rules.json"),
            "secret_files_left_behind": left_behind,
            "secret_files_left_behind_count": len(left_behind),
            "secret_files_notice": notice or None,
            "report": report,
        }

    if action == "report":
        rep_file = copy_path / ".adopt" / "report.json"
        if not rep_file.is_file():
            raise SafetyError(f"No .adopt/report.json found in {copy_path}")
        return {"ok": True, "action": "report", "report": json.loads(rep_file.read_text(encoding="utf-8"))}

    raise SafetyError(f"Unknown defuzz_project action: {action!r}")


def execute_defuzz_place(args: Dict[str, Any]) -> Dict[str, Any]:
    """Core dispatcher for defuzz_place tool and CLI commands."""
    action = str(args.get("action") or "").strip().lower()
    root_raw = args.get("project_root")
    if not root_raw:
        raise SafetyError("project_root is required")
    proj_root = assert_safe_root(root_raw, role="project_root")

    if action == "place":
        return {"ok": True, "action": "place", "moved": place_existing_files(proj_root, args.get("paths") or [])}
    if action == "sweep":
        return {"ok": True, "action": "sweep", "moved": sweep_inbox(proj_root)}
    if action == "add_rule":
        rule = add_placement_rule(
            proj_root,
            str(args.get("ext") or ""),
            str(args.get("dest_dir") or ""),
            kind=args.get("kind"),
            lfs=bool(args.get("lfs", False)),
        )
        return {"ok": True, "action": "add_rule", "rule": rule}
    if action == "undo":
        return {"ok": True, "action": "undo", "undone": undo_placements(proj_root, count=int(args.get("count") or 1))}
    if action == "status":
        rules = load_project_rules(proj_root)
        log = _load_place_log(proj_root)
        trust = inspect_project_trust(proj_root)
        return {
            "ok": True,
            "action": "status",
            "trusted": trust["trusted"],
            "status": trust["status"],
            "reason": trust["reason"],
            "rules_hash": trust["rules_hash"],
            "project_slug": rules.get("project_slug"),
            "declared_dirs": rules.get("declared_dirs"),
            "placement_rules": rules.get("placement_rules"),
            "recent_placements": log[-20:],
        }

    raise SafetyError(f"Unknown defuzz_place action: {action!r}")


def _setup_tools_subparser(sub: Any) -> None:
    p_tools = sub.add_parser(
        "tools",
        help="Seed or inspect project TOOLS.lock",
        epilog=_TOOLS_EXIT_CODES_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    tools_sub = p_tools.add_subparsers(dest="tools_action", metavar="<action>")

    p_init = tools_sub.add_parser("init", help="Seed or refresh TOOLS.lock from project evidence")
    p_init.add_argument(
        "--event", default="adoption", help="Provenance event label recorded in auto reasons (default: adoption)"
    )
    p_init.add_argument("dir", nargs="?", default=None, help="Project root directory (default: current working directory)")

    p_status = tools_sub.add_parser(
        "status",
        help="Check locked tools against TOOLS.lock",
        epilog=_TOOLS_EXIT_CODES_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_status.add_argument("dir", nargs="?", default=None, help="Project root directory (default: current working directory)")
    p_status.add_argument("--json", dest="as_json", action="store_true", help="Print full toolchk report as JSON")

    for act_name, act_help, reason_help in (
        (
            "accept",
            "Accept the currently installed version of TOOL as chosen in TOOLS.lock",
            "Reason for choosing the currently installed version (required, non-empty)",
        ),
        (
            "reason",
            "Update the recorded reason for TOOL in TOOLS.lock",
            "Updated reason for the chosen version (required, non-empty)",
        ),
    ):
        p_act = tools_sub.add_parser(act_name, help=act_help)
        p_act.add_argument(
            "args", nargs="+", metavar="TOOL [DIR]",
            help="Locked tool name in TOOLS.lock and optional project root directory (default: cwd)",
        )
        p_act.add_argument("--reason", required=True, help=reason_help)

    p_snooze = tools_sub.add_parser(
        "snooze", help="Snooze upstream advisory note for TOOL for N days in the plugin state DB"
    )
    p_snooze.add_argument(
        "args", nargs="+", metavar="TOOL [DIR]",
        help="Locked tool name in TOOLS.lock and optional project root directory (default: cwd)",
    )
    p_snooze.add_argument(
        "--days", type=int, required=True, help="Number of days to snooze upstream advisory note (0 clears snooze)"
    )

    p_doctor = tools_sub.add_parser(
        "doctor", help="Check TOOLS.lock across all registered projects (informational, always exits 0)"
    )
    p_doctor.add_argument(
        "--json", dest="as_json", action="store_true", help="Print doctor lines and project summaries as JSON"
    )


def setup_defuzz_cli(parser: argparse.ArgumentParser, ctx: Any = None) -> None:
    """Configure argparse subcommands for 'hermes defuzz ...' or standalone 'defuzz ...'."""
    sub = parser.add_subparsers(dest="defuzz_subcommand", metavar="<subcommand>")

    from .audit.evidence_constants import AUDIT_SCOPE_DISCLOSURE
    p_audit = sub.add_parser(
        "audit",
        help="Manual read-only profile and registered-project audit",
        description=AUDIT_SCOPE_DISCLOSURE,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_audit.add_argument("audit_action", choices=("run", "status", "report", "cancel", "resume"), nargs="?", default="run")
    p_audit.add_argument("--run-id")
    p_audit.add_argument("--root", help="Select one active-profile registered project; trace its tree and evidenced outward dependencies")
    p_audit.add_argument("--as-of", type=int)
    p_audit.add_argument("--full-home", action="store_true", help="Compatibility flag; full project-outward static audit is already the default")
    p_audit.add_argument("--sessions", action="store_true", help="Opt in to bounded session transcript metrics; no text is retained")
    p_audit.add_argument("--quick", action="store_true", help="Explicit incomplete fixed-file audit; skips the full outward trace")
    p_audit.add_argument("--max-entries", type=int, help="Positive outward entry budget (collector default if omitted)")
    p_audit.add_argument("--max-bytes", type=int, help="Positive outward total byte budget (collector default if omitted)")
    p_audit.add_argument("--max-file-bytes", type=int, help="Positive outward per-file byte budget (collector default if omitted)")
    p_audit.add_argument("--unbounded", action="store_true", default=None, help="Disable outward resource budgets; component capture limits still apply")
    p_audit.add_argument("--unused-threshold-days", type=int, default=90)
    p_audit.add_argument("--json", action="store_true", help="JSON report (also the default)")
    p_audit.add_argument("--summary", action="store_true",
                         help="Plain-language summary of the report instead of JSON (falls back to JSON when no report is ready)")

    p_check = sub.add_parser("check", help="Read-only structure check: one project, or nested project roots inside?")
    p_check.add_argument("path", nargs="?", default=".", help="Folder to check (default: current directory)")
    p_check.add_argument("--json", dest="as_json", action="store_true", help="Print the full result as JSON")

    p_scan = sub.add_parser("scan", help="Read-only inventory of a COPY folder -> inventory.json")
    p_scan.add_argument("folder", help="Path to the COPY folder to scan")
    p_scan.add_argument("--source", dest="source_path", help="Optional original source folder (verified disjoint)")
    p_scan.add_argument("--staging", dest="staging_path", help="Optional staging directory (verified disjoint)")
    p_scan.add_argument("--out", dest="inventory_path", help="Output path for inventory.json (outside copy)")

    p_copy = sub.add_parser("copy", help="Create a disjoint, no-follow copy of a source folder")
    p_copy.add_argument("source", help="Source folder (never modified)")
    p_copy.add_argument("copy_path", help="Destination copy folder (must not exist or be empty)")
    p_copy.add_argument("--staging", dest="staging_path", help="Optional disjoint staging folder")
    p_copy.add_argument(
        "--include-secret-files",
        dest="include_secret_files",
        action="store_true",
        help="Also copy secret-named files and symlinks byte for byte into the copy",
    )

    p_rules = sub.add_parser("rules", help="Propose folder rules from inventory.json (1 LLM call or --deterministic)")
    p_rules.add_argument("folder", help="Path to the COPY folder")
    p_rules.add_argument("--inventory", dest="inventory_path", help="Path to inventory.json")
    p_rules.add_argument("--out", dest="rules_path", help="Output path for rules.json")
    p_rules.add_argument("--deterministic", dest="use_fallback_rules", action="store_true", help="Use deterministic rules")

    p_apply = sub.add_parser("apply", help="Expand rules, apply to copy, create Git baseline, write before/after report")
    p_apply.add_argument("folder", help="Path to the COPY folder")
    p_apply.add_argument("--source", dest="source_path", help="Optional source root (verified disjoint & unchanged)")
    p_apply.add_argument("--staging", dest="staging_path", help="Optional staging root")
    p_apply.add_argument("--inventory", dest="inventory_path", help="Path to inventory.json")
    p_apply.add_argument("--rules", dest="rules_path", help="Path to rules.json")
    p_apply.add_argument("--report", dest="report_path", help="Optional external path for report.json")

    p_run = sub.add_parser("run", help="End-to-end: copy (if --source) -> scan -> rules -> apply -> report")
    p_run.add_argument("folder", help="Path to the COPY folder")
    p_run.add_argument("--source", dest="source_path", help="Optional source folder to copy from")
    p_run.add_argument("--staging", dest="staging_path", help="Optional disjoint staging directory")
    p_run.add_argument("--inventory", dest="inventory_path", help="Path to write inventory.json")
    p_run.add_argument("--rules", dest="rules_path", help="Path to write rules.json")
    p_run.add_argument("--report", dest="report_path", help="Path to write report.json")
    p_run.add_argument("--deterministic", dest="use_fallback_rules", action="store_true", help="Use deterministic rules")
    p_run.add_argument(
        "--include-secret-files",
        dest="include_secret_files",
        action="store_true",
        help="Also copy secret-named files and symlinks byte for byte when copying --source",
    )

    p_place = sub.add_parser("place", help="Place loose files, sweep _inbox/, add rules, or undo placements")
    p_place.add_argument("paths", nargs="*", help="Relative paths inside project to place")
    p_place.add_argument("--root", dest="project_root", default=".", help="Adopted project root")
    p_place.add_argument("--sweep", action="store_true", help="Sweep _inbox/ using current rules")
    p_place.add_argument("--rule", nargs=2, metavar=("EXT", "DEST"), help="Add extension rule e.g. .fbx assets/3d")
    p_place.add_argument("--lfs", action="store_true", help="Mark added rule as Git LFS")
    p_place.add_argument("--undo", type=int, metavar="N", help="Undo last N placements")

    p_trust = sub.add_parser("trust", help="Trust an adopted project folder and record its rules.json hash")
    p_trust.add_argument("folder", help="Path to the adopted project folder")
    p_trust.add_argument(
        "--declared-only", dest="declared_only", action="store_true",
        help="Move a new file only when an explicit rule names its folder; never guess, never use _inbox/",
    )

    p_templates = sub.add_parser("templates", help="List available project templates and validation errors")
    p_templates.add_argument("--templates-root", dest="templates_root", help="Optional templates root directory (defaults to repo templates/)")

    p_kits = sub.add_parser("kits", help="List available project kits from the componentize plugin")
    p_kits.add_argument("--json", dest="as_json", action="store_true", help="Print kits and notice as JSON")

    p_list = sub.add_parser(
        "list",
        help="Show every project type you can start: templates and kits",
    )
    p_list.add_argument("--json", dest="as_json", action="store_true", help="Print the list as JSON")
    p_list.add_argument("--templates-root", dest="templates_root", help="Optional templates root directory (defaults to repo templates/)")
    p_list.add_argument("--prompt", help="Optional idea: marks suggested rows only")

    p_new = sub.add_parser(
        "new",
        help="Create a project from a template or kit ID chosen from `list`",
        description=(
            "Create a new project from one entry of `hermes defuzz list`. Run `hermes defuzz list` "
            "first, show the whole list to the user, wait for their choice, then pass it as "
            "--template ID or --kit ID. Without one of them nothing is created: the list is "
            "printed instead. --prompt only supplies the name and answers and marks suggestions."
        ),
    )
    p_new.add_argument("--answers", default="{}", help="Questionnaire answers as a JSON object string")
    p_new.add_argument("--name", help="Project name (overrides the prompt name)")
    p_new.add_argument("--prompt", help="Project idea: gives the name and marks suggested rows only")
    p_new.add_argument("--option", action="append", default=[], metavar="KEY=CHOICE", help="Template default option; repeat for different keys")
    # Not an argparse mutually-exclusive group: giving both is refused with one plain line.
    p_new.add_argument("--template", dest="template_id", help="Template ID from `hermes defuzz list` (or --kit)")
    p_new.add_argument("--kit", dest="kit_id", help="Kit ID from `hermes defuzz list` (or --template)")
    p_new.add_argument("--yes", action="store_true", help="Create the chosen project; never picks a type for you")
    p_new.add_argument("--dest-root", "--root", dest="dest_root", help="Projects folder override for this command")
    p_new.add_argument("--timeout", dest="timeout_s", type=float, default=300.0, help="Overall timeout in seconds")
    p_new.add_argument("--templates-root", dest="templates_root", help="Optional templates root directory (defaults to repo templates/)")

    p_lint = sub.add_parser("lint", help="Run whole-project lint across detected languages")
    p_lint.add_argument("project", help="Path to the project root to lint")
    p_lint.add_argument("--mode", choices=("pre", "post", "both"), default="both", help="Lint mode: pre, post, or both (default: both)")
    p_lint.add_argument("--json", dest="as_json", action="store_true", help="Print full lint result as JSON")

    p_setup = sub.add_parser("setup-tools", help="Inspect or install mandatory user-space lint tools and SDKs")
    p_setup.add_argument("--yes", action="store_true", help="Confirm downloading and installing missing tools")
    p_setup.add_argument("--status", action="store_true", help="Print current tool installation status")
    p_setup.add_argument("--plan", action="store_true", help="Print the download and post-install plan")

    _setup_tools_subparser(sub)
    _setup_folder_subparser(sub)


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[str]], *, pad_last: bool = True) -> None:
    widths = [len(h) for h in headers]
    for r in rows:
        for idx, col in enumerate(r):
            if len(col) > widths[idx]:
                widths[idx] = len(col)
    if pad_last:
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    else:
        fmt = "  ".join(f"{{:<{w}}}" for w in widths[:-1]) + "  {}"
    print(fmt.format(*headers))
    for r in rows:
        print(fmt.format(*r))


def _print_proposal_dry_run(proposal: Proposal) -> None:
    """Print the proposed directory tree per repository and the dry-run re-run instruction."""
    for plan in proposal.repos:
        print(f"Proposed repository: {plan.dest.name} -> {plan.dest}")
        for entry in plan.tree:
            print(f"  {entry}")
    if getattr(proposal, "folder_note", ""):
        print(proposal.folder_note)
    print("Re-run with --yes to create.")


def _print_kit_proposal_dry_run(proposal: Any) -> None:
    """Print the proposed kit id, destination, folder tree, and dry-run re-run instruction."""
    print(f"Proposed kit: {proposal.kit_id} -> {proposal.dest}")
    for entry in proposal.tree:
        print(f"  {entry}")
    if getattr(proposal, "folder_note", ""):
        print(proposal.folder_note)
    print("Re-run with --yes to create.")


KIT_SUMMARY_MAX = 300
KIT_MESSAGE_MAX = 600
KIT_ID_SHOWN_MAX = catalog_list.ID_MAX
KITS_SHOWN_MAX = catalog_list.MAX_KITS
KITS_UNREADABLE_LINE = "Project kits are unavailable: the kit list reply could not be read."


def _handle_kits_subcommand(ns: argparse.Namespace) -> int:
    """List available project kits from the componentize bridge, or print an unavailable notice.

    Everything here comes from the companion plugin: the table and the notice print each
    field as one escaped, capped line; --json keeps the data and emits it ASCII-only.
    """
    as_json = bool(getattr(ns, "as_json", False))
    try:
        res = componentize_bridge.kit_list()
        _infos, notice, status_val = parse_kit_list(res)
    except RecursionError:  # deeply nested reply (componentize_bridge._invoke_kit json.loads)
        res, notice, status_val = None, KITS_UNREADABLE_LINE, "error"
    raw_data = res.get("data") if isinstance(res, dict) else None
    kits_list: List[Any] = (
        list(raw_data["kits"])
        if isinstance(raw_data, dict) and isinstance(raw_data.get("kits"), list)
        else []
    )

    kits_list = [
        {**k, "coming_soon": True, "selectable": False}
        if isinstance(k, dict) and catalog_list.coming_soon_message("kit", k.get("id")) else k
        for k in kits_list
    ]
    if as_json:
        payload = {"kits": kits_list if status_val == "ok" else [], "notice": notice}
        try:
            print(json.dumps(payload, indent=2, ensure_ascii=True))
        except (RecursionError, TypeError, ValueError):
            print(json.dumps({"kits": [], "notice": KITS_UNREADABLE_LINE}, indent=2, ensure_ascii=True))
        return 0

    if status_val == "ok":
        headers = ("ID", "SUMMARY")
        rows = [
            (catalog_list.clean_field(k.get("id", ""), KIT_ID_SHOWN_MAX),
             catalog_list.clean_field("Coming soon" if k.get("coming_soon") else k.get("summary", ""), KIT_SUMMARY_MAX))
            for k in kits_list
            if isinstance(k, dict)
        ]
        _print_table(headers, rows[:KITS_SHOWN_MAX], pad_last=False)
        if len(rows) > KITS_SHOWN_MAX:
            print(f"{len(rows) - KITS_SHOWN_MAX} more kits not shown.")
        return 0

    line = f"Project kits are unavailable: {notice}" if status_val == "unavailable" else notice
    print(catalog_list.clean_field(line, KIT_MESSAGE_MAX))
    return 0


KITS_LIST_TIMEOUT_S = 20.0
"""Budget for the kit catalogue call behind `list` and `new`, so the list never hangs; 20 s covers a cold companion start on a loaded machine (5 s often timed out there)."""

NOTHING_CREATED = "Nothing was created. Run again with --template ID or --kit ID."
CHOICE_PROMPT = "Type a number or an ID (Enter to cancel): "

@dataclasses.dataclass
class _Catalog:
    entries: List[Dict[str, Any]]
    specs: List[Any]
    kits: List[Any]
    kits_ok: bool
    notice: str


def _load_kits() -> tuple:
    """(kit infos, status, notice) from the companion, bounded by KITS_LIST_TIMEOUT_S; never raises."""
    global _KITS_SKIPPED
    try:
        res = parse_kit_list_detailed(componentize_bridge.kit_list(timeout=KITS_LIST_TIMEOUT_S))
    except Exception:  # noqa: BLE001 - a broken companion only hides the kits
        return [], "error", ""
    _KITS_SKIPPED = res.skipped
    return list(res.infos), str(res.status or "error"), str(res.notice or "")


_KITS_SKIPPED = 0
"""Entries the last _load_kits call skipped as malformed (read by _load_catalog)."""


BOTH_IDS_LINE = "Give either --template ID or --kit ID, not both."
SUGGEST_PROMPT_CAP = MAX_PROMPT_CHARS  # characters of a typed idea read for suggestions (the parser's cap)
PROMPT_CUT_LINE = "Your idea was cut at {n} characters to mark suggestions."


def _load_catalog(templates_root: Optional[str]) -> _Catalog:
    """The whole pick-list: templates from the template loader, kits from the companion."""
    specs, _errors = load_templates_lenient(templates_root)
    global _KITS_SKIPPED
    _KITS_SKIPPED = 0
    kits, status, notice = _load_kits()
    entries, dropped = catalog_list.build_catalog_counted(specs, kits)
    notice_line = catalog_list.kits_notice_line(
        status, notice, _KITS_SKIPPED + dropped["kit"], templates_skipped=dropped["template"]
    )
    return _Catalog(entries, list(specs), kits, status == "ok", notice_line)


def _suggestions(catalog: _Catalog, prompt: Optional[str], given_answers: Dict[str, Any]) -> List[str]:
    """Entries a typed idea points at (at most three); any error means no suggestions."""
    if not prompt or not str(prompt).strip():
        return []
    prompt = str(prompt)[:SUGGEST_PROMPT_CAP]  # a huge idea only slows matching; marks need little text
    try:
        from .prompt_parse import explicit_code_from, parse_deterministic

        parsed = parse_deterministic(str(prompt))
        if getattr(parsed, "not_a_project_request", False):
            return []  # same as the dashboard match route: prose, not a project idea
        answers: Dict[str, Any] = {}
        for key, value in {**parsed.answers, **given_answers}.items():
            try:
                answers[key] = validate_answer(key, value)
            except (ValueError, KeyError, TypeError):
                continue
        explicit_code = explicit_code_from(parsed, answers)
        template_matches = matcher.best_matches(
            [s for s in catalog.specs if not catalog_list.coming_soon_message("template", s.id)],
            answers, prompt=str(prompt), explicit_code=explicit_code
        )
        kit_matches = matcher.match_kits([k for k in catalog.kits if not catalog_list.coming_soon_message("kit", k.id)], str(prompt), answers)
        preferred, _best = matcher.choose_catalog_entry(
            template_matches, kit_matches, answers, explicit_code=explicit_code
        )
        return catalog_list.suggested_ids(catalog.entries, template_matches, kit_matches, preferred)
    except Exception:  # noqa: BLE001 - suggestions are optional decoration
        return []


def _shown_id(value: str) -> str:
    """An id as one safe display line: control, format and line-break characters escaped."""
    out = []
    for ch in str(value):
        if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}")
        else:
            out.append(ch)
    return "".join(out)


def _unknown_id_line(given_id: str) -> str:
    return f"No template or kit has the id '{_shown_id(given_id)}'. Run `hermes defuzz list` to see the ids."


def _wrong_kind_line(given_id: str, actual_kind: str) -> str:
    shown = _shown_id(given_id)
    other = "template" if actual_kind == "kit" else "kit"
    return f"'{shown}' is a {actual_kind}, not a {other}: use --{actual_kind} {shown}."


def _check_explicit_id(template_id: Optional[str], kit_id: Optional[str], templates_root: Optional[str]) -> int:
    """0 when the given id can be tried; else print one line and return 2 (nothing created)."""
    for kind, ident in (("template", template_id), ("kit", kit_id)):
        refusal = catalog_list.coming_soon_message(kind, ident)
        if refusal:
            print(refusal, file=sys.stderr)
            return 2
    specs, _errors = load_templates_lenient(templates_root)
    template_ids = {s.id for s in specs}
    if template_id:
        if template_id in template_ids:
            return 0
        kits, status, _notice = _load_kits()
        if status == "ok" and template_id in {k.id for k in kits}:
            print(_wrong_kind_line(template_id, "kit"), file=sys.stderr)
        else:
            print(_unknown_id_line(template_id), file=sys.stderr)
        return 2
    kits, status, _notice = _load_kits()
    if status == "ok" and kit_id in {k.id for k in kits}:
        return 0
    if kit_id in template_ids:
        print(_wrong_kind_line(str(kit_id), "template"), file=sys.stderr)
        return 2
    if status == "ok":
        print(_unknown_id_line(str(kit_id)), file=sys.stderr)
        return 2
    return 0  # kits unavailable: the kit flow says so and how to get them


def _can_ask_for_choice(yes: bool) -> bool:
    """Ask only on an interactive terminal (stdin and stdout) and never with --yes."""
    if yes:
        return False
    for stream in (sys.stdin, sys.stdout):
        isatty = getattr(stream, "isatty", None)
        try:
            if not callable(isatty) or not isatty():
                return False
        except (OSError, ValueError):
            return False
    return True


def _ask_for_choice(entries: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Read one typed number or id; empty, end of input or no match -> None."""
    try:
        typed = input(CHOICE_PROMPT)
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return catalog_list.find_entry(entries, typed)


def _handle_list_subcommand(ns: argparse.Namespace) -> int:
    """Print the whole pick-list (templates and kits), or its JSON form."""
    catalog = _load_catalog(getattr(ns, "templates_root", None))
    prompt = getattr(ns, "prompt", None)
    suggested = _suggestions(catalog, prompt, {})
    if getattr(ns, "as_json", False):
        print(json.dumps(catalog_list.to_json(catalog.entries, suggested=suggested, notice=catalog.notice), indent=2))
    else:
        print(catalog_list.render_text(catalog.entries, suggested=suggested, notice=catalog.notice), end="")
        if isinstance(prompt, str) and len(prompt) > SUGGEST_PROMPT_CAP:
            print(PROMPT_CUT_LINE.format(n=SUGGEST_PROMPT_CAP))
    return 0


def _print_created_repos(repos: Sequence[Dict[str, Any]]) -> None:
    for repo in repos:
        print(repo["path"])
        if repo.get("registration") == "skipped":
            print(f"Registration skipped for {repo['path']}: {repo['registration_reason']}", file=sys.stderr)
        elif repo.get("registration") == "failed":
            from .desktop_registration import failure_notice
            print(failure_notice(repo), file=sys.stderr)


def _handle_templates_subcommand(ns: argparse.Namespace) -> int:
    """List valid templates as a table and report any lenient-load errors."""
    specs, errors = load_templates_lenient(getattr(ns, "templates_root", None))
    headers = ("ID", "NAME", "KIND/LAYOUT/LANGUAGES", "NEEDS")
    rows = [
        (s.id, s.name, f"{s.kind}/{s.layout}/{','.join(s.languages)}", ",".join(s.needs) if s.needs else "-")
        for s in specs
    ]
    _print_table(headers, rows, pad_last=True)
    if errors:
        print("\nErrors:")
        for err in errors:
            print(f"  - {err}")
    return 0


def _template_answers(spec: Any) -> Dict[str, Any]:
    """Questionnaire answers an explicit template already gives (kind, layout, languages, engine)."""
    kind = getattr(spec, "kind", None)
    engine = getattr(spec, "engine", None)
    raw: Dict[str, Any] = {
        "building": kind,
        "layout": getattr(spec, "layout", None),
        "languages": list(getattr(spec, "languages", None) or ()),
    }
    if engine or kind in ("game", "studio"):
        raw["engine"] = engine or "none"
    out: Dict[str, Any] = {}
    for key, value in raw.items():
        if value in (None, "", []):
            continue
        try:
            out[key] = validate_answer(key, value)
        except ValueError:
            continue  # a value outside the questionnaire's choices is simply not prefilled
    return out


def _run_explicit_template_new(
    template_id: str,
    name: str,
    ask_fn: Callable[[Any, List[str]], Optional[Any]],
    dest_root: Optional[str],
    options: Dict[str, str],
    t_root: Optional[str],
    yes: bool,
    timeout_s: float,
    given_answers: Optional[Dict[str, Any]] = None,
) -> int:
    deadline = time.monotonic() + timeout_s
    try:
        specs = load_templates(t_root)
    except TemplateError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    target_spec = next((s for s in specs if s.id == template_id), None)
    if target_spec is None:
        print(_unknown_id_line(template_id), file=sys.stderr)
        return 2

    rem = deadline - time.monotonic()
    if rem <= 0:
        print("Flow timed out", file=sys.stderr)
        return 3
    try:
        # The chosen template answers the questionnaire; explicit --answers still win.
        question_ids = {q.id for q in QUESTIONS}
        given = {k: v for k, v in (given_answers or {}).items() if k in question_ids}
        initial = {**_template_answers(target_spec), **given}
        norm_answers = run_questionnaire(ask_fn, timeout_s=rem, initial_answers=initial)
    except QuestionnaireTimeout as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    try:
        proposal = propose(target_spec, name, norm_answers, dest_root=dest_root, options=options)
    except ScaffoldError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    rem = deadline - time.monotonic()
    if rem <= 0:
        discard(proposal)
        print("Flow timed out", file=sys.stderr)
        return 3

    if not yes:
        _print_proposal_dry_run(proposal)
        discard(proposal)
        return 0

    accept_ok = False
    keep_staging = False
    try:
        try:
            acc = accept(proposal, register=REGISTER_PROJECT, timeout_s=rem)
            accept_ok = True
        except (ScaffoldError, ScaffoldTimeout) as exc:
            keep_staging = exc.keep_staging
            staging_line = f"Staging preserved at {exc.staging_dir or proposal.staging_dir}"
            # A network failure ends on its "needs an internet connection" line, so print staging first.
            network = getattr(exc, "reason", None) == NETWORK_REQUIRED_REASON
            if keep_staging and network:
                print(staging_line, file=sys.stderr)
            print(str(exc), file=sys.stderr)
            if keep_staging and not network:
                print(staging_line, file=sys.stderr)
            return 3 if isinstance(exc, ScaffoldTimeout) else 1
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 1
    finally:
        if not accept_ok and not keep_staging:
            discard(proposal)

    _print_created_repos(acc.repos)
    return 0


INTERRUPTED_RC = 130  # the conventional exit status after Ctrl-C (128 + SIGINT)


def _print_interrupted_new(exc: BaseException) -> int:
    """One plain line after Ctrl-C during `new`: name a project folder that is already in place."""
    from .scaffolder import _AFTER_MOVE_NOTE

    kept = [str(p) for p in (getattr(exc, "created_dirs", None) or [])]
    if kept:
        print("Stopped. " + _AFTER_MOVE_NOTE.format(path=", ".join(kept)), file=sys.stderr)
    else:
        print("Stopped before the project was finished.", file=sys.stderr)
    return INTERRUPTED_RC


def _handle_new_subcommand(ns: argparse.Namespace, ctx: Any = None) -> int:
    """Execute 'defuzz new': create only the --template or --kit the user chose (dry run unless --yes)."""
    if getattr(ns, "template_id", None) and getattr(ns, "kit_id", None):
        print(BOTH_IDS_LINE, file=sys.stderr)
        return 2
    raw_answers = getattr(ns, "answers", "") or ""
    try:
        parsed_answers = json.loads(raw_answers)
    except Exception as exc:
        print(f"Invalid --answers JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(parsed_answers, dict):
        print("--answers must be a JSON object", file=sys.stderr)
        return 1

    options: Dict[str, str] = {}
    for item in getattr(ns, "option", []) or []:
        key, sep, choice = item.partition("=")
        if not sep or not key.strip() or not choice.strip() or key in options:
            print("--option requires unique KEY=CHOICE entries", file=sys.stderr)
            return 1
        options[key] = choice

    name = str(getattr(ns, "name", "") or "")
    prompt = getattr(ns, "prompt", None)
    if prompt:
        from .prompt_parse import PromptTooLongError, parse_deterministic
        try:
            parsed = parse_deterministic(prompt)
        except PromptTooLongError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        parsed_answers = {**parsed.answers, **parsed_answers}
        name = name or parsed.name or ""

    template_id = getattr(ns, "template_id", None)
    kit_id = getattr(ns, "kit_id", None)
    yes = bool(getattr(ns, "yes", False))
    dest_root = getattr(ns, "dest_root", None)
    timeout_s = float(getattr(ns, "timeout_s", 300.0))
    t_root = getattr(ns, "templates_root", None)

    if not template_id and not kit_id:
        # No explicit choice: show the list; a typed idea only marks suggestions.
        catalog = _load_catalog(t_root)
        suggested = _suggestions(catalog, prompt, parsed_answers)
        print(catalog_list.render_text(catalog.entries, suggested=suggested, notice=catalog.notice), end="")
        picked = _ask_for_choice(catalog.entries) if _can_ask_for_choice(yes) else None
        if picked is None:
            print(NOTHING_CREATED)
            return 2
        if picked.get("kind") == "kit":
            kit_id = str(picked["id"])
        else:
            template_id = str(picked["id"])
    else:
        refused = _check_explicit_id(template_id, kit_id, t_root)
        if refused:
            return refused

    if not name:
        print("Supply --name or a project name in --prompt", file=sys.stderr)
        return 1

    if timeout_s <= 0:
        print("Flow timed out", file=sys.stderr)
        return 3

    try:
        resolved_root = workspace_root.ensure_projects_root(
            ctx=ctx,
            cli_root=dest_root,
            allow_cli_relative=True,
        )
    except workspace_root.WorkspaceRootError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    eff_dest_root: Optional[str] = str(resolved_root) if dest_root is not None else None
    if yes:
        state_db_path()  # fail before creating anything when the state folder is not writable

    def _ask(q: Any, _prefill: List[str]) -> Optional[Any]:
        return parsed_answers.get(q.id)

    try:
        if template_id:
            return _run_explicit_template_new(
                template_id, name, _ask, eff_dest_root, options, t_root, yes, timeout_s, given_answers=parsed_answers
            )

        res = run_new_project_flow(
            ask=_ask if parsed_answers else None,
            confirm=lambda _prop: yes,
            name_provider=lambda: name,
            templates_root=t_root,
            register=REGISTER_PROJECT,
            timeout_s=timeout_s,
            dest_root=eff_dest_root,
            initial_answers=parsed_answers,
            prompt=prompt,
            options=options,
            kit_id=kit_id,
        )
    except KeyboardInterrupt as exc:
        return _print_interrupted_new(exc)

    if res.status == "declined" and not yes and getattr(res, "kit_proposal", None) is not None:
        _print_kit_proposal_dry_run(res.kit_proposal)
        return 0
    if res.status == "created" and res.accept is not None:
        _print_created_repos(res.accept.repos)
        if getattr(res, "catalog", "") == "kit":
            print("Automatic file placement: on")
        return 0
    # The kit flow's message can carry the companion's own error text: one escaped, capped line.
    message = catalog_list.clean_field(res.message, KIT_MESSAGE_MAX)
    if res.status in ("no_match", "no_match_handoff"):
        print(message)
        return 2
    if res.status == "timeout":
        print(message, file=sys.stderr)
        return 3
    print(message, file=sys.stderr)
    return 1


def _open_controlling_tty() -> Any:
    """Open the controlling terminal device (/dev/tty on POSIX, CONIN$ on Windows) for reading."""
    return open("CONIN$" if os.name == "nt" else "/dev/tty", "r", encoding="utf-8")


def _handle_trust_subcommand(folder: str, *, declared_only: bool = False) -> Dict[str, Any]:
    """Interactively confirm and trust an adopted project via the controlling terminal."""
    if sys.stdin is None or not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
        raise SafetyError(
            "Refusing non-interactive trust: stdin is not a TTY. "
            "Ask the user to run `hermes defuzz trust <path>` in their own terminal."
        )
    try:
        tty_stream = _open_controlling_tty()
    except OSError as exc:
        raise SafetyError(
            "Refusing non-interactive trust: controlling terminal is unavailable. "
            f"Ask the user to run `hermes defuzz trust <path>` in their own terminal ({exc})."
        ) from exc

    with tty_stream:
        root = assert_safe_root(folder, role="trust_root")
        raw_bytes = _read_rules_bytes_nofollow(root)
        rules_data = _parse_rules_bytes(raw_bytes, root)
        if not _is_valid_adopted_rules(rules_data):
            raise SafetyError(f"Refusing to trust invalid .adopt/rules.json in {root}")
        rules_hash = hashlib.sha256(raw_bytes).hexdigest()
        resolved_root = root.resolve()
        slug = str(rules_data.get("project_slug") or resolved_root.name).strip() or resolved_root.name

        print(f"Resolved root: {resolved_root}")
        print(f"Project slug: {slug}")
        print(f"Rules SHA-256: {rules_hash}")
        print(
            "Placement mode: declared folders only (a new file moves only when a rule names its folder)"
            if declared_only else
            "Placement mode: full (a new file may also be placed by the general fallback rules)"
        )
        for key in ("declared_dirs", "placement_rules", "ignore_patterns", "lfs_patterns"):
            print(f"{key}: {json.dumps(rules_data.get(key) or [])}")
        print(f"Type the project slug {slug!r} to confirm trusting this project: ", end="", flush=True)

        typed = tty_stream.readline().strip()
        if typed != slug:
            raise SafetyError(f"Trust confirmation refused: expected project slug {slug!r}, got {typed!r}.")

    return trust_project(folder, declared_only=declared_only)


def _handle_lint_subcommand(ns: argparse.Namespace) -> int:
    """Execute 'hermes defuzz lint <project> [--mode] [--json]'."""
    project = str(getattr(ns, "project", "") or "")
    mode = str(getattr(ns, "mode", "both") or "both")
    as_json = bool(getattr(ns, "as_json", False))

    proj_path = Path(project).expanduser()
    lock_file = proj_path / "TOOLS.lock"
    if not os.path.islink(lock_file) and lock_file.is_file():
        try:
            loaded_lock = toolchk.load_lock(lock_file)
            toolchk.require(
                list(loaded_lock["tools"].keys()),
                proj_path,
                record_dir=proj_path / ".adopt",
                lock=loaded_lock,
            )
        except toolchk.PreflightError as exc:
            if as_json:
                print(json.dumps(exc.report, indent=2))
            elif exc.code == 4:
                print(exc.report.get("summary", str(exc)), file=sys.stderr)
            return exc.code

    try:
        res = run_lint(project, mode)
    except Exception as exc:  # noqa: BLE001
        if as_json:
            print(json.dumps({"ok": False, "project": project, "mode": mode, "error": str(exc)}, indent=2))
        else:
            print(str(exc), file=sys.stderr)
        return 2

    if not as_json:
        for path in res.get("skipped_generated") or []:
            print(f"Skipped generated: {path}")

    if not res.get("ok", False) or res.get("status") in ("incomplete", "error") or res.get("error"):
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(str(res.get("error") or "Internal lint error"), file=sys.stderr)
            for te in res.get("tool_errors") or []:
                t_msg = te.get("message", "")
                if t_msg:
                    print(f"  - {te.get('tool', '')} ({te.get('status', '')}): {t_msg}", file=sys.stderr)
        return 2

    findings = res.get("findings") or []
    has_errors = any(str(f.get("severity", "")).lower() == "error" for f in findings)

    if as_json:
        print(json.dumps(res, indent=2))
    else:
        if not findings:
            print("No findings.")
        else:
            headers = ("SEVERITY", "TOOL", "FILE:LINE", "RULE", "MESSAGE")
            rows: List[tuple[str, str, str, str, str]] = []
            for f in findings:
                file_str = str(f.get("file", ""))
                line_num = int(f.get("line", 0) or 0)
                loc = f"{file_str}:{line_num}" if line_num > 0 else (file_str or "-")
                rows.append((
                    str(f.get("severity", "")),
                    str(f.get("tool", "")),
                    loc,
                    str(f.get("rule", "")),
                    str(f.get("message", "")),
                ))
            _print_table(headers, rows, pad_last=False)

        for warn in res.get("warnings") or []:
            print(f"warning: {warn}", file=sys.stderr)

    return 1 if has_errors else 0


def _as_dict(obj: Any) -> Dict[str, Any]:
    return dict(obj) if isinstance(obj, dict) else dataclasses.asdict(obj)


def _plan_label(item: Mapping[str, Any]) -> str:
    """What a plan entry installs: the item itself, or only its follow-up package (csharpier
    when a dotnet SDK is already there), named by the package and not by the SDK."""
    name, version = str(item.get("name", "")), str(item.get("version", ""))
    for spec in setup_manifest.ITEMS:
        if spec.name == name and spec.version != version:
            for pkg in spec.packages:
                if pkg.version == version:
                    return f"{pkg.name} {pkg.version} ({pkg.kind.replace('-', ' ')})"
    return f"{name} {version}"


def _handle_setup_tools_subcommand(ns: argparse.Namespace) -> int:
    """Execute 'hermes defuzz setup-tools [--yes] [--status] [--plan]'."""
    if getattr(ns, "status", False):
        st_dict = _as_dict(status())
        if st_dict.get("install_root") is not None:
            st_dict["install_root"] = str(st_dict["install_root"])
        if isinstance(st_dict.get("platform"), tuple):
            st_dict["platform"] = list(st_dict["platform"])
        print(json.dumps(st_dict, indent=2))
        return 0

    if getattr(ns, "plan", False):
        print(json.dumps([{**item, "label": _plan_label(item)} for item in describe_plan()], indent=2))
        return 0

    if not getattr(ns, "yes", False):
        if not bool(getattr(sys.stdin, "isatty", lambda: False)()):
            print(headless_message())
            return 3
        plan = describe_plan()
        try:
            present = {i.name for i in status().items if i.state == "present"}
        except Exception:  # noqa: BLE001 - unknown state: show every item as pending
            present = set()
        pending = [item for item in plan if item.get("name") not in present]
        total_mb = sum(int(item.get("size_mb", 0)) for item in pending)
        print(f"Lint tool setup plan ({len(pending)} to install, ~{total_mb} MB):")
        for item in pending:
            target = item.get("url") or "; ".join(" ".join(c) if isinstance(c, (list, tuple)) else str(c) for c in (item.get("post_install_argv") or item.get("post_install") or [])) or item.get("install_dir")
            print(f"  - {_plan_label(item)} ({item.get('size_mb')} MB) -> {target}")
        done = [str(item.get("name")) for item in plan if item.get("name") in present]
        if done:
            print(f"Already installed: {', '.join(done)}.")
        try:
            ans = input("Proceed? [y/N] ")
        except EOFError:
            ans = ""
        if ans.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1

    def _on_progress(prog: Any) -> None:
        pct = float(getattr(prog, "percent", 0.0))
        print(
            f"[{pct:5.1f}%] {getattr(prog, 'item', '')} ({getattr(prog, 'step', '')}): {getattr(prog, 'message', '')}",
            file=sys.stderr,
        )

    res_dict = _as_dict(run_setup(_on_progress))
    if not res_dict.get("ok", False):
        print(str(res_dict.get("error") or "Setup failed"), file=sys.stderr)
        return 2

    print(json.dumps(res_dict, indent=2))
    return 0


def _extract_tool_and_dir(ns: argparse.Namespace) -> tuple[str, Path]:
    raw_args = getattr(ns, "args", None)
    seq_args: list[Any] = list(raw_args) if isinstance(raw_args, (list, tuple)) else []
    if seq_args:
        if len(seq_args) > 2:
            raise ValueError(f"Expected TOOL [DIR], got {len(seq_args)} positional arguments")
        tool_name = str(seq_args[0] or "")
        raw_dir = seq_args[1] if len(seq_args) == 2 else getattr(ns, "dir", None)
    else:
        tool_name = str(getattr(ns, "tool", "") or "")
        raw_dir = getattr(ns, "dir", None)
    proj_root = _lexical_abs(raw_dir) if raw_dir else Path.cwd().resolve()
    return tool_name, proj_root


def _handle_tools_subcommand(ns: argparse.Namespace) -> int:
    """Execute 'hermes defuzz tools init|status|accept|reason|snooze|doctor'."""
    action = getattr(ns, "tools_action", None)
    if action == "doctor":
        from . import tool_doctor

        paths = tool_doctor.registered_project_paths()
        if getattr(ns, "as_json", False):
            print(json.dumps(tool_doctor.doctor_report(paths), indent=2))
        else:
            for line in tool_doctor.doctor_lines(paths):
                print(line)
        return 0

    raw_dir = getattr(ns, "dir", None)
    proj_root = _lexical_abs(raw_dir) if raw_dir else Path.cwd().resolve()

    if action == "init":
        proj_root = assert_safe_root(proj_root, role="tools_init_root")
        event = str(getattr(ns, "event", None) or "adoption")
        try:
            summary = tool_seed.seed_lock(proj_root, event=event)
        except toolchk.PreflightError as exc:
            print(exc.report.get("summary", str(exc)), file=sys.stderr)
            return exc.code
        print(json.dumps(summary, indent=2))
        return 0

    if action == "status":
        as_json = bool(getattr(ns, "as_json", False))
        try:
            report = tool_seed.status(proj_root)
        except toolchk.PreflightError as exc:
            if as_json:
                print(json.dumps(exc.report, indent=2))
            else:
                print(exc.report.get("summary", str(exc)), file=sys.stderr)
            return exc.code

        if as_json:
            print(json.dumps(report, indent=2))
        else:
            if report.get("text"):
                print(report["text"])
            print(report["summary"])

        if report.get("ok"):
            return 0
        if report.get("probe_failed") and not report.get("blocked"):
            return 3
        return 2

    if action in ("accept", "reason"):
        try:
            tool_name, proj_root = _extract_tool_and_dir(ns)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        proj_root = assert_safe_root(proj_root, role=f"tools_{action}_root")
        reason = str(getattr(ns, "reason", "") or "")
        try:
            from .tool_guard import edit_lock
            row = edit_lock(proj_root, tool_name, reason, action=action)
        except toolchk.PreflightError as exc:
            print(exc.report.get("summary", str(exc)), file=sys.stderr)
            return exc.code
        except (ValueError, KeyError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            if action == "accept":
                print(str(exc), file=sys.stderr)
                return 3
            raise
        print(json.dumps(row, indent=2))
        return 0

    if action == "snooze":
        try:
            tool_name, proj_root = _extract_tool_and_dir(ns)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        proj_root = assert_safe_root(proj_root, role="tools_snooze_root")
        raw_days = getattr(ns, "days", 0)
        days = int(raw_days) if raw_days is not None else 0
        try:
            res = tool_seed.snooze(proj_root, tool_name, days)
        except (ValueError, KeyError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(json.dumps(res, indent=2))
        return 0

    print("Specify a tools action: init, status, accept, reason, or snooze", file=sys.stderr)
    return 2


def _audit_home() -> Optional[str]:
    """Audited profile path, used only to shorten paths in `audit --summary`; None hides all paths."""
    try:
        from hermes_constants import get_hermes_home
        return str(Path(get_hermes_home()).absolute())
    except Exception:  # noqa: BLE001 - without a home the summary simply shows no paths
        return None


def _setup_folder_subparser(sub: Any) -> None:
    p_folder = sub.add_parser(
        "folder",
        help="Show or change the folder where new projects are created",
    )
    p_folder.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Print the projects folder status as JSON",
    )
    folder_sub = p_folder.add_subparsers(dest="folder_action", metavar="[set <path>]")
    p_set = folder_sub.add_parser(
        "set",
        help="Save the folder where new projects are created (terminal only)",
    )
    p_set.add_argument("path", help="Folder path where new projects will be created")


def _handle_folder_subcommand(ns: argparse.Namespace, ctx: Any = None) -> int:
    """Show or update the projects folder setting."""
    action = getattr(ns, "folder_action", None)
    if action == "set":
        if not workspace_root.is_interactive_terminal():
            print(
                "Run `hermes defuzz folder set <path>` in your own terminal so you can confirm "
                "the folder choice. Nothing was changed.",
                file=sys.stderr,
            )
            return 1
        raw_path = str(getattr(ns, "path", "") or "")
        try:
            eff_home = workspace_root.default_projects_root().parent
            expanded = workspace_root._expand_tilde(raw_path.strip(), eff_home)
            was_relative = bool(raw_path.strip()) and not os.path.isabs(expanded)
            validated = workspace_root.validate_projects_root(
                raw_path,
                allow_relative=True,
                source_label="projects folder",
                ctx=ctx,
            )
            if was_relative:
                print(f"Resolved relative path to {validated}.", flush=True)
            saved = workspace_root.set_projects_root(
                validated,
                ctx=ctx,
                allow_relative=False,
            )
        except workspace_root.WorkspaceRootError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"Projects folder set to {saved} (source: saved setting).")
        print("Existing projects stay where they are; only new projects will be created in this folder.")
        return 0

    res = workspace_root.resolve_projects_root(ctx=ctx)
    default_dir = workspace_root.default_projects_root()
    as_json = bool(getattr(ns, "as_json", False))
    is_valid = res.path is not None or res.source == "unset"
    if as_json:
        print(
            json.dumps(
                {
                    "path": str(res.path) if res.path is not None else None,
                    "source": res.source,
                    "valid": is_valid,
                    "default_path": str(default_dir),
                    "message": res.message,
                },
                indent=2,
            )
        )
        return 0 if is_valid else 1

    if res.path is not None:
        source_label = (
            "saved setting"
            if res.source == "setting"
            else f"environment variable {workspace_root.ENV_VAR}"
        )
        print(f"Projects folder: {res.path} (source: {source_label})")
        return 0

    if res.source == "unset":
        print(f"Projects folder: not chosen yet (default suggestion: {default_dir})")
        print("Run `hermes defuzz folder set ~/Tools` in your terminal to choose where new projects go.")
        return 0

    print(f"Projects folder ({res.source}) is invalid: {res.message}", file=sys.stderr)
    return 1


DEBUG_ENV_VAR = "DEFUZZ_DEBUG"


def _yaml_command(ns: argparse.Namespace) -> Optional[str]:
    """The command name when *ns* runs a command that parses YAML, else None."""
    subcmd = getattr(ns, "defuzz_subcommand", None)
    if subcmd in ("audit", "templates", "list"):
        return subcmd
    if subcmd == "new" and not getattr(ns, "kit_id", None):
        return "new"
    if subcmd == "folder" and getattr(ns, "folder_action", None) == "set":
        return "folder set"
    return None


def _missing_yaml_message(ns: argparse.Namespace) -> Optional[str]:
    """One plain line naming PyYAML when the command needs it and it is not installed."""
    command = _yaml_command(ns)
    if command is None:
        return None
    try:
        import yaml  # noqa: F401
    except ImportError:
        return f"defuzz {command} needs the Python package PyYAML, which is not installed."
    return None


def _handle_check_subcommand(ns: argparse.Namespace) -> int:
    """Report structural findings and return the corresponding exit code."""
    # Report-only: an agent home or home folder is a finding here, never a refusal.
    from .structure_check import check_structure, exit_code, format_text

    result = check_structure(ns.path)
    print(json.dumps(result, indent=2) if ns.as_json else format_text(result))
    return exit_code(result)


def _handle_audit_subcommand(ns: argparse.Namespace) -> int:
    """Execute an audit action and print its JSON result or text summary."""
    from .audit_surface import AUDIT_SCOPE_DISCLOSURE, execute_audit
    if ns.audit_action in ("run", "resume"):
        print(AUDIT_SCOPE_DISCLOSURE, file=sys.stderr)
    args: Dict[str, Any] = {
        "action": ns.audit_action,
        "run_id": ns.run_id,
        "root": ns.root,
        "unused_threshold_days": ns.unused_threshold_days,
        "full_home": getattr(ns, "full_home", False),
        "quick": getattr(ns, "quick", False),
        "sessions": getattr(ns, "sessions", False),
    }
    for key in ("max_entries", "max_bytes", "max_file_bytes", "unbounded", "as_of"):
        value = getattr(ns, key, None)
        if value is not None:
            args[key] = value
    try:
        result = execute_audit(args, wait=True)
        report = result.get("report") if isinstance(result, dict) else None
        if getattr(ns, "summary", False) and not getattr(ns, "json", False) and isinstance(report, dict):
            from .audit_summary import render_text, summarize
            print(render_text(summarize(report, home=_audit_home())), end="")
        else:
            print(json.dumps(result, indent=2))
        return 0
    except (ValueError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _handle_copy_subcommand(ns: argparse.Namespace) -> int:
    """Copy a project and report any secret files left behind."""
    include_secret_files = bool(getattr(ns, "include_secret_files", False))
    left_behind: List[str] = []
    dst = copy_tree_nofollow(
        ns.source,
        ns.copy_path,
        staging_root=ns.staging_path,
        include_secret_files=include_secret_files,
        left_behind=left_behind,
        base=ns.copy_path,  # the folder the person chose (links above it are theirs)
    )
    notice = format_secret_files_left_behind(left_behind, ns.source)
    if notice:
        print(notice, file=sys.stderr)
    print(
        json.dumps(
            {
                "ok": True,
                "action": "copy",
                "source": ns.source,
                "copy_root": str(dst),
                "secret_files_left_behind": left_behind,
                "secret_files_left_behind_count": len(left_behind),
                "secret_files_notice": notice or None,
            },
            indent=2,
        )
    )
    return 0


def _handle_place_subcommand(ns: argparse.Namespace) -> int:
    """Execute the requested placement action and print its JSON result."""
    if ns.rule:
        place_args: Dict[str, Any] = {
            "action": "add_rule",
            "project_root": ns.project_root,
            "ext": ns.rule[0],
            "dest_dir": ns.rule[1],
            "lfs": ns.lfs,
        }
    elif ns.undo is not None:
        place_args = {"action": "undo", "project_root": ns.project_root, "count": ns.undo}
    elif ns.sweep:
        place_args = {"action": "sweep", "project_root": ns.project_root}
    elif ns.paths:
        place_args = {"action": "place", "project_root": ns.project_root, "paths": ns.paths}
    else:
        place_args = {"action": "status", "project_root": ns.project_root}
    print(json.dumps(execute_defuzz_place(place_args), indent=2))
    return 0


def _handle_project_subcommand(ns: argparse.Namespace, subcmd: str, ctx: Any = None) -> int:
    """Run a scan, rules proposal, apply, or combined project operation."""
    action_map = {"scan": "scan", "rules": "propose_rules", "apply": "apply", "run": "run"}
    if subcmd in ("apply", "run"):
        state_db_path()  # fail before copying when the state folder is not writable
    res = execute_defuzz_project(
        {
            "action": action_map[subcmd],
            "copy_path": ns.folder,
            "source_path": getattr(ns, "source_path", None),
            "staging_path": getattr(ns, "staging_path", None),
            "inventory_path": getattr(ns, "inventory_path", None),
            "rules_path": getattr(ns, "rules_path", None),
            "report_path": getattr(ns, "report_path", None),
            "use_fallback_rules": getattr(ns, "use_fallback_rules", False),
            "include_secret_files": getattr(ns, "include_secret_files", False),
        },
        ctx=ctx,
    )
    if subcmd == "run" and res.get("secret_files_notice"):
        print(res["secret_files_notice"], file=sys.stderr)
    print(json.dumps(res, indent=2))
    return 0


def handle_defuzz_cli(ns: argparse.Namespace, ctx: Any = None) -> int:
    """Execute parsed CLI namespace and print JSON summary to stdout."""
    subcmd = getattr(ns, "defuzz_subcommand", None)
    missing = _missing_yaml_message(ns)
    if missing:
        print(missing, file=sys.stderr)
        return 1
    try:
        if subcmd == "check":
            return _handle_check_subcommand(ns)
        if subcmd == "audit":
            return _handle_audit_subcommand(ns)
        if subcmd == "templates":
            return _handle_templates_subcommand(ns)
        if subcmd == "kits":
            return _handle_kits_subcommand(ns)
        if subcmd == "list":
            return _handle_list_subcommand(ns)
        if subcmd == "new":
            return _handle_new_subcommand(ns, ctx=ctx)
        if subcmd == "folder":
            return _handle_folder_subcommand(ns, ctx=ctx)
        if subcmd == "lint":
            return _handle_lint_subcommand(ns)
        if subcmd == "setup-tools":
            return _handle_setup_tools_subcommand(ns)
        if subcmd == "tools":
            return _handle_tools_subcommand(ns)
        if subcmd == "copy":
            return _handle_copy_subcommand(ns)
        if subcmd in ("scan", "rules", "apply", "run"):
            return _handle_project_subcommand(ns, subcmd, ctx=ctx)
        if subcmd == "trust":
            print(json.dumps(_handle_trust_subcommand(ns.folder, declared_only=bool(getattr(ns, "declared_only", False))), indent=2))
            return 0
        if subcmd == "place":
            return _handle_place_subcommand(ns)
        print(json.dumps({"ok": False, "error": "Specify a subcommand: scan, copy, rules, apply, run, place, templates, list, new, folder, lint, or setup-tools"}))
        return 2
    except (GitUnavailableError, StateDirNotWritable, workspace_root.WorkspaceRootError) as exc:
        print(f"defuzz {subcmd}: {exc}", file=sys.stderr)
        return 1
    except SafetyError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - a traceback is never the user-facing message
        if os.environ.get(DEBUG_ENV_VAR):
            raise
        reason = " ".join(str(exc).split()) or type(exc).__name__
        print(
            f"defuzz {subcmd}: {reason} ({type(exc).__name__}; set {DEBUG_ENV_VAR}=1 to see the traceback)",
            file=sys.stderr,
        )
        return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="defuzz", description="Project Defuzz CLI (copy-only workspace organizer)")
    setup_defuzz_cli(parser)
    ns, extras = parser.parse_known_args(argv)
    if extras:
        if getattr(ns, "defuzz_subcommand", None) == "tools" and getattr(ns, "tools_action", None) in (
            "accept",
            "reason",
            "snooze",
        ):
            cur = list(getattr(ns, "args", None) or [])
            cur.extend(extras)
            ns.args = cur
        else:
            parser.error(f"unrecognized arguments: {' '.join(extras)}")
    return handle_defuzz_cli(ns)


if __name__ == "__main__":
    raise SystemExit(main())
