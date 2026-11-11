"""Tool schemas for the defuzz Hermes plugin."""

from __future__ import annotations

from typing import Any, Dict

DEFUZZ_PROJECT: Dict[str, Any] = {
    "name": "defuzz_project",
    "description": (
        "Adopt and organize a messy project folder strictly on a disjoint COPY. "
        "Actions: 'scan' (read-only inventory of a copy with collapsed junk dirs, classified links, "
        "and redacted secret placeholders), 'propose_rules' (one LLM call via Hermes provider route "
        "returning folder prefix rules), 'apply' (expand rules, write .gitignore/.gitattributes/AGENTS.md "
        "before baseline git commit, verify SHA-256 integrity), or 'run' (end-to-end copy -> scan -> "
        "rules -> apply -> report)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["scan", "propose_rules", "apply", "run", "report"],
                "description": "Operation to perform.",
            },
            "copy_path": {
                "type": "string",
                "description": "Path to the working COPY folder (must be disjoint from source_path and staging_path).",
            },
            "source_path": {
                "type": "string",
                "description": "Optional read-only source folder to copy from (never modified).",
            },
            "staging_path": {
                "type": "string",
                "description": "Optional disjoint staging folder for inventory.json, rules.json, and report.json.",
            },
            "inventory_path": {
                "type": "string",
                "description": "Path to read or write inventory.json (must be outside copy_path during scan).",
            },
            "rules_path": {
                "type": "string",
                "description": "Path to read or write rules.json.",
            },
            "report_path": {
                "type": "string",
                "description": "Optional path to read or write report.json.",
            },
            "use_fallback_rules": {
                "type": "boolean",
                "description": "When true, use deterministic folder rules without calling ctx.llm.",
            },
        },
        "required": ["action", "copy_path"],
    },
}

DEFUZZ_PLACE: Dict[str, Any] = {
    "name": "defuzz_place",
    "description": (
        "Manage mechanical file placement in an adopted project (.adopt/rules.json). "
        "Actions: 'place' (move loose files into declared folders or _inbox/), 'sweep' (route files in "
        "_inbox/ matching current rules), 'add_rule' (add an extension -> folder rule), 'undo' (revert "
        "recent placements from .adopt/place-log.json), or 'status'."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["place", "sweep", "add_rule", "undo", "status"],
                "description": "Placement action to perform.",
            },
            "project_root": {
                "type": "string",
                "description": "Adopted project root directory containing .adopt/rules.json.",
            },
            "paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Relative file paths to place (for action='place').",
            },
            "ext": {
                "type": "string",
                "description": "File extension e.g. '.fbx' (for action='add_rule').",
            },
            "dest_dir": {
                "type": "string",
                "description": "Target relative folder e.g. 'assets/3d' (for action='add_rule').",
            },
            "kind": {
                "type": "string",
                "description": "Short rule identifier e.g. 'assets_3d' (for action='add_rule').",
            },
            "lfs": {
                "type": "boolean",
                "description": "Whether this extension uses Git LFS (for action='add_rule').",
            },
            "count": {
                "type": "integer",
                "description": "Number of recent placements to undo (for action='undo', default 1).",
            },
        },
        "required": ["action", "project_root"],
    },
}
