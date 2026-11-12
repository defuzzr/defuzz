"""Build plain-language template adaptation hand-off payloads for Hermes."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Dict, Optional

from .matcher import Match
from .templates import templates_root as default_templates_root


def _format_answer_value(val: Any) -> str:
    """Format a single answer value (str or list[str]) as plain text."""
    if isinstance(val, (list, tuple)):
        return ", ".join(str(x) for x in val) if val else "(none)"
    return str(val) if val is not None and val != "" else "(none)"


def build_handoff(
    answers: Mapping[str, Any],
    closest: Optional[Match] = None,
    *,
    templates_root: Optional[os.PathLike[str] | str] = None,
) -> Dict[str, Any]:
    """Build a plain-language hand-off payload for a Hermes session to adapt or draft a template."""
    root_path = Path(templates_root) if templates_root is not None else default_templates_root()
    answers_dict: Dict[str, Any] = dict(answers)
    building = str(answers_dict.get("building") or "project").strip() or "project"
    title = f"Adapt template for {building}"

    lines = [
        f"No existing project template matched the requested setup for '{building}'.",
        "",
        "Questionnaire answers:",
    ]
    for key in ("building", "layout", "languages", "engine"):
        if key in answers_dict:
            lines.append(f"- {key}: {_format_answer_value(answers_dict[key])}")
    for key, val in sorted(answers_dict.items()):
        if key not in {"building", "layout", "languages", "engine"}:
            lines.append(f"- {key}: {_format_answer_value(val)}")

    lines.append("")
    if closest is not None:
        tmpl = closest.template
        reasons_str = "; ".join(closest.reasons) if closest.reasons else "highest ranked candidate"
        if closest.score <= 0:
            fit_line = f"Nearest available template (poor fit): {reasons_str} (score {closest.score})."
        else:
            fit_line = f"Why it is close: {reasons_str} (score {closest.score})."
        lines.extend(
            [
                f"Closest template folder: {tmpl.id} ({tmpl.root})",
                fit_line,
            ]
        )
        request = (
            f"Please adapt '{tmpl.id}' into a new template folder under templates/ "
            f"({root_path}) "
        )
    else:
        lines.append("No template is close to these answers.")
        request = f"Please draft a new template folder under templates/ ({root_path}) "

    lines.extend(
        [
            "",
            request + "following the strict template.yaml contract "
            "(id matching the folder name, name, summary, kind, layout, languages, "
            "placeholder, substitute_in, and repos).",
            "",
            "Keep all work local only: do not push or publish anything public.",
        ]
    )

    return {
        "title": title,
        "text": "\n".join(lines),
        "cwd": str(root_path),
        "answers": answers_dict,
    }
