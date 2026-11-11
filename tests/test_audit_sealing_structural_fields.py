"""Structural sealing: closed-enum fields stay readable when ordinary words are tainted.

Synthetic homes only. Noise is applied at the final report seal, after collection, so
measurements do not change; only the serializer's taint view does.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import REPO_ROOT, load_submodule
from tests.test_audit_wired_sections import _audit, _home, _put

# Ordinary words a broad taint set has been seen to contain, plus every token in
# the structural table (added in the test).
NOISE_WORDS = (
    "config", "default", "text", "git", "none", "local", "main", "yes", "no",
    "true", "false", "auto", "off", "on", "user", "home", "linux", "python",
    "verified", "completed",
)

# Positions that may differ under that noise. Each suffix is the key path with
# list indexes removed. The comment names where the user string comes from.
# A structural field is not in this list: its value must be identical in both runs.
USER_DATA_SUFFIXES = (
    # Profile name chosen by the user (the synthetic home's active profile is "default").
    ("active_profile",),
    ("profile", "name"),  # context_load.profile.name, read from the home
    ("unit_id",),  # profile unit id is that name; a project unit id is a path
    ("profile_name",),  # age evaluation copies the profile name
    # Finding identities and source paths: paths, or withheld relative labels
    # taken from the home (folder names, config.yaml, skill paths).
    ("affected_identities",),
    ("source_paths", "path"),
    # Toolset names read from config.yaml platform_toolsets / agent.disabled_toolsets.
    ("enabled_toolsets",),
    ("disabled_toolsets",),
)

# Clock and per-run handles. Not sealing.
_IGNORED_LEAVES = frozenset({
    "as_of", "age_days", "age_seconds", "source_digest", "fingerprint_digest",
    "caller_rules_digest", "caller_templates_digest",
})
WIRED = (
    "home_workdirs", "secret_file_copies", "dead_stores", "profile_duplicates",
    "skill_ledger", "skill_packs", "unattended_exposure", "memory_load", "kanban_residue",
)


def _noise(ev) -> set[str]:
    return set(NOISE_WORDS) | set(ev.structural_tokens())


def _install_noise(ev, redaction, store, noise: set[str]):
    """Make the final report seal see `noise` as taint. Collection does not."""
    original = ev.EvidenceSerializer._tainted
    real = store.serialize_evidence

    def noisy(value):
        if isinstance(value, str) and noise.intersection(redaction.canonical_forms(value)):
            return True
        return original(value)

    def wrapped(value):
        final = isinstance(value, dict) and "write_settings" in value and "findings" in value
        if not final:
            return real(value)
        ev.EvidenceSerializer._tainted = staticmethod(noisy)
        try:
            return real(value)
        finally:
            ev.EvidenceSerializer._tainted = staticmethod(original)

    store.serialize_evidence = wrapped
    return real, original


def _normalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        if {"kind", "hmac", "location"} <= obj.keys():
            return {"__sealed__": obj.get("kind")}
        out = {}
        sealed = []
        for key, value in obj.items():
            if isinstance(key, str) and key.startswith("hmac:"):
                sealed.append(_normalize(value))
            else:
                out[key] = _normalize(value)
        if sealed:
            out["__sealed_keys__"] = sorted(
                sealed, key=lambda item: json.dumps(item, sort_keys=True, default=str))
        return out
    if isinstance(obj, list):
        items = [_normalize(item) for item in obj]
        if items and all(isinstance(item, dict) for item in items):
            items = sorted(items, key=lambda item: json.dumps(item, sort_keys=True, default=str))
        return items
    return obj


def _diff(left: Any, right: Any, path: tuple = ()) -> list[tuple]:
    if type(left) is not type(right):
        return [(path, left, right)]
    if isinstance(left, dict):
        out = []
        for key in set(left) | set(right):
            child = path + (key,)
            if key not in left or key not in right:
                out.append((child, left.get(key, "<missing>"), right.get(key, "<missing>")))
            else:
                out.extend(_diff(left[key], right[key], child))
        return out
    if isinstance(left, list):
        out = []
        if len(left) != len(right):
            out.append((path + ("<len>",), len(left), len(right)))
        for index, (a, b) in enumerate(zip(left, right)):
            out.extend(_diff(a, b, path + (index,)))
        return out
    if left != right:
        return [(path, left, right)]
    return []


def _suffix(path: tuple) -> tuple:
    return tuple(part for part in path if not isinstance(part, int) and part != "<len>")


def _allowed_user_data(path: tuple, left: Any = None, right: Any = None) -> bool:
    suffix = _suffix(path)
    if not suffix:
        return False
    if suffix[-1] in _IGNORED_LEAVES:
        return True
    if suffix[-1] == "report_store_exclusions":
        return True  # this run's audit-store path, not home data
    if any(suffix[i:] == allowed for i, _part in enumerate(suffix) for allowed in USER_DATA_SUFFIXES):
        return True
    return False


def _structural_values(ev, obj: Any, path: tuple = ()) -> list[tuple]:
    if isinstance(obj, dict):
        if {"kind", "hmac", "location"} <= obj.keys():
            return []
        out = []
        for key, value in obj.items():
            shown = "*" if isinstance(key, str) and key.startswith("hmac:") else key
            out.extend(_structural_values(ev, value, path + (shown,)))
        return out
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(_structural_values(ev, item, path))
        return out
    if isinstance(obj, str):
        field = path[-1] if path else None
        if not ev._is_structural_scalar(field, obj, path):
            return []
        # Group by the matching rule so a sealed parent key does not look like a loss.
        keys = path
        best, best_len = path, -1
        for suffix, _allowed in ev._STRUCTURAL_PATH_RULES:
            n = len(suffix)
            if n <= len(keys) and n > best_len and all(
                pat == "*" or pat == key for pat, key in zip(suffix, keys[-n:])
            ):
                best, best_len = suffix, n
        if best_len < 0:
            best = (field,)
        return [(best, obj)]
    return []


def _structural_mismatches(ev, normal: Any, noisy: Any, path: tuple = ()) -> list:
    from collections import Counter
    left = Counter(_structural_values(ev, normal))
    right = Counter(_structural_values(ev, noisy))
    missing = left - right
    return list(missing.elements())[:8]


def _sealed_positions(obj: Any, path: tuple = ()) -> set[tuple]:
    found = set()
    if isinstance(obj, dict):
        if {"kind", "hmac", "location"} <= obj.keys():
            return {path}
        for key, value in obj.items():
            if isinstance(key, str) and key.startswith("hmac:"):
                found.add(path + ("<sealed-key>",))
            found |= _sealed_positions(value, path + (key,))
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            found |= _sealed_positions(item, path + (index,))
    return found


def _sparse_home(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    project = tmp_path / "project"
    project.mkdir(parents=True)
    (project / "main.py").write_text("print(1)\n", encoding="utf-8")
    home.mkdir()
    _put(home, "config.yaml", "model: test\nterminal:\n  backend: local\n")
    return home, project


def _readable_strings(obj: Any, path: tuple = ()) -> list[tuple]:
    if isinstance(obj, dict):
        if {"kind", "hmac", "location"} <= obj.keys():
            return []
        out = []
        for key, value in obj.items():
            shown = "*" if isinstance(key, str) and key.startswith("hmac:") else key
            out.extend(_readable_strings(value, path + (shown,)))
        return out
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(_readable_strings(item, path))
        return out
    if isinstance(obj, str):
        return [(path, obj)]
    return []


def _compare(ev, normal_report: dict, noisy_report: dict, label: str) -> None:
    mismatches = _structural_mismatches(ev, normal_report, noisy_report)
    assert mismatches == [], f"{label} structural fields changed: {mismatches[:8]}"

    from collections import Counter
    missing = Counter(_readable_strings(normal_report)) - Counter(_readable_strings(noisy_report))
    unexpected = [
        (path, value) for path, value in missing.elements()
        if not ev._is_structural_scalar(path[-1] if path else None, value, path)
        and not _allowed_user_data(path)
    ]
    assert unexpected == [], f"{label} unexpected sealed user strings: {unexpected[:8]}"

    for name in WIRED:
        normal_sealed = {_suffix(path) for path in _sealed_positions(normal_report.get(name))}
        noisy_sealed = {_suffix(path) for path in _sealed_positions(noisy_report.get(name))}
        added = noisy_sealed - normal_sealed
        assert not added, f"{label} noise sealed {name}: {list(added)[:6]}"


@pytest.mark.parametrize("builder", ("wired", "sparse"))
def test_noise_does_not_seal_structural_fields(tmp_path: Path, monkeypatch, builder: str) -> None:
    ev = load_submodule("audit.evidence")
    redaction = load_submodule("audit.redaction")
    store = load_submodule("audit.store")
    summary = load_submodule("audit_summary")
    if builder == "wired":
        root = tmp_path / "wired"
        root.mkdir()
        home, project = _home(root)
    else:
        home, project = _sparse_home(tmp_path / "sparse")
    (tmp_path / "n").mkdir()
    (tmp_path / "y").mkdir()

    sessions = builder == "wired"
    root = str(project) if builder == "wired" else None
    audit_args = {"sessions": sessions}
    if root is not None:
        audit_args["root"] = root
    normal = _audit(tmp_path / "n", monkeypatch, home, **audit_args)
    real, original = _install_noise(ev, redaction, store, _noise(ev))
    try:
        noisy = _audit(tmp_path / "y", monkeypatch, home, **audit_args)
    finally:
        store.serialize_evidence = real
        ev.EvidenceSerializer._tainted = staticmethod(original)

    assert normal["status"] == "completed" and noisy["status"] == "completed"
    _compare(ev, normal["report"], noisy["report"], builder)

    plain = summary.summarize(noisy["report"], home=str(home))
    rendered = summary.render_text(plain)
    assert summary.RENDER_FAILED not in rendered
    normal_plain = summary.summarize(normal["report"], home=str(home))
    for left, right in zip(normal_plain["sections"], plain["sections"]):
        assert left["section"] == right["section"]
        assert left["measured"] == right["measured"], left["section"]
        assert left.get("partial") == right.get("partial"), left["section"]
        assert left.get("headline") == right.get("headline"), left["section"]
    # Setting-source wording is the provenance token in the section, still readable,
    # and the summary still names every measured section.
    assert noisy["report"]["write_settings"]["tool_selection"]["source"] in ("config", "default", "could_not_verify")
    assert "from config" in rendered or "Approval" in rendered
    for sec in plain["sections"]:
        if sec["measured"]:
            assert sec["title"] in rendered


def test_bare_source_stays_taint_first_and_settings_source_does_not(tmp_path: Path) -> None:
    ev = load_submodule("audit.evidence")
    redaction = load_submodule("audit.redaction")
    state = redaction.Taint()
    state.observe_value({"api_key": "config"})
    token = redaction._CURRENT.set(state)
    try:
        bare = ev.serialize_evidence({"source": "config", "value": "config", "name": "config"})
        assert isinstance(bare["source"], ev.SealedEvidence)
        assert isinstance(bare["value"], ev.SealedEvidence)
        assert isinstance(bare["name"], ev.SealedEvidence)
        nested = ev.serialize_evidence({
            "settings": {"terminal.backend": {"value": "local", "source": "config"}},
            "tool_selection": {"source": "default"},
            "input_sources": {"memory_char_limit": "config"},
            "char_limits": {"memory": {"limit_source": "config"}},
        })
        assert nested["settings"]["terminal.backend"]["source"] == "config"
        assert nested["settings"]["terminal.backend"]["value"] == "local"
        assert nested["tool_selection"]["source"] == "default"
        assert nested["input_sources"]["memory_char_limit"] == "config"
        assert nested["char_limits"]["memory"]["limit_source"] == "config"
        # A settings value outside the coerced set is still user data.
        other = ev.serialize_evidence({"settings": {"terminal.backend": {"value": "not-a-label", "source": "user-typed"}}})
        row = other["settings"]["terminal.backend"]
        assert isinstance(row["value"], ev.SealedEvidence)
        assert isinstance(row["source"], ev.SealedEvidence)
    finally:
        redaction._CURRENT.reset(token)


@pytest.mark.parametrize("reason", ("no_projects", "input_unknown"))
def test_memory_foreign_technology_reason_is_structural_only_in_its_section(reason: str) -> None:
    ev = load_submodule("audit.evidence")
    redaction = load_submodule("audit.redaction")
    state = redaction.Taint()
    state.observe_value({"api_key": reason})
    token = redaction._CURRENT.set(state)
    try:
        report = ev.serialize_evidence({
            "memory_load": {"foreign_technology_reason": reason},
            "foreign_technology_reason": reason,
            "name": reason,
            "value": reason,
        })
        assert report["memory_load"]["foreign_technology_reason"] == reason
        for key in ("foreign_technology_reason", "name", "value"):
            assert isinstance(report[key], ev.SealedEvidence)
        # Neither an arbitrary value at the structural path nor an absent reason
        # may be reclassified as a reviewed reason code.
        unknown = ev.serialize_evidence({"memory_load": {"foreign_technology_reason": "user-supplied"}})
        assert isinstance(unknown["memory_load"]["foreign_technology_reason"], ev.SealedEvidence)
        empty = ev.serialize_evidence({"memory_load": {"foreign_technology_reason": None}})
        assert empty["memory_load"]["foreign_technology_reason"] is None
    finally:
        redaction._CURRENT.reset(token)


def test_structural_tokens_are_vocabulary_of_their_section() -> None:
    ev = load_submodule("audit.evidence")
    sheets = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((REPO_ROOT / "audit" / "wiring").glob("*.json"))
    }
    section_for_rule = {
        ("settings", "*", "source"): ("unattended_exposure", "write_settings"),
        ("input_sources", "*"): ("memory_load",),
        ("memory_load", "foreign_technology_reason"): ("memory_load",),
        ("files", "kind"): ("memory_load",),
        ("files", "scope"): ("memory_load",),
        ("copies", "scope"): ("secret_file_copies",),
        ("boards", "board"): ("kanban_residue",),
        ("hook_plugins", "hooks"): ("unattended_exposure",),
        ("hook_plugins", "pinned"): ("unattended_exposure",),
        ("files", "file"): ("profile_duplicates",),
    }
    missing = []
    for suffix, allowed in ev._STRUCTURAL_PATH_RULES:
        sections = section_for_rule.get(suffix)
        if not sections:
            continue
        for token in allowed:
            for section in sections:
                sheet = sheets.get(section)
                vocab = set(sheet["vocabulary"]) if sheet else set()
                if token not in vocab and token not in ev.VOCABULARY:
                    missing.append((suffix, section, token))
                elif sheet and token not in vocab and token not in ev.VOCABULARY:
                    missing.append((suffix, section, token))
    assert missing == []
    # Path-rule tokens used in a wired section must be that section's vocabulary.
    # Core-section tokens must be vocabulary words. Pre-existing component/reason
    # sets are not re-checked here; they predate this table.
    path_tokens = {token for _suffix, allowed in ev._STRUCTURAL_PATH_RULES for token in allowed}
    added_fields = (
        "limit_source", "curator_enabled_source", "last_use_source", "project_families",
        "file_kind", "provenance", "secret_kind", "target_store", "approvals_mode",
        "cli_powerful_tools", "unmeasured", "estimator_version", "schema", "contract",
        "parser_policy", "persistence_policy", "ineligible_reason",
    )
    added = path_tokens | {token for name in added_fields for token in ev._STRUCTURAL_FIELD_TOKENS[name]}
    unknown = sorted(token for token in added if token not in ev.VOCABULARY)
    assert unknown == [], unknown
