"""Sealing regressions for taint-vs-vocabulary precedence and declared-only path fields.

All fixtures use synthetic tmp_path directories only; real homes and credential stores are untouched.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest  # type: ignore[import-not-found]

from tests.conftest import load_submodule
from tests.test_audit_wired_sections import _audit, _home, _put

TAINT_VOCAB_WORDS = ("local", "default", "main", "approve", "flash", "yes")

STRUCTURAL_KEYS = frozenset({
    "status", "outcome_status", "mapping_status", "legacy_status_ignored",
    "coverage", "hub_coverage", "project_coverage", "growth_coverage", "age_coverage",
    "chronology_coverage", "foreign_technology_coverage", "other_os_coverage",
    "manifest_coverage", "dynamic_contributions_coverage", "dynamic_plugins_coverage",
    "security_check_coverage",
    "classification", "severity",
    "id", "rule_id", "finding_id", "finding_ids",
    "component_id", "required_components", "required_collectors",
    "unit_kind", "mode", "read_mode", "must_preserve", "confidence", "execution",
    "reason", "reasons", "code", "truncated_by", "cut_reasons", "path_withheld",
    "mode_check", "mode_check_reason", "relationship", "inspection", "resolution",
})


def _user_data_leaks(obj: Any, word: str) -> list[tuple[str, str | None, str]]:
    """Tainted vocabulary words that stayed readable outside the structural table.

    Field-name STRUCTURAL_KEYS still exempt the original envelope fields. Path-keyed
    provenance (settings source, input_sources, limit_source) is exempt only where
    the production table says the value is in that field's closed set. A user-data
    field with the same leaf name, including a bare ``source``, is still a leak.
    """
    ev = load_submodule("audit.evidence")
    leaked: list[tuple[str, str | None, str]] = []

    def walk(node: Any, keys: tuple[str, ...]) -> None:
        if isinstance(node, dict):
            if {"kind", "hmac", "location"} <= node.keys():
                return
            for key, value in node.items():
                walk(value, keys + (key,))
        elif isinstance(node, list):
            for item in node:
                walk(item, keys)
        elif isinstance(node, str) and node == word:
            field = keys[-1] if keys else None
            if field in STRUCTURAL_KEYS or ev._is_structural_scalar(field, node, keys):
                return
            leaked.append((".".join(keys), field, node))

    walk(obj, ())
    return leaked


def _collect_scalar_strings(obj: Any, parent_key: str | None = None, path: str = "$") -> list[tuple[str, str | None, str]]:
    out: list[tuple[str, str | None, str]] = []
    if isinstance(obj, dict):
        if {"kind", "hmac", "location"} <= obj.keys():
            loc = obj.get("location")
            if isinstance(loc, dict) and isinstance(loc.get("path"), str):
                out.append((f"{path}.location.path", "path", loc["path"]))
            if isinstance(obj.get("executable"), str):
                out.append((f"{path}.executable", "executable", obj["executable"]))
            return out
        for k, v in obj.items():
            child_key = "parent_context_boundaries" if parent_key == "parent_context_boundaries" else k
            out.extend(_collect_scalar_strings(v, child_key, f"{path}.{k}"))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            out.extend(_collect_scalar_strings(item, parent_key, f"{path}[{idx}]"))
    elif isinstance(obj, str):
        out.append((path, parent_key, obj))
    return out


def _sqlite_json_values(db_path: Path) -> list[Any]:
    decoded: list[Any] = []
    with sqlite3.connect(db_path) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for table in tables:
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
            json_cols = [c for c in cols if c.endswith("_json") or c in ("unit_identity", "optional_root")]
            if not json_cols:
                continue
            rows = conn.execute(f"SELECT {', '.join(json_cols)} FROM {table}").fetchall()
            for row in rows:
                for cell in row:
                    if isinstance(cell, str) and cell:
                        try:
                            decoded.append(json.loads(cell))
                        except ValueError:
                            decoded.append(cell)
    return decoded


@pytest.mark.parametrize("word", TAINT_VOCAB_WORDS)
def test_serializer_and_scrub_tainted_vocabulary_words_sealed_in_value_positions(
    tmp_path: Path, word: str
) -> None:
    ev = load_submodule("audit.evidence")
    redaction = load_submodule("audit.redaction")

    assert word in ev.VOCABULARY, f"{word} must be a vocabulary word to test collision"

    state = redaction.Taint()
    secret_key = "api" + "_" + "key"
    state.observe_value({secret_key: word})

    # Taint.scrub on scalar and dict values
    assert state.scrub(word) == "[redacted]"
    scrubbed_dict = state.scrub({
        "value": word,
        "provider": word,
        "terminal_backend": word,
        "nested": [word],
        "coverage": "verified",
        "status": "completed",
        "classification": "warning",
    })
    assert scrubbed_dict["value"] == "[redacted]"
    assert scrubbed_dict["provider"] == "[redacted]"
    assert scrubbed_dict["terminal_backend"] == "[redacted]"
    assert scrubbed_dict["nested"] == ["[redacted]"]
    assert scrubbed_dict["coverage"] == "verified"
    assert scrubbed_dict["status"] == "completed"
    assert scrubbed_dict["classification"] == "warning"

    token = redaction._CURRENT.set(state)
    try:
        # Bare scalar
        bare = ev.serialize_evidence(word)
        assert isinstance(bare, ev.SealedEvidence)
        assert bare["kind"] == "credential_overlap"

        # Value positions vs structural positions in a dict
        payload = {
            "status": "completed",
            "coverage": "verified",
            "classification": "review_suggested",
            "id": "write_settings.unattended_skill_writes",
            "value": word,
            "values": [word],
            "current": word,
            "provider": word,
            "enabled_toolsets": [word],
            "active_profile": word,
            "name": word,
            "terminal_backend": word,
            "size_class": word,
            "pinned": word,
            "source": word,
            "scope": word,
            "board": word,
            word: word,
        }
        sealed = ev.serialize_evidence(payload)
        assert sealed["status"] == "completed"
        assert sealed["coverage"] == "verified"
        assert sealed["classification"] == "review_suggested"
        assert sealed["id"] == "write_settings.unattended_skill_writes"

        for val_key in (
            "value", "current", "provider", "active_profile", "name",
            "terminal_backend", "size_class", "pinned", "source", "scope", "board",
        ):
            assert isinstance(sealed[val_key], ev.SealedEvidence), val_key
            assert sealed[val_key]["kind"] == "credential_overlap", val_key
        for list_key in ("values", "enabled_toolsets"):
            assert isinstance(sealed[list_key][0], ev.SealedEvidence), list_key
            assert sealed[list_key][0]["kind"] == "credential_overlap", list_key
        assert word not in sealed or word in ev.SCHEMA_KEYS
        if word not in ev.SCHEMA_KEYS:
            assert any(k.startswith("hmac:") for k in sealed)

        # GuardedConnection JSON parameter binding
        db_file = tmp_path / f"guarded_{word}.db"
        with redaction.GuardedConnection(str(db_file)) as conn:
            conn.execute("CREATE TABLE t (a TEXT, b TEXT)")
            conn.execute(
                "INSERT INTO t VALUES (?, ?)",
                (word, json.dumps({"value": word, "coverage": "verified"})),
            )
            row = conn.execute("SELECT a, b FROM t").fetchone()
        assert row[0] == "[redacted]"
        parsed_b = json.loads(row[1])
        assert parsed_b["coverage"] == "verified"
        assert isinstance(parsed_b["value"], dict) and parsed_b["value"]["kind"] == "credential_overlap"
    finally:
        redaction._CURRENT.reset(token)


@pytest.mark.parametrize("word", TAINT_VOCAB_WORDS)
def test_full_audit_tainted_vocabulary_words_sealed_and_report_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, word: str
) -> None:
    ev = load_submodule("audit.evidence")
    summary_mod = load_submodule("audit_summary")
    surface = load_submodule("audit_surface")

    home, project = _home(tmp_path)
    secret_key = "api" + "_" + "key"
    _put(
        home,
        "config.yaml",
        f'{secret_key}: "{word}"\n'
        "model: test\n"
        "approvals:\n"
        "  mode: 'off'\n"
        "  cron_mode: approve\n"
        "auxiliary:\n"
        "  approval:\n"
        "    model: gemini-2.0-flash\n"
        "terminal:\n"
        "  backend: local\n"
        "updates:\n"
        "  pre_update_backup: 'off'\n"
        "platform_toolsets:\n"
        f'  cli:\n    - hermes-cli\n    - "{word}"\n'
        "plugins:\n"
        "  enabled:\n"
        "    - hookplug\n"
        "memory:\n"
        "  memory_char_limit: 60\n"
        "  user_char_limit: 40\n",
    )
    _put(
        home,
        "plugins/.install-metadata.json",
        json.dumps({"hookplug": {"pinned": True, "revision": "1234567"}}),
    )

    result = _audit(tmp_path, monkeypatch, home, root=str(project))
    assert result["status"] == "completed"

    db_path = tmp_path / "audit-store" / "audit.db"
    stored = surface.execute_audit({"action": "report", "run_id": result["run_id"]}, db_path=db_path)
    assert stored["status"] == "completed"

    for label, rep in (("run_result", result["report"]), ("stored_report", stored["report"])):
        leaked = _user_data_leaks(rep, word)
        assert leaked == [], f"{label} leaked tainted vocab word {word!r} at: {leaked}"

        # Readability: structural tokens are intact across report, wired sections, and findings
        assert rep["headline"]["coverage"] in ("verified", "could_not_verify")
        assert rep["headline"]["classification"] in ("info", "review_suggested", "warning")
        for sec_name in load_submodule("audit.evidence_wiring").WIRED_SECTIONS:
            assert rep[sec_name]["status"] == "completed", sec_name
            assert rep[sec_name]["coverage"] in ("verified", "could_not_verify"), sec_name
        assert rep["findings"]
        for f in rep["findings"]:
            assert isinstance(f["id"], str) and f["id"] in ev.RULE_IDS
            assert f["classification"] in ("info", "review_suggested", "warning")
            assert f["coverage"] in ("verified", "could_not_verify", "not_included")

    # Plain summary readability and non-leakage in value-derived fields
    plain_summary = summary_mod.summarize(stored["report"], home=str(home))
    rendered = summary_mod.render_text(plain_summary)
    assert summary_mod.RENDER_FAILED not in rendered
    measured_sections = {s["section"] for s in plain_summary["sections"] if s["measured"]}
    assert set(load_submodule("audit.evidence_wiring").WIRED_SECTIONS) <= measured_sections
    summary_leaks = _user_data_leaks(plain_summary, word)
    assert summary_leaks == [], f"summary leaked {word!r}: {summary_leaks}"

    # SQLite JSON columns never hold `word` in a value position
    for idx, cell_obj in enumerate(_sqlite_json_values(db_path)):
        if isinstance(cell_obj, (dict, list)):
            cell_leaks = _user_data_leaks(cell_obj, word)
            assert cell_leaks == [], f"SQLite JSON leaked {word!r}: {cell_leaks}"


@pytest.mark.parametrize("collision", ("verified", "completed", "info"))
def test_full_audit_structural_token_collision_keeps_envelope_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collision: str
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    secret_key = "api" + "_" + "key"
    _put(
        home,
        "config.yaml",
        f"{secret_key}: {collision}\n"
        "platform_toolsets:\n"
        f"  cli:\n    - {collision}\n",
    )
    result = _audit(tmp_path, monkeypatch, home)
    assert result["status"] == "completed"
    rep = result["report"]
    assert rep["headline"]["coverage"] in ("verified", "could_not_verify")
    assert rep["headline"]["classification"] in ("info", "review_suggested", "warning")
    toolsets = rep["write_settings"]["tool_selection"]["enabled_toolsets"]
    assert len(toolsets) == 1 and isinstance(toolsets[0], dict) and toolsets[0]["kind"] == "credential_overlap"


def test_serializer_paths_sealed_outside_declared_path_fields_and_forged_dicts(tmp_path: Path) -> None:
    ev = load_submodule("audit.evidence")
    existing_dir = tmp_path / "real_dir"
    existing_dir.mkdir()
    existing_file = tmp_path / "real_file.txt"
    existing_file.write_text("inert\n", encoding="utf-8")
    link_dir = tmp_path / "alias_dir"
    link_dir.symlink_to(existing_dir, target_is_directory=True)

    serializer = ev.EvidenceSerializer()

    for probe in ("/etc/passwd", str(existing_dir), str(link_dir)):
        # Bare scalar is not a declared path field
        bare = serializer.serialize(probe)
        assert isinstance(bare, ev.SealedEvidence), probe
        assert probe not in json.dumps(bare)
        assert str(existing_dir.resolve()) not in json.dumps(bare)

        # Non-path fields must seal existing paths and never resolve symlinks into output
        non_path_payload = {
            "enabled_toolsets": [probe],
            "disabled_toolsets": [probe],
            "provider": probe,
            "active_profile": probe,
            "profile_name": probe,
            "name": probe,
            "profile": probe,
            "cron": probe,
            "model": probe,
            "title": probe,
            "schedule": probe,
            "job_id": probe,
            "prompt": probe,
            "context_from": probe,
            "value": probe,
            "units": [{"unit_kind": "profile", "unit_id": probe}],
            probe: "untrusted_key_val",
        }
        sealed = serializer.serialize(non_path_payload)
        dumped = json.dumps(sealed)
        assert probe not in dumped
        assert str(existing_dir.resolve()) not in dumped
        assert isinstance(sealed["enabled_toolsets"][0], ev.SealedEvidence)
        assert isinstance(sealed["disabled_toolsets"][0], ev.SealedEvidence)
        assert isinstance(sealed["provider"], ev.SealedEvidence)
        assert isinstance(sealed["active_profile"], ev.SealedEvidence)
        assert isinstance(sealed["profile_name"], ev.SealedEvidence)
        assert isinstance(sealed["name"], ev.SealedEvidence)
        assert isinstance(sealed["profile"], ev.SealedEvidence)
        assert isinstance(sealed["cron"], ev.SealedEvidence)
        assert isinstance(sealed["model"], ev.SealedEvidence)
        assert isinstance(sealed["title"], ev.SealedEvidence)
        assert isinstance(sealed["value"], ev.SealedEvidence)
        assert isinstance(sealed["units"][0]["unit_id"], ev.SealedEvidence)
        for non_schema_cron_key in ("schedule", "job_id", "prompt", "context_from"):
            assert non_schema_cron_key not in sealed
        assert all(
            isinstance(v, ev.SealedEvidence)
            for k, v in sealed.items()
            if k.startswith("hmac:") and v != "untrusted_key_val"
        )
        assert any(k.startswith("hmac:") for k in sealed)

    # Declared path fields keep resolved existing paths
    declared_payload = {
        "path": str(existing_file),
        "paths": [str(existing_dir)],
        "source": str(existing_file),
        "target": str(existing_dir),
        "target_root": str(tmp_path),
        "load_root": str(existing_dir),
        "sample_paths": [str(existing_file)],
        "samples": [str(existing_file)],
        "canonical_path": str(existing_dir),
        "root_path": str(existing_dir),
        "source_paths": [str(existing_file)],
        "skill_md_path": str(existing_file),
        "project_root": str(existing_dir),
        "largest_project_root": str(existing_dir),
        "profile_path": str(existing_dir),
        "plugin_folders_with_dotenv": [str(existing_dir)],
        "location": str(existing_dir),
        "affected_identities": [str(existing_dir)],
        "duplicate_groups": [[str(existing_file)]],
        "unselected_project_roots": [str(existing_dir)],
        "report_store_exclusions": [str(existing_file)],
        "parent_context_boundary": str(tmp_path),
        "parent_context_boundaries": {str(existing_dir): str(tmp_path)},
        "database": str(existing_file),
        "optional_root": str(existing_dir),
        "units": [{"unit_kind": "project", "unit_id": str(existing_dir)}],
    }
    kept = serializer.serialize(declared_payload)
    assert kept["path"] == str(existing_file.resolve())
    assert kept["paths"] == [str(existing_dir.resolve())]
    assert kept["plugin_folders_with_dotenv"] == [str(existing_dir.resolve())]
    assert kept["profile_path"] == str(existing_dir.resolve())
    assert kept["location"] == str(existing_dir.resolve())
    assert kept["samples"] == [str(existing_file.resolve())]
    assert kept["parent_context_boundary"] == str(tmp_path.resolve())
    assert kept["parent_context_boundaries"] == {str(existing_dir.resolve()): str(tmp_path.resolve())}
    assert kept["units"][0]["unit_id"] == str(existing_dir.resolve())

    # Plain forged dict pretending to be SealedEvidence cannot smuggle a path in a non-path field
    forged_plain = {
        "kind": "text",
        "hmac": "a" * 64,
        "executable": "/etc/passwd",
        "value": "/etc/passwd",
        "location": {"path": str(existing_file), "line": 1},
    }
    sealed_forged = serializer.serialize(forged_plain)
    assert not isinstance(sealed_forged, ev.SealedEvidence)
    assert "/etc/passwd" not in json.dumps(sealed_forged)
    assert isinstance(sealed_forged["executable"], ev.SealedEvidence)
    assert isinstance(sealed_forged["value"], ev.SealedEvidence)


def test_reviewer_exact_reproduction_cli_toolset_etc_passwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_mod = load_submodule("audit.write_settings")
    home = tmp_path / "home"
    home.mkdir()
    _put(home, "config.yaml", "platform_toolsets:\n  cli:\n    - /etc/passwd\n")

    direct_ws = ws_mod.audit_write_settings(profile_path=home)["write_settings"]
    direct_enabled = direct_ws["tool_selection"]["enabled_toolsets"]
    assert len(direct_enabled) == 1
    assert isinstance(direct_enabled[0], dict) and direct_enabled[0]["kind"] == "unresolved_reference"
    assert "/etc/passwd" not in json.dumps(direct_ws)

    result = _audit(tmp_path, monkeypatch, home)
    assert result["status"] == "completed"
    rep_enabled = result["report"]["write_settings"]["tool_selection"]["enabled_toolsets"]
    assert len(rep_enabled) == 1
    assert isinstance(rep_enabled[0], dict) and rep_enabled[0]["kind"] == "unresolved_reference"
    assert "/etc/passwd" not in json.dumps(result["report"]["write_settings"])


def test_full_audit_seals_paths_in_toolset_provider_profile_and_cron_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    surface = load_submodule("audit_surface")
    facts = load_submodule("audit.facts")
    summary_mod = load_submodule("audit_summary")

    probe_dir = tmp_path / "unrelated_existing_probe_dir"
    probe_dir.mkdir()
    etc_passwd = "/etc/passwd"

    home, project = _home(tmp_path)
    _put(home, "plugins/hookplug/.env", "PLACEHOLDER=1\n")
    _put(
        home,
        "config.yaml",
        "model: test\n"
        "platform_toolsets:\n"
        f"  cli:\n    - {etc_passwd}\n    - {probe_dir}\n"
        "agent:\n"
        f"  disabled_toolsets:\n    - {etc_passwd}\n"
        "memory:\n"
        f"  provider: {etc_passwd}\n"
        "cron:\n"
        f"  provider: {probe_dir}\n"
        f"  model: {etc_passwd}\n"
        "plugins:\n"
        "  enabled:\n"
        "    - hookplug\n",
    )
    _put(
        home,
        "cron/jobs.json",
        json.dumps({
            "jobs": [
                {
                    "id": etc_passwd,
                    "name": str(probe_dir),
                    "prompt": etc_passwd,
                    "schedule": str(probe_dir),
                    "context_from": [etc_passwd, str(probe_dir)],
                    "enabled": True,
                }
            ]
        }),
    )

    # Also test existing path given as profile name on active_profile / profile_name / facts
    monkeypatch.setattr(facts, "resolve_active_profile_name", lambda **kw: str(probe_dir))

    result = _audit(tmp_path, monkeypatch, home, root=str(project))
    assert result["status"] == "completed"

    db_path = tmp_path / "audit-store" / "audit.db"
    stored = surface.execute_audit({"action": "report", "run_id": result["run_id"]}, db_path=db_path)
    plain_summary = summary_mod.summarize(stored["report"], home=str(home))
    rendered = summary_mod.render_text(plain_summary)

    ws = stored["report"]["write_settings"]
    assert all(isinstance(x, dict) and "hmac" in x for x in ws["tool_selection"]["enabled_toolsets"])
    assert all(isinstance(x, dict) and "hmac" in x for x in ws["tool_selection"]["disabled_toolsets"])
    assert isinstance(ws["external_memory_provider"]["provider"], dict)
    assert isinstance(stored["report"]["context_load"]["external_memory_provider"]["provider"], dict)
    assert isinstance(stored["report"]["active_profile"], dict)
    assert isinstance(stored["report"]["context_load"]["profile"]["name"], dict)

    # Verify neither /etc/passwd nor probe_dir ever appears in any non-path field across
    # report, run result, plain summary, rendered summary, or SQLite JSON columns.
    # (outward literal-path extraction records config.yaml's literal path references under
    # declared path fields `blending[*].target` and `audit.blending`'s `affected_identities`.)
    ev = load_submodule("audit.evidence")
    for label, obj in (
        ("run_result", result["report"]),
        ("stored_report", stored["report"]),
        ("plain_summary", plain_summary),
    ):
        for p_loc, k_name, val in _collect_scalar_strings(obj):
            if val in (etc_passwd, str(probe_dir), str(probe_dir.resolve())):
                assert k_name in ev._PATH_FIELDS, f"{val!r} leaked in non-path field {p_loc} (key={k_name}) in {label}"
        for sec_key in (
            "write_settings", "context_load", "unattended_exposure",
            "skill_hygiene", "skill_ledger", "skill_packs",
            "memory_load", "kanban_residue", "home_workdirs",
            "dead_stores", "profile_duplicates", "secret_file_copies",
        ):
            sec_dump = json.dumps(stored["report"][sec_key])
            assert etc_passwd not in sec_dump, sec_key
            assert str(probe_dir) not in sec_dump, sec_key

    assert etc_passwd not in rendered
    assert str(probe_dir) not in rendered

    for idx, cell_obj in enumerate(_sqlite_json_values(db_path)):
        for p_loc, k_name, val in _collect_scalar_strings(cell_obj, path=f"db[{idx}]"):
            if val in (etc_passwd, str(probe_dir), str(probe_dir.resolve())):
                assert k_name in ev._PATH_FIELDS, f"SQLite leaked {val!r} at {p_loc} (key={k_name})"

    # Direct AuditStore persistence check: path-shaped profile name never reaches SQLite raw
    store_mod = load_submodule("audit.store")
    direct_db = tmp_path / "direct-store" / "audit.db"
    direct_db.parent.mkdir()
    direct_store = store_mod.AuditStore(direct_db)
    for bad_prof in (etc_passwd, str(probe_dir)):
        r_row = direct_store.create_run(
            as_of=1800000000,
            active_profile=bad_prof,
            planned_units=[{"unit_kind": "profile", "unit_id": bad_prof}],
        )
        direct_store.commit_unit_result(
            run_id=r_row["run_id"],
            unit_kind="profile",
            unit_id=bad_prof,
            manifest={"stable": True, "coverage": "verified", "unit_digest": "a" * 64},
            evidence={"coverage": "verified", "name": bad_prof, "unit_id": bad_prof},
        )
        direct_store.finalize_run(r_row["run_id"])
    with sqlite3.connect(direct_db) as conn:
        direct_dump = "\n".join(conn.iterdump())
    assert etc_passwd not in direct_dump
    assert etc_passwd.encode() not in direct_db.read_bytes()
    assert str(probe_dir) not in direct_dump
    assert str(probe_dir).encode() not in direct_db.read_bytes()

    # Declared path fields still retain their legitimate resolved paths
    assert ws["profile_path"] == str(home.resolve())
    assert stored["report"]["skill_hygiene"]["profile_path"] == str(home.resolve())
    assert str((home / "plugins" / "hookplug").resolve()) in (
        stored["report"]["secret_file_copies"]["secret_named_files"]["plugin_folders_with_dotenv"]
    )
    assert stored["report"]["context_load"]["projects"][0]["project_root"] == str(project.resolve())


def test_declared_path_fields_cover_all_legitimate_report_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ev = load_submodule("audit.evidence")
    home, project = _home(tmp_path)
    _put(home, "plugins/hookplug/.env", "PLACEHOLDER=1\n")
    # Add duplicate skills so skill_hygiene.duplicate_groups is exercised
    _put(home, "skills/dup_a/SKILL.md", "---\nname: dup-a\n---\nSame duplicate skill body.\n")
    _put(home, "skills/dup_b/SKILL.md", "---\nname: dup-b\n---\nSame duplicate skill body.\n")

    result = _audit(tmp_path, monkeypatch, home, root=str(project), sessions=True)
    assert result["status"] == "completed"
    rep = result["report"]

    undeclared: list[tuple[str, str | None, str]] = []
    declared_seen: set[str] = set()
    for p_loc, key, val in _collect_scalar_strings(rep):
        if val in ev.VOCABULARY:
            continue
        if val.startswith("/"):
            if key in ev._PATH_FIELDS or (key == "unit_id" and ".units[" in p_loc):
                declared_seen.add(key or "")
            else:
                undeclared.append((p_loc, key, val))

    assert undeclared == [], f"Kept paths found in undeclared fields: {undeclared}"
    assert {"path", "paths", "profile_path", "plugin_folders_with_dotenv", "location", "project_root"} <= declared_seen
