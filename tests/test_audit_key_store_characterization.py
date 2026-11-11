"""Characterization tests for `audit/key.py`, `audit/persistence.py`, and `audit/store.py`."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest  # type: ignore[import-not-found]

from tests import ensure_test_package
from tests.conftest import load_submodule

ensure_test_package()

from hermes_plugins.defuzz.audit import AuditStore  # type: ignore[import-not-found] # noqa: E402


def test_facade_exports_and_seams():
    key_mod = load_submodule("audit.key")
    pers_mod = load_submodule("audit.persistence")
    store_mod = load_submodule("audit.store")

    for attr in (
        "_CURRENT_KEY_PATH",
        "_CURRENT_KEY_BYTES",
        "key_path",
        "key_scope",
        "using_store_key",
        "private_paths",
        "AuditKeyUnavailable",
        "_load_key",
        "_read_or_create_key",
        "keyed_digest",
        "content_digest",
    ):
        assert hasattr(key_mod, attr), f"audit.key missing {attr}"

    for attr in (
        "PERSISTENCE_VERSION",
        "_UNSCOPED",
        "_BOOL_FIELDS",
        "_INT_FIELDS",
        "strict_json",
        "control_digest",
        "stable_content_digest",
        "digest",
        "pick",
        "facts_dto",
        "manifest_dto",
        "finding_dto",
        "component_dto",
    ):
        assert hasattr(pers_mod, attr), f"audit.persistence missing {attr}"

    for attr in (
        "AUDIT_STORE_SCHEMA_VERSION",
        "_AUDIT_SCHEMA_SQL",
        "_stored_json",
        "_stored_digest",
        "_stored_text",
        "_dto_json",
        "_source_text",
        "_component_control_id",
        "_manifest_version",
        "audit_db_path",
        "ensure_audit_tables",
        "compute_evidence_cache_key",
        "compute_derived_cache_key",
        "AuditStore",
        "GeneratedDigest",
        "SealedEvidence",
        "SealedKey",
        "os",
    ):
        assert hasattr(store_mod, attr), f"audit.store missing {attr}"


def test_runtime_keyed_digest_seam(monkeypatch, tmp_path):
    key_mod = load_submodule("audit.key")
    pers_mod = load_submodule("audit.persistence")
    db = tmp_path / "state.db"
    with key_mod.key_scope(db):
        monkeypatch.setattr(key_mod, "keyed_digest", lambda value, *, domain: f"patched-{domain}")
        assert pers_mod.control_digest({"value": 1}) == "patched-control"


def test_key_lifecycle_and_nested_scope(tmp_path):
    key_mod = load_submodule("audit.key")
    db = tmp_path / "store" / "state.db"
    kpath = key_mod.key_path(db)
    assert kpath == tmp_path / "store" / "audit.key"

    # Corrupt short key is replaced on scope entry
    kpath.parent.mkdir(parents=True)
    kpath.write_bytes(b"short")
    with key_mod.key_scope(db):
        assert key_mod.private_paths() == (kpath.resolve(), Path(f"{kpath.resolve()}.lock"))
        d1 = key_mod.content_digest("a" * 64)
        with key_mod.key_scope(db):
            d2 = key_mod.keyed_digest("a" * 64, domain="content")
            d_ctrl = key_mod.keyed_digest("a" * 64, domain="control")
        assert d1 == d2
        assert d1 != d_ctrl
    assert len(kpath.read_bytes()) == 32


def test_persistence_strict_json_and_dtos():
    pers_mod = load_submodule("audit.persistence")
    ev_mod = load_submodule("audit.evidence")

    assert pers_mod.strict_json({"a": [1, True, None, "ok", (2, 3.5)]}) == {
        "a": [1, True, None, "ok", [2, 3.5]]
    }

    for bad in (float("nan"), float("inf"), float("-inf"), {1: "a"}, object()):
        with pytest.raises(ValueError):
            pers_mod.strict_json(bad)

    cyclic: list = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="Cyclic"):
        pers_mod.strict_json(cyclic)

    finding = pers_mod.finding_dto({
        "id": "audit.finding",
        "classification": "info",
        "coverage": "could_not_verify",
        "consequence": "c",
        "evidence": {"reason": "credential_store_not_opened"},
    })
    assert finding["evidence"]["reason"] == "credential_store_not_opened"
    assert isinstance(finding["evidence"]["source_digest"], ev_mod.GeneratedDigest)

    comp = pers_mod.component_dto({
        "component_id": "comp",
        "coverage": "verified",
        "classification": "info",
        "findings": [],
        "operational_error": "raw stack trace",
    })
    assert comp["operational_error"] == "Component verification failed"


def test_store_schema_v1_migration(tmp_path):
    store_mod = load_submodule("audit.store")
    key_mod = load_submodule("audit.key")
    pers_mod = load_submodule("audit.persistence")
    db = tmp_path / "legacy_audit.db"

    # Simulate pre-unit_identity schema with existing rows and v1 inventory
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            CREATE TABLE audit_schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO audit_schema_meta VALUES ('schema_version', '1');
            CREATE TABLE audit_runs (
                run_id TEXT PRIMARY KEY, status TEXT NOT NULL, mode TEXT NOT NULL,
                optional_root TEXT, active_profile TEXT NOT NULL, as_of INTEGER NOT NULL,
                unused_threshold_days INTEGER NOT NULL DEFAULT 90, inventory_json TEXT NOT NULL,
                engine_versions_json TEXT NOT NULL, template_versions_json TEXT NOT NULL,
                manifest_version TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                completed_at INTEGER, canonical_digest TEXT, report_json TEXT
            );
            CREATE TABLE audit_units (
                run_id TEXT NOT NULL, unit_kind TEXT NOT NULL, unit_id TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, coverage TEXT NOT NULL,
                stable INTEGER NOT NULL DEFAULT 1, fingerprint_digest TEXT, manifest_version TEXT NOT NULL,
                manifest_json TEXT, evidence_cache_key TEXT, evidence_json TEXT, updated_at INTEGER NOT NULL,
                PRIMARY KEY (run_id, unit_kind, unit_id)
            );
            CREATE TABLE audit_unit_results (
                run_id TEXT NOT NULL, unit_kind TEXT NOT NULL, unit_id TEXT NOT NULL,
                component_id TEXT NOT NULL, derived_cache_key TEXT NOT NULL, as_of INTEGER NOT NULL,
                unused_threshold_days INTEGER NOT NULL, coverage TEXT NOT NULL, classification TEXT NOT NULL,
                findings_json TEXT NOT NULL, envelope_json TEXT NOT NULL, updated_at INTEGER NOT NULL,
                PRIMARY KEY (run_id, unit_kind, unit_id, component_id)
            );
            CREATE TABLE audit_evidence_cache (
                evidence_cache_key TEXT PRIMARY KEY, unit_kind TEXT NOT NULL, unit_id TEXT NOT NULL,
                fingerprint_digest TEXT NOT NULL, manifest_version TEXT NOT NULL,
                manifest_json TEXT NOT NULL, evidence_json TEXT NOT NULL, created_at INTEGER NOT NULL
            );
            """
        )
        inv_v1 = json.dumps({"required_checks": [{"unit_kind": "profile", "unit_id": "alpha"}]})
        conn.execute(
            "INSERT INTO audit_runs VALUES ('r1', 'running', 'live', NULL, 'default', 100, 90, ?, '{}', '{}', '1.0', 1, 1, NULL, NULL, NULL)",
            (inv_v1,),
        )
        conn.execute(
            "INSERT INTO audit_units VALUES ('r1', 'profile', 'alpha', 0, 'pending', 'could_not_verify', 1, NULL, '1.0', NULL, NULL, NULL, 1)"
        )

    with key_mod.key_scope(db):
        store_mod.ensure_audit_tables(db)
        expected_ctrl = pers_mod.control_digest("alpha")

    store = store_mod.AuditStore(db)
    run = store.get_run("r1")
    assert run is not None
    assert run["inventory"]["_unit_identity_version"] == 2
    assert run["inventory"]["required_checks"][0]["unit_id"] == expected_ctrl
    assert run["units"][0]["unit_control_id"] == expected_ctrl


def test_store_validation_cleanup_and_finalize_modes(tmp_path):
    store = AuditStore(tmp_path / "audit.db")

    # Duplicate or invalid planned units rejected
    with pytest.raises(ValueError, match="Invalid or duplicate"):
        store.create_run(
            as_of=10,
            planned_units=[
                {"unit_kind": "profile", "unit_id": "a"},
                {"unit_kind": "profile", "unit_id": "a"},
            ],
        )
    with pytest.raises(ValueError, match="Invalid or duplicate"):
        store.create_run(as_of=10, planned_units=[{"unit_kind": "profile", "unit_id": ""}])

    # Outward options filtering
    run = store.create_run(
        as_of=10,
        mode="bounded",
        inventory={
            "outward_options": {
                "max_entries": 50,
                "max_bytes": True,
                "max_file_bytes": 0,
                "unbounded": False,
                "ignored": 123,
            }
        },
        planned_units=[{"unit_kind": "profile", "unit_id": "default"}],
    )
    assert run["inventory"]["outward_options"] == {"max_entries": 50, "unbounded": False}

    # Duplicate component_id rejected
    with pytest.raises(ValueError, match="Duplicate component"):
        store.commit_unit_result(
            run_id=run["run_id"],
            unit_kind="profile",
            unit_id="default",
            manifest={"stable": True, "coverage": "verified", "unit_digest": "d1"},
            evidence={"coverage": "verified", "unit_kind": "profile", "name": "default"},
            component_results=[{"component_id": "c1"}, {"component_id": "c1"}],
        )

    # Cleanup proposal insert and upsert
    assert store.get_cleanup_proposal("missing") is None
    p1 = store.record_cleanup_proposal(
        cleanup_id="c1",
        run_id=run["run_id"],
        fix_type="archive",
        target_identity="default",
        fingerprint_digest="d1",
        plan={"step": 1},
        selected=False,
    )
    assert p1["selected"] is False
    assert p1["outcome_status"] == "proposed"
    p2 = store.record_cleanup_proposal(
        cleanup_id="c1",
        run_id=run["run_id"],
        fix_type="archive",
        target_identity="default",
        fingerprint_digest="d2",
        plan={"step": 2},
        selected=True,
    )
    assert p2["selected"] is True
    assert p2["plan"]["execution_supported"] is False

    # Outward report finalization
    outward_data = {
        "regions": {"r1": {"coverage": "verified"}},
        "limits": {"max_file_bytes": 4096},
        "blending": [],
        "credentials": [],
        "dynamic_invocations": [],
        "session_history": [],
    }
    finalized = store.finalize_run(run["run_id"], outward=outward_data)
    assert finalized["status"] == "completed"
    assert finalized["report"]["scope"]["max_file_bytes"] == 4096
    assert finalized["report"]["database_associations"] == []
    assert finalized["report"]["database_records"] == []
