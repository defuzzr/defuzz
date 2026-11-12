"""Plugin DB persistence for audit runs, unit snapshots, results, and cleanup approvals (§1, §4, §8, §10, §12).

Settled invariants enforced here:
- Explicit exception to source read-only: save audit progress and results ONLY in the
  plugin's own DB (`<active_hermes_home>/plugin-data/defuzz/state.db` or explicit `db_path`).
- Never initialize or migrate inspected profile/source databases during a sweep.
- Migration/DDL code (`ensure_audit_tables`) lives in this module, completely separate
  from `readonly_db.py` and `facts.py`.
- Atomic unit commits (`commit_unit_result`), cancel at safe boundary (`cancel_run`),
  and resume after click (`resume_run`).
- Time-independent evidence (`evidence_json` keyed on `fingerprint_digest`) is stored
  separately from time-dependent derived results (`derived_key` includes `as_of` and
  `unused_threshold_days`) (§12).
- Cross-check coherence (`build_coherent_crosscheck_manifest`): verifies all saved units
  belong to the run's current versioned manifest (§4).
"""

from __future__ import annotations

import hashlib
import json
import os  # noqa: F401  re-exported for compatibility
import re
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..state_store import state_db_path
from . import bounded, fingerprint, identity, redaction
from .contract import (
    CONTRACT_VERSION,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
    adapt_component_result,
    canonical_report_bytes,
    canonical_report_digest,
    canonical_report_payload,
    compute_headline,
    normalize_coverage,
    sort_findings,
)
from .evidence import (
    EvidenceSerializer,
    GeneratedDigest,  # noqa: F401  re-exported for compatibility
    PersistedJSON,
    SealedEvidence,  # noqa: F401  re-exported for compatibility
    SealedKey,  # noqa: F401  re-exported for compatibility
    control_identity,
    generated_digest,
    serialize_evidence,
)
from .facts import evaluate_profile_age_and_unused
from .fingerprint import FINGERPRINT_MANIFEST_VERSION, OWNERSHIP_MANIFEST_VERSION
from .key import AuditKeyUnavailable, key_location_scope, key_scope, using_store_key
from .persistence import component_dto, control_digest, digest, facts_dto, finding_dto, manifest_dto, strict_json
from .evidence_wiring import WIRED_SECTIONS

AUDIT_STORE_SCHEMA_VERSION = 2

_STORED_DIGEST_FIELDS = frozenset({
    "raw_evidence_digest", "source_digest", "capture_digest",
    "caller_rules_digest", "caller_templates_digest",
    "engine_digest", "template_digest", "unit_digest", "sha256",
    "config_digest", "configuration_match_digest", "whole_profile_digest",
})
_SEALED_KEY_RE = re.compile(r"hmac:[0-9a-f]{64}")


def _stored_json(text: str) -> Any:
    """Rehydrate evidence only from our own persisted DTO columns."""
    def restore(value: Any) -> Any:
        if isinstance(value, list):
            return [restore(item) for item in value]
        if isinstance(value, dict):
            if {"kind", "hmac", "location"} <= value.keys() or set(value) == {"scheme", "host", "port"}:
                return EvidenceSerializer().serialize(EvidenceSerializer._seal(**value))
            return {
                EvidenceSerializer._seal_key(k) if _SEALED_KEY_RE.fullmatch(k) else k: (
                    generated_digest(v) if k in _STORED_DIGEST_FIELDS and isinstance(v, str) else restore(v)
                )
                for k, v in value.items()
            }
        return value
    return restore(json.loads(text))


def _stored_digest(text):
    value = _stored_text(text)
    return generated_digest(value) if isinstance(value, str) else value


def _stored_text(text):
    if isinstance(text, str) and text.startswith("{"):
        return _stored_json(text)
    return text


def _dto_json(value, **kwargs):
    return PersistedJSON(json.dumps(strict_json(serialize_evidence(value)), **kwargs))


def _source_text(value):
    """SQL TEXT representation of source content (not a control identity)."""
    safe = serialize_evidence(value)
    return safe if isinstance(safe, str) or safe is None else _dto_json(safe, sort_keys=True)


def _component_control_id(value):
    """Stable internal index, separate from the source identity in the DTO."""
    prefix = "cross_" if value.startswith("cross_") else "component_"
    return control_identity(prefix + control_digest(value))


def _manifest_version(value):
    return FINGERPRINT_MANIFEST_VERSION if value == FINGERPRINT_MANIFEST_VERSION else _source_text(value)


_AUDIT_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_runs (
    run_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('running', 'cancelled', 'completed', 'failed')),
    mode TEXT NOT NULL,
    optional_root TEXT,
    active_profile TEXT NOT NULL,
    as_of INTEGER NOT NULL,
    unused_threshold_days INTEGER NOT NULL DEFAULT 90,
    inventory_json TEXT NOT NULL,
    engine_versions_json TEXT NOT NULL,
    template_versions_json TEXT NOT NULL,
    manifest_version TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    completed_at INTEGER,
    canonical_digest TEXT,
    report_json TEXT
);

CREATE TABLE IF NOT EXISTS audit_units (
    run_id TEXT NOT NULL REFERENCES audit_runs(run_id) ON DELETE CASCADE,
    unit_kind TEXT NOT NULL CHECK (unit_kind IN ('profile', 'project')),
    unit_id TEXT NOT NULL,
    unit_identity TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'incomplete', 'invalidated')),
    coverage TEXT NOT NULL,
    stable INTEGER NOT NULL DEFAULT 1,
    fingerprint_digest TEXT,
    manifest_version TEXT NOT NULL,
    manifest_json TEXT,
    evidence_cache_key TEXT,
    evidence_json TEXT,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (run_id, unit_kind, unit_id)
);

CREATE TABLE IF NOT EXISTS audit_unit_results (
    run_id TEXT NOT NULL REFERENCES audit_runs(run_id) ON DELETE CASCADE,
    unit_kind TEXT NOT NULL,
    unit_id TEXT NOT NULL,
    unit_identity TEXT,
    component_id TEXT NOT NULL,
    derived_cache_key TEXT NOT NULL,
    as_of INTEGER NOT NULL,
    unused_threshold_days INTEGER NOT NULL,
    coverage TEXT NOT NULL,
    classification TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (run_id, unit_kind, unit_id, component_id)
);

CREATE TABLE IF NOT EXISTS audit_evidence_cache (
    evidence_cache_key TEXT PRIMARY KEY,
    unit_kind TEXT NOT NULL,
    unit_id TEXT NOT NULL,
    unit_identity TEXT,
    fingerprint_digest TEXT NOT NULL,
    manifest_version TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_derived_cache (
    derived_cache_key TEXT PRIMARY KEY,
    evidence_cache_key TEXT NOT NULL,
    component_id TEXT NOT NULL,
    as_of INTEGER NOT NULL,
    unused_threshold_days INTEGER NOT NULL,
    coverage TEXT NOT NULL,
    classification TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_cleanup_approvals (
    cleanup_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES audit_runs(run_id) ON DELETE CASCADE,
    fix_type TEXT NOT NULL,
    target_identity TEXT NOT NULL,
    fingerprint_digest TEXT NOT NULL,
    selected INTEGER NOT NULL DEFAULT 0,
    approved INTEGER NOT NULL DEFAULT 0,
    plan_json TEXT NOT NULL,
    backup_path TEXT,
    backup_verified INTEGER NOT NULL DEFAULT 0,
    outcome_status TEXT NOT NULL DEFAULT 'proposed',
    outcome_detail TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"""


def audit_db_path(db_path: Path | str | None = None, *, ctx: Any = None) -> Path:
    """Resolve the plugin's own `defuzz/state.db` path (never an inspected foreign profile DB)."""
    return Path(db_path).expanduser() if db_path is not None else state_db_path(ctx=ctx)


def _migrate_audit_schema(conn: sqlite3.Connection) -> None:
    for table in ("audit_units", "audit_unit_results", "audit_evidence_cache"):
        columns = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if "unit_identity" not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN unit_identity TEXT")
            for row in conn.execute(f"SELECT rowid, unit_id FROM {table}").fetchall():
                conn.execute(
                    f"UPDATE {table} SET unit_id = ?, unit_identity = ? WHERE rowid = ?",
                    (control_digest(row["unit_id"]), _source_text(row["unit_id"]), row["rowid"]),
                )
    if conn.execute("SELECT value FROM audit_schema_meta WHERE key = 'schema_version'").fetchone() is not None:
        for row in conn.execute("SELECT run_id, inventory_json FROM audit_runs").fetchall():
            if json.loads(row["inventory_json"]).get("_unit_identity_version") == 2:
                continue
            inventory = _stored_json(row["inventory_json"])
            for required in inventory.get("required_checks", []):
                required["unit_id"] = control_digest(required["unit_id"])
            inventory["_unit_identity_version"] = 2
            conn.execute(
                "UPDATE audit_runs SET inventory_json = ? WHERE run_id = ?",
                (_dto_json(inventory, sort_keys=True), row["run_id"]),
            )
    conn.execute(
        "INSERT INTO audit_schema_meta (key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(AUDIT_STORE_SCHEMA_VERSION),),
    )


def ensure_audit_tables(db_path: Path | str | None = None, *, ctx: Any = None) -> Path:
    """Initialize or migrate the plugin's own audit tables in `defuzz/state.db`."""
    target = audit_db_path(db_path, ctx=ctx)
    target.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(target))) as conn:
        conn.row_factory = sqlite3.Row
        with conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.executescript(_AUDIT_SCHEMA_SQL)
            # The migration computes keyed digests: use the key that belongs to THIS store,
            # never a key created in the Hermes home for a store that lives elsewhere.
            with key_location_scope(target):
                _migrate_audit_schema(conn)
    return target


def _sorted_str_map(mapping: Mapping[str, str] | None) -> dict[str, str]:
    return dict(sorted((str(k), str(v)) for k, v in (mapping or {}).items()))


def compute_evidence_cache_key(
    *, unit_kind: str, unit_id: str, fingerprint_digest: str,
    manifest_version: str = FINGERPRINT_MANIFEST_VERSION,
) -> str:
    """Compute a time-independent cache key for unit evidence (§12: excludes `as_of` and `threshold`)."""
    return control_digest({
        "engine_identity": identity.engine_identity(),
        "unit_kind": str(unit_kind),
        "unit_id": str(unit_id),
        "fingerprint_digest": str(fingerprint_digest),
        "manifest_version": str(manifest_version),
    })


def compute_derived_cache_key(
    *, evidence_cache_key: str, component_id: str, as_of: int | float,
    unused_threshold_days: int, rule_versions: Mapping[str, str] | None = None,
    template_versions: Mapping[str, str] | None = None,
    engine: Mapping[str, Any] | None = None,
) -> str:
    """Compute a time-dependent derived-result cache key (§12: includes `as_of` and `unused_threshold_days`).

    `engine` is a precomputed identity.engine_identity() for callers keying many results at once.
    """
    return control_digest({
        "engine_identity": identity.engine_identity() if engine is None else engine,
        "evidence_cache_key": str(evidence_cache_key),
        "component_id": str(component_id),
        "as_of": int(as_of),
        "unused_threshold_days": int(unused_threshold_days),
        "rule_versions": _sorted_str_map(rule_versions),
        "template_versions": _sorted_str_map(template_versions),
    })


def _build_run_inventory(
    active_profile: str,
    inventory: Mapping[str, Any] | None,
    planned_units: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    options = (inventory or {}).get("outward_options", {})
    return {
        "_unit_identity_version": 2,
        "source_digest": digest(inventory or {}),
        "active_profile_control": control_digest(active_profile),
        "audit_key_id": control_digest("audit-key-generation"),
        "sessions": (inventory or {}).get('sessions') is True,
        "required_checks": [
            {
                "unit_kind": u["unit_kind"],
                "unit_id": control_digest(u["unit_id"]),
                "components": sorted({_component_control_id(c) for c in u.get("required_components", ())}),
                "collectors": sorted(set(u.get("required_collectors", ()))),
            }
            for u in planned_units
        ],
        "outward_options": {
            k: v for k, v in options.items()
            if (k in ("max_entries", "max_bytes", "max_file_bytes") and type(v) is int and v > 0)
            or (k == "unbounded" and type(v) is bool)
        },
    }


def _insert_pending_unit(
    conn: sqlite3.Connection, run_id: str, unit_kind: str, unit_id: str, sort_order: int, now: int
) -> None:
    conn.execute(
        """
        INSERT INTO audit_units (
            run_id, unit_kind, unit_id, unit_identity, sort_order, status,
            coverage, stable, fingerprint_digest, manifest_version,
            manifest_json, evidence_cache_key, evidence_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'pending', ?, 1, NULL, ?, NULL, NULL, NULL, ?)
        """,
        (
            run_id, unit_kind, control_digest(unit_id), _source_text(unit_id),
            sort_order, COVERAGE_COULD_NOT_VERIFY, FINGERPRINT_MANIFEST_VERSION, now,
        ),
    )


def _missing_unit_requirements(
    run_row: sqlite3.Row, unit_kind: str, unit_ctrl_id: str,
    component_ids: Sequence[str], evidence: Mapping[str, Any],
) -> bool:
    requirements = json.loads(run_row["inventory_json"]).get("required_checks", [])
    required = next((r for r in requirements if (r["unit_kind"], r["unit_id"]) == (unit_kind, unit_ctrl_id)), {})
    if set(required.get("components", ())) - {_component_control_id(c) for c in component_ids}:
        return True
    collectors = evidence.get("collectors", {})
    return any(
        collectors.get(c, {}).get("coverage") != COVERAGE_VERIFIED
        or collectors.get(c, {}).get("status") == "error"
        or collectors.get(c, {}).get("error")
        for c in required.get("collectors", ())
    )


def _upsert_unit_snapshot(conn: sqlite3.Connection, values: tuple[Any, ...]) -> None:
    conn.execute(
        """
        INSERT INTO audit_units (
            run_id, unit_kind, unit_id, unit_identity, sort_order, status,
            coverage, stable, fingerprint_digest, manifest_version,
            manifest_json, evidence_cache_key, evidence_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id, unit_kind, unit_id) DO UPDATE SET
            unit_identity = excluded.unit_identity,
            status = excluded.status,
            coverage = excluded.coverage,
            stable = excluded.stable,
            fingerprint_digest = excluded.fingerprint_digest,
            manifest_version = excluded.manifest_version,
            manifest_json = excluded.manifest_json,
            evidence_cache_key = excluded.evidence_cache_key,
            evidence_json = excluded.evidence_json,
            updated_at = excluded.updated_at
        """,
        values,
    )


def _sync_evidence_cache(
    conn: sqlite3.Connection, unit_kind: str, unit_id: str, ctrl_id: str, unit_identity: Any,
    fp_digest: str, m_version: str, unit_cov: str, stable: bool, ev_key: str | None,
    manifest_json: str, evidence_json: str, now: int,
) -> None:
    if unit_cov != COVERAGE_VERIFIED:
        candidate = compute_evidence_cache_key(
            unit_kind=unit_kind, unit_id=unit_id, fingerprint_digest=fp_digest, manifest_version=m_version
        )
        rows = conn.execute(
            "SELECT evidence_cache_key FROM audit_evidence_cache WHERE evidence_cache_key = ?", (candidate,)
        ).fetchall()
        for (stale,) in rows:
            conn.execute("DELETE FROM audit_derived_cache WHERE evidence_cache_key = ?", (stale,))
            conn.execute("DELETE FROM audit_evidence_cache WHERE evidence_cache_key = ?", (stale,))
        return

    if stable and ev_key is not None:
        conn.execute(
            """
            INSERT INTO audit_evidence_cache (
                evidence_cache_key, unit_kind, unit_id, unit_identity,
                fingerprint_digest, manifest_version, manifest_json, evidence_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(evidence_cache_key) DO UPDATE SET
                unit_identity = excluded.unit_identity,
                manifest_json = excluded.manifest_json,
                evidence_json = excluded.evidence_json
            """,
            (
                ev_key, unit_kind, ctrl_id, unit_identity, _source_text(fp_digest),
                _manifest_version(m_version), manifest_json, evidence_json, now,
            ),
        )


def _store_component_results(
    conn: sqlite3.Connection, run_id: str, unit_kind: str, unit_id: str,
    ctrl_id: str, unit_identity: Any, unit_cov: str, stable: bool, ev_key: str | None,
    component_results: Sequence[Mapping[str, Any]], run_row: sqlite3.Row, now: int,
) -> None:
    as_of = int(run_row["as_of"])
    threshold_days = int(run_row["unused_threshold_days"])
    rule_vers = json.loads(run_row["engine_versions_json"])
    tmpl_vers = json.loads(run_row["template_versions_json"])
    conn.execute(
        "DELETE FROM audit_unit_results WHERE run_id = ? AND unit_kind = ? AND unit_id = ?",
        (run_id, unit_kind, ctrl_id),
    )
    # Hash the engine once per unit, not once per component (it reads every engine file).
    engine = identity.engine_identity()
    for comp in component_results:
        comp_id = _component_control_id(str(comp.get("component_id") or "default"))
        comp_cov = (
            COVERAGE_COULD_NOT_VERIFY
            if not stable or unit_cov != COVERAGE_VERIFIED
            else str(comp.get("coverage") or unit_cov)
        )
        comp_cls = str(comp.get("classification") or "info")
        safe_comp = component_dto(comp)
        safe_comp["coverage"] = comp_cov
        comp_findings = sort_findings(safe_comp["findings"])
        d_key = compute_derived_cache_key(
            evidence_cache_key=ev_key or f"unstable:{run_id}:{unit_kind}:{unit_id}",
            component_id=comp_id, as_of=as_of, unused_threshold_days=threshold_days,
            rule_versions=rule_vers, template_versions=tmpl_vers, engine=engine,
        )
        findings_str = _dto_json(serialize_evidence(comp_findings), sort_keys=True)
        env_str = _dto_json(serialize_evidence(safe_comp), sort_keys=True)

        conn.execute(
            """
            INSERT INTO audit_unit_results (
                run_id, unit_kind, unit_id, unit_identity, component_id,
                derived_cache_key, as_of, unused_threshold_days,
                coverage, classification, findings_json, envelope_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, unit_kind, unit_id, component_id) DO UPDATE SET
                unit_identity = excluded.unit_identity,
                derived_cache_key = excluded.derived_cache_key,
                as_of = excluded.as_of,
                unused_threshold_days = excluded.unused_threshold_days,
                coverage = excluded.coverage,
                classification = excluded.classification,
                findings_json = excluded.findings_json,
                envelope_json = excluded.envelope_json,
                updated_at = excluded.updated_at
            """,
            (
                run_id, unit_kind, ctrl_id, unit_identity, comp_id, d_key,
                as_of, threshold_days, comp_cov, comp_cls, findings_str, env_str, now,
            ),
        )
        if stable and comp_cov == COVERAGE_VERIFIED and ev_key is not None:
            conn.execute(
                """
                INSERT INTO audit_derived_cache (
                    derived_cache_key, evidence_cache_key, component_id,
                    as_of, unused_threshold_days, coverage, classification,
                    findings_json, envelope_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(derived_cache_key) DO UPDATE SET
                    coverage = excluded.coverage,
                    classification = excluded.classification,
                    findings_json = excluded.findings_json,
                    envelope_json = excluded.envelope_json
                """,
                (
                    d_key, ev_key, comp_id, as_of, threshold_days,
                    comp_cov, comp_cls, findings_str, env_str, now,
                ),
            )


def _sync_resume_versions(
    conn: sqlite3.Connection, run_id: str, run_row: sqlite3.Row,
    current_engine_versions: Mapping[str, str] | None,
    current_template_versions: Mapping[str, str] | None,
) -> tuple[bool, bool]:
    saved_engine = _stored_json(run_row["engine_versions_json"])
    saved_templates = _stored_json(run_row["template_versions_json"])
    caller_rules = (
        digest(current_engine_versions)
        if current_engine_versions is not None
        else saved_engine.get("caller_rules_digest", "")
    )
    resolved_engine = {"caller_rules_digest": caller_rules, **identity.engine_identity(), "contract": CONTRACT_VERSION}
    engine_changed = dict(resolved_engine) != saved_engine
    resolved_templates = (
        {"caller_templates_digest": digest(current_template_versions)}
        if current_template_versions is not None
        else saved_templates
    )
    templates_changed = dict(resolved_templates or {}) != saved_templates
    if engine_changed:
        conn.execute(
            "UPDATE audit_runs SET engine_versions_json = ? WHERE run_id = ?",
            (_dto_json(dict(resolved_engine), sort_keys=True), run_id),
        )
    if templates_changed and resolved_templates is not None:
        conn.execute(
            "UPDATE audit_runs SET template_versions_json = ? WHERE run_id = ?",
            (_dto_json(dict(resolved_templates), sort_keys=True), run_id),
        )
    return engine_changed, templates_changed


def _reconcile_resume_units(
    conn: sqlite3.Connection, run_id: str,
    existing_map: Mapping[tuple[str, str], sqlite3.Row],
    current_unit_digests: Mapping[tuple[str, str], str | None],
    *, engine_changed: bool, templates_changed: bool, now: int,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]], bool]:
    current_controls = {(kind, control_digest(uid)) for kind, uid in current_unit_digests}
    reused_units: list[tuple[str, str]] = []
    units_to_run: list[tuple[str, str]] = []
    removed_units: list[tuple[str, str]] = []
    any_unit_changed = False

    for key in list(existing_map.keys()):
        if key not in current_controls:
            any_unit_changed = True
            removed_units.append(key)
            conn.execute(
                "DELETE FROM audit_unit_results WHERE run_id = ? AND unit_kind = ? AND unit_id = ?",
                (run_id, key[0], key[1]),
            )
            conn.execute(
                "DELETE FROM audit_units WHERE run_id = ? AND unit_kind = ? AND unit_id = ?",
                (run_id, key[0], key[1]),
            )

    for idx, ((ukind, uid), cur_digest) in enumerate(current_unit_digests.items()):
        ctrl_id = control_digest(uid)
        prev = existing_map.get((ukind, ctrl_id))
        version_invalidated = engine_changed or (templates_changed and ukind == "project")
        if (
            prev is not None
            and not version_invalidated
            and prev["status"] == "completed"
            and bool(prev["stable"])
            and prev["coverage"] == COVERAGE_VERIFIED
            and cur_digest is not None
            and prev["evidence_cache_key"]
            == compute_evidence_cache_key(
                unit_kind=ukind, unit_id=uid,
                fingerprint_digest=cur_digest, manifest_version=prev["manifest_version"],
            )
        ):
            reused_units.append((ukind, uid))
            conn.execute(
                "UPDATE audit_units SET unit_identity = ? WHERE run_id = ? AND unit_kind = ? AND unit_id = ?",
                (_source_text(uid), run_id, ukind, ctrl_id),
            )
        else:
            any_unit_changed = True
            units_to_run.append((ukind, uid))
            conn.execute(
                "DELETE FROM audit_unit_results WHERE run_id = ? AND unit_kind = ? AND unit_id = ?",
                (run_id, ukind, ctrl_id),
            )
            if prev is None:
                _insert_pending_unit(conn, run_id, ukind, uid, idx, now)
            else:
                conn.execute(
                    """
                    UPDATE audit_units
                    SET status = 'invalidated', coverage = ?, fingerprint_digest = NULL,
                        unit_identity = ?, updated_at = ?
                    WHERE run_id = ? AND unit_kind = ? AND unit_id = ?
                    """,
                    (COVERAGE_COULD_NOT_VERIFY, _source_text(uid), now, run_id, ukind, ctrl_id),
                )

    if any_unit_changed:
        conn.execute("DELETE FROM audit_unit_results WHERE run_id = ? AND component_id LIKE 'cross_%'", (run_id,))
    return reused_units, units_to_run, removed_units, any_unit_changed


def _attach_scope_and_outward(
    canonical_payload: dict[str, Any],
    mode: str,
    outward: Mapping[str, Any] | None,
    context_load: Mapping[str, Any] | None = None,
) -> None:
    if mode in ("bounded", "full_home"):
        is_bounded = mode == "bounded"
        canonical_payload["scope"] = {
            "description": "Explicit quick bounded audit" if is_bounded else "Full static audit (outward evidence unavailable)",
            "profile_capture": list(bounded.PATHS) if is_bounded else "active-profile owned regions",
            "max_file_bytes": bounded.MAX_BYTES if is_bounded else fingerprint.DEFAULT_MAX_FILE_BYTES,
            "projects": "explicit selections only" if is_bounded else "registered projects (or explicit selection)",
            "not_included": (
                ["skills", "plugins", "session history", "whole-profile identity"] if is_bounded else []
            ) + ["credentials", "sibling profiles", "shared infrastructure", "dynamic execution", "complete cross-project isolation"],
            "coverage": "could_not_verify",
        }
    if outward is not None:
        regions = outward["regions"]
        all_verified = all(r["coverage"] in ("verified", "not_applicable") for r in regions.values())
        canonical_payload["scope"] = {
            "description": "Project-outward full static audit",
            "profile_capture": "whole active profile and evidenced outgoing paths",
            "projects": "selected roots and evidenced blending only",
            "coverage": "verified" if all_verified else "could_not_verify",
            "regions": regions,
            "limits": outward["limits"],
            "max_file_bytes": outward["limits"]["max_file_bytes"],
            "component_capture_limits": {
                "max_file_bytes": fingerprint.DEFAULT_MAX_FILE_BYTES,
                "max_entries": fingerprint.DEFAULT_MAX_DIR_ENTRIES,
                "max_depth": 64,
                "retained_bytes": 64 * 1024 * 1024,
            },
            "not_included": ["unrelated projects/profiles", "runtime execution", "raw credential values"],
        }
        for key in ("blending", "credentials", "dynamic_invocations", "session_history"):
            canonical_payload[key] = outward[key]
        for key in ("database_associations", "database_records"):
            canonical_payload[key] = outward.get(key, [])
    if mode == "bounded":
        state = redaction._CURRENT.get()
        records = state.credential_metadata if state is not None else {}
        canonical_payload["credentials"] = [records[p] for p in sorted(records)]
        if records:
            canonical_payload["scope"]["reasons"] = ["credential_store_not_opened"]
    if context_load is not None:
        canonical_payload["context_load"] = dict(context_load)


class AuditStore:
    """Persistence manager for audit runs, unit snapshots, results, and cleanup proposals.

    Explicit ``run_id``, ``unit_kind``/``unit_id`` queue keys, ``cleanup_id``, and
    required collector names are operational control inputs. Source identities
    inside DTOs and reports are not controls and always cross the evidence gate.
    Resume callers compare ``inventory.active_profile_control`` with
    ``control_digest(current_profile_name)``; the display name is serialized evidence.
    """

    def __init__(self, db_path: Path | str | None = None, *, ctx: Any = None) -> None:
        self.db_path = ensure_audit_tables(db_path, ctx=ctx)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @staticmethod
    def _require_run_row(conn: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM audit_runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(f"Unknown audit run_id: {run_id!r}")
        return row

    def resume_key_available(self, inventory):
        try:
            with key_scope(self.db_path):
                return inventory.get("audit_key_id") == control_digest("audit-key-generation")
        except AuditKeyUnavailable:
            return False

    @using_store_key
    def create_run(
        self,
        *,
        as_of: int | float,
        mode: str = "live",
        optional_root: str | None = None,
        active_profile: str = "default",
        unused_threshold_days: int = 90,
        inventory: Mapping[str, Any] | None = None,
        engine_versions: Mapping[str, str] | None = None,
        template_versions: Mapping[str, str] | None = None,
        planned_units: Sequence[Mapping[str, Any]] = (),
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a new audit run and register its ordered unit queue (`pending`) (§4)."""
        rid = str(run_id or uuid.uuid4().hex)
        now = int(time.time())
        identities = [(u["unit_kind"], u["unit_id"]) for u in planned_units]
        if (
            any(type(k) is not str or type(i) is not str or not i for k, i in identities)
            or len(set(identities)) != len(identities)
        ):
            raise ValueError("Invalid or duplicate planned unit identities")

        inv_json = _dto_json(_build_run_inventory(active_profile, inventory, planned_units), sort_keys=True)
        eng_json = _dto_json(
            {"caller_rules_digest": digest(engine_versions or {}), **identity.engine_identity(), "contract": CONTRACT_VERSION},
            sort_keys=True,
        )
        tmpl_json = _dto_json({"caller_templates_digest": digest(template_versions or {})}, sort_keys=True)

        with closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO audit_runs (
                    run_id, status, mode, optional_root, active_profile,
                    as_of, unused_threshold_days, inventory_json,
                    engine_versions_json, template_versions_json,
                    manifest_version, created_at, updated_at
                ) VALUES (?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rid, _source_text(str(mode)),
                    _source_text(str(optional_root)) if optional_root is not None else None,
                    _source_text(str(active_profile)), int(as_of), int(unused_threshold_days),
                    inv_json, eng_json, tmpl_json, FINGERPRINT_MANIFEST_VERSION, now, now,
                ),
            )
            for idx, unit in enumerate(planned_units):
                _insert_pending_unit(conn, rid, str(unit["unit_kind"]), str(unit["unit_id"]), idx, now)
        return self.get_run(rid)  # type: ignore[return-value]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """Fetch an audit run record and its ordered unit statuses."""
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT * FROM audit_runs WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            units = conn.execute(
                "SELECT * FROM audit_units WHERE run_id = ? ORDER BY sort_order ASC, unit_kind ASC, unit_id ASC",
                (run_id,),
            ).fetchall()
            results = conn.execute(
                "SELECT * FROM audit_unit_results WHERE run_id = ? ORDER BY unit_kind ASC, unit_id ASC, component_id ASC",
                (run_id,),
            ).fetchall()

        return {
            "run_id": row["run_id"],
            "status": row["status"],
            "mode": _stored_text(row["mode"]),
            "optional_root": _stored_text(row["optional_root"]),
            "active_profile": _stored_text(row["active_profile"]),
            "as_of": int(row["as_of"]),
            "unused_threshold_days": int(row["unused_threshold_days"]),
            "inventory": json.loads(row["inventory_json"]),
            "engine_versions": _stored_json(row["engine_versions_json"]),
            "template_versions": _stored_json(row["template_versions_json"]),
            "manifest_version": row["manifest_version"],
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
            "completed_at": row["completed_at"],
            "canonical_digest": row["canonical_digest"],
            "report": _stored_json(row["report_json"]) if row["report_json"] else None,
            "units": [self._row_to_unit_dict(u) for u in units],
            "unit_results": [self._row_to_unit_result_dict(r) for r in results],
        }

    @staticmethod
    def _row_to_unit_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "run_id": row["run_id"],
            "unit_kind": row["unit_kind"],
            "unit_id": _stored_text(row["unit_identity"]),
            "unit_control_id": row["unit_id"],
            "sort_order": int(row["sort_order"]),
            "status": row["status"],
            "coverage": row["coverage"],
            "stable": bool(row["stable"]),
            "fingerprint_digest": _stored_digest(row["fingerprint_digest"]) if row["fingerprint_digest"] else None,
            "manifest_version": row["manifest_version"],
            "manifest": _stored_json(row["manifest_json"]) if row["manifest_json"] else None,
            "evidence_cache_key": row["evidence_cache_key"],
            "evidence": _stored_json(row["evidence_json"]) if row["evidence_json"] else None,
            "updated_at": int(row["updated_at"]),
        }

    @staticmethod
    def _row_to_unit_result_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "run_id": row["run_id"],
            "unit_kind": row["unit_kind"],
            "unit_id": _stored_text(row["unit_identity"]),
            "unit_control_id": row["unit_id"],
            "component_id": row["component_id"],
            "derived_cache_key": row["derived_cache_key"],
            "as_of": int(row["as_of"]),
            "unused_threshold_days": int(row["unused_threshold_days"]),
            "coverage": row["coverage"],
            "classification": row["classification"],
            "findings": _stored_json(row["findings_json"]),
            "envelope": _stored_json(row["envelope_json"]),
            "updated_at": int(row["updated_at"]),
        }

    @using_store_key
    def commit_unit_result(
        self,
        *,
        run_id: str,
        unit_kind: str,
        unit_id: str,
        manifest: Mapping[str, Any],
        evidence: Mapping[str, Any],
        component_results: Sequence[Mapping[str, Any]] = (),
        sort_order: int = 0,
    ) -> dict[str, Any]:
        """Atomically commit a unit's fingerprint manifest, time-independent evidence, and component results (§4, §12)."""
        now = int(time.time())
        stable = manifest.get("stable") is True
        adapted_results = [
            adapt_component_result(c, component_id=c.get("component_id", "default"))
            for c in component_results
        ]
        component_ids = [c["component_id"] for c in adapted_results]
        if len(set(component_ids)) != len(component_ids):
            raise ValueError("Duplicate component identity")

        coverages = [
            normalize_coverage(manifest.get("coverage", COVERAGE_COULD_NOT_VERIFY)),
            normalize_coverage(evidence.get("coverage", COVERAGE_COULD_NOT_VERIFY)),
            *(c["coverage"] for c in adapted_results),
        ]
        fp_digest = manifest.get("unit_digest") or ""
        m_version = str(manifest.get("manifest_version") or FINGERPRINT_MANIFEST_VERSION)

        if stable and fp_digest and all(c == COVERAGE_VERIFIED for c in coverages):
            unit_status = "completed"
            unit_cov = COVERAGE_VERIFIED
            ev_key: str | None = compute_evidence_cache_key(
                unit_kind=unit_kind, unit_id=unit_id, fingerprint_digest=fp_digest, manifest_version=m_version
            )
        else:
            unit_status, unit_cov, ev_key = "incomplete", COVERAGE_COULD_NOT_VERIFY, None

        clean_evidence = facts_dto({k: v for k, v in evidence.items() if k != "age_evaluation"})
        manifest_json = _dto_json(serialize_evidence(manifest_dto(manifest)), sort_keys=True)
        evidence_json = _dto_json(serialize_evidence(clean_evidence), sort_keys=True)
        ctrl_id = control_digest(unit_id)
        unit_identity = _source_text(unit_id)

        with closing(self._connect()) as conn:
            run_row = self._require_run_row(conn, run_id)
            if _missing_unit_requirements(run_row, unit_kind, ctrl_id, component_ids, evidence):
                unit_status, unit_cov, ev_key = "incomplete", COVERAGE_COULD_NOT_VERIFY, None

            with conn:
                _upsert_unit_snapshot(
                    conn,
                    (
                        run_id, unit_kind, ctrl_id, unit_identity, sort_order,
                        unit_status, unit_cov, 1 if stable else 0,
                        _source_text(fp_digest) if fp_digest else None,
                        _manifest_version(m_version), manifest_json, ev_key, evidence_json, now,
                    ),
                )
                _sync_evidence_cache(
                    conn, unit_kind, unit_id, ctrl_id, unit_identity, fp_digest,
                    m_version, unit_cov, stable, ev_key, manifest_json, evidence_json, now,
                )
                _store_component_results(
                    conn, run_id, unit_kind, unit_id, ctrl_id, unit_identity,
                    unit_cov, stable, ev_key, adapted_results, run_row, now,
                )
                conn.execute("UPDATE audit_runs SET updated_at = ? WHERE run_id = ?", (now, run_id))

        return {
            "unit_kind": unit_kind,
            "unit_id": unit_id,
            "status": unit_status,
            "coverage": unit_cov,
            "stable": stable,
            "fingerprint_digest": serialize_evidence(fp_digest),
            "evidence_cache_key": ev_key,
        }

    @using_store_key
    def get_cached_evidence(
        self,
        *,
        unit_kind: str,
        unit_id: str,
        fingerprint_digest: str,
        manifest_version: str = FINGERPRINT_MANIFEST_VERSION,
    ) -> dict[str, Any] | None:
        """Look up cached time-independent evidence by fingerprint digest (§4, §12)."""
        ev_key = compute_evidence_cache_key(
            unit_kind=unit_kind, unit_id=unit_id,
            fingerprint_digest=fingerprint_digest, manifest_version=manifest_version,
        )
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM audit_evidence_cache WHERE evidence_cache_key = ?", (ev_key,)
            ).fetchone()
        if row is None:
            return None
        return {
            "evidence_cache_key": row["evidence_cache_key"],
            "unit_kind": row["unit_kind"],
            "unit_id": _stored_text(row["unit_identity"]),
            "unit_control_id": row["unit_id"],
            "fingerprint_digest": _stored_digest(row["fingerprint_digest"]) if row["fingerprint_digest"] else None,
            "manifest_version": row["manifest_version"],
            "manifest": _stored_json(row["manifest_json"]),
            "evidence": _stored_json(row["evidence_json"]),
        }

    @using_store_key
    def evaluate_unit_from_evidence(
        self,
        *,
        evidence: Mapping[str, Any],
        as_of: int | float,
        unused_threshold_days: int = 90,
    ) -> dict[str, Any]:
        """Re-evaluate age-derived findings from time-independent evidence against `(as_of, unused_threshold_days)` (§12)."""
        ev_copy = dict(evidence)
        if ev_copy.get("unit_kind") == "profile":
            ev_copy["age_evaluation"] = evaluate_profile_age_and_unused(
                profile_name=str(ev_copy["name"]),
                is_default=bool(ev_copy.get("is_default")),
                is_active=bool(ev_copy.get("is_active")),
                last_use_evidence=ev_copy.get("last_use_evidence") or {},
                as_of=as_of,
                unused_threshold_days=unused_threshold_days,
            )
        return ev_copy

    @using_store_key
    def cancel_run(self, run_id: str) -> dict[str, Any]:
        """Cancel a running audit at a safe boundary, preserving already-committed unit results (§4)."""
        now = int(time.time())
        with closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "UPDATE audit_runs SET status = 'cancelled', updated_at = ? WHERE run_id = ?",
                (now, run_id),
            )
            if cur.rowcount == 0:
                raise KeyError(f"Unknown audit run_id: {run_id!r}")
        return self.get_run(run_id)  # type: ignore[return-value]

    @using_store_key
    def resume_run(
        self,
        run_id: str,
        *,
        current_unit_digests: Mapping[tuple[str, str], str | None],
        current_engine_versions: Mapping[str, str] | None = None,
        current_template_versions: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Resume a cancelled/interrupted run after a user click (§4, §12)."""
        now = int(time.time())
        with closing(self._connect()) as conn:
            run_row = self._require_run_row(conn, run_id)
            if not self.resume_key_available(_stored_json(run_row["inventory_json"])):
                return {"run_id": run_id, "resumable": False, "reason": "audit_key_unavailable"}

            existing_units = conn.execute(
                "SELECT * FROM audit_units WHERE run_id = ? ORDER BY sort_order ASC", (run_id,)
            ).fetchall()
            existing_map = {(str(u["unit_kind"]), str(u["unit_id"])): u for u in existing_units}

            with conn:
                engine_changed, templates_changed = _sync_resume_versions(
                    conn, run_id, run_row, current_engine_versions, current_template_versions
                )
                reused_units, units_to_run, removed_units, any_unit_changed = _reconcile_resume_units(
                    conn, run_id, existing_map, current_unit_digests,
                    engine_changed=engine_changed, templates_changed=templates_changed, now=now,
                )
                conn.execute(
                    "UPDATE audit_runs SET status = 'running', updated_at = ? WHERE run_id = ?",
                    (now, run_id),
                )

        return {
            "run_id": run_id,
            "as_of": int(run_row["as_of"]),
            "reused_units": [{"unit_kind": k, "unit_id": i} for k, i in reused_units],
            "units_to_run": [{"unit_kind": k, "unit_id": i} for k, i in units_to_run],
            "removed_units": [{"unit_kind": k, "unit_id": i} for k, i in removed_units],
            "cross_checks_invalidated": any_unit_changed,
        }

    @using_store_key
    def build_coherent_crosscheck_manifest(self, run_id: str) -> dict[str, Any]:
        """Build a coherent versioned manifest of saved units for system cross-checks (§4)."""
        run_data = self.get_run(run_id)
        if run_data is None:
            raise KeyError(f"Unknown audit run_id: {run_id!r}")

        units = run_data["units"]
        verified_units: list[dict[str, Any]] = []
        missing_or_unfinished: list[dict[str, Any]] = []

        for u in units:
            if (
                u["status"] == "completed"
                and u["stable"]
                and u["fingerprint_digest"]
                and u["manifest_version"] == run_data["manifest_version"]
                and u["evidence"] is not None
            ):
                verified_units.append({
                    "unit_kind": u["unit_kind"],
                    "unit_id": u["unit_id"],
                    "fingerprint_digest": u["fingerprint_digest"],
                    "coverage": u["coverage"],
                    "manifest": u["manifest"],
                    "evidence": self.evaluate_unit_from_evidence(
                        evidence=u["evidence"],
                        as_of=run_data["as_of"],
                        unused_threshold_days=run_data["unused_threshold_days"],
                    ),
                })
            else:
                missing_or_unfinished.append({
                    "unit_kind": u["unit_kind"],
                    "unit_id": u["unit_id"],
                    "status": u["status"],
                    "stable": u["stable"],
                    "coverage": COVERAGE_COULD_NOT_VERIFY,
                })

        coherent_complete = not missing_or_unfinished and len(verified_units) == len(units)
        coverage = (
            COVERAGE_VERIFIED
            if coherent_complete and all(u["coverage"] == COVERAGE_VERIFIED for u in verified_units)
            else COVERAGE_COULD_NOT_VERIFY
        )
        manifest_digest = hashlib.sha256(
            _dto_json(
                {
                    "manifest_version": run_data["manifest_version"],
                    "ownership_manifest_version": OWNERSHIP_MANIFEST_VERSION,
                    "units": [(u["unit_kind"], u["unit_id"], u["fingerprint_digest"]) for u in verified_units],
                    "missing": [(m["unit_kind"], m["unit_id"], m["status"]) for m in missing_or_unfinished],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        return {
            "run_id": run_id,
            "as_of": run_data["as_of"],
            "manifest_version": run_data["manifest_version"],
            "coherent_complete": coherent_complete,
            "coverage": coverage,
            "manifest_digest": manifest_digest,
            "verified_units": verified_units,
            "missing_or_unfinished_units": missing_or_unfinished,
        }

    def _summarize_run_for_finalization(
        self,
        run_data: Mapping[str, Any],
        extra_findings: Sequence[Mapping[str, Any]],
    ) -> tuple[list[Mapping[str, Any]], list[dict[str, Any]], int]:
        all_findings: list[Mapping[str, Any]] = [finding_dto(f) for f in extra_findings]
        for ur in run_data["unit_results"]:
            all_findings.extend(ur["findings"])

        incomplete_count = 1 if run_data["status"] in ("cancelled", "failed") else 0
        present = {(u["unit_kind"], u["unit_control_id"]) for u in run_data["units"]}
        results = {(r["unit_kind"], r["unit_control_id"], r["component_id"]) for r in run_data["unit_results"]}
        for required in run_data["inventory"].get("required_checks", []):
            key = (required["unit_kind"], required["unit_id"])
            if key not in present or any((*key, c) not in results for c in required.get("components", [])):
                incomplete_count += 1

        units_summary: list[dict[str, Any]] = []
        for u in run_data["units"]:
            if u["status"] != "completed" or not u["stable"]:
                incomplete_count += 1
            ev = (
                self.evaluate_unit_from_evidence(
                    evidence=u["evidence"],
                    as_of=run_data["as_of"],
                    unused_threshold_days=run_data["unused_threshold_days"],
                )
                if u["evidence"] is not None
                else None
            )
            units_summary.append({
                "unit_kind": u["unit_kind"],
                "unit_id": u["unit_id"],
                "status": u["status"],
                "coverage": u["coverage"],
                "stable": u["stable"],
                "fingerprint_digest": u["fingerprint_digest"],
                "age_evaluation": ev.get("age_evaluation") if isinstance(ev, Mapping) else None,
            })
        return all_findings, units_summary, incomplete_count

    @using_store_key
    def finalize_run(
        self,
        run_id: str,
        *,
        extra_findings: Sequence[Mapping[str, Any]] = (),
        outward: Mapping[str, Any] | None = None,
        context_load: Mapping[str, Any] | None = None,
        measurements: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compute the canonical report, headline, and digest for `run_id` and mark it completed (§4, §6)."""
        run_data = self.get_run(run_id)
        if run_data is None:
            raise KeyError(f"Unknown audit run_id: {run_id!r}")

        all_findings, units_summary, incomplete_count = self._summarize_run_for_finalization(
            run_data, extra_findings
        )
        headline = compute_headline(
            findings=all_findings,
            unit_coverages=[u["coverage"] for u in units_summary] + [r["coverage"] for r in run_data["unit_results"]],
            incomplete_units=incomplete_count,
        )
        canonical_payload = canonical_report_payload(
            as_of=run_data["as_of"], mode=run_data["mode"], optional_root=run_data["optional_root"],
            active_profile=run_data["active_profile"], unused_threshold_days=run_data["unused_threshold_days"],
            rule_versions=run_data["engine_versions"], template_versions=run_data["template_versions"],
            units=units_summary, findings=all_findings, headline=headline,
        )
        _attach_scope_and_outward(canonical_payload, run_data["mode"], outward, context_load)
        for name in ('skill_hygiene', 'write_settings', 'session_contamination', *WIRED_SECTIONS):
            if measurements is not None and name in measurements:
                canonical_payload[name] = measurements[name]

        # Complete report boundary, not an outward-section filter.
        canonical_payload = serialize_evidence(canonical_payload)
        assert isinstance(canonical_payload, dict)
        report_digest = canonical_report_digest(canonical_payload)
        now = int(time.time())

        with closing(self._connect()) as conn, conn:
            conn.execute(
                """
                UPDATE audit_runs
                SET status = 'completed', completed_at = ?, updated_at = ?,
                    canonical_digest = ?, report_json = ?
                WHERE run_id = ?
                """,
                (now, now, report_digest, PersistedJSON(canonical_report_bytes(canonical_payload).decode("utf-8")), run_id),
            )

        return {
            "run_id": run_id, "status": "completed", "as_of": run_data["as_of"],
            "canonical_digest": report_digest, "report": canonical_payload,
        }

    @using_store_key
    def record_cleanup_proposal(
        self, *, cleanup_id: str, run_id: str, fix_type: str, target_identity: str,
        fingerprint_digest: str, plan: Mapping[str, Any], selected: bool = False,
    ) -> dict[str, Any]:
        """Persist a proposed cleanup item (always unticked `selected=False` by default per §8, §13.5)."""
        now = int(time.time())
        plan_str = _dto_json({"plan_digest": digest(plan), "execution_supported": False}, sort_keys=True)
        with closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO audit_cleanup_approvals (
                    cleanup_id, run_id, fix_type, target_identity,
                    fingerprint_digest, selected, approved, plan_json,
                    outcome_status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 'proposed', ?, ?)
                ON CONFLICT(cleanup_id) DO UPDATE SET
                    fingerprint_digest = excluded.fingerprint_digest,
                    selected = excluded.selected,
                    plan_json = excluded.plan_json,
                    updated_at = excluded.updated_at
                """,
                (
                    cleanup_id, run_id, _source_text(fix_type), _source_text(target_identity),
                    _source_text(fingerprint_digest), 1 if selected else 0, plan_str, now, now,
                ),
            )
        return self.get_cleanup_proposal(cleanup_id)  # type: ignore[return-value]

    @using_store_key
    def get_cleanup_proposal(self, cleanup_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM audit_cleanup_approvals WHERE cleanup_id = ?", (cleanup_id,)
            ).fetchone()
        if row is None:
            return None
        return {
            "cleanup_id": row["cleanup_id"],
            "run_id": row["run_id"],
            "fix_type": row["fix_type"],
            "target_identity": row["target_identity"],
            "fingerprint_digest": _stored_digest(row["fingerprint_digest"]) if row["fingerprint_digest"] else None,
            "selected": bool(row["selected"]),
            "approved": bool(row["approved"]),
            "plan": json.loads(row["plan_json"]),
            "backup_path": row["backup_path"],
            "backup_verified": bool(row["backup_verified"]),
            "outcome_status": row["outcome_status"],
            "outcome_detail": row["outcome_detail"],
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
        }
