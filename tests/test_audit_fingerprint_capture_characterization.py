"""Characterization tests for fingerprint, capture, identity and readonly_db."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from tests import ensure_test_package
from tests.conftest import load_submodule

ensure_test_package()

from hermes_plugins.defuzz.audit import (  # type: ignore[import-not-found] # noqa: E402
    capture,
    evidence,
    fingerprint,
    identity,
    key,
    readonly_db,
)
from hermes_plugins.defuzz.audit.contract import (  # type: ignore[import-not-found] # noqa: E402
    CLASSIFICATION_INFO,
    CLASSIFICATION_REVIEW,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
)


def test_fingerprint_mode_and_path_helpers() -> None:
    assert fingerprint.classify_mode(stat.S_IFREG | 0o644) == "regular"
    assert fingerprint.classify_mode(stat.S_IFLNK | 0o777) == "symlink"
    assert fingerprint.classify_mode(stat.S_IFDIR | 0o755) == "directory"
    assert fingerprint.classify_mode(stat.S_IFIFO | 0o600) == "fifo"
    assert fingerprint.classify_mode(stat.S_IFSOCK | 0o600) == "socket"
    assert fingerprint.classify_mode(stat.S_IFCHR | 0o600) == "char_device"
    assert fingerprint.classify_mode(stat.S_IFBLK | 0o600) == "block_device"
    assert fingerprint.classify_mode(0) == "special"

    assert fingerprint._normalize_rel_parts("") == (".", ())
    assert fingerprint._normalize_rel_parts(".") == (".", ())
    assert fingerprint._normalize_rel_parts("a\\b/./c") == ("a/b/c", ("a", "b", "c"))
    with pytest.raises(ValueError, match="must not be absolute"):
        fingerprint._normalize_rel_parts("/etc/passwd")
    with pytest.raises(ValueError, match="escapes root"):
        fingerprint._normalize_rel_parts("a/../b")


def test_fingerprint_classify_profile_root_entry() -> None:
    for name in ("memories", "skills", "config.yaml", "SOUL.md"):
        assert fingerprint.classify_profile_root_entry(name) == "config_match"
    for name in ("sessions", "state.db", "auth.json.bak", ".env.bak.1", "config.yaml.bak", "config.yaml.corrupt"):
        assert fingerprint.classify_profile_root_entry(name) == "profile_owned"
    for name in ("hermes-agent", "models", "cache", "profiles", "venvs"):
        assert fingerprint.classify_profile_root_entry(name, is_default_profile=True) == "shared_infrastructure"
    assert fingerprint.classify_profile_root_entry("custom_unknown_item") == "unclassified"


def test_safe_read_regular_file_variants_and_symlink_resolution(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    db_path = tmp_path / "store" / "audit.db"

    with key.key_scope(db_path):
        # Root directory target
        root_res = fingerprint.safe_read_regular_file(root, ".")
        assert root_res.kind == "directory"
        assert root_res.coverage == COVERAGE_COULD_NOT_VERIFY
        assert root_res.stable is True

        # Missing file
        missing_res = fingerprint.safe_read_regular_file(root, "does_not_exist.txt")
        assert missing_res.kind == "missing"
        assert missing_res.coverage == COVERAGE_VERIFIED
        assert missing_res.stable is True

        # Escaped path
        esc_res = fingerprint.safe_read_regular_file(root, "../outside.txt")
        assert esc_res.kind == "escaped"
        assert esc_res.coverage == COVERAGE_COULD_NOT_VERIFY
        assert esc_res.stable is False

        # Credential excluded path
        cred_file = root / "auth.json"
        cred_file.write_text("{}", encoding="utf-8")
        cred_res = fingerprint.safe_read_regular_file(root, "auth.json")
        assert cred_res.kind == "excluded"
        assert cred_res.coverage == "not_included"
        assert cred_res.stable is True

        # Regular file + to_dict(include_content=True/False)
        hello = root / "hello.txt"
        hello.write_bytes(b"hello world")
        reg_res = fingerprint.safe_read_regular_file(root, "hello.txt")
        assert reg_res.kind == "regular"
        assert reg_res.coverage == COVERAGE_VERIFIED
        assert reg_res.stable is True
        assert reg_res.content == b"hello world"
        assert reg_res.sha256 == key.content_digest(hashlib.sha256(b"hello world").hexdigest())
        d_no_content = reg_res.to_dict(include_content=False)
        assert "content_utf8" not in d_no_content
        d_with_content = reg_res.to_dict(include_content=True)
        assert d_with_content["content_utf8"] == "hello world"

        # Plain reader returns unkeyed sha256
        plain_res = fingerprint.safe_read_regular_file_plain(root, "hello.txt")
        assert plain_res.sha256 == hashlib.sha256(b"hello world").hexdigest()

        # Permitted symlink resolution (relative inside allowed_roots)
        sub = root / "sub"
        sub.mkdir()
        rel_link = sub / "link.txt"
        rel_link.symlink_to("../hello.txt")
        link_meta = fingerprint.safe_read_regular_file(root, "sub/link.txt")
        assert link_meta.kind == "symlink"
        assert link_meta.symlink_target == "../hello.txt"

        resolved_ok = fingerprint.resolve_permitted_symlink_target(
            link_root=root,
            link_rel_path="sub/link.txt",
            raw_target="../hello.txt",
            allowed_roots=[root],
        )
        assert resolved_ok.kind == "regular"
        assert resolved_ok.coverage == COVERAGE_VERIFIED
        assert resolved_ok.content == b"hello world"


def test_tree_fingerprint_manifest_project_and_profile_behaviors(tmp_path: Path) -> None:
    db_path = tmp_path / "store" / "audit.db"
    proj = tmp_path / "proj"
    (proj / ".git" / "objects").mkdir(parents=True)
    (proj / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (proj / "src").mkdir()
    (proj / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")

    with key.key_scope(db_path):
        proj_fp = fingerprint.build_tree_fingerprint_manifest(
            unit_kind="project",
            unit_id="proj-1",
            root_path=proj,
            expected_rel_paths=["src/app.py", "README.md"],
            excluded_rel_paths=["ignored.txt"],
        )
        assert proj_fp.coverage == COVERAGE_VERIFIED
        assert proj_fp.stable is True
        assert proj_fp.directories[".git"] == ["<git_metadata>"]
        assert "src/app.py" in proj_fp.files
        assert proj_fp.absent_expected_paths == ["README.md"]
        proj_dict = proj_fp.to_dict()
        assert proj_dict["unit_digest"] == proj_fp.unit_digest

        # Entry budget exceeded marks could_not_verify
        budget_fp = fingerprint.build_tree_fingerprint_manifest(
            unit_kind="project",
            unit_id="proj-1",
            root_path=proj,
            max_entries=1,
        )
        assert budget_fp.coverage == COVERAGE_COULD_NOT_VERIFY
        assert any("Directory entry limit" in p["error"] for p in budget_fp.unreadable_paths)


def test_capture_budget_and_coherent_profile_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "store" / "audit.db"
    prof = tmp_path / "prof"
    (prof / "memories").mkdir(parents=True)
    (prof / "config.yaml").write_text("model: test\n", encoding="utf-8")
    (prof / "memories" / "MEMORY.md").write_text("note\n", encoding="utf-8")

    with key.key_scope(db_path):
        # Capture byte limit exceedance (>64 MiB simulated)
        cap = capture.Capture()
        cap.total_bytes = 64 * 1024 * 1024
        res = cap.read(fingerprint._safe_read_regular_file, prof, "config.yaml")
        assert cap.exceeded is True
        assert res.coverage == COVERAGE_COULD_NOT_VERIFY
        assert res.stable is False
        assert res.content is None
        assert res.sha256 is None

        # Coherent profile capture happy path
        @capture.coherent_profile_capture
        def _dummy_collect(**kwargs):
            r = Path(kwargs["profile_dir"])
            m = fingerprint.build_tree_fingerprint_manifest(
                unit_kind="profile",
                unit_id=kwargs["profile_name"],
                root_path=r,
            )
            reg = readonly_db.read_profile_registrations_readonly(kwargs["profile_name"], r)
            return {
                "coverage": COVERAGE_VERIFIED,
                "stable": True,
                "fingerprint_manifest": m.to_dict(),
                "registrations_snapshot": reg.to_dict(),
            }

        out = _dummy_collect(profile_name="default", profile_dir=prof)
        assert out["coverage"] == COVERAGE_VERIFIED
        assert out["stable"] is True
        assert out["capture_policy"] == "optimistic-revalidated-v2; not globally atomic"
        assert "engine_identity" in out["fingerprint_manifest"]

        # Regression: engine artifact mutating during post-capture revalidation must invalidate capture
        fake_root = tmp_path / "plugin_reval"
        (fake_root / "audit" / "vendor").mkdir(parents=True)
        (fake_root / "audit" / "identity.py").write_text("# id\n", encoding="utf-8")
        (fake_root / "audit" / "vendor" / "provenance.json").write_text("{}\n", encoding="utf-8")
        artifact = fake_root / "audit" / "helper.py"
        artifact.write_text("# BEFORE\n", encoding="utf-8")
        monkeypatch.setattr(identity, "__file__", str(fake_root / "audit" / "identity.py"))

        real_build = fingerprint.build_tree_fingerprint_manifest

        def _revalidation_mutates_engine(**kwargs):
            manifest = real_build(**kwargs)
            if capture.CURRENT_CAPTURE.get() is None:
                artifact.write_text("# AFTER\n", encoding="utf-8")
            return manifest

        monkeypatch.setattr(fingerprint, "build_tree_fingerprint_manifest", _revalidation_mutates_engine)
        mutated_out = _dummy_collect(profile_name="default", profile_dir=prof)
        assert mutated_out["coverage"] == COVERAGE_COULD_NOT_VERIFY
        assert mutated_out["stable"] is False
        assert mutated_out["fingerprint_manifest"]["coverage"] == COVERAGE_COULD_NOT_VERIFY
        assert mutated_out["fingerprint_manifest"]["stable"] is False
        assert mutated_out["fingerprint_manifest"]["whole_profile_exact_eligible"] is False
        assert mutated_out["fingerprint_manifest"]["whole_profile_digest"] is None


def test_identity_digest_and_engine_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d1 = identity.digest({"b": 1, "a": 2})
    d2 = identity.digest({"a": 2, "b": 1})
    assert isinstance(d1, evidence.GeneratedDigest)
    assert d1 == d2

    fake_root = tmp_path / "plugin"
    (fake_root / "audit" / "vendor").mkdir(parents=True)
    (fake_root / "audit" / "identity.py").write_text("# id\n", encoding="utf-8")
    (fake_root / "audit" / "vendor" / "provenance.json").write_text("{}\n", encoding="utf-8")
    (fake_root / "templates" / "demo").mkdir(parents=True)
    (fake_root / "templates" / "demo" / "README.md").write_text("demo\n", encoding="utf-8")

    monkeypatch.setattr(identity, "__file__", str(fake_root / "audit" / "identity.py"))
    info = identity.engine_identity()
    assert isinstance(info["engine_digest"], evidence.GeneratedDigest)
    assert isinstance(info["template_digest"], evidence.GeneratedDigest)
    assert info["parser"].startswith("PyYAML:")
    assert info["parser_policy"] == "safe-load-json-v2"
    assert info["persistence_policy"] == "allowlist-v2"


def test_readonly_db_sessions_registrations_and_union(tmp_path: Path) -> None:
    # 1. Session DB with human + worker sessions
    sess_db = tmp_path / "state.db"
    with contextlib.closing(sqlite3.connect(sess_db)) as conn:
        with conn:
            conn.execute(
                "CREATE TABLE sessions ("
                "id TEXT PRIMARY KEY, started_at REAL, source TEXT, title TEXT, "
                "last_activity_at REAL, message_count INTEGER)"
            )
            conn.execute(
                "INSERT INTO sessions VALUES ('w1', 200.0, 'subagent', 'Worker task', 210.0, 3)"
            )
            conn.execute(
                "INSERT INTO sessions VALUES ('h1', 150.0, 'cli', 'Human chat', 180.0, 5)"
            )

    ev = readonly_db.read_profile_session_evidence(sess_db)
    assert ev.exists is True
    assert ev.coverage == COVERAGE_VERIFIED
    assert ev.newest_started_at == 200.0
    assert ev.newest_session_id == "w1"
    assert ev.session_count == 2
    assert ev.newest_worker_session is not None and ev.newest_worker_session["id"] == "w1"
    assert ev.newest_human_session is not None and ev.newest_human_session["id"] == "h1"
    assert ev.to_dict()["row_digest"] == ev.row_digest

    # 2. JSON helper edge cases
    assert readonly_db._parse_json_list(None) == []
    assert readonly_db._parse_json_list(["a", 1]) == ["a", "1"]
    assert readonly_db._parse_json_list('["py", "rs"]') == ["py", "rs"]
    assert readonly_db._parse_json_list("plain-str") == ["plain-str"]
    assert readonly_db._parse_json_list(42) == ["42"]

    assert readonly_db._parse_json_dict(None) is None
    assert readonly_db._parse_json_dict({"k": "v"}) == {"k": "v"}
    assert readonly_db._parse_json_dict('{"k": "v"}') == {"k": "v"}
    assert readonly_db._parse_json_dict("[1, 2]") is None
    assert readonly_db._parse_json_dict("invalid-json") is None

    # 3. Registrations DB with fallback columns (substituted_prefix, locked_hashes_json)
    reg_db = tmp_path / "reg_state.db"
    proj_path = str((tmp_path / "my_proj").resolve())
    with contextlib.closing(sqlite3.connect(reg_db)) as conn:
        with conn:
            conn.execute(
                "CREATE TABLE projects ("
                "path TEXT PRIMARY KEY, name TEXT, slug TEXT, template_id TEXT, "
                "languages TEXT, substituted_prefix TEXT, locked_hashes_json TEXT, created_at INTEGER)"
            )
            conn.execute(
                "INSERT INTO projects VALUES (?, 'MyProj', 'my-proj', 'python-golden', ?, 'my_prefix', ?, 1700000000)",
                (proj_path, '["python"]', '{"README.md": "abc"}'),
            )

    snap = readonly_db.read_profile_registrations_readonly("default", tmp_path, db_path=reg_db)
    assert snap.exists is True
    assert snap.coverage == COVERAGE_VERIFIED
    assert len(snap.records) == 1
    rec = snap.records[0]
    assert rec["prefix"] == "my_prefix"
    assert rec["locked_hashes"] == {"README.md": "abc"}
    assert rec["languages"] == ["python"]

    # 4. Union with unreadable snapshot + valid snapshot
    bad_snap = readonly_db.ProfileRegistrationsSnapshot(
        profile_name="broken",
        db_path=str(tmp_path / "broken.db"),
        exists=True,
        coverage=COVERAGE_COULD_NOT_VERIFY,
        error="disk error",
    )
    unioned = readonly_db.union_profile_registrations([snap, bad_snap])
    assert unioned["coverage"] == COVERAGE_COULD_NOT_VERIFY
    assert len(unioned["project_units"]) == 1
    assert any(f["id"] == "inventory.registration_db_unreadable" for f in unioned["findings"])
    assert any(f["classification"] == CLASSIFICATION_INFO for f in unioned["findings"])
    assert CLASSIFICATION_REVIEW != CLASSIFICATION_INFO
    assert load_submodule("audit.readonly_db") is not None
