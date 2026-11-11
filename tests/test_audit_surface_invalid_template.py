"""Regression tests for audit_surface sweep resilience when a template.yaml is invalid."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import audit_surface, templates as _templates  # noqa: E402
from hermes_plugins.defuzz.audit import contract as _contract  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.audit.contract import (  # noqa: E402
    CLASSIFICATION_INFO,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
)
from hermes_plugins.defuzz.audit.key import key_scope  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.audit.policy import credential_declarations, credential_path  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.audit.redaction import redaction_scope  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.audit.store import AuditStore, _component_control_id as store_component_control_id  # noqa: E402
from hermes_plugins.defuzz.audit.vendor import template_drift  # noqa: E402
from hermes_plugins.defuzz.templates import load_template, load_templates  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


def _build_registered_project_bundle(template_id: str, prefix: str = "my_service") -> dict:
    """Build a substituted project bundle from the real template in templates/<template_id>."""
    spec = load_template(REPO_ROOT / "templates" / template_id)
    repo_root = spec.root / spec.repos[0].name
    raw_template_files: dict[str, bytes] = {}
    for path in sorted(repo_root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(repo_root).as_posix()
            raw_template_files[rel] = path.read_bytes()

    substituted = template_drift.compute_substituted_template_baseline(
        template_files=raw_template_files,
        placeholder=spec.placeholder,
        prefix=prefix,
        substitute_in=spec.substitute_in,
        locked_globs=spec.locked,
    )
    project_files = {
        rel: info["content"]
        for rel, info in substituted["files"].items()
        if isinstance(info.get("content"), bytes)
    }
    locked_hashes = {
        rel: hashlib.sha256(project_files[rel]).hexdigest()
        for rel in substituted["locked_hashes"]
        if rel in project_files
    }
    provenance = {
        "path": f"/tmp/projects/{template_id}-service",
        "canonical_path": f"/tmp/projects/{template_id}-service",
        "template_id": spec.id,
        "plugin_commit": "4a7007e000000000000000000000000000000000",
        "prefix": prefix,
        "locked_hashes": locked_hashes,
    }
    return {
        "spec": spec,
        "project_files": project_files,
        "provenance": provenance,
    }


def _populate_project_tree(project_dir: Path, bundle: dict) -> None:
    for rel, content in bundle["project_files"].items():
        dest = project_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
    (project_dir / "TOOLS.lock").write_text("[lock]\nschema = 1\n", encoding="utf-8")
    (project_dir / ".git").mkdir(parents=True, exist_ok=True)
    (project_dir / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")


def _register_projects(db_path: Path, entries: list[tuple[Path, str, str, dict]]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS projects ("
            "path TEXT PRIMARY KEY, name TEXT, slug TEXT, template_id TEXT, "
            "prefix TEXT, plugin_commit TEXT, locked_hashes_json TEXT)"
        )
        for project_dir, name, template_id, bundle in entries:
            conn.execute(
                "INSERT INTO projects VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(project_dir),
                    name,
                    bundle["provenance"]["prefix"],
                    template_id,
                    bundle["provenance"]["prefix"],
                    bundle["provenance"]["plugin_commit"],
                    json.dumps(bundle["provenance"]["locked_hashes"]),
                ),
            )


class TestAuditSurfaceInvalidTemplate(unittest.TestCase):
    def test_invalid_go_template_does_not_crash_full_audit_and_leaves_rust_project_unaffected(self) -> None:
        """Full audit with invalid go-golden/template.yaml + registered go and rust projects completes; go is could_not_verify and rust matches valid registry."""
        go_bundle = _build_registered_project_bundle("go-golden")
        rust_bundle = _build_registered_project_bundle("rust-golden")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            home = tmp_path / "home"
            profile = home / ".hermes"
            profile.mkdir(parents=True)
            (profile / "config.yaml").write_text("{}\n", encoding="utf-8")

            go_dir = (home / "projects" / "go-service").resolve()
            rust_dir = (home / "projects" / "rust-service").resolve()
            _populate_project_tree(go_dir, go_bundle)
            _populate_project_tree(rust_dir, rust_bundle)

            reg_db = profile / "plugin-data" / "defuzz" / "state.db"
            _register_projects(
                reg_db,
                [
                    (go_dir, "go-service", "go-golden", go_bundle),
                    (rust_dir, "rust-service", "rust-golden", rust_bundle),
                ],
            )

            valid_templates = tmp_path / "templates_valid"
            broken_templates = tmp_path / "templates_broken"
            shutil.copytree(REPO_ROOT / "templates", valid_templates)
            shutil.copytree(REPO_ROOT / "templates", broken_templates)
            (broken_templates / "go-golden" / "template.yaml").write_text(
                "id: [unclosed yaml\n", encoding="utf-8"
            )

            env = {
                "HOME": str(home),
                "HERMES_HOME": str(profile),
                "HERMES_PROFILE": "default",
            }
            valid_audit_db = tmp_path / "store_valid" / "audit.db"
            broken_audit_db = tmp_path / "store_broken" / "audit.db"

            with mock.patch.dict(os.environ, env), mock.patch.object(
                _templates, "templates_root", return_value=valid_templates
            ):
                valid_res = audit_surface.execute_audit(
                    {
                        "action": "run",
                        "as_of": 1700000000,
                        "selected_projects": [str(go_dir), str(rust_dir)],
                    },
                    db_path=valid_audit_db,
                    wait=True,
                )

            with mock.patch.dict(os.environ, env), mock.patch.object(
                _templates, "templates_root", return_value=broken_templates
            ):
                broken_res = audit_surface.execute_audit(
                    {
                        "action": "run",
                        "as_of": 1700000000,
                        "selected_projects": [str(go_dir), str(rust_dir)],
                    },
                    db_path=broken_audit_db,
                    wait=True,
                )

            self.assertEqual(valid_res["status"], "completed")
            self.assertEqual(broken_res["status"], "completed")
            self.assertEqual(broken_res["report"]["headline"]["coverage"], COVERAGE_COULD_NOT_VERIFY)
            self.assertFalse(broken_res["report"]["headline"]["can_claim_clean"])

            valid_store = AuditStore(valid_audit_db)
            broken_store = AuditStore(broken_audit_db)
            valid_run = valid_store.get_run(valid_res["run_id"])
            broken_run = broken_store.get_run(broken_res["run_id"])
            assert valid_run is not None and broken_run is not None

            broken_units_by_id = {u["unit_id"]: u for u in broken_run["units"]}
            valid_units_by_id = {u["unit_id"]: u for u in valid_run["units"]}

            go_unit = broken_units_by_id[str(go_dir)]
            self.assertEqual(go_unit["coverage"], COVERAGE_COULD_NOT_VERIFY)
            self.assertEqual(go_unit["status"], "incomplete")

            rust_unit_broken = broken_units_by_id[str(rust_dir)]
            rust_unit_valid = valid_units_by_id[str(rust_dir)]
            self.assertTrue(rust_unit_broken["stable"])
            self.assertEqual(rust_unit_broken["status"], rust_unit_valid["status"])
            self.assertEqual(rust_unit_broken["coverage"], rust_unit_valid["coverage"])
            self.assertEqual(rust_unit_broken["manifest"]["coverage"], COVERAGE_VERIFIED)
            self.assertEqual(
                rust_unit_broken["manifest"]["coverage"],
                rust_unit_valid["manifest"]["coverage"],
            )

            def _comp_ids(db_path: Path) -> tuple[str, str, str]:
                with key_scope(db_path):
                    return (
                        store_component_control_id("template_drift"),
                        store_component_control_id("static_code"),
                        store_component_control_id("tools_lock"),
                    )

            valid_td_ctrl, valid_sc_ctrl, valid_tl_ctrl = _comp_ids(valid_audit_db)
            broken_td_ctrl, broken_sc_ctrl, broken_tl_ctrl = _comp_ids(broken_audit_db)

            broken_results = {
                (r["unit_id"], r["component_id"]): r for r in broken_run["unit_results"]
            }
            valid_results = {
                (r["unit_id"], r["component_id"]): r for r in valid_run["unit_results"]
            }

            # In the valid registry run, go-service template_drift and static_code have no unverified findings
            self.assertEqual(valid_results[(str(go_dir), valid_td_ctrl)]["classification"], CLASSIFICATION_INFO)
            self.assertEqual(valid_results[(str(go_dir), valid_sc_ctrl)]["classification"], CLASSIFICATION_INFO)
            self.assertEqual(valid_results[(str(go_dir), valid_td_ctrl)]["findings"], [])
            self.assertEqual(valid_results[(str(go_dir), valid_sc_ctrl)]["findings"], [])

            # In the broken registry run, go-service template_drift and static_code are could_not_verify
            go_td = broken_results[(str(go_dir), broken_td_ctrl)]
            go_sc = broken_results[(str(go_dir), broken_sc_ctrl)]
            self.assertEqual(go_td["coverage"], COVERAGE_COULD_NOT_VERIFY)
            self.assertEqual(go_sc["coverage"], COVERAGE_COULD_NOT_VERIFY)
            go_td_ids = {f["id"] for f in go_td["findings"]}
            go_sc_ids = {f["id"] for f in go_sc["findings"]}
            self.assertIn("template_drift.unverified", go_td_ids)
            self.assertIn("static_code.unverified", go_sc_ids)
            self.assertNotIn("template.not_included", go_td_ids)
            self.assertNotIn("static_code.not_included", go_sc_ids)
            self.assertTrue(all(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in go_td["findings"]))
            self.assertTrue(all(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in go_sc["findings"]))

            # Meanwhile rust-service is completely unaffected and matches the valid registry run
            for broken_ctrl, valid_ctrl in (
                (broken_td_ctrl, valid_td_ctrl),
                (broken_sc_ctrl, valid_sc_ctrl),
                (broken_tl_ctrl, valid_tl_ctrl),
            ):
                rust_comp_broken = broken_results[(str(rust_dir), broken_ctrl)]
                rust_comp_valid = valid_results[(str(rust_dir), valid_ctrl)]
                self.assertEqual(rust_comp_broken["classification"], CLASSIFICATION_INFO)
                self.assertEqual(rust_comp_broken["coverage"], rust_comp_valid["coverage"])
                self.assertEqual(rust_comp_broken["classification"], rust_comp_valid["classification"])
                self.assertEqual(
                    [(f["id"], f["coverage"], f["classification"]) for f in rust_comp_broken["findings"]],
                    [(f["id"], f["coverage"], f["classification"]) for f in rust_comp_valid["findings"]],
                )

    def test_a05_credential_exclusion_and_valid_registry_opened_paths_unchanged(self) -> None:
        """Verify with os.open wrapper installed after import that valid registry opens identical paths and excluded credential templates are never opened."""
        rust_bundle = _build_registered_project_bundle("rust-golden")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            home = tmp_path / "home"
            profile = home / ".hermes"
            profile.mkdir(parents=True)
            (profile / "config.yaml").write_text("{}\n", encoding="utf-8")

            rust_dir = (home / "projects" / "rust-service").resolve()
            _populate_project_tree(rust_dir, rust_bundle)

            reg_db = profile / "plugin-data" / "defuzz" / "state.db"
            _register_projects(
                reg_db,
                [(rust_dir, "rust-service", "rust-golden", rust_bundle)],
            )

            custom_templates = (tmp_path / "templates").resolve()
            shutil.copytree(REPO_ROOT / "templates", custom_templates)
            cpp_yaml = (custom_templates / "cpp-golden" / "template.yaml").resolve()
            # Declare cpp-golden/template.yaml as credential AND make it invalid YAML
            cpp_yaml.write_text("id: [protected invalid yaml\n", encoding="utf-8")
            (profile / "settings.json").write_text(
                json.dumps({"credential_file": str(cpp_yaml)}),
                encoding="utf-8",
            )

            from hermes_plugins.defuzz.audit.policy import credential_declarations, credential_path
            from hermes_plugins.defuzz.audit.redaction import redaction_scope

            env = {
                "HOME": str(home),
                "HERMES_HOME": str(profile),
                "HERMES_PROFILE": "default",
            }

            real_os_open = os.open
            real_supports_dir_fd = os.supports_dir_fd

            def record_opens_during(fn):
                opened: set[str] = set()
                protected_opened: list[str] = []
                enabled = [True]

                def observe(raw_path: object) -> None:
                    if not enabled[0] or not isinstance(raw_path, (str, bytes, os.PathLike)):
                        return
                    resolved = Path(os.path.abspath(os.fsdecode(raw_path)))
                    if resolved == cpp_yaml:
                        protected_opened.append(str(resolved))
                    if custom_templates in resolved.parents or resolved == custom_templates:
                        opened.add(str(resolved))

                # An open made through guarded_os_open is counted there (with its dir_fd
                # resolved); the "open" audit event that os.open then raises for the same
                # open is skipped, so each real open is counted exactly once.
                in_guard = threading.local()

                def audit_hook(event: str, args: tuple) -> None:
                    if event == "open" and args and not getattr(in_guard, "active", False):
                        observe(args[0])

                sys.addaudithook(audit_hook)

                def guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
                    if dir_fd is not None and isinstance(path, (str, bytes, os.PathLike)):
                        p_str = os.fsdecode(path)
                        if not os.path.isabs(p_str):
                            full = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / p_str
                        else:
                            full = Path(p_str)
                    else:
                        full = path
                    observe(full)
                    in_guard.active = True
                    try:
                        return real_os_open(path, flags, mode, dir_fd=dir_fd)
                    finally:
                        in_guard.active = False

                try:
                    os.open = guarded_os_open
                    if real_os_open in real_supports_dir_fd:
                        os.supports_dir_fd = set(real_supports_dir_fd) | {guarded_os_open}
                    result = fn()
                finally:
                    enabled[0] = False
                    os.open = real_os_open
                    os.supports_dir_fd = real_supports_dir_fd
                return result, opened, protected_opened

            with mock.patch.dict(os.environ, env), mock.patch.object(
                _templates, "templates_root", return_value=custom_templates
            ):
                @redaction_scope
                def baseline_load():
                    credential_declarations(profile, home)
                    return {s.id: s for s in load_templates(excluded=credential_path)}

                _, expected_manifest_opens, baseline_protected = record_opens_during(baseline_load)
                self.assertEqual(baseline_protected, [])

                audit_db = tmp_path / "store" / "audit.db"
                res, sweep_opens, sweep_protected = record_opens_during(
                    lambda: audit_surface.execute_audit(
                        {"action": "run", "quick": True, "selected_projects": [str(rust_dir)]},
                        db_path=audit_db,
                        wait=True,
                    )
                )

            self.assertEqual(sweep_protected, [])
            self.assertEqual(res["status"], "completed")
            sweep_manifest_opens = {
                p for p in sweep_opens if Path(p).name == "template.yaml"
            }
            self.assertEqual(sweep_manifest_opens, expected_manifest_opens)

            # Also verify for a completely valid registry that the set of opened paths
            # during execute_audit matches the set opened when load_templates is used directly.
            valid_templates = (tmp_path / "templates_all_valid").resolve()
            shutil.copytree(REPO_ROOT / "templates", valid_templates)
            (profile / "settings.json").unlink()

            with mock.patch.dict(os.environ, env), mock.patch.object(
                _templates, "templates_root", return_value=valid_templates
            ):
                def record_all_non_store_opens(fn, store_dir: Path):
                    opened_paths: set[str] = set()
                    enabled = [True]

                    def observe_all(raw_path: object) -> None:
                        if not enabled[0] or not isinstance(raw_path, (str, bytes, os.PathLike)):
                            return
                        resolved = Path(os.path.abspath(os.fsdecode(raw_path)))
                        if store_dir in resolved.parents or resolved == store_dir:
                            return
                        if (
                            valid_templates in resolved.parents
                            or resolved == valid_templates
                            or home in resolved.parents
                            or resolved == home
                        ):
                            opened_paths.add(str(resolved))

                    def hook(event: str, args: tuple) -> None:
                        if event == "open" and args:
                            observe_all(args[0])

                    sys.addaudithook(hook)

                    def wrapped_open(path, flags, mode=0o777, *, dir_fd=None):
                        if dir_fd is not None and isinstance(path, (str, bytes, os.PathLike)):
                            p_str = os.fsdecode(path)
                            if not os.path.isabs(p_str):
                                full = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / p_str
                            else:
                                full = Path(p_str)
                        else:
                            full = path
                        observe_all(full)
                        return real_os_open(path, flags, mode, dir_fd=dir_fd)

                    try:
                        os.open = wrapped_open
                        if real_os_open in real_supports_dir_fd:
                            os.supports_dir_fd = set(real_supports_dir_fd) | {wrapped_open}
                        out = fn()
                    finally:
                        enabled[0] = False
                        os.open = real_os_open
                        os.supports_dir_fd = real_supports_dir_fd
                    return out, opened_paths

                store_a = tmp_path / "store_a"
                _, opens_new = record_all_non_store_opens(
                    lambda: audit_surface.execute_audit(
                        {"action": "run", "selected_projects": [str(rust_dir)], "as_of": 1700000000},
                        db_path=store_a / "audit.db",
                        wait=True,
                    ),
                    store_a,
                )

                orig_load_templates = _templates.load_templates

                def custom_passthrough(*args, **kwargs):
                    return orig_load_templates(*args, **kwargs)

                store_b = tmp_path / "store_b"
                with mock.patch.object(_templates, "load_templates", side_effect=custom_passthrough):
                    _, opens_orig = record_all_non_store_opens(
                        lambda: audit_surface.execute_audit(
                            {"action": "run", "selected_projects": [str(rust_dir)], "as_of": 1700000000},
                            db_path=store_b / "audit.db",
                            wait=True,
                        ),
                        store_b,
                    )

                self.assertEqual(opens_new, opens_orig)

    def test_repro1_and_repro2_cross_template_declaration_preflight_in_execute_audit(self) -> None:
        """Repro 1 & 2: ts-node-golden/settings.json declaring go-golden/template.yaml or go-golden/ directory must result in zero opens of protected paths across full and quick execute_audit, go could_not_verify, rust unchanged vs valid registry, valid registry opened paths unchanged, and each manifest read once per run."""
        go_bundle = _build_registered_project_bundle("go-golden")
        rust_bundle = _build_registered_project_bundle("rust-golden")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            home = tmp_path / "home"
            profile = home / ".hermes"
            profile.mkdir(parents=True)
            (profile / "config.yaml").write_text("{}\n", encoding="utf-8")

            go_dir = (home / "projects" / "go-service").resolve()
            rust_dir = (home / "projects" / "rust-service").resolve()
            _populate_project_tree(go_dir, go_bundle)
            _populate_project_tree(rust_dir, rust_bundle)

            reg_db = profile / "plugin-data" / "defuzz" / "state.db"
            _register_projects(
                reg_db,
                [
                    (go_dir, "go-service", "go-golden", go_bundle),
                    (rust_dir, "rust-service", "rust-golden", rust_bundle),
                ],
            )

            env = {
                "HOME": str(home),
                "HERMES_HOME": str(profile),
                "HERMES_PROFILE": "default",
            }
            real_os_open = os.open
            real_supports_dir_fd = os.supports_dir_fd

            def run_with_open_tracking(
                templates_dir: Path, store_dir: Path, *, quick: bool, legacy_loop: bool = False
            ):
                file_opens: dict[str, int] = {}
                all_non_store_opens: set[str] = set()
                enabled = [True]

                def observe_open(raw_path: object, is_dir_open: bool = False) -> None:
                    if not enabled[0] or not isinstance(raw_path, (str, bytes, os.PathLike)):
                        return
                    resolved = Path(os.path.abspath(os.fsdecode(raw_path)))
                    if store_dir in resolved.parents or resolved == store_dir:
                        return
                    if (
                        templates_dir in resolved.parents
                        or resolved == templates_dir
                        or home in resolved.parents
                        or resolved == home
                    ):
                        all_non_store_opens.add(str(resolved))
                    if not is_dir_open and (templates_dir in resolved.parents or resolved == templates_dir):
                        file_opens[str(resolved)] = file_opens.get(str(resolved), 0) + 1

                # Each real open is counted once: guarded_os_open counts its own opens, and
                # the "open" audit event os.open raises inside it is skipped.
                in_guard = threading.local()

                def audit_hook(event: str, args: tuple) -> None:
                    if event == "open" and args and not getattr(in_guard, "active", False):
                        raw = args[0]
                        flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
                        is_dir = bool(flags & getattr(os, "O_DIRECTORY", 0))
                        observe_open(raw, is_dir_open=is_dir)

                sys.addaudithook(audit_hook)

                def guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
                    if dir_fd is not None and isinstance(path, (str, bytes, os.PathLike)):
                        p_str = os.fsdecode(path)
                        if not os.path.isabs(p_str):
                            full = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / p_str
                        else:
                            full = Path(p_str)
                    else:
                        full = path
                    is_dir = bool(flags & getattr(os, "O_DIRECTORY", 0))
                    observe_open(full, is_dir_open=is_dir)
                    in_guard.active = True
                    try:
                        return real_os_open(path, flags, mode, dir_fd=dir_fd)
                    finally:
                        in_guard.active = False

                req: dict[str, object] = {
                    "action": "run",
                    "as_of": 1700000000,
                    "selected_projects": [str(go_dir), str(rust_dir)],
                }
                if quick:
                    req["quick"] = True

                orig_resolve = _contract.resolve_runtime_golden_registry
                call_idx = [0]

                def legacy_resolve():
                    call_idx[0] += 1
                    if call_idx[0] == 1:
                        # Simulate pre-change _sweep behavior: load each manifest before Phase A preflight
                        specs = {}
                        invalid = {}
                        for entry in sorted(templates_dir.iterdir(), key=lambda p: p.name):
                            if credential_path(entry) or credential_path(entry / "template.yaml"):
                                continue
                            if entry.is_symlink() or not entry.is_dir() or not os.path.lexists(entry / "template.yaml"):
                                continue
                            try:
                                spec = _templates.load_template(entry)
                                specs[spec.id] = spec
                            except Exception as exc:
                                invalid[entry.name] = type(exc).__name__
                        return {
                            "available": True,
                            "reason": None,
                            "discovered_ids": frozenset(specs),
                            "specs": specs,
                            "excluded_ids": frozenset(),
                            "invalid_ids": invalid,
                        }
                    return orig_resolve()

                with mock.patch.dict(os.environ, env), mock.patch.object(
                    _templates, "templates_root", return_value=templates_dir
                ):
                    try:
                        os.open = guarded_os_open
                        if real_os_open in real_supports_dir_fd:
                            os.supports_dir_fd = set(real_supports_dir_fd) | {guarded_os_open}
                        if legacy_loop:
                            with mock.patch.object(
                                _contract, "resolve_runtime_golden_registry", side_effect=legacy_resolve
                            ):
                                res = audit_surface.execute_audit(
                                    req,
                                    db_path=store_dir / "audit.db",
                                    wait=True,
                                )
                        else:
                            res = audit_surface.execute_audit(
                                req,
                                db_path=store_dir / "audit.db",
                                wait=True,
                            )
                    finally:
                        enabled[0] = False
                        os.open = real_os_open
                        os.supports_dir_fd = real_supports_dir_fd

                return res, file_opens, all_non_store_opens

            def _comp_ids(db_path: Path) -> tuple[str, str, str]:
                with key_scope(db_path):
                    return (
                        store_component_control_id("template_drift"),
                        store_component_control_id("static_code"),
                        store_component_control_id("tools_lock"),
                    )

            for quick in (False, True):
                mode_tag = "quick" if quick else "full"
                valid_templates = (tmp_path / f"templates_valid_{mode_tag}").resolve()
                shutil.copytree(REPO_ROOT / "templates", valid_templates)
                valid_store_dir = (tmp_path / f"store_valid_{mode_tag}").resolve()
                valid_res, valid_file_opens, valid_all_opens = run_with_open_tracking(
                    valid_templates, valid_store_dir, quick=quick
                )
                self.assertEqual(valid_res["status"], "completed")

                legacy_store_dir = (tmp_path / f"store_legacy_{mode_tag}").resolve()
                _, _, legacy_all_opens = run_with_open_tracking(
                    valid_templates, legacy_store_dir, quick=quick, legacy_loop=True
                )
                self.assertEqual(valid_all_opens, legacy_all_opens)

                # Assert each template.yaml is read at most once per run in valid registry
                for entry in sorted(valid_templates.iterdir()):
                    if entry.is_dir() and (entry / "template.yaml").exists():
                        manifest_p = str((entry / "template.yaml").resolve())
                        self.assertEqual(
                            valid_file_opens.get(manifest_p, 0),
                            1,
                            msg=f"[{mode_tag}] Expected {manifest_p} to be opened once, got {valid_file_opens.get(manifest_p, 0)}",
                        )

                valid_run = AuditStore(valid_store_dir / "audit.db").get_run(valid_res["run_id"])
                assert valid_run is not None
                valid_units = {u["unit_id"]: u for u in valid_run["units"]}
                valid_results = {(r["unit_id"], r["component_id"]): r for r in valid_run["unit_results"]}
                valid_ctrls = _comp_ids(valid_store_dir / "audit.db")

                for repro_kind in ("repro1_manifest", "repro2_dir"):
                    with self.subTest(mode=mode_tag, repro=repro_kind):
                        repro_templates = (tmp_path / f"templates_{repro_kind}_{mode_tag}").resolve()
                        shutil.copytree(REPO_ROOT / "templates", repro_templates)
                        go_tmpl_dir = (repro_templates / "go-golden").resolve()
                        go_yaml = (go_tmpl_dir / "template.yaml").resolve()
                        target_decl = str(go_yaml) if repro_kind == "repro1_manifest" else str(go_tmpl_dir)
                        (repro_templates / "ts-node-golden" / "settings.json").write_text(
                            json.dumps({"credential_file": target_decl}),
                            encoding="utf-8",
                        )

                        repro_store_dir = (tmp_path / f"store_{repro_kind}_{mode_tag}").resolve()
                        repro_res, repro_file_opens, _ = run_with_open_tracking(
                            repro_templates, repro_store_dir, quick=quick
                        )
                        self.assertEqual(repro_res["status"], "completed")
                        self.assertEqual(
                            repro_res["report"]["headline"]["coverage"],
                            COVERAGE_COULD_NOT_VERIFY,
                        )
                        self.assertFalse(repro_res["report"]["headline"]["can_claim_clean"])

                        # Zero opens of go-golden/template.yaml and zero opens of any file under go-golden/
                        self.assertEqual(
                            repro_file_opens.get(str(go_yaml), 0),
                            0,
                            msg=f"[{mode_tag} {repro_kind}] go-golden/template.yaml was opened!",
                        )
                        opened_under_go = [
                            p
                            for p, count in repro_file_opens.items()
                            if count > 0 and (go_tmpl_dir in Path(p).parents or Path(p) == go_tmpl_dir)
                        ]
                        self.assertEqual(
                            opened_under_go,
                            [],
                            msg=f"[{mode_tag} {repro_kind}] Files under go-golden/ were opened: {opened_under_go}",
                        )

                        # Non-excluded manifests read once per run
                        for entry in sorted(repro_templates.iterdir()):
                            if entry.is_dir() and entry.name != "go-golden" and (entry / "template.yaml").exists():
                                manifest_p = str((entry / "template.yaml").resolve())
                                self.assertEqual(
                                    repro_file_opens.get(manifest_p, 0),
                                    1,
                                    msg=f"[{mode_tag} {repro_kind}] Expected {manifest_p} opened once, got {repro_file_opens.get(manifest_p, 0)}",
                                )

                        repro_run = AuditStore(repro_store_dir / "audit.db").get_run(repro_res["run_id"])
                        assert repro_run is not None
                        repro_units = {u["unit_id"]: u for u in repro_run["units"]}
                        repro_results = {(r["unit_id"], r["component_id"]): r for r in repro_run["unit_results"]}
                        repro_ctrls = _comp_ids(repro_store_dir / "audit.db")

                        # go project is could_not_verify
                        go_unit = repro_units[str(go_dir)]
                        self.assertEqual(go_unit["coverage"], COVERAGE_COULD_NOT_VERIFY)
                        self.assertEqual(go_unit["status"], "incomplete")
                        self.assertIsNone(go_unit["evidence_cache_key"])
                        go_td = repro_results[(str(go_dir), repro_ctrls[0])]
                        go_sc = repro_results[(str(go_dir), repro_ctrls[1])]
                        self.assertEqual(go_td["coverage"], COVERAGE_COULD_NOT_VERIFY)
                        self.assertEqual(go_sc["coverage"], COVERAGE_COULD_NOT_VERIFY)

                        # rust project is unchanged vs valid registry
                        rust_unit_repro = repro_units[str(rust_dir)]
                        rust_unit_valid = valid_units[str(rust_dir)]
                        self.assertEqual(rust_unit_repro["status"], rust_unit_valid["status"])
                        self.assertEqual(rust_unit_repro["coverage"], rust_unit_valid["coverage"])
                        self.assertEqual(
                            rust_unit_repro["manifest"]["coverage"],
                            rust_unit_valid["manifest"]["coverage"],
                        )
                        for r_ctrl, v_ctrl in zip(repro_ctrls, valid_ctrls):
                            r_comp = repro_results[(str(rust_dir), r_ctrl)]
                            v_comp = valid_results[(str(rust_dir), v_ctrl)]
                            self.assertEqual(r_comp["coverage"], v_comp["coverage"])
                            self.assertEqual(r_comp["classification"], v_comp["classification"])
                            self.assertEqual(
                                [(f["id"], f["coverage"], f["classification"]) for f in r_comp["findings"]],
                                [(f["id"], f["coverage"], f["classification"]) for f in v_comp["findings"]],
                            )


if __name__ == "__main__":
    unittest.main()
