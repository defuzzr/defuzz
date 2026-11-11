"""Tests for deriving GOLDEN_TEMPLATE_IDS and ecosystem mappings from templates.py registry."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import audit, audit_surface, templates as _templates  # noqa: E402
from hermes_plugins.defuzz.audit import contract  # noqa: E402
from hermes_plugins.defuzz.audit.contract import (  # noqa: E402
    CLASSIFICATION_INFO,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_NOT_INCLUDED,
    COVERAGE_VERIFIED,
    adapt_component_result,
    compute_headline,
)
from hermes_plugins.defuzz.audit.vendor import static_code, template_drift  # noqa: E402
from hermes_plugins.defuzz.templates import load_template, load_templates  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_GOLDEN = frozenset({
    "rust-golden",
    "ts-node-golden",
    "python-golden",
    "go-golden",
    "cpp-golden",
    "dotnet-golden",
    "web-golden",
})


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
    template_spec = {
        "id": spec.id,
        "placeholder": spec.placeholder,
        "substitute_in": list(spec.substitute_in),
        "locked": list(spec.locked),
        "approved_deps": {k: list(v) for k, v in spec.approved_deps.items()},
        "languages": list(spec.languages),
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
        "template_spec": template_spec,
        "template_files": raw_template_files,
        "project_files": project_files,
        "provenance": provenance,
    }


class TestAuditGoldenRegistry(unittest.TestCase):
    def test_cold_import_reads_zero_template_manifests_or_settings(self) -> None:
        """(a) Cold-import in a fresh subprocess with sys.addaudithook counting open events on any template.yaml/settings.json under templates root => zero."""
        script = r"""
import os
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(repo_root))
from tests import ensure_test_package
ensure_test_package()

templates_dir = (repo_root / "templates").resolve()
opened = []

def hook(event, args):
    if event == "open" and args:
        target = args[0]
        if isinstance(target, (str, bytes, os.PathLike)):
            p = Path(os.path.abspath(os.fsdecode(target)))
            if p.name in ("template.yaml", "settings.json") and (
                p == templates_dir or templates_dir in p.parents
            ):
                opened.append(str(p))

sys.addaudithook(hook)

import hermes_plugins.defuzz.audit as audit
import hermes_plugins.defuzz.audit.contract as contract
import hermes_plugins.defuzz.audit.vendor.template_drift as td
import hermes_plugins.defuzz.audit.vendor.static_code as sc
import hermes_plugins.defuzz.audit_surface as surface

assert len(opened) == 0, f"Unexpected template file opens during cold import: {opened}"
assert len(audit.GOLDEN_TEMPLATE_IDS) == 7
assert contract.GOLDEN_TEMPLATE_IDS == audit.GOLDEN_TEMPLATE_IDS
assert td.GOLDEN_TEMPLATE_IDS == audit.GOLDEN_TEMPLATE_IDS
assert sc.GOLDEN_TEMPLATE_IDS == audit.GOLDEN_TEMPLATE_IDS
print("COLD_IMPORT_OK")
"""
        proc = subprocess.run(
            [sys.executable, "-c", script, str(REPO_ROOT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("COLD_IMPORT_OK", proc.stdout)

    def test_declared_credential_template_yaml_never_opened_during_import_and_full_audit(self) -> None:
        """(b) Declared-credential template.yaml never opened during import AND during a full audit of a go-golden project."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            home = tmp_path / "home"
            profile = home / ".hermes"
            profile.mkdir(parents=True)
            (profile / "config.yaml").write_text("{}\n", encoding="utf-8")

            # Copy templates tree into temp dir and add a settings.json declaring go-golden/template.yaml as credential
            custom_templates = tmp_path / "templates"
            shutil.copytree(REPO_ROOT / "templates", custom_templates)
            go_yaml = (custom_templates / "go-golden" / "template.yaml").resolve()
            (profile / "settings.json").write_text(
                json.dumps({"credential_file": str(go_yaml)}),
                encoding="utf-8",
            )
            (custom_templates / "go-golden" / "settings.json").write_text(
                json.dumps({"credential_file": str(go_yaml)}),
                encoding="utf-8",
            )

            # Verify cold import in a subprocess with custom_templates never opens go_yaml
            import_script = r"""
import os
import sys
from pathlib import Path
from unittest import mock

repo_root = Path(sys.argv[1]).resolve()
custom_root = Path(sys.argv[2]).resolve()
protected_yaml = Path(sys.argv[3]).resolve()
sys.path.insert(0, str(repo_root))
from tests import ensure_test_package
ensure_test_package()

import hermes_plugins.defuzz.templates as templates
opened = []

def hook(event, args):
    if event == "open" and args:
        target = args[0]
        if isinstance(target, (str, bytes, os.PathLike)):
            if Path(os.path.abspath(os.fsdecode(target))) == protected_yaml:
                opened.append(str(protected_yaml))

sys.addaudithook(hook)
with mock.patch.object(templates, "templates_root", return_value=custom_root):
    import hermes_plugins.defuzz.audit as audit
    import hermes_plugins.defuzz.audit.vendor.template_drift as td
    import hermes_plugins.defuzz.audit.vendor.static_code as sc
    import hermes_plugins.defuzz.audit_surface as surface

assert not opened, f"Declared credential template.yaml opened during import: {opened}"
print("IMPORT_CREDENTIAL_SAFE")
"""
            import_proc = subprocess.run(
                [sys.executable, "-c", import_script, str(REPO_ROOT), str(custom_templates), str(go_yaml)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(
                import_proc.returncode,
                0,
                msg=f"stdout={import_proc.stdout}\nstderr={import_proc.stderr}",
            )

            # Create a registered go-golden project on disk
            bundle = _build_registered_project_bundle("go-golden")
            project_dir = home / "projects" / "go-service"
            for rel, content in bundle["project_files"].items():
                dest = project_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
            (project_dir / ".git").mkdir(parents=True, exist_ok=True)
            (project_dir / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")

            # Register the go-golden project in profile state DB
            db_path = profile / "plugin-data" / "defuzz" / "state.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    "CREATE TABLE projects (path TEXT PRIMARY KEY, name TEXT, slug TEXT, template_id TEXT, prefix TEXT, plugin_commit TEXT, locked_hashes_json TEXT)"
                )
                conn.execute(
                    "INSERT INTO projects VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(project_dir),
                        "go-service",
                        "my_service",
                        "go-golden",
                        "my_service",
                        bundle["provenance"]["plugin_commit"],
                        json.dumps(bundle["provenance"]["locked_hashes"]),
                    ),
                )

            opened_protected: list[str] = []
            enabled = [True]

            def check_path(raw_path: object) -> None:
                if not enabled[0] or not isinstance(raw_path, (str, bytes, os.PathLike)):
                    return
                resolved = Path(os.path.abspath(os.fsdecode(raw_path)))
                if resolved == go_yaml:
                    opened_protected.append(str(resolved))
                    raise AssertionError(f"Declared credential template.yaml opened: {resolved}")

            def audit_hook(event: str, args: tuple) -> None:
                if event == "open" and args:
                    check_path(args[0])

            sys.addaudithook(audit_hook)

            real_os_open = os.open
            real_supports_dir_fd = os.supports_dir_fd

            def guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
                if dir_fd is not None and isinstance(path, (str, bytes, os.PathLike)):
                    p_str = os.fsdecode(path)
                    if not os.path.isabs(p_str):
                        full = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / p_str
                    else:
                        full = Path(p_str)
                else:
                    full = path
                check_path(full)
                return real_os_open(path, flags, mode, dir_fd=dir_fd)

            env_patch = mock.patch.dict(
                os.environ,
                {"HOME": str(home), "HERMES_HOME": str(profile), "HERMES_PROFILE": "default"},
            )
            tmpl_patch = mock.patch.object(_templates, "templates_root", return_value=custom_templates)

            with env_patch, tmpl_patch:
                try:
                    os.open = guarded_os_open
                    if real_os_open in real_supports_dir_fd:
                        os.supports_dir_fd = set(real_supports_dir_fd) | {guarded_os_open}
                    # Also test direct vendor calls during active credential declaration scope
                    res = audit_surface.execute_audit(
                        {"action": "run", "selected_projects": [str(project_dir)]},
                        db_path=db_path,
                        wait=True,
                    )
                    from hermes_plugins.defuzz.audit.policy import credential_declarations
                    from hermes_plugins.defuzz.audit.redaction import redaction_scope

                    @redaction_scope
                    def _direct_checks():
                        credential_declarations(profile, home)
                        td_direct = template_drift.audit_template_drift(
                            bundle["provenance"],
                            project_files=bundle["project_files"],
                        )
                        sc_direct = static_code.audit_static_code(
                            bundle["provenance"],
                            project_files=bundle["project_files"],
                        )
                        return td_direct, sc_direct

                    td_direct, sc_direct = _direct_checks()
                finally:
                    enabled[0] = False
                    os.open = real_os_open
                    os.supports_dir_fd = real_supports_dir_fd

            self.assertEqual(opened_protected, [])
            self.assertEqual(res["status"], "completed")
            self.assertEqual(res["report"]["headline"]["coverage"], COVERAGE_COULD_NOT_VERIFY)
            self.assertEqual(td_direct["coverage"], COVERAGE_COULD_NOT_VERIFY)
            self.assertEqual(sc_direct["coverage"], COVERAGE_COULD_NOT_VERIFY)
            td_ids = {f["id"] for f in td_direct["findings"]}
            sc_ids = {f["id"] for f in sc_direct["findings"]}
            self.assertNotIn("template.not_included", td_ids)
            self.assertNotIn("static_code.not_included", sc_ids)

    def test_invalid_template_yaml_does_not_break_import_and_reports_unavailable_coverage(self) -> None:
        """(c) Invalid template.yaml => import audit succeeds and the go project's template/static check reports unavailable/unknown, not not_included and not a crash."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            broken_templates = tmp_path / "templates"
            shutil.copytree(REPO_ROOT / "templates", broken_templates)
            (broken_templates / "go-golden" / "template.yaml").write_text(
                "id: [unclosed yaml\n", encoding="utf-8"
            )

            # Verify import audit succeeds in subprocess when templates_root has invalid template.yaml
            script = r"""
import sys
from pathlib import Path
from unittest import mock

repo_root = Path(sys.argv[1]).resolve()
broken_root = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(repo_root))
from tests import ensure_test_package
ensure_test_package()

import hermes_plugins.defuzz.templates as templates
with mock.patch.object(templates, "templates_root", return_value=broken_root):
    import hermes_plugins.defuzz.audit as audit
    import hermes_plugins.defuzz.audit.vendor.template_drift as td
    import hermes_plugins.defuzz.audit.vendor.static_code as sc
    import hermes_plugins.defuzz.audit_surface as surface
print("IMPORT_WITH_INVALID_YAML_OK")
"""
            proc = subprocess.run(
                [sys.executable, "-c", script, str(REPO_ROOT), str(broken_templates)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stdout={proc.stdout}\nstderr={proc.stderr}")
            self.assertIn("IMPORT_WITH_INVALID_YAML_OK", proc.stdout)

            bundle = _build_registered_project_bundle("go-golden")
            with mock.patch.object(_templates, "templates_root", return_value=broken_templates):
                td_res = template_drift.audit_template_drift(
                    bundle["provenance"],
                    project_files=bundle["project_files"],
                )
                sc_res = static_code.audit_static_code(
                    bundle["provenance"],
                    project_files=bundle["project_files"],
                )

                self.assertEqual(td_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
                self.assertEqual(sc_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
                td_ids = {f["id"] for f in td_res["findings"]}
                sc_ids = {f["id"] for f in sc_res["findings"]}
                self.assertNotIn("template.not_included", td_ids)
                self.assertNotIn("static_code.not_included", sc_ids)
                self.assertTrue(any(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in td_res["findings"]))
                self.assertTrue(any(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in sc_res["findings"]))

                adapted_td = adapt_component_result(td_res, component_id="template_drift.go-golden")
                adapted_sc = adapt_component_result(sc_res, component_id="static_code.go-golden")
                headline = compute_headline(component_results=[adapted_td, adapted_sc])
                self.assertEqual(headline["coverage"], COVERAGE_COULD_NOT_VERIFY)
                self.assertFalse(headline["can_claim_clean"])

    def test_missing_templates_root_reports_unavailable_coverage_not_not_included(self) -> None:
        """(d) Missing templates root => import succeeds and go project's template/static check reports unavailable/unknown, not not_included."""
        with tempfile.TemporaryDirectory() as tmp:
            missing_root = Path(tmp) / "nonexistent_templates_root"
            bundle = _build_registered_project_bundle("go-golden")

            with mock.patch.object(_templates, "templates_root", return_value=missing_root):
                td_res = template_drift.audit_template_drift(
                    bundle["provenance"],
                    project_files=bundle["project_files"],
                )
                sc_res = static_code.audit_static_code(
                    bundle["provenance"],
                    project_files=bundle["project_files"],
                )

                self.assertEqual(td_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
                self.assertEqual(sc_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
                td_ids = {f["id"] for f in td_res["findings"]}
                sc_ids = {f["id"] for f in sc_res["findings"]}
                self.assertNotIn("template.not_included", td_ids)
                self.assertNotIn("static_code.not_included", sc_ids)
                self.assertTrue(any(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in td_res["findings"]))
                self.assertTrue(any(f["coverage"] == COVERAGE_COULD_NOT_VERIFY for f in sc_res["findings"]))

                home = Path(tmp) / "home"
                profile = home / ".hermes"
                profile.mkdir(parents=True)
                (profile / "config.yaml").write_text("{}\n", encoding="utf-8")
                project_dir = home / "projects" / "go-service"
                project_dir.mkdir(parents=True)
                db_path = profile / "plugin-data" / "defuzz" / "state.db"
                db_path.parent.mkdir(parents=True)
                with sqlite3.connect(db_path) as conn:
                    conn.execute(
                        "CREATE TABLE projects (path TEXT PRIMARY KEY, name TEXT, slug TEXT, template_id TEXT)"
                    )
                    conn.execute(
                        "INSERT INTO projects VALUES (?, ?, ?, ?)",
                        (str(project_dir), "go-service", "my_service", "go-golden"),
                    )
                with mock.patch.dict(
                    os.environ,
                    {"HOME": str(home), "HERMES_HOME": str(profile), "HERMES_PROFILE": "default"},
                ):
                    run_res = audit_surface.execute_audit(
                        {"action": "run", "quick": True, "selected_projects": [str(project_dir)]},
                        db_path=db_path,
                        wait=True,
                    )
                self.assertEqual(run_res["status"], "completed")
                self.assertEqual(run_res["report"]["headline"]["coverage"], COVERAGE_COULD_NOT_VERIFY)

    def test_all_bundled_templates_in_golden_template_ids_and_match_registry(self) -> None:
        """(e) Every bundled template (seven) is in the golden registry."""
        registry_ids = frozenset(spec.id for spec in load_templates())
        self.assertEqual(registry_ids, EXPECTED_GOLDEN)

        for mod_name, exported in (
            ("audit", audit.GOLDEN_TEMPLATE_IDS),
            ("audit.contract", contract.GOLDEN_TEMPLATE_IDS),
            ("audit.vendor.template_drift", template_drift.GOLDEN_TEMPLATE_IDS),
            ("audit.vendor.static_code", static_code.GOLDEN_TEMPLATE_IDS),
        ):
            with self.subTest(module=mod_name):
                self.assertIsInstance(exported, frozenset)
                self.assertEqual(exported, EXPECTED_GOLDEN)
                self.assertEqual(exported, registry_ids)

        for tid in EXPECTED_GOLDEN:
            self.assertIn(tid, static_code.TEMPLATE_TO_ECOSYSTEM)

    def test_new_golden_templates_participate_in_template_drift_and_static_code(self) -> None:
        for template_id in ("go-golden", "cpp-golden", "dotnet-golden"):
            with self.subTest(template_id=template_id):
                bundle = _build_registered_project_bundle(template_id)
                td_res = template_drift.audit_template_drift(
                    bundle["provenance"],
                    project_files=bundle["project_files"],
                    template_spec=bundle["template_spec"],
                    template_files=bundle["template_files"],
                    current_plugin_commit="4a7007e000000000000000000000000000000000",
                )
                sc_res = static_code.audit_static_code(
                    bundle["provenance"],
                    approved_deps=bundle["template_spec"]["approved_deps"],
                    project_files=bundle["project_files"],
                    template_spec=bundle["template_spec"],
                    template_files=bundle["template_files"],
                )

                td_finding_ids = {f["id"] for f in td_res["findings"]}
                sc_finding_ids = {f["id"] for f in sc_res["findings"]}
                self.assertNotIn("template.not_included", td_finding_ids)
                self.assertNotIn("static_code.not_included", sc_finding_ids)
                self.assertTrue(td_res["summary"]["included"])
                self.assertTrue(sc_res["summary"]["included"])

                adapted_td = adapt_component_result(td_res, component_id=f"template_drift.{template_id}")
                adapted_sc = adapt_component_result(sc_res, component_id=f"static_code.{template_id}")
                headline = compute_headline(component_results=[adapted_td, adapted_sc])

                self.assertEqual(adapted_td["coverage"], COVERAGE_VERIFIED)
                self.assertEqual(adapted_sc["coverage"], COVERAGE_VERIFIED)
                self.assertEqual(headline["classification"], CLASSIFICATION_INFO)
                self.assertEqual(headline["coverage"], COVERAGE_VERIFIED)
                self.assertTrue(headline["can_claim_clean"])

    def test_node_templates_are_included_and_every_lockfile_package_is_approved(self) -> None:
        """ts-node-golden and web-golden: both checks run and approved_deps covers the whole lockfile.

        Their static_code coverage stays could_not_verify: imports of devDependencies, imports in
        test files and dynamic import() are not mapped by the lexical lockfile check.
        """
        for template_id in ("ts-node-golden", "web-golden"):
            with self.subTest(template_id=template_id):
                bundle = _build_registered_project_bundle(template_id)
                td_res = template_drift.audit_template_drift(
                    bundle["provenance"],
                    project_files=bundle["project_files"],
                    template_spec=bundle["template_spec"],
                    template_files=bundle["template_files"],
                    current_plugin_commit="4a7007e000000000000000000000000000000000",
                )
                sc_res = static_code.audit_static_code(
                    bundle["provenance"],
                    approved_deps=bundle["template_spec"]["approved_deps"],
                    project_files=bundle["project_files"],
                    template_spec=bundle["template_spec"],
                    template_files=bundle["template_files"],
                )
                self.assertTrue(td_res["summary"]["included"])
                self.assertTrue(sc_res["summary"]["included"])
                self.assertEqual(sc_res["summary"]["lockfile"], "pnpm-lock.yaml")
                self.assertGreater(sc_res["summary"]["external_lock_package_count"], 0)
                self.assertEqual(sc_res["summary"]["unapproved_lock_package_count"], 0)
                self.assertEqual(sc_res["summary"]["missing_lock_imports_count"], 0)
                sc_ids = {f["id"] for f in sc_res["findings"]}
                self.assertNotIn("static_code.unapproved_dependency", sc_ids)
                self.assertNotIn("static_code.approved_deps_unavailable", sc_ids)
                adapted_td = adapt_component_result(td_res, component_id=f"template_drift.{template_id}")
                self.assertEqual(adapted_td["coverage"], COVERAGE_VERIFIED)

    def test_unsupported_template_reports_all_bundled_in_supported_templates(self) -> None:
        prov = {
            "canonical_path": "/tmp/projects/custom-app",
            "template_id": "bevy-3d",
            "plugin_commit": "abc",
            "prefix": "custom_app",
        }
        td_res = template_drift.audit_template_drift(prov)
        sc_res = static_code.audit_static_code(prov)
        self.assertEqual(td_res["coverage"], COVERAGE_NOT_INCLUDED)
        self.assertEqual(sc_res["coverage"], COVERAGE_NOT_INCLUDED)

        td_finding = td_res["findings"][0]
        sc_finding = sc_res["findings"][0]
        self.assertEqual(td_finding["evidence"]["supported_templates"], sorted(EXPECTED_GOLDEN))
        self.assertEqual(sc_finding["evidence"]["supported_templates"], sorted(EXPECTED_GOLDEN))
        self.assertNotIn("Only rust-golden, ts-node-golden, and python-golden", td_finding["limitations"])
        self.assertNotIn("Only rust-golden, ts-node-golden, and python-golden", sc_finding["limitations"])

    def test_gap1_two_phase_preflight_late_declaration_never_opens_earlier_manifest_and_caches_once(self) -> None:
        """Gap 1: ts-node-golden/settings.json declaring go-golden/template.yaml must never open go-golden/template.yaml, both resolves must be identical, and each non-excluded manifest is opened at most once per run."""
        from hermes_plugins.defuzz.audit.redaction import redaction_scope

        with tempfile.TemporaryDirectory() as tmp:
            custom_templates = Path(tmp) / "templates"
            shutil.copytree(REPO_ROOT / "templates", custom_templates)
            go_yaml = (custom_templates / "go-golden" / "template.yaml").resolve()
            (custom_templates / "ts-node-golden" / "settings.json").write_text(
                json.dumps({"credential_file": str(go_yaml)}),
                encoding="utf-8",
            )

            opened_manifests: dict[str, int] = {}
            enabled = [True]

            def check_open(raw_path: object) -> None:
                if not enabled[0] or not isinstance(raw_path, (str, bytes, os.PathLike)):
                    return
                resolved = Path(os.path.realpath(os.fsdecode(raw_path)))
                if resolved.name == "template.yaml" and custom_templates.resolve() in resolved.parents:
                    opened_manifests[str(resolved)] = opened_manifests.get(str(resolved), 0) + 1

            def audit_hook(event: str, args: tuple) -> None:
                if event == "open" and args:
                    check_open(args[0])

            sys.addaudithook(audit_hook)

            with mock.patch.object(_templates, "templates_root", return_value=custom_templates):
                @redaction_scope
                def _run():
                    r1 = contract.resolve_runtime_golden_registry()
                    r2 = contract.resolve_runtime_golden_registry()
                    return r1, r2

                try:
                    res1, res2 = _run()
                finally:
                    enabled[0] = False

            self.assertEqual(opened_manifests.get(str(go_yaml), 0), 0)
            self.assertEqual(res1["excluded_ids"], frozenset({"go-golden"}))
            self.assertNotIn("go-golden", res1["specs"])
            self.assertEqual(res1, res2)
            for tid in EXPECTED_GOLDEN - {"go-golden"}:
                manifest_p = str((custom_templates / tid / "template.yaml").resolve())
                self.assertEqual(opened_manifests.get(manifest_p, 0), 1, msg=f"Manifest {tid} opened {opened_manifests.get(manifest_p, 0)} times")

    def test_gap2_excluded_template_directory_never_opens_declaration_sources_inside_it(self) -> None:
        """Gap 2: When project settings.json declares sibling cpp-golden directory, zero files under cpp-golden/ (including cpp-golden/settings.json) are opened during full go audit or registry resolution."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            home = tmp_path / "home"
            profile = home / ".hermes"
            profile.mkdir(parents=True)
            (profile / "config.yaml").write_text("{}\n", encoding="utf-8")

            custom_templates = tmp_path / "templates"
            shutil.copytree(REPO_ROOT / "templates", custom_templates)
            cpp_dir = (custom_templates / "cpp-golden").resolve()
            cpp_settings = cpp_dir / "settings.json"
            cpp_settings.write_text(
                json.dumps({"credential_file": str(custom_templates / "rust-golden" / "template.yaml")}),
                encoding="utf-8",
            )

            bundle = _build_registered_project_bundle("go-golden")
            project_dir = home / "projects" / "go-service"
            for rel, content in bundle["project_files"].items():
                dest = project_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
            (project_dir / ".git").mkdir(parents=True, exist_ok=True)
            (project_dir / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")
            (project_dir / "settings.json").write_text(
                json.dumps({"credential_file": str(cpp_dir)}),
                encoding="utf-8",
            )

            db_path = profile / "plugin-data" / "defuzz" / "state.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    "CREATE TABLE projects (path TEXT PRIMARY KEY, name TEXT, slug TEXT, template_id TEXT, prefix TEXT, plugin_commit TEXT, locked_hashes_json TEXT)"
                )
                conn.execute(
                    "INSERT INTO projects VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(project_dir),
                        "go-service",
                        "my_service",
                        "go-golden",
                        "my_service",
                        bundle["provenance"]["plugin_commit"],
                        json.dumps(bundle["provenance"]["locked_hashes"]),
                    ),
                )

            opened_under_cpp: list[str] = []
            enabled = [True]

            def check_path(raw_path: object) -> None:
                if not enabled[0] or not isinstance(raw_path, (str, bytes, os.PathLike)):
                    return
                resolved = Path(os.path.abspath(os.fsdecode(raw_path)))
                if cpp_dir in resolved.parents:
                    opened_under_cpp.append(str(resolved))

            def audit_hook(event: str, args: tuple) -> None:
                if event == "open" and args:
                    check_path(args[0])

            sys.addaudithook(audit_hook)

            real_os_open = os.open
            real_supports_dir_fd = os.supports_dir_fd

            def guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
                if dir_fd is not None and isinstance(path, (str, bytes, os.PathLike)):
                    p_str = os.fsdecode(path)
                    if not os.path.isabs(p_str):
                        full = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / p_str
                    else:
                        full = Path(p_str)
                else:
                    full = path
                check_path(full)
                return real_os_open(path, flags, mode, dir_fd=dir_fd)

            env_patch = mock.patch.dict(
                os.environ,
                {"HOME": str(home), "HERMES_HOME": str(profile), "HERMES_PROFILE": "default"},
            )
            tmpl_patch = mock.patch.object(_templates, "templates_root", return_value=custom_templates)

            with env_patch, tmpl_patch:
                try:
                    os.open = guarded_os_open
                    if real_os_open in real_supports_dir_fd:
                        os.supports_dir_fd = set(real_supports_dir_fd) | {guarded_os_open}
                    res = audit_surface.execute_audit(
                        {"action": "run", "selected_projects": [str(project_dir)]},
                        db_path=db_path,
                        wait=True,
                    )
                    from hermes_plugins.defuzz.audit.policy import credential_declarations
                    from hermes_plugins.defuzz.audit.redaction import redaction_scope

                    @redaction_scope
                    def _direct_registry():
                        credential_declarations(project_dir, home)
                        return contract.resolve_runtime_golden_registry()

                    reg_info = _direct_registry()
                finally:
                    enabled[0] = False
                    os.open = real_os_open
                    os.supports_dir_fd = real_supports_dir_fd

            self.assertEqual(opened_under_cpp, [])
            self.assertEqual(res["status"], "completed")
            self.assertIn("cpp-golden", reg_info["excluded_ids"])
            self.assertNotIn("rust-golden", reg_info["excluded_ids"])


if __name__ == "__main__":
    unittest.main()
