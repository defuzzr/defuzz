"""Tests for vendored `template_drift` and `static_code` components, fixtures, and packaged provenance (§5, §6, §11, §12, §13.3)."""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
import unittest

import yaml

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.audit.contract import (  # noqa: E402
    CLASSIFICATION_INFO,
    CLASSIFICATION_REVIEW,
    CLASSIFICATION_WARNING,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_NOT_INCLUDED,
    COVERAGE_VERIFIED,
    adapt_component_result,
    compute_headline,
)
from hermes_plugins.defuzz.audit.vendor.static_code import (  # noqa: E402
    audit_static_code,
)
from hermes_plugins.defuzz.audit.vendor.template_drift import (  # noqa: E402
    audit_template_drift,
)
from tests.test_audit_tripwires import sweep_forbidden_call_tripwires  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
VENDOR_DIR = REPO_ROOT / "audit" / "vendor"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "audit_template"



def _load_fixture_bundle(eco_folder: str) -> dict:
    root = FIXTURES_DIR / eco_folder
    meta = yaml.safe_load((root / "template.yaml").read_text(encoding="utf-8"))
    project_files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "template.yaml":
            continue
        rel = path.relative_to(root).as_posix()
        project_files[rel] = path.read_bytes()

    locked_hashes: dict[str, str] = {}
    for rel, raw in sorted(project_files.items()):
        if rel in ("Cargo.toml", "clippy.toml", "rustfmt.toml", "rust-toolchain.toml", "package.json", "tsconfig.base.json", "biome.json", "pyproject.toml") or rel.startswith((".github/workflows/", "xtask/", "tools/xtask/")):
            locked_hashes[rel] = hashlib.sha256(raw).hexdigest()

    return {
        "root": root,
        "template_spec": meta,
        "project_files": project_files,
        "provenance": {
            "path": f"/tmp/projects/{eco_folder}-service",
            "canonical_path": f"/tmp/projects/{eco_folder}-service",
            "template_id": meta["id"],
            "plugin_commit": "4a7007e000000000000000000000000000000000",
            "prefix": "my_service",
            "locked_hashes": locked_hashes,
        },
    }


class TestVendorSyncTemplate(unittest.TestCase):
    def test_packaged_vendor_provenance(self) -> None:
        from tests.vendor_provenance import assert_packaged_vendor
        assert_packaged_vendor(self, ['template_drift.py', 'static_code.py'])


class TestVendoredTemplateAndStaticCode(unittest.TestCase):
    def test_tripwires_on_import_and_fixture_execution(self) -> None:
        bundles = {
            eco: _load_fixture_bundle(eco)
            for eco in ("rust", "ts_node", "python")
        }
        # Both modules decide `_SUPPORTS_OPEN_DIR_FD` at import from `os.open in
        # os.supports_dir_fd`. Reloading them while the tripwires wrap os.open
        # leaves that flag False for every later test in this process, so reload
        # them once more after the tripwires have restored the real functions.
        for name in ("template_drift", "static_code"):
            self.addCleanup(importlib.reload, importlib.import_module(f"hermes_plugins.defuzz.audit.vendor.{name}"))
        with sweep_forbidden_call_tripwires(allowed_write_root=None):
            mod_td = importlib.import_module("hermes_plugins.defuzz.audit.vendor.template_drift")
            mod_sc = importlib.import_module("hermes_plugins.defuzz.audit.vendor.static_code")
            importlib.reload(mod_td)
            importlib.reload(mod_sc)

            # Empty invocation under tripwires
            self.assertEqual(mod_td.audit_template_drift()["coverage"], COVERAGE_NOT_INCLUDED)
            self.assertEqual(mod_sc.audit_static_code()["coverage"], COVERAGE_NOT_INCLUDED)

            for eco, bundle in bundles.items():
                td_res = mod_td.audit_template_drift(
                    bundle["provenance"],
                    project_files=bundle["project_files"],
                    template_spec=bundle["template_spec"],
                    template_files=bundle["project_files"],
                    current_plugin_commit="4a7007e000000000000000000000000000000000",
                )
                sc_res = mod_sc.audit_static_code(
                    bundle["provenance"],
                    approved_deps=bundle["template_spec"]["approved_deps"],
                    project_files=bundle["project_files"],
                    template_spec=bundle["template_spec"],
                    template_files=bundle["project_files"],
                )
                adapted_td = adapt_component_result(td_res, component_id=f"template_drift.{eco}")
                adapted_sc = adapt_component_result(sc_res, component_id=f"static_code.{eco}")
                headline = compute_headline(component_results=[adapted_td, adapted_sc])

                self.assertEqual(adapted_td["coverage"], COVERAGE_VERIFIED)
                self.assertEqual(adapted_sc["coverage"], COVERAGE_VERIFIED)
                self.assertEqual(headline["classification"], CLASSIFICATION_INFO)
                self.assertEqual(headline["coverage"], COVERAGE_VERIFIED)
                self.assertTrue(headline["can_claim_clean"])

    def test_fixture_ecosystems_detect_drift_missing_files_and_placeholders(self) -> None:
        for eco, locked_target, source_target in (
            ("rust", "clippy.toml", "foundation/src/lib.rs"),
            ("ts_node", "biome.json", "packages/adapters/my-service-http-hono/src/index.ts"),
            ("python", "pyproject.toml", "packages/adapters/my-service-http-fastapi/src/my_service_http_fastapi/server.py"),
        ):
            bundle = _load_fixture_bundle(eco)
            mutated = dict(bundle["project_files"])
            mutated[locked_target] = mutated[locked_target] + b"\n# modified\n"
            mutated.pop(source_target)
            mutated["leftover_tmpl_prefix.md"] = b"# TmplPrefix leftover\n"

            res = audit_template_drift(
                bundle["provenance"],
                project_files=mutated,
                template_spec=bundle["template_spec"],
                template_files=bundle["project_files"],
                current_plugin_commit="4a7007e000000000000000000000000000000000",
            )
            adapted = adapt_component_result(res, component_id="template_drift")
            self.assertEqual(adapted["classification"], CLASSIFICATION_WARNING)
            ids = {f["id"] for f in adapted["findings"]}
            self.assertIn("template.locked_hash_drift", ids)
            self.assertIn("template.missing_file", ids)
            self.assertIn("template.leftover_placeholder", ids)

    def test_fixture_ecosystems_detect_unapproved_deps_missing_locks_aliases_and_suppressions(self) -> None:
        # 1. Rust fixture mutations
        rust_b = _load_fixture_bundle("rust")
        rust_files = dict(rust_b["project_files"])
        rust_files["xtask/src/main.rs"] = (
            b"use rand::Rng;\n"
            b"use my_service_foundation::MyServiceError;\n"
            b"#[cfg(test)]\n"
            b"use proptest::prelude::*;\n"
            b"#[allow(dead_code)]\n"
            b"fn main() { todo!(); }\n"
        )
        rust_res = audit_static_code(
            rust_b["provenance"],
            approved_deps={"rust": ["serde"]},  # `toml` in Cargo.lock is now unapproved
            project_files=rust_files,
            template_spec=rust_b["template_spec"],
            template_files=rust_b["project_files"],
        )
        rust_ids = {f["id"] for f in rust_res["findings"]}
        self.assertEqual(rust_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertEqual(rust_res["classification"], CLASSIFICATION_WARNING)
        self.assertIn("static_code.unapproved_dependency", rust_ids)
        self.assertIn("static_code.import_missing_from_lock", rust_ids)
        self.assertIn("static_code.unmappable_import", rust_ids)
        self.assertIn("static_code.suppressions_above_baseline", rust_ids)
        self.assertIn("static_code.stub_detected", rust_ids)

        # 2. TS-Node fixture mutations
        ts_b = _load_fixture_bundle("ts_node")
        ts_files = dict(ts_b["project_files"])
        ts_files["packages/adapters/my-service-http-hono/src/index.ts"] = (
            b'import express from "express";\n'
            b'import { helper } from "@/internal/helper.js";\n'
            b"// biome-ignore lint/suspicious/noExplicitAny: test\n"
            b"export async function boot(modName: string) {\n"
            b"  await import(modName);\n"
            b'  throw new Error("TODO: finish boot");\n'
            b"}\n"
        )
        ts_res = audit_static_code(
            ts_b["provenance"],
            approved_deps={"ts-node": ["hono", "zod"]},  # `@hono/node-server` & `typescript` now unapproved
            project_files=ts_files,
            template_spec=ts_b["template_spec"],
            template_files=ts_b["project_files"],
        )
        ts_ids = {f["id"] for f in ts_res["findings"]}
        self.assertEqual(ts_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertEqual(ts_res["classification"], CLASSIFICATION_WARNING)
        self.assertIn("static_code.unapproved_dependency", ts_ids)
        self.assertIn("static_code.import_missing_from_lock", ts_ids)
        self.assertIn("static_code.unmappable_import", ts_ids)
        self.assertIn("static_code.suppressions_above_baseline", ts_ids)
        self.assertIn("static_code.stub_detected", ts_ids)

        # 3. Python fixture mutations
        py_b = _load_fixture_bundle("python")
        py_files = dict(py_b["project_files"])
        py_files["packages/adapters/my-service-http-fastapi/src/my_service_http_fastapi/server.py"] = (
            b"from typing import TYPE_CHECKING\n"
            b"import boto3  # noqa: F401\n"
            b"from my_service_core import AppError\n"
            b"if TYPE_CHECKING:\n"
            b"    import mypy_extensions\n"
            b"def unimplemented_endpoint() -> None:\n"
            b"    raise NotImplementedError\n"
        )
        py_res = audit_static_code(
            py_b["provenance"],
            approved_deps={"python": ["fastapi", "pydantic"]},  # `pydantic-settings`, `pytest`, `uvicorn` unapproved
            project_files=py_files,
            template_spec=py_b["template_spec"],
            template_files=py_b["project_files"],
        )
        py_ids = {f["id"] for f in py_res["findings"]}
        self.assertEqual(py_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertEqual(py_res["classification"], CLASSIFICATION_WARNING)
        self.assertIn("static_code.unapproved_dependency", py_ids)
        self.assertIn("static_code.import_missing_from_lock", py_ids)
        self.assertIn("static_code.unmappable_import", py_ids)
        self.assertIn("static_code.suppressions_above_baseline", py_ids)
        self.assertIn("static_code.stub_detected", py_ids)

    def test_non_golden_template_returns_not_included(self) -> None:
        prov = {
            "canonical_path": "/tmp/projects/custom-app",
            "template_id": "bevy-3d",
            "plugin_commit": "abc",
            "prefix": "custom_app",
        }
        td = adapt_component_result(audit_template_drift(prov), component_id="template_drift")
        sc = adapt_component_result(audit_static_code(prov), component_id="static_code")
        headline = compute_headline(component_results=[td, sc])
        self.assertEqual(td["coverage"], COVERAGE_NOT_INCLUDED)
        self.assertEqual(sc["coverage"], COVERAGE_NOT_INCLUDED)
        self.assertEqual(headline["coverage"], COVERAGE_NOT_INCLUDED)
        self.assertFalse(headline["can_claim_clean"])


if __name__ == "__main__":
    unittest.main()
