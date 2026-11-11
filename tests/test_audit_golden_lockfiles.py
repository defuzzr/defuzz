"""Lockfile parsing and verification tests for Go, C++ (CMake), and .NET (NuGet) golden templates."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.audit.contract import (  # noqa: E402
    CLASSIFICATION_INFO,
    CLASSIFICATION_WARNING,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
    adapt_component_result,
    compute_headline,
)
from hermes_plugins.defuzz.audit.policy import declare_credential  # noqa: E402
from hermes_plugins.defuzz.audit.redaction import redaction_scope  # noqa: E402
from hermes_plugins.defuzz.audit.vendor import static_code, template_drift  # noqa: E402
from hermes_plugins.defuzz.templates import load_template  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


def _build_bundle(template_id: str, prefix: str = "my_service") -> dict:
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


class TestAuditGoldenLockfiles(unittest.TestCase):
    def test_gap3_root_nuget_lock_does_not_hide_nested_subproject_lockfiles(self) -> None:
        """Gap 3: Root packages.lock.json with empty deps + src/App/packages.lock.json with unapproved Forbidden.Package must report unapproved dependency."""
        bundle = _build_bundle("dotnet-golden")
        project_files = dict(bundle["project_files"])
        project_files["packages.lock.json"] = json.dumps(
            {"version": 1, "dependencies": {"net10.0": {}}}
        ).encode("utf-8")
        project_files["src/App/packages.lock.json"] = json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net10.0": {
                        "Forbidden.Package": {
                            "type": "Direct",
                            "requested": "[1.2.3, )",
                            "resolved": "1.2.3",
                        }
                    }
                },
            }
        ).encode("utf-8")

        sc_res = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=project_files,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(sc_res["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(sc_res["classification"], CLASSIFICATION_WARNING)
        unapproved = [
            f for f in sc_res["findings"] if f["id"] == "static_code.unapproved_dependency"
        ]
        self.assertEqual(len(unapproved), 1)
        self.assertEqual(unapproved[0]["evidence"]["package"], "Forbidden.Package")

    def test_gap3_nested_nuget_lock_malformed_or_symlink_with_valid_root_lock_fails_closed(self) -> None:
        """Gap 3: Even when root packages.lock.json is valid, a malformed or symlinked nested packages.lock.json must fail closed with could_not_verify."""
        bundle = _build_bundle("dotnet-golden")
        project_files = dict(bundle["project_files"])
        project_files["packages.lock.json"] = json.dumps(
            {"version": 1, "dependencies": {"net10.0": {}}}
        ).encode("utf-8")
        project_files["src/App/packages.lock.json"] = b"{not-valid-json"

        sc_res = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=project_files,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(sc_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
        ids = {f["id"] for f in sc_res["findings"]}
        self.assertIn("static_code.lockfile_missing_or_invalid", ids)

        # Disk walk: symlinked nested packages.lock.json outside root is never opened and fails closed
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            outside = tmp_path / "outside_lock.json"
            outside.write_text('{"version": 1, "dependencies": {"net10.0": {}}}', encoding="utf-8")
            proj_dir = tmp_path / "dotnet-proj"
            for rel, content in bundle["project_files"].items():
                dest = proj_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
            (proj_dir / "packages.lock.json").write_text(
                '{"version": 1, "dependencies": {"net10.0": {}}}', encoding="utf-8"
            )
            sub_lock = proj_dir / "apps" / "cli" / "packages.lock.json"
            sub_lock.unlink()
            sub_lock.symlink_to(outside)

            disk_res = static_code.audit_static_code(
                bundle["provenance"],
                approved_deps=bundle["template_spec"]["approved_deps"],
                project_root=proj_dir,
                template_spec=bundle["template_spec"],
                template_files=bundle["template_files"],
            )
            self.assertEqual(disk_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
            disk_ids = {f["id"] for f in disk_res["findings"]}
            self.assertIn("static_code.unverified_file", disk_ids)

            # Declared credential nested packages.lock.json is not opened and marks coverage could_not_verify
            sub_lock.unlink()
            sub_lock.write_text('{"version": 1, "dependencies": {"net10.0": {}}}', encoding="utf-8")

            @redaction_scope
            def _run_declared():
                declare_credential(sub_lock)
                return static_code.audit_static_code(
                    bundle["provenance"],
                    approved_deps=bundle["template_spec"]["approved_deps"],
                    project_root=proj_dir,
                    template_spec=bundle["template_spec"],
                    template_files=bundle["template_files"],
                )

            cred_res = _run_declared()
            self.assertEqual(cred_res["coverage"], COVERAGE_COULD_NOT_VERIFY)

    def test_gap4_malformed_nuget_lock_shapes_report_could_not_verify(self) -> None:
        """Gap 4: NuGet {"version":1,"dependencies":{"net8.0":[...]}} and other wrong shapes must yield could_not_verify and static_code.lockfile_missing_or_invalid."""
        bundle = _build_bundle("dotnet-golden")
        malformed_payloads = [
            json.dumps({"version": 1, "dependencies": {"net8.0": [{"Forbidden": "1.0.0"}]}}),
            json.dumps({"version": 1, "dependencies": {"net8.0": {"Pkg": "1.0.0"}}}),
            json.dumps({"version": 1, "dependencies": {"net8.0": {"Pkg": {"type": "Direct"}}}}),
            json.dumps({"version": 1, "dependencies": {"net8.0": {"Pkg": {"type": 123, "resolved": "1.0.0"}}}}),
            json.dumps({"version": "bad", "dependencies": {"net8.0": {}}}),
        ]
        for payload in malformed_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    static_code.parse_nuget_lock(payload)

                project_files = dict(bundle["project_files"])
                project_files["apps/cli/packages.lock.json"] = payload.encode("utf-8")
                sc_res = static_code.audit_static_code(
                    bundle["provenance"],
                    approved_deps=bundle["template_spec"]["approved_deps"],
                    project_files=project_files,
                    template_spec=bundle["template_spec"],
                    template_files=bundle["template_files"],
                )
                self.assertEqual(sc_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
                ids = {f["id"] for f in sc_res["findings"]}
                self.assertIn("static_code.lockfile_missing_or_invalid", ids)
                adapted = adapt_component_result(sc_res, component_id="static_code.dotnet-golden")
                headline = compute_headline(component_results=[adapted])
                self.assertEqual(headline["coverage"], COVERAGE_COULD_NOT_VERIFY)
                self.assertFalse(headline["can_claim_clean"])

    def test_gap4_malformed_go_sum_entries_report_could_not_verify(self) -> None:
        """Gap 4: Go go.sum line `not-a-module vgarbage h1:` must be rejected as malformed (could_not_verify)."""
        bundle = _build_bundle("go-golden")
        malformed_lines = [
            "not-a-module vgarbage h1:\n",
            "github.com/pkg/errors v0.9.1 h1:\n",
            "github.com/pkg/errors vgarbage h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n",
            "not-a-module v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n",
            "github.com/pkg/errors v0.9.1 h1:short=\n",
        ]
        for bad_go_sum in malformed_lines:
            with self.subTest(bad_go_sum=bad_go_sum.strip()):
                with self.assertRaises(ValueError):
                    static_code.parse_go_sum(bad_go_sum)

                project_files = dict(bundle["project_files"])
                project_files["go.sum"] = bad_go_sum.encode("utf-8")
                sc_res = static_code.audit_static_code(
                    bundle["provenance"],
                    approved_deps=bundle["template_spec"]["approved_deps"],
                    project_files=project_files,
                    template_spec=bundle["template_spec"],
                    template_files=bundle["template_files"],
                )
                self.assertEqual(sc_res["coverage"], COVERAGE_COULD_NOT_VERIFY)
                ids = {f["id"] for f in sc_res["findings"]}
                self.assertIn("static_code.lockfile_missing_or_invalid", ids)

        # Valid go.sum with unapproved module should parse and trigger unapproved_dependency
        valid_go_sum = (
            "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n"
            "github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n"
        )
        parsed = static_code.parse_go_sum(valid_go_sum)
        self.assertEqual(parsed["external_packages"], {"github.com/pkg/errors": ["v0.9.1"]})

    def test_gap5_cmake_quoted_commented_bracket_commented_and_unparseable_calls(self) -> None:
        """Gap 5: CMake quoted FetchContent_Declare/find_package detected; line and bracket comments ignored; unparseable calls report could_not_verify."""
        bundle = _build_bundle("cpp-golden")

        # 1. Quoted FetchContent_Declare("ForbiddenPkg" ...) is detected as unapproved dependency
        cmake_quoted = (
            'cmake_minimum_required(VERSION 3.28)\n'
            'project(my_service LANGUAGES CXX)\n'
            'FetchContent_Declare("ForbiddenPkg" GIT_REPOSITORY https://example.com/forbidden.git)\n'
        )
        project_files_q = dict(bundle["project_files"])
        project_files_q["CMakeLists.txt"] = cmake_quoted.encode("utf-8")
        res_q = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=project_files_q,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(res_q["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(res_q["classification"], CLASSIFICATION_WARNING)
        unapproved_q = [f for f in res_q["findings"] if f["id"] == "static_code.unapproved_dependency"]
        self.assertEqual(len(unapproved_q), 1)
        self.assertEqual(unapproved_q[0]["evidence"]["package"], "ForbiddenPkg")

        # Also test find_package("ForbiddenFindPkg" REQUIRED)
        cmake_find = (
            'cmake_minimum_required(VERSION 3.28)\n'
            'project(my_service LANGUAGES CXX)\n'
            'find_package("ForbiddenFindPkg" REQUIRED)\n'
        )
        project_files_f = dict(bundle["project_files"])
        project_files_f["CMakeLists.txt"] = cmake_find.encode("utf-8")
        res_f = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=project_files_f,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(res_f["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(res_f["classification"], CLASSIFICATION_WARNING)
        unapproved_f = [f for f in res_f["findings"] if f["id"] == "static_code.unapproved_dependency"]
        self.assertEqual(len(unapproved_f), 1)
        self.assertEqual(unapproved_f[0]["evidence"]["package"], "ForbiddenFindPkg")

        # 2. Line comment `# FetchContent_Declare(ForbiddenPkg ...)` is NOT reported as a dependency
        cmake_line_comment = (
            "cmake_minimum_required(VERSION 3.28)\n"
            "project(my_service LANGUAGES CXX)\n"
            "# FetchContent_Declare(ForbiddenPkg GIT_REPOSITORY https://example.com/forbidden.git)\n"
            "# find_package(ForbiddenFindPkg REQUIRED)\n"
        )
        project_files_lc = dict(bundle["project_files"])
        project_files_lc["CMakeLists.txt"] = cmake_line_comment.encode("utf-8")
        res_lc = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=project_files_lc,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(res_lc["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(res_lc["classification"], CLASSIFICATION_INFO)
        self.assertEqual(res_lc["findings"], [])

        # 3. Bracket comment `#[[ FetchContent_Declare(ForbiddenPkg ...) ]]` and `#[=[ ... ]=]` are NOT reported
        cmake_bracket_comment = (
            "cmake_minimum_required(VERSION 3.28)\n"
            "project(my_service LANGUAGES CXX)\n"
            "# [[\n"
            "Not a bracket comment because of space, wait: #[[ is bracket comment:\n"
            "]]\n"
            "#[[ FetchContent_Declare(ForbiddenPkg GIT_REPOSITORY https://example.com/forbidden.git)\n"
            "    find_package(\"ForbiddenFindPkg\" REQUIRED)\n"
            "]]\n"
            "#[==[\n"
            "FetchContent_Declare(\"AnotherForbidden\" URL https://example.com/a.tar.gz)\n"
            "]==]\n"
        )
        project_files_bc = dict(bundle["project_files"])
        project_files_bc["CMakeLists.txt"] = cmake_bracket_comment.encode("utf-8")
        res_bc = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=project_files_bc,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(res_bc["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(res_bc["classification"], CLASSIFICATION_INFO)
        self.assertEqual(res_bc["findings"], [])

        # 4. Unparseable FetchContent_Declare / find_package calls report could_not_verify
        unparseable_samples = [
            "cmake_minimum_required(VERSION 3.28)\nFetchContent_Declare()\n",
            "cmake_minimum_required(VERSION 3.28)\nFetchContent_Declare(${DYNAMIC_PKG} GIT_REPOSITORY https://example.com)\n",
            "cmake_minimum_required(VERSION 3.28)\nFetchContent_Declare(\"UnclosedQuote\n",
            "cmake_minimum_required(VERSION 3.28)\nFetchContent_Declare(PkgWithoutClosingParen\n",
            "cmake_minimum_required(VERSION 3.28)\nfind_package(${DYNAMIC_FIND} REQUIRED)\n",
            "cmake_minimum_required(VERSION 3.28)\nfind_package()\n",
            "cmake_minimum_required(VERSION 3.28)\n#[[ unclosed bracket comment FetchContent_Declare(Foo)\n",
        ]
        for bad_cmake in unparseable_samples:
            with self.subTest(bad_cmake=bad_cmake.strip()):
                with self.assertRaises(ValueError):
                    static_code.parse_cmake_lock(bad_cmake)

                project_files_bad = dict(bundle["project_files"])
                project_files_bad["CMakeLists.txt"] = bad_cmake.encode("utf-8")
                res_bad = static_code.audit_static_code(
                    bundle["provenance"],
                    approved_deps=bundle["template_spec"]["approved_deps"],
                    project_files=project_files_bad,
                    template_spec=bundle["template_spec"],
                    template_files=bundle["template_files"],
                )
                self.assertEqual(res_bad["coverage"], COVERAGE_COULD_NOT_VERIFY)
                ids_bad = {f["id"] for f in res_bad["findings"]}
                self.assertIn("static_code.lockfile_missing_or_invalid", ids_bad)


if __name__ == "__main__":
    unittest.main()
