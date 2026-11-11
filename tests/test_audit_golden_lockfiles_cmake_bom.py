"""Regressions for nested CMake scanning, slashless go.sum modules, CMake strings/args, and UTF-8 BOM lockfiles."""

from __future__ import annotations

import hashlib
import json
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


class TestAuditGoldenLockfilesCmakeBom(unittest.TestCase):
    def test_nested_cmake_lists_and_cmake_scripts_aggregated_and_fail_closed(self) -> None:
        """Fix 1: Aggregate every **/CMakeLists.txt and **/*.cmake in norm_project; fail closed on any parse error; keep all 7 cpp-golden CMake files verified."""
        bundle = _build_bundle("cpp-golden")

        # Baseline check: all 7 real cpp-golden CMake files exist and yield verified with 0 findings
        cmake_paths = sorted(
            rel
            for rel in bundle["project_files"]
            if rel == "CMakeLists.txt" or rel.endswith("/CMakeLists.txt") or rel.endswith(".cmake")
        )
        self.assertEqual(
            cmake_paths,
            [
                "CMakeLists.txt",
                "adapters/CMakeLists.txt",
                "apps/cli/CMakeLists.txt",
                "cmake/xtask.cmake",
                "domain/CMakeLists.txt",
                "foundation/CMakeLists.txt",
                "tests/CMakeLists.txt",
            ],
        )
        clean_res = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=bundle["project_files"],
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(clean_res["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(clean_res["classification"], CLASSIFICATION_INFO)
        self.assertEqual(clean_res["findings"], [])

        # Repro: FetchContent_Declare(googletest ...) in tests/CMakeLists.txt must report unapproved_dependency
        proj_nested_fc = dict(bundle["project_files"])
        proj_nested_fc["tests/CMakeLists.txt"] = (
            bundle["project_files"]["tests/CMakeLists.txt"].decode("utf-8")
            + "\ninclude(FetchContent)\n"
            + "FetchContent_Declare(googletest GIT_REPOSITORY https://github.com/google/googletest.git GIT_TAG v1.14.0)\n"
        ).encode("utf-8")
        res_fc = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=proj_nested_fc,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(res_fc["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(res_fc["classification"], CLASSIFICATION_WARNING)
        unapproved_fc = [
            f for f in res_fc["findings"] if f["id"] == "static_code.unapproved_dependency"
        ]
        self.assertEqual(len(unapproved_fc), 1)
        self.assertEqual(unapproved_fc[0]["evidence"]["package"], "googletest")

        # Nested *.cmake script with find_package(Boost REQUIRED) must also be aggregated
        proj_nested_mod = dict(bundle["project_files"])
        proj_nested_mod["cmake/deps.cmake"] = b"find_package(Boost REQUIRED)\n"
        res_mod = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=proj_nested_mod,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(res_mod["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(res_mod["classification"], CLASSIFICATION_WARNING)
        unapproved_mod = [
            f for f in res_mod["findings"] if f["id"] == "static_code.unapproved_dependency"
        ]
        self.assertEqual(len(unapproved_mod), 1)
        self.assertEqual(unapproved_mod[0]["evidence"]["package"], "Boost")

        # Any nested CMakeLists.txt or *.cmake failing to parse => could_not_verify (fail closed)
        for bad_rel in ("tests/CMakeLists.txt", "cmake/xtask.cmake", "cmake/broken.cmake"):
            with self.subTest(bad_rel=bad_rel):
                proj_bad = dict(bundle["project_files"])
                proj_bad[bad_rel] = b"find_package(${DYNAMIC_UNVERIFIABLE} REQUIRED)\n"
                res_bad = static_code.audit_static_code(
                    bundle["provenance"],
                    approved_deps=bundle["template_spec"]["approved_deps"],
                    project_files=proj_bad,
                    template_spec=bundle["template_spec"],
                    template_files=bundle["template_files"],
                )
                self.assertEqual(res_bad["coverage"], COVERAGE_COULD_NOT_VERIFY)
                ids_bad = {f["id"] for f in res_bad["findings"]}
                self.assertIn("static_code.lockfile_missing_or_invalid", ids_bad)
                adapted = adapt_component_result(res_bad, component_id="static_code.cpp-golden")
                headline = compute_headline(component_results=[adapted])
                self.assertEqual(headline["coverage"], COVERAGE_COULD_NOT_VERIFY)
                self.assertFalse(headline["can_claim_clean"])

        # Declared credential nested CMakeLists.txt on disk is never opened and marks coverage could_not_verify
        with tempfile.TemporaryDirectory() as tmp:
            proj_dir = Path(tmp) / "cpp-proj"
            for rel, content in bundle["project_files"].items():
                dest = proj_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
            nested_cmake = proj_dir / "tests" / "CMakeLists.txt"

            @redaction_scope
            def _run_declared():
                declare_credential(nested_cmake)
                return static_code.audit_static_code(
                    bundle["provenance"],
                    approved_deps=bundle["template_spec"]["approved_deps"],
                    project_root=proj_dir,
                    template_spec=bundle["template_spec"],
                    template_files=bundle["template_files"],
                )

            cred_res = _run_declared()
            self.assertEqual(cred_res["coverage"], COVERAGE_COULD_NOT_VERIFY)

    def test_go_sum_accepts_slashless_domain_modules_and_rejects_garbage(self) -> None:
        """Fix 2: go.sum accepts valid slashless module paths (gotest.tools, gioui.org) while still rejecting garbage."""
        bundle = _build_bundle("go-golden")
        valid_slashless_go_sum = (
            "gotest.tools v2.2.0+incompatible h1:VsBPFP1AI068pPrMxtb/S8Zkgf9xEmTLJjfM+P0UIEo=\n"
            "gotest.tools v2.2.0+incompatible/go.mod h1:DsYFclhRJ6vuDpmuTbkuFWG+y2sxOXAzmJt81HFBacw=\n"
            "gioui.org v0.0.0-20240101120000-abcdef012345 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n"
        )
        parsed = static_code.parse_go_sum(valid_slashless_go_sum)
        self.assertEqual(
            parsed["external_packages"],
            {
                "gioui.org": ["v0.0.0-20240101120000-abcdef012345"],
                "gotest.tools": ["v2.2.0+incompatible"],
            },
        )

        # When unapproved in go-golden, produces verified + unapproved_dependency (not could_not_verify)
        project_files = dict(bundle["project_files"])
        project_files["go.sum"] = valid_slashless_go_sum.encode("utf-8")
        res_unapproved = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=project_files,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(res_unapproved["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(res_unapproved["classification"], CLASSIFICATION_WARNING)
        pkgs = sorted(
            f["evidence"]["package"]
            for f in res_unapproved["findings"]
            if f["id"] == "static_code.unapproved_dependency"
        )
        self.assertEqual(pkgs, ["gioui.org", "gotest.tools"])

        # When approved, produces verified + 0 findings
        res_approved = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps={"go": ["gotest.tools", "gioui.org"]},
            project_files=project_files,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(res_approved["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(res_approved["classification"], CLASSIFICATION_INFO)
        self.assertEqual(res_approved["findings"], [])

        # Still rejects garbage module names without a valid domain dot
        for bad_line in (
            "not-a-module vgarbage h1:\n",
            "not-a-module v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n",
            "not-a-module/subpkg v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n",
            ".leading.dot v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n",
            "trailing.dot. v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n",
        ):
            with self.subTest(bad_line=bad_line.strip()):
                with self.assertRaises(ValueError):
                    static_code.parse_go_sum(bad_line)

    def test_cmake_ignores_find_package_and_fetchcontent_inside_strings_and_arguments(self) -> None:
        """Fix 3: message("... find_package ...") and if(COMMAND find_package) do not trigger false could_not_verify or false dependencies."""
        bundle = _build_bundle("cpp-golden")
        cmake_with_strings_and_args = (
            "cmake_minimum_required(VERSION 3.28)\n"
            "project(my_service LANGUAGES CXX)\n"
            'message(STATUS "Checking find_package and FetchContent_Declare in string")\n'
            'message("Even find_package(FakePkgInString) inside quotes is not a call")\n'
            "if(COMMAND find_package)\n"
            '    message(STATUS "find_package command exists")\n'
            "endif()\n"
            "if(COMMAND FetchContent_Declare)\n"
            '    message(STATUS "FetchContent_Declare command exists")\n'
            "endif()\n"
        )
        parsed = static_code.parse_cmake_lock(cmake_with_strings_and_args)
        self.assertEqual(parsed["external_packages"], {})

        project_files = dict(bundle["project_files"])
        project_files["CMakeLists.txt"] = cmake_with_strings_and_args.encode("utf-8")
        res = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=project_files,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        self.assertEqual(res["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(res["classification"], CLASSIFICATION_INFO)
        self.assertEqual(res["findings"], [])

        # Real call inside an if(...) block is still detected at command position
        cmake_in_branch = (
            cmake_with_strings_and_args
            + "if(BUILD_TESTING)\n"
            + "    find_package(GTest REQUIRED)\n"
            + "endif()\n"
        )
        parsed_branch = static_code.parse_cmake_lock(cmake_in_branch)
        self.assertEqual(parsed_branch["external_packages"], {"GTest": ["declared"]})

    def test_nuget_and_other_lockfiles_with_utf8_bom_verify_cleanly(self) -> None:
        """Fix 4: NuGet packages.lock.json (and go.sum / CMakeLists.txt) with UTF-8 BOM do not cause false could_not_verify."""
        dotnet_bundle = _build_bundle("dotnet-golden")
        raw_lock = dotnet_bundle["project_files"]["apps/cli/packages.lock.json"]
        bom_lock = b"\xef\xbb\xbf" + raw_lock

        # Direct parser accepts leading U+FEFF BOM
        parsed_direct = static_code.parse_nuget_lock(bom_lock.decode("utf-8"))
        self.assertEqual(parsed_direct["external_packages"], {})

        # Full audit_static_code on BOM-prefixed packages.lock.json yields verified
        dotnet_files = dict(dotnet_bundle["project_files"])
        dotnet_files["apps/cli/packages.lock.json"] = bom_lock
        dotnet_res = static_code.audit_static_code(
            dotnet_bundle["provenance"],
            approved_deps=dotnet_bundle["template_spec"]["approved_deps"],
            project_files=dotnet_files,
            template_spec=dotnet_bundle["template_spec"],
            template_files=dotnet_bundle["template_files"],
        )
        self.assertEqual(dotnet_res["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(dotnet_res["classification"], CLASSIFICATION_INFO)
        self.assertEqual(dotnet_res["findings"], [])

        # BOM-prefixed CMakeLists.txt and go.sum also yield verified
        cpp_bundle = _build_bundle("cpp-golden")
        cpp_files = dict(cpp_bundle["project_files"])
        cpp_files["CMakeLists.txt"] = b"\xef\xbb\xbf" + cpp_files["CMakeLists.txt"]
        cpp_res = static_code.audit_static_code(
            cpp_bundle["provenance"],
            approved_deps=cpp_bundle["template_spec"]["approved_deps"],
            project_files=cpp_files,
            template_spec=cpp_bundle["template_spec"],
            template_files=cpp_bundle["template_files"],
        )
        self.assertEqual(cpp_res["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(cpp_res["findings"], [])

        go_bundle = _build_bundle("go-golden")
        go_files = dict(go_bundle["project_files"])
        go_files["go.sum"] = b"\xef\xbb\xbf" + go_files["go.sum"]
        go_res = static_code.audit_static_code(
            go_bundle["provenance"],
            approved_deps=go_bundle["template_spec"]["approved_deps"],
            project_files=go_files,
            template_spec=go_bundle["template_spec"],
            template_files=go_bundle["template_files"],
        )
        self.assertEqual(go_res["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(go_res["findings"], [])


if __name__ == "__main__":
    unittest.main()
