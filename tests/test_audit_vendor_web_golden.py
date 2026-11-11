"""web-golden projects are audited by static_code and template_drift as the ts-node ecosystem."""

from __future__ import annotations

import time
import unittest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.audit.contract import COVERAGE_NOT_INCLUDED  # noqa: E402
from hermes_plugins.defuzz.audit.vendor import static_code, template_drift  # noqa: E402
from tests.test_audit_golden_lockfiles import _build_bundle  # noqa: E402

UNAPPROVED_LOCK_SNIPPET = (
    "  forbidden-pkg@1.2.3:\n"
    "    resolution: {integrity: sha512-AAAA}\n"
)


def _ids(result: dict) -> set[str]:
    return {f["id"] for f in result["findings"]}


class TestAuditVendorWebGolden(unittest.TestCase):
    def _run(self, project_files: dict) -> tuple[dict, dict]:
        bundle = self.bundle
        sc = static_code.audit_static_code(
            bundle["provenance"],
            approved_deps=bundle["template_spec"]["approved_deps"],
            project_files=project_files,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        td = template_drift.audit_template_drift(
            bundle["provenance"],
            project_files=project_files,
            template_spec=bundle["template_spec"],
            template_files=bundle["template_files"],
        )
        return sc, td

    def setUp(self) -> None:
        self.bundle = _build_bundle("web-golden")

    def test_registry_maps_web_golden_to_ts_node(self) -> None:
        self.assertEqual(static_code._FALLBACK_TEMPLATE_TO_ECOSYSTEM.get("web-golden"), "ts-node")
        self.assertIn("web-golden", static_code.GOLDEN_TEMPLATE_IDS)
        self.assertIn("web-golden", template_drift.GOLDEN_TEMPLATE_IDS)
        self.assertEqual(static_code.TEMPLATE_TO_ECOSYSTEM["web-golden"], "ts-node")

    def test_fresh_project_in_scope_and_clean(self) -> None:
        sc, td = self._run(dict(self.bundle["project_files"]))
        for res in (sc, td):
            self.assertNotEqual(res["coverage"], COVERAGE_NOT_INCLUDED, msg=res["findings"])
            self.assertNotIn("static_code.not_included", _ids(res))
            self.assertNotIn("template.not_included", _ids(res))
        self.assertNotIn("static_code.unapproved_dependency", _ids(sc))
        warnings = [f for f in sc["findings"] + td["findings"] if f.get("classification") == "warning"]
        self.assertEqual(warnings, [])
        unmappable = [f["evidence"] for f in sc["findings"] if f["id"] == "static_code.unmappable_import"]
        self.assertEqual({e["reason"] for e in unmappable}, {"dynamic_import"})
        self.assertFalse([e for e in unmappable if e["target"].startswith(("node:", "vite", "@playwright/"))])

    def _seed_lock(self, which: str) -> dict:
        files = dict(self.bundle["project_files"])
        lock = files["pnpm-lock.yaml"].decode("utf-8")
        marker = "\npackages:\n\n"
        self.assertEqual(lock.count(marker), 2)
        i = lock.find(marker) if which == "first" else lock.rfind(marker)
        files["pnpm-lock.yaml"] = (
            lock[: i + len(marker)] + UNAPPROVED_LOCK_SNIPPET.lstrip("\n") + "\n" + lock[i + len(marker) :]
        ).encode("utf-8")
        return files

    def _unapproved(self, files: dict) -> set:
        sc, _td = self._run(files)
        return {
            f["evidence"].get("package")
            for f in sc["findings"]
            if f["id"] == "static_code.unapproved_dependency"
        }

    def test_seeded_unapproved_lock_dependency(self) -> None:
        self.assertIn("forbidden-pkg", self._unapproved(self._seed_lock("main")))

    def test_seeded_unapproved_dependency_in_config_document(self) -> None:
        """The pnpm lockfile's first YAML document (config dependencies) is scanned."""
        self.assertIn("forbidden-pkg", self._unapproved(self._seed_lock("first")))

    def _first_doc_config(self, replacement: str) -> dict:
        files = dict(self.bundle["project_files"])
        lock = files["pnpm-lock.yaml"].decode("utf-8")
        old = "    configDependencies: {}\n"
        self.assertEqual(lock.count(old), 1)
        files["pnpm-lock.yaml"] = lock.replace(old, replacement).encode("utf-8")
        return files

    def test_unapproved_config_dependency_only_in_first_section(self) -> None:
        for block in (
            "    configDependencies:\n      forbidden-pkg: 1.2.3+sha512-AAAA\n",
            "    configDependencies: {forbidden-pkg: 1.2.3+sha512-AAAA}\n",
            "    configDependencies:\n      forbidden-pkg:\n        specifier: 1.2.3\n        version: 1.2.3\n",
        ):
            with self.subTest(block=block):
                self.assertEqual(self._unapproved(self._first_doc_config(block)), {"forbidden-pkg"})

    def test_approved_config_dependency_is_not_reported(self) -> None:
        files = self._first_doc_config("    configDependencies:\n      forbidden-pkg: 1.2.3+sha512-AAAA\n")
        spec = dict(self.bundle["template_spec"])
        spec["approved_deps"] = {k: [*v, "forbidden-pkg"] for k, v in spec["approved_deps"].items()}
        self.bundle = {**self.bundle, "template_spec": spec}
        self.assertEqual(self._unapproved(files), set())
        self.assertEqual(self._unapproved(self._seed_lock("first")), set())

    def test_package_named_only_in_a_comment_is_not_counted(self) -> None:
        files = self._first_doc_config(
            "    # forbidden-pkg: 1.2.3\n    configDependencies: {}  # forbidden-pkg@1.2.3\n"
        )
        lock = files["pnpm-lock.yaml"].decode("utf-8")
        marker = "\npackages:\n\n"
        i = lock.find(marker) + len(marker)
        files["pnpm-lock.yaml"] = (lock[:i] + "  # forbidden-pkg@1.2.3:\n" + lock[i:]).encode("utf-8")
        self.assertEqual(self._unapproved(files), set())

    def test_malformed_first_section_is_could_not_verify(self) -> None:
        for block in (
            "    configDependencies: {forbidden-pkg: 1.2.3\n",
            "    configDependencies: [forbidden-pkg]\n",
            "    configDependencies: forbidden-pkg\n",
        ):
            with self.subTest(block=block):
                sc, _td = self._run(self._first_doc_config(block))
                bad = [f for f in sc["findings"] if f["id"] == "static_code.lockfile_missing_or_invalid"]
                self.assertEqual(len(bad), 1, msg=sc["findings"])
                self.assertEqual(bad[0]["coverage"], "could_not_verify")
                self.assertTrue(bad[0]["evidence"]["reason"].startswith("parse_error:"))

    def test_clean_ts_node_golden_has_no_unapproved_dependency(self) -> None:
        self.bundle = _build_bundle("ts-node-golden")
        self.assertEqual(self._unapproved(dict(self.bundle["project_files"])), set())

    def test_one_megabyte_lockfile_scans_in_linear_time(self) -> None:
        entries = "".join(
            f"      cfg-{n}: 1.0.{n}+sha512-{'A' * 40}  # {'{' * 30}\n" for n in range(10_000)
        )
        cases = (
            (self._first_doc_config("    configDependencies:\n" + entries), 10_000),
            (self._first_doc_config("    configDependencies: {" + "{a: '#, " * 130_000 + "\n"), None),
        )
        for files, expected in cases:
            self.assertGreater(len(files["pnpm-lock.yaml"]), 1_000_000)
            text = files["pnpm-lock.yaml"].decode("utf-8")
            start = time.perf_counter()
            try:
                static_code.parse_pnpm_lock(text)
            except ValueError:
                self.assertIsNone(expected)
            self.assertLess(time.perf_counter() - start, 2.0)
            sc, _td = self._run(files)
            unapproved = {
                f["evidence"]["package"] for f in sc["findings"] if f["id"] == "static_code.unapproved_dependency"
            }
            if expected is None:
                self.assertIn("static_code.lockfile_missing_or_invalid", _ids(sc))
            else:
                self.assertEqual(len(unapproved), expected)


if __name__ == "__main__":
    unittest.main()
