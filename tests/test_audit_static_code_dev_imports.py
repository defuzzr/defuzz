"""static_code maps TS/JS built-ins and declared packages in test, config and tool files.

A fresh web-golden project imports `vitest`, `vite`, `@playwright/test` and `node:` modules
from its tests, config files and tools. Those imports name a built-in module or a declared
package that is in the lockfile, so they are mapped. What cannot be mapped stays visible:
a dynamic import of a computed value or of a URL, a package missing from the lockfile, and a
development package imported from production source.
"""

from __future__ import annotations

import unittest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.audit.vendor import static_code  # noqa: E402
from tests.test_audit_golden_lockfiles import _build_bundle  # noqa: E402

UNMAPPABLE = "static_code.unmappable_import"
MISSING = "static_code.import_missing_from_lock"

_BUNDLES: dict[str, dict] = {}


def _bundle(template_id: str) -> dict:
    if template_id not in _BUNDLES:
        _BUNDLES[template_id] = _build_bundle(template_id)
    return _BUNDLES[template_id]


def _run(template_id: str, extra: dict[str, str] | None = None) -> dict:
    bundle = _bundle(template_id)
    files = dict(bundle["project_files"])
    for rel, text in (extra or {}).items():
        files[rel] = text.encode("utf-8")
    return static_code.audit_static_code(
        bundle["provenance"],
        approved_deps=bundle["template_spec"]["approved_deps"],
        project_files=files,
        template_spec=bundle["template_spec"],
        template_files=bundle["template_files"],
    )


def _notes(sc: dict, path: str | None = None) -> list[dict]:
    return [
        f["evidence"]
        for f in sc["findings"]
        if f["id"] == UNMAPPABLE and (path is None or f["evidence"]["path"] == path)
    ]


def _missing(sc: dict, path: str) -> list[dict]:
    return [f["evidence"] for f in sc["findings"] if f["id"] == MISSING and f["evidence"]["path"] == path]


class TestStaticCodeDevImports(unittest.TestCase):
    def test_builtins_are_mapped_in_tests_and_inside_blocks(self) -> None:
        rel_test = "tests/unit/builtins-extra.test.ts"
        rel_src = "src/lib/builtins-extra.ts"
        sc = _run("web-golden", {
            rel_test: 'import fs from "node:fs";\nimport path from "path";\nfs.readFileSync(path.sep);\n',
            rel_src: 'export function f() {\n  const code = `import os from "node:os";`;\n  return code;\n}\n',
        })
        self.assertEqual(_notes(sc, rel_test), [])
        self.assertEqual(_notes(sc, rel_src), [])

    def test_declared_dependency_imported_from_a_test_is_mapped(self) -> None:
        rel = "packages/adapters/my-service-http-hono/src/extra.test.ts"
        sc = _run("ts-node-golden", {rel: 'import { Hono } from "hono";\nnew Hono();\n'})
        self.assertEqual(_notes(sc, rel), [])
        self.assertEqual(_missing(sc, rel), [])

    def test_declared_dev_dependency_imported_from_test_config_and_tool_is_mapped(self) -> None:
        extra = {
            "tests/unit/extra.test.ts": 'import { it } from "vitest";\nit("x", () => {});\n',
            "extra.config.ts": 'import { defineConfig } from "vite";\nexport default defineConfig({});\n',
            "tools/xtask/extra.ts": 'import { chromium } from "@playwright/test";\nchromium;\n',
            "scripts/extra.ts": 'import { defineConfig } from "vite";\ndefineConfig({});\n',
        }
        sc = _run("web-golden", extra)
        for rel in extra:
            with self.subTest(rel=rel):
                self.assertEqual(_notes(sc, rel), [])
                self.assertEqual(_missing(sc, rel), [])

    def test_dev_dependency_imported_from_production_source_stays_visible(self) -> None:
        rel = "src/lib/uses-vitest.ts"
        sc = _run("web-golden", {rel: 'import { expect } from "vitest";\nexport const e = expect;\n'})
        notes = _notes(sc, rel)
        self.assertEqual([(n["target"], n["reason"]) for n in notes], [("vitest", "conditional_or_dev_scope")])
        self.assertEqual(sc["coverage"], "could_not_verify")

    def test_undeclared_package_stays_a_finding_in_tests_and_source(self) -> None:
        for rel in ("tests/unit/left.test.ts", "src/lib/left.ts", "tools/xtask/left.ts"):
            with self.subTest(rel=rel):
                sc = _run("web-golden", {rel: 'import leftPad from "left-pad-not-locked";\nleftPad;\n'})
                self.assertEqual([m["imported_target"] for m in _missing(sc, rel)], ["left-pad-not-locked"])

    def test_dynamic_import_with_literal_is_mapped_and_expression_stays_a_note(self) -> None:
        rel = "tests/unit/dyn-extra.test.ts"
        text = (
            'const a = await import("./local.ts");\n'
            "const b = await import('node:fs');\n"
            'const c = await import("vitest");\n'
            "const d = await import(SOME_URL);\n"
            'const e = await import("https://example.com/remote.js");\n'
            'const f = await import("left-pad-not-locked");\n'
        )
        sc = _run("web-golden", {rel: text})
        self.assertEqual(
            sorted((n["line"], n["target"], n["reason"]) for n in _notes(sc, rel)),
            [(4, "SOME_URL", "dynamic_import"), (5, '"https://example.com/remote.js"', "dynamic_import")],
        )
        self.assertEqual([m["line"] for m in _missing(sc, rel)], [6])

    def test_fresh_web_golden_numbers(self) -> None:
        sc = _run("web-golden")
        notes = _notes(sc)
        self.assertEqual(
            sorted((n["path"], n["line"], n["target"]) for n in notes),
            [
                ("tests/unit/dist-check.test.ts", 277, '"https://example.com/m.js"'),
                ("tests/unit/dist-check.test.ts", 317, "'https://example.com/m.js'"),
                ("tests/unit/dist-check.test.ts", 395, '"Http://example.com/m.js"'),
                ("tests/unit/xtask-main.test.ts", 1143, "LEFTOVER_URL"),
            ],
        )
        self.assertEqual({n["reason"] for n in notes}, {"dynamic_import"})
        self.assertEqual([f for f in sc["findings"] if f["id"] != UNMAPPABLE], [])
        # Four imports really cannot be mapped; the module has no partial coverage word,
        # so the documented rule keeps the section could_not_verify.
        self.assertEqual(sc["coverage"], "could_not_verify")
        self.assertEqual(sc["summary"]["unmappable_imports_count"], 4)
        self.assertEqual(sc["summary"]["mapped_imports_count"], 19)

    def test_fresh_ts_node_golden_keeps_its_workspace_notes(self) -> None:
        sc = _run("ts-node-golden")
        notes = _notes(sc)
        self.assertEqual(len(notes), 30)
        self.assertEqual({n["reason"] for n in notes}, {"workspace_crate"})
        self.assertEqual([f for f in sc["findings"] if f["id"] != UNMAPPABLE], [])


if __name__ == "__main__":
    unittest.main()
