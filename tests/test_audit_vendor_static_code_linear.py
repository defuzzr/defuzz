"""Bound the vendored static-code source scans and pin them against the base blob.

The exam case ``static_code_open_import`` (a ts-node-golden project whose
``src.js`` is ``import(`` repeated) spent seconds in the dynamic
``import(``/``require(`` pattern ``\\(\\s*([^)]*?)\\s*\\)``: every ``import(`` start
rescanned the rest of the file for a ``)`` that never came. The same file had the
same shape in five more places, profiled at 10/20/40 KB before the fix:

* static ``import ... from`` pattern: lazy ``[\\s\\S]*?\\s+from\\s+`` rescanned the
  rest of the file per line (``import x\\n`` lines quadratic, ``import`` plus
  one long blank run worse than cubic);
* Rust ``#[allow(`` / ``#[expect(``: ``[^)]*`` before a required ``)`` (quadratic on
  one long line) and ``#\\s*!?\\s*\\[`` splitting the same blanks twice;
* Rust ``use\\s+(.+?)\\s*;``: lazy body plus ``\\s*`` over one blank run;
* Python ``noqa:`` / ``ruff: noqa:`` rule lists: ``\\s*`` before a class that
  already holds whitespace;
* TS ``catch`` and ``throw e``: adjacent ``\\s*`` around optional groups;
* every TS match counted newlines (and braces) from offset 0 again.

Hostile cases run in a subprocess with a hard timeout so a regression fails
instead of hanging. The differential corpus compares the whole scanner output
of the live module with the base (pre-fix) module's output on the same inputs,
recorded once into ``tests/fixtures/linear_baseline/static_code.json`` by
``scripts/gen_linear_baseline.py``; the tests need no repository history.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz.audit.vendor import static_code as live  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDOR_FILE = REPO_ROOT / "audit" / "vendor" / "static_code.py"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "linear_baseline" / "static_code.json"
ISOLATED_BUDGET_S = 1.0
SCANNER_BUDGET_S = 2.0
HARD_TIMEOUT_S = 20

# The upstream patterns, verbatim from the base blob (asserted below).
BASE_DYNAMIC = r"(?<![A-Za-z0-9_$.])(?:import|require)\s*\(\s*([^)]*?)\s*\)"
BASE_STATIC = r"(?m)^(\s*)(?:import|export)\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?['\"]([^'\"]+)['\"]\s*;?"
BASE_RUST_SUPPRESSION = r"#\s*!?\s*\[\s*(allow|expect)\s*\(([^)]*)\)\s*\]"
BASE_RUST_USE = r"^(?:pub(?:\([^)]*\))?\s+)?use\s+(.+?)\s*;"

_CHILD = textwrap.dedent(
    """
    import importlib.util
    import json
    import sys
    import time

    from tests import ensure_test_package

    ensure_test_package()
    import hermes_plugins.defuzz.audit.vendor  # noqa: F401

    mode, kind, n, module_path = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    name = "hermes_plugins.defuzz.audit.vendor._static_code_under_test"
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "hermes_plugins.defuzz.audit.vendor"
    spec.loader.exec_module(module)

    def rep(unit):
        return unit * max(1, n // len(unit))

    shapes = {
        # exam shape and five adversarial variants of the dynamic import
        "open_import": ("ts", rep("import(")),
        "require_spaces": ("ts", rep("require( ")),
        "mixed_case": ("ts", rep("Import(import(REQUIRE(require(")),
        "unicode_ws": ("ts", rep("import(" + chr(0x3000) + chr(0x85) + "é")),
        "nested_repeat": ("ts", rep("import(require(import((")),
        "near_miss_terminators": ("ts", rep("import(x]};" + chr(0xff09))),
        "many_closed_calls": ("ts", rep("import()" + chr(10))),
        # same-shape patterns elsewhere in the file
        "static_import_lines": ("ts", rep("import x" + chr(10))),
        "static_import_blank_run": ("ts", "import " + " " * n),
        "static_export_type_run": ("ts", "export type" + " " * n + "x"),
        "static_blank_lines": ("ts", rep(chr(10)) + "import x"),
        "catch_blank_run": ("ts", "catch" + " " * n + "x"),
        "catch_rethrow_blank_run": ("ts", "catch(e){throw e" + " " * n + "x"),
        "catch_many": ("ts", rep("catch{}")),
        "rust_allow_open": ("rs", rep("#[allow(")),
        "rust_allow_unclosed_bracket": ("rs", rep("#[allow(x)")),
        "rust_hash_blank_run": ("rs", "#" + " " * n + "!x"),
        "rust_use_blank_run": ("rs", "use a" + " " * n + "b;"),
        "rust_use_no_semicolon": ("rs", "use a" + " " * n + "b"),
        "py_noqa_blank_run": ("py", "x = 1  # noqa:" + " " * n + "-" + chr(10)),
        "py_ruff_blank_run": ("py", "# ruff: noqa:" + " " * n + "-" + chr(10)),
    }
    lang, text = shapes[kind]
    started = time.perf_counter()
    if mode == "scanner":
        if lang == "ts":
            res = module._scan_ts_imports_and_constructs("src/src.js", text)
            count = len(res["imports"]) + len(res["useless_try_catch"])
        elif lang == "rs":
            res = module._scan_rust_imports_and_constructs(
                "src/lib.rs", text, local_mods=set(), cargo_renamed_deps=set())
            count = len(res["imports"]) + len(res["suppressions"])
        else:
            count = len(module._scan_python_suppressions("a.py", text))
    else:
        if lang == "ts":
            count = len(list(module._iter_ts_dynamic_imports(text)))
            count += len(list(module._iter_ts_static_imports(text)))
        elif lang == "rs":
            count = 0
            for line in text.splitlines():
                count += len(list(module._iter_rust_suppressions(line)))
                count += module._match_rust_use(line.strip()) is not None
        else:
            count = len(module._scan_python_suppressions("a.py", text))
    elapsed = time.perf_counter() - started
    json.dump({"elapsed": elapsed, "count": count, "size": len(text)}, sys.stdout)
    """
)

_KINDS = (
    "open_import", "require_spaces", "mixed_case", "unicode_ws", "nested_repeat",
    "near_miss_terminators", "many_closed_calls", "static_import_lines",
    "static_import_blank_run", "static_export_type_run", "static_blank_lines",
    "catch_blank_run", "catch_rethrow_blank_run", "catch_many", "rust_allow_open",
    "rust_allow_unclosed_bracket", "rust_hash_blank_run", "rust_use_blank_run",
    "rust_use_no_semicolon", "py_noqa_blank_run", "py_ruff_blank_run",
)


def _run_child(mode: str, kind: str, n: int) -> dict:
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, mode, kind, str(n), str(VENDOR_FILE)],
            capture_output=True,
            text=True,
            timeout=HARD_TIMEOUT_S,
            cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"{mode} {kind} n={n} exceeded hard timeout {HARD_TIMEOUT_S}s: {exc}")
    assert proc.returncode == 0, proc.stderr[-800:]
    return json.loads(proc.stdout)


@pytest.mark.parametrize("n", [100_000, 1_000_000])
@pytest.mark.parametrize("kind", _KINDS)
def test_hostile_scanner_input_finishes_under_budget(kind: str, n: int) -> None:
    payload = _run_child("scanner", kind, n)
    print(f"TIMING scanner {kind} n={n} {payload['elapsed']:.4f}s")
    assert payload["elapsed"] < SCANNER_BUDGET_S, (
        f"{kind} n={n} took {payload['elapsed']:.4f}s; budget {SCANNER_BUDGET_S}s"
    )


@pytest.mark.parametrize("n", [100_000, 1_000_000])
@pytest.mark.parametrize("kind", _KINDS)
def test_hostile_isolated_matcher_finishes_under_budget(kind: str, n: int) -> None:
    payload = _run_child("isolated", kind, n)
    print(f"TIMING isolated {kind} n={n} {payload['elapsed']:.4f}s")
    assert payload["elapsed"] < ISOLATED_BUDGET_S, (
        f"{kind} n={n} took {payload['elapsed']:.4f}s; budget {ISOLATED_BUDGET_S}s"
    )


def test_open_import_has_no_match_and_closed_import_still_matches() -> None:
    # Not a size cap: nothing is cut, so no bounded/could_not_verify marker is due.
    assert list(live._iter_ts_dynamic_imports("import(" * 50_000)) == []
    text = "import(" * 50_000 + ")"
    assert list(live._iter_ts_dynamic_imports(text)) == [(0, len(text), "import(" * 49_999)]


@pytest.fixture(scope="module")
def base():
    """Base scanner outputs on the inputs below, recorded once (no git history)."""
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _digest(value) -> str:
    """Short hash of a JSON value: scanner output quotes the input text, so store no text."""
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _key(rel: str, text: str) -> str:
    return _digest([rel, text])


_TOKENS = (
    "import", "export", "require", "type", "from", "x", "e", "mod", "(", ")", "'", '"',
    ";", " ", "  ", "\n", "\t", "{", "}", ".", "$", "a", "catch", "throw", "#", "!",
    "[", "]", "allow", "expect", "use", "pub", "pub(crate)", "\u3000", "\x1c", "\x85",
    "-", ":", ",", "noqa", "ruff", "type: ignore", "\r", "é", "`",
)

_SNIPPETS = (
    'import express from "express";\n',
    'import { helper } from "@/internal/helper.js";\n',
    "export async function boot(modName: string) {\n  await import(modName);\n}\n",
    'const m = require("node:fs");\nconst n = require( \'./local\' );\n',
    "const lazy = () => import ( `./dyn-${x}.js` );\n",
    'import type { T } from "./types";\nexport * from "./x";\nexport { a } from \'a\';\n',
    'import "side-effect";\nimport\t"tab";\n  import "indented";\n',
    'import a,\n  { b, c }\n  from\n  "multi-line";\n',
    'import  from "x";\nimport type  from "y";\nimport type from "z";\n',
    "import x\nconst y = 1\nexport default y\n",
    'import x\n\n\nfoo from "late";\n',
    "obj.import(x); $require(y); a.require(z); _import(w);\n",
    "import(a(b)c)\nrequire()\nrequire(   )\n",
    "try { f() } catch (e) { throw e; }\ntry {} catch {}\ntry {} catch(err){throw err}\n",
    "try {} catch ( e ) {\n  throw e ;\n}\ncatch(e){throw ee}\n",
    'throw new Error("not implemented");\nthrow new TypeError(`TODO`);\n',
    "if (x) {\n  import(\"inside\");\n  import 'braced';\n}\n",
    "use rand::Rng;\nuse my_service_foundation::MyServiceError;\n#[cfg(test)]\nuse proptest::prelude::*;\n",
    "#[allow(dead_code)]\nfn main() { todo!(); }\n#![allow(unused, clippy::x)]\n# ! [ expect ( a ) ]\n",
    "pub use crate::a::{b, c as d};\npub(crate) use super::x;\nuse  ;\nuse   ;\nuse a ;\n",
    "extern crate serde;\nextern crate foo as bar;\nmod tests;\npub mod util;\n",
    "#[allow(a)] #[expect(b)] #[allow(c]\n#[allow(x) ]\n",
    "import boto3  # noqa: F401\nx = 1  # type: ignore[attr-defined]\n",
    "# ruff: noqa: E501, F401\n# flake8: noqa\n# mypy: ignore-errors\n",
    "y = 2  # noqa:E1,  W2 -\nz = 3  # pyright: ignore[reportX]\n# noqa:   \n",
    "x = 1  # NOQA: abc\n# Ruff: NoQA:  \t E501\n",
)


_SUFFIXES = (".ts", ".js", ".mjs", ".mts", ".tsx", ".rs", ".py")
_SKIP_DIRS = {"__pycache__", "node_modules", "target"}


def _source_files() -> list[str]:
    """The plugin's own small source files (a folder walk, no git), sorted."""
    found = []
    for path in REPO_ROOT.rglob("*"):
        rel = path.relative_to(REPO_ROOT)
        if any(part.startswith(".") or part in _SKIP_DIRS for part in rel.parts[:-1]):
            continue
        if rel.name.endswith(_SUFFIXES) and path.is_file() and not path.is_symlink():
            found.append(rel.as_posix())
    return sorted(found)


def _ordinary_texts() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for rel in _source_files():
        path = REPO_ROOT / rel
        if path.stat().st_size > 40_000:
            continue
        rows.append((rel, path.read_text(encoding="utf-8", errors="replace")))
    for index, snippet in enumerate(_SNIPPETS):
        rows.append((f"snippet/{index}.ts", snippet))
    rng = random.Random(20261110)
    for index in range(600):
        text = "".join(rng.choice(_TOKENS) for _ in range(rng.randint(0, 30)))
        rows.append((f"gen/{index}.ts", text))
    return rows


def _rust(module, rel: str, text: str):
    return module._scan_rust_imports_and_constructs(
        rel, text, local_mods={"util"}, cargo_renamed_deps={"renamed"})


def _outcome(fn, *args):
    # The stdlib tokenizer behind the Python scan raises on some generated
    # text; both versions must then raise the same error type.
    try:
        return ("ok", fn(*args))
    except Exception as exc:  # noqa: BLE001
        return ("raised", type(exc).__name__)


def _scanner_outcomes(module, rel: str, text: str) -> list[str]:
    outcomes = [_outcome(module._scan_ts_imports_and_constructs, rel_path, text)
                for rel_path in (rel, "tests/" + rel.rsplit("/", 1)[-1])]
    outcomes.append(_outcome(_rust, module, rel, text))
    outcomes.append(_outcome(module._scan_python_suppressions, rel, text))
    return [_digest(outcome) for outcome in outcomes]


def test_differential_whole_scanners_match_base(base) -> None:
    # The base patterns copied above are the ones the recorded base module used.
    for pattern in (BASE_DYNAMIC, BASE_STATIC, BASE_RUST_SUPPRESSION, BASE_RUST_USE):
        assert hashlib.sha256(pattern.encode()).hexdigest() in base["patterns_in_source"]
    rows = _ordinary_texts()
    assert len(rows) >= 300
    recorded = base["rows"]
    compared = changed = 0
    for rel, text in rows:
        expected = recorded.get(_key(rel, text))
        if expected is None:
            # A plugin source file edited since the base was recorded: no base output.
            assert not rel.startswith(("snippet/", "gen/")), rel
            changed += 1
            continue
        got = _scanner_outcomes(live, rel, text)
        labels = (rel, "tests/" + rel.rsplit("/", 1)[-1], "rust " + rel, "python " + rel)
        for label, new, old in zip(labels, got, expected, strict=True):
            assert new == old, label
        compared += 1
    assert compared >= 300
    print(f"DIFFERENTIAL scanner inputs={compared} (source files changed since recording: {changed})")


def test_differential_matchers_match_base_patterns() -> None:
    dynamic = re.compile(BASE_DYNAMIC)
    static = re.compile(BASE_STATIC)
    suppression = re.compile(BASE_RUST_SUPPRESSION)
    use = re.compile(BASE_RUST_USE)
    rows = _ordinary_texts()
    rng = random.Random(7)
    for index in range(3000):
        rows.append((f"extra/{index}", "".join(rng.choice(_TOKENS) for _ in range(rng.randint(0, 40)))))
    counts = {"dynamic": 0, "static": 0, "suppression_lines": 0, "use_lines": 0}
    for rel, text in rows:
        expected = [(m.start(), m.end(), m.group(1).strip()) for m in dynamic.finditer(text)]
        got = [(s, e, inner.strip()) for s, e, inner in live._iter_ts_dynamic_imports(text)]
        assert got == expected, rel
        expected_static = [(m.start(), m.end(), m.group(2)) for m in static.finditer(text)]
        assert list(live._iter_ts_static_imports(text)) == expected_static, rel
        counts["dynamic"] += 1
        counts["static"] += 1
        for line in text.splitlines():
            expected_sup = [(m.group(1), m.group(2)) for m in suppression.finditer(line)]
            assert list(live._iter_rust_suppressions(line)) == expected_sup, (rel, line)
            stripped = line.strip()
            m_base, m_live = use.match(stripped), live._match_rust_use(stripped)
            assert (m_base and m_base.group(1)) == (m_live and m_live.group(1)), (rel, line)
            counts["suppression_lines"] += 1
            counts["use_lines"] += 1
    print(f"DIFFERENTIAL matchers {counts}")
    assert min(counts.values()) >= 300


def test_linear_shapes_are_pinned_in_the_vendored_source() -> None:
    source = VENDOR_FILE.read_text(encoding="utf-8")
    assert source.count("LOCAL PATCH linear-source-scan-v1") >= 3
    for quadratic in (BASE_DYNAMIC, BASE_STATIC, BASE_RUST_SUPPRESSION, BASE_RUST_USE):
        assert f'r"{quadratic}"' not in source
    assert r"noqa(?::\s*[A-Za-z0-9_,\s-]+)?" not in source
    assert r"\s*;?\s*)?\}" not in source


def record_base_outputs(base_mod, base_file) -> dict:
    """Run the base module on this file's inputs (scripts/gen_linear_baseline.py only)."""
    raw = base_file.read_text(encoding="utf-8")
    patterns = [hashlib.sha256(p.encode()).hexdigest()
                for p in (BASE_DYNAMIC, BASE_STATIC, BASE_RUST_SUPPRESSION, BASE_RUST_USE) if p in raw]
    assert len(patterns) == 4
    rows = {_key(rel, text): _scanner_outcomes(base_mod, rel, text) for rel, text in _ordinary_texts()}
    return {"patterns_in_source": patterns, "rows": rows}
