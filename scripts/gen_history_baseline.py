"""Record the pre-fix outputs that the prompt-parse and matcher tests compare against.

``tests/test_prompt_parse_linear.py`` and ``tests/test_matcher_linear.py`` prove that a
linear rewrite returns what the earlier, slower module returned. They compare the live
code with digests recorded once from the earlier source files, stored in
``tests/fixtures/linear_baseline/``, so the tests need no repository history. This
script writes those files. It is the companion of ``scripts/gen_linear_baseline.py``.

Usage (from the plugin folder, with the Hermes Agent source on PYTHONPATH and a
throwaway HOME, the same environment the tests use)::

    python scripts/gen_history_baseline.py --base-dir DIR [--only NAME ...]

``DIR`` holds the earlier source files under their repository paths
(``prompt_parse.py``, ``matcher.py``). The inputs are built by the test modules
themselves; this script only runs the earlier code on them and writes what it returned.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "tests" / "fixtures" / "linear_baseline"

# fixture name -> (test module, earlier source path)
TARGETS = {
    "prompt_parse": ("tests.test_prompt_parse_linear", "prompt_parse.py"),
    "matcher": ("tests.test_matcher_linear", "matcher.py"),
}


def _load(path: Path):
    from tests import TEST_PACKAGE_NAME, ensure_test_package

    ensure_test_package()
    name = f"{TEST_PACKAGE_NAME}._earlier_{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = TEST_PACKAGE_NAME
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record pre-fix outputs for the prompt-parse and matcher tests.")
    parser.add_argument("--base-dir", required=True, type=Path)
    parser.add_argument("--only", action="append", choices=sorted(TARGETS))
    args = parser.parse_args(argv)
    sys.path.insert(0, str(REPO_ROOT))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for fixture, (test_module, rel) in TARGETS.items():
        if args.only and fixture not in args.only:
            continue
        source = args.base_dir / rel
        tests = importlib.import_module(test_module)
        base = _load(source)
        payload = tests.record_base_outputs(base, source)
        payload = {"source": rel, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                   **payload}
        out = OUT_DIR / f"{fixture}.json"
        out.write_text(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                       + "\n", encoding="utf-8")
        print(f"{out.relative_to(REPO_ROOT)}: {out.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
