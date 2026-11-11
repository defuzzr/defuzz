"""Record the pre-fix outputs that the linear-matcher tests compare against.

Five test modules prove that a linear rewrite returns what the earlier, slower
implementation returned. They compare the live code with outputs recorded once
from the earlier source files, stored in ``tests/fixtures/linear_baseline/``,
so the tests need no repository history. This script writes those files.

Usage (from the plugin folder, with the Hermes Agent source on PYTHONPATH and a
throwaway HOME, the same environment the tests use)::

    python scripts/gen_linear_baseline.py --base-dir DIR [--only NAME ...]

``DIR`` holds the earlier source files under their repository paths
(``audit/skill_hygiene.py``, ``audit/memory_load.py``, ``audit/literal_paths.py``,
``audit/vendor/static_code.py``, ``audit/vendor/executable_inventory.py``).
The inputs are built by the test modules themselves; this script only runs the
earlier code on them and writes what it returned.
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

# fixture name -> (test module, earlier source path, how the module is loaded)
TARGETS = {
    "skill_hygiene": ("tests.test_audit_skill_hygiene_linear", "audit/skill_hygiene.py", "audit"),
    "memory_load": ("tests.test_audit_memory_load_linear", "audit/memory_load.py", "audit"),
    "literal_paths": ("tests.test_audit_literal_paths_linear", "audit/literal_paths.py", "audit"),
    "static_code": ("tests.test_audit_vendor_static_code_linear", "audit/vendor/static_code.py", "vendor"),
    "executable_inventory": ("tests.test_audit_vendor_redaction_bounds",
                             "audit/vendor/executable_inventory.py", "standalone"),
}


def _load(path: Path, how: str):
    from tests import TEST_PACKAGE_NAME, ensure_test_package

    ensure_test_package()
    if how == "audit":
        package = f"{TEST_PACKAGE_NAME}.audit"
        importlib.import_module(package)
    elif how == "vendor":
        package = f"{TEST_PACKAGE_NAME}.audit.vendor"
        importlib.import_module(package)
    else:
        package = "linear_baseline_standalone"
    name = f"{package}._earlier_{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = package
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record pre-fix outputs for the linear-matcher tests.")
    parser.add_argument("--base-dir", required=True, type=Path)
    parser.add_argument("--only", action="append", choices=sorted(TARGETS))
    args = parser.parse_args(argv)
    sys.path.insert(0, str(REPO_ROOT))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for fixture, (test_module, rel, how) in TARGETS.items():
        if args.only and fixture not in args.only:
            continue
        source = args.base_dir / rel
        tests = importlib.import_module(test_module)
        base = _load(source, how)
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
