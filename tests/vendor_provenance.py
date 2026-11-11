"""Validate the shipped vendored modules against audit/vendor/provenance.json."""
import hashlib
import json
from pathlib import Path


def assert_packaged_vendor(testcase, filenames, *, vendor=None):
    if vendor is None:
        vendor = Path(__file__).resolve().parent.parent / "audit" / "vendor"
    manifest = json.loads((vendor / "provenance.json").read_text(encoding="utf-8"))
    testcase.assertEqual(manifest["verification"], "packaged-baseline-only")
    testcase.assertIsNone(manifest["upstream_revision"])
    for filename in filenames:
        record = manifest["files"][filename]
        raw = (vendor / filename).read_bytes()
        testcase.assertEqual(record["source"], f"hermes_audit/{filename}")
        expected_header = (
            f"# vendored module (origin: {record['source']}, from the author's audit toolkit; "
            "not published separately). Do not edit: change the origin and re-vendor.\n"
        ).encode("utf-8")
        testcase.assertTrue(raw.startswith(expected_header))
        testcase.assertEqual(hashlib.sha256(raw).hexdigest(), record["sha256"])
