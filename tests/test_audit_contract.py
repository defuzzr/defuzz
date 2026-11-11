"""Unit tests for `audit/contract.py` and the audit component contract (§5, §6, §13.2)."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.audit.contract import (  # noqa: E402
    CLASSIFICATION_INFO,
    CLASSIFICATION_REVIEW,
    CLASSIFICATION_WARNING,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_NOT_INCLUDED,
    COVERAGE_VERIFIED,
    FIXED_AUDIT_DISCLOSURE,
    adapt_component_result,
    canonical_report_bytes,
    canonical_report_digest,
    canonical_report_payload,
    compute_headline,
    make_component_envelope,
    make_finding,
    normalize_finding,
    sort_findings,
)


from hermes_plugins.defuzz.audit.redaction import redaction_scope


class TestAuditContract(unittest.TestCase):
    def test_make_finding_and_legacy_envelope_compatibility(self) -> None:
        f = make_finding(
            rule_id="memory.duplicate_entry",
            classification=CLASSIFICATION_WARNING,
            coverage=COVERAGE_VERIFIED,
            affected_identities=["coder", "default"],
            source_paths=[{"path": "/tmp/a/MEMORY.md", "start_line": 10, "end_line": 15}],
            evidence={"entry_hash": "abc123", "api_key": "sk-secret-value-should-be-redacted"},
            consequence="Duplicate memory entry wastes prompt tokens.",
            limitations="Exact byte match only.",
            proposed_cleanup_id="cleanup.memory.dup.1",
        )
        self.assertEqual(f["id"], "memory.duplicate_entry")
        self.assertEqual(f["classification"], CLASSIFICATION_WARNING)
        self.assertEqual(f["coverage"], COVERAGE_VERIFIED)
        self.assertEqual(f["affected_identities"], ["coder", "default"])
        self.assertEqual(f["evidence"]["entry_hash"], "abc123")
        # Secret key inside evidence is redacted automatically (§3)
        self.assertEqual(f["evidence"]["api_key"], "<redacted>")
        self.assertEqual(f["proposed_cleanup_id"], "cleanup.memory.dup.1")
        # Legacy fields present
        self.assertIn(f["severity"], ("warn", "error", "info"))
        self.assertEqual(f["detail"], "Duplicate memory entry wastes prompt tokens.")

    def test_executable_fixes_forbidden_in_evidence_and_cleanup_id(self) -> None:
        with self.assertRaises(ValueError):
            make_finding(
                rule_id="test.rule",
                classification=CLASSIFICATION_INFO,
                consequence="Test consequence",
                evidence={"command": "rm -rf /"},
            )
        with self.assertRaises(ValueError):
            make_finding(
                rule_id="test.rule",
                classification=CLASSIFICATION_INFO,
                consequence="Test consequence",
                evidence={"cb": lambda: None},
            )
        with self.assertRaises(ValueError):
            make_finding(
                rule_id="test.rule",
                classification=CLASSIFICATION_INFO,
                consequence="Test consequence",
                proposed_cleanup_id="rm -rf /; echo pwned",
            )

    def test_headline_ignores_legacy_status_and_never_passes_on_unknown(self) -> None:
        """§6 & §13.2: Even when a component returns legacy `status: 'pass'` and `ok: True`,
        if coverage is `could_not_verify` (or any finding has `could_not_verify`), the headline
        reports `could_not_verify` and `can_claim_clean` is False.
        """
        legacy_pass_with_unknown = {
            "ok": True,
            "status": "pass",
            "error": None,
            "coverage": COVERAGE_COULD_NOT_VERIFY,
            "findings": [
                {
                    "id": "profile.dynamic_plugins",
                    "severity": "info",
                    "classification": CLASSIFICATION_INFO,
                    "coverage": COVERAGE_COULD_NOT_VERIFY,
                    "detail": "Dynamic plugin output could not be statically verified.",
                    "consequence": "Dynamic plugin output could not be statically verified.",
                }
            ],
        }
        adapted = adapt_component_result(legacy_pass_with_unknown, component_id="profile_context")
        self.assertEqual(adapted["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertEqual(adapted["classification"], CLASSIFICATION_INFO)
        self.assertEqual(adapted["legacy_status_ignored"], "pass")

        headline = compute_headline(component_results=[adapted])
        self.assertEqual(headline["classification"], CLASSIFICATION_INFO)
        self.assertEqual(headline["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertFalse(headline["can_claim_clean"])
        self.assertEqual(headline["disclosure"], FIXED_AUDIT_DISCLOSURE)

    def test_operational_component_error_maps_to_could_not_verify_not_warning(self) -> None:
        """§6: Operational component errors (`status == 'error'`) are not product severity."""
        op_error_env = make_component_envelope(
            findings=[],
            error="Permission denied reading directory",
        )
        self.assertFalse(op_error_env["ok"])
        self.assertEqual(op_error_env["status"], "error")
        self.assertEqual(op_error_env["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertEqual(op_error_env["classification"], CLASSIFICATION_INFO)

        adapted = adapt_component_result(
            op_error_env,
            component_id="template_drift",
            affected_identities=["/tmp/proj"],
        )
        self.assertEqual(adapted["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertEqual(adapted["classification"], CLASSIFICATION_INFO)
        self.assertEqual(len(adapted["findings"]), 1)
        self.assertEqual(adapted["findings"][0]["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertEqual(adapted["findings"][0]["classification"], CLASSIFICATION_INFO)

    def test_not_included_template_scope(self) -> None:
        """§5 & §13.3: Projects outside the three golden templates get `not_included`."""
        headline = compute_headline(
            findings=[],
            unit_coverages=[COVERAGE_NOT_INCLUDED],
        )
        self.assertEqual(headline["coverage"], COVERAGE_NOT_INCLUDED)
        self.assertEqual(headline["classification"], CLASSIFICATION_INFO)
        self.assertFalse(headline["can_claim_clean"])

    @redaction_scope
    def test_canonical_report_digest_excludes_run_id_and_execution_timestamps(self) -> None:
        """§4 & §11: Same frozen inputs produce byte-identical canonical report regardless of run_id/timestamps."""
        f1 = make_finding(
            rule_id="b.rule",
            classification=CLASSIFICATION_REVIEW,
            coverage=COVERAGE_VERIFIED,
            affected_identities=["p2"],
            consequence="Review item B",
        )
        f2 = make_finding(
            rule_id="a.rule",
            classification=CLASSIFICATION_WARNING,
            coverage=COVERAGE_VERIFIED,
            affected_identities=["p1"],
            consequence="Warning item A",
        )
        r1 = canonical_report_payload(
            as_of=1700000000,
            active_profile="default",
            findings=[f1, f2],
            units=[{"unit_kind": "profile", "unit_id": "default", "status": "completed", "coverage": "verified"}],
        )
        r2 = canonical_report_payload(
            as_of=1700000000,
            active_profile="default",
            findings=[f2, f1],  # reversed input order
            units=[{"unit_kind": "profile", "unit_id": "default", "status": "completed", "coverage": "verified"}],
        )
        r1_with_env = {**r1, "run_id": "run-111", "started_at": 100, "finished_at": 200}
        r2_with_env = {**r2, "run_id": "run-999", "started_at": 500, "finished_at": 900}

        self.assertEqual(canonical_report_bytes(r1_with_env), canonical_report_bytes(r2_with_env))
        self.assertEqual(canonical_report_digest(r1_with_env), canonical_report_digest(r2_with_env))
        # Warning comes before review_suggested in deterministic sort order
        from hermes_plugins.defuzz.audit.redaction import _CURRENT
        self.assertEqual(r1["findings"][0]["id"]["hmac"], _CURRENT.get().serializer._hmac("a.rule"))
        self.assertEqual(r1["findings"][1]["id"]["hmac"], _CURRENT.get().serializer._hmac("b.rule"))


if __name__ == "__main__":
    unittest.main()
