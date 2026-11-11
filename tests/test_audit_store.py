"""Unit tests for `audit/store.py` (§4, §11, §12).

Covers:
- Plugin DB tables for runs, units, unit results, evidence cache, derived cache, and cleanup approvals.
- Cancel/resume revalidation: unchanged verified units are reused; modified or unstable units are
  invalidated and rerun; cross-checks are invalidated whenever any unit changes.
- Coherent cross-check manifest: missing or unfinished units produce partial coverage (`could_not_verify`)
  and never silently combine old and current snapshots.
- Time-dependent cache results (§12): unchanged evidence crossing the unused threshold between new
  runs changes the verdict; resuming the original run keeps the original reference time (`as_of`)
  and original verdict.
"""

from __future__ import annotations

import contextlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.audit import (  # type: ignore[import-not-found] # noqa: E402
    CLASSIFICATION_INFO,
    CLASSIFICATION_WARNING,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
    AuditStore,
    collect_profile_unit_facts,
    make_component_envelope,
    make_finding,
)


class TestAuditStore(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)
        self.plugin_db = self.tmp_root / "plugin_state" / "state.db"
        self.store = AuditStore(db_path=self.plugin_db)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_profile_fixture(self, name: str, started_at: float) -> Path:
        pdir = self.tmp_root / "profiles" / name
        (pdir / "memories").mkdir(parents=True, exist_ok=True)
        (pdir / "skills").mkdir(parents=True, exist_ok=True)
        (pdir / "config.yaml").write_text(f"model: {name}-model\n", encoding="utf-8")
        (pdir / "memories" / "MEMORY.md").write_text(f"Memory for {name}\n", encoding="utf-8")
        db_p = pdir / "state.db"
        with contextlib.closing(sqlite3.connect(str(db_p))) as conn:
            with conn:
                conn.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY, started_at REAL, source TEXT, title TEXT)")
                conn.execute("INSERT INTO sessions VALUES ('s1', ?, 'cli', 'Chat')", (started_at,))
        return pdir

    def test_cancel_resume_reuses_unchanged_and_invalidates_modified_or_unstable(self) -> None:
        """§4 & §11: Cancel/resume does not rerun unchanged units or mix cross-check snapshots; missing units stay incomplete."""
        p_alpha = self._make_profile_fixture("alpha", 1700000000.0)
        p_beta = self._make_profile_fixture("beta", 1700000000.0)

        facts_alpha = collect_profile_unit_facts(
            profile_name="alpha",
            profile_dir=p_alpha,
            is_default=False,
            is_active=True,
            as_of=1700100000,
        )
        facts_beta = collect_profile_unit_facts(
            profile_name="beta",
            profile_dir=p_beta,
            is_default=False,
            is_active=False,
            as_of=1700100000,
        )

        run = self.store.create_run(
            as_of=1700100000,
            active_profile="alpha",
            planned_units=[
                {"unit_kind": "profile", "unit_id": "alpha"},
                {"unit_kind": "profile", "unit_id": "beta"},
                {"unit_kind": "profile", "unit_id": "gamma"},  # not committed before cancel
            ],
        )
        run_id = run["run_id"]

        # Commit alpha and beta, leave gamma pending
        self.store.commit_unit_result(
            run_id=run_id,
            unit_kind="profile",
            unit_id="alpha",
            manifest=facts_alpha["fingerprint_manifest"],
            evidence=facts_alpha,
            sort_order=0,
        )
        self.store.commit_unit_result(
            run_id=run_id,
            unit_kind="profile",
            unit_id="beta",
            manifest=facts_beta["fingerprint_manifest"],
            evidence=facts_beta,
            sort_order=1,
        )

        # Before gamma finishes, cross-check manifest must report incomplete / could_not_verify
        cc_before = self.store.build_coherent_crosscheck_manifest(run_id)
        self.assertFalse(cc_before["coherent_complete"])
        self.assertEqual(cc_before["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertEqual(len(cc_before["missing_or_unfinished_units"]), 1)
        # Display identity is minimized, while SQL control identity remains reusable.
        missing_id = cc_before["missing_or_unfinished_units"][0]["unit_id"]
        self.assertEqual(missing_id['kind'], 'text')
        self.assertEqual(len(missing_id['hmac']), 64)
        from tests.conftest import load_submodule
        key = load_submodule('audit.key')
        persistence = load_submodule('audit.persistence')
        with key.key_scope(self.store.db_path):
            gamma_control = persistence.control_digest('gamma')
        saved_gamma = [u for u in self.store.get_run(run_id)['units']
                       if u['unit_control_id'] == gamma_control]
        self.assertEqual(len(saved_gamma), 1)
        self.assertEqual(saved_gamma[0]['unit_id'], missing_id)
        self.assertEqual(saved_gamma[0]['status'], 'pending')
        self.assertNotIn('gamma', str(cc_before))

        # Cancel run
        self.store.cancel_run(run_id)

        # Modify beta on disk while alpha stays untouched
        (p_beta / "memories" / "MEMORY.md").write_text("Modified beta memory!\n", encoding="utf-8")
        facts_beta_v2 = collect_profile_unit_facts(
            profile_name="beta",
            profile_dir=p_beta,
            is_default=False,
            is_active=False,
            as_of=1700999999,
        )

        resume_info = self.store.resume_run(
            run_id,
            current_unit_digests={
                ("profile", "alpha"): facts_alpha["fingerprint_manifest"]["unit_digest"],
                ("profile", "beta"): facts_beta_v2["fingerprint_manifest"]["unit_digest"],
                ("profile", "gamma"): "digest-gamma-new",
            },
        )
        # Resume keeps original as_of (1700100000)
        self.assertEqual(resume_info["as_of"], 1700100000)
        self.assertEqual(resume_info["reused_units"], [{"unit_kind": "profile", "unit_id": "alpha"}])
        self.assertEqual(
            resume_info["units_to_run"],
            [
                {"unit_kind": "profile", "unit_id": "beta"},
                {"unit_kind": "profile", "unit_id": "gamma"},
            ],
        )
        self.assertTrue(resume_info["cross_checks_invalidated"])

    def test_unstable_unit_is_incomplete_and_never_cached_as_verified(self) -> None:
        """§4 & §12: An unstable unit is incomplete (`status='incomplete'`) and not reused as verified."""
        p_alpha = self._make_profile_fixture("alpha", 1700000000.0)
        facts_alpha = collect_profile_unit_facts(
            profile_name="alpha",
            profile_dir=p_alpha,
            is_default=False,
            is_active=False,
            as_of=1700100000,
        )
        unstable_manifest = dict(facts_alpha["fingerprint_manifest"], stable=False, coverage=COVERAGE_COULD_NOT_VERIFY)

        run = self.store.create_run(
            as_of=1700100000,
            planned_units=[{"unit_kind": "profile", "unit_id": "alpha"}],
        )
        committed = self.store.commit_unit_result(
            run_id=run["run_id"],
            unit_kind="profile",
            unit_id="alpha",
            manifest=unstable_manifest,
            evidence=facts_alpha,
        )
        self.assertEqual(committed["status"], "incomplete")
        self.assertEqual(committed["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertIsNone(committed["evidence_cache_key"])

        # Evidence cache must NOT hold an entry for the unstable read
        cached = self.store.get_cached_evidence(
            unit_kind="profile",
            unit_id="alpha",
            fingerprint_digest=facts_alpha["fingerprint_manifest"]["unit_digest"],
        )
        self.assertIsNone(cached)

    def test_time_dependent_cache_crossing_threshold_vs_resume_original_time(self) -> None:
        """§12 'Time-dependent cache results' fixture:
        - Unchanged evidence crossing the 90-day threshold between new runs changes the verdict.
        - Resuming the original run keeps the original reference time (`as_of`) and original verdict.
        """
        started_at = 1700000000.0
        day_80 = int(started_at + 80 * 86400)
        day_100 = int(started_at + 100 * 86400)

        p_old = self._make_profile_fixture("stale_candidate", started_at)
        facts_day80 = collect_profile_unit_facts(
            profile_name="stale_candidate",
            profile_dir=p_old,
            is_default=False,
            is_active=False,
            as_of=day_80,
            unused_threshold_days=90,
        )
        fp_digest = facts_day80["fingerprint_manifest"]["unit_digest"]

        # Run 1 at day 80 (within 90-day threshold -> NOT unused, NOT archive_candidate)
        run1 = self.store.create_run(
            as_of=day_80,
            active_profile="default",
            unused_threshold_days=90,
            planned_units=[{"unit_kind": "profile", "unit_id": "stale_candidate"}],
        )
        self.store.commit_unit_result(
            run_id=run1["run_id"],
            unit_kind="profile",
            unit_id="stale_candidate",
            manifest=facts_day80["fingerprint_manifest"],
            evidence=facts_day80,
        )
        self.store.cancel_run(run1["run_id"])

        # New Run 2 at day 100 reuses the cached time-independent evidence from Run 1 without touching disk,
        # but evaluates against day 100 (> 90 days -> archive_candidate is True!)
        cached_ev = self.store.get_cached_evidence(
            unit_kind="profile",
            unit_id="stale_candidate",
            fingerprint_digest=fp_digest,
        )
        self.assertIsNotNone(cached_ev)
        assert cached_ev is not None
        self.assertNotIn("age_evaluation", cached_ev["evidence"])

        eval_run2 = self.store.evaluate_unit_from_evidence(
            evidence=cached_ev["evidence"],
            as_of=day_100,
            unused_threshold_days=90,
        )
        self.assertTrue(eval_run2["age_evaluation"]["is_unused_beyond_threshold"])
        self.assertTrue(eval_run2["age_evaluation"]["archive_candidate"])
        self.assertFalse(eval_run2["age_evaluation"]["selected_by_default"])

        # Resuming Run 1 at day 100 keeps Run 1's original reference time (`day_80`) and original verdict!
        resume_r1 = self.store.resume_run(
            run1["run_id"],
            current_unit_digests={("profile", "stale_candidate"): fp_digest},
        )
        self.assertEqual(resume_r1["as_of"], day_80)
        final_r1 = self.store.finalize_run(run1["run_id"])
        unit_r1 = final_r1["report"]["units"][0]
        self.assertEqual(unit_r1["age_evaluation"]["as_of"], float(day_80))
        self.assertFalse(unit_r1["age_evaluation"]["is_unused_beyond_threshold"])
        self.assertFalse(unit_r1["age_evaluation"]["archive_candidate"])


if __name__ == "__main__":
    unittest.main()
