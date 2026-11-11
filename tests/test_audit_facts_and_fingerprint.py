"""Unit tests for `audit/readonly_db.py`, `audit/fingerprint.py`, and `audit/facts.py` (§2, §3, §4, §11, §12)."""

from __future__ import annotations

import contextlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.audit import (  # type: ignore[import-not-found] # noqa: E402
    CLASSIFICATION_INFO,
    CLASSIFICATION_REVIEW,
    COVERAGE_COULD_NOT_VERIFY,
    COVERAGE_VERIFIED,
    ReadOnlyDbError,
    build_tree_fingerprint_manifest,
    choose_duplicate_survivor,
    collect_profile_last_use_evidence,
    collect_profile_unit_facts,
    compute_system_deduplicated_bytes,
    discover_optional_root_repos,
    enumerate_profiles,
    evaluate_profile_age_and_unused,
    open_readonly_sqlite,
    order_profile_units,
    read_profile_registrations_readonly,
    read_profile_session_evidence,
    resolve_permitted_symlink_target,
    resolve_profile_memory_facts,
    resolve_profile_skills_facts,
    resolve_project_context_chain_facts,
    safe_read_regular_file,
    union_profile_registrations,
)


class TestReadOnlyDbAndFacts(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_readonly_db_never_creates_or_migrates_missing_or_existing_db(self) -> None:
        """§1, §2, §11: Opening a missing DB fails without creating it; opening an existing DB refuses writes."""
        missing_parent = self.tmp_root / "nonexistent_dir" / "state.db"
        with self.assertRaises(ReadOnlyDbError):
            with open_readonly_sqlite(missing_parent):
                pass
        self.assertFalse(missing_parent.parent.exists())
        self.assertFalse(missing_parent.exists())

        # Read profile session evidence on missing state.db -> exists=False, could_not_verify, file not created
        ev_missing = read_profile_session_evidence(missing_parent)
        self.assertFalse(ev_missing.exists)
        self.assertEqual(ev_missing.coverage, COVERAGE_COULD_NOT_VERIFY)
        self.assertFalse(missing_parent.exists())

        # Read profile registrations on missing plugin DB -> exists=False, verified (0 registrations), file not created
        reg_missing = read_profile_registrations_readonly("coder", self.tmp_root / "coder_prof")
        self.assertFalse(reg_missing.exists)
        self.assertEqual(reg_missing.coverage, COVERAGE_VERIFIED)
        self.assertEqual(reg_missing.records, [])
        self.assertFalse((self.tmp_root / "coder_prof").exists())

        # Create a legacy-schema DB (without `rules_hash` or modern columns) and verify open_readonly_sqlite
        # neither migrates it nor allows DDL/DML writes, and leaves bytes identical.
        legacy_db = self.tmp_root / "legacy_state.db"
        with contextlib.closing(sqlite3.connect(str(legacy_db))) as conn:
            with conn:
                conn.execute("CREATE TABLE projects (path TEXT PRIMARY KEY, name TEXT, slug TEXT, template_id TEXT)")
                conn.execute("INSERT INTO projects VALUES ('/tmp/p1', 'Proj 1', 'proj-1', 'rust-golden')")
        bytes_before = legacy_db.read_bytes()

        with open_readonly_sqlite(legacy_db) as (ro_conn, _):
            with self.assertRaises(sqlite3.OperationalError):
                ro_conn.execute("CREATE TABLE hacked (id INT)")
            with self.assertRaises(sqlite3.OperationalError):
                ro_conn.execute("ALTER TABLE projects ADD COLUMN rules_hash TEXT")

        snap = read_profile_registrations_readonly("default", self.tmp_root, db_path=legacy_db)
        self.assertTrue(snap.exists)
        self.assertEqual(snap.coverage, COVERAGE_VERIFIED)
        self.assertEqual(len(snap.records), 1)
        self.assertEqual(snap.records[0]["name"], "Proj 1")
        self.assertEqual(legacy_db.read_bytes(), bytes_before)

    def test_profile_enumeration_establishes_readability_separately(self) -> None:
        """§2 & §11: `list_profile_names()` suppresses OSError; adapter detects unreadable profiles container."""
        default_dir = self.tmp_root / "hermes"
        profiles_dir = default_dir / "profiles"
        (profiles_dir / "alpha").mkdir(parents=True)
        (default_dir / "config.yaml").write_text("model: x\n", encoding="utf-8")
        (profiles_dir / "alpha" / "config.yaml").write_text("model: y\n", encoding="utf-8")

        def _list_names() -> list[str]:
            # Simulates list_profile_names() suppressing OSError and returning only ["default"]
            return ["default"]

        def _get_dir(name: str) -> Path:
            return default_dir if name == "default" else (profiles_dir / name)

        # Make profiles_dir unreadable
        os.chmod(profiles_dir, 0o000)
        try:
            res = enumerate_profiles(
                list_profile_names_fn=_list_names,
                get_profile_dir_fn=_get_dir,
            )
            self.assertEqual(res.coverage, COVERAGE_COULD_NOT_VERIFY)
            self.assertFalse(res.enumeration_complete)
            self.assertTrue(len(res.errors) >= 1)
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0]["id"], "inventory.profile_enumeration_incomplete")
        finally:
            os.chmod(profiles_dir, 0o755)

    def test_union_registrations_multi_profile_info_vs_conflict_review(self) -> None:
        """§3, §11, §13.1: Same canonical path in multiple profiles -> Info when matching, Review when conflicting."""
        proj_path = str((self.tmp_root / "shared_proj").resolve())
        db_a = self.tmp_root / "a_state.db"
        db_b = self.tmp_root / "b_state.db"
        db_c = self.tmp_root / "c_state.db"

        for db_p, tmpl, slug in (
            (db_a, "rust-golden", "shared-proj"),
            (db_b, "rust-golden", "shared-proj"),
            (db_c, "python-golden", "other-prefix"),
        ):
            with contextlib.closing(sqlite3.connect(str(db_p))) as conn:
                with conn:
                    conn.execute(
                        "CREATE TABLE projects (path TEXT PRIMARY KEY, name TEXT, slug TEXT, template_id TEXT, created_at INTEGER)"
                    )
                    conn.execute(
                        "INSERT INTO projects VALUES (?, 'Shared', ?, ?, 1700000000)",
                        (proj_path, slug, tmpl),
                    )

        snap_a = read_profile_registrations_readonly("default", self.tmp_root, db_path=db_a)
        snap_b = read_profile_registrations_readonly("coder", self.tmp_root, db_path=db_b)
        snap_c = read_profile_registrations_readonly("research", self.tmp_root, db_path=db_c)

        # Matching multi-profile registration -> Info: registered by 2 profiles
        unioned_ok = union_profile_registrations([snap_a, snap_b])
        self.assertEqual(len(unioned_ok["project_units"]), 1)
        self.assertFalse(unioned_ok["project_units"][0]["conflicting_registrations"])
        self.assertEqual(len(unioned_ok["all_records"]), 2)  # never deduplicated in storage
        self.assertEqual(len(unioned_ok["findings"]), 1)
        self.assertEqual(unioned_ok["findings"][0]["id"], "inventory.multi_profile_registration")
        self.assertEqual(unioned_ok["findings"][0]["classification"], CLASSIFICATION_INFO)
        self.assertIn("Info: registered by 2 profiles", unioned_ok["findings"][0]["consequence"])

        # Conflicting registration -> Review suggested with both records as evidence
        unioned_conflict = union_profile_registrations([snap_a, snap_c])
        self.assertEqual(len(unioned_conflict["project_units"]), 1)
        self.assertTrue(unioned_conflict["project_units"][0]["conflicting_registrations"])
        self.assertEqual(len(unioned_conflict["findings"]), 1)
        self.assertEqual(unioned_conflict["findings"][0]["id"], "inventory.conflicting_profile_registrations")
        self.assertEqual(unioned_conflict["findings"][0]["classification"], CLASSIFICATION_REVIEW)
        self.assertEqual(len(unioned_conflict["findings"][0]["evidence"]["records"]), 2)

    def test_safe_reads_fifo_symlink_escape_and_mid_read_mutation(self) -> None:
        """§12 'Safe content reads and races' fixtures:
        - FIFO never consumed or blocking.
        - File-to-link and ancestor-to-link swaps cannot read an outside sentinel.
        - Changed identity/content mid-read yields incomplete (`stable=False`, `coverage='could_not_verify'`).
        """
        root = self.tmp_root / "safe_root"
        root.mkdir(parents=True)
        outside_sentinel = self.tmp_root / "outside_sentinel.txt"
        outside_sentinel.write_text("TOP_SECRET_OUTSIDE_DATA", encoding="utf-8")

        # 1. FIFO never blocks or gets consumed
        fifo_path = root / "named_pipe.fifo"
        os.mkfifo(fifo_path)
        fifo_res = safe_read_regular_file(root, "named_pipe.fifo")
        self.assertEqual(fifo_res.kind, "fifo")
        self.assertEqual(fifo_res.coverage, COVERAGE_COULD_NOT_VERIFY)
        self.assertIsNone(fifo_res.content)

        # 2. Leaf symlink to outside sentinel is inventoried as symlink metadata, never read
        leaf_link = root / "escape_link.txt"
        os.symlink(str(outside_sentinel), leaf_link)
        link_res = safe_read_regular_file(root, "escape_link.txt")
        self.assertEqual(link_res.kind, "symlink")
        self.assertEqual(link_res.symlink_target, str(outside_sentinel))
        self.assertIsNone(link_res.content)

        # Resolve permitted symlink target rejects outside sentinel
        perm_res = resolve_permitted_symlink_target(
            link_root=root,
            link_rel_path="escape_link.txt",
            raw_target=str(outside_sentinel),
            allowed_roots=[root],
        )
        self.assertEqual(perm_res.kind, "escaped")
        self.assertEqual(perm_res.coverage, COVERAGE_COULD_NOT_VERIFY)
        self.assertIsNone(perm_res.content)

        # 3. Ancestor symlink to outside directory is refused by descriptor-relative walk
        outside_dir = self.tmp_root / "outside_dir"
        outside_dir.mkdir()
        # An ordinary name: a secret-store name would be excluded by policy before the walk.
        (outside_dir / "notes.txt").write_text("OUTSIDE_DIR_SECRET", encoding="utf-8")
        os.symlink(str(outside_dir), root / "subdir_link")

        anc_res = safe_read_regular_file(root, "subdir_link/notes.txt")
        self.assertEqual(anc_res.kind, "escaped")
        self.assertEqual(anc_res.coverage, COVERAGE_COULD_NOT_VERIFY)
        self.assertIsNone(anc_res.content)

        # 4. Mid-read file mutation / replacement yields `stable=False` and `coverage='could_not_verify'`
        mutable_file = root / "changing.txt"
        mutable_file.write_text("initial content", encoding="utf-8")

        def _mutate_mid_read() -> None:
            mutable_file.write_text("mutated mid read with extra bytes!", encoding="utf-8")

        race_res = safe_read_regular_file(root, "changing.txt", _mid_read_hook=_mutate_mid_read)
        self.assertFalse(race_res.stable)
        self.assertEqual(race_res.coverage, COVERAGE_COULD_NOT_VERIFY)
        self.assertIsNone(race_res.content)
        self.assertIsNone(race_res.sha256)

    def test_profile_ownership_prunes_named_profiles_and_separates_shared_infra(self) -> None:
        """§12 'Profile ownership and totals' fixture:
        - Modifying a named profile changes that profile's owned size/identity, NOT default's.
        - Shared infrastructure changes (`hermes-agent`, `models`, `cache`) are attributed separately.
        - Unclassified root entries are reported separately, never silently assigned to default.
        """
        default_root = self.tmp_root / "hermes_root"
        named_coder = default_root / "profiles" / "coder"
        (default_root / "memories").mkdir(parents=True)
        (default_root / "skills").mkdir(parents=True)
        (default_root / "models").mkdir(parents=True)
        (named_coder / "memories").mkdir(parents=True)
        (named_coder / "skills").mkdir(parents=True)

        (default_root / "config.yaml").write_text("model: base\n", encoding="utf-8")
        (default_root / "memories" / "MEMORY.md").write_text("default mem\n", encoding="utf-8")
        (default_root / "models" / "weights.gguf").write_bytes(b"X" * 1024)
        (default_root / "mystery_stray_file.txt").write_text("unclassified", encoding="utf-8")
        (named_coder / "config.yaml").write_text("model: coder-v1\n", encoding="utf-8")
        (named_coder / "memories" / "MEMORY.md").write_text("coder mem v1\n", encoding="utf-8")

        def_fp_1 = build_tree_fingerprint_manifest(
            unit_kind="profile",
            unit_id="default",
            root_path=default_root,
            descendant_profile_roots=[named_coder],
        )
        coder_fp_1 = build_tree_fingerprint_manifest(
            unit_kind="profile",
            unit_id="coder",
            root_path=named_coder,
        )

        # Modify named profile `coder` and shared infrastructure `models/weights.gguf`
        (named_coder / "memories" / "MEMORY.md").write_text("coder mem v2 with much more text!\n", encoding="utf-8")
        (default_root / "models" / "weights.gguf").write_bytes(b"Y" * 4096)

        def_fp_2 = build_tree_fingerprint_manifest(
            unit_kind="profile",
            unit_id="default",
            root_path=default_root,
            descendant_profile_roots=[named_coder],
        )
        coder_fp_2 = build_tree_fingerprint_manifest(
            unit_kind="profile",
            unit_id="coder",
            root_path=named_coder,
        )

        # Default's owned size, config match digest, whole-profile digest, and unit digest are UNCHANGED!
        self.assertEqual(def_fp_1.logical_bytes, def_fp_2.logical_bytes)
        self.assertEqual(def_fp_1.configuration_match_digest, def_fp_2.configuration_match_digest)
        self.assertEqual(def_fp_1.whole_profile_digest, def_fp_2.whole_profile_digest)
        self.assertEqual(def_fp_1.unit_digest, def_fp_2.unit_digest)

        # Named profile `coder` changed size and digests
        self.assertGreater(coder_fp_2.logical_bytes, coder_fp_1.logical_bytes)
        self.assertNotEqual(coder_fp_1.configuration_match_digest, coder_fp_2.configuration_match_digest)
        self.assertNotEqual(coder_fp_1.whole_profile_digest, coder_fp_2.whole_profile_digest)

        # Shared infrastructure and unclassified entries are tracked separately
        self.assertIn("models", def_fp_2.shared_infrastructure_entries)
        self.assertIn("mystery_stray_file.txt", def_fp_2.unclassified_entries)
        self.assertNotIn("mystery_stray_file.txt", def_fp_2.files)

    def test_hardlinked_shared_objects_logical_vs_deduplicated_system_totals(self) -> None:
        """§12: Hard-linked/shared objects report logical per-owner totals distinct from deduplicated system totals."""
        prof_a = self.tmp_root / "prof_a"
        prof_b = self.tmp_root / "prof_b"
        (prof_a / "skills" / "s1").mkdir(parents=True)
        (prof_b / "skills" / "s1").mkdir(parents=True)

        file_a = prof_a / "skills" / "s1" / "SKILL.md"
        file_b = prof_b / "skills" / "s1" / "SKILL.md"
        payload = b"Shared skill content across hardlink\n" * 20
        file_a.write_bytes(payload)
        os.link(file_a, file_b)

        fp_a = build_tree_fingerprint_manifest(unit_kind="profile", unit_id="a", root_path=prof_a)
        fp_b = build_tree_fingerprint_manifest(unit_kind="profile", unit_id="b", root_path=prof_b)

        self.assertEqual(fp_a.logical_bytes, len(payload))
        self.assertEqual(fp_b.logical_bytes, len(payload))
        totals = compute_system_deduplicated_bytes([fp_a, fp_b])
        self.assertEqual(totals["logical_total_bytes"], 2 * len(payload))
        self.assertEqual(totals["deduplicated_system_bytes"], len(payload))

    def test_optional_root_downward_only_and_worktree_pointer_without_git(self) -> None:
        """§3 & §11: Optional root discovery is strictly downward and recognizes worktree pointers without running git."""
        parent_repo = self.tmp_root / "parent_repo"
        (parent_repo / ".git").mkdir(parents=True)
        opt_root = parent_repo / "workspace"
        reg_repo = opt_root / "reg_app"
        unreg_wt = opt_root / "nested" / "unreg_worktree"
        (reg_repo / ".git").mkdir(parents=True)
        unreg_wt.mkdir(parents=True)
        (unreg_wt / ".git").write_text("gitdir: /tmp/main_repo/.git/worktrees/unreg_worktree\n", encoding="utf-8")

        res = discover_optional_root_repos(
            opt_root,
            registered_canonical_paths=[str(reg_repo.resolve())],
        )
        self.assertEqual(res["coverage"], COVERAGE_VERIFIED)
        discovered_paths = [r["path"] for r in res["repos"]]
        # Parent repo above opt_root is NEVER included (under either spelling)
        self.assertNotIn(str(parent_repo.resolve()), discovered_paths)
        self.assertNotIn(os.path.abspath(parent_repo), discovered_paths)
        self.assertEqual(len(res["repos"]), 2)

        # Paths are shown as the root was spelled; registration matches the resolved spelling.
        by_path = {r["path"]: r for r in res["repos"]}
        self.assertTrue(by_path[os.path.abspath(reg_repo)]["registered"])
        self.assertFalse(by_path[os.path.abspath(reg_repo)]["not_set_up_by_plugin"])
        self.assertEqual(by_path[os.path.abspath(reg_repo)]["git_kind"], "git_dir")

        wt_entry = by_path[os.path.abspath(unreg_wt)]
        self.assertFalse(wt_entry["registered"])
        self.assertTrue(wt_entry["not_set_up_by_plugin"])
        self.assertEqual(wt_entry["scope"], "isolation_only")
        self.assertEqual(wt_entry["git_kind"], "worktree_pointer")
        self.assertEqual(wt_entry["gitdir_target"], "/tmp/main_repo/.git/worktrees/unreg_worktree")

    def test_unused_threshold_fallback_mtime_and_survivor_rules(self) -> None:
        """§8 & §13.5: Last-use from state.db -> fallback mtime -> else could_not_verify; survivor rules."""
        # 1. Profile with neither state.db nor memories/sessions -> could_not_verify, never unused
        empty_prof = self.tmp_root / "empty_prof"
        empty_prof.mkdir()
        ev_empty = collect_profile_last_use_evidence(empty_prof)
        self.assertEqual(ev_empty["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertIsNone(ev_empty["last_use_timestamp"])

        eval_empty = evaluate_profile_age_and_unused(
            profile_name="empty_prof",
            is_default=False,
            is_active=False,
            last_use_evidence=ev_empty,
            as_of=1710000000,
            unused_threshold_days=90,
        )
        self.assertEqual(eval_empty["coverage"], COVERAGE_COULD_NOT_VERIFY)
        self.assertIsNone(eval_empty["is_unused_beyond_threshold"])
        self.assertFalse(eval_empty["archive_candidate"])

        # 2. Survivor selection: active -> most recent -> lexical; never archive active/default/unknown
        dups = [
            {"name": "default", "is_active": False, "last_use_timestamp": 1600000000.0},
            {"name": "zeta", "is_active": False, "last_use_timestamp": 1600000500.0},
            {"name": "alpha", "is_active": False, "last_use_timestamp": 1600000500.0},
            {"name": "unknown_age", "is_active": False, "last_use_timestamp": None},
        ]
        surv = choose_duplicate_survivor(dups, active_profile="coder")
        # Between alpha and zeta tied at most recent (1600000500.0), lexical 'alpha' wins as survivor
        self.assertEqual(surv["survivor"], "alpha")
        cand_names = [c["name"] for c in surv["archive_candidates"]]
        # Only 'zeta' is eligible; 'default' and 'unknown_age' are protected
        self.assertEqual(cand_names, ["zeta"])
        self.assertFalse(surv["archive_candidates"][0]["selected_by_default"])
        protected_names = {p["name"] for p in surv["protected_non_survivors"]}
        self.assertEqual(protected_names, {"default", "unknown_age"})

    def test_project_context_precedence_and_shadowing(self) -> None:
        """§2 'What enters the prompt': .hermes.md > AGENTS.md chain > CLAUDE.md > .cursorrules."""
        proj = self.tmp_root / "ctx_proj"
        sub = proj / "packages" / "api"
        sub.mkdir(parents=True)
        (proj / ".git").mkdir()

        (proj / "AGENTS.md").write_text("Root agents guidance", encoding="utf-8")
        (sub / "AGENTS.md").write_text("Subdir agents guidance", encoding="utf-8")
        (sub / "CLAUDE.md").write_text("Shadowed claude guidance", encoding="utf-8")

        ctx = resolve_project_context_chain_facts(proj, cwd=sub)
        self.assertEqual(ctx["winning_kind"], "agents_md")
        injected = [f for f in ctx["files"] if f["injected"]]
        shadowed = [f for f in ctx["files"] if not f["injected"]]
        self.assertEqual(len(injected), 2)
        self.assertEqual(len(shadowed), 1)
        self.assertEqual(shadowed[0]["kind"], "claude_md")
        self.assertEqual(shadowed[0]["injected_chars"], 0)


if __name__ == "__main__":
    unittest.main()
