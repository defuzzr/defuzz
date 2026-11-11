"""Unit tests for safe_state_store.py."""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.safe_state_store import (  # noqa: E402
    SafeStateError,
    SafeStateStore,
    atomic_write_json,
    delete_state,
    get_entry,
    get_state,
    list_namespace,
    save_batch,
    save_state,
    sync_wal,
)


class TestSafeStateStore(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)
        self.db_path = self.tmp_root / "nested" / "safe_state.db"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_save_and_get_enforces_monotonic_seq_guard(self) -> None:
        r1 = save_state(self.db_path, "ui", "split_pct", 70, seq=1, now=1000.0)
        self.assertTrue(r1["applied"])
        self.assertEqual(r1["value"], 70)
        self.assertEqual(r1["seq"], 1)
        self.assertEqual(r1["updated_at"], 1000.0)

        # Duplicate seq is rejected (`seq > old_seq` required)
        r_dup = save_state(self.db_path, "ui", "split_pct", 50, seq=1, now=1005.0)
        self.assertFalse(r_dup["applied"])
        self.assertEqual(r_dup["value"], 70)
        self.assertEqual(r_dup["seq"], 1)

        # Newer seq updates
        r2 = save_state(self.db_path, "ui", "split_pct", 65.5, seq=5, now=1010.0)
        self.assertTrue(r2["applied"])
        self.assertEqual(r2["value"], 65.5)
        self.assertEqual(r2["seq"], 5)

        # Out-of-order lower seq is rejected and leaves seq=5 intact
        r_stale = save_state(self.db_path, "ui", "split_pct", 25, seq=3, now=1020.0)
        self.assertFalse(r_stale["applied"])
        self.assertEqual(r_stale["value"], 65.5)
        self.assertEqual(r_stale["seq"], 5)
        self.assertEqual(get_state(self.db_path, "ui", "split_pct"), 65.5)

    def test_namespaces_are_isolated_and_listed(self) -> None:
        save_state(self.db_path, "never_warn", "clear_all", True, seq=1)
        save_state(self.db_path, "never_warn", "pro_mode", False, seq=2)
        save_state(self.db_path, "rules", "clear_all", {"pre": True, "post": False}, seq=1)

        nw = list_namespace(self.db_path, "never_warn")
        self.assertEqual(sorted(nw.keys()), ["clear_all", "pro_mode"])
        self.assertIs(nw["clear_all"]["value"], True)
        self.assertIs(nw["pro_mode"]["value"], False)
        self.assertEqual(get_state(self.db_path, "rules", "clear_all"), {"pre": True, "post": False})
        self.assertEqual(get_state(self.db_path, "rules", "missing", default="fallback"), "fallback")
        self.assertIsNone(get_entry(self.db_path, "rules", "missing"))

    def test_save_batch_and_delete_with_seq_guard(self) -> None:
        results = save_batch(
            self.db_path,
            [
                {"namespace": "rules", "key": "r1", "value": True, "seq": 2},
                ("rules", "r2", ["a", "b"], 4),
                {"namespace": "rules", "key": "r1", "value": False, "seq": 1},  # stale in same batch
            ],
            now=2000.0,
        )
        self.assertEqual([r["applied"] for r in results], [True, True, False])
        self.assertIs(get_state(self.db_path, "rules", "r1"), True)
        self.assertEqual(get_state(self.db_path, "rules", "r2"), ["a", "b"])

        # Delete with stale min_seq <= current seq is refused
        self.assertFalse(delete_state(self.db_path, "rules", "r2", min_seq=4))
        self.assertIsNotNone(get_entry(self.db_path, "rules", "r2"))

        # Delete with newer min_seq > current seq succeeds
        self.assertTrue(delete_state(self.db_path, "rules", "r2", min_seq=5))
        self.assertIsNone(get_entry(self.db_path, "rules", "r2"))

    def test_store_class_coalesces_staged_writes_and_syncs_wal(self) -> None:
        ticks = iter([10.0, 20.0, 30.0, 40.0, 50.0])
        store = SafeStateStore(
            self.db_path,
            default_namespace="settings",
            clock=lambda: next(ticks, 99.0),
        )
        s1 = store.stage("split_width", 70)
        s2 = store.stage("split_width", 68)
        s3 = store.stage("split_width", 62)
        self.assertEqual((s1, s2, s3), (1, 2, 3))
        # Not yet flushed to disk
        self.assertIsNone(store.get("split_width"))

        # Stale explicit seq in stage is ignored in favor of seq=3
        store.stage("split_width", 99, seq=2)
        flushed = store.flush()
        self.assertEqual(len(flushed), 1)
        self.assertTrue(flushed[0]["applied"])
        self.assertEqual(flushed[0]["seq"], 3)
        self.assertEqual(flushed[0]["value"], 62)
        self.assertEqual(store.get("split_width"), 62)

        # Verify WAL mode is active and sync_wal succeeds
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(str(mode).lower(), "wal")
        cp = store.sync_wal("PASSIVE")
        self.assertEqual(len(cp), 3)

    def test_atomic_write_json_and_validation_errors(self) -> None:
        snap = self.tmp_root / "snapshots" / "state.json"
        written = atomic_write_json(snap, {"seq": 14, "split": 70})
        self.assertEqual(written, snap)
        self.assertEqual(json.loads(snap.read_text(encoding="utf-8")), {"seq": 14, "split": 70})

        # Refuses to overwrite a symlink target
        link_path = self.tmp_root / "symlink_state.json"
        link_path.symlink_to(snap)
        with self.assertRaises(SafeStateError):
            atomic_write_json(link_path, {"seq": 15})

        with self.assertRaises(SafeStateError):
            save_state(self.db_path, "", "k", 1, seq=1)
        with self.assertRaises(SafeStateError):
            save_state(self.db_path, "ns", " ", 1, seq=1)
        with self.assertRaises(SafeStateError):
            save_state(self.db_path, "ns", "k", 1, seq=0)
        with self.assertRaises(SafeStateError):
            save_state(self.db_path, "ns", "k", 1, seq=True)
        with self.assertRaises(SafeStateError):
            save_state(self.db_path, "ns", "k", {1, 2, 3}, seq=1)
        with self.assertRaises(SafeStateError):
            sync_wal(self.db_path, mode="INVALID_MODE")


class TestSafeStateStoreSeqBounds(unittest.TestCase):
    """seq values SQLite cannot store raise SafeStateError, never OverflowError."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "bounds.db"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_huge_seq_raises_plain_error_everywhere(self) -> None:
        from hermes_plugins.defuzz.safe_state_store import MAX_SEQ

        self.assertEqual(MAX_SEQ, 2**63 - 1)
        for bad in (MAX_SEQ + 1, 10**40, 10**400):
            with self.assertRaises(SafeStateError):
                save_state(self.db_path, "ns", "k", 1, seq=bad)
            with self.assertRaises(SafeStateError):
                save_batch(self.db_path, [{"namespace": "ns", "key": "k", "value": 1, "seq": bad}])
            with self.assertRaises(SafeStateError):
                delete_state(self.db_path, "ns", "k", min_seq=bad)
            store = SafeStateStore(self.db_path, default_namespace="ns")
            with self.assertRaises(SafeStateError):
                store.save("k", 1, seq=bad)
        self.assertEqual(save_state(self.db_path, "ns", "k", 1, seq=MAX_SEQ)["seq"], MAX_SEQ)
        store = SafeStateStore(self.db_path, default_namespace="ns")
        with self.assertRaises(SafeStateError):
            store.next_seq("k")

    def test_deeply_nested_value_raises_plain_error(self) -> None:
        value: object = 1
        for _ in range(100_000):
            value = [value]
        with self.assertRaises(SafeStateError):
            save_state(self.db_path, "ns", "k", value, seq=1)


if __name__ == "__main__":
    unittest.main()
