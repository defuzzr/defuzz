"""Unit tests for state_store.py."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import state_store  # noqa: E402
from hermes_plugins.defuzz.state_store import (  # noqa: E402
    get_project,
    get_template_option,
    get_template_options,
    is_registered,
    list_projects,
    list_template_options,
    record_project,
    record_template_option,
    record_template_options,
    save_answers,
    state_db_path,
)


class TestStateStore(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_state_db_path_uses_hermes_home_env(self) -> None:
        fake_home = self.tmp_root / "custom_hermes_home"
        with mock.patch.dict(os.environ, {"HERMES_HOME": str(fake_home)}):
            db_p = state_db_path()
            self.assertEqual(db_p, fake_home / "plugin-data" / "defuzz" / "state.db")
            row_id = save_answers({"building": "game", "languages": ["rust"]})
            self.assertGreaterEqual(row_id, 1)
            self.assertTrue(db_p.is_file())

    def test_state_db_path_prefers_hermes_context_override_and_ctx_home(self) -> None:
        env_home = self.tmp_root / "env_hermes_home"
        override_home = self.tmp_root / "routed_profile_home"
        ctx_home = self.tmp_root / "ctx_profile_home"

        # Invented ctx.home_path / ctx.hermes_home / ctx._manager attributes are ignored
        class _FakeMgr:
            home_path = ctx_home

        class _FakeCtx:
            home_path = ctx_home
            hermes_home = ctx_home
            _manager = _FakeMgr()

        with mock.patch.dict(os.environ, {"HERMES_HOME": str(env_home)}):
            db_ctx = state_db_path(ctx=_FakeCtx())
            self.assertEqual(db_ctx, env_home / "plugin-data" / "defuzz" / "state.db")

        with mock.patch.dict(os.environ, {"HERMES_HOME": str(override_home)}):
            db_p = state_db_path()
            self.assertEqual(db_p, override_home / "plugin-data" / "defuzz" / "state.db")
            save_answers({"building": "tool", "languages": ["python"]})
            self.assertTrue(db_p.is_file())

    def test_save_answers_returns_id_and_round_trips_json(self) -> None:
        db = self.tmp_root / "state.db"
        answers1 = {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}
        answers2 = {"building": "service", "layout": "poly", "languages": ["python", "typescript"]}

        id1 = save_answers(answers1, db_path=db)
        id2 = save_answers(answers2, project_path="/tmp/proj-service", db_path=db)

        self.assertIsInstance(id1, int)
        self.assertIsInstance(id2, int)
        self.assertGreater(id2, id1)

        with closing(sqlite3.connect(str(db))) as conn:
            rows = conn.execute(
                "SELECT id, created_at, answers_json, project_path FROM answers ORDER BY id ASC"
            ).fetchall()

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], id1)
        self.assertIsInstance(rows[0][1], int)
        self.assertEqual(json.loads(rows[0][2]), answers1)
        self.assertIsNone(rows[0][3])

        self.assertEqual(rows[1][0], id2)
        self.assertEqual(json.loads(rows[1][2]), answers2)
        self.assertEqual(rows[1][3], "/tmp/proj-service")

    def test_record_get_list_and_is_registered(self) -> None:
        db = self.tmp_root / "state.db"
        proj_a = str(self.tmp_root / "projects" / "my-game")
        proj_b = str(self.tmp_root / "projects" / "my-service-api")

        self.assertFalse(is_registered(proj_a, db_path=db))
        self.assertIsNone(get_project(proj_a, db_path=db))
        self.assertEqual(list_projects(db_path=db), [])

        record_project(
            path=proj_a,
            name="My Game",
            slug="my-game",
            template_id="fake-rust-game",
            answers={"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"},
            hermes_project_id="proj-111",
            db_path=db,
        )
        record_project(
            path=proj_b,
            name="My Service API",
            slug="my-service-api",
            template_id="fake-py-service",
            answers={"building": "service", "layout": "poly", "languages": ["python", "typescript"]},
            hermes_project_id="proj-222",
            db_path=db,
        )

        self.assertTrue(is_registered(proj_a, db_path=db))
        self.assertTrue(is_registered(proj_b, db_path=db))
        self.assertFalse(is_registered(str(self.tmp_root / "projects" / "unknown"), db_path=db))

        got_a = get_project(proj_a, db_path=db)
        self.assertIsNotNone(got_a)
        assert got_a is not None
        # Project keys are stored resolved (the temp folder may sit behind a link).
        self.assertEqual(got_a["path"], os.path.realpath(proj_a))
        self.assertEqual(got_a["name"], "My Game")
        self.assertEqual(got_a["slug"], "my-game")
        self.assertEqual(got_a["template_id"], "fake-rust-game")
        self.assertEqual(got_a["kind"], "game")
        self.assertEqual(got_a["layout"], "mono")
        self.assertEqual(got_a["languages"], ["rust"])
        self.assertEqual(got_a["engine"], "bevy")
        self.assertEqual(got_a["hermes_project_id"], "proj-111")
        self.assertIsInstance(got_a["created_at"], int)

        got_b = get_project(proj_b, db_path=db)
        self.assertIsNotNone(got_b)
        assert got_b is not None
        self.assertEqual(got_b["languages"], ["python", "typescript"])
        self.assertIsNone(got_b["engine"])

        all_projs = list_projects(db_path=db)
        self.assertEqual(len(all_projs), 2)
        self.assertEqual({p["path"] for p in all_projs}, {os.path.realpath(proj_a), os.path.realpath(proj_b)})

    def test_idempotent_re_record_insert_or_replace(self) -> None:
        db = self.tmp_root / "state.db"
        proj_path = str(self.tmp_root / "projects" / "my-game")

        with mock.patch.object(state_store.time, "time", return_value=1700000000):
            record_project(
                path=proj_path,
                name="My Game v1",
                slug="my-game",
                template_id="fake-rust-game",
                answers={"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"},
                hermes_project_id="proj-old",
                db_path=db,
            )
        with mock.patch.object(state_store.time, "time", return_value=1700000500):
            record_project(
                path=proj_path,
                name="My Game v2",
                slug="my-game-v2",
                template_id="fake-rust-game-v2",
                answers={"building": "studio", "layout": "poly", "languages": ["rust", "gdscript"], "engine": "godot"},
                hermes_project_id="proj-new",
                db_path=db,
            )

        projects = list_projects(db_path=db)
        self.assertEqual(len(projects), 1)
        got = get_project(proj_path, db_path=db)
        self.assertIsNotNone(got)
        assert got is not None
        self.assertEqual(got["created_at"], 1700000000)
        self.assertEqual(got["name"], "My Game v2")
        self.assertEqual(got["slug"], "my-game-v2")
        self.assertEqual(got["template_id"], "fake-rust-game-v2")
        self.assertEqual(got["kind"], "studio")
        self.assertEqual(got["layout"], "poly")
        self.assertEqual(got["languages"], ["rust", "gdscript"])
        self.assertEqual(got["engine"], "godot")
        self.assertEqual(got["hermes_project_id"], "proj-new")

    def test_connect_closes_connection_when_schema_init_fails(self) -> None:
        db = self.tmp_root / "state.db"
        fake_conn = mock.MagicMock()
        fake_conn.executescript.side_effect = sqlite3.OperationalError("boom")
        with mock.patch.object(state_store.sqlite3, "connect", return_value=fake_conn):
            with self.assertRaises(sqlite3.OperationalError):
                state_store._connect(db)
        fake_conn.close.assert_called_once()

    def test_provenance_columns_recorded_and_legacy_registrations_never_backfilled(self) -> None:
        db = self.tmp_root / "state.db"
        legacy_proj = str((self.tmp_root / "projects" / "legacy-app").resolve())
        scaffold_proj = str((self.tmp_root / "projects" / "scaffold-app").resolve())

        # Create a pre-provenance schema database with an existing row
        with closing(sqlite3.connect(str(db))) as conn:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE projects (
                        path TEXT PRIMARY KEY,
                        name TEXT,
                        slug TEXT,
                        template_id TEXT,
                        kind TEXT,
                        layout TEXT,
                        languages TEXT,
                        engine TEXT,
                        created_at INTEGER,
                        hermes_project_id TEXT,
                        rules_hash TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO projects (
                        path, name, slug, template_id, kind, layout,
                        languages, engine, created_at, hermes_project_id, rules_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        legacy_proj,
                        "Legacy App",
                        "legacy-app",
                        "rust-golden",
                        "app",
                        "mono",
                        json.dumps(["rust"]),
                        None,
                        1700000000,
                        "p-legacy",
                        None,
                    ),
                )

        # Opening/migrating via get_project adds provenance columns but never backfills existing rows
        legacy_rec = get_project(legacy_proj, db_path=db)
        self.assertIsNotNone(legacy_rec)
        assert legacy_rec is not None
        self.assertIsNone(legacy_rec["plugin_commit"])
        self.assertIsNone(legacy_rec["prefix"])
        self.assertIsNone(legacy_rec["locked_hashes"])

        # Recording a new scaffolded project stores provenance fields
        expected_hashes = {
            "Cargo.toml": "a" * 64,
            "xtask/src/main.rs": "b" * 64,
        }
        record_project(
            path=scaffold_proj,
            name="Scaffold App",
            slug="scaffold-app",
            template_id="rust-golden",
            answers={"building": "app", "layout": "mono", "languages": ["rust"]},
            hermes_project_id="p-scaffold",
            db_path=db,
            plugin_commit="0123456789abcdef0123456789abcdef01234567",
            prefix="scaffold_app",
            locked_hashes=expected_hashes,
        )

        scaffold_rec = get_project(scaffold_proj, db_path=db)
        self.assertIsNotNone(scaffold_rec)
        assert scaffold_rec is not None
        self.assertEqual(scaffold_rec["template_id"], "rust-golden")
        self.assertEqual(
            scaffold_rec["plugin_commit"],
            "0123456789abcdef0123456789abcdef01234567",
        )
        self.assertEqual(scaffold_rec["prefix"], "scaffold_app")
        self.assertEqual(scaffold_rec["locked_hashes"], expected_hashes)

        # Legacy row remains unbackfilled even after new rows are written or legacy row is re-recorded without provenance
        record_project(
            path=legacy_proj,
            name="Legacy App Renamed",
            slug="legacy-app",
            template_id="rust-golden",
            answers={"building": "app", "layout": "mono", "languages": ["rust"]},
            hermes_project_id="p-legacy",
            db_path=db,
        )
        legacy_after = get_project(legacy_proj, db_path=db)
        assert legacy_after is not None
        self.assertEqual(legacy_after["name"], "Legacy App Renamed")
        self.assertIsNone(legacy_after["plugin_commit"])
        self.assertIsNone(legacy_after["prefix"])
        self.assertIsNone(legacy_after["locked_hashes"])

    def test_template_options_table_record_update_and_query(self) -> None:
        db = self.tmp_root / "state.db"
        self.assertIsNone(get_template_option("ts-node-golden", "http_adapter", db_path=db))
        self.assertEqual(get_template_options("ts-node-golden", db_path=db), {})
        self.assertEqual(list_template_options(db_path=db), [])

        record_template_option(
            "ts-node-golden",
            "http_adapter",
            "hono",
            db_path=db,
            chosen_at=1700000100,
        )
        row = get_template_option("ts-node-golden", "http_adapter", db_path=db)
        self.assertEqual(
            row,
            {
                "template_id": "ts-node-golden",
                "option_id": "http_adapter",
                "choice": "hono",
                "chosen_at": 1700000100,
            },
        )
        self.assertEqual(
            get_template_options("ts-node-golden", db_path=db),
            {"http_adapter": "hono"},
        )

        # Upsert updates choice and chosen_at
        record_template_option(
            "ts-node-golden",
            "http_adapter",
            "node_http",
            db_path=db,
            chosen_at=1700000200,
        )
        row2 = get_template_option("ts-node-golden", "http_adapter", db_path=db)
        self.assertEqual(
            row2,
            {
                "template_id": "ts-node-golden",
                "option_id": "http_adapter",
                "choice": "node_http",
                "chosen_at": 1700000200,
            },
        )

        # Batch record_template_options for another template
        record_template_options(
            "python-golden",
            {"http_adapter": "fastapi"},
            db_path=db,
            chosen_at=1700000300,
        )
        all_rows = list_template_options(db_path=db)
        self.assertEqual(
            all_rows,
            [
                {
                    "template_id": "python-golden",
                    "option_id": "http_adapter",
                    "choice": "fastapi",
                    "chosen_at": 1700000300,
                },
                {
                    "template_id": "ts-node-golden",
                    "option_id": "http_adapter",
                    "choice": "node_http",
                    "chosen_at": 1700000200,
                },
            ],
        )


if __name__ == "__main__":
    unittest.main()
