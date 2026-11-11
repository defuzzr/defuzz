"""Unit tests for tool_doctor.py and `hermes defuzz tools doctor` CLI subcommand."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import state_store, tool_doctor, toolchk  # noqa: E402
from hermes_plugins.defuzz.cli import main as cli_main  # noqa: E402


def _make_lock(tools_map: dict[str, str], chosen: str = "2026-11-06") -> dict[str, Any]:
    tools: dict[str, dict[str, Any]] = {}
    for name, ver in tools_map.items():
        tools[name] = {
            "version": ver,
            "chosen": chosen,
            "reason": f"Pinned {name} to {ver} for deterministic testing.",
            "probe": "command",
            "argv": [name, "--version"],
            "source": "human",
        }
    return {
        "lock": dict(toolchk.DEFAULT_HEADER),
        "tools": tools,
    }


def test_registered_project_paths_and_doctor_lines_with_tmp_state_db(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_file = tmp_path / "state.db"

    proj_ok = tmp_path / "proj-ok"
    proj_drift = tmp_path / "proj-drift"
    proj_missing = tmp_path / "proj-missing-lock"
    proj_deleted = tmp_path / "proj-does-not-exist"

    for p in (proj_ok, proj_drift, proj_missing):
        p.mkdir(parents=True)

    # proj_ok has 4 tools, all matching
    toolchk.dump_lock(
        proj_ok / "TOOLS.lock",
        _make_lock(
            {
                "cargo": "1.82.0",
                "rust": "1.82.0",
                "node": "20.11.0",
                "python": "3.12.0",
            },
            chosen="2026-11-06",
        ),
    )

    # proj_drift has cargo and rust drifted
    toolchk.dump_lock(
        proj_drift / "TOOLS.lock",
        _make_lock({"cargo": "1.82.0", "rust": "1.82.0"}, chosen="2026-11-06"),
    )

    # Record 3 existing projects + 1 non-existent path in state_store
    for idx, (p, slug) in enumerate(
        (
            (proj_ok, "proj-ok"),
            (proj_drift, "proj-drift"),
            (proj_missing, "proj-missing-lock"),
            (proj_deleted, "proj-does-not-exist"),
        )
    ):
        state_store.record_project(
            path=p,
            name=slug,
            slug=slug,
            template_id="rust-golden",
            answers={"building": "app", "layout": "mono", "languages": ["rust"]},
            hermes_project_id=f"pid-{idx}",
            db_path=db_file,
        )

    paths = tool_doctor.registered_project_paths(db_path=db_file)
    assert {p.resolve() for p in paths} == {
        proj_ok.resolve(),
        proj_drift.resolve(),
        proj_missing.resolve(),
    }
    assert len(paths) == 3

    def fake_probe(
        name: str,
        entry: dict[str, Any],
        project_root: Path | str | None = None,
        timeout: float = 3.0,
    ) -> tuple[str, str]:
        if project_root is not None and Path(project_root).resolve() == proj_drift.resolve():
            return "1.97.1", f"/usr/bin/{name}"
        return str(entry["version"]), f"/usr/bin/{name}"

    monkeypatch.setattr(toolchk, "probe", fake_probe)

    lines = tool_doctor.doctor_lines(paths)
    assert sorted(lines) == sorted([
        "  ok     proj-ok  (4 tools, lock 2026-11-06)",
        "  DRIFT  proj-drift  cargo 1.97.1 != 1.82.0; rust 1.97.1 != 1.82.0",
        "  --     proj-missing-lock  no TOOLS.lock",
    ])


def test_doctor_lines_broken_lock(tmp_path: Path) -> None:
    proj_broken = tmp_path / "proj-broken"
    proj_broken.mkdir(parents=True)
    (proj_broken / "TOOLS.lock").write_text("[lock]\nschema = 99\n", encoding="utf-8")

    lines = tool_doctor.doctor_lines([proj_broken])
    assert len(lines) == 1
    assert lines[0].startswith("  BROKEN proj-broken  ")
    assert "schema" in lines[0]


def test_cli_tools_doctor_exit_zero_and_json_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_hermes = tmp_path / "hermes_home"
    monkeypatch.setenv("HERMES_HOME", str(fake_hermes))
    db_file = state_store.state_db_path()

    proj_ok = tmp_path / "alpha"
    proj_drift = tmp_path / "beta"
    proj_nolock = tmp_path / "gamma"
    for p in (proj_ok, proj_drift, proj_nolock):
        p.mkdir(parents=True)

    toolchk.dump_lock(proj_ok / "TOOLS.lock", _make_lock({"node": "20.11.0"}))
    toolchk.dump_lock(proj_drift / "TOOLS.lock", _make_lock({"cargo": "1.82.0"}))

    for idx, p in enumerate((proj_ok, proj_drift, proj_nolock)):
        state_store.record_project(
            path=p,
            name=p.name,
            slug=p.name,
            template_id=None,
            answers={"building": "tool", "languages": ["python"]},
            hermes_project_id=f"id-{idx}",
            db_path=db_file,
        )

    def fake_probe(
        name: str,
        entry: dict[str, Any],
        project_root: Path | str | None = None,
        timeout: float = 3.0,
    ) -> tuple[str, str]:
        if name == "cargo":
            return "1.97.1", "/usr/bin/cargo"
        return str(entry["version"]), f"/usr/bin/{name}"

    monkeypatch.setattr(toolchk, "probe", fake_probe)

    out_txt = io.StringIO()
    with redirect_stdout(out_txt):
        rc_txt = cli_main(["tools", "doctor"])
    assert rc_txt == 0
    txt_lines = out_txt.getvalue().splitlines()
    assert txt_lines == [
        "  ok     alpha  (1 tools, lock 2026-11-06)",
        "  DRIFT  beta  cargo 1.97.1 != 1.82.0",
        "  --     gamma  no TOOLS.lock",
    ]

    out_json = io.StringIO()
    with redirect_stdout(out_json):
        rc_json = cli_main(["tools", "doctor", "--json"])
    assert rc_json == 0
    payload = json.loads(out_json.getvalue())
    assert isinstance(payload, dict)
    assert payload["ok"] is False
    assert payload["lines"] == txt_lines
    assert len(payload["projects"]) == 3
    assert [item["status"] for item in payload["projects"]] == ["ok", "drift", "missing"]


@pytest.mark.parametrize("readonly", [False, True], ids=["writable", "0555"])
def test_registered_project_paths_closed_wal_no_sidecars_or_migration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    readonly: bool,
) -> None:
    import hashlib
    import os
    import sqlite3

    if readonly and os.geteuid() == 0:
        pytest.skip("root bypasses chmod 0555 directory permissions")

    fake_hermes = tmp_path / "hermes_home"
    db_dir = fake_hermes / "plugin-data" / "defuzz"
    db_dir.mkdir(parents=True)
    db_file = db_dir / "state.db"

    proj_a = tmp_path / "proj-a"
    proj_b = tmp_path / "proj-b"
    proj_a.mkdir()
    proj_b.mkdir()

    conn = sqlite3.connect(db_file)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "CREATE TABLE projects (path TEXT PRIMARY KEY, created_at INTEGER)"
    )
    conn.execute("INSERT INTO projects VALUES (?, ?)", (str(proj_a), 1))
    conn.execute("INSERT INTO projects VALUES (?, ?)", (str(proj_b), 2))
    conn.commit()
    conn.close()
    assert not Path(f"{db_file}-wal").exists()
    assert not Path(f"{db_file}-shm").exists()

    def snap(root: Path) -> dict[str, str | None]:
        return {
            str(p.relative_to(root)): (
                hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
            )
            for p in sorted(root.rglob("*"))
        }

    monkeypatch.setenv("HERMES_HOME", str(fake_hermes))
    before = snap(fake_hermes)
    if readonly:
        db_dir.chmod(0o555)
    try:
        got_default = tool_doctor.registered_project_paths()
        got_explicit = tool_doctor.registered_project_paths(db_path=db_file)
        assert [p.resolve() for p in got_default] == [proj_a.resolve(), proj_b.resolve()]
        assert [p.resolve() for p in got_explicit] == [proj_a.resolve(), proj_b.resolve()]
        after = snap(fake_hermes)
        assert after == before
    finally:
        db_dir.chmod(0o755)
