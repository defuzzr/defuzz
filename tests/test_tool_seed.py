"""Unit tests for tool_seed.py and CLI tools subcommands."""

from __future__ import annotations

import argparse
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli, tool_seed, toolchk  # noqa: E402
from hermes_plugins.defuzz.cli import (  # noqa: E402
    _handle_tools_subcommand,
    main as cli_main,
)
from hermes_plugins.defuzz.tool_seed import (  # noqa: E402
    accept_installed,
    load_tools_log,
    lock_path,
    seed_lock,
    set_reason,
    snooze,
    snoozed,
    status,
    table,
    tools_log_path,
)
from hermes_plugins.defuzz.toolchk import dump_lock, load_lock  # noqa: E402

TODAY = "2026-11-06"


def _fake_probe(versions: dict[str, str]):
    def _probe(
        name: str, entry: dict[str, Any], project_root: Path | str | None = None
    ) -> tuple[str, str]:
        if name not in versions:
            raise FileNotFoundError(f"binary {name!r} not found")
        return versions[name], f"/usr/bin/{name}"

    return _probe


def test_seed_lock_rust_toolchain_and_package_json_writes_parseable_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.82.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo", "packageManager": "pnpm@9.12.0"}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolchk,
        "probe",
        _fake_probe(
            {
                "rust": "1.82.0",
                "cargo": "1.82.0",
                "node": "22.11.0",
                "pnpm": "9.12.0",
            }
        ),
    )

    summary = seed_lock(tmp_path, event="adoption", today=TODAY)
    expected_path = lock_path(tmp_path)
    assert summary == {
        "written": str(expected_path),
        "added": ["cargo", "node", "pnpm", "rust"],
        "refreshed": [],
        "kept": [],
        "probe_failed": {},
    }
    assert expected_path.is_file()

    loaded = load_lock(expected_path)
    tools = loaded["tools"]
    assert sorted(tools.keys()) == ["cargo", "node", "pnpm", "rust"]
    assert tools["rust"]["version"] == "1.82.0"
    assert tools["cargo"]["version"] == "1.82.0"
    assert tools["node"]["version"] == "22.11.0"
    assert tools["pnpm"]["version"] == "9.12.0"
    for entry in tools.values():
        assert entry["chosen"] == TODAY
        assert entry["source"] == "auto"

    rep = status(tmp_path)
    assert rep["ok"] is True


def test_seed_lock_probe_failure_records_unknown_and_reason_suffix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")
    monkeypatch.setattr(toolchk, "probe", _fake_probe({}))

    summary = seed_lock(
        tmp_path,
        event="project creation",
        template_needs=("cua-driver",),
        today=TODAY,
    )
    assert summary["added"] == ["cua-driver", "node"]
    assert set(summary["probe_failed"].keys()) == {"cua-driver", "node"}
    assert summary["probe_failed"]["node"].startswith("node: not found on PATH")
    assert "Error" not in summary["probe_failed"]["node"]

    loaded = load_lock(lock_path(tmp_path))
    for name in ("cua-driver", "node"):
        entry = loaded["tools"][name]
        assert entry["version"] == "unknown"
        assert f"Probe failed at seeding: {name}: not found on PATH" in entry["reason"]
        assert "Error" not in entry["reason"]
        assert entry["reason"].endswith(".")


def _fake_node_bin(tmp_path: Path, body: str | None) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if body is not None:
        exe = bin_dir / "node"
        exe.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        exe.chmod(0o755)
    return bin_dir


def _node_project(tmp_path: Path, nvmrc: str | None) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")
    if nvmrc is not None:
        (proj / ".nvmrc").write_text(nvmrc + "\n", encoding="utf-8")
    return proj


def _assert_plain(line: str, tmp_path: Path) -> None:
    assert "Error" not in line
    assert str(tmp_path) not in line
    assert "Traceback" not in line


@pytest.mark.parametrize(
    ("nvmrc", "expected"),
    [
        (None, "node: not found on PATH. Install node, or run `hermes defuzz setup-tools`"),
        ("20", "node: not found on PATH, need >= 20. Install node, or run `hermes defuzz setup-tools`"),
    ],
)
def test_seed_missing_tool_records_plain_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, nvmrc: str | None, expected: str
) -> None:
    proj = _node_project(tmp_path, nvmrc)
    monkeypatch.setenv("PATH", str(_fake_node_bin(tmp_path, None)))
    summary = seed_lock(proj, event="project creation", today=TODAY)
    line = summary["probe_failed"]["node"]
    assert line.startswith(expected)
    _assert_plain(line, tmp_path)


@pytest.mark.parametrize("body", ["exit 1", "echo 'no digits here'"])
def test_seed_unreadable_version_records_plain_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    proj = _node_project(tmp_path, "20")
    monkeypatch.setenv("PATH", str(_fake_node_bin(tmp_path, body)))
    summary = seed_lock(proj, event="project creation", today=TODAY)
    line = summary["probe_failed"]["node"]
    assert line.startswith("node: found, but its version could not be read.")
    assert "hermes defuzz setup-tools" in line
    _assert_plain(line, tmp_path)


def test_seed_then_check_tool_below_floor_names_floor_and_found_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = _node_project(tmp_path, "20")
    monkeypatch.setenv("PATH", str(_fake_node_bin(tmp_path, "echo v18.0.0")))
    summary = seed_lock(proj, event="project creation", today=TODAY)
    assert summary["probe_failed"] == {}
    rep = status(proj)
    assert rep["ok"] is False
    assert rep["blocked"][0].startswith("node: found 18.0.0, need >= 20")
    assert "hermes defuzz setup-tools" in rep["blocked"][0]


def test_reseed_keeps_human_and_agent_entries_and_refreshes_auto(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.81.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")

    monkeypatch.setattr(
        toolchk,
        "probe",
        _fake_probe({"rust": "1.81.0", "cargo": "1.81.0", "node": "20.10.0"}),
    )
    seed_lock(tmp_path, event="adoption", today="2026-01-01")

    # Edit rust entry to source='human', add a custom agent entry, and keep cargo as 'auto'
    loaded1 = load_lock(lock_path(tmp_path))
    loaded1["tools"]["rust"]["version"] = "1.80.0"
    loaded1["tools"]["rust"]["reason"] = "Deliberately pinned to 1.80.0 by human."
    loaded1["tools"]["rust"]["source"] = "human"
    loaded1["tools"]["custom-agent-tool"] = {
        "version": "3.0.0",
        "chosen": "2026-02-02",
        "reason": "Pinned by agent for benchmark reproducibility.",
        "probe": "command",
        "argv": ["custom-agent-tool", "--version"],
        "source": "agent",
    }
    dump_lock(lock_path(tmp_path), loaded1)

    # Now update rust-toolchain and re-seed with newer versions
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.85.0"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        toolchk,
        "probe",
        _fake_probe({"rust": "1.85.0", "cargo": "1.85.0", "node": "22.0.0"}),
    )

    summary2 = seed_lock(tmp_path, event="adoption", today=TODAY)
    assert summary2["added"] == []
    assert summary2["refreshed"] == ["cargo", "node"]
    assert summary2["kept"] == ["custom-agent-tool", "rust"]

    loaded2 = load_lock(lock_path(tmp_path))
    assert loaded2["tools"]["rust"]["version"] == "1.80.0"
    assert loaded2["tools"]["rust"]["reason"] == "Deliberately pinned to 1.80.0 by human."
    assert loaded2["tools"]["rust"]["source"] == "human"
    assert loaded2["tools"]["custom-agent-tool"]["version"] == "3.0.0"
    assert loaded2["tools"]["custom-agent-tool"]["source"] == "agent"
    assert loaded2["tools"]["cargo"]["version"] == "1.85.0"
    assert loaded2["tools"]["cargo"]["chosen"] == TODAY
    assert loaded2["tools"]["node"]["version"] == "22.0.0"


def test_cli_tools_init_and_status_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package.json").write_text('{"name": "cli-demo"}\n', encoding="utf-8")
    monkeypatch.setattr(toolchk, "probe", _fake_probe({"node": "22.1.0"}))

    init_out = io.StringIO()
    with redirect_stdout(init_out):
        rc_init = cli_main(["tools", "init", "--event", "adoption", str(tmp_path)])
    assert rc_init == 0
    init_data = json.loads(init_out.getvalue())
    assert init_data["added"] == ["node"]

    # Exit code 0 when installed matches locked
    out0 = io.StringIO()
    with redirect_stdout(out0):
        rc0 = _handle_tools_subcommand(
            argparse.Namespace(tools_action="status", dir=str(tmp_path), as_json=False)
        )
    assert rc0 == 0
    assert "preflight ok" in out0.getvalue()

    # --json mode also returns 0 and valid JSON report
    out_json = io.StringIO()
    with redirect_stdout(out_json):
        rc_json = cli_main(["tools", "status", str(tmp_path), "--json"])
    assert rc_json == 0
    rep_json = json.loads(out_json.getvalue())
    assert rep_json["ok"] is True

    # Exit code 2 on version drift
    monkeypatch.setattr(toolchk, "probe", _fake_probe({"node": "23.0.0"}))
    out2 = io.StringIO()
    with redirect_stdout(out2):
        rc2 = _handle_tools_subcommand(
            argparse.Namespace(tools_action="status", dir=str(tmp_path), as_json=False)
        )
    assert rc2 == 2
    assert "preflight BLOCKED" in out2.getvalue()

    # Exit code 3 on probe failure
    monkeypatch.setattr(toolchk, "probe", _fake_probe({}))
    out3 = io.StringIO()
    with redirect_stdout(out3):
        rc3 = _handle_tools_subcommand(
            argparse.Namespace(tools_action="status", dir=str(tmp_path), as_json=False)
        )
    assert rc3 == 3
    assert "preflight BLOCKED" in out3.getvalue()

    # Exit code 4 on broken lock
    lock_path(tmp_path).write_text("[node]\nversion = '1.0'\n", encoding="utf-8")
    err4 = io.StringIO()
    with redirect_stderr(err4):
        rc4 = _handle_tools_subcommand(
            argparse.Namespace(tools_action="status", dir=str(tmp_path), as_json=False)
        )
    assert rc4 == 4


def test_seed_lock_refuses_to_follow_symlink_and_records_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside.lock"
    outside.write_text(
        '[lock]\nschema = 1\n\n[human-tool]\nversion = "9.9.9"\nchosen = "2026-01-01"\n'
        'reason = "Do not read or overwrite via symlink."\nprobe = "command"\n'
        'argv = ["human-tool", "--version"]\nsource = "human"\n',
        encoding="utf-8",
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")
    target = lock_path(proj)
    target.symlink_to(outside)

    monkeypatch.setattr(toolchk, "probe", _fake_probe({"node": "22.2.0"}))
    summary = seed_lock(proj, event="adoption", today=TODAY)

    assert not target.is_symlink()
    assert target.is_file()
    assert summary["added"] == ["node"]
    assert summary["kept"] == []
    assert any("symlink" in n.lower() for n in summary.get("notes", []))

    # Outside file was neither read nor overwritten
    loaded_proj = load_lock(target)
    assert list(loaded_proj["tools"].keys()) == ["node"]
    loaded_outside = load_lock(outside)
    assert list(loaded_outside["tools"].keys()) == ["human-tool"]


def test_cli_tools_init_enforces_assert_safe_root_while_status_reads_anywhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / "fake_home"
    fake_hermes = fake_home / ".hermes"
    wt_dir = tmp_path / ".worktrees" / "wt"
    for d in (fake_home, fake_hermes, wt_dir):
        d.mkdir(parents=True, exist_ok=True)
        (d / "package.json").write_text('{"name": "unsafe"}\n', encoding="utf-8")

    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("HERMES_HOME", str(fake_hermes))
    monkeypatch.setattr(toolchk, "probe", _fake_probe({"node": "22.0.0"}))

    for unsafe_root in (Path("/"), fake_home, fake_hermes):
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            rc = cli_main(["tools", "init", str(unsafe_root)])
        assert rc == 1
        assert not (unsafe_root / "TOOLS.lock").exists()

    # A .worktrees directory name alone does not make an output root unsafe.
    assert cli_main(["tools", "init", str(wt_dir)]) == 0
    assert (wt_dir / "TOOLS.lock").is_file()

    # tools status may read anywhere (e.g. inside fake_home)
    dump_lock(
        fake_home / "TOOLS.lock",
        {
            "lock": dict(toolchk.DEFAULT_HEADER),
            "tools": {
                "node": {
                    "version": "22.0.0",
                    "chosen": TODAY,
                    "reason": "manual status check",
                    "probe": "command",
                    "argv": ["node", "--version"],
                    "source": "human",
                }
            },
        },
    )
    out_buf = io.StringIO()
    with redirect_stdout(out_buf):
        rc_status = cli_main(["tools", "status", str(fake_home)])
    assert rc_status == 0
    assert "preflight ok" in out_buf.getvalue()


def test_cli_tools_help_documents_exit_codes() -> None:
    for argv in (["tools", "--help"], ["tools", "status", "--help"]):
        out = io.StringIO()
        with redirect_stdout(out):
            with pytest.raises(SystemExit) as exc_info:
                cli_main(argv)
        assert exc_info.value.code == 0
        help_text = out.getvalue()
        assert "Exit codes:" in help_text
        for code_str in ("0", "2", "3", "4"):
            assert f"  {code_str}  " in help_text


def test_accept_installed_set_reason_snooze_table_and_tools_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".adopt").mkdir()
    (proj / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")
    (proj / "cua-adv.json").write_text('{"latest_version": "0.38.0"}\n', encoding="utf-8")

    monkeypatch.setattr(
        toolchk,
        "probe",
        _fake_probe({"node": "20.11.0", "cua-driver": "0.21.0"}),
    )

    seed_lock(
        proj,
        event="adoption",
        template_needs=("cua-driver",),
        today="2025-05-01",
    )

    # Seed logged initial auto entries because .adopt/ exists
    log1 = load_tools_log(proj)
    assert len(log1) == 2
    assert {e["tool"] for e in log1} == {"cua-driver", "node"}
    assert all(e["who"] == "auto" and e["before"] is None for e in log1)

    # Attach advisory to cua-driver and an agent entry to test set_reason source preservation
    loaded = load_lock(lock_path(proj))
    loaded["tools"]["cua-driver"]["advisory"] = {
        "kind": "json",
        "path": "cua-adv.json",
        "key": "latest_version",
    }
    loaded["tools"]["agent-tool"] = {
        "version": "1.0.0",
        "chosen": TODAY,
        "reason": "Initial agent reason.",
        "probe": "command",
        "argv": ["agent-tool", "--version"],
        "source": "agent",
    }
    dump_lock(lock_path(proj), loaded)

    # Now simulate node drifting to 22.4.0 while cua-driver stays 0.21.0
    monkeypatch.setattr(
        toolchk,
        "probe",
        _fake_probe({"node": "22.4.0", "cua-driver": "0.21.0", "agent-tool": "1.0.0"}),
    )

    # Reject empty/whitespace reason on accept_installed
    with pytest.raises(ValueError, match="reason"):
        accept_installed(proj, "node", "   ", today=TODAY)

    # Accept installed version for node
    db_file = tmp_path / "state.db"
    acc_row = accept_installed(
        proj,
        "node",
        "Upgraded to LTS 22.4.0 after verifying all tests pass.",
        today=TODAY,
        db_path=db_file,
    )
    assert acc_row["tool"] == "node"
    assert acc_row["chosen"] == "22.4.0"
    assert acc_row["installed"] == "22.4.0"
    assert acc_row["chosen_on"] == TODAY
    assert acc_row["by"] == "human"
    assert acc_row["status"] == "ok"
    assert acc_row["nudge"] is False
    assert acc_row["reason"] == "Upgraded to LTS 22.4.0 after verifying all tests pass."

    # set_reason on 'auto' entry promotes source to 'human'
    r_cua = set_reason(
        proj,
        "cua-driver",
        "Confirmed 0.21.0 is our benchmark baseline.",
        db_path=db_file,
    )
    assert r_cua["by"] == "human"
    assert r_cua["reason"] == "Confirmed 0.21.0 is our benchmark baseline."

    # set_reason on 'agent' entry preserves source == 'agent'
    r_agent = set_reason(
        proj,
        "agent-tool",
        "Updated agent note.",
        db_path=db_file,
    )
    assert r_agent["by"] == "agent"
    assert r_agent["reason"] == "Updated agent note."

    # Verify tools-log.json appended all three edits with before/after/who/reason
    log_all = load_tools_log(proj)
    assert len(log_all) == 5
    accept_entry = log_all[2]
    assert accept_entry["who"] == "human"
    assert accept_entry["tool"] == "node"
    assert accept_entry["before"]["version"] == "20.11.0"
    assert accept_entry["after"]["version"] == "22.4.0"
    assert accept_entry["after"]["source"] == "human"
    assert accept_entry["reason"] == "Upgraded to LTS 22.4.0 after verifying all tests pass."

    reason_auto_entry = log_all[3]
    assert reason_auto_entry["who"] == "human"
    assert reason_auto_entry["tool"] == "cua-driver"
    assert reason_auto_entry["before"]["source"] == "auto"
    assert reason_auto_entry["after"]["source"] == "human"

    reason_agent_entry = log_all[4]
    assert reason_agent_entry["who"] == "agent"
    assert reason_agent_entry["tool"] == "agent-tool"
    assert reason_agent_entry["before"]["source"] == "agent"
    assert reason_agent_entry["after"]["source"] == "agent"

    # Snooze upstream note for cua-driver in state.db (never in TOOLS.lock)
    lock_bytes_before_snooze = lock_path(proj).read_bytes()
    snz = snooze(proj, "cua-driver", 30, db_path=db_file, today="2026-11-06")
    assert snz == {"tool": "cua-driver", "snoozed_until": "2026-12-06", "days": 30}
    assert lock_path(proj).read_bytes() == lock_bytes_before_snooze
    assert snoozed(proj, db_path=db_file, today="2026-11-06") == {"cua-driver": "2026-12-06"}

    # Check table() output shape, nudge calculation, and snoozed_until
    rows = table(proj, db_path=db_file)
    by_tool = {r["tool"]: r for r in rows}
    assert set(by_tool.keys()) == {"agent-tool", "cua-driver", "node"}
    cua_row = by_tool["cua-driver"]
    assert cua_row["chosen"] == "0.21.0"
    assert cua_row["installed"] == "0.21.0"
    assert cua_row["upstream_latest"] == "0.38.0"
    assert cua_row["chosen_on"] == "2025-05-01"
    assert cua_row["age_months"] >= 12
    assert cua_row["nudge"] is True
    assert cua_row["snoozed_until"] == "2026-12-06"
    assert tools_log_path(proj).is_file()


def test_cli_tools_accept_reason_and_snooze(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / "home"
    fake_hermes = fake_home / ".hermes"
    fake_hermes.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("HERMES_HOME", str(fake_hermes))

    proj = tmp_path / "cli_proj"
    proj.mkdir()
    (proj / "package.json").write_text('{"name": "cli-proj"}\n', encoding="utf-8")
    monkeypatch.setattr(toolchk, "probe", _fake_probe({"node": "20.0.0"}))
    seed_lock(proj, event="adoption", today=TODAY)

    # Drift node to 22.1.0 and accept via CLI
    monkeypatch.setattr(toolchk, "probe", _fake_probe({"node": "22.1.0"}))
    out_acc = io.StringIO()
    with redirect_stdout(out_acc):
        rc_acc = cli_main(
            ["tools", "accept", "node", "--reason", "CLI accept test", str(proj)]
        )
    assert rc_acc == 0
    acc_data = json.loads(out_acc.getvalue())
    assert acc_data["chosen"] == "22.1.0"
    assert acc_data["by"] == "human"
    assert acc_data["reason"] == "CLI accept test"

    # Update reason via CLI
    out_rsn = io.StringIO()
    with redirect_stdout(out_rsn):
        rc_rsn = cli_main(
            ["tools", "reason", "node", "--reason", "Updated CLI reason", str(proj)]
        )
    assert rc_rsn == 0
    rsn_data = json.loads(out_rsn.getvalue())
    assert rsn_data["reason"] == "Updated CLI reason"

    # Snooze via CLI
    out_snz = io.StringIO()
    with redirect_stdout(out_snz):
        rc_snz = cli_main(
            ["tools", "snooze", "node", "--days", "14", str(proj)]
        )
    assert rc_snz == 0
    snz_data = json.loads(out_snz.getvalue())
    assert snz_data["tool"] == "node"
    assert snz_data["days"] == 14
    assert snz_data["snoozed_until"] is not None

    # Verify tools-log.json has both lock writes (accept + reason)
    logs = load_tools_log(proj)
    assert len(logs) == 2
    assert [e["reason"] for e in logs] == ["CLI accept test", "Updated CLI reason"]

    # Refuse unsafe root for accept/reason/snooze
    for action_args in (
        ["tools", "accept", "node", "--reason", "x", str(fake_home)],
        ["tools", "reason", "node", "--reason", "x", str(fake_home)],
        ["tools", "snooze", "node", "--days", "10", str(fake_home)],
    ):
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            rc_unsafe = cli_main(action_args)
        assert rc_unsafe == 1



def test_snooze_refuses_days_beyond_limit_with_value_error(tmp_path: Path) -> None:
    """Huge day counts raise ValueError (never OverflowError) and leave state unchanged."""
    proj = tmp_path / "proj"
    proj.mkdir()
    db_file = tmp_path / "state.db"
    assert tool_seed.MAX_SNOOZE_DAYS == 3650
    for bad in (tool_seed.MAX_SNOOZE_DAYS + 1, 10**9, 10**30, 10**400):
        with pytest.raises(ValueError):
            snooze(proj, "node", bad, db_path=db_file, today=TODAY)
    assert snoozed(proj, db_path=db_file, today=TODAY) == {}
    res = snooze(proj, "node", tool_seed.MAX_SNOOZE_DAYS, db_path=db_file, today=TODAY)
    assert res["snoozed_until"] == "2036-11-03"


def test_snooze_past_last_supported_date_is_value_error(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    with pytest.raises(ValueError):
        snooze(proj, "node", 30, db_path=tmp_path / "state.db", today="9999-12-30")
