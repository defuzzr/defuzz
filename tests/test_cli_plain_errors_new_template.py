"""Clean-machine errors: the documented headless `new --template <id> --name <Name>` never waits."""

from __future__ import annotations

import json
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli as cli_mod  # noqa: E402
from hermes_plugins.defuzz.cli import main as cli_main  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "templates"


# --- [H2] documented headless `new --template <id> --name <Name>` ---------------------------


def test_new_explicit_template_needs_no_answers(tmp_path, monkeypatch, capsys):
    projects = tmp_path / "projects"
    projects.mkdir()
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(projects))
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    rc = cli_main(["new", "--template", "fake-rust-game", "--name", "Sample Svc",
                   "--templates-root", str(FIXTURES), "--timeout", "5"])
    out, err = capsys.readouterr()
    assert rc == 0, err
    assert "timed out" not in err
    assert f"Proposed repository: sample-svc -> {projects / 'sample-svc'}" in out


def test_new_explicit_template_answers_still_override(tmp_path, monkeypatch, capsys):
    projects = tmp_path / "projects"
    projects.mkdir()
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(projects))
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    seen = {}
    real_propose = cli_mod.propose

    def spy(spec, name, answers, **kw):
        seen.update(answers)
        return real_propose(spec, name, answers, **kw)

    monkeypatch.setattr(cli_mod, "propose", spy)
    rc = cli_main(["new", "--template", "fake-rust-game", "--name", "Sample Svc",
                   "--answers", json.dumps({"engine": "godot"}), "--templates-root", str(FIXTURES)])
    assert rc == 0, capsys.readouterr().err
    assert seen["building"] == "game" and seen["layout"] == "mono" and seen["languages"] == ["rust"]
    assert seen["engine"] == "godot"
