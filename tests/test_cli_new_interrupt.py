"""Ctrl-C during `defuzz new --yes`: one plain line, then the conventional interrupted status."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest

from tests import ensure_test_package, load_submodule
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401

ensure_test_package()

FIXTURES = Path(__file__).parent / "fixtures" / "templates"
ANSWERS = '{"building":"service","layout":"mono","languages":["rust"]}'


def _interrupt(*_a: Any, **_k: Any) -> Any:
    raise KeyboardInterrupt


@pytest.fixture()
def cli(tmp_path, monkeypatch):
    import tools.registry as tools_registry

    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    monkeypatch.setattr(tools_registry.registry, "get_entry", lambda _: None)
    monkeypatch.setattr(tools_registry, "discover_builtin_tools", lambda: [])
    return load_submodule("cli")


def _new(cli, tmp_path, **kw):
    ns = Namespace(answers=ANSWERS, name="Cut Short", yes=True, templates_root=FIXTURES,
                   dest_root=tmp_path / "projects", template_id=None, kit_id=None)
    for key, value in kw.items():
        setattr(ns, key, value)
    return cli._handle_new_subcommand(ns)


def _lines(capsys) -> list[str]:
    out = capsys.readouterr()
    assert "Traceback" not in out.out + out.err
    return [line for line in (out.out + out.err).splitlines() if line.strip()]


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_template_interrupt_after_the_move_names_the_kept_folder(cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(load_submodule("scaffolder"), "record_project", _interrupt)
    status = _new(cli, tmp_path, template_id="fake-rust-game")
    dest = tmp_path / "projects" / "cut-short"
    assert status == 130
    assert dest.is_dir()
    lines = [line for line in _lines(capsys) if str(dest) in line]
    assert len(lines) == 1 and lines[0].startswith("Stopped. The project folder")
    assert "delete it if you do not want it" in lines[0]


def test_template_interrupt_before_the_move_says_stopped(cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(load_submodule("scaffolder"), "ensure_git_available", _interrupt)
    status = _new(cli, tmp_path, template_id="fake-rust-game")
    assert status == 130
    assert not (tmp_path / "projects" / "cut-short").exists()
    assert "Stopped before the project was finished." in _lines(capsys)


def test_kit_interrupt_after_the_move_names_the_kept_folder(cli, tmp_path, monkeypatch, capsys):
    from tests.fake_kit_bridge import FakeKitBridge

    FakeKitBridge().install(monkeypatch, load_submodule("componentize_bridge"))
    monkeypatch.setattr(load_submodule("kit_scaffold"), "record_project", _interrupt)
    status = _new(cli, tmp_path, kit_id="video-production", answers='{"building":"video"}')
    dest = tmp_path / "projects" / "cut-short"
    assert status == 130
    assert dest.is_dir()
    lines = [line for line in _lines(capsys) if str(dest) in line]
    assert len(lines) == 1 and lines[0].startswith("Stopped. The project folder"), lines
