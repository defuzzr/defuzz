"""`run --source` never adopts an empty or half-copied destination.

A copy is trusted again only when an earlier `run` finished and left its
completion marker; anything else is refused with one plain line, the folder is
left exactly as it was, and a refused apply says the copy is incomplete.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path
from typing import Dict, Tuple

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli  # noqa: E402

MARKER = (".adopt", "adopt-complete.json")

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="adopting needs git")


def _snapshot(root: Path) -> Dict[str, Tuple[int, int, str]]:
    snap: Dict[str, Tuple[int, int, str]] = {}
    if not os.path.lexists(root):
        return snap
    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            body = ""
            if stat.S_ISLNK(st.st_mode):
                body = "->" + os.readlink(full)
            elif stat.S_ISREG(st.st_mode):
                body = Path(full).read_bytes().hex()
            snap[os.path.relpath(full, str(root))] = (st.st_mode, st.st_size, body)
    return snap


@pytest.fixture
def case(tmp_path: Path) -> Dict[str, Path]:
    src = tmp_path / "src"
    (src / "src").mkdir(parents=True)
    (src / "README.md").write_text("# demo\n", encoding="utf-8")
    (src / "src" / "main.py").write_text("print('hi')\n", encoding="utf-8")
    for i in range(5):
        (src / f"note_{i}.md").write_text(f"note {i}\n", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    return {"tmp": tmp_path, "src": src, "copy": tmp_path / "copy", "staging": staging}


def _run(case: Dict[str, Path], *extra: str, source: bool = True) -> list:
    argv = ["run", str(case["copy"])]
    if source:
        argv += ["--source", str(case["src"])]
    return argv + ["--staging", str(case["staging"]), "--deterministic", *extra]


def _refused(capsys, argv) -> str:
    rc = cli.main(argv)
    captured = capsys.readouterr()
    assert rc != 0, captured.out
    assert "Traceback" not in captured.err + captured.out
    err = captured.err.strip()
    assert len(err.splitlines()) == 1, err
    return json.loads(err)["error"]


def _ok(capsys, argv) -> dict:
    rc = cli.main(argv)
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    return json.loads(captured.out)


def _assert_partial_refusal(msg: str, copy_dir: Path) -> None:
    assert str(copy_dir) in msg
    assert "incomplete" in msg
    assert "delete it and run again" in msg
    assert "Traceback" not in msg


def test_empty_existing_destination_is_refused_and_left_alone(case, capsys):
    case["copy"].mkdir()
    src_before = _snapshot(case["src"])
    msg = _refused(capsys, _run(case))
    _assert_partial_refusal(msg, case["copy"])
    assert list(case["copy"].iterdir()) == []
    assert _snapshot(case["src"]) == src_before
    assert not (case["staging"] / "inventory.json").exists()


def test_half_copied_destination_is_refused_and_left_alone(case, capsys):
    case["copy"].mkdir()
    shutil.copy2(case["src"] / "README.md", case["copy"] / "README.md")
    before = _snapshot(case["copy"])
    msg = _refused(capsys, _run(case))
    _assert_partial_refusal(msg, case["copy"])
    assert _snapshot(case["copy"]) == before


def test_destination_that_is_a_file_is_refused(case, capsys):
    case["copy"].write_text("not a folder\n", encoding="utf-8")
    msg = _refused(capsys, _run(case))
    assert str(case["copy"]) in msg
    assert case["copy"].read_text(encoding="utf-8") == "not a folder\n"


def test_run_killed_during_copy_is_refused_on_retry(case, capsys, monkeypatch):
    real_copy = cli.copy_tree_nofollow

    def killed_copy(source, dest, **kwargs):
        Path(dest).mkdir()
        shutil.copy2(Path(source) / "README.md", Path(dest) / "README.md")
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "copy_tree_nofollow", killed_copy)
    with pytest.raises(KeyboardInterrupt):
        cli.main(_run(case))
    monkeypatch.setattr(cli, "copy_tree_nofollow", real_copy)
    capsys.readouterr()
    before = _snapshot(case["copy"])
    msg = _refused(capsys, _run(case))
    _assert_partial_refusal(msg, case["copy"])
    assert _snapshot(case["copy"]) == before
    assert not (case["copy"] / "src" / "main.py").exists()


def test_run_killed_during_apply_is_refused_on_retry(case, capsys, monkeypatch):
    def killed_apply(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "apply_rules_to_copy", killed_apply)
    with pytest.raises(KeyboardInterrupt):
        cli.main(_run(case))
    monkeypatch.undo()
    capsys.readouterr()
    assert (case["copy"] / "src" / "main.py").is_file()
    msg = _refused(capsys, _run(case))
    _assert_partial_refusal(msg, case["copy"])


def test_finished_run_leaves_marker_and_rerun_with_source_succeeds(case, capsys):
    first = _ok(capsys, _run(case))
    assert first["ok"] is True
    marker = case["copy"].joinpath(*MARKER)
    assert marker.is_file() and not marker.is_symlink()
    assert (case["copy"] / "src" / "main.py").is_file()
    second = _ok(capsys, _run(case))
    assert second["ok"] is True
    assert marker.is_file()
    assert (case["copy"] / "src" / "main.py").is_file()


def test_rerun_without_source_on_adopted_copy_succeeds(case, capsys):
    _ok(capsys, _run(case))
    res = _ok(capsys, _run(case, source=False))
    assert res["ok"] is True


def test_marker_naming_another_source_is_not_trusted(case, capsys):
    _ok(capsys, _run(case))
    other = case["tmp"] / "other-src"
    other.mkdir()
    (other / "README.md").write_text("# other\n", encoding="utf-8")
    before = _snapshot(case["copy"])
    msg = _refused(capsys, ["run", str(case["copy"]), "--source", str(other), "--staging",
                            str(case["staging"]), "--deterministic"])
    assert str(case["copy"]) in msg
    assert "delete it and run again" in msg
    assert _snapshot(case["copy"]) == before


def test_marker_copied_from_an_adopted_source_does_not_vouch_for_a_partial_copy(case, capsys, monkeypatch):
    # The source is itself an adopted copy, so it carries a marker naming its own source.
    _ok(capsys, _run(case))
    second_copy = case["tmp"] / "copy-of-copy"
    second_copy.mkdir()
    (second_copy / ".adopt").mkdir()
    shutil.copy2(case["copy"].joinpath(*MARKER), second_copy.joinpath(*MARKER))
    before = _snapshot(second_copy)
    msg = _refused(capsys, ["run", str(second_copy), "--source", str(case["copy"]), "--staging",
                            str(case["staging"]), "--deterministic"])
    _assert_partial_refusal(msg, second_copy)
    assert _snapshot(second_copy) == before


def test_marker_that_is_a_symlink_is_not_trusted(case, capsys):
    _ok(capsys, _run(case))
    marker = case["copy"].joinpath(*MARKER)
    real = case["tmp"] / "outside-marker.json"
    real_bytes = marker.read_bytes()
    real.write_bytes(real_bytes)
    marker.unlink()
    marker.symlink_to(real)
    msg = _refused(capsys, _run(case))
    assert str(case["copy"]) in msg
    assert real.read_bytes() == real_bytes
    assert marker.is_symlink()


def test_refused_apply_says_the_copy_is_incomplete_and_retry_is_refused(case, capsys):
    # A symlinked .gitignore is copied as a link; apply then refuses to write through it.
    (case["src"] / ".gitignore").symlink_to("README.md")
    msg = _refused(capsys, _run(case))
    assert "symlink" in msg
    _assert_partial_refusal(msg, case["copy"])
    assert not case["copy"].joinpath(*MARKER).exists()
    retry = _refused(capsys, _run(case))
    _assert_partial_refusal(retry, case["copy"])


def test_refused_rerun_removes_the_old_marker(case, capsys, monkeypatch):
    _ok(capsys, _run(case))
    from hermes_plugins.defuzz.safety import SafetyError

    def refusing_apply(*args, **kwargs):
        raise SafetyError("Refusing for the test")

    monkeypatch.setattr(cli, "apply_rules_to_copy", refusing_apply)
    msg = _refused(capsys, _run(case))
    _assert_partial_refusal(msg, case["copy"])
    monkeypatch.undo()
    assert not case["copy"].joinpath(*MARKER).exists()
    _assert_partial_refusal(_refused(capsys, _run(case)), case["copy"])


def test_refusal_before_anything_is_copied_does_not_mention_a_copy(case, capsys):
    missing = case["tmp"] / "no-such-source"
    msg = _refused(capsys, ["run", str(case["copy"]), "--source", str(missing), "--staging",
                            str(case["staging"]), "--deterministic"])
    assert "incomplete" not in msg
    assert not os.path.lexists(case["copy"])


def test_in_place_refusal_never_tells_the_user_to_delete_their_folder(case, capsys, monkeypatch):
    from hermes_plugins.defuzz.safety import SafetyError

    def refusing_apply(*args, **kwargs):
        raise SafetyError("Refusing for the test")

    monkeypatch.setattr(cli, "apply_rules_to_copy", refusing_apply)
    shutil.copytree(case["src"], case["copy"])
    msg = _refused(capsys, _run(case, source=False))
    assert "Delete" not in msg
    assert msg == "Refusing for the test"
