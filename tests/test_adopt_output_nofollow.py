"""Adopt output files (inventory, rules) are written without following links.

A link at the output path, or in one of its parent folders, must never make
``scan --out`` / ``run --inventory`` / ``rules --out`` write to the link target,
and an output whose real location is inside the source or the scanned copy is
refused.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Dict, Tuple

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli  # noqa: E402

try:
    from hermes_plugins.defuzz import output_file  # noqa: E402
except ImportError:  # before the helper exists the helper tests fail, the rest still run
    output_file = None  # type: ignore[assignment]
from hermes_plugins.defuzz.safety import SafetyError, copy_tree_nofollow  # noqa: E402
from hermes_plugins.defuzz.scanner import scan_folder  # noqa: E402

VICTIM_BYTES = b"precious user data\n"
README_BYTES = b"# source readme\n"


def _snapshot(root: Path) -> Dict[str, Tuple[str, str]]:
    """Map every entry under root to (kind, content-hash or link target), never following links."""
    out: Dict[str, Tuple[str, str]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(full))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", "")
            else:
                out[rel] = ("file", hashlib.sha256(Path(full).read_bytes()).hexdigest())
    return out


@pytest.fixture()
def case(tmp_path: Path):
    src = tmp_path / "src"
    (src / "pkg").mkdir(parents=True)
    (src / "README.md").write_bytes(README_BYTES)
    (src / "notes.txt").write_bytes(b"notes\n")
    (src / "pkg" / "main.py").write_bytes(b"print('hi')\n")
    copy_dir = tmp_path / "copy"
    copy_tree_nofollow(src, copy_dir)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_bytes(VICTIM_BYTES)
    return {"tmp": tmp_path, "src": src, "copy": copy_dir, "outside": outside, "victim": victim}


def _plant(case, kind: str) -> Path:
    """Create the hostile layout ``kind`` under outside/ and return the output path to use."""
    out = case["outside"]
    if kind == "leaf_to_source_file":
        (out / "inv.json").symlink_to(case["src"] / "README.md")
        return out / "inv.json"
    if kind == "leaf_to_victim":
        (out / "inv.json").symlink_to(case["victim"])
        return out / "inv.json"
    if kind == "parent_to_source":
        (out / "link_src_dir").symlink_to(case["src"], target_is_directory=True)
        return out / "link_src_dir" / "injected.json"
    if kind == "grandparent_link":
        real = out / "real_dir"
        (real / "nested").mkdir(parents=True)
        (out / "gp").symlink_to(real, target_is_directory=True)
        return out / "gp" / "nested" / "inv.json"
    if kind == "dangling_leaf":
        (out / "inv.json").symlink_to(out / "does-not-exist.json")
        return out / "inv.json"
    if kind == "leaf_is_folder":
        (out / "inv.json").mkdir()
        return out / "inv.json"
    if kind == "parent_to_victim_dir":
        vdir = out / "victim_dir"
        vdir.mkdir()
        (vdir / "keep.txt").write_bytes(VICTIM_BYTES)
        (out / "via").symlink_to(vdir, target_is_directory=True)
        return out / "via" / "new" / "inv.json"
    raise AssertionError(kind)


HOSTILE = [
    "leaf_to_source_file",
    "leaf_to_victim",
    "parent_to_source",
    "grandparent_link",
    "dangling_leaf",
    "leaf_is_folder",
    "parent_to_victim_dir",
]


def _no_temp_leftovers(root: Path) -> None:
    leftovers = [p for p in root.rglob("*") if p.name.startswith(".defuzz-out-")]
    assert not leftovers, leftovers


# ---------------------------------------------------------------- helper unit tests


@pytest.mark.parametrize("kind", HOSTILE)
def test_helper_refuses_hostile_output(case, kind):
    target = _plant(case, kind)
    before = _snapshot(case["tmp"])
    with pytest.raises(SafetyError) as exc:
        output_file.write_output_text(target, "{}\n", role="inventory_out")
    msg = str(exc.value)
    assert "\n" not in msg and "inventory_out" in msg and "Refusing" in msg
    assert _snapshot(case["tmp"]) == before
    assert case["victim"].read_bytes() == VICTIM_BYTES
    assert (case["src"] / "README.md").read_bytes() == README_BYTES
    _no_temp_leftovers(case["tmp"])


@pytest.mark.parametrize("kind", ["leaf_to_source_file", "parent_to_source", "dangling_leaf"])
def test_helper_symlink_message_names_role_and_path(case, kind):
    target = _plant(case, kind)
    with pytest.raises(SafetyError, match="Refusing to traverse or overwrite symlink"):
        output_file.write_output_text(target, "{}\n", role="rules_out")


def test_helper_creates_nested_folders_and_writes(case):
    target = case["outside"] / "a" / "b" / "c" / "inv.json"
    output_file.write_output_text(target, "hello\n", role="inventory_out")
    assert target.read_bytes() == b"hello\n"
    _no_temp_leftovers(case["tmp"])


def test_helper_overwrites_regular_file_and_keeps_mode(case):
    target = case["outside"] / "inv.json"
    target.write_text("old\n", encoding="utf-8")
    os.chmod(target, 0o640)
    output_file.write_output_text(target, "new\n", role="inventory_out")
    assert target.read_text(encoding="utf-8") == "new\n"
    assert stat.S_IMODE(os.lstat(target).st_mode) == 0o640
    assert not os.path.islink(target)
    _no_temp_leftovers(case["tmp"])


def test_helper_new_file_mode_follows_umask(case):
    old = os.umask(0o027)
    try:
        target = case["outside"] / "fresh.json"
        output_file.write_output_text(target, "x\n", role="inventory_out")
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.lstat(target).st_mode) == 0o640


def test_helper_refuses_real_location_inside_forbidden_root(case, monkeypatch):
    # The ancestor link sits in the trusted part (the home folder), so only the
    # real-path comparison can catch it.
    home = case["tmp"] / "home_link"
    home.symlink_to(case["src"], target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    before = _snapshot(case["tmp"])
    with pytest.raises(SafetyError, match="real location"):
        output_file.write_output_text(home / "inv.json", "{}\n", role="inventory_out",
                                      forbidden_roots=(case["src"], None))
    assert _snapshot(case["tmp"]) == before


def test_helper_symlinked_home_works(case, monkeypatch):
    real_home = case["tmp"] / "real_home"
    real_home.mkdir()
    home = case["tmp"] / "home_link"
    home.symlink_to(real_home, target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    target = home / "work" / "inv.json"
    output_file.write_output_text(target, "ok\n", role="inventory_out",
                                  forbidden_roots=(case["src"], case["copy"]))
    assert (real_home / "work" / "inv.json").read_bytes() == b"ok\n"


def test_helper_cleans_temp_on_failure(case, monkeypatch):
    target = case["outside"] / "inv.json"

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(output_file.os, "replace", boom)
    with pytest.raises(SafetyError, match="disk full"):
        output_file.write_output_text(target, "x\n", role="inventory_out")
    assert not target.exists()
    _no_temp_leftovers(case["tmp"])


# ---------------------------------------------------------------- chosen folder (base)


def _linked_copy(case):
    """A copy folder reached through a link the person made: tmp/drive -> tmp/disk."""
    disk = case["tmp"] / "disk"
    disk.mkdir()
    (case["tmp"] / "drive").symlink_to(disk, target_is_directory=True)
    copy_root = case["tmp"] / "drive" / "adopted"
    copy_root.mkdir()
    return disk, copy_root


def test_helper_base_reached_through_link_writes(case):
    disk, copy_root = _linked_copy(case)
    target = copy_root / ".adopt" / "adopt-complete.json"
    output_file.write_output_text(target, "ok\n", role="copy marker", forbidden_roots=(case["src"],), base=copy_root)
    assert (disk / "adopted" / ".adopt" / "adopt-complete.json").read_bytes() == b"ok\n"
    _no_temp_leftovers(case["tmp"])


def test_helper_without_base_still_refuses_that_link(case):
    _disk, copy_root = _linked_copy(case)
    with pytest.raises(SafetyError, match="symlink"):
        output_file.write_output_text(copy_root / ".adopt" / "m.json", "x\n", role="copy marker")


@pytest.mark.parametrize("where", ["folder", "leaf", "deeper"])
def test_helper_link_below_base_refused(case, where):
    _disk, copy_root = _linked_copy(case)
    if where == "folder":
        (copy_root / ".adopt").symlink_to(case["outside"], target_is_directory=True)
        target = copy_root / ".adopt" / "victim.txt"
    elif where == "leaf":
        (copy_root / ".adopt").mkdir()
        (copy_root / ".adopt" / "m.json").symlink_to(case["victim"])
        target = copy_root / ".adopt" / "m.json"
    else:
        (copy_root / "a").mkdir()
        (copy_root / "a" / "b").symlink_to(case["outside"], target_is_directory=True)
        target = copy_root / "a" / "b" / "new" / "m.json"
    before = _snapshot(case["outside"])
    with pytest.raises(SafetyError, match="symlink"):
        output_file.write_output_text(target, "x\n", role="copy marker", base=copy_root)
    assert _snapshot(case["outside"]) == before
    assert case["victim"].read_bytes() == VICTIM_BYTES
    _no_temp_leftovers(case["tmp"])


def test_helper_base_that_is_a_link_refused(case):
    (case["tmp"] / "copy_link").symlink_to(case["outside"], target_is_directory=True)
    with pytest.raises(SafetyError, match="symlink"):
        output_file.write_output_text(case["tmp"] / "copy_link" / "m.json", "x\n", role="copy marker",
                                      base=case["tmp"] / "copy_link")
    assert sorted(p.name for p in case["outside"].iterdir()) == ["victim.txt"]


def test_helper_path_outside_base_refused(case):
    _disk, copy_root = _linked_copy(case)
    with pytest.raises(SafetyError, match="outside the chosen folder"):
        output_file.write_output_text(case["outside"] / "m.json", "x\n", role="copy marker", base=copy_root)
    assert not (case["outside"] / "m.json").exists()


def test_helper_base_real_location_inside_forbidden_refused(case):
    (case["tmp"] / "src_link").symlink_to(case["src"], target_is_directory=True)
    copy_root = case["tmp"] / "src_link" / "pkg"
    before = _snapshot(case["src"])
    with pytest.raises(SafetyError, match="real location"):
        output_file.write_output_text(copy_root / ".adopt" / "m.json", "x\n", role="copy marker",
                                      forbidden_roots=(case["src"],), base=copy_root)
    assert _snapshot(case["src"]) == before


def test_helper_base_repointed_into_source_after_check_refused(case, monkeypatch):
    """The real location is checked again on the folder actually pinned, not only before."""
    disk = case["tmp"] / "disk"
    (disk / "pkg").mkdir(parents=True)
    drive = case["tmp"] / "drive"
    drive.symlink_to(disk, target_is_directory=True)
    copy_root = drive / "pkg"
    real_check = output_file.assert_output_path_safe

    def check_then_repoint(*a, **k):
        out = real_check(*a, **k)
        drive.unlink()
        drive.symlink_to(case["src"], target_is_directory=True)
        return out

    monkeypatch.setattr(output_file, "assert_output_path_safe", check_then_repoint)
    before = _snapshot(case["src"])
    with pytest.raises(SafetyError, match="real location"):
        output_file.write_output_text(copy_root / ".adopt" / "m.json", "x\n", role="copy marker",
                                      forbidden_roots=(case["src"],), base=copy_root)
    assert _snapshot(case["src"]) == before


@pytest.mark.parametrize("with_base", [False, True])
def test_helper_leaf_link_planted_after_check_refused(case, monkeypatch, with_base):
    """A link that appears at the output name after the first check is refused, not replaced."""
    target = case["outside"] / "late.json"
    real_check = output_file.assert_output_path_safe

    def check_then_plant(*a, **k):
        out = real_check(*a, **k)
        target.symlink_to(case["victim"])
        return out

    monkeypatch.setattr(output_file, "assert_output_path_safe", check_then_plant)
    with pytest.raises(SafetyError, match="symlink"):
        output_file.write_output_text(target, "x\n", role="copy marker",
                                      base=case["outside"] if with_base else None)
    assert os.path.islink(target)
    assert case["victim"].read_bytes() == VICTIM_BYTES
    _no_temp_leftovers(case["tmp"])


def test_helper_base_overwrite_keeps_mode(case):
    _disk, copy_root = _linked_copy(case)
    (copy_root / ".adopt").mkdir()
    target = copy_root / ".adopt" / "m.json"
    target.write_text("old\n", encoding="utf-8")
    os.chmod(target, 0o600)
    output_file.write_output_text(target, "new\n", role="copy marker", base=copy_root)
    assert target.read_text(encoding="utf-8") == "new\n"
    assert stat.S_IMODE(os.lstat(target).st_mode) == 0o600


def test_helper_base_identity_checked(case, monkeypatch):
    """The chosen folder is opened through its real path and must be the folder that was resolved."""
    _disk, copy_root = _linked_copy(case)
    real_stat = os.stat
    other = real_stat(case["outside"])

    def lying_stat(path, *a, **k):
        if not a and not k and os.fspath(path) == os.path.realpath(copy_root):
            return other
        return real_stat(path, *a, **k)

    monkeypatch.setattr(os, "stat", lying_stat)
    with pytest.raises(SafetyError, match="changed"):
        output_file.write_output_text(copy_root / "m.json", "x\n", role="copy marker", base=copy_root)
    assert not (copy_root / "m.json").exists()


def test_helper_trusted_prefix_identity_checked(case, monkeypatch):
    """Without a chosen folder the trusted home/temporary prefix is opened by identity too."""
    real_stat = os.stat
    other = real_stat(case["outside"])
    target = case["outside"] / "m.json"
    prefix, _rest = output_file._split_trusted(target.parent)

    def lying_stat(path, *a, **k):
        if not a and not k and os.fspath(path) == os.path.realpath(prefix):
            return other
        return real_stat(path, *a, **k)

    monkeypatch.setattr(os, "stat", lying_stat)
    with pytest.raises(SafetyError, match="changed"):
        output_file.write_output_text(target, "x\n", role="inventory_out")
    assert not target.exists()


def test_marker_parent_swapped_mid_run_is_refused(case):
    """The copy folder is pinned when the run starts: when a parent is swapped for a link
    meanwhile, the chosen path no longer names that folder, so the completion marker is
    refused: not written into the moved-away original, nor anywhere else."""
    proj = case["tmp"] / "proj"
    copy_root = proj / "adopted"
    copy_root.mkdir(parents=True)
    decoy = case["outside"] / "decoy"
    (decoy / "adopted").mkdir(parents=True)
    before = _snapshot(case["outside"])
    held = case["tmp"] / "proj.held"
    with pytest.raises(SafetyError, match="moved after it was opened"):
        with output_file.adopt_copy_guard(copy_root, case["src"]):
            os.rename(proj, held)
            proj.symlink_to(decoy, target_is_directory=True)
    assert not (held / "adopted" / ".adopt").exists()
    assert _snapshot(case["outside"]) == before


# ---------------------------------------------------------------- scan_folder


@pytest.mark.parametrize("kind", HOSTILE)
def test_scan_folder_refuses_hostile_out(case, kind):
    target = _plant(case, kind)
    before = _snapshot(case["tmp"])
    with pytest.raises(SafetyError) as exc:
        scan_folder(case["copy"], source_root=case["src"], out_path=target)
    assert "\n" not in str(exc.value)
    assert _snapshot(case["tmp"]) == before
    assert case["victim"].read_bytes() == VICTIM_BYTES
    _no_temp_leftovers(case["tmp"])


def test_scan_folder_refuses_real_path_inside_source(case, monkeypatch):
    # HOME is a link to the case folder, so HOME/src is the source by real path only.
    home = case["tmp"] / "home_link"
    home.symlink_to(case["tmp"], target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    before = _snapshot(case["tmp"])
    with pytest.raises(SafetyError, match="real location"):
        scan_folder(case["copy"], source_root=case["src"], out_path=home / "src" / "inv.json")
    assert _snapshot(case["tmp"]) == before


def test_scan_folder_refuses_real_path_inside_copy(case, monkeypatch):
    home = case["tmp"] / "home_link"
    home.symlink_to(case["tmp"], target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    before = _snapshot(case["tmp"])
    with pytest.raises(SafetyError, match="real location"):
        scan_folder(case["copy"], out_path=home / "copy" / "pkg" / "inv.json")
    assert _snapshot(case["tmp"]) == before


def test_scan_folder_lexical_source_message_unchanged(case):
    with pytest.raises(SafetyError, match=r"Refusing to write inventory inside source folder"):
        scan_folder(case["copy"], source_root=case["src"], out_path=case["src"] / "inv.json")


def test_scan_folder_fresh_nested_output_is_byte_identical(case):
    target = case["outside"] / "new" / "deeper" / "inventory.json"
    inv = scan_folder(case["copy"], source_root=case["src"], out_path=target)
    data = target.read_bytes()
    loaded = json.loads(data)
    expected = dict(inv)
    # scan_duration_ms is the only field that differs between runs; compare the serialisation itself.
    assert data == (json.dumps(loaded, indent=2, sort_keys=False) + "\n").encode("utf-8")
    assert set(loaded) == set(expected) and loaded["files"] == inv["files"]
    _no_temp_leftovers(case["tmp"])


def test_scan_folder_overwrites_existing_regular_file(case):
    target = case["outside"] / "inventory.json"
    target.write_text("stale\n", encoding="utf-8")
    scan_folder(case["copy"], source_root=case["src"], out_path=target)
    first = json.loads(target.read_text(encoding="utf-8"))
    scan_folder(case["copy"], source_root=case["src"], out_path=target)
    second = json.loads(target.read_text(encoding="utf-8"))
    assert first["files"] == second["files"]
    assert not os.path.islink(target)


def test_scan_folder_with_symlinked_home(case, monkeypatch):
    real_home = case["tmp"] / "real_home"
    real_home.mkdir()
    home = case["tmp"] / "home_link"
    home.symlink_to(real_home, target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))
    target = home / "adopt" / "inventory.json"
    scan_folder(case["copy"], source_root=case["src"], out_path=target)
    assert json.loads((real_home / "adopt" / "inventory.json").read_text(encoding="utf-8"))["schema"] == 1


# ---------------------------------------------------------------- CLI


def _cli_refused(capsys, argv) -> str:
    rc = cli.main(argv)
    captured = capsys.readouterr()
    assert rc != 0, captured.out
    err = captured.err.strip()
    assert "Traceback" not in captured.err and "Traceback" not in captured.out
    assert len(err.splitlines()) == 1, err
    return json.loads(err)["error"]


@pytest.mark.parametrize("kind", HOSTILE)
def test_cli_scan_out_refuses_hostile(case, kind, capsys):
    target = _plant(case, kind)
    before = _snapshot(case["tmp"])
    msg = _cli_refused(capsys, ["scan", str(case["copy"]), "--source", str(case["src"]),
                                "--out", str(target)])
    assert msg.startswith("Refusing")
    assert _snapshot(case["tmp"]) == before
    _no_temp_leftovers(case["tmp"])


@pytest.mark.parametrize("kind", ["leaf_to_source_file", "parent_to_source", "leaf_to_victim"])
def test_cli_run_inventory_refuses_hostile(case, kind, capsys):
    target = _plant(case, kind)
    copy_dir = case["tmp"] / "copy2"
    src_before = _snapshot(case["src"])
    outside_before = _snapshot(case["outside"])
    msg = _cli_refused(capsys, ["run", str(copy_dir), "--source", str(case["src"]),
                                "--deterministic", "--inventory", str(target)])
    assert msg.startswith("Refusing")
    assert _snapshot(case["src"]) == src_before
    assert _snapshot(case["outside"]) == outside_before
    assert case["victim"].read_bytes() == VICTIM_BYTES


def test_cli_scan_out_overwrite_and_rerun(case, capsys):
    target = case["outside"] / "inventory.json"
    for _ in range(2):
        assert cli.main(["scan", str(case["copy"]), "--out", str(target)]) == 0
        capsys.readouterr()
    assert json.loads(target.read_text(encoding="utf-8"))["schema"] == 1


def test_tool_handler_scan_refuses_inventory_link_into_source(case):
    from hermes_plugins.defuzz import _handle_defuzz_project_tool

    target = _plant(case, "leaf_to_source_file")
    before = _snapshot(case["tmp"])
    res = json.loads(_handle_defuzz_project_tool({
        "action": "scan", "copy_path": str(case["copy"]), "source_path": str(case["src"]),
        "inventory_path": str(target),
    }))
    assert res["ok"] is False and res["error"].startswith("Refusing to traverse or overwrite symlink")
    assert _snapshot(case["tmp"]) == before


# ---------------------------------------------------------------- rules (cli.py follow-up)


@pytest.mark.parametrize("kind", ["leaf_to_source_file", "leaf_to_victim", "parent_to_source",
                                  "dangling_leaf"])
def test_write_rules_file_refuses_hostile(case, kind):
    target = _plant(case, kind)
    before = _snapshot(case["tmp"])
    with pytest.raises(SafetyError):
        cli._write_rules_file(str(target), {"schema": 1})
    assert _snapshot(case["tmp"]) == before


def test_cli_rules_out_refuses_leaf_link_into_source(case, capsys):
    target = _plant(case, "leaf_to_source_file")
    before = _snapshot(case["tmp"])
    msg = _cli_refused(capsys, ["rules", str(case["copy"]), "--deterministic", "--out", str(target)])
    assert msg.startswith("Refusing")
    assert _snapshot(case["tmp"]) == before


def test_write_rules_file_plain_output_still_works(case):
    target = case["outside"] / "r" / "rules.json"
    assert cli._write_rules_file(str(target), {"schema": 1}) == str(target)
    assert target.read_text(encoding="utf-8") == json.dumps({"schema": 1}, indent=2) + "\n"
