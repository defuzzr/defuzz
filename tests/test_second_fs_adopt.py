"""Adopting a folder when the source, the copy, the outputs or the projects folder sit on another filesystem.

Every case runs the real entry points (``cli.main`` for copy/scan/rules/run/apply/place and
the placement hooks) once per layout:

- ``one-fs``: everything on the temporary folder's filesystem (the control cell);
- ``src1-copy2``: source on the temporary filesystem, copy and outputs on the second one;
- ``src2-copy1``: source on the second filesystem, copy and outputs on the temporary one;
- ``both2``: source, copy and outputs all on the second filesystem;
- ``report-other``: copy on the second filesystem, report/inventory/rules on the temporary one;
- ``projects-link``: ``~/Projects`` is a link to a folder on the second filesystem and the copy
  and the outputs are named through that link.

The tests are skipped unless ``DEFUZZ_SECOND_FS`` names a writable folder whose device differs
from the temporary folder's. Each test works in its own new sub-folder of that folder and
removes it afterwards; nothing else there is read or written.

Set ``DEFUZZ_XDEV_TIMINGS`` to a file path to append one JSON line per timed copy.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli  # noqa: E402
from hermes_plugins.defuzz.placer import on_pre_tool_call, on_transform_tool_result  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="adopting needs git")

LAYOUTS = ["one-fs", "src1-copy2", "src2-copy1", "both2", "report-other", "projects-link"]
TEMP_NAME_PREFIXES = (".defuzz-out-", ".defuzz-write-", ".adopt-link-tmp-")
MARKER = (".adopt", "adopt-complete.json")
_FIXTURE_PREFIX = "xdev-case-"


# ---------------------------------------------------------------- environment


def _second_fs_root() -> Path:
    raw = os.environ.get("DEFUZZ_SECOND_FS", "").strip()
    if not raw:
        pytest.skip("DEFUZZ_SECOND_FS is not set: no second filesystem to test against")
    root = Path(raw)
    if not root.is_dir() or not os.access(root, os.W_OK | os.X_OK):
        pytest.skip(f"DEFUZZ_SECOND_FS is not a writable folder: {root}")
    if os.stat(root).st_dev == os.stat(tempfile.gettempdir()).st_dev:
        pytest.skip(f"DEFUZZ_SECOND_FS is on the same filesystem as the temporary folder: {root}")
    return root


def _fs_type(path: Path) -> str:
    """Filesystem type of the mount holding path (from /proc/self/mountinfo), or 'unknown'."""
    real = os.path.realpath(path)
    best, kind = "", "unknown"
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return kind
    for line in lines:
        left, _, right = line.partition(" - ")
        fields = left.split()
        if len(fields) < 5 or not right:
            continue
        mount = fields[4].replace("\\040", " ")
        if (real == mount or real.startswith(mount.rstrip("/") + "/")) and len(mount) >= len(best):
            best, kind = mount, right.split()[0]
    return kind


def _chmod_writable(func, path, _exc):  # rmtree onerror: a folder we made read-only
    try:
        os.chmod(os.path.dirname(path), 0o700)
        func(path)
    except OSError:
        pass


@pytest.fixture()
def fs2(tmp_path: Path):
    """A new, empty folder of our own on the second filesystem; removed after the test."""
    root = _second_fs_root()
    case = root / f"{_FIXTURE_PREFIX}{secrets.token_hex(6)}"
    case.mkdir()
    try:
        yield case
    finally:
        # Only ever the folder made above: a direct child of DEFUZZ_SECOND_FS with our prefix.
        assert case.parent == root and case.name.startswith(_FIXTURE_PREFIX)
        for dirpath, dirnames, filenames in os.walk(case):
            for name in filenames:
                full = os.path.join(dirpath, name)
                if not os.path.islink(full):
                    try:
                        os.chmod(full, 0o600)
                    except OSError:
                        pass
        shutil.rmtree(case, onerror=_chmod_writable)


@pytest.fixture()
def fs1(tmp_path: Path) -> Path:
    path = tmp_path / "fs1"
    path.mkdir()
    return path


def _layout(kind: str, fs1: Path, fs2: Path, home: Path, monkeypatch) -> Dict[str, Path]:
    """Roles -> paths for one layout. 'out' is the folder for report/inventory/rules files."""
    on = {"1": fs1, "2": fs2}
    spec = {
        "one-fs": ("1", "1", "1"),
        "src1-copy2": ("1", "2", "2"),
        "src2-copy1": ("2", "1", "1"),
        "both2": ("2", "2", "2"),
        "report-other": ("1", "2", "1"),
    }
    if kind == "projects-link":
        disk = fs2 / "projects"
        disk.mkdir()
        projects = home / "Projects"
        projects.symlink_to(disk, target_is_directory=True)
        monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(projects))
        src = fs1 / "source"
        copy = projects / "adopted"
        out = projects / "_adopt-out"
        other = fs1
    else:
        s, c, o = spec[kind]
        src = on[s] / "source"
        copy = on[c] / "copy-parent" / "adopted"
        out = on[o] / "adopt-out"
        other = on["1" if c == "2" else "2"]
    return {"src": src, "copy": copy, "out": out, "other": other, "fs1": fs1, "fs2": fs2}


@pytest.fixture(params=LAYOUTS)
def lay(request, fs1: Path, fs2: Path, isolated_home: Path, monkeypatch) -> Dict[str, Any]:
    home = Path(os.environ["HOME"])
    paths = _layout(request.param, fs1, fs2, home, monkeypatch)
    _make_source(paths["src"])
    tmp_before = set(os.listdir(tempfile.gettempdir()))
    yield {"kind": request.param, **paths}
    _assert_no_leftovers(paths, home, tmp_before)


# ---------------------------------------------------------------- helpers


def _make_source(src: Path) -> None:
    (src / "src").mkdir(parents=True)
    (src / "docs").mkdir()
    (src / "README.md").write_text("# demo project\n", encoding="utf-8")
    (src / "src" / "main.py").write_text("print('hi')\n", encoding="utf-8")
    (src / "docs" / "guide.md").write_text("# guide\n", encoding="utf-8")
    for i in range(4):
        (src / f"note_{i}.md").write_text(f"note {i}\n", encoding="utf-8")
    (src / "data.csv").write_text("a,b\n1,2\n", encoding="utf-8")


def _snapshot(root: Path, *, skip: Tuple[str, ...] = ()) -> Dict[str, Tuple[str, str]]:
    out: Dict[str, Tuple[str, str]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir.split(os.sep)[0] in skip:
            dirnames[:] = []
            continue
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if rel.split(os.sep)[0] in skip:
                continue
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(full))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", "")
            elif stat.S_ISREG(st.st_mode):
                try:
                    out[rel] = ("file", Path(full).read_bytes().hex())
                except PermissionError:
                    out[rel] = ("file", "<unreadable>")
            else:
                out[rel] = ("other", stat.filemode(st.st_mode)[0])
    return out


def _assert_no_leftovers(paths: Dict[str, Path], home: Path, tmp_before: set) -> None:
    found: List[str] = []
    for root in (paths["fs1"], paths["fs2"], home):
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for name in dirnames + filenames:
                if name.startswith(TEMP_NAME_PREFIXES):
                    found.append(os.path.join(dirpath, name))
    assert not found, f"temporary files left behind: {found}"
    new_in_tmp = set(os.listdir(tempfile.gettempdir())) - tmp_before
    assert not new_in_tmp, f"left in the temporary folder: {sorted(new_in_tmp)}"


def _cli(capsys, argv: List[str]) -> Tuple[int, Optional[Dict[str, Any]], str]:
    rc = cli.main([str(a) for a in argv])
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    data = None
    if rc == 0:
        data = json.loads(captured.out)
    return rc, data, captured.err.strip()


def _ok(capsys, argv: List[str]) -> Dict[str, Any]:
    rc, data, err = _cli(capsys, argv)
    assert rc == 0, f"{argv[0]} failed: {err}"
    assert data is not None and data.get("ok") is True, data
    return data


def _git_commits(repo: Path) -> int:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--count", "HEAD"],
        capture_output=True, text=True, env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"}, check=False,
    )
    return int(proc.stdout.strip() or 0) if proc.returncode == 0 else 0


def _timing(test: str, lay: Dict[str, Any], seconds: float, **extra: Any) -> None:
    target = os.environ.get("DEFUZZ_XDEV_TIMINGS", "").strip()
    if not target:
        return
    row = {"test": test, "layout": lay["kind"], "fs2": _fs_type(lay["fs2"]), "seconds": round(seconds, 3), **extra}
    with open(target, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def _assert_adopted(copy: Path) -> None:
    assert (copy / ".adopt" / "report.json").is_file()
    assert (copy / ".git").is_dir()
    assert _git_commits(copy) >= 1


# ---------------------------------------------------------------- xfail table (release line)
#
# (test, layout) -> reason. Strict: when a fix lands the cell XPASSes and fails the run, so the
# mark must be removed together with the fix.

_OUTPUT_LINK = (
    "inventory/rules output below the linked ~/Projects is refused by output_file.write_output_text "
    "(only ancestors of HOME/TMPDIR are trusted: output_file._split_trusted)"
)

RELEASE_XFAIL: Dict[str, str] = {
    "test_scan_with_source[projects-link]": _OUTPUT_LINK,
    "test_run_with_output_files[projects-link]": _OUTPUT_LINK,
    "test_scan_rules_apply_output_files[projects-link]": _OUTPUT_LINK,
}


@pytest.fixture(autouse=True)
def _known_failures(request):
    reason = RELEASE_XFAIL.get(request.node.name)
    if reason:
        request.applymarker(pytest.mark.xfail(strict=True, reason=reason))
    yield


# ---------------------------------------------------------------- flows


def test_copy(lay, capsys):
    data = _ok(capsys, ["copy", lay["src"], lay["copy"]])
    assert Path(data["copy_root"]) == lay["copy"]
    assert _snapshot(lay["copy"]) == _snapshot(lay["src"])


def test_scan_with_source(lay, capsys):
    inv = lay["out"] / "scan" / "inventory.json"
    data = _ok(capsys, ["scan", lay["copy"], "--source", lay["src"], "--out", inv])
    assert data["total_regular_files"] == 8
    assert json.loads(inv.read_text(encoding="utf-8"))["files"]
    assert _snapshot(lay["copy"]) == _snapshot(lay["src"])


def test_run_with_output_files(lay, capsys):
    a = lay["out"] / "run"
    report = lay["out"] / "new-report-folder" / "report.json"
    data = _ok(capsys, [
        "run", lay["copy"], "--source", lay["src"], "--deterministic",
        "--inventory", a / "inventory.json", "--rules", a / "rules.json", "--report", report,
    ])
    assert data["report"]
    for f in (a / "inventory.json", a / "rules.json", report):
        assert json.loads(f.read_text(encoding="utf-8")), f
    _assert_adopted(lay["copy"])
    assert lay["copy"].joinpath(*MARKER).is_file()


def test_run_twice(lay, capsys):
    argv = ["run", lay["copy"], "--source", lay["src"], "--deterministic", "--report", lay["out"] / "r" / "report.json"]
    _ok(capsys, argv)
    _ok(capsys, argv)
    _assert_adopted(lay["copy"])
    assert lay["copy"].joinpath(*MARKER).is_file()


@pytest.mark.parametrize("report_folder", ["new", "existing"])
def test_apply_with_report(lay, capsys, report_folder):
    _ok(capsys, ["copy", lay["src"], lay["copy"]])
    folder = lay["out"] / f"{report_folder}-reports"
    keep = None
    if report_folder == "existing":
        folder.mkdir(parents=True)
        keep = folder / "keep.txt"
        keep.write_text("keep me\n", encoding="utf-8")
    report = folder / "report.json"
    data = _ok(capsys, ["apply", lay["copy"], "--source", lay["src"], "--report", report])
    assert data["report"]
    assert json.loads(report.read_text(encoding="utf-8"))
    if keep is not None:
        assert keep.read_text(encoding="utf-8") == "keep me\n"
    _assert_adopted(lay["copy"])


def test_scan_rules_apply_output_files(lay, capsys):
    inv = lay["out"] / "step" / "inventory.json"
    rules = lay["out"] / "step" / "rules.json"
    report = lay["out"] / "step" / "report.json"
    _ok(capsys, ["copy", lay["src"], lay["copy"]])
    _ok(capsys, ["scan", lay["copy"], "--source", lay["src"], "--out", inv])
    _ok(capsys, ["rules", lay["copy"], "--inventory", inv, "--out", rules, "--deterministic"])
    _ok(capsys, ["apply", lay["copy"], "--source", lay["src"], "--inventory", inv, "--rules", rules, "--report", report])
    assert json.loads(rules.read_text(encoding="utf-8"))
    assert json.loads(report.read_text(encoding="utf-8"))
    _assert_adopted(lay["copy"])


def test_run_with_staging_on_other_fs(lay, capsys):
    staging = lay["other"] / "staging"
    _ok(capsys, ["run", lay["copy"], "--source", lay["src"], "--staging", staging, "--deterministic"])
    for name in ("inventory.json", "rules.json", "report.json"):
        assert (staging / name).is_file(), name
    _assert_adopted(lay["copy"])


def test_place_new_root_file_after_run(lay, capsys):
    copy = lay["copy"]
    _ok(capsys, ["run", copy, "--source", lay["src"], "--deterministic"])
    target = copy / "meeting_notes.md"
    res = on_pre_tool_call(
        tool_name="write_file", args={"path": str(target), "content": "# notes\n"}, tool_call_id="xdev1",
    )
    assert res is not None, "the placement hook did not place a new root file"
    new_path = Path(res["args"]["path"])
    assert new_path != target
    assert os.path.realpath(new_path).startswith(os.path.realpath(copy) + os.sep)
    new_path.parent.mkdir(parents=True, exist_ok=True)
    new_path.write_text("# notes\n", encoding="utf-8")
    transformed = on_transform_tool_result(
        tool_name="write_file", args=res["args"],
        result=json.dumps({"verified": True, "resolved_path": str(new_path)}), tool_call_id="xdev1",
    )
    assert transformed is not None and json.loads(transformed)["placed_by_adopt"]
    # A loose root file placed by the CLI, then undone.
    (copy / "loose_plan.md").write_text("# plan\n", encoding="utf-8")
    moved = _ok(capsys, ["place", "loose_plan.md", "--root", copy])["moved"]
    assert len(moved) == 1
    assert not (copy / "loose_plan.md").exists()
    undone = _ok(capsys, ["place", "--undo", "1", "--root", copy])["undone"]
    assert len(undone) == 1
    assert (copy / "loose_plan.md").is_file()


def test_deep_tree_300_levels(lay, capsys):
    deep = lay["src"] / "deep"
    cur = deep
    for _ in range(300):
        cur = cur / "d"
    cur.mkdir(parents=True)
    (cur / "leaf.txt").write_text("bottom\n", encoding="utf-8")
    t0 = time.perf_counter()
    _ok(capsys, ["run", lay["copy"], "--source", lay["src"], "--deterministic"])
    _timing("deep_tree_run", lay, time.perf_counter() - t0, levels=300)
    leaf = lay["copy"].joinpath("deep", *(["d"] * 300), "leaf.txt")
    found = [p for p in lay["copy"].rglob("leaf.txt")]
    assert leaf.is_file() or found, "the deepest file was not copied"
    _assert_adopted(lay["copy"])


def test_many_small_files(lay, capsys):
    for d in range(50):
        sub = lay["src"] / "many" / f"part_{d:02d}"
        sub.mkdir(parents=True)
        for i in range(100):
            (sub / f"f_{i:03d}.txt").write_bytes(b"x" * 64)
    t0 = time.perf_counter()
    _ok(capsys, ["copy", lay["src"], lay["copy"]])
    copy_s = time.perf_counter() - t0
    _timing("copy_5000", lay, copy_s, files=5008)
    assert sum(1 for _ in (lay["copy"] / "many").rglob("f_*.txt")) == 5000
    second = lay["copy"].parent / "adopted-run"
    t0 = time.perf_counter()
    _ok(capsys, ["run", second, "--source", lay["src"], "--deterministic"])
    _timing("run_5000", lay, time.perf_counter() - t0, files=5008)
    _assert_adopted(second)


# ---------------------------------------------------------------- special entries: same answer as one filesystem


def _special_source(src: Path, *, unreadable: bool) -> None:
    outside = src.parent / "outside-target.txt"
    outside.write_text("outside\n", encoding="utf-8")
    (src / "link_rel.md").symlink_to("README.md")
    (src / "link_abs").symlink_to(outside)
    (src / "hard_a.txt").write_text("same inode\n", encoding="utf-8")
    os.link(src / "hard_a.txt", src / "hard_b.txt")
    os.mkfifo(src / "pipe")
    if unreadable:
        locked = src / "locked.txt"
        locked.write_text("no read\n", encoding="utf-8")
        os.chmod(locked, 0)


def _outcome(capsys, flow: str, src: Path, copy: Path) -> Dict[str, Any]:
    argv = ["copy", src, copy] if flow == "copy" else ["run", copy, "--source", src, "--deterministic"]
    rc, _data, err = _cli(capsys, argv)

    def norm(text: str) -> str:
        for path, token in ((copy, "<COPY>"), (src, "<SRC>"), (src.parent, "<PARENT>")):
            for form in sorted({str(path), os.path.realpath(path)}, key=len, reverse=True):
                text = text.replace(form, token)
        return text

    msg = norm(err)
    snap = _snapshot(copy, skip=(".git", ".adopt")) if os.path.lexists(copy) else None
    if snap is not None:
        snap = {k: (kind, norm(body) if kind == "link" else body) for k, (kind, body) in snap.items()}
    links = {}
    if snap is not None:
        a, b = copy / "hard_a.txt", copy / "hard_b.txt"
        if a.exists() and b.exists():
            links["hard_pair_same_inode"] = os.stat(a).st_ino == os.stat(b).st_ino
    return {"rc": rc, "msg": msg, "tree": snap, **links}


@pytest.mark.parametrize("flow", ["copy", "run"])
@pytest.mark.parametrize("unreadable", [False, True], ids=["link-hardlink-fifo", "unreadable-file"])
def test_special_entries_same_as_one_fs(lay, capsys, fs1, flow, unreadable):
    if unreadable and os.geteuid() == 0:
        pytest.skip("root can read a file without read permission")
    _special_source(lay["src"], unreadable=unreadable)
    base_src = fs1 / "baseline" / "source"
    _make_source(base_src)
    _special_source(base_src, unreadable=unreadable)
    expected = _outcome(capsys, flow, base_src, fs1 / "baseline" / "copy-parent" / "adopted")
    got = _outcome(capsys, flow, lay["src"], lay["copy"])
    if got != expected:
        # Make the difference readable in the failure output.
        assert got["rc"] == expected["rc"], (got["msg"], expected["msg"])
        assert got["msg"] == expected["msg"]
    assert got == expected
    for root in (lay["src"], base_src):
        locked = root / "locked.txt"
        if locked.exists():
            os.chmod(locked, 0o600)
