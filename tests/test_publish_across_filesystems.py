"""Publishing a finished template project when the move cannot be a rename.

The projects folder is often on another drive than the staging folder. Then the rename
fails with EXDEV and the project must be copied. These tests prove that the copy goes
into a private temporary folder on the destination filesystem through folder handles
(no symbolic link is followed at either end), that one rename then puts it in place, and
that any failure before that rename leaves nothing behind in the projects folder.

Two ways to get the cross-device branch:
  forced  the first rename of the staged project raises OSError(EXDEV) (no second
          filesystem needed; everything else is real I/O on one filesystem)
  second  the projects folder is really on another filesystem: set DEFUZZ_SECOND_FS to a
          writable folder on a different filesystem from the temp folder (skipped otherwise)

A full destination drive cannot be made without privileges here (a size-limited tmpfs
needs root), so "drive full" is simulated: the file open/copy step raises
OSError(ENOSPC) after N files.
"""

from __future__ import annotations

import errno
import json
import os
import queue
import secrets
import shutil
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pytest

from tests import ensure_test_package, load_submodule

ensure_test_package()

from hermes_plugins.defuzz import cli as cli_mod  # noqa: E402
from hermes_plugins.defuzz import kit_scaffold, scaffolder as sc  # noqa: E402
from tests.test_scaffold_accept_partial_state import _register, _route_accept, _template  # noqa: E402

SECOND_ENV = "DEFUZZ_SECOND_FS"
MOVE_PREFIX = ".adopt-move-"
_BASE_TMP = tempfile.gettempdir()
SWAP_ITERATIONS = 5_000


# --------------------------------------------------------------------------- where


def _second_root() -> Path:
    raw = os.environ.get(SECOND_ENV, "").strip()
    if not raw:
        pytest.skip(f"set {SECOND_ENV} to a writable folder on another filesystem to run this")
    root = Path(raw)
    if not root.is_absolute() or not root.is_dir() or not os.access(root, os.W_OK | os.X_OK):
        pytest.skip(f"{SECOND_ENV}={raw} is not an absolute writable folder")
    if os.stat(root).st_dev == os.stat(_BASE_TMP).st_dev:
        pytest.skip(f"{SECOND_ENV}={raw} is on the same filesystem as the temp folder")
    return root


def _rmtree_writable(path: Path) -> None:
    def onerror(func: Any, p: str, _exc: Any) -> None:
        try:
            os.chmod(os.path.dirname(p), stat.S_IRWXU)
            os.chmod(p, stat.S_IRWXU)
            func(p)
        except OSError:
            pass

    shutil.rmtree(path, onerror=onerror)


@pytest.fixture(params=["forced", "second"])
def where(request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """(projects folder, staging parent, mode). 'forced' patches the first staged rename to EXDEV."""
    if request.param == "second":
        root = _second_root()
        area = root / f"t-{secrets.token_hex(4)}"
        area.mkdir()
        try:
            yield area / "projects", tmp_path / "stage", "second"
        finally:
            assert area.parent == root and area.name.startswith("t-") and len(area.name) == 10
            _rmtree_writable(area)
        return
    yield tmp_path / "projects", tmp_path / "stage", "forced"


def _force_exdev(monkeypatch: pytest.MonkeyPatch, staged: Path, times: int = 1) -> Dict[str, int]:
    """The rename of the staged project fails as if the folders were on two filesystems."""
    real = os.rename
    state = {"left": times, "raised": 0}

    def rename(src: Any, dst: Any, *a: Any, **k: Any) -> Any:
        s = os.fspath(src) if not isinstance(src, int) else src
        if state["left"] > 0 and (s == str(staged) or (s == staged.name and k.get("src_dir_fd") is not None)):
            state["left"] -= 1
            state["raised"] += 1
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real(src, dst, *a, **k)

    monkeypatch.setattr(os, "rename", rename)
    return state


def _propose(projects: Path, stage: Path, tmp_path: Path) -> Any:
    projects.mkdir(parents=True, exist_ok=True)
    return sc.propose(_template(tmp_path), "Demo", {}, dest_root=projects, staging_parent=stage,
                      db_path=tmp_path / "s.db")


def _fill(staged: Path, files: int = 6) -> None:
    """Add regular files, an executable script, links and a nested folder to a staged project."""
    (staged / "scripts").mkdir()
    tool = staged / "scripts" / "run.sh"
    tool.write_text("#!/bin/sh\necho ok\n")
    os.chmod(tool, 0o755)
    (staged / "docs" / "deep").mkdir(parents=True)
    for i in range(files):
        (staged / "docs" / f"f{i}.txt").write_text(f"file {i}\n")
    os.symlink("../README.md", staged / "docs" / "readme-link")
    os.symlink("does-not-exist", staged / "dangling")
    os.symlink("docs/deep", staged / "deep-dir-link")
    old = 1_500_000_000
    os.utime(staged / "docs" / "f0.txt", (old, old))


def _leftovers(projects: Path) -> List[str]:
    return sorted(n for n in os.listdir(projects)) if projects.is_dir() else []


def _plain(message: str) -> None:
    assert "\n" not in message and "Traceback" not in message and "[(" not in message, message
    assert "Errno" not in message, message


class _DiskFull:
    """Simulated full destination drive: the N+1st new file in the copy fails with ENOSPC.

    Covers the handle-based copy (os.open with O_CREAT relative to a folder handle) and
    the old path-based copy (shutil.copyfile), so the same test shows the old behaviour.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch, after: int, err: int = errno.ENOSPC) -> None:
        self.after, self.copied, self.err = after, 0, err
        self.active = False
        real_open, real_copyfile = os.open, shutil.copyfile

        def fail() -> None:
            if not self.active:
                return
            if self.copied >= self.after:
                raise OSError(self.err, os.strerror(self.err))
            self.copied += 1

        def op(path: Any, flags: int, *a: Any, **k: Any) -> int:
            if flags & os.O_CREAT and k.get("dir_fd") is not None:
                fail()
            return real_open(path, flags, *a, **k)

        def copyfile(src: Any, dst: Any, *a: Any, **k: Any) -> Any:
            fail()
            return real_copyfile(src, dst, *a, **k)

        monkeypatch.setattr(os, "open", op)
        monkeypatch.setattr(shutil, "copyfile", copyfile)
        _during_publish(monkeypatch, self)


def _during_publish(monkeypatch: pytest.MonkeyPatch, flag: Any) -> None:
    """Set `flag.active` only while the project is being published (all module copies)."""
    mods = [sc, load_submodule("scaffolder")]
    try:
        api = load_submodule("dashboard.plugin_api")
        mods.append(api._load("dashboard.routes.workspace_routes").scaffolder)
    except Exception:  # noqa: BLE001 - the dashboard is optional for these tests
        pass
    for mod in {id(m): m for m in mods}.values():
        real = mod._publish_staged_repo

        def publish(plan: Any, _real: Callable[..., Any] = real) -> Any:
            flag.active = True
            try:
                return _real(plan)
            finally:
                flag.active = False

        monkeypatch.setattr(mod, "_publish_staged_repo", publish)


# --------------------------------------------------------------- the copy works


def test_cross_device_copy_keeps_links_modes_and_times(where, tmp_path, monkeypatch):
    projects, stage, mode = where
    proposal = _propose(projects, stage, tmp_path)
    plan = proposal.repos[0]
    _fill(plan.staged)
    forced = _force_exdev(monkeypatch, plan.staged) if mode == "forced" else None
    result = sc.accept(proposal, register=_register, db_path=tmp_path / "s.db")
    dest = plan.dest
    assert Path(result.repos[0]["path"]) == dest
    if forced is not None:
        assert forced["raised"] == 1
    assert os.readlink(dest / "docs" / "readme-link") == "../README.md"
    assert os.readlink(dest / "dangling") == "does-not-exist"
    assert os.readlink(dest / "deep-dir-link") == "docs/deep"
    assert stat.S_IMODE(os.stat(dest / "scripts" / "run.sh").st_mode) == 0o755
    assert int(os.stat(dest / "docs" / "f0.txt").st_mtime) == 1_500_000_000
    assert (dest / "docs" / "f5.txt").read_text() == "file 5\n"
    assert not plan.staged.exists() and not proposal.staging_dir.exists()
    assert _leftovers(projects) == [dest.name]


def test_same_filesystem_is_one_rename_and_no_copy(tmp_path, monkeypatch):
    proposal = _propose(tmp_path / "projects", tmp_path / "stage", tmp_path)
    plan = proposal.repos[0]
    real = os.rename
    calls: List[Any] = []

    def rename(src: Any, dst: Any, *a: Any, **k: Any) -> Any:
        calls.append((src, dst))
        return real(src, dst, *a, **k)

    copies: List[Any] = []
    monkeypatch.setattr(os, "rename", rename)
    monkeypatch.setattr(kit_scaffold, "_copy_tree_fd", lambda *a, **k: copies.append(a))
    sc._publish_staged_repo(plan)
    assert len(calls) == 1 and not copies
    assert (plan.dest / "README.md").is_file() and not plan.staged.exists()
    assert _leftovers(plan.dest.parent) == [plan.dest.name]


# ------------------------------------------------ the copy fails part-way (B1)


@pytest.mark.parametrize("err,words", [(errno.ENOSPC, "destination drive is full"), (errno.EACCES, "permission")])
def test_copy_failing_part_way_leaves_nothing(where, tmp_path, monkeypatch, err, words):
    projects, stage, mode = where
    proposal = _propose(projects, stage, tmp_path)
    plan = proposal.repos[0]
    _fill(plan.staged)
    if mode == "forced":
        _force_exdev(monkeypatch, plan.staged)
    full = _DiskFull(monkeypatch, after=3, err=err)
    with pytest.raises(sc.ScaffoldError) as caught:
        sc.accept(proposal, register=_register, db_path=tmp_path / "s.db")
    message = str(caught.value)
    assert full.copied == 3
    assert not os.path.lexists(plan.dest), _leftovers(projects)
    assert _leftovers(projects) == []
    assert words in message and "Nothing was created" in message, message
    _plain(message)
    assert getattr(caught.value, "created_dirs", []) == []
    assert caught.value.keep_staging is False  # the same rule as other refusals of the move
    assert (plan.staged / "docs" / "f5.txt").is_file()  # the staged copy is intact


def test_dashboard_copy_failure_is_ready_not_partial(where, tmp_path, monkeypatch):
    projects, stage, mode = where
    proposal = _propose(projects, stage, tmp_path)
    plan = proposal.repos[0]
    _fill(plan.staged)
    if mode == "forced":
        _force_exdev(monkeypatch, plan.staged)
    _DiskFull(monkeypatch, after=2)
    response, state = _route_accept(tmp_path, monkeypatch, proposal)
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert detail["created_dirs"] == [] and state == "ready", detail
    assert "destination drive is full" in detail["error"]
    _plain(detail["error"])
    assert _leftovers(projects) == [] and plan.staged.is_dir()


@pytest.fixture()
def dash(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    jobs = api._load("dashboard.routes.accept_jobs")
    jobs._reset_for_tests()
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    with routes._LOCK:
        routes._PROPOSALS.clear()
    app = FastAPI()
    app.include_router(api.router)
    yield TestClient(app), routes, jobs
    jobs._reset_for_tests()
    with routes._LOCK:
        routes._PROPOSALS.clear()


def test_start_and_poll_reports_the_copy_failure(where, tmp_path, monkeypatch, dash):
    client, routes, jobs = dash
    projects, stage, mode = where
    proposal = _propose(projects, stage, tmp_path)
    plan = proposal.repos[0]
    _fill(plan.staged)
    if mode == "forced":
        _force_exdev(monkeypatch, plan.staged)
    _DiskFull(monkeypatch, after=2)
    gate = threading.Event()
    real = routes.scaffolder.accept

    def slow(*a: Any, **k: Any) -> Any:
        gate.wait(10)
        return real(*a, **k)

    monkeypatch.setattr(routes.scaffolder, "accept", slow)
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", 0.05)
    with routes._LOCK:
        routes._PROPOSALS["poll"] = {"state": "ready", "proposal": proposal, "remember_options": False,
                                     "kind": "template", "home": routes._active_home(), "created": time.time()}
    monkeypatch.setattr(routes, "_take_expired_locked", lambda: [])
    first = client.post("/scaffold/accept", json={"proposal_id": "poll", "confirm": True})
    assert first.status_code == 202, first.text
    gate.set()
    end = time.monotonic() + 30
    while True:
        body = client.get("/scaffold/accept/poll").json()
        if body["status"] != "running" or time.monotonic() > end:
            break
        time.sleep(0.02)
    assert body["status"] == "failed" and body["partial"] is False, body
    assert body["detail"]["created_dirs"] == [] and "destination drive is full" in body["detail"]["error"]
    assert routes._PROPOSALS["poll"]["state"] == "ready"
    assert _leftovers(projects) == [] and plan.staged.is_dir()


def _cli_fake_check(monkeypatch: pytest.MonkeyPatch, stages: List[Path]) -> None:
    import dataclasses

    real = getattr(sc.propose, "__wrapped__", sc.propose)

    def propose(*a: Any, **k: Any) -> Any:
        proposal = real(*a, **k)
        stages.append(proposal.repos[0].staged)
        for plan in proposal.repos:
            if plan.check is not None:
                plan.check = dataclasses.replace(plan.check, cmd=(sys.executable, "-c", "pass"),
                                                 prepare=(), extra_cmds=())
        return proposal

    monkeypatch.setattr(cli_mod, "propose", propose)


def test_cli_copy_failure_prints_one_plain_line(where, tmp_path, monkeypatch, capsys):
    projects, stage, mode = where
    if str(os.path.realpath(projects.parent)).startswith("/dev/"):
        pytest.skip("the command refuses projects folders below /dev before anything is staged")
    projects.mkdir(parents=True, exist_ok=True)
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE", "HERMES_REAL_HOME"):
        monkeypatch.setenv(key, str(home))
    stages: List[Path] = []
    _cli_fake_check(monkeypatch, stages)
    if mode == "forced":
        real = os.rename

        def rename(src: Any, dst: Any, *a: Any, **k: Any) -> Any:
            if stages and isinstance(src, (str, os.PathLike)) and (
                os.fspath(src) == str(stages[0]) or (os.fspath(src) == stages[0].name and k.get("src_dir_fd") is not None)
            ) and not getattr(rename, "done", False):
                rename.done = True  # type: ignore[attr-defined]
                raise OSError(errno.EXDEV, "Invalid cross-device link")
            return real(src, dst, *a, **k)

        monkeypatch.setattr(os, "rename", rename)
    _DiskFull(monkeypatch, after=3)
    rc = cli_mod.main(["new", "--template", "python-golden", "--name", "Full Demo", "--yes",
                       "--dest-root", str(projects)])
    _out, err = capsys.readouterr()
    assert rc == 1, err
    lines = [line for line in err.strip().splitlines() if line]
    if "preflight ok" in lines:  # the tool table the command prints before it creates anything
        lines = lines[lines.index("preflight ok") + 1:]
    assert len(lines) == 1, err
    assert "destination drive is full" in lines[0] and "Nothing was created" in lines[0], err
    _plain(lines[0])
    assert _leftovers(projects) == []


def test_interrupt_during_the_copy_removes_the_temporary_folder(where, tmp_path, monkeypatch):
    projects, stage, mode = where
    proposal = _propose(projects, stage, tmp_path)
    plan = proposal.repos[0]
    _fill(plan.staged)
    if mode == "forced":
        _force_exdev(monkeypatch, plan.staged)
    real_open = os.open
    count = {"n": 0}
    flag = type("Flag", (), {"active": False})()
    _during_publish(monkeypatch, flag)

    def op(path: Any, flags: int, *a: Any, **k: Any) -> int:
        if flag.active and flags & os.O_CREAT and k.get("dir_fd") is not None:
            count["n"] += 1
            if count["n"] == 3:
                raise KeyboardInterrupt
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", op)
    with pytest.raises(KeyboardInterrupt) as caught:
        sc.accept(proposal, register=_register, db_path=tmp_path / "s.db")
    assert getattr(caught.value, "created_dirs", []) == []
    assert _leftovers(projects) == [] and plan.staged.is_dir()
    assert cli_mod._print_interrupted_new(caught.value) == cli_mod.INTERRUPTED_RC


def test_special_file_in_the_staged_project_is_refused(where, tmp_path, monkeypatch):
    projects, stage, mode = where
    proposal = _propose(projects, stage, tmp_path)
    plan = proposal.repos[0]
    os.mkfifo(plan.staged / "pipe")
    if mode == "forced":
        _force_exdev(monkeypatch, plan.staged)
    elif mode == "second":
        pass
    with pytest.raises(sc.ScaffoldError) as caught:
        sc._publish_staged_repo(plan)
    message = str(caught.value)
    assert "special file" in message and "Nothing was created" in message, message
    _plain(message)
    assert _leftovers(projects) == [] and plan.staged.is_dir()


# ---------------------------------------- the final name appears during the copy


def test_final_name_created_by_someone_else_during_the_copy_is_refused(where, tmp_path, monkeypatch):
    projects, stage, mode = where
    proposal = _propose(projects, stage, tmp_path)
    plan = proposal.repos[0]
    _fill(plan.staged)
    if mode == "forced":
        _force_exdev(monkeypatch, plan.staged)
    real_open = os.open
    theirs = plan.dest

    def op(path: Any, flags: int, *a: Any, **k: Any) -> int:
        if flags & os.O_CREAT and k.get("dir_fd") is not None and not theirs.exists():
            theirs.mkdir()
            (theirs / "their-file").write_text("mine")
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", op)
    with pytest.raises(sc.ScaffoldError) as caught:
        sc._publish_staged_repo(plan)
    assert "Destination already exists" in str(caught.value), str(caught.value)
    assert sorted(os.listdir(theirs)) == ["their-file"] and (theirs / "their-file").read_text() == "mine"
    assert _leftovers(projects) == [theirs.name] and plan.staged.is_dir()


# -------------------------------- the destination parent swapped for a link (B2)


class _Swapper:
    """A second thread swaps the projects folder for a link to `foreign` on request."""

    def __init__(self, parent: Path, foreign: Path) -> None:
        self.parent, self.foreign = parent, foreign
        self.saved = parent.with_name(parent.name + "-saved")
        self.commands: "queue.Queue[str]" = queue.Queue()
        self.answers: "queue.Queue[Optional[BaseException]]" = queue.Queue()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while True:
            command = self.commands.get()
            if command == "stop":
                return
            try:
                if command == "swap":
                    self.parent.rename(self.saved)
                    self.parent.symlink_to(self.foreign, target_is_directory=True)
                else:
                    self.parent.unlink()
                    self.saved.rename(self.parent)
                self.answers.put(None)
            except BaseException as exc:  # noqa: BLE001 - handed back to the test thread
                self.answers.put(exc)

    def call(self, command: str) -> None:
        self.commands.put(command)
        result = self.answers.get(timeout=30)
        if result is not None:
            raise result

    def close(self) -> None:
        self.commands.put("stop")
        self.thread.join(timeout=30)


def test_projects_folder_swapped_for_a_link_during_the_copy(where, tmp_path, monkeypatch):
    projects, stage, mode = where
    proposal = _propose(projects, stage, tmp_path)
    plan = proposal.repos[0]
    _fill(plan.staged, files=4)
    foreign = (tmp_path if mode == "second" else projects.parent) / "elsewhere"
    foreign.mkdir()
    swapper = _Swapper(projects, foreign)
    real_open, real_rename = os.open, os.rename
    state = {"armed": False, "swapped": False}

    def rename(src: Any, dst: Any, *a: Any, **k: Any) -> Any:
        s = os.fspath(src) if not isinstance(src, int) else src
        if mode == "forced" and (s == str(plan.staged) or (s == plan.staged.name and k.get("src_dir_fd") is not None)):
            state["armed"] = True
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real_rename(src, dst, *a, **k)

    def op(path: Any, flags: int, *a: Any, **k: Any) -> int:
        if flags & os.O_CREAT and (k.get("dir_fd") is not None) and not state["swapped"]:
            state["swapped"] = True
            swapper.call("swap")
        return real_open(path, flags, *a, **k)

    def copyfile(src: Any, dst: Any, *a: Any, **k: Any) -> Any:  # the old path-based copy
        if not state["swapped"]:
            state["swapped"] = True
            swapper.call("swap")
        return real_copyfile(src, dst, *a, **k)

    real_copyfile = shutil.copyfile
    monkeypatch.setattr(os, "rename", rename)
    monkeypatch.setattr(os, "open", op)
    monkeypatch.setattr(shutil, "copyfile", copyfile)
    # Flushing to disk is not what this loop tests and costs minutes over 5,000 rounds.
    monkeypatch.setattr(os, "fsync", lambda fd: None)
    escapes = refusals = lost = 0
    start = time.monotonic()
    iterations = SWAP_ITERATIONS
    try:
        for _ in range(iterations):
            state["swapped"] = False
            try:
                sc._publish_staged_repo(plan)
            except sc.ScaffoldError:
                refusals += 1
            escaped = [p for p in foreign.rglob("*")]
            escapes += int(bool(escaped))
            lost += int(not plan.staged.is_dir())
            if state["swapped"]:
                swapper.call("restore")
            if escaped:
                for child in list(foreign.iterdir()):
                    _rmtree_writable(child) if child.is_dir() and not child.is_symlink() else child.unlink()
            if plan.dest.exists():  # the old code moved it: put it back for the next round
                shutil.move(str(plan.dest), str(plan.staged))
            if escapes:  # one escape is enough to fail; do not spend minutes on the old code
                break
    finally:
        if state["swapped"] and projects.is_symlink():
            swapper.call("restore")
        swapper.close()
    took = round(time.monotonic() - start, 2)
    print("SWAP_DURING_COPY", json.dumps(dict(mode=mode, iterations=iterations, escapes=escapes,
                                              refusals=refusals, lost_stage=lost, seconds=took)))
    assert (escapes, lost) == (0, 0)
    assert refusals == iterations
    assert list(foreign.iterdir()) == []
    assert [n for n in os.listdir(projects) if n.startswith(MOVE_PREFIX)] == []
    assert (plan.staged / "docs" / "f3.txt").read_text() == "file 3\n"


# -------------------------------------- nested missing folders above the destination


def test_failed_publish_removes_only_the_folders_it_created(where, tmp_path, monkeypatch):
    projects, stage, mode = where
    projects.mkdir(parents=True)
    nested = projects / "a" / "b"
    proposal = sc.propose(_template(tmp_path), "Demo", {}, dest_root=nested, staging_parent=stage,
                          db_path=tmp_path / "s.db")
    plan = proposal.repos[0]
    (projects / "keep-me").mkdir()
    if mode == "forced":
        _force_exdev(monkeypatch, plan.staged)
    _DiskFull(monkeypatch, after=0)
    response, state = _route_accept(tmp_path, monkeypatch, proposal)
    assert response.status_code == 409, response.text
    assert _leftovers(projects) == ["keep-me"]
    assert state == "ready" and response.json()["detail"]["created_dirs"] == []
    assert plan.staged.is_dir()


def test_route_reports_an_intermediate_folder_that_could_not_be_removed(where, tmp_path, monkeypatch):
    projects, stage, mode = where
    projects.mkdir(parents=True)
    nested = projects / "a"
    proposal = sc.propose(_template(tmp_path), "Demo", {}, dest_root=nested, staging_parent=stage,
                          db_path=tmp_path / "s.db")
    plan = proposal.repos[0]
    if mode == "forced":
        _force_exdev(monkeypatch, plan.staged)
    real_open = os.open
    flag = type("Flag", (), {"active": False})()
    _during_publish(monkeypatch, flag)

    def op(path: Any, flags: int, *a: Any, **k: Any) -> int:
        if flag.active and flags & os.O_CREAT and k.get("dir_fd") is not None:
            (nested / "someone-else.txt").write_text("x")  # someone writes into the new folder
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", op)
    response, state = _route_accept(tmp_path, monkeypatch, proposal)
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert state == "partial" and detail["created_dirs"] == [str(nested)], detail
    assert (nested / "someone-else.txt").read_text() == "x"


# ------------------------------------------------------------------ size and timing


@pytest.mark.parametrize("shape", ["deep-300", "files-5000"])
def test_large_projects_copy_and_timing(where, tmp_path, monkeypatch, shape):
    projects, stage, mode = where
    proposal = _propose(projects, stage, tmp_path)
    plan = proposal.repos[0]
    if shape == "deep-300":
        cur = plan.staged
        for i in range(300):
            cur = cur / f"d{i % 10}"
            os.mkdir(cur)
        (cur / "bottom.txt").write_text("bottom")
        rel = os.path.relpath(cur / "bottom.txt", plan.staged)
    else:
        for d in range(50):
            sub = plan.staged / f"dir{d:02d}"
            sub.mkdir()
            for i in range(100):
                (sub / f"f{i:03d}.txt").write_text(f"{d}-{i}\n")
        rel = "dir49/f099.txt"
    if mode == "forced":
        _force_exdev(monkeypatch, plan.staged)
    start = time.monotonic()
    sc._publish_staged_repo(plan)
    took = round(time.monotonic() - start, 3)
    print("PUBLISH_TIMING", json.dumps(dict(mode=mode, shape=shape, seconds=took)))
    assert (plan.dest / rel).is_file()
    assert not plan.staged.exists()
    assert _leftovers(projects) == [plan.dest.name]


def test_template_copy_is_the_kit_handle_copy(tmp_path, monkeypatch):
    """One implementation, two callers: the template copy across filesystems is the kit's."""
    proposal = _propose(tmp_path / "projects", tmp_path / "stage", tmp_path)
    plan = proposal.repos[0]
    _force_exdev(monkeypatch, plan.staged)
    real = kit_scaffold._copy_tree_fd
    calls: List[Any] = []

    def copy(src_fd: int, dst_fd: int) -> None:
        calls.append((src_fd, dst_fd))
        real(src_fd, dst_fd)

    monkeypatch.setattr(kit_scaffold, "_copy_tree_fd", copy)
    sc._publish_staged_repo(plan)
    assert len(calls) == 1 and (plan.dest / "README.md").is_file()
