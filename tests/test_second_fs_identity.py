"""Opt-in, real-device identity and redirection regression tests.

Set DEFUZZ_SECOND_FS to a private, writable folder on another device. The
mount-parent test additionally needs an empty folder named defuzz-xdev-* directly
under a mount point; it publishes ONLY to that exact folder. Set
DEFUZZ_IDENTITY_TREE to an exported alternate tree to exercise its safety helpers.
Only inode-collision cases synthesize stat fields; redirects and I/O are real.
"""
from __future__ import annotations

import contextlib
import importlib
import json
import os
from pathlib import Path
import queue
import shutil
import stat
import sys
import tempfile
import threading
import time
import types

import pytest

from tests import ensure_test_package, load_submodule

ensure_test_package()
from hermes_plugins.defuzz import kit_scaffold as kit, output_file, placer, safety, scaffolder as sc, workspace_root
from tests.test_kit_scaffold import FakeVideoBridge
from tests.test_scaffold_accept_partial_state import _template, _register, _route_accept

ITERATIONS = 20_000


@pytest.fixture(scope="module")
def second_base(tmp_path_factory):
    raw = os.environ.get("DEFUZZ_SECOND_FS")
    if not raw:
        pytest.skip("set DEFUZZ_SECOND_FS to a private writable folder on another filesystem")
    base = Path(raw).absolute()
    local = tmp_path_factory.mktemp("identity-device-check")
    if not base.is_dir() or base.is_symlink() or not os.access(base, os.W_OK | os.X_OK):
        pytest.skip("DEFUZZ_SECOND_FS must name a writable real folder")
    if base.stat().st_dev == local.stat().st_dev:
        pytest.skip("DEFUZZ_SECOND_FS and pytest temporary folders are on the same device")
    print("DEVICES", json.dumps({"second": base.stat().st_dev, "local": local.stat().st_dev}))
    return base


@pytest.fixture
def second(second_base):
    # Never enumerate or clean the mount point: only our newly allocated child.
    child = Path(tempfile.mkdtemp(prefix="identity-", dir=second_base))
    try:
        yield child
    finally:
        shutil.rmtree(child)


@pytest.fixture(params=["local-to-second", "second-to-local"])
def layout(request, tmp_path, second):
    a, b = (tmp_path, second) if request.param == "local-to-second" else (second, tmp_path)
    parent, foreign = a / "chosen", b / "foreign"
    parent.mkdir()
    foreign.mkdir()
    assert parent.stat().st_dev != foreign.stat().st_dev
    return types.SimpleNamespace(parent=parent, foreign=foreign, local=tmp_path, other=second)


@pytest.fixture
def writer():
    tree = os.environ.get("DEFUZZ_IDENTITY_TREE")
    if not tree:
        return safety
    name = "_defuzz_identity_alternate"
    if name not in sys.modules:
        package = types.ModuleType(name)
        package.__path__ = [str(Path(tree).resolve())]
        sys.modules[name] = package
    return importlib.import_module(name + ".safety")


def _proposal(tmp_path, parent, kind="template"):
    if kind == "kit":
        bridge = FakeVideoBridge()
        p = kit.propose_kit("video-production", "demo", {}, dest_root=parent,
                            staging_parent=tmp_path / "stage", bridge=bridge)
        return p, lambda: kit.accept_kit(p, bridge=bridge, register=_register,
                                         db_path=tmp_path / "state.db")
    p = sc.propose(_template(tmp_path), "demo", {}, dest_root=parent,
                   staging_parent=tmp_path / "stage", db_path=tmp_path / "state.db")
    return p, lambda: sc.accept(p, register=_register, db_path=tmp_path / "state.db")


def _plan(parent, staged):
    dest = parent / "project"
    return sc.RepoPlan("project", dest, staged, [], dest_anchor=sc._dest_anchor(dest))


def _stat_with(st, *, ino=None, dev=None):
    values = list(st)
    if ino is not None:
        values[1] = ino
    if dev is not None:
        values[2] = dev
    return os.stat_result(values)


@contextlib.contextmanager
def _redirect(parent, foreign):
    saved = parent.with_name(parent.name + "-saved")
    parent.rename(saved)
    parent.symlink_to(foreign, target_is_directory=True)
    try:
        yield saved
    finally:
        parent.unlink()
        saved.rename(parent)


def test_mount_parent_preview_accept(second_base, tmp_path):
    """The anchor itself is the real mount point, not a simulated st_dev."""
    if not second_base.name.startswith("defuzz-xdev-") or not os.path.ismount(second_base.parent):
        pytest.skip("mount-parent publication requires a private defuzz-xdev-* mount child")
    if any(second_base.iterdir()):
        pytest.skip("mount-parent publication requires the provided private folder to be empty")
    assert second_base.parent.stat().st_dev != second_base.parent.parent.stat().st_dev
    kw = dict(home=tmp_path / "home", hermes_home=tmp_path / "hh",
              env={"TMPDIR": str(second_base.parent)})
    if Path("/dev") in second_base.parent.parents:
        with pytest.raises(workspace_root.WorkspaceRootError, match="system folder"):
            workspace_root.validate_projects_root(second_base.parent, **kw)
    else:
        assert workspace_root.validate_projects_root(second_base.parent, **kw) == second_base.parent
    second_base.rmdir()  # empty, explicitly supplied private destination only
    try:
        p = sc.propose(_template(tmp_path), second_base.name, {}, dest_root=second_base.parent,
                       staging_parent=tmp_path / "stage", db_path=tmp_path / "state.db")
        assert p.repos[0].dest == second_base
        assert p.repos[0].dest_anchor[:2] == (str(second_base.parent), str(second_base.parent.resolve()))
        result = sc.accept(p, register=_register, db_path=tmp_path / "state.db")
        assert result.repos and (second_base / "README.md").is_file()
        assert not p.staging_dir.exists()
    finally:
        if second_base.exists():
            shutil.rmtree(second_base)
        second_base.mkdir(mode=0o700)


@pytest.mark.parametrize("kind", ["template", "kit"])
def test_legitimate_preview_accept_and_trust(second, tmp_path, kind):
    parent = second / "projects"
    parent.mkdir()
    p, accept = _proposal(tmp_path, parent, kind)
    before = time.monotonic()
    result = accept()
    dest = p.dest if kind == "kit" else p.repos[0].dest
    assert result.repos and dest.is_dir()
    assert placer.inspect_project_trust(dest, db_path=tmp_path / "state.db")["trusted"]
    assert not p.staging_dir.exists()
    print("ACCEPT", kind, "seconds", round(time.monotonic() - before, 4))


def test_workspace_root_policy_and_home_containment(second, tmp_path, monkeypatch):
    home, hh = tmp_path / "home", second / "private-settings"
    home.mkdir()
    hh.mkdir()
    projects = second / "projects"
    projects.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(hh))
    # Bound ancestor marker inspection to this private test area, not neighbours
    # on a user's data drive. This does not bypass any device or identity check.
    kw = dict(home=home, hermes_home=hh, env={"TMPDIR": str(second)})
    if Path("/dev") in second.parents:
        with pytest.raises(workspace_root.WorkspaceRootError, match="system folder"):
            workspace_root.validate_projects_root(projects, **kw)
    else:
        assert workspace_root.validate_projects_root(projects, **kw) == projects
    alias = home / "projects-link"
    alias.symlink_to(projects, target_is_directory=True)
    with pytest.raises(workspace_root.WorkspaceRootError, match="symbolic link"):
        workspace_root.validate_projects_root(alias, **kw)
    safety.assert_not_live_hermes(projects)
    inside_alias = home / "private-link"
    inside_alias.symlink_to(hh, target_is_directory=True)
    with pytest.raises(safety.SafetyError, match="live"):
        safety.assert_not_live_hermes(inside_alias / "project")
    with pytest.raises(workspace_root.WorkspaceRootError, match="Hermes settings"):
        workspace_root.validate_projects_root(hh / "project", **kw)
    output_file.write_output_text(projects / "report.txt", "report", role="report", forbidden_roots=[hh])
    assert (projects / "report.txt").read_text() == "report"
    with pytest.raises(safety.SafetyError, match="symlink"):
        output_file.write_output_text(alias / "bad.txt", "bad", role="report")
    assert not (projects / "bad.txt").exists()


@pytest.mark.parametrize("kind", ["template", "kit"])
@pytest.mark.parametrize("collision", [False, True], ids=["symlink", "equal-inode-other-device"])
def test_preview_redirect_refused(layout, tmp_path, monkeypatch, kind, collision):
    p, accept = _proposal(tmp_path, layout.parent, kind)
    staged = p.staged if kind == "kit" else p.repos[0].staged
    expected = layout.parent.stat()
    with _redirect(layout.parent, layout.foreign):
        if collision:
            real_stat = os.stat
            def observed(path, *args, **kwargs):
                st = real_stat(path, *args, **kwargs)
                if not isinstance(path, int) and os.fspath(path) == str(layout.parent):
                    return _stat_with(st, ino=expected.st_ino)
                return st
            monkeypatch.setattr(os, "stat", observed)
            assert layout.parent.stat().st_ino == expected.st_ino
            assert layout.parent.stat().st_dev != expected.st_dev
        with pytest.raises(sc.ScaffoldError, match="changed after the preview"):
            accept()
        assert staged.is_dir()
        assert list(layout.foreign.iterdir()) == []


@pytest.mark.parametrize("kind", ["template", "kit"])
def test_real_folder_other_device_identity_refused(layout, tmp_path, monkeypatch, kind):
    """Bind mounts need privileges: emulate only stat visibility at the anchor.

    A real foreign directory supplies st_dev/st_ino; no symlink is present, so
    realpath equality cannot accidentally be the reason this test passes.
    """
    p, accept = _proposal(tmp_path, layout.parent, kind)
    foreign_st = layout.foreign.stat()
    real_stat = os.stat
    def observed(path, *args, **kwargs):
        if not isinstance(path, int) and os.fspath(path) == str(layout.parent):
            return foreign_st
        return real_stat(path, *args, **kwargs)
    monkeypatch.setattr(os, "stat", observed)
    with pytest.raises(sc.ScaffoldError, match="changed after the preview"):
        accept()
    assert list(layout.foreign.iterdir()) == []
    assert not (layout.parent / "demo").exists()


@pytest.mark.parametrize("kind", ["template", "kit"])
def test_device_is_checked_even_if_realpath_and_inode_match(layout, tmp_path, monkeypatch, kind):
    p, accept = _proposal(tmp_path, layout.parent, kind)
    original = layout.parent.stat()
    foreign = layout.foreign.stat()
    real_stat = os.stat
    def observed(path, *args, **kwargs):
        if not isinstance(path, int) and os.fspath(path) == str(layout.parent):
            return _stat_with(foreign, ino=original.st_ino)
        return real_stat(path, *args, **kwargs)
    monkeypatch.setattr(os, "stat", observed)
    with pytest.raises(sc.ScaffoldError, match="changed after the preview"):
        accept()
    assert list(layout.foreign.iterdir()) == []


def test_pinned_kit_stage_is_private_empty_owned_same_device(second):
    if Path("/dev") in second.parents:
        # The companion deliberately excludes all of /dev, including shm.
        with pytest.raises(kit._SkipCandidate):
            kit._create_pinned_stage(str(second), str(second.resolve()), ".stage-")
        assert list(second.iterdir()) == []
        return
    stage = kit._create_pinned_stage(str(second), str(second.resolve()), ".stage-")
    try:
        st = stage.path.stat()
        assert st.st_dev == second.stat().st_dev
        assert st.st_uid == os.geteuid()
        assert stat.S_IMODE(st.st_mode) == 0o700
        assert list(stage.path.iterdir()) == []
        stage.verify()
    finally:
        assert stage.remove() == "removed"
        stage.close()


def _route_response(tmp_path, monkeypatch, proposal, kind):
    if kind == "template":
        return _route_accept(tmp_path, monkeypatch, proposal)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    routes = load_submodule("dashboard.routes.workspace_routes")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    rows = {"identity": {"state": "ready", "proposal": proposal, "remember_options": False,
                         "kind": "kit", "home": routes._active_home(), "created": 0.0}}
    routes.accept_jobs._reset_for_tests()
    monkeypatch.setattr(routes, "_PROPOSALS", rows)
    monkeypatch.setattr(routes, "_take_expired_locked", lambda: [])
    monkeypatch.setattr(routes, "componentize_bridge", FakeVideoBridge())
    app = FastAPI()
    app.include_router(routes.router)
    with TestClient(app) as client:
        response = client.post("/scaffold/accept", json={"proposal_id": "identity", "confirm": True})
    return response, rows["identity"]["state"]


@pytest.mark.parametrize("kind", ["template", "kit"])
@pytest.mark.parametrize("when", ["refused", "failed-after-move"])
def test_dashboard_state_across_devices(second, tmp_path, monkeypatch, when, kind):
    parent = second / "projects"
    parent.mkdir()
    p, _ = _proposal(tmp_path, parent, kind)
    dest = p.dest if kind == "kit" else p.repos[0].dest
    if when == "refused":
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        with _redirect(parent, foreign):
            response, state = _route_response(tmp_path, monkeypatch, p, kind)
            assert response.status_code == 409, response.text
            assert state == "ready"
            assert response.json()["detail"]["created_dirs"] == []
            assert list(foreign.iterdir()) == []
    else:
        def failed(*args, **kwargs):
            raise RuntimeError("injected state write failure")
        monkeypatch.setattr(kit if kind == "kit" else sc, "record_project", failed)
        response, state = _route_response(tmp_path, monkeypatch, p, kind)
        assert response.status_code == 409, response.text
        assert state == "partial"
        assert response.json()["detail"]["created_dirs"] == [str(dest)]
        assert dest.is_dir()


def test_default_kit_stage_publication(second, tmp_path):
    projects = second / "projects"
    projects.mkdir()
    bridge = FakeVideoBridge()
    p = kit.propose_kit("video-production", "demo", {}, dest_root=projects, bridge=bridge)
    try:
        assert p.stage is not None
        if Path("/dev") in second.parents:
            assert p.staging_dir.stat().st_dev != second.stat().st_dev
        else:
            assert p.staging_dir.stat().st_dev == second.stat().st_dev
        kit.accept_kit(p, bridge=bridge, register=_register, db_path=tmp_path / "state.db")
        assert (p.dest / "AGENTS.md").is_file()
        assert not p.staging_dir.exists()
        assert [child.name for child in projects.iterdir()] == ["demo"]
    finally:
        p.stage.close()


class _Swapper:
    """A second thread swaps at the exact I/O boundary; never relies on timing."""
    def __init__(self, parent, foreign):
        self.parent, self.foreign = parent, foreign
        self.commands, self.answers = queue.Queue(), queue.Queue()
        self.saved = parent.with_name(parent.name + "-saved")
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
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
            except BaseException as exc:
                self.answers.put(exc)

    def call(self, command):
        self.commands.put(command)
        result = self.answers.get(timeout=30)
        if result is not None:
            raise result

    def close(self):
        self.commands.put("stop")
        self.thread.join(timeout=30)
        assert not self.thread.is_alive()


@pytest.mark.parametrize("kind", ["template", "kit"])
def test_publish_swap_loop(second, tmp_path, monkeypatch, request, kind):
    parent, foreign = tmp_path / "chosen", second / "foreign"
    parent.mkdir()
    foreign.mkdir()
    stage = kit._create_pinned_stage(str(tmp_path), str(tmp_path.resolve()), ".stage-")
    staged = stage.path / "project"
    staged.mkdir()
    (staged / "payload").write_text("original")
    plan = _plan(parent, staged)
    pin = (str(parent), (parent.stat().st_dev, parent.stat().st_ino))
    swapper = _Swapper(parent, foreign)
    real_move, real_rename = shutil.move, os.rename
    active = False
    def move(src, dst, *args, **kwargs):
        nonlocal active
        if not active and Path(src) == staged:
            swapper.call("swap")
            active = True
        return real_move(src, dst, *args, **kwargs)
    def rename(src, dst, *args, **kwargs):
        nonlocal active
        if not active and src == "project" and kwargs.get("src_dir_fd") is not None:
            swapper.call("swap")
            active = True
        return real_rename(src, dst, *args, **kwargs)
    if kind == "template":
        monkeypatch.setattr(shutil, "move", move)
    # Also intercept a future descriptor-relative template implementation;
    # otherwise removing shutil.move would silently remove the attack seam.
    monkeypatch.setattr(os, "rename", rename)
    escapes = lost_stage = refusals = 0
    start = time.monotonic()
    try:
        for _ in range(ITERATIONS):
            try:
                if kind == "template":
                    sc._publish_staged_repo(plan)
                else:
                    kit._move_pinned_into_place(stage, "project", plan.dest, pin)
            except sc.ScaffoldError:
                refusals += 1
            escaped = foreign / "project"
            escapes += int(escaped.exists())
            lost_stage += int(not staged.exists())
            if active:
                swapper.call("restore")
                active = False
            # Reset only the payload this iteration owns, never the foreign root.
            if escaped.exists():
                real_move(str(escaped), str(staged))
            if plan.dest.exists():
                real_move(str(plan.dest), str(staged))
        print("PUBLISH_RACE", json.dumps(dict(kind=kind, iterations=ITERATIONS, escapes=escapes,
              lost_stage=lost_stage, refusals=refusals, seconds=round(time.monotonic() - start, 3))))
        assert (escapes, lost_stage, refusals) == (0, 0, ITERATIONS)
        assert (staged / "payload").read_text() == "original"
        assert list(foreign.iterdir()) == []
    finally:
        if active:
            swapper.call("restore")
        swapper.close()
        stage.close()


def test_writer_swap_loop(second, tmp_path, monkeypatch, writer, request):
    if not hasattr(writer, "PinnedFolder"):
        request.node.add_marker(pytest.mark.xfail(strict=True, raises=AssertionError, reason="safe_write_bytes checks then opens a full path, following swapped ancestors"))
    chosen, foreign = tmp_path / "chosen", second / "foreign"
    chosen.mkdir()
    foreign.mkdir()
    (chosen / "root").mkdir()
    (foreign / "root").mkdir()
    root = chosen / "root"
    swapper = _Swapper(chosen, foreign)
    real_open = os.open
    active = False
    def opened(path, flags, *args, **kwargs):
        nonlocal active
        if flags & os.O_CREAT and not active and os.fspath(path).endswith("payload"):
            swapper.call("swap")
            active = True
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", opened)
    # os.open wrapping must not accidentally turn platform capability off.
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {opened})
    escapes = 0
    started = time.monotonic()
    try:
        for _ in range(ITERATIONS):
            with contextlib.suppress(writer.SafetyError):
                writer.safe_write_text(root, "payload", "original")
            escapes += int((foreign / "root/payload").exists())
            assert active
            swapper.call("restore")
            active = False
            for target in (root / "payload", foreign / "root/payload"):
                target.unlink(missing_ok=True)
        print("WRITE_RACE", json.dumps(dict(tree="pinned" if hasattr(writer, "PinnedFolder") else "release",
              iterations=ITERATIONS, escapes=escapes, seconds=round(time.monotonic() - started, 3))))
        assert escapes == 0
    finally:
        if active:
            swapper.call("restore")
        swapper.close()


@pytest.mark.parametrize("held", [False, True], ids=["recorded-numbers", "held-handle"])
def test_inode_reuse(second, tmp_path, writer, held):
    parent = second / "reused"
    parent.mkdir()
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "payload").write_text("original")
    plan = _plan(parent, staged)
    old = parent.stat()
    if held:
        if not hasattr(writer, "PinnedFolder"):
            pytest.skip("release helpers do not hold a preview folder handle")
        pin = writer.PinnedFolder(parent)
    else:
        pin = None
    reused = False
    attempts = 0
    try:
        for attempts in range(1, 4097):
            parent.rmdir()
            parent.mkdir()
            if parent.stat().st_ino == old.st_ino:
                reused = True
                break
        print("INODE_REUSE", json.dumps(dict(held=held, attempts=attempts, reused=reused,
              old=old.st_ino, new=parent.stat().st_ino, device=old.st_dev)))
        if held:
            assert not reused  # the deleted inode is still referenced by pin.fd
            with pytest.raises(writer.SafetyError):
                writer.safe_write_text(parent, "payload", "original", base=pin)
            assert list(parent.iterdir()) == []
        elif reused:
            # Numeric preview pins cannot identify an inode generation. This
            # acceptance is harmless here ONLY because the replacement is an
            # empty, same-owner directory at the same lexical and real path.
            assert parent.stat().st_uid == old.st_uid
            assert list(parent.iterdir()) == []
            sc._publish_staged_repo(plan)
            assert (plan.dest / "payload").read_text() == "original"
        else:
            with pytest.raises(sc.ScaffoldError, match="changed after the preview"):
                sc._publish_staged_repo(plan)
            assert staged.exists()
    finally:
        if pin is not None:
            pin.close()


def test_kit_numeric_preview_inode_reuse(second, tmp_path):
    parent = second / "reused"
    parent.mkdir()
    p, accept = _proposal(tmp_path, parent, "kit")
    original = parent.stat()
    reused = False
    attempts = 0
    for attempts in range(1, 4097):
        parent.rmdir()
        parent.mkdir()
        if parent.stat().st_ino == original.st_ino:
            reused = True
            break
    print("KIT_INODE_REUSE", json.dumps(dict(attempts=attempts, reused=reused,
          old=original.st_ino, new=parent.stat().st_ino, device=original.st_dev)))
    if reused:
        assert parent.stat().st_uid == original.st_uid and list(parent.iterdir()) == []
        accept()
        assert (p.dest / "AGENTS.md").is_file()
    else:
        with pytest.raises(sc.ScaffoldError, match="changed after the preview"):
            accept()
        assert p.staged.is_dir()


def test_cross_device_inode_collision_search(second, tmp_path):
    original = tmp_path / "recorded"
    original.mkdir()
    wanted = original.stat().st_ino
    matched = False
    attempts = 0
    for attempts in range(1, 4097):
        # Keep candidates allocated so this searches different live inode
        # numbers instead of repeatedly recycling a single ext4 inode.
        candidate = second / f"candidate-{attempts}"
        candidate.mkdir()
        matched = candidate.stat().st_ino == wanted
        if matched:
            break
    print("CROSS_DEVICE_INODE", json.dumps(dict(attempts=attempts, natural_match=matched,
          recorded=wanted, collision_tests="scoped stat injection")))


@pytest.mark.parametrize("check", ["no-escape", "truthful-partial"])
def test_nested_parent_swap_reports_creation(second, tmp_path, monkeypatch, check):
    parent, foreign = tmp_path / "chosen", second / "foreign"
    parent.mkdir()
    foreign.mkdir()
    p, _ = _proposal(tmp_path, parent / "nested")
    real_mkdir = os.mkdir
    redirected = None
    def mkdir(path, *args, **kwargs):
        nonlocal redirected
        if (os.fspath(path) == str(parent / "nested") or
                (os.fspath(path) == "nested" and kwargs.get("dir_fd") is not None)) and redirected is None:
            redirected = _redirect(parent, foreign)
            redirected.__enter__()
        return real_mkdir(path, *args, **kwargs)
    monkeypatch.setattr(os, "mkdir", mkdir)
    try:
        response, state = _route_accept(tmp_path, monkeypatch, p)
        assert response.status_code == 409, response.text
        assert p.repos[0].staged.exists()
        assert redirected is not None
        print("NESTED_SWAP", json.dumps(dict(state=state, detail=response.json()["detail"],
              foreign_children=[child.name for child in foreign.iterdir()])))
        if check == "no-escape":
            assert list(foreign.iterdir()) == []
        elif any(foreign.iterdir()):
            assert state == "partial", "An external folder was created: ready/Nothing was created is false"
        else:
            assert state == "ready"  # a fixed publisher refused before any creation
    finally:
        if redirected is not None:
            redirected.__exit__(None, None, None)


@pytest.mark.parametrize("caller", ["safe-write", "safe-mkdirs", "report"])
def test_held_folder_moved_into_protected_home(second, tmp_path, writer, monkeypatch, request, caller):
    chosen, protected = second / "chosen", second / "private-settings"
    chosen.mkdir()
    protected.mkdir()
    home_alias = tmp_path / "settings-link"
    home_alias.symlink_to(protected, target_is_directory=True)
    monkeypatch.setenv("HERMES_HOME", str(home_alias))
    pinned = hasattr(writer, "PinnedFolder")
    pin = writer.PinnedFolder(chosen) if pinned else None
    try:
        chosen.rename(protected / "moved")
        chosen.mkdir()
        kwargs = {"base": pin} if pinned else {}
        with contextlib.suppress(writer.SafetyError):
            if caller == "safe-write":
                writer.safe_write_text(chosen, "payload", "must-not-touch-settings", **kwargs)
            elif caller == "safe-mkdirs":
                writer.safe_mkdirs(chosen, "payload", **kwargs)
            else:
                reports = importlib.import_module(writer.__package__ + ".output_file")
                reports.write_output_text(chosen / "payload", "must-not-touch-settings",
                                          role="report", forbidden_roots=[protected], **kwargs)
        leaked = (protected / "moved/payload").exists()
        print("PROTECTED_MOVE", json.dumps(dict(tree="pinned" if pinned else "release", caller=caller,
              protected_written=leaked, visible_output=(chosen / "payload").exists())))
        assert not leaked, "A retained folder handle wrote inside the protected Hermes home"
    finally:
        if pin is not None:
            pin.close()


def test_pinned_open_compares_device_even_for_equal_inode(layout, writer, monkeypatch):
    if not hasattr(writer, "PinnedFolder"):
        pytest.skip("PinnedFolder is only present in the alternate helper tree")
    expected = layout.parent.stat()
    real_fstat = os.fstat
    def foreign_handle(path):
        assert path == str(layout.parent)
        return os.open(layout.foreign, os.O_RDONLY | os.O_DIRECTORY)
    def observed(fd):
        st = real_fstat(fd)
        if st.st_dev == layout.foreign.stat().st_dev:
            return _stat_with(st, ino=expected.st_ino)
        return st
    with monkeypatch.context() as patch:
        patch.setattr(writer, "_open_resolved_dir", foreign_handle)
        patch.setattr(os, "fstat", observed)
        with pytest.raises(writer.SafetyError, match="changed while it was opened"):
            writer.PinnedFolder(layout.parent)
    assert list(layout.foreign.iterdir()) == []


@pytest.mark.parametrize("collision", [False, True])
def test_held_ancestor_redirect_is_refused(layout, writer, monkeypatch, request, collision):
    if not hasattr(writer, "PinnedFolder"):
        pytest.skip("held-preview contract is only present in the alternate helper tree")
    root = layout.parent / "root"
    root.mkdir()
    (layout.foreign / "root").mkdir()
    original = root.stat()
    with writer.PinnedFolder(root) as pin, _redirect(layout.parent, layout.foreign) as saved:
        if collision:
            real_stat = os.stat
            def observed(path, *args, **kwargs):
                st = real_stat(path, *args, **kwargs)
                if not isinstance(path, int) and os.fspath(path) == str(root):
                    return _stat_with(st, ino=original.st_ino)
                return st
            monkeypatch.setattr(os, "stat", observed)
        refused = False
        try:
            writer.safe_write_text(root, "payload", "original", base=pin)
        except writer.SafetyError:
            refused = True
        assert not (layout.foreign / "root/payload").exists()
        print("HELD_REDIRECT", json.dumps(dict(collision=collision, refused=refused,
              stale_written=(saved / "root/payload").exists())))
        assert refused, "The saved folder is no longer at the chosen path; do not report a successful write there"


def test_pinned_callers_refuse_static_redirect(layout, writer):
    if not hasattr(writer, "PinnedFolder"):
        with _redirect(layout.parent, layout.foreign):
            with pytest.raises(writer.SafetyError, match="symlink"):
                writer.safe_write_text(layout.parent, "payload", "original")
        return
    with writer.PinnedFolder(layout.parent) as pin:
        with _redirect(layout.parent, layout.foreign):
            with pytest.raises(writer.SafetyError, match="symlink"):
                writer.safe_write_text(layout.parent, "payload", "original", base=pin)
            with pytest.raises(writer.SafetyError, match="symlink"):
                writer.safe_mkdirs(layout.parent, "child", base=pin)
            with pytest.raises(writer.SafetyError, match="symlink"):
                writer.PinnedFolder(layout.parent)
            assert list(layout.foreign.iterdir()) == []
