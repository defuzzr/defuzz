"""Creating projects when the projects folder is on another filesystem than home and temp.

Every test here is SKIPPED unless the environment variable DEFUZZ_SECOND_FS names a
writable folder on a different filesystem from the temp folder (checked by st_dev).
Each test writes only inside a fresh `t-<hex>` folder below that folder (removed after
the test) and below pytest's tmp_path, plus one shared `.pnpm-store` below DEFUZZ_SECOND_FS
so pnpm never falls back to a store at the root of that filesystem.

Layouts (F = first filesystem, the temp folder's; S = the second one):
  a     projects on S, staging is the default temp folder (on F)
  b     projects on S, an explicit staging folder on F (TMPDIR for the command and the
        dashboard, staging_parent for the Python API)
  c     projects on F, an explicit staging folder on S
  d     ~/Projects is a symlink to a folder on S and is used as the projects folder
  dsub  ~/Projects is a symlink to S and the projects folder is ~/Projects/work
  e     HOME and the Hermes home on F; projects and TMPDIR on S

Flows: `hermes defuzz new --template <id> --yes` (cli.main) with each template's real
check, the dashboard routes (propose -> accept inline, start-and-poll, cancel before the
move, failed check, refused accept), kits through the fake kit bridge (command, dashboard,
Python API with an explicit staging folder), desktop registration, TOOLS.lock, AGENTS.md,
and non-ASCII folder names.

Set DEFUZZ_XDEV_LOG to a file path to get one JSON line per cell (outcome, move kind,
timings, leftovers on both filesystems). Set DEFUZZ_XDEV_EXTRA_PATH to folders appended
to PATH when a template tool is installed outside it (for example the Go folder).
"""

from __future__ import annotations

import dataclasses
import functools
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli as cli_mod  # noqa: E402
from hermes_plugins.defuzz import componentize_bridge, kit_scaffold, scaffolder  # noqa: E402
from hermes_plugins.defuzz.state_store import get_project, state_db_path  # noqa: E402
from hermes_plugins.defuzz.templates import load_template, load_templates, templates_root  # noqa: E402
from tests.conftest import load_submodule  # noqa: E402
from tests.fake_kit_bridge import FakeKitBridge  # noqa: E402

SECOND_ENV = "DEFUZZ_SECOND_FS"
LOG_ENV = "DEFUZZ_XDEV_LOG"
EXTRA_PATH_ENV = "DEFUZZ_XDEV_EXTRA_PATH"
TEMPLATE_IDS = [spec.id for spec in load_templates()]
NODE_TEMPLATES = {"ts-node-golden", "web-golden"}
CORE_REAL = ["python-golden", "go-golden", "rust-golden"]
OK_LAYOUTS = ["a", "b", "c", "dsub", "e"]
UNICODE_NAME = "café-ünïcode"
STAGE_PREFIXES = ("adopt-scaffold-", ".adopt-scaffold-", ".adopt-move-")
KIT_ID = "video-production"
WAIT = 120.0

# Cells that fail today: (flow, layout, filesystem kind) -> reason. Filled from the runs.
KNOWN_BUGS: Dict[tuple, str] = {}


# --------------------------------------------------------------------------- helpers


_BASE_TMP = tempfile.gettempdir()  # read once, before any test points TMPDIR elsewhere


def _second_root() -> Path:
    raw = os.environ.get(SECOND_ENV, "").strip()
    if not raw:
        pytest.skip(f"set {SECOND_ENV} to a writable folder on another filesystem to run these")
    root = Path(raw)
    if not root.is_absolute() or not root.is_dir() or not os.access(root, os.W_OK | os.X_OK):
        pytest.skip(f"{SECOND_ENV}={raw} is not an absolute writable folder")
    if os.stat(root).st_dev == os.stat(_BASE_TMP).st_dev:
        pytest.skip(f"{SECOND_ENV}={raw} is on the same filesystem as the temp folder {_BASE_TMP}")
    return root


def _fs_kind(path: Path) -> str:
    try:
        with open("/proc/mounts", encoding="utf-8") as fh:
            mounts = [line.split()[:3] for line in fh]
    except OSError:
        return "unknown"
    real = os.path.realpath(path)
    best = ("", "unknown")
    for _dev, mnt, kind in mounts:
        mnt = mnt.replace("\\040", " ")
        if (real == mnt or real.startswith(mnt.rstrip("/") + "/")) and len(mnt) > len(best[0]):
            best = (mnt, kind)
    return best[1]


def _log(**cell: Any) -> None:
    path = os.environ.get(LOG_ENV)
    if not path:
        return
    cell.setdefault("second_fs", _fs_kind(_second_root()))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(cell, default=str, ensure_ascii=False) + "\n")


def _dev(path: os.PathLike[str] | str) -> int:
    return os.stat(os.path.realpath(path)).st_dev


def _rmtree_writable(path: Path) -> None:
    def onerror(func, p, _exc):
        try:
            os.chmod(os.path.dirname(p), stat.S_IRWXU)
            os.chmod(p, stat.S_IRWXU)
        except OSError:
            pass
        try:
            func(p)
        except OSError:
            pass

    shutil.rmtree(path, onerror=onerror)


def _system_refusal(lay: "Layout") -> Optional[str]:
    """The existing rule: a projects folder inside a system folder (/dev/shm is below /dev) is refused."""
    if not str(lay.projects_real).startswith("/dev/"):
        return None
    return (
        f"Cannot use system folder {lay.projects} as the projects folder. "
        f"Choose a folder in your home directory such as {lay.home / 'Tools'}."
    )


def _assert_refused_cleanly(lay: "Layout", flow: str, got: str, expected: str, **extra: Any) -> None:
    scan = lay.scan([])
    _log(flow=flow, layout=lay.id, outcome="refused", message=got, leftovers=scan, **extra)
    assert got == expected
    assert scan["first"] == [] and scan["second"] == [] and scan["tmpdir"] == [] and scan["staging"] == []
    assert [p for p in scan["projects"] if p != "work"] == []


def _refused_cli(lay: "Layout", capsys: Any, flow: str, argv: List[str], expected: str, **extra: Any) -> None:
    rc = cli_mod.main(argv)
    _out, err = capsys.readouterr()
    assert rc == 1, err
    _assert_refused_cleanly(lay, flow, err.strip(), expected, **extra)


def _refused_dash(lay: "Layout", client: Any, flow: str, body: Dict[str, Any], expected: str, **extra: Any) -> None:
    resp = client.post("/scaffold/propose", json=body)
    assert resp.status_code == 400, resp.text
    _assert_refused_cleanly(lay, flow, resp.json()["detail"], expected, **extra)


@dataclasses.dataclass
class Layout:
    id: str
    first: Path
    second: Path
    second_root: Path
    home: Path
    projects: Path  # as the user writes it
    tmpdir: Path
    staging: Optional[Path]  # explicit staging parent for the Python API

    @property
    def projects_real(self) -> Path:
        return Path(os.path.realpath(self.projects))

    def dest(self, folder: str) -> Path:
        return self.projects / folder

    def pnpm_store_for(self, where: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Pin pnpm's store on the second filesystem when it works there (never the mount root)."""
        if _dev(where) == _dev(self.second_root):
            store = self.second_root / ".pnpm-store"
            store.mkdir(exist_ok=True)
            monkeypatch.setenv("npm_config_store_dir", str(store))
        else:
            monkeypatch.delenv("npm_config_store_dir", raising=False)

    def scan(self, skip: List[Path]) -> Dict[str, Any]:
        """Staging and temp leftovers on both filesystems, plus what the projects folder holds."""
        skip_real = {os.path.realpath(p) for p in skip}

        def walk(root: Path) -> List[str]:
            found: List[str] = []
            for dirpath, dirnames, filenames in os.walk(root):
                keep = []
                for d in dirnames:
                    full = os.path.join(dirpath, d)
                    if d.startswith(STAGE_PREFIXES):
                        found.append(full)
                    elif os.path.realpath(full) in skip_real or d in (
                        ".git", "node_modules", "target", ".venv", ".pnpm-store", "home"
                    ):
                        continue
                    else:
                        keep.append(d)
                dirnames[:] = keep
                found.extend(os.path.join(dirpath, f) for f in filenames if f.startswith(STAGE_PREFIXES))
            return sorted(found)

        def listing(p: Path) -> List[str]:
            try:
                return sorted(os.listdir(p))
            except OSError:
                return []

        return {
            "first": walk(self.first),
            "second": walk(self.second),
            "tmpdir": listing(self.tmpdir),
            "staging": listing(self.staging) if self.staging else [],
            "projects": listing(self.projects_real),
        }


def _make_layout(lid: str, first: Path, second: Path, second_root: Path, monkeypatch: pytest.MonkeyPatch) -> Layout:
    home = first / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE", "HERMES_REAL_HOME"):
        monkeypatch.setenv(key, str(home))
    staging: Optional[Path] = None
    if lid == "a":
        projects, tmpdir = second / "projects", first / "tmp"
    elif lid == "b":
        projects, tmpdir = second / "projects", first / "staging"
        staging = tmpdir
    elif lid == "c":
        projects, tmpdir = first / "projects", second / "staging"
        staging = tmpdir
    elif lid in ("d", "dsub"):
        real = second / "projects"
        (real / "work").mkdir(parents=True)
        (home / "Projects").symlink_to(real, target_is_directory=True)
        projects = home / "Projects" if lid == "d" else home / "Projects" / "work"
        tmpdir = first / "tmp"
    elif lid == "e":
        projects, tmpdir = second / "projects", second / "tmp"
    else:  # pragma: no cover
        raise AssertionError(lid)
    tmpdir.mkdir(parents=True, exist_ok=True)
    if not os.path.lexists(projects):
        projects.mkdir(parents=True)
    monkeypatch.setenv("TMPDIR", str(tmpdir))
    monkeypatch.setattr(tempfile, "tempdir", str(tmpdir))
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(projects))
    hermes_home = Path(os.environ["HERMES_HOME"])
    assert _dev(hermes_home) != _dev(second), "the Hermes home must stay on the first filesystem"
    return Layout(lid, first, second, second_root, home, projects, tmpdir, staging)


@pytest.fixture()
def second(tmp_path: Path) -> Any:
    root = _second_root()
    if _dev(tmp_path) == _dev(root):
        pytest.skip("pytest's tmp_path is on the second filesystem")
    area = root / f"t-{secrets.token_hex(4)}"
    area.mkdir()
    try:
        yield root, area
    finally:
        assert area.parent == root and area.name.startswith("t-") and len(area.name) == 10
        _rmtree_writable(area)


@pytest.fixture()
def layout_factory(tmp_path: Path, second: Any, monkeypatch: pytest.MonkeyPatch) -> Callable[[str], Layout]:
    root, area = second
    extra = os.environ.get(EXTRA_PATH_ENV, "").strip()
    if extra:
        monkeypatch.setenv("PATH", os.environ.get("PATH", "") + os.pathsep + extra)
    first = tmp_path / "first"
    first.mkdir()
    return lambda lid: _make_layout(lid, first, area, root, monkeypatch)


@pytest.fixture()
def desktop(monkeypatch: pytest.MonkeyPatch) -> List[Dict[str, Any]]:
    """The public desktop_project tool, recorded (desktop registration is really dispatched)."""
    import tools.registry as tools_registry

    calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(tools_registry.registry, "get_entry", lambda _name: object())

    def dispatch(name: str, args: Dict[str, Any], **_kw: Any) -> str:
        calls.append({"tool": name, **args})
        return json.dumps({"success": True, "id": f"desk-{len(calls)}", "name": args.get("name"), "path": args.get("path")})

    monkeypatch.setattr(tools_registry.registry, "dispatch", dispatch)
    return calls


class Spy:
    """Times the move into place and tells whether it was a rename or a copy."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, scaf: Any = scaffolder, kit: Any = kit_scaffold) -> None:
        self.active = False
        self.copies: List[str] = []
        self.move_s = 0.0
        self.results: List[Any] = []
        self.stage_parents: List[str] = []
        real_copytree = shutil.copytree

        def copytree(src: Any, dst: Any, *a: Any, **k: Any) -> Any:
            if self.active:
                self.copies.append(f"shutil.copytree {src} -> {dst}")
            return real_copytree(src, dst, *a, **k)

        monkeypatch.setattr(shutil, "copytree", copytree)
        real_fd_copy = kit._copy_tree_fd
        depth = {"n": 0}

        def copy_tree_fd(src_fd: int, dst_fd: int) -> None:
            if self.active and depth["n"] == 0:
                self.copies.append("kit _copy_tree_fd (by handle)")
            depth["n"] += 1
            try:
                return real_fd_copy(src_fd, dst_fd)
            finally:
                depth["n"] -= 1

        monkeypatch.setattr(kit, "_copy_tree_fd", copy_tree_fd)
        for mod, name in (
            (scaf, "_publish_staged_repo"),
            (kit, "_publish_staged_repo"),
            (kit, "_move_pinned_into_place"),
        ):
            monkeypatch.setattr(mod, name, self._timed(getattr(mod, name)))

    def _timed(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*a: Any, **k: Any) -> Any:
            self.active = True
            start = time.monotonic()
            try:
                return fn(*a, **k)
            finally:
                self.move_s += time.monotonic() - start
                self.active = False

        return wrapper

    @property
    def kind(self) -> str:
        return "copy" if self.copies else "rename"


def _fake_check(seconds: float = 0.0, code: int = 0) -> Callable[[Any], Any]:
    def make(check: Any) -> Any:
        return dataclasses.replace(
            check,
            cmd=(sys.executable, "-c", f"import sys, time; time.sleep({seconds}); sys.exit({code})"),
            prepare=(),
            extra_cmds=(),
        )

    return make


def _wrap_propose(
    monkeypatch: pytest.MonkeyPatch, spy: Spy, check: Optional[Callable[[Any], Any]], scaf: Any = scaffolder
) -> None:
    real = getattr(scaf.propose, "__wrapped__", scaf.propose)

    @functools.wraps(real)
    def propose(*a: Any, **k: Any) -> Any:
        proposal = real(*a, **k)
        spy.stage_parents.append(str(Path(proposal.staging_dir).parent))
        if check is not None:
            for plan in proposal.repos:
                if plan.check is not None:
                    plan.check = check(plan.check)
        return proposal

    monkeypatch.setattr(scaf, "propose", propose)
    if scaf is scaffolder:
        monkeypatch.setattr(cli_mod, "propose", propose)


def _wrap_accept(monkeypatch: pytest.MonkeyPatch, spy: Spy) -> None:
    real = scaffolder.accept

    @functools.wraps(real)
    def accept(*a: Any, **k: Any) -> Any:
        result = real(*a, **k)
        spy.results.append(result)
        return result

    monkeypatch.setattr(scaffolder, "accept", accept)
    monkeypatch.setattr(cli_mod, "accept", accept)


def _needs_missing(template_id: str) -> List[str]:
    spec = load_template(templates_root() / template_id)
    return [n for n in spec.needs if n.strip() and shutil.which(n) is None]


def _expected_folder(template_id: str, name: str) -> str:
    from hermes_plugins.defuzz.naming import folder_name, is_ascii_folder, slugify

    allowed = getattr(scaffolder, "UNICODE_FOLDER_TEMPLATES", frozenset())
    folder = folder_name(name)
    return folder if template_id in allowed and not is_ascii_folder(folder) else slugify(name)


def _expected_kit_folder(name: str) -> str:
    from hermes_plugins.defuzz.naming import folder_name, is_ascii_folder, slugify

    folder = folder_name(name)
    return folder if getattr(kit_scaffold, "UNICODE_FOLDER_KITS", False) and not is_ascii_folder(folder) else slugify(name)


def _assert_project(repo: Path, desktop: List[Dict[str, Any]], *, tools_lock: bool = True) -> None:
    assert repo.is_dir() and not repo.is_symlink(), repo
    assert (repo / ".git").is_dir()
    assert (repo / "AGENTS.md").is_file()
    assert (repo / ".adopt" / "rules.json").is_file()
    if tools_lock:
        assert (repo / "TOOLS.lock").is_file()
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True, check=True)
    assert status.stdout == "", status.stdout
    assert any(c.get("path") == str(repo) for c in desktop), desktop
    assert get_project(repo, db_path=state_db_path()) is not None


def _assert_no_stage_left(lay: Layout, scan: Dict[str, Any], *extra_stage: Path) -> None:
    """No Defuzz staging folder is left on either filesystem. Temp files the template's own
    tools write into TMPDIR (MSBuildTemp*, uv locks, pytest-of-*, node-compile-cache) are
    the tools' and are only recorded, under 'tmpdir'."""
    assert scan["first"] == [] and scan["second"] == [], scan
    assert [n for n in scan["tmpdir"] if n.startswith(STAGE_PREFIXES)] == [], scan
    assert [n for n in scan["staging"] if n.startswith(STAGE_PREFIXES)] == [], scan
    for p in extra_stage:
        assert not os.path.lexists(p), p


def _run_ci_in_dest(lay: Layout, template_id: str, repo: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    """The template's own CI commands, run again in the delivered tree (as test_accepted_scaffold_ci does)."""
    spec = load_template(templates_root() / template_id)
    check = spec.repos[0].check
    assert check is not None
    if template_id in NODE_TEMPLATES:
        lay.pnpm_store_for(repo, monkeypatch)
    cwd = repo if check.cwd == "." else repo / check.cwd
    start = time.monotonic()
    for command in [list(c) for c in check.ci_commands()]:
        proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=900, env=dict(os.environ))
        assert proc.returncode == 0, f"{command}\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}"
    return {"dest_ci_s": round(time.monotonic() - start, 2)}


def _xfail_known(request: pytest.FixtureRequest, flow: str, lid: str) -> None:
    kind = _fs_kind(_second_root())
    reason = KNOWN_BUGS.get((flow, lid, kind)) or KNOWN_BUGS.get((flow, lid, "*"))
    if reason:
        request.node.add_marker(pytest.mark.xfail(strict=True, reason=reason))


# ------------------------------------------------------------- command line, real checks


REAL_CELLS = [("a", t) for t in TEMPLATE_IDS] + [(lid, t) for lid in ("b", "c", "dsub", "e") for t in CORE_REAL]
REAL_CELLS += [(lid, t) for lid in ("c", "e") for t in TEMPLATE_IDS if t not in CORE_REAL]


@pytest.mark.skipif(os.environ.get("ADOPT_SKIP_SLOW") == "1", reason="ADOPT_SKIP_SLOW=1")
@pytest.mark.parametrize("lid,template_id", REAL_CELLS, ids=[f"{lid}-{t}" for lid, t in REAL_CELLS])
def test_cli_new_template_real_check(
    request, layout_factory, desktop, monkeypatch, capsys, lid, template_id
) -> None:
    _xfail_known(request, "cli-template-real", lid)
    lay = layout_factory(lid)
    refusal = _system_refusal(lay)
    if refusal:
        return _refused_cli(lay, capsys, "cli-template-real", ["new", "--template", template_id, "--name", "Xdev Demo",
                            "--yes", "--dest-root", str(lay.projects)], refusal, template=template_id)
    missing = _needs_missing(template_id)
    if missing:
        pytest.skip(f"{template_id} needs {missing}, not installed here")
    for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONPATH"):
        monkeypatch.delenv(key, raising=False)
    if template_id in NODE_TEMPLATES:
        lay.pnpm_store_for(lay.tmpdir, monkeypatch)
    spy = Spy(monkeypatch)
    _wrap_propose(monkeypatch, spy, None)
    _wrap_accept(monkeypatch, spy)
    name = "Xdev Demo"
    start = time.monotonic()
    rc = cli_mod.main(
        ["new", "--template", template_id, "--name", name, "--yes", "--dest-root", str(lay.projects), "--timeout", "1500"]
    )
    took = round(time.monotonic() - start, 2)
    out, err = capsys.readouterr()
    repo = lay.dest("xdev-demo")
    scan = lay.scan([lay.projects_real / "xdev-demo"])
    cell = dict(flow="cli-template-real", layout=lid, template=template_id, rc=rc, total_s=took,
                move=spy.kind, move_s=round(spy.move_s, 3), stage_parent=spy.stage_parents,
                leftovers=scan, err=err.strip()[-600:])
    if rc != 0:
        _log(**cell, outcome="failed")
    assert rc == 0, err
    result = spy.results[0].repos[0]
    cell.update(check=result.get("check"), outcome="created")
    expected = "rename" if _dev(spy.stage_parents[0]) == _dev(lay.projects_real) else "copy"
    assert spy.kind == expected, spy.copies
    assert result.get("check") == "ok", result
    _assert_project(repo, desktop)
    _assert_no_stage_left(lay, scan)
    cell.update(_run_ci_in_dest(lay, template_id, repo, monkeypatch))
    _log(**cell)


# ----------------------------------------------- the symlinked ~/Projects (layout d)


def test_symlinked_projects_folder_is_refused_everywhere_but_the_api(
    request, layout_factory, desktop, monkeypatch, capsys
) -> None:
    lay = layout_factory("d")
    link = lay.projects
    assert link.is_symlink()
    expected = f"Cannot use {link} because it is a symbolic link. Choose the real folder instead."
    template_id = "python-golden"
    spy = Spy(monkeypatch)
    _wrap_propose(monkeypatch, spy, _fake_check())
    # 1. Command line with --dest-root ~/Projects.
    rc = cli_mod.main(["new", "--template", template_id, "--name", "Link Demo", "--yes", "--dest-root", "~/Projects"])
    out, err = capsys.readouterr()
    assert rc == 1 and err.strip() == expected, err
    # 2. Command line with only HERMES_PROJECTS_ROOT pointing at the link.
    rc_env = cli_mod.main(["new", "--template", template_id, "--name", "Link Demo", "--yes"])
    _out, err_env = capsys.readouterr()
    # 3. Dashboard propose.
    api = load_submodule("dashboard.plugin_api")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    routes = api._load("dashboard.routes.workspace_routes")
    with routes._LOCK:
        routes._PROPOSALS.clear()
    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)
    resp = client.post("/scaffold/propose", json={"template_id": template_id, "name": "Link Demo",
                                                  "answers": {}, "dest_root": str(link)})
    scan = lay.scan([])
    assert not any(os.scandir(lay.projects_real / "work")) and sorted(os.listdir(lay.projects_real)) == ["work"]
    assert scan["first"] == [] and scan["second"] == [] and scan["tmpdir"] == []
    # 4. The Python API (not a user entry point) takes the link and creates through it.
    proposal = scaffolder.propose(load_template(templates_root() / template_id), "Api Link", {}, dest_root=link)
    result = scaffolder.accept(proposal, db_path=state_db_path(), timeout_s=600)
    api_repo = Path(result.repos[0]["path"])
    _log(flow="symlinked-projects-root", layout="d", outcome="refused", cli_rc=rc, cli_err=err.strip(),
         cli_env_rc=rc_env, cli_env_err=err_env.strip(), dashboard_status=resp.status_code,
         dashboard_detail=resp.json().get("detail"), api_created=str(api_repo), api_move=spy.kind,
         leftovers=lay.scan([lay.projects_real / "api-link"]))
    assert rc_env == 1 and err_env.strip() == expected, err_env
    assert resp.status_code == 400 and resp.json()["detail"] == expected, resp.text
    assert api_repo == link / "api-link" and (lay.projects_real / "api-link" / ".git").is_dir()
    assert spy.kind == "copy"


# ------------------------------------------------------------ dashboard routes


@pytest.fixture()
def dash(monkeypatch: pytest.MonkeyPatch) -> Any:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    jobs = api._load("dashboard.routes.accept_jobs")
    fake = FakeKitBridge()
    fake.install(monkeypatch, routes.componentize_bridge)
    routes._reset_kit_cache_for_tests()
    jobs._reset_for_tests()
    with routes._LOCK:
        routes._PROPOSALS.clear()
    app = FastAPI()
    app.include_router(api.router)
    yield TestClient(app), routes, jobs, fake
    jobs._reset_for_tests()
    with routes._LOCK:
        routes._PROPOSALS.clear()


def _poll(client: Any, pid: str, until: Callable[[Dict[str, Any]], bool], limit: float = WAIT) -> Dict[str, Any]:
    end = time.monotonic() + limit
    while time.monotonic() < end:
        body = client.get(f"/scaffold/accept/{pid}").json()
        if until(body):
            return body
        time.sleep(0.02)
    raise AssertionError(f"no answer in {limit}s: {body}")


def _propose_template(client: Any, lay: Layout, template_id: str, name: str) -> Dict[str, Any]:
    resp = client.post("/scaffold/propose", json={"template_id": template_id, "name": name, "answers": {},
                                                  "dest_root": str(lay.projects)})
    assert resp.status_code == 200, resp.text
    return resp.json()


DASH_CELLS = [(lid, t, n) for lid in OK_LAYOUTS for t in TEMPLATE_IDS for n in ("Xdev Dash", UNICODE_NAME)]


@pytest.mark.parametrize(
    "lid,template_id,name", DASH_CELLS, ids=[f"{lid}-{t}-{'uni' if n != 'Xdev Dash' else 'ascii'}" for lid, t, n in DASH_CELLS]
)
def test_dashboard_template_propose_accept(request, layout_factory, desktop, dash, monkeypatch, lid, template_id, name) -> None:
    _xfail_known(request, "dash-template", lid)
    lay = layout_factory(lid)
    refusal = _system_refusal(lay)
    if refusal:
        return _refused_dash(lay, dash[0], "dash-template", {"template_id": template_id, "name": name, "answers": {},
                             "dest_root": str(lay.projects)}, refusal, template=template_id, name=name)
    missing = _needs_missing(template_id)
    if missing:
        pytest.skip(f"{template_id} needs {missing}, not installed here")
    client, routes, jobs, _fake = dash
    spy = Spy(monkeypatch, routes.scaffolder, routes.kit_scaffold)
    _wrap_propose(monkeypatch, spy, _fake_check(), routes.scaffolder)
    folder = _expected_folder(template_id, name)
    body = _propose_template(client, lay, template_id, name)
    assert body["tree"][0]["dest"] == str(lay.dest(folder))
    start = time.monotonic()
    resp = client.post("/scaffold/accept", json={"proposal_id": body["proposal_id"], "confirm": True})
    took = round(time.monotonic() - start, 2)
    scan = lay.scan([lay.projects_real / folder])
    cell = dict(flow="dash-template", layout=lid, template=template_id, name=name, http=resp.status_code,
                total_s=took, move=spy.kind, move_s=round(spy.move_s, 3), stage_parent=spy.stage_parents, leftovers=scan)
    if resp.status_code != 200:
        _log(**cell, outcome="failed", detail=resp.json().get("detail"))
    assert resp.status_code == 200, resp.text
    final = resp.json()
    assert final["status"] == "created" and final["repos"][0]["check"] == "ok", final
    assert final["repos"][0]["path"] == str(lay.dest(folder))
    expected = "rename" if _dev(spy.stage_parents[0]) == _dev(lay.projects_real) else "copy"
    assert spy.kind == expected
    _assert_project(lay.dest(folder), desktop)
    if name != "Xdev Dash":
        assert unicodedata.normalize("NFC", lay.dest(folder).name) == folder
    _assert_no_stage_left(lay, scan)
    _log(**cell, outcome="created", check="ok")


@pytest.mark.parametrize("lid", OK_LAYOUTS)
def test_dashboard_template_start_poll_cancel_fail_refuse(request, layout_factory, desktop, dash, monkeypatch, lid) -> None:
    """One template through every dashboard path: 202 then polled to done, a cancel during
    the check, a failed check and a refused accept; leftovers recorded after each."""
    _xfail_known(request, "dash-template-paths", lid)
    lay = layout_factory(lid)
    refusal = _system_refusal(lay)
    if refusal:
        return _refused_dash(lay, dash[0], "dash-template-paths", {"template_id": "python-golden", "name": "Poll Demo",
                             "answers": {}, "dest_root": str(lay.projects)}, refusal)
    client, routes, jobs, _fake = dash
    template_id = "python-golden"
    spy = Spy(monkeypatch, routes.scaffolder, routes.kit_scaffold)
    cells: Dict[str, Any] = {}

    # 1. start-and-poll: the check takes 1.5 s, the route waits 0.05 s.
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", 0.05)
    _wrap_propose(monkeypatch, spy, _fake_check(seconds=1.5), routes.scaffolder)
    pid = _propose_template(client, lay, template_id, "Poll Demo")["proposal_id"]
    t0 = time.monotonic()
    first = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    assert first.status_code == 202, first.text
    assert first.json()["status"] == "running" and first.json()["poll"] == f"/scaffold/accept/{pid}"
    done = _poll(client, pid, lambda b: b["status"] != "running")
    cells["poll"] = dict(first=first.status_code, final=done["status"], total_s=round(time.monotonic() - t0, 2),
                         move=spy.kind, leftovers=lay.scan([lay.projects_real / "poll-demo"]))
    assert done["status"] == "done" and done["result"]["status"] == "created", done
    _assert_project(lay.dest("poll-demo"), desktop)
    _assert_no_stage_left(lay, cells["poll"]["leftovers"])

    # 2. cancel while the check runs (before the point of no return).
    _wrap_propose(monkeypatch, spy, _fake_check(seconds=60), routes.scaffolder)
    pid = _propose_template(client, lay, template_id, "Stop Demo")["proposal_id"]
    staging = Path(routes._PROPOSALS[pid]["proposal"].staging_dir)
    assert client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True}).status_code == 202
    _poll(client, pid, lambda b: b.get("step") == jobs.STEP_CHECK, limit=60)
    time.sleep(0.5)
    t0 = time.monotonic()
    cancel = client.post("/scaffold/cancel", json={"proposal_id": pid})
    cancel_s = round(time.monotonic() - t0, 2)
    after_cancel = lay.scan([])
    staging_kept = staging.is_dir()
    discard = client.post("/scaffold/discard", json={"proposal_id": pid})
    after_discard = lay.scan([lay.projects_real / "poll-demo"])
    cells["cancel"] = dict(answer=cancel.json(), cancel_s=cancel_s, staging=str(staging), staging_kept=staging_kept,
                           leftovers_after_cancel=after_cancel, discard=discard.status_code,
                           leftovers_after_discard=after_discard)
    assert cancel.json() == {"status": "cancelled", "proposal_id": pid}, cancel.text
    assert cancel_s < 20
    assert not os.path.lexists(lay.dest("stop-demo"))
    assert staging_kept and discard.status_code == 200
    _assert_no_stage_left(lay, after_discard, staging)

    # 3. a failed check: 409 with the check output, staging kept for inspection.
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", 60.0)
    _wrap_propose(monkeypatch, spy, _fake_check(code=1), routes.scaffolder)
    pid = _propose_template(client, lay, template_id, "Fail Demo")["proposal_id"]
    staging = Path(routes._PROPOSALS[pid]["proposal"].staging_dir)
    failed = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    after_fail = lay.scan([lay.projects_real / "poll-demo"])
    discard = client.post("/scaffold/discard", json={"proposal_id": pid})
    cells["failed_check"] = dict(http=failed.status_code, detail=failed.json().get("detail"), staging=str(staging),
                                 leftovers_after_fail=after_fail, discard=discard.status_code,
                                 leftovers_after_discard=lay.scan([lay.projects_real / "poll-demo"]))
    assert failed.status_code == 409 and failed.json()["detail"]["keep_staging"] is True, failed.text
    assert failed.json()["detail"]["created_dirs"] == []
    assert not os.path.lexists(lay.dest("fail-demo"))
    assert discard.status_code == 200
    _assert_no_stage_left(lay, cells["failed_check"]["leftovers_after_discard"], staging)

    # 4. a refused accept: the destination appeared after the preview.
    _wrap_propose(monkeypatch, spy, _fake_check(), routes.scaffolder)
    pid = _propose_template(client, lay, template_id, "Taken Demo")["proposal_id"]
    staging = Path(routes._PROPOSALS[pid]["proposal"].staging_dir)
    (lay.projects_real / "taken-demo").mkdir()
    refused = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    after_refused = lay.scan([lay.projects_real / "poll-demo", lay.projects_real / "taken-demo"])
    discard = client.post("/scaffold/discard", json={"proposal_id": pid})
    cells["refused"] = dict(http=refused.status_code, detail=refused.json().get("detail"),
                            leftovers_after_refused=after_refused, discard=discard.status_code,
                            leftovers_after_discard=lay.scan([lay.projects_real / "poll-demo", lay.projects_real / "taken-demo"]))
    _log(flow="dash-template-paths", layout=lid, template=template_id, **cells)
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"]["created_dirs"] == []
    assert list((lay.projects_real / "taken-demo").iterdir()) == []
    assert discard.status_code == 200
    _assert_no_stage_left(lay, cells["refused"]["leftovers_after_discard"], staging)


def _gate_kit(routes: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    real = routes.kit_scaffold.accept_kit
    entered, gate = threading.Event(), threading.Event()

    @functools.wraps(real)
    def slow(proposal: Any, **kwargs: Any) -> Any:
        entered.set()
        gate.wait(30)
        return real(proposal, **kwargs)

    monkeypatch.setattr(routes.kit_scaffold, "accept_kit", slow)
    return entered, gate, real


def _propose_kit(client: Any, lay: Layout, name: str) -> Dict[str, Any]:
    resp = client.post("/scaffold/propose", json={"kit_id": KIT_ID, "name": name, "answers": {"building": "video"},
                                                  "dest_root": str(lay.projects)})
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.parametrize("lid", OK_LAYOUTS)
def test_dashboard_kit_paths(request, layout_factory, desktop, dash, monkeypatch, lid) -> None:
    _xfail_known(request, "dash-kit", lid)
    lay = layout_factory(lid)
    refusal = _system_refusal(lay)
    if refusal:
        return _refused_dash(lay, dash[0], "dash-kit", {"kit_id": KIT_ID, "name": "Xdev Kit",
                             "answers": {"building": "video"}, "dest_root": str(lay.projects)}, refusal)
    client, routes, jobs, fake = dash
    spy = Spy(monkeypatch, routes.scaffolder, routes.kit_scaffold)
    cells: Dict[str, Any] = {}

    # 1. inline create (also a Unicode folder).
    for name in ("Xdev Kit", UNICODE_NAME):
        folder = _expected_kit_folder(name)
        body = _propose_kit(client, lay, name)
        stage = Path(routes._PROPOSALS[body["proposal_id"]]["proposal"].staging_dir)
        spy.copies.clear()
        spy.move_s = 0.0
        t0 = time.monotonic()
        resp = client.post("/scaffold/accept", json={"proposal_id": body["proposal_id"], "confirm": True})
        scan = lay.scan([lay.projects_real / f for f in os.listdir(lay.projects_real) if not f.startswith(STAGE_PREFIXES)])
        cells[f"create-{folder}"] = dict(http=resp.status_code, total_s=round(time.monotonic() - t0, 2), move=spy.kind,
                                         move_s=round(spy.move_s, 3), stage_parent=str(stage.parent), leftovers=scan)
        if resp.status_code != 200:
            _log(flow="dash-kit", layout=lid, outcome="failed", detail=resp.json().get("detail"), **cells)
        assert resp.status_code == 200, resp.text
        assert resp.json()["dest"] == str(lay.dest(folder))
        expected = "rename" if _dev(stage.parent) == _dev(lay.projects_real) else "copy"
        assert spy.kind == expected
        _assert_project(lay.dest(folder), desktop, tools_lock=False)
        _assert_no_stage_left(lay, scan, stage)

    # 2. start-and-poll.
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", 0.05)
    entered, gate, real = _gate_kit(routes, monkeypatch)
    pid = _propose_kit(client, lay, "Poll Kit")["proposal_id"]
    first = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    assert first.status_code == 202 and entered.wait(10)
    gate.set()
    done = _poll(client, pid, lambda b: b["status"] != "running")
    cells["poll"] = dict(first=first.status_code, final=done["status"])
    assert done["status"] == "done" and done["result"]["status"] == "created", done

    # 3. cancel before the move.
    monkeypatch.setattr(routes.kit_scaffold, "accept_kit", real)
    entered, gate, _ = _gate_kit(routes, monkeypatch)
    pid = _propose_kit(client, lay, "Stop Kit")["proposal_id"]
    stage = Path(routes._PROPOSALS[pid]["proposal"].staging_dir)
    assert client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True}).status_code == 202
    assert entered.wait(10)
    threading.Timer(0.1, gate.set).start()
    cancel = client.post("/scaffold/cancel", json={"proposal_id": pid})
    after_cancel = lay.scan([lay.projects_real / f for f in os.listdir(lay.projects_real) if not f.startswith(STAGE_PREFIXES)])
    stage_kept = stage.is_dir()
    discard = client.post("/scaffold/discard", json={"proposal_id": pid})
    after_discard = lay.scan([lay.projects_real / f for f in os.listdir(lay.projects_real) if not f.startswith(STAGE_PREFIXES)])
    cells["cancel"] = dict(answer=cancel.json(), stage=str(stage), stage_kept=stage_kept,
                           leftovers_after_cancel=after_cancel, discard=discard.status_code,
                           leftovers_after_discard=after_discard)
    assert cancel.json() == {"status": "cancelled", "proposal_id": pid}, cancel.text
    assert not os.path.lexists(lay.dest("stop-kit")) and stage_kept and discard.status_code == 200
    _assert_no_stage_left(lay, after_discard, stage)

    # 4. failed kit check, then 5. refused accept (destination appeared).
    monkeypatch.setattr(routes.kit_scaffold, "accept_kit", real)
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", 60.0)
    monkeypatch.setattr(fake, "check_ok", False)
    pid = _propose_kit(client, lay, "Fail Kit")["proposal_id"]
    stage = Path(routes._PROPOSALS[pid]["proposal"].staging_dir)
    failed = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    keep = lambda: [lay.projects_real / f for f in os.listdir(lay.projects_real) if not f.startswith(STAGE_PREFIXES)]  # noqa: E731
    after_fail = lay.scan(keep())
    discard = client.post("/scaffold/discard", json={"proposal_id": pid})
    cells["failed_check"] = dict(http=failed.status_code, detail=failed.json().get("detail"), stage=str(stage),
                                 leftovers_after_fail=after_fail, discard=discard.status_code,
                                 leftovers_after_discard=lay.scan(keep()))
    assert failed.status_code == 409 and failed.json()["detail"]["created_dirs"] == [], failed.text
    assert discard.status_code == 200
    _assert_no_stage_left(lay, cells["failed_check"]["leftovers_after_discard"], stage)
    monkeypatch.setattr(fake, "check_ok", True)
    pid = _propose_kit(client, lay, "Taken Kit")["proposal_id"]
    stage = Path(routes._PROPOSALS[pid]["proposal"].staging_dir)
    (lay.projects_real / "taken-kit").mkdir()
    refused = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    after_refused = lay.scan(keep())
    discard = client.post("/scaffold/discard", json={"proposal_id": pid})
    cells["refused"] = dict(http=refused.status_code, detail=refused.json().get("detail"),
                            leftovers_after_refused=after_refused, discard=discard.status_code,
                            leftovers_after_discard=lay.scan(keep()))
    _log(flow="dash-kit", layout=lid, outcome="created", **cells)
    assert refused.status_code == 409 and refused.json()["detail"]["created_dirs"] == [], refused.text
    assert discard.status_code == 200
    _assert_no_stage_left(lay, cells["refused"]["leftovers_after_discard"], stage)


# ------------------------------------------------------------- kits from the command line / API


@pytest.mark.parametrize("lid", OK_LAYOUTS)
def test_cli_new_kit(request, layout_factory, desktop, monkeypatch, capsys, lid) -> None:
    _xfail_known(request, "cli-kit", lid)
    lay = layout_factory(lid)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    refusal = _system_refusal(lay)
    if refusal:
        return _refused_cli(lay, capsys, "cli-kit", ["new", "--kit", KIT_ID, "--name", "Xdev Kit", "--yes",
                            "--dest-root", str(lay.projects)], refusal)
    spy = Spy(monkeypatch)
    stages: List[str] = []
    real_make = kit_scaffold._make_kit_stage

    def make_stage(target_root: Path) -> Any:
        out = real_make(target_root)
        stages.append(str(out[0]))
        return out

    monkeypatch.setattr(kit_scaffold, "_make_kit_stage", make_stage)
    for name in ("Xdev Kit", UNICODE_NAME):
        folder = _expected_kit_folder(name)
        spy.copies.clear()
        t0 = time.monotonic()
        rc = cli_mod.main(["new", "--kit", KIT_ID, "--name", name, "--yes", "--dest-root", str(lay.projects)])
        took = round(time.monotonic() - t0, 2)
        out, err = capsys.readouterr()
        scan = lay.scan([lay.projects_real / f for f in os.listdir(lay.projects_real)])
        cell = dict(flow="cli-kit", layout=lid, name=name, rc=rc, total_s=took, move=spy.kind,
                    move_s=round(spy.move_s, 3), stage=stages[-1] if stages else None, leftovers=scan, err=err.strip())
        _log(**cell, outcome="created" if rc == 0 else "failed")
        assert rc == 0, err
        assert "Automatic file placement: on" in out
        expected = "rename" if _dev(Path(stages[-1]).parent) == _dev(lay.projects_real) else "copy"
        assert spy.kind == expected
        _assert_project(lay.dest(folder), desktop, tools_lock=False)
        _assert_no_stage_left(lay, scan, Path(stages[-1]))


@pytest.mark.parametrize("lid", ["b", "c"])
def test_api_kit_with_explicit_staging(request, layout_factory, desktop, monkeypatch, lid) -> None:
    """The explicit staging_parent path (no pinned stage): the move is _publish_staged_repo."""
    _xfail_known(request, "api-kit-staging", lid)
    lay = layout_factory(lid)
    bridge = FakeKitBridge()
    spy = Spy(monkeypatch)
    assert lay.staging is not None
    proposal = kit_scaffold.propose_kit(KIT_ID, "Api Kit", {"building": "video", "layout": "single", "languages": []},
                                        dest_root=lay.projects, staging_parent=lay.staging, bridge=bridge)
    t0 = time.monotonic()
    result = kit_scaffold.accept_kit(proposal, db_path=state_db_path(), bridge=bridge)
    scan = lay.scan([lay.projects_real / "api-kit"])
    _log(flow="api-kit-staging", layout=lid, outcome="created", total_s=round(time.monotonic() - t0, 2),
         move=spy.kind, move_s=round(spy.move_s, 3), leftovers=scan)
    assert Path(result.repos[0]["path"]) == lay.dest("api-kit")
    assert spy.kind == "copy"
    _assert_project(lay.dest("api-kit"), desktop, tools_lock=False)
    _assert_no_stage_left(lay, scan, proposal.staging_dir)


@pytest.mark.parametrize("lid", OK_LAYOUTS)
def test_cli_new_template_failed_check_leftovers(request, layout_factory, desktop, monkeypatch, capsys, lid) -> None:
    _xfail_known(request, "cli-template-failed", lid)
    lay = layout_factory(lid)
    refusal = _system_refusal(lay)
    if refusal:
        return _refused_cli(lay, capsys, "cli-template-failed", ["new", "--template", "python-golden", "--name",
                            "Fail Cli", "--yes", "--dest-root", str(lay.projects)], refusal)
    spy = Spy(monkeypatch)
    _wrap_propose(monkeypatch, spy, _fake_check(code=1))
    rc = cli_mod.main(["new", "--template", "python-golden", "--name", "Fail Cli", "--yes", "--dest-root", str(lay.projects)])
    out, err = capsys.readouterr()
    scan = lay.scan([])
    _log(flow="cli-template-failed", layout=lid, outcome="refused", rc=rc, err=err.strip(), leftovers=scan,
         stage_parent=spy.stage_parents)
    assert rc != 0
    assert not os.path.lexists(lay.dest("fail-cli"))
    stage_line = [line for line in err.splitlines() if line.startswith("Staging preserved at ")]
    assert len(stage_line) == 1, err
    kept = Path(stage_line[0][len("Staging preserved at "):])
    assert kept.is_dir() and _dev(kept.parent) == _dev(spy.stage_parents[0])
    assert scan["projects"] == []


# ------------------------------------------- the copy across filesystems fails half-way


def _disk_full_during_copy(monkeypatch: pytest.MonkeyPatch, into: Path, after: int = 3) -> Dict[str, int]:
    """The second drive fills up after `after` files of the cross-filesystem copy into `into`.

    The copy creates each file relative to a folder handle (os.open with O_CREAT and dir_fd);
    files created that way on the second drive count, the next one fails with ENOSPC.
    """
    real_open = os.open
    count = {"copied": 0}
    second_dev = os.stat(into).st_dev

    def op(path: Any, flags: int, *a: Any, **k: Any) -> int:
        fd = k.get("dir_fd")
        if flags & os.O_CREAT and fd is not None and os.fstat(fd).st_dev == second_dev:
            if count["copied"] >= after:
                raise OSError(28, "No space left on device", path)
            count["copied"] += 1
        return real_open(path, flags, *a, **k)

    monkeypatch.setattr(os, "open", op)
    return count


@pytest.mark.parametrize("entry", ["dashboard", "cli"])
def test_template_copy_fails_half_way_leaves_no_half_project(
    request, layout_factory, desktop, dash, monkeypatch, capsys, entry
) -> None:
    """Projects on the second drive, staging on the first: the move is a copy. When that copy
    fails part-way (disk full), no half project may stay in the projects folder, the staged
    project must be intact, and the message must be one plain line."""
    lay = layout_factory("a")
    if _system_refusal(lay):
        pytest.skip("projects folders below /dev are refused before anything is staged")
    client, routes, jobs, _fake = dash
    scaf = routes.scaffolder if entry == "dashboard" else scaffolder
    spy = Spy(monkeypatch, scaf, routes.kit_scaffold if entry == "dashboard" else kit_scaffold)
    _wrap_propose(monkeypatch, spy, _fake_check(), scaf)
    count = _disk_full_during_copy(monkeypatch, lay.projects_real)
    dest = lay.dest("full-demo")
    if entry == "dashboard":
        pid = _propose_template(client, lay, "python-golden", "Full Demo")["proposal_id"]
        staged = Path(routes._PROPOSALS[pid]["proposal"].repos[0].staged)
        resp = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
        message = json.dumps(resp.json().get("detail"), ensure_ascii=False)
        state = routes._PROPOSALS.get(pid, {}).get("state")
        answer = dict(http=resp.status_code, detail=resp.json().get("detail"), state=state)
    else:
        try:
            rc = cli_mod.main(["new", "--template", "python-golden", "--name", "Full Demo", "--yes",
                               "--dest-root", str(lay.projects)])
            raised = None
        except BaseException as exc:  # noqa: BLE001 - record what reaches the user
            rc, raised = None, f"{type(exc).__name__}: {str(exc)[:600]}"
        _out, err = capsys.readouterr()
        # The tool table the command prints before it creates anything ends with "preflight ok".
        message = err.strip().split("preflight ok\n")[-1].strip() if raised is None else raised
        staged = Path(spy.stage_parents[0])
        answer = dict(rc=rc, err=err.strip()[-1500:], raised=raised)
    half = sorted(os.listdir(dest)) if dest.is_dir() else None
    scan = lay.scan([dest])
    _log(flow=f"{entry}-template-copy-fails", layout="a", copied_before_failure=count["copied"], half_project=half,
         staged_intact=staged.exists(), leftovers=scan, **answer)
    assert count["copied"] >= 3
    assert not os.path.lexists(dest), f"half project left in the projects folder: {half}"
    assert "\n" not in message and "[(" not in message and "Traceback" not in message, message
    assert "space" in message.lower(), message
    if entry == "dashboard":
        assert resp.status_code == 409 and state == "ready", answer
        assert staged.is_dir(), "the staged project must stay for a retry"


def test_template_cross_fs_copy_never_writes_through_a_swapped_link(request, layout_factory, desktop, dash, monkeypatch) -> None:
    """The move across filesystems copies file by file. If the projects folder is replaced by a
    symlink while that copy runs, no file may be written through the link (the same-filesystem
    rename has no such window; the kit's by-handle copy does not follow it)."""
    lay = layout_factory("a")
    if _system_refusal(lay):
        pytest.skip("projects folders below /dev are refused before anything is staged")
    client, routes, jobs, _fake = dash
    spy = Spy(monkeypatch, routes.scaffolder, routes.kit_scaffold)
    _wrap_propose(monkeypatch, spy, _fake_check(), routes.scaffolder)
    elsewhere = lay.second / "elsewhere"
    (elsewhere / "swap-demo").mkdir(parents=True)
    swapped = {"done": False}
    real_open = os.open
    second_dev = os.stat(lay.projects_real).st_dev

    def op(path: Any, flags: int, *a: Any, **k: Any) -> int:
        fd = k.get("dir_fd")
        out = real_open(path, flags, *a, **k)
        if (not swapped["done"] and flags & os.O_CREAT and fd is not None
                and os.fstat(fd).st_dev == second_dev):
            swapped["done"] = True  # the first file of the copy is written: swap now
            os.rename(lay.projects_real, lay.second / "projects-old")
            os.symlink(elsewhere, lay.projects_real)
        return out

    monkeypatch.setattr(os, "open", op)
    pid = _propose_template(client, lay, "python-golden", "Swap Demo")["proposal_id"]
    resp = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    through_link = sorted(str(p.relative_to(elsewhere)) for p in elsewhere.rglob("*"))
    _log(flow="dash-template-copy-link-swap", layout="a", http=resp.status_code, detail=resp.json().get("detail"),
         written_through_link=len(through_link) - 1, sample=through_link[:8])
    assert swapped["done"]
    assert resp.status_code == 409, resp.text
    assert through_link == ["swap-demo"], f"{len(through_link) - 1} entries written through the swapped link"
