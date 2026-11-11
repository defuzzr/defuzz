"""Tests for the read-only structure check (`defuzz check [PATH]`)."""

from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import time
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import structure_check as sc  # noqa: E402
from hermes_plugins.defuzz.cli import main as cli_main  # noqa: E402


# ---------------------------------------------------------------- helpers

def _w(root: Path, rel: str, text: str = "") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _pkg(root: Path, rel: str = "", extra: dict | None = None) -> None:
    data = {"name": (rel or "root").replace("/", "-")}
    data.update(extra or {})
    _w(root, (rel + "/" if rel else "") + "package.json", json.dumps(data))


@pytest.fixture(autouse=True)
def _private_home(tmp_path, monkeypatch):
    """Home and Hermes home always point at synthetic folders that no fixture uses."""
    home = tmp_path / "_home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))
    return home


def _ids(result, finding_id):
    return [f for f in result["findings"] if f["id"] == finding_id]


def _run_cli(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_main(argv)
    return code, buf.getvalue()


def _single(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    _pkg(root)
    _w(root, "src/index.js", "x")
    _w(root, "README.md", "x")
    return root


def _turbo(tmp_path: Path) -> Path:
    """13 roots: root + apps/3 + packages/5 + tools/2 + services/2, all declared."""
    root = tmp_path / "mono"
    _pkg(root, extra={"workspaces": ["apps/*", "packages/*", "tools/*", "!packages/ignored"]})
    _w(root, "pnpm-workspace.yaml", "packages:\n  - 'apps/*'\n  - \"packages/*\"\n  - services/**  # deep\n")
    for name in ("web", "docs", "admin"):
        _pkg(root, f"apps/{name}")
        _w(root, f"apps/{name}/src/page.tsx", "x")
        _pkg(root, f"apps/{name}/node_modules/dep")
        _w(root, f"apps/{name}/.next/server/package.json", "{}")
    for name in ("ui", "config", "tsconfig", "utils", "db"):
        _pkg(root, f"packages/{name}")
    for name in ("lint", "codegen"):
        _pkg(root, f"tools/{name}")
    for name in ("api", "worker"):
        _pkg(root, f"services/{name}")
    _pkg(root, "node_modules/react")
    _w(root, "apps/web/public/index.html", "<html>")
    (root / "apps/web/public/assets").mkdir(parents=True)
    _w(root, "dist/package.json", "{}")
    _w(root, ".turbo/cache.json", "{}")
    return root


def _nest26(tmp_path: Path) -> Path:
    root = tmp_path / "site"
    _w(root, "index.html", "<html>")
    (root / "assets").mkdir(parents=True)
    (root / ".git").mkdir()
    makers = [
        lambda d: _w(d, "package.json", "{}"),
        lambda d: _w(d, "pyproject.toml", "[project]\nname='x'\n"),
        lambda d: _w(d, "Cargo.toml", "[package]\nname='x'\n"),
        lambda d: _w(d, "go.mod", "module x\n"),
        lambda d: _w(d, "App.sln", ""),
        lambda d: (_w(d, "index.html", "<html>"), (d / "css").mkdir()),
    ]
    for i in range(26):
        d = root / "globe" / f"proj{i:02d}"
        d.mkdir(parents=True)
        makers[i % len(makers)](d)
        if i % 4 == 0:   # committed-style git dir
            (d / ".git" / "objects").mkdir(parents=True)
            _w(d, ".git/HEAD", "ref: refs/heads/main\n")
        elif i % 4 == 1:  # unborn git (git init, no commits)
            (d / ".git").mkdir()
    return root


def _snapshot(root: Path):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames) + sorted(dirnames):
            p = Path(dirpath) / name
            st = os.lstat(p)
            digest = ""
            if p.is_file() and not p.is_symlink():
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
            out.append((str(p.relative_to(root)), st.st_mode, st.st_size, st.st_mtime_ns, digest))
    return out


# ------------------------------------------------------------------ cases

def test_single_clean_project_is_one_project(tmp_path):
    res = sc.check_structure(_single(tmp_path))
    assert res["status"] == "one_project"
    assert res["findings"] == []
    assert [r["path"] for r in res["roots"]] == ["."]
    assert res["roots"][0]["markers"] == ["package.json"]
    assert sc.exit_code(res) == 0


def test_turbo_monorepo_with_13_declared_roots(tmp_path):
    t0 = time.perf_counter()
    res = sc.check_structure(_turbo(tmp_path))
    elapsed = time.perf_counter() - t0
    assert res["status"] == "one_project", res["findings"]
    assert res["findings"] == []
    assert len(res["roots"]) == 13
    assert res["declared_members"] == 12
    assert res["skipped"]["ignored_dirs"] >= 6
    assert elapsed < 2.0


def test_26_nested_projects(tmp_path):
    t0 = time.perf_counter()
    res = sc.check_structure(_nest26(tmp_path))
    elapsed = time.perf_counter() - t0
    nested = _ids(res, "nested_project")
    gits = _ids(res, "git_inside_git")
    assert len(nested) == 26
    assert len(gits) == 14
    assert res["status"] == "nested_projects_found"
    assert sc.exit_code(res) == 1
    first = nested[0]
    assert first["path"] == "globe/proj00"
    assert first["detail"]["depth"] == 2
    assert first["detail"]["markers"] == [".git", "package.json"]
    assert "empty folder" in gits[0]["sentence"]
    assert all(f["next"] for f in nested + gits)
    assert elapsed < 2.0


def test_undeclared_project_inside_declared_member(tmp_path):
    root = tmp_path / "mono"
    _pkg(root, extra={"workspaces": {"packages": ["packages/**"]}})
    _pkg(root, "packages/ui")
    _pkg(root, "packages/ui/rogue-subapp")
    _pkg(root, "apps/stray")
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == ["apps/stray", "packages/ui/rogue-subapp"]
    assert res["declared_members"] == 1


def test_single_star_matches_one_segment_only(tmp_path):
    root = tmp_path / "mono"
    _pkg(root, extra={"workspaces": ["apps/*"]})
    _pkg(root, "apps/web")
    _pkg(root, "apps/web/sub/deep")
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == ["apps/web/sub/deep"]


def test_pnpm_workspace_declaration(tmp_path):
    root = tmp_path / "mono"
    _pkg(root)
    _w(root, "pnpm-workspace.yaml", "# comment\npackages:\n  - 'packages/*'\n  - '!packages/skip'\ncatalog:\n  react: 18\n")
    _pkg(root, "packages/a")
    _pkg(root, "packages/skip")
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == ["packages/skip"]
    assert res["declared_members"] == 1


def test_pnpm_flow_list(tmp_path):
    root = tmp_path / "mono"
    _pkg(root)
    _w(root, "pnpm-workspace.yaml", "packages: ['libs/*', \"apps/*\"]\n")
    _pkg(root, "libs/a")
    _pkg(root, "apps/b")
    res = sc.check_structure(root)
    assert res["status"] == "one_project", res["findings"]


def test_cargo_workspace_members_and_exclude(tmp_path):
    root = tmp_path / "rs"
    _w(root, "Cargo.toml", '[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/old"]\n')
    _w(root, "crates/core/Cargo.toml", "[package]\n")
    _w(root, "crates/cli/Cargo.toml", "[package]\n")
    _w(root, "crates/cli/accidentally-scaffolded/Cargo.toml", "[package]\n")
    _w(root, "crates/old/Cargo.toml", "[package]\n")
    _w(root, "target/package/x/Cargo.toml", "[package]\n")
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == [
        "crates/cli/accidentally-scaffolded", "crates/old"]
    assert res["declared_members"] == 2


def test_go_work_declaration(tmp_path):
    root = tmp_path / "gw"
    _w(root, "go.work", "go 1.22\n\nuse ./tools // comment\nuse (\n\t./svc/api\n\t\"./svc/worker\"\n)\n")
    for rel in ("tools", "svc/api", "svc/worker", "experiments/rogue-go", "vendor/x"):
        _w(root, rel + "/go.mod", "module x\n")
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == ["experiments/rogue-go"]
    assert res["declared_members"] == 3
    # go.work is a root-only marker: a Go workspace root is one project.
    assert _ids(res, "no_project_marker") == []
    assert res["roots"][0]["markers"] == ["go.work"]


def test_gitmodules_declared_submodule_not_flagged(tmp_path):
    root = tmp_path / "outer"
    (root / ".git").mkdir(parents=True)
    _pkg(root)
    _w(root, ".gitmodules", '[submodule "lib"]\n\tpath = vendor-libs/lib\n\turl = https://example.invalid/lib.git\n')
    _w(root, "vendor-libs/lib/.git", "gitdir: ../../.git/modules/lib\n")
    _pkg(root, "vendor-libs/lib")
    (root / "stray/.git").mkdir(parents=True)
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "git_inside_git")] == ["stray"]
    assert [f["path"] for f in _ids(res, "nested_project")] == ["stray"]
    assert res["declared_members"] == 1


def test_git_inside_declared_member_is_still_flagged(tmp_path):
    root = tmp_path / "mono"
    _pkg(root, extra={"workspaces": ["packages/*"]})
    _pkg(root, "packages/a")
    (root / "packages/a/.git").mkdir()
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "git_inside_git")] == ["packages/a"]
    assert _ids(res, "nested_project") == []
    assert sc.exit_code(res) == 1


def test_defuzz_declared_dirs(tmp_path):
    root = tmp_path / "adopted"
    _pkg(root)
    _w(root, ".adopt/rules.json", json.dumps({"declared_dirs": [{"dir": "site", "summary": "s", "why": "w"}, 7]}))
    _pkg(root, "site")
    _pkg(root, "other")
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == ["other"]
    assert res["declared_members"] == 1


def test_unreadable_declaration_means_could_not_verify(tmp_path):
    root = tmp_path / "mono"
    _w(root, "package.json", "{not json")
    _pkg(root, "packages/a")
    res = sc.check_structure(root)
    assert _ids(res, "nested_project") == []
    cnv = _ids(res, "could_not_verify")
    assert {f["path"] for f in cnv} == {"package.json", "packages/a"}
    assert res["status"] == "could_not_verify"
    assert sc.exit_code(res) == 2


def test_dependency_and_build_folders_ignored(tmp_path):
    root = tmp_path / "app"
    _pkg(root)
    (root / ".git").mkdir()
    for skip in sorted(sc.SKIP_DIRS - {".git"}):
        _pkg(root, f"{skip}/inner")
        _pkg(root, f"src/{skip}/deeper")
    res = sc.check_structure(root)
    assert res["status"] == "one_project", res["findings"]
    assert res["skipped"]["ignored_dirs"] == 2 * len(sc.SKIP_DIRS) - 1


def test_symlink_root(tmp_path):
    real = _single(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    res = sc.check_structure(str(link) + "/")
    assert [f["id"] for f in res["findings"]] == ["root_is_symlink"]
    assert res["status"] == "could_not_verify"
    assert sc.exit_code(res) == 2


def test_symlinked_subfolder_not_followed(tmp_path):
    root = _single(tmp_path)
    hidden = tmp_path / "elsewhere"
    _pkg(hidden, "proj")
    (root / "linked").symlink_to(hidden, target_is_directory=True)
    (root / "linked-file.json").symlink_to(hidden / "proj" / "package.json")
    res = sc.check_structure(root)
    assert res["status"] == "one_project"
    assert res["skipped"]["symlinks"] == 2


def test_home_folder_detected(tmp_path, _private_home):
    _pkg(_private_home, "proj")
    res = sc.check_structure(_private_home)
    assert [f["id"] for f in res["findings"]] == ["root_is_home_or_agent_home"]
    assert res["roots"] == []
    assert sc.exit_code(res) == 1
    # an ancestor of the home folder counts too
    res2 = sc.check_structure(tmp_path)
    assert _ids(res2, "root_is_home_or_agent_home")


def test_hermes_home_detected_without_reading_inside(tmp_path, monkeypatch):
    hh = tmp_path / "agent"
    _w(hh, "config.yaml", "x: 1")
    _pkg(hh, "skills/demo")
    monkeypatch.setenv("HERMES_HOME", str(hh))
    seen = []
    real_scandir = os.scandir
    monkeypatch.setattr(sc.os, "scandir", lambda p: seen.append(p) or real_scandir(p))
    for target in (hh, hh / "skills" / "demo"):
        res = sc.check_structure(target)
        assert [f["id"] for f in res["findings"]] == ["root_is_home_or_agent_home"]
    assert seen == []


def test_default_hermes_home_when_env_unset(tmp_path, monkeypatch, _private_home):
    monkeypatch.delenv("HERMES_HOME")
    target = _private_home / ".hermes"
    target.mkdir()
    res = sc.check_structure(target)
    assert _ids(res, "root_is_home_or_agent_home")


def test_walk_skips_hermes_home_below_root(tmp_path, monkeypatch):
    root = _single(tmp_path)
    hh = root / "agent-home"
    _pkg(hh, "inner")
    monkeypatch.setenv("HERMES_HOME", str(hh))
    res = sc.check_structure(root)
    assert res["status"] == "one_project", res["findings"]
    assert res["skipped"]["agent_home"] == 1


def test_entry_cap(tmp_path):
    root = _single(tmp_path)
    for i in range(30):
        _w(root, f"f{i}.txt", "x")
    res = sc.check_structure(root, max_entries=10)
    assert res["status"] == "could_not_verify"
    assert "entries" in res["limits"]["hit"]
    assert res["limits"]["entries_seen"] == 10
    assert sc.exit_code(res) == 2


def test_depth_cap_alone_keeps_verdict(tmp_path):
    root = _single(tmp_path)
    _w(root, "a/b/c/d/e.txt", "x")
    _w(root, "z/y/x/w.txt", "x")
    res = sc.check_structure(root, max_depth=2)
    assert res["status"] == "one_project", res["findings"]
    assert res["limits"]["hit"] == ["depth"]
    assert res["limits"]["folders_not_entered"] == 2
    assert _ids(res, "could_not_verify") == []
    [note] = _ids(res, "depth_limit_reached")
    assert note["path"] == "." and note["detail"]["folders_not_entered"] == 2
    assert note["detail"]["example"] == "a/b/c"
    assert sc.exit_code(res) == 0
    clean = sc.check_structure(root)
    assert clean["limits"]["max_depth"] == 8 and clean["findings"] == []


def test_depth_cap_alone_keeps_nested_verdict(tmp_path):
    root = _single(tmp_path)
    _pkg(root, "stray")
    _w(root, "a/b/c/d/e.txt", "x")
    res = sc.check_structure(root, max_depth=2)
    assert res["status"] == "nested_projects_found"
    assert _ids(res, "depth_limit_reached")
    assert sc.exit_code(res) == 1


def test_entry_cap_with_depth_cap_is_still_could_not_verify(tmp_path):
    root = _single(tmp_path)
    _w(root, "a/b/c/d/e.txt", "x")
    for i in range(30):
        _w(root, f"f{i}.txt", "x")
    res = sc.check_structure(root, max_entries=10, max_depth=1)
    assert res["status"] == "could_not_verify"
    assert sc.exit_code(res) == 2


def test_time_cap_with_jumping_clock(tmp_path):
    root = _nest26(tmp_path)
    ticks = iter([0.0, 0.1, 0.2] + [100.0] * 1000)
    res = sc.check_structure(root, clock=lambda: next(ticks), max_seconds=5)
    assert res["status"] == "nested_projects_found" or res["status"] == "could_not_verify"
    assert res["limits"]["hit"] == ["time"]
    assert 0 < res["limits"]["dirs_scanned"] < 30
    assert _ids(res, "could_not_verify")
    # partial result is never reported as clean
    assert sc.exit_code(res) != 0


def test_time_cap_on_clean_tree_is_not_clean(tmp_path):
    root = _turbo(tmp_path)
    ticks = iter([0.0] + [100.0] * 1000)
    res = sc.check_structure(root, clock=lambda: next(ticks))
    assert res["status"] == "could_not_verify"
    assert sc.exit_code(res) == 2


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores permissions")
def test_unreadable_subfolder(tmp_path):
    root = _single(tmp_path)
    locked = root / "locked"
    _pkg(locked, "hidden")
    locked.chmod(0)
    try:
        res = sc.check_structure(root)
    finally:
        locked.chmod(0o755)
    assert res["skipped"]["unreadable"] == 1
    assert [f["path"] for f in _ids(res, "could_not_verify")] == ["locked"]
    assert res["status"] == "could_not_verify"


def test_read_only_and_opens_only_root_declarations(tmp_path, monkeypatch):
    root = _turbo(tmp_path)
    _w(root, "go.work", "use ./tools/lint\n")
    _w(root, "Cargo.toml", "[workspace]\nmembers=[]\n")
    _w(root, ".gitmodules", "")
    _w(root, ".adopt/rules.json", "{}")
    for secret in (".env", "id_ed25519", "credentials.json", "apps/web/.env.local"):
        _w(root, secret, "SECRET")
    before = _snapshot(root)
    opened = []
    real_os_open, real_open = os.open, builtins.open

    def rec_os_open(path, *a, **k):
        opened.append(os.fsdecode(path))
        return real_os_open(path, *a, **k)

    def rec_open(file, *a, **k):
        opened.append(os.fsdecode(file) if not isinstance(file, int) else f"fd:{file}")
        return real_open(file, *a, **k)

    monkeypatch.setattr(os, "open", rec_os_open)
    monkeypatch.setattr(builtins, "open", rec_open)
    res = sc.check_structure(root)
    monkeypatch.undo()
    assert res["status"] == "one_project", res["findings"]
    allowed = {str(root / n) for n in (
        "package.json", "pnpm-workspace.yaml", "Cargo.toml", "go.work", ".gitmodules", ".adopt/rules.json")}
    assert set(opened) <= allowed, opened
    assert set(opened) == allowed
    assert not any(Path(p).name in {".env", "id_ed25519", "credentials.json", ".env.local"} for p in opened)
    assert _snapshot(root) == before


def test_control_characters_escaped(tmp_path):
    root = _single(tmp_path)
    _pkg(root, "bad\x1bname\nx")
    res = sc.check_structure(root)
    paths = [f["path"] for f in _ids(res, "nested_project")]
    assert paths == ["bad\\x1bname\\nx"]
    code, out = _run_cli(["check", str(root)])
    assert "\x1b" not in out and "bad\\x1bname" in out
    assert code == 1


def test_duplicate_tree_names_info_only(tmp_path):
    root = _single(tmp_path)
    (root / "src" / "src").mkdir(parents=True)
    (root / "dashboard-v2").mkdir()
    (root / "notes copy").mkdir()
    (root / "img (1)").mkdir()
    (root / "app").mkdir()  # same as root name
    (root / "a/b/c/d/x-final").mkdir(parents=True)  # depth 5: too deep
    res = sc.check_structure(root)
    dup = sorted(f["path"] for f in _ids(res, "duplicate_tree_names"))
    assert dup == ["app", "dashboard-v2", "img (1)", "notes copy", "src/src"]
    assert res["status"] == "one_project"
    assert sc.exit_code(res) == 0


def test_not_a_project(tmp_path):
    root = tmp_path / "plain"
    _w(root, "notes.txt", "x")
    res = sc.check_structure(root)
    assert res["status"] == "not_a_project"
    assert [f["id"] for f in res["findings"]] == ["no_project_marker"]
    # Neutral wording: never tell someone with existing files to create a new project.
    assert "No project file was found at the top of this folder" in res["findings"][0]["sentence"]
    assert "hermes defuzz new" not in res["findings"][0]["next"]
    assert "add its manifest at the top" in res["findings"][0]["next"]
    assert "defuzz new" not in sc.format_text(res)
    assert sc.exit_code(res) == 2


def test_missing_path(tmp_path):
    res = sc.check_structure(tmp_path / "nope")
    assert res["status"] == "could_not_verify"
    assert sc.exit_code(res) == 2


def test_index_html_rule_is_conservative(tmp_path):
    root = _single(tmp_path)
    _w(root, "public/index.html", "<html>")
    (root / "public/assets").mkdir()
    _w(root, "docs/page/index.html", "<html>")  # no asset folder
    _w(root, "landing/index.html", "<html>")
    (root / "landing/js").mkdir()
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == ["landing"]
    assert _ids(res, "nested_project")[0]["detail"]["markers"] == ["index.html+js"]


def test_deterministic(tmp_path):
    root = _nest26(tmp_path)
    assert sc.check_structure(root) == sc.check_structure(root)


def test_cli_text_json_and_exit_codes(tmp_path, monkeypatch):
    code, out = _run_cli(["check", str(_single(tmp_path))])
    assert code == 0 and out.startswith("One project:")
    nest = _nest26(tmp_path)
    code, out = _run_cli(["check", str(nest)])
    assert code == 1
    lines = out.splitlines()
    assert lines[0].startswith("Not one project:")
    assert len(lines) <= 20
    assert lines[1] == "Needs a look:"
    assert any("more" in line for line in lines)
    assert any(line.startswith("What to do") for line in lines)
    assert "declare" in lines[-1] and ".adopt/rules.json" in lines[-1]
    code, out = _run_cli(["check", str(nest), "--json"])
    data = json.loads(out)
    assert code == 1 and data["status"] == "nested_projects_found"
    assert data == json.loads(json.dumps(sc.check_structure(nest)))
    plain = tmp_path / "plain"
    plain.mkdir()
    assert _run_cli(["check", str(plain)])[0] == 2
    monkeypatch.chdir(_single(tmp_path / "cwd"))
    code, out = _run_cli(["check", "--json"])
    assert code == 0 and json.loads(out)["path"] == "."


def test_cli_reports_agent_home(tmp_path, monkeypatch):
    hh = tmp_path / "agent"
    hh.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hh))
    code, out = _run_cli(["check", str(hh), "--json"])
    assert code == 1
    assert json.loads(out)["findings"][0]["id"] == "root_is_home_or_agent_home"


# ------------------------------------------------- embedded sub-packages vs nesting

def _cargo(root: Path, rel: str) -> None:
    _w(root, rel + "/Cargo.toml", "[package]\nname='x'\n")


def _py(root: Path, rel: str = "") -> None:
    _w(root, (rel + "/" if rel else "") + "pyproject.toml", "[project]\nname='x'\n")


def _reasons(res):
    out = {}
    for f in _ids(res, "embedded_subproject"):
        out[f["detail"]["reason"]] = out.get(f["detail"]["reason"], 0) + 1
    return out


def _plugin_repo(tmp_path: Path) -> Path:
    """A plugin repo shipping 6 full project templates (some with members) plus test fixtures."""
    root = tmp_path / "plugin"
    _py(root)
    (root / ".git").mkdir(parents=True)
    makers = {
        "ts": lambda rel: _pkg(root, rel),
        "py": lambda rel: _py(root, rel),
        "rs": lambda rel: _cargo(root, rel),
        "go": lambda rel: _w(root, rel + "/go.mod", "module x\n"),
        "dotnet": lambda rel: _w(root, rel + "/TmplPrefix.sln", ""),
        "static": lambda rel: (_w(root, rel + "/index.html", "<html>"), (root / rel / "css").mkdir()),
    }
    for kind, make in makers.items():
        base = f"templates/{kind}-golden/tmpl_prefix"
        make(base)
        if kind in ("ts", "py", "rs"):
            for member in ("packages/apps/cli", "packages/apps/server", "packages/foundation/core",
                           "packages/foundation/config", "packages/foundation/telemetry", "tools/xtask"):
                make(f"{base}/{member}")
    _py(root, "tests/fixtures/audit_template/python")
    _cargo(root, "tests/fixtures/audit_template/rust")
    _pkg(root, "tests/fixtures/audit_template/ts_node")
    _cargo(root, "tests/fixtures/templates/fake-game/tmpl_prefix")
    return root


def test_plugin_repo_with_templates_is_one_project(tmp_path):
    res = sc.check_structure(_plugin_repo(tmp_path))
    assert res["status"] == "one_project", [f for f in res["findings"] if f["id"] != "embedded_subproject"]
    assert _ids(res, "nested_project") == []
    assert _reasons(res) == {"template_or_fixture": 6 + 3 * 6 + 4}
    assert sc.exit_code(res) == 0
    note = _ids(res, "embedded_subproject")[0]
    assert "separate package inside this project" in note["sentence"]
    assert "declar" in note["sentence"]
    code, out = _run_cli(["check", str(tmp_path / "plugin")])
    assert code == 0
    assert out.splitlines()[0].startswith("One project:")
    assert "28 embedded sub-packages noted" in out.splitlines()[0]
    assert "Noted, usually fine:" in out and "Needs a look:" not in out
    assert len(out.splitlines()) <= 20


def _js_monorepo(tmp_path: Path) -> Path:
    root = tmp_path / "mono"
    _pkg(root, extra={"workspaces": ["apps/*", "ui", "ui/packages/*"]})
    (root / ".git").mkdir()
    _pkg(root, "apps/installer")
    _cargo(root, "apps/installer/src-tauri")
    _pkg(root, "apps/desk")
    _pkg(root, "apps/desk/electron/find-native-fixture")
    _pkg(root, "apps/desk/electron/activity-native-fixture")
    _pkg(root, "plugins/platforms/chat/sidecar")  # helper process package: framework_layout
    _pkg(root, "ui")
    _pkg(root, "ui/packages/ink")  # declared explicitly through the member's own path
    _pkg(root, "scripts/bridge")
    _pkg(root, "website")
    return root


def test_js_monorepo_with_framework_and_fixture_subpackages(tmp_path):
    res = sc.check_structure(_js_monorepo(tmp_path))
    assert res["status"] == "one_project", [f for f in res["findings"] if f["id"] != "embedded_subproject"]
    assert sc.exit_code(res) == 0
    assert res["declared_members"] == 4
    got = {f["path"]: f["detail"]["reason"] for f in _ids(res, "embedded_subproject")}
    assert got == {
        "apps/installer/src-tauri": "framework_layout",
        "apps/desk/electron/activity-native-fixture": "template_or_fixture",
        "apps/desk/electron/find-native-fixture": "template_or_fixture",
        "plugins/platforms/chat/sidecar": "framework_layout",
        "scripts/bridge": "framework_layout",
        "website": "framework_layout",
    }
    kinds = {r["path"]: r["kind"] for r in res["roots"]}
    assert kinds["ui/packages/ink"] == "declared_member"
    assert kinds["website"] == "embedded"


def test_explicit_member_path_reaches_inside_member_but_wildcard_alone_does_not(tmp_path):
    root = tmp_path / "mono"
    _pkg(root, extra={"workspaces": ["ui", "ui/packages/*", "libs/**"]})
    _pkg(root, "ui")
    _pkg(root, "ui/packages/ink")
    _pkg(root, "libs/a")
    _pkg(root, "libs/a/rogue")
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == ["libs/a/rogue"]
    assert res["declared_members"] == 3


def test_tools_repo_with_four_unrelated_projects(tmp_path):
    root = tmp_path / "tools"
    _py(root)
    (root / ".git").mkdir(parents=True)
    _pkg(root, "weather-bot")
    _py(root, "budget")
    _w(root, "scraper/go.mod", "module x\n")  # a lone other-language root, but one of 4 siblings
    _pkg(root, "notes")
    res = sc.check_structure(root)
    assert sorted(f["path"] for f in _ids(res, "nested_project")) == ["budget", "notes", "scraper", "weather-bot"]
    assert _ids(res, "embedded_subproject") == []
    assert res["status"] == "nested_projects_found"
    assert sc.exit_code(res) == 1


def test_26_nested_in_another_language_still_nested(tmp_path):
    root = tmp_path / "site"
    _pkg(root)
    for i in range(26):
        _cargo(root, f"globe/proj{i:02d}")
    res = sc.check_structure(root)
    assert len(_ids(res, "nested_project")) == 26
    assert _ids(res, "embedded_subproject") == []
    assert sc.exit_code(res) == 1


def test_26_nested_has_no_embedded_notes(tmp_path):
    res = sc.check_structure(_nest26(tmp_path))
    assert len(_ids(res, "nested_project")) == 26
    assert _ids(res, "embedded_subproject") == []


def test_single_rust_crate_in_js_app_is_embedded(tmp_path):
    root = tmp_path / "app"
    _pkg(root)
    _cargo(root, "engine")
    res = sc.check_structure(root)
    assert res["status"] == "one_project", res["findings"]
    assert [(f["path"], f["detail"]["reason"]) for f in _ids(res, "embedded_subproject")] == [
        ("engine", "different_ecosystem")]
    assert sc.exit_code(res) == 0


def test_two_rust_crates_in_js_app_are_not_excused(tmp_path):
    root = tmp_path / "app"
    _pkg(root)
    _cargo(root, "engine")
    _cargo(root, "parser")
    res = sc.check_structure(root)
    assert sorted(f["path"] for f in _ids(res, "nested_project")) == ["engine", "parser"]


def test_same_ecosystem_unmatched_root_is_nested(tmp_path):
    root = tmp_path / "app"
    _pkg(root)
    _pkg(root, "functions")  # no firebase.json beside it
    _pkg(root, "android")  # parent has package.json: a mobile shell
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == ["functions"]
    assert [f["path"] for f in _ids(res, "embedded_subproject")] == ["android"]


@pytest.mark.parametrize("rel,make,extra", [
    ("functions", "pkg", "firebase.json"),
    ("ios", "pkg", None),
    ("native", "cargo", None),
    ("core-rs", "cargo", None),
    ("bindings", "py", None),
    ("docs", "pkg", None),
    ("docs-site", "pkg", None),
    ("infra", "pkg", None),
    ("xtask", "cargo", None),
    ("tools/release", "py", None),
])
def test_framework_layouts(tmp_path, rel, make, extra):
    root = tmp_path / "app"
    _pkg(root)
    _py(root)
    if extra:
        _w(root, extra, "{}")
    {"pkg": _pkg, "cargo": _cargo, "py": _py}[make](root, rel)
    res = sc.check_structure(root)
    assert [(f["path"], f["detail"]["reason"]) for f in _ids(res, "embedded_subproject")] == [(rel, "framework_layout")]
    assert res["status"] == "one_project"


def test_vendored_code(tmp_path):
    root = tmp_path / "app"
    _pkg(root)
    _pkg(root, "third_party/lib-a")
    _pkg(root, "external/lib-b")
    res = sc.check_structure(root)
    assert _reasons(res) == {"vendored_code": 2}
    assert res["status"] == "one_project"


@pytest.mark.parametrize("rel", ["app-v2", "examples/demo-backup", "_ai_temp/thing", "scratch/engine", "wip/site"])
def test_leftover_and_scratch_overrides(tmp_path, rel):
    root = tmp_path / "app"
    _pkg(root)
    if rel == "scratch/engine":
        _cargo(root, rel)  # would otherwise be a lone other-language root
    else:
        _pkg(root, rel)
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == [rel]
    assert _ids(res, "embedded_subproject") == []
    assert sc.exit_code(res) == 1


def test_embedded_pattern_with_own_git_is_nested(tmp_path):
    root = _plugin_repo(tmp_path)
    (root / "templates/go-golden/tmpl_prefix/.git").mkdir()
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == ["templates/go-golden/tmpl_prefix"]
    assert [f["path"] for f in _ids(res, "git_inside_git")] == ["templates/go-golden/tmpl_prefix"]
    assert sc.exit_code(res) == 1


def test_three_siblings_outside_fixture_folder_are_nested(tmp_path):
    root = tmp_path / "app"
    _pkg(root)
    for name in ("alpha-fixture", "beta-fixture", "gamma-fixture"):
        _pkg(root, f"apps/{name}")
    res = sc.check_structure(root)
    assert len(_ids(res, "nested_project")) == 3


def test_text_output_groups_and_caps(tmp_path):
    root = _plugin_repo(tmp_path)
    _pkg(root, "stray")
    (root / "src/src").mkdir(parents=True)
    res = sc.check_structure(root)
    text = sc.format_text(res)
    lines = text.splitlines()
    assert len(lines) <= 20
    assert lines[1] == "Needs a look:"
    assert any(line.startswith("- [nested_project] stray:") for line in lines)
    i = lines.index("Noted, usually fine:")
    noted = lines[i + 1:]
    assert any("28" in line and "template_or_fixture" in line for line in noted)
    assert any("duplicate_tree_names" in line for line in noted)
    assert ".adopt/rules.json" in lines[-1]


# ------------------------------------------------------------ a folder of separate projects

def _folder_of(tmp_path: Path, n: int, git: bool = False) -> Path:
    root = tmp_path / "Projects"
    root.mkdir()
    _w(root, "notes.txt", "x")
    for i in range(n):
        _pkg(root, f"p{i:02d}")
        _w(root, f"p{i:02d}/src/index.js", "x")
        if git:
            (root / f"p{i:02d}" / ".git").mkdir()
    return root


def test_folder_of_clean_projects_is_not_a_project(tmp_path):
    res = sc.check_structure(_folder_of(tmp_path, 5))
    assert res["status"] == "not_a_project"
    [fop] = _ids(res, "folder_of_projects")
    assert fop["path"] == "." and fop["detail"]["projects"] == 5 and fop["detail"]["with_git"] == 0
    assert "not a project itself" in fop["sentence"] and "5 separate projects" in fop["sentence"]
    assert _ids(res, "nested_project") == [] and _ids(res, "git_inside_git") == []
    assert [t["path"] for t in res["top_level_projects"]] == [f"p{i:02d}" for i in range(5)]
    assert res["top_level_projects"][0] == {"path": "p00", "markers": ["package.json"], "nested_count": 0, "embedded_count": 0}
    assert sc.exit_code(res) == 2


def test_folder_of_projects_still_finds_nesting_inside_each(tmp_path):
    root = _folder_of(tmp_path, 5)
    _pkg(root, "p01/stray")  # undeclared project inside one sibling
    _pkg(root, "p03", extra={"workspaces": ["packages/*"]})  # a declared monorepo
    for name in ("a", "b", "c"):
        _pkg(root, f"p03/packages/{name}")
    res = sc.check_structure(root)
    assert res["status"] == "not_a_project"
    nested = _ids(res, "nested_project")
    assert [f["path"] for f in nested] == ["p01/stray"]
    assert nested[0]["detail"]["depth"] == 2
    assert not any(f["path"].startswith("p03/") for f in res["findings"])
    tops = {t["path"]: t for t in res["top_level_projects"]}
    assert tops["p01"]["nested_count"] == 1 and tops["p03"]["nested_count"] == 0
    assert _ids(res, "folder_of_projects")[0]["detail"]["projects"] == 5
    assert sc.exit_code(res) == 2
    text = sc.format_text(res)
    lines = text.splitlines()
    assert lines[0].startswith("Not a project:") and "5 separate projects" in lines[0]
    assert "Needs a look inside: p01 (1)" in lines
    assert not any("p03" in line for line in lines)
    assert len(lines) <= 20
    code, _out = _run_cli(["check", str(root)])
    assert code == 2


def test_folder_of_git_repos_has_no_git_inside_git(tmp_path):
    res = sc.check_structure(_folder_of(tmp_path, 4, git=True))
    assert _ids(res, "git_inside_git") == [] and _ids(res, "nested_project") == []
    assert _ids(res, "folder_of_projects")[0]["detail"] == {"projects": 4, "with_git": 4}
    assert res["status"] == "not_a_project"


def test_folder_of_60_projects_evaluates_first_50(tmp_path):
    root = _folder_of(tmp_path, 60)
    _pkg(root, "p55/stray")  # beyond the cap: not looked at
    res = sc.check_structure(root)
    assert _ids(res, "folder_of_projects")[0]["detail"]["projects"] == 60
    assert len(res["top_level_projects"]) == 50
    assert res["top_level_projects"][-1]["path"] == "p49"
    cnv = [f for f in _ids(res, "could_not_verify") if f["detail"].get("reason") == "project_cap"]
    assert len(cnv) == 1 and cnv[0]["detail"]["not_evaluated"] == 10
    assert _ids(res, "nested_project") == []
    assert res["status"] == "not_a_project"
    assert sc.exit_code(res) == 2


def test_multi_repo_umbrella(tmp_path):
    root = tmp_path / "umbrella"
    for name, maker in (("api", lambda d: _w(d, "go.mod", "module x\n")),
                        ("web", lambda d: _pkg(d)),
                        ("ml", lambda d: _py(d))):
        d = root / name
        (d / ".git").mkdir(parents=True)
        maker(d)
    res = sc.check_structure(root)
    assert res["status"] == "not_a_project"
    assert _ids(res, "folder_of_projects")[0]["detail"] == {"projects": 3, "with_git": 3}
    assert _ids(res, "nested_project") == [] and _ids(res, "git_inside_git") == []
    assert sc.check_structure(root) == res


# ------------------------------------------------------------ more project markers (H1)

def _one(res):
    assert res["status"] == "one_project", [f for f in res["findings"] if f["id"] != "embedded_subproject"]
    assert sc.exit_code(res) == 0
    return res


def test_flutter_app_with_functions_and_platform_shells(tmp_path):
    root = tmp_path / "flutter_app"
    _w(root, "pubspec.yaml", "name: app\n")
    _w(root, "lib/main.dart", "void main() {}")
    _pkg(root, "functions")  # no firebase.json: a second-language component
    _w(root, "android/build.gradle", "")
    _w(root, "android/settings.gradle", "")
    _w(root, "android/app/build.gradle", "")  # a Gradle module of the android shell
    (root / "ios/Runner.xcodeproj").mkdir(parents=True)
    res = _one(sc.check_structure(root))
    assert res["roots"][0]["markers"] == ["pubspec.yaml"]
    got = {f["path"]: f["detail"]["reason"] for f in _ids(res, "embedded_subproject")}
    assert got == {"functions": "different_ecosystem", "android": "framework_layout",
                   "android/app": "framework_layout", "ios": "framework_layout"}
    assert _ids(res, "folder_of_projects") == []


def test_django_project_with_frontend(tmp_path):
    root = tmp_path / "site"
    _w(root, "manage.py", "")
    _w(root, "requirements.txt", "django\n")
    _w(root, "mysite/settings.py", "")
    _pkg(root, "frontend")
    res = _one(sc.check_structure(root))
    assert res["roots"][0]["markers"] == ["manage.py", "requirements.txt"]
    assert [(f["path"], f["detail"]["reason"]) for f in _ids(res, "embedded_subproject")] == [
        ("frontend", "different_ecosystem")]


@pytest.mark.parametrize("files", [
    {"go.work": "go 1.22\n"},
    {"setup.py": "from setuptools import setup\n"},
    {"requirements.txt": "requests\n"},
    {"pom.xml": "<project/>"},
    {"Gemfile": ""},
    {"Makefile": "all:\n"},
    {"App.csproj": "<Project/>"},
])
def test_root_only_or_strong_marker_alone_is_one_project(tmp_path, files):
    root = tmp_path / "proj"
    for name, text in files.items():
        _w(root, name, text)
    _w(root, "src/main.txt", "x")
    res = _one(sc.check_structure(root))
    assert res["roots"][0]["markers"] == sorted(files)
    assert _ids(res, "no_project_marker") == []


def test_static_site_with_img_folder(tmp_path):
    root = tmp_path / "site"
    _w(root, "index.html", "<html>")
    (root / "img").mkdir(parents=True)
    res = _one(sc.check_structure(root))
    assert res["roots"][0]["markers"] == ["index.html+img"]


def test_git_only_root_is_a_project_with_a_note(tmp_path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    _w(root, "main.c", "int main(){}")
    res = _one(sc.check_structure(root))
    assert res["roots"][0]["markers"] == [".git"]
    [note] = _ids(res, "git_only_root")
    assert note["path"] == "." and "git repository" in note["sentence"]
    assert _ids(res, "no_project_marker") == []
    text = sc.format_text(res)
    assert "git_only_root" in text and "defuzz new" not in text


def test_nested_weak_markers_never_mark_a_nested_project(tmp_path):
    root = _single(tmp_path)
    for name in ("Makefile", "requirements.txt", "Pipfile", "setup.cfg", "CMakeLists.txt", "manage.py", "setup.py", "go.work"):
        _w(root, f"sub-{name.lower().replace('.', '-')}/{name}", "")
    res = _one(sc.check_structure(root))
    assert [r["path"] for r in res["roots"]] == ["."]


def test_folder_of_projects_ignores_weak_markers_and_uses_strong_ones(tmp_path):
    root = tmp_path / "Projects"
    _w(root, "a/Makefile", "")
    _w(root, "b/pubspec.yaml", "")
    res = sc.check_structure(root)
    assert [t["path"] for t in res["top_level_projects"]] == ["b"]


def test_multi_module_builds_are_not_nested(tmp_path):
    root = tmp_path / "jvm"
    _w(root, "settings.gradle.kts", "")
    _w(root, "build.gradle.kts", "")
    for m in ("app", "core", "data", "ui"):
        _w(root, f"modules/{m}/build.gradle.kts", "")
    res = _one(sc.check_structure(root))
    assert len(_ids(res, "embedded_subproject")) == 4
    net = tmp_path / "net"
    _w(net, "App.sln", "")
    for m in ("App", "App.Core", "App.Tests"):
        _w(net, f"src/{m}/{m}.csproj", "<Project/>")
    _one(sc.check_structure(net))


# ------------------------------------------------------------ tighter embedded excuses (M1)

def test_templates_ancestor_excuses_a_copied_app(tmp_path):
    root = _single(tmp_path)
    _pkg(root, "templates/myrealapp")
    res = _one(sc.check_structure(root))
    assert [(f["path"], f["detail"]["reason"]) for f in _ids(res, "embedded_subproject")] == [
        ("templates/myrealapp", "template_or_fixture")]


@pytest.mark.parametrize("rel", ["shop-example", "templates", "fixtures", "tmpl_shop", "apps/web-template"])
def test_own_template_like_name_does_not_excuse(tmp_path, rel):
    root = _single(tmp_path)
    _pkg(root, rel)
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == [rel]
    assert sc.exit_code(res) == 1


def test_own_fixture_name_inside_a_declared_member_is_excused(tmp_path):
    root = tmp_path / "mono"
    _pkg(root, extra={"workspaces": ["apps/*"]})
    _pkg(root, "apps/desk")
    _pkg(root, "apps/desk/electron/find-native-fixture")
    res = _one(sc.check_structure(root))
    assert _reasons(res) == {"template_or_fixture": 1}


def test_13_apps_under_examples_are_excused_with_one_info(tmp_path):
    root = _single(tmp_path)
    for i in range(13):
        _pkg(root, f"examples/app{i:02d}")
    res = _one(sc.check_structure(root))
    assert _reasons(res) == {"template_or_fixture": 13}
    [many] = _ids(res, "many_embedded_subprojects")
    assert many["path"] == "examples" and many["detail"]["count"] == 13
    assert "many_embedded_subprojects" in sc.format_text(res)


def test_12_apps_under_examples_have_no_extra_info(tmp_path):
    root = _single(tmp_path)
    for i in range(12):
        _pkg(root, f"examples/app{i:02d}")
    res = _one(sc.check_structure(root))
    assert _ids(res, "many_embedded_subprojects") == []


def test_crowd_under_non_exact_template_folder_is_nested(tmp_path):
    root = _single(tmp_path)
    for name in ("a", "b", "c"):
        _pkg(root, f"samples/{name}")  # 'samples' excuses one or two, not a crowd
    res = sc.check_structure(root)
    assert len(_ids(res, "nested_project")) == 3


def test_crowd_under_deep_exact_template_folder_is_nested(tmp_path):
    root = _single(tmp_path)
    for name in ("a", "b", "c"):
        _pkg(root, f"x/y/examples/{name}")  # 'examples' at depth 3: crowding wins
    res = sc.check_structure(root)
    assert len(_ids(res, "nested_project")) == 3


@pytest.mark.parametrize("name", ["myotherproject", "myapp", "otherthing", "engine-old", "newtool", "test2", "backupcrate", "webproject"])
def test_project_like_names_get_no_second_language_excuse(tmp_path, name):
    root = _single(tmp_path)
    _py(root, name)
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == [name]
    assert sc.exit_code(res) == 1


def test_second_language_excuse_only_down_to_depth_2(tmp_path):
    root = _single(tmp_path)
    _cargo(root, "a/b/engine")
    res = sc.check_structure(root)
    assert [f["path"] for f in _ids(res, "nested_project")] == ["a/b/engine"]


def test_second_language_excuse_needs_a_small_folder(tmp_path):
    root = _single(tmp_path)
    _cargo(root, "engine")
    for i in range(30):
        _w(root, f"engine/src/f{i}.rs", "")
    old = sc.DIFFERENT_ECOSYSTEM_MAX_ENTRIES
    try:
        sc.DIFFERENT_ECOSYSTEM_MAX_ENTRIES = 20
        res = sc.check_structure(root)
    finally:
        sc.DIFFERENT_ECOSYSTEM_MAX_ENTRIES = old
    assert [f["path"] for f in _ids(res, "nested_project")] == ["engine"]
    assert sc.DIFFERENT_ECOSYSTEM_MAX_ENTRIES == 2000


def test_src_tauri_still_excused(tmp_path):
    root = _single(tmp_path)
    _cargo(root, "src-tauri")
    res = _one(sc.check_structure(root))
    assert [(f["path"], f["detail"]["reason"]) for f in _ids(res, "embedded_subproject")] == [
        ("src-tauri", "framework_layout")]


# ------------------------------------------------------------ wording (LOW)

def test_filesystem_root_wording_without_walking(monkeypatch):
    def no_walk(*_a, **_k):
        raise AssertionError("the filesystem root must never be listed")
    with monkeypatch.context() as mp:
        mp.setattr(sc.os, "scandir", no_walk)
        res = sc.check_structure(os.sep)
    assert [f["id"] for f in res["findings"]] == ["root_is_home_or_agent_home"]
    assert res["findings"][0]["detail"]["kind"] == "the filesystem root"
    first = sc.format_text(res).splitlines()[0]
    assert "the filesystem root" in first and "home" not in first


def test_folder_text_escapes_path_once(tmp_path):
    root = tmp_path / "Pro\\jects"
    _pkg(root, "a")
    _pkg(root, "b")
    res = sc.check_structure(root)
    text = sc.format_text(res)
    assert res["path"].endswith("Pro\\\\jects")
    assert "Pro\\\\jects/a" in text and "Pro\\\\\\\\jects" not in text


def test_folder_budget_stop_reports_real_reason(tmp_path):
    root = _folder_of(tmp_path, 8)
    # The walk of the folder itself reads 25 entries; each project then needs 3.
    res = sc.check_structure(root, max_entries=35)
    assert _ids(res, "folder_of_projects")[0]["detail"]["projects"] == 8
    stops = [f for f in _ids(res, "could_not_verify") if f["path"] == "."]
    assert len(stops) == 1
    stop = stops[0]
    shown = len(res["top_level_projects"])
    assert 0 < shown < 8
    assert stop["detail"]["reason"] == "entries"
    assert stop["detail"]["not_evaluated"] == 8 - shown
    assert stop["detail"]["evaluated"] == shown
    assert "first 50" not in stop["sentence"] and f"{shown} of 8" in stop["sentence"]


def test_folder_time_stop_reports_time(tmp_path):
    root = _folder_of(tmp_path, 5)
    ticks = iter([0.0] * 12 + [100.0] * 1000)
    res = sc.check_structure(root, clock=lambda: next(ticks))
    stops = [f for f in _ids(res, "could_not_verify") if f["path"] == "." and f["detail"].get("reason") == "time"]
    assert stops, res["findings"]
    n = _ids(res, "folder_of_projects")[0]["detail"]["projects"]
    assert stops[-1]["detail"]["not_evaluated"] == n - len(res["top_level_projects"])
    assert "first 50" not in stops[-1]["sentence"]


def test_uv_workspace_members_are_declared(tmp_path):
    """The layout the bundled Python template creates: a uv workspace is one project."""
    root = tmp_path / "proj"
    (root / "packages" / "adapters" / "http").mkdir(parents=True)
    (root / "packages" / "apps" / "cli").mkdir(parents=True)
    (root / "packages" / "apps" / "tests").mkdir(parents=True)
    (root / "tools" / "xtask").mkdir(parents=True)
    (root / "rogue").mkdir()
    (root / "pyproject.toml").write_text(
        '[tool.uv.workspace]\nmembers = ["packages/*/*", "tools/xtask"]\nexclude = ["packages/*/tests"]\n',
        encoding="utf-8")
    for rel in ("packages/adapters/http", "packages/apps/cli", "tools/xtask", "rogue"):
        (root / rel / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    mod = sc
    result = mod.check_structure(str(root))
    nested = sorted(f["path"] for f in result["findings"] if f["id"] == "nested_project")
    assert nested == ["rogue"], result["findings"]
    assert result["declared_members"] == 3

    (root / "rogue" / "pyproject.toml").unlink()
    (root / "pyproject.toml").write_text('[tool.uv.workspace]\nmembers = 5\n', encoding="utf-8")
    result = mod.check_structure(str(root))
    assert not [f for f in result["findings"] if f["id"] == "nested_project"]
    assert any(f["id"] == "could_not_verify" for f in result["findings"])
