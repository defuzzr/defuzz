"""Unit tests for workspace_root.py and projects_root plugin setting."""

from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Any, Callable, Dict, List
import pytest
import yaml

from tests.conftest import REPO_ROOT, ensure_test_package, load_submodule
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401


class _TTYStream(io.StringIO):
    def isatty(self) -> bool:
        return True


class _PipeStream(io.StringIO):
    def isatty(self) -> bool:
        return False


class _FakePluginContext:
    def __init__(self, initial: Dict[str, Any] | None = None) -> None:
        self.values: Dict[str, Any] = dict(initial or {})
        self.tools: List[str] = []
        self.hooks: List[str] = []
        self.cli_commands: List[str] = []
        self.slash_commands: List[str] = []

    def get_config(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def set_config(self, key: str, value: Any) -> None:
        self.values[key] = value

    def register_tool(self, name: str, **kwargs: Any) -> None:
        self.tools.append(name)

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None:
        self.hooks.append(hook_name)

    def register_cli_command(self, name: str, **kwargs: Any) -> None:
        self.cli_commands.append(name)

    def register_command(self, name: str, **kwargs: Any) -> None:
        self.slash_commands.append(name)


def _snapshot_tree(root: Path) -> Dict[str, bytes | str]:
    """Capture every file, symlink, and directory under root for byte-for-byte assertions."""
    snap: Dict[str, bytes | str] = {}
    if not os.path.lexists(root):
        return snap
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = os.path.relpath(dirpath, root)
        snap[f"dir:{rel_dir}"] = "dir"
        for dname in list(dirnames):
            full_d = os.path.join(dirpath, dname)
            if os.path.islink(full_d):
                snap[f"link:{os.path.relpath(full_d, root)}"] = os.readlink(full_d)
        for fname in filenames:
            full_f = os.path.join(dirpath, fname)
            rel_f = os.path.relpath(full_f, root)
            if os.path.islink(full_f):
                snap[f"link:{rel_f}"] = os.readlink(full_f)
            else:
                snap[f"file:{rel_f}"] = Path(full_f).read_bytes()
    return snap


@pytest.fixture
def clean_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    """Synthetic HOME and HERMES_HOME with HERMES_PROJECTS_ROOT cleared."""
    home = tmp_path / "user"
    hermes_home = home / ".hermes"
    cwd = tmp_path / "work"
    home.mkdir(parents=True)
    hermes_home.mkdir(parents=True)
    cwd.mkdir(parents=True)
    for var in ("HOME", "USERPROFILE", "HERMES_REAL_HOME"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.delenv("HERMES_PROJECTS_ROOT", raising=False)
    import hermes_constants

    hermes_constants.reset_hermes_home_key_cache()
    return {"base": tmp_path, "home": home, "hermes_home": hermes_home, "cwd": cwd}


def test_plugin_yaml_declares_projects_root_schema() -> None:
    manifest = yaml.safe_load((REPO_ROOT / "plugin.yaml").read_text(encoding="utf-8"))
    schema = manifest["config_schema"]
    assert "projects_root" in schema
    spec = schema["projects_root"]
    assert spec["type"] == "string"
    assert spec["default"] == ""
    assert spec["label"] == "Projects folder"
    desc = spec["description"].lower()
    assert "where new projects are created" in desc
    assert "first time" in desc
    assert "tools" in desc


def test_no_file_or_folder_created_on_import_or_registration(clean_home: Dict[str, Path]) -> None:
    before_home = _snapshot_tree(clean_home["home"])
    before_base = _snapshot_tree(clean_home["base"])

    pkg = ensure_test_package("test_import_clean.defuzz")
    ws = load_submodule("workspace_root", package_name="test_import_clean.defuzz")
    ctx = _FakePluginContext()
    pkg.register(ctx)
    res = ws.resolve_projects_root(ctx=ctx)

    assert res.path is None
    assert res.source == "unset"
    assert _snapshot_tree(clean_home["home"]) == before_home
    assert _snapshot_tree(clean_home["base"]) == before_base
    assert not (clean_home["home"] / "Tools").exists()


def test_resolution_order_matrix(clean_home: Dict[str, Path]) -> None:
    ws = load_submodule("workspace_root")
    home = clean_home["home"]
    cli_dir = home / "CliFolder"
    cfg_dir = home / "SavedFolder"
    env_dir = home / "EnvFolder"

    # (d) unset when none present
    r_unset = ws.resolve_projects_root(env={"HOME": str(home)}, home=home, hermes_home=clean_home["hermes_home"])
    assert r_unset.path is None
    assert r_unset.source == "unset"
    assert "hermes defuzz folder set" in r_unset.message
    assert "--root" in r_unset.message
    assert "HERMES_PROJECTS_ROOT" in r_unset.message

    # (c) env when setting is empty/unset
    r_env = ws.resolve_projects_root(
        ctx=_FakePluginContext({"projects_root": ""}),
        env={"HOME": str(home), "HERMES_PROJECTS_ROOT": str(env_dir)},
        home=home,
    )
    assert r_env.path == env_dir
    assert r_env.source == "env"

    # (b) saved setting beats env
    r_cfg = ws.resolve_projects_root(
        ctx=_FakePluginContext({"projects_root": str(cfg_dir)}),
        env={"HOME": str(home), "HERMES_PROJECTS_ROOT": str(env_dir)},
        home=home,
    )
    assert r_cfg.path == cfg_dir
    assert r_cfg.source == "setting"

    # (a) explicit CLI --root beats both saved setting and env
    r_cli = ws.resolve_projects_root(
        ctx=_FakePluginContext({"projects_root": str(cfg_dir)}),
        cli_root=cli_dir,
        env={"HOME": str(home), "HERMES_PROJECTS_ROOT": str(env_dir)},
        home=home,
    )
    assert r_cli.path == cli_dir
    assert r_cli.source == "cli"

    # Invalid saved setting fails closed rather than silently falling back to env
    r_bad_cfg = ws.resolve_projects_root(
        ctx=_FakePluginContext({"projects_root": "relative/not-allowed"}),
        env={"HOME": str(home), "HERMES_PROJECTS_ROOT": str(env_dir)},
        home=home,
    )
    assert r_bad_cfg.path is None
    assert r_bad_cfg.source == "setting"
    assert "full path" in r_bad_cfg.message.lower()


@pytest.mark.parametrize("source", ["setting", "env"])
def test_relative_value_in_setting_or_env_is_refused(clean_home: Dict[str, Path], source: str) -> None:
    ws = load_submodule("workspace_root")
    home = clean_home["home"]
    ctx = _FakePluginContext({"projects_root": "rel/folder"} if source == "setting" else {})
    env = {"HOME": str(home), **({"HERMES_PROJECTS_ROOT": "rel/folder"} if source == "env" else {})}

    res = ws.resolve_projects_root(ctx=ctx, env=env, home=home)
    assert res.path is None
    assert res.source == source
    assert "full path" in res.message.lower()

    with pytest.raises(ws.WorkspaceRootError, match="(?i)full path"):
        ws.ensure_projects_root(ctx=ctx, env=env, home=home, interactive=False)


def test_validation_refuses_home_root_hermes_system_symlink_project_and_readonly(
    clean_home: Dict[str, Path],
) -> None:
    ws = load_submodule("workspace_root")
    home = clean_home["home"]
    hermes_home = clean_home["hermes_home"]
    base = clean_home["base"]

    # 1. Filesystem root
    with pytest.raises(ws.WorkspaceRootError):
        ws.validate_projects_root("/", home=home, hermes_home=hermes_home)

    # 2. Home folder itself (and '~')
    for candidate in (str(home), "~"):
        with pytest.raises(ws.WorkspaceRootError, match="(?i)home folder"):
            ws.validate_projects_root(candidate, home=home, hermes_home=hermes_home)

    # 3. Folder containing home
    with pytest.raises(ws.WorkspaceRootError, match="(?i)home folder"):
        ws.validate_projects_root(str(base), home=home, hermes_home=hermes_home)

    # 4. Inside Hermes home (default, active profile, cache/scratch, and symlink into Hermes home)
    active_profile = home / ".hermes" / "profiles" / "work"
    active_profile.mkdir(parents=True)
    link_into_hermes = home / " sneaky-hermes-link"
    link_into_hermes.symlink_to(active_profile / "sub")
    for bad_hermes in (
        hermes_home,
        hermes_home / "projects",
        hermes_home / "cache" / "scratch" / "projects",
        active_profile / "projects",
        link_into_hermes / "projects",
    ):
        with pytest.raises(ws.WorkspaceRootError, match="(?i)hermes"):
            ws.validate_projects_root(bad_hermes, home=home, hermes_home=active_profile)

    # 5. System folders
    for sys_dir in ("/etc/projects", "/usr/local/projects", "/var/lib/projects", "/proc/projects", "/sys/projects", "/dev/projects", "/run/projects", "/tmp"):
        with pytest.raises(ws.WorkspaceRootError, match="(?i)system|cannot use"):
            ws.validate_projects_root(sys_dir, home=home, hermes_home=hermes_home)

    # 6. Symlink root itself
    real_target = home / "RealFolder"
    real_target.mkdir()
    sym_root = home / "SymFolder"
    sym_root.symlink_to(real_target)
    with pytest.raises(ws.WorkspaceRootError, match="(?i)symbolic link|symlink"):
        ws.validate_projects_root(sym_root, home=home, hermes_home=hermes_home)

    # 7. Existing regular file at target or parent
    file_target = home / "not_a_dir.txt"
    file_target.write_text("hello\n", encoding="utf-8")
    for bad_file_path in (file_target, file_target / "nested"):
        with pytest.raises(ws.WorkspaceRootError):
            ws.validate_projects_root(bad_file_path, home=home, hermes_home=hermes_home)

    # 8. Existing project root itself or subfolder inside an existing project
    existing_proj = home / "existing-app"
    existing_proj.mkdir()
    (existing_proj / "pyproject.toml").write_text("[project]\nname = 'app'\n", encoding="utf-8")
    for inside_proj in (existing_proj, existing_proj / "sub" / "projects"):
        with pytest.raises(ws.WorkspaceRootError, match="(?i)project"):
            ws.validate_projects_root(inside_proj, home=home, hermes_home=hermes_home)

    git_proj = home / "git-only-repo"
    (git_proj / ".git").mkdir(parents=True)
    with pytest.raises(ws.WorkspaceRootError, match="(?i)project"):
        ws.validate_projects_root(git_proj / "nested", home=home, hermes_home=hermes_home)

    # A folder that holds sibling projects (no project marker at its own top level) IS allowed
    umbrella = home / "Tools"
    (umbrella / "proj-one").mkdir(parents=True)
    (umbrella / "proj-one" / "Cargo.toml").write_text("[package]\nname = 'one'\n", encoding="utf-8")
    assert ws.validate_projects_root(umbrella, home=home, hermes_home=hermes_home) == umbrella

    # 9. Read-only parent (checked without creating anything)
    ro_parent = home / "readonly_area"
    ro_parent.mkdir()
    ro_parent.chmod(0o555)
    try:
        with pytest.raises(ws.WorkspaceRootError, match="(?i)writable"):
            ws.validate_projects_root(ro_parent / "Tools", home=home, hermes_home=hermes_home)
        assert not (ro_parent / "Tools").exists()
    finally:
        ro_parent.chmod(0o755)


def test_unicode_and_spaces_valid_without_creating_folder(clean_home: Dict[str, Path]) -> None:
    ws = load_submodule("workspace_root")
    home = clean_home["home"]
    fancy = home / "Mes Outils Café 2026"
    validated = ws.validate_projects_root("~/Mes Outils Café 2026", home=home, hermes_home=clean_home["hermes_home"])
    assert validated == fancy
    assert not fancy.exists()


def test_non_terminal_returns_message_and_leaves_tmp_home_byte_unchanged(
    clean_home: Dict[str, Path],
) -> None:
    ws = load_submodule("workspace_root")
    before = _snapshot_tree(clean_home["base"])
    out = _PipeStream()

    with pytest.raises(ws.WorkspaceRootError) as exc_info:
        ws.ensure_projects_root(
            stdin=_PipeStream(""),
            stdout=out,
            home=clean_home["home"],
            hermes_home=clean_home["hermes_home"],
        )

    msg = str(exc_info.value)
    assert "hermes defuzz folder set" in msg
    assert "--root" in msg
    assert "HERMES_PROJECTS_ROOT" in msg
    assert out.getvalue() == ""
    assert _snapshot_tree(clean_home["base"]) == before


def test_first_run_prompt_enter_saves_tools_once_and_reuses_without_reprompting(
    clean_home: Dict[str, Path],
) -> None:
    ws = load_submodule("workspace_root")
    home = clean_home["home"]
    out1 = _TTYStream()

    chosen = ws.ensure_projects_root(
        stdin=_TTYStream("\n"),
        stdout=out1,
        home=home,
        hermes_home=clean_home["hermes_home"],
    )
    expected = home / "Tools"
    assert chosen == expected
    # Choosing saves the setting only; folder is created when the first project is created.
    assert not expected.exists()
    prompt_text = out1.getvalue()
    assert str(expected) in prompt_text
    assert "nothing else" in prompt_text.lower()

    # Subsequent call — even without a terminal — reuses the saved setting and never prompts.
    out2 = _PipeStream()
    reused = ws.ensure_projects_root(
        stdin=_PipeStream(""),
        stdout=out2,
        home=home,
        hermes_home=clean_home["hermes_home"],
    )
    assert reused == expected
    assert out2.getvalue() == ""


def test_first_run_prompt_typed_absolute_tilde_relative_and_refused(
    clean_home: Dict[str, Path],
) -> None:
    ws = load_submodule("workspace_root")
    home = clean_home["home"]
    cwd = clean_home["cwd"]

    # 1. Typed absolute path
    ctx_abs = _FakePluginContext()
    abs_target = home / "AbsProjects"
    res_abs = ws.ensure_projects_root(
        ctx=ctx_abs,
        stdin=_TTYStream(f"{abs_target}\n"),
        stdout=_TTYStream(),
        home=home,
        hermes_home=clean_home["hermes_home"],
    )
    assert res_abs == abs_target
    assert ctx_abs.values["projects_root"] == str(abs_target)
    assert not abs_target.exists()

    # 2. Typed ~/x path
    ctx_tilde = _FakePluginContext()
    res_tilde = ws.ensure_projects_root(
        ctx=ctx_tilde,
        stdin=_TTYStream("~/Custom Box\n"),
        stdout=_TTYStream(),
        home=home,
        hermes_home=clean_home["hermes_home"],
    )
    assert res_tilde == home / "Custom Box"
    assert ctx_tilde.values["projects_root"] == str(home / "Custom Box")

    # 3. Typed relative path resolved against cwd and shown back before saving
    ctx_rel = _FakePluginContext()
    rel_out = _TTYStream()
    res_rel = ws.ensure_projects_root(
        ctx=ctx_rel,
        stdin=_TTYStream("local-tools\n"),
        stdout=rel_out,
        home=home,
        hermes_home=clean_home["hermes_home"],
        cwd=cwd,
    )
    expected_rel = cwd / "local-tools"
    assert res_rel == expected_rel
    assert ctx_rel.values["projects_root"] == str(expected_rel)
    assert str(expected_rel) in rel_out.getvalue()

    # 4. Refused path of each kind at prompt and `folder set`: nothing saved, nothing created
    sym_target = home / "RealTarget"
    sym_target.mkdir()
    sym_link = home / "LinkRoot"
    sym_link.symlink_to(sym_target)

    proj_dir = home / "ExistingRepo"
    (proj_dir / ".git").mkdir(parents=True)

    ro_dir = home / "ReadOnlyParent"
    ro_dir.mkdir()
    ro_dir.chmod(0o555)
    try:
        refused_inputs = [
            "/",
            "~",
            str(clean_home["hermes_home"] / "inside"),
            "/etc/projects",
            str(sym_link),
            f"{sym_link}/",
            str(proj_dir / "nested"),
            str(ro_dir / "Tools"),
        ]
        for bad_input in refused_inputs:
            ctx_bad = _FakePluginContext()
            with pytest.raises(ws.WorkspaceRootError):
                ws.ensure_projects_root(
                    ctx=ctx_bad,
                    stdin=_TTYStream(f"{bad_input}\n"),
                    stdout=_TTYStream(),
                    home=home,
                    hermes_home=clean_home["hermes_home"],
                )
            assert "projects_root" not in ctx_bad.values, bad_input

        # Relative input when cwd itself is inside an existing project
        ctx_rel_proj = _FakePluginContext()
        with pytest.raises(ws.WorkspaceRootError, match="(?i)project"):
            ws.ensure_projects_root(
                ctx=ctx_rel_proj,
                stdin=_TTYStream("sub-tools\n"),
                stdout=_TTYStream(),
                home=home,
                hermes_home=clean_home["hermes_home"],
                cwd=proj_dir,
            )
        assert "projects_root" not in ctx_rel_proj.values

        # EOF without newline at prompt saves nothing
        ctx_eof = _FakePluginContext()
        with pytest.raises(ws.WorkspaceRootError):
            ws.ensure_projects_root(
                ctx=ctx_eof,
                stdin=_TTYStream(""),
                stdout=_TTYStream(),
                home=home,
                hermes_home=clean_home["hermes_home"],
            )
        assert "projects_root" not in ctx_eof.values
    finally:
        ro_dir.chmod(0o755)


def test_env_var_users_are_never_prompted(
    clean_home: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = load_submodule("workspace_root")
    env_target = clean_home["home"] / "LegacyProjects"
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(env_target))
    before = _snapshot_tree(clean_home["base"])

    def _boom_stdin() -> Any:
        raise AssertionError("stdin must not be read when HERMES_PROJECTS_ROOT is set")

    bad_in = _TTYStream()
    monkeypatch.setattr(bad_in, "readline", _boom_stdin)
    out = _TTYStream()

    resolved = ws.ensure_projects_root(stdin=bad_in, stdout=out)
    assert resolved == env_target
    assert out.getvalue() == ""
    assert _snapshot_tree(clean_home["base"]) == before


def test_profile_awareness_isolates_settings_per_active_profile(
    clean_home: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = load_submodule("workspace_root")
    home = clean_home["home"]
    prof_a = home / ".hermes" / "profiles" / "alpha"
    prof_b = home / ".hermes" / "profiles" / "beta"
    prof_a.mkdir(parents=True)
    prof_b.mkdir(parents=True)
    (home / ".hermes" / "config.yaml").write_text("{}\n", encoding="utf-8")
    (prof_a / "config.yaml").write_text("{}\n", encoding="utf-8")
    (prof_b / "config.yaml").write_text("{}\n", encoding="utf-8")

    import hermes_constants

    monkeypatch.setenv("HERMES_HOME", str(prof_a))
    hermes_constants.reset_hermes_home_key_cache()
    ws.set_projects_root(home / "AlphaTools")

    monkeypatch.setenv("HERMES_HOME", str(prof_b))
    hermes_constants.reset_hermes_home_key_cache()
    assert ws.resolve_projects_root().source == "unset"
    ws.set_projects_root(home / "BetaTools")

    monkeypatch.setenv("HERMES_HOME", str(prof_a))
    hermes_constants.reset_hermes_home_key_cache()
    assert ws.resolve_projects_root().path == home / "AlphaTools"

    monkeypatch.setenv("HERMES_HOME", str(prof_b))
    hermes_constants.reset_hermes_home_key_cache()
    assert ws.resolve_projects_root().path == home / "BetaTools"


def _patch_scaffolder_root(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Simulate the one-line swap in scaffolder.projects_root()."""
    ws = load_submodule("workspace_root")
    scaffolder = load_submodule("scaffolder")
    kit_scaffold = load_submodule("kit_scaffold")
    swapped = lambda: ws.ensure_projects_root(interactive=False, error_cls=scaffolder.ScaffoldError)
    monkeypatch.setattr(scaffolder, "projects_root", swapped)
    monkeypatch.setattr(kit_scaffold, "projects_root", swapped)
    return scaffolder


def test_cli_folder_show_and_set_subcommand(
    clean_home: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import redirect_stderr, redirect_stdout
    import json
    import sys

    cli = load_submodule("cli")
    ws = load_submodule("workspace_root")
    home = clean_home["home"]
    cwd = clean_home["cwd"]

    # 1. `folder` when not chosen yet
    out = _PipeStream()
    with redirect_stdout(out):
        rc = cli.main(["folder"])
    assert rc == 0
    assert "not chosen" in out.getvalue().lower()
    assert str(home / "Tools") in out.getvalue()

    # 2. `folder --json` when not chosen
    json_out = _PipeStream()
    with redirect_stdout(json_out):
        assert cli.main(["folder", "--json"]) == 0
    payload = json.loads(json_out.getvalue())
    assert payload["path"] is None
    assert payload["source"] == "unset"
    assert payload["default_path"] == str(home / "Tools")

    # 3. `folder set` refused without a terminal; tmp home stays byte-for-byte unchanged
    before = _snapshot_tree(clean_home["base"])
    err = _PipeStream()
    monkeypatch.setattr(sys, "stdin", _PipeStream(""))
    with redirect_stdout(_PipeStream()), redirect_stderr(err):
        assert cli.main(["folder", "set", str(home / "Tools")]) == 1
    assert "terminal" in err.getvalue().lower()
    assert _snapshot_tree(clean_home["base"]) == before

    # 4. `folder set` with relative path in an interactive terminal resolves against cwd,
    # prints resolved path, notes existing projects stay put, and does not mkdir yet.
    monkeypatch.chdir(cwd)
    tty_in = _TTYStream("")
    tty_out = _TTYStream()
    monkeypatch.setattr(sys, "stdin", tty_in)
    with redirect_stdout(tty_out), redirect_stderr(_TTYStream()):
        assert cli.main(["folder", "set", "my-projects"]) == 0
    set_text = tty_out.getvalue()
    expected_rel = cwd / "my-projects"
    assert str(expected_rel) in set_text
    assert "existing projects" in set_text.lower()
    assert not expected_rel.exists()
    assert ws.resolve_projects_root().path == expected_rel
    assert ws.resolve_projects_root().source == "setting"

    # 5. `folder` now shows saved setting
    show_out = _PipeStream()
    with redirect_stdout(show_out):
        assert cli.main(["folder"]) == 0
    assert str(expected_rel) in show_out.getvalue()
    assert "setting" in show_out.getvalue().lower()

    # 6. `folder` shows environment variable when setting is absent
    (clean_home["hermes_home"] / "config.yaml").unlink()
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(home / "FromEnv"))
    env_out = _PipeStream()
    with redirect_stdout(env_out):
        assert cli.main(["folder"]) == 0
    assert str(home / "FromEnv") in env_out.getvalue()
    assert "HERMES_PROJECTS_ROOT" in env_out.getvalue()


def test_cli_new_noninteractive_unset_fails_without_touching_disk(
    clean_home: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import redirect_stderr, redirect_stdout
    import json
    import sys

    _patch_scaffolder_root(monkeypatch)
    cli = load_submodule("cli")
    pkg = ensure_test_package()
    fixtures_dir = REPO_ROOT / "tests" / "fixtures" / "templates"
    answers_json = json.dumps(
        {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}
    )

    before = _snapshot_tree(clean_home["base"])
    monkeypatch.setattr(sys, "stdin", _PipeStream(""))
    out = _PipeStream()
    err = _PipeStream()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(
            [
                "new",
                "--answers",
                answers_json,
                "--name",
                "Headless Game",
                "--template",
                "fake-rust-game",
                "--yes",
                "--templates-root",
                str(fixtures_dir),
            ]
        )
    assert rc != 0
    assert "hermes defuzz folder set" in err.getvalue()
    assert "--root" in err.getvalue()
    assert "HERMES_PROJECTS_ROOT" in err.getvalue()
    assert _snapshot_tree(clean_home["base"]) == before

    # Slash command `/defuzz new ...` also refuses without blocking even if process stdin is a TTY
    def _must_not_read() -> str:
        raise AssertionError("slash command must never block reading stdin")

    tty_in = _TTYStream()
    monkeypatch.setattr(tty_in, "readline", _must_not_read)
    monkeypatch.setattr(sys, "stdin", tty_in)
    slash_res = pkg._handle_slash_command(
        _FakePluginContext(),
        f"new --name Demo --template fake-rust-game --templates-root {fixtures_dir}",
    )
    assert "hermes defuzz folder set" in slash_res
    assert "exit code: 1" in slash_res.lower()
    assert _snapshot_tree(clean_home["base"]) == before


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_cli_new_first_run_prompt_and_reuse_with_swapped_scaffolder(
    clean_home: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import redirect_stderr, redirect_stdout
    import json
    import sys

    scaffolder = _patch_scaffolder_root(monkeypatch)
    cli = load_submodule("cli")
    templates = load_submodule("templates")
    fixtures_dir = REPO_ROOT / "tests" / "fixtures" / "templates"
    answers = {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"}
    answers_json = json.dumps(answers)
    home = clean_home["home"]
    tools_dir = home / "Tools"

    # Direct scaffolder.propose fails cleanly before any folder is chosen
    spec = templates.load_template(fixtures_dir / "fake-rust-game")
    with pytest.raises(scaffolder.ScaffoldError, match="hermes defuzz folder set"):
        scaffolder.propose(spec, "Unset Direct", answers)

    monkeypatch.setattr(
        cli,
        "REGISTER_PROJECT",
        lambda n, p: json.dumps({"success": True, "id": "p-1", "name": n, "path": p}),
    )

    # 0. Without --template/--kit nothing is chosen, even with --yes: exit 2, no folder
    # question, no saved setting, nothing written.
    before = _snapshot_tree(clean_home["base"])
    monkeypatch.setattr(sys, "stdin", _PipeStream(""))
    none_out = _PipeStream()
    with redirect_stdout(none_out), redirect_stderr(_PipeStream()):
        rc_none = cli.main(
            ["new", "--answers", answers_json, "--name", "No Choice", "--yes",
             "--templates-root", str(fixtures_dir)]
        )
    assert rc_none == 2
    assert "Nothing was created. Run again with --template ID or --kit ID." in none_out.getvalue()
    after = _snapshot_tree(clean_home["base"])
    # Listing the kits opens the companion's (empty) plugin-data folder; nothing else may appear
    # and no existing entry may change.
    added = set(after) - set(before)
    assert added <= {"dir:user/.hermes/plugin-data", "dir:user/.hermes/plugin-data/defuzz"}
    assert {key: after[key] for key in before} == before
    assert not tools_dir.exists()

    # 1. First run in terminal (dry-run without --yes): asks once, saves ~/Tools, does NOT create ~/Tools yet
    monkeypatch.setattr(sys, "stdin", _TTYStream("\n"))
    dry_out = _TTYStream()
    with redirect_stdout(dry_out), redirect_stderr(_TTYStream()):
        rc_dry = cli.main(
            [
                "new",
                "--answers",
                answers_json,
                "--name",
                "First Dry",
                "--template",
                "fake-rust-game",
                "--templates-root",
                str(fixtures_dir),
            ]
        )
    assert rc_dry == 0
    assert str(tools_dir / "first-dry") in dry_out.getvalue()
    assert not tools_dir.exists()

    # 2. Second run (--yes, even non-interactive now because setting is saved): creates ~/Tools/second-real without prompting
    monkeypatch.setattr(sys, "stdin", _PipeStream(""))
    yes_out = _PipeStream()
    with redirect_stdout(yes_out), redirect_stderr(_PipeStream()):
        rc_yes = cli.main(
            [
                "new",
                "--answers",
                answers_json,
                "--name",
                "Second Real",
                "--template",
                "fake-rust-game",
                "--yes",
                "--templates-root",
                str(fixtures_dir),
            ]
        )
    assert rc_yes == 0
    created_repo = tools_dir / "second-real"
    assert (created_repo / ".git").is_dir()
    assert str(created_repo) in yes_out.getvalue()

    # 3. `--root` flag overrides saved setting for one invocation without changing saved setting
    one_off = home / "OneOff"
    root_out = _PipeStream()
    with redirect_stdout(root_out), redirect_stderr(_PipeStream()):
        rc_root = cli.main(
            [
                "new",
                "--answers",
                answers_json,
                "--name",
                "One Off App",
                "--template",
                "fake-rust-game",
                "--root",
                str(one_off),
                "--yes",
                "--templates-root",
                str(fixtures_dir),
            ]
        )
    assert rc_root == 0
    assert (one_off / "one-off-app" / ".git").is_dir()
    assert load_submodule("workspace_root").resolve_projects_root().path == tools_dir


def test_dashboard_projects_root_read_route_and_propose_gate(
    clean_home: Dict[str, Path],
) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    api = load_submodule("dashboard.plugin_api")
    ws = api._load("workspace_root")
    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)

    home = clean_home["home"]
    before = _snapshot_tree(clean_home["base"])

    # 1. Read route when unset returns source='unset' and default_path without touching disk
    resp = client.get("/scaffold/projects-root")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["path"] is None
    assert data["source"] == "unset"
    assert data["valid"] is True
    assert data["default_path"] == str(home / "Tools")
    assert "hermes defuzz folder set" in data["message"]
    assert _snapshot_tree(clean_home["base"]) == before

    # 2. Candidate validation query param (read-only, never saves or creates)
    cand_ok = client.get("/scaffold/projects-root", params={"candidate": "~/Tools"}).json()
    assert cand_ok["candidate"]["valid"] is True
    assert cand_ok["candidate"]["path"] == str(home / "Tools")
    assert not (home / "Tools").exists()

    cand_bad = client.get("/scaffold/projects-root", params={"candidate": "~"}).json()
    assert cand_bad["candidate"]["valid"] is False
    assert cand_bad["candidate"]["path"] is None
    assert "home folder" in cand_bad["candidate"]["message"].lower()

    # 3. Propose without dest_root when unset returns 400 with plain message and leaves home unchanged
    prop_unset = client.post(
        "/scaffold/propose",
        json={
            "template_id": "python-golden",
            "name": "Ledger",
            "answers": {"kind": "service", "layout": "single", "languages": ["python"]},
        },
    )
    assert prop_unset.status_code == 400
    assert "hermes defuzz folder set" in prop_unset.text
    assert _snapshot_tree(clean_home["base"]) == before

    # 4. Once saved in settings, read route reports source='setting' and propose uses it
    ws.set_projects_root(home / "Tools")
    resp_set = client.get("/scaffold/projects-root").json()
    assert resp_set["path"] == str(home / "Tools")
    assert resp_set["source"] == "setting"
    assert resp_set["valid"] is True

    prop_ok = client.post(
        "/scaffold/propose",
        json={
            "template_id": "python-golden",
            "name": "Ledger",
            "answers": {"kind": "service", "layout": "single", "languages": ["python"]},
        },
    )
    assert prop_ok.status_code == 200, prop_ok.text
    p_json = prop_ok.json()
    assert p_json["tree"][0]["dest"] == str(home / "Tools" / "ledger")
    assert not (home / "Tools").exists()
    assert client.post("/scaffold/discard", json={"proposal_id": p_json["proposal_id"]}).status_code == 200


def test_docs_describe_projects_folder_setting() -> None:
    doc_path = REPO_ROOT / "docs" / "projects-folder.md"
    assert doc_path.is_file()
    doc = doc_path.read_text(encoding="utf-8")
    for required in ("projects_root", "HERMES_PROJECTS_ROOT", "hermes defuzz folder"):
        assert required in doc


