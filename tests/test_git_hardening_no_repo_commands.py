"""Regression and hardening tests: repository git config cannot execute commands, while ordinary repos work."""

from __future__ import annotations

import ast
import os
import subprocess
from pathlib import Path

import pytest

from tests import ensure_test_package
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401

ensure_test_package()

from hermes_plugins.defuzz import placer  # noqa: E402
from hermes_plugins.defuzz.applier import apply_rules_to_copy  # noqa: E402
from hermes_plugins.defuzz.rules import build_deterministic_fallback_rules  # noqa: E402
from hermes_plugins.defuzz.safety import (  # noqa: E402
    _ALLOWED_GIT_SUBCOMMANDS,
    HARDENED_GIT_CONFIG_ARGS,
    SafetyError,
    assert_safe_repo_for_git,
    copy_tree_nofollow,
    format_unsafe_repo_git_settings_message,
    hardened_git_env,
    run_git_hardened,
)
from hermes_plugins.defuzz.scanner import (  # noqa: E402
    UnsupportedGitLayoutError,
    inspect_git_layout,
    scan_folder,
)

HOOK_NAMES: tuple[str, ...] = (
    "pre-commit",
    "commit-msg",
    "post-commit",
    "post-checkout",
    "post-index-change",
    "reference-transaction",
)


def _git_raw(repo: Path, *args: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(repo.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        env=env,
        check=True,
        capture_output=True,
    )


def _init_plain_repo(repo: Path) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    _git_raw(repo, "init", "-b", "main")
    _git_raw(repo, "config", "user.name", "t")
    _git_raw(repo, "config", "user.email", "t@example.invalid")
    return repo


def _make_marker_script(
    scripts_dir: Path,
    name: str,
    marker: Path,
    *,
    passthrough: bool = False,
    exit_code: int = 0,
) -> Path:
    scripts_dir.mkdir(parents=True, exist_ok=True)
    script = scripts_dir / name
    lines = ["#!/bin/sh", f"echo {name!r} >> {str(marker)!r}"]
    if passthrough:
        lines.append("cat")
    lines.append(f"exit {exit_code}")
    script.write_text("\n".join(lines) + "\n", encoding="utf-8")
    script.chmod(0o755)
    return script


def _plant_all_hooks(hooks_dir: Path, marker: Path) -> None:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    for hook_name in HOOK_NAMES:
        _make_marker_script(hooks_dir, hook_name, marker)


def _append_git_config(repo: Path, snippet: str) -> None:
    with (repo / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write("\n" + snippet.lstrip("\n"))


def _seed_adoptable_repo_tree(repo: Path, *, gitattributes_line: str | None = None) -> None:
    """Populate tracked files (including loose .md files moved via `git mv` and a tracked .env untracked via `git rm --cached`)."""
    if gitattributes_line:
        (repo / ".gitattributes").write_text(gitattributes_line + "\n", encoding="utf-8")
    (repo / "README.md").write_text("# Sample Project\n", encoding="utf-8")
    (repo / "src").mkdir(exist_ok=True)
    (repo / "src" / "main.py").write_text("print('v1')\n", encoding="utf-8")
    # 6 loose top-level markdown notes trigger deterministic move -> docs/ via `git mv`
    for idx in range(6):
        (repo / f"note_{idx}.md").write_text(f"# Note {idx}\n", encoding="utf-8")
    # Tracked .env triggers `git rm --cached -f -- .env` during baseline staging
    (repo / ".env").write_text("LOCAL_DEV=1\n", encoding="utf-8")
    _git_raw(repo, "add", "-f", ".")
    _git_raw(repo, "commit", "-m", "initial")
    # Modify a tracked file and add an untracked file so status/diff/restore/clean have real work
    (repo / "src" / "main.py").write_text("print('v2')\n", encoding="utf-8")
    (repo / "scratch_untracked.txt").write_text("untracked\n", encoding="utf-8")


def _exercise_all_plugin_git_flows(
    src: Path,
    work_root: Path,
    marker: Path,
) -> dict[str, object]:
    """Run assert_safe_repo_for_git, scan, apply (ls-files/rm/add/diff/commit/mv), placer add, and diff/log/show/restore/reset/clean."""
    copy_dir = work_root / "copy"
    staging = work_root / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    copy_tree_nofollow(src, copy_dir, staging_root=staging)

    assert_safe_repo_for_git(copy_dir)
    assert not marker.exists()

    layout = inspect_git_layout(copy_dir)
    assert layout["layout_refused"] is False, layout["layout_refusal_reasons"]
    assert not marker.exists()

    inv = scan_folder(copy_dir, source_root=src)
    assert not marker.exists()

    # Exercise unstaged diff before apply commits changes
    diff_proc = run_git_hardened(copy_dir, ["diff"])
    assert diff_proc.returncode == 0
    assert not marker.exists()

    rules = build_deterministic_fallback_rules(inv)
    db_path = staging / "state.db"
    report = apply_rules_to_copy(
        copy_dir,
        inv,
        rules,
        source_root=src,
        staging_root=staging,
        db_path=db_path,
    )
    assert report["baseline_commit_sha"]
    assert report["adopted_commit_sha"]
    assert report["counts"]["moved"] >= 6
    assert report["counts"]["untracked_from_index"] >= 1
    assert not marker.exists()

    # Exercise placer git flow (`add -f -- .adopt/rules.json AGENTS.md`)
    placer.trust_project(copy_dir, db_path=db_path)
    placer.add_placement_rule(copy_dir, ".log", "docs", kind="logs", db_path=db_path)
    assert not marker.exists()

    # Exercise remaining allowed subcommands used by scaffolder survey rollback and tests
    assert run_git_hardened(copy_dir, ["log", "-p", "-1"]).returncode == 0
    assert run_git_hardened(copy_dir, ["show", "HEAD"]).returncode == 0
    assert run_git_hardened(copy_dir, ["ls-tree", "-r", "--name-only", "HEAD"]).returncode == 0
    assert run_git_hardened(copy_dir, ["reset", "-q", "HEAD", "--", ".adopt/rules.json", "AGENTS.md"]).returncode == 0
    assert (
        run_git_hardened(
            copy_dir,
            ["restore", "--source=HEAD", "--worktree", "--", ".adopt/rules.json", "AGENTS.md"],
        ).returncode
        == 0
    )
    (copy_dir / "ephemeral.tmp").write_text("temp\n", encoding="utf-8")
    assert run_git_hardened(copy_dir, ["clean", "-f", "--", "ephemeral.tmp"]).returncode == 0
    assert not (copy_dir / "ephemeral.tmp").exists()
    assert not marker.exists()
    return {"copy_dir": copy_dir, "report": report, "layout": layout}


def test_filter_clean_in_copied_repo_never_executes_and_fails_closed(tmp_path: Path) -> None:
    """Reproducer for release blocker: filter.evil.clean + .gitattributes must never execute."""
    src = _init_plain_repo(tmp_path / "src")
    marker = tmp_path / "filter_clean_marker"
    script = _make_marker_script(tmp_path / "bin", "evil_clean.sh", marker, passthrough=True)

    (src / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
    (src / "note.txt").write_text("v1\n", encoding="utf-8")
    _git_raw(src, "add", ".gitattributes", "note.txt")
    _git_raw(src, "commit", "-m", "initial")
    _append_git_config(src, f'[filter "evil"]\n\tclean = {script}\n')

    expected_msg = format_unsafe_repo_git_settings_message([("a custom filter", "filter.evil.clean")])
    assert expected_msg == (
        "This repository's own git settings include a custom filter (filter.evil.clean), "
        "which can run programs and cannot be switched off from outside. "
        "Defuzz will not run git in it. "
        "Remove that setting in the copy, or adopt a copy without its .git folder."
    )

    copy_dir = tmp_path / "copy"
    staging = tmp_path / "staging"
    staging.mkdir()
    copy_tree_nofollow(src, copy_dir, staging_root=staging)

    with pytest.raises(SafetyError) as exc_pre:
        assert_safe_repo_for_git(copy_dir)
    assert expected_msg in str(exc_pre.value)
    assert not marker.exists()

    layout = inspect_git_layout(copy_dir)
    assert not marker.exists(), "inspect_git_layout executed filter.evil.clean!"
    assert layout["layout_refused"] is True
    assert any(expected_msg == r["detail"] for r in layout["layout_refusal_reasons"])

    with pytest.raises(UnsupportedGitLayoutError) as exc_scan:
        scan_folder(copy_dir, source_root=src)
    assert expected_msg in str(exc_scan.value)
    assert not marker.exists()

    inv_untrusted = scan_folder(copy_dir, source_root=src, refuse_unsupported=False)
    rules = build_deterministic_fallback_rules(inv_untrusted)
    with pytest.raises(UnsupportedGitLayoutError) as exc_apply:
        apply_rules_to_copy(
            copy_dir,
            inv_untrusted,
            rules,
            source_root=src,
            staging_root=staging,
            db_path=staging / "state.db",
        )
    assert expected_msg in str(exc_apply.value)
    assert not marker.exists()

    with pytest.raises(SafetyError) as exc_direct:
        run_git_hardened(copy_dir, ["status", "--porcelain=v1"])
    assert expected_msg in str(exc_direct.value)
    assert not marker.exists()


@pytest.mark.parametrize(
    ("label", "gitattributes_line", "config_snippet_tpl", "expected_kind", "expected_key", "direct_args"),
    [
        (
            "filter_smudge",
            "*.txt filter=evil",
            '[filter "evil"]\n\tsmudge = {script}\n',
            "a custom filter",
            "filter.evil.smudge",
            ["restore", "--source=HEAD", "--worktree", "--", "a.txt"],
        ),
        (
            "filter_process",
            "*.txt filter=evil",
            '[filter "evil"]\n\tprocess = {script}\n',
            "a custom filter",
            "filter.evil.process",
            ["status", "--porcelain=v1"],
        ),
        (
            "filter_uppercase_LFS",
            "*.txt filter=LFS",
            '[filter "LFS"]\n\tclean = {script}\n',
            "a custom filter",
            "filter.LFS.clean",
            ["add", "--", "a.txt"],
        ),
        (
            "filter_no_subsection",
            None,
            "[filter]\n\tclean = {script}\n",
            "a custom filter",
            "filter.clean",
            ["status", "--porcelain=v1"],
        ),
        (
            "core_alternate_refs_command",
            None,
            "[core]\n\talternateRefsCommand = {script}\n",
            "a command hook",
            "core.alternateRefsCommand",
            ["for-each-ref"],
        ),
        (
            "core_gitproxy",
            None,
            "[core]\n\tgitProxy = {script}\n",
            "a command hook",
            "core.gitProxy",
            ["remote", "-v"],
        ),
        (
            "uploadpack_hook",
            None,
            "[uploadpack]\n\tpackObjectsHook = {script}\n",
            "a command hook",
            "uploadpack.packObjectsHook",
            ["status"],
        ),
    ],
)
def test_unoverrideable_repo_config_mechanisms_refuse_and_name_setting_without_marker(
    tmp_path: Path,
    label: str,
    gitattributes_line: str | None,
    config_snippet_tpl: str,
    expected_kind: str,
    expected_key: str,
    direct_args: list[str],
) -> None:
    repo = _init_plain_repo(tmp_path / f"repo_{label}")
    marker = tmp_path / f"marker_{label}"
    script = _make_marker_script(tmp_path / "bin", f"{label}.sh", marker, passthrough=True)

    if gitattributes_line:
        (repo / ".gitattributes").write_text(gitattributes_line + "\n", encoding="utf-8")
        _git_raw(repo, "add", ".gitattributes")
    (repo / "a.txt").write_text("v1\n", encoding="utf-8")
    _git_raw(repo, "add", "a.txt")
    _git_raw(repo, "commit", "-m", "c1")
    (repo / "a.txt").write_text("v2\n", encoding="utf-8")

    _append_git_config(repo, config_snippet_tpl.format(script=script))
    expected_msg = format_unsafe_repo_git_settings_message([(expected_kind, expected_key)])

    with pytest.raises(SafetyError) as exc_assert:
        assert_safe_repo_for_git(repo)
    assert expected_msg in str(exc_assert.value)
    assert not marker.exists(), label

    layout = inspect_git_layout(repo)
    assert layout["layout_refused"] is True, label
    assert any(expected_msg == r["detail"] for r in layout["layout_refusal_reasons"]), label
    assert not marker.exists(), label

    with pytest.raises(UnsupportedGitLayoutError) as exc_scan:
        scan_folder(repo)
    assert expected_msg in str(exc_scan.value)
    assert not marker.exists(), label

    with pytest.raises(SafetyError) as exc_git:
        run_git_hardened(repo, direct_args)
    assert expected_msg in str(exc_git.value)
    assert not marker.exists(), label


@pytest.mark.parametrize(
    ("include_header", "expected_key"),
    [
        ("[include]", "include.path"),
        ('[includeIf "onbranch:main"]', "includeIf.onbranch:main.path"),
        ('[includeIf "gitdir:**"]', "includeIf.gitdir:**.path"),
        ('[INCLUDEIF "gitdir:/"]', "includeIf.gitdir:/.path"),
    ],
)
def test_include_and_includeif_to_filter_file_refuse_without_marker(
    tmp_path: Path,
    include_header: str,
    expected_key: str,
) -> None:
    src = _init_plain_repo(tmp_path / "src")
    marker = tmp_path / "include_marker"
    script = _make_marker_script(tmp_path / "bin", "inc_clean.sh", marker, passthrough=True)
    extra_cfg = tmp_path / "included.gitconfig"
    extra_cfg.write_text(f'[filter "evil"]\n\tclean = {script}\n', encoding="utf-8")

    (src / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
    (src / "a.txt").write_text("v1\n", encoding="utf-8")
    _git_raw(src, "add", ".gitattributes", "a.txt")
    _git_raw(src, "commit", "-m", "c1")
    (src / "a.txt").write_text("v2\n", encoding="utf-8")
    _append_git_config(src, f"{include_header}\n\tpath = {extra_cfg}\n")

    expected_msg = format_unsafe_repo_git_settings_message([("a config include", expected_key)])

    with pytest.raises(SafetyError) as exc_pre:
        assert_safe_repo_for_git(src)
    assert expected_msg in str(exc_pre.value)
    assert not marker.exists()

    with pytest.raises(UnsupportedGitLayoutError) as exc_scan:
        scan_folder(src)
    assert expected_msg in str(exc_scan.value)
    assert not marker.exists()

    with pytest.raises(SafetyError) as exc_direct:
        run_git_hardened(src, ["status", "--porcelain=v1"])
    assert expected_msg in str(exc_direct.value)
    assert not marker.exists()


@pytest.mark.parametrize(
    ("mechanism", "gitattributes_line", "config_builder"),
    [
        (
            "hooks_path_and_git_hooks",
            None,
            lambda script, hooks_dir: f"[core]\n\thooksPath = {hooks_dir}\n",
        ),
        (
            "core_fsmonitor_and_builtin_fsmonitor",
            None,
            lambda script, _hooks_dir: (
                f"[core]\n\tfsmonitor = {script}\n\tfsmonitorHookVersion = 2\n"
                "\tuseBuiltinFSMonitor = true\n"
                "[fsmonitor]\n\tallowRemote = true\n"
            ),
        ),
        (
            "gpg_and_ssh_signing",
            None,
            lambda script, _hooks_dir: (
                "[user]\n\tsigningkey = ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI\n"
                "[commit]\n\tgpgSign = true\n"
                "[tag]\n\tgpgSign\n\tforceSignAnnotated = true\n"
                "[push]\n\tgpgSign = true\n"
                "[log]\n\tshowSignature = true\n"
                f"[gpg]\n\tprogram = {script}\n"
                f'[gpg "openpgp"]\n\tprogram = {script}\n'
                f'[gpg "ssh"]\n\tprogram = {script}\n\tdefaultKeyCommand = {script}\n'
                f'[gpg "x509"]\n\tprogram = {script}\n'
            ),
        ),
        (
            "diff_textconv",
            "* diff=evil",
            lambda script, _hooks_dir: f'[diff "evil"]\n\ttextconv = {script}\n\tcachetextconv = true\n',
        ),
        (
            "diff_command_and_external",
            "* diff=evil",
            lambda script, _hooks_dir: (
                f"[diff]\n\texternal = {script}\n"
                f'[diff "evil"]\n\tcommand = {script}\n'
                "[commit]\n\tverbose = true\n"
            ),
        ),
        (
            "merge_driver",
            "* merge=evil",
            lambda script, _hooks_dir: f'[merge "evil"]\n\tdriver = {script}\n',
        ),
        (
            "core_pager_and_subcommand_pager",
            None,
            lambda script, _hooks_dir: (
                f"[core]\n\tpager = {script}\n"
                f"[pager]\n\tstatus = {script}\n\tdiff = {script}\n\tlog = {script}\n"
            ),
        ),
        (
            "editors_and_merge_diff_gui_tools",
            None,
            lambda script, _hooks_dir: (
                f"[core]\n\teditor = {script}\n"
                f"[sequence]\n\teditor = {script}\n"
                "[commit]\n\ttemplate = /nonexistent/commit-msg.tpl\n"
                f'[merge]\n\ttool = custom\n[mergetool "custom"]\n\tcmd = {script}\n'
                f'[diff]\n\ttool = custom\n[difftool "custom"]\n\tcmd = {script}\n'
                f'[guitool "custom"]\n\tcmd = {script}\n'
            ),
        ),
        (
            "browser_man_interactive_and_sendemail",
            None,
            lambda script, _hooks_dir: (
                f'[browser "evil"]\n\tcmd = {script}\n'
                f"[web]\n\tbrowser = {script}\n"
                "[help]\n\tbrowser = evil\n"
                f'[man "evil"]\n\tcmd = {script}\n'
                f"[interactive]\n\tdiffFilter = {script}\n"
                f"[sendemail]\n\tsmtpServer = {script}\n\ttocmd = {script}\n"
            ),
        ),
        (
            "aliases_shadowing_builtins_and_custom",
            None,
            lambda script, _hooks_dir: (
                f"[alias]\n\tstatus = !{script}\n\tadd = !{script}\n\tcommit = !{script}\n"
                f"\tdiff = !{script}\n\tls-files = !{script}\n\tpwn = !{script}\n"
            ),
        ),
        (
            "credential_helpers_and_askpass",
            None,
            lambda script, _hooks_dir: (
                f"[credential]\n\thelper = store\n\thelper = !{script}\n"
                f'[credential "https://example.invalid"]\n\thelper = !{script}\n'
                f"[core]\n\taskPass = {script}\n"
            ),
        ),
        (
            "ssh_url_protocol_http_and_remotes",
            None,
            lambda script, _hooks_dir: (
                f"[core]\n\tsshCommand = {script}\n"
                f'[url "ext::{script} "]\n\tinsteadOf = https://example.invalid/\n'
                f'[remote "origin"]\n\turl = https://example.invalid/repo.git\n'
                f"\tuploadpack = {script}\n\treceivepack = {script}\n\tproxy = http://127.0.0.1:9\n"
                f'[remote "extremote"]\n\turl = ext::{script}\n'
                "[http]\n\tcookieFile = /nonexistent/cookies.txt\n\tsaveCookies = true\n"
                '[protocol "ext"]\n\tallow = always\n'
            ),
        ),
        (
            "submodule_config_entries_without_submodule",
            None,
            lambda script, _hooks_dir: (
                '[submodule "vendor/old"]\n\turl = https://example.invalid/old.git\n'
                f"\tactive = true\n\tupdate = !{script}\n"
            ),
        ),
        (
            "git_lfs_filters",
            "*.py filter=lfs diff=lfs merge=lfs\n*.md filter=lfs diff=lfs merge=lfs",
            lambda script, _hooks_dir: (
                f'[filter "lfs"]\n\tclean = {script}\n\tsmudge = {script}\n'
                f"\tprocess = {script}\n\trequired = true\n"
            ),
        ),
    ],
)
def test_every_overrideable_mechanism_is_allowed_and_writes_no_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mechanism: str,
    gitattributes_line: str | None,
    config_builder,
) -> None:
    case_root = tmp_path / mechanism
    src = _init_plain_repo(case_root / "src")
    marker = case_root / "marker"
    bin_dir = case_root / "bin"
    script = _make_marker_script(bin_dir, f"{mechanism}.sh", marker, passthrough=True)
    hooks_dir = case_root / "custom_hooks"

    _seed_adoptable_repo_tree(src, gitattributes_line=gitattributes_line)
    _plant_all_hooks(hooks_dir, marker)
    _plant_all_hooks(src / ".git" / "hooks", marker)

    if mechanism == "git_lfs_filters":
        _make_marker_script(bin_dir, "git-lfs", marker, passthrough=True)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}")

    assert not marker.exists(), f"Setup unexpectedly triggered marker for {mechanism}"

    _append_git_config(src, config_builder(script, hooks_dir))

    result = _exercise_all_plugin_git_flows(src, case_root, marker)
    if mechanism == "aliases_shadowing_builtins_and_custom":
        copy_dir = result["copy_dir"]
        assert isinstance(copy_dir, Path)
        with pytest.raises(SafetyError, match="Disallowed git subcommand"):
            run_git_hardened(copy_dir, ["pwn"])
        assert not marker.exists()


def test_positive_controls_prove_marker_scripts_fire_without_hardening(tmp_path: Path) -> None:
    """Prove the planted marker mechanisms genuinely execute under plain `git` before hardening neutralises them."""
    # 1. Hooks (pre-commit via core.hooksPath)
    r_hook = _init_plain_repo(tmp_path / "pos_hook")
    m_hook = tmp_path / "m_hook"
    hooks_dir = tmp_path / "pos_hooks_dir"
    _make_marker_script(hooks_dir, "pre-commit", m_hook)
    _append_git_config(r_hook, f"[core]\n\thooksPath = {hooks_dir}\n")
    _git_raw(r_hook, "commit", "--allow-empty", "-m", "fires-hook")
    assert m_hook.exists()
    m_hook.unlink()
    assert run_git_hardened(r_hook, ["commit", "--allow-empty", "-m", "hardened"], allow_literal_pathspecs=False).returncode == 0
    assert not m_hook.exists()

    # 2. core.fsmonitor
    r_fsm = _init_plain_repo(tmp_path / "pos_fsm")
    m_fsm = tmp_path / "m_fsm"
    s_fsm = _make_marker_script(tmp_path / "bin", "fsm.sh", m_fsm)
    (r_fsm / "a.txt").write_text("x\n", encoding="utf-8")
    _git_raw(r_fsm, "add", "a.txt")
    _git_raw(r_fsm, "commit", "-m", "c1")
    _append_git_config(r_fsm, f"[core]\n\tfsmonitor = {s_fsm}\n")
    _git_raw(r_fsm, "status")
    assert m_fsm.exists()
    m_fsm.unlink()
    assert run_git_hardened(r_fsm, ["status", "--porcelain=v1"]).returncode == 0
    assert not m_fsm.exists()

    # 3. commit.gpgSign + gpg.program
    r_gpg = _init_plain_repo(tmp_path / "pos_gpg")
    m_gpg = tmp_path / "m_gpg"
    s_gpg = _make_marker_script(tmp_path / "bin", "gpg.sh", m_gpg, exit_code=1)
    _append_git_config(r_gpg, f"[commit]\n\tgpgSign = true\n[gpg]\n\tprogram = {s_gpg}\n")
    subprocess.run(
        ["git", "-C", str(r_gpg), "-c", "user.name=t", "-c", "user.email=t@e", "commit", "--allow-empty", "-m", "s"],
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
        capture_output=True,
    )
    assert m_gpg.exists()
    m_gpg.unlink()
    assert run_git_hardened(r_gpg, ["commit", "--allow-empty", "-m", "s"], allow_literal_pathspecs=False).returncode == 0
    assert not m_gpg.exists()

    # 4. diff.<name>.command & diff.<name>.textconv
    r_diff = _init_plain_repo(tmp_path / "pos_diff")
    m_diff = tmp_path / "m_diff"
    s_diff = _make_marker_script(tmp_path / "bin", "diffdrv.sh", m_diff)
    (r_diff / ".gitattributes").write_text("*.txt diff=evil\n", encoding="utf-8")
    (r_diff / "a.txt").write_text("v1\n", encoding="utf-8")
    _git_raw(r_diff, "add", ".gitattributes", "a.txt")
    _git_raw(r_diff, "commit", "-m", "c1")
    (r_diff / "a.txt").write_text("v2\n", encoding="utf-8")
    _append_git_config(r_diff, f'[diff "evil"]\n\tcommand = {s_diff}\n')
    _git_raw(r_diff, "diff")
    assert m_diff.exists()
    m_diff.unlink()
    assert run_git_hardened(r_diff, ["diff"]).returncode == 0
    assert not m_diff.exists()

    # 5. filter.lfs.clean via fake git-lfs on PATH
    r_lfs = _init_plain_repo(tmp_path / "pos_lfs")
    m_lfs = tmp_path / "m_lfs"
    lfs_bin = tmp_path / "lfs_bin"
    _make_marker_script(lfs_bin, "git-lfs", m_lfs, passthrough=True)
    (r_lfs / ".gitattributes").write_text("*.bin filter=lfs\n", encoding="utf-8")
    (r_lfs / "x.bin").write_bytes(b"payload")
    _append_git_config(r_lfs, '[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\trequired = true\n')
    path_with_lfs = f"{lfs_bin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
    _git_raw(r_lfs, "add", ".gitattributes", "x.bin", env_extra={"PATH": path_with_lfs})
    assert m_lfs.exists()
    m_lfs.unlink()
    (r_lfs / "x.bin").write_bytes(b"payload-2")
    old_path = os.environ.get("PATH", "")
    try:
        os.environ["PATH"] = path_with_lfs
        assert run_git_hardened(r_lfs, ["add", "--", "x.bin"]).returncode == 0
    finally:
        os.environ["PATH"] = old_path
    assert not m_lfs.exists()


@pytest.mark.parametrize(
    "archetype",
    [
        "husky_repo",
        "gpg_signing_repo",
        "editor_tools_repo",
        "credential_helper_repo",
        "lfs_repo",
        "plain_submodule_config_repo",
        "windows_core_settings_repo",
        "normal_clone_repo",
    ],
)
def test_ordinary_repository_archetypes_accepted_and_complete_scan_and_apply_without_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    archetype: str,
) -> None:
    case_dir = tmp_path / archetype
    src = _init_plain_repo(case_dir / "src")
    marker = case_dir / "marker"
    bin_dir = case_dir / "bin"
    script = _make_marker_script(bin_dir, f"{archetype}.sh", marker, passthrough=True)

    gitattr: str | None = None
    lfs_pointer_bytes = (
        b"version https://git-lfs.github.com/spec/v1\n"
        b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
        b"size 12345\n"
    )

    if archetype == "lfs_repo":
        gitattr = "*.bin filter=lfs diff=lfs merge=lfs -text"
        (src / "assets").mkdir()
        (src / "assets" / "model.bin").write_bytes(lfs_pointer_bytes)
        _make_marker_script(bin_dir, "git-lfs", marker, passthrough=True)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}")

    _seed_adoptable_repo_tree(src, gitattributes_line=gitattr)

    if archetype == "husky_repo":
        _plant_all_hooks(src / ".husky", marker)
        _plant_all_hooks(src / ".git" / "hooks", marker)
        _append_git_config(src, "[core]\n\thooksPath = .husky\n")
    elif archetype == "gpg_signing_repo":
        _append_git_config(
            src,
            "[user]\n\tsigningkey = ABCDEF1234567890\n"
            "[commit]\n\tgpgsign = true\n"
            "[tag]\n\tgpgsign = true\n"
            f"[gpg]\n\tformat = openpgp\n\tprogram = {script}\n",
        )
    elif archetype == "editor_tools_repo":
        _append_git_config(
            src,
            f"[core]\n\teditor = {script}\n\tpager = {script}\n"
            f'[merge]\n\ttool = vscode\n[mergetool "vscode"]\n\tcmd = {script}\n'
            f'[diff]\n\ttool = vscode\n[difftool "vscode"]\n\tcmd = {script}\n',
        )
    elif archetype == "credential_helper_repo":
        _append_git_config(
            src,
            f"[credential]\n\thelper = store\n\thelper = !{script}\n"
            f"[core]\n\taskPass = {script}\n\tsshCommand = {script}\n",
        )
    elif archetype == "lfs_repo":
        _plant_all_hooks(src / ".git" / "hooks", marker)
        _append_git_config(
            src,
            '[filter "lfs"]\n'
            "\tclean = git-lfs clean -- %f\n"
            "\tsmudge = git-lfs smudge -- %f\n"
            "\tprocess = git-lfs filter-process\n"
            "\trequired = true\n",
        )
    elif archetype == "plain_submodule_config_repo":
        _append_git_config(
            src,
            '[submodule "libs/legacy"]\n'
            "\turl = https://example.invalid/libs/legacy.git\n"
            "\tactive = true\n",
        )
    elif archetype == "windows_core_settings_repo":
        _append_git_config(
            src,
            "[core]\n"
            "\tautocrlf = true\n"
            "\tfilemode = false\n"
            "\tsymlinks = false\n"
            "\tignorecase = true\n"
            "\tlongpaths = true\n"
            "\teol = crlf\n"
            "[pull]\n"
            "\trebase = false\n",
        )
    elif archetype == "normal_clone_repo":
        _git_raw(src, "remote", "add", "origin", "https://example.invalid/team/repo.git")
        _git_raw(src, "remote", "add", "upstream", "git@example.invalid:team/repo.git")
        _append_git_config(
            src,
            '[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n'
            "[pull]\n\trebase = true\n"
            "[core]\n\tautocrlf = input\n",
        )

    assert not marker.exists()
    out = _exercise_all_plugin_git_flows(src, case_dir, marker)
    copy_dir = out["copy_dir"]
    assert isinstance(copy_dir, Path)
    if archetype == "lfs_repo":
        # Pointer file is treated as an ordinary small file: never smudged or rewritten
        assert (copy_dir / "assets" / "model.bin").read_bytes() == lfs_pointer_bytes
    if archetype == "normal_clone_repo":
        layout = out["layout"]
        assert isinstance(layout, dict)
        assert layout["remotes"]["origin"] == "https://example.invalid/team/repo.git"
        assert layout["remotes"]["upstream"] == "git@example.invalid:team/repo.git"


def test_partial_clone_promisor_missing_blob_never_triggers_lazy_fetch_command(tmp_path: Path) -> None:
    """Ensure GIT_NO_LAZY_FETCH=1 + per-scheme protocol.allow=never block lazy promisor fetch in local commands."""
    repo = _init_plain_repo(tmp_path / "promisor_repo")
    marker = tmp_path / "promisor_marker"
    script = _make_marker_script(tmp_path / "bin", "promisor_ext.sh", marker)

    (repo / "a.txt").write_text("initial blob\n", encoding="utf-8")
    _git_raw(repo, "add", "a.txt")
    _git_raw(repo, "commit", "-m", "c1")
    blob_sha = _git_raw(repo, "rev-parse", "HEAD:a.txt").stdout.decode("utf-8").strip()
    loose_obj = repo / ".git" / "objects" / blob_sha[:2] / blob_sha[2:]
    loose_obj.chmod(0o644)
    loose_obj.unlink()
    (repo / "a.txt").write_text("modified blob\n", encoding="utf-8")

    _append_git_config(
        repo,
        "[core]\n\trepositoryformatversion = 1\n"
        "[extensions]\n\tpartialClone = origin\n"
        '[protocol "ext"]\n\tallow = always\n'
        '[protocol "file"]\n\tallow = always\n'
        f'[remote "origin"]\n\turl = ext::{script}\n\tuploadpack = {script}\n\tpromisor = true\n',
    )

    assert_safe_repo_for_git(repo)
    proc_diff = run_git_hardened(repo, ["diff"])
    assert proc_diff.returncode != 0
    assert not marker.exists()


def test_bare_repo_and_external_worktree_hazards_refused_while_internal_worktree_allowed(tmp_path: Path) -> None:
    # 1. core.bare = true -> refused
    r_bare = _init_plain_repo(tmp_path / "r_bare")
    (r_bare / ".git" / "config").write_text("[core]\n\tbare = true\n", encoding="utf-8")
    with pytest.raises(SafetyError, match="core.bare"):
        assert_safe_repo_for_git(r_bare)
    with pytest.raises(UnsupportedGitLayoutError, match="core.bare"):
        scan_folder(r_bare)

    # 2. Valueless `[core]\n\tbare\n` (boolean true in git) -> refused
    r_bare_implicit = _init_plain_repo(tmp_path / "r_bare_implicit")
    (r_bare_implicit / ".git" / "config").write_text("[core]\n\tbare\n", encoding="utf-8")
    with pytest.raises(SafetyError, match="core.bare"):
        assert_safe_repo_for_git(r_bare_implicit)

    # 3. core.worktree pointing outside repository -> refused
    outside = tmp_path / "outside_wt"
    outside.mkdir()
    for idx, wt_val in enumerate([str(outside), "../../outside_wt", "~/outside_wt", "."]):
        r_wt = _init_plain_repo(tmp_path / f"r_wt_{idx}")
        _append_git_config(r_wt, f"[core]\n\tworktree = {wt_val}\n")
        with pytest.raises(SafetyError, match="core.worktree"):
            assert_safe_repo_for_git(r_wt)
        with pytest.raises(UnsupportedGitLayoutError, match="core.worktree"):
            scan_folder(r_wt)

    # 4. core.worktree = .. (pointing to repo root itself) and core.bare = false -> allowed
    r_ok = _init_plain_repo(tmp_path / "r_wt_ok")
    (r_ok / "README.md").write_text("# OK\n", encoding="utf-8")
    _git_raw(r_ok, "add", "README.md")
    _git_raw(r_ok, "commit", "-m", "c1")
    _append_git_config(r_ok, "[core]\n\tworktree = ..\n")
    assert_safe_repo_for_git(r_ok)
    assert inspect_git_layout(r_ok)["layout_refused"] is False


def test_plugin_only_invokes_allowed_builtin_git_subcommands_no_merge_or_network(tmp_path: Path) -> None:
    """Static + runtime proof: Defuzz only invokes local compiled-in git builtins and never runs merge or network commands."""
    plugin_root = Path(__file__).resolve().parent.parent
    py_files = [p for p in plugin_root.glob("*.py")] + [p for p in (plugin_root / "audit").rglob("*.py")]

    for py_path in py_files:
        tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Ensure no production module invokes `subprocess.run(["git", ...])` bypassing safety.py
            if py_path.name != "safety.py" and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("run", "Popen", "check_output", "check_call") and node.args:
                    first = node.args[0]
                    if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
                        head = first.elts[0]
                        if isinstance(head, ast.Constant) and head.value == "git":
                            raise AssertionError(f"Direct git subprocess call outside safety.py in {py_path}")

    git_builtins = set(subprocess.check_output(["git", "--list-cmds=builtins"], text=True).splitlines())
    assert _ALLOWED_GIT_SUBCOMMANDS <= git_builtins

    forbidden_subcommands = (
        "fetch",
        "push",
        "pull",
        "clone",
        "ls-remote",
        "submodule",
        "merge",
        "rebase",
        "cherry-pick",
        "revert",
        "am",
        "checkout",
        "difftool",
        "mergetool",
        "send-email",
        "help",
        "web--browse",
        "pwn",
    )
    repo = _init_plain_repo(tmp_path / "subcmd_guard_repo")
    for subcmd in forbidden_subcommands:
        assert subcmd not in _ALLOWED_GIT_SUBCOMMANDS
        with pytest.raises(SafetyError, match="Disallowed git subcommand"):
            run_git_hardened(repo, [subcmd])

    with pytest.raises(SafetyError, match="Disallowed git remote subcommand"):
        run_git_hardened(repo, ["remote", "update"])
    with pytest.raises(SafetyError, match="Disallowed -c override"):
        run_git_hardened(repo, ["-c", "core.hooksPath=/tmp", "status"])
    with pytest.raises(SafetyError, match="Disallowed global git option"):
        run_git_hardened(repo, ["--paginate", "status"])


@pytest.mark.parametrize(
    ("quirk_name", "raw_config_fn"),
    [
        ("dot_subsection", lambda s: f"[filter.evil]\n\tclean = {s}\n".encode("utf-8")),
        ("same_line_after_section", lambda s: f'[filter "evil"] clean = {s}\n'.encode("utf-8")),
        ("uppercase_section_and_key", lambda s: f'[FILTER "evil"]\n\tCLEAN = {s}\n'.encode("utf-8")),
        ("utf8_bom_prefix", lambda s: b"\xef\xbb\xbf" + f'[filter "evil"]\n\tclean = {s}\n'.encode("utf-8")),
        (
            "comment_trailing_backslash_does_not_swallow_next_line",
            lambda s: f'# harmless comment \\\n[filter "evil"]\n\tclean = {s}\n'.encode("utf-8"),
        ),
        (
            "line_continuation_in_value",
            lambda s: f'[filter "evil"]\n\tclean = \\\n{s}\n'.encode("utf-8"),
        ),
        ("valueless_include_path", lambda _s: b"[include]\n\tpath\n"),
        ("valueless_filter_clean", lambda _s: b'[filter "evil"]\n\tclean\n'),
        ("nul_byte_in_config", lambda s: b"[core]\n\tbare = false\x00\n" + f'[filter "evil"]\n\tclean = {s}\n'.encode("utf-8")),
    ],
)
def test_git_config_parser_quirks_and_adversarial_forms_fail_closed(
    tmp_path: Path,
    quirk_name: str,
    raw_config_fn,
) -> None:
    repo = _init_plain_repo(tmp_path / f"quirk_{quirk_name}")
    marker = tmp_path / f"marker_{quirk_name}"
    script = _make_marker_script(tmp_path / "bin", f"{quirk_name}.sh", marker, passthrough=True)
    (repo / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
    (repo / "a.txt").write_text("v1\n", encoding="utf-8")
    _git_raw(repo, "add", ".gitattributes", "a.txt")
    _git_raw(repo, "commit", "-m", "c1")
    (repo / "a.txt").write_text("v2\n", encoding="utf-8")

    (repo / ".git" / "config").write_bytes(raw_config_fn(script))

    with pytest.raises(UnsupportedGitLayoutError) as exc_info:
        scan_folder(repo)
    assert "Defuzz will not run git in it." in str(exc_info.value)
    assert not marker.exists(), quirk_name

    with pytest.raises(SafetyError):
        run_git_hardened(repo, ["status", "--porcelain=v1"])
    assert not marker.exists(), quirk_name


def test_config_worktree_and_symlinked_config_fail_closed(tmp_path: Path) -> None:
    repo_wt = _init_plain_repo(tmp_path / "repo_wt")
    marker = tmp_path / "wt_marker"
    script = _make_marker_script(tmp_path / "bin", "wt.sh", marker, passthrough=True)
    (repo_wt / ".git" / "config.worktree").write_text(
        f'[filter "evil"]\n\tclean = {script}\n',
        encoding="utf-8",
    )
    expected_msg = format_unsafe_repo_git_settings_message([("a custom filter", "filter.evil.clean")])
    with pytest.raises(UnsupportedGitLayoutError) as exc_wt:
        scan_folder(repo_wt)
    assert expected_msg in str(exc_wt.value)
    assert not marker.exists()

    repo_sym = _init_plain_repo(tmp_path / "repo_sym")
    outside_cfg = tmp_path / "outside.cfg"
    outside_cfg.write_text("[core]\n\tbare = false\n", encoding="utf-8")
    (repo_sym / ".git" / "config").unlink()
    os.symlink(str(outside_cfg), str(repo_sym / ".git" / "config"))
    with pytest.raises(UnsupportedGitLayoutError) as exc_sym:
        scan_folder(repo_sym)
    assert "Defuzz will not run git in it." in str(exc_sym.value)
    with pytest.raises(SafetyError):
        run_git_hardened(repo_sym, ["status"])


def test_include_pointing_to_secret_env_refuses_without_opening_secret_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hermes_plugins.defuzz.safety as safety_mod

    repo = _init_plain_repo(tmp_path / "repo_sec")
    (repo / ".env").write_text("API_KEY=" + ("x" * 40) + "\n", encoding="utf-8")
    _append_git_config(repo, "[include]\n\tpath = ../.env\n")

    opened: list[str] = []
    real_open = os.open

    def tracking_open(path, flags, *args, **kwargs):
        opened.append(os.path.basename(os.fspath(path)))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(safety_mod.os, "open", tracking_open)
    with pytest.raises(UnsupportedGitLayoutError):
        scan_folder(repo)
    assert ".env" not in opened


def test_hardened_git_env_is_minimal_uses_nonexistent_home_and_drops_all_inherited_git_vars() -> None:
    polluted = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/tmp/should-not-leak",
        "XDG_CONFIG_HOME": "/tmp/xdg-leak",
        "SSH_AUTH_SOCK": "/tmp/ssh.sock",
        "HTTPS_PROXY": "http://proxy.example.invalid:8080",
        "GIT_DIR": "/tmp/evil.git",
        "GIT_WORK_TREE": "/tmp/evil-wt",
        "GIT_CONFIG": "/tmp/evil-cfg",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "filter.evil.clean",
        "GIT_CONFIG_VALUE_0": "sh -c id",
        "GIT_CONFIG_PARAMETERS": "'filter.evil.clean=id'",
        "GIT_EXTERNAL_DIFF": "/tmp/ext-diff.sh",
        "GIT_SSH": "/tmp/ssh.sh",
        "GIT_SSH_COMMAND": "/tmp/ssh-cmd.sh",
        "GIT_ASKPASS": "/tmp/askpass.sh",
        "GIT_PAGER": "/tmp/pager.sh",
        "GIT_EDITOR": "/tmp/editor.sh",
        "GIT_EXEC_PATH": "/tmp/exec-path",
        "GIT_TEMPLATE_DIR": "/tmp/templates",
        "GIT_ATTR_SOURCE": "HEAD",
    }
    clean = hardened_git_env(polluted)
    assert clean["HOME"] == "/nonexistent"
    assert clean["PATH"] == "/usr/bin:/bin"
    assert clean["LANG"] == "C"
    assert clean["LC_ALL"] == "C"
    assert clean["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert clean["GIT_CONFIG_SYSTEM"] == "/dev/null"
    assert clean["GIT_CONFIG_NOSYSTEM"] == "1"
    assert clean["GIT_TERMINAL_PROMPT"] == "0"
    assert clean["GIT_ASKPASS"] == "/bin/false"
    assert clean["GIT_OPTIONAL_LOCKS"] == "0"
    assert clean["GIT_NO_LAZY_FETCH"] == "1"
    for dropped in (
        "XDG_CONFIG_HOME",
        "SSH_AUTH_SOCK",
        "HTTPS_PROXY",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_PARAMETERS",
        "GIT_EXTERNAL_DIFF",
        "GIT_SSH",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_ATTR_SOURCE",
    ):
        assert dropped not in clean, dropped


def test_inherited_git_env_vars_never_execute_commands_during_scan_apply_or_diff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    src = _init_plain_repo(tmp_path / "src")
    marker = tmp_path / "env_marker"
    script = _make_marker_script(tmp_path / "bin", "env_evil.sh", marker, passthrough=True)

    (src / ".gitattributes").write_text("*.txt filter=envfilter\n", encoding="utf-8")
    (src / "note.txt").write_text("v1\n", encoding="utf-8")
    _git_raw(src, "add", ".gitattributes", "note.txt")
    _git_raw(src, "commit", "-m", "c1")
    (src / "note.txt").write_text("v2\n", encoding="utf-8")

    evil_git = _init_plain_repo(tmp_path / "evil_git_holder")
    _append_git_config(evil_git, f'[filter "envfilter"]\n\tclean = {script}\n')

    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "filter.envfilter.clean")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(script))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'filter.envfilter.clean={script}'")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", str(script))
    monkeypatch.setenv("GIT_SSH_COMMAND", str(script))
    monkeypatch.setenv("GIT_EXEC_PATH", str(tmp_path / "bin"))

    copy_dir = tmp_path / "copy"
    staging = tmp_path / "staging"
    staging.mkdir()
    copy_tree_nofollow(src, copy_dir, staging_root=staging)

    inv = scan_folder(copy_dir, source_root=src)
    assert not marker.exists()

    diff_proc = run_git_hardened(copy_dir, ["diff"])
    assert diff_proc.returncode == 0
    assert b"+v2" in diff_proc.stdout
    assert not marker.exists()

    rules = build_deterministic_fallback_rules(inv)
    report = apply_rules_to_copy(
        copy_dir,
        inv,
        rules,
        source_root=src,
        staging_root=staging,
        db_path=staging / "state.db",
    )
    assert report["adopted_commit_sha"]
    assert not marker.exists()

    plain_no_git = tmp_path / "plain_no_git"
    plain_no_git.mkdir()
    (plain_no_git / ".gitattributes").write_text("*.txt filter=envfilter\n", encoding="utf-8")
    (plain_no_git / "x.txt").write_text("hi\n", encoding="utf-8")
    monkeypatch.setenv("GIT_DIR", str(evil_git / ".git"))
    proc_nogit = run_git_hardened(plain_no_git, ["status", "--porcelain=v1"])
    assert proc_nogit.returncode != 0
    assert not marker.exists()


def test_run_git_hardened_does_not_climb_into_untrusted_parent_git_repo(tmp_path: Path) -> None:
    outer = _init_plain_repo(tmp_path / "outer")
    marker = tmp_path / "ceiling_marker"
    script = _make_marker_script(tmp_path / "bin", "outer_clean.sh", marker, passthrough=True)
    (outer / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
    (outer / "a.txt").write_text("v1\n", encoding="utf-8")
    _git_raw(outer, "add", ".gitattributes", "a.txt")
    _git_raw(outer, "commit", "-m", "c1")
    _append_git_config(outer, f'[filter "evil"]\n\tclean = {script}\n')

    inner = outer / "subfolder_without_git"
    inner.mkdir()
    (inner / "a.txt").write_text("v1\n", encoding="utf-8")

    proc = run_git_hardened(inner, ["status", "--porcelain=v1"])
    assert proc.returncode != 0
    assert not marker.exists()


def test_defence_in_depth_cli_overrides_present() -> None:
    for item in (
        "--no-pager",
        "--no-optional-locks",
        "core.hooksPath=/dev/null",
        "core.fsmonitor=false",
        "core.useBuiltinFSMonitor=false",
        "core.pager=cat",
        "credential.helper=",
        "protocol.allow=never",
        "protocol.ext.allow=never",
        "core.sshCommand=false",
        "core.attributesFile=/dev/null",
        "commit.gpgSign=false",
        "tag.gpgSign=false",
        "diff.external=",
        "submodule.recurse=false",
        "filter.lfs.clean=",
        "filter.lfs.smudge=",
        "filter.lfs.process=",
        "filter.lfs.required=false",
    ):
        assert item in HARDENED_GIT_CONFIG_ARGS, item


def test_multiple_unoverrideable_kinds_named_together_in_refusal_message(tmp_path: Path) -> None:
    repo = _init_plain_repo(tmp_path / "multi_refuse")
    _append_git_config(
        repo,
        '[filter "custom"]\n\tclean = /bin/false\n'
        "[include]\n\tpath = extra.cfg\n"
        "[core]\n\talternateRefsCommand = /bin/false\n",
    )
    expected = (
        "This repository's own git settings include a custom filter, a config include, "
        "and a command hook (filter.custom.clean, include.path, core.alternateRefsCommand), "
        "which can run programs and cannot be switched off from outside. "
        "Defuzz will not run git in it. "
        "Remove that setting in the copy, or adopt a copy without its .git folder."
    )
    with pytest.raises(SafetyError) as exc:
        assert_safe_repo_for_git(repo)
    assert expected in str(exc.value)


def test_valueless_commit_gpgsign_config_is_allowed_without_marker(tmp_path: Path) -> None:
    repo = _init_plain_repo(tmp_path / "valueless_gpg")
    marker = tmp_path / "valueless_gpg_marker"
    script = _make_marker_script(tmp_path / "bin", "gpg_val.sh", marker, exit_code=1)
    (repo / "README.md").write_text("# Valueless bool\n", encoding="utf-8")
    _git_raw(repo, "add", "README.md")
    _git_raw(repo, "commit", "-m", "c1")
    _append_git_config(repo, f"[commit]\n\tgpgSign\n[gpg]\n\tprogram = {script}\n")

    assert_safe_repo_for_git(repo)
    assert inspect_git_layout(repo)["layout_refused"] is False
    assert run_git_hardened(repo, ["commit", "--allow-empty", "-m", "c2"], allow_literal_pathspecs=False).returncode == 0
    assert not marker.exists()


def test_gitattributes_naming_undefined_filter_is_harmless(tmp_path: Path) -> None:
    src = tmp_path / "undef_attr_src"
    src.mkdir()
    (src / ".gitattributes").write_text(
        "*.txt filter=undefined_custom_filter diff=undefined_diff merge=undefined_merge\n",
        encoding="utf-8",
    )
    (src / "hello.txt").write_text("hello world\n", encoding="utf-8")

    copy_dir = tmp_path / "undef_attr_copy"
    staging = tmp_path / "undef_attr_staging"
    staging.mkdir()
    copy_tree_nofollow(src, copy_dir, staging_root=staging)

    inv = scan_folder(copy_dir, source_root=src)
    rules = build_deterministic_fallback_rules(inv)
    report = apply_rules_to_copy(
        copy_dir,
        inv,
        rules,
        source_root=src,
        staging_root=staging,
        db_path=staging / "state.db",
    )
    assert report["baseline_commit_sha"]
    assert report["adopted_commit_sha"]


def test_worktree_gitfile_and_actual_submodules_remain_refused_everywhere(tmp_path: Path) -> None:
    wt = tmp_path / "wt_repo"
    wt.mkdir()
    (wt / ".git").write_text("gitdir: /tmp/nonexistent-worktree\n", encoding="utf-8")
    with pytest.raises(UnsupportedGitLayoutError):
        scan_folder(wt)
    with pytest.raises(SafetyError):
        run_git_hardened(wt, ["status"])

    sub = _init_plain_repo(tmp_path / "sub_repo")
    (sub / ".gitmodules").write_text('[submodule "s"]\n\tpath = s\n\turl = https://example.invalid/s.git\n', encoding="utf-8")
    with pytest.raises(UnsupportedGitLayoutError):
        scan_folder(sub)
    with pytest.raises(SafetyError):
        run_git_hardened(sub, ["status"])

    # Index gitlink (160000) without .gitmodules is also refused and short-circuits further git calls
    gitlink_repo = _init_plain_repo(tmp_path / "gitlink_repo")
    nested = _init_plain_repo(tmp_path / "nested_sub_src")
    (nested / "x.txt").write_text("sub\n", encoding="utf-8")
    _git_raw(nested, "add", "x.txt")
    _git_raw(nested, "commit", "-m", "sub-init")
    sub_sha = _git_raw(nested, "rev-parse", "HEAD").stdout.decode("utf-8").strip()
    _git_raw(gitlink_repo, "update-index", "--add", "--cacheinfo", f"160000,{sub_sha},vendor/sub")
    layout_gl = inspect_git_layout(gitlink_repo)
    assert layout_gl["layout_refused"] is True
    assert layout_gl["layout_refusal_reasons"][0]["kind"] == "submodule"
    with pytest.raises(UnsupportedGitLayoutError):
        scan_folder(gitlink_repo)


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_fresh_adopt_scaffolder_and_kit_scaffold_init_and_commit_write_no_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hermes_plugins.defuzz import kit_scaffold, scaffolder
    from hermes_plugins.defuzz.templates import load_template

    marker = tmp_path / "scaffold_marker"
    bin_dir = tmp_path / "bin"
    script = _make_marker_script(bin_dir, "git-lfs", marker, passthrough=True)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(bin_dir))
    monkeypatch.setenv("GIT_TEMPLATE_DIR", str(bin_dir))
    _ = script

    # 1. Fresh non-git folder: scan + apply with baseline commit
    src = tmp_path / "fresh_src"
    copy_dir = tmp_path / "fresh_copy"
    staging = tmp_path / "fresh_staging"
    src.mkdir()
    staging.mkdir()
    (src / "README.md").write_text("# Fresh\n", encoding="utf-8")
    (src / "src").mkdir()
    (src / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")

    copy_tree_nofollow(src, copy_dir, staging_root=staging)
    inv = scan_folder(copy_dir, source_root=src)
    assert inv["git"]["has_git"] is False
    report = apply_rules_to_copy(
        copy_dir,
        inv,
        build_deterministic_fallback_rules(inv),
        source_root=src,
        staging_root=staging,
        db_path=staging / "state.db",
    )
    assert report["baseline_commit_sha"]
    assert report["adopted_commit_sha"]
    assert inspect_git_layout(copy_dir)["layout_refused"] is False
    assert not marker.exists()

    # 2. Template scaffold accept() git init + initial commit
    fixture_tpl = Path(__file__).resolve().parent / "fixtures" / "templates" / "fake-rust-game"
    spec = load_template(fixture_tpl)
    proposal = scaffolder.propose(
        spec,
        "Space Demo",
        {"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"},
        dest_root=tmp_path / "projects",
        staging_parent=tmp_path / "scaf_staging",
    )
    accepted = scaffolder.accept(
        proposal,
        register=lambda _name, _path: '{"success": true, "id": "p1"}',
        db_path=staging / "state.db",
    )
    dest_repo = Path(accepted.repos[0]["path"])
    assert accepted.repos[0]["commit"]
    assert inspect_git_layout(dest_repo)["layout_refused"] is False
    assert run_git_hardened(dest_repo, ["status", "--porcelain=v1"], check=True).stdout == b""
    assert not marker.exists()

    # 3. Kit scaffold accept_kit() git init + initial commit
    kit_staging_dir = tmp_path / "kit_staging"
    kit_staged = kit_staging_dir / "demo-kit"
    kit_staged.mkdir(parents=True)
    (kit_staged / "AGENTS.md").write_text(
        "<!-- kit:demo-kit v1 begin (managed block: edit outside it) -->\n"
        "## Kit: Demo\n"
        "<!-- kit:demo-kit end -->\n",
        encoding="utf-8",
    )
    (kit_staged / ".gitattributes").write_text("*.png filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8")
    (kit_staged / "docs").mkdir()
    (kit_staged / "docs" / "intro.md").write_text("# Intro\n", encoding="utf-8")

    class _MinimalKitBridge:
        @staticmethod
        def kit_check(kit_id: str, staged: Path, *, timeout: float | None = None) -> dict[str, object]:
            _ = (kit_id, staged, timeout)
            return {"status": "ok", "data": {"ok": True, "status": "pass", "findings": []}}

    kit_prop = kit_scaffold.KitProposal(
        kit_id="demo-kit",
        slug="demo-kit",
        display_name="Demo Kit",
        dest=tmp_path / "projects" / "demo-kit",
        staging_dir=kit_staging_dir,
        staged=kit_staged,
        tree=["AGENTS.md", ".gitattributes", "docs/intro.md"],
        declared_dirs=[{"dir": "docs", "summary": "Docs", "why": "Docs"}],
        placement_rules=[
            {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "lfs": False, "reason": "Docs"}
        ],
        answers={"building": "other", "layout": "mono", "languages": []},
    )
    kit_accepted = kit_scaffold.accept_kit(
        kit_prop,
        register=lambda _name, _path: '{"success": true, "id": "p2"}',
        db_path=staging / "state.db",
        bridge=_MinimalKitBridge(),
    )
    kit_dest = Path(kit_accepted.repos[0]["path"])
    assert kit_accepted.repos[0]["commit"]
    assert inspect_git_layout(kit_dest)["layout_refused"] is False
    assert run_git_hardened(kit_dest, ["status", "--porcelain=v1"], check=True).stdout == b""
    assert not marker.exists()
