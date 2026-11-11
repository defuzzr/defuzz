"""Git context uses synthetic homes only; no inspected Git commands."""
from pathlib import Path
import pytest


def put(path, text=''):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def discover(project, home, **kwargs):
    from .conftest import load_submodule
    module = load_submodule('audit.outward_git')
    return module.discover_git_context(project, home=home, system_config=home / 'system-gitconfig', **kwargs)


def test_enclosing_worktree_gitdir_and_commondir(tmp_path):
    repo = tmp_path / 'repo'
    selected = repo / 'nested'
    selected.mkdir(parents=True)
    private = tmp_path / 'storage' / 'worktrees' / 'one'
    common = tmp_path / 'storage'
    put(repo / '.git', 'gitdir: ../storage/worktrees/one\n')
    put(private / 'commondir', '../..\n')
    put(common / 'config', '[core]\n bare = false\n')
    result = discover(selected, tmp_path / 'home')
    assert result.repository == repo
    edges = {(e.source, e.target, e.relationship) for e in result.edges}
    assert (selected, repo / '.git', 'git_context') in edges
    assert (repo / '.git', private, 'git_directory') in edges
    assert (private / 'commondir', common, 'git_common_directory') in edges
    assert any(e.target == common / 'config' for e in result.edges)
    assert common / 'hooks' in result.hook_roots
    assert result.hook_kind(common / 'hooks' / 'pre-commit') == 'git_hook_unresolved'
    assert result.hook_kind(common / 'objects' / 'pre-commit') is None


def test_all_config_scopes_and_metadata_only_includes(tmp_path):
    repo, home = tmp_path / 'repo', tmp_path / 'home'
    put(repo / '.git' / 'config', '[core]\n hooksPath = "../outside hooks" # comment\n[include]\n path = ../../shared.cfg\n path = ../../second.cfg\n')
    put(tmp_path / 'shared.cfg', '[includeIf "onbranch:release"]\n path = nested.cfg\n')
    put(tmp_path / 'second.cfg', '[core]\n hooksPath = ~/second-hooks\n')
    put(tmp_path / 'nested.cfg', '[core]\n hooksPath = ~/conditional-hooks\n')
    put(repo / '.git' / 'config.worktree', '[core]\n hooksPath = local-hooks\n')
    put(home / '.gitconfig', '[include]\n path = global.cfg\n')
    put(home / 'global.cfg', '[core]\n hooksPath = ~/global-hooks\n')
    put(home / '.config' / 'git' / 'config', '[core]\n hooksPath = ~/xdg-hooks\n')
    put(home / 'system-gitconfig', '[core]\n hooksPath = ~/system-hooks\n')
    result = discover(repo, home)
    assert {tmp_path / 'outside hooks', repo / 'local-hooks',
            home / 'system-hooks'} <= result.hook_roots
    assert not {home / 'second-hooks', home / 'conditional-hooks',
                home / 'global-hooks'} & result.hook_roots
    assert any(e.source == home / '.gitconfig' and e.target == home / 'global.cfg'
               and e.relationship == 'git_config_include' for e in result.edges)
    assert not any(e.target == tmp_path / 'nested.cfg' for e in result.edges)
    assert (tmp_path / 'shared.cfg', 'credential_store_not_opened') in result.issues
    assert home / 'xdg-hooks' not in result.hook_roots
    assert (home / '.config/git/config', 'credential_store_not_opened') in result.issues


def test_discovery_limits_exclusions_and_cycle(tmp_path):
    repo, home = tmp_path / 'repo', tmp_path / 'home'
    put(repo / '.git' / 'config', '[include]\n path = ../../a.cfg\n path = ../../excluded.cfg\n')
    put(tmp_path / 'a.cfg', '[include]\n path = b.cfg\n')
    put(tmp_path / 'b.cfg', '[include]\n path = a.cfg\n')
    blocked = put(tmp_path / 'excluded.cfg', '[core]\n hooksPath = ~/must-not-discover\n')
    result = discover(repo, home, allow_path=lambda p: p != blocked)
    assert home / 'must-not-discover' not in result.hook_roots
    assert (blocked, 'git_path_excluded') in result.issues
    assert len(result.edges) < 20
    limited = discover(repo, home, max_configs=1)
    assert any(reason == 'git_config_limit' for _, reason in limited.issues)
    limited = discover(repo, home, max_edges=2)
    assert len(limited.edges) == 2
    assert any(reason == 'git_edge_limit' for _, reason in limited.issues)


def test_git_values_preserve_spaces_quotes_and_continuations(tmp_path):
    repo, home = tmp_path / 'repo', tmp_path / 'home'
    put(repo / '.git' / 'config', '[CORE]\n hooksPath = two  spaces\n hooksPath = apostrophe\'s\n hooksPath = "semi;#hash" ; comment\n hooksPath = joined\\\npath\n')
    result = discover(repo, home)
    assert {repo / 'two  spaces', repo / "apostrophe's", repo / 'semi;#hash',
            repo / 'joinedpath'} <= result.hook_roots


def test_invalid_pointer_is_not_interpreted_as_directory(tmp_path):
    repo, home = tmp_path / 'repo', tmp_path / 'home'
    put(repo / '.git', 'gitdir: \n')
    result = discover(repo, home)
    assert not any(e.relationship == 'git_directory' for e in result.edges)
    assert (repo / '.git', 'git_path_unresolved') in result.issues


def test_invalid_common_directory_and_missing_include_are_unknown(tmp_path):
    repo, home = tmp_path / 'repo', tmp_path / 'home'
    put(repo / '.git' / 'commondir', '\n')
    put(home / '.gitconfig', '[include]\n path = missing.cfg\n')
    result = discover(repo, home)
    assert (repo / '.git' / 'commondir', 'git_path_unresolved') in result.issues
    assert (home / 'missing.cfg', 'git_include_missing') in result.issues


def test_invalid_limits_rejected_before_inspection(tmp_path):
    put(tmp_path / 'unused' / '.git' / 'config')
    for key in ('max_file_bytes', 'max_configs', 'max_edges'):
        for value in (-2, 0, True, 1.5):
            with pytest.raises(ValueError, match='positive integer'):
                discover(tmp_path / 'unused', tmp_path / 'home', **{key: value})


def test_symlink_files_and_ancestors_never_read(tmp_path, monkeypatch):
    import subprocess
    def forbidden(*args, **kwargs):
        raise AssertionError('Git discovery must not execute commands')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    repo, home = tmp_path / 'repo', tmp_path / 'home'
    outside = put(tmp_path / 'outside' / 'config', '[core]\n hooksPath = ~/forbidden\n')
    put(repo / '.git' / 'config', '[include]\n path = ../../link.cfg\n path = ../../linkdir/config\n')
    (tmp_path / 'link.cfg').symlink_to(outside)
    (tmp_path / 'linkdir').symlink_to(outside.parent, target_is_directory=True)
    result = discover(repo, home)
    assert home / 'forbidden' not in result.hook_roots
    assert (tmp_path / 'link.cfg', 'credential_store_not_opened') in result.issues
    assert (tmp_path / 'linkdir' / 'config', 'git_read_failed') in result.issues


def test_unstable_and_oversized_config_never_parsed(tmp_path, monkeypatch):
    import os
    from .conftest import load_submodule
    module = load_submodule('audit.outward_git')
    repo, home = tmp_path / 'repo', tmp_path / 'home'
    path = put(repo / '.git' / 'config', '[core]\n hooksPath = ~/forbidden\n')
    result = discover(repo, home, max_file_bytes=4)
    assert home / 'forbidden' not in result.hook_roots
    assert (path, 'git_read_failed') in result.issues
    real_fstat = os.fstat
    calls = 0
    def changing_fstat(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            path.write_text('[core]\n hooksPath = ~/replacement\n')
        return real_fstat(fd)
    monkeypatch.setattr(module.os, 'fstat', changing_fstat)
    result = discover(repo, home)
    assert home / 'forbidden' not in result.hook_roots
    assert home / 'replacement' not in result.hook_roots
    assert (path, 'git_read_failed') in result.issues
