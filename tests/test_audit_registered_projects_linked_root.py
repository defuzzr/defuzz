"""Registered projects are matched to discovered folders by real path and identity, never by spelling.

A projects root reached through a symbolic link (macOS puts temp and many home folders
behind /var -> /private/var; a Linux user may link ~/Projects to another drive) spells the
same folder two ways. A registered project under such a root is still set up by the plugin.
Synthetic folders under pytest's tmp_path only.
"""
from __future__ import annotations

import json
import os
import pathlib
import sqlite3

import pytest

from tests.conftest import load_submodule
from tests.test_audit_reasons_present import _register, _typical, _w

facts = load_submodule('audit.facts')
readonly_db = load_submodule('audit.readonly_db')


def _repo(path):
    (path / '.git').mkdir(parents=True)
    return path


def _linked_layout(tmp_path):
    """real/Projects/app (a repository) and link -> real."""
    real = tmp_path / 'real'
    app = _repo(real / 'Projects' / 'app')
    link = tmp_path / 'link'
    link.symlink_to(real, target_is_directory=True)
    return real, link, app


def _entry(res, path):
    by_path = {r['path']: r for r in res['repos']}
    return by_path[str(path)]


def _assert_set_up(entry):
    assert entry['registered'] is True
    assert entry['not_set_up_by_plugin'] is False
    assert entry['scope'] == 'full'


def test_root_behind_a_link_registered_with_the_real_spelling(tmp_path):
    real, link, app = _linked_layout(tmp_path)
    res = facts.discover_optional_root_repos(link / 'Projects', registered_canonical_paths=[str(app)])
    assert res['coverage'] == 'verified'
    # The report keeps the spelling the user gave for the root.
    assert res['optional_root'] == str(link / 'Projects')
    _assert_set_up(_entry(res, link / 'Projects' / 'app'))


def test_root_behind_a_link_registered_with_the_link_spelling(tmp_path):
    real, link, app = _linked_layout(tmp_path)
    res = facts.discover_optional_root_repos(
        real / 'Projects', registered_canonical_paths=[str(link / 'Projects' / 'app')])
    assert res['coverage'] == 'verified'
    _assert_set_up(_entry(res, app))


def test_a_project_folder_that_is_itself_a_link(tmp_path):
    real, link, app = _linked_layout(tmp_path)
    alias = tmp_path / 'alias'
    alias.symlink_to(app, target_is_directory=True)
    res = facts.discover_optional_root_repos(real / 'Projects', registered_canonical_paths=[str(alias)])
    _assert_set_up(_entry(res, app))


def test_identity_matches_when_the_real_paths_are_spelled_differently(tmp_path, monkeypatch):
    # A case-insensitive volume keeps the spelling the user typed in the real path; only the
    # folder identity (device, inode) shows it is the same folder.
    real, link, app = _linked_layout(tmp_path)
    monkeypatch.setattr(facts.os.path, 'realpath', lambda p, strict=False: os.fspath(p))
    res = facts.discover_optional_root_repos(
        real / 'Projects', registered_canonical_paths=[str(link / 'Projects' / 'app')])
    _assert_set_up(_entry(res, app))


def test_a_missing_registered_project_keeps_todays_result(tmp_path):
    real, link, app = _linked_layout(tmp_path)
    res = facts.discover_optional_root_repos(
        link / 'Projects', registered_canonical_paths=[str(tmp_path / 'gone' / 'app')])
    assert res['coverage'] == 'verified'
    assert res['errors'] == []
    entry = _entry(res, link / 'Projects' / 'app')
    assert entry['registered'] is False
    assert entry['not_set_up_by_plugin'] is True
    assert entry['scope'] == 'isolation_only'
    assert 'coverage' not in entry and 'reason' not in entry


def _unresolvable(tmp_path, kind):
    if kind == 'loop' or os.geteuid() == 0:  # root reads any folder: use a loop instead
        (tmp_path / 'loop-a').symlink_to(tmp_path / 'loop-b')
        (tmp_path / 'loop-b').symlink_to(tmp_path / 'loop-a')
        return tmp_path / 'loop-a' / 'app', None
    locked = tmp_path / 'locked'
    (locked / 'app').mkdir(parents=True)
    locked.chmod(0)
    return locked / 'app', locked


@pytest.mark.parametrize('kind', ['loop', 'permission'])
def test_an_unresolvable_registered_path_is_could_not_verify_not_not_set_up(tmp_path, kind):
    real, link, app = _linked_layout(tmp_path)
    registered, locked = _unresolvable(tmp_path, kind)
    try:
        res = facts.discover_optional_root_repos(link / 'Projects', registered_canonical_paths=[str(registered)])
    finally:
        if locked is not None:
            locked.chmod(0o700)
    assert res['coverage'] == 'could_not_verify'
    entry = _entry(res, link / 'Projects' / 'app')
    assert entry['registered'] is None
    assert entry['not_set_up_by_plugin'] is None
    assert entry['coverage'] == 'could_not_verify'
    assert entry['reason'] == 'unresolved'
    assert entry['scope'] == 'isolation_only'
    assert all(str(registered) not in e for e in res['errors'])


def test_an_unresolvable_path_does_not_hide_a_project_that_matches(tmp_path):
    real, link, app = _linked_layout(tmp_path)
    registered, _ = _unresolvable(tmp_path, 'loop')
    res = facts.discover_optional_root_repos(
        link / 'Projects', registered_canonical_paths=[str(registered), str(app)])
    _assert_set_up(_entry(res, link / 'Projects' / 'app'))


def test_plain_layout_output_is_unchanged(tmp_path):
    root = tmp_path / 'Projects'
    _repo(root / 'reg')
    _repo(root / 'other')
    res = facts.discover_optional_root_repos(root, registered_canonical_paths=[str(root / 'reg')])
    assert res == {
        'optional_root': str(root), 'coverage': 'verified', 'errors': [],
        'repos': [
            {'path': str(root / 'other'), 'rel_to_optional_root': 'other', 'git_kind': 'git_dir',
             'gitdir_target': None, 'registered': False, 'not_set_up_by_plugin': True,
             'scope': 'isolation_only'},
            {'path': str(root / 'reg'), 'rel_to_optional_root': 'reg', 'git_kind': 'git_dir',
             'gitdir_target': None, 'registered': True, 'not_set_up_by_plugin': False, 'scope': 'full'},
        ]}


# --- the registry read: a looping registered path does not stop the read ---

def test_a_registered_path_in_a_link_loop_does_not_stop_the_registry_read(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    (tmp_path / 'loop-a').symlink_to(tmp_path / 'loop-b')
    (tmp_path / 'loop-b').symlink_to(tmp_path / 'loop-a')
    looping = tmp_path / 'loop-a' / 'app'
    _register(home, looping)
    original = pathlib.Path.resolve

    def resolve_like_python_311(self, strict=False):
        # Python 3.11 and 3.12 raise RuntimeError for a link loop even when strict is False.
        if 'loop-a' in str(self):
            raise RuntimeError(f'Symlink loop from {str(self)!r}')
        return original(self, strict=strict)

    monkeypatch.setattr(pathlib.Path, 'resolve', resolve_like_python_311)
    snap = readonly_db.read_profile_registrations_readonly('default', home)
    assert snap.coverage == 'verified'
    assert [r['canonical_path'] for r in snap.records] == [str(looping)]
    assert [r['raw_path'] for r in snap.records] == [str(looping)]


# --- the macOS situation: the whole home is reached through a link ---

def _linked_home(tmp_path, monkeypatch):
    real = tmp_path / 'real-home'
    link = tmp_path / 'home-link'
    real.mkdir()
    link.symlink_to(real, target_is_directory=True)
    hermes = _typical(link / '.hermes')
    project = link / 'Projects' / 'app'
    _w(project / 'app.py', 'print(1)\n')
    (project / '.git').mkdir()
    monkeypatch.setenv('HOME', str(link))
    return real, link, hermes, project


def test_inventory_with_home_behind_a_link_reports_the_project_as_set_up(tmp_path, monkeypatch):
    real, link, hermes, project = _linked_home(tmp_path, monkeypatch)
    _register(hermes, project)  # registered with the link spelling, read back resolved
    inv = facts.collect_system_inventory_facts(
        as_of=1_800_000_000, optional_root=link / 'Projects',
        list_profile_names_fn=lambda: ['default'], get_profile_dir_fn=lambda n: hermes,
        active_profile='default')
    assert [p['canonical_path'] for p in inv['project_units']] == [str(real / 'Projects' / 'app')]
    disc = inv['optional_root_discovery']
    assert disc['coverage'] == 'verified'
    assert [r['path'] for r in disc['repos']] == [str(project)]
    _assert_set_up(disc['repos'][0])


def test_real_audit_with_home_behind_a_link(tmp_path, monkeypatch):
    from tests.test_audit_wired_sections import _audit
    real, link, hermes, project = _linked_home(tmp_path, monkeypatch)
    _register(hermes, project)
    run = _audit(tmp_path, monkeypatch, hermes, root=str(project))
    assert run['status'] == 'completed'
    text = json.dumps(run['report'])
    assert '"not_set_up_by_plugin": true' not in text
    assert '"registered": false' not in text
    assert 'Selected project is not registered' not in text


# --- an unreadable project registry is not "no projects" ---

def _make_registry_unreadable(home):
    registry = home / 'plugin-data' / 'defuzz' / 'state.db'
    if os.geteuid() != 0:
        registry.chmod(0)
        return lambda: registry.chmod(0o600)
    # Root reads any file: a folder in place of the registry file fails the read instead.
    registry.unlink()
    registry.mkdir()
    return lambda: None


def test_an_unreadable_registry_is_input_unknown_not_no_projects(tmp_path, monkeypatch):
    from tests.test_audit_wired_sections import _audit
    home = _typical(tmp_path / 'home')
    project = tmp_path / 'project'
    _w(project / 'app.py', 'print(1)\n')
    _register(home, project)
    restore = _make_registry_unreadable(home)
    try:
        run = _audit(tmp_path, monkeypatch, home)
    finally:
        restore()
    assert run['status'] == 'completed'
    sec = run['report']['memory_load']
    assert sec['foreign_technology_reason'] == 'input_unknown'
    assert sec['foreign_technology_coverage'] == 'could_not_verify'
    assert 'input_unknown' in sec['truncated_by']


def test_a_readable_empty_registry_is_still_no_projects(tmp_path, monkeypatch):
    from tests.test_audit_wired_sections import _audit
    home = _typical(tmp_path / 'home')
    registry = home / 'plugin-data' / 'defuzz' / 'state.db'
    registry.parent.mkdir(parents=True)
    conn = sqlite3.connect(registry)
    conn.execute('CREATE TABLE projects(path TEXT PRIMARY KEY, hermes_project_id TEXT)')
    conn.commit()
    conn.close()
    sec = _audit(tmp_path, monkeypatch, home)['report']['memory_load']
    assert sec['foreign_technology_reason'] == 'no_projects'
    assert sec['coverage'] == 'verified'
