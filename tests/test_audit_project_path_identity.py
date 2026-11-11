"""Project roots are compared by resolved path and identity, not by spelling.

A projects folder reached through a link spells every project two ways: the way
the user selected or registered it, and the resolved way the walk reaches it. Each
case runs the same layout spelled both ways and expects the same answer; displayed
paths stay as the user wrote them.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from tests.conftest import load_submodule

PRIVATE = b'UNSELECTED_PROJECT_CANARY\n'


class ReadSpy:
    """Count opens of and bytes read from protected files, by (device, inode)."""

    def __init__(self, monkeypatch, protected):
        load_submodule('audit_surface')
        self.ids = {(os.stat(p).st_dev, os.stat(p).st_ino) for p in protected}
        self.opens = 0
        original_open = os.open

        def spy_open(path, flags, mode=0o777, *, dir_fd=None):
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            try:
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) in self.ids:
                    self.opens += 1
            except OSError:
                pass
            return fd

        monkeypatch.setattr(os, 'open', spy_open)


def _layout(tmp_path):
    home = tmp_path / 'home'
    profile = home / '.hermes'
    profile.mkdir(parents=True)
    real = tmp_path / 'real-projects'
    for name in ('alpha', 'beta'):
        (real / name).mkdir(parents=True)
        (real / name / 'main.py').write_text('print(1)\n')
    (real / 'beta' / 'private.txt').write_bytes(PRIVATE)
    link = tmp_path / 'linked-projects'
    link.symlink_to(real, target_is_directory=True)
    return home, profile, real, link


SPELLINGS = {
    # name: (selected spelling, unselected spelling)
    'direct': lambda real, link: (real, real),
    'selected-through-link': lambda real, link: (link, link),
    'unselected-through-link': lambda real, link: (real, link),
}


@pytest.mark.parametrize('spelling', sorted(SPELLINGS))
def test_unselected_project_behind_a_linked_root_is_never_walked(tmp_path, monkeypatch, spelling):
    """The open question: is a project the user did not select read? It must not be."""
    outward = load_submodule('audit.outward')
    _home, profile, real, link = _layout(tmp_path)
    # A link inside the selected project back to the projects folder (a common shortcut)
    # makes the walk reach every project folder by its resolved spelling.
    (real / 'alpha' / 'all-projects').symlink_to(real, target_is_directory=True)
    selected_base, unselected_base = SPELLINGS[spelling](real, link)
    spy = ReadSpy(monkeypatch, [real / 'beta' / 'private.txt', real / 'beta' / 'main.py'])
    result = outward.collect_outward(profile, [str(selected_base / 'alpha')],
                                     unselected_project_roots=[str(unselected_base / 'beta')])
    assert spy.opens == 0
    assert PRIVATE.decode().strip() not in json.dumps(result, default=str)


@pytest.mark.parametrize('spelling', sorted(SPELLINGS))
def test_reference_into_another_project_is_reported_under_any_spelling(tmp_path, monkeypatch, spelling):
    outward = load_submodule('audit.outward')
    _home, profile, real, link = _layout(tmp_path)
    referenced = real / 'beta' / 'notes.md'
    referenced.write_text('shared notes\n')
    (real / 'alpha' / 'README.md').write_text(f'See {referenced} for the shared notes.\n')
    selected_base, unselected_base = SPELLINGS[spelling](real, link)
    result = outward.collect_outward(profile, [str(selected_base / 'alpha')],
                                     unselected_project_roots=[str(unselected_base / 'beta')])
    targets = {edge['target'] for edge in result['blending']}
    assert str(referenced) in targets


@pytest.mark.parametrize('recorded', ['real', 'link'])
@pytest.mark.parametrize('selected', ['real', 'link'])
def test_session_record_is_linked_to_its_project_under_any_spelling(tmp_path, selected, recorded):
    outward = load_submodule('audit.outward')
    _home, profile, real, link = _layout(tmp_path)
    base = {'real': real, 'link': link}
    sessions = profile / 'sessions'
    sessions.mkdir()
    cwd = base[recorded] / 'alpha' / 'src'
    (real / 'alpha' / 'src').mkdir()
    (sessions / 'session_1.json').write_text(json.dumps({'id': 's1', 'cwd': str(cwd), 'started_at': 1700000000}))
    result = outward.collect_outward(profile, [str(base[selected] / 'alpha')])
    summary = result['session_history']
    assert summary['records_inspected'] == 1
    assert summary['selected_project_records'] == 1


def _state_db(profile, cwd):
    profile.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(profile / 'state.db')
    conn.executescript('''
        CREATE TABLE sessions(id TEXT PRIMARY KEY, cwd TEXT, git_repo_root TEXT,
          system_prompt TEXT, started_at REAL, message_count INTEGER, source TEXT,
          parent_session_id TEXT, system_prompt_hash TEXT);
        CREATE TABLE messages(id INTEGER PRIMARY KEY, session_id TEXT, role TEXT,
          content TEXT, timestamp REAL, api_content TEXT);
        CREATE TABLE system_prompts(hash TEXT PRIMARY KEY, prompt TEXT);
        CREATE INDEX idx_sessions_started ON sessions(started_at DESC);
        CREATE INDEX idx_messages_session ON messages(session_id, timestamp);
    ''')
    stamp = datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp()
    conn.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?)',
                 ('s1', str(cwd), str(cwd), 'You help.', stamp, 1, 'cli', None, None))
    conn.execute('INSERT INTO messages VALUES(?,?,?,?,?,?)', (1, 's1', 'user', 'hello', stamp, None))
    conn.commit()
    conn.close()


@pytest.mark.parametrize('recorded', ['real', 'link'])
@pytest.mark.parametrize('selected', ['real', 'link'])
def test_session_started_through_a_link_counts_inside_its_project(tmp_path, selected, recorded):
    mod = load_submodule('audit.session_contamination')
    _home, profile, real, link = _layout(tmp_path)
    base = {'real': real, 'link': link}
    _state_db(profile, base[recorded] / 'alpha')
    result = mod.audit_session_contamination(profile_path=profile, sessions=True,
                                             selected_projects=[base[selected] / 'alpha'])
    section = result['session_contamination']
    assert section['sessions_outside_registered_projects'] == 0
    roots = [row.get('project_root') for row in section['projects']]
    # Shown as the user selected it.
    assert roots == [str(base[selected] / 'alpha')]
