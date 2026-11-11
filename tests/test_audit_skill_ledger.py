"""Synthetic-only skill ledger and backup store tests."""
from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
from typing import Any, Sequence

from tests.conftest import load_submodule

ACTOR_CONSEQUENCE = (
    'Recorded skill changes are counted by the actor label the ledger stores: curator (curator runs '
    'and background review forks), agent (tool calls in a conversation, which may include edits a '
    'person asked for or approved) and user (hermes curator archive, restore and purge commands); '
    'the ledger does not record who requested or reviewed a change, and edits made to skill files '
    'outside Hermes are not recorded at all.'
)
PATCH_STORM_CONSEQUENCE = (
    'At least one skill has 10 or more ledger changes within a 24-hour window of ledger timestamps; '
    'the ledger records the changes, not why they were made or who asked for them.'
)
ORPHAN_BACKUPS_CONSEQUENCE = (
    'More than 20 MiB of backup blobs under .curator_backups/blobs are not referenced by any entry in '
    'the skill change ledger, or cannot be matched because there is no ledger; this measures disk use, '
    'not whether the files are still wanted.'
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_blob(profile: Path, data: bytes) -> tuple[str, Path]:
    digest = _sha256_hex(data)
    blobs = profile / '.curator_backups' / 'blobs'
    blobs.mkdir(parents=True, exist_ok=True)
    path = blobs / digest
    path.write_bytes(data)
    return digest, path


def _write_skill_dir(profile: Path, rel_dir: str, skill_name: str, body: str = 'Rule body.\n') -> Path:
    pkg = profile / 'skills' / rel_dir
    pkg.mkdir(parents=True, exist_ok=True)
    md = pkg / 'SKILL.md'
    md.write_text(f'---\nname: {skill_name}\n---\n{body}', encoding='utf-8')
    return md


def _write_ledger(profile: Path, entries: Sequence[dict[str, Any] | str]) -> Path:
    skills = profile / 'skills'
    skills.mkdir(parents=True, exist_ok=True)
    ledger = skills / '.curator_ledger.jsonl'
    lines = [
        e if isinstance(e, str) else json.dumps(e, ensure_ascii=False)
        for e in entries
    ]
    ledger.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')
    return ledger


def _write_snapshot(profile: Path, snap_id: str, size_bytes: int = 2048) -> Path:
    snap_dir = profile / 'skills' / '.curator_backups' / snap_id
    snap_dir.mkdir(parents=True, exist_ok=True)
    tgz = snap_dir / 'skills.tar.gz'
    tgz.write_bytes(b'x' * size_bytes)
    (snap_dir / 'manifest.json').write_text(
        json.dumps({'id': snap_id, 'archive': 'skills.tar.gz', 'archive_bytes': size_bytes}),
        encoding='utf-8',
    )
    return tgz


def _tree_snapshot(root: Path) -> dict[str, tuple[str, int, str]]:
    out: dict[str, tuple[str, int, str]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = os.path.relpath(dirpath, root)
        out[f'dir:{rel_dir}'] = ('dir', 0, '')
        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel_file = os.path.relpath(fpath, root)
            st = os.lstat(fpath)
            if os.path.islink(fpath):
                out[f'link:{rel_file}'] = ('link', st.st_size, os.readlink(fpath))
            else:
                out[f'file:{rel_file}'] = (
                    'file',
                    st.st_size,
                    hashlib.sha256(fpath.read_bytes()).hexdigest(),
                )
    return out


def _build_rich_home(profile: Path) -> None:
    """Home that fires every non-could_not_verify rule (shared by the sealing tests)."""
    # Active skill on disk: alpha-review
    _write_skill_dir(profile, 'alpha-review', 'alpha-review')

    # Create 22 versions for alpha-review growing from 4000 -> 10000 bytes within 4 hours
    alpha_hashes: list[str] = []
    for idx in range(22):
        # First two versions differ by < 2% in size (4000 -> 4040 = 1.0%)
        if idx == 0:
            sz = 4000
        elif idx == 1:
            sz = 4040
        else:
            sz = 4040 + idx * 300
        content = (f'v{idx}:' + ('a' * sz)).encode('utf-8')[:sz]
        h, _ = _write_blob(profile, content)
        alpha_hashes.append(h)

    entries: list[dict[str, Any]] = []
    # Entry 0: create alpha-review by curator in 2026-08
    entries.append({
        'id': 'e000',
        'ts': '2026-08-31T23:50:00+00:00',
        'actor': 'curator',
        'action': 'create',
        'skill': 'alpha-review',
        'evidence': {'session_id': 'CANARY_SESSION_ID_0'},
        'before': [],
        'after': [{'path': '/home/user/.hermes/skills/alpha-review/SKILL.md', 'sha256': alpha_hashes[0]}],
    })
    # Entries 1..20: 20 patches in 2026-09 within 2 hours by curator & agent
    for idx in range(1, 21):
        actor = 'curator' if idx <= 12 else 'agent'
        entries.append({
            'id': f'e{idx:03d}',
            'ts': f'2026-09-01T00:{idx:02d}:00+00:00',
            'actor': actor,
            'action': 'patch',
            'skill': 'alpha-review',
            'evidence': {'session_id': f'CANARY_SESSION_ID_{idx}'},
            'before': [{'path': '/home/user/.hermes/skills/alpha-review/SKILL.md', 'sha256': alpha_hashes[idx - 1]}],
            'after': [{'path': '/home/user/.hermes/skills/alpha-review/SKILL.md', 'sha256': alpha_hashes[idx]}],
        })
    # Entry 21: no-op patch (before hash == after hash) by user
    entries.append({
        'id': 'e021',
        'ts': '2026-09-01T01:00:00+00:00',
        'actor': 'user',
        'action': 'patch',
        'skill': 'alpha-review',
        'evidence': {},
        'before': [{'path': '/home/user/.hermes/skills/alpha-review/SKILL.md', 'sha256': alpha_hashes[20]}],
        'after': [{'path': '/home/user/.hermes/skills/alpha-review/SKILL.md', 'sha256': alpha_hashes[20]}],
    })
    # Entry 22: patch to alpha_hashes[21], referencing a missing blob in a support file
    missing_hash = 'f' * 64
    entries.append({
        'id': 'e022',
        'ts': '2026-09-01T01:10:00+00:00',
        'actor': 'agent',
        'action': 'patch',
        'skill': 'alpha-review',
        'evidence': {},
        'before': [{'path': '/home/user/.hermes/skills/alpha-review/SKILL.md', 'sha256': alpha_hashes[20]}],
        'after': [
            {'path': '/home/user/.hermes/skills/alpha-review/SKILL.md', 'sha256': alpha_hashes[21]},
            {'path': '/home/user/.hermes/skills/alpha-review/references/note.md', 'sha256': missing_hash},
        ],
    })
    # Skill temp-skill: created, patched, then deleted
    h_temp1, _ = _write_blob(profile, b't' * 1200)
    h_temp2, _ = _write_blob(profile, b't' * 1500)
    entries.extend([
        {
            'id': 'e023',
            'ts': '2026-09-02T10:00:00+00:00',
            'actor': 'agent',
            'action': 'create',
            'skill': 'temp-skill',
            'evidence': {},
            'before': [],
            'after': [{'path': '/home/user/.hermes/skills/temp-skill/SKILL.md', 'sha256': h_temp1}],
        },
        {
            'id': 'e024',
            'ts': '2026-09-02T11:00:00+00:00',
            'actor': 'agent',
            'action': 'patch',
            'skill': 'temp-skill',
            'evidence': {},
            'before': [{'path': '/home/user/.hermes/skills/temp-skill/SKILL.md', 'sha256': h_temp1}],
            'after': [{'path': '/home/user/.hermes/skills/temp-skill/SKILL.md', 'sha256': h_temp2}],
        },
        {
            'id': 'e025',
            'ts': '2026-09-02T12:00:00+00:00',
            'actor': 'curator',
            'action': 'delete',
            'skill': 'temp-skill',
            'evidence': {'absorbed_into': 'alpha-review', 'archived': True},
            'before': [{'path': '/home/user/.hermes/skills/temp-skill/SKILL.md', 'sha256': h_temp2}],
            'after': [],
        },
    ])

    _write_ledger(profile, entries)

    # Add an unreferenced orphan blob > 20 MiB to trigger orphan_backups
    _write_blob(profile, b'o' * (21 * 1024 * 1024))
    _write_snapshot(profile, '2026-09-02T00-00-00Z', size_bytes=4096)

    # Bookkeeping orphans in .usage.json and .bundled_manifest
    usage_file = profile / 'skills' / ('.' + 'usage.json')
    usage_file.write_text(json.dumps({
        'alpha-review': {'state': 'active', 'use_count': 5, 'patch_count': 21},
        'ghost-usage-skill': {'state': 'active', 'use_count': 3, 'patch_count': 2},
        'archived-skill': {'state': 'archived', 'use_count': 1, 'patch_count': 0},
    }), encoding='utf-8')
    manifest_file = profile / 'skills' / ('.bundled_' + 'manifest')
    manifest_file.write_text(
        'alpha-review:0123456789abcdef0123456789abcdef\n'
        'ghost-manifest-skill:fedcba9876543210fedcba9876543210\n',
        encoding='utf-8',
    )


def test_positive_ledger_metrics_and_findings(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'profile'
    profile.mkdir()

    _build_rich_home(profile)

    res = mod.audit_skill_ledger(profile_path=profile)
    sec = res['skill_ledger']
    assert res['coverage'] == 'verified'
    assert sec['coverage'] == 'verified'
    assert sec['status'] == 'completed'
    assert sec['ledger_present'] is True

    # (a) Changes by actor
    assert sec['total_changes'] == 26
    assert sec['changes_by_actor'] == {'curator': 14, 'agent': 11, 'user': 1, 'other': 0}
    assert sec['curator_or_agent_changes'] == 25
    assert sec['curator_or_agent_share'] == round(25 / 26, 4)
    # Dates are emitted as numbers (epoch seconds from ledger timestamps; year/month integers), so
    # they survive the closed-vocabulary serializer unchanged and never depend on the wall clock.
    assert sec['date_range'] == {
        'earliest_epoch_s': 1788220200,  # 2026-08-31T23:50:00+00:00
        'latest_epoch_s': 1788350400,  # 2026-09-02T12:00:00+00:00
        'span_days': 1,
    }
    assert sec['changes_by_month'] == [
        {'year': 2026, 'month': 8, 'total': 1, 'curator': 1, 'agent': 0, 'user': 0, 'other': 0},
        {'year': 2026, 'month': 9, 'total': 25, 'curator': 13, 'agent': 11, 'user': 1, 'other': 0},
    ]

    # (b) Per skill: rows carry the absolute skill folder when it exists, never the ledger name.
    alpha_dir = os.path.realpath(profile / 'skills' / 'alpha-review')
    assert [s['path'] for s in sec['skills']] == [alpha_dir, None]
    assert sec['skills_without_folder_count'] == 1
    alpha, temp = sec['skills']
    assert alpha['changes'] == 23
    assert alpha['distinct_versions'] == 22
    assert alpha['first_size_bytes'] == 4000
    assert alpha['latest_size_bytes'] == 4040 + 21 * 300
    assert alpha['growth_ratio'] == round((4040 + 21 * 300) / 4000, 2)
    assert alpha['growth_coverage'] == 'verified'
    assert alpha['peak_changes_24h'] == 23
    assert alpha['noop_changes'] == 1
    assert alpha['deleted'] is False
    assert alpha['changes_before_delete'] == 0
    assert alpha['near_identical_size_pairs'] >= 1

    assert temp['changes'] == 3
    assert temp['distinct_versions'] == 2
    assert temp['deleted'] is True
    assert temp['changes_before_delete'] == 3

    # (c) Top 10 lists: located folders as paths, the deleted skill only counted
    assert sec['top_skills_by_changes'] == {'paths': [alpha_dir], 'unlocated_count': 1}
    assert sec['top_skills_by_growth'] == {'paths': [alpha_dir], 'unlocated_count': 1}
    assert 'temp-skill' not in json.dumps(sec)

    # (d) Backup store weight
    bs = sec['backup_store']
    assert bs['blob_count'] == 25
    assert bs['orphan_blob_count'] == 1
    assert bs['orphan_blob_bytes'] == 21 * 1024 * 1024
    assert bs['missing_blob_hashes'] == 1
    assert bs['tarball_count'] == 1
    assert bs['tarball_bytes'] == 4096

    # (e) Bookkeeping orphans
    bo = sec['bookkeeping_orphans']
    # These names have no folder by definition: counted, never named.
    # A bundled-manifest entry without a folder is how Hermes remembers a user-deleted bundled
    # skill (tools/skills_sync.py:431-433): counted, never an orphan.
    assert bo == {'orphan_count': 1, 'usage_orphan_count': 1, 'manifest_entries_not_on_disk_count': 1}
    assert 'ghost' not in json.dumps(sec)

    # Findings check
    f_by_id = {f['id']: f for f in res['findings']}
    assert set(f_by_id) == {
        'skill_ledger.changes_by_recorded_actor',
        'skill_ledger.patch_storm',
        'skill_ledger.skill_growth',
        'skill_ledger.version_churn',
        'skill_ledger.noop_changes',
        'skill_ledger.orphan_backups',
        'skill_ledger.bookkeeping_orphans',
    }
    assert f_by_id['skill_ledger.changes_by_recorded_actor']['classification'] == 'info'
    actor_f = f_by_id['skill_ledger.changes_by_recorded_actor']
    assert actor_f['consequence'] == ACTOR_CONSEQUENCE
    assert actor_f['evidence'] == {
        'total_changes': 26, 'curator_or_agent_changes': 25, 'curator_or_agent_share': round(25 / 26, 4),
        'curator_changes': 14, 'agent_changes': 11, 'user_changes': 1, 'other_changes': 0,
    }
    storm_f = f_by_id['skill_ledger.patch_storm']
    assert storm_f['consequence'] == PATCH_STORM_CONSEQUENCE
    assert storm_f['evidence']['affected_skill_count'] == 1
    assert storm_f['evidence']['max_changes_24h'] == 23
    assert storm_f['evidence']['threshold_changes_24h'] == 10
    assert f_by_id['skill_ledger.noop_changes']['evidence']['noop_changes'] == 1
    orphan_f = f_by_id['skill_ledger.orphan_backups']
    assert orphan_f['consequence'] == ORPHAN_BACKUPS_CONSEQUENCE
    assert orphan_f['evidence']['orphan_blob_count'] == 1
    assert orphan_f['evidence']['orphan_blob_bytes'] == 22020096
    assert orphan_f['evidence']['all_blobs_orphaned_no_ledger'] is False
    # Every consequence is one fixed sentence per rule: no interpolated numbers or names.
    for f in res['findings']:
        assert f['consequence'] == mod.CONSEQUENCES[f['id']]
    assert f_by_id['skill_ledger.patch_storm']['classification'] == 'review_suggested'
    assert f_by_id['skill_ledger.skill_growth']['classification'] == 'review_suggested'
    assert f_by_id['skill_ledger.version_churn']['classification'] == 'info'
    assert f_by_id['skill_ledger.noop_changes']['classification'] == 'info'
    assert f_by_id['skill_ledger.orphan_backups']['classification'] == 'review_suggested'
    assert f_by_id['skill_ledger.bookkeeping_orphans']['classification'] == 'info'


def test_do_not_flag_short_user_ledger_small_backups_and_sync_actor(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'profile'
    profile.mkdir()

    _write_skill_dir(profile, 'my-skill', 'my-skill')
    h1, _ = _write_blob(profile, b'a' * 1000)
    h2, _ = _write_blob(profile, b'b' * 1200)

    # Short ledger of user changes + stock-skill sync entries
    entries: list[dict[str, Any]] = [
        {
            'id': 'u1',
            'ts': '2026-09-01T10:00:00+00:00',
            'actor': 'user',
            'action': 'create',
            'skill': 'my-skill',
            'before': [],
            'after': [{'path': '/home/user/.hermes/skills/my-skill/SKILL.md', 'sha256': h1}],
        },
        {
            'id': 'u2',
            'ts': '2026-09-01T12:00:00+00:00',
            'actor': 'user',
            'action': 'patch',
            'skill': 'my-skill',
            'before': [{'path': '/home/user/.hermes/skills/my-skill/SKILL.md', 'sha256': h1}],
            'after': [{'path': '/home/user/.hermes/skills/my-skill/SKILL.md', 'sha256': h2}],
        },
    ]
    # Add 25 'sync' entries to confirm sync is excluded from unattended share
    for idx in range(25):
        entries.append({
            'id': f's{idx}',
            'ts': f'2026-09-{idx + 1:02d}T00:00:00+00:00',
            'actor': 'sync',
            'action': 'sync',
            'skill': f'stock-{idx}',
            'before': [],
            'after': [{'path': f'/home/user/.hermes/skills/stock-{idx}/SKILL.md', 'sha256': h1}],
        })
    _write_ledger(profile, entries)

    # 2 snapshots totalling < 10 MB, plus 1 small orphan blob (500 bytes)
    _write_blob(profile, b'z' * 500)
    _write_snapshot(profile, '2026-09-01T00-00-00Z', size_bytes=2 * 1024 * 1024)
    _write_snapshot(profile, '2026-09-02T00-00-00Z', size_bytes=2 * 1024 * 1024)

    res = mod.audit_skill_ledger(profile_path=profile, curator_enabled=True)
    sec = res['skill_ledger']
    assert res['coverage'] == 'verified'
    # Hermes never writes actor 'sync' (tools/skill_ledger.py:38,311): any other label is 'other'.
    assert sec['changes_by_actor'] == {'curator': 0, 'agent': 0, 'user': 2, 'other': 25}
    assert sec['curator_or_agent_changes'] == 0
    assert 'sync' not in json.dumps(sec['changes_by_actor'])
    assert sec['curator_or_agent_share'] == 0.0
    assert res['findings'] == []


def test_orphan_blobs_without_ledger_and_curator_disabled(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'profile'
    profile.mkdir()

    # No ledger in the main home, but blobs exist (a shape seen in real homes)
    _write_blob(profile, b'x' * 4096)
    _write_blob(profile, b'y' * 4096)

    # Small blobs: curator_enabled=False alone is not a trigger (the ledger and its blobs are
    # written for every actor, not only the curator: tools/skill_ledger.py:1-8,298-311).
    res = mod.audit_skill_ledger(profile_path=profile, curator_enabled=False)
    sec = res['skill_ledger']
    assert res['coverage'] == 'could_not_verify'
    assert sec['ledger_present'] is False
    assert sec['reason'] == 'ledger_absent'
    assert sec['backup_store']['all_blobs_orphaned_no_ledger'] is True
    assert sec['backup_store']['orphan_blob_count'] == 2
    ids = {f['id'] for f in res['findings']}
    assert ids == {'skill_ledger.could_not_verify'}

    # Over the byte threshold with no ledger: the wording says the blobs cannot be matched.
    _write_blob(profile, b'z' * (21 * 1024 * 1024))
    res2 = mod.audit_skill_ledger(profile_path=profile)
    f = {x['id']: x for x in res2['findings']}['skill_ledger.orphan_backups']
    assert f['classification'] == 'review_suggested'
    assert f['consequence'] == ORPHAN_BACKUPS_CONSEQUENCE
    assert f['evidence']['orphan_blob_count'] == 3
    assert f['evidence']['orphan_blob_bytes'] == 22028288
    assert f['evidence']['all_blobs_orphaned_no_ledger'] is True
    assert 'garbage' not in f['consequence']
    assert f['source_paths'][0]['path'] == '.curator_backups/blobs'


def test_snapshot_tarballs_alone_are_not_orphan_backups(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'profile'
    _write_skill_dir(profile, 'a', 'a')
    h, _ = _write_blob(profile, b'a' * 100)
    _write_ledger(profile, [{
        'ts': '2026-09-01T00:00:00+00:00', 'actor': 'agent', 'action': 'create', 'skill': 'a',
        'before': [], 'after': [{'path': '/home/user/.hermes/skills/a/SKILL.md', 'sha256': h}]}])
    # Several large snapshots (here 3 x 24 MiB). They are retained rollback points
    # (agent/curator_backup.py:118-120,200-211), not unreferenced files.
    for i in range(3):
        _write_snapshot(profile, f'2026-09-0{i + 1}T00-00-00Z', size_bytes=24 * 1024 * 1024)
    res = mod.audit_skill_ledger(profile_path=profile, curator_enabled=False)
    sec = res['skill_ledger']
    assert sec['backup_store']['tarball_count'] == 3
    assert sec['backup_store']['tarball_bytes'] == 3 * 24 * 1024 * 1024
    assert [f['id'] for f in res['findings']] == []


def test_orphan_blobs_not_judged_when_ledger_partly_unreadable(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'profile'
    _write_skill_dir(profile, 'a', 'a')
    big, _ = _write_blob(profile, b'q' * (21 * 1024 * 1024))
    # The only reference to the big blob sits on a malformed line: Hermes itself refuses to GC
    # then (tools/skill_ledger.py:470-481), so the audit must not call the blob unreferenced.
    _write_ledger(profile, [
        '{"ts": "2026-09-01T00:00:00+00:00", "actor": "agent", "skill": "a", "after": [{"sha256": "' + big + '"',
        {'ts': '2026-09-01T01:00:00+00:00', 'actor': 'agent', 'action': 'patch', 'skill': 'a',
         'before': [], 'after': []},
    ])
    res = mod.audit_skill_ledger(profile_path=profile)
    sec = res['skill_ledger']
    assert sec['backup_store']['references_complete'] is False
    ids = {f['id'] for f in res['findings']}
    assert 'skill_ledger.orphan_backups' not in ids
    assert 'skill_ledger.could_not_verify' in ids


def test_missing_empty_home_and_malformed_inputs(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    missing = tmp_path / 'nonexistent'
    res_missing = mod.audit_skill_ledger(profile_path=missing)
    assert str(tmp_path) not in json.dumps(res_missing)
    empty = tmp_path / 'empty'
    empty.mkdir()
    res_empty = mod.audit_skill_ledger(profile_path=empty)
    assert res_empty['skill_ledger']['reason'] == 'ledger_absent'
    assert res_empty['skill_ledger']['reasons'] == ['ledger_absent']
    assert res_missing['coverage'] == 'could_not_verify'
    assert res_missing['skill_ledger']['status'] == 'not_measured'
    assert any(f['id'] == 'skill_ledger.could_not_verify' for f in res_missing['findings'])

    # Malformed ledger lines, wrong JSON types, binary junk, broken usage/manifest
    profile = tmp_path / 'malformed'
    profile.mkdir()
    _write_skill_dir(profile, 'valid-skill', 'valid-skill')
    h1, _ = _write_blob(profile, b'hello world')
    _write_ledger(profile, [
        '{broken json',
        '[]',
        '123',
        json.dumps({'id': 'bad1', 'ts': 'not-a-timestamp', 'actor': 999, 'action': None, 'skill': '', 'before': 'bad', 'after': [123]}),
        json.dumps({
            'id': 'ok1',
            'ts': '2026-09-01T00:00:00+00:00',
            'actor': 'user',
            'action': 'create',
            'skill': 'valid-skill',
            'before': [],
            'after': [{'path': '/home/user/.hermes/skills/valid-skill/SKILL.md', 'sha256': h1}],
        }),
    ])
    (profile / 'skills' / ('.' + 'usage.json')).write_bytes(b'\xff\xfe\x00broken')
    (profile / 'skills' / ('.bundled_' + 'manifest')).write_text('bad_manifest_line_without_valid_md5:xyz\n', encoding='utf-8')

    res_mal = mod.audit_skill_ledger(profile_path=profile)
    sec = res_mal['skill_ledger']
    assert res_mal['coverage'] == 'could_not_verify'
    assert sec['limits']['cuts'] >= 4
    assert sec['total_changes'] == 1
    assert any(f['id'] == 'skill_ledger.could_not_verify' for f in res_mal['findings'])


def test_caps_and_truncation_paths(tmp_path: Path, monkeypatch: Any) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'caps'
    profile.mkdir()
    h1, _ = _write_blob(profile, b'a' * 100)
    h2, _ = _write_blob(profile, b'b' * 100)
    _write_ledger(profile, [
        {
            'id': f'e{i}',
            'ts': f'2026-09-01T00:00:{i:02d}+00:00',
            'actor': 'user',
            'action': 'patch',
            'skill': 'cap-skill',
            'before': [{'path': '/home/user/.hermes/skills/cap-skill/SKILL.md', 'sha256': h1}],
            'after': [{'path': '/home/user/.hermes/skills/cap-skill/SKILL.md', 'sha256': h2}],
        }
        for i in range(5)
    ])

    # 1. Line cap
    monkeypatch.setattr(mod, 'MAX_LEDGER_LINES', 2)
    res_lines = mod.audit_skill_ledger(profile_path=profile)
    assert res_lines['coverage'] == 'could_not_verify'
    assert res_lines['skill_ledger']['truncated_by'] == 'max_ledger_lines'
    assert res_lines['skill_ledger']['total_changes'] == 2
    monkeypatch.undo()

    # 2. Ledger byte cap
    monkeypatch.setattr(mod, 'MAX_LEDGER_BYTES', 120)
    res_bytes = mod.audit_skill_ledger(profile_path=profile)
    assert res_bytes['coverage'] == 'could_not_verify'
    assert res_bytes['skill_ledger']['truncated_by'] == 'max_ledger_bytes'
    monkeypatch.undo()

    # 3. Blob entry cap
    monkeypatch.setattr(mod, 'MAX_BLOB_ENTRIES', 1)
    res_blobs = mod.audit_skill_ledger(profile_path=profile)
    assert res_blobs['coverage'] == 'could_not_verify'
    assert res_blobs['skill_ledger']['truncated_by'] == 'max_blob_entries'
    monkeypatch.undo()

    # 4. Wall-clock timeout via injectable clock
    ticks = iter([0.0, 0.1, 25.0, 26.0, 27.0])
    res_time = mod.audit_skill_ledger(profile_path=profile, clock=lambda: next(ticks, 30.0))
    assert res_time['coverage'] == 'could_not_verify'
    assert res_time['skill_ledger']['truncated_by'] == 'time_budget'


def test_symlinks_credentials_never_opened_and_readonly_invariants(
    tmp_path: Path, monkeypatch: Any
) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'secure_profile'
    profile.mkdir()

    outside = tmp_path / 'outside_target'
    outside.mkdir()
    outside_secret = outside / 'secret.txt'
    outside_secret.write_text('CANARY_OUTSIDE_SECRET', encoding='utf-8')

    # Plant credential files inside skills and blobs
    _write_skill_dir(profile, 'sec-skill', 'sec-skill', body='CANARY_SKILL_BODY_TEXT\n')
    env_file = profile / 'skills' / '.env'
    env_file.write_text('API_KEY=CANARY_ENV_SECRET\n', encoding='utf-8')
    auth_file = profile / '.curator_backups' / 'blobs' / 'auth.json'
    auth_file.parent.mkdir(parents=True, exist_ok=True)
    auth_file.write_text('{"token": "CANARY_AUTH_SECRET"}', encoding='utf-8')

    # Plant a blob with canary content (blobs must only be lstat'ed, NEVER read)
    blob_hash, _blob_path = _write_blob(profile, b'CANARY_BLOB_CONTENT_MUST_NOT_BE_READ')

    # Plant a symlinked skill directory pointing outside
    os.symlink(outside, profile / 'skills' / 'linked-skill')

    # Plant a tarball in profile-exports (must never be opened/extracted)
    exports = profile / 'profile-exports'
    exports.mkdir()
    export_tar = exports / 'profile-20261001.tar.gz'
    export_tar.write_bytes(b'CANARY_TARBALL_BYTES')

    # Ledger with canary session_id, canary deep path, canary hash
    _write_ledger(profile, [
        {
            'id': 'CANARY_ENTRY_ID',
            'ts': '2026-09-01T00:00:00+00:00',
            'actor': 'user',
            'action': 'create',
            'skill': 'sec-skill',
            'evidence': {'session_id': '20260901_000000_CANARYSESSION'},
            'before': [],
            'after': [{
                'path': '/home/user/CANARY_DEEP_PATH/.hermes/skills/sec-skill/SKILL.md',
                'sha256': blob_hash,
            }],
        }
    ])

    before_tree = _tree_snapshot(profile)

    opened_paths: list[str] = []
    orig_builtins_open = builtins.open
    orig_io_open = io.open
    orig_os_open = os.open

    def track_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if not isinstance(file, int):
            opened_paths.append(os.fsdecode(file))
        return orig_builtins_open(file, *args, **kwargs)

    def track_io_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if not isinstance(file, int):
            opened_paths.append(os.fsdecode(file))
        return orig_io_open(file, *args, **kwargs)

    def track_os_open(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        raw = os.fsdecode(path)
        opened_paths.append(raw)
        return orig_os_open(path, flags, mode, dir_fd=dir_fd)

    def forbid_tar_open(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError('tarfile.open must never be called')

    monkeypatch.setattr(builtins, 'open', track_open)
    monkeypatch.setattr(io, 'open', track_io_open)
    monkeypatch.setattr(os, 'open', track_os_open)
    monkeypatch.setattr(tarfile, 'open', forbid_tar_open)

    result = mod.audit_skill_ledger(profile_path=profile)
    monkeypatch.undo()

    after_tree = _tree_snapshot(profile)
    assert after_tree == before_tree, 'Profile directory mutated during read-only audit'

    # Verify credential files, blobs, outside symlink targets, and tarballs were never opened
    for opened in opened_paths:
        assert '.env' not in opened
        assert 'auth.json' not in opened
        assert blob_hash not in opened
        assert 'secret.txt' not in opened
        assert 'outside_target' not in opened
        assert '.tar.gz' not in opened

    # Verify privacy: no canary strings, no session ids, no raw hashes in serialized output
    serialized = json.dumps(result)
    for canary in (
        'CANARY_OUTSIDE_SECRET',
        'CANARY_SKILL_BODY_TEXT',
        'CANARY_ENV_SECRET',
        'CANARY_AUTH_SECRET',
        'CANARY_BLOB_CONTENT_MUST_NOT_BE_READ',
        'CANARY_TARBALL_BYTES',
        'CANARY_ENTRY_ID',
        'CANARYSESSION',
        'CANARY_DEEP_PATH',
        blob_hash,
    ):
        assert canary not in serialized, f'Leaked {canary} in result JSON'


def _entry(ts: str, actor: str, action: str, skill: str, before: list, after: list) -> dict[str, Any]:
    def items(hs: list) -> list:
        return [{'path': f'/home/user/.hermes/skills/{skill}/SKILL.md', 'sha256': h} for h in hs]
    return {'id': 'x', 'ts': ts, 'actor': actor, 'action': action, 'skill': skill,
            'before': items(before), 'after': items(after)}


def test_growth_uses_first_and_latest_by_ledger_order_and_missing_blob_is_unverified(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'profile'
    profile.mkdir()
    h_small, _ = _write_blob(profile, b's' * 1000)
    h_mid, _ = _write_blob(profile, b'm' * 5000)
    h_big, _ = _write_blob(profile, b'b' * 9000)
    gone_first = 'a' * 64
    gone_last = 'b' * 64
    for name in ('ordered', 'first-gone', 'last-gone'):
        _write_skill_dir(profile, name, name)
    _write_ledger(profile, [
        # Ledger order, not timestamp order, decides first/latest (append-only file:
        # tools/skill_ledger.py:315-317). Timestamps here are deliberately out of order.
        _entry('2026-09-05T00:00:00+00:00', 'agent', 'create', 'ordered', [], [h_small]),
        _entry('2026-09-01T00:00:00+00:00', 'agent', 'patch', 'ordered', [h_small], [h_big]),
        _entry('2026-09-02T00:00:00+00:00', 'agent', 'patch', 'ordered', [h_big], [h_mid]),
        # First blob missing: growth must be could_not_verify, never 1.0 or a later-base ratio.
        _entry('2026-09-01T00:00:00+00:00', 'agent', 'create', 'first-gone', [], [gone_first]),
        _entry('2026-09-01T01:00:00+00:00', 'agent', 'patch', 'first-gone', [gone_first], [h_small]),
        _entry('2026-09-01T02:00:00+00:00', 'agent', 'patch', 'first-gone', [h_small], [h_big]),
        # Latest blob missing: also could_not_verify.
        _entry('2026-09-01T00:00:00+00:00', 'agent', 'create', 'last-gone', [], [h_small]),
        _entry('2026-09-01T01:00:00+00:00', 'agent', 'patch', 'last-gone', [h_small], [h_big]),
        _entry('2026-09-01T02:00:00+00:00', 'agent', 'patch', 'last-gone', [h_big], [gone_last]),
    ])
    sec = mod.audit_skill_ledger(profile_path=profile)['skill_ledger']
    by = {Path(r['path']).name: r for r in sec['skills']}
    assert (by['ordered']['first_size_bytes'], by['ordered']['latest_size_bytes']) == (1000, 5000)
    assert by['ordered']['growth_ratio'] == 5.0
    assert by['ordered']['growth_coverage'] == 'verified'
    for name in ('first-gone', 'last-gone'):
        assert by[name]['growth_ratio'] is None
        assert by[name]['growth_coverage'] == 'could_not_verify'
    assert by['first-gone']['first_size_bytes'] is None
    assert by['last-gone']['latest_size_bytes'] is None
    assert sec['skills_growth_could_not_verify'] == 2
    assert 'growth_blob_missing' in sec['reasons']
    assert sec['top_skills_by_growth'] == {
        'paths': [os.path.realpath(profile / 'skills' / 'ordered')], 'unlocated_count': 0}


def test_noop_only_for_identical_recorded_state(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'profile'
    profile.mkdir()
    h1, _ = _write_blob(profile, b'abcd' * 500)
    h2, _ = _write_blob(profile, b'abce' * 500)  # same size, different content: a real change
    _write_ledger(profile, [
        _entry('2026-09-01T00:00:00+00:00', 'agent', 'create', 's', [], [h1]),
        _entry('2026-09-01T01:00:00+00:00', 'agent', 'patch', 's', [h1], [h2]),
        # pre-rollback deliberately records before == after (tools/skill_ledger.py:306-308).
        _entry('2026-09-01T02:00:00+00:00', 'agent', 'pre-rollback', 's', [h2], [h2]),
        # A recorded write with no file change on either side (after _delta): a no-op.
        _entry('2026-09-01T03:00:00+00:00', 'agent', 'write_file', 's', [], []),
    ])
    res = mod.audit_skill_ledger(profile_path=profile)
    sec = res['skill_ledger']
    assert sec['noop_changes'] == 1
    f = {x['id']: x for x in res['findings']}['skill_ledger.noop_changes']
    assert f['consequence'] == (
        'The ledger contains change records whose recorded after-state is identical to the '
        'before-state (same file hashes, or no file recorded on either side); this shows the '
        'record, not why the change was made.'
    )


def test_deterministic_across_clocks_and_no_absolute_paths(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'profile'
    _write_skill_dir(profile, 'a', 'a')
    hs = [_write_blob(profile, (b'%d' % i) * (500 + i * 900))[0] for i in range(12)]
    rows = [_entry('2026-09-01T00:00:00+00:00', 'curator', 'create', 'a', [], [hs[0]])]
    rows += [_entry(f'2026-09-01T0{i // 2}:{(i % 2) * 30:02d}:00+00:00', 'curator', 'patch', 'a',
                    [hs[i - 1]], [hs[i]]) for i in range(1, 12)]
    rows += [_entry(f'2026-10-{d:02d}T00:00:00+00:00', 'agent', 'patch', 'a', [hs[11]], [hs[d % 11]])
             for d in range(1, 10)]
    _write_ledger(profile, rows)
    _write_blob(profile, b'o' * (21 * 1024 * 1024))
    def ticking(start: float, step: float):
        state = [start]

        def clock() -> float:
            state[0] += step
            return state[0]
        return clock

    # Two runs on an unchanged home with clocks nine days apart and different speeds.
    r1 = mod.audit_skill_ledger(profile_path=profile, clock=ticking(1_000.0, 0.0001))
    r2 = mod.audit_skill_ledger(profile_path=profile, clock=ticking(1_000.0 + 9 * 86_400, 0.0003))
    assert json.dumps(r1['skill_ledger'], sort_keys=True) == json.dumps(r2['skill_ledger'], sort_keys=True)
    assert json.dumps(r1['findings'], sort_keys=True) == json.dumps(r2['findings'], sort_keys=True)
    # Run-dependent numbers live only in the top-level run_metrics sibling, never in the section.
    assert set(r1['run_metrics']) == {'elapsed_ms'}
    assert r1['run_metrics']['elapsed_ms'] != r2['run_metrics']['elapsed_ms']
    assert 'elapsed_ms' not in json.dumps(r1['skill_ledger'])
    sec = r1['skill_ledger']
    assert [(m['year'], m['month']) for m in sec['changes_by_month']] == [(2026, 9), (2026, 10)]
    assert sec['skills'][0]['peak_changes_24h'] == 12
    # The only absolute strings are existing skill folders under skills/ (here: skills/a).
    skill_dir = os.path.realpath(profile / 'skills' / 'a')
    assert [r['path'] for r in sec['skills']] == [skill_dir]
    out = json.dumps(r1).replace(json.dumps(skill_dir), '')
    assert str(tmp_path) not in out
    assert 'profile_path' not in sec
    for f in r1['findings']:
        for sp in f['source_paths']:
            assert not sp['path'].startswith('/')


def test_healthy_home_has_no_findings_above_info(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'profile'
    rows = []
    for k in range(8):
        name = f'skill-{k}'
        _write_skill_dir(profile, name, name)
        h1, _ = _write_blob(profile, (name + 'v1').encode() * 200)
        h2, _ = _write_blob(profile, (name + 'v2').encode() * 220)
        rows.append(_entry(f'2026-09-0{k + 1}T10:00:00+00:00', 'agent', 'create', name, [], [h1]))
        rows.append(_entry(f'2026-09-0{k + 1}T15:00:00+00:00', 'agent', 'patch', name, [h1], [h2]))
    rows.append(_entry('2026-09-20T10:00:00+00:00', 'user', 'archive', 'skill-7', [], []))
    _write_ledger(profile, rows)
    for i in range(2):
        _write_snapshot(profile, f'2026-09-1{i}T00-00-00Z', size_bytes=3 * 1024 * 1024)
    (profile / 'skills' / ('.' + 'usage.json')).write_text(json.dumps(
        {f'skill-{k}': {'state': 'active'} for k in range(8)}), encoding='utf-8')
    res = mod.audit_skill_ledger(profile_path=profile, curator_enabled=True)
    assert res['coverage'] == 'verified'
    assert [f for f in res['findings'] if f['classification'] != 'info'] == []


def test_curator_enabled_read_from_profile_config(tmp_path: Path) -> None:
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'profile'
    profile.mkdir()
    # No config.yaml: the Hermes default (agent/curator.py is_enabled: default True).
    sec = mod.audit_skill_ledger(profile_path=profile)['skill_ledger']
    assert (sec['curator_enabled'], sec['curator_enabled_source']) == (True, 'default')
    cfg = profile / 'config.yaml'
    cfg.write_text('curator:\n  enabled: false\n', encoding='utf-8')
    sec = mod.audit_skill_ledger(profile_path=profile)['skill_ledger']
    assert (sec['curator_enabled'], sec['curator_enabled_source']) == (False, 'config')
    cfg.write_text('curator:\n  interval_hours: 4\n', encoding='utf-8')
    sec = mod.audit_skill_ledger(profile_path=profile)['skill_ledger']
    assert (sec['curator_enabled'], sec['curator_enabled_source']) == (True, 'default')
    # A value whose meaning differs between YAML loaders is not guessed.
    cfg.write_text('curator:\n  enabled: n\n', encoding='utf-8')
    sec = mod.audit_skill_ledger(profile_path=profile)['skill_ledger']
    assert (sec['curator_enabled'], sec['curator_enabled_source']) == (None, 'could_not_verify')
    cfg.write_text('curator: [unbalanced\n', encoding='utf-8')
    sec = mod.audit_skill_ledger(profile_path=profile)['skill_ledger']
    assert (sec['curator_enabled'], sec['curator_enabled_source']) == (None, 'could_not_verify')
    # An explicit caller value still wins (kept for callers that already resolved config).
    sec = mod.audit_skill_ledger(profile_path=profile, curator_enabled=True)['skill_ledger']
    assert (sec['curator_enabled'], sec['curator_enabled_source']) == (True, 'caller')
    # The echo never changes coverage or findings.
    assert sec['coverage'] == 'could_not_verify'  # ledger absent



# --- Wiring sheet (audit/wiring/skill_ledger.json) and sealing ------------------------------

WIRING_PATH = Path(__file__).resolve().parents[1] / 'audit' / 'wiring' / 'skill_ledger.json'
USAGE_NAME = '.' + 'usage.json'
MANIFEST_NAME = '.bundled_' + 'manifest'


def _wiring() -> dict[str, Any]:
    return json.loads(WIRING_PATH.read_text(encoding='utf-8'))


def _walk(value: Any, path: str = ''):
    """Yield ('key', path, key) for every dict key and ('value', path, leaf) for every leaf."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield ('key', path, k)
            yield from _walk(v, f'{path}.{k}' if path else k)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item, path + '[]')
    else:
        yield ('value', path, value)


def _branch_results(tmp_path: Path, monkeypatch: Any) -> list[dict[str, Any]]:
    """Run the module over synthetic homes that reach every branch the walker must see."""
    mod = load_submodule('audit.skill_ledger')
    out: list[dict[str, Any]] = []

    rich = tmp_path / 'rich'
    rich.mkdir()
    _build_rich_home(rich)
    out.append(mod.audit_skill_ledger(profile_path=rich))
    out.append(mod.audit_skill_ledger(profile_path=rich, curator_enabled=False))

    out.append(mod.audit_skill_ledger(profile_path=tmp_path / 'missing'))
    not_dir = tmp_path / 'not-a-dir'
    not_dir.write_text('x', encoding='utf-8')
    out.append(mod.audit_skill_ledger(profile_path=not_dir))
    empty = tmp_path / 'empty'
    empty.mkdir()
    out.append(mod.audit_skill_ledger(profile_path=empty))

    no_ledger = tmp_path / 'no-ledger'
    no_ledger.mkdir()
    _write_blob(no_ledger, b'z' * (21 * 1024 * 1024))
    (no_ledger / 'config.yaml').write_text('curator:\n  enabled: n\n', encoding='utf-8')
    out.append(mod.audit_skill_ledger(profile_path=no_ledger))

    mal = tmp_path / 'malformed'
    mal.mkdir()
    _write_skill_dir(mal, 'valid-skill', 'valid-skill')
    h1, _ = _write_blob(mal, b'hello world')
    _write_ledger(mal, [
        '{broken json', '[]',
        json.dumps({'ts': 'nope', 'actor': 'someone-else', 'action': 'patch', 'skill': 'odd',
                    'before': [], 'after': []}),
        json.dumps(_entry('2026-09-01T00:00:00+00:00', 'user', 'create', 'valid-skill', [], [h1])),
        json.dumps(_entry('2026-09-01T01:00:00+00:00', 'agent', 'patch', 'gone', ['c' * 64], ['d' * 64])),
    ])
    (mal / 'skills' / USAGE_NAME).write_bytes(b'\xff\xfe\x00broken')
    (mal / 'skills' / MANIFEST_NAME).write_text('bad:xyz\n', encoding='utf-8')
    (mal / 'config.yaml').write_text('curator: [unbalanced\n', encoding='utf-8')
    os.symlink(tmp_path, mal / 'skills' / 'linked')
    out.append(mod.audit_skill_ledger(profile_path=mal))

    caps = tmp_path / 'caps'
    caps.mkdir()
    ha, _ = _write_blob(caps, b'a' * 100)
    hb, _ = _write_blob(caps, b'b' * 100)
    _write_ledger(caps, [_entry(f'2026-09-01T00:00:{i:02d}+00:00', 'user', 'patch', 'cap', [ha], [hb])
                         for i in range(5)])
    for name, value in (('MAX_LEDGER_LINES', 2), ('MAX_LEDGER_BYTES', 120), ('MAX_BLOB_ENTRIES', 1)):
        monkeypatch.setattr(mod, name, value)
        out.append(mod.audit_skill_ledger(profile_path=caps))
        monkeypatch.undo()
    ticks = iter([0.0, 0.1, 25.0, 26.0, 27.0])
    out.append(mod.audit_skill_ledger(profile_path=caps, clock=lambda: next(ticks, 30.0)))
    return out


def test_wiring_sheet_matches_code() -> None:
    mod = load_submodule('audit.skill_ledger')
    w = _wiring()
    assert set(w) == {'section', 'entry', 'kwargs', 'schema_keys', 'vocabulary', 'numeric_evidence_keys',
                      'vocab_evidence_keys', 'rule_ids', 'classifications', 'consequences', 'free_strings',
                      'run_metrics_keys', 'notes'}
    assert w['section'] == 'skill_ledger'
    assert w['entry'] == 'audit.skill_ledger.audit_skill_ledger'
    import inspect
    assert set(w['kwargs']) == set(inspect.signature(mod.audit_skill_ledger).parameters)
    assert w['rule_ids'] == sorted(mod.CONSEQUENCES)
    assert w['consequences'] == mod.CONSEQUENCES
    assert w['classifications'] == {k: [v] for k, v in mod.RULE_CLASSIFICATIONS.items()}
    for key in ('schema_keys', 'vocabulary', 'numeric_evidence_keys', 'vocab_evidence_keys', 'rule_ids'):
        assert w[key] == sorted(set(w[key])), key
    assert not set(w['numeric_evidence_keys']) & set(w['vocab_evidence_keys'])
    assert set(w['numeric_evidence_keys']) | set(w['vocab_evidence_keys']) <= set(w['schema_keys'])
    for sentence in mod.CONSEQUENCES.values():
        assert not any(ch.isdigit() for ch in sentence.replace('8,000', '').replace('24-hour', '')
                       .replace('20 MiB', '').replace('20 distinct', '').replace('10 or more', ''))
        for word in ('you', 'indicates', 'suggests', 'unpruned', 'abandoned'):
            assert word not in sentence.lower().split(), word


def _free_keys(w: dict[str, Any]) -> set[str]:
    return {f['key'] for f in w['free_strings']}


def _assert_kept_skill_path(profile_like: str, value: Any) -> None:
    """A free string is an absolute, existing, non-symlink folder holding SKILL.md."""
    assert isinstance(value, str) and os.path.isabs(value), value
    assert os.path.isdir(value) and not os.path.islink(value), value
    assert os.path.isfile(os.path.join(value, 'SKILL.md')), value
    assert os.path.realpath(value) == value, value
    assert f'{os.sep}skills{os.sep}' in value, value


def _no_hmac(value: Any) -> None:
    if isinstance(value, dict):
        assert 'hmac' not in value, value
        for v in value.values():
            _no_hmac(v)
    elif isinstance(value, list):
        for v in value:
            _no_hmac(v)


def test_every_emitted_key_and_string_is_declared(tmp_path: Path, monkeypatch: Any) -> None:
    w = _wiring()
    keys, vocab = set(w['schema_keys']), set(w['vocabulary'])
    free = _free_keys(w)
    assert free == {'skills[].path', 'top_skills_by_changes.paths[]', 'top_skills_by_growth.paths[]'}
    seen_free: set[str] = set()
    for res in _branch_results(tmp_path, monkeypatch):
        assert set(res) == {'ok', 'status', 'error', 'coverage', 'classification', 'findings',
                            'skill_ledger', 'run_metrics'}
        assert set(res['run_metrics']) == set(w['run_metrics_keys'])
        for kind, path, item in _walk(res['skill_ledger']):
            if kind == 'key':
                assert item in keys, (path, item)
            elif isinstance(item, str):
                if path in free:
                    seen_free.add(path)
                    _assert_kept_skill_path(str(tmp_path), item)
                else:
                    assert item in vocab, (path, item)
            else:
                assert item is None or type(item) in (bool, int, float), (path, item)
        for f in res['findings']:
            rid = f['id']
            assert rid in w['rule_ids']
            assert f['classification'] in w['classifications'][rid]
            assert f['consequence'] == w['consequences'][rid]
            for ident in f['affected_identities']:
                assert ident in vocab
            for sp in f['source_paths']:
                assert sp['path'] in vocab
            for k, v in f['evidence'].items():
                assert k in keys, (rid, k)
                if isinstance(v, str):
                    assert k in w['vocab_evidence_keys'] and v in vocab, (rid, k, v)
                else:
                    assert k in w['numeric_evidence_keys'] and type(v) in (bool, int, float), (rid, k, v)
    # Every declared free-string location is actually reachable.
    assert seen_free == free


def _patch_sealing_sets(monkeypatch: Any) -> dict[str, Any]:
    """Union the live sealing sets with the wiring sheet, patched where they are read."""
    w = _wiring()
    ev = load_submodule('audit.evidence')
    per = load_submodule('audit.persistence')
    ec = load_submodule('audit.evidence_constants')
    sentences = frozenset(w['consequences'].values())
    vocab = ev.VOCABULARY | frozenset(w['vocabulary']) | frozenset(w['rule_ids']) | sentences
    monkeypatch.setattr(ev, 'SCHEMA_KEYS', ev.SCHEMA_KEYS | frozenset(w['schema_keys']))
    monkeypatch.setattr(ev, 'VOCABULARY', vocab)
    monkeypatch.setattr(per, 'VOCABULARY', vocab)
    monkeypatch.setattr(per, '_EVIDENCE_NUMERIC_KEYS', per._EVIDENCE_NUMERIC_KEYS | frozenset(w['numeric_evidence_keys']))
    monkeypatch.setattr(per, '_EVIDENCE_VOCAB_KEYS', per._EVIDENCE_VOCAB_KEYS | frozenset(w['vocab_evidence_keys']))
    consequences = {**ec.FINDING_CONSEQUENCES, **w['consequences']}
    allowed = ec.ALLOWED_FINDING_CONSEQUENCES | sentences
    for module in (per, ec):
        monkeypatch.setattr(module, 'FINDING_CONSEQUENCES', consequences)
        monkeypatch.setattr(module, 'ALLOWED_FINDING_CONSEQUENCES', allowed)
    monkeypatch.setattr(ec, 'RULE_IDS', ec.RULE_IDS | frozenset(w['rule_ids']))
    return w


def _seal(res: dict[str, Any], w: dict[str, Any]) -> tuple[Any, Any]:
    """Section and findings exactly as the report stores them (adapt -> serialize / persistence)."""
    ev = load_submodule('audit.evidence')
    per = load_submodule('audit.persistence')
    contract = load_submodule('audit.contract')
    adapted = contract.adapt_component_result(res, component_id='skill_ledger', affected_identities=['default'])
    section = per.strict_json(ev.serialize_evidence({'skill_ledger': adapted['skill_ledger']}))['skill_ledger']
    findings = per.strict_json([per.finding_dto(f) for f in adapted['findings']])
    return section, findings


def test_sealing_keeps_everything_unchanged(tmp_path: Path, monkeypatch: Any) -> None:
    results = _branch_results(tmp_path, monkeypatch)
    w = _patch_sealing_sets(monkeypatch)
    per = load_submodule('audit.persistence')
    contract = load_submodule('audit.contract')
    for res in results:
        adapted = contract.adapt_component_result(res, component_id='skill_ledger', affected_identities=['default'])
        # adapt_component_result keeps the section and run_metrics as top-level siblings.
        assert adapted['skill_ledger'] == res['skill_ledger']
        assert adapted['run_metrics'] == res['run_metrics']
        assert adapted['coverage'] == res['coverage']
        section, findings = _seal(res, w)
        # Nothing is dropped, altered or tokenised: kept skill paths come back unchanged.
        assert section == res['skill_ledger']
        _no_hmac(section)
        _no_hmac(findings)
        for f, dto in zip(adapted['findings'], findings):
            assert dto['id'] == f['id']
            assert dto['classification'] == f['classification']
            assert dto['coverage'] == f['coverage']
            assert dto['consequence'] == f['consequence'] == w['consequences'][f['id']]
            assert dto['affected_identities'] == f['affected_identities']
            assert dto['source_paths'] == f['source_paths']
            kept = {k: v for k, v in dto['evidence'].items() if k != 'source_digest'}
            assert kept == f['evidence'], f['id']
        assert len(findings) == len(adapted['findings']) == len([per.finding_dto(f) for f in adapted['findings']])


def test_two_runs_give_identical_sealed_output(tmp_path: Path, monkeypatch: Any) -> None:
    """Fails if any per-run token is produced: each run seals with a fresh serializer key."""
    results = _branch_results(tmp_path, monkeypatch)
    w = _patch_sealing_sets(monkeypatch)
    mod = load_submodule('audit.skill_ledger')
    home = tmp_path / 'rich'
    for res in results:
        first = _seal(res, w)
        second = _seal(res, w)
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    # Two independent module runs on the same unchanged home, each sealed separately.
    run1 = _seal(mod.audit_skill_ledger(profile_path=home), w)
    run2 = _seal(mod.audit_skill_ledger(profile_path=home), w)
    assert json.dumps(run1, sort_keys=True) == json.dumps(run2, sort_keys=True)
    assert run1[0]['skills'][0]['path'] == os.path.realpath(home / 'skills' / 'alpha-review')


def test_skill_folder_location_rules(tmp_path: Path, monkeypatch: Any) -> None:
    """Recorded location first, else a unique folder name; ambiguous, deep, refused or path-like: counted."""
    w = _patch_sealing_sets(monkeypatch)
    mod = load_submodule('audit.skill_ledger')
    profile = tmp_path / 'p'
    _write_skill_dir(profile, 'cat-a/moved', 'moved')         # recorded location skills/cat-a/moved
    _write_skill_dir(profile, 'cat-b/moved', 'moved')         # same folder name elsewhere
    _write_skill_dir(profile, 'cat-a/twin', 'twin')
    _write_skill_dir(profile, 'cat-b/twin', 'twin')           # ambiguous by name, no recorded location
    _write_skill_dir(profile, 'solo', 'solo')                 # unique by name, no recorded location
    _write_skill_dir(profile, 'a/b/deep', 'deep')             # deeper than skills/<category>/<name>
    _write_skill_dir(profile, 'gone-here', 'gone-here')       # recorded elsewhere -> not this folder
    outside = tmp_path / 'outside-skill'
    outside.mkdir()
    (outside / 'SKILL.md').write_text('---\nname: linked\n---\n', encoding='utf-8')
    os.symlink(outside, profile / 'skills' / 'linked')        # refused, counted as a cut
    absolute_name = str(tmp_path / 'outside-file.txt')
    Path(absolute_name).write_text('x', encoding='utf-8')
    h, _ = _write_blob(profile, b'k' * 10)

    def row(skill: str, md: str | None) -> dict[str, Any]:
        after = [{'path': md, 'sha256': h}] if md else []
        return {'ts': '2026-09-01T00:00:00+00:00', 'actor': 'agent', 'action': 'create', 'skill': skill,
                'before': [], 'after': after}
    home = '/home/user/.hermes/skills/'
    _write_ledger(profile, [
        row('moved', home + 'cat-a/moved/SKILL.md'),
        row('twin', '/elsewhere/SKILL.md'),
        row('solo', None),
        row('deep', home + 'a/b/deep/SKILL.md'),
        row('gone-here', home + 'old-cat/gone-here/SKILL.md'),
        row('linked', home + 'linked/SKILL.md'),
        row(absolute_name, None),
        row(str(profile / 'skills' / 'solo'), None),
    ])
    res = mod.audit_skill_ledger(profile_path=profile)
    sec = res['skill_ledger']
    real = os.path.realpath(profile / 'skills')
    paths = sorted(r['path'] for r in sec['skills'] if r['path'])
    assert paths == [os.path.join(real, 'cat-a', 'moved'), os.path.join(real, 'solo')]
    assert sec['skills_without_folder_count'] == 6
    assert 'symlink_refused' in sec['reasons'] and sec['limits']['cuts'] >= 1
    section, findings = _seal(res, w)
    assert section == sec
    blob = json.dumps([section, findings])
    for name in ('twin', 'deep', 'gone-here', 'linked', 'outside', absolute_name):
        assert name not in blob, name
    # The serializer returns each kept path unchanged (it resolves and lstat's absolute paths).
    ev = load_submodule('audit.evidence')
    for p in paths:
        assert ev.EvidenceSerializer().serialize(p, field='path') == p

    # A truncated walk cannot rule out another folder of the same name: nothing is located.
    monkeypatch.setattr(mod, 'MAX_BLOB_ENTRIES', 3)
    capped = mod.audit_skill_ledger(profile_path=profile)['skill_ledger']
    assert all(r['path'] is None for r in capped['skills'])
    assert capped['skills_without_folder_count'] == len(capped['skills'])


def test_canaries_never_reach_sealed_output(tmp_path: Path, monkeypatch: Any) -> None:
    w = _patch_sealing_sets(monkeypatch)
    mod = load_submodule('audit.skill_ledger')
    free = _free_keys(w)
    profile = tmp_path / 'canary-home'
    _write_skill_dir(profile, 'cnryfolderzz', 'cnryfrontmatterzz', body='cnrybodyzz\n')
    (profile / 'skills' / 'cnryfolderzz' / 'references').mkdir()
    (profile / 'skills' / 'cnryfolderzz' / 'references' / 'cnryreffilezz.md').write_text('cnryrefzz', encoding='utf-8')
    # A ledger skill name shaped like an absolute path to an existing file outside the skills tree.
    abs_canary = tmp_path / 'cnryabsfilezz.txt'
    abs_canary.write_text('cnryabscontentzz', encoding='utf-8')
    hs = [_write_blob(profile, (b'cnryblobzz%d' % i) * (300 + 400 * i))[0] for i in range(24)]
    rows = [{'id': 'cnryentryidzz', 'ts': '2026-09-01T00:00:00+00:00', 'actor': 'cnryactorzz',
             'action': 'cnryactionzz', 'skill': 'cnryskillzz', 'evidence': {'session_id': 'cnrysessionzz'},
             'before': [], 'after': [{'path': '/home/user/cnrypathzz/SKILL.md', 'sha256': hs[0]}]}]
    rows += [{'id': f'cnryid{i}zz', 'ts': f'2026-09-01T00:{i:02d}:00+00:00', 'actor': 'curator',
              'action': 'patch', 'skill': 'cnryskillzz', 'evidence': {'reason': 'cnryreasonzz'},
              'before': [{'path': '/home/user/cnrypathzz/SKILL.md', 'sha256': hs[i - 1]}],
              'after': [{'path': '/home/user/cnrypathzz/SKILL.md', 'sha256': hs[i]}]} for i in range(1, 24)]
    rows.append({'id': 'x', 'ts': '2026-09-01T01:00:00+00:00', 'actor': 'agent', 'action': 'write_file',
                 'skill': 'cnryskillzz', 'before': [], 'after': []})
    rows.append({'id': 'y', 'ts': '2026-09-01T02:00:00+00:00', 'actor': 'agent', 'action': 'patch',
                 'skill': str(abs_canary), 'before': [], 'after': []})
    _write_ledger(profile, rows)
    _write_blob(profile, b'cnryorphanzz' * (2 * 1024 * 1024))
    _write_snapshot(profile, '2026-09-02T00-00-00Z')
    (profile / 'skills' / USAGE_NAME).write_text(json.dumps({
        'cnryusagezz': {'state': 'active', 'note': 'cnryusagevaluezz'},
        str(abs_canary): {'state': 'active'}}), encoding='utf-8')
    (profile / 'skills' / MANIFEST_NAME).write_text('cnrymanifestzz:' + 'a' * 32 + '\n', encoding='utf-8')
    (profile / 'config.yaml').write_text('curator:\n  enabled: true\n  note: cnryconfigzz\n', encoding='utf-8')

    res = mod.audit_skill_ledger(profile_path=profile)
    found = {f['id'] for f in res['findings']}
    assert {'skill_ledger.changes_by_recorded_actor', 'skill_ledger.patch_storm', 'skill_ledger.skill_growth',
            'skill_ledger.version_churn', 'skill_ledger.noop_changes', 'skill_ledger.orphan_backups',
            'skill_ledger.bookkeeping_orphans'} <= found
    assert res['skill_ledger']['skills_without_folder_count'] == 2
    assert res['skill_ledger']['bookkeeping_orphans']['usage_orphan_count'] == 2
    section, findings = _seal(res, w)
    _no_hmac(section)
    _no_hmac(findings)
    for kind, path, item in _walk(section):
        if isinstance(item, str) and path in free:
            _assert_kept_skill_path(str(tmp_path), item)
    for blob in (json.dumps(res), json.dumps([section, findings])):
        assert 'cnry' not in blob
        assert str(abs_canary) not in blob
        assert str(tmp_path) not in blob
        for h in hs:
            assert h not in blob


def test_doc_page_matches_rules_keys_and_values():
    from tests.test_audit_dead_stores import _doc_contains, _doc_rule_rows, _doc_words, _doc_bullets
    mod = load_submodule('audit.skill_ledger')
    w = _wiring()
    doc = (Path(__file__).resolve().parents[1] / 'docs/audit-sections/skill_ledger.md').read_text(encoding='utf-8')
    rows = _doc_rule_rows(doc, mod.RULE_CLASSIFICATIONS)
    assert {rid: _doc_words(row['class']) for rid, row in rows.items()} == mod.RULE_CLASSIFICATIONS
    sentences = _doc_bullets(doc)
    assert set(sentences) == set(mod.CONSEQUENCES)
    for rid, sentence in mod.CONSEQUENCES.items():
        assert _doc_words(sentences[rid]) == _doc_words(sentence), rid
    for key in w['schema_keys'] + w['run_metrics_keys']:
        _doc_contains(doc, key)
    for value in w['vocabulary']:
        if value != '.':
            _doc_contains(doc, value)
    for caveat in ('Symlinks are refused', 'symlink_refused', 'counted as a cut'):
        _doc_contains(doc, caveat)
    # Retired fields are a wire-schema contract, not a ban on historical prose.
    for gone in ('orphan_skills', 'usage_orphan_skills', 'skills[].skill', 'per-run tokens'):
        assert gone not in w['schema_keys'], gone
