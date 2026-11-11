"""Synthetic-only skill hygiene regression fixtures."""
import hashlib
import json
from pathlib import Path

from tests.conftest import load_submodule


def skill(home, name, text):
    path = home / 'skills' / name / 'SKILL.md'
    path.parent.mkdir(parents=True)
    path.write_text(text)
    return path


def shipped_hash(root):
    digest = hashlib.md5()
    for path in sorted(root.rglob('*')):
        if path.is_file():
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def hub_hash(package):
    # Replica: tools/skills_guard.py:767-788 (string order, NUL, SHA256 prefix).
    digest = hashlib.sha256()
    for rel, path in sorted((p.relative_to(package).as_posix(), p)
                            for p in package.rglob('*') if p.is_file()):
        digest.update(rel.encode() + b'\0')
        digest.update(path.read_bytes())
    return 'sha256:' + digest.hexdigest()[:16]


def test_official_hub_provenance_and_failed_lock(tmp_path):
    mod = load_submodule('audit.skill_hygiene')
    md = skill(tmp_path, 'creative/official', 'Last time we saw PR 42 commit abcdef1\n' * 12 + 'x' * 9000)
    (tmp_path / 'skills/.bundled_manifest').write_text('')
    (md.parent / 'references').mkdir()
    (md.parent / 'references/z.md').write_text('support')
    (md.parent / 'references.md').write_text('different path order')
    lock = tmp_path / 'skills/.hub/lock.json'
    lock.parent.mkdir()
    entry = {'source': 'official', 'install_path': 'creative/official', 'content_hash': hub_hash(md.parent)}
    lock.write_text(json.dumps({'version': 1, 'installed': {'official': entry}}))
    result = mod.audit_skill_hygiene(profile_path=tmp_path)
    sec = result['skill_hygiene']
    assert sec['coverage'] == 'verified' and sec['hub_coverage'] == 'verified'
    assert sec['hub_verified'] == 1
    assert sec['skills'][0]['provenance'] == 'hub'
    assert sec['residue_skills'] == 0 and sec['top_skills'] == []
    assert not any(f['id'].endswith(('scratchpad_residue', 'oversized_skill_body')) for f in result['findings'])
    md.write_text(md.read_text() + 'edited')
    changed = mod.audit_skill_hygiene(profile_path=tmp_path)
    assert changed['skill_hygiene']['hub_modified'] == 1
    assert next(f for f in changed['findings'] if f['id'].endswith('stock_skill_modified'))['evidence']['provenance'] == 'hub'
    for raw in ('{broken', '[]', '{"installed": []}'):
        lock.write_text(raw)
        broken_res = mod.audit_skill_hygiene(profile_path=tmp_path)
        sec = broken_res['skill_hygiene']
        assert sec['hub_coverage'] == 'could_not_verify'
        assert sec['coverage'] == 'could_not_verify' and broken_res['coverage'] == 'could_not_verify'
        assert any(f['id'] == 'skill_hygiene.could_not_verify' for f in broken_res['findings'])
        assert sec['skills'][0]['provenance'] == 'user_authored'
        assert sec['hub_modified'] == 0 and sec['residue_skills'] == 1
    lock.unlink()
    no_lock = mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']
    assert no_lock['hub_coverage'] == 'not_applicable'
    assert no_lock['coverage'] == 'verified'
    lock.parent.rmdir()
    no_hub_dir = mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']
    assert no_hub_dir['hub_coverage'] == 'not_applicable' and no_hub_dir['coverage'] == 'verified'
    lock.parent.mkdir()
    # Unsafe lock install paths must never authorize traversal or exempt local content.
    entry['install_path'] = '../creative/official'
    lock.write_text(json.dumps({'installed': {'official': entry}}))
    unsafe_sec = mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']
    assert unsafe_sec['hub_verified'] == 0
    assert unsafe_sec['hub_coverage'] == 'could_not_verify' and unsafe_sec['coverage'] == 'could_not_verify'


def test_stock_hash_residue_and_privacy(tmp_path):
    mod = load_submodule('audit.skill_hygiene')
    path = skill(tmp_path, 'example', '---\nname: example\n---\nUse portable rules.\n')
    (path.parent / 'support.txt').write_text('support')
    (tmp_path / 'skills/.bundled_manifest').write_text('example:' + shipped_hash(path.parent) + '\n')
    first = mod.audit_skill_hygiene(profile_path=tmp_path)
    assert first['skill_hygiene']['bundled_tracked'] == 1
    assert first['skill_hygiene']['bundled_modified'] == 0
    path.write_text(path.read_text() + '\n## Lessons\n- Last time 2025-01-02 PR 45 commit abcdef1\n- This session we found /home/user/private/\n- I tried JIRA-12 and it turned out wrong.\n')
    result = mod.audit_skill_hygiene(profile_path=tmp_path)
    section = result['skill_hygiene']
    assert section['bundled_modified'] == 1
    assert section['growth_measurable'] is False
    row = section['top_skills'][0]
    assert row['file_count'] == 2
    assert row['residue_score'] >= mod.RESIDUE_THRESHOLD
    assert row['machine_paths'] == 0
    assert row['longest_bullet_run'] == 3
    assert row['dates'] == 1 and row['commit_refs'] == 1
    ids = {f['id'] for f in result['findings']}
    assert {'skill_hygiene.stock_skill_modified', 'skill_hygiene.scratchpad_residue'} <= ids
    assert 'alice' not in json.dumps(result)
    assert 'Last time' not in json.dumps(result)
    assert result == mod.audit_skill_hygiene(profile_path=tmp_path)


def test_unmodified_stock_exemption_and_upstream_false_positive_rate(tmp_path):
    import pytest
    mod = load_submodule('audit.skill_hygiene')
    stock_body = (
        '---\nname: noisy-stock\n---\n'
        '## Lessons\n'
        '- Last time 2025-01-02 PR 45 commit abcdef1\n'
        '- This session we found /home/user/private/\n'
        '- I tried JIRA-12 and it turned out wrong.\n'
        '- see session 20260101_000000_abcdef\n'
        + ('x' * mod.OVERSIZED_BODY_CHARS) + '\n'
    )
    path = skill(tmp_path, 'noisy-stock', stock_body)
    (tmp_path / 'skills/.bundled_manifest').write_text('noisy-stock:' + shipped_hash(path.parent) + '\n')
    unmod = mod.audit_skill_hygiene(profile_path=tmp_path)
    sec = unmod['skill_hygiene']
    assert sec['bundled_modified'] == 0
    assert sec['residue_skills'] == 0
    assert sec['top_skills'] == []
    assert sec['skills'][0]['residue_score'] >= mod.RESIDUE_THRESHOLD
    assert sec['skills'][0]['body_char_count'] >= mod.OVERSIZED_BODY_CHARS
    assert unmod['findings'] == []

    # Tightened pattern checks on synthetic technical tokens vs real residue
    tech = (
        'Use UTF-8, UTF-16, UTF-32, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, '
        'ISO-8601, ISO-639, ISO-3166, ISO-9660, RFC-2119, MD5, CVE-2024-1234, '
        'HTTP-2, X-509, BASE-64, TOP-10, AES-128, AES-256, RSA-2048, P-256, GPT-4, '
        'colors #fff, #123456, #1a2b3c, #1, and session management or session_search.\n'
    )
    tech_counts = mod.counts(tech)
    assert tech_counts['ticket_refs'] == 0
    assert tech_counts['session_refs'] == 0

    pos = (
        '## Lessons\n'
        '- Last time 2025-01-02 PR 45 commit abcdef1\n'
        '- This session we found /home/user/private/\n'
        '- I tried JIRA-12 and it turned out wrong\n'
        '- see session 20260101_000000_abcdef\n'
    )
    pos_counts = mod.counts(pos)
    pos_score = mod.residue_score(pos_counts)
    assert pos_counts['ticket_refs'] >= 2
    assert pos_counts['session_refs'] >= 1
    assert pos_score >= mod.RESIDUE_THRESHOLD

    import hermes_constants
    src_root = Path(hermes_constants.__file__).resolve().parent
    bundled_dir = src_root / 'skills'
    optional_dir = src_root / 'optional-skills'
    if not bundled_dir.is_dir() or not optional_dir.is_dir():
        pytest.skip('Hermes upstream skills source tree is absent')
    facts = load_submodule('audit.facts')
    mds = []
    for r in (bundled_dir, optional_dir):
        for md in sorted(r.rglob('SKILL.md')):
            rel = md.relative_to(r)
            if any(p in facts.EXCLUDED_SKILL_DIRS for p in rel.parts):
                continue
            if any(
                part in facts.SKILL_SUPPORT_DIRS and (r / Path(*rel.parts[:idx]) / 'SKILL.md').exists()
                for idx, part in enumerate(rel.parts[:-1]) if idx > 0
            ):
                continue
            mds.append((r, md))
    assert len(mds) > 0
    offenders = []
    for r, md in mds:
        pkg = md.parent
        total = {k: 0 for k in (*mod.PATTERNS, 'lesson_headings', 'total_lines', 'characters', 'longest_bullet_run')}
        for p in sorted(pkg.rglob('*')):
            if p.is_file():
                try:
                    t = p.read_bytes().decode('utf-8')
                    if '\x00' not in t:
                        c = mod.counts(t)
                        for k in (*mod.PATTERNS, 'lesson_headings', 'total_lines', 'characters'):
                            total[k] += c[k]
                        total['longest_bullet_run'] = max(total['longest_bullet_run'], c['longest_bullet_run'])
                except UnicodeError:
                    pass
        score = mod.residue_score(total)
        if score >= mod.RESIDUE_THRESHOLD or total['lesson_headings'] >= mod.DATED_LESSON_LINES:
            offenders.append((score, str(md.relative_to(src_root))))
    print('upstream residue:', len(offenders), '/', len(mds), 'percent:', 100 * len(offenders) / len(mds), 'offenders:', offenders)
    assert len(offenders) / len(mds) < 0.03, f'{len(offenders)}/{len(mds)} >= 3%: {offenders}'


def test_cache_legacy_duplicate_missing_and_caps(tmp_path, monkeypatch):
    mod = load_submodule('audit.skill_hygiene')
    path = skill(tmp_path, 'Same_Name', '---\nname: Same_Name\n---\nRule body.\n')
    skill(tmp_path, 'same-name', '---\nname: same-name\n---\nRule   body.\n')
    origin = shipped_hash(path.parent)
    cache = path.parent / '__pycache__'
    cache.mkdir()
    (cache / 'x.pyc').write_bytes(b'cache')
    manifest = tmp_path / 'skills/.bundled_manifest'
    manifest.write_text('Same_Name:' + origin + '\n')
    result = mod.audit_skill_hygiene(profile_path=tmp_path)
    assert result['skill_hygiene']['bundled_modified'] == 0
    assert any(f['id'] == 'skill_hygiene.duplicate_skill' for f in result['findings'])
    manifest.write_text('Same_Name:' + shipped_hash(path.parent) + '\n')
    assert mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']['bundled_modified'] == 0
    manifest.unlink()
    assert mod.audit_skill_hygiene(profile_path=tmp_path)['coverage'] == 'could_not_verify'
    manifest.write_text('Same_Name:' + origin + '\n')
    monkeypatch.setattr(mod, 'MAX_FILE_BYTES', 8)
    result = mod.audit_skill_hygiene(profile_path=tmp_path)
    assert result['coverage'] == 'could_not_verify'
    assert result['skill_hygiene']['limits']['cuts'] > 0
    assert result['skill_hygiene']['bundled_modified'] == 0


def test_excluded_skill_dirs_support_dirs_and_install_path_matching(tmp_path):
    mod = load_submodule('audit.skill_hygiene')
    active = skill(tmp_path, 'devops/sdlc-review', '---\nname: sdlc-review\n---\nShipped rule.\n')
    skill(tmp_path, 'devops/sdlc-review/templates/sub', '---\nname: sdlc-review\n---\nTemplate SKILL.md.\n')
    origin = shipped_hash(active.parent)
    (tmp_path / 'skills/.bundled_manifest').write_text(f'sdlc-review:{origin}\n')
    # Archived, quarantined, and node_modules must be excluded
    skill(tmp_path, '.archive/sdlc-review', '---\nname: sdlc-review\n---\nModified archived copy.\n')
    skill(tmp_path, '.hub/quarantine/sdlc-review', '---\nname: sdlc-review\n---\nModified quarantined copy.\n')
    skill(tmp_path, 'node_modules/pkg-skill', '---\nname: pkg-skill\n---\nShipped rule.\n')
    # Another skill in a non-matching folder claiming the stock name in frontmatter is NOT that stock install path
    impostor = skill(tmp_path, 'custom/impostor', '---\nname: sdlc-review\n---\nDifferent user skill.\n')

    res = mod.audit_skill_hygiene(profile_path=tmp_path)
    sec = res['skill_hygiene']
    examined_paths = {r['skill_md_path'] for r in sec['skills']}
    assert examined_paths == {str(active), str(impostor)}
    assert sec['bundled_modified'] == 0
    by_path = {r['skill_md_path']: r for r in sec['skills']}
    assert by_path[str(active)]['bundled'] is True
    assert by_path[str(active)]['modified'] is False
    assert by_path[str(impostor)]['bundled'] is False
    assert by_path[str(impostor)]['modified'] is False
    # Duplicate group only counts the two loadable skills (active and impostor), never archived/quarantined/support
    assert sec['duplicate_groups'] == [sorted([str(active), str(impostor)])]


def test_package_hash_includes_dependency_and_vcs_files(tmp_path):
    mod = load_submodule('audit.skill_hygiene')
    md = skill(tmp_path, 'stock', 'Official rule.\n')
    for name in ('node_modules/lib/code.js', '.git/description'):
        path = md.parent / name
        path.parent.mkdir(parents=True)
        path.write_text('shipped bytes')
    (tmp_path / 'skills/.bundled_manifest').write_text('stock:' + shipped_hash(md.parent))
    sec = mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']
    assert sec['skills'][0]['verified_unmodified'] is True
    assert sec['skills'][0]['file_count'] == 3
    (md.parent / 'node_modules/lib/code.js').write_text('changed bytes')
    assert mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']['bundled_modified'] == 1


def test_hash_file_ordering_matches_hermes_path_parts(tmp_path):
    import shutil
    mod = load_submodule('audit.skill_hygiene')
    pkg_md = skill(tmp_path, 'creative/baoyu-style', '---\nname: baoyu-style\n---\nBody.\n')
    pkg = pkg_md.parent
    (pkg / 'references').mkdir()
    (pkg / 'references' / 'styles.md').write_text('styles index\n')
    (pkg / 'references' / 'styles').mkdir()
    (pkg / 'references' / 'styles' / 'warm.md').write_text('warm palette\n')

    # Independent replica of Hermes tools/skills_sync.py:187-200 & tools/skills_sync_optional.py:46-58
    cache_dirs = {'__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache'}
    def hermes_dir_hash(directory: Path) -> str:
        hasher = hashlib.md5()
        for fpath in sorted(directory.rglob('*')):
            rel = fpath.relative_to(directory)
            is_cache = (
                any(part in cache_dirs for part in rel.parts[:-1])
                or (fpath.name in cache_dirs and fpath.is_dir())
                or (fpath.suffix in {'.pyc', '.pyo'} and fpath.with_suffix('.py').is_file())
            )
            if not is_cache and fpath.is_file():
                hasher.update(str(rel).encode('utf-8'))
                hasher.update(fpath.read_bytes())
        return hasher.hexdigest()

    origin = hermes_dir_hash(pkg)
    (tmp_path / 'skills/.bundled_manifest').write_text(f'baoyu-style:{origin}\n')
    res = mod.audit_skill_hygiene(profile_path=tmp_path)
    assert res['skill_hygiene']['bundled_modified'] == 0

    import hermes_constants
    src_skill = Path(hermes_constants.__file__).resolve().parent / 'optional-skills/creative/baoyu-article-illustrator'
    if src_skill.is_dir():
        dest = tmp_path / 'skills/creative/baoyu-article-illustrator'
        shutil.copytree(src_skill, dest)
        upstream_hash = hermes_dir_hash(src_skill)
        (tmp_path / 'skills/.bundled_manifest').write_text(
            f'baoyu-style:{origin}\nbaoyu-article-illustrator:{upstream_hash}\n'
        )
        res2 = mod.audit_skill_hygiene(profile_path=tmp_path)
        assert res2['skill_hygiene']['bundled_tracked'] == 2
        assert res2['skill_hygiene']['bundled_modified'] == 0


def test_same_name_collision_resolves_by_hash_then_exact_path(tmp_path):
    mod = load_submodule('audit.skill_hygiene')
    # (a) Single categorized folder claiming a manifest name that does not verify -> modified stock
    cat_home = tmp_path / 'single_cat'
    cat_stock = skill(cat_home, 'autonomous-ai-agents/claude-code', '---\nname: claude-code\n---\nEdited stock.\n')
    (cat_home / 'skills/.bundled_manifest').write_text('claude-code:' + '0' * 32 + '\n')
    cat_res = mod.audit_skill_hygiene(profile_path=cat_home)
    cat_sec = cat_res['skill_hygiene']
    assert cat_sec['coverage'] == 'verified'
    assert cat_sec['bundled_modified'] == 1
    assert cat_sec['bundled_unlocated'] == 0
    assert cat_sec['skills'][0]['provenance'] == 'stock'
    assert cat_sec['skills'][0]['bundled'] is True
    assert cat_sec['skills'][0]['modified'] is True
    assert any(f['id'] == 'skill_hygiene.stock_skill_modified' for f in cat_res['findings'])

    # (b) & (e) Several claim it and one verifies -> verifying one is stock/verified, other is user_authored duplicate
    stock = skill(tmp_path, 'dev/github', '---\nname: github\n---\nOfficial.\n')
    user = skill(tmp_path, 'mine/github', '---\nname: github\n---\nMy own procedure.\n')
    manifest = tmp_path / 'skills/.bundled_manifest'
    manifest.write_text('github:' + shipped_hash(stock.parent) + '\n')
    sec = mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']
    by_path = {r['skill_md_path']: r for r in sec['skills']}
    assert by_path[str(user)]['bundled'] is False
    assert by_path[str(user)]['provenance'] == 'user_authored'
    assert by_path[str(stock)]['verified_unmodified'] is True
    assert by_path[str(stock)]['provenance'] == 'stock'
    assert sec['bundled_modified'] == 0
    assert sec['duplicate_groups'] == [sorted([str(stock), str(user)])]

    # (d) Several claim it, none verifies, none at the manifest's install path -> could_not_verify, none modified
    stock.write_text('---\nname: github\n---\nEdited official.\n')
    sec = mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']
    assert sec['bundled_modified'] == 0 and sec['bundled_unlocated'] == 1 and sec['coverage'] == 'could_not_verify'

    # (c) Several claim it, none verifies, exactly one at the manifest's install path -> that one modified, others user_authored
    manifest.write_text('dev/github:' + '0' * 32 + '\n')
    sec = mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']
    assert sec['bundled_modified'] == 1
    assert sec['modified_skills'][0]['skill_md_path'] == str(stock)
    by_path = {r['skill_md_path']: r for r in sec['skills']}
    assert by_path[str(stock)]['provenance'] == 'stock' and by_path[str(stock)]['modified'] is True
    assert by_path[str(user)]['provenance'] == 'user_authored' and by_path[str(user)]['modified'] is False
    # Also test root install path 'github' when another folder 'mine/github' also claims 'github'
    root_stock = skill(tmp_path, 'github', '---\nname: github\n---\nEdited root official.\n')
    manifest.write_text('github:' + '0' * 32 + '\n')
    sec = mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']
    assert sec['bundled_modified'] == 1
    assert sec['modified_skills'][0]['skill_md_path'] == str(root_stock)
    root_stock.unlink()
    (tmp_path / 'skills/github').rmdir()

    manifest.write_text('dev/github:' + '0' * 32 + '\n')
    stock.unlink()
    sec = mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']
    assert sec['bundled_modified'] == 0 and sec['coverage'] == 'could_not_verify'


def test_incomplete_provenance_never_claims_drift(tmp_path):
    mod = load_submodule('audit.skill_hygiene')
    path = skill(tmp_path, 'example', 'Rule.\n')
    manifest = tmp_path / 'skills/.bundled_manifest'
    manifest.write_text('example:not-a-valid-hash\n')
    assert mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']['bundled_modified'] == 0
    manifest.write_text('example:' + '0' * 32 + '\n')
    (path.parent / 'link').symlink_to(tmp_path / 'outside')
    assert mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']['bundled_modified'] == 0


def test_per_skill_entry_cap_and_symlink_ancestor_above_profile(tmp_path, monkeypatch):
    mod = load_submodule('audit.skill_hygiene')
    # Symlink ABOVE the profile root (e.g. symlinked home) is normal and must NOT cut skills
    real_base = tmp_path / 'real_storage'
    real_base.mkdir()
    sym_home = tmp_path / 'symlinked_home'
    sym_home.symlink_to(real_base)
    profile = sym_home / '.hermes'
    good_md = skill(profile, 'good-skill', '---\nname: good-skill\n---\nClean skill.\n')
    origin = shipped_hash(good_md.parent)
    (profile / 'skills/.bundled_manifest').write_text(f'good-skill:{origin}\n')

    clean_res = mod.audit_skill_hygiene(profile_path=profile)
    assert clean_res['coverage'] == 'verified'
    assert clean_res['skill_hygiene']['skills_examined'] == 1
    assert clean_res['skill_hygiene']['bundled_modified'] == 0
    assert clean_res['skill_hygiene']['limits']['cuts'] == 0

    # A single bloated skill exceeding per-skill entry cap becomes could_not_verify/cut,
    # while good-skill is still examined and verified!
    bad_md = skill(profile, 'bloated-skill', '---\nname: bloated-skill\n---\nBloated.\n')
    for i in range(20):
        (bad_md.parent / f'extra_{i}.txt').write_text(f'file {i}\n')
    monkeypatch.setattr(mod, 'MAX_FILES_PER_SKILL', 5)
    monkeypatch.setattr(mod, 'MAX_TREE_ENTRIES', 10)
    capped_res = mod.audit_skill_hygiene(profile_path=profile)
    sec = capped_res['skill_hygiene']
    assert capped_res['coverage'] == 'could_not_verify'
    assert sec['limits']['cuts'] > 0
    by_name = {Path(r['path']).name: r for r in sec['skills']}
    assert 'good-skill' in by_name
    assert by_name['good-skill']['coverage'] == 'verified'
    assert by_name['good-skill']['modified'] is False
    if 'bloated-skill' in by_name:
        assert by_name['bloated-skill']['coverage'] == 'could_not_verify'

    # A symlinked skill directory INSIDE the profile skills tree is still refused
    ext_skill = tmp_path / 'ext_skill'
    ext_skill.mkdir()
    (ext_skill / 'SKILL.md').write_text('---\nname: ext\n---\nExternal.\n')
    (profile / 'skills/linked-skill').symlink_to(ext_skill)
    sym_res = mod.audit_skill_hygiene(profile_path=profile)
    assert 'linked-skill' not in {Path(r['path']).name for r in sym_res['skill_hygiene']['skills']}


def test_large_non_support_tree_does_not_starve_other_packages(tmp_path, monkeypatch):
    mod = load_submodule('audit.skill_hygiene')
    monkeypatch.setattr(mod, 'MAX_TREE_ENTRIES', 12)
    for huge_name in ('aaa-huge', 'zzz-huge'):
        home = tmp_path / huge_name
        huge = skill(home, huge_name, 'Large package.\n')
        src = huge.parent / 'src'
        src.mkdir()
        for i in range(30):
            (src / f'{i}.txt').write_text('generated')
        good = skill(home, 'middle-good', 'Clean package.\n')
        (home / 'skills/.bundled_manifest').write_text('middle-good:' + shipped_hash(good.parent))
        sec = mod.audit_skill_hygiene(profile_path=home)['skill_hygiene']
        rows = {Path(r['path']).name: r for r in sec['skills']}
        assert set(rows) == {huge_name, 'middle-good'}
        assert rows['middle-good']['verified_unmodified'] is True
        assert rows[huge_name]['coverage'] == 'could_not_verify'

    # Item 5: a large NON-skill folder (no SKILL.md) sorted first or last must not starve other top-level folders
    for non_skill_name in ('aaa-non-skill', 'zzz-non-skill'):
        home = tmp_path / f'non_skill_{non_skill_name}'
        junk = home / 'skills' / non_skill_name
        junk.mkdir(parents=True)
        for i in range(30):
            (junk / f'{i}.txt').write_text('not a skill')
        good = skill(home, 'cat/middle-good', 'Clean categorized package.\n')
        (home / 'skills/.bundled_manifest').write_text('middle-good:' + shipped_hash(good.parent))
        sec = mod.audit_skill_hygiene(profile_path=home)['skill_hygiene']
        assert sec['skills_examined'] == 1, non_skill_name
        assert Path(sec['skills'][0]['path']).name == 'middle-good'
        assert sec['skills'][0]['verified_unmodified'] is True
        assert sec['coverage'] == 'could_not_verify' and sec['limits']['cuts'] > 0


def test_non_utf8_filename_surrogateescape_and_relative_file_paths(tmp_path):
    import os
    mod = load_submodule('audit.skill_hygiene')
    md = skill(tmp_path, 'utf8-skill', '---\nname: utf8-skill\n---\nClean body.\n')
    (md.parent / 'references').mkdir()
    (md.parent / 'references/note.md').write_text('Reference note.\n')
    origin = shipped_hash(md.parent)
    (tmp_path / 'skills/.bundled_manifest').write_text(f'utf8-skill:{origin}\n')

    res = mod.audit_skill_hygiene(profile_path=tmp_path)
    row = res['skill_hygiene']['skills'][0]
    rel_paths = [m['path'] for m in row['files']]
    assert rel_paths == ['SKILL.md', 'references/note.md']
    assert all(not Path(p).is_absolute() for p in rel_paths)

    # Create a non-UTF-8 filename inside the skill package
    bad_file = os.fsencode(md.parent) + b'/bad_\xff_name.txt'
    with open(bad_file, 'wb') as f:
        f.write(b'non-utf8 filename content\n')
    res_bad = mod.audit_skill_hygiene(profile_path=tmp_path)
    sec_bad = res_bad['skill_hygiene']
    assert res_bad['coverage'] == 'could_not_verify'
    assert sec_bad['limits']['cuts'] > 0
    assert sec_bad['skills'][0]['coverage'] == 'could_not_verify'
    assert sec_bad['bundled_modified'] == 0


# Synthetic recall/precision table: no backup text is stored here.
RESIDUE_LINES = [
    'Checked 11/09/2026 after the migration.',
    'Verified 2026-11-09 on the deployment.',
    'As of November 9, 2026 this broke.',
    '2026-11-09: deployment failure.',
    'Merged PR #412 yesterday.',
    'Fixed issue 271 after the retry.',
    'https://github.com/example/repo/issues/173 reproduced this.',
    'https://github.com/example/repo/pull/84 landed.',
    'OPS-741 tracks this incident.',
    'commit abcdef123 fixed the regression.',
    'Reverted ' + 'abcdef1234' * 4 + '.',
    'Diff abcdef123..123456abc shows the regression.',
    'revision: 9abcdef0123 was faulty.',
    'Machine copy: ' + '/Users/' + 'jdoe/work/private/',
    'Working directory: ' + '/Users/' + 'devbox/build/',
    'Local checkout: ' + 'C:\\Users\\' + 'jdoe\\repo',
    'Session 20260101_000000_abcdef was interrupted.',
    'session-id: abcdef12-1234-1234-1234-123456abcdef crashed.',
    'subagent abcdef123456 reported a failure.',
    'Last time we ran this it failed.',
    'Yesterday the deploy broke.',
    'Earlier today I retried it.',
    'We found the service was stopped.',
    'I tried another port.',
    'It turned out the cache was stale.',
    'Deploy to 10.2.3.4 now.',
    'The host is 172.19.8.42.',
    'Connect to 192.168.4.32 or 100.74.8.2.',
    'The machine is build-1.tailnet.ts.net.',
    'Use renderbox.local and labbox.lan.',
]
LEGITIMATE_LINES = [
    '## Notes', '## Lessons', '## Pitfalls',
    'Use UTF-8 and ISO-8601 formatting.',
    'RFC-2119 defines MUST; CVE-2024-1234 is an advisory.',
    'Use AES-256 and SHA-256.',
    'Use GPT-4 for this example.',
    'Set color #abcdef and background #123456.',
    'The expected sha256 is ' + 'a' * 64 + '.',
    'Run git commit with an informative message.',
    'Discuss session management and delegation policies.',
    'Set revision to a branch name.',
    'Use /home/user/project and /home/x/project.',
    'Use /home/<you>/project and /home/<username>/project.',
    'Use /home/<USER>/project and /home/<name>/project.',
    'Use ' + '/Users/' + '<you>/project and /Users/<username>/project.',
    'Use ' + '/Users/' + '<name>/project and /Users/' + 'Shared/project.',
    'Use ' + 'C:\\Users\\' + 'Public\\project or C:\\Users\\<username>\\project.',
    'Use ~, $HOME or %USERPROFILE% for a portable home.',
    'Bind to 127.0.0.1 or 0.0.0.0.',
    'Documentation addresses are 192.0.2.1, 198.51.100.1 and 203.0.113.1.',
    'Version v10.2.3.4 is newer than v192.168.1.2.',
    'Version 10.2.3.4.5 is a five-part version.',
    'Invalid address 10.999.3.4 is not an IPv4 address.',
    'Example CIDR: 10.0.0.0/8 is a private range.',
    'A date example is "2026-11-09".',
    'Parse the format MM/DD/YYYY.',
    'Use https://example.com/2026-11-09/docs.',
    'Create a pull request for review.',
    'Preserve reusable rules, not incident notes.',
]


def test_residue_line_precision_recall_and_diverse_score(tmp_path):
    mod = load_submodule('audit.skill_hygiene')
    hits = lambda text: any(mod.counts(text)[key] for key in mod.PATTERNS)
    misses = [line for line in RESIDUE_LINES if not hits(line)]
    false_hits = [line for line in LEGITIMATE_LINES if hits(line)]
    tp = len(RESIDUE_LINES) - len(misses)
    recall, precision = tp / len(RESIDUE_LINES), tp / (tp + len(false_hits))
    print('line recall/precision:', recall, precision, 'misses:', misses, 'false positives:', false_hits)
    assert len(RESIDUE_LINES) == len(LEGITIMATE_LINES) == 30
    assert recall >= .85 and precision >= .9
    md = skill(tmp_path, 'four-lines', '\n'.join([RESIDUE_LINES[i] for i in (0, 5, 19, 20)]))
    sec = mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']
    assert sec['residue_skills'] == 1
    md.write_text('\n'.join(LEGITIMATE_LINES[:25]))
    assert mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']['residue_skills'] == 0
    assert mod.residue_score(mod.counts('Yesterday this broke.\n' * 100)) < mod.RESIDUE_THRESHOLD
    # Item 7: dated_lesson_lines trigger (at least 3 date-leading lines outside frontmatter, changelog, and tables)
    three_dated = (
        '## Lessons\n'
        '- **2026-11-01**: First incident note.\n'
        '- 2026-11-02: Second incident note.\n'
        '* Nov 9: Third incident note.\n'
    )
    assert mod.dated_lesson_lines(three_dated) == 3
    assert mod.counts(three_dated)['lesson_headings'] == 3
    assert mod.residue_score(mod.counts(three_dated)) < mod.RESIDUE_THRESHOLD
    md.write_text(three_dated)
    res_three = mod.audit_skill_hygiene(profile_path=tmp_path)
    assert res_three['skill_hygiene']['residue_skills'] == 1
    assert res_three['skill_hygiene']['skills'][0]['lesson_headings'] == 3
    assert any(f['id'] == 'skill_hygiene.scratchpad_residue' and f['evidence']['lesson_headings'] == 3 for f in res_three['findings'])

    two_dated = '## Lessons\n- 2026-11-01: First.\n- 2026-11-02: Second.\n'
    md.write_text(two_dated)
    assert mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']['residue_skills'] == 0
    assert mod.counts(two_dated)['lesson_headings'] == 2

    changelog_ten = '## Changelog\n' + ''.join(f'- 2026-11-{i:02d}: Change {i}.\n' for i in range(1, 11))
    md.write_text(changelog_ten)
    assert mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']['residue_skills'] == 0
    assert mod.counts(changelog_ten)['lesson_headings'] == 0

    table_dates = '## Schedule\n| Date | Note |\n|---|---|\n' + ''.join(f'| 2026-11-{i:02d} | Item {i} |\n' for i in range(1, 11))
    md.write_text(table_dates)
    assert mod.audit_skill_hygiene(profile_path=tmp_path)['skill_hygiene']['residue_skills'] == 0
    assert mod.counts(table_dates)['lesson_headings'] == 0


def test_network_boundaries_dates_and_procedural_headings():
    mod = load_submodule('audit.skill_hygiene')
    for text in ('10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.0.1', '100.64.0.1', '100.127.255.255', 'box.local', 'box.lan', 'box.tail.ts.net'):
        assert mod.counts(text)['network_identities'] == 1, text
    for text in ('172.15.0.1', '172.32.0.1', '100.63.0.1', '100.128.0.1', '10.256.0.1', 'v10.2.3.4', '10.2.3.4.5', 'box.localhost', 'example.ts.network'):
        assert mod.counts(text)['network_identities'] == 0, text
    assert mod.counts('---\nchecked: 2026-11-09\n---\nUse a portable rule.')['dates'] == 0
    for heading in ('Changelog', 'Release notes', 'Version history', 'Versions'):
        assert mod.counts(f'## {heading}\n2026-11-09 and 11/09/2026\n### Older\nNovember 8, 2026\n## Procedure\nChecked 11/10/2026')['dates'] == 1
    assert not any(mod.counts('## Notes\n## Lessons\n## Pitfalls')[k] for k in mod.PATTERNS)
    # Item 2: case-sensitive Unix branches, prefix placeholders, and extended PLACEHOLDER_USERS
    for route in ('/users/{id}', '/users/:id', '/users/<id>', '/users/me', '/users/123', '/HOME/jdoe'):
        assert mod.counts(f'GET {route}')['machine_paths'] == 0, route
    for prefix_seg in ('{id}', '<id>', ':id', '$USER', '%USERNAME%'):
        for base in ('/home/', '/Users/', 'C:\\Users\\'):
            assert mod.counts(f'Path {base}{prefix_seg}/app')['machine_paths'] == 0, (base, prefix_seg)
    expected_placeholders = {
        'user', 'x', 'you', 'me', 'username', 'name', 'USER', 'Shared', 'Public',
        'ubuntu', 'runner', 'root', 'alice', 'bob', 'admin', 'example',
        'yourname', 'your-username', 'myuser',
    }
    assert expected_placeholders <= set(mod.PLACEHOLDER_USERS)
    for ph in expected_placeholders:
        for base, sep in (('/home/', '/'), ('/Users/', '/'), ('C:\\Users\\', '\\')):
            assert mod.counts(f'cd {base}{ph}{sep}work')['machine_paths'] == 0, (base, ph)
    for base, sep in (('/home/', '/'), ('/Users/', '/'), ('C:\\Users\\', '\\'), ('c:\\users\\', '\\')):
        assert mod.counts(f'cd {base}' + f'jdoe{sep}work')['machine_paths'] == 1, base
    # Item 6(a) & 6(f): e.g. / for example / example:, networking tables, and /8 /12 /16 /24 CIDRs
    for ex_line in (
        'Use 10.0.0.1 (e.g. a local gateway).',
        'For example, connect to 192.168.1.20.',
        'Example: 172.16.0.5 is internal.',
        '| Subnet | 10.0.0.1 | Gateway |',
        'Allow 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 192.168.1.0/24.',
    ):
        assert mod.counts(ex_line)['network_identities'] == 0, ex_line
    # Item 6(b) & 6(e): ticket case-insensitivity, GitLab MRs, cross-repo refs, and standards denylist
    for t_ref in ('See #812', 'Fixes #12', 'Closes #7', 'group/project!482', 'repo#65828', 'owner/repo#123'):
        assert mod.counts(t_ref)['ticket_refs'] == 1, t_ref
    expected_deny = {
        'ecma', 'psr', 'kb', 'pep', 'jep', 'jsr', 'bcp', 'std', 'fips', 'nist',
        'owasp', 'wcag', 'posix', 'ansi', 'ieee', 'itu', 'mil', 'din', 'en', 'bs', 'as',
    }
    assert expected_deny <= {p.lower() for p in mod.TICKET_PREFIX_DENYLIST}
    for std_id in ('ECMA-262', 'PSR-12', 'KB-5034441', 'OWASP-10', 'WCAG-21', 'POSIX-1', 'ITU-709', 'MIL-810', 'DIN-4711', 'EN-301', 'BS-7799', 'AS-4000'):
        assert mod.counts(f'Follow {std_id} standard.')['ticket_refs'] == 0, std_id
    # Item 6(c): additional date formats and version/release/changelog/updated line exemptions
    for d_pos in ('Failed on Nov 9.', 'Broke on Oct 2.', 'Investigated 9 Nov 2026.', 'As of November 9, 2026.', 'Logged 2026/11/09.'):
        assert mod.counts(d_pos)['dates'] == 1, d_pos
    for d_neg in (
        'v1.2.0 (2026-11-09)',
        '1.4 - Nov 9',
        'Release 2026-11-09',
        'Released on November 9, 2026',
        'Version 2 (9 Nov 2026)',
        'Changelog entry for 2026/11/09',
        'Updated 2026-11-09',
        'Last verified: 2026-11-09',
        'Last updated: Nov 9',
    ):
        assert mod.counts(d_neg)['dates'] == 0, d_neg
    # Item 6(d): narration cues and first-person/session requirement on 'last time'
    for n_pos in ('Earlier we retried.', 'Previously we used v1.', 'This time it worked.', 'Last time we ran this it failed.', 'I checked last time.'):
        assert mod.counts(n_pos)['narration'] >= 1, n_pos
    assert mod.counts('Last time the job ran it succeeded.')['narration'] == 0


def test_size_threshold_above_upstream_p95_and_boundary(tmp_path):
    import math
    import pytest
    import hermes_constants
    mod = load_submodule('audit.skill_hygiene')
    root = Path(hermes_constants.__file__).resolve().parent
    if not all((root / part).is_dir() for part in ('skills', 'optional-skills')):
        pytest.skip('Hermes upstream bundled and optional source trees are absent')
    sizes = []
    for folder in ('skills', 'optional-skills'):
        base = root / folder
        for md in base.rglob('SKILL.md'):
            rel = md.relative_to(base)
            if set(rel.parts) & mod.EXCLUDED_SKILL_DIRS:
                continue
            if any(part in mod.SKILL_SUPPORT_DIRS and (base / Path(*rel.parts[:i]) / 'SKILL.md').exists()
                   for i, part in enumerate(rel.parts[:-1]) if i > 0):
                continue
            sizes.append(len(mod.parse_frontmatter_stdlib(md.read_text())[1]))
    sizes.sort()
    assert mod.OVERSIZED_BODY_CHARS > sizes[math.ceil(.95 * len(sizes)) - 1]
    assert sum(size >= mod.OVERSIZED_BODY_CHARS for size in sizes) / len(sizes) <= .05
    md = skill(tmp_path, 'large-user', 'x' * (mod.OVERSIZED_BODY_CHARS - 1))
    assert not any(f['id'].endswith('oversized_skill_body') for f in mod.audit_skill_hygiene(profile_path=tmp_path)['findings'])
    md.write_text('x' * mod.OVERSIZED_BODY_CHARS)
    assert any(f['id'].endswith('oversized_skill_body') for f in mod.audit_skill_hygiene(profile_path=tmp_path)['findings'])


def test_external_skill_dirs_stay_inside_profile_and_disclose_others(tmp_path, monkeypatch):
    mod = load_submodule('audit.skill_hygiene')
    home = tmp_path / 'profile'
    skill(home, 'local', 'Local procedure.')
    external = home / 'shared/skills/fleet/SKILL.md'
    external.parent.mkdir(parents=True)
    external.write_text('Use 10.42.1.7 for this machine.')
    outside = tmp_path / 'unselected/skills'
    outside.mkdir(parents=True)
    (outside / 'SKILL.md').write_text('Must never read me.')
    (home / 'linked').symlink_to(outside)
    (home / 'config.yaml').write_text('skills:\n  external_dirs:\n    - shared/skills\n    - linked\n    - ' + str(outside) + '\n    - ' + str(outside) + '\n')
    original = mod.os.scandir
    def guarded(path):
        assert not Path(path).is_relative_to(outside)
        assert Path(path) != home / 'linked'
        return original(path)
    with monkeypatch.context() as guard:
        guard.setattr(mod.os, 'scandir', guarded)
        result = mod.audit_skill_hygiene(profile_path=home)
    rows = result['skill_hygiene']['skills']
    assert len(rows) == 2
    assert next(r for r in rows if r['skill_md_path'] == str(external))['provenance'] == 'external_dir'
    disclosure = next(f for f in result['findings'] if f['id'] == 'skill_hygiene.external_skill_dir_not_scanned')
    assert disclosure['evidence']['count'] == 2
    assert disclosure['coverage'] == 'could_not_verify'
    assert str(outside) not in json.dumps(result)


def test_reused_yaml_merge_chain_and_anchored_duplicate_keys(tmp_path):
    mod = load_submodule('audit.skill_hygiene')
    facts = load_submodule('audit.facts')
    ws = load_submodule('audit.write_settings')
    reused_chain = (
        'base: &base\n'
        '  write_approval: false\n'
        '  external_dirs: []\n'
        'mid: &mid\n'
        '  <<: *base\n'
        '  write_approval: true\n'
        'skills:\n'
        '  <<: *mid\n'
        'other:\n'
        '  <<: *mid\n'
    )
    parsed = facts._parse_simple_yaml_mapping(reused_chain, reject_duplicate_keys=True)
    assert parsed['skills']['write_approval'] is True
    assert parsed['other']['write_approval'] is True
    (tmp_path / 'config.yaml').write_text(reused_chain)
    (tmp_path / 'skills').mkdir()
    (tmp_path / 'skills/.bundled_manifest').write_text('')
    hyg = mod.audit_skill_hygiene(profile_path=tmp_path)
    assert hyg['coverage'] == 'verified'
    ws_res = ws.audit_write_settings(profile_path=tmp_path)
    assert ws_res['write_settings']['settings']['skills.write_approval'] == {'value': True, 'source': 'config'}

    for bad_yaml in (
        'base: &base {a: 1, a: 2}\nmid: &mid {<<: *base}\nskills: {<<: *mid}\n',
        'base: &base {a: 1}\nmid: &mid {<<: *base, b: 1, b: 2}\nskills: {<<: *mid}\n',
    ):
        try:
            facts._parse_simple_yaml_mapping(bad_yaml, reject_duplicate_keys=True)
        except facts.DuplicateConfigKeyError:
            pass
        else:
            raise AssertionError(f'Expected DuplicateConfigKeyError for {bad_yaml!r}')


def test_hygiene_scope_documents_current_contract():
    from tests import REPO_ROOT
    from tests.test_audit_dead_stores import _doc_contains
    mod = load_submodule('audit.skill_hygiene')
    doc = (REPO_ROOT / 'docs/audit-scope.md').read_text()
    # Thresholds come from the implementation; historical corpus statistics and
    # a copied scoring expression are not executable contracts.
    assert str(mod.OVERSIZED_BODY_CHARS) in doc.replace(',', '')
    for token in ('dated_lesson_lines', 'PLACEHOLDER_USERS', 'TICKET_PREFIX_DENYLIST',
                  'not_applicable', 'duplicate_config_key', 'external_skill_dir_not_scanned',
                  'skill-change ledger', 'hub', 'external_dir'):
        _doc_contains(doc, token)
    _doc_contains(doc, 'count to review, not a verdict')


def test_surface_persists_hygiene_and_quick_is_unknown(tmp_path, monkeypatch):
    surface = load_submodule('audit_surface')
    home = tmp_path / 'home/.hermes'
    home.mkdir(parents=True)
    (home / 'config.yaml').write_text('{}\n')
    skill(home, 'plain', 'Never store CANARY_SOURCE_TEXT in a report.\n')
    monkeypatch.setenv('HERMES_HOME', str(home))
    git = load_submodule('audit.outward_git')
    discover = git.discover_git_context
    monkeypatch.setattr(git, 'discover_git_context', lambda *a, **kw: discover(*a, **kw, system_config=tmp_path / 'absent'))
    db = tmp_path / 'reports/audit.db'
    result = surface.execute_audit({'action': 'run', 'as_of': 1750000000}, db_path=db, wait=True)
    assert result['report']['skill_hygiene']['skills_examined'] == 1
    assert 'CANARY_SOURCE_TEXT' not in json.dumps(result)
    reread = surface.execute_audit({'action': 'report', 'run_id': result['run_id']}, db_path=db)
    assert reread['report']['skill_hygiene'] == result['report']['skill_hygiene']
    contract = load_submodule('audit.contract')
    changed = dict(result['report'])
    changed['skill_hygiene'] = {}
    assert contract.canonical_report_digest(changed) != result['canonical_digest']
    quick = surface.execute_audit({'action': 'run', 'quick': True}, db_path=db, wait=True)
    assert quick['report']['skill_hygiene']['reason'] == 'bounded_quick_audit_not_collected'
