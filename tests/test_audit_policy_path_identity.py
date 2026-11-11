"""Declared credentials reached through another spelling of their path are never read.

Every case declares a credential under one spelling and reaches it under another:
a linked parent folder, a link to the file, a hard link, '..' segments, extra
slashes, a different letter case, a whole home behind a link (the macOS /var ->
/private/var situation), a link swapped between the check and the open, and a
candidate that cannot be checked. The spy below is portable (no /proc): it
identifies opened files by (device, inode) and counts every byte read from them.
"""
import json
import os
import shutil
import stat
import sys
import threading
from pathlib import Path

import pytest
from tests.conftest import load_submodule

SECRET = b'IDENTITY_CANARY_DO_NOT_READ'


class OpenSpy:
    """Record opens and reads of protected files by identity, not by path spelling."""

    def __init__(self, monkeypatch, protected):
        # Import the audit before wrapping os.open: dir_fd support is recorded at import time.
        load_submodule('audit_surface')
        self.ids = {self._identity(os.stat(p)) for p in protected}
        self.path_opens = []   # opens through Python file objects (content readable)
        self.fd_opens = 0      # raw descriptor opens of a protected file
        self.bytes_read = 0    # bytes read from those descriptors
        self.enabled = True
        self._live = set()
        spy = self

        def hook(event, args):
            if not spy.enabled or event != 'open' or not args:
                return
            target, mode = args[0], args[1] if len(args) > 1 else None
            if mode is None:
                return  # os.open: the descriptor wrapper below accounts for it.
            try:
                if isinstance(target, int):
                    info = os.fstat(target)
                elif isinstance(target, (str, bytes, os.PathLike)) and os.path.isabs(os.fsdecode(target)):
                    info = os.stat(target)
                else:
                    return
            except OSError:
                return
            if spy._identity(info) in spy.ids:
                spy.path_opens.append(os.fsdecode(target) if not isinstance(target, int) else target)

        sys.addaudithook(hook)
        original_open, original_read, original_close = os.open, os.read, os.close

        def spy_open(path, flags, mode=0o777, *, dir_fd=None):
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            if spy.enabled:
                try:
                    if spy._identity(os.fstat(fd)) in spy.ids:
                        spy.fd_opens += 1
                        spy._live.add(fd)
                except OSError:
                    pass
            return fd

        def spy_read(fd, n):
            data = original_read(fd, n)
            if fd in spy._live:
                spy.bytes_read += len(data)
            return data

        def spy_close(fd):
            spy._live.discard(fd)
            return original_close(fd)

        monkeypatch.setattr(os, 'open', spy_open)
        monkeypatch.setattr(os, 'read', spy_read)
        monkeypatch.setattr(os, 'close', spy_close)

    @staticmethod
    def _identity(info):
        return (info.st_dev, info.st_ino)

    def assert_never_opened(self):
        assert self.path_opens == []
        assert self.fd_opens == 0
        assert self.bytes_read == 0

    def assert_never_read(self):
        assert self.path_opens == []
        assert self.bytes_read == 0


def _modules():
    return load_submodule('audit.policy'), load_submodule('audit.fingerprint'), load_submodule('audit.redaction')


def _layout(tmp_path):
    real = tmp_path / 'real'
    (real / 'sub').mkdir(parents=True)
    secret = real / 'sub' / 'payload.dat'
    secret.write_bytes(SECRET)
    (real / 'sub' / 'plain.txt').write_text('ordinary')
    alias = tmp_path / 'alias'
    alias.symlink_to(real, target_is_directory=True)
    return real, alias, secret


def _shape(result):
    return (result.kind, result.coverage, result.error, result.content, result.sha256)


def _metadata_shape(record):
    return {k: v for k, v in record.items() if k != 'path'}


def _declare_from_source(policy, project, declared):
    (project / 'settings.json').write_text(json.dumps({'credential_file': str(declared)}))
    policy.credential_declarations(project, project.parent)


CASES = {
    # name: (declared spelling, read root, read rel, candidate spelling)
    'linked-parent': lambda r, a: (r / 'sub/payload.dat', a / 'sub', 'payload.dat', a / 'sub/payload.dat'),
    'declared-through-link': lambda r, a: (a / 'sub/payload.dat', r / 'sub', 'payload.dat', r / 'sub/payload.dat'),
    'dot-dot': lambda r, a: (r / 'sub/payload.dat', str(a / 'sub/x/..'), 'payload.dat', str(a / 'sub/x/../payload.dat')),
    'extra-slashes': lambda r, a: (r / 'sub/payload.dat', str(a) + '//sub/', 'payload.dat', str(a) + '//sub//payload.dat/'),
}


@pytest.mark.parametrize('case', sorted(CASES))
def test_declared_file_reached_through_another_spelling_is_not_read(tmp_path, monkeypatch, case):
    policy, fingerprint, redaction = _modules()
    real, alias, secret = _layout(tmp_path)
    project = tmp_path / 'project'
    project.mkdir()
    declared, root, rel, candidate = CASES[case](real, alias)
    spy = OpenSpy(monkeypatch, [secret])
    seen = {}

    @redaction.redaction_scope
    def run():
        state = redaction._CURRENT.get()
        _declare_from_source(policy, project, declared)
        seen['candidate'] = policy.credential_path(candidate)
        seen['alias'] = fingerprint.safe_read_regular_file(root, rel)
        alias_meta = dict(state.credential_metadata)
        state.credential_metadata.clear()
        seen['direct'] = fingerprint.safe_read_regular_file(secret.parent, secret.name)
        seen['meta'] = (alias_meta, dict(state.credential_metadata))
        seen['plain'] = fingerprint.safe_read_regular_file(root, 'plain.txt')

    run()
    spy.assert_never_opened()
    assert seen['candidate'] is True
    assert seen['direct'].kind == 'excluded'
    assert _shape(seen['alias']) == _shape(seen['direct'])
    alias_meta, direct_meta = seen['meta']
    assert len(alias_meta) == len(direct_meta) == 1
    assert [_metadata_shape(v) for v in alias_meta.values()] == [_metadata_shape(v) for v in direct_meta.values()]
    # An ordinary neighbour is still read: the rule withholds identity, not folders.
    assert seen['plain'].kind == 'regular' and seen['plain'].content == b'ordinary'


def test_hard_link_to_declared_file_is_not_read(tmp_path, monkeypatch):
    policy, fingerprint, redaction = _modules()
    real, _alias, secret = _layout(tmp_path)
    second = real / 'sub' / 'second-name.dat'
    os.link(secret, second)
    spy = OpenSpy(monkeypatch, [secret])
    seen = {}

    @redaction.redaction_scope
    def run():
        policy.declare_credential(secret)
        seen['path'] = policy.credential_path(second)
        seen['read'] = fingerprint.safe_read_regular_file(real / 'sub', 'second-name.dat')
        seen['direct'] = fingerprint.safe_read_regular_file(real / 'sub', 'payload.dat')

    run()
    spy.assert_never_opened()
    assert seen['path'] is True
    assert _shape(seen['read']) == _shape(seen['direct'])


def test_link_to_declared_file_is_reported_like_the_file(tmp_path, monkeypatch):
    policy, fingerprint, redaction = _modules()
    real, _alias, secret = _layout(tmp_path)
    link = real / 'sub' / 'pointer.dat'
    link.symlink_to(secret)
    spy = OpenSpy(monkeypatch, [secret])
    seen = {}

    @redaction.redaction_scope
    def run():
        policy.declare_credential(secret)
        seen['path'] = policy.credential_path(link)
        seen['read'] = fingerprint.safe_read_regular_file(real / 'sub', 'pointer.dat')
        seen['direct'] = fingerprint.safe_read_regular_file(real / 'sub', 'payload.dat')

    run()
    spy.assert_never_opened()
    assert seen['path'] is True
    # The link's raw target (the declared path) is not disclosed as a symlink entry.
    assert _shape(seen['read']) == _shape(seen['direct'])
    assert seen['read'].symlink_target is None


def test_declared_folder_reached_through_link_is_not_read(tmp_path, monkeypatch):
    policy, fingerprint, redaction = _modules()
    real, alias, secret = _layout(tmp_path)
    keep = real / 'keep'
    keep.mkdir()
    inside = keep / 'notes.txt'
    inside.write_bytes(SECRET)
    spy = OpenSpy(monkeypatch, [inside, secret])
    seen = {}

    @redaction.redaction_scope
    def run():
        policy.declare_credential(alias / 'keep')
        seen['path'] = policy.credential_path(keep / 'notes.txt')
        seen['read'] = fingerprint.safe_read_regular_file(real, 'keep/notes.txt')
        policy.declare_credential(secret.parent)
        seen['read2'] = fingerprint.safe_read_regular_file(alias / 'sub', 'payload.dat')

    run()
    spy.assert_never_opened()
    assert seen['path'] is True
    assert seen['read'].kind == 'excluded' and seen['read2'].kind == 'excluded'


def test_declared_name_with_other_letter_case_is_withheld(tmp_path, monkeypatch):
    """On a case-insensitive disk 'Payload.DAT' and 'payload.dat' are one file.

    The comparison is always case-insensitive. On a case-sensitive disk this can
    withhold an ordinary file whose name differs only by case: over-withholding
    is the accepted direction.
    """
    policy, fingerprint, redaction = _modules()
    real, alias, secret = _layout(tmp_path)
    spy = OpenSpy(monkeypatch, [secret])
    seen = {}

    @redaction.redaction_scope
    def run():
        policy.declare_credential(real / 'SUB' / 'Payload.DAT')  # spelled as a user on macOS might
        seen['path'] = policy.credential_path(alias / 'sub' / 'payload.dat')
        seen['read'] = fingerprint.safe_read_regular_file(real / 'sub', 'payload.dat')

    run()
    spy.assert_never_opened()
    assert seen['path'] is True
    assert seen['read'].kind == 'excluded'


def test_link_swapped_between_check_and_open_never_reads(tmp_path, monkeypatch):
    policy, fingerprint, redaction = _modules()
    a = tmp_path / 'a'
    b = tmp_path / 'b'
    (a / 'sub').mkdir(parents=True)
    (b / 'sub').mkdir(parents=True)
    secret = a / 'sub' / 'payload.dat'
    secret.write_bytes(SECRET)
    (b / 'sub' / 'payload.dat').write_bytes(b'benign')
    link = tmp_path / 'link'
    link.symlink_to(b, target_is_directory=True)
    spy = OpenSpy(monkeypatch, [secret])
    stop = threading.Event()

    def swapper():
        flip = False
        tmp_link = tmp_path / 'link.next'
        while not stop.is_set():
            flip = not flip
            with_target = a if flip else b
            try:
                os.unlink(tmp_link)
            except FileNotFoundError:
                pass
            os.symlink(with_target, tmp_link, target_is_directory=True)
            os.replace(tmp_link, link)

    kinds = {}
    leaked = []

    @redaction.redaction_scope
    def run():
        policy.declare_credential(secret)
        thread = threading.Thread(target=swapper, daemon=True)
        thread.start()
        try:
            for _ in range(5000):
                result = fingerprint.safe_read_regular_file(link / 'sub', 'payload.dat')
                kinds[result.kind] = kinds.get(result.kind, 0) + 1
                if result.content and SECRET in result.content:
                    leaked.append(result.path)
        finally:
            stop.set()
            thread.join()

    run()
    spy.assert_never_read()
    assert leaked == []
    assert sum(kinds.values()) == 5000


def test_swap_after_the_path_check_is_caught_on_the_open_handle(tmp_path, monkeypatch):
    """Deterministic form of the race: the link moves right after the path check passed."""
    policy, fingerprint, redaction = _modules()
    a = tmp_path / 'a'
    b = tmp_path / 'b'
    (a / 'sub').mkdir(parents=True)
    (b / 'sub').mkdir(parents=True)
    secret = a / 'sub' / 'payload.dat'
    secret.write_bytes(SECRET)
    (b / 'sub' / 'payload.dat').write_bytes(b'benign')
    link = tmp_path / 'link'
    link.symlink_to(b, target_is_directory=True)
    spy = OpenSpy(monkeypatch, [secret])
    original_verdict = fingerprint.credential_verdict

    def verdict_then_swap(path):
        verdict = original_verdict(path)
        link.unlink()
        link.symlink_to(a, target_is_directory=True)
        return verdict

    seen = {}

    @redaction.redaction_scope
    def run():
        policy.declare_credential(secret)
        monkeypatch.setattr(fingerprint, 'credential_verdict', verdict_then_swap)
        seen['read'] = fingerprint.safe_read_regular_file(link / 'sub', 'payload.dat')
        monkeypatch.setattr(fingerprint, 'credential_verdict', original_verdict)
        seen['direct'] = fingerprint.safe_read_regular_file(a / 'sub', 'payload.dat')

    run()
    spy.assert_never_read()
    assert spy.fd_opens == 1  # opened once by descriptor, closed with zero bytes read
    assert _shape(seen['read']) == _shape(seen['direct'])


def test_candidate_that_cannot_be_checked_is_not_opened(tmp_path, monkeypatch):
    policy, fingerprint, redaction = _modules()
    real, alias, secret = _layout(tmp_path)
    other = real / 'sub' / 'unchecked.txt'
    other.write_bytes(SECRET)
    spy = OpenSpy(monkeypatch, [other, secret])
    original_lstat = os.lstat

    def failing_lstat(path, *args, **kwargs):
        if os.fspath(path).endswith('unchecked.txt') and kwargs.get('dir_fd') is None and not args:
            raise PermissionError(13, 'simulated: cannot check')
        return original_lstat(path, *args, **kwargs)

    seen = {}

    @redaction.redaction_scope
    def run():
        policy.declare_credential(secret)
        monkeypatch.setattr(os, 'lstat', failing_lstat)
        try:
            seen['path'] = policy.credential_path(alias / 'sub' / 'unchecked.txt')
            seen['read'] = fingerprint.safe_read_regular_file(alias / 'sub', 'unchecked.txt')
        finally:
            monkeypatch.setattr(os, 'lstat', original_lstat)

    run()
    spy.assert_never_opened()
    assert seen['path'] is True  # fail closed
    assert seen['read'].coverage == 'could_not_verify'
    assert seen['read'].content is None


def test_link_loop_in_candidate_fails_closed(tmp_path, monkeypatch):
    policy, fingerprint, redaction = _modules()
    real, _alias, secret = _layout(tmp_path)
    loop = tmp_path / 'loop'
    loop.symlink_to(loop)
    spy = OpenSpy(monkeypatch, [secret])
    seen = {}

    @redaction.redaction_scope
    def run():
        policy.declare_credential(secret)
        seen['path'] = policy.credential_path(loop / 'x' / 'file.txt')

    run()
    spy.assert_never_opened()
    assert seen['path'] is True


def test_no_declarations_means_no_identity_work(tmp_path, monkeypatch):
    """Without declarations the identity rule adds no file-system calls per candidate."""
    policy, _fingerprint, redaction = _modules()
    real, _alias, _secret = _layout(tmp_path)
    calls = []
    original_lstat, original_stat = os.lstat, os.stat
    seen = {}

    @redaction.redaction_scope
    def run():
        monkeypatch.setattr(os, 'lstat', lambda *a, **k: calls.append(a) or original_lstat(*a, **k))
        monkeypatch.setattr(os, 'stat', lambda *a, **k: calls.append(a) or original_stat(*a, **k))
        try:
            seen['path'] = policy.credential_path(real / 'sub' / 'plain.txt')
        finally:
            monkeypatch.setattr(os, 'lstat', original_lstat)
            monkeypatch.setattr(os, 'stat', original_stat)

    run()
    assert seen['path'] is False
    assert calls == []


def _home_with_declarations(base):
    home = base / 'home'
    profile = home / '.hermes'
    profile.mkdir(parents=True)
    project = home / 'project'
    project.mkdir()
    (project / 'main.py').write_text('print(1)\n')
    opaque = project / 'opaque.dat'
    opaque.write_bytes(SECRET)
    keep = project / 'keep'
    keep.mkdir()
    (keep / 'inside.txt').write_bytes(SECRET)
    # Profile files the audit reads through HERMES_HOME's own spelling.
    memory = profile / 'memories' / 'MEMORY.md'
    memory.parent.mkdir()
    memory.write_bytes(SECRET + b'\n')
    skill = profile / 'skills' / 'demo' / 'SKILL.md'
    skill.parent.mkdir(parents=True)
    skill.write_bytes(b'---\nname: demo\ndescription: demo\n---\n' + SECRET + b'\n')
    return home, profile, project, opaque, keep, memory, skill


def _normalise(value, old, new):
    return json.loads(json.dumps(value).replace(old, new))


def _run_audit(monkeypatch, home, profile, project, db):
    surface = load_submodule('audit_surface')
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('HERMES_HOME', str(profile))
    original_inventory = surface._active_inventory

    def inventory(*args):
        result = original_inventory(*args)
        # Selected projects are canonicalised with resolve(), as registrations are.
        result['project_units'] = [{'canonical_path': str(Path(project).resolve()), 'coverage': 'verified'}]
        return result

    monkeypatch.setattr(surface, '_active_inventory', inventory)
    try:
        return surface.execute_audit({'root': str(project)}, db_path=db, wait=True)
    finally:
        monkeypatch.setattr(surface, '_active_inventory', original_inventory)


def test_full_audit_with_home_behind_a_link_matches_direct_home(tmp_path, monkeypatch):
    """The macOS situation: the audit walks /var/... while the user declared /private/var/..."""
    real_base = tmp_path / 'private-base'
    real_base.mkdir()
    home, profile, project, opaque, keep, memory, skill = _home_with_declarations(real_base)
    # Declarations use the fully resolved spelling, as `Path.resolve()` gives on macOS.
    declared = [opaque, keep, memory, skill]
    (profile / 'config.yaml').write_text(
        'credential_file: [' + ', '.join(str(p.resolve()) for p in declared) + ']\n')
    linked_base = tmp_path / 'linked-base'
    linked_base.symlink_to(real_base, target_is_directory=True)
    protected = [opaque, keep / 'inside.txt', memory, skill]
    spy = OpenSpy(monkeypatch, protected)
    responses = {}
    for name, base in (('direct', real_base), ('linked', linked_base)):
        db = tmp_path / f'store-{name}' / 'audit.db'
        db.parent.mkdir()
        try:
            responses[name] = _run_audit(monkeypatch, base / 'home', base / 'home/.hermes',
                                         base / 'home/project', db)
        finally:
            pass
    spy.enabled = False
    spy.assert_never_opened()
    for name, response in responses.items():
        assert response['status'] == 'completed', name
        assert SECRET.decode() not in json.dumps(response)
        for file in (tmp_path / f'store-{name}').rglob('*'):
            if file.is_file():
                assert SECRET not in file.read_bytes()
    # The outward walk records a linked home as a link edge and walks its target once,
    # so a record can appear once instead of twice: compare the distinct records.
    distinct = lambda items: sorted({json.dumps(item, sort_keys=True) for item in items})
    direct = distinct(responses['direct']['report']['credentials'])
    linked = distinct(_normalise(responses['linked']['report']['credentials'], str(linked_base), str(real_base)))
    assert linked == direct
    assert any(json.loads(item)['path'] == str(opaque) for item in direct)
    assert any(json.loads(item)['path'] == str(keep) for item in direct)
    # Sealed reasons carry a per-run key: compare their kinds, not their digests. Only
    # the credentials region is compared: a linked home also changes how other regions
    # disclose the link itself, which is not a credential decision.
    reason = lambda r: r if isinstance(r, str) else str(r.get('kind'))
    region = lambda r: (r['report']['scope']['regions']['credentials']['coverage'],
                        sorted(reason(x) for x in r['report']['scope']['regions']['credentials'].get('reasons', [])))
    assert region(responses['linked']) == region(responses['direct'])
