"""Bounded per-unit captured-byte reuse and optimistic revalidation, not host atomicity."""
from contextvars import ContextVar
from dataclasses import replace
from functools import wraps
from hashlib import sha256
import os
from pathlib import Path
from typing import Any
from .persistence import stable_content_digest as digest
from .policy import credential_path

CURRENT_CAPTURE: ContextVar[Any] = ContextVar('audit_capture', default=None)
_MAX_CAPTURE_BYTES = 64 * 1024 * 1024


class Capture:
    def __init__(self):
        self.reads = {}
        self.total_bytes = 0
        self.exceeded = False

    def read(self, reader, root, rel_path, **kwargs):
        key = (os.path.abspath(os.fspath(root)), str(rel_path))
        if key not in self.reads:
            kwargs['retain_bytes'] = True
            result = reader(root, rel_path, **kwargs)
            from .redaction import observe
            payload = result.content or b''
            observe(Path(root) / rel_path, payload)
            self.total_bytes += len(payload)
            if self.total_bytes > _MAX_CAPTURE_BYTES:
                result = replace(result, content=None, sha256=None, coverage='could_not_verify', stable=False)
                self.exceeded = True
            self.reads[key] = result
        return self.reads[key]


def _root_stat_identity(path: Path | str) -> tuple[int, int, int, int, int] | None:
    try:
        st = os.lstat(path)
        return (st.st_dev, st.st_ino, st.st_mode, st.st_mtime_ns, st.st_ctime_ns)
    except OSError:
        return None


def _scan_profile_and_skill_roots(fp: Any, root: Path, kwargs: dict[str, Any]):
    from .facts import _parse_simple_yaml_mapping, resolve_profile_skill_roots
    scans: list[tuple[dict[str, Any], Any]] = []
    blending: list[Any] = []
    root_identities = {str(root): _root_stat_identity(root)}
    parse_error = False

    profile_args: dict[str, Any] = dict(
        unit_kind='profile', unit_id=kwargs['profile_name'], root_path=root,
        descendant_profile_roots=kwargs.get('descendant_profile_roots', ()),
    )
    scans.append((profile_args, fp.build_tree_fingerprint_manifest(**profile_args)))
    config = fp.safe_read_regular_file(root, 'config.yaml')
    try:
        cfg = _parse_simple_yaml_mapping((config.content or b'').decode('utf-8'))
    except (ValueError, ImportError, UnicodeError, RecursionError):
        cfg, parse_error = {}, True

    for skill_root in resolve_profile_skill_roots(root, config=cfg):
        external = Path(skill_root['path']).absolute()
        if skill_root.get('blending'):
            blending.append(skill_root['blending'])
        if external == root / 'skills' or credential_path(external):
            continue
        root_identities[str(external)] = _root_stat_identity(external)
        ext_args: dict[str, Any] = dict(unit_kind='project', unit_id=str(external), root_path=external)
        scans.append((ext_args, fp.build_tree_fingerprint_manifest(**ext_args)))
    return scans, blending, root_identities, parse_error


def _has_profile_capture_changed(
    fp: Any, capture: Capture, scans: list[tuple[dict[str, Any], Any]],
    root_identities: dict[str, Any], result: dict[str, Any],
    before_identity: Any, parse_error: bool,
) -> bool:
    from .identity import engine_identity
    from .readonly_db import stat_db_identity
    changed = capture.exceeded or parse_error
    if any(_root_stat_identity(path) != before_root for path, before_root in root_identities.items()):
        changed = True
    for args, before in scans:
        after = fp.build_tree_fingerprint_manifest(**args)
        if not (before.stable and after.stable and before.coverage == 'verified' and after.coverage == 'verified'):
            changed = True
        if (before.files, before.directories, before.symlinks, before.absent_expected_paths) != (
            after.files, after.directories, after.symlinks, after.absent_expected_paths
        ):
            changed = True
    for (read_root, rel), before in capture.reads.items():
        if before.to_dict() != fp.safe_read_regular_file(read_root, rel, retain_bytes=False).to_dict():
            changed = True
    snap = result['registrations_snapshot']
    try:
        current = stat_db_identity(snap['db_path']).to_dict() if Path(snap['db_path']).exists() else None
        if current != snap.get('db_identity'):
            changed = True
    except OSError:
        changed = True
    if before_identity != engine_identity():
        changed = True
    return changed


def capture_project_files(root, unit_id=None):
    """Return one revalidated manifest and in-memory file map for every component."""
    from . import fingerprint as fp
    from .identity import engine_identity
    root = Path(root).absolute()
    capture = Capture()
    token = CURRENT_CAPTURE.set(capture)
    args: dict[str, Any] = dict(unit_kind='project', unit_id=unit_id or str(root), root_path=root)
    try:
        before = fp.build_tree_fingerprint_manifest(**args)
    finally:
        CURRENT_CAPTURE.reset(token)
    after = fp.build_tree_fingerprint_manifest(**args)
    if (
        (before.files, before.directories, before.symlinks) != (after.files, after.directories, after.symlinks)
        or not after.stable or after.coverage != 'verified' or capture.exceeded
    ):
        before.stable = False
        before.coverage = 'could_not_verify'
        before.compute_digests()
    files = {
        rel: {
            **r.to_dict(), 'content': r.content,
            'sha256': sha256(r.content).hexdigest() if r.content is not None and r.sha256 else None,
        }
        for (read_root, rel), r in capture.reads.items()
        if read_root == str(root) and r.kind != 'excluded'
    }
    manifest = before.to_dict()
    manifest['engine_identity'] = engine_identity()
    manifest['unit_digest'] = digest({'capture': manifest['unit_digest'], 'engine': manifest['engine_identity']})
    return manifest, files


def coherent_profile_capture(fn):
    @wraps(fn)
    def collect(**kwargs):
        from . import fingerprint as fp
        from .identity import engine_identity
        root = Path(kwargs['profile_dir']).absolute()
        capture = Capture()
        token = CURRENT_CAPTURE.set(capture)
        try:
            scans, blending, root_identities, parse_error = _scan_profile_and_skill_roots(fp, root, kwargs)
            before_identity = engine_identity()
            result = fn(**kwargs)
        finally:
            CURRENT_CAPTURE.reset(token)
        changed = _has_profile_capture_changed(
            fp, capture, scans, root_identities, result, before_identity, parse_error
        )
        manifest = result['fingerprint_manifest']
        manifest['blending'] = blending
        manifest['external_evidence'] = {str(args['root_path']): m.unit_digest for args, m in scans[1:]}
        manifest['engine_identity'] = before_identity
        manifest['unit_digest'] = digest({
            'capture': manifest['unit_digest'], 'external': manifest['external_evidence'], 'engine': before_identity
        })
        if changed:
            result['coverage'] = manifest['coverage'] = 'could_not_verify'
            result['stable'] = manifest['stable'] = False
            manifest['whole_profile_exact_eligible'] = False
            manifest['whole_profile_digest'] = None
        result['capture_policy'] = 'optimistic-revalidated-v2; not globally atomic'
        return result
    return collect
