"""Fixed-file profile capture: no recursive discovery in the default audit."""
from pathlib import Path

from . import facts
from .capture import Capture, CURRENT_CAPTURE
from .fingerprint import TreeFingerprintManifest, safe_read_regular_file
from .identity import engine_identity
from .persistence import stable_content_digest as digest

PATHS = ('config.yaml', 'SOUL.md', 'memories/MEMORY.md', 'memories/USER.md')
MAX_BYTES = 1024 * 1024


def collect_profile(*, profile_name, profile_dir, is_default, **unused):
    root = Path(profile_dir).absolute()
    capture = Capture()
    token = CURRENT_CAPTURE.set(capture)
    config = {}
    config_verified = True
    try:
        reads = {p: safe_read_regular_file(root, p, max_bytes=MAX_BYTES) for p in PATHS}
        try:
            config = facts._parse_simple_yaml_mapping((reads['config.yaml'].content or b'').decode('utf-8'))
        except (ValueError, ImportError, UnicodeError, RecursionError):
            config_verified = False
        config_verified = config_verified and reads['config.yaml'].coverage == 'verified'
        memory = facts.resolve_profile_memory_facts(profile_name, root, config=config, max_bytes=MAX_BYTES)
    finally:
        CURRENT_CAPTURE.reset(token)
    stable = all(safe_read_regular_file(root, p, max_bytes=MAX_BYTES, retain_bytes=False).to_dict()
                 == read.to_dict() for p, read in reads.items())
    manifest = TreeFingerprintManifest(unit_kind='profile', unit_id=profile_name,
        root_path=str(root), coverage='could_not_verify', stable=stable,
        discovery_policy={'mode': 'bounded', 'included_paths': list(PATHS),
                          'max_file_bytes': MAX_BYTES, 'recursive_discovery': False})
    for path, read in reads.items():
        if read.kind == 'missing':
            manifest.absent_expected_paths.append(path)
        else:
            manifest.files[path] = {k: v for k, v in read.to_dict().items() if v is not None}
    manifest.compute_digests()
    result_manifest = manifest.to_dict()
    result_manifest['engine_identity'] = engine_identity()
    result_manifest['unit_digest'] = digest({'capture': manifest.unit_digest,
                                            'engine': result_manifest['engine_identity']})
    if not stable or not config_verified:
        memory['coverage'] = 'could_not_verify'
        for entry in memory['files'].values():
            entry['coverage'] = 'could_not_verify'
    return {'unit_kind': 'profile', 'name': profile_name, 'path': str(root),
            'is_default': is_default, 'is_active': True, 'coverage': 'could_not_verify',
            'config': config, 'memory': memory, 'plugins': [],
            'last_use_evidence': {'coverage': 'not_included', 'reason': 'bounded audit'},
            'fingerprint_manifest': result_manifest,
            'registrations_snapshot': {'coverage': 'could_not_verify'}}
