"""Identity of actual installed audit code, parser, policy and template bytes."""
import hashlib
import importlib.metadata
import json
import stat
from pathlib import Path
from .evidence import generated_digest
from .redaction import redaction_scope


def digest(value):
    """Stable identity of installed code/template artifacts, not captured facts."""
    return generated_digest(hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(',', ':')).encode()).hexdigest())


def _read_identity_artifact(path: Path, anchor: Path):
    from .fingerprint import safe_read_regular_file_plain
    from .policy import credential_path, note_credential_skip
    if credential_path(path):
        note_credential_skip(path)
        return {'kind': 'credential_store_not_opened'}
    read = safe_read_regular_file_plain(anchor, path.relative_to(anchor))
    return read.sha256 if read.sha256 else {'kind': read.kind}


def _discover_template_files(directory: Path, repo_root: Path) -> list[Path]:
    from .policy import credential_declarations, credential_path, note_credential_skip
    found: list[Path] = []

    def _walk(cur_dir: Path) -> None:
        if credential_path(cur_dir):
            note_credential_skip(cur_dir)
            return
        try:
            if not stat.S_ISDIR(cur_dir.lstat().st_mode):
                return
            credential_declarations(cur_dir, repo_root)
            for path in sorted(cur_dir.iterdir()):
                mode = path.lstat().st_mode
                if stat.S_ISREG(mode):
                    found.append(path)
                elif stat.S_ISDIR(mode):
                    _walk(path)
        except OSError:
            return

    _walk(directory)
    return found


@redaction_scope
def engine_identity():
    root = Path(__file__).parent
    files = sorted(root.glob('*.py')) + sorted((root / 'vendor').glob('*.py'))
    files.append(root / 'vendor' / 'provenance.json')
    templates = root.parent / 'templates'
    template_files = _discover_template_files(templates, root.parent)
    engine = {p.relative_to(root).as_posix(): _read_identity_artifact(p, root) for p in files}
    template_hashes = {p.relative_to(templates).as_posix(): _read_identity_artifact(p, templates)
                       for p in template_files}
    try:
        parser = importlib.metadata.version('PyYAML')
    except importlib.metadata.PackageNotFoundError:
        parser = 'missing'
    return {'engine_digest': digest(engine), 'template_digest': digest(template_hashes),
            'parser': 'PyYAML:' + parser, 'parser_policy': 'safe-load-json-v2',
            'persistence_policy': 'allowlist-v2'}
