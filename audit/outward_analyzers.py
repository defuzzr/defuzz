"""Pure, conservative outward metadata classifiers.

Inputs are already bounded/captured by the caller. No filesystem reads, imports
of inspected code, environment expansion, subprocesses, or command retention.
Recognition is not evidence that execution is safe (or will occur).
"""
from pathlib import Path
import re
import tomllib

_CREDENTIAL_NAMES = frozenset({'.npmrc', '.pypirc', '.netrc', 'auth.json', 'secrets.json', 'token', 'tokens.json'})
_DYNAMIC_NAME_KINDS = {
    'makefile': 'build_recipe_unresolved', 'gnumakefile': 'build_recipe_unresolved',
    'justfile': 'build_recipe_unresolved', '.justfile': 'build_recipe_unresolved',
    'dockerfile': 'container_build_unresolved', 'containerfile': 'container_build_unresolved',
    '.envrc': 'environment_script_unresolved', 'build.rs': 'rust_build_unresolved',
    'cargo.toml': 'rust_build_unresolved', 'setup.cfg': 'entry_points_unresolved',
    'entry_points.txt': 'entry_points_unresolved', 'tox.ini': 'test_runner_unresolved',
    'noxfile.py': 'test_runner_unresolved', '.pre-commit-config.yaml': 'precommit_unresolved',
    '.pre-commit-config.yml': 'precommit_unresolved', 'package.json': 'package_scripts_unresolved',
    '.gitlab-ci.yml': 'ci_execution_unresolved', 'jenkinsfile': 'ci_execution_unresolved',
}
_SOURCE_SUFFIXES = frozenset({'.go', '.rs', '.c', '.cpp', '.java'})
_SCRIPT_SUFFIXES = frozenset({
    '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd', '.py', '.js', '.ts',
    '.mjs', '.cjs', '.jsx', '.tsx', '.rb', '.pl', '.php', '.lua', '.r', '.mk',
})
TOOLCHAIN_FILES = frozenset({
    'pyvenv.cfg', '.python-version', '.node-version', '.nvmrc',
    '.tool-versions', 'rust-toolchain', 'rust-toolchain.toml',
})
_NUMERIC_VERSION = re.compile(r'\d+\.\d+(?:\.\d+)?')
_RUST_CHANNEL = re.compile(r'(?:stable|beta|nightly|\d+\.\d+(?:\.\d+)?)(?:-\d{4}-\d{2}-\d{2})?')
_PYVENV_HOME_ROOTS = ('.pyenv/versions', '.asdf/installs/python', '.local/share/mise/installs/python', '.local/share/uv/python')
_ASDF_TOOLS = frozenset({'python', 'nodejs', 'ruby', 'golang', 'java'})


def credential_candidate(path) -> bool:
    """Filename-only credential hint; call before general content inspection."""
    from .file_types import credential_file_kind
    return credential_file_kind(Path(path)) is not None


def credential_key_kind(key) -> str | None:
    """Classify a mapping key, including provider/MCP env names, without echoing it."""
    from .redaction import sensitive
    return 'credential_value' if sensitive(key) else None


def analyze_dynamic(path, data: bytes, *, mode: int = 0) -> list[dict]:
    """Return zero/one fixed-kind unresolved finding; path is caller-supplied."""
    p = Path(path)
    name, suffix = p.name.lower(), p.suffix.lower()
    parts = tuple(part.lower() for part in p.parts)
    kind = _DYNAMIC_NAME_KINDS.get(name)
    if not kind and name.startswith(('dockerfile.', 'containerfile.')):
        kind = 'container_build_unresolved'
    if '.git' in parts and 'hooks' in parts:
        kind = 'git_hook_unresolved'
    elif len(parts) >= 2 and parts[-2:] == ('.git', 'config'):
        kind = 'git_config_unresolved'
    elif any(pair in (('.github', 'workflows'), ('.circleci', 'config.yml')) for pair in zip(parts, parts[1:])):
        kind = 'ci_execution_unresolved'
    if not kind and suffix == '.ipynb':
        kind = 'notebook_execution_unresolved'
    if not kind and suffix in _SOURCE_SUFFIXES:
        kind = 'source_execution_unresolved'
    if not kind and (data.startswith(b'#!') or mode & 0o111 or suffix in _SCRIPT_SUFFIXES):
        kind = 'script_execution_unresolved'
    return [{'path': str(path), 'kind': kind, 'resolution': 'unresolved'}] if kind else []


def _parse_toolchain_declarations(name: str, data: bytes) -> list[tuple[str, str]] | None:
    text = data.decode('utf-8')
    lines = [clean for line in text.splitlines() if (clean := line.split('#', 1)[0].strip())]
    if name == 'pyvenv.cfg':
        declarations = [('home', line.split('=', 1)[1].strip()) for line in lines
                        if '=' in line and line.split('=', 1)[0].strip().lower() == 'home']
        return declarations if len(declarations) == 1 else None
    if name == '.tool-versions':
        return [(fields[0], v) for line in lines if (fields := line.split()) for v in (fields[1:] or [''])]
    if name.startswith('rust-toolchain'):
        if name.endswith('.toml') or text.lstrip().startswith('['):
            cfg = tomllib.loads(text).get('toolchain', {})
            if isinstance(cfg, dict) and 'path' in cfg:
                return None
            return [('rust', cfg.get('channel', '') if isinstance(cfg, dict) else '')]
        return [('rust', text.strip())]
    tool = 'python' if name == '.python-version' else 'nodejs'
    return [(tool, token) for line in lines for token in line.split()]


def _toolchain_candidates(tool: str, version: str, base: Path, inventory: set[Path]) -> set[Path]:
    candidates = set()
    if tool == 'home':
        target = Path(version)
        roots = [base / p for p in _PYVENV_HOME_ROOTS]
        if (target.is_absolute() and '..' not in target.parts and not re.search(r'[$\x00\r\n]', version)
                and any(target.is_relative_to(root) and target != root for root in roots)):
            candidates.add(target)
        return candidates
    if tool == 'rust' and _RUST_CHANNEL.fullmatch(version):
        root = base / '.rustup/toolchains'
        pattern = re.escape(version) + r'-(?:x86_64|aarch64|i686|armv7)[A-Za-z0-9_-]*'
        return {p for p in inventory if p.parent == root and (p.name == version or re.fullmatch(pattern, p.name))}
    if tool == 'nodejs' and version.startswith('v'):
        version = version[1:]
    if tool in _ASDF_TOOLS and _NUMERIC_VERSION.fullmatch(version):
        candidates.add(base / '.asdf/installs' / tool / version)
        if tool == 'python':
            candidates.add(base / '.pyenv/versions' / version)
            uv_root = base / '.local/share/uv/python'
            candidates.update(p for p in inventory if p.parent == uv_root and p.name.startswith(f'cpython-{version}-'))
        elif tool == 'nodejs':
            candidates.add(base / '.nvm/versions/node' / f'v{version}')
    return candidates


def resolve_toolchain(path, data: bytes, *, home, available_paths=()) -> list[dict]:
    """Resolve declarations against a caller-owned, bounded path inventory."""
    name = Path(path).name
    if name not in TOOLCHAIN_FILES:
        return []
    base = Path(home)
    unknown = {'path': str(path), 'kind': 'toolchain_reference', 'resolution': 'unresolved', 'target': None}
    if not base.is_absolute() or '..' in base.parts:
        return [unknown]
    inventory = {p for raw in available_paths if (p := Path(raw)).is_absolute() and '..' not in p.parts}
    try:
        declarations = _parse_toolchain_declarations(name, data)
    except (UnicodeError, ValueError, RecursionError):
        return [unknown]
    if declarations is None:
        return [unknown]
    records = []
    for tool, version in declarations:
        record = dict(unknown)
        if isinstance(version, str):
            matches = _toolchain_candidates(tool, version, base, inventory) & inventory
            if len(matches) == 1:
                record.update(resolution='resolved', target=str(next(iter(matches))))
        records.append(record)
    return records or [unknown]
