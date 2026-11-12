"""Read-only, bounded outward static trace; verified never means runtime-safe.

Only explicit roots and evidenced outgoing edges are inspected. Captured contents
are transient; returned evidence contains locations and fixed vocabulary only.
"""
import configparser
import fnmatch
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import time
import tomllib
from urllib.parse import unquote, urlsplit

from .evidence import Evidence, generated_digest, serialize_evidence
from .facts import _is_registered_folder, _parse_simple_yaml_mapping, _registered_folder_keys
from .file_types import classify_file, credential_file_kind, execution_trigger
from .home_startup import discover as discover_home_startup
from .literal_paths import path_references, safe_config
from .outward_analyzers import TOOLCHAIN_FILES, analyze_dynamic, credential_candidate, credential_key_kind, resolve_toolchain
from .outward_db import SnapshotError, inspect_database
from .fingerprint import CredentialStoreNotOpened, open_checked
from .outward_git import _absolute, _directory as _directory_fd, _identity, discover_git_context
from .outward_git_config import classify_git_config
from .outward_structured import classification, parse_data
from .policy import credential_declarations, credential_path, declare_credential, declaration_source, declared_credential
from .redaction import _CURRENT, extraction, observe, observe_value, redaction_scope

REGIONS = (
    'project_tree', 'active_profile', 'skills', 'plugins', 'session_history',
    'identity', 'credentials', 'shared_infrastructure', 'sibling_profiles',
    'other_projects', 'dynamic_execution', 'cross_project_isolation',
)
MAX_ENTRIES = 1000000
MAX_DEPTH = 128
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
MAX_EDGES = 256
MAX_INVOCATIONS = 256
# Referenced-tree budgets (docs/audit-scope.md). A referenced tree is the folder a
# followed reference points to, or a nested Git checkout met while walking (for
# example a source checkout inside the profile). The active profile and selected
# projects themselves keep only the global budgets above. Hitting a limit cuts only
# that tree and is reported: the regions inside it become could_not_verify and the
# cut tree is listed in limits.regions.<budget>.trees with what was covered.
# MAX_REFERENCED_SECONDS is the wall time shared by all referenced trees of one run.
# ``unbounded`` lifts them all.
MAX_TREE_ENTRIES = 50000
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_TREE_SECONDS = 30
MAX_REFERENCED_SECONDS = 180
# Content outside the audited home and selected projects is read only when it is a
# small text file; larger or binary targets are recorded, never parsed or matched.
MAX_OUTSIDE_FILE_BYTES = 1024 * 1024
# Folders skipped by name (a declared scope rule, counted in pruned_roots, not a cut).
# Each holds installed third-party packages or regenerable tool output, never the
# user's own configuration; local links into them are declared by the manifests that
# stay inspected (package.json file:/link:/workspace:, pnpm-workspace.yaml, pyproject).
SKIPPED_FOLDER_NAMES = frozenset({
    'node_modules', 'bower_components', 'jspm_packages',          # npm/yarn/pnpm, bower, jspm installs
    '__pycache__', '.mypy_cache', '.pytest_cache', '.ruff_cache',  # Python bytecode and tool caches
    '.tox', '.nox',                                                # per-test-run virtual environments
    '.next', '.nuxt', '.svelte-kit', '.parcel-cache', '.turbo',    # framework build output and caches
})
# Not walked when outside the audited home and selected projects (operating-system
# installs; a referenced file there is still recorded and read under the outside cap).
SYSTEM_ROOTS = ('/usr', '/bin', '/sbin', '/lib', '/lib32', '/lib64', '/libx32', '/boot', '/dev', '/proc',
                '/sys', '/run', '/snap', '/var/lib', '/var/cache', '/nix/store', '/System', '/Library')
_GIT_STORAGE_FOLDERS = ('objects', 'lfs')
_VENV_KEPT_FOLDERS = ('lib', 'lib64', 'Lib', 'site-packages')

_PROFILE_REGION_FOLDERS = (('skills', 'skills'), ('plugins', 'plugins'), ('sessions', 'session_history'), ('memories', 'identity'), ('profiles', 'sibling_profiles'))
_LOAD_ROOT_MARKERS = ('package.json', 'pyproject.toml', 'Cargo.toml', 'go.mod', '__init__.py')
_SAFE_CONFIG_KEYS = frozenset({
    'api_key', 'apiKey', 'token', 'secret', 'password', 'passwd', 'credential', 'credentials',
    'auth', 'access_token', 'refresh_token', 'client_secret', 'private_key', 'providers', 'mcp_servers', 'env',
})
_COMMAND_KEYS = frozenset({'command', 'exec', 'shell', 'script', 'scripts', 'hooks', 'entry_points', 'entrypoint'})
_EXTRACTED_COMMAND_KEYS = frozenset({'command', 'exec', 'shell', 'script', 'scripts', 'entrypoint'})
_PATH_CONFIG_KEYS = frozenset({
    'path', 'paths', 'root', 'directory', 'cwd', 'workingDirectory', 'file', 'env_file',
    'plugin_dir', 'context_file', 'config_path', 'credential_file', 'credentials_file',
})
_SIBLING_DECLARATION_KEYS = frozenset({'path', 'paths', 'root', 'directory', 'cwd', 'file', 'plugin_dir', 'create_dir', 'external_dirs'})
_PACKAGE_DEPENDENCY_SECTIONS = ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')
_TOOLCHAIN_INSTALL_SUFFIXES = (
    '.rustup/toolchains', '.nvm/versions/node', '.pyenv/versions', '.local/share/uv/python',
    '.asdf/installs/python', '.asdf/installs/nodejs', '.asdf/installs/ruby', '.asdf/installs/golang', '.asdf/installs/java',
)
_KNOWN_STRUCTURED_NAMES = frozenset({
    'config.yaml', 'config.yml', 'config.json', 'plugin.yaml', 'plugin.yml',
    'plugin.json', 'manifest.json', 'package.json', 'hooks.json', 'settings.json',
    'tsconfig.json', 'package-lock.json', 'composer.lock', 'template.yaml',
    'template.yml', 'provenance.json', '.pre-commit-config.yaml',
})
_PARENT_CONTEXT_FILES = (
    'AGENTS.md', 'agents.md', 'AGENTS.override.md', '.hermes.md', 'HERMES.md', 'CLAUDE.md', 'claude.md',
    '.cursorrules', '.envrc', '.tool-versions', 'pyproject.toml', 'package.json', 'Cargo.toml', 'pnpm-workspace.yaml',
)
_SIBLING_MANIFEST_NAMES = frozenset({'HOOK.yaml', 'HOOK.yml', 'plugin.yaml', 'plugin.yml', 'plugin.json', 'manifest.json', 'mcp.json', '__init__.py'})
_GIT_SECTION_PATTERN = re.compile(rb'(?mi)^\s*\[(?:core|include|includeif|remote|alias|filter|credential)(?:\s|\])')
_DB_SUFFIXES = frozenset({'.db', '.sqlite', '.sqlite3'})


def _credential(path):
    return credential_file_kind(path) is not None or credential_candidate(path) or credential_path(path)


def _is_text(data):
    if b'\x00' in data:
        return False
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        return False
    return True


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _under(path, root) -> bool:
    # Same answer as PurePath.is_relative_to for absolute normalized paths, without
    # building a Path per ancestor (that dominated the walk on deep trees).
    path, root = str(path), str(root)
    return path == root or path.startswith(root if root.endswith('/') else root + '/')


def _within_any(path: Path, roots) -> bool:
    return any(_under(path, r) for r in roots)


def _resolve_target(raw: str, home: Path, base: Path) -> Path:
    target = home / raw[2:] if raw.startswith('~/') else Path(raw)
    return _absolute(target if target.is_absolute() else base / target)


def _extract_commands(value, parent_key=None):
    # Commands are captured before argument redaction, but only as typed
    # ephemeral evidence. The serializer emits no raw argv strings.
    if isinstance(value, dict):
        command = value.get('command')
        if isinstance(command, str) and isinstance(value.get('args'), list):
            yield shlex.join([command, *[arg for arg in value['args'] if isinstance(arg, str)]])
        for name, item in value.items():
            if not (name == 'command' and isinstance(command, str) and isinstance(value.get('args'), list)):
                yield from _extract_commands(item, name if name in _EXTRACTED_COMMAND_KEYS else parent_key)
    elif isinstance(value, list):
        for item in value:
            yield from _extract_commands(item, parent_key)
    elif isinstance(value, str) and parent_key in _EXTRACTED_COMMAND_KEYS:
        yield value


def _extract_sibling_declarations(value, section=None):
    if isinstance(value, dict):
        for name, item in value.items():
            if credential_key_kind(name) or name == 'env':
                continue
            current = name if section is None else section
            if name in _SIBLING_DECLARATION_KEYS:
                for raw in _as_list(item):
                    if isinstance(raw, str):
                        yield current, raw
            else:
                yield from _extract_sibling_declarations(item, current)
    elif isinstance(value, list):
        for item in value:
            yield from _extract_sibling_declarations(item, section)


def _initial_result(entry_limit, parse_limit, byte_limit, unbounded, unselected, report_store):
    return {
        'regions': {
            r: {'coverage': 'verified', 'reasons': [],
                'scope': 'active profile, selected projects, evidenced outgoing paths',
                'limitations': ['Program behavior cannot be verified: code correctness and safety are outside static inventory.']}
            for r in REGIONS
        },
        'blending': [], 'credentials': [], 'dynamic_invocations': [],
        'session_history': {'records_inspected': 0, 'selected_project_records': 0, 'newest_selected_timestamp': None},
        'limits': {
            'execution': 'never', 'meaning': 'static inspection only; not runtime safety',
            'max_entries': entry_limit, 'max_depth': None if unbounded else MAX_DEPTH,
            'max_file_bytes': parse_limit, 'max_total_bytes': byte_limit,
            'unbounded': unbounded, 'regions': {},
            'max_edges': None if unbounded else MAX_EDGES, 'max_invocations': None if unbounded else MAX_INVOCATIONS,
            'entries_inspected': 0, 'bytes_read': 0,
            'unrelated_siblings': 'top-level metadata and config declarations only',
            'unselected_project_roots': sorted(str(p) for p in unselected),
            'yaml_nodes': None if unbounded else 10000, 'yaml_depth': None if unbounded else 64,
            'session_rows': None if unbounded else 10000,
            'report_store_exclusions': [str(p) for p in report_store],
            'git_discovery': {
                'max_configs': None if unbounded else 128, 'max_depth': None if unbounded else 32,
                'max_file_bytes': None if unbounded else 1048576, 'max_edges': None if unbounded else 256,
                'scope': 'Git pointers/config/includes/hooks; object stores not traversed by Git-context edges',
            },
            'credential_scope': 'lstat metadata only; credential stores never opened',
        },
    }


@redaction_scope
def collect_outward(profile_dir: Path, selected_projects: list[str], *, excluded_paths=(), report_store_paths=(), cancelled=None, unselected_project_roots=(), max_entries=None, max_bytes=None, max_file_bytes=None, unbounded=False):
    """Collect static metadata without executing/importing any inspected code.

    ``verified`` requires positive static classification within the declared scope,
    including metadata-only credentials. Unknown executable/config semantics fail closed. Sibling/other-project coverage is *outgoing references only*, not
    a claim those unrelated trees were examined or runtime isolation is proven.
    """
    if type(unbounded) is not bool:
        raise ValueError('unbounded must be boolean')
    for value in (max_entries, max_bytes, max_file_bytes):
        if value is not None and (type(value) is not int or value <= 0):
            raise ValueError('audit budgets must be positive integers')
    entry_limit = None if unbounded else (max_entries or MAX_ENTRIES)
    byte_limit = None if unbounded else (max_bytes or MAX_TOTAL_BYTES)
    parse_limit = None if unbounded else (max_file_bytes or MAX_FILE_BYTES)
    profile = _absolute(profile_dir)
    excluded = tuple(_absolute(p) for p in excluded_paths)
    report_store = tuple(_absolute(p) for p in report_store_paths)
    blocked_paths = excluded + report_store
    unselected = {_absolute(p) for p in unselected_project_roots}
    result = _initial_result(entry_limit, parse_limit, byte_limit, unbounded, unselected, report_store)

    key = secrets.token_bytes(32)
    seen, sensitive_paths, processed_content, classification_conflicts = set(), set(), set(), set()
    credential_references, hardlinks, package_names, workspace_members = {}, {}, {}, {}
    workspace_dependencies, ci_templates, outgoing_targets, registered_folders = [], set(), set(), set()
    budget, reason_index, cut_index, edge_index, invocation_index = {}, {}, set(), {}, {}
    tree_stack, venv_roots, referenced_used = [], [], [0.0]
    tree_entry_limit = None if unbounded else MAX_TREE_ENTRIES
    tree_byte_limit = None if unbounded else MAX_TREE_BYTES
    tree_seconds = None if unbounded else MAX_TREE_SECONDS
    referenced_seconds = None if unbounded else MAX_REFERENCED_SECONDS
    outside_file_limit = None if unbounded else MAX_OUTSIDE_FILE_BYTES
    result['limits']['max_seconds'] = referenced_seconds
    result['limits']['trees'] = {'max_tree_entries': tree_entry_limit, 'max_bytes': tree_byte_limit,
                                 'max_seconds': tree_seconds, 'max_file_bytes': outside_file_limit}
    current_path = profile
    projects = tuple(_absolute(p) for p in selected_projects)
    default_profile = profile.parent.parent if profile.parent.name == 'profiles' else profile
    home = profile.parent.parent.parent if profile.parent.name == 'profiles' else profile.parent
    region_folders = tuple((profile / folder, region) for folder, region in _PROFILE_REGION_FOLDERS)
    root_keys = {}

    def spellings(name, roots):
        # Project roots as written and as resolved, with their (device, inode): a projects
        # folder reached through a link spells each project two ways (facts.py helpers).
        # Shown paths stay as written; only comparisons use these. The sets only grow.
        cached = root_keys.get(name)
        if cached is None or cached[0] != len(roots):
            real_paths, identities, _ = _registered_folder_keys(str(p) for p in roots)
            cached = root_keys[name] = (len(roots), tuple(Path(p) for p in sorted(real_paths)), identities)
        return cached[1], cached[2]

    def selected_roots():
        return spellings('selected', projects)[0]

    def project_roots():
        return selected_roots() + spellings('registered', registered_folders)[0]

    def unselected_roots():
        return spellings('unselected', unselected)[0]

    def owner(path):
        path = _absolute(path)
        if _within_any(path, project_roots()):
            return 'project_tree'
        if _within_any(path, unselected_roots()):
            return 'other_projects'
        if profile != default_profile and (path == default_profile / 'config.yaml' or _under(path, default_profile / 'profiles') and not _under(path, profile)):
            return 'sibling_profiles'
        for folder, region in region_folders:
            if _under(path, folder):
                return region
        if path == profile / 'state.db' or path.name.startswith('state.db-') and path.parent == profile:
            return 'session_history'
        return 'active_profile' if _under(path, profile) else 'shared_infrastructure'

    def in_subject(path):
        return _within_any(path, (home, *project_roots()))

    def regions_within(root):
        # Every region that a cut tree may hold, so an unwalked part is never reported verified.
        regions = [owner(root)]
        regions += [region for folder, region in region_folders if _under(folder, root)]
        if _under(profile / 'state.db', root):
            regions.append('session_history')
        if any(_under(p, root) for p in project_roots()):
            regions.append('project_tree')
        return tuple(dict.fromkeys(regions))

    state = _CURRENT.get()
    if state is not None:
        state.owner = owner

    def start_budget(name):
        nonlocal budget
        budget = {'entries_inspected': 0, 'bytes_read': 0, 'stream_hashed_files': 0,
                  'max_entries': entry_limit, 'max_bytes': byte_limit,
                  'max_file_bytes': parse_limit, 'cuts': [], 'name': name,
                  'pruned_roots': {'count': 0, 'samples': []}, 'trees': []}
        result['limits']['regions'][name] = budget

    def record_entry_inspected():
        budget['entries_inspected'] += 1
        result['limits']['entries_inspected'] += 1

    def record_bytes_read(count):
        budget['bytes_read'] += count
        result['limits']['bytes_read'] += count

    def mark_sensitive_target(target):
        if target not in sensitive_paths:
            if str(target) in processed_content:
                classification_conflicts.add(target)
            seen.discard(str(target))
            sensitive_paths.add(target)
        declare_credential(target)

    def unknown(reason, regions=None):
        code = reason.split(':', 1)[0]
        # Decide from the fixed code only: the text after it may be a path holding any word.
        if budget and ('limit' in code or 'truncated' in code or 'excluded' in code or code == 'time_budget'):
            token = (budget['name'], code)
            if token not in cut_index:
                cut_index.add(token)
                budget['cuts'].append(Evidence(reason, path=str(current_path)))
        for region in regions or (owner(current_path),):
            record = result['regions'][region]
            record['coverage'] = 'could_not_verify'
            token = (region, code)
            if token not in reason_index:
                record['reasons'].append(Evidence(reason, path=str(current_path)))
                detail = {'code': code, 'count': 0, 'samples': []}
                record.setdefault('reason_details', []).append(detail)
                reason_index[token] = detail
            detail = reason_index[token]
            detail['count'] += 1
            if len(detail['samples']) < 3:
                detail['samples'].append(Evidence(reason, path=str(current_path)))

    def edge(source, target, relationship, depth, *, follow=True):
        if extraction(str(target)) is None:
            return
        target = _absolute(target)
        if relationship == 'workspace_folder':
            workspace_members.setdefault(source.parent, set()).add(target)
        if relationship != 'parent_context':
            outgoing_targets.add(target)
        group = (str(source.parent), str(target.parent), relationship) if relationship == 'symlink' else (str(source), str(target), relationship)
        existing = edge_index.get(group)
        if existing is None and not unbounded and len(result['blending']) >= MAX_EDGES:
            unknown('outgoing_edge_report_limit_exceeded', (owner(source),))
            if follow:
                visit(target, depth + 1, explicit=True, referenced=True)
            return
        if relationship not in {'execution_path', 'incoming_execution_reference'} and (_credential(source) or source in sensitive_paths):
            if target not in sensitive_paths:
                mark_sensitive_target(target)
        if existing is None:
            existing = {'source': str(source), 'target': str(target), 'count': 0,
                        'relationship': relationship, 'sample_paths': [],
                        'target_root': str(target.parent),
                        'evidence': {'path': str(source), 'kind': relationship,
                                     'inspection': 'target_static' if follow else 'declaration_or_metadata_only'}}
            edge_index[group] = existing
            result['blending'].append(existing)
        existing['count'] += 1
        if relationship == 'symlink':
            if (str(source), str(target)) < (existing['source'], existing['target']):
                existing['source'], existing['target'] = str(source), str(target)
                existing['evidence']['path'] = str(source)
            existing['sample_paths'] = sorted(existing['sample_paths'] + [str(source)])[:3]
        elif len(existing['sample_paths']) < 3:
            existing['sample_paths'].append(str(source))
        if follow:
            visit(target, depth + 1, explicit=True, referenced=True)

    def expand_glob_reference(source, target, relationship, depth):
        pending = [(Path('/'), target.parts[1:])]
        scanned = 0
        while pending:
            base, parts = pending.pop()
            if not parts:
                edge(source, base, relationship, depth)
                continue
            part, rest = parts[0], parts[1:]
            if not any(c in part for c in '*?['):
                pending.append((base / part, rest))
                continue
            if part == '**':
                pending.append((base, rest))
            try:
                with _directory_fd(base) as fd:
                    with os.scandir(fd) as entries:
                        for entry in entries:
                            scanned += 1
                            if not unbounded and scanned > 10000:
                                unknown('glob_entry_limit_exceeded: ' + str(source))
                                return
                            if part == '**':
                                if entry.is_dir(follow_symlinks=False):
                                    pending.append((base / entry.name, parts))
                            elif fnmatch.fnmatchcase(entry.name, part):
                                pending.append((base / entry.name, rest))
            except FileNotFoundError:
                pass
            except OSError:
                unknown('glob_inspection_failed: ' + str(source))

    def referenced_path(source, raw, relationship, depth, config_key=None, base_dir=None):
        if extraction(raw) is None:
            return
        if not isinstance(raw, str) or not raw.strip():
            unknown('invalid_path_reference: ' + str(source))
            return
        if '$' in raw or '\x00' in raw or '\n' in raw:
            unknown('unresolved_path_reference: ' + str(source), ('skills',) if relationship == 'external_skill_root' else None)
            return
        target = _resolve_target(raw, home, base_dir or source.parent)
        credential_key = config_key in ('env_file', 'credential_file', 'credentials_file')
        if credential_key and not declaration_source(source):
            return
        if config_key and not declaration_source(target) and (_credential(target) or credential_key):
            mark_sensitive_target(target)
            credential_references.setdefault(str(target), set()).add(config_key)
        if any(c in str(target) for c in '*?['):
            expand_glob_reference(source, target, relationship, depth)
            return
        edge(source, target, relationship, depth)

    load_roots = {}

    def code_load_root(path):
        for folder in ('plugins', 'skills'):
            container = profile / folder
            if _under(path, container):
                parts = path.relative_to(container).parts
                return container / parts[0] if len(parts) > 1 else container
        if path.parent in load_roots:
            return load_roots[path.parent] or path
        boundary = next((p for p in (*projects, profile) if _under(path, p)), path.parent)
        root = None
        for parent in (path.parent, *path.parent.parents):
            if not _under(parent, boundary):
                break
            try:
                with _directory_fd(parent) as fd:
                    for name in _LOAD_ROOT_MARKERS:
                        try:
                            if stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
                                root = parent
                                break
                        except FileNotFoundError:
                            pass
            except OSError:
                break
            if root:
                break
        load_roots[path.parent] = root
        return root or path

    def dynamic(path, kind, line=None):
        root = code_load_root(path) if kind == 'program_code' else path
        token = (str(root), kind == 'program_code')
        existing = invocation_index.get(token)
        if existing is not None:
            if kind == 'program_code':
                existing['file_count'] += 1
                if len(existing['samples']) < 5:
                    existing['samples'].append(str(path))
            elif kind not in existing['kinds']:
                existing['kinds'].append(kind)
                if kind != 'execution_surface':
                    existing['kind'] = kind
            return existing
        budget_root = next(('project:' + str(p) for p in projects if _under(path, p)), owner(path))
        counts = result['limits'].setdefault('invocation_roots', {}).setdefault(
            budget_root, {'admitted': 0, 'cuts': 0, 'max_invocations': None if unbounded else MAX_INVOCATIONS})
        if not unbounded and counts['admitted'] >= MAX_INVOCATIONS:
            counts['cuts'] += 1
            unknown('invocation_limit_exceeded: ' + str(root), (owner(path),))
            return
        record = {'path': str(path), 'kind': kind, 'kinds': [kind], 'line': line, 'resolution': 'enumerated',
                  'trigger': execution_trigger(path) or 'configured or implicit execution',
                  'what_runs': 'code or declaration in this file; behavior not evaluated'}
        if kind == 'program_code':
            record.update(load_root=str(root), file_count=1, samples=[str(path)],
                          what_runs='program-code inventory for load root; behavior not evaluated')
        invocation_index[token] = record
        counts['admitted'] += 1
        result['dynamic_invocations'].append(record)
        return record

    def inspect_package_and_ts_config(path, config, depth):
        if path.name == 'package.json':
            if isinstance(config.get('name'), str):
                package_names[path.parent] = config['name']
            for section in _PACKAGE_DEPENDENCY_SECTIONS:
                values = config.get(section, {})
                if not isinstance(values, dict):
                    unknown('dependency_mapping_unclassified: ' + str(path))
                    continue
                for dependency, raw in values.items():
                    if isinstance(raw, str) and raw.startswith(('file:', 'link:', 'workspace:')):
                        value = raw.split(':', 1)[1]
                        if raw.startswith('workspace:') and not value.startswith(('.', '/', '~')):
                            workspace_dependencies.append((path, dependency, value))
                        else:
                            referenced_path(path, value, 'local_dependency', depth)
        if path.name in {'package.json', 'pnpm-workspace.yaml'}:
            if path.name == 'pnpm-workspace.yaml' or 'workspaces' in config:
                workspace_members.setdefault(path.parent, set())
            entries = config.get('packages' if path.name == 'pnpm-workspace.yaml' else 'workspaces', [])
            if isinstance(entries, dict):
                entries = entries.get('packages', [])
            for raw in _as_list(entries):
                referenced_path(path, raw, 'workspace_folder', depth)
        if path.name.startswith('tsconfig') and 'extends' in config:
            for raw in _as_list(config['extends']):
                if isinstance(raw, str) and raw.startswith(('.', '/')):
                    referenced_path(path, raw, 'typescript_extends', depth)
                else:
                    unknown('typescript_extends_unresolved: ' + str(path))
        options = config.get('compilerOptions', {})
        if isinstance(options, dict):
            mappings, base_url = options.get('paths', {}), options.get('baseUrl', '.')
            if isinstance(mappings, dict) and isinstance(base_url, str):
                for values in mappings.values():
                    for raw in _as_list(values):
                        referenced_path(path, raw, 'typescript_path', depth, base_dir=path.parent / base_url)

    def inspect_config(path, data, info, depth):
        observe(path, data)
        try:
            config = json.loads(data) if path.suffix == '.json' else _parse_simple_yaml_mapping(data.decode('utf-8'), unbounded=unbounded)
            if not isinstance(config, dict):
                raise ValueError('config must be mapping')
        except (ValueError, ImportError, UnicodeError, RecursionError):
            unknown('config_parse_failed: ' + str(path))
            return
        skills = config.get('skills', {})
        if isinstance(skills, dict):
            for name in ('create_dir', 'external_dirs'):
                for raw in _as_list(skills.get(name, [])):
                    referenced_path(path, raw, 'external_skill_root', depth)

        def safe_key(name):
            return name if name in _SAFE_CONFIG_KEYS else 'key-hmac:' + hmac.new(key, str(name).encode(), hashlib.sha256).hexdigest()

        def walk(value, key_path=()):
            if isinstance(value, dict):
                for name, item in value.items():
                    if name in _COMMAND_KEYS and item:
                        dynamic(path, 'configured_command_unresolved')
                    if (credential_key_kind(name) and name not in {'credential_file', 'credentials_file'}) or ('env' in key_path and any(k in key_path for k in ('mcp_servers', 'providers'))):
                        result['credentials'].append({
                            'path': str(path), 'exists': True, 'permissions': stat.S_IMODE(info.st_mode),
                            'config_keys': [safe_key(name)], 'key_path': [safe_key(k) for k in key_path + (name,)],
                            'fingerprint_kind': 'hmac-sha256-per-run',
                            'fingerprint': generated_digest(hmac.new(key, json.dumps(item).encode(), hashlib.sha256).hexdigest()),
                        })
                        continue
                    if 'mcp_servers' in key_path and name in {'command', 'args'}:
                        for raw in _as_list(item):
                            if isinstance(raw, str) and raw.startswith(('/', './', '../', '~/')):
                                referenced_path(path, raw, 'mcp_command_path', depth)
                            elif name == 'command' or isinstance(raw, str) and ('$' in raw or '/' in raw):
                                unknown('mcp_command_path_unresolved: ' + str(path))
                    if name == 'template' and (path.name in {'azure-pipelines.yml', 'azure-pipelines.yaml'} or path in ci_templates):
                        if isinstance(item, str) and not any(c in item for c in '@${}'):
                            target = _absolute(path.parent / item)
                            ci_templates.add(target)
                            dynamic(target, 'ci_template')
                            referenced_path(path, item, 'ci_template', depth)
                        else:
                            unknown('ci_template_unresolved: ' + str(path))
                    if name in {'extend', 'extends'} and not path.name.startswith('tsconfig'):
                        for raw in _as_list(item):
                            if isinstance(raw, str) and raw.startswith(('.', '/', '~/')):
                                referenced_path(path, raw, 'config_inheritance', depth)
                            else:
                                unknown('config_inheritance_unresolved: ' + str(path))
                    if name in _PATH_CONFIG_KEYS and not (name == 'paths' and isinstance(item, dict)):
                        for raw in _as_list(item):
                            referenced_path(path, raw, 'configured_path', depth, config_key=name)
                    walk(item, key_path + (name,))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    walk(item, key_path + (str(index),))

        text_decoded = data.decode('utf-8', errors='replace')
        for command in _extract_commands(config):
            invocation = dynamic(path, 'configured_command_unresolved')
            if invocation is not None:
                offset = text_decoded.find(json.dumps(command)[1:-1])
                line = data[:offset].count(b'\n') + 1 if offset >= 0 else None
                invocation.setdefault('commands', []).append(Evidence(command, 'command', str(path), line))
        config = safe_config(config)
        walk(config)
        inspect_package_and_ts_config(path, config, depth)

    def session_in_project(raw):
        # A session folder started through a linked spelling still belongs to its project:
        # compare as written first, then resolved (metadata only, never opened or walked).
        candidate = _absolute(raw)
        if _within_any(candidate, selected_roots()):
            return True
        try:
            real = Path(os.path.realpath(candidate))
        except (OSError, ValueError):
            return False
        return real != candidate and _within_any(real, selected_roots())

    def session_record(record):
        observe_value(record)
        if not isinstance(record, dict):
            unknown('unsupported_session_record', ('session_history',))
            return
        summary = result['session_history']
        summary['records_inspected'] += 1
        associated = any(
            isinstance(record.get(name), str) and session_in_project(record[name])
            for name in ('cwd', 'project_path', 'working_directory')
        ) or any(record.get('git_repo_root') == str(project) for project in projects) or (
            isinstance(record.get('git_repo_root'), str) and os.path.isabs(record['git_repo_root'])
            and _is_registered_folder(record['git_repo_root'], {str(p) for p in selected_roots()},
                                      spellings('selected', projects)[1]))
        if associated:
            summary['selected_project_records'] += 1
            stamp = record.get('started_at') or record.get('timestamp')
            if type(stamp) in (int, float):
                summary['newest_selected_timestamp'] = max(stamp, summary['newest_selected_timestamp'] or stamp)

    def inspect_session_db(path, parent_fd, info):
        def account(size):
            if byte_limit is not None and budget['bytes_read'] + size > byte_limit:
                unknown('database_byte_limit_exceeded: ' + str(path), (owner(path), 'cross_project_isolation'))
                raise SnapshotError('database_byte_limit_exceeded')
            record_bytes_read(size)

        report = inspect_database(path, parent_fd=parent_fd, expected_stat=info,
                                  unbounded=unbounded, selected_projects=selected_projects, account=account, cancelled=cancelled)
        report['limits']['schema'] = report['schema']
        report['limits']['changed_during_read'] = report['changed_during_read']
        report['limits']['association_scope'] = 'path metadata only; historical association does not authorize traversal'
        result['limits'].setdefault('databases', {})[str(path)] = report['limits']
        for issue in report['uncertainties']:
            unknown(issue['reason'] + ': ' + str(path), (owner(path), 'cross_project_isolation'))
        for record in report['records']:
            if record['table'] == 'sessions':
                session_record(record)
        for reference in report.get('folder_references', []):
            target = _absolute(reference['path'])
            registered_folders.add(target)
            edge(path, target, 'registered_project_folder', 0)
        for association in report.get('associations', []):
            if association['table'] in {'projects', 'project_folders'}:
                raw = association.get('primary_path') or association.get('path')
                if isinstance(raw, str) and os.path.isabs(raw):
                    unselected.add(_absolute(raw))
            safe_association = {
                (name[:-7] + '_hmac' if name.endswith('_sha256') else name):
                (hmac.new(key, value.encode(), hashlib.sha256).hexdigest()
                 if name.endswith('_sha256') and value is not None else value)
                for name, value in association.items()
            }
            result.setdefault('database_records', []).append(dict(database=str(path), **safe_association))
            if association['table'] == 'tasks':
                raw = association.get('workspace_path')
                if isinstance(raw, str) and os.path.isabs(raw):
                    target = _absolute(raw)
                    edge(path, target, 'kanban_task_workspace', 0, follow=_within_any(target, project_roots()))
                else:
                    unknown('kanban_task_workspace_unresolved: ' + str(path), (owner(path),))
        result.setdefault('database_associations', []).append({
            'path': str(path), 'schema': report['schema'], 'records_inspected': report['limits']['rows_inspected']})

    tool_inventory = None
    git_contexts = []

    def populate_tool_inventory():
        inventory = set()
        for suffix in _TOOLCHAIN_INSTALL_SUFFIXES:
            root = home / suffix
            try:
                with _directory_fd(root) as fd:
                    with os.scandir(fd) as entries:
                        for index, entry in enumerate(entries):
                            if not unbounded and index >= 10000:
                                unknown('toolchain_inventory_limit_exceeded', ('shared_infrastructure',))
                                break
                            if entry.is_dir(follow_symlinks=False):
                                target = root / entry.name
                                inventory.add(target)
                                with _directory_fd(target) as install_fd:
                                    try:
                                        if stat.S_ISDIR(os.stat('bin', dir_fd=install_fd, follow_symlinks=False).st_mode):
                                            inventory.add(target / 'bin')
                                    except FileNotFoundError:
                                        pass
            except FileNotFoundError:
                pass
            except OSError:
                unknown('toolchain_inventory_unreadable: ' + str(root), ('shared_infrastructure',))
        return inventory

    def inspect_toolchain(path, data, depth):
        nonlocal tool_inventory
        if path.name not in TOOLCHAIN_FILES:
            return
        if tool_inventory is None:
            tool_inventory = populate_tool_inventory()
        for reference in resolve_toolchain(path, data, home=home, available_paths=tool_inventory):
            if reference['resolution'] != 'resolved':
                unknown('toolchain_unresolved: ' + str(path), ('shared_infrastructure', 'cross_project_isolation'))
            else:
                target = Path(reference['target'])
                try:
                    with _directory_fd(target) as fd:
                        metadata = os.fstat(fd)
                    previous_count = len(result['blending'])
                    edge(path, target, 'toolchain_metadata', depth, follow=False)
                    if len(result['blending']) > previous_count:
                        result['blending'][-1]['evidence'].update(
                            permissions=oct(stat.S_IMODE(metadata.st_mode)), inspection='directory_metadata_only')
                except OSError:
                    unknown('toolchain_metadata_unreadable: ' + str(path), ('shared_infrastructure',))

    def inspect_literal_paths(path, data, depth, *, credentials=False):
        trigger = execution_trigger(path)
        for raw, line in path_references(path, data, credentials=credentials):
            target = _resolve_target(raw, home, path.parent)
            containing = next((p for p in (*projects, profile) if _under(path, p)), path.parent)
            if not credentials and _under(target, containing) and owner(target) == owner(path):
                continue
            if not trigger:
                if not any(_under(target, root) for root in (home, *unselected_roots())):
                    continue
                if not (target.exists() or target.is_symlink()):
                    if any(_under(target, root) for root in unselected_roots()):
                        edge(path, target, 'literal_path', depth, follow=False)
                    continue
            relationship = 'execution_path' if trigger else 'literal_path'
            edge(path, target, relationship, depth)
            record = edge_index.get((str(path), str(target), relationship))
            if record:
                record['evidence']['line'] = line

    def inspect_content(path, data, info, depth):
        inspect_toolchain(path, data, depth)
        file_type = 'execution_surface' if path in ci_templates else classify_file(path, data)
        is_history = path.is_relative_to(profile / 'sessions')
        suffix_low = path.suffix.lower()
        if not is_history and (file_type in {'program_code', 'execution_surface'} or suffix_low in {'.md', '.mdc', '.rst', '.txt'}):
            inspect_literal_paths(path, data, depth)
        git_role = any(c.config_kind(path) or c.hook_kind(path) for c in git_contexts)
        if file_type == 'unknown' and not git_role and not (is_history and path.suffix in {'.json', '.jsonl'}):
            unknown('unknown_file_type: ' + str(path))
        if file_type in {'execution_surface', 'program_code'}:
            dynamic(path, file_type)
        for context in git_contexts:
            if kind := context.hook_kind(path):
                dynamic(path, kind)
        git_config = any(context.config_kind(path) for context in git_contexts) or (
            suffix_low not in {'.toml', '.ini', '.cfg', '.txt'} and bool(_GIT_SECTION_PATTERN.search(data)))
        if git_config:
            git_cls = classify_git_config(data)
            if git_cls.status == 'dynamic':
                dynamic(path, 'git_config_execution_unresolved')
            elif git_cls.status != 'inert':
                unknown('git_config_unclassified: ' + str(path))
        if path.name == 'config' and path.parent.name == '.git':
            try:
                config = configparser.ConfigParser(interpolation=None, strict=False)
                config.read_string(data.decode('utf-8'))
                if raw := config.get('core', 'hookspath', fallback=None):
                    referenced_path(path, raw, 'git_hooks_path', depth, base_dir=path.parent.parent)
            except (ValueError, UnicodeError, configparser.Error):
                unknown('git_config_parse_failed: ' + str(path), ('dynamic_execution', 'cross_project_isolation'))
        if path.name.endswith(('-wal', '-journal')):
            unknown('database_journal_requires_live_snapshot: ' + str(path), ('session_history', 'cross_project_isolation'))
        elif suffix_low in _DB_SUFFIXES:
            unknown('unclassified_database_semantics: ' + str(path), ('session_history', 'cross_project_isolation'))
        elif path.name == 'go.mod':
            for line in data.decode('utf-8', errors='replace').splitlines():
                if '=>' in line:
                    raw = line.split('=>', 1)[1].split('//', 1)[0].strip().strip('"')
                    if raw.startswith(('./', '../', '/')):
                        referenced_path(path, raw, 'go_replace', depth)
                    else:
                        unknown('go_replace_unresolved: ' + str(path))
            unknown('go_module_semantics_unclassified: ' + str(path))
        elif path.suffix == '.code-workspace':
            try:
                for document in parse_data(path, data, unbounded=unbounded):
                    inspect_config(path, json.dumps(document).encode(), info, depth)
            except (ValueError, UnicodeError, RecursionError):
                unknown('workspace_parse_failed: ' + str(path))
        elif path.suffix == '.toml':
            try:
                inspect_config(path, json.dumps(tomllib.loads(data.decode('utf-8'))).encode(), info, depth)
            except (ValueError, UnicodeError, TypeError, RecursionError):
                unknown('toml_parse_failed: ' + str(path))
        elif is_history and path.suffix in ('.json', '.jsonl'):
            try:
                for line in (data.splitlines() if path.suffix == '.jsonl' else [data]):
                    if line.strip():
                        session_record(json.loads(line))
            except (ValueError, RecursionError):
                unknown('session_parse_failed: ' + str(path), ('session_history',))
        elif path.suffix == '.jsonl':
            unknown('unclassified_jsonl_semantics: ' + str(path))
        elif path.suffix in {'.yaml', '.yml', '.json', '.jsonc'} and path.name != 'direct_url.json':
            if kind := classification(path):
                try:
                    documents = parse_data(path, data, unbounded=unbounded)
                    if kind in {'jsonc_config', 'jsonc_data'} or path.name == 'pnpm-workspace.yaml':
                        for document in documents:
                            inspect_config(path, json.dumps(document).encode(), info, depth)
                except (ValueError, UnicodeError, RecursionError):
                    unknown('structured_data_parse_failed: ' + str(path))
                return
            if (file_type == 'unknown' and path.name not in _KNOWN_STRUCTURED_NAMES
                    and not (path.name.startswith('tsconfig.') or '.github' in path.parts and 'workflows' in path.parts)):
                unknown('unclassified_structured_file: ' + str(path))
            inspect_config(path, data, info, depth)
        elif path.suffix == '.egg-link':
            try:
                referenced_path(path, data.decode('utf-8').splitlines()[0], 'editable_install', depth)
            except (UnicodeError, IndexError):
                unknown('editable_install_parse_failed: ' + str(path))
        elif path.name == 'direct_url.json':
            try:
                record = json.loads(data)
                if record.get('dir_info', {}).get('editable'):
                    url = urlsplit(record['url'])
                    if url.scheme == 'file' and not url.netloc and not url.query and not url.fragment:
                        referenced_path(path, unquote(url.path), 'editable_install', depth)
                    else:
                        unknown('editable_install_url_unresolved: ' + str(path))
            except (ValueError, KeyError, TypeError, AttributeError):
                unknown('editable_install_parse_failed: ' + str(path))
        elif path.suffix == '.pth':
            try:
                for number, line in enumerate(data.decode('utf-8').splitlines(), 1):
                    if line.startswith(('import ', 'import\t')):
                        dynamic(path, 'pth_execution_unresolved', number)
                    elif line.strip() and not line.startswith('#'):
                        referenced_path(path, line, 'editable_install', depth)
            except UnicodeError:
                unknown('pth_parse_failed: ' + str(path))

    def _regular(name, fd):
        try:
            return stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode)
        except OSError:
            return False

    def _exists(name, fd, kind=None):
        try:
            mode = os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode
        except OSError:
            return False
        return kind is None or kind(mode)

    def skip_kind(path, fd, parent_fd):
        # Declared scope rule, see SKIPPED_FOLDER_NAMES; only for folders reached by walking.
        if path.name in SKIPPED_FOLDER_NAMES:
            return 'skip'
        if path.name in _GIT_STORAGE_FOLDERS and (path.parent.name == '.git' or (
                _regular('HEAD', parent_fd) and _exists('refs', parent_fd, stat.S_ISDIR))):
            return 'skip'  # content-addressed Git storage: never config, hooks or text Git reads
        if _regular('CACHEDIR.TAG', fd):
            return 'skip'  # Cache Directory Tagging spec: regenerable (Cargo target/, tool caches)
        if _regular('pyvenv.cfg', fd):
            return 'venv'  # installed packages skipped; editable-install and .pth metadata kept
        return None

    def venv_kept(entry):
        if entry.is_dir(follow_symlinks=False):
            return entry.name in _VENV_KEPT_FOLDERS or entry.name.startswith('python') or entry.name.endswith('.dist-info')
        return entry.name.endswith(('.pth', '.egg-link')) or entry.name in ('direct_url.json', 'pyvenv.cfg')

    def prune(path):
        pruned = budget['pruned_roots']
        pruned['count'] += 1
        if len(pruned['samples']) < 3:
            pruned['samples'].append(str(path))
        # Not a cut, but not checked either: the owning region says so (docs/audit-scope.md,
        # "Explicit exclusions and inaccessible paths remain could_not_verify").
        unknown('skipped_folders: ' + str(path))

    def cut_tree(tree, code):
        if tree['truncated_by'] is None:
            tree['truncated_by'] = code
            budget['trees'].append(tree)
            unknown(code + ': ' + tree['path'], regions_within(Path(tree['path'])))

    def admit(path):
        if not tree_stack:
            return True
        tree, started = tree_stack[-1]
        if tree['truncated_by'] is not None:
            return False
        if tree_entry_limit is not None and tree['entries_walked'] >= tree_entry_limit:
            cut_tree(tree, 'entry_limit_exceeded')
            return False
        now = time.monotonic()
        if (tree_seconds is not None and now - started > tree_seconds
                or referenced_seconds is not None and referenced_used[0] + now - tree_stack[0][1] > referenced_seconds):
            cut_tree(tree, 'time_budget')
            return False
        tree['entries_walked'] += 1
        return True

    def credential_not_opened(path, info):
        # lstat/fstat metadata only: the store's content is never opened or read.
        result['credentials'].append({
            'kind': 'credential_store', 'path': str(path),
            'size': info.st_size, 'mode': stat.S_IMODE(info.st_mode), 'mtime': info.st_mtime})
        unknown('credential_store_not_opened: ' + str(path), ('credentials',))

    def visit(path, depth=0, explicit=False, parent_fd=None, referenced=False):
        nonlocal current_path
        previous, current_path = current_path, path
        try:
            return _visit(path, depth, explicit, parent_fd, referenced)
        finally:
            current_path = previous

    def admit_directory(path, explicit, parent_fd, referenced, fd):
        """Return None to stop traversal, or a bool to continue (True starts a tree)."""
        starts_tree = False
        if not unbounded:
            if not in_subject(path) and _within_any(path, SYSTEM_ROOTS):
                unknown('excluded: ' + str(path))
                return
            kind = None if explicit else skip_kind(path, fd, parent_fd)
            if kind == 'skip':
                prune(path)
                return
            if kind == 'venv':
                prune(path)
                venv_roots.append(path)
            starts_tree = (referenced and explicit) or (not explicit and _exists('.git', fd))
        if starts_tree:
            tree_stack.append(({'path': str(path), 'entries_walked': 1, 'bytes_read': 0, 'truncated_by': None,
                                'max_tree_entries': tree_entry_limit, 'max_bytes': tree_byte_limit,
                                'max_seconds': tree_seconds}, time.monotonic()))
        return starts_tree

    def _visit(path, depth=0, explicit=False, parent_fd=None, referenced=False):
        path = _absolute(path)
        if cancelled and cancelled():
            unknown('audit_cancelled')
            return
        if not explicit and (path == profile / 'profiles' or path in unselected or path in unselected_roots()) or path in report_store:
            return
        if _within_any(path, excluded):
            unknown('excluded_path: ' + str(path))
            return
        if not unbounded and depth > MAX_DEPTH:
            unknown('depth_limit_exceeded: ' + str(path))
            return
        if str(path) in seen:
            return
        if entry_limit is not None and budget['entries_inspected'] >= entry_limit:
            unknown('entry_limit_exceeded')
            return
        try:
            for ancestor in reversed(path.parents) if parent_fd is None else ():
                if ancestor.is_symlink():
                    target = Path(os.readlink(ancestor))
                    target = _absolute(target if target.is_absolute() else ancestor.parent / target)
                    edge(ancestor, target, 'symlink', depth, follow=False)
                    edge(path, target / path.relative_to(ancestor), 'symlink_suffix', depth)
                    return
            if parent_fd is None and path != Path('/'):
                with _directory_fd(path.parent) as anchored:
                    visit(path, depth, explicit, parent_fd=anchored, referenced=referenced)
                return
            if not admit(path):
                return
            seen.add(str(path))
            record_entry_inspected()
            info = os.stat(path.name or '/', dir_fd=parent_fd, follow_symlinks=False)
            declared = declared_credential(path)
            is_sensitive = _credential(path) or path in sensitive_paths
            if is_sensitive and (declared or not stat.S_ISDIR(info.st_mode)):
                credential_not_opened(path, info)
                return
            if stat.S_ISLNK(info.st_mode):
                target = Path(os.readlink(path.name, dir_fd=parent_fd))
                edge(path, _absolute(target if target.is_absolute() else path.parent / target), 'symlink', depth)
                return
            if stat.S_ISDIR(info.st_mode):
                if path == profile / 'profiles' and not explicit:
                    return
                if not explicit and _identity(info)[:2] in spellings('unselected', unselected)[1]:
                    return  # an unselected project under another spelling: never walked
                fd = os.open(path.name or '/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                try:
                    if _identity(os.fstat(fd)) != _identity(info):
                        unknown('directory_changed_during_inspection: ' + str(path))
                        return
                    starts_tree = admit_directory(path, explicit, parent_fd, referenced, fd)
                    if starts_tree is None:
                        return
                    in_venv = bool(venv_roots) and _within_any(path, venv_roots)
                    try:
                        with os.scandir(fd) as entries:
                            for entry in entries:
                                if cancelled and cancelled():
                                    unknown('audit_cancelled')
                                    break
                                if entry_limit is not None and budget['entries_inspected'] >= entry_limit:
                                    unknown('entry_limit_exceeded')
                                    break
                                if in_venv and not venv_kept(entry):
                                    continue
                                visit(path / entry.name, depth + 1, parent_fd=fd)
                    finally:
                        if starts_tree:
                            _, started = tree_stack.pop()
                            if not tree_stack:
                                referenced_used[0] += time.monotonic() - started
                    if _identity(os.fstat(fd)) != _identity(info):
                        unknown('directory_changed_during_inspection: ' + str(path))
                finally:
                    os.close(fd)
                return
            if not stat.S_ISREG(info.st_mode):
                unknown('non_regular_file_not_read: ' + str(path))
                return
            if info.st_nlink > 1:
                hardlinks.setdefault((info.st_dev, info.st_ino), {'count': info.st_nlink, 'paths': []})['paths'].append(path)
            if path.suffix.lower() in _DB_SUFFIXES and not is_sensitive:
                inspect_session_db(path, parent_fd, info)
                return
            if path.name.endswith(('-wal', '-shm', '-journal')) and Path(str(path).rsplit('-', 1)[0]).suffix.lower() in _DB_SUFFIXES:
                visit(Path(str(path).rsplit('-', 1)[0]), depth, explicit=True)
                return
            outside = not unbounded and not in_subject(path)
            if outside and info.st_size > outside_file_limit:
                unknown('file_byte_limit_exceeded: ' + str(path))
                return
            try:
                fd = open_checked(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd,
                                  full_path=str(path))
            except CredentialStoreNotOpened as refused:
                credential_not_opened(path, refused.info or info)
                return
            with os.fdopen(fd, 'rb') as stream:
                current = os.fstat(stream.fileno())
                if not stat.S_ISREG(current.st_mode) or _identity(current) != _identity(info):
                    unknown('file_changed_during_inspection: ' + str(path))
                    return
                if not is_sensitive and stream.read(16) == b'SQLite format 3\x00':
                    inspect_session_db(path, parent_fd, info)
                    return
                if byte_limit is not None and budget['bytes_read'] + info.st_size > byte_limit:
                    unknown('total_byte_limit_exceeded: ' + str(path))
                    return
                if tree_stack and tree_byte_limit is not None and tree_stack[-1][0]['bytes_read'] + min(
                        info.st_size, (parse_limit or info.st_size) + 1) > tree_byte_limit:
                    cut_tree(tree_stack[-1][0], 'total_byte_limit_exceeded')
                    return
                stream.seek(0)
                digest = hmac.new(key, digestmod=hashlib.sha256)
                captured, read = bytearray(), 0
                while chunk := stream.read(1024 * 1024):
                    read += len(chunk)
                    digest.update(chunk)
                    if parse_limit is None or len(captured) <= parse_limit:
                        captured.extend(chunk if parse_limit is None else chunk[:max(0, parse_limit + 1 - len(captured))])
                    if byte_limit is not None and budget['bytes_read'] + read > byte_limit:
                        unknown('read_byte_limit_exceeded: ' + str(path))
                        break
                    if tree_stack and parse_limit is not None and read > parse_limit:
                        break  # referenced tree: the part past the per-file cap is never parsed, so it is not read
                    if cancelled and cancelled():
                        unknown('audit_cancelled')
                        break
                record_bytes_read(read)
                if tree_stack:
                    tree_stack[-1][0]['bytes_read'] += read
                budget['stream_hashed_files'] += 1
                if _identity(current) != _identity(os.fstat(stream.fileno())):
                    unknown('file_changed_during_inspection: ' + str(path))
                    return
                data = bytes(captured)
            if outside and not _is_text(data):
                # Binary content outside the audited home: inventory only, never parsed or matched.
                processed_content.add(str(path))
                file_type = classify_file(path, data)
                if file_type in {'program_code', 'execution_surface'}:
                    dynamic(path, file_type)
                elif file_type == 'unknown':
                    unknown('unknown_file_type: ' + str(path))
                return
            observe(path, data)
            if parse_limit is not None and read > parse_limit:
                unknown('file_byte_limit_exceeded: ' + str(path))
                return
            processed_content.add(str(path))
            inspect_content(path, data, info, depth)
        except OSError as exc:
            unknown('inspection_failed:' + type(exc).__name__ + ': ' + str(path))

    def read_sibling_file(parent_dir: Path, filename: str, *, exceed_reason: str | None = None) -> bytes | None:
        with _directory_fd(parent_dir) as fd:
            try:
                opened = open_checked(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd,
                                      full_path=str(parent_dir / filename))
            except CredentialStoreNotOpened as refused:
                credential_not_opened(parent_dir / filename, refused.info or os.stat(filename, dir_fd=fd, follow_symlinks=False))
                return None
            with os.fdopen(opened, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('non regular file')
                remaining = byte_limit - budget['bytes_read'] if byte_limit is not None else None
                cap = min(v for v in (parse_limit, remaining, info.st_size) if v is not None)
                if info.st_size > cap:
                    if exceed_reason:
                        unknown(exceed_reason, ('sibling_profiles',))
                        return None
                    raise ValueError('exceeds budget')
                data = stream.read(cap + 1)
                record_bytes_read(len(data))
                if len(data) > cap or _identity(info) != _identity(os.fstat(stream.fileno())):
                    raise ValueError('file changed')
                return data

    def inspect_sibling(sibling, roots):
        if cancelled and cancelled():
            unknown('audit_cancelled', ('sibling_profiles',))
            return
        if _within_any(sibling, blocked_paths):
            unknown('sibling_declarations_excluded: ' + str(sibling), ('sibling_profiles',))
            return
        if _within_any(sibling / 'config.yaml', blocked_paths):
            unknown('sibling_config_excluded: ' + str(sibling), ('sibling_profiles',))
            return
        try:
            with _directory_fd(sibling) as sibling_fd:
                with os.scandir(sibling_fd) as entries:
                    for entry in entries:
                        if entry_limit is not None and budget['entries_inspected'] >= entry_limit:
                            unknown('sibling_entry_limit_exceeded', ('sibling_profiles',))
                            return
                        record_entry_inspected()
                        info = os.stat(entry.name, dir_fd=sibling_fd, follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode):
                            raw = Path(os.readlink(entry.name, dir_fd=sibling_fd))
                            target = _absolute(raw if raw.is_absolute() else sibling / raw)
                            if _within_any(target, roots):
                                edge(sibling / entry.name, target, 'incoming_sibling_symlink', 0, follow=False)
        except OSError:
            unknown('sibling_metadata_unreadable: ' + str(sibling), ('sibling_profiles',))

        relatives = {'.env', 'cron/jobs.json', 'mcp.json', 'hooks/HOOK.yaml', 'plugins/plugin.yaml'}
        pending = [(sibling / folder, 0) for folder in ('hooks', 'plugins')]
        while pending:
            directory, level = pending.pop()
            if _within_any(directory, blocked_paths):
                unknown('sibling_declarations_excluded: ' + str(directory), ('sibling_profiles',))
                continue
            try:
                with _directory_fd(directory) as fd:
                    with os.scandir(fd) as entries:
                        for entry in entries:
                            if entry_limit is not None and budget['entries_inspected'] >= entry_limit:
                                unknown('sibling_entry_limit_exceeded', ('sibling_profiles',))
                                pending.clear()
                                break
                            record_entry_inspected()
                            candidate = directory / entry.name
                            if entry.is_dir(follow_symlinks=False):
                                if level < 3 or unbounded:
                                    pending.append((candidate, level + 1))
                                else:
                                    unknown('sibling_declaration_depth_limit: ' + str(candidate), ('sibling_profiles',))
                            elif entry.name in _SIBLING_MANIFEST_NAMES:
                                relatives.add(str(candidate.relative_to(sibling)))
            except FileNotFoundError:
                pass
            except OSError:
                unknown('sibling_declarations_unreadable: ' + str(directory), ('sibling_profiles',))

        for relative in sorted(relatives):
            source = sibling / relative
            if _credential(source) or source in sensitive_paths:
                try:
                    source.lstat()
                except FileNotFoundError:
                    continue
                except OSError:
                    unknown('sibling_metadata_unreadable: ' + str(source), ('sibling_profiles',))
                    continue
                visit(source, explicit=True)
                continue
            if _within_any(source, blocked_paths):
                unknown('sibling_declarations_excluded: ' + str(source), ('sibling_profiles',))
                continue
            try:
                data = read_sibling_file(source.parent, source.name)
                if data is None:
                    continue  # a declared credential: recorded, never read
                for raw, line in path_references(source, data, credentials=relative == '.env', strict=True):
                    target = _resolve_target(raw, home, sibling)
                    if _within_any(target, roots):
                        edge(source, target, 'incoming_execution_reference', 0, follow=False)
                        dynamic(source, 'incoming_execution_surface', line)
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                unknown('sibling_declaration_parse_or_read_failed: ' + str(source), ('sibling_profiles',))

        source = sibling / 'config.yaml'
        if _credential(source):
            visit(source, explicit=True)
            return
        record_entry_inspected()
        try:
            data = read_sibling_file(sibling, 'config.yaml', exceed_reason='sibling_config_byte_limit_exceeded: ' + str(source))
            if data is None:
                return
            config = safe_config(_parse_simple_yaml_mapping(data.decode('utf-8'), unbounded=unbounded))
            for raw, line in path_references(source, data, strict=True):
                target = _resolve_target(raw, home, sibling)
                if _within_any(target, roots):
                    edge(source, target, 'incoming_execution_reference', 0, follow=False)
                    dynamic(source, 'incoming_execution_surface', line)
            for section, raw in _extract_sibling_declarations(config):
                if '$' in raw or '\x00' in raw or '\n' in raw:
                    unknown('sibling_reference_unresolved: ' + str(source), ('sibling_profiles',))
                    continue
                target = _resolve_target(raw, home, sibling)
                if _within_any(target, roots):
                    edge(source, target, 'incoming_sibling_reference', 0)
                    if section in {'skills', 'plugins'} and (sibling / section).exists():
                        edge(source, sibling / section, 'incoming_sibling_region', 0)
        except FileNotFoundError:
            pass
        except (OSError, ValueError, UnicodeError, RecursionError, ImportError):
            unknown('sibling_config_parse_or_read_failed: ' + str(source), ('sibling_profiles', 'cross_project_isolation'))

    credential_declarations(profile, home, excluded_paths=blocked_paths)
    for root in selected_projects:
        credential_declarations(Path(root), home, excluded_paths=blocked_paths)
    result['limits']['parent_context_boundary'] = None
    result['limits']['parent_context_boundaries'] = {}
    for project in projects:
        start_budget('project:' + str(project))
        from . import outward_git as _outward_git_mod
        context = _outward_git_mod.discover_git_context(
            project, home=home, unbounded=unbounded, allow_path=lambda p: not _within_any(p, blocked_paths))
        git_contexts.append(context)
        for path, reason in context.issues:
            unknown(reason + ': ' + str(path),
                    ('dynamic_execution', 'cross_project_isolation') if reason == 'git_include_condition_unresolved' else (owner(path),))
        for reference in context.edges:
            if reference.target.exists() or reference.target.is_symlink():
                edge(reference.source, reference.target, reference.relationship, 0,
                     follow=reference.relationship not in {'git_context', 'git_directory', 'git_common_directory'})
        visit(project, explicit=True)
        boundary = next((p for p in (project, *project.parents) if (p / '.git').exists()), Path('/'))
        result['limits']['parent_context_boundary'] = str(boundary)
        result['limits']['parent_context_boundaries'][str(project)] = str(boundary)
        for index, parent in enumerate((project, *project.parents)):
            if not unbounded and index > MAX_DEPTH:
                unknown('parent_context_walk_truncated: ' + str(project))
                break
            for name in _PARENT_CONTEXT_FILES:
                candidate = parent / name
                try:
                    candidate.lstat()
                except FileNotFoundError:
                    continue
                except OSError:
                    unknown('parent_context_stat_failed: ' + str(candidate))
                    continue
                edge(project, candidate, 'parent_context', 0)
            rules = parent / '.cursor' / 'rules'
            if rules.is_dir():
                edge(project, rules, 'parent_context', 0)
            if parent == boundary:
                break

    start_budget('home_startup')
    result['limits']['home_startup_scope'] = 'bounded shell, Python, npm, Cargo, user-systemd and desktop-autostart inputs in audited HOME'
    for candidate in discover_home_startup(home, _directory_fd, lambda r: unknown(r, ('shared_infrastructure',)), unbounded=unbounded):
        try:
            with _directory_fd(candidate.parent) as fd:
                os.stat(candidate.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            unknown('home_startup_stat_failed: ' + str(candidate), ('shared_infrastructure',))
            continue
        visit(candidate, explicit=True)

    start_budget('active_profile')
    visit(profile, explicit=True)
    shared_kanban = default_profile / 'kanban.db'
    if profile != default_profile and (shared_kanban.exists() or shared_kanban.is_symlink()):
        edge(profile, shared_kanban, 'shared_kanban', 0)

    container = default_profile / 'profiles'
    result['limits']['unrelated_siblings'] = 'top-level lstat and config.yaml declarations (including default); unrelated content not inspected'
    result['regions']['sibling_profiles']['scope'] = 'top-level symlink metadata, sibling config declarations and evidenced blending regions only'
    roots = {*projects, profile, *outgoing_targets}
    start_budget('sibling_declarations')

    if profile != default_profile:
        inspect_sibling(default_profile, roots)
    try:
        with _directory_fd(container) as container_fd:
            with os.scandir(container_fd) as siblings:
                for entry in siblings:
                    sibling = container / entry.name
                    if sibling != profile:
                        if entry.is_dir(follow_symlinks=False):
                            inspect_sibling(sibling, roots)
                        elif entry.is_symlink():
                            unknown('sibling_declaration_symlink_unverified: ' + str(sibling), ('sibling_profiles',))
    except FileNotFoundError:
        pass
    except OSError:
        unknown('sibling_enumeration_failed: ' + str(container), ('sibling_profiles', 'cross_project_isolation'))

    for source, dependency, spec in workspace_dependencies:
        workspace = next((p for p in (source.parent, *source.parent.parents) if p in workspace_members), None)
        name = spec.rsplit('@', 1)[0] if '@' in spec[1:] else dependency
        candidates = [p for p in workspace_members.get(workspace, ()) if package_names.get(p) == name]
        if len(candidates) == 1:
            edge(source, candidates[0], 'workspace_dependency', 0, follow=False)
        else:
            unknown('workspace_dependency_unresolved: ' + str(source), (owner(source),))

    for link in hardlinks.values():
        paths = list(dict.fromkeys(link['paths']))
        if len(paths) < link['count']:
            result['regions']['cross_project_isolation'].setdefault('disclosures', []).append({
                'kind': 'hardlink_target_unknown', 'path': str(paths[0]),
                'meaning': 'Hardlinked file may be shared outside inspected trees; target unknown.'})
        for target in paths[1:]:
            edge(paths[0], target, 'hardlink', 0, follow=False)

    if classification_conflicts:
        result['blending'] = []
        result['dynamic_invocations'] = []
        result['credentials'] = [c for c in result['credentials'] if Path(c['path']) in classification_conflicts]
        result.pop('database_associations', None)
        result.pop('database_records', None)
        result['limits'].pop('databases', None)
        for entry in result['limits']['regions'].values():
            entry['cuts'] = ['credential_classification_conflict: derived evidence withheld']
        for region in result['regions'].values():
            region['coverage'] = 'could_not_verify'
            region['reasons'] = ['credential_classification_conflict: derived evidence withheld']
            region.pop('reason_details', None)

    for credential in result['credentials']:
        if 'config_keys' in credential:
            credential['config_keys'] = sorted(set(credential['config_keys']) | credential_references.get(credential['path'], set()))
    result['blending'].sort(key=lambda edge: (edge['relationship'], edge['source'], edge['target']))
    return serialize_evidence(result)
