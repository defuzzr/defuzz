"""Versioned read boundary. Credential material is not evidence, even as hashes."""
from pathlib import PurePath, Path
import os
import stat

POLICY_VERSION = '3.1.0'
# Exact paths relative to a profile/project root; no suffix-based discovery.
# Profiles additionally admit profiles/<name>/config.yaml (one level only).
DECLARATION_SOURCE_FILES = (
    'config.yaml', 'profiles/*/config.yaml', '.git/config',
    'settings.json', 'settings.toml', 'package.json', 'pyproject.toml',
    'Cargo.toml', 'pnpm-workspace.yaml',
)


def declaration_source(path):
    from .redaction import _CURRENT
    state = _CURRENT.get()
    return state is not None and os.path.abspath(path) in getattr(state, 'declaration_sources', set())
_SECRET_TREES = frozenset({
    'vault', 'mcp-tokens', 'credentials', 'credential', 'secrets', '.ssh', '.aws',
    '.azure', 'gcloud', '.gnupg', '.kube', '.docker', '.npm', '.config',
    'keyrings', 'keychain', 'backups', 'state-snapshots', 'checkpoints',
    'pairing', 'platforms', 'whatsapp', 'matrix', 'weixin', 'proxy',
    'google_chat_user_tokens', 'google_chat_user_oauth_pending',
    'browser-profile', 'browser_auth', 'bot-desktop', 'browser-profiles',
    'browser_profiles', 'chrome-debug',
})
_SECRET_FILES = frozenset({
    'auth.json', '.env', '.op.env', '.envrc', '.npmrc', 'npmrc', '.netrc',
    '.anthropic_oauth.json', 'google_token.json', 'google_oauth_pending.json',
    'google_client_secret.json', 'google_chat_user_token.json',
    'google_chat_user_client_secret.json', 'google_chat_user_oauth_pending.json',
    '.copilot_jwt.json', 'slack_tokens.json', 'honcho.json', 'mem0.json',
    'webhook_subscriptions.json', 'teams_pipeline_store.json',
    'bws_cache.json', 'bws_cache.enc.json', 'op_cache.json', 'photon-sidecar.json',
    'feishu_comment_pairing.json', 'nous_auth.json', 'credentials.json',
    'vault.key', 'vault.json.enc',
})


def _identity(info):
    return (info.st_dev, info.st_ino)


def _normal(path):
    """Lexical normal form: absolute, no '..', no doubled or trailing slashes."""
    text = os.path.abspath(os.fsdecode(os.fspath(path)))
    return '/' + text.lstrip('/') if text.startswith('//') else text


def _with_parents(text):
    while True:
        yield text
        parent = os.path.dirname(text)
        if parent == text:
            return
        text = parent


class _Declared:
    """Run-local view of the declarations, keyed by identity as well as by spelling.

    Built once per change of the declaration set (declarations are few). Uses lstat,
    stat and realpath only: these read link targets and inode metadata, never content.
    """

    def __init__(self, state):
        known = getattr(state, '_declared_identity_sources', None)
        if known is None:
            known = state._declared_identity_sources = {}
        source_ids, source_real = set(), set()
        for source in tuple(getattr(state, 'declaration_sources', ()) or ()):
            if source not in known:  # Each source is resolved once per run.
                try:
                    real = os.path.realpath(source).casefold()
                except (OSError, ValueError):
                    real = _normal(source).casefold()
                try:
                    ident = _identity(os.stat(source))
                except (OSError, ValueError):
                    ident = None
                known[source] = (real, ident)
            real, ident = known[source]
            source_real.add(real)
            if ident is not None:
                source_ids.add(ident)
        self.lexical, self.real, self.file_ids, self.dir_ids = set(), set(), set(), set()
        self.folders = {}  # folder -> (resolved folder, inside a declared folder)
        for declared in state.credential_paths:
            normal = _normal(declared)
            self.lexical.add(normal.casefold())
            try:
                real = os.path.realpath(normal)
            except (OSError, ValueError):
                real = normal
            try:
                info = os.stat(normal)
            except (OSError, ValueError):
                info = None
            if info is not None and _identity(info) in source_ids or real.casefold() in source_real:
                continue  # Declaring a declaration source has no effect, under any spelling.
            self.real.add(real.casefold())
            if info is not None:
                (self.dir_ids if stat.S_ISDIR(info.st_mode) else self.file_ids).add(_identity(info))


class _Unverified(Exception):
    pass


def _declared_view(state):
    paths = state.credential_paths
    if not paths:
        return None
    key = (frozenset(paths), len(getattr(state, 'declaration_sources', ()) or ()))
    cached = getattr(state, '_declared_identity_view', None)
    if cached is None or cached[0] != key:
        cached = (key, _Declared(state))
        state._declared_identity_view = cached
    return cached[1]


def _folder(state, folder):
    """(resolved path, identities of the folder and every lexical ancestor), cached per folder.

    One lstat per distinct folder: candidates in the same folder share it.
    """
    cache = getattr(state, '_declared_identity_folders', None)
    if cache is None:
        cache = state._declared_identity_folders = {}
    found = cache.get(folder)
    if found is not None:
        if found is _Unverified:
            raise _Unverified(folder)
        return found
    parent = os.path.dirname(folder)
    try:
        if parent == folder:
            info = os.lstat(folder)
            found = (folder, frozenset({_identity(info)}))
        else:
            parent_real, parent_ids = _folder(state, parent)
            try:
                info = os.lstat(folder)
            except (FileNotFoundError, NotADirectoryError):
                info = None
            if info is not None and stat.S_ISLNK(info.st_mode):
                real = os.path.realpath(folder)
                try:
                    info = os.stat(folder)
                except (FileNotFoundError, NotADirectoryError):
                    info = None
            else:
                real = os.path.join(parent_real, os.path.basename(folder))
            ids = parent_ids | {_identity(info)} if info is not None else parent_ids
            found = (real, ids)
    except _Unverified:
        cache[folder] = _Unverified
        raise
    except (OSError, ValueError, RuntimeError):
        # Permission, link loop, a link swapped while it was resolved: fail closed.
        cache[folder] = _Unverified
        raise _Unverified(folder) from None
    cache[folder] = found
    return found


def _declared_match(state, path):
    """'credential' when `path` is a declared credential or inside one, by spelling,
    resolved path or (device, inode); 'unverified' when that cannot be checked; else None."""
    view = _declared_view(state)
    if view is None:
        return None
    normal = _normal(path)
    if normal.casefold() in view.lexical:
        return 'credential'
    folder, name = os.path.split(normal)
    try:
        entry = view.folders.get(folder)
        if entry is None:
            # Once per folder and declaration set: is the folder itself inside a
            # declared folder, by spelling, by resolved path or by identity?
            real_folder, folder_ids = _folder(state, folder)
            inside = (not folder_ids.isdisjoint(view.dir_ids)
                      or any(p.casefold() in view.lexical for p in _with_parents(folder))
                      or any(p.casefold() in view.real for p in _with_parents(real_folder)))
            entry = view.folders[folder] = (real_folder, inside)
        if entry[1] or os.path.join(entry[0], name).casefold() in view.real:
            return 'credential'
        if view.file_ids or view.dir_ids:
            try:
                info = os.lstat(normal)
                if stat.S_ISLNK(info.st_mode):
                    try:
                        info = os.stat(normal)
                    except (FileNotFoundError, NotADirectoryError):
                        return None  # A dangling link names nothing declared.
            except (FileNotFoundError, NotADirectoryError):
                return None
            ident = _identity(info)
            if ident in view.file_ids or ident in view.dir_ids:
                return 'credential'
    except _Unverified:
        return 'unverified'
    except (OSError, ValueError, RuntimeError):
        return 'unverified'
    return None


def declared_credential(path):
    """Declared-credential test alone (no name rules), by spelling and by identity."""
    from .redaction import _CURRENT
    state = _CURRENT.get()
    if state is None or declaration_source(path):
        return False
    absolute = Path(os.path.abspath(path))
    if any(absolute == root or root in absolute.parents
           for root in getattr(state, 'credential_uncertain_roots', ())):
        return True
    return _declared_match(state, path) is not None


def credential_handle(info, path, parent_info=None):
    """Re-check an OPEN descriptor before any byte is read: True when its
    (device, inode), or its folder's, is a declared credential."""
    from .redaction import _CURRENT
    state = _CURRENT.get()
    if state is None or declaration_source(path):
        return False
    view = _declared_view(state)
    if view is None:
        return False
    ident = _identity(info)
    if ident in view.file_ids or ident in view.dir_ids:
        return True
    return parent_info is not None and _identity(parent_info) in view.dir_ids


def has_declarations():
    """True when this run has declared credentials or uncertain roots to check against."""
    from .redaction import _CURRENT
    state = _CURRENT.get()
    return state is not None and bool(state.credential_paths or getattr(state, 'credential_uncertain_roots', ()))


def opened_credential(info, path, real=None, parent_info=None):
    """Re-check an OPEN descriptor before any byte is read.

    True when the opened file's (device, inode) is a declared file or folder, or, for a
    file that is not a declaration source, when its folder's identity is a declared
    folder or its resolved location (`real`, read from the descriptor itself) is a
    declared path, lies inside a declared folder or inside an uncertain root. Unlike the
    path check, a declaration source is also refused when the file opened under its name
    is a declared credential: the name is the source, the content would not be.
    """
    from .redaction import _CURRENT
    state = _CURRENT.get()
    if state is None:
        return False
    view = _declared_view(state)
    ident = _identity(info)
    if view is not None and (ident in view.file_ids or ident in view.dir_ids):
        return True
    if declaration_source(path):
        return False
    if view is not None and parent_info is not None and _identity(parent_info) in view.dir_ids:
        return True
    if real is None:
        return False
    absolute = Path(os.path.abspath(real))
    if any(absolute == root or root in absolute.parents
           for root in getattr(state, 'credential_uncertain_roots', ())):
        return True
    if view is None or declaration_source(real):
        return False
    return any(p.casefold() in view.lexical or p.casefold() in view.real for p in _with_parents(_normal(real)))


def credential_verdict(path):
    """'credential', 'unverified' (could not be checked: never open it) or None."""
    if declaration_source(path):
        return None
    from .redaction import _CURRENT
    state = _CURRENT.get()
    if state is not None:
        absolute = Path(os.path.abspath(path))
        if any(str(parent) in state.credential_paths for parent in (absolute, *absolute.parents)):
            return 'credential'
        if any(absolute == root or root in absolute.parents
               for root in getattr(state, 'credential_uncertain_roots', ())):
            return 'credential'
        if os.path.isabs(os.fspath(path)):
            match = _declared_match(state, path)
            if match is not None:
                return match
    return 'credential' if _named_credential(path) else None


def credential_path(path):
    """Apply to complete paths, including any configured external root.

    Declarations match by spelling, by resolved path and by (device, inode), so a
    declared file reached through a link, a hard link or another spelling is still
    declared. A path that cannot be checked counts as a credential (fail closed).
    """
    return credential_verdict(path) is not None


def _named_credential(path):
    for part in PurePath(str(path)).parts:
        if part.casefold() in _SECRET_TREES:
            return True
    from .file_types import credential_file_kind
    from .outward_analyzers import credential_candidate
    candidate_path = Path(path)
    if credential_file_kind(candidate_path) is not None or credential_candidate(path):
        if candidate_path.is_absolute():
            import stat
            try:
                if stat.S_ISDIR(os.lstat(candidate_path).st_mode):
                    return False
            except OSError:
                pass
        return True
    return False


def note_credential_skip(path):
    """Record lstat-only metadata for an encountered exclusion, never discover more."""
    import stat
    from .redaction import _CURRENT
    state = _CURRENT.get()
    if state is None:
        return
    path = Path(os.path.abspath(path))
    try:
        info = path.lstat()
    except OSError:
        return
    state.credential_metadata[str(path)] = {
        "kind": "credential_store", "path": str(path), "size": info.st_size,
        "mode": stat.S_IMODE(info.st_mode), "mtime": info.st_mtime,
    }


def declare_credential(path):
    """Share a discovered exclusion across all collectors in this audit run."""
    import os
    from .redaction import _CURRENT
    state = _CURRENT.get()
    if state is not None and not declaration_source(path):
        state.credential_paths.add(os.path.abspath(path))


def credential_declarations(root, home, *, max_bytes=1024 * 1024, excluded_paths=()):
    """Read the fixed declaration-source set first, never arbitrary candidates.

    Declaring a source as a credential has no effect: it remains a source.
    """
    from .fingerprint import safe_read_regular_file_plain
    from .facts import _parse_simple_yaml_mapping
    from .redaction import _CURRENT
    state = _CURRENT.get()
    source = Path(os.path.abspath(root))
    if any(source == Path(p).absolute() or source.is_relative_to(Path(p).absolute()) for p in excluded_paths):
        return
    import stat
    try:
        mode = source.lstat().st_mode
    except OSError:
        return
    if stat.S_ISLNK(mode):
        return
    if stat.S_ISDIR(mode):
        if declaration_source(source):
            return  # A directory at a fixed filename is not another search root.
        if source.parent.name == 'profiles':
            credential_declarations(source.parent.parent, home, max_bytes=max_bytes, excluded_paths=excluded_paths)
        candidates = []
        for name in DECLARATION_SOURCE_FILES:
            if '*' in name:
                candidates.extend(source.glob(name))
            else:
                candidates.append(source / name)
        if state is not None:
            sources = getattr(state, 'declaration_sources', set())
            sources.update(str(p) for p in candidates)
            state.declaration_sources = sources
            for candidate in candidates:
                state.declaration_anchors[str(candidate)] = source
            state.credential_paths.difference_update(sources)
        for candidate in candidates:
            credential_declarations(candidate, home, max_bytes=max_bytes, excluded_paths=excluded_paths)
        return
    if state is None or not declaration_source(source):
        return
    # Discovery must not populate the ordinary capture cache or taint state.
    # Only parsed path declarations escape this ephemeral read; its digest does not.
    anchor = state.declaration_anchors[str(source)]
    read = safe_read_regular_file_plain(anchor, source.relative_to(anchor), max_bytes=max_bytes)
    try:
        text = (read.content or b'').decode('utf-8')
        if source.name == 'config' and source.parent.name == '.git':
            # Git includes are declarations only; never recursively read targets.
            import re
            from .outward_git import _value
            section = ''
            text = re.sub(r'(?<!\\)((?:\\\\)*)\\\r?\n', r'\1', text)
            for line in text.splitlines():
                line = line.strip()
                if line.startswith('['):
                    match = re.match(r'\[(include|includeif)(?:\s|\])', line, re.I)
                    section = match[1].lower() if match else ''
                elif section:
                    match = re.match(r'path\s*=\s*(.*)', line, re.I)
                    if match:
                        raw = _value(match[1])
                        if raw and not any(c in raw for c in '$\x00\n'):
                            target = Path(home) / raw[2:] if raw.startswith('~/') else Path(raw)
                            declare_credential(target if target.is_absolute() else source.parent / target)
            return
        if source.suffix.lower() == '.toml':
            import tomllib
            config = tomllib.loads(text)
        else:
            config = _parse_simple_yaml_mapping(text)
    except (ValueError, ImportError, UnicodeError, RecursionError):
        return

    visited = set()
    def walk(value):
        if isinstance(value, (dict, list)):
            if id(value) in visited:
                return
            visited.add(id(value))
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {'credential_file', 'credentials_file', 'env_file'}:
                    for raw in item if isinstance(item, list) else [item]:
                        if isinstance(raw, str) and raw and not any(c in raw for c in '$\x00\n*?['):
                            target = Path(home) / raw[2:] if raw.startswith('~/') else Path(raw)
                            declare_credential(target if target.is_absolute() else source.parent / target)
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(config)
