"""Static Git context discovery; never execute Git or inspected code.

Collector integration (intentionally independent of outward.py):

* Call ``discover_git_context(project, home=audited_home, allow_path=allowed)``
  BEFORE visiting the project. ``home`` is mandatory; never pass process HOME
  or use expanduser. Supply the collector's exclusion/cancellation predicate as
  ``allow_path`` (called before metadata/content reads). Defaults also inspect
  /etc/gitconfig; tests must override system_config with a synthetic path.
* Register ``context.hook_roots`` before any visits. For each regular file,
  call ``context.hook_kind(path)`` and forward non-None results to ``dynamic``.
  This covers extensionless/non-executable files in external hook directories.
* Forward every GitEdge to ``edge(source, target, relationship, depth, ...)``.
  Use follow=False for git_context/git_directory/git_common_directory: these
  disclose outward blending without recursively sweeping Git object stores.
* Config/hook edges may follow through the existing safe visitor. Include
  targets are metadata-only and must never be content-read.
  Absent optional global/config.worktree/default-hooks candidates are normal;
  let the collector apply its optional-path policy rather than declaring them
  missing dependencies. Explicit missing includes are reported in issues.
* Forward every (path, reason) in issues to ``unknown``; repository is the
  enclosing context boundary. Do not mark unresolved conditions verified.

This is conservative discovery, NOT Git's effective configuration evaluator:
all includeIf targets are disclosed without opening them; config.worktree
candidates are inspected, hooksPath values retained, with no precedence or activation claim.
Default hooks stay discoverable even when an override exists. Relative hook
paths use the enclosing working tree. Bare repositories, environment/CLI Git
configuration overrides, and symlink config targets are not resolved here.
Symlink reads are rejected and reported, never implicitly followed. Include
cycles are deduplicated, depth capped at 32, content reads and config/edge counts
bounded independently of the collector's budgets. The collector should choose
limits within its remaining budget; directory/content visits remain its job.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import os
import re
from pathlib import Path
import stat

# CredentialStoreNotOpened: internal read-boundary signal, never derived from file contents.
from .fingerprint import CredentialStoreNotOpened, open_checked

_LINE_CONTINUATION = re.compile(r'(?<!\\)((?:\\\\)*)\\\r?\n')
_SECTION_LINE = re.compile(r'\[([\w-]+)(?:\s+"[^"\n]*")?\]\s*(?:[#;].*)?')
_KEY_VALUE_LINE = re.compile(r'([\w-]+)\s*=\s*(.*)')
_CONFIG_EDGE_KINDS = frozenset({
    'git_config', 'git_worktree_config', 'git_global_config',
    'git_config_include', 'git_config_include_if',
})


def _absolute(path):
    return Path(os.path.abspath(os.fspath(path)))


@contextmanager
def _directory(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in _absolute(path).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _stat(path):
    with _directory(path.parent) as fd:
        return os.stat(path.name, dir_fd=fd, follow_symlinks=False)


def _read(path, limit):
    from .policy import credential_path
    with _directory(path.parent) as parent:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if credential_path(path):
            raise CredentialStoreNotOpened()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('git_non_regular')
        fd = open_checked(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent,
                          full_path=str(_absolute(path)))
        with os.fdopen(fd, 'rb') as stream:
            if _identity(before) != _identity(os.fstat(stream.fileno())):
                raise ValueError('git_file_changed')
            data = stream.read() if limit is None else stream.read(limit + 1)
            if limit is not None and len(data) > limit:
                raise ValueError('git_file_limit')
            if (_identity(before) != _identity(os.fstat(stream.fileno())) or
                    _identity(before) != _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))):
                raise ValueError('git_file_changed')
            return data


def _value(raw):
    """Decode Git double quotes/escapes, not shell quoting or interpolation."""
    output, pending = [], []
    quoted = escaped = False
    escapes = {'n': '\n', 't': '\t', 'b': '\b', '\\': '\\', '"': '"'}
    for char in raw.lstrip():
        if escaped:
            if char not in escapes:
                raise ValueError('git_config_escape')
            output.extend((*pending, escapes[char]))
            pending.clear()
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == '"':
            output.extend(pending)
            pending.clear()
            quoted = not quoted
        elif char in '#;' and not quoted:
            break
        elif char.isspace() and not quoted:
            pending.append(char)
        else:
            output.extend((*pending, char))
            pending.clear()
    if quoted or escaped:
        raise ValueError('git_config_quote')
    return ''.join(output)


@dataclass(frozen=True)
class GitEdge:
    source: Path
    target: Path
    relationship: str


@dataclass
class GitContext:
    repository: Path | None = None
    edges: list[GitEdge] = field(default_factory=list)
    hook_roots: set[Path] = field(default_factory=set)
    issues: list[tuple[Path, str]] = field(default_factory=list)

    @property
    def config_paths(self):
        """Role-identified candidates, including absent/unreadable configs."""
        return {edge.target for edge in self.edges if edge.relationship in _CONFIG_EDGE_KINDS}

    def config_kind(self, path):
        """Return a stable role hint, not a claim of existence or safety."""
        return 'git_config' if _absolute(path) in self.config_paths else None

    def hook_kind(self, path):
        path = _absolute(path)
        if any(path != root and path.is_relative_to(root) for root in self.hook_roots):
            return 'git_hook_unresolved'
        return None


def _xdg_config_root(home: Path) -> Path:
    configured = os.environ.get('XDG_CONFIG_HOME')
    if configured and Path(configured).is_absolute():
        candidate = _absolute(configured)
        if candidate.is_relative_to(home):
            return candidate
    return home / '.config'


def _iter_config_path_values(path, text, issues):
    # Keep parsing lazy: the caller records each path's issues before parsing
    # subsequent lines, preserving their order relative to parse failures.
    section = ''
    for line in _LINE_CONTINUATION.sub(r'\1', text).splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('['):
            match = _SECTION_LINE.fullmatch(line)
            if not match:
                issues.append((path, 'git_config_parse_failed'))
                section = ''
            else:
                section = match[1].lower()
            continue
        match = _KEY_VALUE_LINE.fullmatch(line)
        if not match or (section, match[1].lower()) not in {('core', 'hookspath'), ('include', 'path'), ('includeif', 'path')}:
            continue
        try:
            raw = _value(match[2])
        except ValueError:
            issues.append((path, 'git_config_parse_failed'))
            continue
        yield section, raw


def discover_git_context(project, *, home, system_config=Path('/etc/gitconfig'),
                         max_file_bytes=1024 * 1024, max_configs=128, max_edges=256,
                         allow_path=None, unbounded=False):
    for limit in (max_file_bytes, max_configs, max_edges):
        if type(limit) is not int or limit <= 0:
            raise ValueError('Git discovery limits must be positive integers')
    if unbounded:
        max_file_bytes = max_configs = max_edges = None
    result = GitContext()
    project, home = _absolute(project), _absolute(home)

    def permitted(path):
        if allow_path is not None and not allow_path(path):
            result.issues.append((path, 'git_path_excluded'))
            return False
        return True

    def edge(source, target, kind):
        if max_edges is not None and len(result.edges) >= max_edges:
            issue = (project, 'git_edge_limit')
            if issue not in result.issues:
                result.issues.append(issue)
            return
        result.edges.append(GitEdge(source, _absolute(target), kind))

    def read(path, required=False):
        if not permitted(path):
            return None
        try:
            return _read(path, max_file_bytes).decode('utf-8')
        except FileNotFoundError:
            if required:
                result.issues.append((path, 'git_include_missing'))
            return None
        except CredentialStoreNotOpened:
            result.issues.append((path, 'credential_store_not_opened'))
            return None
        except (OSError, ValueError, UnicodeError):
            result.issues.append((path, 'git_read_failed'))
            return None

    def path_value(source, raw, base):
        if not raw or any(c in raw for c in ('\x00', '\n', '\r', '$')) or raw.startswith(('~', '%(')) and not raw.startswith('~/'):
            result.issues.append((source, 'git_path_unresolved'))
            return None
        return _absolute(home / raw[2:] if raw.startswith('~/') else base / raw)

    def record_include(source, target, conditional):
        edge(source, target, 'git_config_include_if' if conditional else 'git_config_include')
        if conditional:
            result.issues.append((source, 'git_include_condition_unresolved'))
        if not permitted(target):
            return
        from .policy import declare_credential
        declare_credential(target)
        result.issues.append((target, 'credential_store_not_opened'))
        try:
            _stat(target)
        except FileNotFoundError:
            result.issues.append((target, 'git_include_missing'))
        except OSError:
            result.issues.append((target, 'git_read_failed'))

    visited_configs = set()

    def inspect_config_file(path, depth=0):
        if path in visited_configs:
            return
        if not unbounded and (len(visited_configs) >= max_configs or depth >= 32):
            issue = (project, 'git_config_limit')
            if issue not in result.issues:
                result.issues.append(issue)
            return
        visited_configs.add(path)
        text = read(path, required=depth > 0)
        if text is None:
            return
        for section, raw in _iter_config_path_values(path, text, result.issues):
            target = path_value(path, raw, (result.repository or project) if section == 'core' else path.parent)
            if target is None:
                continue
            if section == 'core':
                edge(path, target, 'git_hooks_path')
                result.hook_roots.add(target)
            else:
                record_include(path, target, section == 'includeif')

    configs = []
    for parent in (project, *project.parents):
        marker = parent / '.git'
        if not permitted(marker):
            break
        try:
            info = _stat(marker)
        except FileNotFoundError:
            continue
        except OSError:
            result.issues.append((marker, 'git_context_stat_failed'))
            break
        result.repository = parent
        edge(project, marker, 'git_context')
        if stat.S_ISDIR(info.st_mode):
            gitdir = marker
        else:
            text = read(marker)
            if text is None or not text.startswith('gitdir:'):
                result.issues.append((marker, 'git_directory_unresolved'))
                break
            gitdir = path_value(marker, text[7:].strip(), parent)
            if gitdir is None:
                break
            edge(marker, gitdir, 'git_directory')
        commondir = gitdir / 'commondir'
        text = read(commondir)
        common = gitdir
        if text is not None:
            common = path_value(commondir, text.strip(), gitdir)
            if common is None:
                break
            edge(gitdir, commondir, 'git_common_reference')
            edge(commondir, common, 'git_common_directory')
        edge(common, common / 'config', 'git_config')
        configs.extend((common / 'config', gitdir / 'config.worktree'))
        edge(gitdir, gitdir / 'config.worktree', 'git_worktree_config')
        edge(common, common / 'hooks', 'git_hooks_path')
        result.hook_roots.add(common / 'hooks')
        break

    xdg = _xdg_config_root(home)
    for path in (home / '.gitconfig', xdg / 'git' / 'config', _absolute(system_config)):
        edge(project, path, 'git_global_config')
        configs.append(path)
    for path in configs:
        inspect_config_file(path)
    return result
