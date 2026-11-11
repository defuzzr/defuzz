"""Pure static Python execution hints; never import or execute inspected code.

An empty result is not a runtime safety guarantee. Findings contain fixed kinds
and source lines only, never commands, arguments, or exception messages.
"""
import ast
import re

_CAPABLE = frozenset('os posix pty runpy ctypes cffi multiprocessing subprocess importlib builtins'.split())
_DYNAMIC = frozenset('compile exec eval __import__ getattr open'.split())
_PREFILTER = re.compile(r'\b(?:import|os|posix|pty|runpy|ctypes|cffi|multiprocessing|subprocess|importlib|builtins|compile|exec|eval|__import__|getattr|open)\b|[^\x00-\x7f]')
_BENIGN_LINE = re.compile(r'(?:[A-Za-z_]\w*\s*=\s*(?:[0-9]+|True|False|None)|print\([A-Za-z_]\w*\))\s*')

# Explicit function names, never a blanket module/member-prefix exemption.
_SAFE_MEMBERS = {
    'builtins': 'abs all any ascii bin bool bytearray bytes chr dict divmod enumerate filter float format frozenset hash hex int isinstance issubclass iter len list map max min next oct ord pow print range repr reversed round set slice sorted str sum tuple type zip',
    'os.path': 'abspath basename commonpath commonprefix dirname exists expanduser expandvars getatime getctime getmtime getsize isabs isdir isfile islink ismount join lexists normcase normpath realpath relpath samefile sameopenfile samestat split splitdrive splitext',
    'json': 'load loads dump dumps',
    're': 'compile escape findall finditer fullmatch match search split sub subn',
    'typing': 'cast get_args get_origin NewType TypeVar NamedTuple TypedDict final overload runtime_checkable',
    'dataclasses': 'dataclass field fields asdict astuple is_dataclass replace make_dataclass',
    'pathlib': 'Path PurePath PosixPath PurePosixPath WindowsPath PureWindowsPath',
    '@path': 'read_text read_bytes exists is_file is_dir is_symlink stat lstat iterdir glob rglob absolute resolve expanduser joinpath with_name with_suffix relative_to is_relative_to as_posix as_uri match samefile',
}
_SAFE = frozenset(f'{module}.{member}' for module, members in _SAFE_MEMBERS.items() for member in members.split())
_PATH_CONSTRUCTORS = frozenset('pathlib.' + name for name in _SAFE_MEMBERS['pathlib'].split())
_PATH_CHAIN = frozenset('@path.' + name for name in 'absolute resolve expanduser joinpath with_name with_suffix relative_to'.split())
_KNOWN_IMPORT_ROOTS = _CAPABLE | set(_SAFE_MEMBERS)
_CALLBACK_KWARGS = frozenset({'key', 'default', 'default_factory', 'factory', 'object_hook', 'object_pairs_hook', 'parse_int', 'parse_float', 'parse_constant', 'cls'})


def _collect_bindings(nodes: list[ast.AST]) -> tuple[dict[str, list[str | None]], bool]:
    # Whole-file binding analysis intentionally sacrifices precision across scopes.
    # A reassignment, parameter, or competing import must never inherit trust.
    bindings: dict[str, list[str | None]] = {}
    mutation = False

    def bind(name, value=None):
        bindings.setdefault(name, []).append(value)

    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split('.')[0]
                bind(alias.asname or root, alias.name if alias.asname else root)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == '*':
                    mutation = True
                else:
                    bind(alias.asname or alias.name, f"{node.module or ''}.{alias.name}" if not node.level else None)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(node.id)
        elif isinstance(node, ast.arg):
            bind(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.MatchAs, ast.MatchStar, ast.ExceptHandler)) and getattr(node, 'name', None):
            bind(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bind(node.rest)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            mutation = True
    return bindings, mutation


def _resolve_expr(node: ast.AST | None, bindings: dict[str, list[str | None]]) -> str | None:
    if isinstance(node, ast.Name):
        values = bindings.get(node.id)
        return ('builtins.' + node.id) if values is None else (values[0] if len(values) == 1 else None)
    if isinstance(node, ast.Attribute):
        base = _resolve_expr(node.value, bindings)
        return f'{base}.{node.attr}' if base else None
    if isinstance(node, ast.Call) and _resolve_expr(node.func, bindings) in (_PATH_CONSTRUCTORS | _PATH_CHAIN):
        return '@path'
    return None


def _is_safe_call(node: ast.Call, bindings: dict[str, list[str | None]]) -> bool:
    target = _resolve_expr(node.func, bindings)
    if target not in _SAFE:
        return False
    if target in {'builtins.map', 'builtins.filter'}:
        return bool(node.args) and _resolve_expr(node.args[0], bindings) in _SAFE
    if target in {'re.sub', 're.subn'}:
        replacement = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == 'repl'), None)
        if not (isinstance(replacement, ast.Constant) and isinstance(replacement.value, str)) and _resolve_expr(replacement, bindings) not in _SAFE:
            return False
    return not any(k.arg is None or k.arg in _CALLBACK_KWARGS and _resolve_expr(k.value, bindings) not in _SAFE for k in node.keywords)


def analyze_python(data: bytes | str) -> list[tuple[str, int]]:
    """Classify bounded source supplied by the caller, failing closed on parse errors."""
    try:
        text = data.decode('utf-8') if isinstance(data, bytes) else data
        if not _PREFILTER.search(text):
            return ([] if all(not (s := line.strip()) or s.startswith('#') or _BENIGN_LINE.fullmatch(s) for line in text.splitlines())
                    else [('python_syntax_unclassified', 1)])
        tree = ast.parse(text)
    except (UnicodeError, SyntaxError, ValueError, RecursionError, MemoryError):
        return [('python_parse_unresolved', 1)]

    nodes = list(ast.walk(tree))
    bindings, mutation = _collect_bindings(nodes)
    for _ in range(len(bindings) + 1):
        changed = False
        for node in nodes:
            if isinstance(node, ast.Assign) and _resolve_expr(node.value, bindings) == '@path':
                for target in node.targets:
                    if isinstance(target, ast.Name) and bindings.get(target.id) == [None]:
                        bindings[target.id] = ['@path']
                        changed = True
        if not changed:
            break

    implicit = {('python_implicit_execution_unresolved', n.lineno)
                for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and (any(_resolve_expr(d, bindings) not in _SAFE for d in n.decorator_list)
                     or isinstance(n, ast.ClassDef) and (n.bases or n.keywords))}
    imports = {('python_import_unclassified', n.lineno) for n in nodes
               if isinstance(n, ast.Import) and any(a.name.split('.')[0] not in _KNOWN_IMPORT_ROOTS for a in n.names)
               or isinstance(n, ast.ImportFrom) and (n.level or (n.module or '').split('.')[0] not in _KNOWN_IMPORT_ROOTS)}
    calls = {('python_call_unresolved', n.lineno) for n in nodes if isinstance(n, ast.Call) and (mutation or not _is_safe_call(n, bindings))}
    return sorted(imports | implicit | calls, key=lambda item: (item[1], item[0]))
