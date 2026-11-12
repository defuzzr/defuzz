"""Literal path evidence only: no execution and no inferred call behavior."""
import ast
import re

# Values outside this allowlist in credential-bearing files are never inspected.
ENV_EXEC_KEYS = frozenset({'NODE_OPTIONS', 'PYTHONPATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
    'PYTHONSTARTUP', 'BASH_ENV', 'ENV', 'TERMINAL_CWD', 'ZDOTDIR', 'PATH',
    'node-options', 'script-shell', 'pnpmfile', 'globalconfig', 'userconfig', 'init-module',
    'Exec', 'TryExec', 'ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecReload', 'WorkingDirectory', 'Path'})
_PATH = re.compile(r'''(?<![\w/:*?${}<>\[\].~\\-])(?:git\+file:|file:)?((?:/|\./|\.\./|~/)[^\s"'`<>(),;\[\]{}]+)''')


def safe_arguments(items):
    """Remove credential flags/values before any argument becomes path evidence."""
    from .outward_analyzers import credential_key_kind
    from .redaction import extraction, observe_value
    items = list(items)
    observe_value(items)
    skip = False
    for item in items:
        if skip:
            skip = False
            continue
        if not isinstance(item, str):
            yield item
            continue
        key, sep, _ = item.partition('=')
        if (key.startswith('-') and (credential_key_kind(key) or key in {'-p', '-u'})):
            skip = not sep
            continue
        if sep and credential_key_kind(key):
            continue
        if extraction(item) is not None:
            yield item


# shlex appends one character at a time to a growing token, so a long token costs
# quadratic time (about 6.5 s for one 400 KB whitespace-free line). _split_words is
# the same POSIX grammar as shlex.split (whitespace ' \t\r\n', quotes, backslash
# escapes, optional '#' comments, the same ValueError cases) scanned in runs, so it
# returns the same words in time linear in the line and nothing is capped.
_SPLIT_SPACE = re.compile(r'[ \t\r\n]+')
_SPLIT_WORD = re.compile(r'''[^ \t\r\n'"\\]+''')
_SPLIT_WORD_COMMENTS = re.compile(r'''[^ \t\r\n'"\\#]+''')
_SPLIT_DOUBLE = re.compile(r'[^"\\]*')


def _split_words(text, comments=False):
    """Linear-time equivalent of ``shlex.split(text, comments=comments)``."""
    if not isinstance(text, str):
        import shlex
        return shlex.split(text, comments=comments)
    word_run = _SPLIT_WORD_COMMENTS if comments else _SPLIT_WORD
    words, parts, quoted, pos, end = [], [], False, 0, len(text)
    while pos < end:
        char = text[pos]
        if char in ' \t\r\n' or (comments and char == '#'):
            if parts or quoted:
                words.append(''.join(parts))
                parts, quoted = [], False
            if char == '#':
                newline = text.find('\n', pos)
                pos = end if newline < 0 else newline + 1
            else:
                pos = _SPLIT_SPACE.match(text, pos).end()
        elif char == "'":
            close = text.find("'", pos + 1)
            if close < 0:
                raise ValueError('No closing quotation')
            parts.append(text[pos + 1:close])
            quoted, pos = True, close + 1
        elif char == '"':
            quoted, pos = True, pos + 1
            while True:
                run = _SPLIT_DOUBLE.match(text, pos)
                parts.append(run.group())
                pos = run.end()
                if pos >= end:
                    raise ValueError('No closing quotation')
                if text[pos] == '"':
                    pos += 1
                    break
                if pos + 1 >= end:
                    raise ValueError('No escaped character')
                escaped = text[pos + 1]
                # Inside double quotes only \" and \\ drop the backslash.
                parts.append(escaped if escaped in '"\\' else '\\' + escaped)
                pos += 2
        elif char == '\\':
            if pos + 1 >= end:
                raise ValueError('No escaped character')
            parts.append(text[pos + 1])
            pos += 2
        else:
            run = word_run.match(text, pos)
            parts.append(run.group())
            pos = run.end()
    if parts or quoted:
        words.append(''.join(parts))
    return words


def safe_text(text):
    import shlex
    try:
        return ' '.join(shlex.quote(v) for v in safe_arguments(_split_words(text)))
    except ValueError:
        # Malformed quoting is not authority to retain possible credentials.
        return ''


def safe_config(value):
    """Preserve credential mappings for HMAC handling; sanitize command values."""
    if isinstance(value, dict):
        return {k: safe_config(v) for k, v in value.items()}
    if isinstance(value, list):
        return [safe_config(v) for v in safe_arguments(value)]
    if isinstance(value, str):
        # Preserve exact ordinary strings (paths may contain spaces).
        clean = list(safe_arguments([value]))
        if not clean:
            return ''
        if re.search(r'(?:^|\s)-(?:-?[\w-]+)', value):
            return safe_text(value)
    return value


from .redaction import redaction_scope


@redaction_scope
def path_references(path, data, *, credentials=False, strict=False):
    """Extract literals within one shared observation/redaction context."""
    return list(_path_references(path, data, credentials=credentials, strict=strict))


def _relative_to_file(raw):
    """Prefix a bare name with ``./`` so it reads as relative to the declaring file."""
    if not raw.startswith(('/', '.', '~')):
        raw = './' + raw
    return raw


def _credential_execution_lines(path, text):
    """Yield (line number, declared path) for execution-relevant lines of a credential file.

    Contract: ``text`` is the already-captured content of a credential file
    (e.g. the project ``.env``); this helper never opens or reads a file itself.
    It yields only the value of an ``ENV_EXEC_KEYS`` assignment (``export``
    allowed) or, for ``.envrc``, the argument of a two-word
    ``source``/``.``/``source_env``/``dotenv`` line. Every other line, including
    secret values under other keys, is skipped and never returned.
    """
    for n, line in enumerate(text.splitlines(), 1):
        if '=' in line:
            key, value = line.split('=', 1)
            if key.strip().removeprefix('export ').strip() in ENV_EXEC_KEYS:
                raw = value.strip()
                if path.name == '.npmrc' and key.strip() in {'pnpmfile', 'globalconfig', 'userconfig', 'init-module'}:
                    raw = _relative_to_file(raw.strip('\"\''))
                yield n, raw
                continue
        if path.name != '.envrc':
            continue
        try:
            words = _split_words(line, comments=True)
        except ValueError:
            continue
        if len(words) != 2 or words[0] not in {'source', '.', 'source_env', 'dotenv'}:
            continue
        yield n, _relative_to_file(words[1])


def _path_references(path, data, *, credentials=False, strict=False):
    """Yield (literal, line); never return surrounding prose or commands."""
    from .redaction import extraction
    data = extraction(path=path, data=data)
    if b'/' not in data and not strict and not credentials:
        return
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        return
    lines = enumerate(text.splitlines(), 1)
    if credentials:
        lines = _credential_execution_lines(path, text)
    elif path.suffix.lower() in {'.json', '.jsonc', '.code-workspace', '.yaml', '.yml', '.toml'}:
        from .outward_structured import parse_data
        from .outward_analyzers import credential_key_kind
        try:
            if path.suffix.lower() == '.toml':
                import tomllib
                documents = [tomllib.loads(text)]
            else:
                documents = parse_data(path, data)
        except (ValueError, UnicodeError, ImportError, RecursionError):
            if strict:
                raise ValueError('declaration_parse_failed') from None
            return
        def values(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if credential_key_kind(key) or key in {'env', 'headers'}:
                        continue
                    yield from values(item)
            elif isinstance(value, list):
                for item in value:
                    yield from values(item)
            elif isinstance(value, str):
                yield 1, value
        lines = (line for document in documents for line in values(safe_config(document)))
    elif path.suffix == '.py':
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return
        lines = ((node.lineno, node.value) for node in ast.walk(tree)
                 if isinstance(node, ast.Constant) and isinstance(node.value, str))
    for number, line in lines:
        for match in _PATH.finditer(safe_text(line)):
            value = match[1].rstrip('.')
            # Local file URIs use // for the empty authority, not a UNC path.
            # Do not reinterpret file://host/path as a local reference.
            if match[0].startswith(('file:', 'git+file:')):
                from urllib.parse import unquote, urlsplit
                uri = urlsplit(match[0].removeprefix('git+'))
                if uri.netloc or uri.query or uri.fragment:
                    continue
                value = unquote(uri.path)
            if extraction(value) is not None and value and not value.startswith('//') and not any(c in value for c in '$\\'):
                yield value, number
