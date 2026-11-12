"""Optional, review-only componentize survey after adoption and bounded kit calls."""
from __future__ import annotations

import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath

from .agents_md import clamp_max_lines
from .child_env import COMPONENTIZE_STRIPPED_NAMES, COMPONENTIZE_STRIPPED_PREFIXES
from .safety import SafetyError, safe_write_bytes, safe_write_text, verify_nofollow_within_root

MAX_SURVEY_BYTES = 1024 * 1024
MAX_CLI_OUTPUT_BYTES = MAX_SURVEY_BYTES
SURVEY_PATH = '.adopt/componentize-survey.json'
KIT_SCHEMA = 'componentize.kit/1'
UNAVAILABLE_NOTICE = 'componentize CLI is unavailable'
TIMEOUT_NOTICE = 'Project kits check timed out'

_KIT_ID_RE = re.compile(r'^[a-z0-9]+(-[a-z0-9]+)*$')
# What the companion prints for `hermes componentize --version`: one line,
# "componentize <version>". Anything else (Hermes's own version text, an error,
# several lines) means the companion did not answer.
_COMPANION_VERSION_RE = re.compile(r'componentize [0-9A-Za-z][0-9A-Za-z.+-]{0,63}')
_VAR_KEY_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]*$')

# Strip lists live in child_env.py (shared policy); these public names are kept for
# tests and the README.  Componentize keep/drop semantics are unchanged.
_STRIPPED_CHILD_ENV_NAMES = COMPONENTIZE_STRIPPED_NAMES
_STRIPPED_CHILD_ENV_PREFIXES = COMPONENTIZE_STRIPPED_PREFIXES


def _child_env(base_env=None) -> dict[str, str]:
    """Build a sanitized child environment that strips approval and interactivity flags."""
    src = os.environ if base_env is None else base_env
    return {
        k: v
        for k, v in src.items()
        if k not in _STRIPPED_CHILD_ENV_NAMES
        and not k.startswith(_STRIPPED_CHILD_ENV_PREFIXES)
    }


def _loads(text):
    """json.loads that reports too-deep nesting as ValueError, like other bad JSON."""
    try:
        return json.loads(text)
    except RecursionError as exc:
        raise ValueError('JSON is nested too deeply') from exc


def _probe_with_timeout(command, *, timeout: float | None = None) -> tuple[bool, str | None, bool]:
    eff_timeout = 15.0 if timeout is None else min(15.0, float(timeout))
    if eff_timeout <= 0:
        return False, None, True
    try:
        result = subprocess.run([*command, '--version'], stdin=subprocess.DEVNULL,
                                env=_child_env(), capture_output=True, text=True,
                                timeout=eff_timeout, check=False)
        if result.returncode == 0:
            return True, result.stdout.strip() or None, False
    except subprocess.TimeoutExpired:
        return False, None, True
    except OSError:
        pass
    return False, None, False


def _probe(command, *, timeout: float | None = None):
    found, version, _timed_out = _probe_with_timeout(command, timeout=timeout)
    return found, version


def _executable(path, root):
    candidate = Path(path)
    if not candidate.is_absolute():
        return None
    resolved = candidate.resolve()
    if root is not None and resolved.is_relative_to(Path(root).resolve()):
        return None
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    return os.fspath(path)


def detect_command(override=None, root=None, *, timeout: float | None = None, deadline: float | None = None):
    """Resolve and probe a safe componentize CLI command outside the project root."""
    eff_deadline = deadline
    if eff_deadline is None and timeout is not None:
        eff_deadline = time.monotonic() + float(timeout)

    def _run_probe(cmd: list[str]) -> tuple[bool, str | None, bool]:
        if eff_deadline is not None:
            rem = eff_deadline - time.monotonic()
            if rem <= 0:
                return False, None, True
            probe_timeout: float | None = min(15.0, rem)
        else:
            probe_timeout = 15.0
        found, version, timed_out = _probe_with_timeout(cmd, timeout=probe_timeout)
        if not timed_out and eff_deadline is not None and (eff_deadline - time.monotonic()) <= 0:
            return False, None, True
        return found, version, timed_out

    if override is not None:
        executable = _executable(override, root)
        if executable is None:
            print('componentize override rejected: require an absolute executable '
                  'regular file outside the project.', file=sys.stderr)
            return None, 'absent', None
        found, version, timed_out = _run_probe([executable])
        if timed_out:
            return None, 'timeout', None
        return ([executable], 'override', version) if found else (None, 'absent', None)
    entries = []
    for entry in os.environ.get('PATH', '').split(os.pathsep):
        if not Path(entry).is_absolute():
            continue
        directory = Path(entry)
        if root is None or not directory.resolve().is_relative_to(Path(root).resolve()):
            entries.append(str(directory))
    safe_path = os.pathsep.join(entries)
    any_timed_out = False
    for name, suffix, source in [('hermes', ['componentize'], 'hermes'),
                                  ('componentize', [], 'path')]:
        located = shutil.which(name, path=safe_path)
        executable = _executable(located, root) if located else None
        if executable:
            if eff_deadline is not None and (eff_deadline - time.monotonic()) <= 0:
                return None, 'timeout', None
            command = [executable, *suffix]
            found, version, timed_out = _run_probe(command)
            if timed_out:
                any_timed_out = True
                if eff_deadline is not None and (eff_deadline - time.monotonic()) <= 0:
                    return None, 'timeout', None
                continue
            if found and source == 'hermes' and not (
                    version and _COMPANION_VERSION_RE.fullmatch(version)):
                found, version = False, None
            if found or (source == 'path' and not any_timed_out):
                return command, source, version
    return None, ('timeout' if any_timed_out else 'absent'), None


def _valid_survey_envelope(data, root):
    return (isinstance(data, dict) and data.get('schema') == 'componentize.survey/1'
            and data.get('ok') is True and type(data.get('exit')) is int
            and data['exit'] == 0 and data.get('status') in ('pass', 'ok')
            and isinstance(data.get('path'), str) and 'error' in data
            and all(isinstance(data.get(key), list)
                    for key in ('files', 'proposed_splits', 'findings'))
            and os.path.realpath(data['path']) == os.path.realpath(root))


def read_survey(root):
    """Bounded, no-follow, nonblocking read, including FIFO/device rejection."""
    path = verify_nofollow_within_root(Path(root), SURVEY_PATH)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SURVEY_BYTES:
            raise ValueError('unsafe survey file or size limit exceeded')
        raw = stream.read(MAX_SURVEY_BYTES + 1)
    if len(raw) > MAX_SURVEY_BYTES:
        raise ValueError('survey size limit exceeded')
    data = _loads(raw)
    if not _valid_survey_envelope(data, root):
        raise ValueError('invalid or failed componentize.survey/1 envelope')
    return data


class CliCancelled(Exception):
    """The caller's cancel hook was set while the companion was running; it was stopped."""


def _run_cli(command, args, *, cwd, timeout: float = 60.0, cancel=None):
    """Drain both pipes with bounded buffers and one wall-clock deadline.

    With ``cancel`` (an object with ``is_set()``) the companion runs in its own process
    group, and the whole group is stopped when the hook is set (CliCancelled)."""
    argv = [*command, *args]
    group = cancel is not None and os.name != 'nt'
    with subprocess.Popen(argv, cwd=cwd, env=_child_env(), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          **({'start_new_session': True} if group else {})) as proc:
        assert proc.stdout is not None and proc.stderr is not None
        buffers = {proc.stdout.fileno(): bytearray(), proc.stderr.fileno(): bytearray()}
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                for stream in buffers:
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    if cancel is not None and cancel.is_set():
                        raise CliCancelled()
                    for key, _ in selector.select(remaining if cancel is None else min(remaining, 0.2)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        buffers[key.fd].extend(chunk)
                        if len(buffers[key.fd]) > MAX_CLI_OUTPUT_BYTES:
                            raise ValueError('componentize output size limit exceeded')
                proc.wait(timeout=max(0, deadline - time.monotonic()))
        finally:
            if proc.poll() is None:
                if group:
                    from .lint_env import _kill_process_group
                    _kill_process_group(proc)
                else:
                    proc.kill()
            proc.wait()
        return subprocess.CompletedProcess(argv, proc.returncode,
            buffers[proc.stdout.fileno()].decode('utf-8'),
            buffers[proc.stderr.fileno()].decode('utf-8', errors='replace'))


def _run_survey(command, root):
    """Run componentize survey via the bounded CLI runner."""
    return _run_cli(command, ['survey', str(root), '--json'], cwd=root, timeout=60)


def _is_safe_rel_dir(value) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value.startswith('/') or '\\' in value or '\x00' in value:
        return False
    parts = PurePosixPath(value).parts
    if not parts:
        return False
    return all(part not in ('', '.', '..') for part in parts)


def _valid_kit_meta(item) -> bool:
    return (
        isinstance(item, dict)
        and isinstance(item.get('id'), str) and bool(item['id'])
        and isinstance(item.get('name'), str)
        and isinstance(item.get('summary'), str)
        and isinstance(item.get('tags'), list)
        and all(isinstance(tag, str) for tag in item['tags'])
        and type(item.get('version')) is int
    )


def _valid_declared_dirs(items) -> bool:
    if not isinstance(items, list):
        return False
    for item in items:
        if not isinstance(item, dict):
            return False
        if not _is_safe_rel_dir(item.get('dir')):
            return False
        if not isinstance(item.get('summary'), str) or not isinstance(item.get('why'), str):
            return False
    return True


def _valid_placement_rules(items) -> bool:
    if not isinstance(items, list):
        return False
    for item in items:
        if not isinstance(item, dict):
            return False
        if not isinstance(item.get('kind'), str) or not item['kind']:
            return False
        exts = item.get('match_ext')
        if (not isinstance(exts, list) or not exts
                or not all(isinstance(ext, str) and ext.startswith('.') and len(ext) > 1 for ext in exts)):
            return False
        if not _is_safe_rel_dir(item.get('dest_dir')):
            return False
        if type(item.get('lfs')) is not bool:
            return False
        if not isinstance(item.get('reason'), str):
            return False
    return True


def _valid_items(items) -> bool:
    if not isinstance(items, list):
        return False
    for entry in items:
        if not isinstance(entry, dict):
            return False
        if not _is_safe_rel_dir(entry.get('path')):
            return False
        if not isinstance(entry.get('state'), str) or not entry['state']:
            return False
    return True


def _valid_kit_envelope(data, call: str) -> bool:
    if not isinstance(data, dict):
        return False
    if data.get('schema') != KIT_SCHEMA:
        return False
    if type(data.get('ok')) is not bool:
        return False
    if data.get('status') not in ('pass', 'fail', 'error'):
        return False
    if not isinstance(data.get('findings'), list):
        return False
    if not all(isinstance(f, dict) for f in data['findings']):
        return False

    if call == 'list':
        kits = data.get('kits')
        return isinstance(kits, list) and all(_valid_kit_meta(k) for k in kits)
    if call == 'show':
        tree = data.get('tree')
        return (
            _valid_kit_meta(data.get('kit'))
            and _valid_declared_dirs(data.get('declared_dirs'))
            and _valid_placement_rules(data.get('placement_rules'))
            and isinstance(tree, list)
            and all(isinstance(entry, str) for entry in tree)
            and isinstance(data.get('agents_block'), str)
        )
    if call in ('apply', 'check'):
        return (
            isinstance(data.get('root'), str) and bool(data['root'])
            and isinstance(data.get('kit'), str) and bool(data['kit'])
            and _valid_items(data.get('items'))
            and _valid_declared_dirs(data.get('declared_dirs'))
            and _valid_placement_rules(data.get('placement_rules'))
        )
    return False


def _kit_result(status: str, data, notice: str, exit_code) -> dict:
    clean_notice = ' '.join(str(notice or '').splitlines()).strip() or status
    if len(clean_notice) > 240:
        clean_notice = clean_notice[:237] + '...'
    return {'status': status, 'data': data, 'notice': clean_notice, 'exit': exit_code}


def _validate_kit_id(kit_id):
    if not isinstance(kit_id, str) or not _KIT_ID_RE.fullmatch(kit_id):
        return 'invalid kit_id: must match ^[a-z0-9]+(-[a-z0-9]+)*$'
    return None


def _expected_root(dest_str: str) -> str:
    """The folder the companion will report: realpath of the request, taken now.

    The companion resolves the path once and answers with that resolved folder.
    Resolving here, before it runs, means a link changed during the run is caught.
    """
    return os.path.realpath(os.path.normpath(dest_str))


def _validate_dest(dest):
    if not isinstance(dest, (str, os.PathLike)):
        return None, None, 'invalid dest: must be an absolute path'
    raw = os.fspath(dest)
    if not isinstance(raw, str) or not raw or '\x00' in raw or '\\' in raw:
        return None, None, 'invalid dest: must be an absolute path'
    path = Path(raw)
    if not path.is_absolute():
        return None, None, 'invalid dest: must be an absolute path'
    if '..' in path.parts:
        return None, None, 'invalid dest: path must not contain .. segments'
    parent = path.parent
    try:
        if not parent.exists() or not parent.is_dir():
            return None, None, f'invalid dest: parent directory does not exist ({parent})'
    except OSError as exc:
        return None, None, f'invalid dest: {exc}'
    return str(path), parent, None


def _validate_variables(variables):
    if variables is None:
        return [], None
    if not isinstance(variables, dict):
        return None, 'invalid variables: must be a dict of str->str'
    flags = []
    for key, val in variables.items():
        if not isinstance(key, str) or not isinstance(val, str):
            return None, 'invalid variables: keys and values must be strings'
        if not _VAR_KEY_RE.fullmatch(key):
            return None, f'invalid variable name: {key!r}'
        if '\n' in val or '\r' in val or '\x00' in val:
            return None, f'invalid variable value for {key!r}: must be single-line string'
        flags.extend(['--set', f'{key}={val}'])
    return flags, None


def _kit_deadline(timeout: float | None) -> float:
    budget = 60.0 if timeout is None else float(timeout)
    return time.monotonic() + budget


def _kit_timeout_result(call: str) -> dict:
    return _kit_result('error', None, f'{TIMEOUT_NOTICE}: componentize kit {call} timed out.', None)


def _invoke_kit(
    call: str,
    args: list[str],
    *,
    cwd: Path,
    root: Path | None,
    kit_id: str | None = None,
    dest: str | None = None,
    expected_root: str | None = None,
    timeout: float | None = None,
    deadline: float | None = None,
    cancel=None,
) -> dict:
    eff_deadline = _kit_deadline(timeout) if deadline is None else float(deadline)
    rem_start = eff_deadline - time.monotonic()
    if rem_start <= 0:
        return _kit_timeout_result(call)
    from .componentize_settings import load
    try:
        settings = load()
    except (OSError, TypeError, ValueError) as exc:
        return _kit_result('error', None, f'componentize settings error: {exc}', None)
    rem_detect = eff_deadline - time.monotonic()
    if rem_detect <= 0:
        return _kit_timeout_result(call)
    det = detect_command(
        settings['cli_path_override'],
        root=root,
        timeout=min(60.0, rem_detect),
        deadline=eff_deadline,
    )
    command = det[0]
    source = det[1] if len(det) > 1 else ('absent' if command is None else 'path')
    if source == 'timeout':
        return _kit_timeout_result(call)
    if command is None:
        return _kit_result('unavailable', None, UNAVAILABLE_NOTICE, None)
    rem_run = eff_deadline - time.monotonic()
    if rem_run <= 0:
        return _kit_timeout_result(call)
    try:
        proc = _run_cli(command, args, cwd=cwd, timeout=min(60.0, rem_run),
                        **({'cancel': cancel} if cancel is not None else {}))
    except CliCancelled:
        return _kit_result('error', None, f'componentize kit {call} was cancelled.', None)
    except subprocess.TimeoutExpired:
        return _kit_timeout_result(call)
    except (OSError, ValueError) as exc:
        return _kit_result('error', None, f'componentize kit {call} failed: {exc}', None)

    return _interpret_kit_reply(proc, call, kit_id=kit_id, dest=dest, expected_root=expected_root)


def _interpret_kit_reply(
    proc: subprocess.CompletedProcess, call: str, *, kit_id: str | None,
    dest: str | None, expected_root: str | None,
) -> dict:
    """Validate the companion reply against its envelope and original request."""
    try:
        data = _loads(proc.stdout)
    except (ValueError, TypeError):
        data = None
    skipped = 0
    if call == 'list' and isinstance(data, dict) and isinstance(data.get('kits'), list):
        # Leave out bad entries one by one; one bad entry must not hide every kit.
        kept = [kit for kit in data['kits'] if _valid_kit_meta(kit)]
        skipped = len(data['kits']) - len(kept)
        if skipped:
            data['kits'] = kept
            data['skipped_kits'] = skipped

    if proc.returncode not in (0, 1):
        err_msg = data.get('error') if isinstance(data, dict) and isinstance(data.get('error'), str) else None
        if not err_msg and proc.stderr:
            err_msg = proc.stderr.splitlines()[0][:240]
        detail = err_msg or f'exit {proc.returncode}'
        return _kit_result('error', None, f'componentize kit {call} error (exit {proc.returncode}): {detail}', proc.returncode)

    if data is None:
        return _kit_result('error', None, f'componentize kit {call} returned invalid JSON.', proc.returncode)
    if not isinstance(data, dict) or data.get('schema') != KIT_SCHEMA:
        return _kit_result('error', None, f'componentize kit {call} returned wrong schema.', proc.returncode)
    if data.get('status') == 'error' or not _valid_kit_envelope(data, call):
        return _kit_result('error', None, f'componentize kit {call} envelope validation failed.', proc.returncode)
    if call == 'show' and kit_id is not None and data['kit']['id'] != kit_id:
        return _kit_result('error', None, f'componentize kit {call} reply did not match the request.', proc.returncode)
    if call in ('apply', 'check'):
        # The reply root is compared as text, never resolved: it must be the path
        # as written or the folder it resolved to before the companion ran.
        allowed = {os.path.normpath(p) for p in (dest, expected_root) if p is not None}
        if (kit_id is not None and data.get('kit') != kit_id) or (
            allowed and os.path.normpath(data['root']) not in allowed
        ):
            return _kit_result('error', None, f'componentize kit {call} reply did not match the request.', proc.returncode)
    if proc.returncode == 0 and (data.get('ok') is not True or data.get('status') != 'pass'):
        return _kit_result('error', None, f'componentize kit {call} envelope status mismatch on exit 0.', proc.returncode)
    if proc.returncode == 1 and (call not in ('apply', 'check') or data.get('ok') is not False or data.get('status') != 'fail'):
        return _kit_result('error', None, f'componentize kit {call} exited 1 without valid fail envelope.', proc.returncode)

    notice = f'componentize kit {call} {data["status"]}.'
    if skipped:
        notice += (' 1 malformed kit entry was left out.' if skipped == 1
                   else f' {skipped} malformed kit entries were left out.')
    return _kit_result('ok', data, notice, proc.returncode)


def kit_list(*, timeout: float | None = None) -> dict:
    """List available componentize project kits."""
    deadline = _kit_deadline(timeout)
    return _invoke_kit(
        'list',
        ['kit', 'list', '--json'],
        cwd=Path(tempfile.gettempdir()),
        root=None,
        timeout=timeout,
        deadline=deadline,
    )


def kit_show(kit_id: str, *, timeout: float | None = None) -> dict:
    """Show metadata, declared_dirs, placement_rules, tree, and agents_block for a kit."""
    deadline = _kit_deadline(timeout)
    err = _validate_kit_id(kit_id)
    if err:
        return _kit_result('error', None, err, None)
    return _invoke_kit(
        'show',
        ['kit', 'show', kit_id, '--json'],
        cwd=Path(tempfile.gettempdir()),
        root=None,
        kit_id=kit_id,
        timeout=timeout,
        deadline=deadline,
    )


def kit_apply(kit_id: str, dest, variables=None, *, timeout: float | None = None) -> dict:
    """Apply a componentize kit to an absolute destination path."""
    deadline = _kit_deadline(timeout)
    err = _validate_kit_id(kit_id)
    if err:
        return _kit_result('error', None, err, None)
    dest_str, parent, dest_err = _validate_dest(dest)
    if dest_err or dest_str is None or parent is None:
        return _kit_result('error', None, dest_err or 'invalid dest', None)
    var_flags, var_err = _validate_variables(variables)
    if var_err or var_flags is None:
        return _kit_result('error', None, var_err or 'invalid variables', None)
    return _invoke_kit(
        'apply',
        ['kit', 'apply', kit_id, dest_str, *var_flags, '--json'],
        cwd=parent,
        root=Path(dest_str),
        kit_id=kit_id,
        dest=dest_str,
        expected_root=_expected_root(dest_str),
        timeout=timeout,
        deadline=deadline,
    )


def kit_check(kit_id: str, dest, *, timeout: float | None = None, cancel=None) -> dict:
    """Check whether an absolute destination directory satisfies a componentize kit."""
    deadline = _kit_deadline(timeout)
    err = _validate_kit_id(kit_id)
    if err:
        return _kit_result('error', None, err, None)
    dest_str, parent, dest_err = _validate_dest(dest)
    if dest_err or dest_str is None or parent is None:
        return _kit_result('error', None, dest_err or 'invalid dest', None)
    return _invoke_kit(
        'check',
        ['kit', 'check', kit_id, dest_str, '--json'],
        cwd=parent,
        root=Path(dest_str),
        kit_id=kit_id,
        dest=dest_str,
        expected_root=_expected_root(dest_str),
        timeout=timeout,
        deadline=deadline,
        cancel=cancel,
    )


def survey_after_apply(root: Path, agents_md_max_lines=40):
    """Adoption entry point; new projects have their own caller-side flag."""
    from .componentize_settings import load
    try:
        enabled = load()['enabled_on_adopt']
    except (OSError, TypeError, ValueError) as exc:
        print(f'componentize survey skipped: {exc}', file=sys.stderr)
        return {'status': 'skipped', 'exit': 0}
    if not enabled:
        return {'status': 'skipped', 'exit': 0}
    return survey_project(root, agents_md_max_lines=agents_md_max_lines)


def survey_project(root: Path, *, agents_md_max_lines=40):
    """Run a caller-authorized survey, publishing only after AGENTS succeeds."""
    # Lazy import avoids the settings/status -> bridge dependency cycle.
    from .componentize_settings import load
    try:
        root = Path(root).resolve()
        settings = load()
        command = detect_command(settings['cli_path_override'], root=root, timeout=15.0)[0]
        if command is None:
            print('componentize unavailable; optional survey skipped (no job started).', file=sys.stderr)
            return {'status': 'skipped', 'exit': 0}
        target = verify_nofollow_within_root(root, SURVEY_PATH)
        if target.exists() and not stat.S_ISREG(target.lstat().st_mode):
            raise ValueError('survey target is not a regular file')
        proc = _run_survey(command, root)
        if proc.returncode != 0:
            detail = proc.stderr.splitlines()[0][:300] if proc.stderr else ''
            raise ValueError(f'survey exited {proc.returncode}: {detail}')
        if len(proc.stdout.encode('utf-8')) > MAX_SURVEY_BYTES:
            raise ValueError('survey output size limit exceeded')
        data = _loads(proc.stdout)
        if not _valid_survey_envelope(data, root):
            raise ValueError('invalid or failed componentize.survey/1 envelope')
        serialized = json.dumps(data) + '\n'
        if len(serialized.encode('utf-8')) > MAX_SURVEY_BYTES:
            raise ValueError('survey file size limit exceeded')
        agents = verify_nofollow_within_root(root, 'AGENTS.md')
        original_bytes = agents.read_bytes() if agents.exists() else None
        original = original_bytes.decode('utf-8') if original_bytes is not None else ''
        marker = 'Componentize candidates:'
        # Generated AGENTS.md uses LF; normalize existing CRLF consistently.
        lines = [line for line in original.splitlines() if not line.startswith(marker)]
        line = (f'{marker} {len(data["proposed_splits"])}; review .adopt/componentize-survey.json. '
                'Never begin automatically; explicit user approval required.')
        agents_written = len(lines) + 1 <= clamp_max_lines(agents_md_max_lines)
        if agents_written:
            safe_write_text(root, 'AGENTS.md', '\n'.join([*lines, line]) + '\n', overwrite=True)
        else:
            print('componentize AGENTS.md line skipped: line budget exceeded.', file=sys.stderr)
        try:
            safe_write_text(root, SURVEY_PATH, serialized, overwrite=True)
        except (OSError, TypeError, ValueError, SafetyError):
            if agents_written:
                if original_bytes is None:
                    verify_nofollow_within_root(root, 'AGENTS.md').unlink()
                else:
                    safe_write_bytes(root, 'AGENTS.md', original_bytes, overwrite=True)
            raise
        return {'status': 'ok', 'exit': 0}
    except (OSError, TypeError, ValueError, SafetyError, subprocess.TimeoutExpired) as exc:
        print(f'componentize survey skipped: {exc}', file=sys.stderr)
        return {'status': 'skipped', 'exit': 0}
