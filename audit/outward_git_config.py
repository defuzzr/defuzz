"""Pure fail-closed classification of caller-captured Git configuration.

Call classify_git_config(data) for content- OR role-identified Git configs;
no filename assumption, filesystem access, Git invocation, or value retention.
'inert' means only this file's parsed keys are inert, not the repository safe.
Unsupported syntax and unknown keys cannot be verified.
"""
from dataclasses import dataclass
import re
from .outward_git import _LINE_CONTINUATION, _value


@dataclass(frozen=True)
class GitConfigClassification:
    status: str
    reasons: tuple[str, ...] = ()


# Deliberately small: never allow an entire section or namespace.
_INERT = {
    'core': {'repositoryformatversion', 'filemode', 'bare', 'logallrefupdates',
             'ignorecase', 'precomposeunicode', 'autocrlf', 'eol', 'safecrlf'},
    'user': {'name', 'email'},
    'init': {'defaultbranch'},
    'extensions': {'worktreeconfig', 'objectformat'},
}
_EXECUTING = {
    'core': {'fsmonitor', 'sshcommand', 'pager', 'editor', 'hookspath', 'askpass', 'gitproxy'},
    'sequence': {'editor'}, 'filter': {'clean', 'smudge', 'process'},
    'diff': {'textconv', 'command', 'external'}, 'merge': {'driver'},
    'credential': {'helper'}, 'gpg': {'program'},
    'remote': {'uploadpack', 'receivepack'},
    'uploadpack': {'packobjectshook'}, 'receive': {'procreceiverefs'},
    'upload': {'command'}, 'receivepack': {'command'},
}
_SECTION_HEADER = re.compile(r'\[([A-Za-z0-9-]+)(?:(\.[A-Za-z0-9.-]+)|\s+("(?:[^"\\\n]|\\.)*"))?\]\s*(?:[#;].*)?')
_KEY_ENTRY = re.compile(r'([A-Za-z][A-Za-z0-9-]*)(?:\s*=\s*(.*)|\s*(?:[#;].*)?)')


def _classify_section(line: str, reasons: set[str]) -> tuple[str, bool]:
    match = _SECTION_HEADER.fullmatch(line)
    if not match:
        raise ValueError
    section, subsection = match[1].lower(), bool(match[2] or match[3])
    if section == 'includeif':
        reasons.add('git_include_condition_unresolved')
    elif section == 'include':
        reasons.add('git_include_unresolved')
    elif section not in _INERT and section not in _EXECUTING and section not in {'alias', 'pager'}:
        reasons.add('git_config_unknown_section')
    if subsection and section in _INERT:
        reasons.add('git_config_unknown_section')
    return section, subsection


def classify_git_config(data: bytes | str) -> GitConfigClassification:
    """Return status inert/dynamic/could_not_verify and fixed, redacted reasons."""
    try:
        text = data.decode('utf-8-sig') if isinstance(data, bytes) else data
        if '\x00' in text:
            raise ValueError
        section, subsection, reasons, dynamic = None, False, set(), False
        for raw_line in _LINE_CONTINUATION.sub(r'\1', text).splitlines():
            line = raw_line.strip()
            if not line or line.startswith(('#', ';')):
                continue
            if line.startswith('['):
                section, subsection = _classify_section(line, reasons)
                continue
            match = _KEY_ENTRY.fullmatch(line)
            if not match or section is None:
                raise ValueError
            value = _value(match[2]) if match[2] is not None else ''
            key = match[1].lower()
            if (key in _EXECUTING.get(section, set()) or section == 'pager'
                    or section == 'alias' and value.lstrip().startswith('!')):
                dynamic = True
                reasons.add('git_config_execution_unresolved')
            elif subsection or key not in _INERT.get(section, set()):
                reasons.add('git_config_unknown_key')
        status = 'dynamic' if dynamic else 'could_not_verify' if reasons else 'inert'
        return GitConfigClassification(status, tuple(sorted(reasons)))
    except (ValueError, UnicodeError, TypeError):
        return GitConfigClassification('could_not_verify', ('git_config_parse_failed',))
