"""Profile-scoped componentize preferences; no dashboard dependency."""
from __future__ import annotations

import json
import os
import tempfile
from plugins.plugin_storage import plugin_data_dir

DEFAULTS = dict(enabled_on_adopt=True, run_survey_on_new=False, cli_path_override=None)


def _validated(settings) -> dict:
    if not isinstance(settings, dict) or settings.keys() - DEFAULTS.keys():
        raise ValueError('unknown componentize settings or non-object input')
    value = {**DEFAULTS, **settings}
    for key in ('enabled_on_adopt', 'run_survey_on_new'):
        if type(value[key]) is not bool:
            raise ValueError(f'{key} must be a boolean')
    path = value['cli_path_override']
    if path is not None and (not isinstance(path, str) or not path.strip() or '\x00' in path):
        raise ValueError('cli_path_override must be a nonempty executable path or null')
    return value


def load() -> dict:
    """Read preferences; missing files use defaults."""
    try:
        return _validated(json.loads((plugin_data_dir('defuzz') / 'componentize-settings.json').read_text(encoding='utf-8')))
    except FileNotFoundError:
        return DEFAULTS.copy()


def save(settings: dict) -> dict:
    """Atomically replace preferences and return the saved object."""
    value = _validated(settings)
    target = plugin_data_dir('defuzz') / 'componentize-settings.json'
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=target.parent,
                                         prefix='.componentize-', delete=False) as stream:
            temporary = stream.name
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return value


def status(project_root=None) -> dict:
    """Probe availability without running survey or starting a job."""
    # Lazy import avoids the bridge -> settings dependency cycle.
    from .componentize_bridge import detect_command, read_survey
    command, source, version = detect_command(load()['cli_path_override'], root=project_root, timeout=15.0)
    summary = None
    if project_root is not None:
        from .safety import SafetyError
        try:
            data = read_survey(project_root)
            summary = {key: data[key] for key in ('schema', 'status', 'path')}
            summary.update({key: len(data[key]) for key in ('files', 'proposed_splits', 'findings')})
        except (OSError, ValueError, SafetyError):
            pass
    return dict(detected=command is not None, version=version, source=source, last_survey=summary)
