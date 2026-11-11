"""Tests for audit.unattended_exposure (what can run without a person approving it)."""
from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from tests.conftest import load_submodule


def _mod():
    return load_submodule('audit.unattended_exposure')


def _snapshot_tree(root: Path) -> list[tuple]:
    records = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        st_dir = os.lstat(dirpath)
        records.append(('dir', rel_dir, st_dir.st_mode, st_dir.st_mtime_ns))
        for names, kind in ((dirnames, 'subdir'), (filenames, 'file')):
            for name in names:
                full = os.path.join(dirpath, name)
                rel = Path(full).relative_to(root).as_posix()
                st = os.lstat(full)
                if os.path.islink(full):
                    records.append(('symlink', rel, os.readlink(full), st.st_mtime_ns))
                elif kind == 'file':
                    digest = hashlib.sha256(Path(full).read_bytes()).hexdigest()
                    records.append(('file', rel, st.st_mode, st.st_size, st.st_mtime_ns, digest))
    return records


def _ids(res) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in res['findings']:
        out.setdefault(f['id'], []).append(f)
    return out


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


def _plugin(root: Path, dirname: str, manifest: str, *, init: str | None = None) -> Path:
    d = root / 'plugins' / dirname
    _write(d / 'plugin.yaml', manifest)
    if init is not None:
        _write(d / '__init__.py', init)
    return d


def _meta(root: Path, records: dict) -> None:
    _write(root / 'plugins' / '.install-metadata.json', json.dumps(records))


SHA = 'a' * 40


def test_missing_and_empty_home_returns_not_measured(tmp_path):
    mod = _mod()
    missing = tmp_path / 'does_not_exist'
    res_missing = mod.audit_unattended_exposure(profile_path=missing)
    sec_missing = res_missing['unattended_exposure']
    assert res_missing['coverage'] == 'could_not_verify'
    assert sec_missing['status'] == 'not_measured'
    assert sec_missing['reason'] == 'missing'
    assert {f['id'] for f in res_missing['findings']} == {'unattended_exposure.could_not_verify'}
    assert all(f['classification'] == 'info' for f in res_missing['findings'])
    assert 'profile_path' not in sec_missing
    assert str(tmp_path) not in json.dumps(res_missing)

    empty = tmp_path / 'empty_home'
    empty.mkdir()
    res_empty = mod.audit_unattended_exposure(empty)
    sec_empty = res_empty['unattended_exposure']
    assert sec_empty['status'] == 'not_measured'
    assert sec_empty['reason'] == 'empty'
    assert {f['id'] for f in res_empty['findings']} == {'unattended_exposure.could_not_verify'}

    a_file = tmp_path / 'a_file'
    a_file.write_text('x', encoding='utf-8')
    res_file = mod.audit_unattended_exposure(a_file)
    assert res_file['unattended_exposure']['reason'] == 'unreadable'


def test_clean_defaults_and_negative_do_not_flag_cases(tmp_path):
    mod = _mod()
    _write(tmp_path / 'config.yaml', '{}\n')

    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    sec = res['unattended_exposure']
    assert res['coverage'] == 'verified'
    assert sec['status'] == 'completed'
    assert res['findings'] == []

    s = sec['settings']
    expected = {
        'approvals.mode': ('smart', False),
        'approvals.cron_mode': ('deny', False),
        'approvals.unattended_mode': ('deny', False),
        'approvals.single_query_mode': ('deny', False),
        'command_allowlist': (0, False),
        'auxiliary.approval.model': ('unset', False),
        'terminal.backend': ('local', True),
        'browser.use_real_profile': (False, False),
        'code_execution.mode': ('project', False),
        'security.protected_instruction_files': (True, False),
        'security.allow_private_urls': (False, False),
        'tool_loop_guardrails.hard_stop_enabled': (False, False),
        'tool_loop_guardrails.non_interactive_hard_stop_enabled': (True, False),
        'agent.max_turns': ('unlimited', True),
        'delegation.max_concurrent_children': (10, False),
        'delegation.max_spawn_depth': (1, False),
        'delegation.max_iterations': (250, False),
        'cron.allow_agent_scheduling': (False, False),
        'cron.catch_up_missed': (True, True),
        'gateway.trust_recent_files': (True, True),
        'curator.enabled': (True, True),
        'plugins.auto_apply': (False, False),
        'updates.check': (True, False),
        'updates.auto_switch_parked_branch': (True, True),
        'updates.pre_update_backup': ('quick', False),
        'updates.non_interactive_local_changes': ('stash', False),
        'updates.parked_branch_strategy': ('switch', False),
        'skills.auto_load': (0, False),
        'plugins.enabled': (0, False),
        'mcp_servers': (0, False),
        'a2a_agents': (0, False),
    }
    assert set(s) == set(expected)
    for key, (value, widens) in expected.items():
        assert s[key] == {'value': value, 'source': 'default', 'widens_unattended_action': widens}, key

    # Negative cases: approvals off with docker; shipped messaging bundle; MCP servers counted only;
    # pinned plugin with pre_llm_call; disabled plugin with ten hooks; normal model/provider values.
    _write(tmp_path / 'config.yaml',
           'approvals:\n  mode: off\n'
           'terminal:\n  backend: docker\n'
           'delegation:\n  provider: openrouter\n  model: anthropic/claude-opus-4.6\n'
           'platform_toolsets:\n  cli: [hermes-cli]\n  telegram: [hermes-telegram]\n'
           'mcp_servers:\n  context7:\n    enabled: true\n  blender:\n    enabled: false\n'
           'plugins:\n  enabled: [security-guidance, disk-cleanup, pinned-injector]\n  disabled: [status-panel]\n')
    _plugin(tmp_path, 'pinned-injector', 'name: pinned-injector\nversion: 1.2.0\nhooks:\n  - pre_llm_call\n')
    _plugin(tmp_path, 'status-panel',
            'name: status-panel\nversion: 1.0.0\nprovides_hooks:\n'
            '  - on_session_start\n  - pre_llm_call\n  - post_llm_call\n'
            '  - pre_tool_call\n  - post_tool_call\n  - pre_approval_request\n'
            '  - post_approval_response\n  - on_session_end\n'
            '  - on_session_finalize\n  - on_session_reset\n')
    _meta(tmp_path, {'pinned-injector': {'pinned': True, 'revision': SHA}})

    res2 = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res2['coverage'] == 'verified'
    assert res2['findings'] == []
    sec2 = res2['unattended_exposure']
    assert sec2['mcp_servers'] == {'configured_count': 2, 'enabled_count': 1, 'disabled_count': 1}
    tg = sec2['platform_toolsets']['non_cli_platforms']['telegram']
    assert tg['high_risk_tools'] == ['code_execution', 'computer_use', 'cronjob', 'terminal']
    assert tg['beyond_default_high_risk_tools'] == []
    by_name = {Path(p['path']).name: p for p in sec2['plugins']['hook_plugins']}
    assert by_name['pinned-injector']['enabled'] is True
    assert by_name['pinned-injector']['pinned'] == 'yes'
    assert by_name['status-panel']['enabled'] is False
    assert by_name['status-panel']['hook_count'] == 10
    assert 'pre_approval_request' in by_name['status-panel']['prompt_or_approval_hooks']


def test_healthy_careful_home_has_no_findings_above_info(tmp_path):
    mod = _mod()
    _write(tmp_path / 'config.yaml',
           'approvals:\n  mode: manual\n  cron_mode: deny\n'
           'terminal:\n  backend: docker\n'
           'auxiliary:\n  approval:\n    model: claude-opus-4\n'
           'security:\n  allow_private_urls: false\n  protected_instruction_files: true\n'
           'tool_loop_guardrails:\n  hard_stop_enabled: false\n  non_interactive_hard_stop_enabled: true\n'
           'platform_toolsets:\n  cli: [hermes-cli]\n  telegram: [hermes-telegram]\n  webhook: [hermes-webhook]\n'
           'plugins:\n  enabled: [helper]\n')
    _plugin(tmp_path, 'helper', 'name: helper\nversion: 2.0.0\nhooks: [on_session_start]\n')
    _meta(tmp_path, {'helper': {'pinned': True, 'revision': SHA, 'source': 'url'}})
    _write(tmp_path / 'cron' / 'jobs.json', json.dumps({'jobs': [
        {'id': 'abc123def456', 'enabled': True, 'prompt': 'p', 'schedule': {'kind': 'cron', 'expr': '0 9 * * *'},
         'failure_streak': 0},
    ]}))
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res['coverage'] == 'verified'
    assert [f for f in res['findings'] if f['classification'] != 'info'] == []


# --- command_approval_off ---------------------------------------------------------------------


def test_command_approval_off_positive_and_near_misses(tmp_path):
    mod = _mod()
    cfg = tmp_path / 'config.yaml'

    _write(cfg, "approvals:\n  mode: 'off'\nterminal:\n  backend: local\n")
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    f = _ids(res)['unattended_exposure.command_approval_off'][0]
    assert f['classification'] == 'warning'
    assert f['evidence'] == {'approvals_mode': 'approval_off', 'terminal_backend': 'local', 'command_allowlist_count': 0}
    assert f['affected_identities'] == ['config.yaml']
    assert f['source_paths'][0]['path'] == 'config.yaml'

    # Unquoted YAML off (bool False) is the same mode per tools/approval_context.py:271-272.
    _write(cfg, 'approvals:\n  mode: off\nterminal:\n  backend: local\n')
    assert 'unattended_exposure.command_approval_off' in _ids(mod.audit_unattended_exposure(profile_path=tmp_path))

    # Near miss 1: approvals off but terminal.backend absent (TERMINAL_ENV may override the default).
    _write(cfg, 'approvals:\n  mode: off\n')
    res1 = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res1['unattended_exposure']['settings']['terminal.backend']['source'] == 'default'
    assert 'unattended_exposure.command_approval_off' not in _ids(res1)

    # Near miss 2: approvals.mode absent (default smart) with local backend.
    _write(cfg, 'terminal:\n  backend: local\n')
    assert 'unattended_exposure.command_approval_off' not in _ids(mod.audit_unattended_exposure(profile_path=tmp_path))

    # Near miss 3: off with an isolated container backend; off with ssh.
    for backend in ('docker', 'ssh', 'modal'):
        _write(cfg, f'approvals:\n  mode: off\nterminal:\n  backend: {backend}\n')
        assert 'unattended_exposure.command_approval_off' not in _ids(
            mod.audit_unattended_exposure(profile_path=tmp_path)), backend

    # Near miss 4: an env template the audit cannot resolve.
    _write(cfg, 'approvals:\n  mode: ${APPROVAL_MODE}\nterminal:\n  backend: local\n')
    res4 = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res4['unattended_exposure']['settings']['approvals.mode']['source'] == 'could_not_verify'
    assert 'unattended_exposure.command_approval_off' not in _ids(res4)

    # YAML true is 'manual' (tools/approval_context.py:271-272), not unknown.
    _write(cfg, 'approvals:\n  mode: true\n')
    assert mod.audit_unattended_exposure(profile_path=tmp_path)['unattended_exposure']['settings'][
        'approvals.mode']['value'] == 'manual'


def test_binary_approval_modes_follow_hermes_string_rule(tmp_path):
    mod = _mod()
    cfg = tmp_path / 'config.yaml'
    # tools/approval_context.py:347-353: str(value).lower().strip() in {approve, off, allow, yes}.
    cases = {
        'approve': 'approve', '"off"': 'approve', 'allow': 'approve', '"yes"': 'approve',
        'true': 'deny', 'yes': 'deny', 'off': 'deny', 'deny': 'deny', 'bogus': 'deny', 'null': 'deny',
    }
    for raw, want in cases.items():
        _write(cfg, f'approvals:\n  cron_mode: {raw}\n')
        row = mod.audit_unattended_exposure(profile_path=tmp_path)['unattended_exposure']['settings']['approvals.cron_mode']
        assert row['value'] == want and row['source'] == 'config', (raw, row)


# --- unattended_auto_approve ------------------------------------------------------------------
# tools/approval_context.py:347-371 (_binary_approval_mode); tools/approval.py:674-693 (contexts),
# 737-754 (_unattended_deny returns None = allow for approve), 1252-1287 (floors run first).

_MODE_EVIDENCE_KEYS = {
    'cron_mode': 'cron_mode_approve',
    'unattended_mode': 'unattended_mode_approve',
    'single_query_mode': 'single_query_mode_approve',
}


@pytest.mark.parametrize('mode_key', ['cron_mode', 'unattended_mode', 'single_query_mode'])
def test_unattended_auto_approve_each_mode_key_with_local_backend_is_warning(tmp_path, mode_key):
    mod = _mod()
    _write(tmp_path / 'config.yaml', f'approvals:\n  {mode_key}: approve\nterminal:\n  backend: local\n')
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    found = _ids(res)['unattended_exposure.unattended_auto_approve']
    assert len(found) == 1
    f = found[0]
    assert f['classification'] == 'warning'
    expected = {v: (k == mode_key) for k, v in _MODE_EVIDENCE_KEYS.items()}
    assert f['evidence'] == {**expected, 'approve_mode_count': 1,
                             'terminal_backend': 'local', 'terminal_backend_source': 'config'}
    assert f['consequence'] == mod.FINDING_CONSEQUENCES['unattended_exposure.unattended_auto_approve']
    assert f['affected_identities'] == ['config.yaml']


def test_unattended_auto_approve_defaults_and_deny_give_no_finding(tmp_path):
    mod = _mod()
    cfg = tmp_path / 'config.yaml'
    for text in ('{}\n', 'terminal:\n  backend: local\n',
                 'approvals:\n  cron_mode: deny\n  unattended_mode: deny\n  single_query_mode: deny\n'
                 'terminal:\n  backend: local\n',
                 # YAML booleans stringify to 'true'/'false' and resolve to deny.
                 'approvals:\n  cron_mode: true\n  unattended_mode: yes\nterminal:\n  backend: local\n'):
        _write(cfg, text)
        assert 'unattended_exposure.unattended_auto_approve' not in _ids(
            mod.audit_unattended_exposure(profile_path=tmp_path)), text


def test_unattended_auto_approve_non_local_or_default_backend_is_review_suggested(tmp_path):
    mod = _mod()
    cfg = tmp_path / 'config.yaml'
    _write(cfg, 'approvals:\n  cron_mode: approve\n  unattended_mode: allow\n  single_query_mode: \"yes\"\n'
                'terminal:\n  backend: docker\n')
    f = _ids(mod.audit_unattended_exposure(profile_path=tmp_path))['unattended_exposure.unattended_auto_approve'][0]
    assert f['classification'] == 'review_suggested'
    assert f['evidence']['approve_mode_count'] == 3
    assert f['evidence']['terminal_backend'] == 'docker'
    # terminal.backend absent: TERMINAL_ENV may replace the default, so not a warning.
    _write(cfg, 'approvals:\n  cron_mode: approve\n')
    f2 = _ids(mod.audit_unattended_exposure(profile_path=tmp_path))['unattended_exposure.unattended_auto_approve'][0]
    assert f2['classification'] == 'review_suggested'
    assert (f2['evidence']['terminal_backend'], f2['evidence']['terminal_backend_source']) == ('local', 'default')
    # A managed overlay leaves every row unverified: no finding.
    managed = tmp_path / 'etc_hermes'
    managed.mkdir()
    _write(cfg, 'approvals:\n  cron_mode: approve\nterminal:\n  backend: local\n')
    assert 'unattended_exposure.unattended_auto_approve' not in _ids(
        mod.audit_unattended_exposure(profile_path=tmp_path, managed_dir=managed))


# --- remote_platform_has_powerful_tools -------------------------------------------------------


def test_remote_platform_powerful_tools_positive_and_near_misses(tmp_path):
    mod = _mod()
    cfg = tmp_path / 'config.yaml'
    agents = ''.join(f'        peer-{i:02d}:\n          timeout: 3600\n' for i in range(1, 18))

    _write(cfg, 'platform_toolsets:\n'
                '  a2a: [browser, code_execution, computer_use, cronjob, delegation, file, hermes-a2a, memory, skills, terminal]\n'
                f'platforms:\n  a2a:\n    extra:\n      agents:\n{agents}')
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    f = _ids(res)['unattended_exposure.remote_platform_has_powerful_tools'][0]
    assert f['classification'] == 'warning'
    assert f['evidence'] == {
        'platform_count': 1, 'beyond_default_code_execution': True, 'beyond_default_computer_use': True,
        'beyond_default_cronjob': True, 'beyond_default_terminal': True, 'max_peer_or_user_count': 17,
    }
    flagged = {k for k, v in res['unattended_exposure']['platform_toolsets']['non_cli_platforms'].items()
               if v['remote'] and v['beyond_default_high_risk_tools']}
    assert flagged == {'a2a'}
    plat = res['unattended_exposure']['platform_toolsets']['non_cli_platforms']['a2a']
    assert plat['powerful_tools'] == ['browser', 'code_execution', 'computer_use', 'cronjob',
                                      'delegation', 'memory', 'skill_manage', 'terminal']

    # Webhook's shipped bundle has no terminal; an explicit terminal on it is beyond default.
    _write(cfg, 'platform_toolsets:\n  webhook: [hermes-webhook, terminal]\n')
    res_wh = mod.audit_unattended_exposure(profile_path=tmp_path)
    ev_wh = _ids(res_wh)['unattended_exposure.remote_platform_has_powerful_tools'][0]['evidence']
    assert (ev_wh['platform_count'], ev_wh['beyond_default_terminal'], ev_wh['beyond_default_cronjob']) == (1, True, False)
    assert res_wh['unattended_exposure']['platform_toolsets']['non_cli_platforms']['webhook'][
        'beyond_default_high_risk_tools'] == ['terminal']

    # Near miss 1: built-in messaging platform with its shipped bundle, explicit or by key list.
    for lst in ('[hermes-telegram]', '[a2a, hermes-telegram, no_mcp]', '[terminal, code_execution, cronjob]'):
        _write(cfg, f'platform_toolsets:\n  telegram: {lst}\n')
        assert 'unattended_exposure.remote_platform_has_powerful_tools' not in _ids(
            mod.audit_unattended_exposure(profile_path=tmp_path)), lst

    # Near miss 2: plugin platform with only plugin toolsets and its own (static-empty) bundle.
    _write(cfg, 'platform_toolsets:\n  a2a: [a2a, connections, hermes-a2a, guard, web, file]\n')
    res2 = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert 'unattended_exposure.remote_platform_has_powerful_tools' not in _ids(res2)
    assert res2['unattended_exposure']['platform_toolsets']['non_cli_platforms']['a2a']['high_risk_tools'] == []

    # Near miss 3: agent.disabled_toolsets strips the grants; cron is local, not remote.
    _write(cfg, 'agent:\n  disabled_toolsets: [terminal, code_execution, cronjob, computer_use]\n'
                'platform_toolsets:\n  a2a: [terminal, code_execution, cronjob, computer_use]\n')
    assert 'unattended_exposure.remote_platform_has_powerful_tools' not in _ids(
        mod.audit_unattended_exposure(profile_path=tmp_path))
    _write(cfg, 'platform_toolsets:\n  cron: [terminal, code_execution]\n')
    res3 = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res3['unattended_exposure']['platform_toolsets']['non_cli_platforms']['cron']['remote'] is False
    assert 'unattended_exposure.remote_platform_has_powerful_tools' not in _ids(res3)

    # A disabled hermes-* bundle removes only non-core tools (model_tools.py:300-318).
    _write(cfg, 'agent:\n  disabled_toolsets: [hermes-cli]\nplatform_toolsets:\n  a2a: [terminal]\n')
    assert 'unattended_exposure.remote_platform_has_powerful_tools' in _ids(
        mod.audit_unattended_exposure(profile_path=tmp_path))


# --- unpinned_prompt_injector -----------------------------------------------------------------


def test_unpinned_prompt_injector_positive_and_near_misses(tmp_path):
    mod = _mod()
    cfg = _write(tmp_path / 'config.yaml', 'plugins:\n  enabled: [memory-helper]\n')
    _plugin(tmp_path, 'memory-helper', 'name: memory-helper\nversion: 0.5.1\nhooks: [pre_llm_call, on_session_end]\n',
            init='def register(ctx):\n    ctx.register_hook("pre_llm_call", lambda **k: None)\n')
    _meta(tmp_path, {'memory-helper': {'pinned': False, 'revision': SHA, 'source': 'url'}})
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    f = _ids(res)['unattended_exposure.unpinned_prompt_injector'][0]
    assert f['classification'] == 'warning'
    assert f['evidence'] == {'hook_plugin_index': 0, 'pinned': 'no',
                             'declares_pre_llm_call': True, 'declares_pre_gateway_dispatch': False}
    row0 = res['unattended_exposure']['plugins']['hook_plugins'][0]
    assert row0['path'] == str((tmp_path / 'plugins' / 'memory-helper').resolve())
    assert row0['version_declared'] is True

    # pinned True without a str revision is not pinned (hermes_cli/plugins_cmd_git.py:90-94).
    _meta(tmp_path, {'memory-helper': {'pinned': True}})
    assert 'unattended_exposure.unpinned_prompt_injector' in _ids(mod.audit_unattended_exposure(profile_path=tmp_path))

    # Near miss 1: no install record at all (hand-copied plugin): pinned unknown, not reported as unpinned.
    _meta(tmp_path, {})
    res1 = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res1['unattended_exposure']['plugins']['hook_plugins'][0]['pinned'] == 'unknown'
    assert 'unattended_exposure.unpinned_prompt_injector' not in _ids(res1)
    _meta(tmp_path, {'memory-helper': {'pinned': False, 'revision': SHA}})

    # Near miss 2: __init__.py carries a memory-provider marker -> exclusive kind, not loaded via enabled.
    _write(tmp_path / 'plugins' / 'memory-helper' / '__init__.py', 'class X(MemoryProvider):\n    pass\n')
    res2 = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res2['unattended_exposure']['plugins']['hook_plugins'][0]['enabled'] is False
    assert 'unattended_exposure.unpinned_prompt_injector' not in _ids(res2)
    _write(tmp_path / 'plugins' / 'memory-helper' / '__init__.py', 'def register(ctx):\n    pass\n')

    # Near miss 3: listed in both enabled and disabled (disable wins), and not listed at all.
    _write(cfg, 'plugins:\n  enabled: [memory-helper]\n  disabled: [memory-helper]\n')
    assert 'unattended_exposure.unpinned_prompt_injector' not in _ids(mod.audit_unattended_exposure(profile_path=tmp_path))
    _write(cfg, 'plugins:\n  disabled: []\n')
    assert 'unattended_exposure.unpinned_prompt_injector' not in _ids(mod.audit_unattended_exposure(profile_path=tmp_path))

    # Near miss 4: the top-level gate name is the manifest name, not the directory name.
    _write(cfg, 'plugins:\n  enabled: [memory-helper-dir]\n')
    shutil_dir = tmp_path / 'plugins' / 'memory-helper'
    shutil_dir.rename(tmp_path / 'plugins' / 'memory-helper-dir')
    _meta(tmp_path, {'memory-helper-dir': {'pinned': False, 'revision': SHA}})
    res4 = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res4['unattended_exposure']['plugins']['hook_plugins'][0]['enabled'] is False
    assert 'unattended_exposure.unpinned_prompt_injector' not in _ids(res4)

    # Near miss 5: only an output transform / approval observer, no prompt hook.
    _write(cfg, 'plugins:\n  enabled: [output-filter]\n')
    _plugin(tmp_path, 'output-filter', 'name: output-filter\nversion: 3.1.0\nhooks: [transform_tool_result, pre_approval_request]\n')
    _meta(tmp_path, {'output-filter': {'pinned': False, 'revision': SHA}})
    res5 = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert 'unattended_exposure.unpinned_prompt_injector' not in _ids(res5)
    row = next(p for p in res5['unattended_exposure']['plugins']['hook_plugins'] if Path(p['path']).name == 'output-filter')
    assert row['prompt_or_approval_hooks'] == ['pre_approval_request', 'transform_tool_result']


def test_plugin_version_is_reported_as_declared_flag_only(tmp_path):
    mod = _mod()
    _write(tmp_path / 'config.yaml', 'plugins:\n  enabled: [sample-plugin]\n')
    _plugin(tmp_path, 'sample-plugin', 'name: sample-plugin\nversion: 0.15.0+someone.1\nhooks: [on_session_end]\n')
    row = mod.audit_unattended_exposure(profile_path=tmp_path)['unattended_exposure']['plugins']['hook_plugins'][0]
    assert row['version_declared'] is True and 'version' not in row
    _plugin(tmp_path, 'sample-plugin', 'name: sample-plugin\nversion: not-a-version\nhooks: [on_session_end]\n')
    row = mod.audit_unattended_exposure(profile_path=tmp_path)['unattended_exposure']['plugins']['hook_plugins'][0]
    assert row['version_declared'] is False


# --- other settings against the Hermes readers ------------------------------------------------


def test_guardrail_findings_only_for_default_on_checks(tmp_path):
    mod = _mod()
    cfg = tmp_path / 'config.yaml'
    # hard_stop_enabled is off by default (config_defaults.py:544-547): explicit false is not a finding.
    _write(cfg, 'tool_loop_guardrails:\n  hard_stop_enabled: false\n')
    assert 'unattended_exposure.guardrail_disabled' not in _ids(mod.audit_unattended_exposure(profile_path=tmp_path))

    _write(cfg, 'tool_loop_guardrails:\n  non_interactive_hard_stop_enabled: "off"\n')
    g = _ids(mod.audit_unattended_exposure(profile_path=tmp_path))['unattended_exposure.guardrail_disabled']
    assert [x['evidence']['guard'] for x in g] == ['tool_loop_guardrails.non_interactive_hard_stop_enabled']

    # A string "false" keeps the instruction-file gate on (file_tools_write_guards.py:211-212).
    _write(cfg, 'security:\n  protected_instruction_files: "false"\n')
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res['unattended_exposure']['settings']['security.protected_instruction_files']['value'] is True
    assert 'unattended_exposure.guardrail_disabled' not in _ids(res)

    # Legacy browser.allow_private_urls counts (tools/url_safety.py:170-173).
    _write(cfg, 'browser:\n  allow_private_urls: "yes"\n')
    g2 = _ids(mod.audit_unattended_exposure(profile_path=tmp_path))['unattended_exposure.guardrail_disabled']
    assert g2[0]['evidence']['guard'] == 'security.allow_private_urls'


def test_bool_readers_and_numeric_floors(tmp_path):
    mod = _mod()
    cfg = tmp_path / 'config.yaml'
    _write(cfg, 'browser:\n  use_real_profile: "false"\n'
                'cron:\n  catch_up_missed: "no"\n'
                'delegation:\n  max_concurrent_children: 0\n  max_spawn_depth: 0\n'
                'max_turns: 40\n')
    s = mod.audit_unattended_exposure(profile_path=tmp_path)['unattended_exposure']['settings']
    # bool("false") is True in Hermes; the audit does not guess at string truthiness.
    assert s['browser.use_real_profile']['source'] == 'could_not_verify'
    # cron/missed_runs.py:41 only a real False disables catch-up.
    assert s['cron.catch_up_missed']['value'] is True
    # tools/delegate_tool_config.py:110,207-211 floor both at 1.
    assert s['delegation.max_concurrent_children']['value'] == 1
    assert s['delegation.max_spawn_depth']['value'] == 1
    # Legacy root max_turns moves under agent (hermes_cli/config.py:2255-2260).
    assert s['agent.max_turns'] == {'value': 40, 'source': 'config', 'widens_unattended_action': False}


def test_small_model_tokens_are_whole_words(tmp_path):
    mod = _mod()
    cfg = tmp_path / 'config.yaml'
    _write(cfg, 'auxiliary:\n  approval:\n    model: gemini-3-pro\n')
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res['unattended_exposure']['smart_approval']['size_class'] == 'unclassified'
    assert 'unattended_exposure.small_model_decides_approvals' not in _ids(res)
    _write(cfg, 'auxiliary:\n  approval:\n    model: gpt-5-mini\n')
    assert _ids(mod.audit_unattended_exposure(profile_path=tmp_path))[
        'unattended_exposure.small_model_decides_approvals'][0]['evidence']['size_class'] == 'mini'
    # Manual mode: the auxiliary model does not decide.
    _write(cfg, 'approvals:\n  mode: manual\nauxiliary:\n  approval:\n    model: gpt-5-mini\n')
    assert 'unattended_exposure.small_model_decides_approvals' not in _ids(mod.audit_unattended_exposure(profile_path=tmp_path))


# --- cron -------------------------------------------------------------------------------------


def test_measured_home_with_broad_exposure_and_paused_failing_cron_jobs(tmp_path):
    mod = _mod()
    agents_block = '\n'.join(
        f'        peer-{i:02d}:\n          profile: peer-{i:02d}\n          timeout: 3600'
        for i in range(1, 18)
    )
    _write(tmp_path / 'config.yaml',
           'approvals:\n  mode: off\n  cron_mode: approve\n  single_query_mode: approve\n  unattended_mode: approve\n'
           'command_allowlist:\n  - example_rule\n'
           'terminal:\n  backend: local\n'
           'browser:\n  use_real_profile: true\n'
           'code_execution:\n  mode: project\n'
           'security:\n  allow_private_urls: true\n  protected_instruction_files: false\n'
           'tool_loop_guardrails:\n  hard_stop_enabled: true\n'
           'agent:\n  max_turns: "350"\n  disabled_toolsets: [kanban]\n'
           'delegation:\n  model: gemini-3.8-flash\n  provider: custom:local-proxy\n  max_iterations: 150\n'
           '  max_concurrent_children: 8\n  max_spawn_depth: 1\n'
           'cron:\n  allow_agent_scheduling: false\n'
           'curator:\n  enabled: false\n'
           'platform_toolsets:\n'
           '  cli: [a2a, browser, code_execution, computer_use, cronjob, delegation, file, memory, skills, terminal, web]\n'
           '  discord: [a2a, connections, hermes-discord, no_mcp, guard]\n'
           '  a2a: [browser, clarify, code_execution, computer_use, connections, cronjob, delegation, file, guard, '
           'hermes-a2a, image_gen, memory, session_search, skills, terminal, todo, tts, video_gen, vision, web]\n'
           'platforms:\n  a2a:\n    extra:\n      agents:\n'
           f'{agents_block}\n'
           'plugins:\n  enabled: [chat-bridge, memory-helper, intake-notes, security-guidance]\n'
           'hooks:\n  pre_tool_call:\n    - command: /home/user/.hermes/hooks/pre-tool-check.py\n'
           '      matcher: "^(memory|context_notes)$"\n')
    _plugin(tmp_path, 'memory-helper', 'name: memory-helper\nversion: 0.5.1\nhooks:\n  - pre_llm_call\n  - on_session_start\n  - on_session_end\n')
    (tmp_path / 'plugins' / 'intake-notes').mkdir(parents=True)
    _meta(tmp_path, {'memory-helper': {'pinned': False, 'revision': '87dca4af' * 5}})
    _write(tmp_path / 'hooks' / 'pre-tool-check.py', '#!/usr/bin/env python3\n' + ('# padding line\n' * 180))

    jobs = [{'id': 'b2c5e1993963', 'enabled': False, 'state': 'paused', 'prompt': 'Run oct check', 'script': None,
             'no_agent': False, 'schedule': {'kind': 'cron', 'expr': '0 * 5 10 *'}, 'failure_streak': 0}]
    for jid, streak in (('c8d3e5058cf6', 27), ('200b46bfbb1a', 26), ('4fc3126499aa', 27), ('b531de747373', 27)):
        jobs.append({'id': jid, 'enabled': False, 'state': 'paused', 'prompt': '',
                     'script': f'/home/user/.hermes/scripts/{jid}.py', 'no_agent': True,
                     'schedule': {'kind': 'interval', 'minutes': 15}, 'failure_streak': streak})
    _write(tmp_path / 'cron' / 'jobs.json', json.dumps({'jobs': jobs}))
    _write(tmp_path / 'cron' / 'usage_audit.jsonl',
           json.dumps({'ts': '2026-09-09T10:29:30.145Z', 'job_id': '8565a21f3565', 'model': 'gpt-6'}) + '\n')

    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res['coverage'] == 'verified'
    sec = res['unattended_exposure']
    s = sec['settings']
    assert s['approvals.mode']['value'] == 'approval_off'
    assert s['approvals.cron_mode']['value'] == 'approve'
    assert s['terminal.backend']['value'] == 'local'
    assert s['browser.use_real_profile']['value'] is True
    assert s['security.protected_instruction_files']['value'] is False
    assert s['security.allow_private_urls']['value'] is True
    assert s['agent.max_turns']['value'] == 350
    assert s['curator.enabled']['value'] is False

    a2a_plat = sec['platform_toolsets']['non_cli_platforms']['a2a']
    assert a2a_plat['high_risk_tools'] == ['code_execution', 'computer_use', 'cronjob', 'terminal']
    assert a2a_plat['beyond_default_high_risk_tools'] == ['code_execution', 'computer_use', 'cronjob', 'terminal']
    assert a2a_plat['peer_or_user_count'] == 17
    assert sec['platform_toolsets']['non_cli_platforms']['discord']['beyond_default_high_risk_tools'] == []
    assert sec['a2a'] == {'peer_count': 17, 'outbound_peer_count': 0, 'inbound_agent_count': 17,
                          'served_profile_count': 18, 'peer_timeouts': [3600]}

    assert sec['plugins']['missing_or_empty_enabled'] == [
        {'path': str((tmp_path / 'plugins' / 'intake-notes').resolve()), 'status': 'empty_dir'}]
    helper_row = next(p for p in sec['plugins']['hook_plugins'] if Path(p['path']).name == 'memory-helper')
    assert helper_row['enabled'] is True
    assert helper_row['pinned'] == 'no'
    assert helper_row['prompt_or_approval_hooks'] == ['pre_llm_call']

    assert sec['hooks'] == {'total_scripts': 1, 'scripts_by_event': {'pre_tool_call': 1},
                            'files': [{'path': str((tmp_path / 'hooks' / 'pre-tool-check.py').resolve()),
                                       'size_bytes': (tmp_path / 'hooks' / 'pre-tool-check.py').stat().st_size,
                                       'interpreter': 'python'}]}

    c = sec['cron']
    assert (c['total'], c['enabled'], c['paused'], c['script_jobs'], c['prompt_jobs']) == (5, 0, 5, 4, 1)
    assert c['schedule_classes'] == {'more_often_than_hourly': 4, 'hourly_to_daily': 0, 'less_often': 1,
                                     'unclassified': 0}
    assert (c['failing_jobs_count'], c['max_failure_streak']) == (4, 27)
    assert c['ghost_jobs_count'] == 1

    by_id = _ids(res)
    for rid in ('command_approval_off', 'remote_platform_has_powerful_tools', 'unpinned_prompt_injector'):
        assert by_id[f'unattended_exposure.{rid}'][0]['classification'] == 'warning'
    assert sorted(f['evidence']['guard'] for f in by_id['unattended_exposure.guardrail_disabled']) == [
        'security.allow_private_urls', 'security.protected_instruction_files']
    assert by_id['unattended_exposure.real_browser_profile'][0]['classification'] == 'review_suggested'
    assert by_id['unattended_exposure.cron_failing_jobs'][0]['classification'] == 'info'
    assert by_id['unattended_exposure.cron_runs_scripts'][0]['classification'] == 'info'
    assert by_id['unattended_exposure.ghost_cron_job'][0]['classification'] == 'info'


def test_cron_script_field_and_schedule_classes(tmp_path):
    mod = _mod()
    _write(tmp_path / 'config.yaml', '{}\n')
    jobs = [
        {'id': 'aa0000000001', 'no_agent': True, 'prompt': 'x', 'schedule': {'kind': 'cron', 'expr': '0,30 9 * * *'}},
        {'id': 'aa0000000002', 'monitor_script': 'check.sh', 'schedule': {'kind': 'cron', 'expr': '*/5 * * * *'}},
        {'id': 'aa0000000003', 'script': '  ', 'prompt': 'x', 'schedule': {'kind': 'cron', 'expr': '* * * * 1-5'}},
        {'id': 'aa0000000004', 'prompt': 'x', 'schedule': {'kind': 'cron', 'expr': '0 9 * * 1'}},
        {'id': 'aa0000000005', 'prompt': 'x', 'schedule': {'kind': 'cron', 'expr': 'not a cron'}},
        {'id': 'aa0000000006', 'prompt': 'x', 'schedule': {'kind': 'once', 'run_at': '2026-01-01T00:00:00'}},
        {'id': 'aa0000000007', 'prompt': 'x', 'schedule': 'every 5m'},
    ]
    _write(tmp_path / 'cron' / 'jobs.json', json.dumps({'jobs': jobs}))
    c = mod.audit_unattended_exposure(profile_path=tmp_path)['unattended_exposure']['cron']
    # no_agent without a script runs nothing (cron/scheduler.py:1516-1519); blank script is not a script.
    assert c['script_jobs'] == 1
    assert c['prompt_jobs'] == 6
    assert c['schedule_classes'] == {'more_often_than_hourly': 2, 'hourly_to_daily': 1, 'less_often': 2,
                                     'unclassified': 2}


def test_enabled_failing_cron_job_is_review_suggested_and_executions_db(tmp_path):
    mod = _mod()
    _write(tmp_path / 'config.yaml', '{}\n')
    _write(tmp_path / 'cron' / 'jobs.json', json.dumps({'jobs': [
        {'id': 'a11111111111', 'enabled': True, 'state': 'scheduled', 'prompt': 'Hourly check',
         'schedule': {'kind': 'cron', 'expr': '0 * * * *'}, 'failure_streak': 6}]}))
    (tmp_path / 'cron' / 'output' / 'b22222222222').mkdir(parents=True)
    conn = sqlite3.connect(tmp_path / 'cron' / 'executions.db')
    try:
        conn.execute('CREATE TABLE executions (id TEXT PRIMARY KEY, job_id TEXT NOT NULL)')
        conn.execute("INSERT INTO executions VALUES ('e1', 'c33333333333')")
        conn.commit()
    finally:
        conn.close()
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    sec = res['unattended_exposure']
    assert sec['cron']['enabled'] == 1
    assert sec['cron']['schedule_classes']['hourly_to_daily'] == 1
    assert sec['cron']['ghost_jobs_count'] == 2
    by_id = {f['id']: f for f in res['findings']}
    assert by_id['unattended_exposure.cron_failing_jobs']['classification'] == 'review_suggested'
    assert by_id['unattended_exposure.ghost_cron_job']['classification'] == 'info'


# --- backups, sanity, overlays ----------------------------------------------------------------


def test_measured_home_with_backup_drift_small_model_and_config_sanity(tmp_path):
    mod = _mod()
    bak1 = _write(tmp_path / 'config.yaml.bak', 'approvals:\n  mode: smart\nplatform_toolsets:\n  cli: [hermes-cli]\n')
    os.utime(bak1, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
    bak2 = _write(tmp_path / 'config.yaml.bak-manual-20260930-234257',
                  'approvals:\n  mode: off\nplatform_toolsets:\n  cli: [hermes-cli]\n')
    os.utime(bak2, ns=(1_700_001_000_000_000_000, 1_700_001_000_000_000_000))
    cli_22 = ['a2a', 'browser', 'clarify', 'code_execution', 'computer_use', 'connections', 'context_engine',
              'cronjob', 'delegation', 'file', 'image_gen', 'kanban', 'memory', 'session_search', 'skills',
              'terminal', 'todo', 'tts', 'video', 'video_gen', 'vision', 'web']
    cfg = _write(tmp_path / 'config.yaml',
                 'approvals:\n  mode: smart\n'
                 'auxiliary:\n  approval:\n    provider: local-proxy\n    model: gemini-3.8-flash\n'
                 '    base_url: http://127.0.0.1:8317/v1\n'
                 'delegation:\n  provider: http://127.0.0.1:8317/v1\n  model: " gemini-3.8-flash"\n'
                 'tool_loop_guardrails:\n  hard_stop_enabled: false\n'
                 f'platform_toolsets:\n  cli: {json.dumps(cli_22)}\n'
                 'plugins:\n  enabled: []\n  disabled: [status-panel]\n')
    # The current config is always compared last, whatever its mtime.
    os.utime(cfg, ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
    _plugin(tmp_path, 'status-panel', 'name: status-panel\nversion: 1.0.0\nprovides_hooks: [pre_llm_call, pre_tool_call]\n')

    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res['coverage'] == 'verified'
    sec = res['unattended_exposure']
    assert sec['smart_approval'] == {'model_set': True, 'size_class': 'flash', 'is_small': True,
                                     'uses_local_proxy': True}
    assert sec['platform_toolsets']['cli_toolset_count'] == 22
    d = sec['config_backup_drift']
    assert (d['copies_compared'], d['backup_count']) == (3, 2)
    assert d['changes']['approvals.mode'] == {'values': ['smart', 'approval_off', 'smart'], 'current': 'smart'}
    assert sec['config_sanity'] == {
        'provider_url_count': 1, 'provider_url_keys': ['delegation.provider'],
        'whitespace_value_count': 1, 'whitespace_value_keys': ['delegation.model'], 'total_malformed': 2,
    }
    assert {f['id'] for f in res['findings']} == {
        'unattended_exposure.small_model_decides_approvals',
        'unattended_exposure.approval_setting_changed_in_backups',
        'unattended_exposure.config_value_malformed',
    }


def test_memory_provider_plugin_detection(tmp_path):
    mod = _mod()
    _write(tmp_path / 'config.yaml', 'plugins:\n  enabled: [custom-mem]\n')
    _plugin(tmp_path, 'custom-mem', 'name: custom-mem\nversion: 0.4.0\nkind: exclusive\nhooks: [pre_llm_call]\n')
    _meta(tmp_path, {'custom-mem': {'pinned': False, 'revision': SHA}})
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    sec = res['unattended_exposure']
    assert sec['plugins']['memory_provider_count'] == 1
    assert sec['plugins']['hook_plugins'][0]['enabled'] is False
    assert 'unattended_exposure.unpinned_prompt_injector' not in _ids(res)


def test_unknown_scalars_duplicate_yaml_keys_and_managed_overlay(tmp_path):
    mod = _mod()
    cfg = tmp_path / 'config.yaml'
    _write(cfg, 'approvals:\n  mode: custom_secret_mode\nbrowser:\n  use_real_profile: y\n')
    res_unk = mod.audit_unattended_exposure(profile_path=tmp_path)
    sec_unk = res_unk['unattended_exposure']
    assert res_unk['coverage'] == 'could_not_verify'
    assert sec_unk['settings']['approvals.mode'] == {
        'value': 'other', 'source': 'could_not_verify', 'widens_unattended_action': None}
    assert sec_unk['settings']['browser.use_real_profile'] == {
        'value': None, 'source': 'could_not_verify', 'widens_unattended_action': None}
    assert 'custom_secret_mode' not in json.dumps(res_unk)
    cnv = _ids(res_unk)['unattended_exposure.could_not_verify'][0]
    assert cnv['classification'] == 'info'

    _write(cfg, 'approvals:\n  mode: off\n  mode: manual\nterminal:\n  backend: local\n')
    res_dup = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res_dup['coverage'] == 'could_not_verify'
    assert res_dup['unattended_exposure']['settings']['approvals.mode']['source'] == 'could_not_verify'
    assert 'unattended_exposure.command_approval_off' not in _ids(res_dup)

    _write(cfg, 'approvals:\n  mode: off\nterminal:\n  backend: local\n')
    managed = tmp_path / 'etc_hermes'
    managed.mkdir()
    res_mgr = mod.audit_unattended_exposure(profile_path=tmp_path, managed_dir=managed)
    assert res_mgr['coverage'] == 'could_not_verify'
    assert res_mgr['unattended_exposure']['reason'] == 'managed_overlay'
    assert {f['id'] for f in res_mgr['findings']} == {'unattended_exposure.could_not_verify'}
    assert res_mgr['unattended_exposure']['config_backup_drift']['copies_compared'] == 0


# --- safety: symlinks, credentials, read-only, privacy, caps, determinism ---------------------


def test_symlink_refusal_and_no_outside_traversal(tmp_path):
    mod = _mod()
    outside = tmp_path / 'outside'
    _write(outside / 'plugin.yaml', 'name: outside-plugin\nhooks: [pre_llm_call]\n')
    profile = tmp_path / 'profile'
    _write(profile / 'config.yaml', 'plugins:\n  enabled: [linked-plugin]\n')
    (profile / 'plugins').mkdir()
    os.symlink(outside, profile / 'plugins' / 'linked-plugin')
    os.symlink(profile / 'plugins' / 'loop', profile / 'plugins' / 'loop')
    (profile / 'hooks').mkdir()
    os.symlink(outside / 'plugin.yaml', profile / 'hooks' / 'linked_hook.py')
    (profile / 'cron').mkdir()
    os.symlink(outside, profile / 'cron' / 'output')

    res = mod.audit_unattended_exposure(profile_path=profile)
    assert res['coverage'] == 'could_not_verify'
    sec = res['unattended_exposure']
    assert sec['limits']['cuts'] >= 3
    assert sec['plugins']['missing_or_empty_enabled'] == [{'path': None, 'status': 'symlink_skipped'}]
    assert sec['hooks']['files'] == []
    assert 'outside-plugin' not in json.dumps(res)


def _record_opens(monkeypatch):
    opened: list[str] = []
    fd_names: dict[int, str] = {}
    bytes_read: dict[str, int] = {}
    o_open, o_io, o_os_open, o_read = builtins.open, io.open, os.open, os.read

    def w_open(file, *a, **k):
        if isinstance(file, (str, os.PathLike)):
            opened.append(os.fspath(file))
        return o_open(file, *a, **k)

    def w_io(file, *a, **k):
        if isinstance(file, (str, os.PathLike)):
            opened.append(os.fspath(file))
        return o_io(file, *a, **k)

    def w_os_open(path, flags, mode=0o777, *, dir_fd=None):
        name = os.fsdecode(path)
        opened.append(name)
        fd = o_os_open(path, flags, mode, dir_fd=dir_fd)
        fd_names[fd] = name
        return fd

    def w_read(fd, n):
        chunk = o_read(fd, n)
        if fd in fd_names:
            bytes_read[fd_names[fd]] = bytes_read.get(fd_names[fd], 0) + len(chunk)
        return chunk

    monkeypatch.setattr(builtins, 'open', w_open)
    monkeypatch.setattr(io, 'open', w_io)
    monkeypatch.setattr(os, 'open', w_os_open)
    monkeypatch.setattr(os, 'read', w_read)
    return opened, bytes_read


def test_credential_files_never_opened_and_hook_first_line_bound(tmp_path, monkeypatch):
    mod = _mod()
    _write(tmp_path / 'config.yaml', 'hooks:\n  pre_tool_call:\n    - command: big_hook.py\n')
    for rel in ('.env', '.env.bak-1', 'auth.json', 'secrets.yaml', 'id_ed25519', 'mcp-tokens/x.json',
                'pairing/pair.json', 'vault/vault.key', 'plugins/p1/.env', 'plugins/p1/auth.json',
                'cron/secrets.yaml', 'hooks/auth_token.py', 'hooks/id_ed25519', 'config.yaml.bak-mcp-tokens'):
        _write(tmp_path / rel, 'approvals:\n  mode: off\nSECRETVALUE\n')
    _plugin(tmp_path, 'p1', 'name: p1\nversion: 1.0.0\nhooks: [pre_llm_call]\n')
    big_hook = _write(tmp_path / 'hooks' / 'big_hook.py', '#!/usr/bin/env bash\n' + ('echo hi\n' * 1500))
    _write(tmp_path / 'hooks' / 'long_line.sh', '#!/bin/sh ' + ('x' * 2000) + '\n')

    opened, bytes_read = _record_opens(monkeypatch)
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    joined = ' '.join(opened).lower()
    for forbidden in ('.env', 'auth.json', 'token', 'secret', 'id_ed25519', 'pairing', 'vault'):
        assert forbidden not in joined, (forbidden, opened)
    assert bytes_read.get('big_hook.py', 0) <= 256
    assert bytes_read.get('long_line.sh', 0) <= 256
    files = res['unattended_exposure']['hooks']['files']
    assert files == [
        {'path': str(big_hook.resolve()), 'size_bytes': big_hook.stat().st_size, 'interpreter': 'bash'},
        {'path': str((tmp_path / 'hooks' / 'long_line.sh').resolve()), 'size_bytes': (tmp_path / 'hooks' / 'long_line.sh').stat().st_size,
         'interpreter': 'sh'},
    ]


def test_hook_file_names_outside_pattern_use_placeholder(tmp_path):
    mod = _mod()
    _write(tmp_path / 'config.yaml', '{}\n')
    _write(tmp_path / 'hooks' / 'my private hook ünï.py', '#!/usr/bin/python3\n')
    _write(tmp_path / 'hooks' / ('n' * 70 + '.sh'), '#!/bin/bash\n')
    files = mod.audit_unattended_exposure(profile_path=tmp_path)['unattended_exposure']['hooks']['files']
    assert [f['path'] for f in files] == [None, None]
    assert sorted(f['interpreter'] for f in files) == ['bash', 'python']


def test_read_only_unchanged_home_hash_including_readonly_dirs(tmp_path):
    mod = _mod()
    home = tmp_path / 'home'
    _write(home / 'config.yaml', 'approvals:\n  mode: off\n')
    _write(home / 'config.yaml.bak', 'approvals:\n  mode: smart\n')
    _plugin(home, 'memory-helper', 'name: memory-helper\nversion: 0.5.1\nhooks: [pre_llm_call]\n', init='x = 1\n')
    _meta(home, {'memory-helper': {'pinned': False, 'revision': SHA}})
    _write(home / 'config.yaml', 'approvals:\n  mode: off\nplugins:\n  enabled: [memory-helper]\n')
    _write(home / 'hooks' / 'h.sh', '#!/bin/sh\nexit 0\n')
    _write(home / 'cron' / 'jobs.json', '{"jobs": []}\n')
    db = home / 'cron' / 'executions.db'
    conn = sqlite3.connect(db)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('CREATE TABLE executions (id TEXT, job_id TEXT)')
    conn.commit()
    conn.close()

    before = _snapshot_tree(home)
    mod.audit_unattended_exposure(profile_path=home)
    assert _snapshot_tree(home) == before

    dirs = [Path(dp) for dp, _, _ in os.walk(home)]
    try:
        for d in dirs:
            d.chmod(0o555)
        before_ro = _snapshot_tree(home)
        res = mod.audit_unattended_exposure(profile_path=home)
        assert _snapshot_tree(home) == before_ro
        assert res['unattended_exposure']['status'] == 'completed'
    finally:
        for d in dirs:
            d.chmod(0o755)


def test_canary_privacy_no_config_value_leaks(tmp_path):
    mod = _mod()
    lc = 'zqcanary'
    cfg_text = (
        f'# {lc}-comment CANARY_COMMENT\n'
        'approvals:\n  mode: CANARY_MODE_VALUE\n  smart_policy: "CANARY_SMART_POLICY_TEXT"\n'
        f'  deny: ["{lc}-deny-rule"]\n'
        f'command_allowlist:\n  - "CANARY_ALLOWLIST_CMD --host 10.99.88.77 {lc}-allow"\n'
        'auxiliary:\n  approval:\n'
        f'    provider: "https://{lc}-user:sk-CANARYKEY@{lc}-host.example:8317/v1"\n'
        f'    model: " {lc}-model-flash "\n    base_url: "http://{lc}-base:1/v1"\n'
        f'delegation:\n  provider: "http://{lc}-proxy:9000"\n  model: " {lc}-delegation-model "\n'
        f'a2a_agents:\n  {lc}-peer:\n    url: "http://10.99.88.77:9900/{lc}-peerpath"\n    timeout: 600\n'
        f'    auth:\n      token: "{lc}-peer-token"\n'
        f'platforms:\n  a2a:\n    extra:\n      agents:\n        {lc}-served:\n          profile: {lc}-prof\n'
        f'  {lc}platform:\n    allow_from: ["{lc}-user-id"]\n'
        f'platform_toolsets:\n  {lc}platform: [terminal, {lc}-toolset]\n  a2a: [terminal, {lc}-mcp]\n'
        f'mcp_servers:\n  {lc}-mcp:\n    command: "/home/user/{lc}-path"\n    args: ["--key", "{lc}-mcp-arg"]\n'
        f'    env:\n      API_KEY: "{lc}-env-secret"\n    enabled: true\n'
        f'skills:\n  auto_load:\n    - {lc}-skill\n'
        f'hooks:\n  pre_tool_call:\n    - command: "/home/user/{lc}-hook-cmd --x"\n'
        f'{lc}_unknown_key:\n  nested: "{lc}-unknown-value"\n'
        f'model:\n  default: "{lc}-main-model"\n  provider: "{lc}-provider"\n'
        f'terminal:\n  backend: {lc}backend\n  ssh_host: "{lc}-ssh-host"\n'
        f'plugins:\n  enabled: [{lc}-enabled-only]\n  entries:\n    x:\n      key: "{lc}-plugin-entry"\n'
    )
    _write(tmp_path / 'config.yaml', cfg_text)
    _write(tmp_path / 'config.yaml.bak', cfg_text.replace('CANARY_MODE_VALUE', 'off'))
    _write(tmp_path / 'config.yaml.bak-other', cfg_text.replace('CANARY_MODE_VALUE', f'{lc}-mode2'))
    _plugin(tmp_path, 'CANARY_PLUGIN_NAME',
            'name: CANARY_PLUGIN_NAME\nversion: CANARY_VERSION\n'
            f'description: {lc}-plugin-description\nhooks: [pre_llm_call]\n')
    _meta(tmp_path, {'CANARY_PLUGIN_NAME': {'pinned': False, 'revision': SHA, 'source': f'https://{lc}-src'}})
    _write(tmp_path / 'hooks' / 'CANARY hook.py', f'#!/usr/bin/env CANARY_INTERP\nprint("{lc}-hook-body")\n')
    _write(tmp_path / 'cron' / 'jobs.json', json.dumps({'jobs': [{
        'id': 'CANARY_JOB_ID', 'name': f'{lc}-job-name', 'prompt': f'{lc}-prompt',
        'script': f'/home/user/{lc}-script.py', 'enabled': True,
        'schedule': {'kind': 'cron', 'expr': '*/7 * * * *', 'display': f'{lc}-display'},
        'failure_streak': 9, 'last_error': f'{lc}-error', 'deliver': f'{lc}-deliver',
    }]}))
    _write(tmp_path / 'cron' / 'usage_audit.jsonl',
           json.dumps({'job_id': 'CANARY_GHOST_ID', 'error': f'{lc}-audit-err', 'model': f'{lc}-m'}) + '\n')

    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    # Existing plugin directories are emitted as absolute paths (kept by the report serializer);
    # nothing else may carry the canaries or the home path.
    for row in res['unattended_exposure']['plugins']['hook_plugins']:
        assert row.pop('path') == str((tmp_path / 'plugins' / 'CANARY_PLUGIN_NAME').resolve())
    serialized = json.dumps(res)
    assert 'CANARY' not in serialized
    assert lc not in serialized
    assert '10.99.88.77' not in serialized
    assert str(tmp_path) not in serialized
    assert '/home/user' not in serialized
    sec = res['unattended_exposure']
    assert sec['mcp_servers'] == {'configured_count': 1, 'enabled_count': 1, 'disabled_count': 0}
    assert set(sec['platform_toolsets']['non_cli_platforms']) == {'a2a'}
    assert len(sec['platform_toolsets']['other_platforms']) == 1
    assert sec['config_sanity']['provider_url_keys'] == ['auxiliary.approval.provider', 'delegation.provider']


def test_all_truncation_caps_and_malformed_inputs(tmp_path, monkeypatch):
    mod = _mod()
    _write(tmp_path / 'config.yaml', '{}\n')
    for i in range(5):
        _plugin(tmp_path, f'plug-{i}', f'name: plug-{i}\nversion: 1.0.0\n')

    res_entries = mod.audit_unattended_exposure(profile_path=tmp_path, max_entries=2)
    assert res_entries['coverage'] == 'could_not_verify'
    assert res_entries['unattended_exposure']['truncated_by'] == 'entry_cap'

    monkeypatch.setattr(mod, 'MAX_DEPTH', 1)
    res_depth = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res_depth['unattended_exposure']['truncated_by'] == 'depth_cap'
    monkeypatch.undo()

    res_fsize = mod.audit_unattended_exposure(profile_path=tmp_path, max_file_bytes=2)
    assert res_fsize['unattended_exposure']['truncated_by'] == 'file_size_cap'

    res_tbytes = mod.audit_unattended_exposure(profile_path=tmp_path, max_total_bytes=10)
    assert res_tbytes['unattended_exposure']['truncated_by'] == 'total_bytes_cap'
    assert res_tbytes['unattended_exposure']['limits']['bytes_read'] <= 10

    ticks = iter([0.0, 100.0, 100.0, 100.0])
    res_time = mod.audit_unattended_exposure(profile_path=tmp_path, now_fn=lambda: next(ticks, 100.0), max_seconds=1.0)
    assert res_time['coverage'] == 'could_not_verify'
    assert res_time['unattended_exposure']['truncated_by'] == 'time_budget'

    cdir = tmp_path / 'cron'
    cdir.mkdir()
    db_path = cdir / 'executions.db'
    conn = sqlite3.connect(db_path)
    try:
        conn.execute('CREATE TABLE executions (id TEXT PRIMARY KEY, job_id TEXT NOT NULL)')
        for idx in range(5):
            conn.execute('INSERT INTO executions VALUES (?, ?)', (f'e{idx}', f'deadbeef000{idx}'))
        conn.commit()
    finally:
        conn.close()
    monkeypatch.setattr(mod, 'MAX_DB_ROWS', 2)
    res_rows = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res_rows['unattended_exposure']['truncated_by'] == 'row_cap'
    assert res_rows['unattended_exposure']['cron']['ghost_jobs_count'] == 2
    monkeypatch.undo()
    monkeypatch.setattr(mod, 'MAX_SQL_STEPS', 1)
    res_sql = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res_sql['unattended_exposure']['truncated_by'] == 'sql_steps'
    monkeypatch.undo()

    (tmp_path / 'config.yaml').write_bytes(b'\xff\xfe\x00broken: [yaml')
    _write(tmp_path / 'plugins' / '.install-metadata.json', '{broken json')
    _write(cdir / 'jobs.json', '{broken jobs json')
    _write(cdir / 'usage_audit.jsonl', 'not-json-line\n{"job_id": 123}\n[1,2]\n')
    db_path.write_bytes(b'not a sqlite database')
    (tmp_path / 'hooks').mkdir()
    if hasattr(os, 'mkfifo'):
        os.mkfifo(tmp_path / 'hooks' / 'pipe.sh')
    (tmp_path / 'hooks' / b'bad-\xff-name.sh'.decode('utf-8', 'surrogateescape')).write_bytes(b'#!/bin/sh\n')
    res_mal = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert res_mal['coverage'] == 'could_not_verify'
    assert 'unattended_exposure.could_not_verify' in _ids(res_mal)
    json.dumps(res_mal)


@pytest.mark.parametrize('cfg_text', [
    '- just\n- a list\n',
    'approvals: [1, 2]\nterminal: "x"\nplatform_toolsets: 7\nplugins: {enabled: "a,b"}\nmcp_servers: [x]\n',
    'agent:\n  max_turns: [1]\ndelegation:\n  max_iterations: {a: 1}\ncron: null\nhooks: [1]\n',
    'x: ' + ('a' * 200_000) + '\n',
])
def test_wrong_types_never_raise(tmp_path, cfg_text):
    mod = _mod()
    _write(tmp_path / 'config.yaml', cfg_text)
    _write(tmp_path / 'cron' / 'jobs.json', json.dumps({'jobs': [1, 'x', {'id': 5, 'schedule': [1], 'failure_streak': 'x'}]}))
    _plugin(tmp_path, 'odd', 'name: [1]\nversion: {a: 1}\nhooks: 7\nkind: 9\n')
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    json.dumps(res)
    assert res['unattended_exposure']['status'] == 'completed'


def test_determinism_across_clocks(tmp_path):
    mod = _mod()
    _write(tmp_path / 'config.yaml', 'approvals:\n  mode: off\nterminal:\n  backend: local\n')
    b1 = _write(tmp_path / 'config.yaml.bak-1', 'approvals:\n  mode: smart\n')
    b2 = _write(tmp_path / 'config.yaml.bak-2', 'approvals:\n  mode: manual\n')
    os.utime(b1, ns=(5, 5))
    os.utime(b2, ns=(5, 5))  # equal mtimes: name breaks the tie
    _write(tmp_path / 'cron' / 'jobs.json', json.dumps({'jobs': [{'id': 'aa', 'script': 's.sh'}]}))
    day = 86_400.0
    r1 = mod.audit_unattended_exposure(profile_path=tmp_path, now_fn=lambda: 1_000.0)
    r2 = mod.audit_unattended_exposure(profile_path=tmp_path, now_fn=lambda: 1_000.0 + 9 * day)
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)
    assert r1['unattended_exposure']['config_backup_drift']['changes']['approvals.mode']['values'] == [
        'smart', 'manual', 'approval_off']


def test_envelope_keys_and_run_metrics_outside_section(tmp_path):
    mod = _mod()
    contract = load_submodule('audit.contract')
    _write(tmp_path / 'config.yaml', 'approvals:\n  mode: off\nterminal:\n  backend: local\n')
    ticks = iter([10.0, 10.25, 10.5])
    res = mod.audit_unattended_exposure(profile_path=tmp_path, now_fn=lambda: next(ticks, 10.5))
    assert set(res) == {'unattended_exposure', 'findings', 'run_metrics', 'status', 'coverage'}
    assert set(res['run_metrics']) == {'elapsed_ms'} and res['run_metrics']['elapsed_ms'] >= 0
    for early in (tmp_path / 'missing', ):
        assert set(mod.audit_unattended_exposure(profile_path=early)) == set(res)
    adapted = contract.adapt_component_result(res, component_id='unattended_exposure')
    # adapt_component_result keeps unknown top-level keys verbatim and re-derives coverage.
    assert adapted['run_metrics'] == res['run_metrics']
    assert adapted['unattended_exposure'] == res['unattended_exposure']
    assert adapted['coverage'] == res['coverage'] == 'verified'
    assert adapted['classification'] == 'warning'


def test_section_and_findings_identical_with_clocks_days_apart(tmp_path):
    mod = _mod()
    _write(tmp_path / 'config.yaml', 'approvals:\n  mode: off\n  cron_mode: approve\nterminal:\n  backend: local\n')
    _write(tmp_path / 'config.yaml.bak', 'approvals:\n  mode: smart\n')
    _write(tmp_path / 'cron' / 'jobs.json', json.dumps({'jobs': [{'id': 'aa', 'script': 's.sh', 'failure_streak': 9}]}))
    day = 86_400.0

    def clock(start, step):
        state = {'t': start}

        def now():
            state['t'] += step
            return state['t']
        return now

    r1 = mod.audit_unattended_exposure(profile_path=tmp_path, now_fn=clock(1_000.0, 0.001))
    r2 = mod.audit_unattended_exposure(profile_path=tmp_path, now_fn=clock(1_000.0 + 3 * day, 0.002))
    assert json.dumps(r1['unattended_exposure'], sort_keys=True) == json.dumps(r2['unattended_exposure'], sort_keys=True)
    assert json.dumps(r1['findings'], sort_keys=True) == json.dumps(r2['findings'], sort_keys=True)
    assert r1['run_metrics'] != r2['run_metrics']


def test_finding_paths_are_relative(tmp_path):
    mod = _mod()
    _write(tmp_path / 'config.yaml', 'approvals:\n  mode: off\nterminal:\n  backend: local\n')
    _write(tmp_path / 'cron' / 'jobs.json', json.dumps({'jobs': [{'id': 'aa', 'script': 's.sh', 'failure_streak': 9}]}))
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert str(tmp_path) not in json.dumps(res)
    for f in res['findings']:
        for p in f['affected_identities']:
            assert not str(p).startswith('/')


@pytest.mark.parametrize('variant', ['zero_byte', 'truncated', 'view_named_like_table', 'wal_empty_wal', 'rollback'])
def test_executions_db_variants_create_no_sidecars(tmp_path, variant):
    mod = _mod()
    _write(tmp_path / 'config.yaml', '{}\n')
    cdir = tmp_path / 'cron'
    cdir.mkdir()
    db = cdir / 'executions.db'
    if variant == 'zero_byte':
        db.write_bytes(b'')
    else:
        conn = sqlite3.connect(db)
        if variant == 'wal_empty_wal':
            conn.execute('PRAGMA journal_mode=WAL')
        if variant == 'view_named_like_table':
            conn.execute('CREATE TABLE t (job_id TEXT)')
            conn.execute("INSERT INTO t VALUES ('dddddddddddd')")
            conn.execute('CREATE VIEW executions AS SELECT job_id FROM t')
        else:
            conn.execute('CREATE TABLE executions (id TEXT, job_id TEXT)')
            conn.execute("INSERT INTO executions VALUES ('e', 'eeeeeeeeeeee')")
        conn.commit()
        conn.close()
        if variant == 'truncated':
            db.write_bytes(db.read_bytes()[:150])
        if variant == 'wal_empty_wal':
            (cdir / 'executions.db-wal').write_bytes(b'')
    before = _snapshot_tree(tmp_path)
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    assert _snapshot_tree(tmp_path) == before
    ghosts = res['unattended_exposure']['cron']['ghost_jobs_count']
    if variant == 'view_named_like_table':
        assert ghosts == 0
    if variant in ('zero_byte', 'truncated'):
        assert res['coverage'] == 'could_not_verify'


# --- wiring sheet (audit/wiring/unattended_exposure.json) and sealing -------------------------

_WIRING_PATH = Path(__file__).resolve().parents[1] / 'audit' / 'wiring' / 'unattended_exposure.json'
_SECTION = 'unattended_exposure'


def _wiring() -> dict:
    return json.loads(_WIRING_PATH.read_text(encoding='utf-8'))


def _norm_path(parts: list[str]) -> str:
    out = []
    for i, part in enumerate(parts):
        out.append('<key>' if i > 0 and parts[i - 1] == 'non_cli_platforms' else part)
    return '.'.join(out).replace('.[]', '[]')


def _walk(value, parts, visit):
    """visit(kind, path_str, key_or_value) for every dict key and string leaf."""
    if isinstance(value, dict):
        for k, v in value.items():
            visit('key', _norm_path(parts + [k]), k)
            _walk(v, parts + [k], visit)
    elif isinstance(value, list):
        for item in value:
            _walk(item, parts + ['[]'], visit)
    elif isinstance(value, str):
        visit('str', _norm_path(parts), value)


def _strict_check(env: dict, wiring: dict) -> list[str]:
    schema = set(wiring['schema_keys'])
    vocab = set(wiring['vocabulary'])
    free = {f['key'] for f in wiring['free_strings']}
    problems: list[str] = []

    def visit(kind, path, item):
        if kind == 'key':
            if item not in schema:
                problems.append(f'key {item!r} at {path}')
        elif path in free:
            # Free strings are only absolute paths of existing items inside the audited home.
            if not (item.startswith('/') and os.path.lexists(item) and not os.path.islink(item)):
                problems.append(f'free string {item!r} at {path} is not an existing absolute path')
        elif item not in vocab:
            problems.append(f'string {item!r} at {path}')

    _walk(env[_SECTION], [], visit)
    for f in env['findings']:
        _walk(f, [], visit)
    assert set(env.get('run_metrics', {})) <= set(wiring['run_metrics_keys'])
    return problems


def _scenario_envelopes(tmp_path, monkeypatch) -> list[dict]:
    """Synthetic homes that reach every rule, classification and enumerated label the module emits."""
    mod = _mod()
    envs: list[dict] = []
    run = lambda home, **kw: envs.append(mod.audit_unattended_exposure(profile_path=home, **kw))  # noqa: E731

    # A: wide exposure (a realistic wide-exposure shape) plus every plugin/hook/cron branch.
    a = tmp_path / 'a'
    agents = ''.join(f'        peer-{i:02d}:\n          timeout: 3600\n' for i in range(1, 18))
    _write(a / 'config.yaml',
           'approvals:\n  mode: off\n  cron_mode: approve\n  single_query_mode: allow\n  unattended_mode: approve\n'
           'command_allowlist:\n  - example_rule\n'
           'terminal:\n  backend: local\n'
           'browser:\n  use_real_profile: true\n'
           'security:\n  allow_private_urls: true\n  protected_instruction_files: false\n'
           'tool_loop_guardrails:\n  non_interactive_hard_stop_enabled: false\n'
           'agent:\n  max_turns: 0\n'
           'delegation:\n  max_concurrent_children: 20\n'
           'cron:\n  allow_agent_scheduling: true\n'
           'updates:\n  pre_update_backup: false\n  non_interactive_local_changes: discard\n'
           '  parked_branch_strategy: update_in_place\n'
           'code_execution:\n  mode: strict\n'
           'skills:\n  auto_load: [one, two]\n'
           'mcp_servers:\n  srv:\n    enabled: true\n'
           'platform_toolsets:\n  cli: [hermes-cli]\n'
           '  a2a: [terminal, code_execution, cronjob, computer_use, browser, memory, skills, delegation]\n'
           '  telegram: [hermes-telegram]\n  cron: [terminal]\n  customchat: [terminal]\n  zzchat: [safe]\n'
           f'platforms:\n  a2a:\n    extra:\n      agents:\n{agents}'
           'plugins:\n  enabled: [injector, kindless, gone, emptyone, portable, cat, linked, memprov]\n'
           'hooks:\n  pre_tool_call:\n    - command: /home/user/hook.sh\n  on_session_start:\n    - command: x\n')
    _plugin(a, 'injector', 'name: injector\nversion: 1.2.0\nhooks: [pre_llm_call, pre_gateway_dispatch, '
                           'transform_tool_result, pre_approval_request]\n', init='x = 1\n')
    _plugin(a, 'kindless', 'name: kindless\nversion: 2.0.0+local.1\nhooks: [pre_llm_call]\n')
    os.symlink(a / 'plugins' / 'injector' / '__init__.py', a / 'plugins' / 'kindless' / '__init__.py')
    _plugin(a, 'memprov', 'name: memprov\nversion: x\nkind: exclusive\nhooks: [pre_llm_call]\n')
    (a / 'plugins' / 'emptyone').mkdir()
    _write(a / 'plugins' / 'portable' / 'plugin.json', '{}')
    _write(a / 'plugins' / 'cat' / 'notes.txt', 'x')  # category dir: no manifest, one level of recursion
    _write(a / 'plugins' / 'cat' / 'sub' / 'plugin.yaml', 'name: sub\nhooks: [post_llm_call]\n')
    os.symlink(a / 'plugins' / 'injector', a / 'plugins' / 'linked')
    _meta(a, {'injector': {'pinned': False, 'revision': SHA}, 'kindless': {'pinned': False, 'revision': SHA},
              'memprov': {'pinned': True, 'revision': SHA}})
    for name, line in (('h-python.py', '#!/usr/bin/env python3'), ('h-bash.sh', '#!/bin/bash'),
                       ('h-zsh', '#!/bin/zsh'), ('h-sh', '#!/bin/sh'), ('h-node', '#!/usr/bin/env node'),
                       ('h-ruby', '#!/usr/bin/ruby'), ('h-perl', '#!/usr/bin/perl'), ('h-other', '#!/bin/fish'),
                       ('h-none', 'echo hi'), ('bad name.sh', '#!/bin/sh')):
        _write(a / 'hooks' / name, line + '\n')
    jobs = [
        {'id': 'aa0000000001', 'enabled': True, 'script': 's.sh', 'schedule': {'kind': 'interval', 'minutes': 5},
         'failure_streak': 7, 'context_from': ['ffff00000001']},
        {'id': 'aa0000000002', 'prompt': 'p', 'schedule': {'kind': 'interval', 'minutes': 120}},
        {'id': 'aa0000000003', 'prompt': 'p', 'schedule': {'kind': 'once'}},
        {'id': 'aa0000000004', 'prompt': 'p', 'schedule': 'bad'},
    ]
    _write(a / 'cron' / 'jobs.json', json.dumps({'jobs': jobs}))
    _write(a / 'cron' / 'usage_audit.jsonl', json.dumps({'job_id': 'ffff00000002'}) + '\n')
    (a / 'cron' / 'output' / 'ffff00000003').mkdir(parents=True)
    run(a)

    # B: smart approvals with a small model, backups, sanity, paused failing jobs.
    b = tmp_path / 'b'
    bak = _write(b / 'config.yaml.bak', 'approvals:\n  mode: manual\n  cron_mode: approve\n')
    os.utime(bak, ns=(1_700_000_000_000_000_000,) * 2)
    _write(b / 'config.yaml',
           'approvals:\n  mode: smart\n'
           'auxiliary:\n  approval:\n    provider: \" http://127.0.0.1:1/v1\"\n    model: gpt-5-mini\n'
           'delegation:\n  provider: http://127.0.0.1:1/v1\n  model: \" m \"\n'
           'cron:\n  provider: \"https://x.example\"\n  model: \"m \"\nmemory:\n  provider: \"http://y.example\"\n'
           'terminal:\n  backend: \" docker\"\n'
           'agent:\n  max_turns: \" 12\"\n')
    _write(b / 'cron' / 'jobs.json', json.dumps({'jobs': [
        {'id': 'bb0000000001', 'enabled': False, 'script': 's', 'failure_streak': 9,
         'schedule': {'kind': 'cron', 'expr': '0 9 * * *'}}]}))
    run(b)
    # Other small-model labels and the unclassified/unset paths.
    for model in ('x-flash', 'x-nano', 'claude-haiku', 'x-lite', 'x-small', 'llama-7b', 'big-model'):
        c = tmp_path / f'model-{model}'
        _write(c / 'config.yaml', f'auxiliary:\n  approval:\n    model: {model}\n')
        run(c)

    # C: unknown enum strings -> 'other' / could_not_verify rows; docker-backend auto-approve.
    c = tmp_path / 'c'
    _write(c / 'config.yaml',
           'approvals:\n  mode: weird\n  cron_mode: approve\n'
           'terminal:\n  backend: weird\n'
           'code_execution:\n  mode: weird\n'
           'updates:\n  pre_update_backup: weird\n  non_interactive_local_changes: weird\n'
           '  parked_branch_strategy: weird\n'
           'agent:\n  max_turns: weird\n')
    run(c)
    d = tmp_path / 'd'
    _write(d / 'config.yaml', 'approvals:\n  mode: true\nupdates:\n  pre_update_backup: true\n'
                              'terminal:\n  backend: ssh\nagent:\n  max_turns: unlimited\n')
    run(d)
    for backend in ('modal', 'daytona', 'vercel_sandbox', 'managed_modal'):
        e = tmp_path / f'backend-{backend}'
        _write(e / 'config.yaml', f'terminal:\n  backend: {backend}\nupdates:\n  pre_update_backup: \"yes\"\n')
        run(e)

    # D: preflight branches, managed overlay, unreadable config.
    run(tmp_path / 'missing')
    (tmp_path / 'empty').mkdir()
    run(tmp_path / 'empty')
    _write(tmp_path / 'a_file', 'x')
    run(tmp_path / 'a_file')
    managed = tmp_path / 'managed'
    managed.mkdir()
    run(b, managed_dir=managed)
    bad = tmp_path / 'badcfg'
    _write(bad / 'config.yaml', 'a: [unclosed\n')
    run(bad)

    # E: every cap.
    caps = tmp_path / 'caps'
    _write(caps / 'config.yaml', '{}\n')
    for i in range(4):
        _plugin(caps, f'plug-{i}', f'name: plug-{i}\nversion: 1.0.0\n')
    run(caps, max_entries=2)
    run(caps, max_file_bytes=2)
    run(caps, max_total_bytes=10)
    ticks = iter([0.0, 100.0])
    run(caps, now_fn=lambda: next(ticks, 100.0), max_seconds=1.0)
    monkeypatch.setattr(mod, 'MAX_DEPTH', 1)
    run(caps)
    monkeypatch.setattr(mod, 'MAX_DEPTH', 4)
    (caps / 'cron').mkdir()
    conn = sqlite3.connect(caps / 'cron' / 'executions.db')
    conn.execute('CREATE TABLE executions (id TEXT, job_id TEXT)')
    for idx in range(4):
        conn.execute('INSERT INTO executions VALUES (?, ?)', (f'e{idx}', f'deadbeef000{idx}'))
    conn.commit()
    conn.close()
    monkeypatch.setattr(mod, 'MAX_DB_ROWS', 2)
    run(caps)
    monkeypatch.setattr(mod, 'MAX_DB_ROWS', 2000)
    monkeypatch.setattr(mod, 'MAX_SQL_STEPS', 1)
    run(caps)
    monkeypatch.setattr(mod, 'MAX_SQL_STEPS', 1_000_000)
    return envs


def test_wiring_sheet_matches_module_constants():
    mod = _mod()
    w = _wiring()
    assert set(w) == {'section', 'entry', 'kwargs', 'schema_keys', 'vocabulary', 'numeric_evidence_keys',
                      'vocab_evidence_keys', 'rule_ids', 'classifications', 'consequences', 'free_strings',
                      'run_metrics_keys', 'notes'}
    assert w['section'] == _SECTION
    assert w['entry'] == 'audit.unattended_exposure.audit_unattended_exposure'
    assert set(w['kwargs']) >= {'profile_path'}
    assert w['rule_ids'] == sorted(mod.FINDING_CONSEQUENCES)
    assert w['consequences'] == dict(sorted(mod.FINDING_CONSEQUENCES.items()))
    assert set(w['classifications']) == set(w['rule_ids'])
    for key in ('schema_keys', 'vocabulary', 'numeric_evidence_keys', 'vocab_evidence_keys', 'rule_ids'):
        assert w[key] == sorted(set(w[key])), key
    assert _SECTION in w['schema_keys']
    for f in w['free_strings']:
        assert set(f) == {'key', 'what', 'example', 'why_safe'}
    # Fixed sentences only: no interpolation, no second person, no inferred cause.
    for sentence in w['consequences'].values():
        assert not __import__('re').search(r'\byou\b|indicat|suggest|unpruned|abandoned|\{', sentence), sentence


def test_every_emitted_key_and_string_is_declared_in_the_wiring_sheet(tmp_path, monkeypatch):
    w = _wiring()
    envs = _scenario_envelopes(tmp_path, monkeypatch)
    problems = sorted({p for env in envs for p in _strict_check(env, w)})
    assert problems == []
    seen: dict[str, set[str]] = {}
    for env in envs:
        assert set(env) == {_SECTION, 'findings', 'run_metrics', 'status', 'coverage'}
        for f in env['findings']:
            seen.setdefault(f['id'], set()).add(f['classification'])
            assert f['consequence'] == w['consequences'][f['id']]
            ev = f['evidence']
            assert set(ev) <= set(w['numeric_evidence_keys']) | set(w['vocab_evidence_keys'])
            for k, v in ev.items():
                if k in w['numeric_evidence_keys']:
                    assert type(v) in (int, float, bool), (f['id'], k, v)
                else:
                    assert type(v) is str and v in w['vocabulary'], (f['id'], k, v)
    # Every rule and every declared classification is reached by the scenarios.
    assert {k: sorted(v) for k, v in seen.items()} == w['classifications']
    # Every free-string location is actually exercised.
    hit: set[str] = set()

    def visit(kind, path, item):
        if path in {f['key'] for f in w['free_strings']}:
            hit.add(path)
    for env in envs:
        _walk(env[_SECTION], [], visit)
    assert hit == {f['key'] for f in w['free_strings']}


def _patch_sealing_sets(monkeypatch, w):
    ev = load_submodule('audit.evidence')
    per = load_submodule('audit.persistence')
    consts = load_submodule('audit.evidence_constants')
    sentences = frozenset(w['consequences'].values())
    vocab = ev.VOCABULARY | frozenset(w['vocabulary']) | frozenset(w['rule_ids']) | sentences
    monkeypatch.setattr(ev, 'SCHEMA_KEYS', ev.SCHEMA_KEYS | frozenset(w['schema_keys']))
    monkeypatch.setattr(ev, 'VOCABULARY', vocab)
    monkeypatch.setattr(per, 'VOCABULARY', vocab)
    monkeypatch.setattr(per, '_EVIDENCE_NUMERIC_KEYS', per._EVIDENCE_NUMERIC_KEYS | frozenset(w['numeric_evidence_keys']))
    monkeypatch.setattr(per, '_EVIDENCE_VOCAB_KEYS', per._EVIDENCE_VOCAB_KEYS | frozenset(w['vocab_evidence_keys']))
    monkeypatch.setattr(per, 'ALLOWED_FINDING_CONSEQUENCES', per.ALLOWED_FINDING_CONSEQUENCES | sentences)
    monkeypatch.setattr(per, 'FINDING_CONSEQUENCES', {**per.FINDING_CONSEQUENCES, **w['consequences']})
    monkeypatch.setattr(consts, 'RULE_IDS', consts.RULE_IDS | frozenset(w['rule_ids']))
    return ev, per


def _compare_sealed(raw, sealed, parts, free, report):
    """Sealed must equal raw everywhere: no key, number, label or path is dropped, altered or hashed."""
    path = _norm_path(parts)
    if isinstance(raw, dict):
        assert isinstance(sealed, dict) and list(sealed) == list(raw), (path, list(raw), list(sealed))
        for k, v in raw.items():
            _compare_sealed(v, sealed[k], parts + [k], free, report)
        return
    if isinstance(raw, list):
        assert isinstance(sealed, list) and len(sealed) == len(raw), path
        for r_item, s_item in zip(raw, sealed):
            _compare_sealed(r_item, s_item, parts + ['[]'], free, report)
        return
    assert sealed == raw and type(sealed) is type(raw), (path, raw, sealed)
    if isinstance(raw, str) and path in free:
        report.setdefault(path, set()).add('kept unchanged (existing absolute path)')


def _hmac_spots(value, parts=()) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if k == 'hmac' or str(k).startswith('hmac:'):
                out.append('.'.join(parts + (str(k),)))
            out += _hmac_spots(v, parts + (str(k),))
    elif isinstance(value, list):
        for v in value:
            out += _hmac_spots(v, parts + ('[]',))
    return out


def _seal_envelope(env, ev, per, contract):
    adapted = contract.adapt_component_result(env, component_id=_SECTION, affected_identities=['default'])
    sealed_section = ev.serialize_evidence({_SECTION: adapted[_SECTION]})
    stored_findings = ev.serialize_evidence(per.component_dto(adapted)['findings'])
    # source_digest is a keyed digest of the raw finding (persistence.digest), not section content.
    for f in stored_findings:
        f['evidence'].pop('source_digest', None)
    return adapted, sealed_section, stored_findings


def test_sealing_keeps_every_key_number_label_and_sentence(tmp_path, monkeypatch):
    w = _wiring()
    envs = _scenario_envelopes(tmp_path, monkeypatch)
    ev, per = _patch_sealing_sets(monkeypatch, w)
    contract = load_submodule('audit.contract')
    free = {f['key'] for f in w['free_strings']}
    report: dict[str, set[str]] = {}
    for env in envs:
        adapted = contract.adapt_component_result(env, component_id=_SECTION, affected_identities=['default'])
        assert adapted[_SECTION] == env[_SECTION]
        assert adapted['run_metrics'] == env['run_metrics']
        sealed = ev.serialize_evidence({_SECTION: adapted[_SECTION]})
        assert set(sealed) == {_SECTION}
        _compare_sealed(env[_SECTION], sealed[_SECTION], [], free, report)

        dto = per.component_dto(adapted)
        stored = ev.serialize_evidence(dto['findings'])
        assert len(stored) == len(adapted['findings'])

        def ev_key(f):
            return (f['id'], json.dumps({k: v for k, v in f['evidence'].items() if k != 'source_digest'},
                                        sort_keys=True))
        for raw_f, dto_f in zip(sorted(adapted['findings'], key=ev_key), sorted(stored, key=ev_key)):
            assert dto_f['id'] == raw_f['id']
            assert dto_f['classification'] == raw_f['classification']
            assert dto_f['coverage'] == raw_f['coverage']
            assert dto_f['severity'] == raw_f['severity']
            assert dto_f['consequence'] == raw_f['consequence'] == w['consequences'][raw_f['id']]
            assert dto_f['affected_identities'] == raw_f['affected_identities']
            assert dto_f['source_paths'] == raw_f['source_paths']
            kept = {k: v for k, v in dto_f['evidence'].items() if k != 'source_digest'}
            assert kept == raw_f['evidence'], raw_f['id']
        assert _hmac_spots(sealed) == [] and _hmac_spots(stored) == []
    # What the serializer does to each free string (documented in the sheet).
    assert report == {k: {'kept unchanged (existing absolute path)'} for k in free}


def test_two_runs_give_identical_sealed_section_and_findings(tmp_path, monkeypatch):
    """Each sealing uses a fresh serializer (fresh per-run HMAC key): any token would differ."""
    w = _wiring()
    _scenario_envelopes(tmp_path, monkeypatch)  # builds the synthetic homes
    ev, per = _patch_sealing_sets(monkeypatch, w)
    contract = load_submodule('audit.contract')
    mod = _mod()
    homes = sorted(p for p in tmp_path.iterdir() if p.is_dir())
    assert len(homes) > 10
    for home in homes:
        outs = []
        for _ in range(2):
            env = mod.audit_unattended_exposure(profile_path=home)
            _, sealed, stored = _seal_envelope(env, ev, per, contract)
            assert _hmac_spots(sealed) == [] and _hmac_spots(stored) == [], home.name
            outs.append(json.dumps([sealed, stored], sort_keys=True))
        assert outs[0] == outs[1], home.name


def test_canaries_reach_sealed_output_only_through_declared_free_strings(tmp_path, monkeypatch):
    w = _wiring()
    mod = _mod()
    canary = 'zqcanary'
    home = tmp_path / 'home'
    _write(home / 'config.yaml',
           f'# {canary}-comment\n'
           f'approvals:\n  mode: off\n  cron_mode: approve\n  deny: [\"{canary}-deny\"]\n'
           f'command_allowlist: [\"{canary}-allow\"]\n'
           f'terminal:\n  backend: local\n  ssh_host: {canary}-host\n'
           f'auxiliary:\n  approval:\n    model: {canary}-mini\n    provider: \"http://{canary}.example\"\n'
           f'platform_toolsets:\n  {canary}chat: [terminal, {canary}-toolset]\n'
           f'platforms:\n  {canary}chat:\n    allow_from: [\"{canary}-user\"]\n'
           f'mcp_servers:\n  {canary}-srv:\n    command: {canary}-cmd\n'
           f'hooks:\n  pre_tool_call:\n    - command: \"{canary}-hook-cmd\"\n'
           f'plugins:\n  enabled: [{canary}-plugin]\n')
    _write(home / 'config.yaml.bak', f'approvals:\n  mode: smart\n  smart_policy: {canary}-policy\n')
    _plugin(home, f'{canary}-plugin', f'name: {canary}-plugin\nversion: 9.9.9+{canary}\n'
                                      f'description: {canary}-desc\nhooks: [pre_llm_call]\n',
            init=f'# {canary}-init\n')
    _meta(home, {f'{canary}-plugin': {'pinned': False, 'revision': SHA, 'source': f'https://{canary}.example'}})
    _write(home / 'hooks' / f'{canary}-hook.sh', f'#!/bin/sh {canary}-interp\necho {canary}-body\n')
    _write(home / 'cron' / 'jobs.json', json.dumps({'jobs': [{
        'id': f'{canary}job', 'name': f'{canary}-name', 'prompt': f'{canary}-prompt', 'script': f'{canary}.sh',
        'enabled': True, 'failure_streak': 9, 'last_error': f'{canary}-err',
        'schedule': {'kind': 'cron', 'expr': '*/5 * * * *', 'display': f'{canary}-display'}}]}))
    _write(home / 'cron' / 'usage_audit.jsonl', json.dumps({'job_id': f'{canary}ghost', 'model': f'{canary}-m'}) + '\n')
    conn = sqlite3.connect(home / 'cron' / 'executions.db')
    conn.execute('CREATE TABLE executions (id TEXT, job_id TEXT, output TEXT)')
    conn.execute('INSERT INTO executions VALUES (?, ?, ?)', (f'{canary}-row', f'{canary}dbghost', f'{canary}-out'))
    conn.commit()
    conn.close()

    res = mod.audit_unattended_exposure(profile_path=home)
    free = {f['key'] for f in w['free_strings']}
    home_abs = str(home.resolve()) + '/'
    leaks: list[str] = []

    def visit(kind, path, item):
        if canary in item and not (kind == 'str' and path in free and item.startswith(home_abs)):
            leaks.append(f'{kind} {path}: {item}')
    _walk(res[_SECTION], [], visit)
    for f in res['findings']:
        _walk(f, [], visit)
    assert leaks == []
    assert canary not in json.dumps(res['findings'])
    # Only the existing plugin directory and hook file carry the canary, as absolute paths.
    raw = json.dumps(res[_SECTION])
    assert json.dumps(home_abs + f'plugins/{canary}-plugin') in raw
    assert json.dumps(home_abs + f'hooks/{canary}-hook.sh') in raw
    for absent in ('-deny', '-allow', '-host', '-toolset', '-user', '-srv', '-cmd', '-hook-cmd', '-policy',
                   '-desc', '-init', '-interp', '-body', 'job', '-name', '-prompt', '-err', '-display',
                   'ghost', 'dbghost', '-row', '-out', '-m"', 'chat'):
        assert canary + absent not in raw, absent
    # Sealing keeps those paths unchanged and produces no token.
    ev, per = _patch_sealing_sets(monkeypatch, w)
    contract = load_submodule('audit.contract')
    adapted, sealed, stored = _seal_envelope(res, ev, per, contract)
    assert sealed[_SECTION] == res[_SECTION]
    assert _hmac_spots(sealed) == [] and _hmac_spots(stored) == []
    assert canary not in json.dumps(stored)
    _walk(sealed[_SECTION], [], visit)
    assert leaks == []


# --- doc page vs code -------------------------------------------------------------------------

_DOC_PATH = Path(__file__).resolve().parents[1] / 'docs' / 'audit-sections' / 'unattended_exposure.md'


def test_doc_rule_table_and_consequence_sentences_match_code():
    from tests.test_audit_dead_stores import _doc_rule_rows, _doc_words, _doc_bullets
    mod = _mod()
    w = _wiring()
    doc = _DOC_PATH.read_text(encoding='utf-8')
    rows = _doc_rule_rows(doc, w['classifications'])
    table = {rid: sorted(_doc_words(c) for c in row['classification'].split('/'))
             for rid, row in rows.items()}
    assert table == w['classifications']
    sentences = {rid: text for rid, text in _doc_bullets(doc).items()
                 if rid.startswith('unattended_exposure.')}
    assert set(sentences) == set(mod.FINDING_CONSEQUENCES)
    for rid, sentence in mod.FINDING_CONSEQUENCES.items():
        assert _doc_words(sentences[rid]) == _doc_words(sentence), rid


def test_doc_lists_every_key_label_and_free_string_of_the_wiring_sheet():
    w = _wiring()
    doc = _DOC_PATH.read_text(encoding='utf-8')
    skip = set(w['rule_ids']) | set(w['consequences'].values())
    missing = [k for k in w['schema_keys'] if f'`{k}`' not in doc]
    missing += [v for v in w['vocabulary'] if v not in skip and f'`{v}`' not in doc]
    missing += [f['key'] for f in w['free_strings'] if f'`{f["key"]}`' not in doc]
    assert missing == []


@pytest.mark.parametrize('mode, backup', [("'off'", "'off'"), ('false', 'false'), ('OFF', 'no')])
def test_off_is_emitted_as_unambiguous_labels(tmp_path, mode, backup):
    """'off' is a sealed plain value in the report, so approvals.mode and updates.pre_update_backup emit
    approval_off / backup_off (input parsing still accepts the config word)."""
    mod = _mod()
    _write(tmp_path / 'config.yaml', f'approvals:\n  mode: {mode}\nterminal:\n  backend: local\n'
                                     f'updates:\n  pre_update_backup: {backup}\n')
    res = mod.audit_unattended_exposure(profile_path=tmp_path)
    s = res['unattended_exposure']['settings']
    assert s['approvals.mode'] == {'value': 'approval_off', 'source': 'config', 'widens_unattended_action': True}
    assert s['updates.pre_update_backup'] == {'value': 'backup_off', 'source': 'config',
                                              'widens_unattended_action': True}
    [f] = [f for f in res['findings'] if f['id'] == 'unattended_exposure.command_approval_off']
    assert f['evidence']['approvals_mode'] == 'approval_off'
    assert '"off"' not in json.dumps(res)
