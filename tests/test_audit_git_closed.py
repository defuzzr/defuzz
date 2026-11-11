"""Fail-closed Git configuration classification uses only captured bytes."""
import pytest
from tests.conftest import load_submodule


@pytest.mark.parametrize('section,key,value', [
    ('core', key, 'CANARY') for key in ('fsmonitor', 'sshCommand', 'pager', 'editor', 'hooksPath')
] + [
    ('sequence', 'editor', 'CANARY'), ('alias', 'run', '!CANARY'),
    ('filter "x"', 'clean', 'CANARY'), ('filter "x"', 'smudge', 'CANARY'),
    ('filter "x"', 'process', 'CANARY'), ('diff "x"', 'textconv', 'CANARY'),
    ('diff', 'command', 'CANARY'), ('merge "x"', 'driver', 'CANARY'),
    ('credential "https://example"', 'helper', 'CANARY'), ('gpg', 'program', 'CANARY'),
    ('gpg "ssh"', 'program', 'CANARY'), ('uploadpack', 'packObjectsHook', 'CANARY'),
    ('remote "x"', 'uploadpack', 'CANARY'), ('remote "x"', 'receivepack', 'CANARY'),
    ('pager', 'status', 'CANARY'), ('receive', 'procReceiveRefs', 'CANARY'),
])
def test_executing_keys_are_dynamic(section, key, value):
    config = load_submodule('audit.outward_git_config')
    result = config.classify_git_config(f'[{section}]\n{key} = {value}\n')
    assert result.status == 'dynamic'
    assert 'CANARY' not in repr(result)


@pytest.mark.parametrize('text', [
    '[include]\npath=other', '[includeIf "gitdir:never/"]\npath=other',
    '[includeIf "unknown:condition"]', '[core]\nbare=true\ninvalid key',
    '[core]\nbare="unterminated', '[core]\nbare=bad\\q',
    '[core]\nbare=true\x00', '[core]\nnewkey=true', '[core "x"]\nbare=true',
    '[alias]\nco=checkout', '[unknown]', b'\xff',
])
def test_unresolved_or_invalid_configs_are_not_inert(text):
    config = load_submodule('audit.outward_git_config')
    assert config.classify_git_config(text).status == 'could_not_verify'


def test_case_continuations_duplicates_and_deprecated_sections():
    config = load_submodule('audit.outward_git_config')
    assert config.classify_git_config('[CORE]\nBare=false\nEDITOR=one\\\n two').status == 'dynamic'
    assert config.classify_git_config('[core]\nbare=false\neditor=one\neditor=').status == 'dynamic'
    assert config.classify_git_config('[diff.custom]\ncommand=secret').status == 'dynamic'
    assert config.classify_git_config('[core]\neditor=secret\n[broken').status != 'inert'



def test_discovery_exposes_config_roles_including_arbitrary_includes(tmp_path):
    git = load_submodule('audit.outward_git')
    home, project, separate = (tmp_path / n for n in ('home', 'project', 'separate'))
    for p in (home, project, separate):
        p.mkdir()
    (project / '.git').write_text(f'gitdir: {separate}\n')
    (separate / 'config').write_text('[include]\npath=unusual.data\n')
    (separate / 'unusual.data').write_text('[core]\neditor=secret\n')
    (separate / 'config.worktree').write_text('[core]\nbare=false\n')
    system = tmp_path / 'system-config'
    context = git.discover_git_context(project, home=home, system_config=system)
    expected = {separate / 'config', separate / 'config.worktree', separate / 'unusual.data',
                home / '.gitconfig', home / '.config/git/config', system}
    assert expected <= context.config_paths
    assert all(context.config_kind(p) == 'git_config' for p in expected)
    assert context.config_kind(project / 'unrelated') is None


def test_config_classifier_requires_every_key_to_be_inert():
    config = load_submodule('audit.outward_git_config')
    assert config.classify_git_config(b'[core]\n bare = false\n filemode\n').status == 'inert'
    result = config.classify_git_config(b'[core]\n bare=false\n futureExecutor=secret\n')
    assert result.status == 'could_not_verify'
    assert 'secret' not in repr(result)
