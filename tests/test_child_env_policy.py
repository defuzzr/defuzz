"""Shared child-environment policy: template checks get a stripped env and no stdin."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz import componentize_bridge as bridge  # noqa: E402
from hermes_plugins.defuzz.scaffolder import ScaffoldError, accept, propose  # noqa: E402
from hermes_plugins.defuzz.templates import CheckSpec, load_template  # noqa: E402

# Synthetic parent environment (no real values).
PARENT_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/synthetic/home",
    "LANG": "C.UTF-8",
    "LC_ALL": "C",
    "TMPDIR": "/synthetic/tmp",
    "TERM": "xterm",
    "HERMES_HOME": "/synthetic/home/.hermes",
    "HERMES_PROFILE": "work",
    "HERMES_DESKTOP": "1",
    "HERMES_OTHER": "x",
    "HERMES_YOLO_MODE": "1",
    "HERMES_ACP_AUTO_APPROVE": "1",
    "HERMES_SESSION_ID": "sess-1",
    "HERMES_CRON_AUTO_DELIVER_PLATFORM": "chat",
    "HERMES_DASHBOARD_SESSION_TOKEN": "tok-1",
    "SUDO_PASSWORD": "pw",
    "SUDO_ASKPASS": "/synthetic/askpass",
    "SSH_ASKPASS": "/synthetic/ssh-askpass",
    "OPENAI_API_KEY": "sk-synthetic",
    "GITHUB_TOKEN": "ghp-synthetic",
    "CARGO_REGISTRIES_PRIV_TOKEN": "reg-synthetic",
    "SSH_AUTH_SOCK": "/synthetic/agent.sock",
    "npm_config_registry": "https://registry.example.invalid/",
    "npm_config__authToken": "npm-synthetic",
    "HTTPS_PROXY": "http://proxy.example.invalid:3128",
    "https_proxy": "http://proxy.example.invalid:3128",
    "NO_PROXY": "localhost",
    "CARGO_HOME": "/synthetic/cargo",
    "RUSTUP_HOME": "/synthetic/rustup",
    "GOPATH": "/synthetic/go",
    "DOTNET_ROOT": "/synthetic/dotnet",
    "UV_CACHE_DIR": "/synthetic/uv",
    "XDG_CACHE_HOME": "/synthetic/cache",
    "VIRTUAL_ENV": "/synthetic/venv",
    "PYTHONPATH": "/synthetic/py",
}

# Snapshot of componentize_bridge._child_env(PARENT_ENV) taken on the pre-change code
# (HEAD 22a90f6). The componentize child must stay byte-identical.
COMPONENTIZE_DROPPED_BEFORE = {
    "HERMES_YOLO_MODE",
    "HERMES_ACP_AUTO_APPROVE",
    "HERMES_SESSION_ID",
    "HERMES_CRON_AUTO_DELIVER_PLATFORM",
    "HERMES_DASHBOARD_SESSION_TOKEN",
    "SUDO_PASSWORD",
}

CHECK_DROPPED = {
    "HERMES_HOME", "HERMES_PROFILE", "HERMES_DESKTOP", "HERMES_OTHER",
    "HERMES_YOLO_MODE", "HERMES_ACP_AUTO_APPROVE", "HERMES_SESSION_ID",
    "HERMES_CRON_AUTO_DELIVER_PLATFORM", "HERMES_DASHBOARD_SESSION_TOKEN",
    "SUDO_PASSWORD", "SUDO_ASKPASS", "SSH_ASKPASS",
    "OPENAI_API_KEY", "GITHUB_TOKEN", "CARGO_REGISTRIES_PRIV_TOKEN",
    "SSH_AUTH_SOCK", "npm_config__authToken",
    "VIRTUAL_ENV", "PYTHONPATH",
}
CHECK_KEPT = set(PARENT_ENV) - CHECK_DROPPED


def test_componentize_child_env_is_unchanged():
    expected = {k: v for k, v in PARENT_ENV.items() if k not in COMPONENTIZE_DROPPED_BEFORE}
    assert bridge._child_env(dict(PARENT_ENV)) == expected


def test_componentize_public_lists_come_from_shared_policy():
    from hermes_plugins.defuzz import child_env

    assert bridge._STRIPPED_CHILD_ENV_NAMES is child_env.COMPONENTIZE_STRIPPED_NAMES
    assert bridge._STRIPPED_CHILD_ENV_PREFIXES is child_env.COMPONENTIZE_STRIPPED_PREFIXES


def test_stripped_child_env_drop_and_keep_rules():
    from hermes_plugins.defuzz import child_env

    env = child_env.stripped_child_env(dict(PARENT_ENV), extra_drop=("VIRTUAL_ENV", "PYTHONPATH"))
    assert set(env) == CHECK_KEPT
    assert all(env[k] == PARENT_ENV[k] for k in env)
    # every componentize-stripped name is also stripped for template checks
    probe = {name: "1" for name in child_env.COMPONENTIZE_STRIPPED_NAMES}
    probe.update({p + "X": "1" for p in child_env.COMPONENTIZE_STRIPPED_PREFIXES})
    assert child_env.stripped_child_env(probe) == {}


def _fake_proposal(tmp_path, cmd, prepare=None):
    spec = load_template(Path(__file__).parent / "fixtures/templates/fake-py-service")
    proposal = propose(spec, "env-policy", {}, dest_root=tmp_path / "projects",
                       staging_parent=tmp_path / "staging")
    proposal.repos[0].check = CheckSpec(cmd=cmd, cwd=".", prepare=prepare)
    return proposal


def _accept(proposal, tmp_path, monkeypatch):
    mod = sys.modules[accept.__module__]
    monkeypatch.setattr(mod.toolchk, "probe", lambda *a, **k: ("1.0.0", "fixture-tool"))
    monkeypatch.setattr(mod.toolchk, "require", lambda *a, **k: None)
    return accept(
        proposal,
        register=lambda *_: json.dumps({"success": True, "id": "env-policy"}),
        db_path=tmp_path / "state.db",
        timeout_s=30,
    )


def test_template_check_child_gets_stripped_env_and_devnull_stdin(tmp_path, monkeypatch):
    import os

    # keep the real PATH/HOME/TMPDIR so accept() and the actual check child can run
    for k, v in PARENT_ENV.items():
        if k not in {"PATH", "HOME", "TMPDIR"}:
            monkeypatch.setenv(k, v)
    # A runner may not set TMPDIR at all: give it the folder Python already uses, so the
    # check below (passed through unchanged) holds on every machine.
    monkeypatch.setenv("TMPDIR", os.environ.get("TMPDIR") or tempfile.gettempdir())
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    sentinel = [sys.executable, "-c", "import sys; sys.exit(0)  # env-policy-check"]
    prep = [sys.executable, "-c", "import sys; sys.exit(0)  # env-policy-prepare"]
    seen = []
    # The check child is started with subprocess.Popen (so a cancel can stop its process group).
    real_popen = subprocess.Popen

    def recorder(cmd, *a, **kw):
        if isinstance(cmd, list) and cmd and "env-policy-" in str(cmd[-1]):
            seen.append(kw)
        return real_popen(cmd, *a, **kw)

    monkeypatch.setattr(sys.modules[accept.__module__].subprocess, "Popen", recorder)
    result = _accept(_fake_proposal(tmp_path, sentinel, prepare=prep), tmp_path, monkeypatch)
    assert result.repos[0]["check"] == "ok"
    assert len(seen) == 2  # prepare + check
    for kw in seen:
        assert kw.get("stdin") is subprocess.DEVNULL
        env = kw["env"]
        assert not CHECK_DROPPED & env.keys(), CHECK_DROPPED & env.keys()
        for k in CHECK_KEPT:
            assert env.get(k) == os.environ[k], k


def test_template_check_failure_mentions_credentials_not_passed(tmp_path, monkeypatch):
    failing = [sys.executable, "-c", "import sys; sys.exit(3)"]
    with pytest.raises(ScaffoldError) as excinfo:
        _accept(_fake_proposal(tmp_path, failing), tmp_path, monkeypatch)
    assert "failed with exit code 3" in str(excinfo.value)
    assert "credentials" in str(excinfo.value).lower()
    assert "template checks run without HERMES_* variables" in str(excinfo.value)
    assert "configuration files on disk" in str(excinfo.value)
    assert "are not passed" not in str(excinfo.value)


def test_privilege_helper_names_still_stripped():
    from hermes_plugins.defuzz import child_env
    assert 'SUDO_PASSWORD' in child_env.COMPONENTIZE_STRIPPED_NAMES
    assert {'SUDO_PASSWORD', 'SUDO_ASKPASS', 'SSH_ASKPASS'} <= child_env.CHECK_STRIPPED_NAMES
    assert child_env.CHECK_STRIPPED_SUFFIXES == ('ASKPASS',)


# Lint children get an allow-list, not the template-check strip list. Exactly
# these DOTNET_* names pass: runtime and user-file locations, and the user's own
# telemetry and banner opt-outs. Names that change what runs or loads (start-up
# hooks, extra assemblies, roll-forward, host path, UI language, telemetry
# profile) are dropped.
LINT_DOTNET_PASSED = {
    "DOTNET_ROOT", "DOTNET_ROOT_ARM64", "DOTNET_ROOT_X64", "DOTNET_CLI_HOME",
    "DOTNET_CLI_TELEMETRY_OPTOUT", "DOTNET_NOLOGO", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE",
}
LINT_DOTNET_DROPPED = {
    "DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "DOTNET_SHARED_STORE",
    "DOTNET_ROLL_FORWARD", "DOTNET_ROLL_FORWARD_TO_PRERELEASE", "DOTNET_MULTILEVEL_LOOKUP",
    "DOTNET_HOST_PATH", "DOTNET_CLI_UI_LANGUAGE", "DOTNET_CLI_TELEMETRY_PROFILE",
    "DOTNET_ENVIRONMENT", "DOTNET_gcServer", "DOTNET_INSTALL_DIR",
}


def test_lint_env_passes_exactly_these_dotnet_names(tmp_path):
    from unittest import mock

    from hermes_plugins.defuzz import lint_env

    assert {k for k in lint_env.LINT_ENV_KEYS if k.startswith("DOTNET_")} == LINT_DOTNET_PASSED
    base = {"PATH": str(tmp_path), "HOME": str(tmp_path)}
    base.update({k: f"/synthetic/{k}" for k in LINT_DOTNET_PASSED | LINT_DOTNET_DROPPED})
    with mock.patch.object(lint_env, "real_home", return_value=tmp_path):
        env = lint_env.build_env(base)
    assert {k for k in env if k.startswith("DOTNET_")} == LINT_DOTNET_PASSED
    assert all(env[k] == base[k] for k in LINT_DOTNET_PASSED)


def test_lint_env_passes_user_set_toolchain_locations(tmp_path):
    from unittest import mock

    from hermes_plugins.defuzz import lint_env

    locations = {
        "GOPATH", "GOROOT", "GOMODCACHE", "CARGO_HOME", "RUSTUP_HOME", "DOTNET_ROOT", "HOME",
    }
    not_passed = {"VIRTUAL_ENV", "PYTHONPATH", "NODE_PATH", "XDG_CONFIG_HOME", "UV_INDEX_URL"}
    base = {"PATH": str(tmp_path)}
    base.update({k: f"/synthetic/{k}" for k in locations | not_passed})
    with mock.patch.object(lint_env, "real_home", return_value=tmp_path):
        env = lint_env.build_env(base)
    assert all(env.get(k) == base[k] for k in locations), {k: env.get(k) for k in locations}
    assert not not_passed & env.keys()
