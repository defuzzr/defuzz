"""A check that fails because it cannot download ends on a plain 'needs an internet connection' line.

The files under ``fixtures/network_failure/`` are real tool outputs: captured with no network,
against a loopback registry answering 401/403/404/407/429/500/503 or serving HTML, through a proxy
that needs a login or is not running, with a self-signed certificate, and (``online-`` files)
online test-suite failures. Only home folders were rewritten. The classifier is conservative: a
missed offline case keeps the old ending (acceptable); a wrong 'needs an internet connection' is not.
"""
import json
import sys
import time
from pathlib import Path

import pytest
from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz import cli  # noqa: E402
from hermes_plugins.defuzz import network_failure as nf  # noqa: E402
from hermes_plugins.defuzz.child_env import CREDENTIALS_NOT_PASSED_NOTE  # noqa: E402
from hermes_plugins.defuzz.scaffolder import ScaffoldError, ScaffoldTimeout, accept, propose  # noqa: E402
from hermes_plugins.defuzz.templates import CheckSpec, load_template  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures/templates"
OUTPUTS = Path(__file__).parent / "fixtures/network_failure"


def _out(name):
    return (OUTPUTS / f"{name}.txt").read_text(encoding="utf-8")


def _host(*parts):
    # Host names in Python source are built from pieces.
    return ".".join(parts)


# Real offline download failures: these end on the internet sentence.
OFFLINE = {
    "uv-pip-install", "uv-run-with", "uv-python-install", "uv-golden-xtask-ci",
    "pip-download",
    "npm-install", "npm-view",
    "pnpm-add", "pnpm-golden-prepare",
    "cargo-fetch", "cargo-golden-xtask-ci",
    "go-mod-download", "go-build", "go-toolchain-auto",
    "dotnet-restore",
    "cmake-fetchcontent-git", "cmake-fetchcontent-url",
    "git-clone", "curl-get",
}
# Real offline failure that names no registry host: missed on purpose (old ending).
KNOWN_MISSES = {"cmake-file-download"}

# Short made-up non-network cases kept as extra guards (all must keep the old ending).
OTHER_SAMPLES = {
    "mentions-network": (
        f"FAILED tests/test_network.py::test_network_layer - AssertionError: see https://{_host('github', 'com')}/x\n"
        "1 failed, 12 passed"
    ),
    "mentions-url-only": f"error: lint failed, docs at https://{_host('pypi', 'org')}/project/ruff/\nfound 3 errors",
    "local-db-refused": (
        "psycopg.OperationalError: connection to server at localhost (::1), port 5432 failed: "
        "Connection refused\nFAILED tests/test_db.py::test_insert"
    ),
    "test-timed-out": "FAILED tests/test_slow.py::test_retry - TimeoutError: operation timed out",
}


def _all_fixture_names():
    return sorted(p.stem for p in OUTPUTS.glob("*.txt"))


def test_every_tool_has_the_required_fixture_kinds():
    names = set(_all_fixture_names())
    for tool in ("uv", "pip", "npm", "cargo", "go"):
        for kind in ("s401", "s403", "s404", "s407", "px407", "tls", "s503", "pxdead"):
            assert f"{tool}-{kind}" in names, f"{tool}-{kind}"
    for kind in ("restore", "s401", "s403", "s404", "s503", "tls"):
        assert f"dotnet-{kind}" in names
    for name in ("git-px407", "git-tls", "curl-px407", "curl-tls", "go-test-local", "node-fetch-localhost",
                 "online-go-test-dbhost", "online-py-socket-dbhost", "online-py-urllib3-localhost-refused",
                 "online-py-requests-localhost-refused", "online-go-downloading-then-local-refused",
                 "online-go-downloading-then-test-timeout"):
        assert name in names
    assert OFFLINE | KNOWN_MISSES <= names


@pytest.mark.parametrize("name", _all_fixture_names())
def test_real_tool_output_classification(name):
    assert nf.looks_like_network_failure(_out(name)) is (name in OFFLINE)


@pytest.mark.parametrize("name", sorted(OTHER_SAMPLES))
def test_other_samples_keep_old_ending(name):
    assert nf.looks_like_network_failure(OTHER_SAMPLES[name]) is False


# Review findings, named so a regression points at the finding.
@pytest.mark.parametrize("name", ["dotnet-s401", "dotnet-s403", "dotnet-s404", "dotnet-s503", "dotnet-tls"])
def test_high1_nuget_nu1301_alone_is_not_offline(name):
    assert nf.looks_like_network_failure(_out(name)) is False


def test_high1_real_offline_dotnet_is_still_offline():
    assert nf.looks_like_network_failure(_out("dotnet-restore")) is True


@pytest.mark.parametrize("name", ["online-py-urllib3-localhost-refused", "online-py-requests-localhost-refused",
                                  "pip-pxdead", "py-urllib3-localhost"])
def test_high2_refused_connection_is_not_offline(name):
    assert nf.looks_like_network_failure(_out(name)) is False


@pytest.mark.parametrize("name", ["uv-px407", "uv-tls", "uv-pxdead", "uv-slow"])
def test_high3_uv_proxy_login_and_bad_certificate_are_not_offline(name):
    assert nf.looks_like_network_failure(_out(name)) is False


@pytest.mark.parametrize("veto", [
    "tunnel error: proxy authorization required",
    "407 Proxy Authentication Required",
    "invalid peer certificate: UnknownIssuer",
    "Response status code does not indicate success: 401 (Unauthorized).",
    "HTTP status client error (403 Forbidden)",
    "reading x/@v/v1.mod: 404 Not Found",
])
def test_high3_veto_wins_over_offline_text(veto):
    assert nf.looks_like_network_failure(_out("uv-pip-install") + "\n" + veto) is False


@pytest.mark.parametrize("name", ["online-go-downloading-then-local-refused",
                                  "online-go-downloading-then-test-timeout",
                                  "online-go-test-dbhost", "online-py-socket-dbhost",
                                  "online-py-urllib3-dbhost", "go-test-local", "py-socket-dbhost"])
def test_m5_test_suite_failures_are_not_offline(name):
    assert nf.looks_like_network_failure(_out(name)) is False


@pytest.mark.parametrize("host", ["db", "postgres", "localhost", "cache.local", "api.internal"])
def test_m5_local_names_never_count(host):
    lines = [
        f"x_test.go:4: dial tcp: lookup {host} on 127.0.0.53:53: server misbehaving",
        f"curl: (6) Could not resolve host: {host}",
        f"Error: getaddrinfo EAI_AGAIN {host}",
        f"error NU1301:   Resource temporarily unavailable ({host}:443)",
        f"error: Failed to fetch: http://{host}:8080/simple/x/\n  cause: dns error\n"
        "  cause: failed to lookup address information: Temporary failure in name resolution",
    ]
    for line in lines:
        assert nf.looks_like_network_failure(line) is False, line


def test_classifier_rejects_non_text():
    assert nf.looks_like_network_failure(None) is False  # type: ignore[arg-type]
    assert nf.looks_like_network_failure(b"Temporary failure in name resolution") is False  # type: ignore[arg-type]
    assert nf.looks_like_network_failure("") is False


def test_classifier_is_case_insensitive():
    assert nf.looks_like_network_failure(_out("curl-get").upper()) is True


def test_huge_output_is_fast_and_capped():
    filler = "a" * (40 * 1024 * 1024)
    marker = _out("uv-pip-install")
    start = time.monotonic()
    assert nf.looks_like_network_failure(filler + marker) is True  # error at the end: in the tail window
    assert nf.looks_like_network_failure(marker + filler) is True  # error at the start: in the head window
    assert nf.looks_like_network_failure(filler + marker + filler) is False  # middle is not scanned
    # adversarial: many near-misses and many context-free hits of every marker
    near = ("temporary failure in name resolutio " * 200000) + ("could not resolve host: x " * 200000)
    assert nf.looks_like_network_failure(near) is False
    many = ("failed to fetch: https://" + "a" * 3000 + " temporary failure in name resolution\n") * 2000
    assert nf.looks_like_network_failure(many) is False
    assert time.monotonic() - start < 2.0


def test_note_wording_is_one_sentence_plus_optional_claim():
    untouched = nf.network_required_note(projects_untouched=True)
    other = nf.network_required_note(projects_untouched=False)
    assert untouched == f"{other} Nothing was added to your projects folder."
    assert other.count(".") == 1 and other.endswith(".")
    for note in (untouched, other):
        assert "\n" not in note
        assert "needs an internet connection" in note
        assert "command" not in note and "(" not in note
        assert "token" not in note.lower()


def test_with_network_note_only_for_network_output():
    msg = "componentize kit check failed for 'web-app'"
    out = nf.with_network_note(msg, _out("pnpm-add"))
    assert out.splitlines()[0] == msg
    assert out.splitlines()[-1] == nf.network_required_note(projects_untouched=True)
    assert nf.with_network_note(msg, _out("npm-s403")) == msg
    assert nf.with_network_note(msg, _out("pnpm-add"), projects_untouched=False).endswith(
        nf.network_required_note(projects_untouched=False))


# --- template check integration (scaffolder) -------------------------------------------------


def _proposal(tmp_path, cmd, *, prepare=None, staging_parent=None):
    spec = load_template(FIXTURES / "fake-py-service")
    proposal = propose(
        spec, "offline-demo", {}, dest_root=tmp_path / "projects",
        staging_parent=staging_parent or tmp_path / "staging",
    )
    proposal.repos[0].check = CheckSpec(cmd=cmd, cwd=".", prepare=prepare)
    return proposal


def _accept(proposal, tmp_path, monkeypatch, timeout_s=30):
    mod = sys.modules[accept.__module__]
    monkeypatch.setattr(mod.toolchk, "probe", lambda *a, **k: ("1.0.0", "fixture-tool"))
    monkeypatch.setattr(mod.toolchk, "require", lambda *a, **k: None)
    return accept(
        proposal,
        register=lambda *_: json.dumps({"success": True, "id": "offline-demo"}),
        db_path=tmp_path / "state.db",
        timeout_s=timeout_s,
    )


def _emit(name, code=2):
    path = str(OUTPUTS / f"{name}.txt")
    return [sys.executable, "-c",
            f"import sys; sys.stderr.write(open({path!r}, encoding='utf-8').read()); sys.exit({code})"]


def _emit_then_hang(name):
    path = str(OUTPUTS / f"{name}.txt")
    return [sys.executable, "-c",
            f"import sys, time; sys.stderr.write(open({path!r}, encoding='utf-8').read()); "
            "sys.stderr.flush(); time.sleep(60)"]


def _projects_entries(tmp_path):
    root = tmp_path / "projects"
    return sorted(p.name for p in root.iterdir()) if root.exists() else []


def test_network_check_failure_ends_with_internet_sentence(tmp_path, monkeypatch):
    with pytest.raises(ScaffoldError) as excinfo:
        _accept(_proposal(tmp_path, _emit("uv-golden-xtask-ci")), tmp_path, monkeypatch)
    lines = str(excinfo.value).splitlines()
    assert lines[-1] == nf.network_required_note(projects_untouched=True)
    assert CREDENTIALS_NOT_PASSED_NOTE in lines  # still shown, but not last
    assert "failed with exit code 2" in lines[0]
    assert "Temporary failure in name resolution" in str(excinfo.value)
    assert excinfo.value.reason == nf.NETWORK_REQUIRED_REASON
    assert excinfo.value.returncode == 2
    assert _projects_entries(tmp_path) == []


def test_network_prepare_failure_also_ends_with_internet_sentence(tmp_path, monkeypatch):
    ok = [sys.executable, "-c", "import sys; sys.exit(0)"]
    proposal = _proposal(tmp_path, ok, prepare=_emit("pnpm-add", 1))
    with pytest.raises(ScaffoldError) as excinfo:
        _accept(proposal, tmp_path, monkeypatch)
    assert str(excinfo.value).splitlines()[-1] == nf.network_required_note(projects_untouched=True)
    assert _projects_entries(tmp_path) == []


def test_staging_inside_projects_folder_drops_nothing_added_claim(tmp_path, monkeypatch):
    proposal = _proposal(tmp_path, _emit("go-build"), staging_parent=tmp_path / "projects" / "stage")
    with pytest.raises(ScaffoldError) as excinfo:
        _accept(proposal, tmp_path, monkeypatch)
    assert str(excinfo.value).splitlines()[-1] == nf.network_required_note(projects_untouched=False)


@pytest.mark.parametrize("name", ["dotnet-s401", "uv-px407", "online-py-urllib3-localhost-refused",
                                  "online-go-test-dbhost", "npm-s404"])
def test_other_check_failures_keep_token_note_last(tmp_path, monkeypatch, name):
    with pytest.raises(ScaffoldError) as excinfo:
        _accept(_proposal(tmp_path, _emit(name, 3)), tmp_path, monkeypatch)
    assert str(excinfo.value).splitlines()[-1] == CREDENTIALS_NOT_PASSED_NOTE
    assert "internet connection" not in str(excinfo.value)
    assert excinfo.value.reason is None


def test_m4_offline_check_that_times_out_ends_with_internet_sentence(tmp_path, monkeypatch):
    with pytest.raises(ScaffoldTimeout) as excinfo:
        _accept(_proposal(tmp_path, _emit_then_hang("pnpm-golden-prepare")), tmp_path, monkeypatch, timeout_s=3)
    lines = str(excinfo.value).splitlines()
    assert lines[-1] == nf.network_required_note(projects_untouched=True)
    assert "timed out" in lines[0]
    assert excinfo.value.reason == nf.NETWORK_REQUIRED_REASON
    assert excinfo.value.keep_staging is True
    assert _projects_entries(tmp_path) == []


def test_m4_other_check_that_times_out_keeps_old_ending(tmp_path, monkeypatch):
    with pytest.raises(ScaffoldTimeout) as excinfo:
        _accept(_proposal(tmp_path, _emit_then_hang("online-go-test-dbhost")), tmp_path, monkeypatch, timeout_s=3)
    assert "internet connection" not in str(excinfo.value)
    assert getattr(excinfo.value, "reason", None) is None


# --- CLI --template path: the internet sentence stays the last line ----------------------------


def _run_cli_template(tmp_path, monkeypatch, exc):
    def failing_accept(*_a, **_k):
        raise exc

    # The real propose() stages under TMPDIR: point it into tmp_path so nothing is left behind.
    stage_parent = tmp_path / "tmp"
    stage_parent.mkdir()
    monkeypatch.setenv("TMPDIR", str(stage_parent))
    monkeypatch.setattr(cli, "accept", failing_accept)
    code = cli._run_explicit_template_new(
        "fake-py-service", "Offline Demo", lambda *_: None, str(tmp_path / "projects"), {},
        str(FIXTURES), True, 60.0,
    )
    assert [p.name.startswith("adopt-scaffold-") for p in stage_parent.iterdir()] == [True]
    return code


def test_cli_template_network_failure_prints_staging_before_sentence(tmp_path, monkeypatch, capsys):
    note = nf.network_required_note(projects_untouched=True)
    stage = tmp_path / "staging-kept"
    exc = ScaffoldError(
        f"Check command x failed with exit code 2 in demo:\n{_out('uv-pip-install')}\n"
        f"{CREDENTIALS_NOT_PASSED_NOTE}\n{note}",
        staging_dir=stage, keep_staging=True, returncode=2, reason=nf.NETWORK_REQUIRED_REASON,
    )
    assert _run_cli_template(tmp_path, monkeypatch, exc) == 1
    err_lines = capsys.readouterr().err.strip().splitlines()
    assert err_lines[-1] == note
    assert f"Staging preserved at {stage}" in err_lines


def test_cli_template_network_timeout_keeps_exit_3_and_sentence_last(tmp_path, monkeypatch, capsys):
    note = nf.network_required_note(projects_untouched=True)
    stage = tmp_path / "staging-kept"
    exc = ScaffoldTimeout(
        f"Check command x timed out in demo:\n{_out('pnpm-golden-prepare')}\n{note}",
        staging_dir=stage, keep_staging=True, reason=nf.NETWORK_REQUIRED_REASON,
    )
    assert _run_cli_template(tmp_path, monkeypatch, exc) == 3
    err_lines = capsys.readouterr().err.strip().splitlines()
    assert err_lines[-1] == note
    assert f"Staging preserved at {stage}" in err_lines


def test_cli_template_other_failure_keeps_old_order(tmp_path, monkeypatch, capsys):
    stage = tmp_path / "staging-kept"
    exc = ScaffoldError(
        f"Check command x failed with exit code 3 in demo:\nboom\n{CREDENTIALS_NOT_PASSED_NOTE}",
        staging_dir=stage, keep_staging=True, returncode=3,
    )
    assert _run_cli_template(tmp_path, monkeypatch, exc) == 1
    err_lines = capsys.readouterr().err.strip().splitlines()
    assert err_lines[-2] == CREDENTIALS_NOT_PASSED_NOTE
    assert err_lines[-1] == f"Staging preserved at {stage}"


# An ordinary failing unit test whose assertion merely quotes a registry lookup error is not offline.
def _real_unittest_output(tmp_path):
    import subprocess
    host = _host("registry", "npmjs", "org")
    test = tmp_path / "test_quote.py"
    test.write_text(
        "import unittest\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_message(self):\n"
        f"        self.assertEqual('request cancelled', 'getaddrinfo EAI_AGAIN {host}')\n\n"
        "if __name__ == '__main__':\n    unittest.main()\n",
        encoding="utf-8",
    )
    proc = subprocess.run([sys.executable, "-B", str(test)], capture_output=True, text=True, cwd=tmp_path, timeout=60)
    assert proc.returncode != 0
    out = proc.stdout + proc.stderr
    assert "AssertionError" in out and host in out
    return out


def test_real_failing_unittest_quoting_registry_error_is_not_offline(tmp_path):
    assert nf.looks_like_network_failure(_real_unittest_output(tmp_path)) is False


@pytest.mark.parametrize("line", [
    "E   AssertionError: assert 'ok' == 'getaddrinfo ENOTFOUND {h}'",
    "--- FAIL: TestMsg (0.00s)\n    x_test.go:9: got \"dial tcp: lookup {h}: no such host\"\nFAIL",
    "thread 'msg' panicked: assertion `left == right` failed\n  right: \"could not resolve host: {h}\"\n"
    "test result: FAILED. 0 passed; 1 failed",
    "expected message: could not resolve host: {h}",
])
def test_named_registry_host_without_download_context_is_not_offline(line):
    assert nf.looks_like_network_failure(line.format(h=_host("registry", "npmjs", "org"))) is False


