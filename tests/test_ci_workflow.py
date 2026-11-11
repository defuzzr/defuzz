"""Static checks of the CI workflow (.github/workflows/ci.yml). No network."""
from __future__ import annotations

import re
import shlex
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
ALLOWED_ACTIONS = {"actions/checkout", "actions/setup-python", "actions/setup-node"}


def _text():
    return WORKFLOW.read_text(encoding="utf-8")


def _workflow():
    data = yaml.safe_load(_text())
    assert isinstance(data, dict)
    return data


def _triggers(data):
    # PyYAML reads the bare key `on` as the boolean True.
    return data.get("on", data.get(True))


def _steps(data):
    for job in data["jobs"].values():
        yield from job["steps"]


def test_workflow_parses_and_runs_on_push_and_pull_request():
    data = _workflow()
    triggers = _triggers(data)
    keys = set(triggers) if isinstance(triggers, dict) else set(triggers if isinstance(triggers, list) else [triggers])
    assert keys == {"push", "pull_request"}
    assert data["jobs"], "no jobs"


def test_only_allowed_actions_each_pinned_to_a_full_commit_sha():
    uses = [step["uses"] for step in _steps(_workflow()) if "uses" in step]
    assert uses
    for ref in uses:
        name, _, sha = ref.partition("@")
        assert name in ALLOWED_ACTIONS, ref
        assert re.fullmatch(r"[0-9a-f]{40}", sha), ref
    # Every `uses:` line carries the version it pins in a comment.
    for line in _text().splitlines():
        if re.match(r"\s*-?\s*uses:", line):
            assert re.search(r"@[0-9a-f]{40} # v\d+(\.\d+)*$", line), line


def test_least_privilege_and_no_risky_constructs():
    data = _workflow()
    assert data["permissions"] == {"contents": "read"}
    for job in data["jobs"].values():
        assert "permissions" not in job
    text = _text()
    assert not re.search(r"\b" + "su" + r"do\b", text)
    assert "secrets." not in text and "secrets[" not in text
    assert "pull_request_" + "target" not in text
    for step in _steps(data):
        if step.get("uses", "").startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False, step


def test_every_job_has_a_timeout_and_superseded_runs_are_cancelled():
    data = _workflow()
    for name, job in data["jobs"].items():
        assert isinstance(job.get("timeout-minutes"), int) and job["timeout-minutes"] > 0, name
    assert data["concurrency"]["cancel-in-progress"] is True


def test_hermes_agent_checkout_is_pinned_to_a_commit():
    checkouts = [step["with"] for step in _steps(_workflow())
                 if step.get("uses", "").startswith("actions/checkout@") and "repository" in step.get("with", {})]
    assert [c["repository"] for c in checkouts] == ["NousResearch/hermes-agent"]
    assert re.fullmatch(r"[0-9a-f]{40}", checkouts[0]["ref"])


def test_python_matrix_covers_the_floor():
    job = _workflow()["jobs"]["python"]
    assert job["strategy"]["matrix"]["python"] == ["3.13", "3.14"]
    # Python 3.11 and 3.12 are no longer supported: neither appears anywhere.
    assert "3.11" not in _text() and "3.12" not in _text()


def test_every_job_runs_on_ubuntu_latest_only_and_a_failure_fails_the_run():
    data = _workflow()
    assert set(data["jobs"]) == {"python", "desktop"}
    for name, job in data["jobs"].items():
        strategy = job["strategy"]
        assert strategy["matrix"]["os"] == ["ubuntu-latest"], name
        assert strategy["fail-fast"] is False, name
        assert job["runs-on"] == "${{ matrix.os }}", name
        assert "continue-on-error" not in job, name
        assert "continue-on-error" not in strategy, name
        assert "exclude" not in strategy["matrix"] and "include" not in strategy["matrix"], name
        for step in job["steps"]:
            assert "continue-on-error" not in step, (name, step)
    assert "continue-on-error" not in _text()


def test_no_macos_or_windows_runner_anywhere_in_the_file():
    # The plugin is Linux only; macOS and Windows runners bill at a multiple.
    assert not re.search(r"macos|windows|darwin|self-hosted", _text(), re.IGNORECASE)
    for job in _workflow()["jobs"].values():
        for runner in job["strategy"]["matrix"]["os"]:
            assert runner.startswith("ubuntu-"), runner


def test_test_commands_name_only_files_that_exist():
    runs = [step["run"] for step in _steps(_workflow()) if "run" in step]
    pytest_runs = [r for r in runs if "-m pytest" in r]
    assert len(pytest_runs) == 1
    words = shlex.split(pytest_runs[0])
    words = words[words.index("pytest") + 1:]
    files = [w for w in words if w.startswith("tests/")]
    assert files, pytest_runs[0]
    for rel in files:
        assert (REPO_ROOT / rel).is_file(), rel
    # The workflow selects files only: no deselection or keyword filter.
    for option in ("-k", "--deselect", "--ignore", "-m"):
        assert option not in words, option
    assert "tests/test_ci_workflow.py" in files
    node_runs = [r for r in runs if r.startswith("node ")]
    assert len(node_runs) == 1
    for word in shlex.split(node_runs[0]):
        if word.startswith("./") or word.startswith("desktop/"):
            matches = list(REPO_ROOT.glob(word.removeprefix("./")))
            assert matches, word
