"""Kit creation: a cancel during the companion's check stops the companion's whole process tree."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from tests import ensure_test_package, load_submodule
from tests.fake_kit_bridge import FakeKitBridge
from tests.test_scaffolder_cancel_check import _tree_cmd, _wait_file, _wait_gone

ensure_test_package()

bridge = load_submodule("componentize_bridge")
kit_scaffold = load_submodule("kit_scaffold")
POSIX = pytest.mark.skipif(os.name == "nt", reason="process groups are POSIX")


@POSIX
def test_cancel_stops_the_companion_and_its_children(tmp_path):
    pid_file = tmp_path / "grandchild.pid"
    cancel = threading.Event()
    threading.Thread(target=lambda: (_wait_file(pid_file), cancel.set()), daemon=True).start()
    start = time.monotonic()
    with pytest.raises(bridge.CliCancelled):
        bridge._run_cli(_tree_cmd(pid_file), [], cwd=tmp_path, timeout=60, cancel=cancel)
    assert time.monotonic() - start < 15.0
    assert _wait_gone(int(pid_file.read_text(encoding="utf-8")))


def test_with_a_cancel_hook_output_timeout_and_cap_behave_as_before(tmp_path, monkeypatch):
    never = threading.Event()
    code = "import sys; print('{\"a\": 1}'); print('note', file=sys.stderr); sys.exit(1)"
    done = bridge._run_cli([sys.executable, "-c", code], [], cwd=tmp_path, timeout=30, cancel=never)
    assert (done.returncode, done.stdout, done.stderr) == (1, '{"a": 1}\n', "note\n")
    with pytest.raises(subprocess.TimeoutExpired):
        bridge._run_cli([sys.executable, "-c", "import time; time.sleep(30)"], [], cwd=tmp_path,
                        timeout=0.5, cancel=never)
    monkeypatch.setattr(bridge, "MAX_CLI_OUTPUT_BYTES", 1000)
    with pytest.raises(ValueError):
        bridge._run_cli([sys.executable, "-c", "print('x' * 5000)"], [], cwd=tmp_path, timeout=30, cancel=never)


class _BlockingCheckBridge(FakeKitBridge):
    """kit_check takes the cancel hook and runs until it is set, like the real companion run."""

    def kit_check(self, kit_id: str, dest: Path | str, *, timeout: Any = None, cancel: Any = None):
        self.check_calls.append({"kit_id": kit_id, "dest": Path(dest), "timeout": timeout, "cancel": cancel})
        while cancel is not None and not cancel.is_set():
            time.sleep(0.01)
        return {"status": "error", "data": None, "notice": "componentize kit check was cancelled.", "exit": None}


def test_accept_kit_passes_cancel_and_answers_the_cancelled_shape(tmp_path, monkeypatch):
    fake = _BlockingCheckBridge()
    fake.install(monkeypatch, bridge)
    projects = tmp_path / "projects"
    projects.mkdir()
    proposal = kit_scaffold.propose_kit("video-production", "Stop Kit", {"building": "video"},
                                        dest_root=str(projects), bridge=bridge)
    cancel = threading.Event()
    threading.Timer(0.2, cancel.set).start()
    with pytest.raises(kit_scaffold.ScaffoldError) as caught:
        kit_scaffold.accept_kit(proposal, db_path=tmp_path / "s.db", bridge=bridge, cancel=cancel)
    assert caught.value.cancelled is True and caught.value.keep_staging is True
    assert fake.check_calls[-1]["cancel"] is cancel
    assert not (projects / "stop-kit").exists()
    assert Path(proposal.staged).is_dir()
    kit_scaffold.discard_kit(proposal)
