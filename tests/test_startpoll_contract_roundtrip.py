"""Start-and-poll, end to end: the real routes, the real job machinery and a real slow check.

Each test drives a sequence the desktop page performs (desktop/plugin.js: startAndPoll,
pollAccept, cancelAccept, the accept onError) and asserts the exact JSON the page reads.
The template's check is a real child process that waits for a gate file, so cancel really
stops a running check.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests import ensure_test_package, load_submodule

ensure_test_package()

from hermes_plugins.defuzz.templates import CheckSpec, RepoSpec, TemplateSpec  # noqa: E402

WAIT = 20.0
UNKNOWN = {"detail": "Unknown or consumed proposal_id"}


class World:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        api = load_submodule("dashboard.plugin_api")
        self.routes = api._load("dashboard.routes.workspace_routes")
        self.jobs = api._load("dashboard.routes.accept_jobs")
        self.scaffolder = self.routes.scaffolder
        self.tmp = tmp_path
        self.mp = monkeypatch
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
        (tmp_path / "hh").mkdir()
        monkeypatch.setattr(self.jobs, "ACCEPT_INLINE_WAIT_S", 0.05)
        self.jobs._reset_for_tests()
        with self.routes._LOCK:
            self.routes._PROPOSALS.clear()
        app = FastAPI()
        app.include_router(api.router)
        self.client = TestClient(app, raise_server_exceptions=False)
        self.projects = tmp_path / "projects"
        self.projects.mkdir()
        self.gate = tmp_path / "gate"     # holds the check's exit code once written
        self.starts = tmp_path / "starts"  # one line per check process started

    # --- set-up -------------------------------------------------------------------------

    def _spec(self, name: str) -> TemplateSpec:
        root = self.tmp / f"tpl-{name}"
        repo = root / "tmpl_prefix"
        repo.mkdir(parents=True)
        (repo / "README.md").write_text("tmpl_prefix\n", encoding="utf-8")
        code = (
            "import os, sys, time\n"
            f"open({str(self.starts)!r}, 'a').write('start\\n')\n"
            "end = time.time() + 60\n"
            f"while not os.path.exists({str(self.gate)!r}) and time.time() < end: time.sleep(0.02)\n"
            f"sys.exit(int(open({str(self.gate)!r}).read() or 0))\n"
        )
        return TemplateSpec(
            id="mini", name="Mini", summary="Minimal template.", kind="lib", layout="mono",
            languages=("python",), engine=None, tags=(), needs=(), placeholder="tmpl_prefix",
            substitute_in=("**/*.md",), repos=(RepoSpec(name="tmpl_prefix", check=CheckSpec(cmd=(sys.executable, "-c", code))),),
            root=root,
        )

    def propose(self, name: str = "Demo") -> tuple[str, Path]:
        proposal = self.scaffolder.propose(self._spec(name), name, {}, dest_root=self.projects,
                                           staging_parent=self.tmp / "stage", db_path=self.tmp / "s.db")
        pid = uuid.uuid4().hex
        row = self.routes._new_row("template")
        row.update(state="ready", proposal=proposal, remember_options=False)
        with self.routes._LOCK:
            self.routes._PROPOSALS[pid] = row
        return pid, proposal.repos[0].dest

    def open_gate(self, code: int = 0) -> None:
        self.gate.write_text(str(code), encoding="utf-8")

    def check_starts(self) -> int:
        return len(self.starts.read_text(encoding="utf-8").splitlines()) if self.starts.exists() else 0

    # --- what the page sends --------------------------------------------------------------

    def post(self, pid: str) -> Any:
        return self.client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})

    def poll(self, pid: str) -> Any:
        return self.client.get(f"/scaffold/accept/{pid}")

    def cancel(self, pid: str) -> Any:
        return self.client.post("/scaffold/cancel", json={"proposal_id": pid})

    def until(self, pid: str, predicate, limit: float = WAIT) -> dict:
        end = time.monotonic() + limit
        while time.monotonic() < end:
            resp = self.poll(pid)
            assert resp.status_code == 200, resp.text
            body = resp.json()
            if predicate(body):
                return body
            time.sleep(0.02)
        raise AssertionError(f"no matching poll answer; last: {body}")

    def final(self, pid: str) -> dict:
        return self.until(pid, lambda b: b["status"] != "running")

    def in_check(self, pid: str) -> dict:
        body = self.until(pid, lambda b: b["status"] != "running" or b["step"] == self.jobs.STEP_CHECK)
        assert body["status"] == "running", body
        end = time.monotonic() + WAIT
        while not self.check_starts() and time.monotonic() < end:
            time.sleep(0.02)
        return body

    def state(self, pid: str) -> str | None:
        row = self.routes._PROPOSALS.get(pid)
        return None if row is None else row["state"]


@pytest.fixture()
def w(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    yield world
    world.open_gate(0)  # let any check still waiting finish
    for job in list(world.jobs._JOBS.values()):
        job.done.wait(WAIT)
    world.jobs._reset_for_tests()
    with world.routes._LOCK:
        world.routes._PROPOSALS.clear()


def _running_shape(body: dict, pid: str, *, poll: bool) -> None:
    keys = {"status", "proposal_id", "step", "elapsed_s"} | ({"poll"} if poll else set())
    assert set(body) == keys, body
    assert body["status"] == "running" and body["proposal_id"] == pid
    assert body["step"] in {"Preparing the project", "Running the project's first check",
                            "Moving the project into place", "Registering the project"}
    assert isinstance(body["elapsed_s"], (int, float)) and body["elapsed_s"] >= 0
    if poll:
        assert body["poll"] == f"/scaffold/accept/{pid}"


def test_start_202_polls_then_done_with_todays_body(w):
    pid, dest = w.propose()
    first = w.post(pid)
    assert first.status_code == 202, first.text
    _running_shape(first.json(), pid, poll=True)
    _running_shape(w.in_check(pid), pid, poll=False)
    again = w.post(pid)  # a second POST while it runs: the same job, not a second one
    assert again.status_code == 202 and again.json()["proposal_id"] == pid
    w.open_gate(0)
    done = w.final(pid)
    assert set(done) == {"status", "proposal_id", "result"} and done["status"] == "done"
    result = done["result"]
    assert result["status"] == "created" and result["repos"][0]["path"] == str(dest)
    assert result["repos"][0]["check"] == "ok"
    assert w.check_starts() == 1
    assert (dest / ".git").is_dir() and w.state(pid) is None
    stored = w.post(pid)
    assert stored.status_code == 200 and stored.json() == result
    # The same body a POST that finishes within the wait answers.
    w.mp.setattr(w.jobs, "ACCEPT_INLINE_WAIT_S", WAIT)
    fast_pid, _ = w.propose("Fast")
    fast = w.post(fast_pid)
    assert fast.status_code == 200 and set(fast.json()) == set(result)


def test_failed_check_polls_failed_and_create_again_starts_a_new_job(w):
    pid, dest = w.propose()
    assert w.post(pid).status_code == 202
    w.in_check(pid)
    w.open_gate(1)
    failed = w.final(pid)
    assert set(failed) == {"status", "proposal_id", "http_status", "detail", "partial"}
    assert failed["status"] == "failed" and failed["http_status"] == 409 and failed["partial"] is False
    detail = failed["detail"]
    assert isinstance(detail, dict)
    assert set(detail) == {"error", "output", "keep_staging", "created_dirs", "accepted_repos"}
    assert detail["error"].startswith("Check command") and detail["created_dirs"] == []
    assert w.state(pid) == "ready" and not dest.exists()
    assert w.cancel(pid).json() == {"status": "idle", "proposal_id": pid}
    # Create again (the page allows it: not partial): a new job, which succeeds.
    w.gate.unlink()
    assert w.post(pid).status_code == 202
    w.in_check(pid)
    w.open_gate(0)
    assert w.final(pid)["status"] == "done" and dest.is_dir()
    assert w.check_starts() == 2


def test_failed_after_the_move_is_partial_and_never_replayed(w):
    pid, dest = w.propose()

    def locked(*_a, **_k):
        raise sqlite3.OperationalError("database is locked")

    w.mp.setattr(w.scaffolder, "record_project", locked)
    w.open_gate(0)
    first = w.post(pid)
    failed = w.final(pid)
    assert failed["status"] == "failed" and failed["http_status"] == 409 and failed["partial"] is True
    assert failed["detail"]["created_dirs"] == [str(dest)]
    assert w.state(pid) == "partial" and dest.is_dir()
    again = w.post(pid)  # the stored answer, the same as the first time
    assert again.status_code == 409 and again.json() == {"detail": failed["detail"]}
    if first.status_code != 202:
        assert first.json() == {"detail": failed["detail"]}
    assert w.cancel(pid).json() == {"status": "running", "proposal_id": pid, "cancel": "too_late"}
    assert w.check_starts() == 1


def test_cancel_during_the_check_stops_it_and_create_again_works(w):
    pid, dest = w.propose()
    staging = w.routes._PROPOSALS[pid]["proposal"].staging_dir
    assert w.post(pid).status_code == 202
    w.in_check(pid)
    resp = w.cancel(pid)
    assert resp.status_code == 200 and resp.json() == {"status": "cancelled", "proposal_id": pid}
    assert w.poll(pid).json() == {"status": "cancelled", "proposal_id": pid}
    assert w.state(pid) == "ready" and not dest.exists() and staging.is_dir()
    assert not w.gate.exists()  # the check was stopped, it did not finish by itself
    assert w.cancel(pid).json() == {"status": "cancelled", "proposal_id": pid}
    # Create again: a new job (a second check process), which finishes.
    assert w.post(pid).status_code == 202
    w.in_check(pid)
    assert w.check_starts() == 2
    w.open_gate(0)
    assert w.final(pid)["status"] == "done" and dest.is_dir()


def test_create_right_after_a_cancel_starts_a_new_job(w):
    """A cancel can answer 'cancelled' while the job is still unwinding; Create pressed at
    once must start a new job, not attach to the cancelled one."""
    pid, dest = w.propose()
    real_kill = w.scaffolder._kill_process_group

    def slow_unwind(proc):
        real_kill(proc)
        time.sleep(0.5)  # the job is still stopping when the cancel answers

    w.mp.setattr(w.scaffolder, "_kill_process_group", slow_unwind)
    w.mp.setattr(w.scaffolder, "_CHECK_POLL_S", 0.01)
    w.mp.setattr(w.jobs, "ACCEPT_CANCEL_WAIT_S", 0.1)
    assert w.post(pid).status_code == 202
    w.in_check(pid)
    assert w.cancel(pid).json() == {"status": "cancelled", "proposal_id": pid}
    assert w.jobs._JOBS[pid].finished is False  # still stopping
    w.mp.setattr(w.jobs, "ACCEPT_CANCEL_WAIT_S", 15.0)
    again = w.post(pid)
    assert again.status_code == 202, again.text
    w.in_check(pid)
    w.until(pid, lambda b: w.check_starts() == 2 or b["status"] != "running")
    assert w.check_starts() == 2
    w.open_gate(0)
    assert w.final(pid)["status"] == "done" and dest.is_dir()


def test_cancel_after_the_move_is_too_late_and_the_job_finishes(w):
    pid, dest = w.propose()
    gate, entered = threading.Event(), threading.Event()
    real = w.scaffolder._attempt_project_registration

    def slow_register(*a, **k):
        entered.set()
        gate.wait(WAIT)
        return real(*a, **k)

    w.mp.setattr(w.scaffolder, "_attempt_project_registration", slow_register)
    w.open_gate(0)
    assert w.post(pid).status_code == 202
    assert entered.wait(WAIT)
    assert w.poll(pid).json()["step"] == "Registering the project"
    assert w.cancel(pid).json() == {"status": "running", "proposal_id": pid, "cancel": "too_late"}
    gate.set()
    assert w.final(pid)["status"] == "done" and dest.is_dir()
    assert w.cancel(pid).json() == {"status": "running", "proposal_id": pid, "cancel": "too_late"}


def test_poll_after_the_answer_expired_is_404(w):
    pid, _ = w.propose()
    w.open_gate(0)
    assert w.post(pid).status_code in (200, 202)
    assert w.final(pid)["status"] == "done"
    w.mp.setattr(w.jobs, "ACCEPT_RESULT_TTL_S", 0.0)
    for resp in (w.poll(pid), w.post(pid), w.cancel(pid)):
        assert resp.status_code == 404 and resp.json() == UNKNOWN, resp.text


def test_a_fifth_create_while_four_run_is_429(w):
    running = [w.propose(f"Job {n}")[0] for n in range(4)]
    for pid in running:
        assert w.post(pid).status_code == 202
    fifth, _ = w.propose("Job five")
    resp = w.post(fifth)
    assert resp.status_code == 429 and resp.json() == {"detail": w.jobs.BUSY_DETAIL}
    assert w.state(fifth) == "ready"
    assert w.poll(fifth).status_code == 404  # no job was made for it
    w.open_gate(0)
    for pid in running:
        assert w.final(pid)["status"] == "done"
    assert w.post(fifth).status_code in (200, 202)
    assert w.final(fifth)["status"] == "done"


def test_unknown_and_other_home_are_404_everywhere(w, tmp_path, monkeypatch):
    pid, _ = w.propose()
    for resp in (w.poll("0" * 32), w.cancel("0" * 32), w.post("0" * 32)):
        assert resp.status_code == 404 and resp.json() == UNKNOWN
    assert w.post(pid).status_code == 202
    other = tmp_path / "other-home"
    other.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(other))
    for resp in (w.poll(pid), w.cancel(pid), w.post(pid)):
        assert resp.status_code == 404 and resp.json() == UNKNOWN
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
    w.open_gate(0)
    assert w.final(pid)["status"] == "done"


def test_answers_are_plain_json(w):
    """Every answer the page reads parses as JSON and carries no traceback."""
    pid, _ = w.propose()
    texts = [w.post(pid).text, w.poll(pid).text, w.cancel(pid).text]
    w.open_gate(0)
    texts.append(json.dumps(w.final(pid)))
    for text in texts:
        json.loads(text)
        assert "Traceback" not in text
