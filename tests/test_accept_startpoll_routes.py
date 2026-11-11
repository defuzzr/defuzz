"""Start-and-poll project creation through the real routes (POST/GET /scaffold/accept, POST /scaffold/cancel)."""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import load_submodule
from tests.fake_kit_bridge import FakeKitBridge

WAIT = 5.0


@pytest.fixture()
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    bridge_mod = load_submodule("componentize_bridge")
    fake = FakeKitBridge()
    fake.install(monkeypatch, bridge_mod)
    api = load_submodule("dashboard.plugin_api")
    routes = api._load("dashboard.routes.workspace_routes")
    jobs = api._load("dashboard.routes.accept_jobs")
    fake.install(monkeypatch, routes.componentize_bridge)
    routes._reset_kit_cache_for_tests()
    jobs._reset_for_tests()
    with routes._LOCK:
        routes._PROPOSALS.clear()
    app = FastAPI()
    app.include_router(api.router)
    projects = tmp_path / "projects"
    projects.mkdir()
    yield TestClient(app), routes, jobs, projects, monkeypatch
    jobs._reset_for_tests()
    with routes._LOCK:
        routes._PROPOSALS.clear()


def _propose(client, projects, name):
    resp = client.post("/scaffold/propose", json={"kit_id": "video-production", "name": name,
                                                  "answers": {"building": "video"}, "dest_root": str(projects)})
    assert resp.status_code == 200, resp.text
    return resp.json()["proposal_id"]


def _gate_kit_accept(routes, monkeypatch):
    """Hold the real kit accept until released; the real accept still does all the work."""
    real = routes.kit_scaffold.accept_kit
    entered, gate = threading.Event(), threading.Event()

    def slow_accept(proposal, **kwargs):
        entered.set()
        gate.wait(WAIT)
        return real(proposal, **kwargs)

    monkeypatch.setattr(routes.kit_scaffold, "accept_kit", slow_accept)
    return entered, gate


def _wait_finished(client, pid):
    for _ in range(500):
        body = client.get(f"/scaffold/accept/{pid}").json()
        if body["status"] != "running":
            return body
        threading.Event().wait(0.01)
    raise AssertionError("job did not finish")


def test_old_client_that_only_posts_gets_todays_answer(env):
    client, routes, jobs, projects, _ = env
    pid = _propose(client, projects, "Quick Shoot")
    resp = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "created" and body["placement"] == "on"
    assert (projects / "quick-shoot" / ".git").is_dir()
    assert pid not in routes._PROPOSALS
    # Posting again gets the same stored answer.
    again = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    assert again.status_code == 200 and again.json() == body
    assert client.get(f"/scaffold/accept/{pid}").json() == {"status": "done", "proposal_id": pid, "result": body}


def test_slow_accept_goes_202_then_running_then_done_with_the_same_final_body(env):
    client, routes, jobs, projects, monkeypatch = env
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", 0.05)
    entered, gate = _gate_kit_accept(routes, monkeypatch)
    pid = _propose(client, projects, "Slow Shoot")
    first = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    assert first.status_code == 202, first.text
    started = first.json()
    assert started["status"] == "running" and started["proposal_id"] == pid
    assert started["poll"] == f"/scaffold/accept/{pid}"
    assert started["step"] in jobs.PHASE_STEPS.values()
    assert entered.wait(WAIT)
    again = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    assert again.status_code == 202 and again.json()["status"] == "running"
    poll = client.get(f"/scaffold/accept/{pid}")
    assert poll.status_code == 200 and poll.json()["status"] == "running"
    assert routes._PROPOSALS[pid]["state"] == "accepting"
    # A discard while it runs keeps today's refusal.
    assert client.post("/scaffold/discard", json={"proposal_id": pid}).status_code == 409
    gate.set()
    done = _wait_finished(client, pid)
    assert done["status"] == "done"
    final = done["result"]
    assert final["status"] == "created" and final["placement"] == "on"
    assert final["dest"] == str(projects / "slow-shoot")
    stored = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    assert stored.status_code == 200 and stored.json() == final
    # Same body shape as a fast accept.
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", WAIT)
    fast_pid = _propose(client, projects, "Fast Shoot")
    fast = client.post("/scaffold/accept", json={"proposal_id": fast_pid, "confirm": True}).json()
    assert set(fast) == set(final)


def test_cancel_before_the_move_creates_nothing_and_the_proposal_is_ready_again(env):
    client, routes, jobs, projects, monkeypatch = env
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", 0.05)
    entered, gate = _gate_kit_accept(routes, monkeypatch)
    pid = _propose(client, projects, "Stop Shoot")
    staging = routes._PROPOSALS[pid]["proposal"].staging_dir
    assert client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True}).status_code == 202
    assert entered.wait(WAIT)
    # The real accept sees the cancel at its first step once it is let go.
    threading.Timer(0.1, gate.set).start()
    resp = client.post("/scaffold/cancel", json={"proposal_id": pid})
    assert resp.status_code == 200 and resp.json() == {"status": "cancelled", "proposal_id": pid}
    assert client.get(f"/scaffold/accept/{pid}").json() == {"status": "cancelled", "proposal_id": pid}
    assert routes._PROPOSALS[pid]["state"] == "ready"
    assert staging.is_dir()
    assert not (projects / "stop-shoot").exists()
    assert client.post("/scaffold/cancel", json={"proposal_id": pid}).json() == {"status": "cancelled", "proposal_id": pid}
    # Accept again: a new job, which creates the project.
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", WAIT)
    again = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    assert again.status_code == 200, again.text
    assert (projects / "stop-shoot").is_dir()


def test_cancel_idle_unknown_and_too_late(env):
    client, routes, jobs, projects, monkeypatch = env
    pid = _propose(client, projects, "Idle Shoot")
    assert client.post("/scaffold/cancel", json={"proposal_id": pid}).json() == {"status": "idle", "proposal_id": pid}
    unknown = client.post("/scaffold/cancel", json={"proposal_id": "0" * 32})
    assert unknown.status_code == 404 and unknown.json() == {"detail": "Unknown or consumed proposal_id"}
    missing = client.get("/scaffold/accept/" + "0" * 32)
    assert missing.status_code == 404 and missing.json() == {"detail": "Unknown or consumed proposal_id"}
    assert client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True}).status_code == 200
    late = client.post("/scaffold/cancel", json={"proposal_id": pid})
    assert late.json() == {"status": "running", "proposal_id": pid, "cancel": "too_late"}
    assert (projects / "idle-shoot").is_dir()


class _FakeTemplateProposal:
    """Just enough of a template proposal for the route's before/after folder check."""
    repos: list = []


def test_template_accept_gets_the_token_and_reports_phases(env):
    client, routes, jobs, projects, monkeypatch = env
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", 0.05)
    seen, gate, in_check = {}, threading.Event(), threading.Event()

    def fake_accept(proposal, *, db_path=None, remember_options=True, cancel=None, progress=None):
        seen["cancel"] = cancel
        progress("check")
        in_check.set()
        gate.wait(WAIT)
        progress("move")
        progress("register")
        return routes.scaffolder.AcceptResult(repos=[{"path": "/x"}], answers_id=3, options={})

    row = routes._new_row("template")
    row.update(state="ready", proposal=_FakeTemplateProposal(), remember_options=True)
    with routes._LOCK:
        routes._PROPOSALS["t1"] = row
    monkeypatch.setattr(routes.scaffolder, "accept", fake_accept)
    assert client.post("/scaffold/accept", json={"proposal_id": "t1", "confirm": True}).status_code == 202
    assert in_check.wait(WAIT)
    assert client.get("/scaffold/accept/t1").json()["step"] == jobs.STEP_CHECK
    gate.set()
    done = _wait_finished(client, "t1")
    assert done == {"status": "done", "proposal_id": "t1",
                    "result": {"status": "created", "repos": [{"path": "/x"}], "answers_id": 3, "options": {}}}
    assert seen["cancel"] is not None


def test_failed_accept_polls_as_failed_and_allows_accept_again(env):
    client, routes, jobs, projects, monkeypatch = env
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", 0.05)
    gate = threading.Event()

    def failing(proposal, **kwargs):
        gate.wait(WAIT)
        raise routes.scaffolder.ScaffoldError("Check command failed with exit code 1 in app", output="boom")

    monkeypatch.setattr(routes.kit_scaffold, "accept_kit", failing)
    pid = _propose(client, projects, "Fail Shoot")
    assert client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True}).status_code == 202
    gate.set()
    failed = _wait_finished(client, pid)
    assert failed["status"] == "failed" and failed["http_status"] == 409 and failed["partial"] is False
    assert failed["detail"]["error"].startswith("Check command failed") and failed["detail"]["output"] == "boom"
    assert routes._PROPOSALS[pid]["state"] == "ready"
    # Expiry never removes it while the failed answer is kept.
    monkeypatch.setattr(routes, "_PROPOSAL_TTL_S", 0.0)
    with routes._LOCK:
        assert routes._take_expired_locked() == []
    monkeypatch.setattr(routes, "_PROPOSAL_TTL_S", 30 * 60.0)
    # A discard after the failure works and forgets the job.
    assert client.post("/scaffold/discard", json={"proposal_id": pid}).status_code == 200
    assert client.get(f"/scaffold/accept/{pid}").status_code == 404


def test_another_hermes_home_gets_404_everywhere(env, tmp_path):
    client, routes, jobs, projects, monkeypatch = env
    monkeypatch.setattr(jobs, "ACCEPT_INLINE_WAIT_S", 0.05)
    entered, gate = _gate_kit_accept(routes, monkeypatch)
    pid = _propose(client, projects, "Home Shoot")
    assert client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True}).status_code == 202
    home_a = os.environ["HERMES_HOME"]
    other = tmp_path / "other-home"
    other.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(other))
    for resp in (client.get(f"/scaffold/accept/{pid}"),
                 client.post("/scaffold/cancel", json={"proposal_id": pid}),
                 client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})):
        assert resp.status_code == 404 and resp.json() == {"detail": "Unknown or consumed proposal_id"}
    monkeypatch.setenv("HERMES_HOME", home_a)
    gate.set()
    assert _wait_finished(client, pid)["status"] == "done"


# --- an interrupt inside the accept never leaves the proposal 'accepting' -----------------


@pytest.mark.parametrize("after_move", [False, True])
def test_interrupt_inside_kit_accept_records_ready_or_partial(env, after_move):
    client, routes, jobs, projects, monkeypatch = env
    pid = _propose(client, projects, "Cut Shoot")
    dest = projects / "cut-shoot"
    if after_move:
        def interrupted(*_a, **_k):
            raise KeyboardInterrupt
        monkeypatch.setattr(routes.kit_scaffold, "record_project", interrupted)
    else:
        real = routes.kit_scaffold.accept_kit

        def interrupted_early(proposal, **kwargs):
            raise KeyboardInterrupt
        monkeypatch.setattr(routes.kit_scaffold, "accept_kit", interrupted_early)
    resp = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
    assert resp.status_code == 500 and resp.json() == {"detail": jobs.CRASH_DETAIL}, resp.text
    poll = client.get(f"/scaffold/accept/{pid}").json()
    assert poll == {"status": "failed", "proposal_id": pid, "http_status": 500,
                    "detail": jobs.CRASH_DETAIL, "partial": after_move}
    assert routes._PROPOSALS[pid]["state"] == ("partial" if after_move else "ready")
    assert dest.is_dir() is after_move
    if not after_move:
        # Nothing was created: the proposal can be accepted again, and this time it works.
        monkeypatch.setattr(routes.kit_scaffold, "accept_kit", real)
        again = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
        assert again.status_code == 200, again.text
        assert dest.is_dir()
    else:
        again = client.post("/scaffold/accept", json={"proposal_id": pid, "confirm": True})
        assert again.status_code == 500  # the stored answer, never a second job
