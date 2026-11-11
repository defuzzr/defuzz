"""The recorded kit fixture is consistent, matches the companion plugin, and its generator detects drift."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GEN = REPO_ROOT / "scripts" / "gen_kit_fixture.py"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "kit_contract"
ROUTER_FIELDS = ("id", "name", "summary", "tags", "version")
ENV_VAR = "DEFUZZ_COMPONENTIZE_SOURCE"


def _run_gen(*args: str, env_source: str | None = None) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != ENV_VAR}
    if env_source:
        env[ENV_VAR] = env_source
    return subprocess.run([sys.executable, "-B", str(GEN), *args], capture_output=True, text=True, env=env, timeout=300)


# (a) internal consistency
def test_fixture_internally_consistent():
    listing = json.loads((FIXTURE / "list.json").read_text(encoding="utf-8"))
    kits = listing["kits"]
    ids = [k["id"] for k in kits]
    assert len(kits) == 14
    assert len(set(ids)) == len(ids)
    for kit in kits:
        missing = [f for f in ROUTER_FIELDS if f not in kit]
        assert not missing, f"kit {kit.get('id')}: missing {missing}"
        assert isinstance(kit["tags"], list) and isinstance(kit["version"], int)
    shown = {p.stem for p in (FIXTURE / "shows").glob("*.json")}
    assert shown == set(ids)
    for kit in kits:
        show = json.loads((FIXTURE / "shows" / f"{kit['id']}.json").read_text(encoding="utf-8"))
        for f in ROUTER_FIELDS:
            assert show["kit"][f] == kit[f], f"kit {kit['id']}: list and show disagree on {f}"
        assert show["declared_dirs"] and "agents_block" in show
    contract = json.loads((FIXTURE / "show.json").read_text(encoding="utf-8"))
    assert contract == json.loads((FIXTURE / "shows" / f"{contract['kit']['id']}.json").read_text(encoding="utf-8"))


# (b) sync with the real companion plugin
def test_fixture_matches_companion():
    source = os.environ.get(ENV_VAR)
    if not source:
        pytest.skip(
            f"{ENV_VAR} not set; to check the kit fixture against the companion plugin run: "
            f"env {ENV_VAR}=<defuzz-componentize folder> pytest tests/test_kit_fixture_sync.py"
        )
    res = _run_gen("--check", env_source=source)
    assert res.returncode == 0, res.stdout + res.stderr


# (c) the generator detects drift against a tiny fake companion
_FAKE_KIT_COMMANDS = '''
import json
from pathlib import Path
KITS = Path(__file__).resolve().parent / "vendor" / "kits"

def _kits():
    return [json.loads(p.read_text()) for p in sorted(KITS.glob("*/kit.json"))]

def run(argv, *, cwd, home):
    cmd = argv[0]
    if cmd == "list":
        kits = [{f: k[f] for f in ("id", "name", "summary", "tags", "version")} for k in _kits()]
        env = {"schema": "componentize.kit/1", "ok": True, "status": "pass", "error": None, "findings": [], "kits": kits}
    elif cmd == "show":
        k = [k for k in _kits() if k["id"] == argv[1]][0]
        env = {"schema": "componentize.kit/1", "ok": True, "status": "pass", "error": None, "findings": [],
               "kit": {f: k[f] for f in ("id", "name", "summary", "tags", "version")},
               "declared_dirs": [{"dir": "src", "summary": "s", "why": "w"}], "placement_rules": [],
               "tree": ["AGENTS.md", "src/"], "agents_block": "<!-- kit -->", "cwd_seen": cwd}
    else:
        return {"exit": 2, "stdout": "", "stderr": "unsupported"}
    return {"exit": 0, "stdout": json.dumps(env, indent=2) + "\\n", "stderr": ""}
'''


def _fake_companion(root: Path, kits: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "plugin.yaml").write_text("name: defuzz-componentize\n", encoding="utf-8")
    (root / "__init__.py").write_text("", encoding="utf-8")
    (root / "kit_commands.py").write_text(textwrap.dedent(_FAKE_KIT_COMMANDS), encoding="utf-8")
    kroot = root / "vendor" / "kits"
    if kroot.exists():
        for p in kroot.glob("*/kit.json"):
            p.unlink()
    for kid, kit in kits.items():
        (kroot / kid).mkdir(parents=True, exist_ok=True)
        (kroot / kid / "kit.json").write_text(json.dumps({"id": kid, **kit}), encoding="utf-8")
    return root


def test_generator_detects_drift(tmp_path):
    base = {
        "alpha": {"name": "Alpha", "summary": "First kit.", "tags": ["a"], "version": 1},
        "beta": {"name": "Beta", "summary": "Second kit.", "tags": ["b"], "version": 1},
    }
    src = _fake_companion(tmp_path / "companion", base)
    out = tmp_path / "fixture"
    res = _run_gen("--source", str(src), "--out", str(out))
    assert res.returncode == 0, res.stderr
    assert sorted(p.name for p in (out / "shows").glob("*.json")) == ["alpha.json", "beta.json"]
    assert str(tmp_path) not in (out / "shows" / "alpha.json").read_text(encoding="utf-8")
    first = {p: p.read_bytes() for p in out.rglob("*.json")}
    assert _run_gen("--source", str(src), "--out", str(out), "--check").returncode == 0
    assert _run_gen("--source", str(src), "--out", str(out)).returncode == 0
    assert first == {p: p.read_bytes() for p in out.rglob("*.json")}, "generator is not deterministic"

    cases = {
        "kit alpha: summary changed": {**base, "alpha": {**base["alpha"], "summary": "Changed."}},
        "kit beta: tags changed": {**base, "beta": {**base["beta"], "tags": ["b", "new"]}},
        "kit gamma: added": {**base, "gamma": {"name": "G", "summary": "Third.", "tags": [], "version": 1}},
        "kit beta: removed": {"alpha": base["alpha"]},
    }
    for expected, kits in cases.items():
        _fake_companion(src, kits)
        res = _run_gen("--source", str(src), "--out", str(out), "--check")
        assert res.returncode == 1, (expected, res.stdout, res.stderr)
        assert expected in res.stdout, (expected, res.stdout)
    assert first == {p: p.read_bytes() for p in out.rglob("*.json")}, "--check wrote files"


def test_generator_errors(tmp_path):
    assert _run_gen("--source", str(tmp_path / "missing")).returncode == 2
    wrong = tmp_path / "wrong"
    wrong.mkdir()
    (wrong / "plugin.yaml").write_text("name: something-else\n", encoding="utf-8")
    (wrong / "kit_commands.py").write_text("", encoding="utf-8")
    res = _run_gen("--source", str(wrong))
    assert res.returncode == 2 and "not the defuzz-componentize plugin" in res.stderr
    assert _run_gen().returncode == 2
