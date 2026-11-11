"""Credential-shaped tokens in file or folder names must not reach a report.

Synthetic homes only. Token-shaped values are assembled at runtime so the
source file itself stays free of credential literals.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from tests.conftest import load_submodule
from tests.test_audit_wired_sections import _audit, _home

# Withheld-path count on the wired-sections fixture home before credential-shaped
# path names were withheld.
# A false positive that hides a previously readable path changes this.
_ORDINARY_HOME_WITHHELD = 2


def _sk(n: int = 8) -> str:
    return "sk-" + ("aB" + "12") * n


def _aws(prefix: str) -> str:
    return prefix[:2] + prefix[2:] + ("A1" * 8)


def _gh(kind: str, n: int = 18) -> str:
    return kind + "_" + ("Ab" * n)


def _pat() -> str:
    return "github" + "_pat_" + ("a1" * 12)


def _xox(kind: str) -> str:
    return "xox" + kind + "-" + ("1a" * 10)


def _jwt() -> str:
    return "eyJ" + ("aB" * 6) + "." + "eyJ" + ("cD" * 6) + "." + ("ab" + "CD" * 6)


def _tokens() -> list[str]:
    return [
        _sk(),
        "sk-ant-" + ("aB" + "12") * 6,
        "sk-proj-" + ("cD" + "34") * 6,
        _aws("AKIA"),
        _aws("ASIA"),
        _gh("ghp"),
        _gh("gho"),
        _gh("ghu"),
        _gh("ghs"),
        _gh("ghr"),
        _pat(),
        _xox("b"),
        _xox("a"),
        _xox("p"),
        _xox("r"),
        _xox("s"),
        _jwt(),
        "server_" + _sk(),
        "notes." + _aws("AKIA"),
        "prefix-" + _gh("ghp"),
    ]


_ORDINARY = (
    "sk-learn-notes",
    "sk-learn",
    "sklearn",
    "sk-learn-documentation-page",
    "token_counter.py",
    "ghp-pages",
    "ghp_pages",
    "gho_test",
    "github_pat",
    "github_path_to_notes",
    "task-runner",
    "server_config",
    "plugin.yaml",
    "config.yaml",
    "SOUL.md",
    "hookplug",
    "node_modules",
    "dist",
    "build-20261110",
    "cache_v2",
    "AKIA",
    "ASIA",
    "ASIAN-FOOD-MARKET",
    "xox-board",
    "xoxb-test",
    "eyJ",
    "eyJhbGciOiJIUzI1NiJ9",
    "token",
    "secret",
    "credentials",
    "id_rsa",
    "my-app-v1",
    "profiles",
    "plugins",
    "memories",
    "sha256",
    "ab" * 32,
    "550e8400-e29b-41d4-a716-446655440000",
    "build-" + "a1b2c3d4" * 6,
    "server",
    "api",
    "sk-ant",
    "notes",
    "README.md",
    "main.py",
    ".git",
    "state.db",
    "request_dump_0_20261001.json",
    "abc" + "sk-" + ("aB" + "12") * 8,  # glued to a letter: not a boundary
)


def _mod():
    return load_submodule("audit.secret_paths")


def test_ordinary_names_stay_readable() -> None:
    mod = _mod()
    assert len(_ORDINARY) >= 40
    kept = [name for name in _ORDINARY if not mod.credential_like_segment(name)]
    assert kept == list(_ORDINARY), [n for n in _ORDINARY if n not in kept]


def test_token_shapes_are_withheld() -> None:
    mod = _mod()
    tokens = _tokens()
    assert len(tokens) >= 15
    missed = [name for name in tokens if not mod.credential_like_segment(name)]
    assert missed == []
    # Below the provider minimum: not a recognizable token.
    assert not mod.credential_like_segment("sk-" + ("aB" + "12") * 3)  # 12 < 20
    assert not mod.credential_like_segment(_gh("ghp", n=10))  # 20 < 36
    assert not mod.credential_like_segment("AKIA" + "A1" * 7)  # 14 < 16


def test_recognizer_is_bounded_on_ten_thousand_paths() -> None:
    mod = _mod()
    paths = []
    for i in range(10_000):
        head = f"/d{'0' * 20}/n{i}/"
        paths.append(head + ("x" * (200 - len(head))))
    assert all(len(p) == 200 for p in paths)
    started = time.perf_counter()
    hits = sum(mod.path_has_credential_segment(p) for p in paths)
    elapsed = time.perf_counter() - started
    assert hits == 0
    assert elapsed < 1.0, elapsed


def _walk_strings(value, found: list[str]) -> None:
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.append(str(key))
            _walk_strings(item, found)
    elif isinstance(value, list):
        for item in value:
            _walk_strings(item, found)


def _withheld_paths(value) -> list[dict]:
    found = []
    if isinstance(value, dict):
        if value.get("path") is None and value.get("path_withheld"):
            found.append({"path_withheld": value.get("path_withheld")})
        for item in value.values():
            found.extend(_withheld_paths(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_withheld_paths(item))
    return found


def _db_text(db_path: Path) -> str:
    blob = db_path.read_bytes()
    conn = sqlite3.connect(db_path)
    try:
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        chunks = [blob.decode("utf-8", "replace")]
        for table in tables:
            info = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
            text_cols = [row[1] for row in info if "CHAR" in (row[2] or "").upper() or (row[2] or "").upper() in {"TEXT", "CLOB", ""}]
            # Every column: numeric casts are harmless, text columns are required.
            cols = [row[1] for row in info]
            if not cols:
                continue
            quoted = ", ".join(f'"{c}"' for c in cols)
            for row in conn.execute(f'SELECT {quoted} FROM "{table}"'):
                chunks.append("\n".join("" if cell is None else str(cell) for cell in row))
            assert text_cols or True
        return "\n".join(chunks)
    finally:
        conn.close()


def _assert_token_absent(token: str, report, reloaded, summary_text: str, db_path: Path) -> None:
    for label, blob in (
        ("report", json.dumps(report)),
        ("reload", json.dumps(reloaded)),
        ("summary", summary_text),
        ("db", _db_text(db_path)),
    ):
        assert token not in blob, label
        assert token.casefold() not in blob.casefold(), label


def _reload(tmp_path, run_id):
    surface = load_submodule("audit_surface")
    return surface.execute_audit(
        {"action": "report", "run_id": run_id},
        db_path=tmp_path / "audit-store" / "audit.db",
    )


def _summary_text(report, home: Path) -> str:
    summary = load_submodule("audit_summary")
    return summary.render_text(summary.summarize(report, str(home)))


def test_plugin_folder_token_is_withheld_end_to_end(tmp_path, monkeypatch) -> None:
    token = _sk()
    home = tmp_path / "home"
    plug = home / "plugins" / ("server_" + token)
    plug.mkdir(parents=True)
    (plug / "plugin.yaml").write_text("name: innocent\nversion: 1.0.0\n", encoding="utf-8")
    (home / "config.yaml").write_text("model: test\n", encoding="utf-8")
    result = _audit(tmp_path, monkeypatch, home)
    assert result.get("status") == "completed"
    report = result["report"]
    reloaded = _reload(tmp_path, result["run_id"])
    _assert_token_absent(token, report, reloaded, _summary_text(report, home), tmp_path / "audit-store" / "audit.db")
    findings = [
        f for f in report.get("findings", [])
        if isinstance(f, dict) and isinstance(f.get("id"), str) and f["id"].startswith("executable_inventory.plugin")
    ]
    assert findings, "plugin finding must still appear"
    withheld = _withheld_paths(findings)
    assert any(row["path_withheld"] == "credential_in_name" for row in withheld), [
        {k: f.get(k) for k in ("id", "source_paths", "affected_identities")} for f in findings
    ]
    assert "credential_in_name" == load_submodule("audit.secret_paths").CREDENTIAL_IN_NAME


def test_sibling_profile_token_is_withheld_end_to_end(tmp_path, monkeypatch) -> None:
    token = _sk()
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.yaml").write_text("model: test\n", encoding="utf-8")
    sibling = home / "profiles" / ("server_" + token)
    sibling.mkdir(parents=True)
    (sibling / "config.yaml").write_text('{"model": "test"}\n', encoding="utf-8")
    result = _audit(tmp_path, monkeypatch, home)
    assert result.get("status") == "completed"
    report = result["report"]
    reloaded = _reload(tmp_path, result["run_id"])
    _assert_token_absent(token, report, reloaded, _summary_text(report, home), tmp_path / "audit-store" / "audit.db")
    section = report.get("profile_duplicates") or {}
    profiles = section.get("profiles") if isinstance(section, dict) else None
    assert isinstance(profiles, list) and profiles, "sibling profile row must still appear"
    assert any(
        isinstance(row, dict) and row.get("path") is None and row.get("path_withheld") == "credential_in_name"
        for row in profiles
    ), profiles


def test_ordinary_wired_home_paths_stay_readable(tmp_path, monkeypatch) -> None:
    home, _project = _home(tmp_path)
    result = _audit(tmp_path, monkeypatch, home)
    assert result.get("status") == "completed"
    report = result["report"]
    withheld = _withheld_paths(report)
    reasons = [row["path_withheld"] for row in withheld]
    assert "credential_in_name" not in reasons
    assert len(withheld) == _ORDINARY_HOME_WITHHELD, (len(withheld), sorted(set(reasons)))


def test_path_gate_routes_withhold_and_register_taint(tmp_path) -> None:
    token = _sk()
    folder = tmp_path / ("server_" + token)
    folder.mkdir()
    target = folder / "plugin.yaml"
    target.write_text("name: innocent\n", encoding="utf-8")
    ev = load_submodule("audit.evidence")
    redaction = load_submodule("audit.redaction")
    state = redaction.Taint()
    handle = redaction._CURRENT.set(state)
    try:
        serializer = state.serializer
        sealed = serializer.serialize({
            "path": str(target),
            "affected_identities": [str(folder)],
            "source_paths": [{"path": str(target), "start_line": 1, "end_line": 1}],
            "files": {str(target): {"size": 1}},
        })
        blob = json.dumps(sealed)
        assert token not in blob
        assert sealed["path"] is None
        assert sealed["path_withheld"] == "credential_in_name"
        assert sealed["affected_identities"][0]["path_withheld"] == "credential_in_name"
        assert sealed["source_paths"][0]["path"] is None
        assert sealed["source_paths"][0]["path_withheld"] == "credential_in_name"
        assert all(not str(key).startswith(str(tmp_path)) for key in sealed["files"])
        assert token in state.values or any(token in item for item in state.values)
        leaf = serializer._seal(
            kind="text", hmac="ab" * 32,
            location={"path": str(target), "line": 1},
        )
        again = serializer.serialize(leaf)
        assert again["location"]["path"] is None
        assert token not in json.dumps(again)
        command = serializer.serialize(ev.Evidence(value=str(target) + " --flag", kind="command", path=str(target)))
        assert command["executable"] is None
        assert command["location"]["path"] is None
        assert token not in json.dumps(command)
    finally:
        redaction._CURRENT.reset(handle)
    # Without a run taint, the path is still withheld (the gate does not depend on prior taint).
    bare = ev.EvidenceSerializer().serialize({"path": str(target)})
    assert token not in json.dumps(bare)
    assert bare["path"] is None and bare["path_withheld"] == "credential_in_name"


# --- Wider provider shapes. Every sample is assembled from pieces at run time.

def _new_shape_tokens() -> dict[str, str]:
    return {
        "huggingface": "hf" + "_" + ("Ab1" * 12)[:34],
        "google": "AI" + "za" + ("Sy" + "b1_-" * 9)[:35],
        "stripe_sk_live": "sk" + "_live_" + ("a1B2" * 6),
        "stripe_sk_test": "sk" + "_test_" + ("a1B2" * 6),
        "stripe_rk_live": "rk" + "_live_" + ("a1B2" * 6),
        "stripe_rk_test": "rk" + "_test_" + ("a1B2" * 6),
        "stripe_pk_live": "pk" + "_live_" + ("a1B2" * 6),
        "anthropic": "sk-" + "ant-" + "api0" + "3-" + ("aB1_" * 24)[:93],
        "gitlab": "gl" + "pat-" + ("aB1-" * 5),
        "npm": "np" + "m_" + ("aB1" * 12),
        "pypi": "py" + "pi-" + ("AgEI" + "cHlw_-") * 9,
        "telegram": "1234" + "56789" + ":" + ("AAb1_-" * 6)[:35],
    }


_NEW_NEAR_MISSES = {
    "huggingface": ("hf_hub_download.py", "hf_cache", "hf_" + "a" * 29, "hf_" + "A1" * 31,
                    "xhf_" + "Ab1" * 12, "hf-" + "Ab1" * 12),
    "google": ("AIzaExample.md", "AIza", "AIza" + "b1" * 17, "AIza" + "b1" * 18,
               "xAIza" + ("b1" * 18)[:35], "aiza" + ("b1" * 18)[:35]),
    "stripe": ("sk_live_demo", "sk_test_runner.py", "pk_live_" + "a1" * 7, "rk_test_" + "a" * 3,
               "sk_live_" + "a1" * 65, "pk_test_" + "a1" * 10, "xsk_live_" + "a1" * 10),
    "anthropic": ("sk-ant", "sk-ant-notes", "sk-ant-api-docs", "sk-ant-" + "ab" * 10, "sk-anthology"),
    "gitlab": ("glpat-notes", "glpat-", "glpat-" + "a" * 19, "glpat_" + "a1" * 12, "xglpat-" + "a1" * 12,
               "glpat-" + "a1" * 33),
    "npm": ("npm_package.json", "npm_modules", "npm_" + "a1" * 17, "npm_" + "a1" * 19,
            "xnpm_" + "a1" * 18, "npm-" + "a1" * 18),
    "pypi": ("pypi-publish.yml", "pypi-release-notes", "pypi-" + "a1" * 24, "xpypi-" + "a1" * 30,
             "pypi_" + "a1" * 30, "pypi-" + "a1" * 126),
    "telegram": ("12345678:notes", "1234567:" + "A1" * 18, "123456789:" + "A1" * 17,
                 "x123456789:" + ("A1" * 18)[:35], "12345678901:" + ("A1" * 18)[:35],
                 "2026-11-10T12:00:00"),
}


def test_new_shapes_are_recognized() -> None:
    mod = _mod()
    missed = [k for k, v in _new_shape_tokens().items() if not mod.credential_like_segment("dir_" + v)]
    assert missed == []


def test_new_shape_near_misses_stay_readable() -> None:
    mod = _mod()
    for kind, names in _NEW_NEAR_MISSES.items():
        assert len(names) >= 5, kind
        hit = [n for n in names if mod.credential_like_segment(n)]
        assert hit == [], (kind, hit)


import pytest  # noqa: E402


@pytest.mark.parametrize("kind", sorted(_new_shape_tokens()))
def test_new_shape_plugin_folder_is_withheld_end_to_end(kind, tmp_path, monkeypatch) -> None:
    # Plugin folders, not sibling profiles: profile names over 64 characters
    # or with ``:`` never become profile rows at all.
    token = _new_shape_tokens()[kind]
    home = tmp_path / "home"
    plug = home / "plugins" / ("server_" + token)
    plug.mkdir(parents=True)
    (plug / "plugin.yaml").write_text("name: innocent\nversion: 1.0.0\n", encoding="utf-8")
    (home / "config.yaml").write_text("model: test\n", encoding="utf-8")
    result = _audit(tmp_path, monkeypatch, home)
    assert result.get("status") == "completed"
    report = result["report"]
    reloaded = _reload(tmp_path, result["run_id"])
    _assert_token_absent(token, report, reloaded, _summary_text(report, home), tmp_path / "audit-store" / "audit.db")
    findings = [
        f for f in report.get("findings", [])
        if isinstance(f, dict) and isinstance(f.get("id"), str) and f["id"].startswith("executable_inventory.plugin")
    ]
    assert findings, "plugin finding must still appear"
    assert any(row["path_withheld"] == "credential_in_name" for row in _withheld_paths(findings))
