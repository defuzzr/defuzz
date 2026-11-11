"""Regression tests ensuring TOOLS.lock file probes and advisories never open or echo credentials."""

from __future__ import annotations

import builtins
import contextlib
import io
import json
import os
from pathlib import Path
from typing import Any

import pytest

from tests import ensure_test_package

ensure_test_package()

import hermes_constants  # noqa: E402
from hermes_plugins.defuzz import toolchk  # noqa: E402


@contextlib.contextmanager
def _record_opens(monkeypatch: pytest.MonkeyPatch):
    """Record every path passed to os.open, builtins.open, io.open, and Path.open."""
    opened: list[str] = []
    real_os_open = os.open
    real_builtins_open = builtins.open
    real_io_open = io.open
    real_path_open = Path.open

    def _rec(p: Any) -> None:
        if isinstance(p, (str, bytes, os.PathLike)):
            opened.append(os.fsdecode(os.fspath(p)))

    def wrapped_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        _rec(path)
        return real_os_open(path, flags, *args, **kwargs)

    def wrapped_builtins_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        _rec(file)
        return real_builtins_open(file, *args, **kwargs)

    def wrapped_io_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        _rec(file)
        return real_io_open(file, *args, **kwargs)

    def wrapped_path_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        _rec(self)
        return real_path_open(self, *args, **kwargs)

    monkeypatch.setattr(os, "open", wrapped_os_open)
    monkeypatch.setattr(builtins, "open", wrapped_builtins_open)
    monkeypatch.setattr(io, "open", wrapped_io_open)
    monkeypatch.setattr(Path, "open", wrapped_path_open)
    yield opened


def _setup_fake_homes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    fake_home = tmp_path / "home"
    hermes_home = fake_home / ".hermes"
    proj = tmp_path / "workspace"
    hermes_home.mkdir(parents=True)
    proj.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr(hermes_constants, "get_hermes_home", lambda: hermes_home)
    return fake_home, hermes_home, proj


def _assert_never_opened(opened: list[str], forbidden_paths: list[Path], lock_path: Path) -> None:
    lock_abs = os.path.abspath(lock_path)
    lock_real = os.path.realpath(lock_path)
    forbidden_abs = {os.path.abspath(p) for p in forbidden_paths}
    forbidden_real = {os.path.realpath(p) for p in forbidden_paths}
    for raw in opened:
        abs_p = os.path.abspath(raw)
        real_p = os.path.realpath(raw)
        if abs_p == lock_abs or real_p == lock_real:
            continue
        assert abs_p not in forbidden_abs, f"Forbidden path was opened (abspath): {raw}"
        assert real_p not in forbidden_real, f"Forbidden path was opened (realpath): {raw}"


def _assert_canary_absent(canary: str, obj: Any) -> None:
    serialized = json.dumps(obj, default=str)
    assert canary not in serialized, f"Canary leaked in output: {serialized}"


def test_shared_guard_refuses_secret_file_probes_without_opening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home, hermes_home, proj = _setup_fake_homes(tmp_path, monkeypatch)
    assert hasattr(toolchk, "_refuse_secret_path"), "Expected shared _refuse_secret_path guard"

    canary = "1.2.3"
    auth_json = hermes_home / "auth.json"
    auth_json.write_text(json.dumps({"version": canary, "token": "CANARY_AUTH_9911"}), encoding="utf-8")

    outside_file = tmp_path / "outside_ver.txt"
    outside_file.write_text(f"{canary}\n", encoding="utf-8")

    abs_target = tmp_path / "abs_target.json"
    abs_target.write_text(json.dumps({"version": canary}), encoding="utf-8")

    secret_targets: list[tuple[str, dict[str, Any], Path]] = []
    for rel_name in (
        ".env",
        ".env.local",
        "secrets.json",
        "id_ed25519",
        "auth.json",
        "service-auth.json",
        "oauth_client.json",
        "credentials.txt",
        "api_token.json",
        "db_password.txt",
        "cert.pem",
        "private.key",
        "bundle.p12",
        "cert.pfx",
        ".netrc",
        ".pgpass",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
        "audit.key",
        "vault/package.json",
        "mcp-tokens/package.json",
        "pairing/package.json",
        "platforms/package.json",
        ".ssh/package.json",
        ".aws/package.json",
        ".gnupg/package.json",
        ".config/gh/package.json",
    ):
        target = proj / rel_name
        target.parent.mkdir(parents=True, exist_ok=True)
        if rel_name.endswith(".json"):
            target.write_text(json.dumps({"version": canary, "secret": "CANARY_FILE_8822"}), encoding="utf-8")
            entry = {"probe": "file", "file": rel_name, "key": "version"}
        else:
            target.write_text(f"VERSION={canary}\nSECRET=CANARY_FILE_8822\n", encoding="utf-8")
            entry = {"probe": "file", "file": rel_name, "regex": r"(\d+\.\d+\.\d+)"}
        secret_targets.append((rel_name, entry, target))

    # Symlink named like a legitimate manifest pointing at $HERMES_HOME/auth.json
    sym_manifest = proj / "package.json"
    sym_manifest.symlink_to(auth_json)
    secret_targets.append(
        ("symlink_auth", {"probe": "file", "file": "package.json", "key": "version"}, sym_manifest)
    )
    secret_targets.append(
        ("outside_rel", {"probe": "file", "file": "../outside_ver.txt", "regex": r"(\d+\.\d+\.\d+)"}, outside_file)
    )
    secret_targets.append(
        ("abs_path", {"probe": "file", "file": str(abs_target), "key": "version"}, abs_target)
    )

    tools_dict: dict[str, dict[str, Any]] = {}
    forbidden_paths: list[Path] = [auth_json, outside_file, abs_target]
    for idx, (_label, spec, p) in enumerate(secret_targets):
        tname = f"t{idx}"
        tools_dict[tname] = {
            "version": "9.9.9",
            "chosen": "2026-11-06",
            "reason": "test",
            "source": "human",
            **spec,
        }
        forbidden_paths.append(p)

    lock_file = proj / "TOOLS.lock"
    toolchk.dump_lock(lock_file, {"lock": dict(toolchk.DEFAULT_HEADER), "tools": tools_dict})

    with _record_opens(monkeypatch) as opened:
        for tname, entry in tools_dict.items():
            with pytest.raises(ValueError) as exc_info:
                toolchk.probe(tname, entry, proj)
            _assert_canary_absent("CANARY_FILE_8822", str(exc_info.value))
            _assert_canary_absent("CANARY_AUTH_9911", str(exc_info.value))

        report = toolchk.check(list(tools_dict.keys()), None, proj)

    _assert_never_opened(opened, forbidden_paths, lock_file)
    assert report["ok"] is False
    for tname in tools_dict:
        assert report["tools"][tname]["status"] == "probe-failed"
        assert "installed" not in report["tools"][tname]
    _assert_canary_absent("CANARY_FILE_8822", report)
    _assert_canary_absent("CANARY_AUTH_9911", report)
    _assert_canary_absent(canary, report)


def test_shared_guard_refuses_secret_advisory_paths_without_opening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_home, hermes_home, proj = _setup_fake_homes(tmp_path, monkeypatch)

    canary_ver = "9.8.7"
    auth_file = hermes_home / "auth.json"
    auth_file.write_text(json.dumps({"latest_version": canary_ver, "tok": "CANARY_ADV_7733"}), encoding="utf-8")
    cfg_file = hermes_home / "config.yaml"
    cfg_file.write_text(json.dumps({"latest_version": canary_ver, "api_key": "CANARY_CFG_6644"}), encoding="utf-8")
    mcp_tok = hermes_home / "mcp-tokens" / "x.json"
    mcp_tok.parent.mkdir(parents=True)
    mcp_tok.write_text(json.dumps({"latest_version": canary_ver, "tok": "CANARY_MCP_5511"}), encoding="utf-8")

    tools_dict = {}
    for idx, adv_path in enumerate((str(auth_file), str(cfg_file), str(mcp_tok))):
        tools_dict[f"adv{idx}"] = {
            "version": "1.0.0",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "interpreter",
            "source": "human",
            "advisory": {"kind": "json", "path": adv_path, "key": "latest_version"},
        }

    lock_file = proj / "TOOLS.lock"
    toolchk.dump_lock(lock_file, {"lock": dict(toolchk.DEFAULT_HEADER), "tools": tools_dict})

    monkeypatch.setattr(toolchk, "probe", lambda *a, **k: ("1.0.0", "/usr/bin/python3"))
    with _record_opens(monkeypatch) as opened:
        report = toolchk.check(list(tools_dict.keys()), None, proj)

    _assert_never_opened(opened, [auth_file, cfg_file, mcp_tok], lock_file)
    for tname in tools_dict:
        row = report["tools"][tname]
        assert "upstream_latest" not in row
        assert "secret_path_refused" in row.get("advisory_error", "")
    for secret_str in (canary_ver, "CANARY_ADV_7733", "CANARY_CFG_6644", "CANARY_MCP_5511"):
        _assert_canary_absent(secret_str, report)


def test_probe_file_allowlist_and_1mib_cap_never_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_home, _hermes_home, proj = _setup_fake_homes(tmp_path, monkeypatch)
    assert hasattr(toolchk, "ALLOWED_PROBE_FILES"), "Expected named ALLOWED_PROBE_FILES constant"
    assert toolchk.MAX_FILE_PROBE_BYTES == 64 * 1024

    unlisted_json = proj / "random.json"
    unlisted_json.write_text(json.dumps({"version": "1.2.3", "secret": "CANARY_UNLISTED_4411"}), encoding="utf-8")
    unlisted_txt = proj / "notes.txt"
    unlisted_txt.write_text("1.2.3 CANARY_UNLISTED_4411\n", encoding="utf-8")

    # 1 MiB allowlisted filename (package.json) -> must be refused BEFORE os.open
    huge_proj = tmp_path / "huge_workspace"
    huge_proj.mkdir()
    huge_pkg = huge_proj / "package.json"
    huge_payload = '{"version": "1.2.3", "canary": "CANARY_1MIB_3322", "pad": "' + ("x" * (1024 * 1024)) + '"}\n'
    huge_pkg.write_text(huge_payload, encoding="utf-8")
    assert huge_pkg.stat().st_size > 1024 * 1024

    # Symlink directory leading outside project root
    outside_dir = tmp_path / "outside_pkg_dir"
    outside_dir.mkdir()
    outside_pkg = outside_dir / "package.json"
    outside_pkg.write_text('{"version": "1.2.3", "canary": "CANARY_SYMDIR_2211"}\n', encoding="utf-8")
    (proj / "linked_sub").symlink_to(outside_dir)

    tools_proj = {
        "u_json": {
            "version": "1.2.3",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "file",
            "file": "random.json",
            "key": "version",
            "source": "human",
        },
        "u_txt": {
            "version": "1.2.3",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "file",
            "file": "notes.txt",
            "regex": r"(\d+\.\d+\.\d+)",
            "source": "human",
        },
        "sym_dir": {
            "version": "1.2.3",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "file",
            "file": "linked_sub/package.json",
            "key": "version",
            "source": "human",
        },
    }
    lock_proj = proj / "TOOLS.lock"
    toolchk.dump_lock(lock_proj, {"lock": dict(toolchk.DEFAULT_HEADER), "tools": tools_proj})

    tools_huge = {
        "huge_pkg": {
            "version": "1.2.3",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "file",
            "file": "package.json",
            "key": "version",
            "source": "human",
        }
    }
    lock_huge = huge_proj / "TOOLS.lock"
    toolchk.dump_lock(lock_huge, {"lock": dict(toolchk.DEFAULT_HEADER), "tools": tools_huge})

    with _record_opens(monkeypatch) as opened:
        with pytest.raises(ValueError, match="probe_file_not_allowed"):
            toolchk.probe("u_json", tools_proj["u_json"], proj)
        with pytest.raises(ValueError, match="probe_file_not_allowed"):
            toolchk.probe("u_txt", tools_proj["u_txt"], proj)
        with pytest.raises(ValueError) as exc_huge:
            toolchk.probe("huge_pkg", tools_huge["huge_pkg"], huge_proj)
        _assert_canary_absent("CANARY_1MIB_3322", str(exc_huge.value))

        rep1 = toolchk.check(list(tools_proj.keys()), None, proj)
        rep2 = toolchk.check(["huge_pkg"], None, huge_proj)

    _assert_never_opened(opened, [unlisted_json, unlisted_txt, outside_pkg], lock_proj)
    _assert_never_opened(opened, [huge_pkg], lock_huge)
    assert rep1["tools"]["u_json"]["status"] == "probe-failed"
    assert "probe_file_not_allowed" in rep1["tools"]["u_json"]["error"]
    assert rep1["tools"]["u_txt"]["status"] == "probe-failed"
    assert "probe_file_not_allowed" in rep1["tools"]["u_txt"]["error"]
    assert rep1["tools"]["sym_dir"]["status"] == "probe-failed"
    assert rep2["tools"]["huge_pkg"]["status"] == "probe-failed"
    for canary in ("CANARY_UNLISTED_4411", "CANARY_1MIB_3322", "CANARY_SYMDIR_2211"):
        _assert_canary_absent(canary, rep1)
        _assert_canary_absent(canary, rep2)


def test_legitimate_manifest_file_probes_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_home, _hermes_home, proj = _setup_fake_homes(tmp_path, monkeypatch)

    (proj / "package.json").write_text('{"name": "demo", "version": "1.2.3"}\n', encoding="utf-8")
    (proj / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.4.2"\n', encoding="utf-8")
    (proj / ".tool-versions").write_text("nodejs 22.11.0\n", encoding="utf-8")
    (proj / ".nvmrc").write_text("v20.18.0\n", encoding="utf-8")
    (proj / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.82.0"\n', encoding="utf-8")
    (proj / "go.mod").write_text("module example.com/demo\n\ngo 1.23.2\n", encoding="utf-8")
    (proj / "global.json").write_text('{"sdk": {"version": "8.0.403"}}\n', encoding="utf-8")
    (proj / "VERSION").write_text("2.5.1\n", encoding="utf-8")
    (proj / "Game").mkdir()
    (proj / "Game" / "GreyboxTD.uproject").write_text('{"EngineAssociation": "5.6.1"}\n', encoding="utf-8")

    cases = [
        ("pkg", {"probe": "file", "file": "package.json", "key": "version"}, "1.2.3"),
        ("pyproj", {"probe": "file", "file": "pyproject.toml", "key": "project.version"}, "0.4.2"),
        ("tv", {"probe": "file", "file": ".tool-versions", "regex": r"^nodejs\s+(\d+\.\d+\.\d+)"}, "22.11.0"),
        ("nvm", {"probe": "file", "file": ".nvmrc", "regex": r"^v?(\d+\.\d+\.\d+)"}, "20.18.0"),
        ("rust", {"probe": "file", "file": "rust-toolchain.toml", "key": "toolchain.channel"}, "1.82.0"),
        ("gomod", {"probe": "file", "file": "go.mod", "regex": r"^go\s+(\d+\.\d+\.\d+)"}, "1.23.2"),
        ("dotnet", {"probe": "file", "file": "global.json", "key": "sdk.version"}, "8.0.403"),
        ("ver", {"probe": "file", "file": "VERSION", "regex": r"^(\d+\.\d+\.\d+)"}, "2.5.1"),
        ("ue", {"probe": "file", "file": "Game/GreyboxTD.uproject", "key": "EngineAssociation"}, "5.6.1"),
    ]
    for name, entry, expected in cases:
        got, _where = toolchk.probe(name, entry, proj)
        assert got == expected, f"{name}: {got!r} != {expected!r}"


def test_advisory_json_fixed_allowlist_and_hermes_home_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home, hermes_home, proj = _setup_fake_homes(tmp_path, monkeypatch)
    assert hasattr(toolchk, "ALLOWED_ADVISORY_JSON_FILES")
    assert not hasattr(toolchk, "_allowed_advisory_abs_roots")

    hermes_any = hermes_home / "anything.json"
    hermes_any.write_text('{"latest_version": "9.1.1", "canary": "CANARY_HERMES_ANY_1199"}\n', encoding="utf-8")
    hermes_dev = fake_home / ".hermes-dev"
    hermes_dev.mkdir()
    dev_any = hermes_dev / "anything.json"
    dev_any.write_text('{"latest_version": "9.1.2", "canary": "CANARY_DEV_ANY_2288"}\n', encoding="utf-8")
    cua_dir = fake_home / ".cua-driver"
    cua_dir.mkdir()
    cua_other = cua_dir / "other.json"
    cua_other.write_text('{"latest_version": "9.1.3", "canary": "CANARY_CUA_OTHER_3377"}\n', encoding="utf-8")

    # Legitimate fixed advisory file + legitimate project-local advisory file
    cua_fixed = cua_dir / "version_check.json"
    cua_fixed.write_text('{"latest_version": "0.38.0"}\n', encoding="utf-8")
    proj_adv = proj / "vc.json"
    proj_adv.write_text('{"latest_version": "0.39.0"}\n', encoding="utf-8")

    tools_bad = {
        "tilde_hermes": {
            "version": "1.0.0",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "interpreter",
            "source": "human",
            "advisory": {"kind": "json", "path": "~/.hermes/anything.json", "key": "latest_version"},
        },
        "abs_hermes": {
            "version": "1.0.0",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "interpreter",
            "source": "human",
            "advisory": {"kind": "json", "path": str(hermes_any), "key": "latest_version"},
        },
        "dev_hermes": {
            "version": "1.0.0",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "interpreter",
            "source": "human",
            "advisory": {"kind": "json", "path": "~/.hermes-dev/anything.json", "key": "latest_version"},
        },
        "cua_unlisted": {
            "version": "1.0.0",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "interpreter",
            "source": "human",
            "advisory": {"kind": "json", "path": "~/.cua-driver/other.json", "key": "latest_version"},
        },
    }
    lock_file = proj / "TOOLS.lock"
    toolchk.dump_lock(lock_file, {"lock": dict(toolchk.DEFAULT_HEADER), "tools": tools_bad})

    monkeypatch.setattr(toolchk, "probe", lambda *a, **k: ("1.0.0", "/usr/bin/python3"))
    with _record_opens(monkeypatch) as opened:
        rep_bad = toolchk.check(list(tools_bad.keys()), None, proj)
        # Also refuse relative advisory when project_root itself is a Hermes home
        rep_rel_in_hermes = toolchk.check(
            ["rel_h"],
            {
                "lock": dict(toolchk.DEFAULT_HEADER),
                "tools": {
                    "rel_h": {
                        "version": "1.0.0",
                        "chosen": "2026-11-06",
                        "reason": "test",
                        "probe": "interpreter",
                        "source": "human",
                        "advisory": {"kind": "json", "path": "anything.json", "key": "latest_version"},
                    }
                },
            },
            hermes_home,
        )

    _assert_never_opened(opened, [hermes_any, dev_any, cua_other], lock_file)
    for tname in tools_bad:
        row = rep_bad["tools"][tname]
        assert "upstream_latest" not in row
        assert "advisory_path_not_allowed" in row.get("advisory_error", "")
    assert "upstream_latest" not in rep_rel_in_hermes["tools"]["rel_h"]
    for secret in ("9.1.1", "9.1.2", "9.1.3", "CANARY_HERMES_ANY_1199", "CANARY_DEV_ANY_2288", "CANARY_CUA_OTHER_3377"):
        _assert_canary_absent(secret, rep_bad)
        _assert_canary_absent(secret, rep_rel_in_hermes)

    # Verify legitimate fixed advisory file and relative project advisory file work
    rep_ok = toolchk.check(
        ["cua_tilde", "cua_abs", "local_vc"],
        {
            "lock": dict(toolchk.DEFAULT_HEADER),
            "tools": {
                "cua_tilde": {
                    "version": "1.0.0",
                    "chosen": "2026-11-06",
                    "reason": "test",
                    "probe": "interpreter",
                    "source": "human",
                    "advisory": {"kind": "json", "path": "~/.cua-driver/version_check.json", "key": "latest_version"},
                },
                "cua_abs": {
                    "version": "1.0.0",
                    "chosen": "2026-11-06",
                    "reason": "test",
                    "probe": "interpreter",
                    "source": "human",
                    "advisory": {"kind": "json", "path": str(cua_fixed), "key": "latest_version"},
                },
                "local_vc": {
                    "version": "1.0.0",
                    "chosen": "2026-11-06",
                    "reason": "test",
                    "probe": "interpreter",
                    "source": "human",
                    "advisory": {"kind": "json", "path": "vc.json", "key": "latest_version"},
                },
            },
        },
        proj,
    )
    assert rep_ok["tools"]["cua_tilde"]["upstream_latest"] == "0.38.0"
    assert rep_ok["tools"]["cua_abs"]["upstream_latest"] == "0.38.0"
    assert rep_ok["tools"]["local_vc"]["upstream_latest"] == "0.39.0"


def test_manifest_with_secret_tokens_rejected_without_value_echo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_home, _hermes_home, proj = _setup_fake_homes(tmp_path, monkeypatch)

    secret_tokens = [
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",  # 40-char hex starting with digit
        "ghp_1234567890abcdefghijklmnopqrstuvwx12",  # 40-char PAT
        "1a2b3c4d5e6f7a8b9c0d1e2f",                  # 24-char dotless run starting with digit
        "1.0-x9y8z7w6v5u4t3s2r1q0p9o8",              # <=32 chars with dot but 24+ dotless run
        "sk1.2.3.4",                                 # starts with non-'v' letters
        "API_KEY=CANARY_SPACE_SECRET_9001",          # invalid chars / spaces
    ]

    for idx, tok in enumerate(secret_tokens):
        sub = proj / f"case_{idx}"
        sub.mkdir()
        (sub / "package.json").write_text(json.dumps({"version": tok}), encoding="utf-8")
        (sub / "vc.json").write_text(json.dumps({"latest_version": tok}), encoding="utf-8")

        entry_probe = {
            "version": "1.0.0",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "file",
            "file": f"case_{idx}/package.json",
            "key": "version",
            "source": "human",
        }
        with pytest.raises(ValueError) as exc_info:
            toolchk.probe(f"p{idx}", entry_probe, proj)
        err_msg = str(exc_info.value)
        assert f"invalid version token ({len(tok)} chars" in err_msg
        assert tok not in err_msg
        assert tok[:8] not in err_msg
        assert tok not in repr(exc_info.value)

        entry_adv = {
            "version": "1.0.0",
            "chosen": "2026-11-06",
            "reason": "test",
            "probe": "interpreter",
            "source": "human",
            "advisory": {"kind": "json", "path": f"case_{idx}/vc.json", "key": "latest_version"},
        }
        rep = toolchk.check(
            [f"p{idx}", f"a{idx}"],
            {"lock": dict(toolchk.DEFAULT_HEADER), "tools": {f"p{idx}": entry_probe, f"a{idx}": entry_adv}},
            proj,
        )
        assert rep["tools"][f"p{idx}"]["status"] == "probe-failed"
        assert "upstream_latest" not in rep["tools"][f"a{idx}"]
        assert f"invalid version token ({len(tok)} chars" in rep["tools"][f"a{idx}"]["advisory_error"]
        _assert_canary_absent(tok, rep)
        _assert_canary_absent(tok[:8], rep)

    # Non-string JSON value and malformed JSON/TOML must never echo content either
    (proj / "dict_case").mkdir()
    (proj / "dict_case" / "package.json").write_text(
        json.dumps({"version": {"secret": "CANARY_DICT_SECRET_9002"}}),
        encoding="utf-8",
    )
    (proj / "mal_case").mkdir()
    (proj / "mal_case" / "pyproject.toml").write_text(
        'CANARY_PARSE_SECRET_9003 = "unterminated\n',
        encoding="utf-8",
    )
    (proj / "mal_case" / "vc.json").write_text(
        '{"latest_version": CANARY_JSON_SECRET_9004}\n',
        encoding="utf-8",
    )

    rep_edge = toolchk.check(
        ["dict_t", "mal_t", "mal_adv"],
        {
            "lock": dict(toolchk.DEFAULT_HEADER),
            "tools": {
                "dict_t": {
                    "version": "1.0.0",
                    "chosen": "2026-11-06",
                    "reason": "test",
                    "probe": "file",
                    "file": "dict_case/package.json",
                    "key": "version",
                    "source": "human",
                },
                "mal_t": {
                    "version": "1.0.0",
                    "chosen": "2026-11-06",
                    "reason": "test",
                    "probe": "file",
                    "file": "mal_case/pyproject.toml",
                    "key": "project.version",
                    "source": "human",
                },
                "mal_adv": {
                    "version": "1.0.0",
                    "chosen": "2026-11-06",
                    "reason": "test",
                    "probe": "interpreter",
                    "source": "human",
                    "advisory": {"kind": "json", "path": "mal_case/vc.json", "key": "latest_version"},
                },
            },
        },
        proj,
    )
    assert rep_edge["tools"]["dict_t"]["status"] == "probe-failed"
    assert rep_edge["tools"]["mal_t"]["status"] == "probe-failed"
    assert "upstream_latest" not in rep_edge["tools"]["mal_adv"]
    for canary in ("CANARY_DICT_SECRET_9002", "CANARY_PARSE_SECRET_9003", "CANARY_JSON_SECRET_9004"):
        _assert_canary_absent(canary, rep_edge)


def test_tightened_version_grammar_accepts_versions_and_rejects_secrets() -> None:
    for valid in (
        "1.2.3",
        "v24.11.0",
        "20",
        "v20",
        "0.21.0",
        "5.6.1",
        "1.82.0-nightly",
        "3.20160805.1",
        "1.2.3-rc.1+build.5",
    ):
        assert toolchk.SAFE_VERSION_TOKEN_RE.fullmatch(valid), f"Expected valid version: {valid!r}"

    for invalid in (
        "",
        "v",
        "stable",
        "a1.2.3",
        "sk-1.2.3",
        "1" * 20,
        "v" + "1" * 19,
        "1.2." + "a" * 20,
        "1.2." + ("3." * 15) + "0",  # > 32 chars
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
    ):
        assert toolchk.SAFE_VERSION_TOKEN_RE.fullmatch(invalid) is None, f"Expected rejected token: {invalid!r}"



