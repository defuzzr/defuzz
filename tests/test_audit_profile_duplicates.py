"""Tests for audit.profile_duplicates (content copied across profiles)."""
from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import re
import stat
from pathlib import Path

from tests.conftest import load_submodule


def _snapshot_tree(root: Path) -> list[tuple[str, str, int, str]]:
    """Return a deterministic recursive listing + content hash snapshot of `root`."""
    records: list[tuple[str, str, int, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        records.append((rel_dir, f"dir-{os.lstat(dirpath).st_mode:o}", 0, ""))
        for name in dirnames:
            full = Path(dirpath) / name
            if full.is_symlink():
                records.append(((full.relative_to(root)).as_posix(), "symlink_dir", 0, os.readlink(full)))
        for name in filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            st = full.lstat()
            if full.is_symlink():
                records.append((rel, "symlink", st.st_size, os.readlink(full)))
            elif not stat.S_ISREG(st.st_mode):
                records.append((rel, f"special-{st.st_mode:o}", st.st_size, ""))
            else:
                digest = hashlib.sha256(full.read_bytes()).hexdigest()
                records.append((rel, f"file-{st.st_mode:o}", st.st_size, digest))
    return records


def _names(paths: list[str]) -> list[str]:
    """Profile (or folder) names from the absolute folder paths the section emits."""
    return [Path(p).name for p in paths]


def _groups(sec: dict) -> dict:
    """Duplicate groups keyed by (file_kind, name of the location folder)."""
    return {(g["file_kind"], Path(g["location"]).name): g for g in sec["top_duplicate_groups"]}


def test_missing_and_empty_home(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")

    # 1. Missing home returns not_measured / could_not_verify without raising
    missing = tmp_path / "does_not_exist"
    res_missing = mod.audit_profile_duplicates(missing)
    sec_missing = res_missing["profile_duplicates"]
    assert res_missing["coverage"] == "could_not_verify"
    assert sec_missing["coverage"] == "could_not_verify"
    assert sec_missing["status"] == "not_measured"
    assert sec_missing["reason"] == "missing_profile_root"
    assert {f["id"] for f in res_missing["findings"]} == {"profile_duplicates.could_not_verify"}
    # A path that does not exist is never named (it would become a per-run token in the report).
    assert res_missing["findings"][0]["affected_identities"] == [] and res_missing["findings"][0]["source_paths"] == []

    # 2. Empty home (no profiles/ directory) returns verified with 0 profiles and 0 findings
    empty_home = tmp_path / "empty_home"
    empty_home.mkdir()
    res_empty = mod.audit_profile_duplicates(profile_path=empty_home)
    sec_empty = res_empty["profile_duplicates"]
    assert sec_empty["skipped_credential_dirs"] == 0
    assert res_empty["coverage"] == "verified"
    assert sec_empty["status"] == "completed"
    assert sec_empty["profile_count"] == 0
    assert sec_empty["empty_profiles"] == {"count": 0, "paths": []}
    assert sec_empty["log_only_profiles"]["count"] == 0
    assert sec_empty["no_config_profiles"]["count"] == 0
    assert sec_empty["total_wasted_bytes"] == 0
    assert res_empty["findings"] == []


def test_named_profile_given_instead_of_home_root_is_not_measured(tmp_path: Path) -> None:
    """`profile_path` must be the Hermes home root; a named profile `<home>/profiles/<name>` is reported, not
    silently measured as a home with 0 profiles."""
    mod = load_submodule("audit.profile_duplicates")
    named = tmp_path / "profiles" / "work"
    (named / "memories").mkdir(parents=True)
    (tmp_path / "profiles" / "other").mkdir()
    res = mod.audit_profile_duplicates(named)
    sec = res["profile_duplicates"]
    assert sec["status"] == "not_measured" and sec["reason"] == "named_profile_given"
    assert res["coverage"] == "could_not_verify" and "profile_count" not in sec
    (finding,) = res["findings"]
    assert finding["id"] == "profile_duplicates.could_not_verify" and finding["evidence"]["reason"] == "named_profile_given"
    assert finding["affected_identities"] == [str(named)]
    # The home root two levels up is measured normally.
    assert mod.audit_profile_duplicates(tmp_path)["profile_duplicates"]["profile_count"] == 2
    # A named profile that itself holds a profiles/ folder is measured as a root (nothing is guessed).
    (named / "profiles").mkdir()
    assert mod.audit_profile_duplicates(named)["profile_duplicates"]["status"] == "completed"
    # A plain folder without profiles/ whose parent is not called "profiles" is a home with 0 profiles.
    plain = tmp_path / "plain"
    plain.mkdir()
    assert mod.audit_profile_duplicates(plain)["profile_duplicates"]["profile_count"] == 0


def test_profile_inventory_empty_log_only_and_no_config(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()

    # Hidden .deleted tombstone directory must be ignored
    (profiles_dir / ".deleted").mkdir()
    (profiles_dir / ".deleted" / "old_prof").write_text("deleted\n", encoding="utf-8")

    # 3 empty profiles (including one with an empty sub-folder)
    for name in ("empty_a", "empty_b", "empty_c"):
        p = profiles_dir / name
        p.mkdir()
    (profiles_dir / "empty_c" / "logs").mkdir()

    # 3 log-only profiles without config.yaml
    for name in ("log_a", "log_b", "log_c"):
        p = profiles_dir / name
        (p / "logs").mkdir(parents=True)
        (p / "logs" / "gateway.log").write_text("started\n", encoding="utf-8")
        (p / "logs" / "errors.log").write_text("none\n", encoding="utf-8")

    # 1 populated profile with config.yaml
    full = profiles_dir / "configured_one"
    full.mkdir()
    (full / "config.yaml").write_text("model: test\n", encoding="utf-8")
    (full / "SOUL.md").write_text("Unique identity.\n", encoding="utf-8")

    res = mod.audit_profile_duplicates(tmp_path)
    sec = res["profile_duplicates"]
    assert res["coverage"] == "verified"
    assert sec["profile_count"] == 7
    assert sec["empty_profiles"]["count"] == 3
    assert sec["empty_profiles"]["paths"] == [str(profiles_dir / n) for n in ("empty_a", "empty_b", "empty_c")]
    assert sec["log_only_profiles"]["count"] == 3
    assert _names(sec["log_only_profiles"]["paths"]) == ["log_a", "log_b", "log_c"]
    assert sec["no_config_profiles"]["count"] == 6
    assert _names(sec["no_config_profiles"]["paths"]) == ["empty_a", "empty_b", "empty_c", "log_a", "log_b", "log_c"]
    assert [r["path"] for r in sec["profiles"]] == sorted(str(p) for p in profiles_dir.iterdir() if p.name[0] != ".")

    by_id = {f["id"]: f for f in res["findings"]}
    assert "profile_duplicates.empty_profiles" in by_id
    f_empty = by_id["profile_duplicates.empty_profiles"]
    assert f_empty["classification"] == "info"
    assert f_empty["evidence"]["empty_profiles"] == 3
    assert f_empty["evidence"]["log_only_profiles"] == 3
    assert f_empty["evidence"]["total_empty_or_log_only"] == 6


def test_exact_duplicates_repeated_binary_and_caches(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.profile_duplicates")
    # Lower byte thresholds slightly for fast synthetic test execution while testing exact arithmetic
    monkeypatch.setattr(mod, "MIN_REPEATED_BINARY_BYTES", 2 * 1024 * 1024)
    # Cache groups (hub index, models_dev) do not count toward this trigger; the binary alone wastes ~4 MiB.
    monkeypatch.setattr(mod, "IDENTICAL_FILES_WASTED_BYTES_THRESHOLD", 3 * 1024 * 1024)
    monkeypatch.setattr(mod, "PER_PROFILE_CACHE_BYTES_THRESHOLD", 3 * 1024 * 1024)

    bin_payload = b"\x7fELF" + (b"\x90" * (2 * 1024 * 1024))
    hub_payload = b'{"skills": [' + (b"x" * (2 * 1024 * 1024)) + b"]}"
    models_payload = b'{"models": "cached"}\n' * 100
    prov_payload = b'{"openai": ["gpt-4"]}\n' * 50
    db_payload = b"SQLite format 3\x00" + (b"\x00" * 4080)

    for pname in ("qaanalyst", "qabuilder", "qaverifier"):
        p = tmp_path / "profiles" / pname
        (p / "bin").mkdir(parents=True)
        (p / "bin" / "tool").write_bytes(bin_payload)
        (p / "skills" / ".hub" / "index-cache").mkdir(parents=True)
        (p / "skills" / ".hub" / "index-cache" / "hermes-index.json").write_bytes(hub_payload)
        (p / "models_dev_cache.json").write_bytes(models_payload)
        (p / "provider_models_cache.json").write_bytes(prov_payload)
        (p / "cron").mkdir(parents=True)
        (p / "cron" / "executions.db").write_bytes(db_payload)
        (p / "projects.db").write_bytes(db_payload)
        (p / "config.yaml").write_text(f"profile: {pname}\n", encoding="utf-8")

    res = mod.audit_profile_duplicates(tmp_path)
    sec = res["profile_duplicates"]
    assert res["coverage"] == "verified"
    assert sec["profile_count"] == 3

    groups = _groups(sec)
    tool = groups[("executable_file", "bin")]
    assert tool["location"] == str(tmp_path / "profiles" / "qaanalyst" / "bin")  # first member, first-level folder
    assert tool["copies"] == 3
    assert tool["size_bytes"] == len(bin_payload)
    assert tool["wasted_bytes"] == 2 * len(bin_payload)

    hub = groups[("hub_index_cache", "skills")]
    assert hub["copies"] == 3 and hub["regenerable_cache"] is True
    assert hub["wasted_bytes"] == 2 * len(hub_payload)

    # A file in the profile root is located by the profile folder itself.
    assert groups[("models_dev_cache", "qaanalyst")]["copies"] == 3
    # cron/executions.db and projects.db hold the same bytes: one group of 6 copies, located by its first member.
    assert groups[("database", "cron")]["copies"] == 6

    caches = sec["per_profile_caches"]
    assert caches["hub_index_cache_bytes"] == 3 * len(hub_payload)
    assert caches["models_dev_cache_bytes"] == 3 * len(models_payload)
    assert caches["provider_models_cache_bytes"] == 3 * len(prov_payload)
    assert caches["total_bytes"] == 3 * (len(hub_payload) + len(models_payload) + len(prov_payload))

    by_id = {f["id"]: f for f in res["findings"]}
    assert "profile_duplicates.repeated_binary" in by_id
    assert by_id["profile_duplicates.repeated_binary"]["classification"] == "review_suggested"
    assert by_id["profile_duplicates.repeated_binary"]["evidence"]["copies"] == 3
    assert by_id["profile_duplicates.repeated_binary"]["evidence"]["wasted_bytes"] == 2 * len(bin_payload)

    assert "profile_duplicates.identical_files" in by_id
    assert by_id["profile_duplicates.identical_files"]["classification"] == "review_suggested"

    assert "profile_duplicates.per_profile_caches" in by_id
    assert by_id["profile_duplicates.per_profile_caches"]["classification"] == "info"


def test_cloned_identity_exact_and_near_clones(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")

    # Part 1: 3 profiles with byte-identical MEMORY.md and USER.md
    home_exact = tmp_path / "exact_home"
    for pname in ("rxanalyst", "rxbuilder", "rxverifier"):
        p = home_exact / "profiles" / pname
        (p / "memories").mkdir(parents=True)
        (p / "config.yaml").write_text(f"name: {pname}\n", encoding="utf-8")
        (p / "memories" / "MEMORY.md").write_text(" Always run pytest first.\nPrefer stdlib.\n", encoding="utf-8")
        (p / "memories" / "USER.md").write_text("Role: systems engineer.\n", encoding="utf-8")
        (p / "SOUL.md").write_text(f"Unique soul for {pname} only.\n", encoding="utf-8")

    res_exact = mod.audit_profile_duplicates(home_exact)
    sec_exact = res_exact["profile_duplicates"]
    cid = sec_exact["cloned_identity"]
    assert cid["identical_profiles_count"] == 3
    assert cid["by_kind"]["MEMORY.md"]["identical_group_sizes"] == [3]
    assert cid["by_kind"]["USER.md"]["identical_group_sizes"] == [3]
    assert cid["by_kind"]["SOUL.md"]["identical_group_sizes"] == []

    by_id_exact = {f["id"]: f for f in res_exact["findings"]}
    assert "profile_duplicates.cloned_identity_files" in by_id_exact
    f_exact = by_id_exact["profile_duplicates.cloned_identity_files"]
    assert f_exact["classification"] == "review_suggested"
    assert f_exact["consequence"] == mod.FINDING_CONSEQUENCES["profile_duplicates.cloned_identity_files"]
    assert f_exact["evidence"]["affected_profiles"] == 3

    # Part 2: 4 profiles with near-clone MEMORY.md (not byte-identical, 80% shared lines after case/whitespace norm)
    home_near = tmp_path / "near_home"
    shared_lines = [
        "You are a focused specialist agent.",
        "Always verify file paths before writing.",
        "Keep summaries concise and direct.",
        "Never fabricate tool outputs.",
    ]
    for idx in range(1, 5):
        p = home_near / "profiles" / f"t{idx}"
        (p / "memories").mkdir(parents=True)
        (p / "config.yaml").write_text(f"id: {idx}\n", encoding="utf-8")
        # Vary whitespace and case so byte-identical check is False, plus 1 unique line out of 5 (80% shared)
        lines = [
            shared_lines[0].upper() if idx % 2 == 0 else shared_lines[0],
            "  " + shared_lines[1] + "   ",
            shared_lines[2],
            shared_lines[3],
            f"Unique specialist lane number {idx} with distinct text.",
        ]
        (p / "memories" / "MEMORY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    res_near = mod.audit_profile_duplicates(home_near)
    sec_near = res_near["profile_duplicates"]
    cid_near = sec_near["cloned_identity"]
    assert cid_near["identical_profiles_count"] == 0
    assert cid_near["median_shared_line_share"] == 0.8
    assert cid_near["max_shared_line_share"] == 0.8
    assert cid_near["profiles_above_50pct"] == 4

    by_id_near = {f["id"]: f for f in res_near["findings"]}
    assert "profile_duplicates.cloned_identity_files" in by_id_near
    f_near = by_id_near["profile_duplicates.cloned_identity_files"]
    assert f_near["consequence"] == mod.FINDING_CONSEQUENCES["profile_duplicates.cloned_identity_files"]
    assert f_near["evidence"]["affected_profiles"] == 4


def test_profile_families_prefix_and_digit_series(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")
    names = [
        "qaanalyst", "qaastra", "qabuilder", "qaoperator", "qaverifier",
        "rxanalyst", "rxastra", "rxbuilder", "rxoperator", "rxverifier",
        "zkanalyst", "zkastra", "zkbuilder", "zkoperator", "zkverifier",
        "t1", "t2", "t3", "t4",
        "solo", "other", "workspace",
    ]
    for name in names:
        p = tmp_path / "profiles" / name
        p.mkdir(parents=True)
        (p / "config.yaml").write_text("model: default\n", encoding="utf-8")

    res = mod.audit_profile_duplicates(tmp_path)
    fams = res["profile_duplicates"]["profile_families"]
    assert fams["family_count"] == 4
    by_kind = sorted((f["kind"], f["member_count"], tuple(_names(f["paths"]))) for f in fams["families"])
    assert by_kind == [
        ("alphabetic_prefix", 5, ("qaanalyst", "qaastra", "qabuilder", "qaoperator", "qaverifier")),
        ("alphabetic_prefix", 5, ("rxanalyst", "rxastra", "rxbuilder", "rxoperator", "rxverifier")),
        ("alphabetic_prefix", 5, ("zkanalyst", "zkastra", "zkbuilder", "zkoperator", "zkverifier")),
        ("digit_series", 4, ("t1", "t2", "t3", "t4")),
    ]
    assert all(p.startswith(str(tmp_path / "profiles") + os.sep) for f in fams["families"] for p in f["paths"])


def test_do_not_flag_negative_cases(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.profile_duplicates")
    monkeypatch.setattr(mod, "MIN_REPEATED_BINARY_BYTES", 1024 * 1024)

    # 1. Home with only 2 profiles even with identical binary, SOUL.md, MEMORY.md, and bundled SKILL.md
    two_home = tmp_path / "two_profiles"
    elf_blob = b"\x7fELF" + (b"B" * (1024 * 1024))
    for pname in ("work", "personal"):
        p = two_home / "profiles" / pname
        (p / "bin").mkdir(parents=True)
        (p / "bin" / "tool").write_bytes(elf_blob)
        (p / "memories").mkdir(parents=True)
        (p / "memories" / "MEMORY.md").write_text("Shared memory\n", encoding="utf-8")
        (p / "SOUL.md").write_text("Shared soul\n", encoding="utf-8")
        (p / "skills" / "bundled-one").mkdir(parents=True)
        (p / "skills" / "bundled-one" / "SKILL.md").write_text("---\nname: bundled-one\n---\nStock\n", encoding="utf-8")
        (p / "config.yaml").write_text("model: x\n", encoding="utf-8")

    res_two = mod.audit_profile_duplicates(two_home)
    assert res_two["coverage"] == "verified"
    assert res_two["findings"] == []

    # 2. Home with 4 profiles having distinct state.db, distinct .env/auth.json, and identical tiny .lock/.gitkeep
    four_home = tmp_path / "four_normal"
    for idx in range(1, 5):
        p = four_home / "profiles" / f"norm_{idx}"
        p.mkdir(parents=True)
        (p / "config.yaml").write_text(f"profile_num: {idx}\n", encoding="utf-8")
        # Same size (4096 bytes), distinct content
        (p / "state.db").write_bytes(f"SQLite-{idx}-".encode("utf-8").ljust(4096, b"\x00"))
        (p / ".env").write_text(f"API_KEY=secret_{idx}\n", encoding="utf-8")
        (p / "auth.json").write_text(f'{{"token": "tok_{idx}"}}\n', encoding="utf-8")
        # Identical empty .lock and .gitkeep files and non-allowlisted small files
        (p / "gateway.lock").write_bytes(b"")
        (p / ".gitkeep").write_bytes(b"")
        (p / "notes.txt").write_text("Identical small non-target note.\n", encoding="utf-8")

    res_four = mod.audit_profile_duplicates(four_home)
    assert res_four["coverage"] == "verified"
    assert res_four["profile_duplicates"]["total_wasted_bytes"] == 0
    assert res_four["findings"] == []


def test_credential_files_never_opened_and_size_only_observation(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.profile_duplicates")
    policy = load_submodule("audit.policy")

    for idx in range(1, 4):
        p = tmp_path / "profiles" / f"p{idx}"
        (p / "mcp-tokens").mkdir(parents=True)
        (p / "vault").mkdir(parents=True)
        (p / "pairing").mkdir(parents=True)
        (p / "config.yaml").write_text(f"p: {idx}\n", encoding="utf-8")
        # Credential files with identical size across all 3 profiles
        (p / ".env").write_text(f"SECRET_KEY=val_{idx:04d}\n", encoding="utf-8")
        (p / "auth.json").write_text(f'{{"key": "secret_{idx:04d}"}}\n', encoding="utf-8")
        (p / "mcp-tokens" / "server.json").write_text('{"token": "mcp_secret"}\n', encoding="utf-8")
        (p / "vault" / "vault.key").write_text("vault_secret_key\n", encoding="utf-8")
        (p / "pairing" / "pair.json").write_text('{"code": "123456"}\n', encoding="utf-8")
        (p / "id_ed25519").write_text("PRIVATE KEY DATA\n", encoding="utf-8")
        (p / "server.pem").write_text("PEM DATA\n", encoding="utf-8")

    opened_paths: list[str] = []
    real_builtins_open = builtins.open
    real_io_open = io.open
    real_os_open = os.open

    def guarded_builtins_open(file, *args, **kwargs):
        p_str = os.fsdecode(file) if not isinstance(file, int) else str(file)
        opened_paths.append(p_str)
        assert not policy.credential_path(p_str), f"Credential file opened via builtins.open: {p_str}"
        return real_builtins_open(file, *args, **kwargs)

    def guarded_io_open(file, *args, **kwargs):
        p_str = os.fsdecode(file) if not isinstance(file, int) else str(file)
        opened_paths.append(p_str)
        assert not policy.credential_path(p_str), f"Credential file opened via io.open: {p_str}"
        return real_io_open(file, *args, **kwargs)

    def guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
        p_str = os.fsdecode(path)
        opened_paths.append(p_str)
        assert not policy.credential_path(p_str), f"Credential file opened via os.open: {p_str}"
        if dir_fd is not None:
            return real_os_open(path, flags, mode, dir_fd=dir_fd)
        return real_os_open(path, flags, mode)

    monkeypatch.setattr(builtins, "open", guarded_builtins_open)
    monkeypatch.setattr(io, "open", guarded_io_open)
    monkeypatch.setattr(os, "open", guarded_os_open)

    res = mod.audit_profile_duplicates(tmp_path)
    sec = res["profile_duplicates"]
    assert res["coverage"] == "verified"
    cred_obs = {(r["file_kind"], r["suffixed_copy"], r["at_profile_root"]): r for r in sec["credential_same_size_groups"]}
    env = cred_obs[("env_file", False, True)]
    assert env["profiles_count"] == 3
    assert env["hashed"] is False
    assert env["observation"] == "size_only_not_hashed"
    auth = cred_obs[("auth_json", False, True)]
    assert auth["profiles_count"] == 3
    assert auth["hashed"] is False
    # Credential-named files are never named and never located by path.
    assert str(tmp_path) not in json.dumps(sec["credential_same_size_groups"])
    # Credential-classified folders are never walked, but the skip is counted (3 folders x 3 profiles).
    assert sec["skipped_credential_dirs"] == 9


def test_caps_and_truncation_paths(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.profile_duplicates")
    for idx in range(1, 5):
        p = tmp_path / "profiles" / f"cap_{idx}"
        (p / "memories").mkdir(parents=True)
        (p / "config.yaml").write_text("a: 1\n", encoding="utf-8")
        (p / "SOUL.md").write_text("Shared soul text line.\n", encoding="utf-8")
        (p / "memories" / "MEMORY.md").write_text("Shared memory text.\n", encoding="utf-8")
        (p / "projects.db").write_bytes(b"SQLite format 3\x00" + b"X" * 2048)

    # 1. Entries cap
    with monkeypatch.context() as m:
        m.setattr(mod, "MAX_ENTRIES", 5)
        res = mod.audit_profile_duplicates(tmp_path)
        assert res["coverage"] == "could_not_verify"
        assert res["profile_duplicates"]["truncated_by"] == "entries_limit"
        assert res["profile_duplicates"]["limits"]["cuts"] >= 1
        assert any(f["id"] == "profile_duplicates.could_not_verify" for f in res["findings"])

    # 2. Files hashed cap
    with monkeypatch.context() as m:
        m.setattr(mod, "MAX_FILES_HASHED", 2)
        res = mod.audit_profile_duplicates(tmp_path)
        assert res["coverage"] == "could_not_verify"
        assert res["profile_duplicates"]["truncated_by"] == "files_hashed_limit"
        assert any(f["id"] == "profile_duplicates.could_not_verify" for f in res["findings"])

    # 3. Bytes hashed cap
    with monkeypatch.context() as m:
        m.setattr(mod, "MAX_BYTES_HASHED", 1024)
        res = mod.audit_profile_duplicates(tmp_path)
        assert res["coverage"] == "could_not_verify"
        assert res["profile_duplicates"]["truncated_by"] == "bytes_hashed_limit"
        assert any(f["id"] == "profile_duplicates.could_not_verify" for f in res["findings"])

    # 4. Wall-clock timeout cap via injectable clock
    ticks = iter([0.0, 0.1, 0.2, 35.0, 36.0, 37.0])
    res_clock = mod.audit_profile_duplicates(tmp_path, clock=lambda: next(ticks, 40.0))
    assert res_clock["coverage"] == "could_not_verify"
    assert res_clock["profile_duplicates"]["truncated_by"] == "time_budget"
    assert any(f["id"] == "profile_duplicates.could_not_verify" for f in res_clock["findings"])

    # 5. Depth limit cap
    with monkeypatch.context() as m:
        m.setattr(mod, "MAX_DEPTH", 0)
        res_depth = mod.audit_profile_duplicates(tmp_path)
        assert res_depth["coverage"] == "could_not_verify"
        assert res_depth["profile_duplicates"]["truncated_by"] == "depth_limit"

    # 6. Identity files count cap and per-file byte cap
    with monkeypatch.context() as m:
        m.setattr(mod, "MAX_IDENTITY_FILES", 2)
        res_id_cnt = mod.audit_profile_duplicates(tmp_path)
        assert res_id_cnt["coverage"] == "could_not_verify"
        assert res_id_cnt["profile_duplicates"]["truncated_by"] == "identity_files_limit"

    with monkeypatch.context() as m:
        m.setattr(mod, "MAX_IDENTITY_FILE_BYTES", 4)
        res_id_bytes = mod.audit_profile_duplicates(tmp_path)
        assert res_id_bytes["coverage"] == "could_not_verify"
        assert res_id_bytes["profile_duplicates"]["truncated_by"] == "identity_file_bytes_limit"


def test_main_home_to_profile_duplicate_detection(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")
    # Main home has a 2 MiB file that is copied into 1 named profile out of 3
    payload = b"MAIN_HOME_DATA_" + (b"M" * (2 * 1024 * 1024))
    (tmp_path / "models_dev_cache.json").write_bytes(payload)
    for idx in range(1, 4):
        p = tmp_path / "profiles" / f"p{idx}"
        p.mkdir(parents=True)
        (p / "config.yaml").write_text(f"id: {idx}\n", encoding="utf-8")
    (tmp_path / "profiles" / "p1" / "models_dev_cache.json").write_bytes(payload)

    res = mod.audit_profile_duplicates(tmp_path)
    sec = res["profile_duplicates"]
    assert res["coverage"] == "verified"
    grp = _groups(sec)[("models_dev_cache", "p1")]
    assert grp["copies"] == 2
    assert grp["profile_copies"] == 1
    assert grp["in_main_home"] is True
    assert grp["wasted_bytes"] == len(payload)


def test_symlink_refusal(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")
    outside = tmp_path / "outside_secret"
    outside.mkdir()
    outside_file = outside / "SOUL.md"
    outside_file.write_text("OUTSIDE_CANARY_TEXT\n", encoding="utf-8")

    home = tmp_path / "hermes_home"
    for idx in range(1, 4):
        p = home / "profiles" / f"p{idx}"
        p.mkdir(parents=True)
        (p / "config.yaml").write_text("ok: true\n", encoding="utf-8")

    # Symlinked profile directory and symlinked file inside a profile
    (home / "profiles" / "linked_profile").symlink_to(outside)
    (home / "profiles" / "p1" / "SOUL.md").symlink_to(outside_file)

    res = mod.audit_profile_duplicates(home)
    assert res["coverage"] == "could_not_verify"
    assert res["profile_duplicates"]["limits"]["cuts"] >= 1
    assert "OUTSIDE_CANARY_TEXT" not in json.dumps(res)
    assert "linked_profile" not in _names([p["path"] for p in res["profile_duplicates"]["profiles"]])


def test_unchanged_home_canary_privacy_and_malformed_inputs(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")
    canary_mem = "CANARY_SECRET_MEMORY_PHRASE_98765"
    canary_soul = "CANARY_SECRET_SOUL_PROMPT_54321"
    canary_path = "CANARY_DEEP_NESTED_SUBFOLDER_11111"

    for idx in range(1, 4):
        p = tmp_path / "profiles" / f"prof_{idx}"
        (p / "memories").mkdir(parents=True)
        # Malformed YAML / binary junk in config.yaml and broken JSON in models_dev_cache.json
        (p / "config.yaml").write_bytes(b"\xff\xfe: : broken yaml [\x00\n")
        (p / "models_dev_cache.json").write_bytes(b"{broken json \xff\xfe")
        (p / "SOUL.md").write_bytes(f"Line one {canary_soul}\n".encode("utf-8") + b"\xff\xfe\n")
        (p / "memories" / "MEMORY.md").write_text(
            f"Remember {canary_mem} at /home/user/{canary_path} and 192.0.2.42\n",
            encoding="utf-8",
        )
        deep = p / "workspace" / canary_path / "nested"
        deep.mkdir(parents=True)
        (deep / "data.db").write_bytes(b"SQLite format 3\x00" + b"Z" * 1024)

    before = _snapshot_tree(tmp_path)
    res = mod.audit_profile_duplicates(tmp_path)
    after = _snapshot_tree(tmp_path)

    assert before == after, "Audit modified the home directory tree!"
    serialized = json.dumps(res)
    assert canary_mem not in serialized
    assert canary_soul not in serialized
    assert canary_path not in serialized
    assert "192.0.2.42" not in serialized


# --- regression tests -----------------------------------------------------------------------------------------

def _record_opens(monkeypatch) -> list[str]:
    opened: list[str] = []
    real_b, real_io, real_os = builtins.open, io.open, os.open

    def wrap(real):
        def inner(file, *args, **kwargs):
            if not isinstance(file, int):
                opened.append(os.fsdecode(file))
            return real(file, *args, **kwargs)
        return inner

    monkeypatch.setattr(builtins, "open", wrap(real_b))
    monkeypatch.setattr(io, "open", wrap(real_io))
    monkeypatch.setattr(os, "open", wrap(real_os))
    return opened


def test_config_yaml_is_size_only_never_opened_in_profiles_or_main_home(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.profile_duplicates")
    (tmp_path / "config.yaml").write_text("api_key: KEYCANARY01\n", encoding="utf-8")
    for idx in range(1, 4):
        p = tmp_path / "profiles" / f"c{idx}"
        p.mkdir(parents=True)
        (p / "config.yaml").write_text("api_key: KEYCANARY01\n", encoding="utf-8")
        (p / "config.yaml.bak").write_text("api_key: KEYCANARY01\n", encoding="utf-8")
        (p / "config.yaml.bak-20260101-LABELCANARY").write_text("api_key: KEYCANARY01\n", encoding="utf-8")
        (p / ("R" * 70)).write_bytes(b"\x7fELF" + b"r" * (1024 * 1024))
        (p / ".env.bak-1").write_text("K=1\n", encoding="utf-8")
        (p / "secrets.yaml").write_text("k: v\n", encoding="utf-8")
        (p / "id_ed25519").write_text("x\n", encoding="utf-8")
    opened = _record_opens(monkeypatch)
    res = mod.audit_profile_duplicates(tmp_path)
    monkeypatch.undo()
    names = {os.path.basename(o) for o in opened}
    assert not names & {"config.yaml", "config.yaml.bak", ".env.bak-1", "secrets.yaml", "id_ed25519"}, opened
    sec = res["profile_duplicates"]
    size_only = {(r["file_kind"], r["suffixed_copy"]): r for r in sec["credential_same_size_groups"]}
    assert size_only[("config_yaml", False)]["profiles_count"] == 3
    assert size_only[("config_yaml", False)]["hashed"] is False
    assert size_only[("config_yaml", True)]["profiles_count"] == 3
    assert size_only[("env_file", True)]["profiles_count"] == 3
    text = json.dumps(res)
    assert "LABELCANARY" not in text and "R" * 10 not in text and "config.yaml" not in text
    assert [(g["file_kind"], Path(g["location"]).name) for g in sec["top_duplicate_groups"]] == [("executable_file", "c1")]
    assert [r["has_config"] for r in sec["profiles"]] == [True, True, True]


def test_live_database_hashed_as_raw_bytes_without_sqlite_or_blocking(tmp_path: Path, monkeypatch) -> None:
    import sqlite3

    mod = load_submodule("audit.profile_duplicates")
    for idx in range(1, 4):
        p = tmp_path / "profiles" / f"d{idx}"
        (p / "cron").mkdir(parents=True)
        con = sqlite3.connect(str(p / "cron" / "executions.db"))
        con.execute("create table t(x)")
        con.commit()
        con.close()
    # Hold an exclusive lock on one database for the duration of the audit.
    holder = sqlite3.connect(str(tmp_path / "profiles" / "d1" / "cron" / "executions.db"), isolation_level=None)
    holder.execute("begin exclusive")
    try:
        before = _snapshot_tree(tmp_path)
        connects: list[object] = []
        monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: connects.append(a))
        flags_seen: list[int] = []
        real_os_open = os.open

        def spy(path, flags, *args, **kwargs):
            flags_seen.append(flags)
            return real_os_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", spy)
        res = mod.audit_profile_duplicates(tmp_path)
        monkeypatch.undo()
        assert connects == []
        assert flags_seen and all(f & os.O_NOFOLLOW and not f & (os.O_WRONLY | os.O_RDWR) for f in flags_seen)
        assert _groups(res["profile_duplicates"])[("database", "cron")]["copies"] == 3
        assert _snapshot_tree(tmp_path) == before
    finally:
        holder.execute("rollback")
        holder.close()


def test_locations_stop_at_first_level_folder_and_file_names_never_appear(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")
    blob = b"\x7fELF" + b"Q" * (1024 * 1024 + 5)
    for idx in range(1, 4):
        p = tmp_path / "profiles" / f"w{idx}"
        deep = p / "workspace" / "LEVELTWOCANARY" / "LEVELTHREECANARY"
        deep.mkdir(parents=True)
        (deep / "big.bin").write_bytes(blob)
        (deep / ".env").write_text("Z=1\n", encoding="utf-8")
        (p / "plans").mkdir()
        (p / "plans" / ("x" * 60 + ".bin")).write_bytes(blob + b"2")
    res = mod.audit_profile_duplicates(tmp_path)
    text = json.dumps(res)
    assert "LEVELTHREECANARY" not in text and "LEVELTWOCANARY" not in text
    assert "big.bin" not in text and "x" * 10 not in text
    sec = res["profile_duplicates"]
    assert "profile_path" not in sec and "elapsed_ms" not in sec
    locations = {g["location"] for g in sec["top_duplicate_groups"]}
    assert locations == {str(tmp_path / "profiles" / "w1" / "workspace"), str(tmp_path / "profiles" / "w1" / "plans")}
    assert [(r["file_kind"], r["at_profile_root"]) for r in sec["credential_same_size_groups"]] == [("env_file", False)]
    # Findings name the measured folder the same way other sections do: the absolute `<home>/profiles` path,
    # which the report's path rule keeps as is.
    for finding in res["findings"]:
        assert finding["affected_identities"] == [str(tmp_path / "profiles")]
        assert [sp["path"] for sp in finding["source_paths"]] == [str(tmp_path / "profiles")]
    assert str(tmp_path) not in json.dumps(res["run_metrics"])


def test_determinism_only_run_metrics_differ(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")
    for idx in range(1, 5):
        p = tmp_path / "profiles" / f"t{idx}"
        (p / "memories").mkdir(parents=True)
        (p / "memories" / "MEMORY.md").write_text("same\n", encoding="utf-8")
        (p / "bin").mkdir()
        (p / "bin" / "tool").write_bytes(b"\x7fELF" + b"A" * (1024 * 1024))
    base_a, base_b = [0.0], [5 * 86400.0]

    def clock_a() -> float:
        base_a[0] += 0.001
        return base_a[0]

    def clock_b() -> float:
        base_b[0] += 0.007
        return base_b[0]

    res_a = mod.audit_profile_duplicates(tmp_path, clock=clock_a)
    res_b = mod.audit_profile_duplicates(tmp_path, clock=clock_b)
    assert "run_metrics" in res_a and "elapsed_ms" in res_a["run_metrics"]
    assert res_a["run_metrics"] != res_b["run_metrics"]
    strip = lambda r: {k: v for k, v in r.items() if k != "run_metrics"}
    assert strip(res_a) == strip(res_b)
    assert json.dumps(res_a["profile_duplicates"], sort_keys=True) == json.dumps(res_b["profile_duplicates"], sort_keys=True)
    assert json.dumps(res_a["findings"], sort_keys=True) == json.dumps(res_b["findings"], sort_keys=True)
    assert set(res_a["run_metrics"]) == {"elapsed_ms"}
    missing = mod.audit_profile_duplicates(tmp_path / "nope", clock=clock_a)
    assert "run_metrics" in missing and str(tmp_path) not in json.dumps(missing["profile_duplicates"])


def test_envelope_has_exactly_the_wiring_keys(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")
    contract = load_submodule("audit.contract")
    for home in (tmp_path / "missing", tmp_path):
        res = mod.audit_profile_duplicates(home)
        assert set(res) == {"profile_duplicates", "findings", "run_metrics", "status", "coverage"}, home
        assert res["status"] in {"pass", "fail"}
        adapted = contract.adapt_component_result(res, component_id="profile_duplicates", affected_identities=["x"])
        assert adapted["profile_duplicates"] == res["profile_duplicates"]
        assert adapted["run_metrics"] == res["run_metrics"]
        assert adapted["coverage"] == res["coverage"] and adapted["operational_error"] is None


def test_profile_names_safe_pattern_and_list_caps(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.profile_duplicates")
    monkeypatch.setattr(mod, "MAX_NAMES_LISTED", 3)
    names = ["e1", "e2", "e3", "e4", "e5", "bad name", "x" * 65, "ok.name-1"]
    for name in names:
        (tmp_path / "profiles" / name).mkdir(parents=True)
    res = mod.audit_profile_duplicates(tmp_path)
    sec = res["profile_duplicates"]
    text = json.dumps(res)
    assert "bad name" not in text and "x" * 65 not in text
    assert sec["profile_count"] == 8
    assert sec["unsafe_profile_name_count"] == 2
    assert sec["empty_profiles"]["count"] == 8
    assert len(sec["empty_profiles"]["paths"]) == 3 and len(sec["profiles"]) == 3
    assert len(sec["no_config_profiles"]["paths"]) == 3
    assert sec["limits"]["max_names_listed"] == 3
    monkeypatch.setattr(mod, "MAX_NAMES_LISTED", 50)
    full = mod.audit_profile_duplicates(tmp_path)["profile_duplicates"]
    listed = _names([r["path"] for r in full["profiles"]])
    # Unsafe names are counted, never listed (not even as a placeholder).
    assert sorted(listed) == ["e1", "e2", "e3", "e4", "e5", "ok.name-1"]
    assert full["empty_profiles"]["count"] == 8 and len(full["empty_profiles"]["paths"]) == 6
    fam_names = json.dumps(full["profile_families"])
    assert "bad" not in fam_names
    assert res["coverage"] == "verified"


def test_time_budget_checked_between_chunks_keeps_partial_results(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.profile_duplicates")
    monkeypatch.setattr(mod, "HASH_CHUNK_BYTES", 1024)
    big = b"\x7fELF" + b"B" * (3 * 1024 * 1024)
    small = b"\x7fELF" + b"S" * (1024 * 1024)
    for idx in range(1, 4):
        p = tmp_path / "profiles" / f"p{idx}"
        (p / "bin").mkdir(parents=True)
        (p / "bin" / "big").write_bytes(big)
        (p / "bin" / "small").write_bytes(small)
    reads = {"n": 0}
    real_read = os.read

    def counting_read(fd, n):
        reads["n"] += 1
        return real_read(fd, n)

    monkeypatch.setattr(os, "read", counting_read)
    # Clock jumps past the budget once the 4th big-file chunk has been read (mid-file, first file).
    clock = lambda: 0.0 if reads["n"] < 4 else 1000.0
    res = mod.audit_profile_duplicates(tmp_path, clock=clock)
    sec = res["profile_duplicates"]
    assert sec["truncated_by"] == "time_budget"
    assert res["coverage"] == "could_not_verify"
    assert reads["n"] < 10, "hashing must stop between chunks, not at file end"
    assert sec["profile_count"] == 3 and sec["profiles_total_bytes"] == 3 * (len(big) + len(small))
    assert sec["limits"]["cuts"] >= 1


def test_stop_cap_named_even_after_earlier_exclusion_and_read_error_does_not_abort_bucket(
    tmp_path: Path, monkeypatch
) -> None:
    mod = load_submodule("audit.profile_duplicates")
    blob = b"\x7fELF" + b"C" * (1024 * 1024)
    for idx in range(1, 5):
        p = tmp_path / "profiles" / f"p{idx}"
        (p / "bin").mkdir(parents=True)
        (p / "bin" / "tool").write_bytes(blob)
    (tmp_path / "profiles" / "p1" / "lnk").symlink_to("/")
    (tmp_path / "profiles" / "p1" / "bin" / "tool").chmod(0o000)
    try:
        res = mod.audit_profile_duplicates(tmp_path)
    finally:
        (tmp_path / "profiles" / "p1" / "bin" / "tool").chmod(0o644)
    sec = res["profile_duplicates"]
    assert _groups(sec)[("executable_file", "bin")]["copies"] == 3
    assert "symlink_refused" in sec["cut_reasons"] and "read_error" in sec["cut_reasons"]
    with monkeypatch.context() as m:
        m.setattr(mod, "MAX_FILES_HASHED", 1)
        res2 = mod.audit_profile_duplicates(tmp_path)
    assert res2["profile_duplicates"]["truncated_by"] == "files_hashed_limit"


def test_readonly_on_0555_home_and_hostile_inputs(tmp_path: Path) -> None:
    import sqlite3

    mod = load_submodule("audit.profile_duplicates")
    home = tmp_path / "h"
    for idx in range(1, 4):
        p = home / "profiles" / f"p{idx}"
        (p / "memories").mkdir(parents=True)
        (p / "memories" / "MEMORY.md").write_bytes(b"\xff\xfe\x00junk\n" * 3)
        (p / "state.db").write_bytes(b"")
        (p / "projects.db").write_bytes(b"SQLite format 3\x00")
        os.mkfifo(p / "fifo.db")
        (p / ("bad\udcffname".encode("utf-8", "surrogateescape").decode("utf-8", "surrogateescape"))).write_bytes(b"x")
        con = sqlite3.connect(str(p / "views.db"))
        con.execute("create table x(a)")
        con.execute("create view sessions as select 1")
        con.commit()
        con.close()
    (home / "profiles" / "afile").write_text("not a dir", encoding="utf-8")
    (home / "profiles" / "p1" / "memories" / "USER.md").mkdir()
    (home / "profiles" / "p2" / "loop").symlink_to("loop")
    dirs = [d for d, _, _ in os.walk(home)]
    before = _snapshot_tree(home)
    for d in dirs:
        os.chmod(d, 0o555)
    try:
        res = mod.audit_profile_duplicates(home)
    finally:
        for d in dirs:
            os.chmod(d, 0o755)
    assert _snapshot_tree(home) == before
    assert res["profile_duplicates"]["status"] == "completed"
    assert res["coverage"] == "could_not_verify"
    json.dumps(res)
    file_as_home = tmp_path / "plainfile"
    file_as_home.write_text("x", encoding="utf-8")
    r2 = mod.audit_profile_duplicates(file_as_home)
    assert r2["profile_duplicates"]["reason"] == "invalid_profile_root"


def test_healthy_home_has_no_findings_above_info(tmp_path: Path) -> None:
    """Fresh profiles get the same default SOUL.md, a placeholder .env and the same bundled skills from Hermes
    (hermes_cli/profiles_initialization.py:39-48, hermes_cli/profiles.py:1451): none of that is a finding."""
    mod = load_submodule("audit.profile_duplicates")
    default_soul = "You are a helpful default agent persona.\nBe direct.\n"
    for idx, name in enumerate(("work", "home", "research"), start=1):
        p = tmp_path / "profiles" / name
        (p / "memories").mkdir(parents=True)
        (p / "config.yaml").write_text(f"model: m{idx}\n", encoding="utf-8")
        (p / ".env").write_text("# placeholder\n", encoding="utf-8")
        (p / "SOUL.md").write_text(default_soul, encoding="utf-8")
        (p / "memories" / "MEMORY.md").write_text(f"Profile {name} keeps its own notes {idx}.\n", encoding="utf-8")
        for skill in ("alpha", "beta", "gamma"):
            (p / "skills" / skill).mkdir(parents=True)
            (p / "skills" / skill / "SKILL.md").write_text(f"---\nname: {skill}\n---\nStock text.\n", encoding="utf-8")
        (p / "skills" / ".hub").mkdir()
        (p / "skills" / ".hub" / "lock.json").write_text("{}\n", encoding="utf-8")
        (p / "state.db").write_bytes(f"db-{idx}".encode("utf-8").ljust(8192, b"\x00"))
        (p / "logs").mkdir()
        (p / "logs" / "agent.log").write_text("ok\n", encoding="utf-8")
    res = mod.audit_profile_duplicates(tmp_path)
    assert res["coverage"] == "verified"
    assert [f["id"] for f in res["findings"] if f["classification"] != "info"] == []
    soul = res["profile_duplicates"]["cloned_identity"]["by_kind"]["SOUL.md"]
    assert soul["identical_group_sizes"] == [3]  # still measured, just not a finding


def test_unreadable_profile_is_not_counted_empty_and_credential_root_is_reported(tmp_path: Path) -> None:
    mod = load_submodule("audit.profile_duplicates")
    home = tmp_path / "h"
    for name in ("a", "b", "c"):
        (home / "profiles" / name / "sub").mkdir(parents=True)
    os.chmod(home / "profiles" / "b" / "sub", 0)
    os.chmod(home / "profiles" / "c", 0)
    try:
        res = mod.audit_profile_duplicates(home)
    finally:
        os.chmod(home / "profiles" / "b" / "sub", 0o755)
        os.chmod(home / "profiles" / "c", 0o755)
    sec = res["profile_duplicates"]
    assert res["coverage"] == "could_not_verify"
    assert _names(sec["empty_profiles"]["paths"]) == ["a"]
    assert "unreadable_directory" in sec["cut_reasons"]

    cred_home = tmp_path / "backups" / "h"
    (cred_home / "profiles" / "p1").mkdir(parents=True)
    res2 = mod.audit_profile_duplicates(cred_home)
    assert res2["coverage"] == "could_not_verify"
    assert res2["profile_duplicates"]["truncated_by"] == "credential_root_refused"


def test_doc_lists_every_rule_and_exact_consequence():
    from tests.test_audit_dead_stores import _doc_contains, _doc_rule_rows, _doc_words
    w = _wiring()
    doc = (Path(__file__).resolve().parents[1] / "docs/audit-sections/profile_duplicates.md").read_text(encoding="utf-8")
    rows = _doc_rule_rows(doc, w["rule_ids"])
    for rid, row in rows.items():
        classification = row.get("classification", row.get("class"))
        assert _doc_words(classification) == _doc_words(w["classifications"][rid][0]), rid
        assert _doc_words(row["consequence"]) == _doc_words(w["consequences"][rid]), rid
    for key in w["schema_keys"]:
        _doc_contains(doc, key)
    for value in w["vocabulary"]:
        _doc_contains(doc, value)
    mod = load_submodule("audit.profile_duplicates")
    assert w["consequences"] == mod.FINDING_CONSEQUENCES
    _doc_contains(doc, "Sizes are file sizes, not unique disk blocks; on filesystems with shared blocks duplicate totals are an upper bound")
    _doc_contains(doc, "Symlinks (to files or folders) are never followed and their targets are not measured")
    for caveat in ("named_profile_given", "HOME ROOT", "access times may change"):
        _doc_contains(doc, caveat)


def test_consequences_are_fixed_sentences_without_numbers_or_verdict_words() -> None:
    mod = load_submodule("audit.profile_duplicates")
    assert set(mod.FINDING_CONSEQUENCES) == {
        "profile_duplicates.repeated_binary", "profile_duplicates.identical_files",
        "profile_duplicates.cloned_identity_files", "profile_duplicates.per_profile_caches",
        "profile_duplicates.empty_profiles", "profile_duplicates.could_not_verify",
    }
    assert not hasattr(mod, "_cloned_identity_consequence")
    banned = ("indicat", "suggest", "unpruned", "abandon", "you ", "you'", "leftover", "waste")
    for text in mod.FINDING_CONSEQUENCES.values():
        low = text.casefold()
        assert not any(word in low for word in banned), text
        assert not re.search(r"\b\d+ profiles\b", text), text


def test_identical_files_trigger_excludes_regenerable_cache_bytes(tmp_path: Path) -> None:
    """Four profiles each holding the same ~41 MB hub index cache is normal: only per_profile_caches (info)."""
    mod = load_submodule("audit.profile_duplicates")
    hub = b'{"index": [' + b"h" * (41 * 1000 * 1000) + b"]}"
    cache_home = tmp_path / "cache_only"
    for idx in range(1, 5):
        p = cache_home / "profiles" / f"p{idx}"
        (p / "skills" / ".hub" / "index-cache").mkdir(parents=True)
        (p / "skills" / ".hub" / "index-cache" / "hermes-index.json").write_bytes(hub)
    res = mod.audit_profile_duplicates(cache_home)
    sec = res["profile_duplicates"]
    ids = {f["id"] for f in res["findings"]}
    assert sec["total_wasted_bytes"] == 3 * len(hub)
    assert sec["total_wasted_bytes"] > mod.IDENTICAL_FILES_WASTED_BYTES_THRESHOLD
    assert sec["cache_duplicate_wasted_bytes"] == 3 * len(hub)
    assert sec["wasted_bytes_excluding_caches"] == 0
    assert "profile_duplicates.identical_files" not in ids
    assert "profile_duplicates.per_profile_caches" in ids
    assert [g["regenerable_cache"] for g in sec["top_duplicate_groups"]] == [True]

    # A real (non-cache) duplicate above the threshold still fires next to the same caches.
    blob = b"D" * (36 * 1000 * 1000)
    for idx in range(1, 5):
        (cache_home / "profiles" / f"p{idx}" / "plans").mkdir()
        (cache_home / "profiles" / f"p{idx}" / "plans" / "dataset.bin").write_bytes(blob)
    res2 = mod.audit_profile_duplicates(cache_home)
    sec2 = res2["profile_duplicates"]
    by_id = {f["id"]: f for f in res2["findings"]}
    assert sec2["wasted_bytes_excluding_caches"] == 3 * len(blob)
    f_ident = by_id["profile_duplicates.identical_files"]
    assert f_ident["evidence"]["wasted_bytes_excluding_caches"] == 3 * len(blob)
    assert f_ident["evidence"]["cache_duplicate_wasted_bytes"] == 3 * len(hub)
    assert f_ident["evidence"]["wasted_bytes"] == 3 * (len(blob) + len(hub))


def _noatime_home(root: Path) -> Path:
    blob = b"\x7fELF" + b"N" * (1024 * 1024)
    for idx in range(1, 4):
        prof = root / "profiles" / f"n{idx}"
        (prof / "bin").mkdir(parents=True)
        (prof / "bin" / "tool").write_bytes(blob)
        (prof / "memories").mkdir()
        (prof / "memories" / "MEMORY.md").write_text("same memory\n", encoding="utf-8")
    return root


def test_reads_try_o_noatime_first(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.profile_duplicates")
    if not getattr(os, "O_NOATIME", 0):
        return  # platform without O_NOATIME: covered by the fallback tests below
    _noatime_home(tmp_path)
    flags_seen: list[int] = []
    real_os_open = os.open

    def spy(path, flags, *args, **kwargs):
        flags_seen.append(flags)
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    res = mod.audit_profile_duplicates(tmp_path)
    monkeypatch.undo()
    assert flags_seen and all(f & os.O_NOATIME for f in flags_seen)
    assert ("executable_file", "bin") in _groups(res["profile_duplicates"])


def test_o_noatime_permission_error_falls_back_cleanly(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.profile_duplicates")
    _noatime_home(tmp_path)
    noatime = getattr(os, "O_NOATIME", 0) or 0o1000000
    monkeypatch.setattr(os, "O_NOATIME", noatime, raising=False)
    real_os_open = os.open
    refused: list[str] = []

    def not_owner(path, flags, *args, **kwargs):
        if flags & noatime:
            refused.append(os.fsdecode(path))
            raise PermissionError(1, "Operation not permitted")
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", not_owner)
    res = mod.audit_profile_duplicates(tmp_path)
    monkeypatch.undo()
    sec = res["profile_duplicates"]
    assert refused, "O_NOATIME was not attempted"
    assert res["coverage"] == "verified" and "read_error" not in sec["cut_reasons"]
    assert _groups(sec)[("executable_file", "bin")]["copies"] == 3
    assert sec["cloned_identity"]["identical_profiles_count"] == 3


def test_missing_o_noatime_attribute_uses_plain_read(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.profile_duplicates")
    _noatime_home(tmp_path)
    monkeypatch.delattr(os, "O_NOATIME", raising=False)
    res = mod.audit_profile_duplicates(tmp_path)
    monkeypatch.undo()
    assert res["coverage"] == "verified"
    assert _groups(res["profile_duplicates"])[("executable_file", "bin")]["copies"] == 3


# --- wiring: sealing tests against audit/wiring/profile_duplicates.json ------------------------------------------

_WIRING_PATH = Path(__file__).resolve().parents[1] / "audit" / "wiring" / "profile_duplicates.json"
# The only non-vocabulary strings: absolute paths of existing folders (a profile folder, or a first-level folder
# inside one). The report serializer keeps an existing absolute path unchanged.
_FREE_SECTION_KEYS = frozenset({"path", "paths", "location"})


def _wiring() -> dict:
    return json.loads(_WIRING_PATH.read_text(encoding="utf-8"))


def _depth_below_profiles(value: str) -> int | None:
    """1 for `<home>/profiles/<name>`, 2 for `<home>/profiles/<name>/<folder>`, else None."""
    parts = Path(value).parts
    for depth in (1, 2):
        if len(parts) > depth + 1 and parts[-depth - 1] == "profiles":
            return depth
    return None


def _is_kept_folder_path(value) -> bool:
    return (
        isinstance(value, str) and os.path.isabs(value) and os.path.isdir(value) and not os.path.islink(value)
        and os.path.realpath(value) == value and _depth_below_profiles(value) is not None
    )


def _rich_home(root: Path, *, symlink: bool = True, canary: str = "", top: str = "data") -> Path:
    """One synthetic home that reaches every finding and every section shape."""
    exe = b"\x7fELF" + b"E" * (1024 * 1024 + 4)
    plain = b"P" * (1024 * 1024 + 8)
    hub = b'{"i": "' + b"h" * (1024 * 1024) + b'"}'
    memory = f"Remember the build order {canary}.\nPrefer small steps.\n"
    for name in ("qa-alpha", "qa-beta", "qa-gamma"):
        p = root / "profiles" / name
        for sub in ("bin", top, "memories", "skills/.hub/index-cache", "skills/tool-skill", "mcp-tokens"):
            (p / sub).mkdir(parents=True, exist_ok=True)
        (p / "bin" / "tool").write_bytes(exe)
        (p / top / "blob.bin").write_bytes(plain)
        (p / "skills" / ".hub" / "index-cache" / "hermes-index.json").write_bytes(hub)
        (p / "skills" / "tool-skill" / "SKILL.md").write_text(f"---\nname: tool-skill\n---\n{canary}\n", encoding="utf-8")
        (p / "memories" / "MEMORY.md").write_text(memory, encoding="utf-8")
        (p / "memories" / "USER.md").write_text(f"Role: builder {canary}\n", encoding="utf-8")
        (p / "SOUL.md").write_text(f"Default soul {canary}\n", encoding="utf-8")
        (p / "models_dev_cache.json").write_bytes(b'{"m": 1}\n' * 20)
        (p / "provider_models_cache.json").write_bytes(b'{"p": 1}\n' * 20)
        (p / "config.yaml").write_text(f"model: {canary or 'm'}\n", encoding="utf-8")
        (p / "config.yaml.bak-1").write_text(f"model: {canary or 'm'}\n", encoding="utf-8")
        (p / ".env").write_text("K=placeholder\n", encoding="utf-8")
        (p / "mcp-tokens" / "srv.json").write_text('{"t": "x"}\n', encoding="utf-8")
        (p / "state.db").write_bytes(f"db-{name}".encode("utf-8").ljust(4096, b"\x00"))
    for idx in range(1, 5):
        (root / "profiles" / f"t{idx}").mkdir(parents=True)
        (root / "profiles" / f"t{idx}" / "config.yaml").write_text("model: m\n", encoding="utf-8")
    for idx in range(1, 6):
        (root / "profiles" / f"e{idx}").mkdir(parents=True)
    for name in ("logs-a", "logs-b"):
        (root / "profiles" / name / "logs").mkdir(parents=True)
        (root / "profiles" / name / "logs" / "agent.log").write_text("ok\n", encoding="utf-8")
    bad = root / "profiles" / "bad name"
    (bad / "memories").mkdir(parents=True)
    (bad / "memories" / "MEMORY.md").write_text(memory, encoding="utf-8")
    (root / "profiles" / ".deleted").mkdir(parents=True)
    (root / "models_dev_cache.json").write_bytes(b"M" * (1024 * 1024 + 16))
    (root / "profiles" / "t1" / "models_dev_cache.json").write_bytes(b"M" * (1024 * 1024 + 16))
    if symlink:
        (root / "profiles" / "t2" / "lnk").symlink_to("/")
        os.mkfifo(root / "profiles" / "t3" / "pipe")
    return root


def _low_thresholds(mod, m) -> None:
    m.setattr(mod, "MIN_REPEATED_BINARY_BYTES", 1024 * 1024)
    m.setattr(mod, "IDENTICAL_FILES_WASTED_BYTES_THRESHOLD", 1024 * 1024)
    m.setattr(mod, "PER_PROFILE_CACHE_BYTES_THRESHOLD", 1024 * 1024)


def _build_homes(tmp_path: Path) -> None:
    _rich_home(tmp_path / "rich")
    _rich_home(tmp_path / "clean", symlink=False)
    (tmp_path / "plainfile").write_text("x", encoding="utf-8")
    (tmp_path / "backups" / "h" / "profiles" / "p1").mkdir(parents=True)
    (tmp_path / "pfile").mkdir()
    (tmp_path / "pfile" / "profiles").write_text("x", encoding="utf-8")


def _run_all(tmp_path: Path, monkeypatch) -> list[dict]:
    """Every branch, on homes already built by `_build_homes` (so a second call re-audits the same homes)."""
    mod = load_submodule("audit.profile_duplicates")
    out: list[dict] = []
    with monkeypatch.context() as m:
        _low_thresholds(mod, m)
        out.append(mod.audit_profile_duplicates(tmp_path / "rich"))
        out.append(mod.audit_profile_duplicates(tmp_path / "clean"))
        for name, value in (("MAX_ENTRIES", 5), ("MAX_FILES_HASHED", 1), ("MAX_BYTES_HASHED", 1024), ("MAX_DEPTH", 0),
                            ("MAX_IDENTITY_FILES", 1), ("MAX_IDENTITY_FILE_BYTES", 4), ("MAX_NAMES_LISTED", 2)):
            with monkeypatch.context() as cap:
                cap.setattr(mod, name, value)
                out.append(mod.audit_profile_duplicates(tmp_path / "clean"))
        ticks = iter([0.0, 0.1, 0.2, 35.0])
        out.append(mod.audit_profile_duplicates(tmp_path / "clean", clock=lambda: next(ticks, 40.0)))
    out.append(mod.audit_profile_duplicates(tmp_path / "missing"))
    out.append(mod.audit_profile_duplicates(tmp_path / "plainfile"))
    out.append(mod.audit_profile_duplicates(tmp_path / "backups" / "h"))
    out.append(mod.audit_profile_duplicates(tmp_path / "pfile"))
    out.append(mod.audit_profile_duplicates(tmp_path / "clean" / "profiles" / "qa-alpha"))
    return out


def _all_envelopes(tmp_path: Path, monkeypatch) -> list[dict]:
    _build_homes(tmp_path)
    return _run_all(tmp_path, monkeypatch)


def _leaves(value, key=None):
    """Yield (parent_key, leaf) for every scalar; dict keys are yielded as ("<key>", key)."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield "<key>", k
            yield from _leaves(v, k)
    elif isinstance(value, list):
        for item in value:
            yield from _leaves(item, key)
    else:
        yield key, value


def test_wiring_json_shape_and_static_agreement_with_code() -> None:
    mod = load_submodule("audit.profile_duplicates")
    w = _wiring()
    assert set(w) == {
        "section", "entry", "kwargs", "schema_keys", "vocabulary", "numeric_evidence_keys", "vocab_evidence_keys",
        "rule_ids", "classifications", "consequences", "free_strings", "run_metrics_keys", "notes",
    }
    assert w["section"] == "profile_duplicates"
    assert w["entry"] == "audit.profile_duplicates.audit_profile_duplicates"
    assert w["schema_keys"] == sorted(set(w["schema_keys"])) and w["vocabulary"] == sorted(set(w["vocabulary"]))
    assert w["consequences"] == mod.FINDING_CONSEQUENCES
    assert w["rule_ids"] == list(mod.FINDING_CONSEQUENCES) and set(w["classifications"]) == set(w["rule_ids"])
    assert set(w["kwargs"]) == {"profile_path", "clock"}
    assert "named_profile_given" in w["kwargs"]["profile_path"]
    assert {f["key"] for f in w["free_strings"]} == _FREE_SECTION_KEYS | {"affected_identities", "source_paths.path"}
    assert all(set(f) == {"key", "what", "example", "why_safe"} for f in w["free_strings"])
    assert w["run_metrics_keys"] == ["elapsed_ms"]
    src = Path(mod.__file__).read_text(encoding="utf-8")
    literals = set(re.findall(r'(?:record_cut|not_measured)\("([a-z_]+)"[,)]', src))
    assert len(literals) == 24 and literals <= set(w["vocabulary"]) and "named_profile_given" in literals
    for token in (mod.SIZE_ONLY_OBSERVATION, mod.SIZE_ONLY_OTHER_CLASS, "cut_or_exclusion", "profile_duplicates",
                  *mod.FILE_KINDS, *(label for _, label in mod._SIZE_ONLY_CLASSES)):
        assert token in w["vocabulary"], token
    assert "<unsafe-name>" not in w["vocabulary"] and not hasattr(mod, "UNSAFE_NAME_PLACEHOLDER")


def test_strict_walk_every_key_and_string_is_declared(tmp_path: Path, monkeypatch) -> None:
    w = _wiring()
    schema, vocab = set(w["schema_keys"]), set(w["vocabulary"])
    num_ev, vocab_ev = set(w["numeric_evidence_keys"]), set(w["vocab_evidence_keys"])
    seen_keys: set[str] = set()
    seen_rules: set[str] = set()
    seen_free: set[str] = set()
    envelopes = _all_envelopes(tmp_path, monkeypatch)
    for env in envelopes:
        assert set(env) == {"profile_duplicates", "findings", "run_metrics", "status", "coverage"}
        assert set(env["run_metrics"]) == set(w["run_metrics_keys"])
        for parent, leaf in _leaves({"profile_duplicates": env["profile_duplicates"]}):
            if parent == "<key>":
                assert leaf in schema, leaf
                seen_keys.add(leaf)
            elif isinstance(leaf, str):
                if leaf not in vocab:
                    # Every other string is the absolute path of an existing profile folder or first-level folder.
                    assert parent in _FREE_SECTION_KEYS and _is_kept_folder_path(leaf), (parent, leaf)
                    seen_free.add(parent)
            else:
                assert leaf is None or type(leaf) in (int, float, bool), (parent, leaf)
        for finding in env["findings"]:
            rid = finding["id"]
            seen_rules.add(rid)
            assert rid in w["rule_ids"]
            assert finding["classification"] in w["classifications"][rid]
            assert finding["consequence"] == w["consequences"][rid]
            for ident in finding["affected_identities"] + [sp["path"] for sp in finding["source_paths"]]:
                assert os.path.isabs(ident) and os.path.isdir(ident) and os.path.realpath(ident) == ident, ident
            for key, value in finding["evidence"].items():
                assert key in schema, key
                seen_keys.add(key)
                if isinstance(value, str):
                    assert key in vocab_ev and value in vocab, (key, value)
                else:
                    assert key in num_ev and type(value) in (int, float, bool), (key, value)
    assert seen_rules == set(w["rule_ids"])
    assert seen_free == _FREE_SECTION_KEYS
    # Tight, not just complete: every declared key is actually emitted by some branch.
    assert seen_keys == schema, sorted(schema ^ seen_keys)


def _patched_sealing(monkeypatch, w):
    evidence = load_submodule("audit.evidence")
    persistence = load_submodule("audit.persistence")
    constants = load_submodule("audit.evidence_constants")
    rules = frozenset(w["rule_ids"])
    sentences = frozenset(w["consequences"].values())
    vocab = evidence.VOCABULARY | frozenset(w["vocabulary"]) | rules | sentences
    monkeypatch.setattr(evidence, "SCHEMA_KEYS", frozenset(evidence.SCHEMA_KEYS) | frozenset(w["schema_keys"]))
    monkeypatch.setattr(evidence, "VOCABULARY", vocab)
    monkeypatch.setattr(persistence, "VOCABULARY", vocab)
    monkeypatch.setattr(persistence, "_EVIDENCE_NUMERIC_KEYS",
                        persistence._EVIDENCE_NUMERIC_KEYS | frozenset(w["numeric_evidence_keys"]))
    monkeypatch.setattr(persistence, "_EVIDENCE_VOCAB_KEYS",
                        persistence._EVIDENCE_VOCAB_KEYS | frozenset(w["vocab_evidence_keys"]))
    allowed = frozenset(constants.ALLOWED_FINDING_CONSEQUENCES) | sentences
    merged = {**dict(constants.FINDING_CONSEQUENCES), **w["consequences"]}
    for module in (persistence, constants, evidence):
        monkeypatch.setattr(module, "ALLOWED_FINDING_CONSEQUENCES", allowed, raising=False)
        monkeypatch.setattr(module, "FINDING_CONSEQUENCES", merged, raising=False)
    monkeypatch.setattr(constants, "RULE_IDS", frozenset(constants.RULE_IDS) | rules)
    monkeypatch.setattr(evidence, "RULE_IDS", frozenset(constants.RULE_IDS) | rules, raising=False)
    return evidence, persistence, vocab


def _seal(env: dict, evidence, persistence) -> tuple[dict, list[dict], dict]:
    """The report path: adapt_component_result, then serialize_evidence (section) and finding_dto (findings)."""
    contract = load_submodule("audit.contract")
    adapted = contract.adapt_component_result(env, component_id="profile_duplicates", affected_identities=[])
    sealed = evidence.serialize_evidence({"profile_duplicates": adapted["profile_duplicates"]})
    return adapted, sealed, [persistence.finding_dto(f) for f in adapted["findings"]]


def _hmac_dicts(value) -> list:
    found = []
    if isinstance(value, dict):
        if "hmac" in value or any(isinstance(k, str) and k.startswith("hmac:") for k in value):
            found.append(value)
        for v in value.values():
            found.extend(_hmac_dicts(v))
    elif isinstance(value, list):
        for v in value:
            found.extend(_hmac_dicts(v))
    return found


def _compare_sealed(raw, sealed, key, vocab, outcomes) -> None:
    if isinstance(raw, dict):
        assert isinstance(sealed, dict) and set(sealed) == set(raw), (key, sorted(set(raw) ^ set(sealed or {})))
        for k in raw:
            _compare_sealed(raw[k], sealed[k], k, vocab, outcomes)
    elif isinstance(raw, list):
        assert isinstance(sealed, list) and len(sealed) == len(raw), key
        for r, s in zip(raw, sealed):
            _compare_sealed(r, s, key, vocab, outcomes)
    elif isinstance(raw, str):
        # Nothing is tokenised: vocabulary strings and kept absolute folder paths come back unchanged.
        assert sealed == raw, (key, raw, sealed)
        outcomes.setdefault(key, set()).add("vocabulary" if raw in vocab else "kept_path")
    else:
        assert sealed == raw and type(sealed) is type(raw), (key, raw, sealed)


def test_sealing_round_trip_keeps_everything_with_wiring_sets(tmp_path: Path, monkeypatch) -> None:
    w = _wiring()
    envelopes = _all_envelopes(tmp_path, monkeypatch)
    evidence, persistence, vocab = _patched_sealing(monkeypatch, w)
    outcomes: dict[str, set[str]] = {}
    for env in envelopes:
        adapted, sealed, dtos = _seal(env, evidence, persistence)
        assert adapted["profile_duplicates"] == env["profile_duplicates"]
        assert adapted["run_metrics"] == env["run_metrics"]
        assert adapted["operational_error"] is None and adapted["coverage"] == env["coverage"]
        _compare_sealed({"profile_duplicates": adapted["profile_duplicates"]}, sealed, None, vocab, outcomes)
        for finding, dto in zip(adapted["findings"], dtos):
            rid = finding["id"]
            assert dto["id"] == rid
            assert dto["consequence"] == w["consequences"][rid] == dto["detail"]
            assert dto["classification"] == finding["classification"] and dto["coverage"] == finding["coverage"]
            ev = {k: v for k, v in dto["evidence"].items() if k != "source_digest"}
            assert ev == finding["evidence"], sorted(set(ev) ^ set(finding["evidence"]))
            # Identities and source paths are existing absolute folders: returned unchanged.
            assert dto["affected_identities"] == finding["affected_identities"]
            assert [sp["path"] for sp in dto["source_paths"]] == [sp["path"] for sp in finding["source_paths"]]
        assert _hmac_dicts(sealed) == [] and _hmac_dicts(dtos) == []
    for key in _FREE_SECTION_KEYS:
        assert outcomes[key] == {"kept_path"}, (key, outcomes.get(key))


def test_no_hmac_token_anywhere_in_sealed_output(tmp_path: Path, monkeypatch) -> None:
    envelopes = _all_envelopes(tmp_path, monkeypatch)
    evidence, persistence, _ = _patched_sealing(monkeypatch, _wiring())
    for env in envelopes:
        _, sealed, dtos = _seal(env, evidence, persistence)
        assert _hmac_dicts(sealed) == [], _hmac_dicts(sealed)[:3]
        assert _hmac_dicts(dtos) == [], _hmac_dicts(dtos)[:3]


def test_two_runs_on_the_same_home_seal_identically(tmp_path: Path, monkeypatch) -> None:
    """Each serialize_evidence call uses a fresh per-run key; any token would make the two runs differ."""
    _build_homes(tmp_path)
    first = _run_all(tmp_path, monkeypatch)
    second = _run_all(tmp_path, monkeypatch)
    evidence, persistence, _ = _patched_sealing(monkeypatch, _wiring())
    assert len(first) == len(second)
    sealed_runs = []
    for run in (first, second):
        sealed_runs.append([
            json.dumps({"section": sealed, "findings": dtos}, sort_keys=True)
            for _, sealed, dtos in (_seal(env, evidence, persistence) for env in run)
        ])
    assert sealed_runs[0] == sealed_runs[1]


def test_live_sealing_sets_keep_the_section(tmp_path: Path, monkeypatch) -> None:
    """The live (unpatched) sets now include the sheet: keys and sentences survive without monkeypatching."""
    evidence = load_submodule("audit.evidence")
    persistence = load_submodule("audit.persistence")
    mod = load_submodule("audit.profile_duplicates")
    with monkeypatch.context() as m:
        _low_thresholds(mod, m)
        env = mod.audit_profile_duplicates(_rich_home(tmp_path / "rich", symlink=False))
    sealed = evidence.serialize_evidence({"profile_duplicates": env["profile_duplicates"]})
    assert set(_wiring()["schema_keys"]) <= set(evidence.SCHEMA_KEYS)
    assert set(sealed) == {"profile_duplicates"}
    assert set(sealed["profile_duplicates"]) == set(env["profile_duplicates"])
    assert env["findings"]
    assert all(persistence.finding_dto(f)["consequence"] == f["consequence"] for f in env["findings"])
    assert all(s in persistence.ALLOWED_FINDING_CONSEQUENCES for s in mod.FINDING_CONSEQUENCES.values())


def test_canaries_reach_sealed_output_only_inside_kept_folder_paths(tmp_path: Path, monkeypatch) -> None:
    import sqlite3

    mod = load_submodule("audit.profile_duplicates")
    w = _wiring()
    content = "CANARYCONTENTQZ"
    name_canary = "CANARYNAMEQZ"
    top_canary = "CANARYTOPQZ"
    home = _rich_home(tmp_path / "canary", symlink=False, canary=content, top=top_canary)
    p = home / "profiles" / name_canary
    deep = p / "work" / "CANARYDEEPQZ" / "inner"
    deep.mkdir(parents=True)
    (deep / "CANARYFILEQZ.db").write_bytes(b"SQLite format 3\x00" + content.encode() * 64)
    (p / "config.yaml").write_text(f"api_key: {content}\nmodel: {content}\n", encoding="utf-8")
    (p / ".env.CANARYSUFFIXQZ").write_text(f"K={content}\n", encoding="utf-8")
    (p / "memories").mkdir()
    (p / "memories" / "MEMORY.md").write_text(f"{content}\n", encoding="utf-8")
    for prof in ("qa-alpha", "qa-beta", "qa-gamma"):
        sub = home / "profiles" / prof / top_canary / "CANARYDEEPQZ"
        sub.mkdir(parents=True)
        (sub / "CANARYFILEQZ.bin").write_bytes(b"F" * (1024 * 1024 + 32))
        con = sqlite3.connect(str(home / "profiles" / prof / "rows.db"))
        con.execute("create table t(v)")
        con.execute("insert into t values (?)", (content,))
        con.commit()
        con.close()
    with monkeypatch.context() as m:
        _low_thresholds(mod, m)
        env = mod.audit_profile_duplicates(home)
    raw_text = json.dumps(env)
    for never in (content, "CANARYDEEPQZ", "CANARYFILEQZ", "CANARYSUFFIXQZ"):
        assert never not in raw_text, never
    evidence, persistence, _ = _patched_sealing(monkeypatch, w)
    _, sealed, dtos = _seal(env, evidence, persistence)
    seen = {name_canary: set(), top_canary: set()}
    for parent, leaf in _leaves({"s": sealed, "f": dtos, "m": env["run_metrics"]}):
        if isinstance(leaf, str) and "CANARY" in leaf:
            # Only inside a kept absolute path, and only as a profile folder or a first-level folder inside one.
            assert parent in _FREE_SECTION_KEYS and _is_kept_folder_path(leaf), (parent, leaf)
            rel = Path(leaf).relative_to(home / "profiles").parts
            assert len(rel) in (1, 2) and all("CANARY" not in part or part in seen for part in rel), leaf
            for part in rel:
                if part in seen:
                    seen[part].add(len(rel))
    assert seen[name_canary] == {1}  # the canary profile folder itself
    assert seen[top_canary] == {2}  # the first-level folder holding the duplicated copies
    for never in (content, "CANARYDEEPQZ", "CANARYFILEQZ", "CANARYSUFFIXQZ"):
        assert never not in json.dumps([sealed, dtos]), never


def test_executable_kind_is_emitted_as_executable_file():
    """'executable' is a sealed plain value in the report; the emitted file kind is executable_file."""
    mod = load_submodule("audit.profile_duplicates")
    assert mod._file_kind("bin/tool", True) == "executable_file"
    assert "executable" not in mod.FILE_KINDS and "executable_file" in mod.FILE_KINDS
