"""Home workdirs tests never consult a real Hermes home."""
import builtins
import hashlib
import io
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from tests.conftest import load_submodule


def _hash_tree(root: Path) -> str:
    """Hash the complete recursive directory listing + file contents + mtimes of root."""
    hasher = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        hasher.update(f"D:{rel_dir}\n".encode("utf-8"))
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            st = os.lstat(p)
            hasher.update(
                f"E:{rel}:{st.st_mode}:{st.st_size}:{st.st_mtime_ns}\n".encode("utf-8")
            )
            if p.is_symlink():
                hasher.update(f"L:{os.readlink(p)}\n".encode("utf-8"))
            elif p.is_file():
                hasher.update(p.read_bytes())
    return hasher.hexdigest()


def test_positive_work_folders_huge_files_working_trees_and_nested_homes(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "hermes_home"
    home.mkdir()

    # Hermes-owned entries
    (home / "config.yaml").write_text("model: test\n", encoding="utf-8")
    (home / "SOUL.md").write_text("You are Hermes.\n", encoding="utf-8")
    (home / "skills" / "my-skill").mkdir(parents=True)
    (home / "skills" / "my-skill" / "SKILL.md").write_text("skill\n", encoding="utf-8")
    # .git inside skills/ must NOT be counted as working-tree .git
    (home / "skills" / "my-skill" / ".git").mkdir()
    (home / "plugins" / "my-plugin" / ".git").mkdir(parents=True)

    # Not-owned top-level work folder 1: plans/
    plans = home / "plans"
    plans.mkdir()
    t1 = datetime(2026, 8, 15, tzinfo=timezone.utc).timestamp()
    t2 = datetime(2026, 9, 10, tzinfo=timezone.utc).timestamp()
    f_plan = plans / "category-migration-20260907-very-long-folder-name-exceeding-forty-characters" / "deep" / "run.stdout"
    f_plan.parent.mkdir(parents=True)
    f_plan.write_bytes(b"x" * 2048)
    os.utime(f_plan, (t1, t1))

    # Nested Hermes home inside plans/
    nested = plans / "fixture-1" / ".hermes"
    nested.mkdir(parents=True)
    (nested / "config.yaml").write_text("{}\n", encoding="utf-8")
    (nested / "auth.json").write_text('{"secret": "DO_NOT_READ"}\n', encoding="utf-8")
    os.utime(nested / "config.yaml", (t2, t2))
    os.utime(nested / "auth.json", (t2, t2))

    # Real named profile under profiles/ must NOT be counted as nested Hermes home
    prof = home / "profiles" / "coder"
    prof.mkdir(parents=True)
    (prof / "config.yaml").write_text("{}\n", encoding="utf-8")
    (prof / "state.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 84)
    (prof / "skills").mkdir()

    # Not-owned top-level work folder 2: tmp/ with virtualenv, source tree, node_modules, .git, archive+extracted, ELF executable
    tmp_dir = home / "tmp"
    tmp_dir.mkdir()
    venv_dir = tmp_dir / "my-venv"
    venv_dir.mkdir()
    (venv_dir / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (venv_dir / "bin").mkdir()
    elf_bin = venv_dir / "bin" / "ruff"
    elf_bin.write_bytes(b"\x7fELF" + b"\x00" * 100)

    src_copy = tmp_dir / "repo-copy"
    src_copy.mkdir()
    (src_copy / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (src_copy / "subpkg").mkdir()
    # Nested package.json inside src_copy must not double-count src_copy
    (src_copy / "subpkg" / "package.json").write_text("{}\n", encoding="utf-8")
    (src_copy / "node_modules" / "pkg").mkdir(parents=True)
    (src_copy / "node_modules" / "pkg" / "index.js").write_bytes(b"a" * 500)
    (src_copy / ".git").mkdir()
    (src_copy / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    # Archive sitting next to extracted folder of the same stem
    (tmp_dir / "release-pack.tar.gz").write_bytes(b"z" * 400)
    (tmp_dir / "release-pack").mkdir()
    (tmp_dir / "release-pack" / "readme.txt").write_bytes(b"r" * 100)

    before_hash = _hash_tree(home)
    res = mod.audit_home_workdirs(
        profile_path=home, huge_file_threshold_bytes=1024, hermes_folder_other_bytes_threshold=1024,
    )
    after_hash = _hash_tree(home)
    assert before_hash == after_hash

    assert res["coverage"] == "verified"
    sec = res["home_workdirs"]
    assert sec["status"] == "completed"
    assert sec["coverage"] == "verified"

    # `plans/` is a folder Hermes creates (hermes_cli/profiles.py:40): never "not Hermes".
    by_name = {os.path.basename(entry["path"]): entry for entry in sec["not_hermes_folders"]}
    assert all(entry["path"] == os.path.join(os.path.realpath(home), os.path.basename(entry["path"]))
               and entry["path_withheld"] is None for entry in sec["not_hermes_folders"])
    assert set(by_name) == {"tmp"}
    plans_rec = {e["name"]: e for e in sec["hermes_folders_holding_work_output"]}
    assert set(plans_rec) == {"plans"}
    # UTC year-month as an integer YYYYMM (a number survives the sealed report; a date string would not).
    assert plans_rec["plans"]["oldest_year_month"] == 202608
    assert plans_rec["plans"]["newest_year_month"] == 202609
    assert "oldest_mtime" not in plans_rec["plans"]
    assert by_name["tmp"]["oldest_year_month"] is not None and type(by_name["tmp"]["oldest_year_month"]) is int
    assert plans_rec["plans"]["file_count"] == 3
    assert plans_rec["plans"]["other_kind_files"] == 3

    # Huge file check (threshold lowered to 1024 B)
    huge = sec["huge_files"]
    assert len(huge) == 1
    assert huge[0]["size_bytes"] == 2048
    assert huge[0]["extension_class"] == "text_like"
    # Privacy path cap: at most two components below the home; a component over 40 characters
    # withholds the path (the long folder name here) instead of truncating it.
    assert huge[0]["path"] is None
    assert huge[0]["path_withheld"] == "long_name"

    # Working trees check
    wt = sec["working_trees"]
    assert wt["virtualenv_count"] == 1
    assert wt["virtualenv_bytes"] == (venv_dir / "pyvenv.cfg").stat().st_size + 104
    assert wt["source_tree_count"] == 1
    assert wt["node_modules_count"] == 1
    assert wt["node_modules_bytes"] == 500
    assert wt["git_dir_count"] == 1
    assert wt["archive_count"] == 1
    assert wt["archive_bytes"] == 400
    assert wt["archives_beside_extracted_count"] == 1
    assert wt["executable_count"] == 1
    assert wt["executable_bytes"] == 104

    # Nested Hermes homes check
    assert sec["nested_hermes_homes"]["count"] == 1

    # Totals check
    totals = sec["totals"]
    assert totals["total_home_bytes"] == totals["hermes_named_bytes"] + totals["not_hermes_bytes"]
    assert totals["not_hermes_share"] > 0.20

    # Findings check
    rule_ids = {f["id"] for f in res["findings"]}
    assert {
        "home_workdirs.work_folders_in_home",
        "home_workdirs.huge_files",
        "home_workdirs.working_trees_in_home",
        "home_workdirs.nested_hermes_homes",
        "home_workdirs.oversized_hermes_folders",
    } <= rule_ids


def test_negative_normal_fresh_home_and_do_not_flag_cases(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "normal_home"
    home.mkdir()

    # Normal fresh home + cache/ + bin/ with a few tool binaries + profiles/* + rotated logs + empty unknown folder
    (home / "config.yaml").write_text("model: default\n", encoding="utf-8")
    (home / "SOUL.md").write_text("Persona\n", encoding="utf-8")
    (home / "state.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 4000)
    (home / "cache" / "scratch").mkdir(parents=True)
    (home / "cache" / "scratch" / "temp.bin").write_bytes(b"c" * 10000)
    (home / "bin").mkdir()
    (home / "bin" / "uv").write_bytes(b"\x7fELF" + b"\x00" * 1000)
    (home / "bin" / "scanner").write_bytes(b"\x7fELF" + b"\x00" * 1000)
    (home / "logs").mkdir()
    (home / "logs" / "gateway.log.1").write_bytes(b"l" * 2000)
    (home / "logs" / "errors.log.2").write_bytes(b"e" * 2000)
    (home / "profiles" / "alpha").mkdir(parents=True)
    (home / "profiles" / "alpha" / "config.yaml").write_text("{}\n", encoding="utf-8")
    (home / "profiles" / "alpha" / "skills").mkdir()
    (home / "profiles" / "alpha" / "bin").mkdir()
    (home / "profiles" / "alpha" / "bin" / "scanner").write_bytes(b"\x7fELF" + b"\x00" * 500)

    # An empty unknown folder at top level must not flag
    (home / "empty_unknown_dir").mkdir()

    res = mod.audit_home_workdirs(profile_path=home)
    assert res["coverage"] == "verified"
    assert res["findings"] == []
    sec = res["home_workdirs"]
    assert sec["huge_files"] == []
    assert sec["nested_hermes_homes"]["count"] == 0
    assert sec["totals"]["not_hermes_bytes"] == 0


def test_credential_files_never_opened_and_symlinks_not_followed(tmp_path, monkeypatch):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "home"
    home.mkdir()

    # Plant credential files that look like executables (>4 bytes) or huge files
    (home / ".env").write_bytes(b"\x7fELF_SECRET_ENV_VALUE")
    (home / "auth.json").write_bytes(b"\x7fELF_SECRET_AUTH_VALUE")
    (home / "mcp-tokens").mkdir()
    (home / "mcp-tokens" / "token.json").write_bytes(b"\x7fELF_SECRET_TOKEN")
    (home / "plans").mkdir()
    (home / "plans" / "my_secret_key.pem").write_bytes(b"\x7fELF_SECRET_PEM")

    # Outside target for symlinks
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "outside_exe"
    outside_file.write_bytes(b"\x7fELF" + b"O" * 1000)
    (home / "plans" / "sym_dir").symlink_to(outside, target_is_directory=True)
    (home / "plans" / "sym_file").symlink_to(outside_file)

    opened_paths = []
    orig_os_open = os.open
    orig_builtins_open = builtins.open
    orig_io_open = io.open

    def track_os_open(path, flags, mode=0o777, *, dir_fd=None):
        p_str = os.fsdecode(path)
        opened_paths.append(p_str)
        return orig_os_open(path, flags, mode, dir_fd=dir_fd)

    def track_b_open(file, *args, **kwargs):
        if not isinstance(file, int):
            opened_paths.append(os.fsdecode(file))
        return orig_builtins_open(file, *args, **kwargs)

    def track_i_open(file, *args, **kwargs):
        if not isinstance(file, int):
            opened_paths.append(os.fsdecode(file))
        return orig_io_open(file, *args, **kwargs)

    monkeypatch.setattr(os, "open", track_os_open)
    monkeypatch.setattr(builtins, "open", track_b_open)
    monkeypatch.setattr(io, "open", track_i_open)

    res = mod.audit_home_workdirs(profile_path=home)
    for p in opened_paths:
        assert ".env" not in p
        assert "auth.json" not in p
        assert "mcp-tokens" not in p
        assert ".pem" not in p
        assert "outside" not in p
        assert "sym_file" not in p

    sec = res["home_workdirs"]
    assert sec["working_trees"]["executable_count"] == 0
    assert sec["symlinks_skipped"] >= 2


def test_canary_privacy_and_missing_or_empty_home(tmp_path):
    mod = load_submodule("audit.home_workdirs")

    # Missing home
    missing_res = mod.audit_home_workdirs(profile_path=tmp_path / "nonexistent")
    assert missing_res["coverage"] == "could_not_verify"
    assert missing_res["home_workdirs"]["status"] == "not_measured"

    # Empty home
    empty = tmp_path / "empty"
    empty.mkdir()
    empty_res = mod.audit_home_workdirs(profile_path=empty)
    assert empty_res["coverage"] == "verified"
    assert empty_res["findings"] == []

    # Canary check
    home = tmp_path / "canary_home"
    home.mkdir()
    (home / "memories").mkdir()
    (home / "memories" / "MEMORY.md").write_text("CANARY_MEMORY_SECRET_TEXT\n", encoding="utf-8")
    deep_dir = home / "plans" / "sub1" / "CANARY_DEEP_COMPONENT_NAME"
    deep_dir.mkdir(parents=True)
    huge_f = deep_dir / "CANARY_FILENAME_SECRET.json"
    huge_f.write_bytes(b"CANARY_FILE_CONTENT_SECRET " * 100)

    res = mod.audit_home_workdirs(profile_path=home, huge_file_threshold_bytes=100)
    dumped = json.dumps(res)
    assert "CANARY_MEMORY_SECRET_TEXT" not in dumped
    assert "CANARY_DEEP_COMPONENT_NAME" not in dumped
    assert "CANARY_FILENAME_SECRET" not in dumped
    assert "CANARY_FILE_CONTENT_SECRET" not in dumped


@pytest.mark.parametrize("cap_kind", ["max_entries", "max_depth", "max_magic_reads", "max_seconds"])
def test_caps_and_truncation_paths(tmp_path, cap_kind):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "capped_home"
    home.mkdir()
    work = home / "plans" / "a" / "b" / "c"
    work.mkdir(parents=True)
    for i in range(5):
        (work / f"bin_{i}").write_bytes(b"\x7fELF" + b"\x00" * 50)

    kwargs = {"profile_path": home}
    if cap_kind == "max_entries":
        kwargs["max_entries"] = 2
    elif cap_kind == "max_depth":
        kwargs["max_depth"] = 2
    elif cap_kind == "max_magic_reads":
        kwargs["max_magic_reads"] = 2
    elif cap_kind == "max_seconds":
        ticks = [0.0]

        def clock():
            ticks[0] += 15.0
            return ticks[0]

        kwargs["clock"] = clock
        kwargs["max_seconds"] = 20.0

    res = mod.audit_home_workdirs(**kwargs)
    assert res["coverage"] == "could_not_verify"
    sec = res["home_workdirs"]
    assert sec["coverage"] == "could_not_verify"
    assert sec["limits"]["cuts"] > 0
    assert sec["truncated_by"] == cap_kind
    assert any(f["id"] == "home_workdirs.could_not_verify" for f in res["findings"])


def test_malformed_inputs_and_executable_magics(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "malformed_home"
    home.mkdir()

    # Broken JSON, binary junk, Mach-O and PE 'MZ' executables, symlinked home root refusal
    work = home / "work_output"
    work.mkdir()
    (work / "config.yaml").write_bytes(b"\xff\xfe: broken: yaml: [[[")
    (work / "pyproject.toml").write_bytes(b"\x00\xff\x80 invalid toml")
    (work / "package.json").write_text("{broken json", encoding="utf-8")
    (work / "macho_bin").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
    (work / "pe_bin.exe").write_bytes(b"MZ" + b"\x90" * 60)
    (work / "tiny").write_bytes(b"MZ")  # < 4 bytes, skipped safely

    res = mod.audit_home_workdirs(profile_path=home)
    assert res["coverage"] == "verified"
    wt = res["home_workdirs"]["working_trees"]
    assert wt["executable_count"] == 2
    assert wt["executable_bytes"] == 64 + 62
    assert wt["source_tree_count"] == 1

    # Symlinked profile root itself is refused as invalid_home_root
    sym_root = tmp_path / "sym_root"
    sym_root.symlink_to(home, target_is_directory=True)
    sym_res = mod.audit_home_workdirs(profile_path=sym_root)
    assert sym_res["coverage"] == "could_not_verify"
    assert sym_res["home_workdirs"]["status"] == "not_measured"
    assert sym_res["home_workdirs"]["reason"] == "invalid_home_root"



def _clean_home(home: Path) -> None:
    """A careful user's healthy home: Hermes folders holding only what Hermes puts there."""
    (home / "config.yaml").write_text("model: default\n", encoding="utf-8")
    (home / "skills" / "s").mkdir(parents=True)
    (home / "skills" / "s" / "SKILL.md").write_text("s\n", encoding="utf-8")
    (home / "plans").mkdir()
    (home / "plans" / "2026-01-02_030405-tidy.md").write_bytes(b"p" * 3000)
    (home / "tools" / "node-gen" / "bin").mkdir(parents=True)
    (home / "tools" / "facts.json").write_text("{}\n", encoding="utf-8")
    (home / "tools" / "node-gen" / "bin" / "node").write_bytes(b"\x7fELF" + b"\x00" * 4000)
    (home / "tools" / "node-gen" / "node_modules" / "npm").mkdir(parents=True)
    (home / "tools" / "node-gen" / "node_modules" / "npm" / "package.json").write_text("{}\n", encoding="utf-8")
    (home / "venvs" / "hermes").mkdir(parents=True)
    (home / "venvs" / "hermes" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (home / "venvs" / "hermes" / "lib.bin").write_bytes(b"v" * 4000)
    env = home / "installs" / "g1" / "environments" / "e1" / "venv"
    env.mkdir(parents=True)
    (env / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (home / "hermes-agent" / ".git").mkdir(parents=True)
    (home / "hermes-agent" / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (home / "state.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 9000)
    (home / "state.db-wal").write_bytes(b"\x00" * 9000)


def test_hermes_named_folders_are_separate_from_not_hermes_folders(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "h"
    home.mkdir()
    (home / "config.yaml").write_text("{}\n", encoding="utf-8")
    (home / "plans" / "run-1").mkdir(parents=True)
    (home / "plans" / "2026-01-02_030405-ok.md").write_bytes(b"m" * 100)
    (home / "plans" / "run-1" / "out.stdout").write_bytes(b"o" * 5000)
    (home / "tools" / "browser").mkdir(parents=True)  # no facts.json: not the pm store layout
    (home / "tools" / "browser" / "chrome.pak").write_bytes(b"c" * 4000)
    (home / "venvs" / "a").mkdir(parents=True)
    (home / "venvs" / "a" / "pyvenv.cfg").write_text("x\n", encoding="utf-8")
    (home / "venvs" / "a" / "big").write_bytes(b"v" * 9000)
    (home / "tmp").mkdir()
    (home / "tmp" / "x.log").write_bytes(b"t" * 3000)
    (home / "dbtmp").mkdir()
    (home / "dbtmp" / "copy.db").write_bytes(b"d" * 10)

    res = mod.audit_home_workdirs(
        home, hermes_folder_other_bytes_threshold=1000, work_folders_bytes_threshold=1000,
    )
    sec = res["home_workdirs"]
    assert [e["path"] for e in sec["not_hermes_folders"]] == [str(home.resolve() / "tmp"), str(home.resolve() / "dbtmp")]
    hf = {e["name"]: e for e in sec["hermes_folders_holding_work_output"]}
    assert set(hf) == {"plans", "tools"}
    assert hf["plans"]["expected_kind_bytes"] == 100
    assert hf["plans"]["other_kind_bytes"] == 5000
    assert hf["plans"]["expectation"] == "markdown_plans_at_folder_root"
    assert hf["tools"]["other_kind_bytes"] == 4000
    assert hf["tools"]["expectation"] == "pm_tool_store_with_facts_json"
    assert hf["tools"]["layout_marker_present"] is False
    totals = sec["totals"]
    assert totals["not_hermes_bytes"] == 3010
    assert totals["hermes_folders_other_kind_bytes"] == 9000
    by_id = {f["id"]: f for f in res["findings"]}
    assert by_id["home_workdirs.work_folders_in_home"]["consequence"] == mod.CONSEQUENCE_WORK_FOLDERS
    assert "does not create" not in mod.CONSEQUENCE_WORK_FOLDERS
    over = by_id["home_workdirs.oversized_hermes_folders"]
    assert over["classification"] == "review_suggested"
    assert over["consequence"] == mod.CONSEQUENCE_OVERSIZED_HERMES_FOLDERS
    assert over["evidence"]["folder_count"] == 2
    assert over["evidence"]["other_kind_bytes"] == 9000


def test_healthy_home_with_hermes_folders_has_no_findings_above_info(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "h"
    home.mkdir()
    _clean_home(home)
    res = mod.audit_home_workdirs(
        home, huge_file_threshold_bytes=5000, hermes_folder_other_bytes_threshold=1000,
        work_folders_bytes_threshold=1000,
    )
    sec = res["home_workdirs"]
    assert res["coverage"] == "verified"
    assert res["findings"] == []
    assert sec["not_hermes_folders"] == []
    assert sec["hermes_folders_holding_work_output"] == []
    wt = sec["working_trees"]
    # venvs/<name> (hermes_constants.py:1374) and installs/ (pm store) are Hermes layouts.
    assert wt["virtualenv_count"] == 0
    assert wt["node_modules_count"] == 0 and wt["git_dir_count"] == 0 and wt["source_tree_count"] == 0


def test_hermes_databases_listed_apart_from_huge_files(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "h"
    home.mkdir()
    (home / "state.db").write_bytes(b"s" * 6000)
    (home / "kanban.db-wal").write_bytes(b"k" * 50)
    (home / "cron").mkdir()
    (home / "cron" / "executions.db").write_bytes(b"e" * 70)
    (home / "profiles" / "coder").mkdir(parents=True)
    (home / "profiles" / "coder" / "state.db").write_bytes(b"p" * 5500)
    (home / "kanban" / "boards" / "_archived" / "old").mkdir(parents=True)
    (home / "kanban" / "boards" / "_archived" / "old" / "kanban.db").write_bytes(b"a" * 30)
    (home / "kanban" / "boards" / "b1").mkdir(parents=True)
    (home / "kanban" / "boards" / "b1" / "kanban.db-shm").write_bytes(b"a" * 20)
    (home / "kanban" / "boards" / "b1" / "notes.db").write_bytes(b"n" * 5)
    res = mod.audit_home_workdirs(home, huge_file_threshold_bytes=5000)
    sec = res["home_workdirs"]
    assert sec["huge_files"] == []
    assert not any(f["id"] == "home_workdirs.huge_files" for f in res["findings"])
    dbs = sec["hermes_databases"]
    assert dbs["count"] == 6
    assert dbs["bytes"] == 6000 + 50 + 70 + 5500 + 30 + 20
    root = str(home.resolve())
    assert [d["path"] for d in dbs["files"]] == [os.path.join(root, rel) for rel in (
        "state.db", "profiles/coder/state.db", "cron/executions.db", "kanban.db-wal",
        "kanban/boards/_archived/old/kanban.db", "kanban/boards/b1/kanban.db-shm",
    )]
    assert {d["path_withheld"] for d in dbs["files"]} == {None}
    assert sec["totals"]["hermes_database_bytes"] == dbs["bytes"]

    # A database-named file inside a work folder is not Hermes's store: it stays a huge file.
    (home / "plans" / "fixture").mkdir(parents=True)
    (home / "plans" / "fixture" / "state.db").write_bytes(b"f" * 7000)
    res2 = mod.audit_home_workdirs(home, huge_file_threshold_bytes=5000)
    huge = res2["home_workdirs"]["huge_files"]
    assert [(h["path"], h["extension_class"]) for h in huge] == [(str(home.resolve() / "plans" / "fixture"), "database")]
    assert res2["home_workdirs"]["hermes_databases"]["count"] == 6


def test_nested_home_counts_config_with_marker_and_config_only(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "h"
    home.mkdir()
    for rel, marker in [("plans/a/.hermes", "state.db"), ("tmp/b", "SOUL.md"), ("plans/c", None),
                        ("profiles/coder", "state.db"), ("plugins/p", "plugin.yaml"),
                        # Hermes's own copies: quick snapshots, pre-update backups, tombstones.
                        ("state-snapshots/20260101", "state.db"), ("backups/b1", "SOUL.md"),
                        ("profiles/coder/state-snapshots/s1", "state.db"), ("profiles/.deleted/old", "SOUL.md")]:
        d = home / rel
        d.mkdir(parents=True)
        (d / "config.yaml").write_text("{}\n", encoding="utf-8")
        if marker:
            (d / marker).write_bytes(b"")
    nested = mod.audit_home_workdirs(home)["home_workdirs"]["nested_hermes_homes"]
    assert nested == {"count": 2, "config_with_marker": 2, "config_only": 1}


def test_result_is_identical_under_clocks_days_apart(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "h"
    home.mkdir()
    _clean_home(home)
    (home / "tmp").mkdir()
    (home / "tmp" / "big.json").write_bytes(b"j" * 9000)

    def ticking(start: float, step: float):
        state = [start]

        def clock():
            state[0] += step
            return state[0]
        return clock

    first = mod.audit_home_workdirs(home, huge_file_threshold_bytes=5000, clock=ticking(1_000.0, 0.0001))
    second = mod.audit_home_workdirs(
        home, huge_file_threshold_bytes=5000, clock=ticking(1_000.0 + 9 * 86_400, 0.003),
    )
    assert json.dumps(first["home_workdirs"], sort_keys=True) == json.dumps(second["home_workdirs"], sort_keys=True)
    assert json.dumps(first["findings"], sort_keys=True) == json.dumps(second["findings"], sort_keys=True)
    assert first["findings"]
    # Run time lives only in the sibling `run_metrics`, never inside the digested section.
    assert first["run_metrics"]["elapsed_ms"] != second["run_metrics"]["elapsed_ms"]
    assert "elapsed_ms" not in json.dumps(first["home_workdirs"])
    first.pop("run_metrics")
    second.pop("run_metrics")
    assert first == second


def test_envelope_has_exactly_the_wiring_keys(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "h"
    home.mkdir()
    _clean_home(home)
    wanted = {"home_workdirs", "findings", "run_metrics", "status", "coverage"}
    for res in (mod.audit_home_workdirs(home), mod.audit_home_workdirs(tmp_path / "absent")):
        assert set(res) == wanted
        assert set(res["run_metrics"]) == {"elapsed_ms"}
        assert type(res["run_metrics"]["elapsed_ms"]) is int and res["run_metrics"]["elapsed_ms"] >= 0
        assert res["status"] == "pass"
        assert res["coverage"] == res["home_workdirs"]["coverage"]


def test_token_secret_credential_named_files_never_opened(tmp_path, monkeypatch):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "h"
    home.mkdir()
    names = ["api_token", "client_secret", "my_credential", "id_ed25519", ".env.bak-1", "secrets.yaml"]
    for base in [home, home / "tmp" / "a", home / "plans" / "p" / "deep"]:
        base.mkdir(parents=True, exist_ok=True)
        for n in names:
            (base / n).write_bytes(b"\x7fELF" + b"\x00" * 80)
            os.chmod(base / n, 0o755)
    opened = []
    real = os.open

    def track(path, flags, mode=0o777, *, dir_fd=None):
        opened.append(os.fsdecode(path))
        return real(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", track)
    res = mod.audit_home_workdirs(home)
    monkeypatch.undo()
    assert [p for p in opened if os.path.basename(p) in names] == []
    assert res["home_workdirs"]["working_trees"]["executable_count"] == 0


def test_time_budget_keeps_partial_numbers(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    home = tmp_path / "h"
    home.mkdir()
    (home / "tmp").mkdir()
    for i in range(40):
        (home / "tmp" / f"f{i:02d}").write_bytes(b"x" * 10)
    ticks = [0.0]

    def clock():
        ticks[0] += 1.0
        return ticks[0]

    sec = mod.audit_home_workdirs(home, clock=clock, max_seconds=30.0)["home_workdirs"]
    assert sec["truncated_by"] == "max_seconds"
    assert sec["coverage"] == "could_not_verify"
    assert 0 < sec["totals"]["total_home_bytes"] < 400


def test_non_utf8_names_and_invalid_profile_path_values(tmp_path):
    mod = load_submodule("audit.home_workdirs")
    for value in (None, 5, "a\x00b"):
        res = mod.audit_home_workdirs(value)
        assert res["home_workdirs"]["status"] == "not_measured"
        assert res["home_workdirs"]["reason"] == "invalid_home_root"
    home = tmp_path / "h"
    home.mkdir()
    bad = os.fsdecode(b"w\xffork")
    os.makedirs(os.path.join(home, bad, os.fsdecode(b"s\xfeub")))
    with open(os.path.join(home, bad, os.fsdecode(b"s\xfeub"), "f"), "wb") as fh:
        fh.write(b"x" * 5000)
    res = mod.audit_home_workdirs(home, work_folders_bytes_threshold=10, huge_file_threshold_bytes=100)
    json.dumps(res, ensure_ascii=False).encode("utf-8")  # no lone surrogates anywhere
    sec = res["home_workdirs"]
    assert sec["not_hermes_folders"][0]["path"] is None
    assert sec["not_hermes_folders"][0]["path_withheld"] == "undecodable_name"
    assert sec["huge_files"][0]["path"] is None
    assert sec["huge_files"][0]["path_withheld"] == "undecodable_name"



# --- Wiring sheet (audit/wiring/home_workdirs.json) and sealing ------------------------------------

_WIRING_PATH = Path(__file__).resolve().parents[1] / "audit" / "wiring" / "home_workdirs.json"
_FINDING_FIELDS = {
    "id", "classification", "coverage", "affected_identities", "source_paths", "evidence",
    "consequence", "limitations", "proposed_cleanup_id", "severity", "detail", "fix",
}
_UNREACHABLE_VOCABULARY = {"io_error"}  # defensive fallback, documented in the sheet's notes


def _wiring() -> dict:
    return json.loads(_WIRING_PATH.read_text(encoding="utf-8"))


def _rich_home(home: Path) -> None:
    """Every reachable branch of a completed walk in one synthetic home."""
    home.mkdir()
    (home / "config.yaml").write_text("model: test\n", encoding="utf-8")
    (home / "SOUL.md").write_text("persona\n", encoding="utf-8")
    # Root entries of every kind that is not Hermes-named.
    (home / "notes.txt").write_bytes(b"n" * 10)
    (home / "link").symlink_to(home / "SOUL.md")
    os.mkfifo(home / "pipe")
    tmp = home / "tmp"
    (tmp / "my-venv" / "bin").mkdir(parents=True)
    (tmp / "my-venv" / "pyvenv.cfg").write_text("x\n", encoding="utf-8")
    (tmp / "my-venv" / "bin" / "tool").write_bytes(b"\x7fELF" + b"\x00" * 60)
    (tmp / "repo" / "node_modules" / "p").mkdir(parents=True)
    (tmp / "repo" / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (tmp / "repo" / "node_modules" / "p" / "i.js").write_bytes(b"a" * 50)
    (tmp / "repo" / ".git").mkdir()
    (tmp / "repo" / ".git" / "HEAD").write_text("ref\n", encoding="utf-8")
    (tmp / "release-pack").mkdir()
    (tmp / "release-pack.zip").write_bytes(b"z" * 40)
    (tmp / "pkg" / "dl").mkdir(parents=True)
    (tmp / "pkg" / "dl" / "pkg-1.0.tar.xz").write_bytes(b"x" * 30)
    # Huge files of every extension class.
    (tmp / "big.json").write_bytes(b"j" * 2000)
    (tmp / "big.tar.gz").write_bytes(b"g" * 2000)
    (tmp / "pic.png").write_bytes(b"p" * 2000)
    (tmp / "elfbig").write_bytes(b"\x7fELF" + b"\x00" * 2000)
    (tmp / "copy.db").write_bytes(b"d" * 2000)
    (tmp / "blob.dat").write_bytes(b"o" * 2000)
    (tmp / ("long-" + "n" * 45 + ".json")).write_bytes(b"L" * 2000)  # over the 40-character cap
    (home / "api_token_dump").mkdir()  # credential-named folder: listed, path never shown
    (home / "api_token_dump" / "x").write_bytes(b"t" * 10)
    # Hermes-named folders holding other-kind bytes (all three expectations).
    (home / "plans" / "run").mkdir(parents=True)
    (home / "plans" / "2026-01-02_030405-plan.md").write_bytes(b"m" * 100)
    (home / "plans" / "run" / "out.stdout").write_bytes(b"s" * 5000)
    (home / "plans" / "a" / ".hermes").mkdir(parents=True)
    (home / "plans" / "a" / ".hermes" / "config.yaml").write_text("{}\n", encoding="utf-8")
    (home / "plans" / "a" / ".hermes" / "SOUL.md").write_text("x\n", encoding="utf-8")
    (home / "plans" / "c").mkdir()
    (home / "plans" / "c" / "config.yaml").write_text("{}\n", encoding="utf-8")
    (home / "tools" / "browser").mkdir(parents=True)
    (home / "tools" / "browser" / "chrome.pak").write_bytes(b"c" * 4000)
    (home / "venvs" / "a").mkdir(parents=True)
    (home / "venvs" / "a" / "pyvenv.cfg").write_text("x\n", encoding="utf-8")
    (home / "venvs" / "a" / "lib.bin").write_bytes(b"v" * 300)
    (home / "venvs" / "loose.bin").write_bytes(b"l" * 3000)
    # Hermes databases at the root, in a profile and on a kanban board.
    (home / "state.db").write_bytes(b"s" * 6000)
    (home / "profiles" / "coder").mkdir(parents=True)
    (home / "profiles" / "coder" / "config.yaml").write_text("{}\n", encoding="utf-8")
    (home / "profiles" / "coder" / "state.db").write_bytes(b"p" * 500)
    (home / "kanban" / "boards" / "b1").mkdir(parents=True)
    (home / "kanban" / "boards" / "b1" / "kanban.db").write_bytes(b"k" * 20)


_SMALL = {"huge_file_threshold_bytes": 1000, "work_folders_bytes_threshold": 1000,
          "hermes_folder_other_bytes_threshold": 1000}


class _VanishingEntry:
    """A scandir entry whose lstat fails, as when a file is removed mid-walk."""

    def __init__(self, entry):
        self._entry = entry
        self.name = entry.name
        self.path = entry.path

    def stat(self, *, follow_symlinks=True):
        raise FileNotFoundError(self.path)


class _ScandirWithVanishing:
    def __init__(self, real, path):
        self._ctx = real(path)

    def __enter__(self):
        it = self._ctx.__enter__()
        return (_VanishingEntry(e) if e.name == "vanishing" else e for e in it)

    def __exit__(self, *exc):
        return self._ctx.__exit__(*exc)


def _all_results(tmp_path, monkeypatch) -> list[dict]:
    """Envelopes covering every reachable branch: completed, every cut, every not_measured reason."""
    mod = load_submodule("audit.home_workdirs")
    results = []
    rich = tmp_path / "rich"
    _rich_home(rich)
    results.append(mod.audit_home_workdirs(rich, **_SMALL))
    clean = tmp_path / "clean"
    clean.mkdir()
    _clean_home(clean)
    results.append(mod.audit_home_workdirs(clean))
    for kwargs in ({"max_entries": 3}, {"max_depth": 1}, {"max_magic_reads": 1}):
        results.append(mod.audit_home_workdirs(rich, **_SMALL, **kwargs))
    ticks = [0.0]

    def clock():
        ticks[0] += 15.0
        return ticks[0]
    results.append(mod.audit_home_workdirs(rich, clock=clock, max_seconds=20.0))
    locked = tmp_path / "locked_home"
    locked.mkdir()
    (locked / "tmp").mkdir()
    (locked / "tmp" / "f").write_bytes(b"x")
    (locked / "closed").mkdir()
    os.chmod(locked / "closed", 0)
    try:
        results.append(mod.audit_home_workdirs(locked))
    finally:
        os.chmod(locked / "closed", 0o755)
    vanish = tmp_path / "vanish"
    vanish.mkdir()
    (vanish / "vanishing").write_bytes(b"x")
    real = os.scandir
    monkeypatch.setattr(os, "scandir", lambda path: _ScandirWithVanishing(real, path))
    results.append(mod.audit_home_workdirs(vanish))
    monkeypatch.setattr(os, "scandir", real)
    results.append(mod.audit_home_workdirs(tmp_path / "absent"))
    gate = tmp_path / "gate"
    gate.mkdir()
    os.chmod(gate, 0)
    try:
        results.append(mod.audit_home_workdirs(gate / "home"))
    finally:
        os.chmod(gate, 0o755)
    results.append(mod.audit_home_workdirs(None))
    results.append(mod.audit_home_workdirs(rich / "notes.txt"))
    odd = tmp_path / "odd"
    odd.mkdir()
    bad = os.fsdecode(b"w\xffork")
    os.makedirs(os.path.join(odd, bad))
    with open(os.path.join(odd, bad, "f"), "wb") as fh:
        fh.write(b"x" * 5000)
    results.append(mod.audit_home_workdirs(odd, **_SMALL))
    return results


def _walk(value, key, wiring, seen) -> None:
    free = {f["key"] for f in wiring["free_strings"]}
    if isinstance(value, dict):
        for k, v in value.items():
            assert k in wiring["schema_keys"], k
            seen["keys"].add(k)
            _walk(v, k, wiring, seen)
    elif isinstance(value, list):
        for item in value:
            _walk(item, key, wiring, seen)
    elif isinstance(value, str):
        if value in wiring["vocabulary"]:
            seen["vocab"].add(value)
        else:
            assert key in free, (key, value)
            seen["free"].add(key)
    else:
        assert value is None or type(value) in (int, float, bool), (key, value)


def _walk_finding(f, wiring, seen) -> None:
    assert set(f) == _FINDING_FIELDS
    rid = f["id"]
    assert rid in wiring["rule_ids"]
    assert f["classification"] in wiring["classifications"][rid]
    seen["rules"].setdefault(rid, set()).add(f["classification"])
    assert f["consequence"] == wiring["consequences"][rid] == f["detail"]
    assert f["limitations"] == "" and f["fix"] is None and f["proposed_cleanup_id"] is None
    for v in (f["classification"], f["coverage"], f["severity"]):
        assert v in wiring["vocabulary"], v
        seen["vocab"].add(v)
    for ident in f["affected_identities"]:
        assert type(ident) is str
        seen["free"].add("affected_identities")
    for sp in f["source_paths"]:
        assert set(sp) == {"path", "start_line", "end_line"}
        assert sp["start_line"] is None and sp["end_line"] is None
        assert type(sp["path"]) is str
        seen["free"].add("path")
    for k, v in f["evidence"].items():
        assert k in wiring["schema_keys"], k
        seen["keys"].add(k)
        if k in wiring["numeric_evidence_keys"]:
            assert type(v) in (int, float, bool), (k, v)
        else:
            assert k in wiring["vocab_evidence_keys"], k
            assert v in wiring["vocabulary"], (k, v)
            seen["vocab"].add(v)


def test_wiring_sheet_shape_matches_module():
    mod = load_submodule("audit.home_workdirs")
    wiring = _wiring()
    assert set(wiring) == {
        "section", "entry", "kwargs", "schema_keys", "vocabulary", "numeric_evidence_keys",
        "vocab_evidence_keys", "rule_ids", "classifications", "consequences", "free_strings",
        "run_metrics_keys", "notes",
    }
    assert wiring["section"] == "home_workdirs"
    assert wiring["entry"] == "audit.home_workdirs.audit_home_workdirs"
    for name in ("schema_keys", "vocabulary", "numeric_evidence_keys", "vocab_evidence_keys", "rule_ids"):
        assert wiring[name] == sorted(set(wiring[name])), name
    rules = {getattr(mod, n): getattr(mod, "CONSEQUENCE_" + n[len("RULE_"):])
             for n in dir(mod) if n.startswith("RULE_")}
    assert wiring["consequences"] == rules
    assert set(wiring["rule_ids"]) == set(rules) == set(wiring["classifications"])
    assert all(r.startswith("home_workdirs.") for r in rules)
    import inspect
    params = inspect.signature(mod.audit_home_workdirs).parameters
    assert set(wiring["kwargs"]) == set(params)
    assert wiring["run_metrics_keys"] == ["elapsed_ms"]
    for item in wiring["free_strings"]:
        assert set(item) == {"key", "what", "example", "why_safe"}
    # Fixed sentences only: no numbers, names or the words the tone rules exclude.
    for sentence in wiring["consequences"].values():
        assert not re.search(r"\d|\{|\byou\b|indicat|suggest|unpruned|abandon", sentence, re.I), sentence


def test_wiring_sheet_is_complete_for_every_reachable_output(tmp_path, monkeypatch):
    wiring = _wiring()
    seen = {"keys": set(), "vocab": set(), "free": set(), "rules": {}}
    for res in _all_results(tmp_path, monkeypatch):
        assert set(res) == {"home_workdirs", "findings", "status", "coverage", "run_metrics"}
        assert set(res["run_metrics"]) == set(wiring["run_metrics_keys"])
        for v in (res["status"], res["coverage"]):
            assert v in wiring["vocabulary"]
            seen["vocab"].add(v)
        seen["keys"].add("home_workdirs")
        seen["vocab"].add("home_workdirs")  # the component id the caller passes; sealed with the envelope
        _walk(res["home_workdirs"], "home_workdirs", wiring, seen)
        for f in res["findings"]:
            _walk_finding(f, wiring, seen)
    # Both directions: nothing emitted outside the sheet, nothing in the sheet that is never emitted.
    assert seen["keys"] == set(wiring["schema_keys"])
    assert seen["vocab"] == set(wiring["vocabulary"]) - _UNREACHABLE_VOCABULARY
    assert seen["free"] == {f["key"] for f in wiring["free_strings"]}
    assert {k: sorted(v) for k, v in seen["rules"].items()} == wiring["classifications"]


def _patch_sealing_sets(monkeypatch, wiring) -> dict:
    """The union of the current closed sets and this sheet, patched where the code reads them."""
    ev = load_submodule("audit.evidence")
    per = load_submodule("audit.persistence")
    ec = load_submodule("audit.evidence_constants")
    sentences = frozenset(wiring["consequences"].values())
    vocab = ev.VOCABULARY | frozenset(wiring["vocabulary"]) | frozenset(wiring["rule_ids"]) | sentences
    monkeypatch.setattr(ev, "SCHEMA_KEYS", ev.SCHEMA_KEYS | frozenset(wiring["schema_keys"]))
    monkeypatch.setattr(ev, "VOCABULARY", vocab)
    monkeypatch.setattr(per, "VOCABULARY", vocab)
    monkeypatch.setattr(per, "_EVIDENCE_NUMERIC_KEYS",
                        per._EVIDENCE_NUMERIC_KEYS | frozenset(wiring["numeric_evidence_keys"]))
    monkeypatch.setattr(per, "_EVIDENCE_VOCAB_KEYS",
                        per._EVIDENCE_VOCAB_KEYS | frozenset(wiring["vocab_evidence_keys"]))
    monkeypatch.setattr(per, "ALLOWED_FINDING_CONSEQUENCES", per.ALLOWED_FINDING_CONSEQUENCES | sentences)
    monkeypatch.setattr(per, "FINDING_CONSEQUENCES", {**per.FINDING_CONSEQUENCES, **wiring["consequences"]})
    monkeypatch.setattr(ec, "RULE_IDS", ec.RULE_IDS | frozenset(wiring["rule_ids"]))
    monkeypatch.setattr(ec, "FINDING_CONSEQUENCES", {**ec.FINDING_CONSEQUENCES, **wiring["consequences"]})
    monkeypatch.setattr(ec, "ALLOWED_FINDING_CONSEQUENCES", ec.ALLOWED_FINDING_CONSEQUENCES | sentences)
    return {"ev": ev, "per": per, "contract": load_submodule("audit.contract")}


def _has_hmac(value) -> bool:
    if isinstance(value, dict):
        return "hmac" in value or any(_has_hmac(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_hmac(v) for v in value)
    return False


def _path_outcome(original: str, sealed) -> str:
    assert sealed == original, (original, sealed)
    assert os.path.isabs(original) and os.path.lexists(original)
    return "kept_unchanged"


def _compare_section(orig, sealed, key, wiring, outcomes) -> None:
    if isinstance(orig, dict):
        assert isinstance(sealed, dict) and list(sealed) == list(orig), (key, sealed)
        for k in orig:
            _compare_section(orig[k], sealed[k], k, wiring, outcomes)
    elif isinstance(orig, list):
        assert isinstance(sealed, list) and len(sealed) == len(orig)
        for a, b in zip(orig, sealed):
            _compare_section(a, b, key, wiring, outcomes)
    elif isinstance(orig, str) and orig not in wiring["vocabulary"]:
        assert key == "path", (key, orig)
        outcomes.setdefault(key, set()).add(_path_outcome(orig, sealed))
    else:
        assert sealed == orig and type(sealed) is type(orig), (key, orig, sealed)


def test_sealing_keeps_every_key_number_label_and_sentence(tmp_path, monkeypatch):
    wiring = _wiring()
    results = _all_results(tmp_path, monkeypatch)
    mods = _patch_sealing_sets(monkeypatch, wiring)
    ev, per, contract = mods["ev"], mods["per"], mods["contract"]
    outcomes: dict[str, set] = {}
    for res in results:
        adapted = contract.adapt_component_result(res, component_id="home_workdirs", affected_identities=["default"])
        # adapt keeps the section and run_metrics untouched; findings re-normalize to the same dicts.
        assert adapted["home_workdirs"] is res["home_workdirs"]
        assert adapted["run_metrics"] == res["run_metrics"]
        assert adapted["coverage"] == res["coverage"]
        assert adapted["operational_error"] is None
        assert adapted["findings"] == res["findings"]
        report = per.strict_json(ev.serialize_evidence({"home_workdirs": adapted["home_workdirs"]}))
        _compare_section(res["home_workdirs"], report["home_workdirs"], "home_workdirs", wiring, outcomes)
        # Findings take the store path: component_dto -> finding_dto -> serialize_evidence.
        comp = per.component_dto(adapted)
        assert set(comp) == {"component_id", "coverage", "classification", "findings", "operational_error"}
        stored = per.strict_json(ev.serialize_evidence(contract.sort_findings(comp["findings"])))
        assert len(stored) == len(res["findings"])
        by_id = {f["id"]: f for f in stored}
        assert len(by_id) == len(stored)
        for f in res["findings"]:
            s = by_id[f["id"]]
            for k in ("classification", "coverage", "severity"):
                assert s[k] == f[k]
            assert s["consequence"] == s["detail"] == f["consequence"]
            assert {k: v for k, v in s["evidence"].items() if k != "source_digest"} == f["evidence"]
            assert len(s["affected_identities"]) == len(f["affected_identities"])
            for a, b in zip(f["affected_identities"], s["affected_identities"]):
                outcomes.setdefault("affected_identities", set()).add(_path_outcome(a, b))
            assert len(s["source_paths"]) == len(f["source_paths"])
            for a, b in zip(sorted(f["source_paths"], key=lambda x: x["path"]), s["source_paths"]):
                assert b["start_line"] is None and b["end_line"] is None
                outcomes.setdefault("path", set()).add(_path_outcome(a["path"], b["path"]))
    # The exact serializer outcome of each free string (recorded in the sheet's free_strings).
    assert outcomes == {
        "path": {"kept_unchanged"},
        "affected_identities": {"kept_unchanged"},
    }


def _seal(res, mods) -> tuple:
    ev, per, contract = mods["ev"], mods["per"], mods["contract"]
    adapted = contract.adapt_component_result(res, component_id="home_workdirs", affected_identities=["default"])
    section = per.strict_json(ev.EvidenceSerializer().serialize({"home_workdirs": adapted["home_workdirs"]}))
    comp = per.component_dto(adapted)
    findings = per.strict_json(ev.EvidenceSerializer().serialize(contract.sort_findings(comp["findings"])))
    return section, findings


def test_two_runs_give_identical_sealed_output_and_no_tokens(tmp_path, monkeypatch):
    """Each run seals with its own serializer key: any per-run token would make the runs differ."""
    wiring = _wiring()
    mod = load_submodule("audit.home_workdirs")
    results = _all_results(tmp_path, monkeypatch)
    mods = _patch_sealing_sets(monkeypatch, wiring)
    home = tmp_path / "rich"
    first = _seal(mod.audit_home_workdirs(home, **_SMALL), mods)
    second = _seal(mod.audit_home_workdirs(home, **_SMALL), mods)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first[0]["home_workdirs"]["not_hermes_folders"] and first[1]
    for res in results:
        section, findings = _seal(res, mods)
        assert not _has_hmac(section), section
        assert not _has_hmac(findings), findings


def test_canaries_reach_sealed_output_only_under_justified_free_strings(tmp_path, monkeypatch):
    wiring = _wiring()
    mod = load_submodule("audit.home_workdirs")
    top, second, deeper, fname = "CANARYTOPQ7", "CANARYSECONDQ7", "CANARYDEEPERQ7", "CANARYFILEQ7"
    content, config, dbrow = "CANARYCONTENTQ7", "CANARYCONFIGQ7", "CANARYDBROWQ7"
    profile, slug = "CANARYPROFILEQ7", "CANARYSLUGQ7"
    home = tmp_path / "h"
    home.mkdir()
    (home / "config.yaml").write_text(f"model: {config}\ndisplay:\n  skin: {config}\n", encoding="utf-8")
    (home / top / second / deeper).mkdir(parents=True)
    (home / top / f"{fname}.json").write_bytes((content + "\n").encode() * 200)
    (home / top / second / deeper / f"{fname}.log").write_bytes((content + "\n").encode() * 200)
    (home / "plans" / second / deeper).mkdir(parents=True)
    (home / "plans" / second / deeper / f"{fname}.stdout").write_bytes((content + "\n").encode() * 200)
    (home / "state.db").write_bytes(b"SQLite format 3\x00" + dbrow.encode() * 50)
    (home / "profiles" / profile).mkdir(parents=True)
    (home / "profiles" / profile / "config.yaml").write_text(f"model: {config}\n", encoding="utf-8")
    (home / "profiles" / profile / "state.db").write_bytes(dbrow.encode() * 50)
    (home / "kanban" / "boards" / slug).mkdir(parents=True)
    (home / "kanban" / "boards" / slug / "kanban.db").write_bytes(dbrow.encode() * 50)
    canaries = (top, second, deeper, fname, content, config, dbrow, profile, slug)

    res = mod.audit_home_workdirs(home, **_SMALL)
    free_keys = {f["key"] for f in wiring["free_strings"]}

    def hits(value, key, out):
        if isinstance(value, dict):
            for k, v in value.items():
                assert not any(c in k for c in canaries), k
                hits(v, k, out)
        elif isinstance(value, list):
            for v in value:
                hits(v, key, out)
        elif isinstance(value, str):
            for c in canaries:
                if c in value:
                    out.add((key, c))
        return out

    raw = hits({"s": res["home_workdirs"], "f": res["findings"], "m": res["run_metrics"]}, None, set())
    assert {k for k, _ in raw} <= free_keys
    # Contents, config values and database bytes never leave the home; huge-file paths stop at two
    # components, so the third-level folder never appears.
    assert {c for _, c in raw} == {top, second, fname, profile, slug}

    mods = _patch_sealing_sets(monkeypatch, wiring)
    ev, per, contract = mods["ev"], mods["per"], mods["contract"]
    adapted = contract.adapt_component_result(res, component_id="home_workdirs")
    sealed_section = per.strict_json(ev.serialize_evidence({"home_workdirs": adapted["home_workdirs"]}))
    sealed_findings = per.strict_json(ev.serialize_evidence(per.component_dto(adapted)))
    sealed = hits({"s": sealed_section, "f": sealed_findings}, None, set())
    # Names survive only inside kept absolute paths of existing items.
    assert sealed == {("path", c) for c in (top, second, fname, profile, slug)}
    assert not _has_hmac(sealed_section) and not _has_hmac(sealed_findings)



def test_doc_page_matches_rules_keys_and_labels():
    from tests.test_audit_dead_stores import _doc_contains, _doc_rule_rows, _doc_words
    w = _wiring()
    doc = (Path(__file__).resolve().parents[1] / "docs/audit-sections/home_workdirs.md").read_text(encoding="utf-8")
    rows = _doc_rule_rows(doc, w["rule_ids"])
    for rid, row in rows.items():
        classification = row.get("classification", row.get("class"))
        assert _doc_words(classification) == _doc_words(w["classifications"][rid][0]), rid
        assert _doc_words(row["consequence"]) == _doc_words(w["consequences"][rid]), rid
    for key in w["schema_keys"]:
        if key != "home_workdirs":
            _doc_contains(doc, key)
    for value in w["vocabulary"]:
        _doc_contains(doc, value)
    _doc_contains(doc, "Sizes are file sizes, not unique disk blocks")
    _doc_contains(doc, "Symlinks are never followed")


def test_executable_class_is_emitted_as_executable_file():
    """'executable' is a sealed plain value in the report; the emitted class label is executable_file."""
    mod = load_submodule("audit.home_workdirs")
    assert mod._classify_extension("tool", is_executable_magic=True) == "executable_file"
    assert mod._classify_extension("notes.md", is_executable_magic=False) == "text_like"
