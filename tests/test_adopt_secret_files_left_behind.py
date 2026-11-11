"""Tests for leaving secret-named files behind by default during adopt copy/run."""

from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import stat
import sys
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import applier, audit_summary, cli, placer, rules, safety, scanner  # noqa: E402

# Import the audit package now, with the real os.open. `cli.main` imports it
# lazily, and audit/fingerprint.py decides `_SUPPORTS_OPEN_DIR_FD` at import
# from `os.open in os.supports_dir_fd`. A first import under the os.open
# wrapper below would leave that flag False for every later test in the
# process ("os.open does not support dir_fd").
from hermes_plugins.defuzz import audit as _audit  # noqa: E402,F401


ALL_SECRET_FILENAMES: Tuple[str, ...] = (
    ".env",
    ".env.local",
    ".netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    "sub/credentials",
    "credentials.json",
    "client_secret.json",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "tls.pem",
    "deploy.key",
    "bundle.p12",
    "cert.pfx",
    "app.keystore",
    "nested/deep/.env.production",
    "nested/deep/id_ed25519",
    "credentials/service.key",
)

SAFE_ORDINARY_FILENAMES: Tuple[str, ...] = (
    "README.md",
    "src/main.py",
    ".env.example",
    ".env.sample",
    "tls.pem.template",
    "deploy.key.dist",
    "cert.pfx.schema",
    "credentials/README.md",
    "credentials/client_secret.json.example",
)


def _snapshot_tree(root: Path) -> Dict[str, Tuple[int, int, int, str | None]]:
    """Snapshot relative paths -> (st_mode, st_size, st_mtime_ns, readlink_or_None) via lstat only."""
    snap: Dict[str, Tuple[int, int, int, str | None]] = {}
    for dirpath, dirnames, filenames in os.walk(str(root), topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = os.path.relpath(dirpath, str(root)).replace("\\", "/")
        entries = [(d, True) for d in dirnames] + [(f, False) for f in filenames]
        keep_dirs: List[str] = []
        for name, is_dir_bucket in entries:
            full = os.path.join(dirpath, name)
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            st = os.lstat(full)
            link_target = os.readlink(full) if stat.S_ISLNK(st.st_mode) else None
            # Directory sizes vary across filesystems only if mutated; record exact size/mode/mtime_ns.
            snap[rel] = (st.st_mode, st.st_size, st.st_mtime_ns, link_target)
            if is_dir_bucket and not stat.S_ISLNK(st.st_mode):
                keep_dirs.append(name)
        dirnames[:] = keep_dirs
    return snap


@contextmanager
def _record_file_access(monkeypatch: pytest.MonkeyPatch):
    """Record open/os.open/os.stat/os.readlink calls plus sys.addaudithook open events."""
    active = [True]
    records: Dict[str, List[str]] = {
        "audit_open": [],
        "os_open": [],
        "builtin_open": [],
        "os_stat": [],
        "os_readlink": [],
    }

    real_os_open = os.open
    real_builtin_open = builtins.open
    real_os_stat = os.stat
    real_os_readlink = os.readlink

    def audit_hook(event: str, args: Tuple[Any, ...]) -> None:
        if not active[0] or event != "open" or not args:
            return
        raw = args[0]
        if isinstance(raw, (str, bytes, os.PathLike)):
            records["audit_open"].append(os.path.abspath(os.fsdecode(raw)))

    def wrapped_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if isinstance(path, (str, bytes, os.PathLike)):
            records["os_open"].append(os.path.abspath(os.fsdecode(path)))
        return real_os_open(path, flags, *args, **kwargs)

    def wrapped_builtin_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, (str, bytes, os.PathLike)):
            records["builtin_open"].append(os.path.abspath(os.fsdecode(file)))
        return real_builtin_open(file, *args, **kwargs)

    def wrapped_os_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if isinstance(path, (str, bytes, os.PathLike)) and kwargs.get("follow_symlinks", True):
            records["os_stat"].append(os.path.abspath(os.fsdecode(path)))
        return real_os_stat(path, *args, **kwargs)

    def wrapped_os_readlink(path: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(path, (str, bytes, os.PathLike)):
            records["os_readlink"].append(os.path.abspath(os.fsdecode(path)))
        return real_os_readlink(os.fsdecode(path), *args, **kwargs)

    sys.addaudithook(audit_hook)
    monkeypatch.setattr(os, "open", wrapped_os_open)
    monkeypatch.setattr(builtins, "open", wrapped_builtin_open)
    monkeypatch.setattr(os, "stat", wrapped_os_stat)
    monkeypatch.setattr(os, "readlink", wrapped_os_readlink)
    try:
        yield records
    finally:
        active[0] = False


def _populate_rich_source(base: Path) -> Tuple[Path, Dict[str, bytes], Set[str]]:
    """Create a synthetic source tree with canaries in every secret-named file/symlink."""
    src = base / "source_proj"
    ext_dir = base / "external_secrets"
    src.mkdir(parents=True)
    ext_dir.mkdir(parents=True)

    canaries: Dict[str, bytes] = {}
    secret_abs_paths: Set[str] = set()

    # Note: a directory named 'credentials' is an ordinary directory under scanner._is_secret_filename
    # (which checks regular file and symlink basenames, never real directories).
    (src / "credentials").mkdir(parents=True, exist_ok=True)

    for idx, rel in enumerate(SAFE_ORDINARY_FILENAMES):
        target = src / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"ordinary content {idx} for {rel}\n", encoding="utf-8")

    for idx, rel in enumerate(ALL_SECRET_FILENAMES):
        canary = f"SECRET_CANARY_{idx:03d}_{rel}_DO_NOT_COPY_OR_OPEN\n".encode("utf-8")
        target = src / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(canary)
        canaries[rel] = canary
        secret_abs_paths.add(os.path.abspath(str(target)))

    # External targets for secret-named symlinks (file symlink and directory symlink)
    ext_file = ext_dir / "outside_target.txt"
    ext_file_canary = b"SECRET_CANARY_SYMLINK_FILE_TARGET\n"
    ext_file.write_bytes(ext_file_canary)
    canaries["linked_secret.pem"] = ext_file_canary

    ext_subdir = ext_dir / "outside_dir"
    ext_subdir.mkdir()
    ext_dir_canary = b"SECRET_CANARY_SYMLINK_DIR_TARGET\n"
    (ext_subdir / "inside.txt").write_bytes(ext_dir_canary)
    canaries["secret_dir_link.key"] = ext_dir_canary

    link_file = src / "linked_secret.pem"
    os.symlink(str(ext_file), str(link_file))
    secret_abs_paths.add(os.path.abspath(str(link_file)))
    secret_abs_paths.add(os.path.abspath(str(ext_file)))

    link_dir = src / "secret_dir_link.key"
    os.symlink(str(ext_subdir), str(link_dir))
    secret_abs_paths.add(os.path.abspath(str(link_dir)))
    secret_abs_paths.add(os.path.abspath(str(ext_subdir / "inside.txt")))

    # Ordinary-named symlink pointing to a relative secret-named file (copied as raw link, never followed)
    os.symlink(".env", str(src / "ordinary_link_to_env"))

    return src, canaries, secret_abs_paths


def _assert_zero_canaries_under(roots: Tuple[Path, ...], canaries: Dict[str, bytes]) -> None:
    for root in roots:
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(str(root), topdown=True, followlinks=False):
            dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                st = os.lstat(fpath)
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    continue
                data = fpath.read_bytes()
                for label, canary in canaries.items():
                    assert canary not in data, f"Canary for {label} leaked into {fpath}"


def test_default_copy_and_run_never_open_secret_files_and_leave_zero_canary_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    src, canaries, secret_abs_paths = _populate_rich_source(tmp_path)
    copy_from_copy = tmp_path / "copy_cmd_out"
    copy_from_run = tmp_path / "run_cmd_out"
    staging = tmp_path / "staging"
    staging.mkdir()

    expected_left_behind = sorted([*ALL_SECRET_FILENAMES, "linked_secret.pem", "secret_dir_link.key"])
    before_snap = _snapshot_tree(src)

    out_copy, err_copy = io.StringIO(), io.StringIO()
    out_run, err_run = io.StringIO(), io.StringIO()

    with _record_file_access(monkeypatch) as records:
        with redirect_stdout(out_copy), redirect_stderr(err_copy):
            rc_copy = cli.main(["copy", str(src), str(copy_from_copy), "--staging", str(staging)])
        with redirect_stdout(out_run), redirect_stderr(err_run):
            rc_run = cli.main([
                "run",
                str(copy_from_run),
                "--source",
                str(src),
                "--staging",
                str(staging),
                "--deterministic",
            ])

    assert rc_copy == 0, err_copy.getvalue()
    assert rc_run == 0, err_run.getvalue()

    # 1. Hard invariant: zero secret-named source files opened, stat'ed (beyond walk lstat), or readlink'd
    for bucket in ("audit_open", "os_open", "builtin_open", "os_stat", "os_readlink"):
        hits = sorted(set(records[bucket]) & secret_abs_paths)
        assert hits == [], f"Unexpected {bucket} on secret-named source path(s): {hits}"

    # 2. Hard invariant: source folder completely unmodified (names, sizes, mtimes, modes, links)
    after_snap = _snapshot_tree(src)
    assert after_snap == before_snap

    # 3. Hard invariant: zero canary bytes anywhere under either copy or staging
    _assert_zero_canaries_under((copy_from_copy, copy_from_run, staging), canaries)

    # 4. Secret-named files and secret-named symlinks absent from both copies;
    #    secret-named directory 'credentials/' treated as ordinary directory per scanner._is_secret_filename
    for target_copy in (copy_from_copy, copy_from_run):
        for rel in expected_left_behind:
            assert not os.path.lexists(target_copy / rel), f"{rel} should not exist in {target_copy}"
        assert (target_copy / "credentials").is_dir()
        for ordinary_rel in SAFE_ORDINARY_FILENAMES:
            assert (target_copy / ordinary_rel).is_file(), f"Missing ordinary file {ordinary_rel}"
        assert os.path.islink(target_copy / "ordinary_link_to_env")
        assert os.readlink(target_copy / "ordinary_link_to_env") == ".env"

    # 5. JSON and plain-text outputs for both copy and run list left-behind files and count
    copy_json = json.loads(out_copy.getvalue())
    run_json = json.loads(out_run.getvalue())
    for payload in (copy_json, run_json):
        assert payload["secret_files_left_behind"] == expected_left_behind
        assert payload["secret_files_left_behind_count"] == len(expected_left_behind)

    for plain in (err_copy.getvalue(), err_run.getvalue()):
        assert "look like they hold secrets, so they were not copied" in plain
        assert f"untouched in {src}" in plain
        assert "--include-secret-files" in plain
        for rel in expected_left_behind:
            assert rel in plain


def test_opt_in_include_secret_files_copies_byte_for_byte_never_stages_and_preserves_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    src, canaries, secret_abs_paths = _populate_rich_source(tmp_path)
    copy_cmd = tmp_path / "copy_opt_in"
    run_cmd = tmp_path / "run_opt_in"
    staging = tmp_path / "staging"
    staging.mkdir()

    before_snap = _snapshot_tree(src)

    out_copy, err_copy = io.StringIO(), io.StringIO()
    out_run, err_run = io.StringIO(), io.StringIO()
    with redirect_stdout(out_copy), redirect_stderr(err_copy):
        rc_copy = cli.main([
            "copy",
            str(src),
            str(copy_cmd),
            "--staging",
            str(staging),
            "--include-secret-files",
        ])
    assert rc_copy == 0, err_copy.getvalue()

    # Also verify scan + apply during `run --include-secret-files` never opens the copied secret files
    copied_secret_paths = {
        os.path.abspath(str(run_cmd / rel))
        for rel in (*ALL_SECRET_FILENAMES, "linked_secret.pem", "secret_dir_link.key")
    }
    with _record_file_access(monkeypatch) as records:
        with redirect_stdout(out_run), redirect_stderr(err_run):
            rc_run = cli.main([
                "run",
                str(run_cmd),
                "--source",
                str(src),
                "--staging",
                str(staging),
                "--deterministic",
                "--include-secret-files",
            ])
    assert rc_run == 0, err_run.getvalue()

    # Copy opened the source files to copy them, then wrote the destination files once;
    # neither scanner nor applier opened the copied secret files for reading!
    read_hits_in_copy = []
    for p in records["os_open"]:
        if p in copied_secret_paths:
            read_hits_in_copy.append(p)
    # shutil.copy2 opens destination via builtin open('wb'), never os.open O_RDONLY in scanner/applier
    assert read_hits_in_copy == [], f"Scanner or applier opened copied secret file(s): {read_hits_in_copy}"

    assert _snapshot_tree(src) == before_snap

    copy_json = json.loads(out_copy.getvalue())
    run_json = json.loads(out_run.getvalue())
    for payload in (copy_json, run_json):
        assert payload["secret_files_left_behind"] == []
        assert payload["secret_files_left_behind_count"] == 0
    assert err_copy.getvalue() == ""
    assert "look like they hold secrets" not in err_run.getvalue()

    for target_copy in (copy_cmd, run_cmd):
        for rel in ALL_SECRET_FILENAMES:
            expected_bytes = (src / rel).read_bytes()
            actual_bytes = (target_copy / rel).read_bytes()
            assert hashlib.sha256(actual_bytes).digest() == hashlib.sha256(expected_bytes).digest(), rel
        assert os.path.islink(target_copy / "linked_secret.pem")
        assert os.readlink(target_copy / "linked_secret.pem") == os.readlink(src / "linked_secret.pem")
        assert os.path.islink(target_copy / "secret_dir_link.key")
        assert os.readlink(target_copy / "secret_dir_link.key") == os.readlink(src / "secret_dir_link.key")

    # Verify never staged in git index or baseline/adopted commits
    tracked = safety.run_git_hardened(run_cmd, ["ls-files"]).stdout.decode("utf-8").splitlines()
    baseline_sha = run_json["report"]["baseline_commit_sha"]
    adopted_sha = run_json["report"]["adopted_commit_sha"]
    baseline_tree = safety.run_git_hardened(
        run_cmd, ["ls-tree", "-r", "--name-only", baseline_sha]
    ).stdout.decode("utf-8").splitlines()
    adopted_tree = safety.run_git_hardened(
        run_cmd, ["ls-tree", "-r", "--name-only", adopted_sha]
    ).stdout.decode("utf-8").splitlines()
    for secret_rel in (*ALL_SECRET_FILENAMES, "linked_secret.pem", "secret_dir_link.key"):
        assert secret_rel not in tracked
        assert secret_rel not in baseline_tree
        assert secret_rel not in adopted_tree


def test_cli_plain_output_escapes_control_chars_and_caps_at_fifty(tmp_path: Path) -> None:
    src = tmp_path / "src_55"
    copy_dir = tmp_path / "copy_55"
    src.mkdir()
    (src / "README.md").write_text("# Demo\n", encoding="utf-8")

    # 54 numbered .key files + 1 hostile filename with ESC + bidi override = 55 secret files
    for idx in range(54):
        (src / f"k_{idx:03d}.key").write_text("x\n", encoding="utf-8")
    hostile_name = "00_evil_\x1b[31m_\u202e_secret.pem"
    (src / hostile_name).write_text("x\n", encoding="utf-8")

    out_buf, err_buf = io.StringIO(), io.StringIO()
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        rc = cli.main(["copy", str(src), str(copy_dir)])
    assert rc == 0

    payload = json.loads(out_buf.getvalue())
    assert payload["secret_files_left_behind_count"] == 55
    assert len(payload["secret_files_left_behind"]) == 55

    plain = err_buf.getvalue()
    assert "\x1b" not in plain
    assert "\u202e" not in plain
    assert audit_summary.safe_text(hostile_name, path=True) in plain
    assert "and 5 more" in plain
    # The 55th sorted item (k_053.key) is beyond the 50-item display cap
    assert "k_053.key" not in plain
    assert "k_048.key" in plain


def test_consumer_scan_inventory_and_tracked_git_secrets_when_absent(tmp_path: Path) -> None:
    src = tmp_path / "src_git"
    copy_dir = tmp_path / "copy_git"
    src.mkdir()
    safety.run_git_hardened(src, ["init", "-b", "main"], allow_literal_pathspecs=False)
    safety.run_git_hardened(src, ["config", "user.name", "Test"], allow_literal_pathspecs=False)
    safety.run_git_hardened(src, ["config", "user.email", "t@example.invalid"], allow_literal_pathspecs=False)
    (src / "README.md").write_text("# Tracked\n", encoding="utf-8")
    (src / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (src / "sub").mkdir()
    (src / "sub" / "id_rsa").write_text("UNTRACKED_KEY\n", encoding="utf-8")
    safety.run_git_hardened(src, ["add", "-f", "--", "README.md", ".env"])
    safety.run_git_hardened(src, ["commit", "-m", "init"], allow_literal_pathspecs=False)

    safety.copy_tree_nofollow(src, copy_dir)
    assert not (copy_dir / ".env").exists()
    assert not (copy_dir / "sub" / "id_rsa").exists()

    # 1. With source_root: discovers both tracked .env and untracked sub/id_rsa without opening either
    inv = scanner.scan_folder(copy_dir, source_root=src)
    assert [f["path"] for f in inv["files"]] == ["README.md"]
    assert inv["secret_files_left_behind"] == [".env", "sub/id_rsa"]
    flagged_paths = [s["path"] for s in inv["secrets_flagged"]]
    assert flagged_paths == [".env", "sub/id_rsa"]
    placeholder_paths = [s["path"] for s in inv["model_summary"]["secrets_placeholders"]]
    assert placeholder_paths == [".env", "sub/id_rsa"]

    # 2. Without source_root: still flags tracked .env from git index so apply removes it and ignores it
    inv_no_src = scanner.scan_folder(copy_dir)
    assert [s["path"] for s in inv_no_src["secrets_flagged"]] == [".env"]


def test_consumer_rules_and_plan_with_absent_secrets(tmp_path: Path) -> None:
    src = tmp_path / "src_rules"
    copy_dir = tmp_path / "copy_rules"
    (src / "sub").mkdir(parents=True)
    (src / "README.md").write_text("# Rules\n", encoding="utf-8")
    (src / ".env").write_text("A=1\n", encoding="utf-8")
    (src / "sub" / "my space.key").write_text("B=2\n", encoding="utf-8")
    os.symlink(".env", str(src / "env_alias"))

    safety.copy_tree_nofollow(src, copy_dir)
    inv = scanner.scan_folder(copy_dir, source_root=src)

    det_spec = rules.build_deterministic_fallback_rules(inv)
    assert ".env" in det_spec["ignore_patterns"]

    class _MockRes:
        parsed = {
            "project_slug": "rules-demo",
            "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
            "folder_rules": [],
            "placement_rules": [
                {"kind": "docs", "match_ext": [".md"], "dest_dir": "docs", "lfs": False, "reason": "docs"}
            ],
            "ignore_patterns": [],
            "lfs_patterns": [],
        }
        provider = "mock"
        model = "mock"

    class _MockLlm:
        @staticmethod
        def complete_structured(**_kwargs: Any) -> _MockRes:
            return _MockRes()

    llm_spec = rules.propose_rules_via_llm(inv, _MockLlm())
    assert ".env" in llm_spec["ignore_patterns"]

    plan = rules.expand_rules(inv, det_spec)
    assert [f["source_path"] for f in plan["files"]] == ["README.md"]
    assert [ln["source_path"] for ln in plan["links"]] == ["env_alias"]


def test_consumer_applier_gitignore_tracked_index_and_post_apply_when_absent(tmp_path: Path) -> None:
    src = tmp_path / "src_apply"
    copy_dir = tmp_path / "copy_apply"
    staging = tmp_path / "staging"
    (src / "sub").mkdir(parents=True)
    staging.mkdir()

    safety.run_git_hardened(src, ["init", "-b", "main"], allow_literal_pathspecs=False)
    safety.run_git_hardened(src, ["config", "user.name", "Test"], allow_literal_pathspecs=False)
    safety.run_git_hardened(src, ["config", "user.email", "t@example.invalid"], allow_literal_pathspecs=False)
    for idx in range(6):
        (src / f"note_{idx}.md").write_text(f"# Note {idx}\n", encoding="utf-8")
    (src / ".env").write_text("TRACKED_SECRET=1\n", encoding="utf-8")
    (src / "sub" / "id_ed25519").write_text("UNTRACKED_SECRET=2\n", encoding="utf-8")
    safety.run_git_hardened(src, ["add", "-f", "--", ".env", "note_0.md"])
    safety.run_git_hardened(src, ["commit", "-m", "before-adopt"], allow_literal_pathspecs=False)

    safety.copy_tree_nofollow(src, copy_dir, staging_root=staging)
    inv = scanner.scan_folder(copy_dir, source_root=src, out_path=staging / "inventory.json")
    spec = rules.build_deterministic_fallback_rules(inv)
    report = applier.apply_rules_to_copy(
        copy_dir,
        inv,
        spec,
        source_root=src,
        staging_root=staging,
        report_out_path=staging / "report.json",
        db_path=staging / "state.db",
    )

    assert report["counts"]["moved"] == 6
    assert report["counts"]["secrets_locked_to_ignore"] == 2
    assert report["counts"]["untracked_from_index"] == 1
    assert report["secret_files_left_behind"] == [".env", "sub/id_ed25519"]
    assert report["secret_files_left_behind_count"] == 2

    gitignore_lines = (copy_dir / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in gitignore_lines
    assert "sub/id_ed25519" in gitignore_lines

    # If the user later copies .env in manually, .gitignore prevents git from staging/showing it
    (copy_dir / ".env").write_text("USER_COPIED_LATER=1\n", encoding="utf-8")
    status_out = safety.run_git_hardened(copy_dir, ["status", "--porcelain=v1"]).stdout.decode("utf-8")
    assert ".env" not in status_out


def test_consumer_placer_place_sweep_add_rule_and_undo_after_default_adopt(tmp_path: Path) -> None:
    src = tmp_path / "src_place"
    copy_dir = tmp_path / "copy_place"
    staging = tmp_path / "staging"
    src.mkdir()
    staging.mkdir()
    (src / "README.md").write_text("# Place\n", encoding="utf-8")
    (src / ".env").write_text("S=1\n", encoding="utf-8")
    (src / "my space.pem").write_text("S=2\n", encoding="utf-8")

    out_buf, err_buf = io.StringIO(), io.StringIO()
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        rc = cli.main([
            "run",
            str(copy_dir),
            "--source",
            str(src),
            "--staging",
            str(staging),
            "--deterministic",
        ])
    assert rc == 0

    placer.trust_project(copy_dir)
    # User copies .env in later; placer rule update must never stage .env
    (copy_dir / ".env").write_text("LATER=1\n", encoding="utf-8")
    placer.add_placement_rule(copy_dir, ".txt", "docs", kind="notes")
    tracked = safety.run_git_hardened(copy_dir, ["ls-files"]).stdout.decode("utf-8").splitlines()
    assert ".env" not in tracked

    (copy_dir / "draft.txt").write_text("hello\n", encoding="utf-8")
    moved = placer.place_existing_files(copy_dir, ["draft.txt"])
    assert len(moved) == 1
    assert (copy_dir / "docs" / "draft.txt").is_file()

    undone = placer.undo_placements(copy_dir, count=1)
    assert len(undone) == 1
    assert (copy_dir / "draft.txt").is_file()


def test_consumer_applier_handles_prebuilt_plan_with_absent_left_behind_secret_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    src = tmp_path / "src_defensive"
    copy_dir = tmp_path / "copy_defensive"
    (src / "notes").mkdir(parents=True)
    (src / "notes" / "guide.md").write_text("# Guide\n", encoding="utf-8")
    (src / "notes" / ".env").write_text("CANARY_DEFENSIVE=1\n", encoding="utf-8")

    safety.copy_tree_nofollow(src, copy_dir)
    inv = scanner.scan_folder(copy_dir, source_root=src)
    # Simulate a caller supplying an inventory whose files list also recorded a left_behind secret entry
    inv["files"].append({
        "path": "notes/.env",
        "size": 0,
        "mode": "0o600",
        "tracked": False,
        "is_binary": False,
        "sha256": None,
        "secret_placeholder": "<secret-1>",
        "left_behind": True,
    })
    spec = {
        "project_slug": "defensive-demo",
        "declared_dirs": [{"dir": "docs", "summary": "docs", "why": "docs"}],
        "folder_rules": [
            {
                "match": "notes",
                "ext": [],
                "disposition": "move",
                "git_policy": "track",
                "to": "docs",
                "reason": "move notes to docs",
            }
        ],
        "placement_rules": [],
        "ignore_patterns": [],
        "lfs_patterns": [],
    }
    secret_abs = {os.path.abspath(str(src / "notes" / ".env"))}
    with _record_file_access(monkeypatch) as records:
        report = applier.apply_rules_to_copy(
            copy_dir,
            inv,
            spec,
            source_root=src,
            db_path=tmp_path / "state.db",
        )
    assert set(records["audit_open"]) & secret_abs == set()
    assert (copy_dir / "docs" / "guide.md").is_file()
    assert not (copy_dir / "docs" / ".env").exists()
    assert report["counts"]["moved"] == 1

