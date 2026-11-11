"""Synthetic-only tests for audit.secret_file_copies (by-name and lstat only)."""
from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import stat

from tests.conftest import load_submodule


def _snapshot_tree(root: Path) -> str:
    """Hash recursive listing, lstat modes/sizes, and file bytes of a synthetic home."""
    digest = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = os.path.relpath(dirpath, root)
        st_dir = os.lstat(dirpath)
        digest.update(f"D:{rel_dir}:{stat.S_IMODE(st_dir.st_mode)}\n".encode("utf-8", "surrogateescape"))
        for name in (*dirnames, *filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                digest.update(f"L:{rel}:{os.readlink(full)}\n".encode("utf-8", "surrogateescape"))
            elif stat.S_ISREG(st.st_mode):
                digest.update(f"F:{rel}:{stat.S_IMODE(st.st_mode)}:{st.st_size}:".encode("utf-8", "surrogateescape"))
                with builtins.open(full, "rb") as fh:
                    digest.update(hashlib.sha256(fh.read()).hexdigest().encode("utf-8", "surrogateescape"))
                digest.update(b"\n")
    return digest.hexdigest()


def _touch(path: Path, content: bytes = b"secret", mode: int = 0o600, mtime: float | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    os.chmod(path, mode)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


def _kept_paths(result) -> list[str]:
    """Every absolute path the section emits (top-level folders and plugin folders only)."""
    sec = result["secret_file_copies"]["secret_named_files"]
    return ([row["path"] for row in sec["by_top_level_folder"]]
            + [row["path"] for row in sec["example_locations"]]
            + list(sec["plugin_folders_with_dotenv"]))


def _assert_paths_capped(result, home: Path) -> None:
    """Paths are the home root, a top-level folder of it, or a plugin folder; nothing else
    of the temporary tree appears anywhere in the result."""
    home_s = os.path.abspath(str(home))
    sec = result["secret_file_copies"]["secret_named_files"]
    for row in sec["by_top_level_folder"] + sec["example_locations"]:
        p = row["path"]
        assert p == home_s or os.path.dirname(p) == home_s, p
    for p in sec["plugin_folders_with_dotenv"]:
        rel = Path(p).relative_to(home_s).parts
        assert (len(rel) == 2 and rel[0] in ("plugins", "desktop-plugins")) or (
            len(rel) == 4 and rel[0] == "profiles" and rel[2] in ("plugins", "desktop-plugins")), p
        assert os.path.isdir(p), p
    rest = json.loads(json.dumps(result))
    for key in ("by_top_level_folder", "example_locations", "plugin_folders_with_dotenv"):
        rest["secret_file_copies"]["secret_named_files"].pop(key)
    assert home_s not in json.dumps(rest)


def test_never_opens_or_stats_beyond_lstat(tmp_path, monkeypatch):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / ".env", b"OPENAI_API_KEY=sk-1234567890\n", mode=0o600)
    _touch(home / ".env.bak-20260910-230014", b"OPENAI_API_KEY=sk-1234567890\n", mode=0o600)
    _touch(home / "auth.json", b'{"providers": {"nous": {"access_token": "tok"}}}')
    _touch(home / "mcp-tokens" / "github.json", b'{"access_token": "gho_123"}')
    _touch(home / "pairing" / "discord-approved.json", b'{"user1": {}}')
    _touch(home / "vault" / "vault.key", b"fernet-key")
    _touch(home / "vault" / "vault.json.enc", b"ciphertext")
    _touch(home / "config.yaml", b"model: gpt-4\n")
    _touch(home / "config.yaml.bak", b"model: gpt-4\n")
    _touch(home / "side-project" / ".env.odds", b"PROJ_KEY=1\n")
    _touch(home / "plugins" / "voice-plugin" / ".env", b"PLUGIN_KEY=1\n")
    _touch(home / "plans" / "trial" / "discord-auth.json", b"{}")
    _touch(home / "plans" / "fix" / ".hermes" / ".env", b"FAKE=1\n")
    os.symlink("/nonexistent/secret.pem", home / "plans" / "trial" / "linked-secret.pem")

    home_prefix = os.path.abspath(home)

    def _under_home(p) -> bool:
        if isinstance(p, int):
            return False
        raw = os.path.abspath(os.fsdecode(p))
        return raw == home_prefix or raw.startswith(home_prefix + os.sep)

    orig_builtins_open = builtins.open
    orig_io_open = io.open
    orig_os_open = os.open
    orig_os_read = os.read
    orig_read_bytes = Path.read_bytes
    orig_read_text = Path.read_text
    orig_os_stat = os.stat

    def forbid_builtins_open(file, *args, **kwargs):
        if _under_home(file):
            raise AssertionError(f"builtins.open called on {file}")
        return orig_builtins_open(file, *args, **kwargs)

    def forbid_io_open(file, *args, **kwargs):
        if _under_home(file):
            raise AssertionError(f"io.open called on {file}")
        return orig_io_open(file, *args, **kwargs)

    def forbid_os_open(path, flags, mode=0o777, *, dir_fd=None):
        if _under_home(path):
            raise AssertionError(f"os.open called on {path}")
        return orig_os_open(path, flags, mode, dir_fd=dir_fd)

    def forbid_os_read(fd, n):
        raise AssertionError(f"os.read called on fd={fd}")

    def forbid_read_bytes(self):
        if _under_home(self):
            raise AssertionError(f"Path.read_bytes called on {self}")
        return orig_read_bytes(self)

    def forbid_read_text(self, *args, **kwargs):
        if _under_home(self):
            raise AssertionError(f"Path.read_text called on {self}")
        return orig_read_text(self, *args, **kwargs)

    def forbid_os_stat(path, *args, **kwargs):
        if _under_home(path) and kwargs.get("follow_symlinks", True):
            raise AssertionError(f"os.stat (follow_symlinks=True) called on {path}")
        return orig_os_stat(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", forbid_builtins_open)
    monkeypatch.setattr(io, "open", forbid_io_open)
    monkeypatch.setattr(os, "open", forbid_os_open)
    monkeypatch.setattr(os, "read", forbid_os_read)
    monkeypatch.setattr(Path, "read_bytes", forbid_read_bytes)
    monkeypatch.setattr(Path, "read_text", forbid_read_text)
    monkeypatch.setattr(os, "stat", forbid_os_stat)

    res = mod.audit_secret_file_copies(profile_path=home)
    sec = res["secret_file_copies"]
    assert res["coverage"] == "verified"
    assert sec["expected_secret_files"]["total"] == 6
    assert sec["backup_copies"]["count"] == 1
    assert sec["backup_copies"]["same_size_as_live_count"] == 1
    assert sec["secret_named_files"]["count"] == 3
    assert sec["fixture_homes"]["secret_named_file_count"] == 1
    assert sec["symlinks"]["secret_named_symlinks"] == 1


def test_expected_secret_files_counted_by_kind_and_not_flagged(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    # Home root expected stores
    _touch(home / ".env")
    _touch(home / ".op.env")
    _touch(home / "auth.json")
    _touch(home / "mcp-tokens" / "cloudflare.json")
    _touch(home / "mcp-tokens" / "cloudflare.client.json")
    _touch(home / "pairing" / "discord-approved.json")
    _touch(home / "platforms" / "pairing" / "telegram-pending.json")
    _touch(home / "vault" / "vault.key")
    _touch(home / "vault" / "vault.json.enc")
    _touch(home / "vault" / ".vault.lock")
    _touch(home / "slack_tokens.json")
    _touch(home / "webhook_subscriptions.json")
    _touch(home / "teams_pipeline_store.json")
    _touch(home / "honcho.json")
    _touch(home / "mem0.json")
    _touch(home / "weixin" / "accounts" / "bot1.json")
    _touch(home / "webapp" / "session-token")
    _touch(home / ".anthropic_oauth.json")
    _touch(home / "auth" / "google_oauth.json")
    _touch(home / "google_token.json")
    _touch(home / "google_chat_user_tokens" / "user@example.com.json")
    _touch(home / ".copilot_jwt.json")
    # Named profile expected stores
    _touch(home / "profiles" / "coder" / ".env")
    _touch(home / "profiles" / "coder" / "auth.json")
    _touch(home / "profiles" / "coder" / "mcp-tokens" / "github.json")

    res = mod.audit_secret_file_copies(profile_path=home)
    sec = res["secret_file_copies"]
    assert res["coverage"] == "verified"
    assert sec["expected_secret_files"]["by_kind"] == {
        "dotenv": 3,
        "auth_json": 2,
        "mcp_tokens": 3,
        "pairing": 2,
        "vault": 2,
        "platform_token_stores": 7,
        "oauth_stores": 5,
        "shared_auth": 0,
        "credentials_store": 0,
        "browser_and_home_stores": 0,
        "os_credential_dirs": 0,
    }
    assert sec["expected_secret_files"]["total"] == 24
    assert sec["backup_copies"]["count"] == 0
    assert sec["secret_named_files"]["count"] == 0
    assert sec["fixture_homes"]["secret_named_file_count"] == 0
    assert res["findings"] == []


def test_backup_copies_of_secret_files_and_size_equality(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    # July 2026 & August 2026 mtimes
    mt_aug = 1787793492.0  # 2026-08
    mt_sep = 1789095614.0  # 2026-09
    _touch(home / ".env", b"A" * 25432, mtime=mt_sep)
    _touch(home / "auth.json", b"B" * 1876, mtime=mt_sep)
    _touch(home / ".env.bak-20260903-mcp-tokens", b"A" * 24800, mtime=mt_sep)
    _touch(home / ".env.bak-20260910-230014", b"A" * 25432, mtime=mt_sep)
    _touch(home / ".env.bak-pre-windows-credentials-20260826-220710", b"A" * 27700, mtime=mt_aug)
    _touch(home / ".env.codex-backup-20260830-222726", b"A" * 26100, mtime=mt_aug)
    _touch(home / ".env.orig", b"A" * 100, mtime=mt_aug)
    _touch(home / ".env.old", b"A" * 100, mtime=mt_aug)
    _touch(home / ".env.save", b"A" * 100, mtime=mt_aug)
    _touch(home / ".env~", b"A" * 100, mtime=mt_aug)
    _touch(home / "backups" / "auth-before-copilot-suppression-20260827T151924.json", b"B" * 1876, mtime=mt_aug)

    res = mod.audit_secret_file_copies(profile_path=home)
    sec = res["secret_file_copies"]
    assert sec["backup_copies"]["count"] == 9
    assert sec["backup_copies"]["same_size_as_live_count"] == 2
    assert sec["secret_named_files"]["count"] == 0
    months = {(c["year"], c["month"]) for c in sec["backup_copies"]["copies"]}
    assert months == {(2026, 8), (2026, 9)}
    # Sizes of secret files must never appear in the result
    dumped = json.dumps(res)
    for size_num in ("25432", "24800", "27700", "26100", "1876"):
        assert size_num not in dumped

    finding = next(f for f in res["findings"] if f["id"] == "secret_file_copies.backup_copies_of_secret_files")
    assert finding["classification"] == "warning"
    assert finding["evidence"] == {"count": 9, "same_size_as_live_count": 2}
    assert "matched file names" in finding["consequence"].lower() or "matched names" in finding["consequence"].lower()
    assert "did not open" in finding["consequence"].lower() or "opened none" in finding["consequence"].lower()


def test_secret_named_files_in_work_folders_plugins_and_masked_examples(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / "side-project" / ".env.odds")
    _touch(home / "plugins" / "voice-plugin" / ".env")
    _touch(home / "shared" / "nous_auth.json")
    _touch(home / "tmp" / "remote-gateway-clients" / "mac" / "native-oauth-tokens.json")
    _touch(home / "plans" / "trial" / "baseline" / "analyst" / "discord-auth.json")
    _touch(home / "plans" / "switch" / "token-receipt.json")
    _touch(home / "exports" / "dump" / "my-tokens.dat")
    _touch(home / "logs" / "gcp-service-account.json")
    _touch(home / "work" / "client-credential.json")
    _touch(home / "work" / "app-secret.yaml")
    _touch(home / "work" / "cert.pem")
    _touch(home / "work" / "private.key")
    _touch(home / "work" / "id_rsa")
    _touch(home / "work" / "id_ed25519")
    _touch(home / "work" / "id_ecdsa")
    _touch(home / "work" / "bundle.p12")
    _touch(home / "work" / "bundle.pfx")
    _touch(home / "work" / ".netrc")
    _touch(home / "work" / ".npmrc")
    _touch(home / "work" / ".pypirc")
    _touch(home / "skills" / "custom-skill" / "service.env")

    res = mod.audit_secret_file_copies(profile_path=home)
    sec = res["secret_file_copies"]
    # shared/nous_auth.json is Hermes's cross-profile Nous store (hermes_cli/auth_nous.py:346-365).
    assert sec["secret_named_files"]["count"] == 20
    assert sec["expected_secret_files"]["by_kind"]["shared_auth"] == 1
    assert sec["secret_named_files"]["plugin_dotenv_count"] == 1
    assert sec["secret_named_files"]["plugin_folders_with_dotenv"] == [str(home / "plugins" / "voice-plugin")]
    locs = sec["secret_named_files"]["example_locations"]
    pairs = [(loc["path"], loc["class"]) for loc in locs]
    assert len(pairs) == len(set(pairs))
    assert all(set(loc) == {"path", "class"} for loc in locs)
    assert (str(home / "plans"), "auth-json") in pairs
    assert (str(home / "side-project"), "dotenv") in pairs
    assert (str(home / "plugins"), "dotenv") in pairs
    assert all("trial" not in p and "voice-plugin" not in p for p, _ in pairs)
    _assert_paths_capped(res, home)

    dumped = json.dumps(res)
    for raw_name in (
        "discord-auth.json",
        ".env.odds",
        "native-oauth-tokens.json",
        "token-receipt.json",
        "gcp-service-account.json",
        "client-credential.json",
        "app-secret.yaml",
    ):
        assert raw_name not in dumped

    ids = {f["id"]: f for f in res["findings"]}
    assert "secret_file_copies.secret_named_files_in_work_folders" in ids
    assert ids["secret_file_copies.secret_named_files_in_work_folders"]["classification"] == "warning"
    assert "secret_file_copies.plugin_holds_secret_file" in ids
    assert ids["secret_file_copies.plugin_holds_secret_file"]["classification"] == "review_suggested"


def test_do_not_flag_exclusions_and_token_exclusion_constant(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    assert hasattr(mod, "TOKEN_NAME_EXCLUSIONS")
    assert len(mod.TOKEN_NAME_EXCLUSIONS) >= 5

    home = tmp_path / "home"
    # Examples, templates, samples
    _touch(home / ".env.example")
    _touch(home / ".env.sample")
    _touch(home / ".env.template")
    _touch(home / "plugins" / "voice-plugin" / ".env.example")
    _touch(home / "plans" / "auth.json.example")
    # Public certs and keys
    _touch(home / "work" / "ca.crt")
    _touch(home / "work" / "id_rsa.pub")
    _touch(home / "work" / "id_ed25519.pub")
    # Token non-stores (test every pattern in TOKEN_NAME_EXCLUSIONS)
    _touch(home / "models" / "tokenizer.json")
    _touch(home / "models" / "tokenizer_config.json")
    _touch(home / "styles" / "tokens.css")
    _touch(home / "styles" / "design-tokens.json")
    _touch(home / "styles" / "design-tokens-dark.yaml")
    _touch(home / "metrics" / "token_count.json")
    _touch(home / "metrics" / "token_counts_summary.json")
    _touch(home / "styles" / "brand.tokens.json")
    # Vendored cacert.pem under site-packages / certifi
    _touch(home / "venvs" / "v1" / "lib" / "python3.12" / "site-packages" / "certifi" / "cacert.pem")
    # macOS AppleDouble stubs
    _touch(home / "._.env")
    _touch(home / "._auth.json")
    _touch(home / "._config.yaml.bak")

    res = mod.audit_secret_file_copies(profile_path=home)
    sec = res["secret_file_copies"]
    assert sec["backup_copies"]["count"] == 0
    assert sec["secret_named_files"]["count"] == 0
    assert sec["config_backups"]["count"] == 0
    assert res["findings"] == []

    # cacert.pem is the conventional public CA-bundle name and is never flagged; a private
    # key PEM outside a vendored package tree IS flagged.
    _touch(home / "plans" / "work" / "cacert.pem")
    _touch(home / "plans" / "work" / "privkey.pem")
    res2 = mod.audit_secret_file_copies(profile_path=home)
    assert res2["secret_file_copies"]["secret_named_files"]["count"] == 1


def test_nested_fixture_homes_counted_separately(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    # Nested .hermes fixture home with a profile inside it
    f1 = home / "plans" / "repair" / "fixtures" / "ambient-1" / ".hermes"
    _touch(f1 / ".env")
    _touch(f1 / "profiles" / "fictional" / "config.yaml", b"{}")
    _touch(f1 / "profiles" / "fictional" / ".env")
    _touch(f1 / "profiles" / "fictional" / "auth.json")
    # Another nested fixture home identified by Hermes home markers (config.yaml + SOUL.md)
    f2 = home / "plans" / "repair" / "fixtures" / "sim_home"
    _touch(f2 / "config.yaml", b"{}")
    _touch(f2 / "SOUL.md", b"persona")
    _touch(f2 / ".env")

    res = mod.audit_secret_file_copies(profile_path=home)
    sec = res["secret_file_copies"]
    assert sec["secret_named_files"]["count"] == 0
    assert sec["fixture_homes"]["fixture_home_count"] == 2
    assert sec["fixture_homes"]["secret_named_file_count"] == 4
    ids = {f["id"]: f for f in res["findings"]}
    assert set(ids) == {"secret_file_copies.secret_named_files_in_fixture_homes"}
    assert ids["secret_file_copies.secret_named_files_in_fixture_homes"]["classification"] == "review_suggested"
    assert "did not open" in ids["secret_file_copies.secret_named_files_in_fixture_homes"]["consequence"].lower()


def test_mode_bits_readable_by_others_and_fat_ntfs_mount(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / ".env", mode=0o600)
    _touch(home / "auth.json", mode=0o644)
    _touch(home / "config.yaml", mode=0o600)

    res = mod.audit_secret_file_copies(profile_path=home)
    sec = res["secret_file_copies"]
    assert sec["mode_bits"]["mode_check"] == "verified"
    assert sec["mode_bits"]["readable_by_others_count"] == 1
    ids = {f["id"]: f for f in res["findings"]}
    assert "secret_file_copies.readable_by_others" in ids
    assert ids["secret_file_copies.readable_by_others"]["classification"] == "warning"

    # Simulate FAT/NTFS mount where all files are 0o777 or 0o666
    fat_home = tmp_path / "fat_home"
    _touch(fat_home / ".env", mode=0o777)
    _touch(fat_home / "auth.json", mode=0o666)
    _touch(fat_home / "config.yaml", mode=0o777)
    res_fat = mod.audit_secret_file_copies(profile_path=fat_home)
    assert res_fat["secret_file_copies"]["mode_bits"]["mode_check"] == "could_not_verify"
    assert "secret_file_copies.readable_by_others" not in {f["id"] for f in res_fat["findings"]}


def test_config_backup_copies_thresholds_and_burst_detection(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / "config.yaml", b"model: a\n", mtime=1790915153.0)
    _touch(home / "config.yaml.bak", b"model: a\n", mtime=1790819639.0)
    # 4 backups within 5 seconds under backups/config/
    for idx, ts in enumerate((1790912843.0, 1790912845.0, 1790912846.0, 1790912848.0)):
        _touch(home / "backups" / "config" / f"config.yaml.good.20261001-23472{idx}", b"model: a\n", mtime=ts)

    res5 = mod.audit_secret_file_copies(profile_path=home)
    sec5 = res5["secret_file_copies"]
    assert sec5["config_backups"]["count"] == 5
    assert sec5["config_backups"]["burst_count"] == 1
    assert sec5["config_backups"]["max_burst_files"] == 4
    f5 = next(f for f in res5["findings"] if f["id"] == "secret_file_copies.config_backup_copies")
    assert f5["classification"] == "info"

    # Add a 6th config backup (> 5 -> review_suggested)
    _touch(home / "config.yaml.pre-migration-20260901", b"model: a\n", mtime=1790000000.0)
    res6 = mod.audit_secret_file_copies(profile_path=home)
    f6 = next(f for f in res6["findings"] if f["id"] == "secret_file_copies.config_backup_copies")
    assert f6["classification"] == "review_suggested"


def test_symlinks_counted_and_never_followed(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    outside = tmp_path / "outside"
    _touch(outside / ".env", b"OUTSIDE_CANARY=1")
    home = tmp_path / "home"
    home.mkdir()
    os.symlink(outside, home / "linked_dir")
    os.symlink("/nonexistent/target", home / "id_rsa_link")
    os.symlink("/nonexistent/readme", home / "readme_link.txt")

    res = mod.audit_secret_file_copies(profile_path=home)
    sec = res["secret_file_copies"]
    assert sec["symlinks"]["symlinks_skipped"] == 3
    assert sec["symlinks"]["secret_named_symlinks"] == 1
    assert sec["secret_named_files"]["count"] == 0
    assert sec["expected_secret_files"]["total"] == 0


def test_caps_entries_depth_and_wall_clock(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    for i in range(6):
        _touch(home / "work" / f"f{i}.env")

    # Entries cap
    res_entries = mod.audit_secret_file_copies(profile_path=home, max_entries=3)
    assert res_entries["coverage"] == "could_not_verify"
    assert res_entries["secret_file_copies"]["truncated_by"] == "max_entries"
    assert res_entries["secret_file_copies"]["limits"]["cuts"] >= 1
    assert any(f["id"] == "secret_file_copies.could_not_verify" for f in res_entries["findings"])

    # Depth cap
    deep_home = tmp_path / "deep"
    _touch(deep_home / "a" / "b" / "c" / "d" / "e" / "secret.key")
    res_depth = mod.audit_secret_file_copies(profile_path=deep_home, max_depth=2)
    assert res_depth["coverage"] == "could_not_verify"
    assert res_depth["secret_file_copies"]["truncated_by"] == "max_depth"
    assert res_depth["secret_file_copies"]["limits"]["cuts"] >= 1
    assert any(f["id"] == "secret_file_copies.could_not_verify" for f in res_depth["findings"])

    # Wall-clock cap via injectable clock
    ticks = iter([0.0, 0.1, 20.0, 21.0])
    res_time = mod.audit_secret_file_copies(profile_path=home, clock=lambda: next(ticks, 25.0), max_seconds=1.0)
    assert res_time["coverage"] == "could_not_verify"
    assert res_time["secret_file_copies"]["truncated_by"] == "time_budget"
    assert res_time["secret_file_copies"]["limits"]["cuts"] >= 1
    assert any(f["id"] == "secret_file_copies.could_not_verify" for f in res_time["findings"])


def test_unchanged_home_hash_canary_privacy_missing_empty_and_malformed(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    # Malformed binary junk and canary strings in file contents, memory text, and deep path components
    _touch(home / ".env", b"\xff\xfe\x00CANARY_ENV_CONTENT_12345")
    _touch(home / "auth.json", b"{not valid json CANARY_AUTH_CONTENT_67890")
    _touch(home / "memories" / "MEMORY.md", b"CANARY_MEMORY_TEXT_SECRET")
    _touch(
        home / "plans" / "migration" / "CANARY_DEEP_PATH_COMPONENT" / "sub" / "CANARY_BASENAME_auth.json",
        b"CANARY_DEEP_FILE_CONTENT",
    )

    before_hash = _snapshot_tree(home)
    res1 = mod.audit_secret_file_copies(profile_path=home)
    res2 = mod.audit_secret_file_copies(profile_path=home)
    after_hash = _snapshot_tree(home)

    assert before_hash == after_hash
    # Run time differs between runs by design; everything else must be identical.
    assert ({k: v for k, v in res1.items() if k != "run_metrics"}
            == {k: v for k, v in res2.items() if k != "run_metrics"})
    dumped = json.dumps(res1)
    # Only the top-level folder appears as a path, never a deeper component or a basename.
    assert _kept_paths(res1) == [str(home / "plans")] * 2
    assert "CANARY" not in dumped
    _assert_paths_capped(res1, home)
    for f in res1["findings"]:
        assert "matched" in f["consequence"].lower()
        assert "open" in f["consequence"].lower()

    # Missing home -> not_measured, no exception
    missing = mod.audit_secret_file_copies(profile_path=tmp_path / "missing_home")
    assert missing["coverage"] == "could_not_verify"
    assert missing["secret_file_copies"]["status"] == "not_measured"
    assert missing["secret_file_copies"]["reason"] == "missing"

    # Empty home -> completed, verified, no findings
    empty_dir = tmp_path / "empty_home"
    empty_dir.mkdir()
    empty = mod.audit_secret_file_copies(profile_path=empty_dir)
    assert empty["coverage"] == "verified"
    assert empty["secret_file_copies"]["status"] == "completed"
    assert empty["findings"] == []



# ---------------------------------------------------------------------------
# Regression group: no-touch harness, Hermes store locations, name
# precision/recall, output privacy, mode-bit honesty, determinism.
# ---------------------------------------------------------------------------

import mmap
import shutil
import sqlite3
import subprocess
import sys
from collections import Counter

import pytest

_AUDIT_WATCH: dict = {"active": False, "events": []}
_AUDITED_EVENTS = frozenset({
    "open", "os.listdir", "os.scandir", "os.chmod", "os.chown", "os.mkdir", "os.remove",
    "os.rename", "os.rmdir", "os.symlink", "os.link", "os.truncate", "os.utime",
    "shutil.copyfile", "shutil.copymode", "shutil.copystat", "shutil.copytree",
    "shutil.move", "shutil.rmtree", "shutil.make_archive", "shutil.unpack_archive",
    "sqlite3.connect", "subprocess.Popen", "os.system", "os.posix_spawn", "os.exec",
    "os.spawn", "os.fork", "mmap.__new__", "tempfile.mkstemp", "tempfile.mkdtemp",
    "glob.glob", "os.getxattr", "os.listxattr", "os.setxattr", "os.removexattr",
})


def _x8_audit_hook(event, args):
    if _AUDIT_WATCH["active"] and event in _AUDITED_EVENTS:
        _AUDIT_WATCH["events"].append((event, tuple(repr(a)[:200] for a in args)))


sys.addaudithook(_x8_audit_hook)  # gated: records only while a harness window is open


class _NoTouchHarness:
    """Replace every file-touching API with a recorder; only lstat/scandir/DirEntry(no-follow) pass."""

    def __init__(self, home: Path):
        import threading
        self._infra = threading.local()
        self.home = os.path.abspath(home)
        self.violations: list[str] = []
        self.calls: Counter = Counter()
        self._saved: list[tuple[object, str, object]] = []

    def _under(self, p) -> bool:
        try:
            raw = os.path.abspath(os.fsdecode(os.fspath(p)))
        except TypeError:
            return False
        return raw == self.home or raw.startswith(self.home + os.sep)

    def _rel(self, p) -> str:
        return "home" if self._under(p) else "outside"

    def _patch(self, owner, attr, repl):
        self._saved.append((owner, attr, getattr(owner, attr)))
        setattr(owner, attr, repl)

    def _forbid(self, label, orig):
        def _f(*args, **kwargs):
            # tests/conftest.py installs a real-home tripwire audit hook that itself calls
            # realpath/readlink on every audited event; that hook is test infrastructure,
            # not the module under test, so it passes through unrecorded.
            if sys._getframe(1).f_code.co_filename.endswith(os.sep + "conftest.py"):
                self._infra.on = True
                try:
                    return orig(*args, **kwargs)
                finally:
                    self._infra.on = False
            self.violations.append(f"{label} args={args[:1]!r}")
            raise AssertionError(f"forbidden filesystem call: {label}")
        return _f

    def __enter__(self):
        h = self
        orig_lstat = os.lstat
        orig_scandir = os.scandir

        def rec_lstat(path, *a, **k):
            if getattr(h._infra, "on", False):
                return orig_lstat(path, *a, **k)
            h.calls[f"os.lstat[{h._rel(path)}]"] += 1
            if not h._under(path):
                h.violations.append(f"os.lstat outside home: {path!r}")
            return orig_lstat(path, *a, **k)

        class _Entry:
            __slots__ = ("_e",)

            def __init__(self, e):
                self._e = e

            @property
            def name(self):
                return self._e.name

            @property
            def path(self):
                return self._e.path

            def is_symlink(self):
                h.calls["DirEntry.is_symlink"] += 1
                return self._e.is_symlink()

            def is_dir(self, *, follow_symlinks=True):
                if follow_symlinks:
                    h.violations.append(f"DirEntry.is_dir(follow_symlinks=True) {self._e.path!r}")
                    raise AssertionError("DirEntry.is_dir follows symlinks")
                h.calls["DirEntry.is_dir(follow_symlinks=False)"] += 1
                return self._e.is_dir(follow_symlinks=False)

            def is_file(self, *, follow_symlinks=True):
                if follow_symlinks:
                    h.violations.append(f"DirEntry.is_file(follow_symlinks=True) {self._e.path!r}")
                    raise AssertionError("DirEntry.is_file follows symlinks")
                h.calls["DirEntry.is_file(follow_symlinks=False)"] += 1
                return self._e.is_file(follow_symlinks=False)

            def stat(self, *, follow_symlinks=True):
                if follow_symlinks:
                    h.violations.append(f"DirEntry.stat(follow_symlinks=True) {self._e.path!r}")
                    raise AssertionError("DirEntry.stat follows symlinks")
                h.calls["DirEntry.stat(follow_symlinks=False)"] += 1
                return self._e.stat(follow_symlinks=False)

            def inode(self):
                h.calls["DirEntry.inode"] += 1
                return self._e.inode()

            def __fspath__(self):
                h.violations.append("DirEntry.__fspath__")
                raise AssertionError("DirEntry used as a path")

        class _Scan:
            def __init__(self, it):
                self._it = it

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._it.close()
                return False

            def __iter__(self):
                for e in self._it:
                    yield _Entry(e)

            def close(self):
                self._it.close()

        def rec_scandir(path=".", *a, **k):
            if getattr(h._infra, "on", False):
                return orig_scandir(path, *a, **k)
            h.calls[f"os.scandir[{h._rel(path)}]"] += 1
            if not h._under(path):
                h.violations.append(f"os.scandir outside home: {path!r}")
            return _Scan(orig_scandir(path, *a, **k))

        self._patch(os, "lstat", rec_lstat)
        self._patch(os, "scandir", rec_scandir)
        forbidden = [
            (builtins, "open"), (io, "open"), (io, "open_code"), (io, "FileIO"),
            (os, "open"), (os, "read"), (os, "pread"), (os, "fdopen"), (os, "stat"),
            (os, "readlink"), (os, "access"), (os, "listdir"), (os, "walk"), (os, "fwalk"),
            (os, "chmod"), (os, "utime"), (os, "remove"), (os, "unlink"), (os, "rename"),
            (os, "replace"), (os, "mkdir"), (os, "makedirs"), (os, "rmdir"), (os, "system"),
            (os, "popen"), (os, "truncate"), (os, "statvfs"),
            (os.path, "getsize"), (os.path, "getmtime"), (os.path, "getatime"),
            (os.path, "getctime"), (os.path, "exists"), (os.path, "isfile"),
            (os.path, "isdir"), (os.path, "islink"), (os.path, "lexists"),
            (os.path, "realpath"), (os.path, "samefile"),
            (Path, "open"), (Path, "read_text"), (Path, "read_bytes"), (Path, "write_text"),
            (Path, "write_bytes"), (Path, "stat"), (Path, "lstat"), (Path, "exists"),
            (Path, "is_file"), (Path, "is_dir"), (Path, "is_symlink"), (Path, "resolve"),
            (Path, "readlink"), (Path, "iterdir"), (Path, "glob"), (Path, "rglob"),
            (Path, "samefile"), (Path, "touch"), (Path, "mkdir"), (Path, "unlink"),
            (Path, "chmod"), (Path, "owner"), (Path, "group"), (Path, "walk"),
            (mmap, "mmap"), (hashlib, "file_digest"), (sqlite3, "connect"),
            (subprocess, "Popen"), (subprocess, "run"), (subprocess, "call"),
            (subprocess, "check_call"), (subprocess, "check_output"),
            (subprocess, "getoutput"), (subprocess, "getstatusoutput"),
        ]
        forbidden += [(shutil, n) for n in getattr(shutil, "__all__", ()) if callable(getattr(shutil, n, None))]
        for owner, attr in forbidden:
            if hasattr(owner, attr):
                label = f"{getattr(owner, '__name__', owner)}.{attr}"
                self._patch(owner, attr, self._forbid(label, getattr(owner, attr)))
        _AUDIT_WATCH["events"] = []
        _AUDIT_WATCH["active"] = True
        return self

    def __exit__(self, *exc):
        _AUDIT_WATCH["active"] = False
        for owner, attr, orig in reversed(self._saved):
            setattr(owner, attr, orig)
        self._saved.clear()
        self.audit_events = list(_AUDIT_WATCH["events"])
        return False


def _plant_everything(base: Path) -> Path:
    """A home that reaches every code path: stores, copies, work folders, fixtures, oddities."""
    home = base / "home"
    _touch(home / ".env", b"K=v\n")
    _touch(home / ".env.bak-1", b"K=v\n")
    _touch(home / "auth.json", b"{}")
    _touch(home / "auth.json.bak", b"{}")
    _touch(home / "shared" / "nous_auth.json", b"{}")
    _touch(home / "mcp-tokens" / "x.json", b"{}")
    _touch(home / "vault" / "vault.key", b"k")
    _touch(home / "secrets.yaml", b"k: v\n")
    _touch(home / "config.yaml", b"a: 1\n", mode=0o644)
    _touch(home / "config.yaml.bak", b"a: 1\n")
    _touch(home / "SOUL.md", b"persona\n", mode=0o644)
    for d in ("plans/p1", "tmp/t1/deep", "plugins/plg"):
        _touch(home / d / "id_ed25519", b"k")
        _touch(home / d / ".env", b"K=v\n", mode=0o644)
        _touch(home / d / "secrets.yaml", b"k: v\n")
        _touch(home / d / "mcp-tokens" / "x.json", b"{}")
    _touch(home / "backups" / "auth.json", b"{}")
    _touch(home / "plans" / "fx" / ".hermes" / ".env", b"K=v\n")
    _touch(home / "plans" / "fx" / ".hermes" / "auth.json", b"{}")
    _touch(home / "profiles" / "coder" / ".env", b"K=v\n")
    _touch(home / "profiles" / "coder" / "auth.json.old", b"{}")
    outside = base / "outside"
    _touch(outside / ".env", b"OUT=1\n")
    os.symlink(outside, home / "plans" / "linkdir")
    os.symlink(outside / ".env", home / "plans" / "linked.env")
    os.symlink("/nonexistent/target-text", home / "id_rsa")
    os.symlink("loop_b", home / "tmp" / "loop_a")
    os.symlink("loop_a", home / "tmp" / "loop_b")
    os.mkfifo(home / "tmp" / "pipe.env")
    locked = home / "tmp" / "locked"
    _touch(locked / ".env", b"K=v\n")
    os.chmod(locked, 0)
    noexec = home / "tmp" / "noexec"
    _touch(noexec / "auth.json", b"{}")
    os.chmod(noexec, 0o444)
    bad = os.path.join(os.fsencode(home / "tmp"), b"\xff\xfe-secret.json")
    with builtins.open(bad, "wb") as fh:
        fh.write(b"x")
    return home


def _restore_modes(home: Path) -> None:
    for d in (home / "tmp" / "locked", home / "tmp" / "noexec"):
        if os.path.lexists(d):
            os.chmod(d, 0o700)


def test_x8_no_touch_harness_every_code_path(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = _plant_everything(tmp_path)
    clock_ticks = iter([0.0, 0.0, 0.0] + [100.0] * 100000)
    runs = [
        dict(),
        dict(max_entries=5),
        dict(max_depth=1),
        dict(clock=lambda: next(clock_ticks), max_seconds=1.0),
    ]
    fat = tmp_path / "fat"
    _touch(fat / ".env", mode=0o777)
    _touch(fat / "auth.json", mode=0o666)
    extracted = tmp_path / "extracted"
    _touch(extracted / ".env", mode=0o600)
    _touch(extracted / "config.yaml", mode=0o600)
    _touch(extracted / "plans" / "a" / "auth.json", mode=0o600)
    a_file = tmp_path / "a_file"
    a_file.write_bytes(b"x")
    os.symlink(home, tmp_path / "home_link")
    results = []
    try:
        with _NoTouchHarness(tmp_path) as h:
            for kw in runs:
                results.append(mod.audit_secret_file_copies(home, **kw))
            for target in (fat, extracted, a_file, tmp_path / "home_link", tmp_path / "missing"):
                results.append(mod.audit_secret_file_copies(target))
    finally:
        _restore_modes(home)
    assert h.violations == []
    assert h.audit_events == [] or all(ev == "os.scandir" for ev, _ in h.audit_events), h.audit_events
    assert not [ev for ev, _ in h.audit_events if ev == "open"]
    allowed = {
        "os.lstat[home]", "os.scandir[home]", "DirEntry.is_symlink",
        "DirEntry.is_dir(follow_symlinks=False)", "DirEntry.is_file(follow_symlinks=False)",
        "DirEntry.stat(follow_symlinks=False)", "DirEntry.inode",
    }
    assert set(h.calls) <= allowed, sorted(h.calls)
    assert h.calls["os.scandir[home]"] > 0
    first = results[0]["secret_file_copies"]
    assert first["truncated_by"] == "subpath_unreadable"
    assert results[1]["secret_file_copies"]["truncated_by"] == "max_entries"
    assert results[2]["secret_file_copies"]["truncated_by"] == "max_depth"
    assert results[3]["secret_file_copies"]["truncated_by"] == "time_budget"
    assert first["fixture_homes"]["secret_named_file_count"] == 2
    assert first["symlinks"]["symlinks_skipped"] == 5
    assert results[4]["secret_file_copies"]["mode_bits"]["mode_check"] == "could_not_verify"
    assert results[5]["secret_file_copies"]["mode_bits"]["mode_check"] == "could_not_verify"
    assert [r["secret_file_copies"]["reason"] for r in results[6:]] == ["not_directory", "symlink_root", "missing"]


def test_x8_shared_nous_auth_is_an_expected_store(tmp_path):
    # hermes_cli/auth_nous.py:346-361: <root>/shared/nous_auth.json, shared across profiles.
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / "shared" / "nous_auth.json")
    _touch(home / "shared" / "nous_auth.lock", b"")
    res = mod.audit_secret_file_copies(home)
    sec = res["secret_file_copies"]
    assert sec["expected_secret_files"]["by_kind"]["shared_auth"] == 1
    assert sec["secret_named_files"]["count"] == 0
    assert res["findings"] == []
    # The shared store lives at the root only; a profile-level copy is not a Hermes location.
    _touch(home / "profiles" / "coder" / "shared" / "nous_auth.json")
    res2 = mod.audit_secret_file_copies(home)
    assert res2["secret_file_copies"]["secret_named_files"]["count"] == 1


def test_x8_every_source_derived_store_is_expected(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    expected_paths = [
        ".env", ".op.env", ".envrc", "auth.json", "shared/nous_auth.json",
        "mcp-tokens/github.json", "pairing/discord-approved.json",
        "platforms/pairing/telegram-pending.json", "feishu_comment_pairing.json",
        "vault/vault.key", "vault/vault.json.enc", "slack_tokens.json", "honcho.json",
        "mem0.json", "webhook_subscriptions.json", "teams_pipeline_store.json", "npmrc",
        "bws_cache.json", "op_cache.json", "photon-sidecar.json", "cache/bws_cache.enc.json",
        "runtime/photon-sidecar.json", "workspace/meetings/node_token.json",
        "weixin/accounts/bot.json", "whatsapp/session/creds.json",
        "platforms/matrix/store/secret-store.json", "webapp/session-token",
        "webapp/native-sign-in-tokens.json", "proxy/ca.key", ".anthropic_oauth.json",
        "auth/google_oauth.json", "google_token.json", "google_client_secret.json",
        "google_chat_user_tokens/u.json", ".copilot_jwt.json",
        "browser-profile/Default/auth-token.json", "browser_auth/state-secret.json",
        "bot-desktop/token.json", "browser-profiles/p/oauth-cookies.json",
        "chrome-debug/Default/secrets.json", "home/.ssh/id_ed25519",
        "home/.git-credentials", "home/.config/gh/oauth.json", ".ssh/id_rsa",
        ".aws/credentials", ".config/gcloud/application_default_credentials.json",
        "credentials.json", "profiles/coder/.env", "profiles/coder/home/.ssh/id_rsa",
    ]
    for rel in expected_paths:
        _touch(home / rel)
    # Hermes-written files whose names merely look secret: not stores, not flagged.
    for rel in ("cache/oauth_heal_clean.json", "cache/image_token_costs.json",
                "cache/platform-ca-bundle.pem"):
        _touch(home / rel)
    res = mod.audit_secret_file_copies(home)
    sec = res["secret_file_copies"]
    assert sec["secret_named_files"]["count"] == 0, sec["secret_named_files"]
    assert sec["expected_secret_files"]["total"] == len(expected_paths)
    assert res["findings"] == []


INNOCENT_NAMES = (
    "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json", "tokens.css",
    "design-tokens.json", "token_counts.json", "secretary.md", "keyboard.json", "monkey.png",
    "turkey.key", "package-lock.json", "auth.md", "oauth-flow.png", "credentials.example.json",
    ".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults",
    "id_rsa.pub", "server.crt", "root-ca.cer", "tokens.txt", "secretary-notes.txt",
    "secretaries.csv", "author.json", "authority.json", "id_mapping.csv", ".envoy.yaml",
    "environment.yml", "debug.keystore", "keymap.json", "hotkeys.json",
    "credentials.sample.yaml", "secrets.template.yaml", "auth.template.json", "example.env",
    "tokenize.py", "auth_test.go", "secret_santa.md", "token_usage.json", "ca-bundle.pem",
    "cacert.pem", "fullchain.pem", "Q3 Review.key", "presentation.key", "jwt-decoder.html",
    "id_card.png", ".env.local.example", "README.md", "id_FEMININE.pak", "server.csr",
)
SECRET_LIKE_NAMES = (
    ".env", ".env.local", ".env.production", ".env.bak", "prod.env", "service.env", ".envrc",
    "auth.json", "discord-auth.json", "google-auth.json", "client_secret.json",
    "client_secret_123.apps.googleusercontent.com.json", "secrets.yaml", "secrets.json",
    "app-secret.yaml", "credentials", "credentials.json", "aws-credentials", ".git-credentials",
    "gcp-service-account.json", "token.json", "refresh_token.json", "access-tokens.json",
    "slack_tokens.json", "oauth_creds.json", "native-oauth-tokens.json", "private.key",
    "server.key", "tls.key", "www.mysite.org.key", "privkey.pem", "id_rsa", "id_ed25519",
    "id_ecdsa", "id_dsa", "bundle.p12", "cert.pfx", "release.keystore", "upload.jks",
    "putty.ppk", ".netrc", ".npmrc", ".pypirc", ".pgpass", "pip.conf", "master.key",
    "api_key.txt", "openai-apikey.txt", "my-tokens.dat",
)


def test_x8_name_precision_and_recall(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    assert len(INNOCENT_NAMES) >= 40 and len(SECRET_LIKE_NAMES) >= 40
    false_pos = [n for n in INNOCENT_NAMES if mod.classify_secret_filename(n, ("plans", "p", n))]
    missed = [n for n in SECRET_LIKE_NAMES if not mod.classify_secret_filename(n, ("plans", "p", n))]
    assert false_pos == []
    assert missed == []
    # Same through the entry point, plus vendored package trees.
    home = tmp_path / "home"
    for n in INNOCENT_NAMES:
        _touch(home / "plans" / "innocent" / n, mode=0o644)
    for vend in ("lib/python3.12/site-packages/certifi", "node_modules/pkg/test",
                 "lib/python3.12/site-packages/pkg/tests", "vendor/pip/_vendor/certifi"):
        _touch(home / "tools" / "env" / vend / "test.pem")
        _touch(home / "tools" / "env" / vend / "server.key")
        _touch(home / "tools" / "env" / vend / ".env")
    res = mod.audit_secret_file_copies(home)
    assert res["secret_file_copies"]["secret_named_files"]["count"] == 0
    for n in SECRET_LIKE_NAMES:
        _touch(home / "plans" / "secret" / n)
    res2 = mod.audit_secret_file_copies(home)
    assert res2["secret_file_copies"]["secret_named_files"]["count"] == len(SECRET_LIKE_NAMES)


def test_x8_example_locations_hide_deep_components_and_basenames(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / "plans" / "ZQXCANARYSECONDLEVEL" / "ZQXCANARYTHIRD" / "ZQXCANARYleaf-auth.json")
    _touch(home / "plans" / "ZQXCANARYSHALLOW" / "ZQXCANARYtoken.json")
    _touch(home / "plugins" / "zqxcanaryplugin" / "deep" / "ZQXCANARY-secret.yaml")
    _touch(home / "tmp" / "ZQXCANARYdotenv.env")
    _touch(home / "ZQXCANARYtop-credentials.json")
    os.symlink("/srv/ZQXCANARYLINKTARGET/key.pem", home / "plans" / "ZQXCANARYlink.pem")
    res = mod.audit_secret_file_copies(home)
    dumped = json.dumps(res)
    # The only canary that may appear is none: no top-level folder or plugin folder here
    # carries one (the secret-named root file is attributed to the home root path).
    assert "ZQXCANARY" not in dumped.upper()
    sec = res["secret_file_copies"]["secret_named_files"]
    h = str(home)
    assert sec["by_top_level_folder"] == [
        {"path": h, "count": 1, "classes": {"credential": 1}},
        {"path": h + "/plans", "count": 2, "classes": {"auth-json": 1, "token-json": 1}},
        {"path": h + "/plugins", "count": 1, "classes": {"secret_word": 1}},
        {"path": h + "/tmp", "count": 1, "classes": {"dotenv": 1}},
    ]
    assert sorted((r["path"], r["class"]) for r in sec["example_locations"]) == sorted([
        (h, "credential"), (h + "/plans", "auth-json"), (h + "/plans", "token-json"),
        (h + "/plugins", "secret_word"), (h + "/tmp", "dotenv"),
    ])
    # A non-.env file in a plugin folder names no plugin folder.
    assert sec["plugin_folders_with_dotenv"] == []
    _assert_paths_capped(res, home)


def test_x8_secret_sizes_never_output_and_months_only(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / ".env", b"A" * 7919, mtime=1789095614.0)
    _touch(home / ".env.bak", b"A" * 7919, mtime=1787793492.0)
    _touch(home / "plans" / "x" / "auth.json", b"B" * 6037)
    res = mod.audit_secret_file_copies(home)
    dumped = json.dumps(res)
    assert "7919" not in dumped and "6037" not in dumped
    copies = res["secret_file_copies"]["backup_copies"]["copies"]
    assert copies == [{"secret_kind": "dotenv", "scope": "home", "same_size_as_live": True,
                       "year": 2026, "month": 8}]


def test_x8_could_not_verify_is_info_and_warnings_are_warnings(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / ".env")
    _touch(home / ".env.bak")
    _touch(home / "plans" / "a" / "secrets.yaml")
    res = mod.audit_secret_file_copies(home, max_entries=2)
    cls = {f["id"]: f["classification"] for f in res["findings"]}
    assert cls["secret_file_copies.could_not_verify"] == "info"
    res_full = mod.audit_secret_file_copies(home)
    cls_full = {f["id"]: f["classification"] for f in res_full["findings"]}
    assert cls_full["secret_file_copies.backup_copies_of_secret_files"] == "warning"
    assert cls_full["secret_file_copies.secret_named_files_in_work_folders"] == "warning"
    missing = mod.audit_secret_file_copies(tmp_path / "nope")
    assert [f["classification"] for f in missing["findings"]] == ["info"]


def _healthy_home(base: Path) -> Path:
    home = base / "home"
    _touch(home / ".env", mode=0o600)
    _touch(home / "auth.json", mode=0o600)
    _touch(home / "config.yaml", b"model: x\n", mode=0o644)
    _touch(home / "SOUL.md", b"persona\n", mode=0o644)
    _touch(home / "memories" / "MEMORY.md", b"note\n", mode=0o644)
    _touch(home / "shared" / "nous_auth.json", mode=0o600)
    _touch(home / "mcp-tokens" / "github.json", mode=0o600)
    _touch(home / "backups" / "config" / "config.yaml.20261001-120000", mode=0o600)
    _touch(home / "skills" / "writing" / "SKILL.md", b"x\n", mode=0o644)
    _touch(home / "skills" / "writing" / "references" / "auth.md", b"x\n", mode=0o644)
    _touch(home / "models" / "tokenizer.json", mode=0o644)
    _touch(home / "cache" / "image_token_costs.json", mode=0o644)
    _touch(home / "cache" / "oauth_heal_clean.json", mode=0o644)
    _touch(home / "cache" / "platform-ca-bundle.pem", mode=0o644)
    _touch(home / "home" / ".ssh" / "id_ed25519", mode=0o600)
    _touch(home / "home" / ".ssh" / "id_ed25519.pub", mode=0o644)
    _touch(home / "profiles" / "coder" / ".env", mode=0o600)
    _touch(home / "profiles" / "coder" / "config.yaml", mode=0o644)
    _touch(home / "tools" / "py" / "lib" / "site-packages" / "certifi" / "cacert.pem", mode=0o644)
    _touch(home / "plans" / "design" / "design-tokens.json", mode=0o644)
    _touch(home / "plans" / "design" / "deck.key", mode=0o644)
    return home


def test_x8_healthy_home_has_no_finding_above_info(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = _healthy_home(tmp_path)
    res = mod.audit_secret_file_copies(home)
    assert [f for f in res["findings"] if f["classification"] != "info"] == []
    sec = res["secret_file_copies"]
    assert sec["mode_bits"]["mode_check"] == "verified"
    assert sec["mode_bits"]["readable_by_others_count"] == 0
    assert sec["secret_named_files"]["count"] == 0


def test_x8_mode_bits_not_representable_or_normalised(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    # Extraction set every file owner-only: cannot tell anything, must not claim safe.
    ex = tmp_path / "extracted"
    for rel, m in ((".env", 0o600), ("config.yaml", 0o600), ("SOUL.md", 0o400),
                   ("scripts/run.sh", 0o700), ("plans/a/auth.json", 0o600)):
        _touch(ex / rel, mode=m)
    r = mod.audit_secret_file_copies(ex)["secret_file_copies"]["mode_bits"]
    assert r["mode_check"] == "could_not_verify"
    assert r["mode_check_reason"] == "no_group_or_other_bits_anywhere"
    assert r["readable_by_others_count"] is None
    # One uniform permissive mode for everything (FAT/NTFS, or an extraction to 0644).
    for name, mode in (("fat", 0o777), ("uniform", 0o644)):
        d = tmp_path / name
        _touch(d / ".env", mode=mode)
        _touch(d / "config.yaml", mode=mode)
        _touch(d / "SOUL.md", mode=mode)
        res = mod.audit_secret_file_copies(d)
        mb = res["secret_file_copies"]["mode_bits"]
        assert mb["mode_check"] == "could_not_verify", name
        assert mb["readable_by_others_count"] is None
        assert "secret_file_copies.readable_by_others" not in {f["id"] for f in res["findings"]}


def test_x8_deterministic_across_clocks(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = _healthy_home(tmp_path)
    _touch(home / ".env.bak", mtime=1787793492.0)
    _touch(home / "plans" / "a" / "secrets.yaml")
    day = 86400.0
    t0 = iter(float(i) for i in range(10**6))
    t1 = iter(9 * day + i * 0.001 for i in range(10**6))
    a = mod.audit_secret_file_copies(home, clock=lambda: next(t0), max_seconds=10**9)
    b = mod.audit_secret_file_copies(home, clock=lambda: next(t1), max_seconds=10**9)
    assert a["secret_file_copies"] == b["secret_file_copies"]
    assert a["findings"] == b["findings"]


@pytest.mark.parametrize("bad", [None, 7, "bad\x00path", b"\xff\x00", ""])
def test_x8_invalid_profile_path_never_raises(bad):
    mod = load_submodule("audit.secret_file_copies")
    res = mod.audit_secret_file_copies(bad)
    sec = res["secret_file_copies"]
    assert sec["status"] == "not_measured"
    assert res["coverage"] == "could_not_verify"
    assert [f["classification"] for f in res["findings"]] == ["info"]


def test_x8_read_only_on_0555_tree(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = _plant_everything(tmp_path)
    _restore_modes(home)
    dirs = [d for d, _, _ in os.walk(home)]
    modes = {d: stat.S_IMODE(os.lstat(d).st_mode) for d in dirs}
    try:
        for d in dirs:
            os.chmod(d, 0o555)
        before = _snapshot_tree(home)
        mod.audit_secret_file_copies(home)
        after = _snapshot_tree(home)
    finally:
        for d in reversed(dirs):
            os.chmod(d, modes[d])
    assert after == before


def test_x8_fixture_roots_are_outermost_marker_directories(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    outer = home / "plans" / "fx" / ".hermes"
    _touch(outer / ".env")
    _touch(outer / "profiles" / "p" / "SOUL.md")
    _touch(outer / "profiles" / "p" / ".env")
    _touch(outer / "nested" / ".hermes" / "auth.json")
    _touch(home / "plans" / "other" / "SOUL.md")
    _touch(home / "plans" / "other" / ".env")
    sec = mod.audit_secret_file_copies(home)["secret_file_copies"]["fixture_homes"]
    assert sec["fixture_home_count"] == 2
    assert sec["secret_named_file_count"] == 4


def test_x8_deleted_profile_config_copy_counts_as_profile(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / "config.yaml.bak", mode=0o644)
    _touch(home / "profiles" / ".deleted" / "config.yaml.bak-20260903-x")
    _touch(home / "profiles" / "coder" / "config.yaml.bak-20260912-y")
    cb = mod.audit_secret_file_copies(home)["secret_file_copies"]["config_backups"]
    assert (cb["count"], cb["root_count"], cb["profile_count"]) == (3, 1, 2)


def test_x8_doc_lists_every_consequence_and_kind_verbatim():
    mod = load_submodule("audit.secret_file_copies")
    doc = (Path(__file__).resolve().parent.parent / "docs" / "audit-sections" / "secret_file_copies.md").read_text(encoding="utf-8")
    for rule_id, sentence in mod.FINDING_CONSEQUENCES.items():
        assert f"`{rule_id}`" in doc
        assert sentence in doc, rule_id
    for kind in mod.EXPECTED_SECRET_KINDS:
        assert f"`{kind}`" in doc
    for cls_label, _ in mod.SECRET_PATTERN_CLASSES:
        assert f"`{cls_label}`" in doc


# ---------------------------------------------------------------------------
# Wiring preparation: fixed consequences, digest safety, envelope, sealing.
# ---------------------------------------------------------------------------


def test_wire_third_party_plugin_auth_store_at_root_stays_flagged(tmp_path):
    # A third-party plugin writing its own auth store at the home root is not a place the
    # Hermes source keeps secrets, so it is counted as a secret-named file and the
    # consequence sentence says why.
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / ".env")
    _touch(home / "thirdparty-auth.json")
    res = mod.audit_secret_file_copies(home)
    sec = res["secret_file_copies"]["secret_named_files"]
    assert sec["count"] == 1
    # A file at the home root is attributed to the home root path, never its own path.
    assert sec["by_top_level_folder"] == [{"path": str(home), "count": 1, "classes": {"auth-json": 1}}]
    assert sec["example_locations"] == [{"path": str(home), "class": "auth-json"}]
    assert sec["by_pattern_class"] == {"auth-json": 1}
    finding = next(f for f in res["findings"]
                   if f["id"] == "secret_file_copies.secret_named_files_in_work_folders")
    assert "third-party plugins" in finding["consequence"]
    assert "not known to the audit as expected stores" in finding["consequence"]


def test_wire_every_consequence_is_one_fixed_sentence_set():
    mod = load_submodule("audit.secret_file_copies")
    import re as _re
    for rule_id, sentence in mod.FINDING_CONSEQUENCES.items():
        assert rule_id.startswith("secret_file_copies.")
        assert not _re.search(r"\d+ (files?|copies|folders?)", sentence), rule_id
        assert "{" not in sentence and "%" not in sentence, rule_id
        low = sentence.lower()
        for banned in (" you ", "you ", " your ", "indicates", "suggests", "unpruned", "abandoned"):
            assert not low.startswith(banned.strip() + " ") and banned not in f" {low} ", (rule_id, banned)


def test_wire_digest_safe_section_and_run_metrics_outside(tmp_path):
    # Two runs on an unchanged home with clocks days apart: byte-identical section and
    # identical findings; elapsed time lives only in the top-level run_metrics sibling.
    mod = load_submodule("audit.secret_file_copies")
    home = _healthy_home(tmp_path)
    _touch(home / ".env.bak", mtime=1787793492.0)
    _touch(home / "plans" / "a" / "secrets.yaml")
    _touch(home / "config.yaml.bak", mtime=1787793492.0)
    day = 86400.0
    t0 = iter(1000.0 + i * 0.5 for i in range(10**6))
    t1 = iter(40 * day + i * 0.001 for i in range(10**6))
    a = mod.audit_secret_file_copies(home, clock=lambda: next(t0), max_seconds=10**9)
    b = mod.audit_secret_file_copies(home, clock=lambda: next(t1), max_seconds=10**9)
    assert json.dumps(a["secret_file_copies"], sort_keys=True) == json.dumps(b["secret_file_copies"], sort_keys=True)
    assert json.dumps(a["findings"], sort_keys=True) == json.dumps(b["findings"], sort_keys=True)
    assert set(a["run_metrics"]) == {"elapsed_seconds"}
    assert a["run_metrics"]["elapsed_seconds"] != b["run_metrics"]["elapsed_seconds"]
    assert "elapsed_seconds" not in json.dumps(a["secret_file_copies"])
    for copy in a["secret_file_copies"]["backup_copies"]["copies"]:
        assert set(copy) == {"secret_kind", "scope", "same_size_as_live", "year", "month"}


def test_wire_envelope_shape_and_adapt_component_result(tmp_path):
    mod = load_submodule("audit.secret_file_copies")
    contract = load_submodule("audit.contract")
    home = _healthy_home(tmp_path)
    _touch(home / "plans" / "a" / "secrets.yaml")
    envelopes = [mod.audit_secret_file_copies(home), mod.audit_secret_file_copies(tmp_path / "nope"),
                 mod.audit_secret_file_copies(None)]
    for env in envelopes:
        assert set(env) == {"secret_file_copies", "findings", "run_metrics", "status", "coverage"}
        assert env["status"] in {"pass", "fail"}
        for f in env["findings"]:
            assert f["id"].startswith("secret_file_copies.")
        adapted = contract.adapt_component_result(env, component_id="secret_file_copies",
                                                  affected_identities=["profile:default"])
        assert adapted["secret_file_copies"] == env["secret_file_copies"]
        assert adapted["run_metrics"] == env["run_metrics"]
        assert adapted["coverage"] == env["coverage"]
        assert adapted["operational_error"] is None
        assert [f["id"] for f in adapted["findings"]] == [f["id"] for f in env["findings"]]
        assert [f["consequence"] for f in adapted["findings"]] == [f["consequence"] for f in env["findings"]]


def test_wire_free_string_maps_have_count_twins(tmp_path):
    # Top-level and plugin folders are reported as absolute paths of existing folders; the
    # section also carries plain counts of them.
    mod = load_submodule("audit.secret_file_copies")
    home = tmp_path / "home"
    _touch(home / "plans" / "a" / "secrets.yaml")
    _touch(home / "tmp" / "token.json")
    _touch(home / "plugins" / "p1" / ".env")
    _touch(home / "plugins" / "p2" / "sub" / ".env")
    _touch(home / "profiles" / "coder" / "plugins" / "p3" / ".env.local")
    _touch(home / "thirdparty-auth.json")
    res = mod.audit_secret_file_copies(home)
    sec = res["secret_file_copies"]["secret_named_files"]
    assert sec["top_level_folder_count"] == len(sec["by_top_level_folder"]) == 5
    assert [r["path"] for r in sec["by_top_level_folder"]] == sorted(
        [str(home), str(home / "plans"), str(home / "plugins"), str(home / "profiles"), str(home / "tmp")])
    assert sum(r["count"] for r in sec["by_top_level_folder"]) == sec["count"] == 6
    for r in sec["by_top_level_folder"]:
        assert sum(r["classes"].values()) == r["count"]
    assert sec["plugin_folder_count"] == len(sec["plugin_folders_with_dotenv"]) == 3
    # Plugin FOLDERS, never the .env file path.
    assert sec["plugin_folders_with_dotenv"] == sorted([
        str(home / "plugins" / "p1"), str(home / "plugins" / "p2"),
        str(home / "profiles" / "coder" / "plugins" / "p3")])
    _assert_paths_capped(res, home)
    empty = mod.audit_secret_file_copies(tmp_path / "nope")["secret_file_copies"]["secret_named_files"]
    assert (empty["top_level_folder_count"], empty["plugin_folder_count"]) == (0, 0)


# --- Sealing: audit/wiring/secret_file_copies.json is complete and nothing is lost --------

_WIRING_PATH = Path(__file__).resolve().parent.parent / "audit" / "wiring" / "secret_file_copies.json"
_FINDING_FIELDS = frozenset({
    "id", "classification", "coverage", "affected_identities", "source_paths", "evidence",
    "consequence", "limitations", "proposed_cleanup_id", "severity", "detail", "fix",
})
# Kept absolute paths (the only non-vocabulary strings): the `path` field of the objects in
# these lists, and the values of the plugin folder list.
_PATH_ROW_LISTS = frozenset({"by_top_level_folder", "example_locations"})
_PATH_VALUE_LISTS = frozenset({"plugin_folders_with_dotenv"})
_FREE_STRING_KEYS = frozenset({"by_top_level_folder.path", "example_locations.path",
                               "plugin_folders_with_dotenv"})


def _is_kept_path_position(path: tuple) -> bool:
    return ((len(path) >= 3 and path[-1] == "path" and path[-2] == "[]" and path[-3] in _PATH_ROW_LISTS)
            or (len(path) >= 2 and path[-1] == "[]" and path[-2] in _PATH_VALUE_LISTS))


def _wiring() -> dict:
    return json.loads(_WIRING_PATH.read_text(encoding="utf-8"))


def _wire_envelopes(tmp_path: Path) -> list[dict]:
    """Envelopes from synthetic homes that reach every reachable branch of the module."""
    mod = load_submodule("audit.secret_file_copies")
    envs: list[dict] = []
    home = _plant_everything(tmp_path / "all")
    ticks = iter([0.0, 0.0, 0.0] + [100.0] * 100000)
    try:
        for kw in (dict(), dict(max_entries=5), dict(max_depth=1),
                   dict(clock=lambda: next(ticks), max_seconds=1.0)):
            envs.append(mod.audit_secret_file_copies(home, **kw))
    finally:
        _restore_modes(home)
    envs.append(mod.audit_secret_file_copies(_healthy_home(tmp_path / "healthy")))
    # Mode bits verified with a readable-by-others secret, backup folders, profiles.
    mixed = tmp_path / "mixed"
    _touch(mixed / ".env", mode=0o600)
    _touch(mixed / "auth.json", mode=0o644)
    _touch(mixed / "config.yaml", mode=0o600)
    _touch(mixed / ".env.bak-20260910", mode=0o644, mtime=1787793492.0)
    _touch(mixed / "backups" / "auth.json", mode=0o600)
    _touch(mixed / "profiles" / "coder" / ".env", mode=0o600)
    _touch(mixed / "profiles" / "coder" / ".env.old", mode=0o600)
    _touch(mixed / "profiles" / ".deleted" / "auth.json.bak", mode=0o600)
    _touch(mixed / "shared" / "nous_auth.json.bak", mode=0o600)
    _touch(mixed / "thirdparty-auth.json", mode=0o600)
    for idx, ts in enumerate((1790912843.0, 1790912845.0, 1790912846.0, 1790912848.0,
                              1790912849.0, 1790912850.0)):
        _touch(mixed / "backups" / "config" / f"config.yaml.{idx}", mtime=ts)
    _touch(mixed / "plugins" / "p1" / ".env")
    _touch(mixed / "plans" / "fx" / "fixture" / "SOUL.md")
    _touch(mixed / "plans" / "fx" / "fixture" / "secrets.json")
    envs.append(mod.audit_secret_file_copies(mixed))
    # Every not-measured reason.
    a_file = tmp_path / "a_file"
    a_file.write_bytes(b"x")
    os.symlink(mixed, tmp_path / "link_root")
    noperm = tmp_path / "noperm"
    (noperm / "child").mkdir(parents=True)
    os.chmod(noperm, 0)
    try:
        for target in (a_file, tmp_path / "link_root", tmp_path / "missing", None, "",
                       noperm / "child"):
            envs.append(mod.audit_secret_file_copies(target))
    finally:
        os.chmod(noperm, 0o700)
    for name, mode in (("fat", 0o777), ("uniform", 0o644)):
        d = tmp_path / name
        _touch(d / ".env", mode=mode)
        _touch(d / "config.yaml", mode=mode)
        envs.append(mod.audit_secret_file_copies(d))
    return envs


def _walk_section(node, wiring, path=(), seen=None):
    """Strict walk: every key in schema_keys, every string in vocabulary or under a free key."""
    seen = seen if seen is not None else {"strings": set(), "keys": set()}
    schema, vocab = set(wiring["schema_keys"]), set(wiring["vocabulary"])
    if isinstance(node, dict):
        for k, v in node.items():
            assert isinstance(k, str), path
            assert k in schema, ("unlisted key", path, k)
            seen["keys"].add(k)
            _walk_section(v, wiring, path + (k,), seen)
    elif isinstance(node, list):
        for item in node:
            _walk_section(item, wiring, path + ("[]",), seen)
    elif isinstance(node, str) and _is_kept_path_position(path):
        assert os.path.isabs(node) and os.path.isdir(node), (path, node)
        seen["paths"] = seen.get("paths", 0) + 1
    elif isinstance(node, str):
        assert node in vocab, ("unlisted string", path, node)
        seen["strings"].add(node)
    else:
        assert node is None or type(node) in (bool, int, float), (path, node)
    return seen


def test_wire_json_is_complete_strict_walk(tmp_path):
    wiring = _wiring()
    assert set(wiring) == {
        "section", "entry", "kwargs", "schema_keys", "vocabulary", "numeric_evidence_keys",
        "vocab_evidence_keys", "rule_ids", "classifications", "consequences", "free_strings",
        "run_metrics_keys", "notes",
    }
    mod = load_submodule("audit.secret_file_copies")
    assert wiring["section"] == "secret_file_copies"
    assert wiring["entry"] == "audit.secret_file_copies.audit_secret_file_copies"
    assert wiring["schema_keys"] == sorted(set(wiring["schema_keys"]))
    assert wiring["vocabulary"] == sorted(set(wiring["vocabulary"]))
    assert wiring["consequences"] == mod.FINDING_CONSEQUENCES
    assert sorted(wiring["rule_ids"]) == sorted(mod.FINDING_CONSEQUENCES)
    assert {f["key"] for f in wiring["free_strings"]} == _FREE_STRING_KEYS
    for f in wiring["free_strings"]:
        assert set(f) == {"key", "what", "example", "why_safe"}
    num_keys, voc_keys = set(wiring["numeric_evidence_keys"]), set(wiring["vocab_evidence_keys"])
    seen = {"strings": set(), "keys": set()}
    rules_seen: dict[str, set] = {}
    for env in _wire_envelopes(tmp_path):
        assert set(env["run_metrics"]) == set(wiring["run_metrics_keys"])
        assert "secret_file_copies" in wiring["schema_keys"]
        _walk_section(env["secret_file_copies"], wiring, seen=seen)
        assert env["status"] in wiring["vocabulary"] or env["status"] in {"pass", "fail"}
        assert env["coverage"] in wiring["vocabulary"]
        for f in env["findings"]:
            assert set(f) <= _FINDING_FIELDS, set(f) - _FINDING_FIELDS
            rid = f["id"]
            assert rid in wiring["rule_ids"]
            assert f["classification"] in wiring["classifications"][rid]
            rules_seen.setdefault(rid, set()).add(f["classification"])
            assert f["consequence"] == f["detail"] == wiring["consequences"][rid]
            for text in (f["coverage"], f["severity"], f["classification"], rid):
                assert text in wiring["vocabulary"], text
            assert f["affected_identities"] == [] and f["source_paths"] == []
            assert f["limitations"] == "" and f["fix"] is None and f["proposed_cleanup_id"] is None
            for k, v in f["evidence"].items():
                if k in num_keys:
                    assert type(v) in (int, float, bool), (rid, k, v)
                else:
                    assert k in voc_keys, (rid, k)
                    assert v in wiring["vocabulary"], (rid, k, v)
                assert k in wiring["schema_keys"], k
    # Every rule and every classification is reached by the synthetic homes.
    assert {r: sorted(c) for r, c in rules_seen.items()} == {
        r: sorted(c) for r, c in wiring["classifications"].items()}
    # Every enumerated section value except the defensive fallback is reached.
    reachable = set(wiring["vocabulary"]) - set(wiring["rule_ids"]) - set(wiring["consequences"].values())
    reachable -= {"limit_exceeded", "warning", "review_suggested", "info", "warn", "secret_file_copies"}
    reachable -= set(mod.EXPECTED_SECRET_KINDS) | {c for c, _ in mod.SECRET_PATTERN_CLASSES}
    assert reachable - seen["strings"] == set()
    section_keys = set(wiring["schema_keys"]) - num_keys - voc_keys - {"secret_file_copies"}
    section_keys -= set(mod.EXPECTED_SECRET_KINDS) | {c for c, _ in mod.SECRET_PATTERN_CLASSES}
    assert section_keys - seen["keys"] == set()
    assert seen.get("paths", 0) > 0


def _patch_sealing_sets(monkeypatch, wiring):
    evidence = load_submodule("audit.evidence")
    persistence = load_submodule("audit.persistence")
    constants = load_submodule("audit.evidence_constants")
    cons = dict(wiring["consequences"])
    rule_ids = frozenset(wiring["rule_ids"])
    vocab = frozenset(wiring["vocabulary"]) | rule_ids | frozenset(cons.values())
    monkeypatch.setattr(evidence, "SCHEMA_KEYS", evidence.SCHEMA_KEYS | frozenset(wiring["schema_keys"]))
    monkeypatch.setattr(evidence, "VOCABULARY", evidence.VOCABULARY | vocab)
    monkeypatch.setattr(persistence, "VOCABULARY", persistence.VOCABULARY | vocab)
    monkeypatch.setattr(persistence, "_EVIDENCE_NUMERIC_KEYS",
                        persistence._EVIDENCE_NUMERIC_KEYS | frozenset(wiring["numeric_evidence_keys"]))
    monkeypatch.setattr(persistence, "_EVIDENCE_VOCAB_KEYS",
                        persistence._EVIDENCE_VOCAB_KEYS | frozenset(wiring["vocab_evidence_keys"]))
    merged = {**persistence.FINDING_CONSEQUENCES, **cons}
    allowed = persistence.ALLOWED_FINDING_CONSEQUENCES | frozenset(cons.values())
    monkeypatch.setattr(persistence, "FINDING_CONSEQUENCES", merged)
    monkeypatch.setattr(persistence, "ALLOWED_FINDING_CONSEQUENCES", allowed)
    monkeypatch.setattr(constants, "FINDING_CONSEQUENCES", merged)
    monkeypatch.setattr(constants, "ALLOWED_FINDING_CONSEQUENCES", allowed)
    monkeypatch.setattr(constants, "RULE_IDS", constants.RULE_IDS | rule_ids)
    return evidence, persistence


def _compare_sealed(raw, sealed, path=(), report=None):
    """Assert sealed == raw except at free-string positions; record what happened there."""
    report = report if report is not None else Counter()
    evidence = load_submodule("audit.evidence")
    if isinstance(raw, dict):
        assert isinstance(sealed, dict) and not isinstance(sealed, evidence.SealedEvidence), path
        assert list(sealed) == list(raw), ("key dropped or renamed", path)
        assert not any(isinstance(k, evidence.SealedKey) for k in sealed), path
        for k in raw:
            _compare_sealed(raw[k], sealed[k], path + (k,), report)
    elif isinstance(raw, list):
        assert isinstance(sealed, list) and len(sealed) == len(raw), path
        for a, b in zip(raw, sealed):
            _compare_sealed(a, b, path + ("[]",), report)
    else:
        # Every value, kept absolute paths included, comes back unchanged (no token).
        assert sealed == raw and type(sealed) is type(raw), ("value altered", path, raw, sealed)
        if _is_kept_path_position(path):
            key = path[-3] + ".path" if path[-1] == "path" else path[-2]
            report[f"{key}:kept as is"] += 1
    return report


def _hmac_dicts(node, path=()):
    """Paths of every dict carrying an `hmac` field (a serializer token) or a sealed key."""
    found = []
    if isinstance(node, dict):
        if "hmac" in node:
            found.append(path)
        for k, v in node.items():
            if isinstance(k, str) and k.startswith("hmac:"):
                found.append(path + (k,))
            found.extend(_hmac_dicts(v, path + (str(k),)))
    elif isinstance(node, (list, tuple)):
        for i, v in enumerate(node):
            found.extend(_hmac_dicts(v, path + (i,)))
    return found


def test_wire_sealing_keeps_everything_and_produces_no_token(tmp_path, monkeypatch):
    wiring = _wiring()
    contract = load_submodule("audit.contract")
    evidence, persistence = _patch_sealing_sets(monkeypatch, wiring)
    report = Counter()
    for env in _wire_envelopes(tmp_path):
        adapted = contract.adapt_component_result(env, component_id="secret_file_copies",
                                                  affected_identities=["profile:default"])
        assert adapted["run_metrics"] == env["run_metrics"]
        section = adapted["secret_file_copies"]
        sealed = evidence.serialize_evidence({"secret_file_copies": section})
        assert list(sealed) == ["secret_file_copies"]
        _compare_sealed(section, sealed["secret_file_copies"], report=report)
        assert _hmac_dicts(sealed) == []
        # The same section passes the report digest serializer (strict JSON, no raise).
        contract.canonical_report_bytes({"secret_file_copies": section})
        dto = persistence.component_dto(adapted)
        assert dto["component_id"] == "secret_file_copies"
        assert dto["coverage"] == env["coverage"]
        assert len(dto["findings"]) == len(env["findings"])
        for raw, out in zip(env["findings"], dto["findings"]):
            assert out["id"] == raw["id"]
            assert out["classification"] == raw["classification"]
            assert out["coverage"] == raw["coverage"]
            assert out["severity"] == raw["severity"]
            assert out["consequence"] == out["detail"] == raw["consequence"]
            kept = {k: v for k, v in out["evidence"].items() if k != "source_digest"}
            assert kept == raw["evidence"], (raw["id"], raw["evidence"], kept)
        assert _hmac_dicts(dto) == []
    # Every kept-path position was reached and returned unchanged by the serializer.
    assert set(report) == {f"{k}:kept as is" for k in _FREE_STRING_KEYS}, report


def test_wire_two_runs_seal_identically(tmp_path, monkeypatch):
    # Each run gets a fresh serializer (a fresh per-run token key): any token in the output
    # would make the two sealed results differ.
    wiring = _wiring()
    contract = load_submodule("audit.contract")
    evidence, persistence = _patch_sealing_sets(monkeypatch, wiring)
    mod = load_submodule("audit.secret_file_copies")
    homes = [_plant_everything(tmp_path / "all"), _healthy_home(tmp_path / "healthy")]
    dirty = tmp_path / "dirty" / "home"
    _touch(dirty / "plans" / "a" / "secrets.yaml")
    _touch(dirty / "plugins" / "p1" / ".env")
    _touch(dirty / "thirdparty-auth.json")
    homes.append(dirty)
    try:
        for home in homes:
            runs = []
            for _ in range(2):
                adapted = contract.adapt_component_result(
                    mod.audit_secret_file_copies(home), component_id="secret_file_copies")
                serializer = evidence.EvidenceSerializer()
                sealed = serializer.serialize({"secret_file_copies": adapted["secret_file_copies"]})
                dto = persistence.component_dto(adapted)
                assert _hmac_dicts(sealed) == [] and _hmac_dicts(dto) == []
                runs.append((json.dumps(sealed, sort_keys=True),
                             json.dumps(dto["findings"], sort_keys=True, default=str)))
            assert runs[0] == runs[1], home
    finally:
        _restore_modes(homes[0])


def test_wire_canaries_never_reach_sealed_output(tmp_path, monkeypatch):
    wiring = _wiring()
    contract = load_submodule("audit.contract")
    evidence, persistence = _patch_sealing_sets(monkeypatch, wiring)
    mod = load_submodule("audit.secret_file_copies")
    c = "QZCANARY"
    home = tmp_path / "home"
    _touch(home / ".env", f"{c}ENVVALUE=1\n".encode())
    _touch(home / "auth.json", f'{{"{c}AUTH": 1}}'.encode())
    _touch(home / "config.yaml", f"model: {c}CONFIGVALUE\nplugins:\n  enabled: [{c}PLUGINCFG]\n".encode())
    _touch(home / f".env.bak-{c}BAKSUFFIX", b"x")
    _touch(home / "config.yaml.bak", f"key: {c}CFGBAK\n".encode())
    _touch(home / f"{c}TOPFOLDER" / f"{c}MID" / f"{c}LEAF-secret.yaml", f"{c}CONTENT".encode())
    _touch(home / "plans" / f"{c}DEEP" / f"{c}-auth.json", f"{c}CONTENT".encode())
    _touch(home / "plugins" / f"{c}PLUGIN" / ".env", f"{c}PLUGINENV".encode())
    _touch(home / f"{c}ROOTFILE-token.json", f"{c}CONTENT".encode())
    _touch(home / "plans" / "fx" / ".hermes" / f"{c}FIXTURE.env", f"{c}CONTENT".encode())
    db = home / "state.db"
    import sqlite3 as _sqlite3
    con = _sqlite3.connect(db)
    con.execute("create table t (v text)")
    con.execute("insert into t values (?)", (f"{c}DBROW",))
    con.commit()
    con.close()
    os.symlink(f"/srv/{c}LINKTARGET", home / f"{c}LINK.pem")
    env = mod.audit_secret_file_copies(home)
    # Raw envelope: canaries only inside the kept absolute paths of existing top-level and
    # plugin folders (the justified free-string positions).
    sec = env["secret_file_copies"]["secret_named_files"]
    kept = set(_kept_paths(env))
    assert str(home / f"{c}TOPFOLDER") in kept
    assert str(home / "plugins" / f"{c}PLUGIN") in kept
    _assert_paths_capped(env, home)
    for leak in ("MID", "LEAF", "DEEP", "ROOTFILE", "BAKSUFFIX", "CONTENT", "DBROW",
                 "CONFIGVALUE", "PLUGINCFG", "ENVVALUE", "LINKTARGET", "FIXTURE"):
        assert f"{c}{leak}" not in json.dumps(env), leak
    # Sealed output: the same kept paths, unchanged; no canary anywhere else, no token.
    adapted = contract.adapt_component_result(env, component_id="secret_file_copies")
    sealed = evidence.serialize_evidence({"secret_file_copies": adapted["secret_file_copies"]})
    dto = persistence.component_dto(adapted)
    assert _hmac_dicts(sealed) == [] and _hmac_dicts(dto) == []
    sealed_sec = sealed["secret_file_copies"]["secret_named_files"]
    assert sealed_sec == sec
    out = json.dumps([sealed, dto, adapted["run_metrics"]], sort_keys=True, default=str)
    for p in sorted(kept, key=len, reverse=True):
        out = out.replace(json.dumps(p)[1:-1], "")
    assert c not in out
    assert str(tmp_path) not in out


def test_wire_only_lstat_and_scandir_after_import(tmp_path, monkeypatch):
    # Own hook, installed after the module is imported: wrap the filesystem entry points and
    # attribute calls to frames of audit/secret_file_copies.py only.
    mod = load_submodule("audit.secret_file_copies")
    home = _plant_everything(tmp_path)
    target = os.path.abspath(mod.__file__)
    calls: Counter = Counter()
    events: list = []
    state = {"on": False}

    def _from_module(depth: int = 2) -> bool:
        f = sys._getframe(depth)
        while f is not None:
            name = os.path.abspath(f.f_code.co_filename)
            if name.endswith(os.sep + "conftest.py"):
                return False
            if name == target:
                return True
            f = f.f_back
        return False

    def hook(event, args):
        if state["on"] and (event == "open" or event.startswith(("os.", "shutil.", "sqlite3.", "subprocess."))):
            if _from_module(2):
                events.append(event)

    sys.addaudithook(hook)

    def wrap(owner, attr):
        orig = getattr(owner, attr)

        def _w(*a, **k):
            if state["on"] and _from_module(2):
                calls[f"{getattr(owner, '__name__', owner)}.{attr}"] += 1
            return orig(*a, **k)
        monkeypatch.setattr(owner, attr, _w)

    for owner, attr in ((os, "open"), (builtins, "open"), (io, "open"), (os, "stat"),
                        (os, "lstat"), (os, "scandir"), (os, "listdir"), (os, "readlink"),
                        (os, "walk"), (os.path, "realpath"), (os.path, "exists"),
                        (os.path, "isdir"), (os.path, "isfile"), (os.path, "islink"),
                        (Path, "open"), (Path, "read_bytes"), (Path, "read_text"),
                        (Path, "stat"), (Path, "resolve"), (Path, "exists")):
        wrap(owner, attr)
    try:
        state["on"] = True
        for kw in (dict(), dict(max_entries=5), dict(max_depth=1)):
            mod.audit_secret_file_copies(home, **kw)
        for t in (tmp_path / "missing", None):
            mod.audit_secret_file_copies(t)
    finally:
        state["on"] = False
        _restore_modes(home)
    assert set(calls) == {"os.lstat", "os.scandir"}, calls
    assert calls["os.lstat"] > 0 and calls["os.scandir"] > 0
    assert set(events) <= {"os.scandir"}, Counter(events)
    assert "open" not in events


def test_wire_doc_matches_wiring_json():
    from tests.test_audit_dead_stores import _doc_contains, _doc_bullets
    wiring = _wiring()
    doc = (Path(__file__).resolve().parents[1] / "docs/audit-sections/secret_file_copies.md").read_text(encoding="utf-8")
    for value in wiring["schema_keys"] + wiring["vocabulary"] + wiring["run_metrics_keys"]:
        _doc_contains(doc, value)
    blocks = _doc_bullets(doc)
    for rid, classes in wiring["classifications"].items():
        for cls in classes:
            _doc_contains(blocks[rid], cls)
    for field in wiring["free_strings"]:
        _doc_contains(doc, field["key"])
    _doc_contains(doc, "audit/wiring/secret_file_copies.json")
    for keyword in ("third-party", "plugins"):
        _doc_contains(doc, keyword)


def test_secret_pattern_class_is_emitted_as_secret_word():
    """'secret' is a sealed plain value in the report; the emitted class label is secret_word."""
    mod = load_submodule("audit.secret_file_copies")
    assert mod._classify_lower_name("my_secret.txt") == "secret_word"
    assert mod._classify_lower_name("secretary_notes.txt") is None
    assert "secret" not in {label for label, _patterns in mod.SECRET_PATTERN_CLASSES}
