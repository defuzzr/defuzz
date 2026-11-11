"""The project scan never opens files that are secret by NAME (.env, keys, credential files)."""

from __future__ import annotations

import os
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import scanner  # noqa: E402
from hermes_plugins.defuzz.safety import run_git_hardened  # noqa: E402

SECRET_NAMES = (".env", ".env.local", "server.pem", "id_ed25519", "credentials.json", "deploy.key")


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "copy_repo"
    (root / "sub").mkdir(parents=True)
    run_git_hardened(root, ["init", "-b", "main"], allow_literal_pathspecs=False)
    (root / "README.md").write_text("hello\n", encoding="utf-8")
    (root / "notes.txt").write_text("api_key = " + "Zq9" * 12 + "\n", encoding="utf-8")
    for name in SECRET_NAMES:
        (root / name).write_text("CANARY_" + name.strip(".").upper() + "=" + "x" * 40 + "\n", encoding="utf-8")
    (root / "sub" / ".env").write_text("NESTED=" + "y" * 40 + "\n", encoding="utf-8")
    (root / ".env.example").write_text("API_KEY=YOUR_KEY_HERE\n", encoding="utf-8")
    return root


def test_scan_never_opens_secret_named_files(tmp_path, monkeypatch):
    root = _project(tmp_path)
    opened: list[str] = []
    real_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        opened.append(os.fspath(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(scanner.os, "open", recording_open)
    report = scanner.scan_folder(root)

    opened_names = {os.path.basename(p) for p in opened}
    assert not opened_names & set(SECRET_NAMES), sorted(opened_names & set(SECRET_NAMES))
    # Ordinary files are still read (hashing and content sniffing still work).
    assert {"README.md", "notes.txt", ".env.example"} <= opened_names

    flagged = {entry["path"]: entry for entry in report["secrets_flagged"]}
    for name in SECRET_NAMES:
        assert flagged[name]["reasons"] == ["secret_filename"]
    assert flagged["sub/.env"]["reasons"] == ["secret_filename"]
    # A secret found by CONTENT in an ordinary file is still flagged.
    assert "notes.txt" in flagged and "secret_filename" not in flagged["notes.txt"]["reasons"]

    by_path = {entry["path"]: entry for entry in report["files"]}
    for name in (*SECRET_NAMES, "sub/.env"):
        assert by_path[name]["sha256"] is None
        assert by_path[name]["secret_placeholder"]
    assert by_path["README.md"]["sha256"]
    # Unopened files can never be reported as duplicates of each other.
    for group in report.get("duplicate_hashes", []):
        assert not set(group["paths"]) & {*SECRET_NAMES, "sub/.env"}


def test_post_apply_check_does_not_open_files_without_a_recorded_hash(tmp_path, monkeypatch):
    """The scan records no hash for secret-named files, so the post-apply check must not open them."""
    from hermes_plugins.defuzz import applier

    copy = tmp_path / "copy"
    copy.mkdir()
    (copy / ".env").write_text("K=" + "z" * 40 + "\n", encoding="utf-8")
    (copy / "README.md").write_text("hello\n", encoding="utf-8")
    readme_sha = scanner._sha256_nofollow(copy / "README.md")
    plan = {"files": [
        {"source_path": ".env", "dest_path": ".env", "sha256": None},
        {"source_path": "README.md", "dest_path": "README.md", "sha256": readme_sha},
    ]}
    opened: list[str] = []
    real_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        opened.append(os.path.basename(os.fspath(path)))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(scanner.os, "open", recording_open)
    assert applier._verify_post_apply_integrity(copy, plan, None, None) == 2
    assert opened == ["README.md"]
    # A missing file is still an error even when no hash was recorded.
    (copy / ".env").unlink()
    import pytest
    with pytest.raises(applier.SafetyError):
        applier._verify_post_apply_integrity(copy, plan, None, None)
