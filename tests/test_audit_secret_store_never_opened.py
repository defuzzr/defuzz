"""Credential-bearing files by name or Hermes store path are never opened during audit."""
from __future__ import annotations

import builtins
import io
import json
import os
from pathlib import Path
import sqlite3
import sys

from tests.conftest import load_submodule
from tests.test_audit_secret_file_copies import INNOCENT_NAMES, SECRET_LIKE_NAMES

# Import before any test wraps os.open: audit/fingerprint.py checks `os.open in os.supports_dir_fd` at import.
load_submodule("audit_surface")

NAMED_HOME_SECRET_FILES: tuple[str, ...] = (
    "prod.env",
    "service-account.json",
    "my_api_key.json",
    "oauth_token.json",
    "shared/nous_auth.json",
    "google_chat_user_client_secret.json",
    ".copilot_jwt.json",
    "bws_cache.json",
    "cert.p12",
    "release.keystore",
)

PROJECT_SECRET_FILES: tuple[str, ...] = (
    ".env.production",
    "deploy.key",
    "firebase-adminsdk.json",
    "id_rsa",
    "kubeconfig",
    "secrets.yaml",
    "terraform.tfvars",
    ".pypirc",
)

EXPECTED_STORE_RELPATHS: tuple[str, ...] = (
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
)

EXTRA_INNOCENT_RELPATHS: tuple[str, ...] = (
    "package.json",
    "tsconfig.json",
    "token_counter.py",
    "monkey.py",
    "oauth.md",
    "secretary.txt",
    "keys.md",
    "auth/handler.py",
    "terraform.tfvars.example",
    "kubeconfig.sample",
)


def _register_project(hermes_home: Path, project: Path) -> None:
    registry = hermes_home / "plugin-data" / "defuzz" / "state.db"
    registry.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(registry)
    try:
        conn.execute("CREATE TABLE projects(path TEXT PRIMARY KEY, hermes_project_id TEXT)")
        conn.execute("INSERT INTO projects VALUES (?, ?)", (str(project), "synthetic-proj"))
        conn.commit()
    finally:
        conn.close()


def _run_full_audit(tmp_path: Path, monkeypatch, hermes_home: Path, **args):
    surface = load_submodule("audit_surface")
    monkeypatch.setenv("HOME", str(tmp_path / "user-home"))
    (tmp_path / "user-home").mkdir(exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    git = load_submodule("audit.outward_git")
    discover = getattr(git.discover_git_context, "unpatched", git.discover_git_context)

    def no_system_gitconfig(*a, **kw):
        return discover(*a, **kw, system_config=tmp_path / "absent-gitconfig")

    setattr(no_system_gitconfig, "unpatched", discover)
    monkeypatch.setattr(git, "discover_git_context", no_system_gitconfig)
    store_dir = tmp_path / "audit-store"
    store_dir.mkdir(exist_ok=True)
    db_path = store_dir / "audit.db"
    result = surface.execute_audit({"action": "run", **args}, db_path=db_path, wait=True)
    stored = surface.execute_audit(
        {"action": "report", "run_id": result["run_id"]}, db_path=db_path, wait=True
    )
    return result, stored, db_path


def _install_open_recorder(monkeypatch):
    """Record every opened path via sys.addaudithook plus os.open, io.open and builtins.open."""
    opened: list[str] = []
    enabled = [True]

    def record(raw_path, dir_fd=None):
        if not enabled[0] or isinstance(raw_path, int):
            return
        if not isinstance(raw_path, (str, bytes, os.PathLike)):
            return
        decoded = os.fsdecode(raw_path)
        if dir_fd is not None and not os.path.isabs(decoded):
            try:
                base = os.readlink(f"/proc/self/fd/{dir_fd}")
                decoded = os.path.join(base, decoded)
            except OSError:
                pass
        opened.append(os.path.abspath(decoded))

    def audit_hook(event, args):
        if event == "open" and args:
            record(args[0])

    sys.addaudithook(audit_hook)

    orig_os_open = os.open
    orig_io_open = io.open
    orig_builtins_open = builtins.open

    def wrapped_os_open(path, flags, mode=0o777, *, dir_fd=None):
        record(path, dir_fd=dir_fd)
        return orig_os_open(path, flags, mode, dir_fd=dir_fd)

    def wrapped_io_open(file, *args, **kwargs):
        record(file)
        return orig_io_open(file, *args, **kwargs)

    def wrapped_builtins_open(file, *args, **kwargs):
        record(file)
        return orig_builtins_open(file, *args, **kwargs)

    monkeypatch.setattr(os, "open", wrapped_os_open)
    monkeypatch.setattr(io, "open", wrapped_io_open)
    monkeypatch.setattr(builtins, "open", wrapped_builtins_open)
    return opened, enabled


def test_home_and_project_secret_stores_never_opened(tmp_path, monkeypatch):
    policy = load_submodule("audit.policy")
    summary_mod = load_submodule("audit_summary")

    home = tmp_path / "hermes-home"
    project = tmp_path / "project"
    home.mkdir()
    project.mkdir()
    _register_project(home, project)

    # Declaration sources must remain readable and drive write_settings even if self-declared.
    config_path = home / "config.yaml"
    config_path.write_text(
        "credential_file: config.yaml\n"
        "memory:\n"
        "  nudge_interval: 23\n"
        "  write_approval: true\n"
        "skills:\n"
        "  write_approval: true\n",
        encoding="utf-8",
    )
    pkg_json = project / "package.json"
    pkg_json.write_text('{"name": "demo-app", "version": "1.0.0"}\n', encoding="utf-8")
    (project / "main.py").write_text("print('ok')\n", encoding="utf-8")

    protected: dict[str, str] = {}
    idx = 0
    for rel in NAMED_HOME_SECRET_FILES:
        idx += 1
        canary = f"CANARY_SECRET_STORE_{idx:02d}_9f4a2b"
        target = home / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f'{{"secret": "{canary}"}}\n', encoding="utf-8")
        protected[os.path.abspath(target)] = canary

    for rel in PROJECT_SECRET_FILES:
        idx += 1
        canary = f"CANARY_SECRET_STORE_{idx:02d}_9f4a2b"
        target = project / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"SECRET_VALUE={canary}\n", encoding="utf-8")
        protected[os.path.abspath(target)] = canary

    opened, enabled = _install_open_recorder(monkeypatch)
    try:
        result, stored, db_path = _run_full_audit(tmp_path, monkeypatch, home, root=str(project))
    finally:
        enabled[0] = False

    opened_protected = [p for p in opened if p in protected]
    assert opened_protected == [], f"Secret stores were opened ({len(opened_protected)} opens): {opened_protected}"
    false_negatives = [p for p in protected if not policy.credential_path(p)]
    assert false_negatives == []
    assert result["status"] == "completed"
    assert stored["status"] == "completed"

    # Canaries appear nowhere in run result, stored report, plain summary, or audit DB bytes.
    plain_summary = summary_mod.summarize(stored["report"], home=str(home))
    plain_text = summary_mod.render_text(plain_summary)
    combined_text = "\n".join([
        json.dumps(result),
        json.dumps(stored),
        json.dumps(plain_summary),
        plain_text,
    ])
    for canary in protected.values():
        assert canary not in combined_text
    for f in db_path.parent.rglob("*"):
        if f.is_file():
            raw = f.read_bytes()
            for canary in protected.values():
                assert canary.encode("utf-8") not in raw

    # Reported as credential_store_not_opened / credential_store metadata.
    cred_records = {os.path.abspath(r["path"]): r for r in result["report"]["credentials"] if "path" in r}
    for secret_abs in protected:
        assert secret_abs in cred_records, secret_abs
        assert cred_records[secret_abs]["kind"] == "credential_store"
    assert "credential_store_not_opened" in json.dumps(result["report"]["scope"]["regions"]["credentials"])

    # Declaration sources were still opened and parsed (config.yaml drives write_settings).
    opened_set = set(opened)
    assert os.path.abspath(config_path) in opened_set
    assert os.path.abspath(pkg_json) in opened_set
    ws_settings = result["report"]["write_settings"]["settings"]
    assert ws_settings["memory.nudge_interval"] == {"value": 23, "source": "config"}
    assert ws_settings["memory.write_approval"] == {"value": True, "source": "config"}
    assert ws_settings["skills.write_approval"] == {"value": True, "source": "config"}


def test_innocent_corpus_stays_readable_and_secret_corpora_are_path_only(tmp_path, monkeypatch):
    policy = load_submodule("audit.policy")

    home = tmp_path / "hermes-home"
    project = tmp_path / "project"
    home.mkdir()
    project.mkdir()
    _register_project(home, project)
    (home / "config.yaml").write_text("model: test\n", encoding="utf-8")

    # Skill directory whose folder name contains 'secrets' must still be readable.
    skill_md = home / "skills" / "secrets-management" / "SKILL.md"
    skill_md.parent.mkdir(parents=True, exist_ok=True)
    skill_md.write_text("---\nname: secrets-management\ndescription: Manage secrets.\n---\nBody.\n", encoding="utf-8")

    # 1. Every SECRET_LIKE_NAMES entry and every Hermes expected store path is path-only.
    missed_secret_names = [n for n in SECRET_LIKE_NAMES if not policy.credential_path(project / n)]
    assert missed_secret_names == []
    missed_expected = [rel for rel in EXPECTED_STORE_RELPATHS if not policy.credential_path(home / rel)]
    assert missed_expected == []

    # 2. Hermes non-secret cache lookalikes stay non-credential.
    for non_secret in ("cache/oauth_heal_clean.json", "cache/image_token_costs.json", "cache/platform-ca-bundle.pem"):
        assert not policy.credential_path(home / non_secret), non_secret

    # 3. Every INNOCENT_NAMES entry + extra innocent paths stay readable (not credential_path) and are opened/hashed.
    innocent_targets: list[Path] = []
    for name in INNOCENT_NAMES:
        p = project / "innocent" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}", encoding="utf-8")
        innocent_targets.append(p)
    for rel in EXTRA_INNOCENT_RELPATHS:
        p = project / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}\n" if rel.endswith(".json") else "# ok\n", encoding="utf-8")
        innocent_targets.append(p)

    false_positives = [str(p.relative_to(project)) for p in innocent_targets if policy.credential_path(p)]
    assert false_positives == []
    assert not policy.credential_path(skill_md)

    opened, enabled = _install_open_recorder(monkeypatch)
    try:
        result, _stored, _db = _run_full_audit(tmp_path, monkeypatch, home, root=str(project))
    finally:
        enabled[0] = False

    assert result["status"] == "completed"
    opened_set = set(opened)
    unopened_innocent = [str(p.relative_to(project)) for p in innocent_targets if os.path.abspath(p) not in opened_set]
    assert unopened_innocent == []
    assert os.path.abspath(skill_md) in opened_set


def test_home_workdirs_withholds_secret_named_entries_with_shared_rule(tmp_path, monkeypatch):
    hw = load_submodule("audit.home_workdirs")

    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "config.yaml").write_text("model: test\n", encoding="utf-8")

    # Root-level secret-named files that are NOT in HERMES_OWNED_TOP_LEVEL:
    # all must be counted in not_hermes_folders with path=None, path_withheld='credential_named'.
    root_secret_files = (
        "prod.env",
        "service-account.json",
        "my_api_key.json",
        "oauth_token.json",
        "cert.p12",
        "release.keystore",
        "firebase-adminsdk.json",
        "kubeconfig",
        "terraform.tfvars",
        "deploy.key",
        "id_rsa",
        ".pypirc",
        "secrets.yaml",
    )
    for name in root_secret_files:
        (home / name).write_bytes(b"S" * 64)

    # Secret-named folder at root and containing a huge file: folder name must also be withheld.
    (home / "my_api_keys").mkdir()
    (home / "my_api_keys" / "dump.bin").write_bytes(b"B" * 2048)

    # Innocent root entries (including token/example/secretary false-positive traps) stay shown.
    innocent_root_files = (
        "notes.txt",
        ".env.example",
        "tokenizer.json",
        "secretary-notes.txt",
        "secrets.template.yaml",
        "turkey.key",
        "author.json",
    )
    for name in innocent_root_files:
        (home / name).write_bytes(b"I" * 32)

    res = hw.audit_home_workdirs(home, huge_file_threshold_bytes=1024, work_folders_bytes_threshold=100)
    sec = res["home_workdirs"]
    assert sec["status"] == "completed"

    dumped = json.dumps(sec)
    for secret_name in (*root_secret_files, "my_api_keys"):
        assert secret_name not in dumped, f"Secret name leaked in home_workdirs: {secret_name}"

    withheld_entries = [e for e in sec["not_hermes_folders"] if e["path_withheld"] == "credential_named"]
    assert all(e["path"] is None for e in withheld_entries)
    assert len(withheld_entries) == len(root_secret_files) + 1  # +1 for my_api_keys folder

    shown_basenames = {os.path.basename(e["path"]) for e in sec["not_hermes_folders"] if e["path"] is not None}
    assert shown_basenames == set(innocent_root_files)

    assert len(sec["huge_files"]) == 1
    assert sec["huge_files"][0]["path"] is None
    assert sec["huge_files"][0]["path_withheld"] == "credential_named"

    # Also verify through a full execute_audit run that root secret names do not appear in report.home_workdirs.
    result, _stored, _db = _run_full_audit(tmp_path, monkeypatch, home)
    assert result["status"] == "completed"
    report_hw = json.dumps(result["report"]["home_workdirs"])
    for secret_name in (*root_secret_files, "my_api_keys"):
        assert secret_name not in report_hw

