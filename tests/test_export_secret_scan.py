"""Release gate: the public export must contain no credential-shaped string or credential-named file.

Every sample secret below is built at runtime from pieces and written to a
temporary folder, so this file never holds a complete secret-shaped literal.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "secret_scan.py"
EXPORTER = ROOT / "scripts" / "export_public.py"
ALLOWLIST = ROOT / "scripts" / "secret_scan_allow.json"
_B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_B64 = _B62 + "+/"


def _load():
    spec = importlib.util.spec_from_file_location("secret_scan_under_test", SCANNER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ss = _load()


def rnd(n: int, seed: str, alphabet: str = _B62) -> str:
    """Deterministic high-entropy synthetic string (no secret, only its shape)."""
    out, counter = [], 0
    while len(out) < n:
        digest = hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        out.extend(alphabet[b % len(alphabet)] for b in digest)
        counter += 1
    return "".join(out[:n])


def q(name: str, value: str, sep: str = " = ", quote: str = '"') -> str:
    return name + sep + quote + value + quote


def _positives() -> list[tuple[str, str, str]]:
    """(rule id, full line, secret value) for one synthetic positive per rule."""
    tg = "12345" + "6789"
    cases = [
        ("private-key", "-" * 5 + "BEGIN " + "RSA PRIVATE" + " KEY" + "-" * 5, "-" * 5 + "BEGIN"),
        ("github-token", None, "gh" + "p_" + rnd(36, "gh")),
        ("github-fine-grained-pat", None, "github" + "_pat_" + rnd(22, "fg1") + "_" + rnd(59, "fg2")),
        ("gitlab-pat", None, "gl" + "pat-" + rnd(20, "gl")),
        ("aws-access-key-id", None, "AK" + "IA" + rnd(16, "aws", _UPPER)),
        ("aws-secret-access-key", "aws_secret" + "_access_key = {v}", rnd(40, "awss", _B64)),
        ("google-api-key", None, "AI" + "za" + rnd(35, "goog")),
        ("slack-token", None, "xo" + "xb-" + "1234567" + "89012-" + rnd(24, "slack")),
        ("stripe-live-key", None, "sk" + "_live_" + rnd(24, "stripe")),
        ("anthropic-key", None, "sk" + "-ant-" + "api03-" + rnd(40, "anth")),
        ("openai-key", None, "sk" + "-proj-" + rnd(40, "oai") + "9"),
        ("huggingface-token", None, "h" + "f_" + rnd(34, "hf")),
        ("npm-token", None, "np" + "m_" + rnd(36, "npm")),
        ("pypi-token", None, "py" + "pi-AgEI" + rnd(60, "pypi")),
        ("telegram-bot-token", None, tg + ":" + rnd(35, "tg")),
        ("discord-bot-token", None, "M" + rnd(23, "d1") + "." + rnd(6, "d2") + "." + rnd(27, "d3")),
        ("jwt", None, "ey" + "J" + rnd(20, "j1") + ".ey" + "J" + rnd(30, "j2") + "." + rnd(30, "j3")),
        ("bearer-header", "Authorization: " + "Bearer {v}", rnd(32, "bearer")),
        ("connection-string-credentials", "url = postgres" + "://admin:{v}" + "@db.internal.corp:5432/app",
         rnd(16, "conn")),
        ("netrc-password", "machine api.service.io login bot " + "password {v}", rnd(16, "netrc")),
        ("generic-secret-assignment", "db_pass" + 'word = "{v}"', rnd(20, "generic")),
        ("env-secret-assignment", "API_TO" + "KEN={v}", rnd(24, "env")),
    ]
    out = []
    for rule, template, value in cases:
        line = (template or "value: {v}").replace("{v}", value) if rule != "private-key" else template
        out.append((rule, line, value))
    return out


POSITIVES = _positives()


def test_every_rule_has_a_positive():
    assert {rule for rule, _, _ in POSITIVES} == set(ss.RULE_IDS)


@pytest.mark.parametrize("rule,line,value", POSITIVES, ids=[p[0] for p in POSITIVES])
def test_positive_found_with_rule_path_line_and_masked(tmp_path, rule, line, value):
    target = tmp_path / "src" / "settings.txt"
    target.parent.mkdir()
    target.write_text("# config\n\n" + line + "\n", encoding="utf-8")
    findings = ss.scan_tree(tmp_path)
    assert [(f.rule, f.path, f.line) for f in findings] == [(rule, "src/settings.txt", 3)], findings
    for args in ([str(tmp_path)], [str(tmp_path), "--json"]):
        proc = subprocess.run([sys.executable, "-B", str(SCANNER), *args], capture_output=True, text=True,
                              timeout=60)
        assert proc.returncode == 1
        output = proc.stdout + proc.stderr
        assert rule in output and "src/settings.txt" in output
        assert value not in output
        if rule != "private-key":
            assert value[4:] not in output
            assert f"({len(value)} chars)" in output


def _negatives() -> list[str]:
    hex64 = rnd(64, "h64", "0123456789abcdef")
    hex40 = rnd(40, "h40", "0123456789abcdef")
    b64img = base64.b64encode(bytes(range(256)) * 4).decode()
    integrity = base64.b64encode(hashlib.sha512(b"pkg").digest()).decode()
    uuid = "123e4567-e89b-12d3-a456-426614174000"
    at = "@"
    return [
        q("cut_reason", "metadata_byte_budget", quote="'"),
        q("token_kind", "bearer_header"),
        q("pass" + "word", "changeme"),
        q("api" + "_key", "your-api-key-here"),
        q("sec" + "ret", "<your-secret>"),
        q("tok" + "en", "${GITHUB_TOKEN}"),
        "pass" + 'word: "{{ vault_password }}"',
        q("API" + "_KEY", "x" * 24),
        q("auth" + "_token", "a" * 24),
        q("token_env", "MY_SERVICE_API_TOKEN"),
        q("secret_path", "settings.auth.client_secret"),
        q("password_field", "confirm_password_input"),
        q("api_key_status", "not_configured"),
        q("token_type", "refresh_token"),
        q("credential_source", "environment-variable"),
        q("auth_mode", "oauth-device-flow"),
        q("TOKEN_FORMAT", "service-kit-token-v1"),
        q("secret_file", "/etc/app/secret.json"),
        q("sec" + "ret_code", "aaaa1111bbbb"),
        q("author", "JaneQPublic2024"),
        "key_id = " + "AK" + "IA" + "IOSFODNN7" + "EXAMPLE",
        "aws_secret" + "_access_key = " + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLE" + "KEY",
        '"integrity": "sha512-' + integrity + '"',
        '"sha256": "' + hex64 + '"',
        q("token_sha256", hex64),
        q("resolved_commit", hex40),
        "commit " + hex40,
        q("checksum", hex40),
        '<img src="data:image/png;base64,' + b64img[:600] + '">',
        q("request_id", uuid),
        q("tok" + "en", uuid),
        q("SEC" + "RET", "CANARY_" + rnd(20, "canary")) + "  # secret-scan: allow generic-secret-assignment test canary",
        "!function(e,t){var n=e.token||t.apiKey||\"\";e.auth=!0;return n.split(\".\").map(function(r){return r})}",
        "url = postgres" + "://user:password" + at + "example.com/db",
        "url = https" + "://user:pass" + at + "localhost:8080/",
        "url = mysql" + "://root:${DB_PASSWORD}" + at + "db:3306/app",
        "url = redis" + "://admin:<password>" + at + "cache.example.org:6379",
        "url = amqp" + "://guest:secret" + at + "broker.test:5672",
        "Authorization: " + "Bearer <token>",
        "Authorization: " + "Bearer ${TOKEN}",
        'headers["Authorization"] = f"' + 'Bearer {api_token}"',
        "Authorization: " + "Bearer " + "x" * 32,
        "pass" + 'word = os.environ["DB_PASSWORD"]',
        '"pass' + 'word": "********"',
        "machine example.invalid login demo " + "pass" + "word {secret}",
        "pass" + "word should be at least 12 characters long",
        "pass" + "word",
        "the scikit alias sk" + "-learn-is-a-python-library-for-ml",
        "gh" + "p_" + "x" * 36,
        "hf_hub_download(repo_id='org/model')",
        "main.3f2a9c1b8d7e6f5a.js",
        "started 12:34:56 finished 12:35:01",
        q("tok" + "en", "ey" + "J..."),
        "OPENAI" + "_API_KEY=your-openai-key-here",
        "API" + "_TOKEN=${API_TOKEN}",
        "tok" + 'en = request.headers.get("Authorization")',
        "pass" + "word = getpass.getpass()",
        "api" + "_key: !secret openai_api_key",
        "-" * 5 + "BEGIN PUBLIC KEY" + "-" * 5,
        q("api" + "_key", "{prefix}-{name}-suffix"),
        q("secret_ref", "vault.kv.app.secret"),
        q("passwordHint", "enterYourPasswordHere"),
    ]


NEGATIVES = _negatives()


def test_at_least_forty_negatives():
    assert len(NEGATIVES) >= 40


@pytest.mark.parametrize("line", NEGATIVES, ids=[f"neg{i:02d}" for i in range(len(NEGATIVES))])
def test_negative_not_flagged(line):
    assert ss.line_findings(line) == [] or "secret-scan: allow" in line


def test_negatives_as_a_file_and_marker_on_line_above(tmp_path):
    canary = q("SEC" + "RET", "CANARY_" + rnd(20, "above"))
    (tmp_path / "fixture.py").write_text("\n".join(NEGATIVES) + "\n# secret-scan: allow generic-secret-assignment "
                                         "fixture canary\n" + canary + "\n", encoding="utf-8")
    assert ss.scan_tree(tmp_path) == []
    result = ss.scan(tmp_path)
    assert result.allowed == 2


def test_marker_for_another_rule_does_not_allow(tmp_path):
    value = rnd(20, "wrongmarker")
    (tmp_path / "a.py").write_text(q("db_pass" + "word", value) + "  # secret-scan: allow jwt wrong rule\n")
    assert [f.rule for f in ss.scan_tree(tmp_path)] == ["generic-secret-assignment"]


FILE_CASES = {
    ".env": "file-env", ".env.local": "file-env", "config/.env.production": "file-env",
    ".env.example": None, ".env.sample": None, ".env.template": None, ".env.dist": None,
    "certs/server.pem": "file-private-key", "server.key": "file-private-key", "cert.p12": "file-private-key",
    "cert.pfx": "file-private-key", "release.keystore": "file-private-key", "debug.jks": "file-private-key",
    "putty.ppk": "file-private-key", "id_rsa": "file-ssh-key", "id_ed25519": "file-ssh-key",
    "id_ecdsa": "file-ssh-key", "id_dsa": "file-ssh-key", "id_rsa.pub": None, ".netrc": "file-netrc",
    ".pgpass": "file-pgpass", "credentials.json": "file-cloud-credentials",
    "client_secret_123.apps.json": "file-cloud-credentials", "service-account-prod.json": "file-cloud-credentials",
    "vault.kdbx": "file-keepass", "keys.md": None, "credentials.py": None,
}


def test_file_name_rules(tmp_path):
    for rel in FILE_CASES:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x00\x01binary" if rel.endswith((".p12", ".kdbx")) else b"placeholder\n")
    found = {f.path: f.rule for f in ss.scan_tree(tmp_path)}
    assert found == {rel: rule for rel, rule in FILE_CASES.items() if rule}


def test_npmrc_only_with_a_literal_auth_token(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "c").mkdir()
    (tmp_path / "a" / ".npmrc").write_text("//registry.npmjs.org/:_auth" + "Token=" + rnd(36, "npmrc") + "\n")
    (tmp_path / "b" / ".npmrc").write_text("//registry.npmjs.org/:_auth" + "Token=${NPM_TOKEN}\n")
    (tmp_path / "c" / ".npmrc").write_text("registry=https://registry.npmjs.org/\n")
    assert [(f.path, f.rule) for f in ss.scan_tree(tmp_path)] == [("a/.npmrc", "file-npmrc-token")]


def test_symlinks_not_followed_and_reported(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.txt").write_text(q("db_pass" + "word", rnd(20, "outside")) + "\n")
    tree = tmp_path / "tree"
    tree.mkdir()
    os.symlink(outside / "leak.txt", tree / "link.txt")
    os.symlink(outside, tree / "linkdir")
    result = ss.scan(tree)
    assert result.findings == []
    assert {rel for rel, _ in result.skipped} == {"link.txt", "linkdir"}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _write_allow(path: Path, entries: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"entries": entries}), encoding="utf-8")
    return path


def test_allowlist_exact_line_and_stale_entries(tmp_path):
    line = q("db_pass" + "word", rnd(20, "allow"))
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text("x = 1\n" + line + "\n")
    good = {"path": "tests/t.py", "rule": "generic-secret-assignment", "line_sha256": _sha(line),
            "reason": "deliberate canary"}
    allow = _write_allow(tmp_path / "scripts" / "secret_scan_allow.json", [good])
    assert ss.scan_tree(tmp_path) == []
    # The line changed: the finding comes back and the entry is reported as stale.
    (tmp_path / "tests" / "t.py").write_text("x = 1\n" + line + " # edited\n")
    assert sorted(f.rule for f in ss.scan_tree(tmp_path)) == ["allowlist-stale", "generic-secret-assignment"]
    # Wrong rule id does not allow either.
    (tmp_path / "tests" / "t.py").write_text("x = 1\n" + line + "\n")
    _write_allow(allow, [dict(good, rule="jwt")])
    assert sorted(f.rule for f in ss.scan_tree(tmp_path)) == ["allowlist-stale", "generic-secret-assignment"]
    # An entry for a file that is absent is stale only in strict mode (the export omits some files).
    _write_allow(allow, [good, dict(good, path="tests/gone.py")])
    assert ss.scan_tree(tmp_path) == []
    assert [f.rule for f in ss.scan_tree(tmp_path, strict=True)] == ["allowlist-stale"]
    # A reviewed gitleaks false positive needs only its line to still exist.
    _write_allow(allow, [good, {"path": "tests/t.py", "rule": "gitleaks:generic-api-key",
                                "line_sha256": _sha("x = 1"), "reason": "reviewed"}])
    assert ss.scan_tree(tmp_path) == []
    (tmp_path / "tests" / "t.py").write_text("x = 2\n" + line + "\n")
    assert [f.rule for f in ss.scan_tree(tmp_path)] == ["allowlist-stale"]


def test_allowlist_entry_without_reason_is_a_usage_error(tmp_path):
    (tmp_path / "a.txt").write_text("hello\n")
    _write_allow(tmp_path / "scripts" / "secret_scan_allow.json",
                 [{"path": "a.txt", "rule": "jwt", "line_sha256": _sha("hello"), "reason": " "}])
    with pytest.raises(ValueError):
        ss.scan_tree(tmp_path)
    proc = subprocess.run([sys.executable, "-B", str(SCANNER), str(tmp_path)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 2


def test_cli_exit_codes(tmp_path):
    run = lambda *a: subprocess.run([sys.executable, "-B", str(SCANNER), *a], capture_output=True, text=True,
                                    timeout=60).returncode
    assert run(str(tmp_path)) == 0
    assert run() == 2
    assert run(str(tmp_path / "missing")) == 2
    assert run(str(tmp_path), "--bogus") == 2


def test_linear_on_two_mib_single_line(tmp_path):
    unit = ('pass' + 'word="' + "aA1-" * 4 + "eyJ" + "a" * 5 + ".x://u:" + "p" * 3 + "sk-" + "bearer ")
    blob = (unit * (2 * 1024 * 1024 // len(unit) + 1))[: 2 * 1024 * 1024]
    (tmp_path / "big.txt").write_text(blob)
    start = time.monotonic()
    result = ss.scan(tmp_path)
    assert time.monotonic() - start < 5
    assert any("scanned only to" in reason for _, reason in result.skipped)


def test_linear_on_fifty_thousand_lines(tmp_path):
    shapes = ["tok" + "en = '" + "a" * 70, "x" * 60 + "://" + "a:" * 10, "eyJ" + "A" * 70 + ".",
              "aws" + "_" * 40 + "secret" + "=" * 30, " " * 60 + "pass" + "word", "Bearer " + "A1b2" * 18]
    lines = [shapes[i % len(shapes)] + str(i) for i in range(50_000)]
    (tmp_path / "many.txt").write_text("\n".join(lines))
    start = time.monotonic()
    ss.scan(tmp_path)
    assert time.monotonic() - start < 10
    worst = "a" * (ss.MAX_LINE_CHARS - 10) + "="
    start = time.monotonic()
    for _ in range(50):
        ss.line_findings(worst)
        ss.line_findings("eyJ" + "a." * 2040)
        ss.line_findings("a:" * 2048 + "@")
    assert time.monotonic() - start < 5


def test_oversize_file_skipped_and_reported(tmp_path):
    (tmp_path / "huge.log").write_bytes(b"a\n" * (ss.MAX_FILE_BYTES // 2 + 1))
    result = ss.scan(tmp_path)
    assert result.files_scanned == 0 and result.skipped[0][0] == "huge.log"


def _export(tmp_path: Path) -> Path:
    dest = tmp_path / "export"
    text = EXPORTER.read_text(encoding="utf-8")
    args = ["--source", str(ROOT)] if "'--source'" in text or '"--source"' in text else []
    proc = subprocess.run([sys.executable, "-B", str(EXPORTER), *args, "--dest", str(dest)],
                          capture_output=True, text=True, timeout=600, cwd=ROOT)
    assert dest.is_dir() and any(dest.iterdir()), proc.stderr[-2000:]
    return dest


def _in_git() -> bool:
    try:
        return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--is-inside-work-tree"], capture_output=True,
                              text=True, timeout=30).stdout.strip() == "true"
    except OSError:
        return False


needs_exporter = pytest.mark.skipif(not EXPORTER.is_file() or not _in_git(),
                                    reason="scripts/export_public.py is maintainer release tooling and is not in "
                                           "the public tree; the export gate runs only in the private source")
needs_git = pytest.mark.skipif(not _in_git(), reason="not a Git checkout; run scripts/secret_scan.py <folder> instead")


@needs_exporter
def test_gate_exported_tree_has_no_secrets(tmp_path):
    """THE GATE: what export_public.py would publish contains no credential."""
    dest = _export(tmp_path)
    result = ss.scan(dest, None, ss.load_allowlist(dest / "scripts" / "secret_scan_allow.json"))
    assert (dest / "scripts" / "secret_scan_allow.json").is_file()
    assert [f.text() for f in result.findings] == []


@needs_git
def test_tracked_files_clean_and_allowlist_not_stale():
    paths = ss.git_files(ROOT)
    result = ss.scan(ROOT, paths, ss.load_allowlist(ALLOWLIST), strict=True)
    assert [f.text() for f in result.findings] == []


def _covered(dest: Path, rel: str, line_no: int, raw: set[tuple[str, int]], entries: list[dict]) -> bool:
    if (rel, line_no) in raw:
        return True
    try:
        lines = (dest / rel).read_text(encoding="utf-8", errors="surrogateescape").splitlines()
    except OSError:
        return False
    if not 0 < line_no <= len(lines):
        return False
    digest = ss.sha256_text(lines[line_no - 1])
    if any(e["path"] == rel and e["line_sha256"] == digest for e in entries):
        return True
    near = lines[max(0, line_no - 2):line_no]
    return any("secret-scan: allow" in text for text in near)


@needs_exporter
def test_gitleaks_second_opinion(tmp_path):
    gitleaks = shutil.which("gitleaks")
    if gitleaks is None:
        pytest.skip("gitleaks is not on PATH; the second opinion is skipped (install gitleaks to enable it)")
    dest = _export(tmp_path)
    report = tmp_path / "gitleaks.json"
    proc = subprocess.run([gitleaks, "detect", "--no-git", "--redact", "--no-banner", "--source", str(dest),
                           "--report-format", "json", "--report-path", str(report)],
                          capture_output=True, text=True, timeout=600, env=dict(os.environ, HOME=str(tmp_path)))
    assert proc.returncode in (0, 1) and report.is_file(), "gitleaks failed to run"
    leaks = json.loads(report.read_text(encoding="utf-8") or "[]") or []
    entries = ss.load_allowlist(dest / "scripts" / "secret_scan_allow.json")
    raw = {(f.path, f.line) for f in ss.scan(dest).findings}
    uncovered = []
    seen = set()
    for leak in leaks:
        rel = Path(os.path.relpath(leak["File"], dest)).as_posix()
        line_no = int(leak["StartLine"])
        seen.add((rel, "gitleaks:" + leak["RuleID"]))
        if not _covered(dest, rel, line_no, raw, entries):
            uncovered.append(f"{rel}: {leak['RuleID']}")
    assert uncovered == [], "gitleaks findings not covered by the scanner or the allowlist"
    stale = [f"{e['path']}: {e['rule']}" for e in entries
             if e["rule"].startswith("gitleaks:") and (e["path"], e["rule"]) not in seen]
    assert stale == [], "gitleaks allowlist entries that gitleaks no longer reports"
