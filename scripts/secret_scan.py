#!/usr/bin/env python3
"""Release gate: find credential-shaped strings and credential-named files in a tree.

Usage: python3 scripts/secret_scan.py <folder> [--json] [--git] [--allowlist FILE] [--hashes]

Exit status: 0 when clean, 1 when findings exist (including stale allowlist
entries), 2 on a usage error. Output names the rule id, the relative path, the
line number and a MASKED preview only: the first 4 characters of the matched
value and its length. The value itself is never printed.

Deliberate test canaries are allowed in exactly two ways, never by folder:
  * an inline marker on the same line or the line above:
        secret-scan: allow <rule-id> <reason>
  * an entry in ``scripts/secret_scan_allow.json`` (relative to the scanned
    folder): exact relative path, rule id, sha256 of the exact line text and a
    reason. An entry that matches nothing is reported as a finding
    (``allowlist-stale``) so the list cannot rot. Entries whose rule starts with
    ``gitleaks:`` record a reviewed gitleaks false positive; they only need the
    line to still exist.

Limits: lines are scanned up to 4096 characters, files up to 2 MiB (larger or
truncated items are counted and reported), binary files (NUL byte) and symbolic
links are skipped. Standard library only, Python 3.11+.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable

MAX_LINE_CHARS = 4096
MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_ALLOWLIST = "scripts/secret_scan_allow.json"
# Bits per character. Random keys of 12+ characters over a 36+ symbol alphabet
# score 3.2 or more; repeated or patterned values ("aaaa1111bbbb", "abcabcabc123")
# score 2.6 or less. 3.0 sits between the two with margin on both sides.
ENTROPY_THRESHOLD = 3.0
MIN_GENERIC_LENGTH = 12
SKIP_DIRS = frozenset({".git", "__pycache__", ".pytest_cache", "node_modules", ".mypy_cache", ".ruff_cache"})

_MARKER = re.compile(r"secret-scan:\s{0,4}allow\s{1,4}([a-z0-9:_-]{1,64})\s{1,4}\S")
_KEYCHARS = r"[A-Za-z0-9_-]"
_B64URL = r"[A-Za-z0-9_-]"
_NB = r"(?<![A-Za-z0-9_-])"  # not preceded by a token character
_NA = r"(?![A-Za-z0-9_-])"  # not followed by a token character


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    preview: str
    line_sha256: str = field(default="", compare=False)

    def text(self, hashes: bool = False) -> str:
        tail = f" sha256={self.line_sha256}" if hashes and self.line_sha256 else ""
        return f"{self.path}:{self.line}: {self.rule} {self.preview}{tail}"


@dataclass
class ScanResult:
    findings: list[Finding]
    skipped: list[tuple[str, str]]
    files_scanned: int
    allowed: int


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    group: int = 0
    check: Callable[[str], bool] | None = None


def mask(value: str) -> str:
    """Masked preview: first 4 characters and the length, never the value."""
    return f"{value[:4]}...({len(value)} chars)"


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    size = len(value)
    return -sum(n / size * math.log2(n / size) for n in counts.values())


def char_classes(value: str) -> int:
    return (any(c.islower() for c in value) + any(c.isupper() for c in value)
            + any(c.isdigit() for c in value) + any(not c.isalnum() for c in value))


_PLACEHOLDER_WORDS = ("example", "changeme", "change_me", "change-me", "placeholder", "dummy",
                      "redacted", "sample", "xxxx", "****", "...", "\u2026", "fake")
# <angle> text, ${VAR}, {{ template }}, %(name)s, $(cmd), $VAR, %VAR%, {field} format fields, your-...-here.
_PLACEHOLDER_SHAPES = re.compile(r"<[^>]{0,80}>|\$\{|\{\{|%\(|\$\(|^\$|^%[A-Z_]|\{[A-Za-z_][A-Za-z0-9_.]{0,40}(?:![rsa])?\}"
                                 r"|your[-_]|[-_]here$", re.IGNORECASE)
_SHOUTY = re.compile(r"[A-Z][A-Z0-9_]{1,255}")  # environment-variable NAME such as MY_APP_TOKEN
_LOWER_WORDS = re.compile(r"[a-z_-]{1,256}")  # lowercase words with underscores or hyphens
_LETTERS = re.compile(r"[A-Za-z]{1,256}")  # camelCase / PascalCase candidates
_DOTTED = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,255}")  # dotted settings path
_LOWER_PATH = re.compile(r"[a-z0-9_./-]{1,256}")  # lowercase relative file path
_PATH_SEGMENT = re.compile(r"[a-z0-9_.-]{1,128}|[A-Z][A-Z_.-]{0,127}|[A-Z][a-z_.-]{1,127}")  # one word per segment
_SLUG_SEGMENT = re.compile(r"[a-z]{2,40}[0-9]{0,3}|[0-9]{1,4}|v[0-9]{1,4}")  # word, short number or version


def identifier_like(value: str) -> bool:
    """True when the value names a variable, setting or path instead of holding a secret."""
    if _SHOUTY.fullmatch(value.lstrip("_")) and "_" in value.strip("_"):
        return True
    if _LOWER_WORDS.fullmatch(value):
        return True
    if _LETTERS.fullmatch(value) and not re.search(r"[A-Z]{2}", value):
        humps = sum(c.isupper() for c in value)
        if humps and (len(value) - humps) / (humps + 1) >= 3:
            return True
    if "." in value and _DOTTED.fullmatch(value) and all(part[:1].isalpha() or part[:1] == "_"
                                                         for part in value.split(".")):
        return True
    if "/" in value and (_LOWER_PATH.fullmatch(value)
                         or all(_PATH_SEGMENT.fullmatch(part) for part in value.split("/") if part)):
        return True
    # Slug or version string such as name-kit-v1 or tool_2026.1: words and short numbers only.
    parts = re.split(r"[-_.]", value)
    return len(parts) >= 3 and all(_SLUG_SEGMENT.fullmatch(part) for part in parts)


_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_DIGEST_PREFIX = re.compile(r"(?:sha1|sha256|sha384|sha512|md5)[-:]", re.IGNORECASE)


def placeholder(value: str) -> bool:
    """True for documentation placeholders and template references."""
    low = value.lower()
    if any(word in low for word in _PLACEHOLDER_WORDS) or _PLACEHOLDER_SHAPES.search(value):
        return True
    return len(set(value)) <= 1


def looks_secret(value: str) -> bool:
    """Generic value test: long, mixed, high-entropy, and not a placeholder or identifier."""
    if len(value) < MIN_GENERIC_LENGTH or placeholder(value):
        return False
    if identifier_like(value) or _UUID.fullmatch(value) or _DIGEST_PREFIX.match(value):
        return False
    return char_classes(value) >= 2 and entropy(value) > ENTROPY_THRESHOLD


def _token_check(value: str) -> bool:
    """Prefixed tokens: reject placeholders and lowercase identifiers after the prefix."""
    return not placeholder(value) and char_classes(value) >= 2 and not identifier_like(value)


def _not_placeholder(value: str) -> bool:
    return not placeholder(value)


_SECRET_NAME = re.compile(r"password|passwd|secret|api_?key|apikey|token|auth(?!or(?!i[sz]))|credential",
                          re.IGNORECASE)
_DIGEST_NAME = re.compile(r"hash|sha\d|digest|checksum|integrity|fingerprint|nonce_?len", re.IGNORECASE)
_PLACEHOLDER_PASSWORDS = frozenset({"password", "passwd", "pass", "pwd", "secret", "changeme", "test",
                                    "user", "username", "mypassword", "yourpassword", "hunter2", "admin"})
_RESERVED_HOST = re.compile(r"(?:^|\.)(?:example(?:\.(?:com|net|org))?|invalid|test|localhost)$|^localhost(?::\d+)?$",
                            re.IGNORECASE)

# Each rule: id, regex (anchored by a literal prefix or boundary, every repeat bounded).
RULES: tuple[Rule, ...] = (
    # PEM header of a private key (RSA, EC, OpenSSH, DSA, PGP, encrypted or generic PKCS#8).
    Rule("private-key", re.compile(r"-{5}BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-{5}")),
    # GitHub classic tokens: personal, OAuth, user-to-server, server-to-server, refresh.
    Rule("github-token", re.compile(_NB + r"gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])"), 0, _token_check),
    # GitHub fine-grained personal access token: 22 + 59 base62 characters.
    Rule("github-fine-grained-pat", re.compile(_NB + r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}(?![A-Za-z0-9])")),
    # GitLab personal access token.
    Rule("gitlab-pat", re.compile(_NB + r"glpat-[A-Za-z0-9_-]{20,64}" + _NA), 0, _token_check),
    # AWS access key id (long-term AKIA, temporary ASIA).
    Rule("aws-access-key-id", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"), 0, _not_placeholder),
    # AWS secret access key: 40 base64 characters assigned to a name containing aws and secret.
    Rule("aws-secret-access-key", re.compile(
        r"(?i:aws[A-Za-z0-9_.-]{0,40}secret[A-Za-z0-9_.-]{0,40})[\"']?\s{0,8}[:=]{1,2}\s{0,8}[\"']?"
        r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), 1, _not_placeholder),
    # Google API key.
    Rule("google-api-key", re.compile(_NB + r"AIza[0-9A-Za-z_-]{35}" + _NA), 0, _not_placeholder),
    # Slack bot, app, user, refresh or legacy token.
    Rule("slack-token", re.compile(_NB + r"xox[abprs]-[0-9]{6,20}-[A-Za-z0-9-]{8,250}" + _NA), 0, _not_placeholder),
    # Stripe live secret or restricted key.
    Rule("stripe-live-key", re.compile(_NB + r"(?:sk|rk)_live_[A-Za-z0-9]{20,247}(?![A-Za-z0-9])"), 0, _token_check),
    # Anthropic-style key.
    Rule("anthropic-key", re.compile(_NB + r"sk-ant-[A-Za-z0-9_-]{20,250}" + _NA), 0, _token_check),
    # OpenAI-style key: sk- then 20+ key characters (project and service-account forms included).
    Rule("openai-key", re.compile(_NB + r"sk-(?!ant-)[A-Za-z0-9_-]{20,250}" + _NA), 0,
         lambda v: _token_check(v) and any(c.isdigit() for c in v)),
    # Hugging Face access token.
    Rule("huggingface-token", re.compile(_NB + r"hf_[A-Za-z0-9]{30,64}(?![A-Za-z0-9])"), 0, _token_check),
    # npm access token.
    Rule("npm-token", re.compile(_NB + r"npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"), 0, _token_check),
    # PyPI upload token (macaroon).
    Rule("pypi-token", re.compile(_NB + r"pypi-AgEI[A-Za-z0-9_-]{50,1000}" + _NA)),
    # Telegram bot token: bot id, colon, 35 characters.
    Rule("telegram-bot-token", re.compile(r"(?<![\w:])[0-9]{8,10}:[A-Za-z0-9_-]{35}" + _NA), 0, _token_check),
    # Discord bot token: base64 user id, timestamp, HMAC.
    Rule("discord-bot-token", re.compile(
        r"(?<![\w.-])[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}(?![\w.-])"), 0, _token_check),
    # JSON Web Token: header, payload, signature (header begins eyJ).
    Rule("jwt", re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{10,2000}\.[A-Za-z0-9_-]{10,4000}\.[A-Za-z0-9_-]{10,2000}"
                           + _NA)),
    # Authorization bearer header value.
    Rule("bearer-header", re.compile(r"(?i:\bbearer)\s{1,8}([A-Za-z0-9._~+/=-]{20,2000})"), 1, looks_secret),
    # Connection string with embedded credentials: scheme://user:password@host.
    Rule("connection-string-credentials", re.compile(
        r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^\s:/@\"'<>]{1,64}:([^\s/@\"'<>]{3,128})@([A-Za-z0-9._\[\]-]{1,253})"), 1),
    # .netrc-style password line.
    Rule("netrc-password", re.compile(r"(?:^\s{0,16}|\blogin\s{1,8}\S{1,256}\s{1,8})password\s{1,8}(\S{3,256})\s{0,16}$"),
         1, lambda v: not placeholder(v) and v.lower() not in _PLACEHOLDER_PASSWORDS),
    # Generic: secret-named key assigned a quoted, long, high-entropy literal.
    Rule("generic-secret-assignment", re.compile(
        r"([A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']?\s{0,8}(?::=|=|:)\s{0,8}[bru]{0,2}([\"'])([^\"'\s\\]{12,256})\2"), 3),
    # Generic, unquoted .env / shell form: a whole line NAME=value with a secret-like name and value.
    Rule("env-secret-assignment", re.compile(
        r"^\s{0,16}(?:export\s{1,8})?([A-Za-z_][A-Za-z0-9_]{0,63})\s{0,4}=\s{0,4}([^\s\"'#`;|&()\[\]{}<>,]{12,256})\s{0,16}$"), 2),
)
RULE_IDS = tuple(rule.id for rule in RULES)

FILE_RULES = ("file-env", "file-private-key", "file-ssh-key", "file-netrc", "file-pgpass", "file-npmrc-token",
              "file-cloud-credentials", "file-keepass")
_ENV_TEMPLATE_SUFFIXES = frozenset({"example", "sample", "template", "dist", "defaults"})
_KEY_SUFFIXES = frozenset({".pem", ".key", ".p12", ".pfx", ".keystore", ".jks", ".ppk"})
_SSH_KEY_NAMES = frozenset({"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"})
_NPM_AUTH = re.compile(r"_authToken\s{0,8}=\s{0,8}(?!\$\{)\S")
_CLOUD_JSON = re.compile(r"credentials\.json|client_secret[^/]{0,200}\.json|service-account[^/]{0,200}\.json",
                         re.IGNORECASE)


def file_rule(rel: str, data: bytes | None) -> str | None:
    """Rule id when the file NAME (or an .npmrc auth line) says it must never ship."""
    name = PurePosixPath(rel).name
    low = name.lower()
    if low == ".env" or (low.startswith(".env.") and low.rsplit(".", 1)[1] not in _ENV_TEMPLATE_SUFFIXES):
        return "file-env"
    if PurePosixPath(low).suffix in _KEY_SUFFIXES:
        return "file-private-key"
    if low in _SSH_KEY_NAMES:
        return "file-ssh-key"
    if low in {".netrc", "_netrc"}:
        return "file-netrc"
    if low == ".pgpass":
        return "file-pgpass"
    if low == ".npmrc" and data is not None and _NPM_AUTH.search(data.decode("utf-8", "replace")):
        return "file-npmrc-token"
    if _CLOUD_JSON.fullmatch(name):
        return "file-cloud-credentials"
    if low.endswith(".kdbx"):
        return "file-keepass"
    return None


def _generic_ok(match: re.Match[str], value_group: int = 3) -> bool:
    name, value = match.group(1), match.group(value_group)
    if not _SECRET_NAME.search(name) or _DIGEST_NAME.search(name):
        return False
    return looks_secret(value)


def _connection_ok(match: re.Match[str]) -> bool:
    password, host = match.group(1), match.group(2)
    if placeholder(password) or password.lower() in _PLACEHOLDER_PASSWORDS:
        return False
    if password.startswith((":", "$", "{", "%", "*")):
        return False
    return not _RESERVED_HOST.search(host.rstrip(".").split(":", 1)[0])


def line_findings(text: str) -> list[tuple[str, str]]:
    """(rule id, masked preview) for every credential-shaped value in one line.

    Generic rules run last and skip values a specific rule already reported.
    """
    text = text[:MAX_LINE_CHARS]
    found: list[tuple[str, str]] = []
    spans: list[tuple[int, int]] = []
    for rule in RULES:
        generic = rule.id in ("generic-secret-assignment", "env-secret-assignment")
        for match in rule.pattern.finditer(text):
            value = match.group(rule.group)
            start, end = match.span(rule.group)
            if generic:
                if any(start < e and s < end for s, e in spans) or not _generic_ok(match, rule.group):
                    continue
            elif rule.id == "connection-string-credentials":
                if not _connection_ok(match):
                    continue
            elif rule.check is not None and not rule.check(value):
                continue
            spans.append((start, end))
            found.append((rule.id, mask(value)))
    return found


def _marked(lines: list[str], index: int, rule: str) -> bool:
    for probe in (index, index - 1):
        if 0 <= probe < len(lines):
            for match in _MARKER.finditer(lines[probe][:MAX_LINE_CHARS]):
                if match.group(1) == rule:
                    return True
    return False


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


def _walk(root: Path) -> Iterable[str]:
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        base = Path(current)
        for name in sorted(files):
            yield (base / name).relative_to(root).as_posix()
        for name in dirs:
            if (base / name).is_symlink():
                yield (base / name).relative_to(root).as_posix()


def git_files(root: Path) -> list[str]:
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True,
                         timeout=60).stdout
    return sorted(name for name in out.decode("utf-8").split("\0") if name)


def load_allowlist(path: Path | None) -> list[dict[str, str]]:
    if path is None or not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("entries", []) if isinstance(data, dict) else data
    for entry in entries:
        missing = {"path", "rule", "line_sha256", "reason"} - set(entry)
        if missing or not str(entry.get("reason", "")).strip():
            raise ValueError(f"allowlist entry needs path, rule, line_sha256 and a reason: {entry.get('path')}")
    return entries


def scan(root: Path, paths: Iterable[str] | None = None, allowlist: list[dict[str, str]] | None = None,
         strict: bool = False) -> ScanResult:
    """Scan ``root`` (or the given relative ``paths``); apply markers and the allowlist.

    ``strict`` also reports allowlist entries whose file is absent from the scan.
    """
    root = Path(root)
    rels = sorted(set(paths)) if paths is not None else list(_walk(root))
    raw: list[Finding] = []
    skipped: list[tuple[str, str]] = []
    present: set[str] = set()
    line_hashes: dict[str, set[str]] = {}
    scanned = allowed = 0
    for rel in rels:
        full = root / rel
        try:
            info = full.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            skipped.append((rel, "symbolic link"))
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        present.add(rel)
        if info.st_size > MAX_FILE_BYTES:
            named = file_rule(rel, None)
            if named:
                raw.append(Finding(named, rel, 0, PurePosixPath(rel).name, ""))
            skipped.append((rel, f"larger than {MAX_FILE_BYTES} bytes"))
            continue
        data = full.read_bytes()
        named = file_rule(rel, data)
        if named:
            raw.append(Finding(named, rel, 0, PurePosixPath(rel).name, hashlib.sha256(data).hexdigest()))
        if b"\0" in data:
            skipped.append((rel, "binary (NUL byte)"))
            continue
        scanned += 1
        lines = data.decode("utf-8", "surrogateescape").splitlines()
        hashes = line_hashes.setdefault(rel, set())
        truncated = 0
        for index, line in enumerate(lines):
            digest = sha256_text(line)
            hashes.add(digest)
            if len(line) > MAX_LINE_CHARS:
                truncated += 1
            for rule, preview in line_findings(line):
                if _marked(lines, index, rule):
                    allowed += 1
                    continue
                raw.append(Finding(rule, rel, index + 1, preview, digest))
        if truncated:
            skipped.append((rel, f"{truncated} line(s) scanned only to {MAX_LINE_CHARS} characters"))
    findings: list[Finding] = []
    used: set[int] = set()
    entries = allowlist or []
    for finding in raw:
        hit = next((i for i, e in enumerate(entries) if e["path"] == finding.path and e["rule"] == finding.rule
                    and e["line_sha256"] == finding.line_sha256), None)
        if hit is None:
            findings.append(finding)
        else:
            used.add(hit)
            allowed += 1
    for i, entry in enumerate(entries):
        if i in used:
            continue
        if entry["rule"].startswith("gitleaks:"):
            if entry["path"] in present and entry["line_sha256"] in line_hashes.get(entry["path"], set()):
                continue
            if entry["path"] not in present and not strict:
                continue
        elif entry["path"] not in present and not strict:
            continue
        findings.append(Finding("allowlist-stale", entry["path"], 0, f"entry for {entry['rule']} matches nothing",
                                entry["line_sha256"]))
    return ScanResult(findings, skipped, scanned, allowed)


def scan_tree(root: Path | str, allowlist: Path | str | None = None, strict: bool = False) -> list[Finding]:
    """Findings for every file under ``root`` after markers and the allowlist.

    ``allowlist`` defaults to ``<root>/scripts/secret_scan_allow.json`` when present.
    """
    root = Path(root)
    path = Path(allowlist) if allowlist is not None else root / DEFAULT_ALLOWLIST
    return scan(root, None, load_allowlist(path), strict).findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Find credential-shaped strings and credential-named files.")
    parser.add_argument("folder", type=Path)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--git", action="store_true",
                        help="scan only files tracked by Git (and report allowlist entries for absent files)")
    parser.add_argument("--allowlist", type=Path, help=f"allowlist file (default: <folder>/{DEFAULT_ALLOWLIST})")
    parser.add_argument("--hashes", action="store_true", help="also print the sha256 of each finding's line")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    root = args.folder
    if not root.is_dir():
        print(f"secret_scan: not a directory: {root}", file=sys.stderr)
        return 2
    try:
        entries = load_allowlist(args.allowlist if args.allowlist else root / DEFAULT_ALLOWLIST)
        paths = git_files(root) if args.git else None
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"secret_scan: {exc}", file=sys.stderr)
        return 2
    result = scan(root, paths, entries, strict=args.git)
    if args.json:
        rows = [asdict(f) if args.hashes else {k: v for k, v in asdict(f).items() if k != "line_sha256"}
                for f in result.findings]
        print(json.dumps({"findings": rows, "skipped": [{"path": p, "reason": r} for p, r in result.skipped],
                          "files_scanned": result.files_scanned, "allowed": result.allowed}, indent=2))
    else:
        for finding in result.findings:
            print(finding.text(args.hashes))
        for rel, reason in result.skipped:
            print(f"skipped: {rel}: {reason}", file=sys.stderr)
        status = "FAILED" if result.findings else "ok"
        print(f"secret scan {status}: {len(result.findings)} findings, {result.files_scanned} files scanned, "
              f"{len(result.skipped)} skipped, {result.allowed} allowed")
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
