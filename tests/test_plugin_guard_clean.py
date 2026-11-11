"""Regression guard: keep the plugin clear of the Hermes plugin-guard ``hardcoded_secret`` rule.

Hermes blocks a plugin (verdict ``dangerous``, not overridable) when runtime code holds a line
matching its generic secret pattern, e.g. ``cut_token = 'metadata_byte_budget'``: any name
CONTAINING ``token``/``secret``/``password``/``api_key`` assigned a 20+ char literal.

The regex below is copied verbatim from the Hermes source, ``tools/skills_guard.py:489-492``
(pattern id ``hardcoded_secret``, severity ``critical``, compiled with ``re.IGNORECASE`` at
``tools/skills_guard.py:536``). ``tools/plugin_guard.py`` only demotes it in docs/CI
(``DOC_PROSE_DEMOTIONS``, line 95), ``if __name__ == '__main__'`` blocks (line 105), test trees
and whole-line comments; runtime code keeps ``critical``.

This lint needs no Hermes checkout. If ``DEFUZZ_HERMES_SOURCE`` points at one, the real
scanner also runs over a fresh public export.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Verbatim from hermes-agent tools/skills_guard.py:489-491, matched case-insensitively.
HARDCODED_SECRET_RE = re.compile(
    r'(?:api[_-]?key|token|secret|password)\s*[=:]\s*["\']'
    r'(?!(?-i:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)["\'])'
    r'[A-Za-z0-9+/=_-]{20,}',
    re.IGNORECASE,
)

RUNTIME_SUFFIXES = {".py", ".js", ".ts"}
COMMENT_PREFIX = {".py": "#", ".js": "//", ".ts": "//"}

# Explicit exemptions only: {"relative/path.py:LINE": "reason"}. Keep empty unless justified.
ALLOWED: dict[str, str] = {}


def _runtime_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True).stdout
    files = []
    for rel in (p for p in out.decode().split("\0") if p):
        parts = Path(rel).parts
        if parts[0] in {"tests", "docs"} or Path(rel).suffix not in RUNTIME_SUFFIXES:
            continue
        if (REPO_ROOT / rel).is_file():
            files.append(Path(rel))
    return files


def _main_guard_lines(text: str) -> set[int]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            names = {getattr(n, "id", None) for n in (node.test.left, *node.test.comparators)}
            consts = {getattr(n, "value", None) for n in (node.test.left, *node.test.comparators)}
            if "__name__" in names and "__main__" in consts:
                for st in node.body:
                    lines.update(range(st.lineno, (st.end_lineno or st.lineno) + 1))
    return lines


def find_secret_shaped_lines(root: Path = REPO_ROOT, files: list[Path] | None = None) -> list[str]:
    hits = []
    for rel in files if files is not None else _runtime_files():
        try:
            text = (root / rel).read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue
        guarded = _main_guard_lines(text) if rel.suffix == ".py" else set()
        prefix = COMMENT_PREFIX[rel.suffix]
        for no, line in enumerate(text.split("\n"), start=1):
            if line.lstrip().startswith(prefix) or no in guarded:
                continue  # scanner demotes these below critical
            key = f"{rel.as_posix()}:{no}"
            if HARDCODED_SECRET_RE.search(line) and key not in ALLOWED:
                hits.append(f"{key}: {line.strip()[:100]}")
    return hits


def test_pattern_mirror_catches_known_false_positive():
    assert HARDCODED_SECRET_RE.search("cut_token = 'metadata_byte_budget' if x else 'y'")
    assert not HARDCODED_SECRET_RE.search("cut_reason = 'metadata_byte_budget' if x else 'y'")
    assert not HARDCODED_SECRET_RE.search("token = 'GITHUB_PERSONAL_TOKEN'")  # env-var name shape


def test_runtime_code_has_no_secret_shaped_assignment():
    hits = find_secret_shaped_lines()
    assert not hits, (
        "Hermes plugin guard would mark these lines `hardcoded_secret` (critical -> verdict "
        "`dangerous`, catalog rejects the plugin). Rename the variable/key so its name does not "
        "contain token/secret/password/api_key (e.g. cut_token -> cut_reason):\n  " + "\n  ".join(hits))


EXPORT_SCRIPT = REPO_ROOT / "scripts/export_public.py"


def _guard_target(tmp_path: Path, script: Path | None = None) -> Path:
    """The tree to scan: a fresh export, or the repository itself when it IS the export.

    The public repository does not ship scripts/export_public.py.
    """
    script = EXPORT_SCRIPT if script is None else script
    if not script.is_file():
        return REPO_ROOT
    dest = tmp_path / "export"
    subprocess.run([sys.executable, str(script), "--dest", str(dest)],
                   cwd=REPO_ROOT, check=True, capture_output=True)
    return dest


def test_guard_target_without_export_script_is_the_repository(tmp_path):
    assert _guard_target(tmp_path, tmp_path / "absent" / "export_public.py") == REPO_ROOT
    assert not (tmp_path / "export").exists()


def test_guard_target_with_export_script_is_a_fresh_export(tmp_path):
    stub = tmp_path / "export_public.py"
    stub.write_text("import pathlib, sys\n"
                    "dest = pathlib.Path(sys.argv[sys.argv.index('--dest') + 1])\n"
                    "dest.mkdir()\n(dest / 'exported').write_text('1')\n")
    dest = _guard_target(tmp_path, stub)
    assert dest == tmp_path / "export" and (dest / "exported").is_file()


@pytest.mark.skipif(not os.environ.get("DEFUZZ_HERMES_SOURCE"),
                    reason="set DEFUZZ_HERMES_SOURCE to a hermes-agent checkout to run the real plugin guard")
def test_real_plugin_guard_verdict_not_dangerous(tmp_path, monkeypatch):
    src = Path(os.environ["DEFUZZ_HERMES_SOURCE"]).resolve()
    dest = _guard_target(tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    monkeypatch.syspath_prepend(str(src))
    from tools.plugin_guard import scan_plugin  # noqa: PLC0415
    result = scan_plugin(dest)
    critical = [f"{f.pattern_id} {f.file}:{f.line}" for f in result.findings if f.severity == "critical"]
    assert result.verdict != "dangerous", critical
