"""Shipped project templates must not tell worktree tools to copy secret files.

Hermes (``hermes_cli/worktree_ops.py``) copies every non-comment entry of a repository's
``.worktreeinclude`` into each new git worktree. A template that lists ``.env`` there would
spread the user's secrets into every worktree automatically, so the templates list no
secret-named path and their docs must not claim that ``.env`` is copied.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.scanner import _is_secret_filename  # noqa: E402

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
TEXT_SUFFIXES = {".md", ".txt", ".yaml", ".yml", ".toml", ""}

# A `.env` token that is not `.env.example` / `.env.sample` / `.env.template`.
_ENV_TOKEN = re.compile(r"(?<![\w.])\.env(?![\w.-])")
_COPY_WORD = re.compile(r"(?i)\bcop(?:y|ies|ied|ying)\b")
_NEGATION = re.compile(r"(?i)\b(?:not|never|no)\b")


def _template_roots() -> list[Path]:
    return sorted(p for p in TEMPLATES_DIR.iterdir() if (p / "template.yaml").is_file())


def _include_entries(path: Path) -> list[str]:
    entries = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            entries.append(entry)
    return entries


def _claims_env_copied(line: str) -> bool:
    return (
        "worktree" in line.lower()
        and bool(_ENV_TOKEN.search(line))
        and bool(_COPY_WORD.search(line))
        and not _NEGATION.search(line)
    )


class TemplatesDoNotCopySecretsTests(unittest.TestCase):
    def test_every_shipped_template_is_checked(self) -> None:
        # The checks below walk exactly these roots; a template without a
        # .worktreeinclude (web-golden) has nothing copied into worktrees.
        self.assertEqual({p.name for p in _template_roots()}, {
            "cpp-golden", "dotnet-golden", "go-golden", "python-golden",
            "rust-golden", "ts-node-golden", "web-golden",
        })

    def test_worktreeinclude_lists_no_secret_file(self) -> None:
        for root in _template_roots():
            for include in sorted(root.rglob(".worktreeinclude")):
                with self.subTest(file=str(include.relative_to(TEMPLATES_DIR))):
                    secret = [e for e in _include_entries(include) if _is_secret_filename(e.rstrip("/"))]
                    self.assertEqual(secret, [], "secret-named entries would be copied into every worktree")

    def test_worktreeinclude_explains_secrets_are_not_copied(self) -> None:
        for root in _template_roots():
            for include in sorted(root.rglob(".worktreeinclude")):
                with self.subTest(file=str(include.relative_to(TEMPLATES_DIR))):
                    text = include.read_text(encoding="utf-8")
                    self.assertTrue(text.startswith("#"), "file should start with an explanatory comment")
                    self.assertIn("not copied", text)
                    self.assertIn(".env.example", text)

    def test_template_docs_do_not_claim_env_is_copied(self) -> None:
        offenders = []
        for path in sorted(TEMPLATES_DIR.rglob("*")):
            if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if _claims_env_copied(line):
                    offenders.append(f"{path.relative_to(TEMPLATES_DIR)}:{lineno}: {line.strip()}")
        self.assertEqual(offenders, [])

    def test_claim_detector(self) -> None:
        self.assertTrue(_claims_env_copied("├── .worktreeinclude  # Copies .env into git worktrees automatically"))
        self.assertFalse(_claims_env_copied("# .env is not copied into worktrees; create it from .env.example"))
        self.assertFalse(_claims_env_copied("Copy .env.example into each worktree"))


if __name__ == "__main__":
    unittest.main()
