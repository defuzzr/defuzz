#!/usr/bin/env python3
"""Copy (or check) the bundled web-golden template from its source repository.

Usage:
    python3 scripts/sync_web_golden.py <source-repo-path> [--check]

The source is a separate Git repository laid out as::

    web-golden/template.yaml      manifest
    web-golden/rules.json         placement rules
    web-golden/tmpl_prefix/       the project
    proposals/AGENTS.root.md      agent rules proposed for the generated project

Only files tracked by Git in the source (``git -C <source> ls-files``) are read, so
``node_modules/``, ``dist/`` and ``.xtask-cache/`` are never copied. They are also
refused by name, in case one is ever committed by mistake. The result is written to
``templates/web-golden/`` of this repository; files there that the source no longer
has are removed.

Integration adjustments are the explicit transformations in ``TRANSFORMS`` below,
and nothing else is changed:

1. ``rules.json``: the ``reason`` of the ``docs`` and ``test`` placement rules is
   replaced by a shorter one with the same meaning (``SHORT_REASONS``). A moved
   write's one-line notice keeps at most 100 characters of a reason, and the
   template test suite requires every bundled reason to fit. The file is written
   back with ``json.dumps(indent=2)``, the source's own layout.
2. ``proposals/AGENTS.root.md`` -> ``tmpl_prefix/AGENTS.md``, without the
   ``<!-- Proposal for the integrator ... -->`` comment line, which becomes the
   blank line Markdown needs after the heading, and its table cells are padded to
   equal widths as ``biome format`` (which the project's check runs) writes them.
   A template's own
   AGENTS.md is how the golden templates hand their agent rules to a new project:
   at creation the scaffolder keeps it as ``docs/AGENTS.template.md`` and writes
   the generated AGENTS.md from the rules.

Tool versions need no transformation: like ts-node-golden, the template states
its floors in its own build files (``.nvmrc``, ``engines``, ``packageManager``)
and ships no TOOLS.lock, so creation seeds the lock from the user's machine.

With ``--check`` nothing is written; the exit code is 1 when any file differs,
and each differing path is printed.

Exit codes: 0 in sync / synced, 1 out of date (--check), 2 usage or source error.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
DEST = REPO_ROOT / "templates" / "web-golden"
SOURCE_DIR = "web-golden"
COPIED = ("template.yaml", "rules.json")
PROJECT_DIR = "tmpl_prefix"
NEVER_COPY = frozenset({"node_modules", "dist", ".xtask-cache"})
PROPOSAL_COMMENT = "<!-- Proposal for the integrator:"


def _agents_md(text: str) -> str:
    lines = text.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.lstrip().startswith(PROPOSAL_COMMENT)]
    if len(hits) != 1:
        raise SystemExit(f"error: expected exactly one line starting {PROPOSAL_COMMENT!r} in AGENTS.root.md")
    # The comment sits between the heading and the first list; a blank line keeps both
    # separated as Markdown requires (rumdl MD022/MD032).
    lines[hits[0]] = "\n"
    return _align_tables("".join(lines))


def _align_tables(text: str) -> str:
    """Pad Markdown table cells to equal column widths, the layout `biome format` writes."""
    out: List[str] = []
    block: List[List[str]] = []

    def flush() -> None:
        if not block:
            return
        widths = [max(len(row[i]) for row in block) for i in range(len(block[0]))]
        for row in block:
            if all(set(cell) == {"-"} for cell in row):
                row = ["-" * w for w in widths]
            out.append("| " + " | ".join(cell.ljust(w) for cell, w in zip(row, widths)) + " |\n")
        block.clear()

    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\n")
        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [cell.strip() for cell in stripped[1:-1].split("|")]
            if block and len(cells) != len(block[0]):
                raise SystemExit("error: AGENTS.root.md has a table row with a different number of cells")
            block.append(cells)
            continue
        flush()
        out.append(line)
    flush()
    return "".join(out)


# Placement reasons are quoted in the one-line notice a moved write gets, which keeps
# at most 100 characters of a reason; the source's two reasons are longer.
SHORT_REASONS = {
    "docs": "Loose Markdown notes go in docs/; README, LICENSE, CHANGELOG and other governance files stay",
    "test": "Vitest finds tests only in tests/unit/ (test.include in vite.config.ts); *.e2e.ts never moves",
}


def _rules_json(text: str) -> str:
    rules = json.loads(text)
    seen = set()
    for rule in rules.get("placement_rules") or []:
        kind = rule.get("kind")
        if kind in SHORT_REASONS and len(rule.get("reason") or "") > 100:
            rule["reason"] = SHORT_REASONS[kind]
            seen.add(kind)
    if seen != set(SHORT_REASONS):
        missing = sorted(set(SHORT_REASONS) - seen)
        raise SystemExit(f"error: rules.json no longer has an over-long reason for {missing}; update SHORT_REASONS")
    return json.dumps(rules, indent=2, ensure_ascii=False) + "\n"


# destination (relative to templates/web-golden) -> (source path, transformation)
TRANSFORMS: Dict[str, tuple[str, Callable[[str], str]]] = {
    "rules.json": (f"{SOURCE_DIR}/rules.json", _rules_json),
    f"{PROJECT_DIR}/AGENTS.md": ("proposals/AGENTS.root.md", _agents_md),
}


def _tracked(source: Path) -> List[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(source), "ls-files", "-z"], check=True, capture_output=True
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"error: {source} is not a readable Git repository: {exc}") from exc
    return sorted(name for name in out.decode("utf-8").split("\0") if name)


def expected_files(source: Path) -> Dict[str, bytes]:
    """Return {destination path: bytes} for everything templates/web-golden must hold."""
    tracked = _tracked(source)
    files: Dict[str, bytes] = {}
    prefix = f"{SOURCE_DIR}/"
    for rel in tracked:
        if not rel.startswith(prefix):
            continue
        inner = rel[len(prefix):]
        parts = PurePosixPath(inner).parts
        if inner not in COPIED and parts[0] != PROJECT_DIR:
            raise SystemExit(f"error: unexpected source file {rel} (only {COPIED} and {PROJECT_DIR}/ are copied)")
        if any(part in NEVER_COPY for part in parts):
            raise SystemExit(f"error: refusing generated folder in source: {rel}")
        path = source / rel
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"error: {rel} is not a regular file in the working tree")
        files[inner] = path.read_bytes()
    for name in COPIED:
        if name not in files:
            raise SystemExit(f"error: source has no tracked {SOURCE_DIR}/{name}")
    if not any(name.startswith(f"{PROJECT_DIR}/") for name in files):
        raise SystemExit(f"error: source has no tracked {SOURCE_DIR}/{PROJECT_DIR}/ files")
    for dest, (src_rel, transform) in TRANSFORMS.items():
        if src_rel not in tracked:
            raise SystemExit(f"error: source has no tracked {src_rel}")
        if dest in files and src_rel != f"{SOURCE_DIR}/{dest}":
            raise SystemExit(f"error: {dest} is shipped by the source and also produced from {src_rel}")
        text = (source / src_rel).read_text(encoding="utf-8")
        files[dest] = transform(text).encode("utf-8")
    return files


def _current_files(dest: Path) -> Dict[str, bytes]:
    if not dest.is_dir():
        return {}
    return {
        path.relative_to(dest).as_posix(): path.read_bytes()
        for path in sorted(dest.rglob("*"))
        if path.is_file() and not any(part in NEVER_COPY for part in path.relative_to(dest).parts)
    }


def differences(want: Dict[str, bytes], have: Dict[str, bytes]) -> List[str]:
    out = []
    for name in sorted(set(want) | set(have)):
        if name not in have:
            out.append(f"missing: {name}")
        elif name not in want:
            out.append(f"extra: {name}")
        elif want[name] != have[name]:
            out.append(f"differs: {name}")
    return out


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Copy or check templates/web-golden from its source repository.")
    parser.add_argument("source", type=Path, help="path to the web-golden source repository")
    parser.add_argument("--check", action="store_true", help="only report differences; exit 1 if any")
    args = parser.parse_args(argv)
    source = args.source.resolve()
    want = expected_files(source)
    have = _current_files(DEST)
    diff = differences(want, have)
    if args.check:
        for line in diff:
            print(line)
        print(f"web-golden: {len(want)} files, {len(diff)} differ")
        return 1 if diff else 0
    for name in sorted(set(have) - set(want)):
        (DEST / name).unlink()
    for name, data in sorted(want.items()):
        target = DEST / name
        if have.get(name) == data:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for folder in sorted((p for p in DEST.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        if not any(folder.iterdir()):
            folder.rmdir()
    print(f"web-golden: {len(want)} files written, {len(diff)} changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
