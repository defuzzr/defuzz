"""Check standalone evidence references without depending on source positions."""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOC = REPO_ROOT / "docs" / "DISCLOSURE-EVIDENCE.md"
ANCHOR_RE = re.compile(r"`(?P<path>[\w./-]+)`\s+\(`(?P<symbol>[^`]+)`\)")
TEST_RE = re.compile(r"`(tests/[\w./-]+\.py)`")


def check(text: str, root: Path = REPO_ROOT) -> list[str]:
    problems = []
    rows = [line for line in text.splitlines() if re.match(r"\| \d+ \|", line)]
    if not rows:
        problems.append("missing evidence rows")
    for row in rows:
        cells = row.strip("| ").split(" | ")
        if len(cells) != 4:
            problems.append(f"malformed evidence row: {row}")
            continue
        evidence, tested_by = cells[2:]
        anchors = list(ANCHOR_RE.finditer(evidence))
        if not anchors or ANCHOR_RE.sub("", evidence).strip(" ,"):
            problems.append(f"expected file-and-symbol anchors: {evidence}")
        for match in anchors:
            path = root / match["path"]
            if not path.is_file():
                problems.append(f"{match['path']}: missing file")
                continue
            symbol = match["symbol"]
            source = path.read_text(encoding="utf-8")
            pattern = rf"(?<!\w){re.escape(symbol)}(?!\w)" if symbol.isidentifier() else re.escape(symbol)
            if not re.search(pattern, source):
                problems.append(f"{match['path']}: missing symbol/text {symbol!r}")
        for name in TEST_RE.findall(tested_by):
            if not (root / name).is_file():
                problems.append(f"{name}: missing test file")
        if TEST_RE.sub("", tested_by).strip(" ,") not in ("", "Not tested as a whole", "Manual inspection"):
            problems.append(f"expected test files or coverage note: {tested_by}")
    return problems


def test_every_anchor_and_test_file_resolves():
    assert not (problems := check(DOC.read_text(encoding="utf-8"))), "\n".join(problems)


def test_anchor_survives_moves_but_detects_removed_or_renamed_symbol(tmp_path):
    source = tmp_path / "sample.py"
    text = "| 1 | Example | `sample.py` (`target`) | Manual inspection |"
    source.write_text("def target():\n    pass\n", encoding="utf-8")
    assert not check(text, tmp_path)
    source.write_text("\n" * 100 + source.read_text(), encoding="utf-8")
    assert not check(text, tmp_path)
    source.write_text("def renamed_target():\n    pass\n", encoding="utf-8")
    assert check(text, tmp_path)
    source.write_text("", encoding="utf-8")
    assert check(text, tmp_path)


def test_missing_files_and_malformed_anchors_fail(tmp_path):
    text = "| 1 | Example | `missing.py` (`target`) | `tests/missing.py` |"
    problems = check(text, tmp_path)
    assert any("missing file" in problem for problem in problems)
    assert any("missing test file" in problem for problem in problems)
    assert check(text.replace(" (`target`)", ""), tmp_path)


def test_limits_exists_and_is_linked():
    assert (REPO_ROOT / "docs" / "limits.md").is_file()
    assert "(limits.md)" in DOC.read_text(encoding="utf-8")
