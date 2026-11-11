"""Linear-time skill hygiene matching, pinned against the base blob.

The adversarial exam case ``skill_hygiene_ticket_paths`` (SKILL.md of ``a/`` * 24000) ran
11.6 s: the base ``ticket_refs`` path form
``\\b[A-Za-z0-9_.-]{1,64}(?:/[A-Za-z0-9_.-]{1,64})+[#!]\\d+\\b`` was retried at every word
boundary of the run and rescanned the run each time. Profiled on the base blob at 10 KB ->
20 KB (counts(), seconds): ``a/`` 0.42 -> 1.66 and ``1/`` 0.42 -> 1.64 (that path form);
``<!--`` 0.26 -> 1.08 (``re.sub(r'<!--.*?-->')``, unclosed openers); ``10.0.0.1 `` on one
line 0.61 -> 2.34 (``_network_specific`` cut and searched the whole line per match). All
three now run in one pass. Checked and linear on the base (10 KB -> 20 KB doubles):
``dates``, ``commit_refs`` (``a`` * 7 + ``..``), ``machine_paths`` (``/home/``),
``network_identities`` hostname ``{0,250}`` (``a.``), ``session_refs``, ``narration``
(``we ``), the other ticket forms (``a#``, ``PR ``, ``AB-``, ``a#1...1x``), the
frontmatter strip, heading/bullet line matches.

Hostile timings run in a subprocess with a hard timeout so a regression fails instead of
hanging. The base (pre-fix) module's outputs on the inputs below were recorded once into
``tests/fixtures/linear_baseline/skill_hygiene.json`` by ``scripts/gen_linear_baseline.py``;
the tests compare the live module with that record and need no repository history.
"""

from __future__ import annotations

import ast
import hashlib
import json
import random
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests import REPO_ROOT, load_submodule

MODULE_FILE = Path(REPO_ROOT) / "audit" / "skill_hygiene.py"
FIXTURE = Path(REPO_ROOT) / "tests" / "fixtures" / "linear_baseline" / "skill_hygiene.json"
BASE_TICKET_RE = re.compile(
    r'(?i:\bgithub\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:issues|pull)/\d+\b)'
    r'|(?i:\b(?:PR|issue|ticket)[ \t]{1,3}#?\d+\b)'
    r'|(?i:\b(?:pull|fixes|closes|see)[ \t]{1,3}#\d+\b)'
    r'|(?<![:\\@\w.-])[A-Za-z][A-Za-z0-9_.-]{1,63}#\d{2,}\b'
    r'|\b[A-Za-z0-9_.-]{1,64}(?:/[A-Za-z0-9_.-]{1,64})+[#!]\d+\b'
    r'|(?<![A-Za-z0-9_.-])(?P<prefix>[A-Z]{2,10})-(?P<num>[1-9]\d{1,6})(?![A-Za-z0-9_.-])'
)
BUDGET_S = 1.0  # Isolated matcher on 100 KB and 1 MB hostile text.
COUNTS_1MB_BUDGET_S = 4.0  # Whole counts() at 1 MB: ten linear regex passes, base included.
HARD_TIMEOUT_S = 30
SIZES = (100_000, 1_000_000)
RECORD_TIMEOUT_S = 240  # Generation only: the base on a hostile 1 MB input does not finish.

_CHILD = textwrap.dedent(
    """
    import importlib.util, json, sys, time, types
    repo, module_path, target, kind, size = sys.argv[1:6]
    size = int(size)
    for name, path in (('lin', [repo]), ('lin.audit', [repo + '/audit'])):
        pkg = types.ModuleType(name); pkg.__path__ = path; pkg.__package__ = name
        sys.modules[name] = pkg
    spec = importlib.util.spec_from_file_location('lin.audit.skill_hygiene_child', module_path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    unit = json.loads(sys.argv[6])
    head, body, tail = unit['head'], unit['body'], unit['tail']
    text = head + body * max(1, (size - len(head) - len(tail)) // len(body)) + tail
    if target == 'tickets':
        fn = (lambda t: sum(1 for _ in mod._ticket_ref_spans(t))) if hasattr(mod, '_ticket_ref_spans') \\
            else (lambda t: sum(1 for _ in mod.PATTERNS['ticket_refs'].finditer(t)))
    elif target == 'strip':
        fn = getattr(mod, '_strip_html_comments', None) or (
            lambda t: mod.re.sub(r'<!--.*?-->', '', t, flags=mod.re.S))
    elif target == 'network':
        fn = getattr(mod, '_network_count', None) or (lambda t: sum(
            mod._network_specific(m, t) for m in mod.PATTERNS['network_identities'].finditer(t)))
    else:
        fn = mod.counts
    start = time.perf_counter()
    result = fn(text)
    print(json.dumps({'seconds': time.perf_counter() - start, 'chars': len(text),
                      'result': result if isinstance(result, (int, dict)) else len(result)}))
    """
)

# (target, kind, head, body, tail). `body` repeats to the size; head/tail are near misses.
HOSTILE = [
    ("tickets", "exam_a_slash", "", "a/", ""),
    ("tickets", "digits_slash", "", "1/", ""),
    ("tickets", "separators_dot_dash_underscore", "", "a.-_/", ""),
    ("tickets", "mixed_case", "", "aB/Cd/", ""),
    ("tickets", "unicode_break", "", "a/\u00e9b/", ""),
    ("tickets", "nested_long_piece", "", "a/" * 40 + "b" * 70 + "/", "#12"),
    ("tickets", "near_miss_empty_last_piece", "", "a/", "/#12"),
    ("tickets", "near_miss_hash_no_digit", "", "a/", "#x"),
    ("tickets", "near_miss_digit_then_word", "", "a/", "#12x"),
    ("tickets", "near_miss_bang", "", "a/", "!"),
    ("tickets", "many_viable_runs", "", "a/b#1 ", ""),
    ("tickets", "github_inside_one_run", "", "github.com/o/r/issues/1/", "x#12"),
    ("strip", "unclosed_openers", "", "<!--", ""),
    ("strip", "openers_and_dashes", "", "<!-- --", "->"),
    ("network", "private_ips_one_line", "", "10.0.0.1 ", ""),
    ("network", "private_ips_table_line", "| ", "192.168.1.2 | ", ""),
]


def _run(module_path, target, kind, size, unit, timeout):
    return subprocess.run(
        [sys.executable, "-c", _CHILD, str(REPO_ROOT), str(module_path), target, kind, str(size),
         json.dumps(unit)],
        capture_output=True, text=True, timeout=timeout, check=True,
    )


def _key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def _digest(value) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


@pytest.fixture(scope="module")
def recorded():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_base_pattern_is_the_one_replaced(recorded):
    # The base pattern, recorded from the base module, is the one copied above verbatim.
    pattern_sha = hashlib.sha256(BASE_TICKET_RE.pattern.encode()).hexdigest()
    assert recorded["ticket_refs_pattern_sha256"] == pattern_sha
    live = load_submodule("audit.skill_hygiene")
    assert live.PATTERNS["ticket_refs"].pattern != BASE_TICKET_RE.pattern


EXAM = [("counts", "exam_a_slash", 100_000), ("counts", "exam_a_slash", 1_000_000),
        ("counts", "unclosed_openers", 100_000), ("counts", "private_ips_one_line", 100_000)]


@pytest.mark.parametrize(("target", "kind", "size"), EXAM)
def test_red_base_exceeds_budget(recorded, target, kind, size):
    # The base took longer than the budget on these exam shapes (recorded, or it did not
    # finish within the recording timeout). The live module must finish within the budget
    # and, where the base finished, return what the base returned.
    row = recorded["exam"][f"{target}/{kind}/{size}"]
    assert row["timed_out"] or row["seconds"] > BUDGET_S, row
    unit = next({"head": h, "body": b, "tail": t} for _, k, h, b, t in HOSTILE if k == kind)
    live = json.loads(_run(MODULE_FILE, target, kind, size, unit, HARD_TIMEOUT_S).stdout)
    assert live["seconds"] < (BUDGET_S if size <= 100_000 else COUNTS_1MB_BUDGET_S), live
    if not row["timed_out"]:
        assert live["result"] == row["result"], (live, row)


@pytest.mark.parametrize(("target", "kind", "head", "body", "tail"), HOSTILE,
                         ids=[row[1] for row in HOSTILE])
@pytest.mark.parametrize("size", SIZES, ids=["100KB", "1MB"])
def test_hostile_isolated_call_is_linear(target, kind, head, body, tail, size):
    out = _run(MODULE_FILE, target, kind, size, {"head": head, "body": body, "tail": tail},
               HARD_TIMEOUT_S)
    row = json.loads(out.stdout)
    assert row["chars"] >= size * 0.9
    assert row["seconds"] < BUDGET_S, row


@pytest.mark.parametrize(("kind", "size", "budget"), [
    ("exam_a_slash", 100_000, BUDGET_S), ("unclosed_openers", 100_000, BUDGET_S),
    ("private_ips_one_line", 100_000, BUDGET_S), ("exam_a_slash", 1_000_000, COUNTS_1MB_BUDGET_S),
    ("unclosed_openers", 1_000_000, COUNTS_1MB_BUDGET_S),
    ("private_ips_one_line", 1_000_000, COUNTS_1MB_BUDGET_S),
])
def test_hostile_counts_end_to_end(kind, size, budget):
    unit = next({"head": h, "body": b, "tail": t} for _, k, h, b, t in HOSTILE if k == kind)
    row = json.loads(_run(MODULE_FILE, "counts", kind, size, unit, HARD_TIMEOUT_S).stdout)
    assert row["seconds"] < budget, row


def _fixture_strings():
    tree = ast.parse((Path(REPO_ROOT) / "tests" / "test_audit_skill_hygiene.py").read_text())
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.strip():
            found.append(node.value)
    return sorted(set(found))


FRAGMENTS = [
    "a/b#12", "owner/repo#123", "group/project!482", "repo#65828", "See #812", "Fixes #12",
    "Closes #7", "PR 42", "issue #9", "ticket 77", "pull #3", "ECMA-262", "JIRA-1234",
    "ABC-12", "AB-0", "github.com/o/r/issues/1", "github.com/o/r/pull/22", "x.y/z#1",
    "-a/b#1", ".a/b#12", "a//b#1", "/a/b#1", "a/b/#1", "a/b#", "a/b#1x", "a/b#1_", "a/b!7",
    "a/" + "b" * 64 + "#1", "a/" + "b" * 65 + "#1", "c" * 64 + "/d#1", "c" * 65 + "/d#1",
    "c" * 70 + "/d/e#1", "\u00e9/a/b#1", "a\u00e9/b#1", "a/b#\u0661\u0662", "a/b#1\u00e9",
    "x:a/b#12", "@a/b#12", "a/b#12/c/d#34", "12/c/d#34", "a/b#1 c/d#2", "k8s/x-y.z_w/v#99",
    "AB-12/c#3", "a/AB-12#3", "AB-12#34", "x/AB-123", "10.0.0.1", "192.168.1.20", "172.16.0.5",
    "100.64.0.1", "10.0.0.0/8", "10.1.2.3/30", "box.local", "host.lan", "n.tail.ts." + "net",
    "e.g.", "for example", "example:", "example", "RFC1918", "private range", "| ", "|",
    "<!--", "-->", "<!-- note -->", "<!---->", "<!-->", "2026-11-09", "Nov 9", "9 Nov 2026",
    "11/09/2026", "v1.2.0", "## Changelog", "## Notes", "- ", "* ", "1. ", "---", "\n", "\n",
    "\n", " ", " ", " ", "\t", "/" + "home/jdoe/work", "/" + "Users/x/y", "C:\\" + "Users\\bob\\x",
    "commit abcdef1", "abcdef1..1234567", "session 20261109_" + "101010_abcdef",
    "this session", "we found", "last time we", "I tried", "yesterday", ".", ",", "#", "!",
    "/", "-", "_", "a", "Z", "9", "word", "path/to/file.py",
]


def _corpus():
    rng = random.Random(25)
    corpus = list(_fixture_strings())
    corpus += FRAGMENTS
    for _ in range(900):
        pieces = rng.choices(FRAGMENTS, k=rng.randint(1, 12))
        joiner = rng.choice(["", " ", "\n", "/", "", " "])
        corpus.append(joiner.join(pieces))
    for body in ("a/", "1/", "a.-_/", "aB/Cd/", "<!--", "10.0.0.1 ", "a/b#1 "):
        for n in (1, 2, 3, 31, 32, 33, 64, 65, 200):
            for tail in ("", "#12", "/#12", "#x", "#12x", "!", "!5", "-->", "\n"):
                corpus.append(body * n + tail)
    return corpus


def _base_spans(text):
    return [(m.start(), m.end(), m.group("prefix")) for m in BASE_TICKET_RE.finditer(text)]


def _base_row(base_mod, text):
    network = sum(base_mod._network_specific(m, text)
                  for m in base_mod.PATTERNS["network_identities"].finditer(text))
    return [network, base_mod.dated_lesson_lines(text), _digest(base_mod.counts(text))]


def _live_row(mod, text):
    return [mod._network_count(text), mod.dated_lesson_lines(text), mod.counts(text)]


def test_differential_against_base(recorded):
    # Ticket spans and comment stripping are compared with the base expressions copied
    # above; network count, counts() and dated_lesson_lines() with the recorded base.
    mod = load_submodule("audit.skill_hygiene")
    corpus = _corpus()
    assert len(corpus) >= 300
    base_rows = recorded["corpus"]
    spans_hit = differences = compared = 0
    for text in corpus:
        expected_spans = _base_spans(text)
        assert list(mod._ticket_ref_spans(text)) == expected_spans, text
        spans_hit += bool(expected_spans)
        assert mod._strip_html_comments(text) == re.sub(r"<!--.*?-->", "", text, flags=re.S), text
        expected = base_rows.get(_key(text))
        if expected is None:
            continue  # Input added after the base was recorded (from the unit-test strings).
        compared += 1
        network, dated, counts = _live_row(mod, text)
        assert [network, dated] == expected[:2], text
        if _digest(counts) != expected[2]:
            differences += 1
    assert differences == 0
    assert compared >= 300, compared
    assert spans_hit >= 200, spans_hit  # The corpus exercises the matcher, not just misses.
    print(f"differential corpus: {len(corpus)} inputs, {compared} against the recorded base, "
          f"{spans_hit} with ticket matches, 0 differences")


NETWORK_TEXTS = ("Use 10.0.0.1 (e.g. a gateway).", "| a | 10.0.0.1 |", "10.0.0.0/8 x",
                 "10.1.0.0/30 example", "10.1.0.0/30", "box.local\n10.0.0.2\n| 10.0.0.3")


def test_network_specific_without_cache_matches_base(recorded):
    mod = load_submodule("audit.skill_hygiene")
    assert len(recorded["network_specific"]) == len(NETWORK_TEXTS)
    for text, old in zip(NETWORK_TEXTS, recorded["network_specific"], strict=True):
        new = [mod._network_specific(m, text) for m in mod.PATTERNS["network_identities"].finditer(text)]
        assert new == old, text


def record_base_outputs(base_mod, base_file):
    """Run the base module on this file's inputs (scripts/gen_linear_baseline.py only)."""
    assert base_mod.PATTERNS["ticket_refs"].pattern == BASE_TICKET_RE.pattern
    exam = {}
    for target, kind, size in EXAM:
        unit = next({"head": h, "body": b, "tail": t} for _, k, h, b, t in HOSTILE if k == kind)
        try:
            row = json.loads(_run(base_file, target, kind, size, unit, RECORD_TIMEOUT_S).stdout)
            exam[f"{target}/{kind}/{size}"] = {"timed_out": False, "seconds": round(row["seconds"], 2),
                                               "result": row["result"]}
        except subprocess.TimeoutExpired:
            exam[f"{target}/{kind}/{size}"] = {"timed_out": True, "seconds": None, "result": None}
    corpus = {_key(text): _base_row(base_mod, text) for text in _corpus()}
    network = [[base_mod._network_specific(m, text)
                for m in base_mod.PATTERNS["network_identities"].finditer(text)]
               for text in NETWORK_TEXTS]
    return {"ticket_refs_pattern_sha256": hashlib.sha256(BASE_TICKET_RE.pattern.encode()).hexdigest(),
            "exam": exam, "corpus": corpus, "network_specific": network,
            "record_timeout_s": RECORD_TIMEOUT_S}
