"""Literal-path extraction stays linear on one very long line, with base results.

``safe_text`` tokenised every candidate line with ``shlex.split``. shlex appends
one character at a time to the token it is building, so one whitespace-free line
costs quadratic time (exam case ``outward_shlex_long_line``: a 1 MB ``a/a/...``
Markdown line, 18 s end to end; 0.16 s at 100 KB, 6.5 s at 400 KB in isolation).
``_split_words`` scans the same POSIX grammar in runs.

Hostile cases run in a subprocess with a hard timeout so a regression fails
instead of hanging. The differential tests require output identical to the base
(pre-fix) module's output on the same inputs, recorded once into
``tests/fixtures/linear_baseline/literal_paths.json`` by
``scripts/gen_linear_baseline.py``; they need no repository history.

Other patterns in ``audit/literal_paths.py`` timed on worst-case 100 KB inputs
(``test_other_patterns_in_file_are_linear``): ``_PATH`` (lookbehind-anchored;
the alternation ``/|./|../|~/`` has a fixed length; its run class has no
required literal after it) and the flag probe ``(?:^|\\s)-(?:-?[\\w-]+)`` used by
``safe_config``. Both grow linearly.
"""

from __future__ import annotations

import hashlib
import json
import random
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests import load_submodule

REPO_ROOT = Path(__file__).resolve().parents[1]
LIVE_FILE = REPO_ROOT / "audit" / "literal_paths.py"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "linear_baseline" / "literal_paths.json"
HARD_TIMEOUT_S = 20
# Budget per size. Base safe_text took 0.15-0.6 s at 100 KB and over 20 s at 1 MB;
# after the fix it is about 0.01 s and 0.1 s (the rest is linear per-word checks).
BUDGET_S = {100_000: 0.05, 1_000_000: 0.5}
TOTAL_BUDGET_S = {100_000: 0.25, 1_000_000: 1.5}

_CHILD = textwrap.dedent(
    """
    import importlib.util
    import json
    import re
    import sys
    import time
    from pathlib import Path

    kind, n, module_path, repo = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    sys.path.insert(0, repo)
    from tests import TEST_PACKAGE_NAME, ensure_test_package
    ensure_test_package()
    name = TEST_PACKAGE_NAME + '.audit._literal_paths_timed'
    spec = importlib.util.spec_from_file_location(name, Path(module_path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    q, t, b = chr(34), chr(39), chr(92)

    def fill(unit, prefix=''):
        return prefix + unit * ((n - len(prefix)) // len(unit))

    shapes = {
        'exam_a_slash': fill('a/'),
        'unclosed_double': fill('a/', q),
        'escaped_quotes_never_close': fill(b + q, q),
        'unicode': fill('\\u00e9/\\u4e2d'),
        'other_separators_mixed_case': fill('/Ab,c:D=e;F'),
        'nested_quoting': fill(t + 'a/' + t + q + 'B/' + q + b + 'c'),
        'escape_every_char': fill(b + 'a'),
        'near_miss_single': fill(t + 'x' + t + 'y/', t),
        'flag_long_value': fill('a/', '--path='),
    }
    if kind == 'envrc':
        data = ('source ' + fill('a/')).encode()
        started = time.perf_counter()
        refs = module.path_references(Path('.envrc'), data, credentials=True)
        elapsed = time.perf_counter() - started
        json.dump({'elapsed': elapsed, 'refs': len(refs)}, sys.stdout)
        raise SystemExit(0)
    text = shapes[kind]
    started = time.perf_counter()
    cleaned = module.safe_text(text)
    split_s = time.perf_counter() - started
    refs = module.path_references(Path('SKILL.md'), text.encode())
    config = module.safe_config(text)
    elapsed = time.perf_counter() - started
    json.dump({'elapsed': elapsed, 'safe_text': split_s, 'refs': len(refs),
               'cleaned': len(cleaned), 'config': len(config)}, sys.stdout)
    """
)

KINDS = [
    "exam_a_slash",
    "unclosed_double",
    "escaped_quotes_never_close",
    "unicode",
    "other_separators_mixed_case",
    "nested_quoting",
    "escape_every_char",
    "near_miss_single",
    "flag_long_value",
    "envrc",
]


def _timed(kind: str, n: int, module_file: Path = LIVE_FILE) -> dict:
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, kind, str(n), str(module_file), str(REPO_ROOT)],
            capture_output=True,
            text=True,
            timeout=HARD_TIMEOUT_S,
            cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"{kind} n={n} exceeded hard timeout {HARD_TIMEOUT_S}s: {exc}")
    assert proc.returncode == 0, proc.stderr[-800:]
    return json.loads(proc.stdout)


@pytest.mark.parametrize("n", sorted(BUDGET_S))
@pytest.mark.parametrize("kind", KINDS)
def test_long_line_finishes_under_budget(kind: str, n: int) -> None:
    payload = _timed(kind, n)
    isolated = payload.get("safe_text", payload["elapsed"])
    print(f"TIMING {kind} n={n} safe_text={isolated:.4f}s all={payload['elapsed']:.4f}s")
    # The isolated split-and-clean call that used to be quadratic. The envrc case times a
    # whole path_references call (no isolated safe_text), so it gets the whole-call budget;
    # 0.05 s failed under machine load at 0.051-0.064 s. The 1 MB budget still catches a
    # quadratic split (the base took over 20 s there).
    budget = TOTAL_BUDGET_S[n] if kind == "envrc" else BUDGET_S[n]
    assert isolated < budget, f"{kind} n={n} safe_text {isolated:.4f}s; budget {budget}s"
    # All three entry points together (safe_text, path_references, safe_config).
    assert payload["elapsed"] < TOTAL_BUDGET_S[n], (
        f"{kind} n={n} took {payload['elapsed']:.4f}s; budget {TOTAL_BUDGET_S[n]}s"
    )


def test_exam_shape_still_yields_no_reference_and_no_cut() -> None:
    # The 1 MB a/a/... line is one word with no path start: nothing is dropped.
    payload = _timed("exam_a_slash", 1_000_000)
    assert payload["refs"] == 0
    assert payload["cleaned"] == 1_000_000


# ---------------------------------------------------------------- differential


@pytest.fixture(scope="module")
def modules():
    """(recorded base outputs, live module). The base outputs need no git history."""
    base = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert base["corpus_sha"] == _digest(CORPUS), "inputs changed since the base was recorded"
    return base, load_submodule("audit.literal_paths")


def _digest(value) -> str:
    """Short hash of a JSON value: outputs quote path-shaped samples, so store no text."""
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


Q, T, B = '"', "'", "\\"

SEEDS = [
    "", " ", "\t", "\r\n", "a", "a b", "  a  b  ", "/usr/bin/env python3", "./run.sh --flag",
    "../x/y", "~/bin/tool", "cat /etc/hosts", "file:///tmp/x", "git+file:///srv/repo.git",
    "file://host/share", "see /a/b.", "path=/opt/x", "--config=/a/b", "--token /never/x",
    "--api-key=/never/x", "-p secret /a", "-u user /b", "echo $HOME/x", "C:\\x\\y",
    f"{Q}/a b/c{Q}", f"{T}/a b/c{T}", f"{Q}{Q}", f"{T}{T}", f"{Q}{Q} {T}{T}", f"a{Q}{Q}b",
    f"{Q}/a{B}{Q}b{Q}", f"{Q}{B}{B}{Q}", f"{Q}{B}x{Q}", f"{Q}{B}$HOME{Q}", f"{T}{B}{T}",
    f"{B} /a", f"a{B} b", f"{B}{B}", f"{B}", f"a{B}", f"{Q}", f"{T}", f"{Q}abc", f"{T}abc",
    f"{Q}a{B}", f"a{Q}b{Q}c{T}d{T}e", f"{B}{Q}/x{B}{Q}", "#", "# /a", "a#b /c", "a #b /c",
    f"{Q}#{Q} /x", f"{T}#{T}", "source ./env.sh", "source_env /x # trailing", ". ~/x",
    "dotenv .env.local", "source", "source a b", f"source {Q}/a b{Q}", "source /a #c\nx",
    "\u00e9/\u4e2d", "/\u00e9t\u00e9/x", "a\u00a0/b", "a\x0b/b", "a\x0c/b", "a\x00/b",
    "\u2028/x", "(/a)", "[/b]", "{/c}", "</d>", "`/e`", "x,/f;", "/g\n/h", "/i\r/j",
    "npx -y @scope/pkg /tmp/x", "node --require ./hook.js app.js",
    "python -m http.server --directory /srv", "--password=" + "p" * 3 + " /z",
    "export PATH=/a:/b", "NODE_OPTIONS=--require=/x/y.js", "a\\\nb /c",
]


def _random_corpus(count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    alphabet = ["a", "Z", "/", ".", "~", "-", "=", ":", " ", "\t", "\n", "\r", Q, T, B, "#",
                "$", "é", "中", ",", ";", "(", "{", "file:", "--token", "-p", "./", "../"]
    return ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24))) for _ in range(count)]


CORPUS = SEEDS + _random_corpus(600, 20261110)


def _outcome(fn, *args, **kwargs):
    try:
        return ("ok", fn(*args, **kwargs))
    except ValueError as exc:
        return ("ValueError", str(exc))


def test_corpus_size() -> None:
    assert len(CORPUS) >= 300
    assert len(set(CORPUS)) >= 300


@pytest.mark.parametrize("comments", [False, True])
def test_split_words_matches_shlex(modules, comments: bool) -> None:
    _, live = modules
    mismatches = [
        text for text in CORPUS
        if _outcome(live._split_words, text, comments=comments)
        != _outcome(shlex.split, text, comments=comments)
    ]
    assert mismatches == []


def _config_values():
    return CORPUS + [{"command": "x", "args": CORPUS[:40]}, CORPUS[40:80]]


def _reference_data(name: str, text: str) -> bytes:
    if name == "run.py":
        return f"X = {text!r}\n".encode()
    if name == "x.json":
        return json.dumps({"cmd": text, "args": [text]}).encode()
    if name == ".env":
        return f"PATH={text}\nNODE_OPTIONS={text}\n".encode()
    if name == ".envrc":
        return f"source {text}\n{text}\n".encode()
    return (text + "\n" + text).encode()


REFERENCE_CASES = [("SKILL.md", False), ("run.py", False), ("x.json", False), (".env", True),
                   (".envrc", True)]
HOSTILE_100KB = ["a/" * 50_000, Q + "a/" * 50_000, "/x" + "a/" * 50_000 + " /y",
                 (T + "a/" + T + Q + "B/" + Q + B + "c") * 8_000, (B + "a") * 50_000]


def _hashes(fn, values) -> list[str]:
    return [_digest(fn(value)) for value in values]


def test_safe_text_matches_base(modules) -> None:
    base, live = modules
    assert _hashes(live.safe_text, CORPUS) == base["safe_text"]


def test_safe_config_matches_base(modules) -> None:
    base, live = modules
    assert _hashes(live.safe_config, _config_values()) == base["safe_config"]


def _reference_hashes(module, name: str, credentials: bool) -> list[str]:
    return [_digest(_outcome(module.path_references, Path(name), _reference_data(name, text),
                             credentials=credentials)) for text in CORPUS]


def _hostile_hashes(module) -> list[list[str]]:
    return [[_digest(module.safe_text(text)), _digest(module.path_references(Path("SKILL.md"), text.encode()))]
            for text in HOSTILE_100KB]


@pytest.mark.parametrize(("name", "credentials"), REFERENCE_CASES)
def test_path_references_match_base(modules, name: str, credentials: bool) -> None:
    base, live = modules
    expected = base["path_references"][name]
    got = _reference_hashes(live, name, credentials)
    assert [text for text, new, old in zip(CORPUS, got, expected, strict=True) if new != old] == []


def test_hostile_100kb_matches_base(modules) -> None:
    # The base was still fast enough to record at 100 KB.
    base, live = modules
    assert _hostile_hashes(live) == base["hostile_100kb"]


# ----------------------------------------------------- other patterns, same file


def test_other_patterns_in_file_are_linear(modules) -> None:
    import re
    import time

    _, live = modules
    flag = re.compile(r"(?:^|\s)-(?:-?[\w-]+)")
    worst = {
        "_PATH run": (live._PATH.finditer, "/" + "a" * 100_000),
        "_PATH failing starts": (live._PATH.finditer, "/(" * 50_000),
        "_PATH file: prefixes": (live._PATH.finditer, "file:" * 20_000),
        "_PATH dot prefixes": (live._PATH.finditer, " ." * 50_000),
        "flag probe misses": (flag.search, " -" * 50_000),
        "flag probe dashes": (flag.search, " " + "-" * 100_000),
    }
    for label, (fn, text) in worst.items():
        started = time.perf_counter()
        result = fn(text)
        if not isinstance(result, (re.Match, type(None))):
            list(result)
        elapsed = time.perf_counter() - started
        print(f"PATTERN {label} {elapsed:.4f}s")
        assert elapsed < 0.1, (label, elapsed)


def record_base_outputs(base_mod, base_file) -> dict:
    """Run the base module on this file's inputs (scripts/gen_linear_baseline.py only)."""
    return {
        "corpus_sha": _digest(CORPUS),
        "safe_text": _hashes(base_mod.safe_text, CORPUS),
        "safe_config": _hashes(base_mod.safe_config, _config_values()),
        "path_references": {name: _reference_hashes(base_mod, name, credentials)
                            for name, credentials in REFERENCE_CASES},
        "hostile_100kb": _hostile_hashes(base_mod),
    }
