"""Linear private-network matching in audit/memory_load.py, pinned against the base blob.

The exam cases ``memory_load_dotted_host`` (``a.`` * 14000) and ``memory_load_ip_dots``
(``1.`` * 50000) spent 7.9 s and 86.3 s in the base ``NETWORK_RE``
``\\b(?:[a-z0-9-]+\\.)+(?:ts\\.net|local)\\b``: every word boundary in a long dotted run is
a new start and each start walks the rest of the run before failing, so the work is
quadratic. Hostile calls run in a subprocess with a hard timeout so a regression fails
instead of hanging the suite.

The base (pre-fix) module's outputs on the differential inputs below were recorded once
into ``tests/fixtures/linear_baseline/memory_load.json`` by ``scripts/gen_linear_baseline.py``;
the tests compare the live module with that record and need no repository history.
"""

from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, load_submodule

FIXTURE = Path(REPO_ROOT) / "tests" / "fixtures" / "linear_baseline" / "memory_load.json"
BUDGET_S = 1.0
AUDIT_BUDGET_S = 3.0
HARD_TIMEOUT_S = 10

_CHILD = textwrap.dedent(
    """
    import json
    import sys
    import time
    from pathlib import Path

    repo, kind, size, mode = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    sys.path.insert(0, repo)
    from tests.conftest import load_submodule
    mod = load_submodule('audit.memory_load')

    def unit(u):
        return (u * (size // len(u) + 1))[:size]

    shapes = {
        'a_dots': lambda: unit('a.'),
        'digit_dots': lambda: unit('1.'),
        # Variants: other separators, mixed case, unicode class members, nested
        # repetition and near-miss terminators.
        'hyphen_labels': lambda: unit('a-b.-.'),
        'mixed_case': lambda: unit('Ab.cD.'),
        'unicode_labels': lambda: unit('\\u017f\\u0130.\\u212a.'),
        'nested_repetition': lambda: unit('a.' * 200 + 'b-c.') ,
        'near_miss_local': lambda: unit('a.loca.'),
        'near_miss_ts_net': lambda: unit('a.ts.ne.'),
        'terminator_glued': lambda: unit('a.') + 'localx',
        'terminator_underscore': lambda: unit('a.') + 'ts.net_',
        'many_hits': lambda: unit('a.local.'),
        'date_month_spaces': lambda: unit('Jan ' + ' ' * 60 + '1 '),
        'date_digits': lambda: unit('2026-01-0'),
        'order_words': lambda: unit('alway nevermust '),
        'ip_octets': lambda: unit('1.1.1.'),
        'drive_letters': lambda: unit('C:C:'),
    }
    text = shapes[kind]()
    started = time.perf_counter()
    if mode == 'network':
        out = mod._private_network(text)
    elif mode == 'metrics':
        row, _ = mod._metrics(text, 'memory', 'main', 2200, 'linux')
        out = row['private_network_entries']
    elif mode == 'patterns':
        out = [bool(p.search(text)) for p in (mod.DATE_RE, mod.ORDER_RE, mod.APPROVAL_RE, mod.WRITE_RE,
                                              mod.ARTIFACT_RE, mod.UNASKED_RE)]
        out.append(sum(1 for _ in mod.IP_RE.finditer(text)))
        out.append(mod._other_os(text, 'linux'))
    elif mode == 'audit':
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / 'memories').mkdir()
            (Path(home) / 'memories' / 'MEMORY.md').write_text(text, encoding='utf-8')
            started = time.perf_counter()
            res = mod.audit_memory_load(profile_path=home, memory_char_limit=2200, user_char_limit=1375,
                                        memory_provider=None, home_os='linux', project_families={},
                                        prompt_injecting_plugins=[])
            out = [res['memory_load']['status'], res['memory_load']['truncated_by'],
                   res['memory_load']['files'][0].get('private_network_entries')]
    else:
        raise SystemExit('unknown mode ' + mode)
    json.dump({'elapsed': time.perf_counter() - started, 'out': out}, sys.stdout)
    """
)


def _child(kind: str, size: int, mode: str) -> dict:
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, str(REPO_ROOT), kind, str(size), mode],
            capture_output=True, text=True, timeout=HARD_TIMEOUT_S, cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{kind} {mode} size={size} exceeded hard timeout {HARD_TIMEOUT_S}s")
        raise
    assert proc.returncode == 0, proc.stderr[-800:]
    payload = json.loads(proc.stdout)
    print(f"TIMING {mode} {kind} size={size} {payload['elapsed']:.4f}s out={payload['out']}")
    return payload


HOSTILE = ("a_dots", "digit_dots")
VARIANTS = ("hyphen_labels", "mixed_case", "unicode_labels", "nested_repetition",
            "near_miss_local", "near_miss_ts_net", "terminator_glued", "terminator_underscore")


@pytest.mark.parametrize("size", [100_000, 1_000_000])
@pytest.mark.parametrize("kind", HOSTILE + VARIANTS)
def test_private_network_is_fast_on_hostile_runs(kind: str, size: int) -> None:
    payload = _child(kind, size, "network")
    assert payload["elapsed"] < BUDGET_S
    assert payload["out"] is False


def test_many_hits_still_match_fast() -> None:
    payload = _child("many_hits", 1_000_000, "network")
    assert payload["elapsed"] < BUDGET_S
    assert payload["out"] is True


@pytest.mark.parametrize("kind", ["a_dots", "digit_dots"])
def test_metrics_row_is_fast_on_hostile_runs(kind: str) -> None:
    payload = _child(kind, 1_000_000, "metrics")
    assert payload["elapsed"] < BUDGET_S
    assert payload["out"] == 0


@pytest.mark.parametrize(("kind", "size"), [("a_dots", 28_000), ("digit_dots", 100_000), ("a_dots", 500_000)])
def test_whole_audit_completes_unbounded_on_exam_inputs(kind: str, size: int) -> None:
    # 500 000 bytes stays under MAX_FILE_BYTES, so the file is fully measured, not cut.
    payload = _child(kind, size, "audit")
    assert payload["elapsed"] < AUDIT_BUDGET_S
    assert payload["out"] == ["completed", [], 0]


@pytest.mark.parametrize("kind", ["date_month_spaces", "date_digits", "order_words", "ip_octets",
                                  "drive_letters", "a_dots", "digit_dots"])
@pytest.mark.parametrize("size", [100_000, 1_000_000])
def test_other_patterns_in_the_file_stay_linear(kind: str, size: int) -> None:
    payload = _child(kind, size, "patterns")
    assert payload["elapsed"] < BUDGET_S


# --- differential against the recorded base outputs -------------------------------------


def _digest(value) -> str:
    """Short hash of a JSON value: recorded rows may quote corpus samples, so store no text."""
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _bits(flags) -> str:
    """Pack booleans as "<count>:<hex>" to keep the fixture small."""
    text = "".join("1" if flag else "0" for flag in flags)
    return f"{len(text)}:{int(text or '0', 2):0{(len(text) + 3) // 4}x}"


def _unbits(packed: str) -> str:
    count, value = packed.split(":")
    return format(int(value, 16), f"0{count}b") if int(count) else ""


def _ip(*parts: int) -> str:
    return ".".join(str(p) for p in parts)


def _corpus() -> list[str]:
    hosts = ["host", "node-1", "a", "x-y-z", "NAS", "Pi4", "box9", "-lead", "trail-", "a_b", "caf\u00e9",
             "\u017fhop", "\u0130x", "\u212aelvin", "\u00e9t\u00e9", "_"]
    suffixes = ["local", "LOCAL", "Local", "ts.net", "TS.NET", "Ts.Net", "\u017fs.net", "ts.ne", "loca",
                "localhost", "local-", "local.", "local_", "localx", "ts.net.", "ts.netx", "ts.net-",
                "ts..net", "lan", "home.arpa"]
    joins = [".", "..", ". ", "-.", ".-"]
    rows: list[str] = []
    for host in hosts:
        for suffix in suffixes:
            rows.append(host + "." + suffix)
        for join in joins:
            rows.append(host + join + "local")
    for pre in ["", " ", "x", "_", "-", ".", "@", "(", "\u00e9", "1", "\n"]:
        for post in ["", " ", ".", "!", ")", "_", "x", "-", "\u00e9"]:
            rows.append(pre + "nas.local" + post)
            rows.append(pre + "pi.tail1.ts." + "net" + post)
    ips = [_ip(10, 1, 2, 3), _ip(172, 16, 0, 1), _ip(172, 31, 255, 255), _ip(172, 32, 0, 1),
           _ip(192, 168, 7, 9), _ip(100, 64, 0, 1), _ip(100, 127, 255, 255), _ip(100, 128, 0, 1),
           _ip(198, 51, 100, 4), _ip(8, 8, 8, 8), "999.999.999.999", "010.1.2.3", _ip(10, 0, 0),
           _ip(10, 1, 2, 3, 4)]
    for ip in ips:
        for wrap in ("{}", "at {} now", "{}.", "x{}", "{}:8080", "[{}]", "v{}", "{}/24"):
            rows.append(wrap.format(ip))
    rows += ["", " ", "plain text", "Python project", "/home/user/a", "/Users/" + "user/a",
             r"C:\\work\\a", "2026-01-01 entry", "Always write skills unasked", "approval required",
             "a." * 40, "1." * 40, "a." * 40 + "local", "1." * 40 + "local", "a.b.c.d.e.f.ts." + "net",
             "x.local.local", ".local", "local", "ts.net", "-.local", "--.local", "a-.-.local",
             "-a.local", "_a.local", "a._.local", "\u00e9a.local", "a\u00e9.local", "ssh pi" + "@nas.local -p 22",
             "http://printer.local:631/", "joined" + "\n§\n" + "node.ts." + "net"]
    rng = random.Random(25)
    alphabet = list("aZ09-._ ") + ["local", "LoCaL", "ts.net", "\u017f", "\u0130", "\u212a", "\u00e9", ".."]
    for _ in range(200):
        rows.append("".join(rng.choice(alphabet) for _ in range(rng.randint(1, 14))))
    return rows


HOME_OSES = ("linux", "macos", "windows", None)


def _metric_texts(corpus):
    return ["\n§\n".join(corpus[chunk:chunk + 25]) for chunk in range(0, len(corpus), 25)]


def _random_short_strings():
    rng = random.Random(1)
    alphabet = list("aAz09-._ .\n") + ["ts.net", "local", "LOCAL", "Ts.NeT", "\u017f", "\u0130", "\u0131",
                                       "\u212a", "\u00e9", "..", "ts.ne", "loca", "TS.NET", "1."]
    return ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12))) for _ in range(40_000)]


@pytest.fixture(scope="module")
def base():
    """Outputs of the base module on the inputs below, recorded once (no git history)."""
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_corpus_is_large_enough():
    assert len(_corpus()) >= 300


def test_private_network_is_identical_to_base(base):
    live = load_submodule("audit.memory_load")
    corpus = _corpus()
    assert _digest(corpus) == base["corpus_sha"], "inputs changed since the base was recorded"
    got = _unbits(_bits(live._private_network(s) for s in corpus))
    diffs = [s for s, new, old in zip(corpus, got, _unbits(base["private_network"]), strict=True)
             if new != old]
    assert diffs == []
    assert "1" in got and "0" in got


def test_metrics_rows_are_identical_to_base(base):
    live = load_submodule("audit.memory_load")
    texts = _metric_texts(_corpus())
    expected = base["metrics"]
    assert len(expected) == len(texts) * len(HOME_OSES)
    index = 0
    for text in texts:
        for home_os in HOME_OSES:
            assert _digest(live._metrics(text, "memory", "main", 2200, home_os)) == expected[index], \
                (index, home_os)
            index += 1


def test_network_matcher_is_identical_to_base_regex_on_random_short_strings(base):
    live = load_submodule("audit.memory_load")
    strings = _random_short_strings()
    assert _digest(strings) == base["random_sha"], "inputs changed since the base was recorded"
    for s, old in zip(strings, _unbits(base["network_name"]), strict=True):
        assert live._network_name(s) == (old == "1"), repr(s)


def record_base_outputs(base_mod, base_file):
    """Run the base module on this file's inputs (scripts/gen_linear_baseline.py only)."""
    corpus = _corpus()
    strings = _random_short_strings()
    return {
        "corpus_sha": _digest(corpus),
        "private_network": _bits(base_mod._private_network(s) for s in corpus),
        "metrics": [_digest(base_mod._metrics(text, "memory", "main", 2200, home_os))
                    for text in _metric_texts(corpus) for home_os in HOME_OSES],
        "random_sha": _digest(strings),
        "network_name": _bits(bool(base_mod.NETWORK_RE.search(s)) for s in strings),
    }
