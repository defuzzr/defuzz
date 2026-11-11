"""Bound vendored executable-inventory redaction and pin it against the base blob.

The audit calls ``audit_executable_inventory`` (``audit_surface.py``). That entry
redacts MCP ``args`` through ``redact_arg_or_url``. Hostile cases run in a
subprocess with a hard timeout so a superlinear regex fails the test instead
of hanging the suite.

Profiled before the fix (4 s alarm, 100 KB shapes): ``Authorization:`` + spaces
is only ``_AUTH_HEADER_INLINE_RE``; ``A_`` * 50000 and ``https://h/?`` + ``q`` *
100000 are only ``_SECRET_ASSIGNMENT_RE``. ``_redact_url`` on the query shape
finished in well under a millisecond. No third pattern was superlinear.

The base (pre-fix) module's ``redact_arg_or_url`` outputs on the corpus below
were recorded once into ``tests/fixtures/linear_baseline/executable_inventory.json``
by ``scripts/gen_linear_baseline.py``, so the comparison needs no repository
history. The record holds no secret-shaped sample: each occurrence of a row's
own sample in the base output is stored as a numbered marker and restored from
the corpus (which builds the samples from pieces) at test time.
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz.audit.vendor.executable_inventory import (  # noqa: E402
    audit_executable_inventory,
    redact_arg_or_url,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDOR_FILE = REPO_ROOT / "audit" / "vendor" / "executable_inventory.py"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "linear_baseline" / "executable_inventory.json"
BUDGET_S = 2.0
HARD_TIMEOUT_S = 8
PLACEHOLDER = "<redacted>"

_CHILD = textwrap.dedent(
    """
    import importlib.util
    import json
    import sys
    import time
    from pathlib import Path

    kind, n_s, module_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    spec = importlib.util.spec_from_file_location(
        "executable_inventory_under_test", Path(module_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    quote, tick = chr(34), chr(39)
    if kind == "auth_spaces":
        text = "Authorization:" + (" " * n_s) + quote
    elif kind == "auth_tabs":
        text = "Authorization:" + ("\\t" * n_s) + quote
    elif kind == "auth_mixed_ws":
        text = "Authorization:" + (" \\t" * n_s) + quote
    elif kind == "ident_underscore":
        text = "A_" * n_s
    elif kind == "ident_hyphen":
        text = "A-" * n_s
    elif kind == "ident_dot":
        text = "A." * n_s
    elif kind == "ident_then_assignment":
        text = ("A_" * n_s) + "password=x"
    elif kind == "repeated_equals":
        text = "password" + ("=" * n_s) + "x"
    elif kind == "nested_quotes":
        text = "password=" + quote + tick + ("q" * n_s) + tick + quote
    elif kind == "query_q":
        text = "https://h/?" + ("q" * n_s)
    else:
        raise SystemExit("unknown kind " + kind)
    started = time.perf_counter()
    result = module.audit_executable_inventory(
        {"profiles": [{"profile": "synthetic", "config_data": {
            "mcp_servers": {"s": {"command": "node", "args": [text]}}}}]}
    )
    direct, _changed = module.redact_arg_or_url(text)
    elapsed = time.perf_counter() - started
    declared = result["inventory"]["mcp_servers"][0]["declared_args"][0]
    json.dump({
        "elapsed": elapsed,
        "declared_len": len(declared),
        "direct_len": len(direct),
        "coverage": result["coverage"],
    }, sys.stdout)
    """
)


def _hostile(kind: str, n: int) -> dict:
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, kind, str(n), str(VENDOR_FILE)],
            capture_output=True,
            text=True,
            timeout=HARD_TIMEOUT_S,
            cwd=str(REPO_ROOT),
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"{kind} n={n} exceeded hard timeout {HARD_TIMEOUT_S}s: {exc}")
    assert proc.returncode == 0, proc.stderr[-500:]
    return json.loads(proc.stdout)


@pytest.mark.parametrize(
    ("kind", "n"),
    [
        ("auth_spaces", 100_000),
        ("ident_underscore", 50_000),
        ("query_q", 100_000),
        ("auth_spaces", 1_000_000),
        ("ident_underscore", 500_000),
        ("query_q", 1_000_000),
        ("auth_tabs", 100_000),
        ("auth_mixed_ws", 50_000),
        ("ident_hyphen", 50_000),
        ("ident_dot", 50_000),
        ("ident_then_assignment", 50_000),
        ("repeated_equals", 100_000),
        ("nested_quotes", 100_000),
    ],
)
def test_hostile_redaction_finishes_under_budget(kind: str, n: int) -> None:
    payload = _hostile(kind, n)
    print(f"TIMING {kind} n={n} {payload['elapsed']:.4f}s")
    assert payload["elapsed"] < BUDGET_S, (
        f"{kind} n={n} took {payload['elapsed']:.4f}s; budget {BUDGET_S}s"
    )
    assert payload["coverage"] == "could_not_verify"


def _canary(*parts: str) -> str:
    return "".join(parts)


def _corpus() -> list[tuple[str, tuple[str, ...]]]:
    """At least 300 argument strings. Secret-shaped values are built here, not literals."""
    short = ("a", "ab", "xyz", "abcde")
    longer = (
        _canary("syn", "mark"),
        _canary("opq", "value"),
        _canary("can", "ary", "12"),
    )
    keys = (
        "password", "token", "secret", "api_key", "api-key", "access_token",
        "auth_token", "client_secret", "bearer", "secret_key", "API_KEY",
    )
    rows: list[tuple[str, tuple[str, ...]]] = []
    for key in keys:
        for value in short + longer:
            for sep in ("=", ":", " = ", "\t=\t"):
                for prefix in ("", "--", "cfg_"):
                    rows.append((f"{prefix}{key}{sep}{value}", (value,)))
            rows.append((f"{key}'='{value}", (value,)))
            rows.append((f'"{key}":"{value}"', (value,)))
            rows.append((f"'{key}': '{value}'", (value,)))
            rows.append((f"--{key} {value}", (value,)))
    for scheme in ("", "Bearer ", "bearer ", "Basic ", "Token ", "BEARER\t"):
        for spacing in (":", ": ", " : ", ":\t", ":  "):
            for name in ("Authorization", "authorization", "AUTHORIZATION"):
                payload = _canary("hdr", scheme.strip() or "plain")
                rows.append((f"{name}{spacing}{scheme}{payload}", (payload,)))
    rows.append(("Authorization:Bearertoken", ("Bearertoken", "token")))
    host = "example.test"
    userinfo = _canary("user", "info")
    query = _canary("qry", "value")
    fragment = _canary("frag", "ment")
    rows.extend([
        (f"https://{host}/plain", ()),
        (f"https://user:{userinfo}@{host}/path", (userinfo,)),
        (f"https://{host}/?custom={query}", (query,)),
        (f"https://{host}/?custom={query}&keep=1", (query,)),
        (f"https://{host}/#{fragment}", (fragment,)),
        (f"https://{host}/?%70assword={query}", (query,)),
        (f"https://{host}/?a=1;b={query}", (query,)),
        (f"https://{host}/?next=foo://bar&token={query}", (query,)),
        (f"connect https://user:{userinfo}@{host}/ now", (userinfo,)),
        (f"see https://{host}/?custom={query} later", (query,)),
        ("", ()),
        (" ", ()),
        ("\t", ()),
        ("\n", ()),
        ("   \t  ", ()),
        ("node", ()),
        ("--version", ()),
        ("./server.js", ()),
        ("ordinary-argument", ()),
        ("café", ()),
        ("密码", ()),
        ("пароль", ()),
        (f"password=\u00a0{_canary('nbsp', 'val')}", (_canary("nbsp", "val"),)),
        ("password=", ()),
        ("password=   ", ()),
        ("YOUR_password=example", ()),
        ("token=NONE", ()),
    ])
    for index in range(12):
        rows.append((f"tool-{index}", ()))
        rows.append((f"https://{host}/item/{index}", ()))
    return rows


def _marker(index: int) -> str:
    return f"\x00{index}\x00"


SAMPLE_MIN_LEN = 6  # _corpus builds longer samples from pieces; shorter ones are plain words.


def _hide_samples(out: str, secrets: tuple[str, ...]) -> str:
    """Replace the row's built samples (longest first) in a base output with numbered markers."""
    assert "\x00" not in out
    for index in sorted(range(len(secrets)), key=lambda i: -len(secrets[i])):
        if len(secrets[index]) >= SAMPLE_MIN_LEN:
            out = out.replace(secrets[index], _marker(index))
    return out


def _restore_samples(stored: str, secrets: tuple[str, ...]) -> str:
    for index, secret in enumerate(secrets):
        stored = stored.replace(_marker(index), secret)
    return stored


def _load_base(corpus) -> list:
    """Base (out, changed) per corpus row from the record, or None if it timed out."""
    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert recorded["secret_assignment_has_ident_prefix"] is True  # base: "[A-Z0-9_]*_"
    assert recorded["secret_assignment_has_open_repeat"] is True  # base: "{1,}"
    rows = recorded["rows"]
    assert len(rows) == len(corpus), "corpus changed since the base was recorded"
    results = []
    for (text, secrets), row in zip(corpus, rows, strict=True):
        if row is None:
            results.append(None)
            continue
        text_len, stored, changed = row
        assert text_len == len(text), "corpus changed since the base was recorded"
        results.append((_restore_samples(stored, secrets), changed))
    return results


def _bounded(fn, text: str, seconds: float = 1.0):
    def _handler(signum, frame):
        raise TimeoutError

    old = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return fn(text)
    except TimeoutError:
        return None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _residue(text: str) -> str:
    return text.replace(PLACEHOLDER, "")


def _is_subsequence(needle: str, haystack: str) -> bool:
    iterator = iter(haystack)
    return all(char in iterator for char in needle)


def test_linear_shapes_keep_local_redaction_policy() -> None:
    pattern = redact_arg_or_url.__globals__["_SECRET_ASSIGNMENT_RE"].pattern
    auth = redact_arg_or_url.__globals__["_AUTH_HEADER_INLINE_RE"].pattern
    assert "(?<![A-Za-z0-9])" in pattern
    assert "[A-Z0-9_]*_" not in pattern
    assert "{1,}" in pattern
    assert "{6,}" not in pattern
    assert "(?:(?:bearer|basic|token)\\s+)?" in auth
    source = VENDOR_FILE.read_text(encoding="utf-8")
    assert "LOCAL PATCH: share parser approval" in source
    assert "uncaptured-manifest-v1" in source
    assert "opaque custom parameters" in source
    short = "z"
    redacted, changed = redact_arg_or_url("password=" + short)
    assert changed and short not in redacted
    five = "abcde"
    redacted, changed = redact_arg_or_url("token=" + five)
    assert changed and five not in redacted
    query = _canary("opq", "canary")
    fragment = _canary("frag", "canary")
    for text, secret in (
        (f"https://example.test/?custom={query}", query),
        (f"https://example.test/#{fragment}", fragment),
    ):
        redacted, changed = redact_arg_or_url(text)
        assert changed and secret not in redacted
    result = audit_executable_inventory(
        {"profiles": [{"profile": "synthetic", "config_data": {
            "mcp_servers": {"s": {"command": "node", "args": ["--version"]}}}}]}
    )
    assert result["coverage"] == "could_not_verify"
    assert result["findings"][0]["coverage"] == "could_not_verify"


def test_patched_redaction_is_not_weaker_than_base() -> None:
    corpus = _corpus()
    assert len(corpus) >= 300
    base = _load_base(corpus)
    differences: list[str] = []
    compared = 0
    skipped = 0
    for (text, secrets), base_result in zip(corpus, base, strict=True):
        new_result = _bounded(redact_arg_or_url, text)
        if base_result is None or new_result is None:
            skipped += 1
            continue
        compared += 1
        base_out, base_changed = base_result
        new_out, _new_changed = new_result
        if base_out == new_out:
            continue
        hidden = [secret for secret in secrets if secret and secret not in base_out]
        leaked = [secret for secret in hidden if secret in new_out]
        more = (
            not leaked
            and _is_subsequence(_residue(new_out), _residue(base_out))
            and not (base_changed and PLACEHOLDER not in new_out and PLACEHOLDER in base_out)
        )
        shown = text if len(text) <= 120 else text[:117] + "..."
        differences.append(
            f"{'MORE' if more else 'LESS'} input={shown!r} base={base_out!r} new={new_out!r}"
        )
        assert more, "less redaction:\n" + "\n".join(differences)
    assert compared >= 300
    assert skipped == 0
    print(f"DIFFERENTIAL compared={compared} differences={len(differences)}")
    for line in differences:
        print(line)


def record_base_outputs(base_mod, base_file) -> dict:
    """Run the base module on this file's corpus (scripts/gen_linear_baseline.py only)."""
    corpus = _corpus()
    samples = {secret for _, secrets in corpus for secret in secrets if len(secret) >= SAMPLE_MIN_LEN}
    rows = []
    for text, secrets in corpus:
        result = _bounded(base_mod.redact_arg_or_url, text)
        if result is None:
            rows.append(None)
            continue
        out, changed = result
        stored = _hide_samples(out, secrets)
        assert _restore_samples(stored, secrets) == out
        assert not any(sample in stored for sample in samples), (text, stored)
        rows.append([len(text), stored, bool(changed)])
    pattern = base_mod._SECRET_ASSIGNMENT_RE.pattern
    return {"secret_assignment_has_ident_prefix": "[A-Z0-9_]*_" in pattern,
            "secret_assignment_has_open_repeat": "{1,}" in pattern, "rows": rows}
