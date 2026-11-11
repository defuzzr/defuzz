"""Tell a beginner plainly when a project check failed only because it could not download.

The classifier is conservative: a missed offline case keeps the ordinary failure ending, which is
acceptable; a wrong "needs an internet connection" is not. It is linear and uses no regular
expressions: it lowercases a capped head and tail window of the check output, collapses
whitespace (so wrapped tool output still matches), and looks for fixed substrings.

1. A *veto* checked first: HTTP 401/403/404/407, proxy login and certificate text mean the
   machine reached a server and something else is wrong, so the answer is "no".
   A test runner's failed-assertion or failed-test report is a veto too: the lookup text there is
   what the test compared, not a download.
2. A *named* lookup failure ("could not resolve host: X", "dial tcp: lookup X", ...) counts only
   when X is a well-known public package registry or toolchain host and a package tool's own
   download wording sits near it. A test that looks up
   ``db``, ``postgres``, ``localhost`` or a ``*.local`` name never counts.
3. An *unnamed* lookup failure ("temporary failure in name resolution", ...) counts only when a
   package tool's own download wording sits just before or after it, together with a registry
   URL (or pip's ``/simple/`` index path), and no local host name appears there.

Refused connections and time-outs never count on their own: urllib3 and Go print the same words
for a local test server that is not running. Nothing here touches the network.
"""

from __future__ import annotations

from typing import Iterator

NETWORK_REQUIRED_REASON = "network-required"

# Characters scanned from each end of the output; the middle of huge output is skipped.
SCAN_CAP = 64 * 1024
# Around each unnamed lookup failure: how far back and forward to look for the tool's wording.
_BEFORE = 2048
_AFTER = 512
# Occurrences of each marker examined, so adversarial output costs a fixed amount.
_MAX_HITS = 32
_MAX_HOST = 253

# The server, proxy or certificate said no: never "offline".
_VETO = (
    "401 unauthorized", "401 (unauthorized)", "(401)",
    "403 forbidden", "403 (forbidden)", "(403)",
    "404 not found", "404 (not found)", "(404)",
    "407 proxy", "(407)", "proxy authorization required", "proxy authentication required",
    "certificate", "self-signed", "self signed", "ssl connection could not be established",
)

# A test runner reporting a failed assertion or test: the error text is what a test compared,
# not a download that failed, so the answer is "no".
_TEST_VETO = (
    "assertionerror", "failed (failures=", "failed (errors=", "--- fail: ",
    "test result: failed", "assertion failed", "assertion `left == right` failed",
)

# Lookup failures that name the host right after the marker (curl/git/cargo, go, npm, nuget, urllib3 2).
_NAMED = (
    "could not resolve host: ",
    "dial tcp: lookup ",
    "getaddrinfo eai_again ",
    "getaddrinfo enotfound ",
    "resource temporarily unavailable (",
    "failed to resolve '",
)

# Lookup failures without a host name (uv/pnpm, pip, glibc, macOS, Windows).
_UNNAMED = (
    "temporary failure in name resolution",
    "failed to lookup address information",
    "name or service not known",
    "nodename nor servname provided",
    "no address associated with hostname",
    "no such host is known",
)

# Wording that a package tool's own download prints.
_TOOL_CONTEXT = (
    "failed to fetch",  # uv, pnpm
    "failed to download",  # uv
    "error sending request",  # uv, pnpm
    "pip._vendor.urllib3",  # pip
    "spurious network error",  # cargo
    "unable to access '",  # git
    "each download failed",  # cmake FetchContent
    "unable to load the service index",  # nuget
    "/@v/",  # go module proxy
)

# A named registry host counts only near download wording: the tool context above, or npm/curl's own.
_NAMED_CONTEXT = _TOOL_CONTEXT + (
    "npm error request to ", "npm err! request to ",  # npm
    "curl: (6) ",  # curl
)

# Well-known public package registries and toolchain downloads (host or parent domain).
_REGISTRY_HOSTS = (
    "pypi.org", "pythonhosted.org", "python.org", "astral.sh",
    "npmjs.org", "npmjs.com", "yarnpkg.com", "nodejs.org",
    "crates.io", "rust-lang.org",
    "golang.org", "go.dev", "googlesource.com",
    "nuget.org",
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
)

_LOCAL_SUFFIXES = (".local", ".internal", ".localdomain", ".lan", ".home.arpa", ".localhost", ".test")
_HOST_END = frozenset(" \t\n'\"`()[]{}<>,;:/\\@?#")


def _window(text: str) -> str:
    if len(text) > 2 * SCAN_CAP:
        text = text[:SCAN_CAP] + "\n" + text[-SCAN_CAP:]
    # Box-drawing bars from wrapped tool output become spaces, then every whitespace run is one space.
    return " ".join(text.lower().replace("\u2502", " ").split())


def _hits(hay: str, marker: str) -> Iterator[int]:
    start = 0
    for _ in range(_MAX_HITS):
        pos = hay.find(marker, start)
        if pos < 0:
            return
        yield pos
        start = pos + len(marker)


def _host_at(hay: str, pos: int) -> str:
    end, limit = pos, min(len(hay), pos + _MAX_HOST)
    while end < limit and hay[end] not in _HOST_END:
        end += 1
    return hay[pos:end].rstrip(".")


def _is_registry(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in _REGISTRY_HOSTS)


def _is_local(host: str) -> bool:
    return "." not in host or host == "localhost" or any(host.endswith(s) for s in _LOCAL_SUFFIXES)


def _hosts_in(part: str) -> Iterator[str]:
    for marker in ("://", "host='"):
        for pos in _hits(part, marker):
            host = _host_at(part, pos + len(marker))
            if host:  # file:/// URLs have no host
                yield host


def _unnamed_counts(hay: str, pos: int) -> bool:
    part = hay[max(0, pos - _BEFORE):pos + _AFTER]
    if not any(c in part for c in _TOOL_CONTEXT):
        return False
    hosts = list(_hosts_in(part))
    if any(_is_local(h) for h in hosts):
        return False
    if any(_is_registry(h) for h in hosts):
        return True
    return "pip._vendor.urllib3" in part and "': /simple/" in part


def looks_like_network_failure(output: str) -> bool:
    """True only when the output shows a package tool failing to look up a public registry."""
    if not isinstance(output, str) or not output:
        return False
    hay = _window(output)
    if any(v in hay for v in _VETO) or any(v in hay for v in _TEST_VETO):
        return False
    for marker in _NAMED:
        for pos in _hits(hay, marker):
            if not _is_registry(_host_at(hay, pos + len(marker))):
                continue
            part = hay[max(0, pos - _BEFORE):pos + _AFTER]
            if any(c in part for c in _NAMED_CONTEXT):
                return True
    return any(_unnamed_counts(hay, pos) for marker in _UNNAMED for pos in _hits(hay, marker))


def network_required_note(*, projects_untouched: bool) -> str:
    """One sentence, plus the true-only 'Nothing was added…' when the projects folder is untouched."""
    note = (
        "This project needs an internet connection to be created because its check could not "
        "download what it needs, so connect to the internet and try again."
    )
    if projects_untouched:
        note += " Nothing was added to your projects folder."
    return note


def with_network_note(message: str, output: str, *, projects_untouched: bool = True) -> str:
    """Append the internet line to ``message`` when ``output`` shows a network failure."""
    if not looks_like_network_failure(output):
        return message
    return f"{message}\n{network_required_note(projects_untouched=projects_untouched)}"
