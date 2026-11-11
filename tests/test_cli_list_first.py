"""`hermes defuzz list` and `hermes defuzz new` create a project only from an explicit choice."""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

from tests.conftest import ensure_test_package
from tests.fake_kit_bridge import FakeKitBridge, load_list_fixture
from tests.toolchain_needs import fake_rust_toolchain  # noqa: F401

ensure_test_package()

import hermes_plugins.defuzz as plugin  # noqa: E402
from hermes_plugins.defuzz import catalog_list, cli, componentize_bridge, placer  # noqa: E402

TEMPLATES_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "templates"
REPO_ROOT = Path(__file__).resolve().parent.parent
NOTHING = "Nothing was created. Run again with --template ID or --kit ID."
ASK = "Type a number or an ID (Enter to cancel): "
FIXTURE_KIT_IDS = [k["id"] for k in load_list_fixture()["kits"]]
VIDEO_PROMPT = "set up a video production project called Night Shoot"
RUST_ANSWERS = json.dumps({"building": "game", "layout": "mono", "languages": ["rust"], "engine": "bevy"})


@pytest.fixture(autouse=True)
def _reset_placer_notices() -> None:
    placer._reset_notice_state_for_tests()


@pytest.fixture()
def projects(tmp_path: Path) -> Path:
    root = tmp_path / "projects"
    root.mkdir()
    (root / "keep.txt").write_text("already here\n", encoding="utf-8")
    return root


def _register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "list-first-1", "name": name, "path": path})


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            digest.update(f"L {rel}\n".encode())
        elif path.is_dir():
            digest.update(f"D {rel}\n".encode())
        else:
            digest.update(f"F {rel} ".encode() + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


class _NoReadStdin:
    """A stdin that fails the test if anything reads it."""

    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def fileno(self) -> int:
        raise OSError("no fileno")

    def _fail(self, *args: Any, **kwargs: Any) -> str:
        raise AssertionError("stdin must not be read here")

    read = readline = readlines = _fail

    def __iter__(self):
        self._fail()


class _TtyIn(io.StringIO):
    def isatty(self) -> bool:
        return True


class _TtyOut(io.StringIO):
    def isatty(self) -> bool:
        return True


def _no_tty(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("the controlling terminal must not be opened here")


def _guard_stdin(monkeypatch: pytest.MonkeyPatch, *, tty: bool) -> None:
    monkeypatch.setattr(sys, "stdin", _NoReadStdin(tty))
    monkeypatch.setattr(cli, "_open_controlling_tty", _no_tty)


def _rows(text: str) -> List[str]:
    """Numbered list rows, each joined to one line, whatever the wrapping."""
    flat = " ".join(text.split())
    parts = re.split(r"(?:^| )\d+\. ", flat)
    return parts[1:]


def _row_for(text: str, flag: str) -> str:
    hits = [r for r in _rows(text) if f"[{flag}]" in r]
    assert len(hits) == 1, (flag, text)
    return hits[0]


def _assert_every_flag_once(text: str, entries: List[Dict[str, Any]]) -> None:
    for entry in entries:
        assert text.count(f"[{entry['flag']}]") == (0 if entry.get("coming_soon") else 1), (entry["flag"], text)
        if entry.get("coming_soon"):
            assert entry["title"] + "  [coming soon]" in text


def _entries(templates_root: Path = TEMPLATES_FIXTURES, kits: bool = True) -> List[Dict[str, Any]]:
    from hermes_plugins.defuzz.matcher import parse_kit_list
    from hermes_plugins.defuzz.templates import load_templates_lenient

    specs, _ = load_templates_lenient(templates_root)
    infos = parse_kit_list({"status": "ok", "data": load_list_fixture()})[0] if kits else []
    return catalog_list.build_catalog(specs, infos)


def _new(*args: str) -> List[str]:
    return ["new", "--templates-root", str(TEMPLATES_FIXTURES), *args]


# --------------------------------------------------------------------------- list


def test_list_prints_every_template_and_kit(monkeypatch, capsys) -> None:
    _guard_stdin(monkeypatch, tty=False)
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    rc = cli.main(["list", "--templates-root", str(TEMPLATES_FIXTURES)])
    out = capsys.readouterr()
    assert rc == 0
    entries = _entries()
    assert {e["id"] for e in entries} >= {"fake-rust-game", "fake-py-service", *FIXTURE_KIT_IDS}
    _assert_every_flag_once(out.out, entries)
    assert "(suggested)" not in out.out
    assert len(_rows(out.out)) == len(entries)
    assert bridge.list_calls == [{"timeout": cli.KITS_LIST_TIMEOUT_S}]
    assert 0 < cli.KITS_LIST_TIMEOUT_S <= 30


def test_list_json_is_catalog_to_json(monkeypatch, capsys) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    rc = cli.main(["list", "--json", "--templates-root", str(TEMPLATES_FIXTURES)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload == catalog_list.to_json(_entries())
    assert payload["suggested"] == [] and payload["notice"] == ""


def test_list_kits_unavailable_shows_templates_and_one_notice(monkeypatch, capsys) -> None:
    _guard_stdin(monkeypatch, tty=False)
    # The hermetic guard leaves the real bridge with no companion: kits are unavailable.
    rc = cli.main(["list", "--templates-root", str(TEMPLATES_FIXTURES)])
    out = capsys.readouterr().out
    assert rc == 0
    entries = _entries(kits=False)
    _assert_every_flag_once(out, entries)
    assert "--kit" not in out
    notice_lines = [ln for ln in out.splitlines() if "defuzz-componentize" in ln]
    assert len(notice_lines) == 1
    assert notice_lines[0] == catalog_list.kits_notice_line("unavailable", "")
    assert "hermes plugins install" not in notice_lines[0]

    rc_json = cli.main(["list", "--json", "--templates-root", str(TEMPLATES_FIXTURES)])
    payload = json.loads(capsys.readouterr().out)
    assert rc_json == 0
    assert [e["kind"] for e in payload["entries"]] == ["template"] * len(entries)
    assert "defuzz-componentize" in payload["notice"]


@pytest.mark.parametrize(
    ("bridge_kwargs", "word"),
    [
        ({"list_status": "error", "list_notice": "Project kits check timed out: componentize kit list timed out."}, "did not answer in time"),
        ({"list_status": "error", "list_notice": "componentize kit list returned invalid JSON."}, "unavailable right now"),
    ],
)
def test_list_kit_errors_give_one_short_notice(monkeypatch, capsys, bridge_kwargs, word) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge(**bridge_kwargs).install(monkeypatch, componentize_bridge)
    rc = cli.main(["list", "--json", "--templates-root", str(TEMPLATES_FIXTURES)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert word in payload["notice"]
    assert "hermes defuzz kits" in payload["notice"]
    assert len(payload["notice"]) <= 100


def test_list_survives_a_kit_bridge_that_raises(monkeypatch, capsys) -> None:
    _guard_stdin(monkeypatch, tty=False)

    def boom(**_kw: Any) -> Dict[str, Any]:
        raise ImportError("settings module missing")

    monkeypatch.setattr(componentize_bridge, "kit_list", boom)
    rc = cli.main(["list", "--templates-root", str(TEMPLATES_FIXTURES)])
    out = capsys.readouterr().out
    assert rc == 0
    _assert_every_flag_once(out, _entries(kits=False))
    assert "hermes defuzz kits" in out


# ------------------------------------------------------------- new without an id


_NO_ID_ARGS = [
    [],
    ["--name", "Some Game", "--answers", RUST_ANSWERS],
    ["--name", "Some Game", "--answers", RUST_ANSWERS, "--yes"],
    ["--prompt", VIDEO_PROMPT],
    ["--prompt", VIDEO_PROMPT, "--yes"],
    ["--prompt", "a rust game called Moon Lander", "--yes"],
]


# On a terminal only --yes rules out the question; without --yes it is covered below.
@pytest.mark.parametrize(
    ("extra", "tty"),
    [(a, False) for a in _NO_ID_ARGS] + [(a, True) for a in _NO_ID_ARGS if "--yes" in a],
)
def test_new_without_id_prints_list_and_creates_nothing(monkeypatch, capsys, projects, extra, tty) -> None:
    _guard_stdin(monkeypatch, tty=tty)
    if tty:
        monkeypatch.setattr(sys, "stdout", _TtyOut())
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    monkeypatch.setattr(cli, "REGISTER_PROJECT", _register)
    before = _tree_hash(projects)

    rc = cli.main(_new("--dest-root", str(projects), *extra))

    out = sys.stdout.getvalue() if tty else capsys.readouterr().out  # type: ignore[attr-defined]
    assert rc == 2
    assert out.rstrip("\n").splitlines()[-1] == NOTHING
    assert out.count(NOTHING) == 1
    assert ASK not in out
    _assert_every_flag_once(out, _entries())
    assert _tree_hash(projects) == before
    assert bridge.apply_calls == []


def test_new_without_id_marks_suggestions_from_prompt(monkeypatch, capsys, projects) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    rc = cli.main(_new("--dest-root", str(projects), "--prompt", VIDEO_PROMPT))
    out = capsys.readouterr().out
    assert rc == 2
    assert "(suggested)" in _row_for(out, "--kit video-production")
    marked = [r for r in _rows(out) if "(suggested)" in r]
    assert 1 <= len(marked) <= 3


def test_new_without_prompt_suggests_nothing(monkeypatch, capsys, projects) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    rc = cli.main(_new("--dest-root", str(projects), "--name", "X", "--answers", RUST_ANSWERS))
    out = capsys.readouterr().out
    assert rc == 2
    assert "(suggested)" not in out


def test_new_suggestion_errors_never_fail_the_list(monkeypatch, capsys, projects) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)

    def boom(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("matcher broke")

    monkeypatch.setattr(cli.matcher, "match_kits", boom)
    rc = cli.main(_new("--dest-root", str(projects), "--prompt", VIDEO_PROMPT))
    out = capsys.readouterr().out
    assert rc == 2
    assert "(suggested)" not in out
    assert out.rstrip("\n").splitlines()[-1] == NOTHING


def test_new_without_id_kits_unavailable_lists_templates_and_notice(monkeypatch, capsys, projects) -> None:
    _guard_stdin(monkeypatch, tty=False)
    before = _tree_hash(projects)
    rc = cli.main(_new("--dest-root", str(projects), "--prompt", VIDEO_PROMPT, "--yes"))
    out = capsys.readouterr()
    assert rc == 2
    _assert_every_flag_once(out.out, _entries(kits=False))
    assert "--kit" not in out.out.replace(NOTHING, "")
    assert sum("defuzz-componentize" in ln for ln in out.out.splitlines()) == 1
    assert out.out.rstrip("\n").splitlines()[-1] == NOTHING
    assert "hand-off" not in out.out + out.err
    assert _tree_hash(projects) == before


def test_new_without_id_needs_no_projects_folder(monkeypatch, capsys) -> None:
    """Nothing is created, so a missing projects folder is never asked for or reported."""
    _guard_stdin(monkeypatch, tty=False)
    monkeypatch.delenv("HERMES_PROJECTS_ROOT", raising=False)
    rc = cli.main(_new("--name", "Some Game", "--yes"))
    out = capsys.readouterr()
    assert rc == 2
    assert out.out.rstrip("\n").splitlines()[-1] == NOTHING
    assert "projects folder" not in out.err.lower()


# ------------------------------------------------------------ interactive choice


def _interactive(monkeypatch: pytest.MonkeyPatch, answer: str) -> _TtyOut:
    monkeypatch.setattr(sys, "stdin", _TtyIn(answer))
    monkeypatch.setattr(cli, "_open_controlling_tty", _no_tty)
    out = _TtyOut()
    monkeypatch.setattr(sys, "stdout", out)
    return out


@pytest.mark.parametrize("answer", ["", "\n", "   \n", "zzz-nope\n", "999\n"])
def test_interactive_empty_or_invalid_answer_creates_nothing(monkeypatch, projects, answer) -> None:
    out = _interactive(monkeypatch, answer)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    before = _tree_hash(projects)
    rc = cli.main(_new("--dest-root", str(projects), "--name", "Picked", "--answers", RUST_ANSWERS))
    text = out.getvalue()
    assert rc == 2
    assert ASK in text
    # A fake terminal does not echo the typed newline, so the sentence may follow the question.
    assert text.rstrip("\n").splitlines()[-1].endswith(NOTHING)
    assert text.count(NOTHING) == 1
    assert _tree_hash(projects) == before


@pytest.mark.parametrize("pick", ["fake-rust-game", "template:fake-rust-game", "number"])
def test_interactive_template_pick_continues_as_if_flag_given(monkeypatch, projects, pick) -> None:
    entries = _entries()
    if pick == "number":
        pick = str(next(i for i, e in enumerate(entries, 1) if e["id"] == "fake-rust-game"))
    out = _interactive(monkeypatch, pick + "\n")
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    rc = cli.main(_new("--dest-root", str(projects), "--name", "Picked Game", "--prompt", VIDEO_PROMPT))
    text = out.getvalue()
    assert rc == 0, text
    assert ASK in text
    assert f"Proposed repository: picked-game -> {projects / 'picked-game'}" in text
    assert "Cargo.toml" in text
    assert "Re-run with --yes to create." in text
    assert NOTHING not in text
    assert not (projects / "picked-game").exists()


def test_interactive_kit_pick_continues_as_if_flag_given(monkeypatch, projects) -> None:
    out = _interactive(monkeypatch, "kit:video-production\n")
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    rc = cli.main(_new("--dest-root", str(projects), "--prompt", "a rust game called Night Shoot"))
    text = out.getvalue()
    assert rc == 0, text
    assert "Proposed kit: video-production" in text
    assert "Re-run with --yes to create." in text
    assert len(bridge.apply_calls) == 1
    assert not (projects / "night-shoot").exists()


# ------------------------------------------------------------- explicit ids win


@pytest.mark.usefixtures("fake_rust_toolchain")
def test_explicit_template_wins_over_prompt(monkeypatch, capsys, projects) -> None:
    _guard_stdin(monkeypatch, tty=False)
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    monkeypatch.setattr(cli, "REGISTER_PROJECT", _register)
    rc = cli.main(
        _new("--template", "fake-rust-game", "--prompt", VIDEO_PROMPT, "--answers", RUST_ANSWERS,
             "--dest-root", str(projects), "--yes")
    )
    out = capsys.readouterr()
    assert rc == 0, out.err
    target = projects / "night-shoot"
    assert (target / "Cargo.toml").is_file()
    assert not (target / "assets" / "generated").exists()
    assert bridge.apply_calls == []


def test_explicit_kit_wins_over_prompt(monkeypatch, capsys, projects) -> None:
    _guard_stdin(monkeypatch, tty=False)
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    monkeypatch.setattr(cli, "REGISTER_PROJECT", _register)
    rc = cli.main(
        _new("--kit", "video-production", "--prompt", "a rust game called Moon Lander",
             "--dest-root", str(projects), "--yes")
    )
    out = capsys.readouterr()
    assert rc == 0, out.err
    target = projects / "moon-lander"
    assert (target / "assets" / "generated").is_dir()
    assert not (target / "Cargo.toml").exists()
    assert [c["kit_id"] for c in bridge.apply_calls] == ["video-production"]


# -------------------------------------------------------------- unknown / wrong id


def _refused(capsys: Any, rc: int) -> str:
    out = capsys.readouterr()
    assert rc == 2
    lines = [ln for ln in out.err.splitlines() if ln.strip()]
    assert len(lines) == 1, out.err
    assert NOTHING not in out.out
    return lines[0]


@pytest.mark.parametrize("flag", ["--template", "--kit"])
def test_unknown_id_is_one_line_naming_the_id(monkeypatch, capsys, projects, flag) -> None:
    _guard_stdin(monkeypatch, tty=False)
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    before = _tree_hash(projects)
    rc = cli.main(_new(flag, "no-such-thing", "--name", "X", "--dest-root", str(projects), "--yes"))
    line = _refused(capsys, rc)
    assert "'no-such-thing'" in line
    assert "hermes defuzz list" in line
    assert _tree_hash(projects) == before
    assert bridge.apply_calls == []


def test_unknown_id_with_control_characters_is_escaped(monkeypatch, capsys, projects) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    rc = cli.main(_new("--template", "bad\x1b[31mid\nnext", "--name", "X", "--dest-root", str(projects)))
    line = _refused(capsys, rc)
    assert "\x1b" not in line
    assert "\\x1b" in line and "\\x0a" in line
    assert "hermes defuzz list" in line


def test_kit_id_given_to_template_says_use_kit(monkeypatch, capsys, projects) -> None:
    _guard_stdin(monkeypatch, tty=False)
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    before = _tree_hash(projects)
    rc = cli.main(_new("--template", "video-production", "--name", "X", "--dest-root", str(projects), "--yes"))
    line = _refused(capsys, rc)
    assert "--kit video-production" in line
    assert _tree_hash(projects) == before
    assert bridge.apply_calls == []


@pytest.mark.parametrize("kits_available", [True, False])
def test_template_id_given_to_kit_says_use_template(monkeypatch, capsys, projects, kits_available) -> None:
    _guard_stdin(monkeypatch, tty=False)
    if kits_available:
        FakeKitBridge().install(monkeypatch, componentize_bridge)
    before = _tree_hash(projects)
    rc = cli.main(_new("--kit", "fake-rust-game", "--name", "X", "--dest-root", str(projects), "--yes"))
    line = _refused(capsys, rc)
    assert "--template fake-rust-game" in line
    assert _tree_hash(projects) == before


# ------------------------------------------------------------------ slash command


def _slash(args: str) -> str:
    return plugin._handle_slash_command(None, args)


def test_slash_list_matches_cli_list(monkeypatch, capsys) -> None:
    _guard_stdin(monkeypatch, tty=True)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    reply = _slash(f"list --templates-root {TEMPLATES_FIXTURES}")
    assert reply.endswith("List exit code: 0")
    _assert_every_flag_once(reply, _entries())


@pytest.mark.parametrize("yes", ["", " --yes"])
def test_slash_new_without_id_never_prompts_and_creates_nothing(monkeypatch, projects, yes) -> None:
    _guard_stdin(monkeypatch, tty=True)
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    before = _tree_hash(projects)
    reply = _slash(
        f"new --templates-root {TEMPLATES_FIXTURES} --dest-root {projects} --prompt '{VIDEO_PROMPT}'{yes}"
    )
    assert reply.endswith("New exit code: 2")
    assert NOTHING in reply
    assert ASK not in reply
    assert "(suggested)" in _row_for(reply, "--kit video-production")
    assert _tree_hash(projects) == before
    assert bridge.apply_calls == []


def test_slash_usage_names_list_and_explicit_ids() -> None:
    usage = _slash("")
    assert "/defuzz list" in usage
    assert "--template" in usage and "--kit" in usage


def test_new_help_tells_a_model_to_list_first(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main(["new", "--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "hermes defuzz list" in help_text


# ---------------------------------------------------------------- source checks


def test_nothing_created_sentence_lives_in_one_place() -> None:
    hits = []
    for path in sorted(REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT)
        if rel.parts[0] in ("tests", ".git") or ".worktrees" in rel.parts:
            continue
        count = path.read_text(encoding="utf-8").count("Nothing was created. Run again with")
        hits.extend([str(rel)] * count)
    assert hits == ["cli.py"]


def test_cli_never_takes_the_top_match() -> None:
    source = (REPO_ROOT / "cli.py").read_text(encoding="utf-8")
    assert "matches[0]" not in source
    assert "choose=" not in source


def test_new_and_list_help_use_list_first_wording(capsys) -> None:
    for argv, wanted in (
        (["--help"], [
            "Create a project from a template or kit ID chosen from `list`",
            "Show every project type you can start: templates and kits",
        ]),
        (["new", "--help"], [
            "Template ID from `hermes defuzz list` (or --kit)",
            "Kit ID from `hermes defuzz list` (or --template)",
            "Project idea: gives the name and marks suggested rows only",
            "Create the chosen project; never picks a type for you",
        ]),
        (["list", "--help"], ["Print the list as JSON"]),
    ):
        with pytest.raises(SystemExit):
            cli.main(argv)
        out = " ".join(capsys.readouterr().out.split())
        for text in wanted:
            assert text in out, (argv, text)


def test_slash_usage_is_list_first() -> None:
    usage = plugin._handle_slash_command(None, "")
    assert usage.split("In chat: ", 1)[1].startswith(
        "Usage: /defuzz list | /defuzz new --template ID|--kit ID --name NAME | "
        "/defuzz scan|run <copy_dir> [--source <src_dir>] | /defuzz report <copy_dir> | "
        "/defuzz lint <project> [--mode pre|post|both]"
    )


# ------------------------------------------------------------- list --prompt

BOTH_LINE = "Give either --template ID or --kit ID, not both."
_SUGGESTED = re.compile(r" ?\(suggested\)")


def _list(*args: str) -> List[str]:
    return ["list", "--templates-root", str(TEMPLATES_FIXTURES), *args]


def test_list_prompt_only_marks_suggested_rows(monkeypatch, capsys, projects) -> None:
    _guard_stdin(monkeypatch, tty=False)
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(projects))
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    before = _tree_hash(projects)
    assert cli.main(_list()) == 0
    plain = capsys.readouterr().out
    assert cli.main(_list("--prompt", VIDEO_PROMPT)) == 0
    marked = capsys.readouterr().out
    assert "(suggested)" in _row_for(marked, "--kit video-production")
    assert 1 <= len([r for r in _rows(marked) if "(suggested)" in r]) <= 3
    # A marker may re-wrap its row, so compare the words, not the line breaks.
    assert " ".join(_SUGGESTED.sub("", marked).split()) == " ".join(plain.split())
    assert _tree_hash(projects) == before
    assert bridge.apply_calls == []


def test_list_prompt_json_fills_suggested(monkeypatch, capsys) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    assert cli.main(_list("--json", "--prompt", VIDEO_PROMPT)) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "kit:video-production" in payload["suggested"] and len(payload["suggested"]) <= 3
    assert payload["entries"] == catalog_list.to_json(_entries())["entries"]


@pytest.mark.parametrize("prompt", ["", "   \t "])
def test_list_blank_prompt_is_no_prompt(monkeypatch, capsys, prompt) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    assert cli.main(_list()) == 0
    plain = capsys.readouterr().out
    assert cli.main(_list("--prompt", prompt)) == 0
    assert capsys.readouterr().out == plain


def test_list_prompt_errors_mean_no_suggestions(monkeypatch, capsys) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)

    def boom(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("matcher broke")

    monkeypatch.setattr(cli.matcher, "match_kits", boom)
    assert cli.main(_list("--prompt", VIDEO_PROMPT)) == 0
    assert "(suggested)" not in capsys.readouterr().out


def test_list_huge_prompt_is_fast(monkeypatch, capsys) -> None:
    import time

    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    start = time.monotonic()
    rc = cli.main(_list("--prompt", "video " * ((1 << 20) // 6) + "x" * 10))
    elapsed = time.monotonic() - start
    out = capsys.readouterr()
    assert rc == 0 and "Traceback" not in out.err
    assert elapsed < 5, elapsed


def test_slash_list_prompt(monkeypatch) -> None:
    _guard_stdin(monkeypatch, tty=True)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    reply = _slash(f"list --templates-root {TEMPLATES_FIXTURES} --prompt '{VIDEO_PROMPT}'")
    assert reply.endswith("List exit code: 0")
    assert "(suggested)" in _row_for(reply, "--kit video-production")


def test_list_help_names_prompt(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main(["list", "--help"])
    assert "Optional idea: marks suggested rows only" in " ".join(capsys.readouterr().out.split())


# --------------------------------------------------------- new: both flags


@pytest.mark.parametrize("order", ["tk", "kt"])
@pytest.mark.parametrize("yes", [[], ["--yes"]])
def test_new_both_flags_one_line(monkeypatch, capsys, projects, order, yes) -> None:
    _guard_stdin(monkeypatch, tty=False)
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    monkeypatch.setattr(cli, "load_templates_lenient", _no_tty)
    monkeypatch.setattr(cli, "_load_kits", _no_tty)
    pair = [["--template", "fake-rust-game"], ["--kit", "video-production"]]
    flags = pair[0] + pair[1] if order == "tk" else pair[1] + pair[0]
    before = _tree_hash(projects)
    rc = cli.main(_new(*flags, "--name", "X", "--dest-root", str(projects), *yes))
    out = capsys.readouterr()
    assert rc == 2
    assert out.err == BOTH_LINE + "\n"
    assert out.out == ""
    assert _tree_hash(projects) == before
    assert bridge.apply_calls == []


def test_new_both_flags_before_projects_folder(monkeypatch, capsys) -> None:
    _guard_stdin(monkeypatch, tty=False)
    monkeypatch.delenv("HERMES_PROJECTS_ROOT", raising=False)
    rc = cli.main(_new("--kit", "a", "--template", "b", "--name", "X", "--yes"))
    out = capsys.readouterr()
    assert rc == 2 and out.err == BOTH_LINE + "\n"


def test_slash_new_both_flags(monkeypatch, projects) -> None:
    _guard_stdin(monkeypatch, tty=True)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    before = _tree_hash(projects)
    reply = _slash(f"new --templates-root {TEMPLATES_FIXTURES} --dest-root {projects} "
                   "--kit video-production --template fake-rust-game --name X --yes")
    assert reply == f"```\n{BOTH_LINE}\n```\n{APP_LINE}\nNew exit code: 2"
    assert _tree_hash(projects) == before


def test_new_help_still_shows_both_flags(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main(["new", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    assert "Template ID from `hermes defuzz list` (or --kit)" in text
    assert "Kit ID from `hermes defuzz list` (or --template)" in text


# ------------------------------------------- prose that is not a project request


@pytest.mark.parametrize("cmd", ["list", "new"])
def test_not_a_project_request_marks_no_row(monkeypatch, capsys, projects, cmd) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    extra = ["--dest-root", str(projects)] if cmd == "new" else []
    rc = cli.main([cmd, "--prompt", "blog post about godot", *extra])
    out = capsys.readouterr().out
    assert rc == (2 if cmd == "new" else 0)
    assert "(suggested)" not in out


@pytest.mark.parametrize("cmd", ["list", "new"])
def test_website_idea_still_suggests_web_golden_first(monkeypatch, capsys, projects, cmd) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    extra = ["--dest-root", str(projects)] if cmd == "new" else []
    cli.main([cmd, "--prompt", "make me a website", *extra])
    marked = [r for r in _rows(capsys.readouterr().out) if "(suggested)" in r]
    assert marked and "[--template web-golden]" in marked[0]


# ------------------------------------------------------------- app pointer

APP_LINE = "Open the plugin page to create a project."


def _assert_app_line(reply: str) -> None:
    lines = reply.splitlines()
    assert lines.count(APP_LINE) == 1, reply
    assert lines.index(APP_LINE) == len(lines) - 2 and "exit code:" in lines[-1]


def test_slash_list_and_new_point_to_the_app(monkeypatch, projects, capsys) -> None:
    _guard_stdin(monkeypatch, tty=True)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    root = f"--templates-root {TEMPLATES_FIXTURES}"
    tid = next(e["flag"] for e in _entries() if e["kind"] == "template")
    for args in (f"list {root}", f"new {root} --dest-root {projects}",
                 f"new {root} --dest-root {projects} --template no-such-id --name X",
                 f"new {root} --dest-root {projects} {tid} --name X"):
        _assert_app_line(_slash(args))
        capsys.readouterr()
        cli.main(args.split())
        out = capsys.readouterr()
        assert APP_LINE not in out.out + out.err


def test_other_slash_subcommands_have_no_app_line(tmp_path, monkeypatch) -> None:
    # `scan` writes ./inventory.json by default: run from tmp_path so nothing lands in the repo.
    copy = tmp_path / "copy"
    copy.mkdir()
    monkeypatch.chdir(tmp_path)
    for args in (f"scan {copy}", f"report {copy}", f"lint {copy}"):
        assert APP_LINE not in _slash(args)
    assert (tmp_path / "inventory.json").is_file()
    assert not (REPO_ROOT / "inventory.json").exists()


def test_usage_starts_with_app_line() -> None:
    assert _slash("").startswith(f"{APP_LINE} In chat: Usage:")

_SECRET = "ZZBADKITTEXT"


def _bad_kits(n: int) -> list:
    """Entries the bridge accepts but the parser skips (empty name / empty tag)."""
    out = []
    for i in range(n):
        if i % 2:
            out.append({"id": f"bad-{i}", "name": "", "summary": _SECRET, "tags": [], "version": 1})
        else:
            out.append({"id": f"bad-{i}", "name": _SECRET, "summary": _SECRET, "tags": [""], "version": 1})
    return out


_SKIP_LINES = {
    0: "",
    1: "1 kit was skipped because its description is not valid. Run `hermes defuzz kits`.",
    3: "3 kits were skipped because their descriptions are not valid. Run `hermes defuzz kits`.",
}


@pytest.mark.parametrize("n", [0, 1, 3])
def test_list_and_new_say_how_many_kits_were_skipped(monkeypatch, capsys, n) -> None:
    _guard_stdin(monkeypatch, tty=False)
    bridge = FakeKitBridge()
    bridge._list_data["kits"] = list(bridge._list_data["kits"]) + _bad_kits(n)
    bridge.install(monkeypatch, componentize_bridge)
    rc = cli.main(["list", "--json", "--templates-root", str(TEMPLATES_FIXTURES)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["notice"] == _SKIP_LINES[n]
    assert {e["id"] for e in payload["entries"]} >= set(FIXTURE_KIT_IDS)
    assert _SECRET not in json.dumps(payload)
    rc = cli.main(["list", "--templates-root", str(TEMPLATES_FIXTURES)])
    out = capsys.readouterr().out
    assert rc == 0 and _SECRET not in out
    if n:
        assert [ln for ln in out.splitlines() if "skipped" in ln] == [_SKIP_LINES[n]]
    cli.main(_new())
    out = capsys.readouterr().out
    assert _SECRET not in out
    if n:
        assert [ln for ln in out.splitlines() if "skipped" in ln] == [_SKIP_LINES[n]]
    else:
        assert "skipped" not in out


def test_list_all_kits_malformed_lists_templates(monkeypatch, capsys) -> None:
    _guard_stdin(monkeypatch, tty=False)
    bridge = FakeKitBridge()
    bridge._list_data["kits"] = _bad_kits(3)
    bridge.install(monkeypatch, componentize_bridge)
    rc = cli.main(["list", "--json", "--templates-root", str(TEMPLATES_FIXTURES)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["notice"] == _SKIP_LINES[3]
    kinds = [e["kind"] for e in payload["entries"]]
    assert kinds and set(kinds) == {"template"}


# ------------------------------------------------------- hostile chat text

import time as _time
import unicodedata as _ud

_USAGE_START = "Usage: /defuzz list | /defuzz new --template ID|--kit ID --name NAME"


def _raw_controls(text: str) -> List[str]:
    """Characters that must never reach a terminal or chat raw (a newline between lines is fine)."""
    return [c for c in text if c != "\n" and _ud.category(c) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")]


@pytest.mark.parametrize("args", [
    "new it's a site",
    "new --prompt \"it's a video",
    "new --prompt 'unterminated",
    "list \"",
    "list --prompt 'x",
    "new \\",
    "new --name x \\",
    "lint 'oops",
])
def test_slash_unmatched_quote_is_one_plain_line(monkeypatch, projects, args) -> None:
    _guard_stdin(monkeypatch, tty=True)
    bridge = FakeKitBridge().install(monkeypatch, componentize_bridge)
    before = _tree_hash(projects)
    reply = _slash(args)
    lines = reply.splitlines()
    assert "Traceback" not in reply and "ValueError" not in reply
    assert lines[0] == plugin.UNREADABLE_LINE
    assert "quote" in lines[0]
    assert lines[1].startswith(_USAGE_START)
    if args.split()[0] in ("new", "list"):
        assert lines == [plugin.UNREADABLE_LINE, lines[1], APP_LINE]
    else:
        assert len(lines) == 2
    assert _tree_hash(projects) == before and bridge.apply_calls == []


@pytest.mark.parametrize("args", [
    "list --prompt \"a\x00b\x1b[31mc\u202ed\x07\"",
    "list --bogus \x1b]8;;http://evil\x07CLICK\x1b]8;;\x07\x1b[2J\x1b[31mRED\u202e",
    "new --kit \x1b[2Jx --name y",
    "new \x00\x01\x02\x7f",
    "lint \x1b[31m --mode \u2066bad",
])
def test_slash_control_characters_never_reach_the_reply(monkeypatch, projects, args) -> None:
    _guard_stdin(monkeypatch, tty=True)
    monkeypatch.setenv("HERMES_PROJECTS_ROOT", str(projects))
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    reply = _slash(args)
    assert _raw_controls(reply) == [], [hex(ord(c)) for c in _raw_controls(reply)]
    assert "Traceback" not in reply
    assert re.search(r"exit code: -?\d+$", reply), reply[-200:]


def test_slash_argparse_echo_is_escaped_and_capped(monkeypatch) -> None:
    _guard_stdin(monkeypatch, tty=True)
    reply = _slash("list --bogus " + "\x1b[2J" * 1500)
    assert _raw_controls(reply) == []
    assert "\\x1b[2J" in reply
    assert len(reply) <= plugin.SLASH_REPLY_MAX + 100
    assert reply.endswith("List exit code: 2")


@pytest.mark.parametrize("args", [
    "new --prompt '" + "video " * 175000 + "'",
    "list --prompt " + "video " * 175000,
    "new it's " + "a" * (1 << 20),
    "scan " + "x" * (1 << 20),
])
def test_slash_one_megabyte_of_chat_text_answers_fast(monkeypatch, projects, args) -> None:
    _guard_stdin(monkeypatch, tty=True)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    before = _tree_hash(projects)
    start = _time.monotonic()
    reply = _slash(args)
    elapsed = _time.monotonic() - start
    assert elapsed < 0.5, elapsed
    lines = reply.splitlines()
    assert lines[0] == plugin.TOO_LONG_LINE
    assert lines[1].startswith(_USAGE_START)
    if args.split()[0] in ("new", "list"):
        assert lines[-1] == APP_LINE and len(lines) == 3
    else:
        assert len(lines) == 2
    assert len(reply) < 2000
    assert _tree_hash(projects) == before


@pytest.mark.parametrize("cmd", ["new", "list"])
@pytest.mark.parametrize("idea", ["a" + " " * 16000 + "b", "a" + "\t" * 16000 + "b", "video " * 2700,
                                  "video " * 11000, "video " * 100000])
def test_every_entry_point_caps_a_long_idea_fast(monkeypatch, capsys, projects, cmd, idea) -> None:
    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    extra = ["--dest-root", str(projects)] if cmd == "new" else []
    start = _time.monotonic()
    rc = cli.main([cmd, "--templates-root", str(TEMPLATES_FIXTURES), "--prompt", idea, *extra])
    elapsed = _time.monotonic() - start
    out = capsys.readouterr()
    assert elapsed < 1.0, elapsed
    assert "Traceback" not in out.err
    assert rc == (1 if cmd == "new" else 0)
    start = _time.monotonic()
    reply = _slash(f"{cmd} --templates-root {TEMPLATES_FIXTURES} --prompt '{idea}'")
    assert _time.monotonic() - start < 1.0
    assert "Traceback" not in reply


def test_slash_json_reply_has_no_app_line(monkeypatch) -> None:
    _guard_stdin(monkeypatch, tty=True)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    for args, label in ((f"list --json --templates-root {TEMPLATES_FIXTURES}", "List"),
                        (f"list --templates-root {TEMPLATES_FIXTURES} --json --prompt 'a website'", "List")):
        reply = _slash(args)
        body, last = reply.rsplit("\n", 1)
        assert last == f"{label} exit code: 0"
        assert APP_LINE not in reply
        assert json.loads(body)["entries"]


# ------------------------------------------------------- hostile kit lists

_HOSTILE_IDS = ["--yes", "../../etc/passwd", "a b; rm -rf ~", "id\x1b[31mred", "id\u202ertl", "3"]


def _hostile_kit(kid: str) -> Dict[str, Any]:
    return {"id": kid, "name": "Hostile kit", "summary": "Looks fine.", "tags": ["x"], "version": 1}


def test_list_drops_unsafe_kit_ids_and_counts_them(monkeypatch, capsys) -> None:
    _guard_stdin(monkeypatch, tty=False)
    bridge = FakeKitBridge()
    bridge._list_data["kits"] = list(bridge._list_data["kits"]) + [_hostile_kit(i) for i in _HOSTILE_IDS]
    bridge.install(monkeypatch, componentize_bridge)
    assert cli.main(["list", "--json", "--templates-root", str(TEMPLATES_FIXTURES)]) == 0
    payload = json.loads(capsys.readouterr().out)
    ids = {e["id"] for e in payload["entries"]}
    assert ids >= set(FIXTURE_KIT_IDS)
    assert not ids & set(_HOSTILE_IDS)
    assert payload["notice"] == catalog_list.kits_notice_line("ok", "", len(_HOSTILE_IDS))
    assert cli.main(["list", "--templates-root", str(TEMPLATES_FIXTURES)]) == 0
    out = capsys.readouterr().out
    for bad in ("--kit --yes", "etc/passwd", "rm -rf", "Hostile kit", "rtl", "--kit 3"):
        assert bad not in out
    assert f"{len(_HOSTILE_IDS)} kits were skipped" in out


_NASTY = "A\x1b]8;;http://evil\x07CLICK\x1b]8;;\x07\x1b[2J\x1b[31mRED\u202eX\u2066\u2069\u200b\u2028\u2029\nNEXT"


def test_kits_table_escapes_companion_text(monkeypatch, capsys) -> None:
    bridge = FakeKitBridge()
    kits = [dict(k) for k in bridge._list_data["kits"][:2]]
    kits[0]["summary"] = _NASTY + " tail" * 200
    kits[1]["id"] = "id\x1b[31m\u202e\nx"
    bridge._list_data["kits"] = kits
    bridge.install(monkeypatch, componentize_bridge)
    assert cli.main(["kits"]) == 0
    out = capsys.readouterr().out
    assert _raw_controls(out) == []
    assert "\\x1b]8;;http://evil\\x07CLICK" in out and "\\u202e" in out and "\\nNEXT" in out
    lines = out.splitlines()
    assert len(lines) == 1 + len(kits)  # header, then one line per kit
    assert all(len(line) <= 300 + 100 for line in lines)


def test_kits_json_is_valid_and_ascii(monkeypatch, capsys) -> None:
    bridge = FakeKitBridge()
    bridge._list_data["kits"][0]["summary"] = _NASTY
    bridge.install(monkeypatch, componentize_bridge)
    assert cli.main(["kits", "--json"]) == 0
    out = capsys.readouterr().out
    assert out.isascii() and _raw_controls(out) == []
    assert json.loads(out)["kits"][0]["summary"] == _NASTY


@pytest.mark.parametrize("as_json", [False, True])
def test_kits_error_notice_is_escaped(monkeypatch, capsys, as_json) -> None:
    notice = "componentize kit list error (exit 2): " + _NASTY + " x" * 1000
    FakeKitBridge(list_status="error", list_notice=notice).install(monkeypatch, componentize_bridge)
    assert cli.main(["kits", *(["--json"] if as_json else [])]) == 0
    out = capsys.readouterr().out
    assert _raw_controls(out) == [] and out.isascii()
    if as_json:
        assert json.loads(out)["notice"] == notice
    else:
        assert out.count("\n") == 1 and len(out) <= 600 + 1


@pytest.mark.parametrize("exc", [RecursionError("maximum recursion depth exceeded"), RecursionError()])
def test_kits_survives_deeply_nested_reply(monkeypatch, capsys, exc) -> None:
    def deep(*_a: Any, **_kw: Any) -> Any:
        raise exc

    monkeypatch.setattr(componentize_bridge, "kit_list", deep)
    for argv in (["kits"], ["kits", "--json"]):
        rc = cli.main(argv)
        out = capsys.readouterr()
        assert rc == 0, out
        assert "recursion" not in (out.out + out.err).lower() and "Stack overflow" not in out.err
        text = out.out
        if "--json" in argv:
            text = json.loads(text)["notice"]
        assert text.strip() == cli.KITS_UNREADABLE_LINE


def test_kits_survives_deeply_nested_json_from_the_companion(monkeypatch, capsys) -> None:
    import subprocess

    deep = "[" * 200000 + "]" * 200000
    monkeypatch.setattr(componentize_bridge, "detect_command", lambda *a, **k: ("componentize", "path"))
    monkeypatch.setattr(componentize_bridge, "_run_cli", lambda *a, **k: subprocess.CompletedProcess(
        ["componentize"], 0, deep, ""))
    rc = cli.main(["kits"])
    out = capsys.readouterr()
    assert rc == 0 and "Stack overflow" not in out.err and "Traceback" not in out.err
    assert _raw_controls(out.out) == []


def test_new_kit_error_text_is_escaped(monkeypatch, capsys, projects) -> None:
    _guard_stdin(monkeypatch, tty=False)
    message = "componentize kit show error (exit 2): " + _NASTY + " y" * 1000
    FakeKitBridge(show_status="error", show_notice=message,
                  apply_status="error", apply_notice=message).install(monkeypatch, componentize_bridge)
    for yes in ([], ["--yes"]):
        rc = cli.main(_new("--kit", "video-production", "--name", "x", "--dest-root", str(projects), *yes))
        out = capsys.readouterr()
        assert rc != 0
        text = out.out + out.err
        assert _raw_controls(text) == [] and "\\x1b]8;;http://evil" in text
        assert all(len(line) <= 600 for line in text.splitlines())


def test_new_kit_passes_no_ignored_arguments(monkeypatch, projects) -> None:
    import inspect

    seen: Dict[str, Any] = {}

    def fake_flow(**kwargs: Any) -> Any:
        seen.update(kwargs)
        from hermes_plugins.defuzz.new_project import FlowResult
        return FlowResult(status="error", message="stop")

    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    monkeypatch.setattr(cli, "run_new_project_flow", fake_flow)
    cli.main(_new("--kit", "video-production", "--name", "x", "--dest-root", str(projects)))
    assert seen and not {"choose", "sender", "persist_answers"} & set(seen)
    from hermes_plugins.defuzz import new_project
    assert set(seen) <= set(inspect.signature(new_project.run_new_project_flow).parameters)


# ------------------------------------------------- chat markup, caps, cut idea

_MARKUP_NAME = "[Official update](https://evil.example) **bold** @everyone <@123> ``` x"


def _kits_reply(kits: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"status": "ok", "data": {"kits": kits, "schema": "componentize.kit/1"}, "notice": "", "exit": 0}


def _fenced_body(reply: str) -> str:
    """The text inside the one fenced block of a slash reply (fails if there is none)."""
    m = re.match(r"(`{3,})\n(.*)\n\1\n", reply, re.S)
    assert m, reply[:300]
    return m.group(2)


def test_slash_list_kit_markup_stays_in_a_code_block(monkeypatch) -> None:
    _guard_stdin(monkeypatch, tty=True)
    kit = {"id": "markup-kit", "name": _MARKUP_NAME, "summary": "**Click** ``` [here](https://evil.example).",
           "tags": [], "version": 1}
    monkeypatch.setattr(componentize_bridge, "kit_list", lambda **kw: _kits_reply([kit]))
    reply = _slash(f"list --templates-root {TEMPLATES_FIXTURES}")
    body = _fenced_body(reply)
    assert "[Official" in body and "[here](https://evil.example)" in body and "```" in body
    outside = reply.replace(body, "")
    assert "evil.example" not in outside and "[Official" not in outside
    assert reply.splitlines()[-2:] == [APP_LINE, "List exit code: 0"]


def test_kits_table_caps_count_and_id_length(monkeypatch, capsys) -> None:
    kits = [{"id": f"kit-{i}", "summary": "s"} for i in range(10_000)]
    kits.insert(0, {"id": "k" * (1 << 20), "summary": "long"})
    monkeypatch.setattr(componentize_bridge, "kit_list", lambda **kw: _kits_reply(kits))
    assert cli.main(["kits"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) <= cli.KITS_SHOWN_MAX + 2
    assert lines[-1] == f"{10_001 - cli.KITS_SHOWN_MAX} more kits not shown."
    assert max(len(line) for line in lines) <= catalog_list.ID_MAX + 20


def test_slash_list_with_10000_kits_stays_small(monkeypatch) -> None:
    _guard_stdin(monkeypatch, tty=True)
    kits = [{"id": f"kit-{i}", "name": f"Kit {i}", "summary": "s", "tags": [], "version": 1} for i in range(10_000)]
    monkeypatch.setattr(componentize_bridge, "kit_list", lambda **kw: _kits_reply(kits))
    reply = _slash(f"list --templates-root {TEMPLATES_FIXTURES}")
    assert len(reply) < 64_000, len(reply)
    assert reply.endswith("List exit code: 0")


def test_list_prompt_over_the_cap_says_it_was_cut(monkeypatch, capsys) -> None:
    from hermes_plugins.defuzz.prompt_parse import MAX_PROMPT_CHARS

    _guard_stdin(monkeypatch, tty=False)
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    line = f"Your idea was cut at {MAX_PROMPT_CHARS} characters to mark suggestions."
    rc = cli.main(_list("--prompt", VIDEO_PROMPT + " x" * MAX_PROMPT_CHARS))
    out = capsys.readouterr().out
    assert rc == 0 and out.count(line) == 1
    assert "(suggested)" in _row_for(out, "--kit video-production")
    cli.main(_list("--prompt", VIDEO_PROMPT))
    assert line not in capsys.readouterr().out
