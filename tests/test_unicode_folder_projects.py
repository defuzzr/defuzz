"""Projects whose folder name is not plain ASCII.

The folder name follows naming.folder_name only for templates listed in
scaffolder.UNICODE_FOLDER_TEMPLATES (and for kits when kit_scaffold.UNICODE_FOLDER_KITS is
true); everything else keeps the ASCII code identifier as its folder name. The fast tests
check that rule against whatever the tree contains. The slow proof (every bundled template
created in non-ASCII folders, then its own check and the Defuzz gates run with the real
tools) runs only when DEFUZZ_UNICODE_FOLDER_PROOF=1.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import cli, kit_scaffold, scaffolder  # noqa: E402
from hermes_plugins.defuzz.naming import folder_name, is_ascii_folder, slugify  # noqa: E402
from hermes_plugins.defuzz.state_store import get_project, list_projects  # noqa: E402
from hermes_plugins.defuzz.structure_check import check_structure, exit_code  # noqa: E402
from hermes_plugins.defuzz.templates import load_template, load_templates, templates_root  # noqa: E402

PROOF_ENV = "DEFUZZ_UNICODE_FOLDER_PROOF"
PROOF_LOG_ENV = "DEFUZZ_UNICODE_FOLDER_PROOF_LOG"
PROOF = os.environ.get(PROOF_ENV) == "1"
proof_only = pytest.mark.skipif(
    not PROOF,
    reason=f"slow real-toolchain proof in non-ASCII folders; set {PROOF_ENV}=1 to run it",
)

NFD_RESUME = unicodedata.normalize("NFD", "Résumé Nfd")
# (id, typed name, parent folder name or None). The last one is typed decomposed and is
# created inside a parent folder whose name is stored decomposed on disk.
NAMES = [
    ("latin", "café-ünïcode", None),
    ("japanese", "日本語サイト", None),
    ("cyrillic", "привет-мир", None),
    ("mixed", "tokyo-東京", None),
    ("nfd", NFD_RESUME, unicodedata.normalize("NFD", "projé")),
]
TEMPLATE_IDS = [spec.id for spec in load_templates()]


def _expected_template_folder(template_id: str, name: str) -> str:
    allowed = getattr(scaffolder, "UNICODE_FOLDER_TEMPLATES", frozenset())
    folder = folder_name(name)
    return folder if template_id in allowed and not is_ascii_folder(folder) else slugify(name)


def _expected_kit_folder(name: str) -> str:
    folder = folder_name(name)
    on = getattr(kit_scaffold, "UNICODE_FOLDER_KITS", False)
    return folder if on and not is_ascii_folder(folder) else slugify(name)


def _dest_root(tmp_path: Path, parent: str | None) -> Path:
    root = tmp_path / "projects"
    return root / parent if parent else root


def _register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "unicode-proj", "name": name, "path": path})


def _assert_no_unicode_name_inside(root: Path, name: str, files: list[str] | None = None) -> None:
    """File contents and inner paths never receive the Unicode folder name."""
    folder = folder_name(name)
    needles = {folder, unicodedata.normalize("NFD", folder), name.strip()}
    if files is None:
        files = [
            os.path.relpath(os.path.join(dirpath, fn), root)
            for dirpath, _dirs, filenames in os.walk(root) for fn in filenames
        ]
    for rel in files:
        assert not any(n in rel for n in needles), rel
        data = (root / rel).read_bytes()
        for n in needles:
            assert n.encode("utf-8") not in data, rel


def _tracked_files(repo: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=repo, capture_output=True, check=True).stdout
    return [p.decode("utf-8") for p in out.split(b"\0") if p]


# ---------------------------------------------------------------- fast, always on


@pytest.mark.parametrize("case_id,name,parent", NAMES, ids=[n[0] for n in NAMES])
def test_folder_name_round_trips_on_disk(tmp_path, case_id, name, parent):
    root = _dest_root(tmp_path, parent)
    root.mkdir(parents=True)
    folder = folder_name(name)
    assert len(Path(folder).parts) == 1 and folder == unicodedata.normalize("NFC", folder)
    (root / folder).mkdir()
    assert os.listdir(root) == [folder]  # bytes kept as given (Linux) or equivalent (macOS)
    assert (root / folder_name(name.upper())).is_dir()  # case variant finds the same folder
    if parent:
        assert os.listdir(tmp_path / "projects") in ([parent], [unicodedata.normalize("NFC", parent)])
    ident = slugify(name)
    assert ident.isascii() and not is_ascii_folder(folder)


@pytest.mark.parametrize("case_id,name,parent", NAMES, ids=[n[0] for n in NAMES])
@pytest.mark.parametrize("template_id", TEMPLATE_IDS)
def test_proposal_folder_rule_and_ascii_contents(tmp_path, template_id, case_id, name, parent):
    spec = load_template(templates_root() / template_id)
    proposal = scaffolder.propose(
        spec, name, {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
        dest_root=_dest_root(tmp_path, parent), staging_parent=tmp_path / "staging",
    )
    try:
        assert proposal.slug == slugify(name)
        assert [r.dest.name for r in proposal.repos] == [_expected_template_folder(template_id, name)]
        assert not proposal.repos[0].dest.exists()
        for plan in proposal.repos:
            _assert_no_unicode_name_inside(plan.staged, name)
            assert all(entry.isascii() for entry in plan.tree), plan.tree
        note = getattr(proposal, "folder_note", None)
        if note is not None:  # the preview note, once the wiring is in
            shown = proposal.repos[0].dest.name
            if shown == " ".join(name.split()):
                assert note == ""
            else:
                assert repr(shown) in note and "\n" not in note
    finally:
        scaffolder.discard(proposal)


def test_ascii_names_keep_ascii_folders(tmp_path):
    for template_id in TEMPLATE_IDS:
        spec = load_template(templates_root() / template_id)
        for name in ("My Game", "ＦＵＬＬ ｗｉｄｔｈ", "Game 🎮 Night"):
            proposal = scaffolder.propose(
                spec, name, {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
                dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging",
            )
            try:
                assert proposal.repos[0].dest.name == slugify(name)
                if name.isascii():
                    assert getattr(proposal, "folder_note", "") == ""
            finally:
                scaffolder.discard(proposal)


def test_existing_variant_folder_is_refused(tmp_path):
    spec = load_template(templates_root() / TEMPLATE_IDS[0])
    folder = _expected_template_folder(spec.id, "Café Ünïcode")
    (tmp_path / "projects" / folder).mkdir(parents=True)
    for variant in ("CAFÉ ÜNÏCODE", "Cafe\u0301 U\u0308ni\u0308code", "ｃａｆé ünïcode"):
        with pytest.raises(scaffolder.ScaffoldError, match="already exists"):
            scaffolder.propose(
                spec, variant, {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
                dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging",
            )


@pytest.mark.parametrize("case_id,name,parent", NAMES, ids=[n[0] for n in NAMES])
def test_kit_in_unicode_folder(tmp_path, case_id, name, parent):
    from tests.test_kit_scaffold import FakeVideoBridge

    bridge = FakeVideoBridge()
    db_path = tmp_path / "state.db"
    proposal = kit_scaffold.propose_kit(
        "video-production", name, {"building": "video", "layout": "single", "languages": []},
        dest_root=_dest_root(tmp_path, parent), staging_parent=tmp_path / "ステージ", bridge=bridge,
    )
    assert proposal.dest.name == _expected_kit_folder(name)
    result = kit_scaffold.accept_kit(proposal, register=_register, db_path=db_path, bridge=bridge)
    repo = Path(result.repos[0]["path"])
    assert repo == proposal.dest and repo.is_dir()
    assert result.repos[0]["registration"] == "registered"
    rules = json.loads((repo / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    assert rules["project_slug"] == slugify(name)
    row = get_project(repo, db_path=db_path)
    assert row is not None and row["slug"] == slugify(name)
    assert str(repo) in [p["path"] for p in list_projects(db_path=db_path)]
    assert exit_code(check_structure(repo)) == 0
    assert cli.main(["check", str(repo), "--json"]) == 0


def test_adopt_copy_into_unicode_destination(tmp_path, capsys):
    if shutil.which("git") is None:
        pytest.skip("adopting needs git")
    src = tmp_path / "源"
    (src / "src").mkdir(parents=True)
    (src / "README.md").write_text("# demo\n", encoding="utf-8")
    (src / "src" / "main.py").write_text("print('hi')\n", encoding="utf-8")
    copy_dir = tmp_path / unicodedata.normalize("NFD", "copié-コピー")
    staging = tmp_path / "staging"
    staging.mkdir()
    rc = cli.main(["run", str(copy_dir), "--source", str(src), "--staging", str(staging), "--deterministic"])
    out = capsys.readouterr()
    assert rc == 0, out.err
    assert (copy_dir / ".adopt" / "rules.json").is_file()
    assert cli.main(["check", str(copy_dir), "--json"]) == 0


def test_desktop_store_keeps_unicode_path(tmp_path):
    # A subprocess: the real Desktop project store, in a throwaway Hermes home.
    script = """
import json, os, sys
from pathlib import Path
from tests import ensure_test_package
ensure_test_package()
from hermes_plugins.defuzz.desktop_registration import create_project
path = Path(sys.argv[1]); path.mkdir(parents=True)
reply = json.loads(create_project(sys.argv[2], str(path)))
from hermes_cli import projects_db as pdb
with pdb.connect_closing() as conn:
    projects = pdb.list_projects(conn, include_archived=True)
print(json.dumps({"reply": reply, "paths": [p.primary_path for p in projects], "names": [p.name for p in projects]}))
"""
    env = dict(os.environ)
    for key in ("HOME", "HERMES_HOME", "HERMES_REAL_HOME"):
        env[key] = str(tmp_path / key)
        Path(env[key]).mkdir()
    target = tmp_path / "projects" / folder_name("tokyo-東京 Café")
    proc = subprocess.run([sys.executable, "-c", script, str(target), "Tokyo 東京 Café"], env=env,
                          capture_output=True, text=True, timeout=90, cwd=Path(__file__).resolve().parents[1])
    if proc.returncode != 0 and "No module named 'tools'" in proc.stderr:
        pytest.skip("Hermes agent is not importable here (PYTHONPATH)")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    assert data["paths"] == [str(target)], data
    assert data["names"] == ["Tokyo 東京 Café"], data


# ---------------------------------------------------------------- slow proof (opt-in)


# Where the official installers put tools that are often not on a test runner's PATH
# (the Go installer for Linux and macOS uses /usr/local/go/bin).
STANDARD_TOOL_DIRS = (Path("/usr/local/go/bin"),)


def _add_standard_tool_dirs(monkeypatch, needs) -> None:
    """Append a standard install folder to PATH (this test only) for a needed tool found there."""
    path = os.environ.get("PATH", "")
    for need in needs:
        if not need.strip() or shutil.which(need):
            continue
        for folder in STANDARD_TOOL_DIRS:
            if (folder / need).is_file() and os.access(folder / need, os.X_OK):
                path = f"{path}{os.pathsep}{folder}" if path else str(folder)
                monkeypatch.setenv("PATH", path)
                break


def _record(entry: dict) -> None:
    log = os.environ.get(PROOF_LOG_ENV)
    if log:
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


@proof_only
@pytest.mark.parametrize("case_id,name,parent", NAMES, ids=[n[0] for n in NAMES])
@pytest.mark.parametrize("template_id", TEMPLATE_IDS)
def test_template_passes_own_check_in_unicode_folder(tmp_path, monkeypatch, template_id, case_id, name, parent):
    for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONPATH"):
        monkeypatch.delenv(key, raising=False)
    spec = load_template(templates_root() / template_id)
    _add_standard_tool_dirs(monkeypatch, spec.needs)
    missing = [need for need in spec.needs if need.strip() and not shutil.which(need)]
    entry: dict = {"template": template_id, "name": case_id, "missing": missing}
    if missing:
        _record({**entry, "created": False})
        pytest.skip(f"{missing[0]} not installed")
    db_path = tmp_path / "state.db"
    proposal = scaffolder.propose(
        spec, name, {"building": spec.kind, "layout": spec.layout, "languages": list(spec.languages)},
        dest_root=_dest_root(tmp_path, parent), staging_parent=tmp_path / "ステージ",
    )
    folder = proposal.repos[0].dest.name
    entry["folder"] = folder
    entry["unicode_folder"] = not folder.isascii()
    try:
        result = scaffolder.accept(proposal, register=_register, db_path=db_path, timeout_s=900)
    except scaffolder.ScaffoldError as exc:
        _record({**entry, "created": False, "error": str(exc)[-2000:]})
        raise
    repo = Path(result.repos[0]["path"])
    entry.update(created=repo.is_dir(), accept_check=result.repos[0]["check"])
    check_spec = spec.repos[0].check
    check_cwd = repo if check_spec.cwd == "." else repo / check_spec.cwd
    own = []
    for command in [list(c) for c in check_spec.ci_commands()]:
        proc = subprocess.run(command, cwd=check_cwd, capture_output=True, text=True, timeout=900)
        own.append({"cmd": command, "rc": proc.returncode, "tail": (proc.stdout + proc.stderr)[-1500:]})
        if proc.returncode != 0:
            break
    entry["own_check"] = own
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True)
    entry["git_clean"] = status.stdout == ""
    from hermes_plugins.defuzz.linter import run_lint
    from tests.template_lint_known import assert_lint_clean_or_known

    report = run_lint(repo, env=dict(os.environ), db_path=db_path)
    entry["lint"] = report.get("status")
    entry["lint_findings"] = [(f.get("file"), f.get("rule")) for f in report.get("findings") or []][:20]
    entry["structure_check"] = exit_code(check_structure(repo))
    entry["cli_check"] = cli.main(["check", str(repo), "--json"])
    entry["tools_lock"] = (repo / "TOOLS.lock").is_file()
    row = get_project(repo, db_path=db_path)
    entry["db_slug"] = row["slug"] if row else None
    _record(entry)

    assert result.repos[0]["check"] == "ok", result.repos[0]
    assert folder == _expected_template_folder(template_id, name)
    assert all(step["rc"] == 0 for step in own), own
    assert entry["git_clean"], status.stdout
    assert_lint_clean_or_known(spec.id, report)
    assert entry["structure_check"] == 0 and entry["cli_check"] == 0
    assert entry["tools_lock"]
    assert entry["db_slug"] == slugify(name)
    rules = json.loads((repo / ".adopt" / "rules.json").read_text(encoding="utf-8"))
    assert rules["project_slug"] == slugify(name)
    _assert_no_unicode_name_inside(repo, name, _tracked_files(repo))
