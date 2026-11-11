"""`new --kit` never hands the companion a staging folder inside a Hermes home.

Under Hermes, TMPDIR points inside the Hermes home (its cache/scratch folder), and
`componentize kit apply` refuses any target inside a Hermes home.  These tests run the
real bridge against a fake companion executable that applies the companion's real target
rule (cases listed above `_FAKE_COMPANION`).  They also cover a staging parent swapped
after it was checked, and HOME empty, relative or unset.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List

import pytest

from tests import ensure_test_package

pwd = pytest.importorskip("pwd")

ensure_test_package()

from hermes_plugins.defuzz import componentize_bridge, componentize_settings, kit_scaffold  # noqa: E402
from hermes_plugins.defuzz.kit_scaffold import accept_kit, discard_kit, propose_kit  # noqa: E402
from hermes_plugins.defuzz.scaffolder import ScaffoldError  # noqa: E402
from hermes_plugins.defuzz.state_store import state_db_path  # noqa: E402
from hermes_plugins.defuzz.new_project import run_new_project_flow  # noqa: E402
from tests.fake_kit_bridge import (  # noqa: E402
    VIDEO_DECLARED_DIRS,
    VIDEO_KIT_BLOCK,
    VIDEO_PLACEMENT_RULES,
    FakeKitBridge,
)

KIT_ID = "video-production"
ANSWERS = {"building": "video", "layout": "single", "languages": []}

# The fake applies the companion's real target rule (defuzz-componentize `_kit_runtime.py`):
#  1. target must be an absolute path                               (verify_target)
#  2. home = HOME if an absolute existing folder, else the account
#     home from the password database, else refuse everything         (resolve_home; kit_commands.run)
#  3. protected Hermes homes: <home>/.hermes always, plus HERMES_HOME
#     after $VAR/${VAR} expansion (unknown name: ignored), ~ and ~/
#     against <home>; relative HERMES_HOME ignored                    (_hermes_homes, _stable_hermes_home)
#  4. refuse when the target, as written or resolved, is inside a
#     Hermes home taken as written or resolved                        (_decide, first loop)
#  5. refuse system subtrees, /var and /opt exactly, the filesystem
#     root and any top-level folder (covers /lib*)                    (_decide, system tables)
#  6. refuse the home itself or an ancestor, and a path that only
#     resolves into the home through a symlink                        (_decide, home checks)
#  7. refuse an existing symlink as the final component               (verify_target)
# Test-only substitution: the password database is read from FAKE_COMPANION_PWD_HOME so the
# fake never consults the real account. Not mirrored: `~user` in HERMES_HOME (ignored here).
_FAKE_COMPANION = r'''
import json, os, re, sys

ENV_REF = re.compile(r'\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)')
SUBTREES = ('/etc', '/usr', '/bin', '/sbin', '/boot', '/dev', '/proc', '/sys')
EXACT = ('/var', '/opt')

def inside(path, base):
    return True if base == os.sep else (path == base or path.startswith(base + os.sep))

def resolve_home():
    env_home = os.environ.get('HOME')
    if env_home and os.path.isabs(env_home) and os.path.isdir(env_home):
        return os.path.normpath(env_home)
    pw_dir = os.environ.get('FAKE_COMPANION_PWD_HOME', '')
    if pw_dir and os.path.isabs(pw_dir) and os.path.isdir(pw_dir):
        return os.path.normpath(pw_dir)
    return None

def hermes_homes(home):
    out = [os.path.normpath(os.path.join(home, '.hermes'))]
    raw = os.environ.get('HERMES_HOME', '').strip()
    try:
        raw = ENV_REF.sub(lambda m: os.environ[m.group(1) or m.group(2)], raw)
    except KeyError:
        raw = ''
    path = None
    if raw == '~':
        path = home
    elif raw.startswith('~/'):
        path = os.path.join(home, raw[2:])
    elif raw and not raw.startswith('~') and os.path.isabs(raw):
        path = raw
    if path and os.path.normpath(path) not in out:
        out.append(os.path.normpath(path))
    return out

def refusal(target):
    if not os.path.isabs(target):
        return 'project folder must be an absolute normalized path'
    home = resolve_home()
    if home is None:
        return 'cannot determine your home folder, so the safety check cannot run'
    lexical = os.path.normpath(target)
    resolved = os.path.realpath(lexical)
    forms = (lexical, resolved)
    for hh in hermes_homes(home):
        if any(inside(f, b) for f in forms for b in (hh, os.path.realpath(hh))):
            return 'refusing %s: pick a dedicated folder outside Hermes home (%s)' % (lexical, hh)
    for root in SUBTREES:
        real = os.path.realpath(root)
        if any(inside(f, b) for f in forms for b in ((root,) + ((real,) if real != os.sep else ()))):
            return 'refusing %s: pick a dedicated folder, not a system directory' % lexical
    if any(f in EXACT or f in [os.path.realpath(e) for e in EXACT] for f in forms):
        return 'refusing %s: pick a dedicated folder, not a system directory' % lexical
    if any(f == os.sep or os.path.dirname(f) == os.sep for f in forms):
        return 'refusing %s: not a top-level folder' % lexical
    home_real = os.path.realpath(home)
    if any(f == h or h.startswith(f + os.sep) for f, h in ((lexical, home), (resolved, home_real))):
        return 'refusing %s: pick a dedicated folder, not a home or filesystem root' % lexical
    if inside(resolved, home_real) and not inside(lexical, home):
        return 'refusing %s: resolves into the home folder' % lexical
    if os.path.islink(lexical):
        return '%s exists and is a symlink, not a directory' % lexical
    return None

args = sys.argv[1:]
if args == ['--version']:
    print('componentize 0.0-fake')
    sys.exit(0)
if len(args) < 4 or args[0] != 'kit' or args[1] not in ('apply', 'check'):
    sys.exit(3)
call, kit_id, dest = args[1], args[2], args[3]
with open(os.environ['FAKE_COMPANION_LOG'], 'a', encoding='utf-8') as log:
    log.write(json.dumps({'call': call, 'dest': dest}) + '\n')
why = refusal(dest)
if why:
    sys.stderr.write(why + '\n')
    sys.exit(2)
if os.environ.get('FAKE_COMPANION_RULE_ONLY'):
    sys.exit(0)
with open(os.environ['FAKE_COMPANION_SPEC'], encoding='utf-8') as fh:
    spec = json.load(fh)
items = []
if call == 'apply':
    os.makedirs(dest)
    for entry in spec['declared_dirs']:
        folder = os.path.join(dest, entry['dir'])
        os.makedirs(folder, exist_ok=True)
        open(os.path.join(folder, '.gitkeep'), 'w').close()
        items.append({'path': entry['dir'], 'state': 'created'})
    with open(os.path.join(dest, 'AGENTS.md'), 'w', encoding='utf-8') as fh:
        fh.write('# %s\n\n%s\n' % (os.path.basename(dest), spec['agents_block']))
print(json.dumps({
    'schema': 'componentize.kit/1', 'ok': True, 'status': 'pass', 'error': None,
    'findings': [], 'root': dest, 'kit': kit_id, 'items': items,
    'declared_dirs': spec['declared_dirs'], 'placement_rules': spec['placement_rules'],
}))
'''


@pytest.fixture
def componentize_live() -> None:
    """Opt out of the hermetic guard: these tests run the real bridge against a fake companion."""


@pytest.fixture
def hermes_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, componentize_live: None) -> Dict[str, Path]:
    user = tmp_path / "user"
    account = tmp_path / "account"  # stands in for the password-database home
    hermes_home = tmp_path / "custom-hermes"
    scratch = hermes_home / "cache" / "scratch"
    default_home = user / ".hermes"
    projects = tmp_path / "projects"
    for folder in (user, account, scratch, default_home / "cache" / "scratch", projects):
        folder.mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "componentize"
    exe.write_text(f"#!{sys.executable}\n{_FAKE_COMPANION}", encoding="utf-8")
    exe.chmod(0o755)
    git = shutil.which("git")
    if git:  # accept_kit commits the project; PATH below holds only this folder.
        (bin_dir / "git").symlink_to(git)
    spec = tmp_path / "kit-spec.json"
    spec.write_text(
        json.dumps(
            {
                "declared_dirs": VIDEO_DECLARED_DIRS,
                "placement_rules": VIDEO_PLACEMENT_RULES,
                "agents_block": VIDEO_KIT_BLOCK,
            }
        ),
        encoding="utf-8",
    )
    log = tmp_path / "companion-log.jsonl"
    log.write_text("", encoding="utf-8")

    monkeypatch.setenv("HOME", str(user))
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("TMPDIR", str(scratch))
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("FAKE_COMPANION_LOG", str(log))
    monkeypatch.setenv("FAKE_COMPANION_SPEC", str(spec))
    monkeypatch.setenv("FAKE_COMPANION_PWD_HOME", str(account))
    monkeypatch.delenv("FAKE_COMPANION_RULE_ONLY", raising=False)
    # Never consult the real account: the password-database home is a tmp folder.
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(account)))
    monkeypatch.setattr(
        componentize_settings, "load", lambda: {**componentize_settings.DEFAULTS, "cli_path_override": None}
    )
    return {
        "hermes_home": hermes_home,
        "default_home": default_home,
        "account": account,
        "exe": exe,
        "scratch": scratch,
        "projects": projects,
        "log": log,
    }


def _homes(env: Dict[str, Path]) -> List[Path]:
    return [env["hermes_home"], env["default_home"]]


def _inside(path: Path, parent: Path) -> bool:
    real = Path(os.path.realpath(path))
    top = Path(os.path.realpath(parent))
    return real == top or top in real.parents


def _companion_calls(env: Dict[str, Path]) -> List[Dict[str, str]]:
    lines = env["log"].read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _leftovers(folder: Path) -> List[str]:
    return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []


def test_kit_stage_is_outside_every_hermes_home_when_tmpdir_is_inside(hermes_env: Dict[str, Path]) -> None:
    proposal = propose_kit(
        KIT_ID,
        "Launch Trailer",
        ANSWERS,
        dest_root=hermes_env["projects"],
        bridge=componentize_bridge,
    )
    try:
        calls = _companion_calls(hermes_env)
        assert [c["call"] for c in calls] == ["apply"]
        handed = Path(calls[0]["dest"])
        assert handed == proposal.staged
        assert proposal.staging_dir.parent == Path(os.path.realpath(hermes_env["projects"]))
        for home in _homes(hermes_env):
            assert not _inside(handed, home)
            assert not _inside(proposal.staging_dir, home)
        # Private staging folder on the same filesystem as the destination.
        assert stat.S_IMODE(os.lstat(proposal.staging_dir).st_mode) == 0o700
        assert os.lstat(proposal.staging_dir).st_dev == os.lstat(hermes_env["projects"]).st_dev
        assert proposal.staged.is_dir()
        assert _leftovers(hermes_env["scratch"]) == []
    finally:
        discard_kit(proposal)
    assert not proposal.staging_dir.exists()
    assert _leftovers(hermes_env["projects"]) == []
    assert _leftovers(hermes_env["scratch"]) == []


def test_kit_accept_moves_into_projects_and_leaves_no_staging(hermes_env: Dict[str, Path]) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    proposal = propose_kit(
        KIT_ID,
        "Launch Trailer",
        ANSWERS,
        dest_root=hermes_env["projects"],
        bridge=componentize_bridge,
    )
    try:
        accept_kit(
            proposal,
            register=lambda name, path: json.dumps({"success": True, "id": "p1", "name": name, "path": path}),
            db_path=state_db_path(),
            bridge=componentize_bridge,
        )
    finally:
        discard_kit(proposal)
    calls = _companion_calls(hermes_env)
    assert [c["call"] for c in calls] == ["apply", "check"]
    assert all(Path(c["dest"]) == proposal.staged for c in calls)
    assert (proposal.dest / ".git").is_dir()
    assert (proposal.dest / "AGENTS.md").is_file()
    assert _leftovers(hermes_env["projects"]) == [proposal.slug]
    assert _leftovers(hermes_env["scratch"]) == []


def test_kit_stage_is_cleaned_when_the_companion_fails(
    hermes_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_COMPANION_SPEC", str(hermes_env["projects"] / "missing-spec.json"))
    with pytest.raises(ScaffoldError):
        propose_kit(
            KIT_ID,
            "Launch Trailer",
            ANSWERS,
            dest_root=hermes_env["projects"],
            bridge=componentize_bridge,
        )
    assert len(_companion_calls(hermes_env)) == 1
    assert _leftovers(hermes_env["projects"]) == []
    assert _leftovers(hermes_env["scratch"]) == []


def test_kit_stage_falls_back_to_system_temp_outside_hermes_home(
    hermes_env: Dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system_tmp = tmp_path / "system-tmp"
    system_tmp.mkdir()
    monkeypatch.setattr(kit_scaffold, "_system_stage_candidates", lambda: [str(system_tmp)])
    missing_root = hermes_env["projects"] / "not-yet-created"
    proposal = propose_kit(
        KIT_ID,
        "Launch Trailer",
        ANSWERS,
        dest_root=missing_root,
        bridge=componentize_bridge,
    )
    try:
        assert proposal.staging_dir.parent == system_tmp
        assert stat.S_IMODE(os.lstat(proposal.staging_dir).st_mode) == 0o700
        handed = Path(_companion_calls(hermes_env)[0]["dest"])
        for home in _homes(hermes_env):
            assert not _inside(handed, home)
    finally:
        discard_kit(proposal)
    assert _leftovers(system_tmp) == []
    assert _leftovers(hermes_env["scratch"]) == []
    assert not missing_root.exists()


def test_kit_stage_fails_plainly_when_only_hermes_home_folders_are_left(
    hermes_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit_scaffold, "_system_stage_candidates", lambda: [str(hermes_env["scratch"])])
    missing_root = hermes_env["projects"] / "not-yet-created"
    with pytest.raises(ScaffoldError) as excinfo:
        propose_kit(
            KIT_ID,
            "Launch Trailer",
            ANSWERS,
            dest_root=missing_root,
            bridge=componentize_bridge,
        )
    message = str(excinfo.value)
    assert "\n" not in message
    assert "outside" in message and "Hermes home" in message
    assert _companion_calls(hermes_env) == []
    assert _leftovers(hermes_env["scratch"]) == []
    assert not missing_root.exists()


# --- A: a staging parent swapped after it was checked ------------------------------------------


def _swap_parent_into_home(env: Dict[str, Path], stage_name: str) -> Dict[str, Path]:
    """Rename the projects folder aside, point its name at the Hermes home, plant a marker there."""
    saved = env["projects"].with_name("projects-saved")
    env["projects"].rename(saved)
    env["projects"].symlink_to(env["hermes_home"], target_is_directory=True)
    foreign = env["hermes_home"] / stage_name
    foreign.mkdir(mode=0o700)
    marker = foreign / "unrelated-marker"
    marker.write_text("retain me", encoding="utf-8")
    return {"saved": saved, "marker": marker}


def _propose(env: Dict[str, Path], bridge=componentize_bridge):
    return propose_kit(KIT_ID, "Launch Trailer", ANSWERS, dest_root=env["projects"], bridge=bridge)


def test_parent_swapped_right_after_stage_creation_stops_and_deletes_only_its_own_stage(
    hermes_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    real_mkdir = os.mkdir
    swapped: Dict[str, Path] = {}
    started: List[str] = []

    def mkdir(path, mode=0o777, *, dir_fd=None):
        if dir_fd is None:
            real_mkdir(path, mode)
        else:
            real_mkdir(path, mode, dir_fd=dir_fd)
        name = os.path.basename(os.fspath(path))
        if name.startswith(".adopt-scaffold-") and not started:
            started.append(name)
            swapped.update(_swap_parent_into_home(hermes_env, name))

    with monkeypatch.context() as m:
        m.setattr(os, "mkdir", mkdir)
        with pytest.raises(ScaffoldError) as excinfo:
            _propose(hermes_env)
    assert swapped, "the race window was not reached"
    assert "\n" not in str(excinfo.value)
    assert _companion_calls(hermes_env) == []
    assert swapped["marker"].read_text(encoding="utf-8") == "retain me"
    assert _leftovers(swapped["saved"]) == []


@pytest.mark.parametrize("companion_fails", [False, True])
def test_parent_swapped_during_apply_cleanup_removes_only_its_own_stage(
    hermes_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch, companion_fails: bool
) -> None:
    if companion_fails:
        monkeypatch.setenv("FAKE_COMPANION_SPEC", str(hermes_env["projects"] / "missing-spec.json"))
    swapped: Dict[str, Path] = {}

    class SwappingBridge:
        def kit_apply(self, kit_id, dest, variables=None, **kw):
            res = componentize_bridge.kit_apply(kit_id, dest, variables, **kw)
            swapped.update(_swap_parent_into_home(hermes_env, Path(dest).parent.name))
            return res

        def kit_check(self, kit_id, dest, **kw):
            return componentize_bridge.kit_check(kit_id, dest, **kw)

    with pytest.raises(ScaffoldError) as excinfo:
        _propose(hermes_env, bridge=SwappingBridge())
    assert "\n" not in str(excinfo.value)
    assert [c["call"] for c in _companion_calls(hermes_env)] == ["apply"]
    assert swapped["marker"].read_text(encoding="utf-8") == "retain me"
    assert _leftovers(swapped["saved"]) == []


def test_discard_after_parent_swap_removes_only_its_own_stage(hermes_env: Dict[str, Path]) -> None:
    proposal = _propose(hermes_env)
    swapped = _swap_parent_into_home(hermes_env, proposal.staging_dir.name)
    discard_kit(proposal)
    discard_kit(proposal)  # a second discard must not fall back to deleting by path
    assert swapped["marker"].read_text(encoding="utf-8") == "retain me"
    assert _leftovers(swapped["saved"]) == []


def test_accept_after_parent_swap_never_hands_the_stage_to_the_companion(hermes_env: Dict[str, Path]) -> None:
    proposal = _propose(hermes_env)
    swapped = _swap_parent_into_home(hermes_env, proposal.staging_dir.name)
    try:
        with pytest.raises(ScaffoldError) as excinfo:
            accept_kit(
                proposal,
                register=lambda name, path: json.dumps({"success": True, "id": "p1", "name": name, "path": path}),
                db_path=state_db_path(),
                bridge=componentize_bridge,
            )
        assert "\n" not in str(excinfo.value)
        assert [c["call"] for c in _companion_calls(hermes_env)] == ["apply"]
    finally:
        discard_kit(proposal)
    assert swapped["marker"].read_text(encoding="utf-8") == "retain me"
    assert _leftovers(swapped["saved"]) == []
    assert not (swapped["saved"] / proposal.slug).exists()


def test_stage_replaced_by_symlink_before_apply_is_never_handed_over(
    hermes_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = hermes_env["hermes_home"] / "unrelated-marker"
    marker.write_text("retain me", encoding="utf-8")
    original = kit_scaffold.verify_nofollow_within_root
    replaced: List[str] = []

    def check(root, rel):
        value = original(root, rel)
        if not replaced:
            Path(root).rmdir()
            Path(root).symlink_to(hermes_env["hermes_home"], target_is_directory=True)
            replaced.append(str(root))
        return value

    monkeypatch.setattr(kit_scaffold, "verify_nofollow_within_root", check)
    with pytest.raises(ScaffoldError) as excinfo:
        _propose(hermes_env)
    assert replaced
    assert "\n" not in str(excinfo.value)
    assert _companion_calls(hermes_env) == []
    assert marker.read_text(encoding="utf-8") == "retain me"
    assert Path(replaced[0]).is_symlink()  # not ours: left alone


# --- B: HOME empty, relative or unset uses the password-database home --------------------------


@pytest.mark.parametrize("home_value", ["", "relative-home", None])
def test_projects_inside_the_account_default_hermes_home_is_never_used_for_staging(
    hermes_env: Dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, home_value
) -> None:
    monkeypatch.chdir(tmp_path)
    if home_value is None:
        monkeypatch.delenv("HOME")
    else:
        monkeypatch.setenv("HOME", home_value)
    projects = hermes_env["account"] / ".hermes" / "cache" / "scratch" / "projects"
    projects.mkdir(parents=True)
    system_tmp = tmp_path / "system-tmp"
    system_tmp.mkdir()
    monkeypatch.setattr(kit_scaffold, "_system_stage_candidates", lambda: [str(system_tmp)])
    proposal = propose_kit(KIT_ID, "Launch Trailer", ANSWERS, dest_root=projects, bridge=componentize_bridge)
    try:
        calls = _companion_calls(hermes_env)
        assert [c["call"] for c in calls] == ["apply"]
        assert Path(os.path.realpath(proposal.staging_dir)).parent == Path(os.path.realpath(system_tmp))
        for home in (hermes_env["account"] / ".hermes", hermes_env["hermes_home"]):
            assert not _inside(Path(calls[0]["dest"]), home)
        assert _leftovers(projects) == []
    finally:
        discard_kit(proposal)
    assert _leftovers(system_tmp) == []


def test_no_home_folder_at_all_stops_before_creating_anything(
    hermes_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", "")
    monkeypatch.setenv("FAKE_COMPANION_PWD_HOME", "")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=""))
    with pytest.raises(ScaffoldError) as excinfo:
        _propose(hermes_env)
    assert "\n" not in str(excinfo.value)
    assert "home folder" in str(excinfo.value)
    assert _companion_calls(hermes_env) == []
    assert _leftovers(hermes_env["projects"]) == []


# --- C: the fake applies the real rule, and Defuzz is at least as strict -----------------------


def _rule_cases(env: Dict[str, Path], tmp_path: Path):
    user = Path(os.environ["HOME"])
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    escape = user / ".hermes" / "escape"
    escape.parent.mkdir(parents=True, exist_ok=True)
    if not escape.is_symlink():
        escape.symlink_to(outside, target_is_directory=True)
    alias = tmp_path / "alias-into-home"
    if not alias.is_symlink():
        alias.symlink_to(env["hermes_home"], target_is_directory=True)
    final_link = tmp_path / "final-link"
    if not final_link.is_symlink():
        final_link.symlink_to(outside, target_is_directory=True)
    var_home = tmp_path / "var-hermes"
    # (name, extra env, target, companion refuses)
    return [
        ("outside every home", {}, outside / "stage", False),
        ("custom HERMES_HOME scratch", {}, env["scratch"] / "stage", True),
        ("default <home>/.hermes", {}, user / ".hermes" / "cache" / "scratch" / "stage", True),
        ("lexical .hermes symlink pointing outward", {}, escape / "stage", True),
        ("symlink alias resolving into a Hermes home", {}, alias / "stage", True),
        ("empty HOME: account default home", {"HOME": ""}, env["account"] / ".hermes" / "x", True),
        ("relative HOME: account default home", {"HOME": "rel"}, env["account"] / ".hermes" / "x", True),
        ("$VAR in HERMES_HOME", {"HERMES_HOME": "$KST_VAR_HOME", "KST_VAR_HOME": str(var_home)}, var_home / "x", True),
        ("~/ in HERMES_HOME", {"HERMES_HOME": "~/hh"}, user / "hh" / "x", True),
        ("relative HERMES_HOME is ignored", {"HERMES_HOME": "rel-hh"}, outside / "stage2", False),
        ("system subtree", {}, Path("/usr") / "kst-not-there" / "x", True),
        ("top-level folder", {}, Path("/kst-not-there"), True),
        ("the home folder itself", {}, user, True),
        ("final component is a symlink", {}, final_link, True),
        ("no home folder at all", {"HOME": "", "FAKE_COMPANION_PWD_HOME": ""}, outside / "stage3", True),
    ]


def test_fake_companion_applies_the_real_rule_and_defuzz_is_at_least_as_strict(
    hermes_env: Dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FAKE_COMPANION_RULE_ONLY", "1")
    mismatches = []
    for name, extra, target, refuses in _rule_cases(hermes_env, tmp_path):
        with monkeypatch.context() as m:
            for key, value in extra.items():
                m.setenv(key, value)
            if extra.get("FAKE_COMPANION_PWD_HOME") == "":
                m.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=""))
            proc = subprocess.run(
                [sys.executable, str(hermes_env["exe"]), "kit", "apply", KIT_ID, str(target)],
                capture_output=True,
                text=True,
                env=dict(os.environ),
                timeout=30,
            )
            fake_refuses = proc.returncode == 2
            defuzz_refuses = kit_scaffold._inside_any_hermes_home(target)
        if fake_refuses != refuses:
            mismatches.append(f"fake {name}: refused={fake_refuses} ({proc.stderr.strip()})")
        if refuses and not defuzz_refuses:
            mismatches.append(f"defuzz {name}: would stage where the companion refuses")
    assert mismatches == []


def test_stage_is_private_and_removable_under_an_owner_masking_umask(hermes_env: Dict[str, Path]) -> None:
    old = os.umask(0o777)
    try:
        path, stage = kit_scaffold._make_kit_stage(hermes_env["projects"])
    finally:
        os.umask(old)
    assert stage is not None
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o700
    locked = path / "launch-trailer" / "nested"
    locked.mkdir(parents=True)
    (locked / "file.txt").write_text("x", encoding="utf-8")
    locked.chmod(0)
    (path / "launch-trailer").chmod(0)  # as left by a companion run under that umask
    kit_scaffold._remove_kit_stage(stage, path)
    assert _leftovers(hermes_env["projects"]) == []



# --- D: HOME or HERMES_HOME reached through a symlink ------------------------------------------


def _register(name: str, path: str) -> str:
    return json.dumps({"success": True, "id": "p1", "name": name, "path": path})


def _symlinked_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    """HOME is a symlink to a real folder; Hermes' ambient TMPDIR is that home's .hermes scratch."""
    real = tmp_path / "real-home"
    scratch = real / ".hermes" / "cache" / "scratch"
    scratch.mkdir(parents=True)
    link = tmp_path / "link-home"
    link.symlink_to(real, target_is_directory=True)
    projects = link / "projects"
    projects.mkdir()
    monkeypatch.setenv("HOME", str(link))
    monkeypatch.setenv("TMPDIR", str(link / ".hermes" / "cache" / "scratch"))
    return {"link": link, "real": real, "projects": projects, "scratch": scratch}


def _assert_outside_homes(paths, homes) -> None:
    for path in paths:
        for home in homes:
            assert not _inside(Path(path), home), f"{path} is inside {home}"
            lexical = os.path.normpath(os.fspath(path))
            assert not (lexical + os.sep).startswith(os.path.normpath(os.fspath(home)) + os.sep)


def test_home_through_a_symlink_stages_in_the_projects_folder_and_creates_the_project(
    hermes_env: Dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    home = _symlinked_home(tmp_path, monkeypatch)
    proposal = propose_kit(KIT_ID, "Launch Trailer", ANSWERS, dest_root=home["projects"], bridge=componentize_bridge)
    try:
        # Handed over as written (through the HOME symlink), pinned on the resolved side.
        assert proposal.staging_dir.parent == home["projects"]
        assert Path(os.path.realpath(proposal.staging_dir)).parent == home["real"] / "projects"
        accept_kit(proposal, register=_register, db_path=state_db_path(), bridge=componentize_bridge)
    finally:
        discard_kit(proposal)
    calls = _companion_calls(hermes_env)
    assert [c["call"] for c in calls] == ["apply", "check"]
    homes = [hermes_env["hermes_home"], home["link"] / ".hermes", home["real"] / ".hermes"]
    _assert_outside_homes([c["dest"] for c in calls], homes)
    assert (proposal.dest / ".git").is_dir()
    assert _leftovers(home["projects"]) == [proposal.slug]
    assert _leftovers(home["scratch"]) == []


class _RuleCheckingFakeBridge(FakeKitBridge):
    """The shared fake kit bridge, refusing like the companion (rule-only fake) would."""

    def __init__(self, exe: Path) -> None:
        super().__init__()
        self.exe = exe
        self.refusals: List[str] = []

    def _refusal(self, dest):
        proc = subprocess.run(
            [sys.executable, str(self.exe), "kit", "apply", KIT_ID, str(dest)],
            capture_output=True,
            text=True,
            env={**os.environ, "FAKE_COMPANION_RULE_ONLY": "1"},
            timeout=30,
        )
        if proc.returncode == 0:
            return None
        self.refusals.append(proc.stderr.strip())
        return {"status": "error", "data": None, "notice": proc.stderr.strip(), "exit": 2}

    def kit_apply(self, kit_id, dest, variables=None, *, timeout=None):
        return self._refusal(dest) or super().kit_apply(kit_id, dest, variables, timeout=timeout)

    def kit_check(self, kit_id, dest, *, timeout=None):
        return self._refusal(dest) or super().kit_check(kit_id, dest, timeout=timeout)


def test_new_kit_flow_with_a_symlinked_home_creates_the_project_outside_every_hermes_home(
    hermes_env: Dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    home = _symlinked_home(tmp_path, monkeypatch)
    bridge = _RuleCheckingFakeBridge(hermes_env["exe"])
    res = run_new_project_flow(
        kit_id=KIT_ID,
        name_provider=lambda: "Night Shoot",
        confirm_kit=lambda _proposal: True,
        register=_register,
        db_path=state_db_path(),
        dest_root=home["projects"],
        kit_bridge=bridge,
        timeout_s=120,
    )
    assert bridge.refusals == []
    assert res.status == "created", res.message
    handed = [c["dest"] for c in bridge.apply_calls + bridge.check_calls]
    assert len(handed) == 2
    homes = [hermes_env["hermes_home"], home["link"] / ".hermes", home["real"] / ".hermes"]
    _assert_outside_homes(handed, homes)
    assert (home["projects"] / "night-shoot" / ".git").is_dir()
    assert _leftovers(home["projects"]) == ["night-shoot"]
    assert _leftovers(home["scratch"]) == []


@pytest.mark.parametrize("projects_via", ["link", "real"])
def test_hermes_home_through_a_symlink_is_never_used_for_staging(
    hermes_env: Dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, projects_via: str
) -> None:
    link = tmp_path / "hermes-link"
    link.symlink_to(hermes_env["hermes_home"], target_is_directory=True)
    monkeypatch.setenv("HERMES_HOME", str(link))
    monkeypatch.setenv("TMPDIR", str(link / "cache" / "scratch"))
    base = link if projects_via == "link" else hermes_env["hermes_home"]
    projects = base / "cache" / "scratch" / "projects"
    projects.mkdir()
    system_tmp = tmp_path / "system-tmp"
    system_tmp.mkdir()
    monkeypatch.setattr(kit_scaffold, "_system_stage_candidates", lambda: [str(system_tmp)])
    proposal = propose_kit(KIT_ID, "Launch Trailer", ANSWERS, dest_root=projects, bridge=componentize_bridge)
    try:
        assert Path(os.path.realpath(proposal.staging_dir)).parent == Path(os.path.realpath(system_tmp))
        handed = [c["dest"] for c in _companion_calls(hermes_env)]
        _assert_outside_homes(handed, [hermes_env["hermes_home"], link, hermes_env["default_home"]])
    finally:
        discard_kit(proposal)
    assert _leftovers(projects) == []
    assert _leftovers(system_tmp) == []


def test_fallback_temp_folder_is_never_inside_a_hermes_home(
    hermes_env: Dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _symlinked_home(tmp_path, monkeypatch)
    monkeypatch.setenv("TMPDIR", str(home["scratch"]))  # the default Hermes scratch by its real path
    temp_alias = tmp_path / "temp-alias"  # a system temp folder that is an alias into a Hermes home
    temp_alias.symlink_to(hermes_env["scratch"], target_is_directory=True)
    system_tmp = tmp_path / "system-tmp"
    system_tmp.mkdir()
    monkeypatch.setattr(kit_scaffold, "_system_stage_candidates", lambda: [str(temp_alias), str(system_tmp)])
    missing = home["link"] / "projects-not-created"
    proposal = propose_kit(KIT_ID, "Launch Trailer", ANSWERS, dest_root=missing, bridge=componentize_bridge)
    try:
        assert proposal.staging_dir.parent == system_tmp
    finally:
        discard_kit(proposal)
    assert _leftovers(home["scratch"]) == []
    assert _leftovers(hermes_env["scratch"]) == []
    assert _leftovers(system_tmp) == []


# --- E: the stage swapped for another folder between creation and pinning (R1) ----------------


def test_stage_swapped_right_after_mkdir_is_never_used_and_the_substitute_is_kept(
    hermes_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    real_mkdir = os.mkdir
    swapped: List[Path] = []

    def mkdir(path, mode=0o777, *, dir_fd=None):
        if dir_fd is None:
            real_mkdir(path, mode)
        else:
            real_mkdir(path, mode, dir_fd=dir_fd)
        name = os.path.basename(os.fspath(path))
        if name.startswith(".adopt-scaffold-") and not swapped:
            created = hermes_env["projects"] / name
            created.rename(created.with_name(name + ".moved"))
            real_mkdir(created, 0o700)
            (created / "keep.txt").write_text("retain me", encoding="utf-8")
            swapped.append(created)

    with monkeypatch.context() as m:
        m.setattr(os, "mkdir", mkdir)
        with pytest.raises(ScaffoldError) as excinfo:
            _propose(hermes_env)
    assert swapped, "the race window was not reached"
    assert "\n" not in str(excinfo.value)
    assert _companion_calls(hermes_env) == []
    assert (swapped[0] / "keep.txt").read_text(encoding="utf-8") == "retain me"
    assert _leftovers(swapped[0]) == ["keep.txt"]


# --- F: the final move happens relative to the pinned folders (R2) -----------------------------


def _swap_at(kind: str, env: Dict[str, Path], proposal) -> Dict[str, Path]:
    """Swap the staged project (or the projects folder) for a link into the Hermes home."""
    if kind == "staged":
        holder = env["hermes_home"] / "vault" / "holder"
        holder.mkdir(parents=True)
        (holder / "MARK").write_text("retain me", encoding="utf-8")
        proposal.staged.rename(proposal.staged.with_name(proposal.slug + ".moved"))
        proposal.staged.symlink_to(holder, target_is_directory=True)
        return {"holder": holder}
    return _swap_parent_into_home(env, "unused-" + proposal.slug)


def _home_listing(home: Path) -> List[str]:
    """Everything under the Hermes home except Defuzz's own state folder (the state DB lives there)."""
    rels = (str(p.relative_to(home)) for p in home.rglob("*"))
    return sorted(r for r in rels if r.split(os.sep)[0] != "plugin-data")


@pytest.mark.parametrize("kind", ["staged", "parent"])
@pytest.mark.parametrize("point", ["dest-parent", "rename"])
def test_swap_during_the_final_move_never_moves_or_creates_anything_in_a_hermes_home(
    hermes_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch, kind: str, point: str
) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    proposal = _propose(hermes_env)
    before = _home_listing(hermes_env["hermes_home"])
    swapped: Dict[str, Path] = {}
    real_mkdir, real_rename = os.mkdir, os.rename

    def trigger() -> None:
        if not swapped:
            swapped.update(_swap_at(kind, hermes_env, proposal))
            swapped["done"] = Path(".")

    real_make_parent = kit_scaffold._make_pinned_dest_parent

    def mkdir(path, mode=0o777, *, dir_fd=None):
        if point == "dest-parent" and os.fspath(path) == os.fspath(proposal.dest.parent):
            trigger()
        return real_mkdir(path, mode) if dir_fd is None else real_mkdir(path, mode, dir_fd=dir_fd)

    def make_parent(*args, **kwargs):
        # The projects folder is ready (created by handle when missing): swap before the move.
        result = real_make_parent(*args, **kwargs)
        if point == "dest-parent":
            trigger()
        return result

    def rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        if point == "rename" and os.path.basename(os.fspath(dst)) == proposal.dest.name:
            trigger()
        return real_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    try:
        with monkeypatch.context() as m:
            m.setattr(os, "mkdir", mkdir)
            m.setattr(os, "rename", rename)
            m.setattr(kit_scaffold, "_make_pinned_dest_parent", make_parent)
            with pytest.raises(ScaffoldError) as excinfo:
                accept_kit(proposal, register=_register, db_path=state_db_path(), bridge=componentize_bridge)
        assert swapped, "the race window was not reached"
        assert "\n" not in str(excinfo.value)
    finally:
        discard_kit(proposal)
    home = hermes_env["hermes_home"]
    assert not list(home.rglob(".git")), "a repository was created inside the Hermes home"
    after = _home_listing(home)
    added = {"vault", "vault/holder", "vault/holder/MARK"} if kind == "staged" else {
        "unused-" + proposal.slug, "unused-" + proposal.slug + "/unrelated-marker"}
    assert set(after) - set(before) <= added
    if kind == "staged":
        assert (swapped["holder"] / "MARK").read_text(encoding="utf-8") == "retain me"
        assert not proposal.dest.is_symlink()
    else:
        assert not (home / proposal.slug).exists()


def test_final_move_across_filesystems_copies_through_the_pinned_folders(
    hermes_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    proposal = _propose(hermes_env)
    real_rename = os.rename
    refused: List[str] = []

    def rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        if not refused and os.path.basename(os.fspath(dst)) == proposal.dest.name:
            refused.append(os.fspath(src))
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    try:
        with monkeypatch.context() as m:
            m.setattr(os, "rename", rename)
            accept_kit(proposal, register=_register, db_path=state_db_path(), bridge=componentize_bridge)
    finally:
        discard_kit(proposal)
    assert refused
    assert (proposal.dest / ".git").is_dir()
    assert (proposal.dest / "AGENTS.md").is_file()
    for entry in VIDEO_DECLARED_DIRS:
        assert (proposal.dest / entry["dir"]).is_dir()
    assert _leftovers(hermes_env["projects"]) == [proposal.slug]


def test_accept_refuses_a_destination_created_just_before_the_move(
    hermes_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    proposal = _propose(hermes_env)
    real_rename = os.rename
    planted: List[Path] = []

    def rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        if not planted and os.path.basename(os.fspath(dst)) == proposal.dest.name:
            if not proposal.dest.exists():
                proposal.dest.mkdir()
            (proposal.dest / "theirs.txt").write_text("retain me", encoding="utf-8")
            planted.append(proposal.dest)
        return real_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    try:
        with monkeypatch.context() as m:
            m.setattr(os, "rename", rename)
            with pytest.raises((ScaffoldError, OSError)):
                accept_kit(proposal, register=_register, db_path=state_db_path(), bridge=componentize_bridge)
    finally:
        discard_kit(proposal)
    assert planted
    assert sorted(p.name for p in proposal.dest.iterdir()) == ["theirs.txt"]
