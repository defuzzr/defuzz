"""Tests for the go-golden template: metadata, substitution, scaffold accept, own CI, and defuzz lint."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import toolchk  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.agents_md import render_agents_md_files  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.lint_tools import is_generated_lockfile  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.linter import run_lint  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.naming import MAX_NAME_LENGTH  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.scaffolder import accept, discard, propose  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.templates import load_template  # type: ignore[import-not-found]  # noqa: E402
from tests.toolchain_needs import check_tools, need, need_lint_tools  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = REPO_ROOT / "templates" / "go-golden"
TEMPLATE_YAML = TEMPLATE_DIR / "template.yaml"
TMPL_REPO_DIR = TEMPLATE_DIR / "tmpl_prefix"
GO_FLOOR = "1.22"  # go.mod `go 1.22`
GOLANGCI_FLOOR = "2.0.0"  # .golangci.yml `version: "2"`

LEFTOVER_TOKENS = ("tmpl_prefix", "tmpl-prefix", "TMPL_PREFIX", "TmplPrefix")
SCAFFOLD_NAMES = (
    "a",
    "z" * MAX_NAME_LENGTH,
    "probe-svc",
    "a-" * 31 + "ab",
)


def test_go_toolchain_binaries_and_versions_present() -> None:
    """An installed Go / golangci-lint toolchain must meet the template's floors (skips when absent)."""
    need("go", "gofmt", "golangci-lint", "yamllint", "rumdl")

    go_proc = subprocess.run(
        ["go", "version"],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    go_ver = re.search(r"go(\d+(?:\.\d+)+)", go_proc.stdout)
    assert go_ver and not toolchk.version_below(go_ver.group(1), GO_FLOOR), (
        f"Expected Go >= {GO_FLOOR}, got: {go_proc.stdout}"
    )

    lint_proc = subprocess.run(
        ["golangci-lint", "--version"],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    lint_ver = re.search(r"version v?(\d+(?:\.\d+)+)", lint_proc.stdout)
    assert lint_ver and not toolchk.version_below(lint_ver.group(1), GOLANGCI_FLOOR), (
        f"Expected golangci-lint >= {GOLANGCI_FLOOR}, got: {lint_proc.stdout}"
    )


def test_template_metadata_and_contents() -> None:
    assert TEMPLATE_YAML.is_file(), "templates/go-golden/template.yaml must exist"
    data = yaml.safe_load(TEMPLATE_YAML.read_text(encoding="utf-8"))
    assert isinstance(data, dict)

    required_keys = {
        "id",
        "name",
        "summary",
        "kind",
        "layout",
        "languages",
        "tags",
        "needs",
        "placeholder",
        "substitute_in",
        "locked",
        "approved_deps",
        "repos",
        "version_probes",
    }
    assert set(data.keys()) == required_keys
    assert data["id"] == TEMPLATE_DIR.name == "go-golden"
    assert data["kind"] == "service"
    assert data["layout"] == "mono"
    assert data["languages"] == ["go"]
    assert data["needs"] == ["go", "golangci-lint", "gofmt"]
    assert data["placeholder"] == "tmpl_prefix"

    expected_locked = [
        "go.mod",
        ".golangci.yml",
        ".github/workflows/*",
        "xtask/**",
    ]
    assert data["locked"] == expected_locked
    assert data["approved_deps"] == {"go": []}

    spec = load_template(TEMPLATE_DIR)
    assert spec.id == "go-golden"
    assert spec.kind == "service"
    assert spec.layout == "mono"
    assert spec.languages == ("go",)
    assert spec.needs == ("go", "golangci-lint", "gofmt")
    assert spec.placeholder == "tmpl_prefix"
    assert spec.locked == tuple(expected_locked)
    assert dict(spec.approved_deps) == {"go": ()}
    assert len(spec.repos) == 1
    assert spec.repos[0].name == "tmpl_prefix"
    assert spec.repos[0].check is not None
    assert spec.repos[0].check.cmd == ("go", "run", "./xtask", "ci")
    assert spec.repos[0].check.cwd == "."

    expected_files = (
        "go.mod",
        "go.sum",
        ".golangci.yml",
        "TOOLS.lock",
        "README.md",
        "00-INDEX.md",
        "AGENTS.md",
        "COMPONENTS.md",
        "docs/component-boundaries.md",
        ".github/workflows/ci.yml",
        ".gitignore",
        ".worktreeinclude",
        "foundation/foundation.go",
        "foundation/foundation_test.go",
        "domain/domain.go",
        "domain/domain_test.go",
        "adapters/adapters.go",
        "adapters/adapters_test.go",
        "apps/cli/main.go",
        "apps/cli/main_test.go",
        "xtask/main.go",
        "xtask/main_test.go",
    )
    for rel in expected_files:
        assert (TMPL_REPO_DIR / rel).is_file(), f"Missing template file {rel}"

    loaded_lock = toolchk.load_lock(TMPL_REPO_DIR / "TOOLS.lock")
    assert set(loaded_lock["tools"].keys()) == {"go", "golangci-lint"}
    for tool_name, floor in (("go", GO_FLOOR), ("golangci-lint", GOLANGCI_FLOOR)):
        entry = loaded_lock["tools"][tool_name]
        assert entry["source"] == "auto" and entry["minimum"] == floor and entry["version"] == floor

    ci_workflow = yaml.safe_load(
        (TMPL_REPO_DIR / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    assert isinstance(ci_workflow, dict)
    ci_steps = ci_workflow["jobs"]["ci"]["steps"]
    assert isinstance(ci_steps, list)
    go_ci_ver = None
    lint_ci_ver = None

    setup_go_idx = None
    install_lint_idx = None
    xtask_idx = None
    for idx, step in enumerate(ci_steps):
        uses = str(step.get("uses", ""))
        run_cmd = str(step.get("run", ""))
        with_cfg = step.get("with") or {}
        if uses.startswith("actions/setup-go@"):
            go_ci_ver = str(with_cfg.get("go-version"))
            setup_go_idx = idx
        if uses.startswith("golangci/golangci-lint-action@"):
            lint_ci_ver = str(with_cfg.get("version")).lstrip("v")
            install_lint_idx = idx
        elif "golangci-lint" in run_cmd:
            lint_m = re.search(r"golangci-lint@v(\d+(?:\.\d+)+)", run_cmd)
            if lint_m:
                lint_ci_ver = lint_m.group(1)
                install_lint_idx = idx
        if "go run ./xtask ci" in run_cmd:
            xtask_idx = idx

    assert setup_go_idx is not None, "CI workflow must set up Go"
    assert install_lint_idx is not None, "CI workflow must install a pinned golangci-lint"
    assert go_ci_ver and not toolchk.version_below(go_ci_ver, GO_FLOOR), go_ci_ver
    assert lint_ci_ver and not toolchk.version_below(lint_ci_ver, GOLANGCI_FLOOR), lint_ci_ver
    assert xtask_idx is not None, "CI workflow must run `go run ./xtask ci`"
    assert setup_go_idx < install_lint_idx < xtask_idx, (
        f"Expected setup-go ({setup_go_idx}) < install golangci-lint ({install_lint_idx}) < xtask ({xtask_idx})"
    )

    for path in TMPL_REPO_DIR.rglob("*"):
        if path.is_file() and path.name != "README.md":
            content = path.read_text(encoding="utf-8")
            assert "go-golden" not in content, f"found 'go-golden' in {path}"
            assert "go_golden" not in content, f"found 'go_golden' in {path}"

    # The installed toolchain passes the shipped lock's preflight (needs the real tools).
    need("go", "golangci-lint")
    preflight = toolchk.check(["go", "golangci-lint"], loaded_lock, TMPL_REPO_DIR)
    assert preflight["ok"] is True, preflight


def test_propose_substitutes_all_four_placeholder_forms(tmp_path: Path) -> None:
    spec = load_template(TEMPLATE_DIR)
    proposal = propose(
        spec,
        "Probe Svc",
        {"building": spec.kind, "layout": "mono", "languages": ["go"]},
        dest_root=tmp_path / "dest",
        staging_parent=tmp_path / "staging",
    )
    try:
        assert proposal.slug == "probe-svc"
        assert proposal.forms.kebab == "probe-svc"
        assert proposal.forms.snake == "probe_svc"
        assert proposal.forms.screaming == "PROBE_SVC"
        assert proposal.forms.pascal == "ProbeSvc"

        staged = proposal.repos[0].staged
        foundation_go = (staged / "foundation" / "foundation.go").read_text(encoding="utf-8")
        assert "probe-svc" in foundation_go
        assert "probe_svc" in foundation_go
        assert "PROBE_SVC" in foundation_go
        assert "ProbeSvc" in foundation_go

        index_md = (staged / "00-INDEX.md").read_text(encoding="utf-8")
        assert "probe-svc" in index_md
        assert "probe_svc" in index_md
        assert "PROBE_SVC" in index_md
        assert "ProbeSvc" in index_md

        for path in staged.rglob("*"):
            rel_str = path.relative_to(staged).as_posix()
            for tok in LEFTOVER_TOKENS:
                assert tok not in rel_str, f"leftover {tok!r} in path {rel_str}"
            if path.is_file():
                txt = path.read_text(encoding="utf-8")
                for tok in LEFTOVER_TOKENS:
                    assert tok not in txt, f"leftover {tok!r} in file {rel_str}"
    finally:
        discard(proposal)


@pytest.mark.parametrize(
    "name",
    SCAFFOLD_NAMES,
    ids=lambda n: f"len-{len(n)}-{n[:16]}",
)
def test_scaffold_accept_own_ci_and_defuzz_lint_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONPATH"):
        monkeypatch.delenv(key, raising=False)

    assert len(SCAFFOLD_NAMES[0]) == 1
    assert len(SCAFFOLD_NAMES[1]) == MAX_NAME_LENGTH
    assert len(SCAFFOLD_NAMES[3]) == MAX_NAME_LENGTH

    spec = load_template(TEMPLATE_DIR)
    need(*check_tools(spec))
    proposal = propose(
        spec,
        name,
        {"building": spec.kind, "layout": "mono", "languages": list(spec.languages)},
        dest_root=tmp_path / "projects",
        staging_parent=tmp_path / "staging",
    )
    db_path = tmp_path / "state.db"
    result = accept(
        proposal,
        register=lambda *_: json.dumps({"success": True, "id": "test-go-project"}),
        db_path=db_path,
        timeout_s=300,
    )
    assert result.repos[0]["check"] == "ok", result.repos[0]
    repo = Path(result.repos[0]["path"])
    assert (repo / ".adopt" / "rules.json").is_file()
    assert (repo / "AGENTS.md").is_file()
    assert (repo / "TOOLS.lock").is_file()

    assert spec.repos[0].check is not None
    check_cmd = list(spec.repos[0].check.cmd)
    proc = subprocess.run(
        check_cmd,
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, f"{check_cmd}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"

    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    assert status.stdout == "", f"Expected clean git tree, got:\n{status.stdout}"

    report = run_lint(repo, env=dict(os.environ), db_path=db_path)
    need_lint_tools(report)
    assert report["ok"] is True, report
    assert report["status"] == "clean", report
    assert report["findings"] == [], report
    assert report["tools_missing"] == [], report
    assert report["tool_errors"] == [], report
    assert "go.sum" in report["skipped_generated"], report

    tools_by_name = {entry["tool"]: entry["status"] for entry in report["tool_statuses"]}
    for expected_tool in ("gofmt", "go-vet", "golangci-lint", "yamllint", "rumdl"):
        assert tools_by_name.get(expected_tool) == "clean", (
            f"Expected {expected_tool} to run clean, got tool_statuses={report['tool_statuses']}"
        )


NAME_LENGTHS = (
    range(1, MAX_NAME_LENGTH + 1)
    if os.environ.get("ADOPT_ALL_NAME_LENGTHS") == "1"
    else (1, 2, 59, 60, 61, MAX_NAME_LENGTH - 1, MAX_NAME_LENGTH)
)
BOUNDARY_NAMES = [
    *("a" * length for length in NAME_LENGTHS),
    "northstar",
    "acceptance-ts",
    "my-app-2",
    "c2-python-final",
    "z" * MAX_NAME_LENGTH,
    "a-" * 31 + "ab",
]


@pytest.mark.parametrize(
    "name",
    BOUNDARY_NAMES,
    ids=lambda n: f"length-{len(n)}-{n[:15]}",
)
def test_scaffold_name_lengths_pass_gofmt_yamllint_and_rumdl(
    tmp_path: Path,
    name: str,
) -> None:
    need("yamllint", "rumdl", "gofmt")
    spec = load_template(TEMPLATE_DIR)
    proposal = propose(
        spec,
        name,
        {"building": spec.kind, "layout": "mono", "languages": list(spec.languages)},
        dest_root=tmp_path / "projects",
        staging_parent=tmp_path / "staging",
    )
    try:
        root = proposal.repos[0].staged
        for relative, content in render_agents_md_files(
            project_slug=name,
            declared_dirs={},
            placement_rules=[],
        ).items():
            target = root / relative
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")

        for tool, args, suffixes in (
            ("yamllint", ["--strict"], {".yaml", ".yml"}),
            ("rumdl", ["check", "--no-cache"], {".md"}),
        ):
            executable = shutil.which(tool)
            assert executable is not None, f"Install {tool} for scaffold lint regression coverage"
            files = sorted(
                str(path.relative_to(root))
                for path in root.rglob("*")
                if path.is_file()
                and path.suffix in suffixes
                and not is_generated_lockfile(str(path))
            )
            assert files, f"Expected files matching {suffixes} in {root}"
            proc = subprocess.run(
                [executable, *args, *files],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            assert proc.returncode == 0, f"{tool} failed:\n{proc.stdout}\n{proc.stderr}"

        gofmt = shutil.which("gofmt")
        assert gofmt is not None, "Install Go with gofmt"
        fmt_proc = subprocess.run(
            [gofmt, "-e", "-l", "."],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert fmt_proc.returncode == 0, fmt_proc.stdout + fmt_proc.stderr
        assert fmt_proc.stdout.strip() == "", f"Unformatted Go files:\n{fmt_proc.stdout}"
    finally:
        discard(proposal)

