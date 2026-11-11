"""Template kit tests: data-only template discovery, version_probes, nested lockfiles, interface freeze, and fail-closed validation."""

from __future__ import annotations

import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import scaffolder, tool_detect, tool_seed, toolchk  # noqa: E402
from hermes_plugins.defuzz.templates import (  # noqa: E402
    FormatCmdSpec,
    TemplateError,
    _ToolNeedStr,
    format_check_commands,
    load_template,
    load_templates,
    run_scaffold_format_checks,
)
from tests import (  # noqa: E402
    test_accepted_scaffold_ci,
    test_matcher,
    test_scaffold_name_lengths,
    test_template_componentize,
    test_scaffold_rules_context,
)
from tests import toolchain_needs  # noqa: E402
from tests.toolchain_needs import fake_toolchain, need, write_fake_tool  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
# The acceptance harness lives outside the plugin payload; DEFUZZ_E2E_HARNESS names its location.
_E2E_HARNESS = os.environ.get("DEFUZZ_E2E_HARNESS", "")
E2E_HARNESS_ROOT = Path(_E2E_HARNESS) if _E2E_HARNESS else Path("/nonexistent-e2e-harness")


def _require_harness() -> None:
    if not (E2E_HARNESS_ROOT / "run.py").is_file():
        pytest.skip("set DEFUZZ_E2E_HARNESS to the e2e acceptance harness directory")


def _write_dummy_template(
    templates_dir: Path,
    template_id: str = "dummy-golden",
    *,
    kind: str = "tool",
    layout: str = "mono",
    languages: list[str] | None = None,
    needs: list[str] | None = None,
    version_probes: dict[str, Any] | None = None,
    extra_check_keys: dict[str, Any] | None = None,
    with_lockfile: bool = True,
    lockfile_rel: str = "uv.lock",
    lockfiles_field: list[str] | None = None,
) -> Path:
    """Create a complete data-only template descriptor and tmpl_prefix tree in templates_dir."""
    langs = languages if languages is not None else ["python"]
    req_needs = needs if needs is not None else ["go", "uv"]
    tdir = templates_dir / template_id
    repo_dir = tdir / "tmpl_prefix"
    (repo_dir / "src" / "tmpl_prefix").mkdir(parents=True, exist_ok=True)
    (repo_dir / "docs").mkdir(parents=True, exist_ok=True)

    (repo_dir / "README.md").write_text(
        "# TmplPrefix\n\nDummy golden workspace:\n\n`tmpl-prefix`\n",
        encoding="utf-8",
    )
    (repo_dir / "COMPONENTS.md").write_text(
        "# Component index\n\nRecord each reusable public API, its purpose, owning module, inputs and return\ncontract here.\n",
        encoding="utf-8",
    )
    (repo_dir / "docs" / "component-boundaries.md").write_text(
        "# Component boundaries\n\nKeep runners thin and record APIs in COMPONENTS.md.\n",
        encoding="utf-8",
    )
    (repo_dir / "pyproject.toml").write_text(
        '[project]\nname = "tmpl-prefix"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n\n'
        '[tool.ruff]\nline-length = 100\n',
        encoding="utf-8",
    )
    (repo_dir / "src" / "tmpl_prefix" / "__init__.py").write_text(
        '"""Package for tmpl_prefix."""\n\nPREFIX = (\n    # Keep multiline layout stable across 1..64 project names.\n    "tmpl_prefix"\n)\n',
        encoding="utf-8",
    )
    substitute_in = ["**/*.py", "**/*.toml", "**/*.md"]
    if with_lockfile:
        lf_path = repo_dir / lockfile_rel
        lf_path.parent.mkdir(parents=True, exist_ok=True)
        lf_path.write_text(
            'version = 1\nrequires-python = ">=3.11"\n',
            encoding="utf-8",
        )
        substitute_in.append(lockfile_rel)

    check_dict: dict[str, Any] = {
        "cmd": ["python3", "-c", "import pathlib; assert pathlib.Path('README.md').is_file()"],
        "cwd": ".",
        "format_cmds": [
            ["ruff", "format", "--check", "."],
            ["ruff", "check", "."],
        ],
    }
    if extra_check_keys:
        check_dict.update(extra_check_keys)

    descriptor: dict[str, Any] = {
        "id": template_id,
        "name": f"Dummy {template_id}",
        "summary": "Synthetic data-only template descriptor for template-kit acceptance.",
        "kind": kind,
        "layout": layout,
        "languages": langs,
        "needs": req_needs,
        "placeholder": "tmpl_prefix",
        "substitute_in": substitute_in,
        "repos": [{"name": "tmpl_prefix", "check": check_dict}],
    }
    if lockfiles_field is not None:
        descriptor["lockfiles"] = lockfiles_field
    if version_probes is not None:
        descriptor["version_probes"] = version_probes
    elif "go" in req_needs:
        descriptor["version_probes"] = {"go": ["go", "version"]}

    import yaml

    (tdir / "template.yaml").write_text(
        yaml.safe_dump(descriptor, sort_keys=False),
        encoding="utf-8",
    )
    return tdir


def _load_e2e_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Any]:
    """Load the acceptance harness run.py and matrix.py isolated beneath its directory."""
    _require_harness()
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    e2e_base = E2E_HARNESS_ROOT / f"selftest-kit-{os.getpid()}"
    e2e_base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DEFUZZ_E2E_BASE", str(e2e_base))
    monkeypatch.setenv("DEFUZZ_CANDIDATE", head)
    monkeypatch.syspath_prepend(str(E2E_HARNESS_ROOT))

    run_spec = importlib.util.spec_from_file_location("run", E2E_HARNESS_ROOT / "run.py")
    assert run_spec and run_spec.loader
    run_mod = importlib.util.module_from_spec(run_spec)
    monkeypatch.setitem(sys.modules, "run", run_mod)
    run_spec.loader.exec_module(run_mod)

    matrix_spec = importlib.util.spec_from_file_location("matrix", E2E_HARNESS_ROOT / "matrix.py")
    assert matrix_spec and matrix_spec.loader
    matrix_mod = importlib.util.module_from_spec(matrix_spec)
    monkeypatch.setitem(sys.modules, "matrix", matrix_mod)
    matrix_spec.loader.exec_module(matrix_mod)
    return run_mod, matrix_mod


def test_dummy_descriptor_discovered_by_every_generic_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dummy template in tmp is discovered by every generic test matrix and the acceptance harness with zero code edits."""
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    _write_dummy_template(
        templates_dir,
        "dummy-golden",
        kind="tool",
        layout="mono",
        languages=["python"],
        needs=["go", "uv"],
        version_probes={"go": ["go", "version"]},
        extra_check_keys={
            "extra_cmds": [["python3", "-c", "import sys; assert sys.version_info[0] == 3"]],
        },
    )
    _write_dummy_template(
        templates_dir,
        "dummy-rust",
        kind="app",
        layout="mono",
        languages=["rust"],
        needs=["cargo"],
        version_probes=None,
        extra_check_keys={
            "format_cmds": [["python3", "-c", "print('ok')"]],
        },
        with_lockfile=False,
    )

    # 1. Core loader discovery + version_probes + generated_lockfiles
    specs = load_templates(templates_dir)
    assert [s.id for s in specs] == ["dummy-golden", "dummy-rust"]
    by_id = {s.id: s for s in specs}
    assert dict(by_id["dummy-golden"].version_probes) == {"go": ("go", "version")}
    assert by_id["dummy-golden"].tool_version_argv("go") == ("go", "version")
    assert by_id["dummy-golden"].tool_version_argv("uv") == ("uv", "--version")
    assert by_id["dummy-golden"].generated_lockfiles() == ("uv.lock",)
    assert by_id["dummy-rust"].generated_lockfiles() == ()

    # 2. Every generic test module discovers both dummy templates with zero code edits
    for mod in (
        test_accepted_scaffold_ci,
        test_scaffold_name_lengths,
        test_template_componentize,
        test_scaffold_rules_context,
    ):
        assert mod.discover_template_ids(templates_dir) == ["dummy-golden", "dummy-rust"]

    # 3. Execute each generic test body against the dummy descriptor. The dummies only
    # declare go, uv and cargo (their checks run python3), so stand-ins answer for those;
    # the formatters and linters the bodies run stay real.
    with fake_toolchain(tmp_path / "fake-bin", ("go", "uv", "cargo")):
        test_scaffold_name_lengths.test_scaffold_name_passes_format_and_check(
            tmp_path / "nl-min", "dummy-golden", "a", templates_dir=templates_dir
        )
        test_scaffold_name_lengths.test_scaffold_name_passes_format_and_check(
            tmp_path / "nl-max", "dummy-golden", "z" * 64, templates_dir=templates_dir
        )
        test_scaffold_name_lengths.test_scaffold_name_passes_format_and_check(
            tmp_path / "nl-rust", "dummy-rust", "a", templates_dir=templates_dir
        )

        test_template_componentize.test_componentize_scaffold_contract(
            tmp_path / "comp", "dummy-golden", templates_dir=templates_dir
        )
        test_scaffold_rules_context.test_golden_scaffold_rules_are_committed_and_reproducible(
            tmp_path / "rules", "dummy-golden", templates_dir=templates_dir
        )
        test_accepted_scaffold_ci.test_accepted_scaffold_passes_own_ci(
            tmp_path / "acc", monkeypatch, "dummy-golden", "northstar", templates_dir=templates_dir
        )

    matcher_case = test_matcher.TestMatcher()
    matcher_case.setUp()
    matcher_case.test_python_app_mono_does_not_offer_rust_golden_in_best_matches(
        templates_dir=templates_dir
    )

    # 4. The acceptance harness matrix.py discovers dummy templates, extra_cmds, and version_probes without code edits
    run_mod, matrix_mod = _load_e2e_modules(tmp_path, monkeypatch)
    try:
        discovered = matrix_mod.discover_templates(
            templates_dir, plugin_dir=REPO_ROOT
        )
        assert [d["template"] for d in discovered] == ["dummy-golden", "dummy-rust"]
        dg = discovered[0]
        assert dg["kind"] == "tool"
        assert dg["layout"] == "mono"
        assert dg["languages"] == ["python"]
        assert dg["needs"] == ["go", "uv"]
        assert dg["extra_cmds"] == [["python3", "-c", "import sys; assert sys.version_info[0] == 3"]]
        assert len(dg["ci_cmds"]) == 2
        assert dg["version_probes"]["go"] == ["go", "version"]
        assert dg["version_probes"]["uv"] == ["uv", "--version"]
        assert dg["lockfiles"] == ["uv.lock"]
        probes = matrix_mod.version_probes_for_templates(discovered)
        assert probes["go"] == ["go", "version"]
        assert probes["uv"] == ["uv", "--version"]
        assert probes["cargo"] == ["cargo", "--version"]

        # Typed file probe is carried through TemplateSpec, discover_templates, and version_probes_for_templates,
        # and executed generically by run_version_probe without any gofmt special case in matrix.py.
        assert "gofmt" not in (E2E_HARNESS_ROOT / "matrix.py").read_text(encoding="utf-8")
        gofmt_file_probe = {
            "probe": "file",
            "file": "go.mod",
            "regex": r"^\s*go\s+(\d+(?:\.\d+)*)",
        }
        tdir_go = _write_dummy_template(
            templates_dir,
            "dummy-go",
            kind="service",
            layout="mono",
            languages=["go"],
            needs=["go", "gofmt"],
            version_probes={
                "go": ["go", "version"],
                "gofmt": gofmt_file_probe,
            },
            extra_check_keys={
                "format_cmds": [["python3", "-c", "print('ok')"]],
            },
            with_lockfile=False,
        )
        (tdir_go / "tmpl_prefix" / "go.mod").write_text(
            "module example.com/dummy\n\ngo 1.27.3\n", encoding="utf-8"
        )
        go_spec = load_template(tdir_go)
        assert go_spec.tool_version_argv("gofmt") == gofmt_file_probe
        assert go_spec.tool_version_probe("gofmt") == gofmt_file_probe

        discovered_with_go = matrix_mod.discover_templates(
            templates_dir, plugin_dir=REPO_ROOT
        )
        dgo = next(d for d in discovered_with_go if d["template"] == "dummy-go")
        assert dgo["version_probes"]["gofmt"] == gofmt_file_probe
        all_probes = matrix_mod.version_probes_for_templates(discovered_with_go)
        assert all_probes["gofmt"] == gofmt_file_probe

        probe_receipt = matrix_mod.run_version_probe(
            "gofmt",
            all_probes["gofmt"],
            cwd=run_mod.base,
            items=discovered_with_go,
        )
        assert probe_receipt["exit_code"] == 0
        assert probe_receipt["version"] == "1.27.3"
        assert (run_mod.base / "logs/version-gofmt.stdout").read_text(encoding="utf-8").strip() == "1.27.3"

        bad_probe_receipt = matrix_mod.run_version_probe(
            "gofmt-bad",
            {"probe": "file", "file": "missing-go.mod", "regex": r"^\s*go\s+(\d+(?:\.\d+)*)"},
            cwd=run_mod.base,
            items=discovered_with_go,
        )
        assert bad_probe_receipt["exit_code"] != 0

        # Fail closed when plugin_dir lacks templates.py (no fallback to another checkout)
        with pytest.raises(AssertionError, match="Missing templates.py"):
            matrix_mod.discover_templates(templates_dir, plugin_dir=tmp_path / "nonexistent-plugin")
    finally:
        shutil.rmtree(run_mod.base, ignore_errors=True)


def test_shipped_descriptors_declare_format_and_extra_cmds_as_pure_data() -> None:
    """Shipped python/ts/rust descriptors carry format_cmds and rust extra_cmds as pure YAML data."""
    specs = {s.id: s for s in load_templates(REPO_ROOT / "templates")}
    assert set(specs.keys()) >= {"python-golden", "ts-node-golden", "rust-golden"}

    py_check = specs["python-golden"].repos[0].check
    assert py_check is not None
    assert py_check.format_cmds == (
        ("ruff", "format", "--check", "."),
        ("ruff", "check", "."),
    )

    ts_check = specs["ts-node-golden"].repos[0].check
    assert ts_check is not None
    assert ts_check.format_cmds == (("biome", "ci", "."),)

    rust_check = specs["rust-golden"].repos[0].check
    assert rust_check is not None
    assert rust_check.extra_cmds == (("cargo", "check", "--workspace", "--locked"),)
    assert rust_check.ci_commands() == (
        ("cargo", "xtask", "ci"),
        ("cargo", "check", "--workspace", "--locked"),
    )
    assert rust_check.format_cmds == (("cargo", "fmt", "--all", "--check"),)


def _xtask_sources(repo_dir: Path) -> str:
    """Text of the files under a template repo whose path names its xtask."""
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(repo_dir.rglob("*"))
        if path.is_file() and "xtask" in path.relative_to(repo_dir).as_posix()
    )


def test_toolchain_needs_tables_match_template_files() -> None:
    """tests/toolchain_needs.py names exactly the tools each bundled template's files call for.

    Check tools: template.yaml `needs`, then the other command-probed tools TOOLS.lock is
    seeded with at creation (tool_detect on the template tree plus a shipped TOOLS.lock),
    then the check, extra and prepare commands; anything after that must be a program the
    template's xtask names in quotes. Format tools: exactly what
    templates.format_check_commands looks up, in its order.
    """
    specs = {s.id: s for s in load_templates(REPO_ROOT / "templates")}
    assert set(toolchain_needs.TEMPLATE_CHECK_TOOLS) == set(specs)
    assert set(toolchain_needs.TEMPLATE_FORMAT_TOOLS) == set(specs)
    for template_id, spec in sorted(specs.items()):
        repo_dir = spec.root / spec.repos[0].name
        check = spec.repos[0].check
        assert check is not None, template_id

        derived = [n for n in spec.needs if n.strip()]
        seeded = tool_detect.detect_tools(
            repo_dir, chosen="2026-01-01", event="table check", template_needs=spec.needs
        )
        lock_file = repo_dir / "TOOLS.lock"
        if lock_file.is_file():
            seeded.update(toolchk.load_lock(lock_file)["tools"])
        for name in sorted(seeded):
            entry = seeded[name]
            if entry.get("probe") == "command":
                derived.append(entry["argv"][0])
        commands = [*check.ci_commands(), *([check.prepare] if check.prepare else [])]
        derived.extend(cmd[0] for cmd in commands)
        derived = list(dict.fromkeys(derived))

        table = toolchain_needs.TEMPLATE_CHECK_TOOLS[template_id]
        assert list(table[: len(derived)]) == derived, (template_id, table, derived)
        sources = _xtask_sources(repo_dir)
        for extra in table[len(derived):]:
            assert f'"{extra}"' in sources, f"{template_id}: xtask never names {extra!r}"

        expected_format = [n for n in spec.needs if n.strip()]
        expected_format.extend(toolchain_needs.SCAFFOLD_LINT_TOOLS)
        expected_format.extend(getattr(entry, "cmd", entry)[0] for entry in check.format_cmds)
        assert toolchain_needs.TEMPLATE_FORMAT_TOOLS[template_id] == tuple(
            dict.fromkeys(expected_format)
        ), template_id
        assert toolchain_needs.check_tools(spec) == table
        assert toolchain_needs.format_tools(spec) == toolchain_needs.TEMPLATE_FORMAT_TOOLS[template_id]


def test_toolchain_needs_skip_reason_and_stand_in_tools(tmp_path: Path) -> None:
    """need() skips naming the first absent tool; fake_toolchain answers a probe and restores PATH."""
    with pytest.raises(pytest.skip.Exception, match="^definitely-missing-tool-xyz not installed$"):
        need("sh", "definitely-missing-tool-xyz", "also-missing-tool-xyz")
    need("sh")  # present: no skip
    before = os.environ.get("PATH")
    with fake_toolchain(tmp_path / "bin", ("definitely-missing-tool-xyz",)) as bin_dir:
        need("definitely-missing-tool-xyz")
        out = subprocess.run(
            ["definitely-missing-tool-xyz", "check"], capture_output=True, text=True, check=True
        ).stdout
        assert toolchk.VERSION_RE.search(out).group(0) == toolchain_needs.FAKE_TOOL_VERSION
        assert shutil.which("definitely-missing-tool-xyz") == str(bin_dir / "definitely-missing-tool-xyz")
    assert os.environ.get("PATH") == before
    assert shutil.which("definitely-missing-tool-xyz") is None
    with pytest.raises(pytest.skip.Exception, match="^taplo not installed$"):
        toolchain_needs.need_lint_tools({
            "tools_missing": ["taplo"],
            "tool_errors": [{"tool": "taplo", "mode": "pre", "status": "not_installed",
                             "message": "tool taplo is not installed (missing binary: taplo)"}],
        })
    toolchain_needs.need_lint_tools({"tools_missing": [], "tool_errors": []})  # nothing missing: no skip


def test_format_cmd_spec_mapping_with_suffixes_and_empty_stdout(tmp_path: Path) -> None:
    """FormatCmdSpec dict entries support suffixes, globs, and require_empty_stdout without language tables."""
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    tdir = _write_dummy_template(
        templates_dir,
        "fmt-dict-tmpl",
        languages=["customlang"],
        needs=["python3"],
        version_probes=None,
        extra_check_keys={
            "format_cmds": [
                {
                    "cmd": ["python3", "-c", "import sys; assert any(a.endswith('.py') for a in sys.argv[1:])"],
                    "suffixes": [".py"],
                    "require_empty_stdout": True,
                }
            ]
        },
    )
    spec = load_template(tdir)
    assert spec.repos[0].check is not None
    fmt_entry = spec.repos[0].check.format_cmds[0]
    assert isinstance(fmt_entry, FormatCmdSpec)
    assert fmt_entry.suffixes == (".py",)
    assert fmt_entry.require_empty_stdout is True

    repo_root = tdir / "tmpl_prefix"
    need("python3", *toolchain_needs.SCAFFOLD_LINT_TOOLS)  # format_check_commands runs the real linters
    cmds = format_check_commands(spec, repo_root)
    assert any(req_empty for _cmd, req_empty in cmds)
    run_scaffold_format_checks(spec, repo_root)


def test_nested_generated_lockfiles_preserve_relative_paths(tmp_path: Path) -> None:
    """substitute_in: ['nested/uv.lock'] yields only existing nested relative paths, never bare basenames."""
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    tdir = _write_dummy_template(
        templates_dir,
        "nested-lock-tmpl",
        needs=["uv"],
        version_probes=None,
        with_lockfile=True,
        lockfile_rel="nested/uv.lock",
    )
    spec = load_template(tdir)
    assert spec.generated_lockfiles() == ("nested/uv.lock",)
    assert "uv.lock" not in spec.generated_lockfiles()

    # Non-existent declared lockfile in substitute_in is not fabricated when repo_root exists
    tdir_missing = _write_dummy_template(
        templates_dir,
        "missing-nested-lock",
        needs=["uv"],
        version_probes=None,
        with_lockfile=False,
        lockfiles_field=["nested/uv.lock"],
    )
    spec_missing = load_template(tdir_missing)
    assert spec_missing.generated_lockfiles() == ()


def test_public_signatures_frozen_for_seed_lock_and_detect_tools() -> None:
    """seed_lock and detect_tools keep their exact public parameter lists without new public kwargs."""
    seed_params = list(inspect.signature(tool_seed.seed_lock).parameters.keys())
    assert seed_params == ["project_root", "event", "template_needs", "today"]

    detect_params = list(inspect.signature(tool_detect.detect_tools).parameters.keys())
    assert detect_params == ["project_root", "chosen", "event", "template_needs"]


@pytest.mark.parametrize(
    ("case_name", "needs", "version_probes", "check_override", "expected_err"),
    [
        ("probes-not-dict", ["go"], ["go", "version"], None, "version_probes"),
        ("probes-empty-dict", ["go"], {}, None, "version_probes"),
        ("probes-unlisted-need", ["uv"], {"go": ["go", "version"]}, None, "version_probes.go"),
        ("probes-bad-tool-name", ["../evil"], {"../evil": ["evil", "--version"]}, None, "version_probes"),
        ("probes-single-arg", ["go"], {"go": ["go"]}, None, "version_probes.go"),
        ("probes-empty-argv", ["go"], {"go": []}, None, "version_probes.go"),
        ("probes-non-str-arg", ["go"], {"go": ["go", 123]}, None, "version_probes.go"),
        ("probes-empty-str-arg", ["go"], {"go": ["go", ""]}, None, "version_probes.go"),
        ("probes-whitespace-arg", ["go"], {"go": ["go", " version "]}, None, "version_probes.go"),
        ("probes-path-in-exe", ["go"], {"go": ["/usr/bin/go", "version"]}, None, "version_probes.go"),
        ("probes-exe-mismatch", ["go"], {"go": ["cargo", "--version"]}, None, "version_probes.go"),
        ("probes-disallowed-flag", ["go"], {"go": ["go", "env"]}, None, "version_probes.go"),
        (
            "probes-dict-unknown-key",
            ["go"],
            {"go": {"argv": ["go", "version"], "extra": 1}},
            None,
            "version_probes.go.extra",
        ),
        ("probes-dict-missing-argv", ["go"], {"go": {}}, None, "version_probes.go.argv"),
        ("probes-file-no-key-or-regex", ["gofmt"], {"gofmt": {"probe": "file", "file": "go.mod"}}, None, "version_probes.gofmt"),
        ("extra-cmds-empty", ["uv"], None, {"extra_cmds": []}, "repos.check.extra_cmds"),
        ("extra-cmds-bad-item", ["uv"], None, {"extra_cmds": [[]]}, "repos.check.extra_cmds[0]"),
        ("format-cmds-empty", ["uv"], None, {"format_cmds": []}, "repos.check.format_cmds"),
        ("format-cmds-bad-dict", ["uv"], None, {"format_cmds": [{"unknown": 1}]}, "repos.check.format_cmds[0]"),
    ],
)
def test_malformed_descriptors_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_name: str,
    needs: list[str],
    version_probes: Any,
    check_override: dict[str, Any] | None,
    expected_err: str,
) -> None:
    """Malformed template.yaml descriptors and version_probes fail closed in load_template and load_templates."""
    templates_dir = tmp_path / case_name
    templates_dir.mkdir()
    tdir = _write_dummy_template(
        templates_dir,
        case_name,
        needs=needs,
        version_probes=version_probes,
        extra_check_keys=check_override,
    )
    if version_probes == {}:
        import yaml

        data = yaml.safe_load((tdir / "template.yaml").read_text(encoding="utf-8"))
        data["version_probes"] = {}
        (tdir / "template.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    with pytest.raises(TemplateError) as exc_info:
        load_template(tdir)
    assert expected_err in str(exc_info.value)

    with pytest.raises(TemplateError):
        load_templates(templates_dir)


def test_tool_detect_and_seed_lock_version_probes_and_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """tool_detect and tool_seed use version_probes carried on _ToolNeedStr and fail closed on malformed probes."""
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    tdir = _write_dummy_template(
        templates_dir,
        "probe-demo",
        needs=["go", "gofmt", "uv"],
        version_probes={
            "go": ["go", "version"],
            "gofmt": {
                "probe": "file",
                "file": "go.mod",
                "regex": r"^\s*go\s+(\d+(?:\.\d+)*)",
            },
        },
    )
    spec = load_template(tdir)
    proposal = scaffolder.propose(
        spec,
        "Probe Demo",
        {"building": "tool", "layout": "mono", "languages": ["python"]},
        dest_root=tmp_path / "dest",
        staging_parent=tmp_path / "staging",
    )
    # The command probe must record what `go version` reports, whatever Go the machine
    # has. A stand-in `go` first on PATH reports a version that differs from go.mod, so the
    # lock shows each probe read its own source.
    fake_bin = tmp_path / "fake-go-bin"
    fake_bin.mkdir()
    fake_go = fake_bin / "go"
    fake_go.write_text(
        "#!/bin/sh\n[ \"$1\" = version ] || exit 2\necho 'go version go1.26.10 linux/amd64'\n",
        encoding="utf-8",
    )
    fake_go.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    # uv is only probed here (its version is not checked), so a stand-in answers for it.
    write_fake_tool(fake_bin, "uv")
    try:
        staged = proposal.repos[0].staged
        (staged / "go.mod").write_text("module example.com/demo\n\ngo 1.27.3\n", encoding="utf-8")
        detected = tool_detect.detect_tools(
            staged,
            chosen="2026-11-09",
            event="project creation",
            template_needs=proposal.needs,
        )
        assert detected["go"]["probe"] == "command"
        assert detected["go"]["argv"] == ["go", "version"]
        assert detected["gofmt"]["probe"] == "file"
        assert detected["gofmt"]["file"] == "go.mod"
        assert detected["uv"]["argv"] == ["uv", "--version"]

        # Seed lock with real probes on staged repo
        summary = tool_seed.seed_lock(
            staged,
            event="project creation",
            template_needs=proposal.needs,
            today="2026-11-09",
        )
        assert summary["probe_failed"] == {}
        loaded = toolchk.load_lock(staged / "TOOLS.lock")
        assert loaded["tools"]["go"]["version"] == "1.26.10"
        assert loaded["tools"]["gofmt"]["version"] == "1.27.3"
    finally:
        scaffolder.discard(proposal)

    # Malformed version_probe attached to _ToolNeedStr fails closed in detect_tools and seed_lock
    with pytest.raises(ValueError, match="version probe"):
        tool_detect.detect_tools(
            tmp_path,
            chosen="2026-11-09",
            event="project creation",
            template_needs=[_ToolNeedStr("go", ("go", "--evil"))],
        )
    with pytest.raises(ValueError, match="version probe"):
        tool_seed.seed_lock(
            tmp_path,
            event="project creation",
            template_needs=[_ToolNeedStr("go", ("/usr/bin/go", "version"))],
        )


def test_missing_toolchain_fails_closed_never_skips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The product's format check fails closed on a missing tool; the generic CI test skips naming it.

    templates.run_scaffold_format_checks raises AssertionError. The test-suite body
    test_accepted_scaffold_passes_own_ci skips with "<tool> not installed" instead, so a
    machine without a template's toolchain reports a skip with the reason, not a failure.
    """
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    tdir = _write_dummy_template(
        templates_dir,
        "missing-tool-tmpl",
        needs=["definitely-missing-toolchain-xyz"],
        version_probes={"definitely-missing-toolchain-xyz": ["definitely-missing-toolchain-xyz", "--version"]},
    )
    spec = load_template(tdir)
    proposal = scaffolder.propose(
        spec,
        "Missing Tool",
        {"building": "tool", "layout": "mono", "languages": ["python"]},
        dest_root=tmp_path / "dest",
        staging_parent=tmp_path / "staging",
    )
    try:
        with pytest.raises(AssertionError, match="definitely-missing-toolchain-xyz"):
            run_scaffold_format_checks(spec, proposal.repos[0].staged)
    finally:
        scaffolder.discard(proposal)

    with pytest.raises(pytest.skip.Exception, match="^definitely-missing-toolchain-xyz not installed$"):
        test_accepted_scaffold_ci.test_accepted_scaffold_passes_own_ci(
            tmp_path / "acc-missing",
            monkeypatch,
            "missing-tool-tmpl",
            "northstar",
            templates_dir=templates_dir,
        )


def test_pm_venv_first_clang_resolution_and_no_pm_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PM venv bin stays first on PATH (clang-format 23.1.5 / clang-tidy 23.1.4) and the acceptance harness never mutates PM installs."""
    need("clang-format", "clang-tidy", "ruff", "yamllint", "taplo", "rumdl", "shfmt", "shellcheck", "hadolint")
    cf = shutil.which("clang-format")
    ct = shutil.which("clang-tidy")
    assert cf is not None and ct is not None
    cf_ver = subprocess.check_output([cf, "--version"], text=True)
    ct_ver = subprocess.check_output([ct, "--version"], text=True)
    assert "23.1.5" in cf_ver, cf_ver
    assert "23.1.4" in ct_ver, ct_ver

    for pm_tool in ("ruff", "yamllint", "taplo", "rumdl", "shfmt", "shellcheck", "hadolint"):
        resolved = shutil.which(pm_tool)
        assert resolved is not None, f"PM tool {pm_tool!r} missing from PATH"

    run_mod, matrix_mod = _load_e2e_modules(tmp_path, monkeypatch)
    try:
        assert not hasattr(run_mod, "unshadow_pm_clang")
        assert not hasattr(run_mod, "resolve_system_clang")
        fake_venv_bin = run_mod.base / "hh/installs/k1/environments/g1/venv/bin"
        fake_venv_bin.mkdir(parents=True, exist_ok=True)
        for tool_name, ver in (("clang-format", "23.1.5"), ("clang-tidy", "23.1.4"), ("ruff", "0.15.22")):
            p = fake_venv_bin / tool_name
            p.write_text(f"#!/bin/sh\necho '{tool_name} version {ver}'\n", encoding="utf-8")
            p.chmod(0o755)

        recorded = run_mod.record_clang_toolchain()
        assert (fake_venv_bin / "clang-format").is_file()
        assert (fake_venv_bin / "clang-tidy").is_file()
        assert recorded["clang-format"]["path"] == str(fake_venv_bin / "clang-format")
        assert recorded["clang-format"]["version"] == "23.1.5"
        assert recorded["clang-tidy"]["path"] == str(fake_venv_bin / "clang-tidy")
        assert recorded["clang-tidy"]["version"] == "23.1.4"

        # Child process in run() gets fake_venv_bin FIRST in actual env PATH and executes PM clang 23.1.5
        cf_receipt = matrix_mod.run_version_probe(
            "clang-format", ["clang-format", "--version"], cwd=run_mod.base
        )
        assert cf_receipt["exit_code"] == 0
        assert cf_receipt["env"]["PATH"].split(":")[0] == str(fake_venv_bin)
        assert cf_receipt["clang_toolchain"]["clang-format"]["path"] == str(fake_venv_bin / "clang-format")
        assert cf_receipt["clang_toolchain"]["clang-format"]["version"] == "23.1.5"
        cf_stdout = (run_mod.base / "logs/version-clang-format.stdout").read_text(encoding="utf-8").strip()
        assert cf_stdout == "clang-format version 23.1.5"
    finally:
        shutil.rmtree(run_mod.base, ignore_errors=True)


def test_reconcile_exact_case_set_and_row_count_negative_selftest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """reconcile.py requires the exact {(template, name)} set across matrix.NAMES and the exact row count."""
    import runpy

    run_mod, matrix_mod = _load_e2e_modules(tmp_path, monkeypatch)
    try:
        checks_spec = importlib.util.spec_from_file_location("checks", E2E_HARNESS_ROOT / "checks.py")
        assert checks_spec and checks_spec.loader
        checks_mod = importlib.util.module_from_spec(checks_spec)
        monkeypatch.setitem(sys.modules, "checks", checks_mod)
        checks_spec.loader.exec_module(checks_mod)
        monkeypatch.setattr(checks_mod, "validate_receipts", lambda: {"security_scan": "safe"})

        templates = matrix_mod.discover_templates(REPO_ROOT / "templates", plugin_dir=REPO_ROOT)
        monkeypatch.setattr(matrix_mod, "discover_templates", lambda *a, **kw: templates)

        expected_cases = len(templates) * len(matrix_mod.NAMES)
        valid_cases = [
            {
                "template": t["template"],
                "language": t["language"],
                "name": name,
                "lint_ok": True,
                "lint_status": "clean",
                "tools_missing": [],
                "tool_errors": [],
                "tracked_diff": "",
                "context_files": {"AGENTS.md": True, ".adopt/rules.json": True, "TOOLS.lock": True},
            }
            for t in templates
            for name in matrix_mod.NAMES
        ]
        (run_mod.base / "verification.json").write_text("{}", encoding="utf-8")
        (run_mod.base / "suites.json").write_text("[]", encoding="utf-8")
        (run_mod.base / "logs/validate.stdout").write_text(
            json.dumps({"ok": True, "checks": [{"ok": True}] * 16, "warnings": []}),
            encoding="utf-8",
        )

        # Negative case 1: exact count and unique pair count match, and all templates present,
        # but one name is outside matrix.NAMES ('wrong-slug' instead of 'my-app-2').
        bad_name_cases = [dict(c) for c in valid_cases]
        bad_name_cases[-1]["name"] = "wrong-slug"
        (run_mod.base / "summary.json").write_text(
            json.dumps(
                {
                    "case_count": expected_cases,
                    "totals": {
                        "scaffold_pass": expected_cases,
                        "ci_pass": expected_cases,
                        "lint_clean": expected_cases,
                        "findings": 0,
                    },
                    "cases": bad_name_cases,
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(AssertionError):
            runpy.run_path(str(E2E_HARNESS_ROOT / "reconcile.py"))

        # Negative case 2: set of (template, name) pairs equals expected_case_set and case_count == expected_cases,
        # but s['cases'] has a duplicate row so len(s['cases']) != expected_cases.
        dup_cases = [dict(c) for c in valid_cases] + [dict(valid_cases[0])]
        (run_mod.base / "summary.json").write_text(
            json.dumps(
                {
                    "case_count": expected_cases,
                    "totals": {
                        "scaffold_pass": expected_cases,
                        "ci_pass": expected_cases,
                        "lint_clean": expected_cases,
                        "findings": 0,
                    },
                    "cases": dup_cases,
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(AssertionError):
            runpy.run_path(str(E2E_HARNESS_ROOT / "reconcile.py"))
    finally:
        shutil.rmtree(run_mod.base, ignore_errors=True)
