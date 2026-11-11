"""Tests for the dotnet-golden template: loader, scaffolder (min/max/hyphenated), own CI, and defuzz lint."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from tests import ensure_test_package

ensure_test_package()

# ruff: noqa: E402
from hermes_plugins.defuzz import agents_md, toolchk  # type: ignore[import-not-found]
from hermes_plugins.defuzz.linter import run_lint  # type: ignore[import-not-found]
from hermes_plugins.defuzz.naming import MAX_NAME_LENGTH  # type: ignore[import-not-found]
from hermes_plugins.defuzz.scaffolder import (  # type: ignore[import-not-found]
    accept,
    discard,
    propose,
)
from hermes_plugins.defuzz.templates import load_template  # type: ignore[import-not-found]
from tests.toolchain_needs import need

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = REPO_ROOT / "templates" / "dotnet-golden"
TEMPLATE_YAML = TEMPLATE_DIR / "template.yaml"
TMPL_REPO_DIR = TEMPLATE_DIR / "tmpl_prefix"
DOTNET_SDK_FLOOR = "10.0.100"  # net10.0 target framework; global.json rollForward latestFeature

def _require_tool(binary: str) -> str:
    """Path of an installed tool; the test skips with "<tool> not installed" when it is absent.

    csharpier comes from `hermes defuzz setup-tools --yes` or `dotnet tool install csharpier --version 1.3.0`.
    """
    need(binary)
    found = shutil.which(binary)
    assert found is not None
    return found


def _build_lint_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONPATH"):
        env.pop(key, None)
    return env


class DotnetGoldenTemplateTests(unittest.TestCase):
    def test_template_metadata_and_contents(self) -> None:
        self.assertTrue(TEMPLATE_YAML.is_file(), "template.yaml must exist")
        data = yaml.safe_load(TEMPLATE_YAML.read_text(encoding="utf-8"))
        self.assertIsInstance(data, dict)

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
        }
        self.assertEqual(set(data.keys()), required_keys)
        self.assertEqual(data["id"], TEMPLATE_DIR.name)
        self.assertEqual(data["id"], "dotnet-golden")
        self.assertEqual(data["kind"], "service")
        self.assertEqual(data["layout"], "mono")
        self.assertEqual(data["languages"], ["csharp"])
        self.assertEqual(data["needs"], ["dotnet"])
        self.assertEqual(data["placeholder"], "tmpl_prefix")
        self.assertEqual(data["approved_deps"], {"csharp": []})

        expected_locked = [
            "Directory.Build.props",
            "Directory.Build.targets",
            "NuGet.Config",
            "global.json",
            ".editorconfig",
            ".github/workflows/*",
            "xtask/**",
        ]
        self.assertEqual(data["locked"], expected_locked)

        spec = load_template(TEMPLATE_DIR)
        self.assertEqual(spec.id, "dotnet-golden")
        self.assertEqual(spec.languages, ("csharp",))
        self.assertEqual(spec.needs, ("dotnet",))
        self.assertEqual(spec.locked, tuple(expected_locked))
        self.assertEqual(dict(spec.approved_deps), {"csharp": ()})
        self.assertEqual(len(spec.repos), 1)
        self.assertEqual(spec.repos[0].name, "tmpl_prefix")
        self.assertIsNotNone(spec.repos[0].check)
        assert spec.repos[0].check is not None
        self.assertEqual(
            spec.repos[0].check.cmd,
            ("dotnet", "run", "--project", "xtask", "--", "ci"),
        )
        self.assertEqual(spec.repos[0].check.cwd, ".")

        self.assertTrue(TMPL_REPO_DIR.is_dir(), "tmpl_prefix directory must exist")
        for rel in (
            "00-INDEX.md",
            "AGENTS.md",
            "COMPONENTS.md",
            "README.md",
            "TOOLS.lock",
            "Directory.Build.props",
            "Directory.Build.targets",
            "NuGet.Config",
            "global.json",
            "TmplPrefix.sln",
            ".editorconfig",
            ".gitignore",
            ".worktreeinclude",
            ".github/workflows/ci.yml",
            "docs/component-boundaries.md",
            "foundation/TmplPrefix.Foundation.csproj",
            "foundation/packages.lock.json",
            "domain/TmplPrefix.Domain.csproj",
            "domain/packages.lock.json",
            "adapters/TmplPrefix.Adapters.csproj",
            "adapters/packages.lock.json",
            "apps/cli/TmplPrefix.Cli.csproj",
            "apps/cli/packages.lock.json",
            "xtask/Xtask.csproj",
            "xtask/packages.lock.json",
        ):
            self.assertTrue(
                (TMPL_REPO_DIR / rel).is_file(),
                f"Expected template file missing: {rel}",
            )

        loaded_lock = toolchk.load_lock(TMPL_REPO_DIR / "TOOLS.lock")
        self.assertIn("dotnet", loaded_lock["tools"])
        dotnet_entry = loaded_lock["tools"]["dotnet"]
        # The shipped lock is a floor, re-seeded from the user's machine at creation.
        self.assertEqual(dotnet_entry["source"], "auto")
        self.assertEqual(dotnet_entry["minimum"], DOTNET_SDK_FLOOR)
        self.assertEqual(dotnet_entry["version"], DOTNET_SDK_FLOOR)

        global_json = json.loads((TMPL_REPO_DIR / "global.json").read_text(encoding="utf-8"))
        self.assertIsInstance(global_json, dict)
        self.assertEqual(
            global_json.get("sdk"),
            {"version": DOTNET_SDK_FLOOR, "rollForward": "latestFeature"},
        )

        ci_workflow = yaml.safe_load(
            (TMPL_REPO_DIR / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        )
        self.assertIsInstance(ci_workflow, dict)
        ci_steps = ci_workflow["jobs"]["ci"]["steps"]
        self.assertIsInstance(ci_steps, list)

        checkout_idx = None
        setup_dotnet_idx = None
        xtask_idx = None
        for idx, step in enumerate(ci_steps):
            uses = str(step.get("uses", ""))
            run_cmd = str(step.get("run", ""))
            with_cfg = step.get("with") or {}
            if uses.startswith("actions/checkout@"):
                checkout_idx = idx
            if uses.startswith("actions/setup-dotnet@"):
                ci_sdk = str(with_cfg.get("dotnet-version"))
                floor_major, floor_minor = DOTNET_SDK_FLOOR.split(".")[:2]
                self.assertEqual(ci_sdk, f"{floor_major}.{floor_minor}.x")
                setup_dotnet_idx = idx
            if "dotnet run --project xtask -- ci" in run_cmd:
                xtask_idx = idx

        self.assertIsNotNone(checkout_idx, "CI workflow must check out repository")
        self.assertIsNotNone(
            setup_dotnet_idx, "CI workflow must set up a .NET SDK at or above the TOOLS.lock minimum"
        )
        self.assertIsNotNone(
            xtask_idx, "CI workflow must run `dotnet run --project xtask -- ci`"
        )
        assert checkout_idx is not None and setup_dotnet_idx is not None and xtask_idx is not None
        self.assertLess(checkout_idx, setup_dotnet_idx)
        self.assertLess(setup_dotnet_idx, xtask_idx)

        for path in TMPL_REPO_DIR.rglob("*"):
            if path.is_file() and path.name != "README.md":
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("dotnet-golden", content, f"found 'dotnet-golden' in {path}")
                self.assertNotIn("dotnet_golden", content, f"found 'dotnet_golden' in {path}")

        # The installed SDK is in the template's band and passes the shipped lock (needs dotnet).
        dotnet_bin = _require_tool("dotnet")
        ver_proc = subprocess.run(
            [dotnet_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        installed_dotnet_version = ver_proc.stdout.strip()
        # Any SDK in the template's band works: 10.0.100 or newer within major 10 (global.json latestFeature).
        self.assertEqual(installed_dotnet_version.split(".")[0], "10", installed_dotnet_version)
        self.assertFalse(toolchk.version_below(installed_dotnet_version, DOTNET_SDK_FLOOR))
        preflight = toolchk.check(["dotnet"], loaded_lock, TMPL_REPO_DIR)
        self.assertTrue(preflight["ok"], preflight)

    def test_propose_substitutes_all_four_forms_for_min_max_and_hyphenated_names(self) -> None:
        spec = load_template(TEMPLATE_DIR)
        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="dotnet-golden-propose-", dir=tmpdir_base))
        try:
            cases = (
                ("a", "a", "a", "A", "A"),
                ("z" * MAX_NAME_LENGTH, "z" * 64, "z" * 64, "Z" * 64, "Z" + "z" * 63),
                (
                    "a-" * 31 + "ab",
                    "a-" * 31 + "ab",
                    "a_" * 31 + "ab",
                    "A_" * 31 + "AB",
                    "A" * 31 + "Ab",
                ),
                ("Probe Svc", "probe-svc", "probe_svc", "PROBE_SVC", "ProbeSvc"),
            )
            for idx, (raw_name, exp_kebab, exp_snake, exp_screaming, exp_pascal) in enumerate(
                cases
            ):
                with self.subTest(name=raw_name):
                    proposal = propose(
                        spec,
                        raw_name,
                        {
                            "building": "service",
                            "layout": "mono",
                            "languages": ["csharp"],
                        },
                        dest_root=work_root / f"dest-{idx}",
                        staging_parent=work_root / f"staging-{idx}",
                    )
                    try:
                        self.assertEqual(proposal.slug, exp_kebab)
                        self.assertEqual(proposal.forms.kebab, exp_kebab)
                        self.assertEqual(proposal.forms.snake, exp_snake)
                        self.assertEqual(proposal.forms.screaming, exp_screaming)
                        self.assertEqual(proposal.forms.pascal, exp_pascal)

                        staged = proposal.repos[0].staged
                        self.assertTrue((staged / f"{exp_pascal}.sln").is_file())
                        self.assertTrue(
                            (staged / "foundation" / f"{exp_pascal}.Foundation.csproj").is_file()
                        )
                        self.assertTrue(
                            (staged / "domain" / f"{exp_pascal}.Domain.csproj").is_file()
                        )
                        self.assertTrue(
                            (staged / "adapters" / f"{exp_pascal}.Adapters.csproj").is_file()
                        )
                        self.assertTrue(
                            (staged / "apps" / "cli" / f"{exp_pascal}.Cli.csproj").is_file()
                        )
                        self.assertTrue((staged / "xtask" / "Xtask.csproj").is_file())

                        foundation_cs = (staged / "foundation" / "WorkspaceException.cs").read_text(
                            encoding="utf-8"
                        )
                        self.assertIn(f"namespace {exp_pascal}.Foundation;", foundation_cs)
                        self.assertIn(f'"{exp_kebab}"', foundation_cs)
                        self.assertIn(f'"{exp_snake}"', foundation_cs)
                        self.assertIn(f'"{exp_screaming}"', foundation_cs)

                        leftover_tokens = (
                            "tmpl_prefix",
                            "tmpl-prefix",
                            "TMPL_PREFIX",
                            "TmplPrefix",
                        )
                        for path in staged.rglob("*"):
                            rel_str = path.relative_to(staged).as_posix()
                            for tok in leftover_tokens:
                                self.assertNotIn(
                                    tok, rel_str, f"leftover {tok!r} in path {rel_str}"
                                )
                            if path.is_file():
                                txt = path.read_text(encoding="utf-8")
                                for tok in leftover_tokens:
                                    self.assertNotIn(
                                        tok, txt, f"leftover {tok!r} in file {rel_str}"
                                    )
                    finally:
                        discard(proposal)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)

    def test_scaffold_name_lengths_pass_formatters_and_linters(self) -> None:
        yamllint_bin = _require_tool("yamllint")
        rumdl_bin = _require_tool("rumdl")
        biome_bin = _require_tool("biome")
        csharpier_bin = _require_tool("csharpier")

        spec = load_template(TEMPLATE_DIR)
        lengths = (
            range(1, MAX_NAME_LENGTH + 1)
            if os.environ.get("ADOPT_ALL_NAME_LENGTHS") == "1"
            else (1, 2, 59, 60, 61, MAX_NAME_LENGTH - 1, MAX_NAME_LENGTH)
        )
        names = [*(f"a{'a' * (length - 1)}" for length in lengths)] + [
            "c2-python-final",
            "z" * MAX_NAME_LENGTH,
            "a-" * 31 + "ab",
        ]
        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="dotnet-golden-lengths-", dir=tmpdir_base))
        try:
            for idx, name in enumerate(names):
                with self.subTest(name=name):
                    proposal = propose(
                        spec,
                        name,
                        {
                            "building": spec.kind,
                            "layout": "mono",
                            "languages": list(spec.languages),
                        },
                        dest_root=work_root / f"projects-{idx}",
                        staging_parent=work_root / f"staging-{idx}",
                    )
                    try:
                        root = proposal.repos[0].staged
                        for relative, content in agents_md.render_agents_md_files(
                            project_slug=name,
                            declared_dirs={},
                            placement_rules=[],
                        ).items():
                            target = root / relative
                            if not target.exists():
                                target.parent.mkdir(parents=True, exist_ok=True)
                                target.write_text(content, encoding="utf-8")

                        for cmd in (
                            [yamllint_bin, "--strict", ".github/workflows/ci.yml"],
                            [rumdl_bin, "check", "--no-cache", "."],
                            [biome_bin, "ci", "."],
                            [csharpier_bin, "check", "."],
                        ):
                            res = subprocess.run(
                                cmd,
                                cwd=str(root),
                                capture_output=True,
                                text=True,
                                timeout=120,
                                check=False,
                            )
                            self.assertEqual(
                                res.returncode,
                                0,
                                f"{cmd}\n{res.stdout}\n{res.stderr}",
                            )
                    finally:
                        discard(proposal)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)

    def test_scaffold_accept_check_and_defuzz_lint_clean(self) -> None:
        for tool in ("dotnet", "csharpier", "yamllint", "rumdl", "biome"):
            _require_tool(tool)

        spec = load_template(TEMPLATE_DIR)
        lint_env = _build_lint_env()
        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="dotnet-golden-accept-", dir=tmpdir_base))
        try:
            names = ("a", "z" * MAX_NAME_LENGTH, "a-" * 31 + "ab")
            for idx, name in enumerate(names):
                with self.subTest(name=name):
                    case_root = work_root / f"case-{idx}"
                    proposal = propose(
                        spec,
                        name,
                        {
                            "building": spec.kind,
                            "layout": "mono",
                            "languages": list(spec.languages),
                        },
                        dest_root=case_root / "projects",
                        staging_parent=case_root / "staging",
                    )
                    db_path = case_root / "state.db"
                    result = accept(
                        proposal,
                        register=lambda *_, _i=idx: json.dumps(
                            {"success": True, "id": f"test-dotnet-{_i}"}
                        ),
                        db_path=db_path,
                        timeout_s=600,
                    )
                    self.assertEqual(result.repos[0]["check"], "ok", result.repos[0])
                    repo = Path(result.repos[0]["path"])
                    self.assertTrue((repo / ".adopt" / "rules.json").is_file())
                    self.assertTrue((repo / "AGENTS.md").is_file())
                    self.assertTrue((repo / "TOOLS.lock").is_file())

                    assert spec.repos[0].check is not None
                    check_cmd = list(spec.repos[0].check.cmd)
                    proc = subprocess.run(
                        check_cmd,
                        cwd=str(repo),
                        env=lint_env,
                        capture_output=True,
                        text=True,
                        timeout=600,
                        check=False,
                    )
                    self.assertEqual(
                        proc.returncode,
                        0,
                        f"check command {check_cmd!r} failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
                    )

                    status_proc = subprocess.run(
                        ["git", "status", "--porcelain"],
                        cwd=str(repo),
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    self.assertEqual(status_proc.stdout, "", status_proc.stdout)

                    report = run_lint(repo, env=lint_env, db_path=db_path)
                    self.assertTrue(report["ok"], report)
                    self.assertEqual(report["status"], "clean", report)
                    self.assertEqual(report["findings"], [], report)
                    self.assertEqual(report["tools_missing"], [], report)
                    self.assertEqual(report["tool_errors"], [], report)
                    tools_run_names = {entry["tool"] for entry in report["tools_run"]}
                    self.assertIn("dotnet-format", tools_run_names)
                    self.assertIn("csharpier", tools_run_names)
                    self.assertIn("yamllint", tools_run_names)
                    self.assertIn("rumdl", tools_run_names)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)

    def test_xtask_layers_rejects_unknown_directory_and_xtask_reference(self) -> None:
        dotnet_bin = _require_tool("dotnet")
        spec = load_template(TEMPLATE_DIR)
        lint_env = _build_lint_env()
        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="dotnet-golden-layers-", dir=tmpdir_base))
        try:
            proposal = propose(
                spec,
                "layer-probe",
                {
                    "building": spec.kind,
                    "layout": "mono",
                    "languages": list(spec.languages),
                },
                dest_root=work_root / "projects",
                staging_parent=work_root / "staging",
            )
            try:
                staged = proposal.repos[0].staged
                layers_cmd = [dotnet_bin, "run", "--project", "xtask", "--", "layers"]

                clean_res = subprocess.run(
                    layers_cmd,
                    cwd=str(staged),
                    env=lint_env,
                    capture_output=True,
                    text=True,
                    timeout=180,
                    check=False,
                )
                self.assertEqual(
                    clean_res.returncode,
                    0,
                    f"clean workspace layers failed:\n{clean_res.stdout}\n{clean_res.stderr}",
                )

                rogue_dir = staged / "rogue"
                rogue_dir.mkdir(parents=True, exist_ok=True)
                rogue_csproj = rogue_dir / "Rogue.csproj"
                rogue_csproj.write_text(
                    '<Project Sdk="Microsoft.NET.Sdk">\n'
                    "  <PropertyGroup>\n"
                    "    <PackageId>layer-probe-rogue</PackageId>\n"
                    "  </PropertyGroup>\n"
                    "</Project>\n",
                    encoding="utf-8",
                )
                try:
                    rogue_res = subprocess.run(
                        layers_cmd,
                        cwd=str(staged),
                        env=lint_env,
                        capture_output=True,
                        text=True,
                        timeout=180,
                        check=False,
                    )
                    self.assertNotEqual(rogue_res.returncode, 0)
                    self.assertIn(
                        "does not belong to a known layer directory",
                        rogue_res.stdout + rogue_res.stderr,
                    )
                finally:
                    shutil.rmtree(rogue_dir, ignore_errors=True)

                foundation_csproj = staged / "foundation" / "LayerProbe.Foundation.csproj"
                orig_foundation = foundation_csproj.read_text(encoding="utf-8")
                foundation_csproj.write_text(
                    orig_foundation.replace(
                        "</Project>",
                        '  <ItemGroup>\n    <ProjectReference Include="../xtask/Xtask.csproj" />\n  </ItemGroup>\n</Project>',
                    ),
                    encoding="utf-8",
                )
                try:
                    xtask_ref_res = subprocess.run(
                        layers_cmd,
                        cwd=str(staged),
                        env=lint_env,
                        capture_output=True,
                        text=True,
                        timeout=180,
                        check=False,
                    )
                    self.assertNotEqual(xtask_ref_res.returncode, 0)
                    self.assertIn(
                        "cannot depend on `xtask`",
                        xtask_ref_res.stdout + xtask_ref_res.stderr,
                    )
                finally:
                    foundation_csproj.write_text(orig_foundation, encoding="utf-8")
            finally:
                discard(proposal)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)

    def test_xtask_ci_passes_when_temp_folder_path_has_a_space(self) -> None:
        dotnet_bin = _require_tool("dotnet")
        spec = load_template(TEMPLATE_DIR)
        env = _build_lint_env()
        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="dotnet-golden-space-", dir=tmpdir_base))
        try:
            spaced_tmp = work_root / "temp with space"
            spaced_tmp.mkdir()
            env["TMPDIR"] = str(spaced_tmp)
            proposal = propose(
                spec,
                "space-probe",
                {
                    "building": spec.kind,
                    "layout": "mono",
                    "languages": list(spec.languages),
                },
                dest_root=work_root / "projects",
                staging_parent=work_root / "staging",
            )
            try:
                staged = proposal.repos[0].staged
                res = subprocess.run(
                    [dotnet_bin, "run", "--project", "xtask", "--", "ci"],
                    cwd=str(staged),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                self.assertEqual(
                    res.returncode,
                    0,
                    f"xtask ci failed with spaced TMPDIR:\n{res.stdout}\n{res.stderr}",
                )
                self.assertIn("layer check passed", res.stdout)
            finally:
                discard(proposal)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
