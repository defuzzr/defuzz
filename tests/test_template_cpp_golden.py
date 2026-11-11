"""Tests for the vendored cpp-golden CMake + Ninja template, scaffolding, xtask CI, and defuzz lint."""

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

from hermes_plugins.defuzz import (  # type: ignore[import-not-found]  # noqa: E402
    linter,
    toolchk,
)
from hermes_plugins.defuzz.agents_md import (  # type: ignore[import-not-found]  # noqa: E402
    render_agents_md_files,
)
from hermes_plugins.defuzz.naming import (  # type: ignore[import-not-found]  # noqa: E402
    MAX_NAME_LENGTH,
    PrefixForms,
    forms_from_placeholder,
    rename_text,
    slugify,
)
from hermes_plugins.defuzz.scaffolder import (  # type: ignore[import-not-found]  # noqa: E402
    Proposal,
    ScaffoldError,
    accept,
    discard,
    propose,
)
from hermes_plugins.defuzz.templates import (  # type: ignore[import-not-found]  # noqa: E402
    load_template,
)
from tests.toolchain_needs import check_tools, need, need_lint_tools  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = REPO_ROOT / "templates" / "cpp-golden"
TEMPLATE_YAML = TEMPLATE_DIR / "template.yaml"
TMPL_REPO_DIR = TEMPLATE_DIR / "tmpl_prefix"

def _pm_venv_bin() -> Path:
    """The Defuzz plugin-managed tool dir: the PATH entry providing clang-format (PM venv first on PATH)."""
    need("clang-format")  # installed with the Defuzz lint tools (PM venv bin on PATH)
    found = shutil.which("clang-format")
    assert found
    return Path(found).resolve().parent if Path(found).parent.name != "bin" else Path(found).parent


EXPECTED_NEEDS = ("cmake", "ninja", "clang", "clang-format", "clang-tidy")
# Floors stated by the shipped TOOLS.lock (re-seeded from the user's machine at creation).
EXPECTED_MINIMUMS = {
    "cmake": "3.20",
    "ninja": "1.10",
    "clang": "14.0",
    "clang-format": "23.1",
    "clang-tidy": "23.1",
}
# What the template's GitHub CI job installs and verifies on ubuntu-24.04 (a runner choice, not a floor).
CI_RUNNER_VERSIONS = {
    "cmake": "3.28.3",
    "ninja": "1.11.1",
    "clang": "18.1.3",
    "clang-format": "23.1.5",
    "clang-tidy": "23.1.4",
}
EXPECTED_LOCKED = (
    "CMakeLists.txt",
    ".clang-format",
    ".clang-tidy",
    ".editorconfig",
    ".github/workflows/*",
    "cmake/**",
)
LEFTOVER_TOKENS = ("tmpl_prefix", "tmpl-prefix", "TMPL_PREFIX", "TmplPrefix")
REQUIRED_TEMPLATE_FILES = (
    "CMakeLists.txt",
    ".clang-format",
    ".clang-tidy",
    ".editorconfig",
    ".gitignore",
    ".worktreeinclude",
    ".github/workflows/ci.yml",
    "00-INDEX.md",
    "AGENTS.md",
    "README.md",
    "COMPONENTS.md",
    "docs/component-boundaries.md",
    "cmake/xtask.cmake",
    "foundation/CMakeLists.txt",
    "foundation/include/foundation/error.hpp",
    "foundation/src/error.cpp",
    "domain/CMakeLists.txt",
    "domain/include/domain/service.hpp",
    "domain/src/service.cpp",
    "adapters/CMakeLists.txt",
    "adapters/include/adapters/memory_repo.hpp",
    "adapters/src/memory_repo.cpp",
    "apps/cli/CMakeLists.txt",
    "apps/cli/src/main.cpp",
    "tests/CMakeLists.txt",
    "tests/workspace_test.cpp",
)


def _with_pm_first_path(base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Construct an explicit PATH with the Defuzz PM venv bin first, then /usr/bin."""
    env = dict(os.environ if base_env is None else base_env)
    PM_VENV_BIN = _pm_venv_bin()
    current_path = env.get("PATH", "")
    tail = [
        p
        for p in current_path.split(os.pathsep)
        if p and p not in {str(PM_VENV_BIN), "/usr/bin", "/bin", "/usr/lib/llvm-18/bin"}
    ]
    env["PATH"] = os.pathsep.join([str(PM_VENV_BIN), "/usr/bin", "/bin", *tail])
    pm_python = PM_VENV_BIN / "python"
    if pm_python.is_file():
        env["DEFUZZ_LINT_PYTHON"] = str(pm_python)
    return env


def _collect_staged_files_by_suffix(
    staged: Path,
    cpp_out: list[str],
    md_out: list[str],
    yml_out: list[str],
) -> None:
    for path in staged.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix in {".hpp", ".cpp", ".h"}:
            cpp_out.append(str(path))
        elif path.suffix == ".md":
            md_out.append(str(path))
        elif path.suffix in {".yml", ".yaml"}:
            yml_out.append(str(path))


class CppGoldenTemplateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_path = os.environ.get("PATH")
        self._orig_lint_py = os.environ.get("DEFUZZ_LINT_PYTHON")
        if shutil.which("clang-format") is None:
            return  # no PM tool dir to put first; tests that need clang-format skip
        pm_env = _with_pm_first_path()
        os.environ["PATH"] = pm_env["PATH"]
        if "DEFUZZ_LINT_PYTHON" in pm_env:
            os.environ["DEFUZZ_LINT_PYTHON"] = pm_env["DEFUZZ_LINT_PYTHON"]

    def tearDown(self) -> None:
        if self._orig_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = self._orig_path
        if self._orig_lint_py is None:
            os.environ.pop("DEFUZZ_LINT_PYTHON", None)
        else:
            os.environ["DEFUZZ_LINT_PYTHON"] = self._orig_lint_py

    def test_toolchain_metadata_and_lock(self) -> None:
        self.assertTrue(TEMPLATE_YAML.is_file(), "templates/cpp-golden/template.yaml must exist")
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
        self.assertEqual(data["id"], "cpp-golden")
        self.assertEqual(data["layout"], "mono")
        self.assertEqual(data["languages"], ["cpp"])
        self.assertEqual(tuple(data["needs"]), EXPECTED_NEEDS)
        self.assertEqual(data["placeholder"], "tmpl_prefix")
        self.assertEqual(tuple(data["locked"]), EXPECTED_LOCKED)
        self.assertEqual(data["approved_deps"], {"cpp": []})

        spec = load_template(TEMPLATE_DIR)
        self.assertEqual(spec.id, "cpp-golden")
        self.assertEqual(spec.languages, ("cpp",))
        self.assertEqual(spec.needs, EXPECTED_NEEDS)
        self.assertEqual(spec.locked, EXPECTED_LOCKED)
        self.assertEqual(dict(spec.approved_deps), {"cpp": ()})
        self.assertEqual(len(spec.repos), 1)
        self.assertEqual(spec.repos[0].name, "tmpl_prefix")
        self.assertIsNotNone(spec.repos[0].check)
        assert spec.repos[0].check is not None
        self.assertEqual(
            spec.repos[0].check.cmd,
            ("cmake", "-P", "cmake/xtask.cmake", "--", "ci"),
        )
        self.assertEqual(spec.repos[0].check.cwd, ".")

        for required_rel in REQUIRED_TEMPLATE_FILES:
            self.assertTrue(
                (TMPL_REPO_DIR / required_rel).is_file(),
                f"Missing required template file: {required_rel}",
            )

        for path in TMPL_REPO_DIR.rglob("*"):
            if path.is_file() and path.name != "README.md":
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("cpp-golden", content, f"found 'cpp-golden' in {path}")
                self.assertNotIn("cpp_golden", content, f"found 'cpp_golden' in {path}")

        # The rest probes the installed toolchain against the shipped lock.
        need("cmake", "ctest", "ninja", "clang", "clang++", "clang-format", "clang-tidy")
        lock_file = TMPL_REPO_DIR / "TOOLS.lock"
        self.assertTrue(lock_file.is_file(), "tmpl_prefix/TOOLS.lock must exist")
        loaded_lock = toolchk.load_lock(lock_file)
        self.assertEqual(set(loaded_lock["tools"].keys()), set(EXPECTED_NEEDS))
        for tool_name, floor in EXPECTED_MINIMUMS.items():
            entry = loaded_lock["tools"][tool_name]
            self.assertEqual(entry["source"], "auto")
            self.assertEqual(entry["minimum"], floor)
            self.assertEqual(entry["version"], floor)
            installed_ver, _where = toolchk.probe(tool_name, entry, TMPL_REPO_DIR)
            self.assertFalse(toolchk.version_below(installed_ver, floor), f"{tool_name} {installed_ver} < {floor}")

        check_rep = toolchk.check(list(EXPECTED_NEEDS), loaded_lock, TMPL_REPO_DIR)
        self.assertTrue(check_rep["ok"], check_rep["summary"])

        clang_tidy_bin = shutil.which("clang-tidy")
        assert clang_tidy_bin is not None
        verify_cfg = subprocess.run(
            [
                clang_tidy_bin,
                "--verify-config",
                f"--config-file={TMPL_REPO_DIR / '.clang-tidy'}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(
            verify_cfg.returncode,
            0,
            f".clang-tidy failed --verify-config:\n{verify_cfg.stdout}\n{verify_cfg.stderr}",
        )
        self.assertNotIn("warning:", verify_cfg.stderr.lower())

    def test_ci_workflow_pins_and_verifies_toolchain_versions(self) -> None:
        loaded_lock = toolchk.load_lock(TMPL_REPO_DIR / "TOOLS.lock")
        ci_workflow = yaml.safe_load(
            (TMPL_REPO_DIR / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        )
        self.assertIsInstance(ci_workflow, dict)
        ci_job = ci_workflow["jobs"]["ci"]
        self.assertEqual(ci_job["runs-on"], "ubuntu-24.04")
        ci_steps = ci_job["steps"]
        self.assertIsInstance(ci_steps, list)

        install_sys_idx = None
        install_pip_idx = None
        verify_idx = None
        xtask_idx = None
        fmt_ver = CI_RUNNER_VERSIONS["clang-format"]
        tidy_ver = CI_RUNNER_VERSIONS["clang-tidy"]
        for tool_name, ci_ver in CI_RUNNER_VERSIONS.items():
            floor = loaded_lock["tools"][tool_name]["minimum"]
            self.assertFalse(toolchk.version_below(ci_ver, floor), f"CI {tool_name} {ci_ver} < floor {floor}")

        for idx, step in enumerate(ci_steps):
            run_cmd = str(step.get("run", ""))
            if (
                "apt-get install" in run_cmd
                and "cmake" in run_cmd
                and "ninja-build" in run_cmd
                and "clang-18" in run_cmd
            ):
                install_sys_idx = idx
            if (
                f"clang-format=={fmt_ver}" in run_cmd
                and f"clang-tidy=={tidy_ver}" in run_cmd
                and "pip install" in run_cmd
            ):
                install_pip_idx = idx
            if (
                all(ver in run_cmd for ver in CI_RUNNER_VERSIONS.values())
                and "clang-format --version" in run_cmd
            ):
                verify_idx = idx
            if "cmake -P cmake/xtask.cmake -- ci" in run_cmd:
                xtask_idx = idx

        self.assertIsNotNone(install_sys_idx, "CI workflow must install cmake, ninja, and clang-18")
        self.assertIsNotNone(
            install_pip_idx, "CI workflow must pip install pinned clang-format/clang-tidy wheels"
        )
        self.assertIsNotNone(
            verify_idx, "CI workflow must verify the runner's pinned tool versions"
        )
        self.assertIsNotNone(xtask_idx, "CI workflow must run `cmake -P cmake/xtask.cmake -- ci`")
        assert install_sys_idx is not None
        assert install_pip_idx is not None
        assert verify_idx is not None
        assert xtask_idx is not None
        self.assertLess(install_sys_idx, verify_idx)
        self.assertLess(install_pip_idx, verify_idx)
        self.assertLess(verify_idx, xtask_idx)

    def _verify_staged_proposal(self, proposal: Proposal) -> None:
        staged = proposal.repos[0].staged
        err_hpp = (staged / "foundation/include/foundation/error.hpp").read_text(encoding="utf-8")
        self.assertIn(f"namespace ws_{proposal.forms.snake}::foundation", err_hpp)
        self.assertNotIn(f"namespace {proposal.forms.snake}::", err_hpp)
        self.assertIn(f'"{proposal.forms.kebab}"', err_hpp)
        self.assertIn(f'"{proposal.forms.snake}"', err_hpp)
        self.assertIn(f'"{proposal.forms.screaming}"', err_hpp)
        self.assertIn(f"struct {proposal.forms.pascal}Info", err_hpp)

        index_md = (staged / "00-INDEX.md").read_text(encoding="utf-8")
        self.assertIn(proposal.forms.kebab, index_md)
        self.assertIn(proposal.forms.snake, index_md)
        self.assertIn(proposal.forms.screaming, index_md)
        self.assertIn(proposal.forms.pascal, index_md)

        for path in staged.rglob("*"):
            rel_str = path.relative_to(staged).as_posix()
            for tok in LEFTOVER_TOKENS:
                self.assertNotIn(tok, rel_str, f"leftover {tok!r} in path {rel_str}")
            if path.is_file():
                txt = path.read_text(encoding="utf-8")
                for tok in LEFTOVER_TOKENS:
                    self.assertNotIn(tok, txt, f"leftover {tok!r} in file {rel_str}")

        for rel_guide, guide_content in render_agents_md_files(
            project_slug=proposal.slug,
            declared_dirs={},
            placement_rules=[],
        ).items():
            guide_target = staged / rel_guide
            if not guide_target.exists():
                guide_target.parent.mkdir(parents=True, exist_ok=True)
                guide_target.write_text(guide_content, encoding="utf-8")

    def test_propose_substitutes_all_four_forms_and_sweeps_lengths_1_to_64(self) -> None:
        need("yamllint", "rumdl", "clang-format")
        spec = load_template(TEMPLATE_DIR)
        yamllint_bin = shutil.which("yamllint")
        rumdl_bin = shutil.which("rumdl")
        clang_format_bin = shutil.which("clang-format")
        self.assertIsNotNone(yamllint_bin, "yamllint must be installed")
        self.assertIsNotNone(rumdl_bin, "rumdl must be installed")
        self.assertIsNotNone(clang_format_bin, "clang-format must be installed")
        assert yamllint_bin is not None
        assert rumdl_bin is not None
        assert clang_format_bin is not None

        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="cpp-golden-propose-", dir=tmpdir_base))
        try:
            with self.assertRaises(ValueError):
                slugify("2app")
            with self.assertRaises(ScaffoldError):
                propose(
                    spec,
                    "2app",
                    {"building": spec.kind, "layout": "mono", "languages": ["cpp"]},
                    dest_root=work_root / "dest-invalid",
                    staging_parent=work_root / "staging-invalid",
                )
            raw_err_hpp = (TMPL_REPO_DIR / "foundation/include/foundation/error.hpp").read_text(
                encoding="utf-8"
            )
            renamed_2app = rename_text(
                raw_err_hpp,
                forms_from_placeholder("tmpl_prefix"),
                PrefixForms(kebab="2app", snake="2app", screaming="2APP", pascal="App2"),
            )
            self.assertIn("namespace ws_2app::foundation", renamed_2app)

            sweep_names = [
                *("a" * length for length in range(1, MAX_NAME_LENGTH + 1)),
                "Probe Svc",
                "a-" * 31 + "ab",
                "z" * MAX_NAME_LENGTH,
                "my-domain",
                "adapters-x",
                "cli-tool",
                "class",
                "int",
                "namespace",
                "template",
            ]
            all_cpp_files: list[str] = []
            all_md_files: list[str] = []
            all_yml_files: list[str] = []
            proposals: list[Proposal] = []

            for idx, raw_name in enumerate(sweep_names):
                proposal = propose(
                    spec,
                    raw_name,
                    {"building": spec.kind, "layout": "mono", "languages": ["cpp"]},
                    dest_root=work_root / f"dest-{idx}",
                    staging_parent=work_root / f"staging-{idx}",
                )
                proposals.append(proposal)
                self._verify_staged_proposal(proposal)
                _collect_staged_files_by_suffix(
                    proposal.repos[0].staged,
                    all_cpp_files,
                    all_md_files,
                    all_yml_files,
                )

            first_staged = proposals[0].repos[0].staged
            for cmd in (
                [
                    clang_format_bin,
                    f"--style=file:{first_staged / '.clang-format'}",
                    "--dry-run",
                    "-Werror",
                    *sorted(all_cpp_files),
                ],
                [rumdl_bin, "check", "--no-cache", *sorted(all_md_files)],
                [yamllint_bin, "--strict", *sorted(all_yml_files)],
            ):
                proc = subprocess.run(
                    cmd,
                    cwd=str(work_root),
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
                self.assertEqual(
                    proc.returncode,
                    0,
                    f"{cmd[:3]} failed:\n{proc.stdout}\n{proc.stderr}",
                )

            for proposal in proposals:
                discard(proposal)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)

    def _verify_negative_xtask_gates(self, repo: Path, snake_prefix: str) -> None:
        # 1. Layer check rejects forbidden #include upward dependency
        err_hpp_path = repo / "foundation/include/foundation/error.hpp"
        orig_err_hpp = err_hpp_path.read_text(encoding="utf-8")
        try:
            err_hpp_path.write_text(
                '#include "domain/service.hpp"\n' + orig_err_hpp,
                encoding="utf-8",
            )
            bad_layers = subprocess.run(
                ["cmake", "-P", "cmake/xtask.cmake", "--", "layers"],
                cwd=str(repo),
                env=_with_pm_first_path(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(bad_layers.returncode, 0)
            self.assertIn("layer violation", bad_layers.stderr.lower())
        finally:
            err_hpp_path.write_text(orig_err_hpp, encoding="utf-8")

        # 2. Layer check rejects forbidden target_link_libraries dependency
        fnd_cmake_path = repo / "foundation/CMakeLists.txt"
        orig_fnd_cmake = fnd_cmake_path.read_text(encoding="utf-8")
        try:
            fnd_cmake_path.write_text(
                orig_fnd_cmake
                + f"\ntarget_link_libraries({snake_prefix}_foundation PUBLIC {snake_prefix}_domain)\n",
                encoding="utf-8",
            )
            bad_cmake_layers = subprocess.run(
                ["cmake", "-P", "cmake/xtask.cmake", "--", "layers"],
                cwd=str(repo),
                env=_with_pm_first_path(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(bad_cmake_layers.returncode, 0)
            self.assertIn("layer violation", bad_cmake_layers.stderr.lower())
        finally:
            fnd_cmake_path.write_text(orig_fnd_cmake, encoding="utf-8")

        # 3. Missing tool on PATH fails closed (no /usr/bin fallback). CMake itself is the
        # one found on PATH, as the product runs it; only the tools xtask looks up are hidden.
        cmake_bin = shutil.which("cmake", path=_with_pm_first_path()["PATH"])
        self.assertIsNotNone(cmake_bin, "cmake not on PATH")
        missing_proc = subprocess.run(
            [str(cmake_bin), "-P", "cmake/xtask.cmake", "--", "ci"],
            cwd=str(repo),
            env={"PATH": "/nonexistent"},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(missing_proc.returncode, 0)
        self.assertIn("not found on path", " ".join(missing_proc.stderr.lower().split()))

        # 4. A tool below the TOOLS.lock minimum fails with a clear message (a fake
        # clang-format that reports an old version stands in for a distribution one).
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR") or None) as old_dir:
            fake_fmt = Path(old_dir) / "clang-format"
            fake_fmt.write_text("#!/bin/sh\necho 'Ubuntu clang-format version 18.1.3'\n", encoding="utf-8")
            fake_fmt.chmod(0o755)
            drift_proc = subprocess.run(
                [str(cmake_bin), "-P", "cmake/xtask.cmake", "--", "ci"],
                cwd=str(repo),
                env={"PATH": old_dir},
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertNotEqual(drift_proc.returncode, 0)
        drift_err = " ".join(drift_proc.stderr.lower().split())
        self.assertIn("tool version too old for 'clang-format'", drift_err)
        self.assertIn("need >= 23.1 from tools.lock, found '18.1.3'", drift_err)

    def test_accept_scaffold_runs_own_ci_layers_keywords_and_defuzz_lint_clean(self) -> None:
        spec = load_template(TEMPLATE_DIR)
        need(*check_tools(spec))
        names = (
            "a",
            "a-" * 31 + "ab",
            "z" * MAX_NAME_LENGTH,
            "my-domain",
            "adapters-x",
            "cli-tool",
            "class",
            "int",
            "namespace",
            "template",
        )
        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="cpp-golden-accept-", dir=tmpdir_base))
        try:
            for idx, name in enumerate(names):
                proposal = propose(
                    spec,
                    name,
                    {"building": spec.kind, "layout": "mono", "languages": ["cpp"]},
                    dest_root=work_root / f"projects-{idx}",
                    staging_parent=work_root / f"staging-{idx}",
                )
                result = accept(
                    proposal,
                    register=lambda *_, _i=idx: json.dumps({"success": True, "id": f"cpp-{_i}"}),
                    db_path=work_root / f"state-{idx}.db",
                    timeout_s=300,
                )
                self.assertEqual(result.repos[0]["check"], "ok", result.repos[0])
                repo = Path(result.repos[0]["path"])
                self.assertTrue((repo / ".adopt/rules.json").is_file())
                self.assertTrue((repo / "AGENTS.md").is_file())
                self.assertTrue((repo / "docs/AGENTS.template.md").is_file())
                self.assertTrue((repo / "TOOLS.lock").is_file())

                git_proc = subprocess.run(
                    ["git", "status", "--porcelain"],
                    cwd=str(repo),
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(git_proc.stdout, "", git_proc.stdout)

                if name in {"a", "z" * MAX_NAME_LENGTH, "my-domain", "class"}:
                    assert spec.repos[0].check is not None
                    ci_proc = subprocess.run(
                        list(spec.repos[0].check.cmd),
                        cwd=str(repo),
                        env=_with_pm_first_path(),
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )
                    self.assertEqual(
                        ci_proc.returncode,
                        0,
                        f"CI check failed for {name!r}:\n{ci_proc.stdout}\n{ci_proc.stderr}",
                    )
                    self.assertTrue(
                        (repo / "build/compile_commands.json").is_file(),
                        "CI must produce build/compile_commands.json for clang-tidy",
                    )

                    cli_bin = repo / "build/apps/cli" / proposal.forms.kebab
                    self.assertTrue(cli_bin.is_file(), f"Missing CLI binary {cli_bin}")
                    cli_proc = subprocess.run(
                        [str(cli_bin)],
                        cwd=str(repo),
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    self.assertEqual(cli_proc.returncode, 0)
                    self.assertEqual(cli_proc.stdout.strip(), proposal.forms.kebab)

                    git_after_ci = subprocess.run(
                        ["git", "status", "--porcelain"],
                        cwd=str(repo),
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    self.assertEqual(git_after_ci.stdout, "", git_after_ci.stdout)

                    report = linter.run_lint(
                        repo,
                        env=_with_pm_first_path(),
                        db_path=work_root / f"state-{idx}.db",
                    )
                    need_lint_tools(report)
                    self.assertTrue(report["ok"], json.dumps(report, indent=2))
                    self.assertEqual(report["status"], "clean", json.dumps(report, indent=2))
                    self.assertEqual(report["findings"], [], json.dumps(report, indent=2))
                    tools_by_name = {
                        (entry["tool"], entry["mode"]): entry["status"]
                        for entry in report["tool_statuses"]
                    }
                    self.assertEqual(tools_by_name.get(("clang-format", "pre")), "clean")
                    self.assertEqual(tools_by_name.get(("clang-tidy", "post")), "clean")

                if idx == 0:
                    self._verify_negative_xtask_gates(repo, proposal.forms.snake)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
