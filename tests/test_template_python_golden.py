"""Tests for the vendored python-golden template, options schema, propose substitution, and xtask CI."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.scaffolder import discard, propose  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.templates import (  # type: ignore[import-not-found]  # noqa: E402
    OptionSpec,
    TemplateError,
    load_template,
    options_as_json,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = REPO_ROOT / "templates" / "python-golden"
TEMPLATE_YAML = TEMPLATE_DIR / "template.yaml"
TMPL_REPO_DIR = TEMPLATE_DIR / "tmpl_prefix"
FIXTURES_TEMPLATES = Path(__file__).resolve().parent / "fixtures" / "templates"


class PythonGoldenTemplateMetadataTests(unittest.TestCase):
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
            "options",
            "repos",
        }
        self.assertEqual(set(data.keys()), required_keys)
        self.assertEqual(data["id"], TEMPLATE_DIR.name)
        self.assertEqual(data["id"], "python-golden")
        self.assertEqual(data["kind"], "service")
        self.assertEqual(data["layout"], "mono")
        self.assertEqual(data["languages"], ["python"])
        self.assertEqual(data["placeholder"], "tmpl_prefix")

        sub_in = list(data["substitute_in"])
        for expected_glob in (
            "**/*.py",
            "**/*.toml",
            "**/*.md",
            "**/*.yml",
            ".env.example",
            "**/*.tmpl",
            "uv.lock",
        ):
            self.assertIn(expected_glob, sub_in)

        expected_locked = [
            "pyproject.toml",
            ".editorconfig",
            ".github/workflows/*",
            "tools/xtask/**",
        ]
        self.assertEqual(data["locked"], expected_locked)

        lock_data = tomllib.loads((TMPL_REPO_DIR / "uv.lock").read_text(encoding="utf-8"))
        pyproj_data = tomllib.loads((TMPL_REPO_DIR / "pyproject.toml").read_text(encoding="utf-8"))
        ws_members = set(lock_data.get("manifest", {}).get("members", []))
        lock_external = {
            pkg["name"]
            for pkg in lock_data.get("package", [])
            if pkg["name"] not in ws_members
            and not (
                isinstance(pkg.get("source"), dict)
                and any(k in pkg["source"] for k in ("editable", "virtual", "directory"))
            )
        }
        catalogue_constraints = {
            re.split(r"[<>=!~;\s\[]", spec, maxsplit=1)[0].strip()
            for spec in pyproj_data.get("tool", {}).get("uv", {}).get("constraint-dependencies", [])
        }
        expected_deps = sorted(lock_external | catalogue_constraints)
        self.assertEqual(data["approved_deps"], {"python": expected_deps})

        spec = load_template(TEMPLATE_DIR)
        self.assertEqual(spec.id, "python-golden")
        self.assertEqual(spec.locked, tuple(expected_locked))
        self.assertEqual(dict(spec.approved_deps), {"python": tuple(expected_deps)})
        self.assertEqual(len(spec.repos), 1)
        self.assertEqual(spec.repos[0].name, "tmpl_prefix")
        self.assertIsNotNone(spec.repos[0].check)
        assert spec.repos[0].check is not None
        self.assertEqual(spec.repos[0].check.cmd, ("uv", "run", "xtask", "ci"))
        self.assertEqual(spec.repos[0].check.cwd, ".")

        # Verify frozen options schema from OPTIONS.md
        self.assertIn("http_adapter", spec.options)
        opt = spec.options["http_adapter"]
        self.assertIsInstance(opt, OptionSpec)
        self.assertEqual(opt.id, "http_adapter")
        self.assertEqual(opt.label, "HTTP adapter")
        self.assertEqual(opt.choices, ("fastapi", "stdlib_http"))
        self.assertEqual(opt.default, "fastapi")
        self.assertEqual(opt.env_key, "TMPL_PREFIX_HTTP__ADAPTER")
        self.assertEqual(
            opt.description,
            "Both adapters ship; this picks the default wired in config.",
        )

        expected_options_json = [
            {
                "id": "http_adapter",
                "label": "HTTP adapter",
                "choices": ["fastapi", "stdlib_http"],
                "default": "fastapi",
                "env_key": "TMPL_PREFIX_HTTP__ADAPTER",
                "description": "Both adapters ship; this picks the default wired in config.",
            }
        ]
        self.assertEqual(spec.options_as_json(), expected_options_json)
        self.assertEqual(options_as_json(spec), expected_options_json)

        self.assertTrue(TMPL_REPO_DIR.is_dir(), "tmpl_prefix directory must exist")
        self.assertTrue((TMPL_REPO_DIR / "pyproject.toml").is_file(), "pyproject.toml must exist")
        self.assertTrue((TMPL_REPO_DIR / "uv.lock").is_file(), "uv.lock must exist")
        self.assertTrue((TMPL_REPO_DIR / "00-INDEX.md").is_file(), "00-INDEX.md must exist")
        self.assertTrue((TMPL_REPO_DIR / ".env.example").is_file(), ".env.example must exist")
        self.assertIn(
            "TMPL_PREFIX_HTTP__ADAPTER=fastapi",
            (TMPL_REPO_DIR / ".env.example").read_text(encoding="utf-8"),
        )

        for path in TMPL_REPO_DIR.rglob("*"):
            if path.is_file() and path.name != "README.md":
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("python-golden", content, f"found 'python-golden' in {path}")
                self.assertNotIn("python_golden", content, f"found 'python_golden' in {path}")

    def test_python_options_fixtures(self) -> None:
        valid_yaml = (FIXTURES_TEMPLATES / "python_options_valid.yaml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp) / "python-options-valid"
            (tdir / "tmpl_prefix").mkdir(parents=True)
            (tdir / "template.yaml").write_text(valid_yaml, encoding="utf-8")
            spec = load_template(tdir)
            self.assertEqual(
                spec.options["http_adapter"].choices,
                ("fastapi", "stdlib_http"),
            )
            self.assertEqual(
                spec.options["http_adapter"].env_key,
                "TMPL_PREFIX_HTTP__ADAPTER",
            )

        bad_yaml = (FIXTURES_TEMPLATES / "python_options_bad_default.yaml").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp) / "python-options-bad-default"
            (tdir / "tmpl_prefix").mkdir(parents=True)
            (tdir / "template.yaml").write_text(bad_yaml, encoding="utf-8")
            with self.assertRaises(TemplateError) as ctx:
                load_template(tdir)
            self.assertIn("default", str(ctx.exception))

    def test_propose_probe_svc_substitutes_all_four_forms_and_src_dirs(self) -> None:
        spec = load_template(TEMPLATE_DIR)
        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="python-golden-propose-", dir=tmpdir_base))
        try:
            proposal = propose(
                spec,
                "Probe Svc",
                {
                    "building": "service",
                    "layout": "mono",
                    "languages": ["python"],
                },
                dest_root=work_root / "dest",
                staging_parent=work_root / "staging",
            )
            try:
                self.assertEqual(proposal.slug, "probe-svc")
                self.assertEqual(proposal.forms.kebab, "probe-svc")
                self.assertEqual(proposal.forms.snake, "probe_svc")
                self.assertEqual(proposal.forms.screaming, "PROBE_SVC")
                self.assertEqual(proposal.forms.pascal, "ProbeSvc")

                self.assertEqual(len(proposal.repos), 1)
                staged = proposal.repos[0].staged

                # Verify distribution directories (kebab) and src/probe_svc_* module directories (snake)
                expected_pkg_and_mod_dirs = (
                    ("foundation", "probe-svc-core", "probe_svc_core"),
                    ("foundation", "probe-svc-config", "probe_svc_config"),
                    ("foundation", "probe-svc-telemetry", "probe_svc_telemetry"),
                    ("domain", "probe-svc-accounts", "probe_svc_accounts"),
                    ("adapters", "probe-svc-storage-memory", "probe_svc_storage_memory"),
                    ("adapters", "probe-svc-http-fastapi", "probe_svc_http_fastapi"),
                    ("adapters", "probe-svc-http-stdlib", "probe_svc_http_stdlib"),
                    ("apps", "probe-svc-server", "probe_svc_server"),
                    ("apps", "probe-svc-cli", "probe_svc_cli"),
                )
                for layer, dist_dir, mod_dir in expected_pkg_and_mod_dirs:
                    pkg_path = staged / "packages" / layer / dist_dir
                    mod_path = pkg_path / "src" / mod_dir
                    self.assertTrue(pkg_path.is_dir(), f"Missing package dir {pkg_path}")
                    self.assertTrue(mod_path.is_dir(), f"Missing src module dir {mod_path}")
                    self.assertTrue((mod_path / "__init__.py").is_file())
                    self.assertTrue((mod_path / "py.typed").is_file())

                # Verify all four forms in substituted files
                env_example = (staged / ".env.example").read_text(encoding="utf-8")
                self.assertIn("PROBE_SVC_HTTP__ADAPTER=fastapi", env_example)
                self.assertIn("PROBE_SVC_SERVICE_NAME=probe-svc-service", env_example)

                xtask_ws = (staged / "tools" / "xtask" / "src" / "xtask" / "workspace.py").read_text(
                    encoding="utf-8"
                )
                self.assertIn('PREFIX: str = "probe_svc"', xtask_ws)

                index_text = (staged / "00-INDEX.md").read_text(encoding="utf-8")
                self.assertIn("ProbeSvc", index_text)
                self.assertIn("probe_svc", index_text)
                self.assertIn("probe-svc", index_text)
                self.assertIn("PROBE_SVC", index_text)

                readme_text = (staged / "README.md").read_text(encoding="utf-8")
                self.assertIn("probe-svc", readme_text)

                lock_text = (staged / "uv.lock").read_text(encoding="utf-8")
                self.assertIn('name = "probe-svc-core"', lock_text)
                self.assertIn('name = "probe-svc-server"', lock_text)

                tmpl_text = (staged / "templates" / "component.py.tmpl").read_text(
                    encoding="utf-8"
                )
                self.assertIn("probe_svc_core", tmpl_text)

                # Verify zero leftover placeholder tokens anywhere in paths or file contents
                leftover_tokens = ("tmpl_prefix", "tmpl-prefix", "TMPL_PREFIX", "TmplPrefix")
                for path in staged.rglob("*"):
                    rel_str = path.relative_to(staged).as_posix()
                    for tok in leftover_tokens:
                        self.assertNotIn(tok, rel_str, f"leftover {tok!r} in path {rel_str}")
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


@unittest.skipUnless(shutil.which("uv") is not None, "uv not installed")
@unittest.skipIf(os.environ.get("ADOPT_SKIP_SLOW") == "1", "ADOPT_SKIP_SLOW=1")
class PythonGoldenScaffoldSlowTests(unittest.TestCase):
    """slow"""

    def test_propose_uv_lock_check_ci_wheel_smoke_and_rename_round_trip(self) -> None:
        spec = load_template(TEMPLATE_DIR)
        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="python-golden-scaffold-", dir=tmpdir_base))
        try:
            proposal = propose(
                spec,
                "Probe Svc",
                {
                    "building": "service",
                    "layout": "mono",
                    "languages": ["python"],
                },
                dest_root=work_root / "dest",
                staging_parent=work_root / "staging",
            )
            try:
                plan = proposal.repos[0]
                self.assertIsNotNone(plan.check)
                assert plan.check is not None
                run_cwd = (plan.staged / plan.check.cwd).resolve()

                # Isolate from outer active virtual environments
                run_env = dict(os.environ)
                run_env.pop("VIRTUAL_ENV", None)
                run_env.pop("CONDA_PREFIX", None)

                # 1. Verify `uv lock --check` passes immediately after substitution
                lock_proc = subprocess.run(
                    ["uv", "lock", "--check"],
                    cwd=str(run_cwd),
                    env=run_env,
                    shell=False,
                    timeout=300,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    lock_proc.returncode,
                    0,
                    f"uv lock --check failed:\nSTDOUT:\n{lock_proc.stdout}\nSTDERR:\n{lock_proc.stderr}",
                )

                # 2. Run repos.check explicitly (`uv run xtask ci`, which includes wheel-install smoke)
                check_proc = subprocess.run(
                    list(plan.check.cmd),
                    cwd=str(run_cwd),
                    env=run_env,
                    shell=False,
                    timeout=900,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    check_proc.returncode,
                    0,
                    f"check command {plan.check.cmd!r} failed:\nSTDOUT:\n{check_proc.stdout}\nSTDERR:\n{check_proc.stderr}",
                )
                self.assertIn("wheel-smoke", check_proc.stdout)
                self.assertTrue(
                    list((run_cwd / "dist").glob("probe_svc_server-*.whl")),
                    "wheel-install smoke must produce probe_svc_server wheel in dist/",
                )

                # 3. Single-word rename round-trip: probe_svc -> nova -> probe_svc
                for target_prefix, expected_kebab, expected_snake, expected_screaming, expected_pascal in (
                    ("nova", "nova", "nova", "NOVA", "Nova"),
                    ("probe_svc", "probe-svc", "probe_svc", "PROBE_SVC", "ProbeSvc"),
                ):
                    ren_proc = subprocess.run(
                        ["uv", "run", "xtask", "rename", target_prefix],
                        cwd=str(run_cwd),
                        env=run_env,
                        shell=False,
                        timeout=600,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        ren_proc.returncode,
                        0,
                        f"uv run xtask rename {target_prefix} failed:\nSTDOUT:\n{ren_proc.stdout}\nSTDERR:\n{ren_proc.stderr}",
                    )
                    ci_proc = subprocess.run(
                        list(plan.check.cmd),
                        cwd=str(run_cwd),
                        env=run_env,
                        shell=False,
                        timeout=900,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        ci_proc.returncode,
                        0,
                        f"uv run xtask ci after rename {target_prefix} failed:\nSTDOUT:\n{ci_proc.stdout}\nSTDERR:\n{ci_proc.stderr}",
                    )
                    self.assertTrue(
                        (
                            run_cwd
                            / "packages"
                            / "apps"
                            / f"{expected_kebab}-server"
                            / "src"
                            / f"{expected_snake}_server"
                        ).is_dir()
                    )
                    env_txt = (run_cwd / ".env.example").read_text(encoding="utf-8")
                    self.assertIn(f"{expected_screaming}_HTTP__ADAPTER=fastapi", env_txt)
                    index_txt = (run_cwd / "00-INDEX.md").read_text(encoding="utf-8")
                    self.assertIn(f"{expected_pascal}Settings", index_txt)
                    readme_txt = (run_cwd / "README.md").read_text(encoding="utf-8")
                    self.assertIn(expected_kebab, readme_txt)
            finally:
                discard(proposal)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
