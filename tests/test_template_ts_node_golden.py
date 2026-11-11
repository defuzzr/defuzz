"""Tests for the vendored ts-node-golden template, options schema, propose substitution, and xtask CI."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.scaffolder import discard, propose  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.templates import (  # type: ignore[import-not-found]  # noqa: E402
    OptionSpec,
    load_template,
    options_as_json,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = REPO_ROOT / "templates" / "ts-node-golden"
TEMPLATE_YAML = TEMPLATE_DIR / "template.yaml"
TMPL_REPO_DIR = TEMPLATE_DIR / "tmpl_prefix"


class TsNodeGoldenTemplateMetadataTests(unittest.TestCase):
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
        self.assertEqual(data["id"], "ts-node-golden")
        self.assertEqual(data["kind"], "service")
        self.assertEqual(data["layout"], "mono")
        self.assertEqual(data["languages"], ["typescript"])
        self.assertEqual(data["placeholder"], "tmpl_prefix")

        sub_in = list(data["substitute_in"])
        self.assertIn(".env.example", sub_in)
        self.assertIn("**/*.tmpl", sub_in)
        self.assertIn("pnpm-lock.yaml", sub_in)

        expected_locked = [
            "package.json",
            "pnpm-workspace.yaml",
            "biome.json",
            "tsconfig.base.json",
            "tsconfig.json",
            ".nvmrc",
            ".npmrc",
            ".github/workflows/*",
            "tools/xtask/**",
        ]
        self.assertEqual(data["locked"], expected_locked)

        lock_docs = list(
            yaml.safe_load_all((TMPL_REPO_DIR / "pnpm-lock.yaml").read_text(encoding="utf-8"))
        )
        ws_doc = yaml.safe_load(
            (TMPL_REPO_DIR / "pnpm-workspace.yaml").read_text(encoding="utf-8")
        )
        expected_deps_set: set[str] = set()
        for doc in lock_docs:
            if isinstance(doc, dict):
                for pkg_key in doc.get("packages", {}) or {}:
                    expected_deps_set.add(str(pkg_key).rsplit("@", 1)[0])
                for cat in (doc.get("catalogs", {}) or {}).values():
                    if isinstance(cat, dict):
                        expected_deps_set.update(str(k) for k in cat.keys())
        for cat_key in (ws_doc.get("catalog", {}) or {}).keys():
            expected_deps_set.add(str(cat_key))

        expected_deps = sorted(expected_deps_set)
        self.assertEqual(data["approved_deps"], {"typescript": expected_deps})

        spec = load_template(TEMPLATE_DIR)
        self.assertEqual(spec.id, "ts-node-golden")
        self.assertEqual(spec.locked, tuple(expected_locked))
        self.assertEqual(dict(spec.approved_deps), {"typescript": tuple(expected_deps)})
        self.assertEqual(len(spec.repos), 1)
        self.assertEqual(spec.repos[0].name, "tmpl_prefix")
        self.assertIsNotNone(spec.repos[0].check)
        assert spec.repos[0].check is not None
        self.assertEqual(spec.repos[0].check.cmd, ("pnpm", "xtask", "ci"))
        self.assertEqual(spec.repos[0].check.cwd, ".")

        # Verify frozen options schema from OPTIONS.md
        self.assertIn("http_adapter", spec.options)
        opt = spec.options["http_adapter"]
        self.assertIsInstance(opt, OptionSpec)
        self.assertEqual(opt.id, "http_adapter")
        self.assertEqual(opt.label, "HTTP adapter")
        self.assertEqual(opt.choices, ("hono", "node_http"))
        self.assertEqual(opt.default, "hono")
        self.assertEqual(opt.env_key, "TMPL_PREFIX_HTTP_ADAPTER")
        self.assertEqual(
            opt.description,
            "Both adapters ship; this picks the default wired in config.",
        )

        expected_options_json = [
            {
                "id": "http_adapter",
                "label": "HTTP adapter",
                "choices": ["hono", "node_http"],
                "default": "hono",
                "env_key": "TMPL_PREFIX_HTTP_ADAPTER",
                "description": "Both adapters ship; this picks the default wired in config.",
            }
        ]
        self.assertEqual(spec.options_as_json(), expected_options_json)
        self.assertEqual(options_as_json(spec), expected_options_json)

        self.assertTrue(TMPL_REPO_DIR.is_dir(), "tmpl_prefix directory must exist")
        self.assertTrue((TMPL_REPO_DIR / "package.json").is_file(), "package.json must exist")
        self.assertTrue((TMPL_REPO_DIR / "00-INDEX.md").is_file(), "00-INDEX.md must exist")
        self.assertTrue((TMPL_REPO_DIR / ".env.example").is_file(), ".env.example must exist")
        self.assertIn(
            "TMPL_PREFIX_HTTP_ADAPTER=hono",
            (TMPL_REPO_DIR / ".env.example").read_text(encoding="utf-8"),
        )

        for path in TMPL_REPO_DIR.rglob("*"):
            if path.is_file() and path.name != "README.md":
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("ts-node-golden", content, f"found 'ts-node-golden' in {path}")
                self.assertNotIn("ts_node_golden", content, f"found 'ts_node_golden' in {path}")

    def test_propose_probe_svc_substitutes_all_four_placeholder_forms(self) -> None:
        spec = load_template(TEMPLATE_DIR)
        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="ts-node-golden-propose-", dir=tmpdir_base))
        try:
            proposal = propose(
                spec,
                "Probe Svc",
                {
                    "building": "service",
                    "layout": "mono",
                    "languages": ["typescript"],
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
                self.assertTrue((staged / "packages" / "foundation" / "probe-svc-core").is_dir())
                self.assertTrue(
                    (staged / "packages" / "adapters" / "probe-svc-http-hono").is_dir()
                )
                self.assertTrue(
                    (staged / "packages" / "adapters" / "probe-svc-http-node").is_dir()
                )
                self.assertTrue((staged / "packages" / "apps" / "probe-svc-server").is_dir())
                self.assertTrue((staged / "packages" / "apps" / "probe-svc-cli").is_dir())

                # Verify all four forms in substituted files
                env_example = (staged / ".env.example").read_text(encoding="utf-8")
                self.assertIn("PROBE_SVC_HTTP_ADAPTER=hono", env_example)
                self.assertIn("PROBE_SVC_SERVICE_NAME=probe-svc-server", env_example)

                xtask_main = (staged / "tools" / "xtask" / "main.ts").read_text(encoding="utf-8")
                self.assertIn('export const PREFIX = "probe_svc";', xtask_main)

                readme_text = (staged / "README.md").read_text(encoding="utf-8")
                source_readme = (TMPL_REPO_DIR / "README.md").read_text(encoding="utf-8")
                expected_readme = source_readme
                for old, new in (
                    ("tmpl_prefix", "probe_svc"),
                    ("tmpl-prefix", "probe-svc"),
                    ("TMPL_PREFIX", "PROBE_SVC"),
                    ("TmplPrefix", "ProbeSvc"),
                ):
                    expected_readme = expected_readme.replace(old, new)
                self.assertEqual(expected_readme, readme_text)

                lock_text = (staged / "pnpm-lock.yaml").read_text(encoding="utf-8")
                self.assertIn("packages/adapters/probe-svc-http-hono:", lock_text)
                self.assertIn("probe-svc-core:", lock_text)

                tmpl_text = (staged / "templates" / "component.ts.tmpl").read_text(
                    encoding="utf-8"
                )
                self.assertIn("probe-svc-core", tmpl_text)

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


@unittest.skipUnless(shutil.which("pnpm") is not None, "pnpm not installed")
@unittest.skipIf(os.environ.get("ADOPT_SKIP_SLOW") == "1", "ADOPT_SKIP_SLOW=1")
class TsNodeGoldenScaffoldSlowTests(unittest.TestCase):
    """slow"""

    def test_propose_frozen_lockfile_check_and_rename_round_trip(self) -> None:
        spec = load_template(TEMPLATE_DIR)
        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="ts-node-golden-scaffold-", dir=tmpdir_base))
        try:
            proposal = propose(
                spec,
                "Probe Svc",
                {
                    "building": "service",
                    "layout": "mono",
                    "languages": ["typescript"],
                },
                dest_root=work_root / "dest",
                staging_parent=work_root / "staging",
            )
            try:
                plan = proposal.repos[0]
                self.assertIsNotNone(plan.check)
                assert plan.check is not None
                run_cwd = (plan.staged / plan.check.cwd).resolve()

                # 1. Verify --frozen-lockfile resolves directly after substitution
                frozen_proc = subprocess.run(
                    ["pnpm", "install", "--frozen-lockfile"],
                    cwd=str(run_cwd),
                    shell=False,
                    timeout=600,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    frozen_proc.returncode,
                    0,
                    f"pnpm install --frozen-lockfile failed:\nSTDOUT:\n{frozen_proc.stdout}\nSTDERR:\n{frozen_proc.stderr}",
                )

                # 2. Run repos.check explicitly (pnpm xtask ci)
                check_proc = subprocess.run(
                    list(plan.check.cmd),
                    cwd=str(run_cwd),
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

                # 3. Rename round-trip: probe_svc -> nova -> probe_svc
                for target_prefix, expected_kebab, expected_screaming, expected_pascal in (
                    ("nova", "nova", "NOVA", "Nova"),
                    ("probe_svc", "probe-svc", "PROBE_SVC", "ProbeSvc"),
                ):
                    ren_proc = subprocess.run(
                        ["pnpm", "xtask", "rename", target_prefix],
                        cwd=str(run_cwd),
                        shell=False,
                        timeout=600,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        ren_proc.returncode,
                        0,
                        f"pnpm xtask rename {target_prefix} failed:\nSTDOUT:\n{ren_proc.stdout}\nSTDERR:\n{ren_proc.stderr}",
                    )
                    ci_proc = subprocess.run(
                        list(plan.check.cmd),
                        cwd=str(run_cwd),
                        shell=False,
                        timeout=900,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        ci_proc.returncode,
                        0,
                        f"pnpm xtask ci after rename {target_prefix} failed:\nSTDOUT:\n{ci_proc.stdout}\nSTDERR:\n{ci_proc.stderr}",
                    )
                    self.assertTrue(
                        (run_cwd / "packages" / "apps" / f"{expected_kebab}-server").is_dir()
                    )
                    env_txt = (run_cwd / ".env.example").read_text(encoding="utf-8")
                    self.assertIn(f"{expected_screaming}_HTTP_ADAPTER=hono", env_txt)
                    readme_txt = (run_cwd / "README.md").read_text(encoding="utf-8")
                    self.assertIn(expected_kebab, readme_txt)
            finally:
                discard(proposal)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


XTASK_MAIN = TMPL_REPO_DIR / "tools" / "xtask" / "main.ts"


def _node_eval(script: str) -> subprocess.CompletedProcess[str]:
    node = shutil.which("node")
    if node is None:
        raise unittest.SkipTest("node not installed")
    return subprocess.run(
        [node, "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


class TsNodeGoldenNodeFloorTests(unittest.TestCase):
    def test_node_version_problem_compares_found_with_floor(self) -> None:
        script = (
            f"import {{ nodeVersionProblem }} from {str(XTASK_MAIN)!r};\n"
            "const cases = [['22.23.4', '24'], ['24.0.0', '24'], ['26.1.0', '24'], ['23.99.0', '24\\n']];\n"
            "for (const [f, r] of cases) console.log(JSON.stringify(nodeVersionProblem(f, r)));\n"
        )
        proc = _node_eval(script)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.strip().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertEqual(
            lines[0],
            '"This project needs Node.js 24 or newer, but this is Node.js 22.23.4."',
        )
        self.assertEqual(lines[1], "null")
        self.assertEqual(lines[2], "null")
        self.assertIn("Node.js 24 or newer", lines[3])
        self.assertIn("23.99.0", lines[3])

    def test_ci_and_prepare_scaffold_check_the_floor_first(self) -> None:
        text = XTASK_MAIN.read_text(encoding="utf-8")
        for case in ('case "ci": {', 'case "prepare-scaffold": {'):
            body = text.split(case, 1)[1].split("case ", 1)[0]
            self.assertIn("requireNodeFloor(root)", body, case)
