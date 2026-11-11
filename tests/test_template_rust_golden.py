import fnmatch
import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.templates import load_template  # type: ignore[import-not-found]  # noqa: E402


REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = REPO_ROOT / "templates" / "rust-golden"
TEMPLATE_YAML = TEMPLATE_DIR / "template.yaml"
TMPL_REPO_DIR = TEMPLATE_DIR / "tmpl_prefix"

REPLACEMENTS = (
    ("tmpl_prefix", "scaffold_probe"),
    ("tmpl-prefix", "scaffold-probe"),
    ("TMPL_PREFIX", "SCAFFOLD_PROBE"),
    ("TmplPrefix", "ScaffoldProbe"),
)


def _apply_replacements(text: str) -> str:
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    return text


def _matches_substitute_in(rel_posix: str, patterns: list[str]) -> bool:
    basename = os.path.basename(rel_posix)
    for pat in patterns:
        if pat.startswith("**/"):
            sub_pat = pat[3:]
            if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, sub_pat) or fnmatch.fnmatch(basename, sub_pat):
                return True
        elif fnmatch.fnmatch(rel_posix, pat):
            return True
    return False


class RustGoldenTemplateMetadataTests(unittest.TestCase):
    def test_template_metadata_and_contents(self):
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
        self.assertEqual(data["id"], "rust-golden")
        self.assertEqual(data["kind"], "app")
        self.assertEqual(data["layout"], "mono")
        self.assertEqual(data["languages"], ["rust"])
        self.assertEqual(data["placeholder"], "tmpl_prefix")
        self.assertEqual(
            data["locked"],
            [
                "Cargo.toml",
                "clippy.toml",
                "rustfmt.toml",
                "rust-toolchain.toml",
                ".github/workflows/*",
                "xtask/**",
            ],
        )

        lock_data = tomllib.loads((TMPL_REPO_DIR / "Cargo.lock").read_text(encoding="utf-8"))
        external_crates = sorted(
            {
                pkg["name"]
                for pkg in lock_data.get("package", [])
                if "source" in pkg
            }
        )
        self.assertEqual(data["approved_deps"], {"rust": external_crates})

        spec = load_template(TEMPLATE_DIR)
        self.assertEqual(
            spec.locked,
            (
                "Cargo.toml",
                "clippy.toml",
                "rustfmt.toml",
                "rust-toolchain.toml",
                ".github/workflows/*",
                "xtask/**",
            ),
        )
        self.assertEqual(dict(spec.approved_deps), {"rust": tuple(external_crates)})

        self.assertTrue(TMPL_REPO_DIR.is_dir(), "tmpl_prefix directory must exist")
        self.assertTrue((TMPL_REPO_DIR / "Cargo.toml").is_file(), "Cargo.toml must exist")
        self.assertTrue((TMPL_REPO_DIR / "AGENTS.md").is_file(), "AGENTS.md must exist")

        for path in TMPL_REPO_DIR.rglob("*"):
            if path.is_file() and path.name != "README.md":
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("rust-golden", content, f"found 'rust-golden' in {path}")
                self.assertNotIn("rust_golden", content, f"found 'rust_golden' in {path}")


@unittest.skipUnless(shutil.which("cargo") is not None, "cargo not installed")
@unittest.skipIf(os.environ.get("ADOPT_SKIP_SLOW") == "1", "ADOPT_SKIP_SLOW=1")
class RustGoldenScaffoldSlowTests(unittest.TestCase):
    """slow"""

    def test_scaffold_and_cargo_xtask_ci(self):
        data = yaml.safe_load(TEMPLATE_YAML.read_text(encoding="utf-8"))
        substitute_in = list(data["substitute_in"])
        repo_entry = data["repos"][0]
        check_spec = repo_entry["check"]
        check_cmd = list(check_spec["cmd"])
        check_cwd = check_spec.get("cwd", ".")

        tmpdir_base = os.environ.get("TMPDIR") or None
        work_root = Path(tempfile.mkdtemp(prefix="rust-golden-scaffold-", dir=tmpdir_base))
        try:
            dest_repo = work_root / _apply_replacements(repo_entry["name"])
            shutil.copytree(TMPL_REPO_DIR, dest_repo, symlinks=True)

            # Rename placeholder in file and directory paths (bottom-up so children rename before parents)
            for root, dirs, files in os.walk(dest_repo, topdown=False):
                root_path = Path(root)
                for fname in files:
                    new_fname = _apply_replacements(fname)
                    if new_fname != fname:
                        (root_path / fname).rename(root_path / new_fname)
                for dname in dirs:
                    new_dname = _apply_replacements(dname)
                    if new_dname != dname:
                        (root_path / dname).rename(root_path / new_dname)

            # Substitute placeholder in matching file contents
            for path in dest_repo.rglob("*"):
                if not path.is_file():
                    continue
                rel_posix = path.relative_to(dest_repo).as_posix()
                if _matches_substitute_in(rel_posix, substitute_in):
                    raw = path.read_text(encoding="utf-8")
                    updated = _apply_replacements(raw)
                    if updated != raw:
                        path.write_text(updated, encoding="utf-8")

            run_cwd = (dest_repo / check_cwd).resolve()
            proc = subprocess.run(
                check_cmd,
                cwd=str(run_cwd),
                shell=False,
                timeout=900,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                print("STDOUT:\n", proc.stdout)
                print("STDERR:\n", proc.stderr)
            self.assertEqual(
                proc.returncode,
                0,
                f"check command {check_cmd!r} failed with exit code {proc.returncode}:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )
        finally:
            shutil.rmtree(work_root, ignore_errors=True)
