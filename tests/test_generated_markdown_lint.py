"""Golden generated guides obey Markdown rules without suppressions."""
import json
import shutil
import subprocess

import pytest
from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz.agents_md import render_agents_md_files


@pytest.mark.skipif(shutil.which("rumdl") is None, reason="rumdl not installed")
def test_default_guide_is_markdown_clean(tmp_path):
    files = render_agents_md_files(project_slug="acceptance-ts", declared_dirs={
        "packages": ("Layered packages with independent responsibilities", "Keep application and domain dependencies explicit and separate")
    }, placement_rules=[])
    assert len(files["AGENTS.md"].splitlines()) <= 40
    guide = tmp_path / "AGENTS.md"
    guide.write_text(files["AGENTS.md"])
    tool = shutil.which("rumdl")
    assert tool, "rumdl is required for this regression"
    result = subprocess.run([tool, "check", "--no-cache", "--output-format", "json", str(guide)], capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == []
