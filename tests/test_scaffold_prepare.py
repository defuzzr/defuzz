"""Preparation is explicit, checked, and precedes read-only scaffold CI."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.scaffolder import ScaffoldError, accept, propose
from hermes_plugins.defuzz.templates import TemplateError, _parse_check, load_template


@pytest.mark.parametrize("value", [[], "echo hi", [""], [3], None])
def test_prepare_rejects_invalid_argv(value):
    with pytest.raises(TemplateError, match="prepare"):
        _parse_check({"cmd": ["check"], "prepare": value}, "fixture")


@pytest.mark.parametrize("fail", [False, True])
def test_prepare_runs_after_context_and_before_check(tmp_path, fail):
    template = tmp_path / "fixture"
    source = template / "tmpl_prefix"
    source.mkdir(parents=True)
    # Keep a visible sentinel in generated metadata: regenerating after CI loses it.
    prepare = (
        "from pathlib import Path; "
        "assert Path('.adopt/rules.json').is_file(); "
        "assert Path('TOOLS.lock').is_file(); "
        "p=Path('AGENTS.md'); p.write_text(p.read_text()+'\\nPrepared context.\\n'); "
        f"raise SystemExit({int(fail)})"
    )
    check = (
        "from pathlib import Path; "
        "assert 'Prepared context.' in Path('AGENTS.md').read_text(); "
        "Path('checked.txt').write_text('checked')"
    )
    (template / "template.yaml").write_text(json.dumps({
        "id": "fixture", "name": "Fixture", "summary": "Preparation fixture",
        "kind": "app", "layout": "single", "languages": ["python"],
        "placeholder": "tmpl_prefix", "substitute_in": ["*.py"],
        "repos": [{"name": "tmpl_prefix", "check": {
            "prepare": [sys.executable, "-c", prepare],
            "cmd": [sys.executable, "-c", check], "cwd": ".",
        }}],
    }))
    proposal = propose(load_template(template), "example", {},
                       dest_root=tmp_path / "projects", staging_parent=tmp_path / "staging")
    kwargs = {"register": lambda *_: json.dumps({"success": True, "id": "test"}),
              "db_path": tmp_path / "state.db"}
    if fail:
        with pytest.raises(ScaffoldError, match="failed with exit code 1"):
            accept(proposal, **kwargs)
        assert not proposal.repos[0].dest.exists()
        assert not (proposal.repos[0].staged / "checked.txt").exists()
    else:
        result = accept(proposal, **kwargs)
        assert result.repos[0]["check"] == "ok"
        dest = Path(result.repos[0]["path"])
        assert "Prepared context." in (dest / "AGENTS.md").read_text()
        assert (dest / "checked.txt").read_text() == "checked"
