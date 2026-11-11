"""A kit project whose check fails only because it cannot download ends on the internet line."""
from __future__ import annotations

from pathlib import Path

import pytest
from tests import ensure_test_package

ensure_test_package()
from hermes_plugins.defuzz import network_failure as nf  # noqa: E402
from hermes_plugins.defuzz.kit_scaffold import accept_kit, discard_kit, propose_kit  # noqa: E402
from hermes_plugins.defuzz.scaffolder import ScaffoldError  # noqa: E402
from tests.test_kit_scaffold import FakeVideoBridge, _fake_register  # noqa: E402

OUTPUTS = Path(__file__).parent / "fixtures/network_failure"
NOTE = nf.network_required_note(projects_untouched=True)


def _fail_kit(tmp_path, detail, *, staging_inside=False):
    dest_root = tmp_path / "projects"
    dest_root.mkdir()
    staging_parent = dest_root / ".staging" if staging_inside else tmp_path / "staging"
    staging_parent.mkdir()
    bridge = FakeVideoBridge(
        check_ok=False, check_env_status="fail", check_notice="componentize kit check fail.",
        check_findings=[{"id": "setup", "severity": "error", "detail": detail}],
    )
    answers = {"building": "video", "layout": "single", "languages": []}
    prop = propose_kit("video-production", "Net Video", answers, dest_root=dest_root,
                       staging_parent=staging_parent, bridge=bridge)
    with pytest.raises(ScaffoldError) as info:
        accept_kit(prop, register=_fake_register, bridge=bridge)
    assert prop.staging_dir.is_dir() and not prop.dest.exists()
    discard_kit(prop)
    return info.value


@pytest.mark.parametrize("name", ["npm-install", "go-mod-download", "cargo-fetch", "uv-pip-install"])
def test_offline_kit_check_ends_with_internet_line(tmp_path, name):
    exc = _fail_kit(tmp_path, (OUTPUTS / f"{name}.txt").read_text(encoding="utf-8"))
    text = str(exc)
    assert text.splitlines()[-1] == NOTE
    assert text.count(NOTE) == 1
    assert exc.reason == nf.NETWORK_REQUIRED_REASON


def test_offline_kit_check_with_staging_in_projects_drops_claim(tmp_path):
    exc = _fail_kit(tmp_path, (OUTPUTS / "npm-install.txt").read_text(encoding="utf-8"), staging_inside=True)
    assert str(exc).splitlines()[-1] == nf.network_required_note(projects_untouched=False)


def test_other_kit_check_failure_has_no_internet_line(tmp_path):
    exc = _fail_kit(tmp_path, "renders directory is missing")
    assert "internet" not in str(exc)
    assert exc.reason is None
