"""`new --kit` stages in a writable temp folder when TMPDIR is read-only, like `new --template`."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

import pytest

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import kit_scaffold, scaffolder  # noqa: E402
from hermes_plugins.defuzz.kit_scaffold import discard_kit, propose_kit  # noqa: E402
from tests.test_kit_scaffold import FakeVideoBridge  # noqa: E402


def test_kit_scaffold_shares_the_scaffolder_stage_helper() -> None:
    assert kit_scaffold._writable_stage_parent is scaffolder._writable_stage_parent


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_propose_kit_falls_back_when_tmpdir_is_read_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    read_only = tmp_path / "ro-tmp"
    read_only.mkdir()
    dest_root = tmp_path / "projects"
    dest_root.mkdir()
    read_only.chmod(stat.S_IRUSR | stat.S_IXUSR)
    proposal = None
    try:
        if os.access(read_only, os.W_OK):
            pytest.skip("permissions are not enforced here")
        monkeypatch.setenv("TMPDIR", str(read_only))
        proposal = propose_kit(
            "video-production",
            "Launch Trailer",
            {"building": "video", "layout": "single", "languages": []},
            dest_root=dest_root,
            variables={"fps": "24"},
            bridge=FakeVideoBridge(),
        )
        assert proposal.staging_dir.is_dir()
        assert read_only not in proposal.staging_dir.parents
        assert proposal.staged.is_dir()
    finally:
        read_only.chmod(stat.S_IRWXU)
        if proposal is not None:
            discard_kit(proposal)
            shutil.rmtree(proposal.staging_dir, ignore_errors=True)
