"""Pytest/unittest wrapper that runs the Node unit tests for desktop/plugin.js createHandoff."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


class TestDesktopHandoff(unittest.TestCase):
    def test_desktop_handoff_node_suite(self) -> None:
        node_bin = shutil.which("node")
        if node_bin is None:
            self.skipTest("node binary not found in PATH")

        repo_root = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [node_bin, "--import", "./desktop/tests/sdk-shim.mjs", "--test", "desktop/tests/*.test.mjs"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
        self.assertEqual(
            proc.returncode,
            0,
            f"Node handoff test suite failed:\n{proc.stdout}\n{proc.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
