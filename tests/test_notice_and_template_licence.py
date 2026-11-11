"""NOTICE attributes the copied Hermes Agent text and ships in the export; the code
templates tell a new project's owner which licence applies without choosing one."""
import importlib.util
import re
import subprocess

import pytest

from .conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "export_public.py"
NOTICE = REPO_ROOT / "NOTICE"
THIS_FILE = "tests/test_notice_and_template_licence.py"
needs_exporter = pytest.mark.skipif(not SCRIPT.is_file(),
                                    reason="scripts/export_public.py is maintainer release tooling, not shipped")

# Distinctive lines of Hermes Agent prompt text (agent/prompt_builder.py). Each lies on
# one source line wherever it is copied, so a plain substring search finds every copy.
COPIED_TEXT_FINGERPRINTS = (
    "You are Hermes Agent, built by Nous Research.",
    "You MUST use your tools to take action",
    "<tool_persistence>",
    "# Google model operational directives",
    "Mid-turn, the user can steer you",
    "Memory is the narrow exception for facts that apply to EVERY",
    "Before replying, scan the skills below.",
    "is not listed: it shares both its name and its path",
    "[...truncated {filename}: kept {head_chars}+{tail_chars}",
)

CODE_TEMPLATES = ("cpp-golden", "dotnet-golden", "go-golden", "python-golden", "rust-golden", "ts-node-golden")


def _module():
    spec = importlib.util.spec_from_file_location("export_public", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tracked() -> list[str]:
    out = subprocess.run(["git", "-C", str(REPO_ROOT), "ls-files"], check=True, capture_output=True, text=True)
    return out.stdout.splitlines()


def _files_with_copied_text() -> set[str]:
    found = set()
    for rel in _tracked():
        if rel == THIS_FILE or not rel.endswith(".py"):
            continue
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(fingerprint in text for fingerprint in COPIED_TEXT_FINGERPRINTS):
            found.add(rel)
    return found


def _named_in_notice() -> set[str]:
    return set(re.findall(r"^- ([\w./-]+\.py):", NOTICE.read_text(encoding="utf-8"), re.MULTILINE))


def test_notice_names_every_file_with_copied_hermes_text():
    found = _files_with_copied_text()
    assert "audit/vendor/profile_context.py" in found  # the check itself still works
    named = _named_in_notice()
    assert found <= named, f"copied Hermes Agent text not attributed in NOTICE: {sorted(found - named)}"
    assert named <= found, f"NOTICE names files without copied text: {sorted(named - found)}"


def test_notice_carries_the_upstream_mit_notice():
    notice = NOTICE.read_text(encoding="utf-8")
    assert "Copyright (c) 2025 Nous Research" in notice
    assert "see LICENSE" in notice
    # The permission notice and disclaimer are the standard MIT text, the same as this
    # repository's own LICENSE below its copyright line.
    own = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    body = own.split("\n", 3)[3].lstrip("\n")
    assert body.startswith("Permission is hereby granted")
    assert notice.endswith("MIT License\n\nCopyright (c) 2025 Nous Research\n\n" + body)


@needs_exporter
def test_export_contains_license_and_notice(tmp_path):
    module = _module()
    assert module.REQUIRED == ("LICENSE", "NOTICE")
    dest = tmp_path / "out"
    module.export(REPO_ROOT, dest)
    for rel in ("LICENSE", "NOTICE"):
        assert (dest / rel).read_bytes() == (REPO_ROOT / rel).read_bytes(), rel


@needs_exporter
@pytest.mark.parametrize("missing", ["LICENSE", "NOTICE"])
def test_export_fails_without_a_licence_file(tmp_path, capsys, missing):
    repo = tmp_path / "repo"
    repo.mkdir()
    files = {"LICENSE": "MIT License\n", "NOTICE": "notices\n", "README.md": "# Demo\n"}
    del files[missing]
    for rel, text in files.items():
        (repo / rel).write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "--", *files], check=True)
    assert _module().main(["--dest", str(tmp_path / "out"), "--repo", str(repo)]) == 1
    assert f"{missing}:0: required licence file missing" in capsys.readouterr().err


@pytest.mark.parametrize("template", CODE_TEMPLATES)
def test_template_readme_states_the_licence_position(template):
    readme = (REPO_ROOT / "templates" / template / "tmpl_prefix" / "README.md").read_text(encoding="utf-8")
    licence = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    licence_name = licence.splitlines()[0].removesuffix(" License")
    copyright_line = next(line for line in licence.splitlines() if line.startswith("Copyright"))
    normalized = " ".join(readme.split())
    assert licence_name in normalized, template
    assert all(word in normalized for word in re.findall(r"\w+", copyright_line)), template
    assert re.search(r"choos\w*.*licen[cs]e", normalized, re.IGNORECASE), template


@pytest.mark.parametrize("template", CODE_TEMPLATES)
def test_template_ships_no_licence_and_claims_none(template):
    root = REPO_ROOT / "templates" / template / "tmpl_prefix"
    assert not [p for p in root.rglob("*") if p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING"))]
    claims = []
    for path in root.rglob("*"):
        if path.is_file() and path.name in {"pyproject.toml", "package.json", "go.mod", "Cargo.toml",
                                            "CMakeLists.txt", "vcpkg.json", "Directory.Build.props"}:
            for line in path.read_text(encoding="utf-8").splitlines():
                if re.match(r'\s*"?license"?\s*[=:]', line, re.IGNORECASE):
                    claims.append((str(path.relative_to(root)), line.strip()))
    if template == "rust-golden":
        # Member crates inherit `license.workspace = true`, so the workspace keeps a
        # value: an SPDX LicenseRef that says no licence has been chosen.
        assert claims == [("Cargo.toml", 'license = "LicenseRef-not-chosen" # choose a licence: see README.md')]
        assert "\npublish = false\n" in (root / "Cargo.toml").read_text(encoding="utf-8")
    else:
        assert claims == [], claims
