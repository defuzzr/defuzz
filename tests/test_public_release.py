"""Release hygiene and code contracts, independent of README wording."""



import ast
import hashlib
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from .conftest import REPO_ROOT, load_submodule

README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")


NEW_AUDIT_SECTIONS = (
    "home_workdirs", "secret_file_copies", "dead_stores", "profile_duplicates", "skill_ledger",
    "skill_packs", "unattended_exposure", "memory_load", "kanban_residue",
)
_SKIP_TREES = ("tests/", "templates/", ".git/", ".worktrees/")


def _flat(text):
    return " ".join(text.split())


def _plugin_sources(*extra_skips):
    for path in sorted(REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if not rel.startswith(_SKIP_TREES + extra_skips):
            yield rel, path.read_text(encoding="utf-8")


def _export_module():
    spec = importlib.util.spec_from_file_location("export_public", REPO_ROOT / "scripts" / "export_public.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_readme_states_the_in_place_database_rule():
    source = (REPO_ROOT / "audit" / "readonly_db.py").read_text(encoding="utf-8")
    opener = source.split("def open_readonly_sqlite(", 1)[1].split("\ndef ", 1)[0]
    for token in ("'-journal'", "reason='hot_journal'", "pre_id.shm_identity is None",
                  "reason='wal_needs_index'", "'&immutable=1'"):
        assert token in opener, token
    outward = (REPO_ROOT / "audit" / "outward_db.py").read_text(encoding="utf-8")
    assert "open_readonly_sqlite(target" in outward
    for copier in ("tempfile", "mkdtemp", "shutil.copy", ".backup("):
        assert copier not in outward, copier


def test_readme_quotes_the_secret_filename_rule():
    scanner = load_submodule("scanner")
    assert scanner._is_secret_filename(".env.local") and not scanner._is_secret_filename(".env.example")
    scan_source = (REPO_ROOT / "scanner.py").read_text(encoding="utf-8")
    assert "sha256 = None if secret_by_name else _sha256_nofollow(f_full)" in scan_source


def test_adopt_copy_leaves_secret_named_files_behind_by_default(tmp_path):
    safety = load_submodule("safety")
    src = tmp_path / "src"
    (src / "deep").mkdir(parents=True)
    secret_payloads = {".env": b"TOKEN=x\n", "deep/id_rsa": b"key\n", "server.pem": b"pem\n"}
    plain_payloads = {"a.txt": b"plain\n", ".env.example": b"EXAMPLE=1\n"}
    for rel, data in {**secret_payloads, **plain_payloads}.items():
        (src / rel).write_bytes(data)

    left_behind = []
    dst_default = safety.copy_tree_nofollow(src, tmp_path / "copy_default", left_behind=left_behind)
    assert left_behind == sorted(secret_payloads)
    for rel in secret_payloads:
        assert not (dst_default / rel).exists(), rel
        assert (src / rel).read_bytes() == secret_payloads[rel], rel
    for rel, data in plain_payloads.items():
        assert hashlib.sha256((dst_default / rel).read_bytes()).digest() == hashlib.sha256(data).digest(), rel

    dst_opt_in = safety.copy_tree_nofollow(src, tmp_path / "copy_opt_in", include_secret_files=True)
    for rel, data in {**secret_payloads, **plain_payloads}.items():
        assert hashlib.sha256((dst_opt_in / rel).read_bytes()).digest() == hashlib.sha256(data).digest(), rel


def test_audit_section_modules_exist():
    pages = sorted(p.stem for p in (REPO_ROOT / "docs" / "audit-sections").glob("*.md"))
    assert sorted(NEW_AUDIT_SECTIONS) == pages
    for name in NEW_AUDIT_SECTIONS:
        assert (REPO_ROOT / "audit" / f"{name}.py").is_file(), name
        assert (REPO_ROOT / "audit" / "wiring" / f"{name}.json").is_file(), name


def test_readme_describes_defuzz_check():
    sc = load_submodule("structure_check")
    assert sc.BLOCKING_IDS == frozenset({"nested_project", "git_inside_git", "root_is_home_or_agent_home"})
    assert sc.exit_code({"status": "not_a_project", "findings": []}) == 2
    assert sc.exit_code({"status": "one_project", "findings": []}) == 0
    assert sc.exit_code({"status": "one_project", "findings": [{"id": "nested_project"}]}) == 1
    assert sc.exit_code({"status": "one_project", "findings": [{"id": "embedded_subproject"}]}) == 0


def test_readme_does_not_promise_digest_comparison():
    evidence = load_submodule("audit.evidence")
    assert evidence.EvidenceSerializer()._key != evidence.EvidenceSerializer()._key
    bounded = (REPO_ROOT / "tests" / "test_audit_bounded.py").read_text(encoding="utf-8")
    assert "again['canonical_digest'] != result['canonical_digest']" in bounded


def test_readme_matches_worktreeinclude_templates():
    includes = sorted((REPO_ROOT / "templates").glob("*/tmpl_prefix/.worktreeinclude"))
    assert includes
    for path in includes:
        entries = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
                   if ln.strip() and not ln.strip().startswith("#")]
        assert not any(e == ".env" or e.startswith(".env.") for e in entries), path
    rust = (REPO_ROOT / "templates" / "rust-golden" / "tmpl_prefix" / ".worktreeinclude").read_text(encoding="utf-8")
    assert ".cargo/config.local.toml" in rust.splitlines()


def test_no_shell_true_in_plugin_code():
    for rel, text in _plugin_sources():
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert not (isinstance(node.value, ast.Constant) and node.value.value is True), rel


def test_only_network_call_site_is_the_setup_download():
    pattern = re.compile(
        r"urlopen\(|build_opener\(|http\.client|^import socket|^import (?:requests|httpx|aiohttp)", re.MULTILINE
    )
    callers = [rel for rel, text in _plugin_sources("scripts/") if pattern.search(text)]
    assert callers == ["lint_setup.py"]


_EXPORTER = REPO_ROOT / "scripts" / "export_public.py"
_CATALOG = REPO_ROOT / "docs" / "catalog-entry.defuzz.yaml"
needs_exporter = pytest.mark.skipif(not _EXPORTER.is_file(),
                                    reason="scripts/export_public.py is maintainer release tooling, not shipped")
needs_catalog = pytest.mark.skipif(not _CATALOG.is_file(),
                                   reason="the draft catalog entry is maintainer material, not shipped")


@needs_exporter
def test_public_docs_contain_no_private_names():
    export = _export_module()
    for rel in ("README.md", "docs/DISCLOSURE-EVIDENCE.md", "docs/release-secret-scan.md"):
        assert export.file_problems(rel, (REPO_ROOT / rel).read_bytes()) == [], rel


def test_license_is_mit_with_owner_copyright():
    text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License\n")
    assert "Copyright (c) 2026 defuzzr" in text
    assert "Permission is hereby granted, free of charge, to any person obtaining a copy" in text
    assert 'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND' in text


def test_manifest_public_identity():
    manifest = yaml.safe_load((REPO_ROOT / "plugin.yaml").read_text(encoding="utf-8"))
    assert manifest["name"] == "defuzz"
    assert manifest["author"] == "defuzzr"
    assert manifest["license"] == "MIT"
    assert re.fullmatch(r">=\d+\.\d+\.\d+", manifest["requires_hermes"])


@needs_catalog
def test_catalog_entry_draft_matches_manifest():
    entry = yaml.safe_load((REPO_ROOT / "docs" / "catalog-entry.defuzz.yaml").read_text(encoding="utf-8"))
    manifest = yaml.safe_load((REPO_ROOT / "plugin.yaml").read_text(encoding="utf-8"))
    assert entry["name"] == manifest["name"]
    assert entry["repo"] == "https://github.com/defuzzr/defuzz"
    assert entry["maintainer"] == "defuzzr"
    assert entry["tier"] == "community"
    assert entry["requires_hermes"] == manifest["requires_hermes"]
    assert entry["version"] == manifest["version"]
    assert entry["platforms"] == ["linux"]
    assert not re.fullmatch(r"[0-9a-f]{40}", entry["sha"])  # placeholder until submission
    caps = entry["capabilities"]
    assert sorted(caps["provides_tools"]) == sorted(manifest["provides_tools"])
    assert sorted(caps["provides_hooks"]) == sorted(manifest["provides_hooks"])
    assert caps["provides_middleware"] == []
    assert caps["requires_env"] == list(manifest.get("requires_env") or [])


@needs_catalog
def test_catalog_description_matches_readme_disclosure():
    entry = yaml.safe_load((REPO_ROOT / "docs" / "catalog-entry.defuzz.yaml").read_text(encoding="utf-8"))
    description = entry["description"]
    for stale in ("temp dir", "temporary", "copied to a temp", "secret-named files included"):
        assert stale not in description.lower(), stale
    for concept in ("read in place", "never opened", "byte for byte", "--include-secret-files", "ctx.llm", "--deterministic",
                    "static.rust-lang.org", "go.dev", "builds.dotnet.microsoft.com", "github.com",
                    "hermes componentize", "pre_tool_call", "transform_tool_result", "tools.registry",
                    "No telemetry", "defuzz check"):
        assert concept in description, concept


@pytest.mark.skipif(not os.environ.get("DEFUZZ_HERMES_SOURCE") or not _EXPORTER.is_file(),
                    reason="set DEFUZZ_HERMES_SOURCE to a hermes-agent checkout (and keep the exporter) "
                           "to re-measure the scanner findings")
def test_real_scanner_high_findings_match_readme(tmp_path, monkeypatch):
    src = Path(os.environ["DEFUZZ_HERMES_SOURCE"]).resolve()
    dest = tmp_path / "export"
    subprocess.run([sys.executable, str(_EXPORTER), "--dest", str(dest)],
                   cwd=REPO_ROOT, check=True, capture_output=True)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    monkeypatch.syspath_prepend(str(src))
    from tools.plugin_guard import scan_plugin  # noqa: PLC0415
    result = scan_plugin(dest)
    assert result.verdict == "caution"
    assert not [f for f in result.findings if f.severity == "critical"]


def test_creation_git_preflight():
    safety = (REPO_ROOT / "safety.py").read_text(encoding="utf-8")
    assert "git is required but was not found on PATH; install git" in safety
    scaffolder = (REPO_ROOT / "scaffolder.py").read_text(encoding="utf-8")
    assert "Destination already exists: {plan.dest}" in scaffolder
    # Templates check git before anything runs; kits only after the move.
    assert 'raise ScaffoldError(f"{exc}. Nothing was created.", staging_dir=proposal.staging_dir)' in scaffolder
    assert "ensure_git_available" not in (REPO_ROOT / "kit_scaffold.py").read_text(encoding="utf-8")


def test_python_template_floor():
    lock = (REPO_ROOT / "templates/python-golden/tmpl_prefix/uv.lock").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.13"' in lock


def test_creation_network_failure_handling():
    cli = (REPO_ROOT / "cli.py").read_text(encoding="utf-8")
    assert "return 3 if isinstance(exc, ScaffoldTimeout) else 1" in cli
    assert "network_failure" in (REPO_ROOT / "kit_scaffold.py").read_text(encoding="utf-8")


def test_setup_tool_locations():
    lint_env = load_submodule("lint_env")
    lint_setup = load_submodule("lint_setup")
    assert lint_env.INSTALL_ROOT_REL == Path(".local/opt/defuzz")
    assert lint_setup.pwsh_modules_root(("linux", "x86_64"), Path("/h")) == Path("/h/.local/share/powershell/Modules")
    assert lint_setup._PWSH_MODULE_MARKER == ".defuzz-installed"
    assert lint_env.managed_install_root({"DEFUZZ_INSTALL_ROOT": "/opt/x/tools"}) == Path("/opt/x/tools")


def test_chat_exit_and_test_guard():
    init = (REPO_ROOT / "__init__.py").read_text(encoding="utf-8")
    assert 'text = f"{text}\\n{app_line}".strip()' in init
    assert 'return f"{text}\\n{label} exit code: {code}".strip()' in init
    conftest_source = (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    assert "raise SystemExit(int(pytest.ExitCode.USAGE_ERROR))" in conftest_source
    assert int(pytest.ExitCode.USAGE_ERROR) == 4
    from . import conftest as live_conftest  # noqa: PLC0415
    guarded = [Path(p).name for p in live_conftest._PROTECTED]
    assert guarded == [".hermes", ".hermes-qol", "Projects"]
    assert "read_roots=(str(REPO_ROOT),)" in conftest_source


def test_desktop_creation_and_naming_contracts():
    page = (REPO_ROOT / "desktop" / "plugin.js").read_text(encoding="utf-8")
    found = re.search(r"export const SCAFFOLD_ACCEPT_TIMEOUT_MS = (\d+)\n", page)
    assert found is not None
    accept_ms = int(found.group(1))
    assert "}, { timeoutMs: SCAFFOLD_ACCEPT_TIMEOUT_MS, onError })" in page
    assert "'The project is still being created." in page
    assert "export const SCAFFOLD_POLL_INTERVAL_MS = 1500\n" in page
    assert "export const SCAFFOLD_POLL_LIMIT_MS = 15 * 60 * 1000\n" in page
    jobs = (REPO_ROOT / "dashboard" / "routes" / "accept_jobs.py").read_text(encoding="utf-8")
    assert "ACCEPT_INLINE_WAIT_S = 20.0" in jobs
    routes = (REPO_ROOT / "dashboard" / "routes" / "workspace_routes.py").read_text(encoding="utf-8")
    assert "_PROPOSAL_TTL_S = 30 * 60.0" in routes
    output_file = (REPO_ROOT / "output_file.py").read_text(encoding="utf-8")
    assert 'ADOPT_COMPLETE_MARKER = (".adopt", "adopt-complete.json")' in output_file
    assert "is incomplete: delete it and run again." in output_file
    recover = page.split("const recoverLostAccept = async name => {", 1)[1].split("\n  }\n", 1)[0]
    assert "await model.load()" in recover and "ACCEPT_RECHECK_MS" in recover
    naming = load_submodule("naming")
    assert naming.slugify("Caf\u00e9 Noir") == "cafe-noir"
    assert naming.folder_name("Caf\u00e9 Noir") == "caf\u00e9-noir"
    assert load_submodule("kit_scaffold").UNICODE_FOLDER_KITS is False
    assert re.fullmatch(r"project-[0-9a-f]{8}", naming.slugify("\u65e5\u672c"))
    assert load_submodule("audit.bounded_call").DEFAULT_COMPONENT_BUDGET_S == 60.0
    notice = (REPO_ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "Copyright (c) 2025 Nous Research" in notice


def test_companion_version_envelope():
    bridge = (REPO_ROOT / "componentize_bridge.py").read_text(encoding="utf-8")
    assert "_COMPANION_VERSION_RE = re.compile(r'componentize " in bridge


def test_audit_skipped_folder_policy():
    outward = load_submodule("audit.outward")
    summary = load_submodule("audit_summary")
    assert {"node_modules", "__pycache__"} <= outward.SKIPPED_FOLDER_NAMES
    codes = [code for code, _ in summary._SCOPE_SENTENCES]
    assert codes == ["skipped_folders", "entry_limit_exceeded", "total_byte_limit_exceeded", "time_budget"]


def test_adopt_output_protections():
    cli = (REPO_ROOT / "cli.py").read_text(encoding="utf-8")
    rules_writer = cli.split("def _write_rules_file(", 1)[1].split("\ndef ", 1)[0]
    assert "write_output_text(r_lex," in rules_writer and "forbidden_roots=forbidden_roots" in rules_writer
    assert cli.count("_write_rules_file(rules_arg, rules_spec, (copy_path, source_path))") == 2
    scanner = (REPO_ROOT / "scanner.py").read_text(encoding="utf-8")
    assert 'write_output_text(out_lex, inventory_text, role="inventory_out", forbidden_roots=(copy_root, src_lex))' in scanner
    applier = (REPO_ROOT / "applier.py").read_text(encoding="utf-8")
    assert "assert_disjoint_roots(source=effective_source, staging=report_out_path, output=copy_root)" in applier
    assert "report_dest.write(report_json)" in applier and (
        "safe_write_text(self.path.parent, self.path.name, text, overwrite=True, base=self.folder)" in applier)


def test_readme_requirements_match_manifest_and_ci():
    manifest = yaml.safe_load((REPO_ROOT / "plugin.yaml").read_text(encoding="utf-8"))
    ci = yaml.safe_load((REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    assert manifest["platforms"] == ["linux"]
    assert "linux only" in README.lower()
    assert manifest["requires_hermes"].removeprefix(">=") in README
    versions = ci["jobs"]["python"]["strategy"]["matrix"]["python"]
    floor = min(versions, key=lambda value: tuple(map(int, value.split("."))))
    assert re.search(rf"Python\s+{re.escape(floor)}\b", README)


def test_readme_is_lean_and_discloses_machine_effects():
    assert len(README.splitlines()) <= 80
    for label in ("Reads", "Writes", "Runs", "Network", "Background processes", "Credentials and telemetry"):
        assert f"**{label}:**" in README
