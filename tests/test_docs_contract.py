"""Release documentation contracts; behavior is exercised by the cited suites."""
import re
from pathlib import Path
from unittest.mock import patch

import pytest


def test_contracts_allow_equivalent_non_a05_prose(tmp_path):
    """Copy edits must not change the release contract being asserted."""
    original = text
    replacements = {
        "checked automatic migration": "automatic migration with integrity checks",
        "never overwritten": "not overwritten",
        "external bridge contract": "external contract for the bridge",
        "after successful acceptance": "after acceptance succeeds",
        "independent of enabled_on_adopt": "not controlled by enabled_on_adopt",
        "full project-outward static capture": "full static capture outward from the project",
        "Electron rendering is not certified": "Electron rendering remains uncertified",
        "staging is kept": "staging is retained",
        "durable per-profile audit key": "persistent per-profile audit key",
        "Linux only": "only Linux",
    }

    rewritten = []
    for source in (ROOT / "AGENTS.md", *ROOT.glob("docs/*.md")):
        path = source.relative_to(ROOT)
        doc = original(path)
        for before, after in replacements.items():
            doc = doc.replace(before, after)
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(doc, encoding="utf-8")
        if doc != original(path):
            rewritten.append(str(path))
    assert "AGENTS.md" in rewritten

    def rephrased(path):
        return (tmp_path / path).read_text(encoding="utf-8")

    with patch(__name__ + ".text", side_effect=rephrased):
        test_storage_documentation_matches_migration()
        test_release_disclosures_match_behavior()
        test_historical_design_is_not_a_current_debt_checklist()
        test_contracts_reject_non_a05_behavior_regressions()


_INTERNAL_DOCS_PRESENT = all((Path(__file__).resolve().parents[1] / rel).is_file()
                             for rel in ("docs/design-chosen-tools.md", "docs/plugin-readiness.md"))


@pytest.mark.skipif(not _INTERNAL_DOCS_PRESENT,
                    reason="design and readiness notes are maintainer documents, not shipped")
def test_historical_design_is_not_a_current_debt_checklist():
    if not _INTERNAL_DOCS_PRESENT:  # also called directly by the rephrasing test
        return
    doc = text("docs/design-chosen-tools.md")
    # Check the status notice, not historic proposal text below it.
    notice = doc.split("## The problem", 1)[0]
    concepts(notice, r"historical.{0,20}(?:design|rationale)",
             r"not.{0,20}current.{0,20}(?:checklist|gaps)",
             r"automatic.{0,40}lint hooks.{0,20}not.{0,30}delivered",
             path="docs/design-chosen-tools.md", guarantee="historical design status")
    for identifier in ("toolchk.py", "tool_seed.py", "scaffolder.py",
                       "cli.py", "tools-lock-spec.md", "scaffold-ci.md"):
        assert identifier in notice, identifier


def test_contracts_reject_non_a05_behavior_regressions():
    """Relaxed wording must still detect removed or reversed guarantees."""
    original = text
    cases = (
        (test_storage_documentation_matches_migration,
         "checked automatic migration", "automatic migration without integrity checks"),
        (test_storage_documentation_matches_migration,
         "legacy files remain untouched", "legacy files do not remain untouched"),
        (test_storage_documentation_matches_migration,
         "never overwritten", "always overwritten"),
        (test_storage_documentation_matches_migration, "WAL", "journal"),
    )
    # Match supported concept variants, never a single spelling in live prose.
    variants = {
        "checked automatic migration": r"(?:checked.{0,30}automatic.{0,30}migration|automatic.{0,30}migration.{0,40}(?:checks|checked))",
        "legacy files remain untouched": r"legacy.{0,30}untouched",
        "staging is kept": r"staging.{0,20}(?:kept|retained)",
        "optional failures leave project creation successful": r"\boptional\b.{0,30}\bfailures\b.{0,60}\bproject creation\b.{0,30}\bsuccessful\b",
        "never overwritten": r"(?:never|not).{0,20}overwritten",
        "after successful acceptance": r"after\s+(?:successful\s+acceptance|acceptance\s+succeeds)",
        "independent of enabled_on_adopt": r"(?:independent of|not controlled by).{0,5}enabled_on_adopt",
        "Electron rendering is not certified": r"Electron.{0,30}(?:not certified|uncertified)",
        "durable per-profile audit key": r"(?:durable|persistent)\s+per-profile\s+audit\s+key",
        "Linux only": r"\b(?:Linux\s+only|only\s+Linux)\b",
        "missing unrelated SDKs do not disable lint": r"missing unrelated SDKs.{0,20}(?:do not|never).{0,10}disable lint",
    }
    failures = []
    for contract, before, after in cases:
        changed_paths = []

        def changed(path):
            doc = original(path)
            mutated = re.sub(variants.get(before, re.escape(before)), after, doc,
                             flags=re.IGNORECASE)
            if mutated != doc:
                changed_paths.append(path)
            return mutated

        rejected = False
        with patch(__name__ + ".text", side_effect=changed):
            try:
                contract()
            except AssertionError:
                rejected = True
        assert changed_paths, f"Mutation did not change any document: {before}"
        if rejected:
            continue
        failures.append(f"{before} -> {after}")
    assert not failures, "Contracts accepted changed behavior: " + "; ".join(failures)


def test_docs_contract_failure_messages_identify_guarantee_and_path():
    for checker in (concepts, positive_concepts):
        try:
            checker("missing", r"staging.*kept", path="README.md",
                    guarantee="staging retention")
        except AssertionError as exc:
            assert "README.md" in str(exc)
            assert "staging retention" in str(exc)
        else:
            raise AssertionError("Missing guarantee was accepted")


ROOT = Path(__file__).resolve().parents[1]


def text(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


def concepts(doc, *patterns, path, guarantee):
    """Match related concepts locally, tolerating prose and Markdown copy edits.

    Keep machine identifiers literal. Regex alternatives cover wording, not
    behavior: negation and ordering remain part of the contract.
    """
    for pattern in patterns:
        assert re.search(pattern, doc, re.IGNORECASE), f"{path}: {guarantee}: {pattern}"


def positive_concepts(doc, *patterns, path, guarantee):
    """Require bounded concepts in a clause without negative polarity.

    Inspect the whole clause so a prefix such as 'no' or 'non-' cannot be
    skipped by an unanchored positive match. Do not borrow words across clauses.
    """
    clauses = re.split(r"[,.;!?]", doc)
    # "untouched" expresses the required preservation, not its negation.
    negative = (r"\b(?:no|not|never|non|without)\b|\b\w+n't\b"
                r"|\bun-(?=\w)|\bun(?!touched\b|related\b)\w+")
    for pattern in patterns:
        assert any(
            re.search(pattern, clause, re.IGNORECASE)
            and not re.search(negative, clause, re.IGNORECASE)
            for clause in clauses
        ), f"{path}: {guarantee} (positive clause required): {pattern}"


def test_storage_documentation_matches_migration():
    for path in ("AGENTS.md",):
        doc = text(path)
        for phrase in ("active profile", "SQLite", "backup", "WAL", "provenance", "state_store.py"):
            assert phrase in doc, (path, phrase)
        positive_concepts(doc,
                          r"(?:checked.{0,30}automatic.{0,30}migration|automatic.{0,30}migration.{0,40}(?:checks|checked))",
                          r"legacy.{0,30}untouched", path=path,
                          guarantee="checked migration and legacy preservation")
        concepts(doc, r"(?:never|not).{0,20}overwritten", path=path,
                 guarantee="existing destination preservation")
        assert "Never copy legacy databases automatically" not in doc
        assert "not copied or migrated automatically" not in doc


def test_componentize_documentation_matches_delivery():
    template = ROOT / "templates/python-golden/tmpl_prefix"
    for delivered in ("COMPONENTS.md", "componentize/spec.example.json", "tools/xtask/src/xtask/componentize.py"):
        assert (template / delivered).is_file(), delivered


def test_release_disclosures_match_behavior():
    for path in ('AGENTS.md',):
        policy = text(path)
        assert 'credential files are never opened' in policy
        assert 'lstat' in policy
        assert 'A05 is pending' not in policy
        assert 'pending owner decision' not in policy


def test_audit_fixed_declaration_source_docs_contract():
    from tests.conftest import load_submodule
    policy = load_submodule('audit.policy')
    disclosure = load_submodule('audit.evidence_constants').AUDIT_SCOPE_DISCLOSURE
    assert policy.DECLARATION_SOURCE_FILES == (
        'config.yaml', 'profiles/*/config.yaml', '.git/config',
        'settings.json', 'settings.toml', 'package.json', 'pyproject.toml',
        'Cargo.toml', 'pnpm-workspace.yaml',
    )
    for name in policy.DECLARATION_SOURCE_FILES:
        assert name in disclosure
    for doc in (disclosure,):
        assert 'Declaring a declaration source as a credential has no effect' in doc
        assert 'Git include' in doc
        for phrase in ('before registration inventory', 'declared template.yaml',
                       'declared directories are never traversed', 'without expanding quick scope'):
            assert phrase in doc
        assert 'could_not_verify' in doc
        assert 'credential_store_not_opened' in doc
