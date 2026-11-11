#!/usr/bin/env python3
"""Generate audit/evidence_wiring.py from the wiring sheets in audit/wiring/*.json.

Usage: python3 scripts/gen_audit_wiring.py [--wiring-dir DIR] [--out FILE] [--check]

The sheets are the single source of truth for what the nine wired audit
sections may store: report keys, vocabulary tokens, finding rule ids, their
fixed consequence sentences and the finding evidence keys. This script
validates every sheet and writes a deterministic (sorted), human-reviewable
Python module that the shared sealing sets union in. ``--check`` writes
nothing and exits 1 when the existing file differs from what would be
generated. Standard library only; the generated module imports nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WIRING_DIR = REPO_ROOT / "audit" / "wiring"
DEFAULT_OUT = REPO_ROOT / "audit" / "evidence_wiring.py"

REQUIRED_FIELDS = (
    "section", "entry", "kwargs", "schema_keys", "vocabulary", "numeric_evidence_keys",
    "vocab_evidence_keys", "rule_ids", "classifications", "consequences", "free_strings",
    "run_metrics_keys", "notes",
)
CLASSIFICATIONS = frozenset(("info", "review_suggested", "warning"))
PLACEHOLDER_RE = re.compile(r"[{}]|%s")

# Order in which audit_surface calls the sections (each sheet must appear once).
CALL_ORDER = (
    "home_workdirs", "secret_file_copies", "dead_stores", "profile_duplicates", "skill_ledger",
    "skill_packs", "unattended_exposure", "memory_load", "kanban_residue",
)

# Sentences for the two fallback rules audit_surface emits for every section:
# <section>.unverified (not collected: bounded audit) and
# <section>.operational_error (the collector raised or returned an error).
# section -> (what was measured, what a missing measurement does not establish, check name)
FALLBACKS = {
    "home_workdirs": ("Home work-folder measurements",
                      "that the home holds no work folders, working trees or large files",
                      "Home work-folder"),
    "secret_file_copies": ("Secret-file copy measurements",
                           "that no copies of secret-named files exist",
                           "Secret-file copy"),
    "dead_stores": ("Unused-store measurements",
                    "that the home holds no unused plugin data, caches, backups or logs",
                    "Unused-store"),
    "profile_duplicates": ("Profile duplicate measurements",
                           "that profiles hold no duplicated files",
                           "Profile duplicate"),
    "skill_ledger": ("Skill change-ledger measurements",
                     "that skills were not changed or that no bookkeeping is orphaned",
                     "Skill change-ledger"),
    "skill_packs": ("Skill pack measurements",
                    "that installed skills are used or that their index is small",
                    "Skill pack"),
    "unattended_exposure": ("Unattended exposure measurements",
                            "that commands, plugins or scheduled jobs need a person's approval",
                            "Unattended exposure"),
    "memory_load": ("Memory load measurements",
                    "that memory files are within their limits or free of repeated entries",
                    "Memory load"),
    "kanban_residue": ("Kanban residue measurements",
                       "that the kanban store holds no leftover tasks or boards",
                       "Kanban residue"),
}

# Whitespace-containing "vocabulary" entries. A sheet's own consequence
# sentences need no entry here: they reach VOCABULARY through
# ALLOWED_FINDING_CONSEQUENCES and are left out of WIRED_VOCABULARY. Any other
# whitespace entry must be a fixed sentence the section emits as a VALUE and be
# listed here by section; those go to WIRED_FIXED_SENTENCES (kept apart from
# the token set so WIRED_VOCABULARY stays whitespace-free). Anything else with
# whitespace is a validation error.
FIXED_SENTENCE_VALUES = {
    "secret_file_copies": (
        "Counted apart from work folders because names alone cannot tell test values from real "
        "secrets; the audit opened no file.",
    ),
    # Also a code label in audit/evidence.py (CODE_LABELS); listed for completeness.
    "unattended_exposure": ("static inspection only; not runtime safety",),
}


# Words that existing hardening tests require to be sealed when they appear as
# plain values, so they can never be VOCABULARY:
# - fields of the serializer's own sealed leaves (audit/evidence.py), pinned by
#   tests/test_audit_sealing_and_key_durability.py::test_audit_schema_provenance;
# - identifier-like words pinned by
#   tests/test_audit_gate_regressions.py::test_audit_vocabulary_is_schema_not_identifier_scrape.
# A sheet that lists one of these words in its vocabulary fails generation: such
# a value would be sealed as a per-run token (and dropped from finding evidence).
# The emitting module must emit an unambiguous label instead (for example
# executable_file, approval_off, backup_off, secret_word).
RESERVED_VALUES = frozenset((
    "value", "location", "hmac", "argument_count", "arguments", "executable", "hosts",
    "root", "password", "secret", "repr", "object_hook", "compute_headline", "on", "off",
))


def fallback_sentences(section: str) -> dict[str, str]:
    measured, not_established, check = FALLBACKS[section]
    return {
        section + ".unverified": (f"{measured} were not collected or could not be verified. "
                                  f"Missing measurements do not establish {not_established}."),
        section + ".operational_error": (f"{check} check could not complete verification; "
                                         "missing measurements are not a clean result."),
    }


def load_sheets(wiring_dir: Path) -> list[dict]:
    sheets = []
    for path in sorted(Path(wiring_dir).glob("*.json")):
        sheet = json.loads(path.read_text(encoding="utf-8"))
        sheet["_file"] = path.name
        sheets.append(sheet)
    return sheets


def _strings(value) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def validate(sheets: list[dict]) -> list[str]:
    errors: list[str] = []
    seen_rules: dict[str, str] = {}
    sections = []
    for sheet in sheets:
        name = sheet.get("_file", "?")
        missing = [field for field in REQUIRED_FIELDS if field not in sheet]
        if missing:
            errors.append(f"{name}: missing field(s) {', '.join(missing)}")
            continue
        section = sheet["section"]
        sections.append(section)
        if not isinstance(section, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", section):
            errors.append(f"{name}: invalid section name {section!r}")
            continue
        if name != section + ".json":
            errors.append(f"{name}: file name does not match section {section}")
        for field in ("schema_keys", "vocabulary", "numeric_evidence_keys", "vocab_evidence_keys",
                      "rule_ids", "run_metrics_keys"):
            if not (_strings(sheet[field]) or sheet[field] == []):
                errors.append(f"{name}: {field} must be a list of non-empty strings")
        if not isinstance(sheet["consequences"], dict):
            errors.append(f"{name}: consequences must be an object")
            continue
        own_sentences = set(sheet["consequences"].values())
        reserved = sorted(set(sheet["vocabulary"]) & RESERVED_VALUES)
        if reserved:
            errors.append(f"{name}: vocabulary lists {reserved}, words that existing tests require to be "
                          "sealed as plain values (RESERVED_VALUES); rename the label the module emits")
        for token in sheet["vocabulary"]:
            if (re.search(r"\s", token) and token not in own_sentences
                    and token not in FIXED_SENTENCE_VALUES.get(section, ())):
                errors.append(f"{name}: vocabulary token contains whitespace: {token[:60]!r}")
        for field in ("schema_keys", "numeric_evidence_keys", "vocab_evidence_keys"):
            for token in sheet[field]:
                if re.search(r"\s", token):
                    errors.append(f"{name}: {field} entry contains whitespace: {token[:60]!r}")
        overlap = set(sheet["numeric_evidence_keys"]) & set(sheet["vocab_evidence_keys"])
        if overlap:
            errors.append(f"{name}: keys listed as both numeric and vocabulary evidence: {sorted(overlap)}")
        for rule in sheet["rule_ids"]:
            if not rule.startswith(section + "."):
                errors.append(f"{name}: rule id {rule} is outside its section prefix {section}.")
            if rule not in sheet["consequences"]:
                errors.append(f"{name}: rule id {rule} has no consequence")
            if rule in seen_rules:
                errors.append(f"{name}: duplicate rule id {rule} (also in {seen_rules[rule]})")
            seen_rules.setdefault(rule, name)
        for rule, sentence in sheet["consequences"].items():
            if rule not in sheet["rule_ids"]:
                errors.append(f"{name}: consequence for {rule}, which is not in rule_ids")
            if not isinstance(sentence, str) or not sentence.strip():
                errors.append(f"{name}: consequence for {rule} is not a sentence")
            elif PLACEHOLDER_RE.search(sentence):
                errors.append(f"{name}: consequence for {rule} contains a placeholder")
        for rule in fallback_sentences(section) if section in FALLBACKS else ():
            if rule in sheet["rule_ids"]:
                errors.append(f"{name}: {rule} is a fallback rule the generator owns")
        classifications = sheet["classifications"]
        if not isinstance(classifications, dict):
            errors.append(f"{name}: classifications must be an object")
        else:
            for rule, values in classifications.items():
                if rule not in sheet["rule_ids"] or not _strings(values) or not set(values) <= CLASSIFICATIONS:
                    errors.append(f"{name}: invalid classifications for {rule}")
        if section not in FALLBACKS:
            errors.append(f"{name}: section {section} has no fallback sentences in the generator")
        if section not in CALL_ORDER:
            errors.append(f"{name}: section {section} is not in CALL_ORDER")
    if sorted(sections) != sorted(CALL_ORDER):
        errors.append(f"sections {sorted(sections)} do not match CALL_ORDER {sorted(CALL_ORDER)}")
    sentences: dict[str, str] = {}
    for sheet in sheets:
        if not isinstance(sheet.get("consequences"), dict) or sheet.get("section") not in FALLBACKS:
            continue
        for rule, sentence in {**sheet["consequences"], **fallback_sentences(sheet["section"])}.items():
            if sentence in sentences and sentences[sentence] != rule:
                errors.append(f"consequence sentence shared by {sentences[sentence]} and {rule}")
            sentences.setdefault(sentence, rule)
    return errors


def _frozenset(name: str, items) -> list[str]:
    lines = [f"{name} = frozenset(("]
    lines += [f"    {item!r}," for item in sorted(set(items))]
    lines.append("))")
    return lines


def render(sheets: list[dict]) -> str:
    schema, vocab, numeric, vocab_keys, rules, fixed = (set() for _ in range(6))
    consequences: dict[str, str] = {}
    for sheet in sheets:
        section = sheet["section"]
        schema.update(sheet["schema_keys"])
        schema.add(section)
        vocab.update(token for token in sheet["vocabulary"] if not re.search(r"\s", token))
        vocab.add(section)
        fixed.update(token for token in sheet["vocabulary"]
                     if re.search(r"\s", token) and token in FIXED_SENTENCE_VALUES.get(section, ()))
        numeric.update(sheet["numeric_evidence_keys"])
        vocab_keys.update(sheet["vocab_evidence_keys"])
        rules.update(sheet["rule_ids"])
        consequences.update(sheet["consequences"])
        fallbacks = fallback_sentences(section)
        rules.update(fallbacks)
        consequences.update(fallbacks)
    lines = [
        "# GENERATED FILE: do not edit. Regenerate with: python3 scripts/gen_audit_wiring.py",
        "# Source: audit/wiring/*.json (one sheet per wired audit section).",
        '"""Sealing data for the wired audit sections, unioned into the shared sets.',
        "",
        "audit/evidence_vocabulary.py adds them to SCHEMA_KEYS and VOCABULARY (tokens",
        "and fixed sentences), audit/evidence_constants.py to RULE_IDS and",
        "FINDING_CONSEQUENCES, audit/persistence.py to the finding evidence key sets.",
        "This module imports nothing so that it can be imported first.",
        '"""',
        "",
        "# Call order in audit_surface._sweep.",
        "WIRED_SECTIONS = (",
        *[f"    {section!r}," for section in CALL_ORDER],
        ")",
        "",
        *_frozenset("WIRED_SCHEMA_KEYS", schema),
        "",
        *_frozenset("WIRED_VOCABULARY", vocab),
        "",
        "# Fixed sentences a section emits as values (not consequences).",
        *_frozenset("WIRED_FIXED_SENTENCES", fixed),
        "",
        *_frozenset("WIRED_NUMERIC_EVIDENCE_KEYS", numeric),
        "",
        *_frozenset("WIRED_VOCAB_EVIDENCE_KEYS", vocab_keys),
        "",
        *_frozenset("WIRED_RULE_IDS", rules),
        "",
        "WIRED_FINDING_CONSEQUENCES = {",
    ]
    for rule in sorted(consequences):
        lines.append(f"    {rule!r}:")
        lines.append(f"        {consequences[rule]!r},")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or '').splitlines()[0])
    parser.add_argument("--wiring-dir", type=Path, default=DEFAULT_WIRING_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true", help="exit 1 if --out differs; write nothing")
    args = parser.parse_args(argv)
    sheets = load_sheets(args.wiring_dir)
    errors = validate(sheets)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 2
    text = render(sheets)
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else None
        if current != text:
            print(f"{args.out} is out of date; regenerate with scripts/gen_audit_wiring.py", file=sys.stderr)
            return 1
        return 0
    args.out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
