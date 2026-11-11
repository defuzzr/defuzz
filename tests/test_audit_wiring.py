"""The sealing sets for the nine wired audit sections are generated from audit/wiring/*.json."""
import importlib.util
import json

import pytest

from tests.conftest import REPO_ROOT, load_submodule

SCRIPT = REPO_ROOT / "scripts" / "gen_audit_wiring.py"
GENERATED = REPO_ROOT / "audit" / "evidence_wiring.py"
WIRING_DIR = REPO_ROOT / "audit" / "wiring"


def _gen():
    spec = importlib.util.spec_from_file_location("gen_audit_wiring", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sheets():
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(WIRING_DIR.glob("*.json"))]


def test_regenerating_gives_a_byte_identical_module(tmp_path):
    out = tmp_path / "evidence_wiring.py"
    assert _gen().main(["--wiring-dir", str(WIRING_DIR), "--out", str(out)]) == 0
    assert out.read_bytes() == GENERATED.read_bytes()
    # Deterministic: a second run gives the same bytes again.
    assert _gen().render(_gen().load_sheets(WIRING_DIR)).encode("utf-8") == out.read_bytes()


def test_check_mode_reports_drift(tmp_path):
    gen = _gen()
    assert gen.main(["--wiring-dir", str(WIRING_DIR), "--out", str(GENERATED), "--check"]) == 0
    stale = tmp_path / "evidence_wiring.py"
    stale.write_text(GENERATED.read_text(encoding="utf-8").replace("'home_workdirs',", "'home_workdirs', 'hand_added',", 1),
                     encoding="utf-8")
    assert gen.main(["--wiring-dir", str(WIRING_DIR), "--out", str(stale), "--check"]) == 1


def test_generated_module_imports_nothing_and_says_it_is_generated():
    text = GENERATED.read_text(encoding="utf-8")
    assert text.startswith("# GENERATED FILE")
    assert "scripts/gen_audit_wiring.py" in text.splitlines()[0] + text.splitlines()[1]
    assert not [line for line in text.splitlines() if line.startswith(("import ", "from "))]


def test_every_sheet_validates():
    gen = _gen()
    sheets = gen.load_sheets(WIRING_DIR)
    assert [s["section"] for s in sheets] == sorted(s["section"] for s in sheets)
    assert gen.validate(sheets) == []
    assert {s["section"] for s in sheets} == set(gen.CALL_ORDER)


@pytest.mark.parametrize("mutate, message", [
    (lambda s: s.pop("rule_ids"), "missing field"),
    (lambda s: s["rule_ids"].append("other_section.thing"), "outside its section prefix"),
    (lambda s: s["rule_ids"].append(s["section"] + ".no_sentence"), "no consequence"),
    (lambda s: s["consequences"].update({s["rule_ids"][0]: "Counted {n} items."}), "placeholder"),
    (lambda s: s["consequences"].update({s["rule_ids"][0]: "Counted %s items."}), "placeholder"),
    (lambda s: s["vocabulary"].append("two words"), "whitespace"),
])
def test_validation_rejects_bad_sheets(mutate, message):
    gen = _gen()
    sheets = gen.load_sheets(WIRING_DIR)
    mutate(sheets[0])
    errors = gen.validate(sheets)
    assert any(message in e for e in errors), errors


def test_validation_rejects_duplicate_rule_ids_across_sheets():
    gen = _gen()
    sheets = gen.load_sheets(WIRING_DIR)
    stolen = sheets[0]["rule_ids"][0]
    sheets[1]["rule_ids"].append(stolen)
    sheets[1]["consequences"][stolen] = sheets[0]["consequences"][stolen]
    errors = gen.validate(sheets)
    assert any("duplicate rule id" in e for e in errors), errors


def test_no_sheet_key_or_token_is_missing_from_the_live_sets():
    ev = load_submodule("audit.evidence")
    voc = load_submodule("audit.evidence_vocabulary")
    ec = load_submodule("audit.evidence_constants")
    per = load_submodule("audit.persistence")
    for sheet in _sheets():
        section = sheet["section"]
        assert section in voc.SCHEMA_KEYS and section in voc.VOCABULARY and section in ev.VOCABULARY
        assert set(sheet["schema_keys"]) <= ev.SCHEMA_KEYS, set(sheet["schema_keys"]) - ev.SCHEMA_KEYS
        assert set(sheet["vocabulary"]) <= ev.VOCABULARY, set(sheet["vocabulary"]) - ev.VOCABULARY
        assert set(sheet["numeric_evidence_keys"]) <= per._EVIDENCE_NUMERIC_KEYS
        assert set(sheet["vocab_evidence_keys"]) <= per._EVIDENCE_VOCAB_KEYS
        assert set(sheet["rule_ids"]) <= ec.RULE_IDS
        for rule, sentence in sheet["consequences"].items():
            assert ec.FINDING_CONSEQUENCES[rule] == sentence
            assert per.FINDING_CONSEQUENCES[rule] == sentence
            assert sentence in ec.ALLOWED_FINDING_CONSEQUENCES
            assert sentence in per.ALLOWED_FINDING_CONSEQUENCES


def test_wired_sets_are_unioned_into_the_shared_sets():
    w = load_submodule("audit.evidence_wiring")
    voc = load_submodule("audit.evidence_vocabulary")
    ec = load_submodule("audit.evidence_constants")
    per = load_submodule("audit.persistence")
    assert w.WIRED_SCHEMA_KEYS <= voc.SCHEMA_KEYS
    assert w.WIRED_VOCABULARY <= voc.VOCABULARY
    assert w.WIRED_RULE_IDS <= ec.RULE_IDS
    assert w.WIRED_NUMERIC_EVIDENCE_KEYS <= per._EVIDENCE_NUMERIC_KEYS
    assert w.WIRED_VOCAB_EVIDENCE_KEYS <= per._EVIDENCE_VOCAB_KEYS
    assert set(w.WIRED_RULE_IDS) == set(w.WIRED_FINDING_CONSEQUENCES)
    for rule, sentence in w.WIRED_FINDING_CONSEQUENCES.items():
        assert ec.FINDING_CONSEQUENCES[rule] == sentence


def test_no_meaning_collision_between_numeric_and_vocabulary_evidence_keys():
    w = load_submodule("audit.evidence_wiring")
    per = load_submodule("audit.persistence")
    assert not (w.WIRED_NUMERIC_EVIDENCE_KEYS & per._EVIDENCE_VOCAB_KEYS)
    assert not (w.WIRED_VOCAB_EVIDENCE_KEYS & per._EVIDENCE_NUMERIC_KEYS)
    assert not (w.WIRED_NUMERIC_EVIDENCE_KEYS & w.WIRED_VOCAB_EVIDENCE_KEYS)


def test_both_fallback_rules_exist_for_every_section_with_fixed_sentences():
    w = load_submodule("audit.evidence_wiring")
    ec = load_submodule("audit.evidence_constants")
    assert len(w.WIRED_SECTIONS) == 9
    for section in w.WIRED_SECTIONS:
        assert section in w.WIRED_VOCABULARY and section in w.WIRED_SCHEMA_KEYS
        unverified = w.WIRED_FINDING_CONSEQUENCES[section + ".unverified"]
        assert "were not collected or could not be verified. Missing measurements do not establish" in unverified
        assert "could not complete verification" in w.WIRED_FINDING_CONSEQUENCES[section + ".operational_error"]
        for rule in (section + ".unverified", section + ".operational_error"):
            assert rule in ec.RULE_IDS


def test_no_consequence_sentence_is_shared_by_two_rules():
    ec = load_submodule("audit.evidence_constants")
    w = load_submodule("audit.evidence_wiring")
    by_sentence = {}
    for rule, sentence in ec.FINDING_CONSEQUENCES.items():
        by_sentence.setdefault(sentence, set()).add(rule)
    shared = {s: r for s, r in by_sentence.items() if len(r) > 1 and r & set(w.WIRED_RULE_IDS)}
    assert shared == {}


def test_reserved_values_are_never_vocabulary():
    """No sheet lists a word the hardening tests require to be sealed, and none is vocabulary."""
    w = load_submodule("audit.evidence_wiring")
    ev = load_submodule("audit.evidence")
    gen = _gen()
    assert not hasattr(w, "WIRED_VOCABULARY_WITHHELD")
    assert not (w.WIRED_VOCABULARY & gen.RESERVED_VALUES)
    serializer = ev.EvidenceSerializer()
    for token in gen.RESERVED_VALUES:
        assert token not in ev.VOCABULARY
        assert isinstance(serializer.serialize(token), ev.SealedEvidence), token
    for sheet in _sheets():
        assert not set(sheet["vocabulary"]) & gen.RESERVED_VALUES, sheet["section"]


@pytest.mark.parametrize("word", ["executable", "off", "secret", "on", "root", "password", "value", "hosts"])
def test_a_sheet_listing_a_reserved_word_fails_generation(word, tmp_path):
    gen = _gen()
    sheets = gen.load_sheets(WIRING_DIR)
    sheets[0]["vocabulary"] = sorted(set(sheets[0]["vocabulary"]) | {word})
    errors = gen.validate(sheets)
    assert any(f"vocabulary lists ['{word}']" in e and "RESERVED_VALUES" in e for e in errors), errors
    wiring = tmp_path / "wiring"
    wiring.mkdir()
    for sheet in sheets:
        (wiring / sheet["_file"]).write_text(json.dumps({k: v for k, v in sheet.items() if k != "_file"}),
                                             encoding="utf-8")
    out = tmp_path / "evidence_wiring.py"
    assert gen.main(["--wiring-dir", str(wiring), "--out", str(out)]) == 2
    assert not out.exists()


def test_emitted_labels_use_unambiguous_tokens():
    """The renamed labels are vocabulary; the plain words they replace are not in any sheet."""
    ev = load_submodule("audit.evidence")
    serializer = ev.EvidenceSerializer()
    for token in ("executable_file", "approval_off", "backup_off", "secret_word"):
        assert token in ev.VOCABULARY
        assert serializer.serialize({"file_kind": token}) == {"file_kind": token}
