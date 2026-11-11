"""Characterization tests for audit/evidence*, audit/redaction.py and audit/contract.py."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest  # type: ignore[import-not-found]
from tests.conftest import load_submodule


def test_vocabulary_and_constants_invariants() -> None:
    import hashlib

    ec = load_submodule("audit.evidence_constants")
    ev = load_submodule("audit.evidence_vocabulary")
    ev_mod = load_submodule("audit.evidence")

    def _set_digest(items: frozenset[str]) -> str:
        return hashlib.sha256(json.dumps(sorted(items), ensure_ascii=True).encode()).hexdigest()

    assert isinstance(ec.RULE_IDS, frozenset)
    assert len(ec.RULE_IDS) == 248
    assert "audit_scope.unverified" in ec.RULE_IDS
    assert "tools_lock.unverified" in ec.RULE_IDS
    assert "memory.cross_project_exposure" in ec.RULE_IDS

    assert isinstance(ec.AUDIT_SCOPE_DISCLOSURE, str)
    assert "A05 is decided strict" in ec.AUDIT_SCOPE_DISCLOSURE
    assert isinstance(ec.SCOPE_LABELS, frozenset)
    assert len(ec.SCOPE_LABELS) == 15
    assert ec.AUDIT_SCOPE_DISCLOSURE in ec.SCOPE_LABELS

    assert isinstance(ev.SCHEMA_KEYS, frozenset)
    assert len(ev.SCHEMA_KEYS) == 1752  # + foreign_technology_reason (memory_load)
    assert "preservation_assessments" in ev.SCHEMA_KEYS
    assert "zero_counted_skills" in ev.SCHEMA_KEYS

    assert isinstance(ev.CREDENTIAL_KEY_LABELS, frozenset)
    assert len(ev.CREDENTIAL_KEY_LABELS) == 19
    assert {"api_key", "password", "env_file"} <= ev.CREDENTIAL_KEY_LABELS

    assert isinstance(ev.VOCABULARY, frozenset)
    assert len(ev.VOCABULARY) == 750  # + input_unknown, no_projects (memory_load reason codes)
    assert {"verified", "could_not_verify", "not_included", "user_data"} <= ev.VOCABULARY

    assert isinstance(ev_mod.CODE_LABELS, frozenset)
    # 204 base labels + 38 component time-budget sentences; 1198 words (with
    # credential_in_name) + the same 38 sentences.
    assert len(ev_mod.CODE_LABELS) == 242
    assert _set_digest(ev_mod.CODE_LABELS) == "62f9ed5b801b04551beec7a06c2b80c3907ffaeeca36c2647429f57ffe2e86ef"
    assert len(ev_mod.VOCABULARY) == 1242  # + skipped_folders (outward sweep), input_unknown, no_projects (memory_load),
    # default_profile_never_archived, active_profile_never_archived, within_active_threshold (profile age)
    assert _set_digest(ev_mod.VOCABULARY) == "6e8c2a2021b9985d2c442b8ca43587b16c5c9d9778e0084b056f4c9c41b334a7"
    assert ev_mod.RULE_IDS == ec.RULE_IDS
    assert ev_mod.SCOPE_LABELS == ec.SCOPE_LABELS
    assert ev_mod.SCHEMA_KEYS == ev.SCHEMA_KEYS
    assert ev_mod.CREDENTIAL_KEY_LABELS == ev.CREDENTIAL_KEY_LABELS
    assert ev.VOCABULARY <= ev_mod.VOCABULARY
    assert ec.RULE_IDS <= ev_mod.VOCABULARY
    assert ec.SCOPE_LABELS <= ev_mod.VOCABULARY
    assert ev_mod.CODE_LABELS <= ev_mod.VOCABULARY
    assert _set_digest(ec.RULE_IDS) == "1135c8ba1514d22f990377abae92d2bb96cef156808ea12312946e49d80347d9"
    assert _set_digest(ec.SCOPE_LABELS) == "7d188c20dff5447327a96f1fc65c2ad9679131216142b0d9fbfc5bf6d8c9bb63"
    assert _set_digest(ev.SCHEMA_KEYS) == "b25cb0b0a402787ff80675a07e99f33a27cb0a08cceb766e2952347f55a24c92"
    assert _set_digest(ev.CREDENTIAL_KEY_LABELS) == "38123ec86493bd8a9255c1a4fb4a1158afd74a38e29033f7722528f44a624110"
    assert _set_digest(ev.VOCABULARY) == "806f8b13b8f93fbe7804c1ce51f39e8d20feb3c103665ccdad197d3765372677"

    # The nine wired sections' share, generated from audit/wiring/*.json by
    # scripts/gen_audit_wiring.py. A token added to audit/evidence_wiring.py by
    # hand changes these digests (and the totals above); tests/test_audit_wiring.py
    # separately requires the module to equal a fresh regeneration from the sheets.
    w = load_submodule("audit.evidence_wiring")
    assert len(w.WIRED_SECTIONS) == 9
    assert _set_digest(w.WIRED_SCHEMA_KEYS) == "edeed5f8283a05443661b5b7ab938dced925df8a703cd27b4b3c74ebb993e9f3"
    assert _set_digest(w.WIRED_VOCABULARY) == "5f766a6600f11e81741a99d8f0418182e6c86d2868a62fa7f027ac327cd8733d"
    assert _set_digest(w.WIRED_FIXED_SENTENCES) == "e377f20b8a14f135f9d1476bd6a3968e828bd70e3f153696d35931f9f9b5be2f"
    assert _set_digest(w.WIRED_NUMERIC_EVIDENCE_KEYS) == "90a82ae99d0db3c0caa53f5327901d20cf73dfce4aa6b7043295b19e99c3a659"
    assert _set_digest(w.WIRED_VOCAB_EVIDENCE_KEYS) == "da160e8703867635f134b165f08b7ad16f68673dc6726a3fd2e96f7653689c3a"
    assert _set_digest(w.WIRED_RULE_IDS) == "e1bd0e3ca6b60c15c7a4f800be80752ff55a486dc20958d05d318efb7dab4ea4"
    assert hashlib.sha256(json.dumps(w.WIRED_FINDING_CONSEQUENCES, sort_keys=True).encode()).hexdigest() == (
        "95aa092c31d309396ca14f7a4ce9f53f87dd8e101c8cba7fa0288cd7b8152c22")
    assert w.WIRED_SCHEMA_KEYS <= ev.SCHEMA_KEYS and w.WIRED_VOCABULARY <= ev.VOCABULARY
    assert not hasattr(w, "WIRED_VOCABULARY_WITHHELD")
    assert {"executable_file", "approval_off", "backup_off", "secret_word"} <= w.WIRED_VOCABULARY
    assert not {"executable", "off", "secret"} & ev_mod.VOCABULARY
    assert w.WIRED_RULE_IDS <= ec.RULE_IDS


def test_evidence_sealed_types_and_serializer(tmp_path: Path) -> None:
    ev_mod = load_submodule("audit.evidence")
    redaction = load_submodule("audit.redaction")

    # Factory enforcement and format checks
    with pytest.raises(TypeError, match="Use the generated digest factory"):
        ev_mod.GeneratedDigest("a" * 64)
    with pytest.raises(ValueError, match="Invalid generated digest"):
        ev_mod.generated_digest("not-a-digest")
    gd = ev_mod.generated_digest("a" * 64)
    assert isinstance(gd, ev_mod.GeneratedDigest) and gd == "a" * 64

    with pytest.raises(TypeError, match="Use the control identity factory"):
        ev_mod.ControlIdentity("cross_" + "b" * 64)
    with pytest.raises(ValueError, match="Invalid control identity"):
        ev_mod.control_identity("invalid_" + "b" * 64)
    ci = ev_mod.control_identity("component_" + "b" * 64)
    assert isinstance(ci, ev_mod.ControlIdentity) and ci == "component_" + "b" * 64

    with pytest.raises(TypeError, match="Use the evidence serializer factory"):
        ev_mod.SealedKey("hmac:" + "c" * 64)
    with pytest.raises(ValueError, match="Invalid sealed key"):
        ev_mod.EvidenceSerializer._seal_key("bad-key")
    sk = ev_mod.EvidenceSerializer._seal_key("hmac:" + "c" * 64)
    assert isinstance(sk, ev_mod.SealedKey)

    # SealedEvidence immutability
    serializer = ev_mod.EvidenceSerializer()
    sealed = serializer.serialize("unlisted-scalar-value")
    assert isinstance(sealed, ev_mod.SealedEvidence)
    for mutator in (
        lambda: sealed.__setitem__("kind", "url"),
        lambda: sealed.__delitem__("kind"),
        lambda: sealed.clear(),
        lambda: sealed.pop("kind"),
        lambda: sealed.popitem(),
        lambda: sealed.setdefault("x", 1),
        lambda: sealed.update({"x": 1}),
        lambda: sealed.__ior__({"x": 1}),
    ):
        with pytest.raises(TypeError, match="Sealed evidence cannot be mutated"):
            mutator()

    # Endpoint serialization: valid vs invalid vs tainted
    ep_ok = ev_mod.EvidenceEndpoint(host="example.com", scheme="https", port=443)
    ep_ser = serializer.serialize(ep_ok)
    assert isinstance(ep_ser, ev_mod.SealedEvidence)
    assert ep_ser == {"scheme": "https", "host": "example.com", "port": 443}
    assert serializer.serialize(ep_ser) == ep_ser

    ep_bad_port = ev_mod.EvidenceEndpoint(host="example.com", scheme="https", port=70000)
    ep_bad_ser = serializer.serialize(ep_bad_port)
    assert ep_bad_ser["kind"] == "endpoint"

    # URL scalar serialization and taint handling
    url_ser = serializer.serialize("https://api.example.com:8443/v1/items")
    assert url_ser["kind"] == "url"
    assert url_ser["host"] == "api.example.com"
    assert url_ser["port"] == 8443

    # Command Evidence serialization (malformed quotes vs valid command)
    bad_cmd = ev_mod.Evidence(value='unclosed "quote', kind="command")
    bad_cmd_ser = serializer.serialize(bad_cmd)
    assert bad_cmd_ser["kind"] == "command"
    assert "arguments" not in bad_cmd_ser

    exe = tmp_path / "tool.sh"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    good_cmd = ev_mod.Evidence(value=f"{exe} arg1 arg2", kind="command", path=str(exe), line=5)
    good_cmd_ser = serializer.serialize(good_cmd)
    assert good_cmd_ser["kind"] == "command"
    assert good_cmd_ser["executable"] == str(exe.resolve())
    assert good_cmd_ser["argument_count"] == 2
    assert len(good_cmd_ser["arguments"]) == 2
    assert serializer.serialize(good_cmd_ser) == good_cmd_ser

    # Primitives, non-finite floats, cyclic structures, non-string dict keys
    assert serializer.serialize(None) is None
    assert serializer.serialize(True) is True
    assert serializer.serialize(42) == 42
    assert serializer.serialize(3.5) == 3.5
    with pytest.raises(ValueError, match="Non-finite audit evidence"):
        serializer.serialize(math.nan)
    with pytest.raises(ValueError, match="Audit evidence requires string keys"):
        serializer.serialize({1: "a"})
    with pytest.raises(ValueError, match="Unsupported audit evidence"):
        serializer.serialize(object())
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="Cyclic audit evidence"):
        serializer.serialize(cyclic)

    # Tainted URL host and tainted revalidation
    state = redaction.Taint()
    state.add("secret.example.com")
    token = redaction._CURRENT.set(state)
    try:
        tainted_url = ev_mod.serialize_evidence("https://secret.example.com/path")
        assert tainted_url["kind"] == "credential_overlap"
        pre_sealed = state.serializer._seal(scheme="https", host="secret.example.com", port=None)
        reval = state.serializer.serialize(pre_sealed)
        assert reval["host"] is None
    finally:
        redaction._CURRENT.reset(token)


def test_redaction_canonical_forms_observe_scrub_and_guarded_connection(tmp_path: Path) -> None:
    redaction = load_submodule("audit.redaction")
    ev_mod = load_submodule("audit.evidence")

    assert not redaction.sensitive("credential_file")
    assert not redaction.sensitive("credentials_file")
    assert redaction.sensitive("my_api_key")
    assert redaction.sensitive("nested.client-secret.value")
    assert not redaction.sensitive(123)

    forms = redaction.canonical_forms(" '%2F%2Ftmp%2FSecretDir%2F' ")
    assert "/tmp/SecretDir" in forms
    assert "//tmp/SecretDir" in forms
    assert "//tmp/secretdir" in forms

    state = redaction.Taint()
    # Observe cyclic value without infinite recursion
    cyclic_dict: dict[str, Any] = {"api_key": "CANARY_SECRET_ONE"}
    cyclic_dict["self"] = cyclic_dict
    state.observe_value(cyclic_dict)
    assert state.scrub("prefix CANARY_SECRET_ONE suffix") == "[redacted]"

    # Observe CLI flags in list and text
    state.observe_value(["--auth-token", "CANARY_FLAG_SEP", "--secret=CANARY_FLAG_EQ", "-p", "CANARY_PASS_FLAG"])
    assert state.scrub("CANARY_FLAG_SEP") == "[redacted]"
    assert state.scrub("CANARY_FLAG_EQ") == "[redacted]"
    assert state.scrub("CANARY_PASS_FLAG") == "[redacted]"

    # Unparseable YAML withholds source in extraction
    bad_yaml = b"api_key: [unclosed\n"
    out_bytes = redaction.extraction(path=Path("broken.yaml"), data=bad_yaml)
    assert out_bytes == b""

    # Nested redaction_scope reuses current Taint state
    @redaction.redaction_scope
    def outer() -> Any:
        s1 = redaction._CURRENT.get()
        redaction.observe_value({"password": "NESTED_SCOPE_CANARY"})

        @redaction.redaction_scope
        def inner() -> Any:
            assert redaction._CURRENT.get() is s1
            return redaction.extraction("NESTED_SCOPE_CANARY")

        assert inner() is None
        assert redaction.extraction("clean_value") == "clean_value"
        return s1

    outer()
    assert redaction._CURRENT.get() is None

    # GuardedConnection with dict parameters and PersistedJSON
    @redaction.redaction_scope
    def check_db() -> None:
        redaction.observe_value({"secret": "DB_PARAM_CANARY"})
        with redaction.GuardedConnection(str(tmp_path / "test.db")) as conn:
            conn.execute("CREATE TABLE t (a TEXT, b TEXT, c TEXT)")
            conn.execute(
                "INSERT INTO t VALUES (:a, :b, :c)",
                {
                    "a": ev_mod.PersistedJSON('{"trusted":true}'),
                    "b": "plain text with DB_PARAM_CANARY",
                    "c": json.dumps({"value": "DB_PARAM_CANARY"}),
                },
            )
            row = conn.execute("SELECT a, b, c FROM t").fetchone()
            assert row[0] == '{"trusted":true}'
            assert row[1] == "[redacted]"
            assert "DB_PARAM_CANARY" not in row[2]

    check_db()


def test_contract_normalization_findings_and_report() -> None:
    contract = load_submodule("audit.contract")

    assert contract.GOLDEN_TEMPLATE_IDS == contract.discover_golden_template_ids()

    # Classification & coverage normalization
    assert contract.normalize_classification(None, legacy_severity=None) == "info"
    assert contract.normalize_classification("WARN") == "warning"
    assert contract.normalize_classification(None, legacy_severity="review") == "review_suggested"
    with pytest.raises(ValueError, match="Invalid audit classification"):
        contract.normalize_classification("bogus")
    with pytest.raises(ValueError, match="Invalid legacy finding severity"):
        contract.normalize_classification(None, legacy_severity="bogus")

    assert contract.normalize_coverage(None) == "verified"
    assert contract.normalize_coverage("Could-Not Verify") == "could_not_verify"
    with pytest.raises(ValueError, match="Invalid audit coverage"):
        contract.normalize_coverage("bogus")

    # Source paths normalization and sorting
    paths = contract.normalize_source_paths([
        {"path": "b.py", "line": 10},
        "a.py",
        {"path": "a.py", "start_line": 2, "end_line": 5},
    ])
    assert paths == [
        {"path": "a.py", "start_line": None, "end_line": None},
        {"path": "a.py", "start_line": 2, "end_line": 5},
        {"path": "b.py", "start_line": 10, "end_line": 10},
    ]

    # Structured finding content re-serialization in normalize_finding
    token_obj = {"kind": "text", "hmac": "a" * 64, "location": {"path": None, "line": None}}
    norm = contract.normalize_finding({
        "id": token_obj,
        "consequence": token_obj,
        "affected_identities": [token_obj],
        "source_paths": [{"path": token_obj, "start_line": 1, "end_line": 1}],
    })
    assert isinstance(norm["id"], dict) and norm["id"]["kind"] == "text"
    assert isinstance(norm["consequence"], dict)
    assert len(norm["affected_identities"]) == 1

    with pytest.raises(ValueError, match="Invalid structured finding content"):
        contract.normalize_finding({"id": {"bad": "shape"}})

    # Duplicate unit identities rejected in canonical_report_payload
    u = {"unit_kind": "profile", "unit_id": "default", "status": "completed", "coverage": "verified"}
    with pytest.raises(ValueError, match="Duplicate audit unit identity"):
        contract.canonical_report_payload(as_of=1, units=[u, u])
    with pytest.raises(ValueError, match="Unit identities must be nonempty strings"):
        contract.canonical_report_payload(as_of=1, units=[{"unit_kind": "", "unit_id": "x"}])

    # Reload order resilience (contract reloaded before evidence)
    import importlib
    ev_mod = load_submodule("audit.evidence")
    importlib.reload(contract)
    importlib.reload(ev_mod)
    fresh_digest = ev_mod.generated_digest("d" * 64)
    assert contract.sanitize_evidence({"source_digest": fresh_digest}) == {"source_digest": "d" * 64}


def test_redaction_flag_case_sensitivity() -> None:
    redaction = load_submodule("audit.redaction")

    t1 = redaction.Taint()
    t1.observe_text("-P x cookie=PROBE_FLAG_CASE_CANARY")
    assert t1.scrub("PROBE_FLAG_CASE_CANARY") == "PROBE_FLAG_CASE_CANARY"

    t2 = redaction.Taint()
    t2.observe_text("-U x bearer=PROBE_FLAG_CASE_CANARY")
    assert t2.scrub("PROBE_FLAG_CASE_CANARY") == "PROBE_FLAG_CASE_CANARY"

    t3 = redaction.Taint()
    t3.observe_text("-p x cookie=PROBE_FLAG_CASE_CANARY")
    assert t3.scrub("PROBE_FLAG_CASE_CANARY") == "[redacted]"

    t4 = redaction.Taint()
    t4.observe_text("-u x bearer=PROBE_FLAG_CASE_CANARY")
    assert t4.scrub("PROBE_FLAG_CASE_CANARY") == "[redacted]"


def test_endpoint_unhashable_scheme_rejection() -> None:
    ev_mod = load_submodule("audit.evidence")
    serializer = ev_mod.EvidenceSerializer()

    with pytest.raises(TypeError):
        serializer.serialize(ev_mod.EvidenceEndpoint(scheme=[], host="example.invalid", port=443))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        serializer.serialize(ev_mod.EvidenceEndpoint(scheme={}, host="example.invalid", port=443))  # type: ignore[arg-type]

    # Sealed leaf revalidation retains tuple membership (does not raise TypeError on unhashable scheme)
    forged_leaf = serializer._seal(scheme=[], host="example.invalid", port=443)
    res = serializer.serialize(forged_leaf)
    assert isinstance(res, dict) and "scheme" in res


def test_factory_non_string_type_errors() -> None:
    ev_mod = load_submodule("audit.evidence")
    serializer = ev_mod.EvidenceSerializer()

    for bad in (None, 0, False, 1.0, b"abc", [], {}):
        with pytest.raises(TypeError):
            ev_mod.generated_digest(bad)
        with pytest.raises(TypeError):
            ev_mod.control_identity(bad)
        with pytest.raises(TypeError):
            serializer._seal_key(bad)


