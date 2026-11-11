"""Routing corpus test: evaluates deterministic request corpus against templates and kits."""

from __future__ import annotations

import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from tests.conftest import ensure_test_package
from tests.fake_kit_bridge import load_list_fixture
from tests.routing_corpus import KNOWN_VIOLATIONS, iter_cases

ensure_test_package()

from hermes_plugins.defuzz.matcher import (  # noqa: E402
    KitInfo,
    best_matches,
    choose_catalog_entry,
    match_kits,
)
from hermes_plugins.defuzz.prompt_parse import parse_deterministic  # noqa: E402
from hermes_plugins.defuzz.questionnaire import KIT_BUILDING_KINDS  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # noqa: E402

BASELINE_PATH = Path(__file__).resolve().parent / "fixtures" / "routing_corpus_baseline.json"

_TEMPLATES = load_templates()
_KITS: List[KitInfo] = []
for _raw in load_list_fixture()["kits"]:
    _kit = KitInfo.from_dict(_raw)
    assert _kit is not None
    _KITS.append(_kit)


def _route_sentence(sentence: str) -> Dict[str, Any]:
    parsed = parse_deterministic(sentence)
    answers = parsed.answers
    if parsed.not_a_project_request:
        return {
            "building": answers.get("building"),
            "actual_catalog": "none",
            "actual_id": None,
        }
    t_matches = best_matches(_TEMPLATES, answers, prompt=sentence, explicit_code=parsed.explicit_code)
    k_matches = match_kits(_KITS, sentence, answers)
    actual_catalog, chosen = choose_catalog_entry(
        t_matches, k_matches, answers, explicit_code=parsed.explicit_code
    )
    if actual_catalog == "template" and chosen is not None:
        actual_id: Optional[str] = chosen.template.id
    elif actual_catalog == "kit" and chosen is not None:
        actual_id = chosen.kit.id
    else:
        actual_id = None
    return {
        "building": answers.get("building"),
        "actual_catalog": actual_catalog,
        "actual_id": actual_id,
    }


def _make_case_id(idx: int, group: str, expected_id: Optional[str], sentence: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", sentence.lower()).strip("-")[:42]
    target = expected_id or "none"
    return f"{idx:04d}-{group}-{target}-{slug}"


# Legacy confusable entries from tests/routing_corpus.py that previously relied on silent
# building->language defaults: 'backend service' with no language now asks ('none', None),
# and 'web app' with no language now reaches kit:web-app (still never comic-storyboard).
_SUPERSEDED_SILENT_DEFAULTS: dict[str, Tuple[str, Optional[str], str]] = {
    "music streaming backend service": ("none", None, "confusable"),
    "web app for a comic shop": ("kit", "web-app", "kit"),
}

_ALL_CASES: List[Tuple[str, str, Optional[str], str]] = [
    (
        sent,
        *(_SUPERSEDED_SILENT_DEFAULTS[sent] if sent in _SUPERSEDED_SILENT_DEFAULTS else (exp_cat, exp_id, grp)),
    )
    for sent, exp_cat, exp_id, grp in iter_cases()
]
_CASE_IDS: List[str] = [
    _make_case_id(i, grp, exp_id, sent)
    for i, (sent, _exp_cat, exp_id, grp) in enumerate(_ALL_CASES)
]


def _evaluate_all_cases() -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    by_target: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    by_group: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for idx, (sentence, expected_catalog, expected_id, group) in enumerate(_ALL_CASES):
        routed = _route_sentence(sentence)
        actual_catalog = routed["actual_catalog"]
        actual_id = routed["actual_id"]
        building = routed["building"]
        passed = (actual_catalog == expected_catalog) and (actual_id == expected_id)
        row = {
            "id": _CASE_IDS[idx],
            "sentence": sentence,
            "group": group,
            "expected_catalog": expected_catalog,
            "expected_id": expected_id,
            "building": building,
            "actual_catalog": actual_catalog,
            "actual_id": actual_id,
            "passed": passed,
        }
        rows.append(row)
        by_group[group].append(row)
        if group in ("template", "kit") and expected_id is not None:
            by_target[expected_id].append(row)
        else:
            by_target[group].append(row)

    def _summarize(t_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(t_rows)
        hits = sum(1 for r in t_rows if r["passed"])
        wrong_counter: Counter[str] = Counter()
        wrong_example: Dict[str, str] = {}
        for r in t_rows:
            if not r["passed"]:
                outcome_label = f"{r['actual_catalog']}:{r['actual_id']}"
                wrong_counter[outcome_label] += 1
                if outcome_label not in wrong_example:
                    wrong_example[outcome_label] = r["sentence"]
        top_wrong = [
            {"outcome": out, "count": cnt, "example": wrong_example[out]}
            for out, cnt in wrong_counter.most_common(3)
        ]
        return {
            "cases": total,
            "hits": hits,
            "hit_rate": round(hits / total, 4) if total else 0.0,
            "top_wrong": top_wrong,
        }

    summary_by_target: Dict[str, Any] = {
        target_key: _summarize(t_rows) for target_key, t_rows in by_target.items()
    }
    summary_by_group: Dict[str, Any] = {
        grp_key: _summarize(g_rows) for grp_key, g_rows in by_group.items()
    }

    return {
        "schema": "defuzz.routing_corpus_baseline/1",
        "total_cases": len(rows),
        "summary_by_group": summary_by_group,
        "summary_by_target": summary_by_target,
        "known_violations": dict(KNOWN_VIOLATIONS),
        "cases": rows,
    }


_EVALUATED_CORPUS: Dict[str, Any] = _evaluate_all_cases()

# Group cases into readable parametrized buckets so the whole suite runs in < 1s
# without 1,000+ per-test tmpdir fixture setups while keeping readable parametrized IDs.
_TARGET_BUCKETS: List[Tuple[str, List[Dict[str, Any]]]] = []
_bucket_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
for _r in _EVALUATED_CORPUS["cases"]:
    _bkey = (
        f"{_r['group']}-{_r['expected_id']}"
        if _r["group"] in ("template", "kit")
        else f"{_r['group']}-{_r['id']}"
    )
    _bucket_map[_bkey].append(_r)
for _bkey, _brows in _bucket_map.items():
    _TARGET_BUCKETS.append((_bkey, _brows))


@pytest.mark.parametrize(
    ("bucket_id", "bucket_rows"),
    _TARGET_BUCKETS,
    ids=[b[0] for b in _TARGET_BUCKETS],
)
def test_corpus_safety_invariants(
    bucket_id: str,
    bucket_rows: List[Dict[str, Any]],
) -> None:
    assert bucket_id
    for row in bucket_rows:
        sentence = row["sentence"]
        group = row["group"]
        expected_id = row["expected_id"]
        actual_catalog = row["actual_catalog"]
        actual_id = row["actual_id"]
        building = row["building"]
        actual_desc = f"{actual_catalog}:{actual_id} (building={building})"

        if sentence in KNOWN_VIOLATIONS:
            assert actual_desc == KNOWN_VIOLATIONS[sentence], (
                f"KNOWN_VIOLATIONS entry for {sentence!r} changed: "
                f"expected {KNOWN_VIOLATIONS[sentence]!r}, got {actual_desc!r}"
            )
            continue

        # (a) NO case in the NEGATIVE and CONFUSABLE sets lands on a kit;
        #     also NEGATIVE cases must not land on a wrong template.
        if group in ("negative", "confusable"):
            assert actual_catalog != "kit", (
                f"{group.upper()} sentence landed on kit {actual_id!r}: {sentence!r}"
            )
        if group == "negative":
            assert actual_catalog == "none", (
                f"NEGATIVE sentence landed on {actual_catalog}:{actual_id}: {sentence!r}"
            )

        # (b) No generated TEMPLATE sentence lands on a kit, and no generated KIT sentence
        #     lands on a code template when its `building` parses as a kit kind.
        if group == "template":
            assert actual_catalog != "kit", (
                f"Generated TEMPLATE sentence for {expected_id!r} landed on kit {actual_id!r}: {sentence!r}"
            )
        if group == "kit" and building in KIT_BUILDING_KINDS:
            assert actual_catalog != "template", (
                f"Generated KIT sentence for {expected_id!r} (building={building!r}) "
                f"landed on template {actual_id!r}: {sentence!r}"
            )


def test_corpus_baseline_and_hit_rates(
    capsys: pytest.CaptureFixture[str],
) -> None:
    evaluated_corpus = _EVALUATED_CORPUS
    refresh = os.environ.get("REFRESH_ROUTING_BASELINE") == "1"
    if refresh:
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(
            json.dumps(evaluated_corpus, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        return

    assert BASELINE_PATH.is_file(), (
        f"Baseline file {BASELINE_PATH} does not exist. "
        "Run with REFRESH_ROUTING_BASELINE=1 to generate it."
    )
    committed = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    committed_by_sentence = {
        c["sentence"]: c for c in committed.get("cases", [])
    }

    regressions: List[str] = []
    newly_passing: List[str] = []

    for row in evaluated_corpus["cases"]:
        sent = row["sentence"]
        prev = committed_by_sentence.get(sent)
        if prev is None:
            regressions.append(f"New sentence missing from baseline: {sent!r}")
            continue
        if prev["passed"] and not row["passed"]:
            regressions.append(
                f"{row['id']} ({sent!r}): was passing ({prev['actual_catalog']}:{prev['actual_id']}), "
                f"now {row['actual_catalog']}:{row['actual_id']}"
            )
        elif not prev["passed"] and row["passed"]:
            newly_passing.append(
                f"{row['id']} ({sent!r}): newly passes -> {row['actual_catalog']}:{row['actual_id']}"
            )

    if newly_passing:
        with capsys.disabled():
            print(
                f"\n[routing_corpus] {len(newly_passing)} case(s) newly pass! "
                "Re-run with REFRESH_ROUTING_BASELINE=1 to update tests/fixtures/routing_corpus_baseline.json:"
            )
            for msg in newly_passing:
                print(f"  + {msg}")

    assert not regressions, (
        f"{len(regressions)} routing regression(s) against committed baseline:\n"
        + "\n".join(f"  - {r}" for r in regressions)
    )


def test_website_section_routes_as_expected() -> None:
    """Every hand-written website case (tests/routing_corpus.py WEBSITE_CASES) routes as stated."""
    rows = [r for r in _EVALUATED_CORPUS["cases"] if r["group"] == "website"]
    assert len(rows) >= 60
    assert sum(1 for r in rows if r["expected_id"] == "web-golden") >= 30
    wrong = [
        f"{r['sentence']!r}: expected {r['expected_catalog']}:{r['expected_id']}, got {r['actual_catalog']}:{r['actual_id']}"
        for r in rows
        if not r["passed"]
    ]
    assert not wrong, "\n".join(wrong)
