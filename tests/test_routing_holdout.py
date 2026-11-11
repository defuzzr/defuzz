"""Held-out routing evaluation for weak kits, confusable requests, and negatives."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from tests.conftest import ensure_test_package
from tests.fake_kit_bridge import load_list_fixture

ensure_test_package()

from hermes_plugins.defuzz.matcher import (  # noqa: E402
    KitInfo,
    best_matches,
    choose_catalog_entry,
    closest,
    match_kits,
)
from hermes_plugins.defuzz.prompt_parse import parse_deterministic  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # noqa: E402

HOLDOUT_PATH = Path(__file__).resolve().parent / "fixtures" / "routing_holdout.json"
_TEMPLATES = load_templates()
_KITS: List[KitInfo] = [
    k for raw in load_list_fixture()["kits"] if (k := KitInfo.from_dict(raw)) is not None
]


def _route(prompt: str) -> Dict[str, Any]:
    parsed = parse_deterministic(prompt)
    if parsed.not_a_project_request:
        return {"catalog": "none", "id": None, "closest": None}
    t_matches = best_matches(_TEMPLATES, parsed.answers, prompt=prompt, explicit_code=parsed.explicit_code)
    k_matches = match_kits(_KITS, prompt, parsed.answers)
    cat, chosen = choose_catalog_entry(
        t_matches, k_matches, parsed.answers, explicit_code=parsed.explicit_code
    )
    if cat == "template" and chosen is not None:
        chosen_id = chosen.template.id
    elif cat == "kit" and chosen is not None:
        chosen_id = chosen.kit.id
    else:
        chosen_id = None
    near = None if (t_matches or cat == "kit") else closest(_TEMPLATES, parsed.answers)
    return {
        "catalog": cat,
        "id": chosen_id,
        "closest": near.template.id if near is not None else None,
    }


def evaluate_holdout() -> Dict[str, Any]:
    data = json.loads(HOLDOUT_PATH.read_text(encoding="utf-8"))
    weak_summary: Dict[str, Any] = {}
    for kit_id, prompts in data["weak_kits"].items():
        hits = 0
        misses: List[Dict[str, Any]] = []
        for p in prompts:
            r = _route(p)
            if r["catalog"] == "kit" and r["id"] == kit_id:
                hits += 1
            else:
                misses.append({"prompt": p, **r})
        weak_summary[kit_id] = {
            "total": len(prompts),
            "hits": hits,
            "rate": round(hits / len(prompts), 4),
            "misses": misses,
        }

    weak_template_summary: Dict[str, Any] = {}
    for template_id, prompts in data.get("weak_templates", {}).items():
        hits = 0
        misses = []
        for p in prompts:
            r = _route(p)
            if r["catalog"] == "template" and r["id"] == template_id:
                hits += 1
            else:
                misses.append({"prompt": p, **r})
        weak_template_summary[template_id] = {
            "total": len(prompts),
            "hits": hits,
            "rate": round(hits / len(prompts), 4),
            "misses": misses,
        }

    conf_entries = data["confusable_and_negative"]
    false_positives: List[Dict[str, Any]] = []
    ask_misses: List[Dict[str, Any]] = []
    for item in conf_entries:
        p = item["prompt"]
        exp_cat = item["expected_catalog"]
        exp_id = item["expected_id"]
        r = _route(p)
        act_cat = r["catalog"]
        act_id = r["id"]
        if act_cat == "kit":
            false_positives.append({"prompt": p, "expected": f"{exp_cat}:{exp_id}", **r})
        elif exp_cat == "none" and act_cat != "none":
            false_positives.append({"prompt": p, "expected": "none:None", **r})
        elif exp_cat == "template":
            if act_cat == "template" and act_id == exp_id:
                continue
            if act_cat == "none":
                ask_misses.append({"prompt": p, "expected": f"template:{exp_id}", **r})
            else:
                false_positives.append({"prompt": p, "expected": f"template:{exp_id}", **r})

    return {
        "weak_kits": weak_summary,
        "weak_templates": weak_template_summary,
        "confusable": {
            "total": len(conf_entries),
            "false_positives": len(false_positives),
            "fp_rate": round(len(false_positives) / len(conf_entries), 4),
            "ask_misses": len(ask_misses),
            "fp_details": false_positives,
            "ask_miss_details": ask_misses,
        },
    }


def test_holdout_minimum_sizes() -> None:
    data = json.loads(HOLDOUT_PATH.read_text(encoding="utf-8"))
    assert data["schema"] == "defuzz.routing_holdout/1"
    for kit_id in ("component-library", "godot-game"):
        assert len(data["weak_kits"][kit_id]) >= 20, kit_id
    # 11 of the 25 web-app prompts named a site or page; they moved to the web-golden
    # template target when that template was added, so the two together still hold 25.
    assert len(data["weak_kits"]["web-app"]) >= 14
    assert len(data["weak_kits"]["web-app"]) + len(data["weak_templates"]["web-golden"]) >= 25
    assert len(data["confusable_and_negative"]) >= 60


def test_holdout_targets(capsys: pytest.CaptureFixture[str]) -> None:
    report = evaluate_holdout()
    with capsys.disabled():
        print("\n=== HELD-OUT EVALUATION ===")
        for kit_id, s in report["weak_kits"].items():
            print(f"  {kit_id:20s}: {s['hits']}/{s['total']} ({s['rate']*100:.1f}%)")
            for m in s["misses"]:
                print(f"    MISS: {m['prompt']!r} -> {m['catalog']}:{m['id']} (closest={m['closest']})")
        for template_id, s in report["weak_templates"].items():
            print(f"  {template_id:20s}: {s['hits']}/{s['total']} ({s['rate']*100:.1f}%)")
            for m in s["misses"]:
                print(f"    MISS: {m['prompt']!r} -> {m['catalog']}:{m['id']} (closest={m['closest']})")
        c = report["confusable"]
        print(
            f"  {'confusable_fp':20s}: {c['false_positives']}/{c['total']} "
            f"({c['fp_rate']*100:.1f}%), ask_misses={c['ask_misses']}"
        )
        for fp in c["fp_details"]:
            print(f"    FP: {fp['prompt']!r} (expected {fp['expected']}) -> {fp['catalog']}:{fp['id']}")
        for am in c["ask_miss_details"]:
            print(f"    ASK_MISS: {am['prompt']!r} (expected {am['expected']}) -> {am['catalog']}:{am['id']}")

    assert report["weak_kits"]["component-library"]["rate"] >= 0.80
    assert report["weak_kits"]["web-app"]["rate"] >= 0.85
    assert report["weak_kits"]["godot-game"]["rate"] >= 0.90
    assert report["weak_templates"]["web-golden"]["rate"] >= 0.85
    assert report["confusable"]["fp_rate"] <= 0.05
