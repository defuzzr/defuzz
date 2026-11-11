"""Routing evaluation for seven error classes against a beginner-phrased fixture."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

import pytest  # type: ignore[import-not-found]

from tests.conftest import ensure_test_package
from tests.fake_kit_bridge import load_list_fixture

ensure_test_package()

from hermes_plugins.defuzz.matcher import (  # type: ignore[import-not-found]  # noqa: E402
    KitInfo,
    best_matches,
    choose_catalog_entry,
    closest,
    match_kits,
)
from hermes_plugins.defuzz.prompt_parse import parse_deterministic  # type: ignore[import-not-found]  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # type: ignore[import-not-found]  # noqa: E402

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "routing_error_classes.json"
_TEMPLATES = load_templates()
_KITS: List[KitInfo] = [
    k for raw in load_list_fixture()["kits"] if (k := KitInfo.from_dict(raw)) is not None
]

EXPECTED_CLASSES = (
    "class_1_web_app",
    "class_2_vague_no_silent_default",
    "class_3_website_subject_words",
    "class_4_page_targets_and_non_web_pages",
    "class_5_component_library_python_vs_ui",
    "class_6_prose_and_non_project",
    "class_7_implied_languages_and_engines",
)


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


def _score_bucket(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    hits = 0
    misses: List[Dict[str, Any]] = []
    for item in entries:
        p = item["prompt"]
        r = _route(p)
        ok = r["catalog"] == item["expected_catalog"] and r["id"] == item["expected_id"]
        if ok and "expected_closest" in item:
            ok = r["closest"] == item["expected_closest"]
        if ok:
            hits += 1
        else:
            misses.append(
                {
                    "prompt": p,
                    "expected": f"{item['expected_catalog']}:{item['expected_id']}",
                    "expected_closest": item.get("expected_closest", "<any>"),
                    **r,
                }
            )
    return {
        "total": len(entries),
        "hits": hits,
        "rate": round(hits / len(entries), 4) if entries else 0.0,
        "misses": misses,
    }


def evaluate_error_classes() -> Dict[str, Any]:
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    classes_report = {
        cls_name: _score_bucket(data["classes"][cls_name]) for cls_name in EXPECTED_CLASSES
    }
    mnr_report = _score_bucket(data["must_not_regress"])
    return {
        "classes": classes_report,
        "must_not_regress": mnr_report,
    }


def test_error_classes_minimum_sizes_and_uniqueness() -> None:
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert data["schema"] == "defuzz.routing_error_classes/1"
    seen: set[str] = set()
    for cls_name in EXPECTED_CLASSES:
        items = data["classes"][cls_name]
        assert len(items) >= 25, f"{cls_name} has only {len(items)} items"
        for it in items:
            norm = it["prompt"].strip().lower()
            assert norm not in seen, f"duplicate prompt: {norm!r}"
            seen.add(norm)
    mnr = data["must_not_regress"]
    assert len(mnr) >= 80, f"must_not_regress has only {len(mnr)} items"
    for it in mnr:
        norm = it["prompt"].strip().lower()
        assert norm not in seen, f"duplicate prompt: {norm!r}"
        seen.add(norm)


def test_error_classes_evaluation(capsys: pytest.CaptureFixture[str]) -> None:
    report = evaluate_error_classes()
    with capsys.disabled():
        print("\n=== ROUTING ERROR-CLASS EVALUATION ===")
        for cls_name in EXPECTED_CLASSES:
            s = report["classes"][cls_name]
            print(f"  {cls_name:42s}: {s['hits']:2d}/{s['total']:2d} ({s['rate']*100:5.1f}%)")
            for m in s["misses"]:
                print(
                    f"    MISS: {m['prompt']!r} (exp {m['expected']}, closest={m['expected_closest']}) "
                    f"-> {m['catalog']}:{m['id']} (closest={m['closest']})"
                )
        mnr = report["must_not_regress"]
        print(f"  {'must_not_regress':42s}: {mnr['hits']:2d}/{mnr['total']:2d} ({mnr['rate']*100:5.1f}%)")
        for m in mnr["misses"]:
            print(f"    MNR_MISS: {m['prompt']!r} (exp {m['expected']}) -> {m['catalog']}:{m['id']}")
    for cls_name in EXPECTED_CLASSES:
        assert report["classes"][cls_name]["rate"] >= 0.90, cls_name
    assert report["must_not_regress"]["rate"] == 1.0


def test_best_matches_and_closest_never_guess_without_named_language() -> None:
    assert best_matches(_TEMPLATES, {}) == []
    assert best_matches(_TEMPLATES, {"building": "app", "layout": "mono"}) == []
    assert best_matches(_TEMPLATES, {"building": "service", "layout": "mono"}) == []
    assert closest(_TEMPLATES, {"building": "app", "layout": "mono"}) is None
    assert closest(_TEMPLATES, {"building": "tool", "layout": "mono"}) is None


def test_cli_and_route_parity_for_vague_web_app_and_prose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from hermes_plugins.defuzz import cli, componentize_bridge  # type: ignore[import-not-found]
    from tests.fake_kit_bridge import FakeKitBridge
    from tests.test_kit_routes import _DEFAULT_SYNC_ANSWERS, _build_client

    dest_root = tmp_path / "projects"
    dest_root.mkdir()
    FakeKitBridge().install(monkeypatch, componentize_bridge)
    monkeypatch.setattr(
        cli,
        "REGISTER_PROJECT",
        lambda name, path: json.dumps({"success": True, "id": "p1", "name": name, "path": path}),
    )

    nothing = "Nothing was created. Run again with --template ID or --kit ID."
    flag_re = re.compile(r"\[--(template|kit) ([^\]\s]+)\]")

    def _suggested_rows(out: str) -> list[str]:
        rows = []
        for line in out.splitlines():
            if line.rstrip().endswith("(suggested)"):
                m = flag_re.search(line)
                assert m, line
                rows.append(f"{m.group(1)}:{m.group(2)}")
        return rows

    def _run_new(prompt: str) -> tuple[int, str]:
        before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
        rc = cli.main(["new", "--prompt", prompt, "--dest-root", str(dest_root)])
        out = capsys.readouterr()
        assert rc == 2, (prompt, rc, out)
        assert out.out.rstrip().splitlines()[-1] == nothing, out.out
        assert "--template web-golden" in out.out and "--kit web-app" in out.out  # the whole list
        assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before
        assert list(dest_root.iterdir()) == []
        return rc, out.out

    # 1. CLI vague prompts ('an app', 'notes app'): exit 2, the list, nothing suggested, nothing created
    for vague in ("an app", "notes app"):
        _rc, out = _run_new(vague)
        assert _suggested_rows(out) == [], (vague, out)

    # 2. CLI 'make a web app': exit 2, the list with the web-app kit suggested first, nothing created
    _rc, out_web = _run_new("make a web app")
    assert _suggested_rows(out_web)[:1] == ["kit:web-app"], out_web

    # 3. CLI prose request ('blog post about godot') is not a project request: exit 2,
    #    nothing suggested (same as the route below), nothing created
    _rc, out_prose = _run_new("blog post about godot")
    assert _suggested_rows(out_prose) == [], out_prose
    prose_route = _build_client(monkeypatch, FakeKitBridge()).post(
        "/scaffold/match", json={"prompt": "blog post about godot"}
    )
    assert prose_route.status_code == 200
    assert prose_route.json()["preferred"] == "none"
    assert prose_route.json()["catalog"]["suggested"] == []

    # 4. Desktop /scaffold/match parity with and without unchosen desktop defaults
    client = _build_client(monkeypatch, FakeKitBridge())
    for answers in (None, _DEFAULT_SYNC_ANSWERS):
        for vague in ("an app", "notes app"):
            resp = client.post("/scaffold/match", json={"answers": dict(answers or {}), "prompt": vague})
            assert resp.status_code == 200
            body = resp.json()
            assert body["preferred"] == "none"
            assert body["matches"] == []
            assert body["closest"] == []
            assert body["catalog"]["suggested"] == []

        resp_subj = client.post(
            "/scaffold/match",
            json={"answers": dict(answers or {}), "prompt": "can you make a homepage for my minecraft server"},
        )
        assert resp_subj.status_code == 200
        subj_body = resp_subj.json()
        # Changed when web-golden was added (was: the web-app kit): a homepage is a site.
        assert subj_body["preferred"] == "template"
        assert subj_body["matches"][0]["template_id"] == "web-golden"
        assert subj_body["catalog"]["suggested"][0] == "template:web-golden"
