"""Tests for audit.skill_packs: synthetic fixtures only, no real home reads."""
from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import shutil

import pytest

from tests.conftest import load_submodule

# Usage-file window used by most fixtures: records span 2026-09-01 .. 2026-10-01 (UTC).
USAGE_FIRST = "2026-09-01T00:00:00+00:00"
USAGE_LAST = "2026-10-01T00:00:00+00:00"
TS_INSIDE = 1_789_000_000.0  # 2026-09-10, inside the usage window
TS_BEFORE = 1_780_000_000.0  # 2026-05-28, before the first usage record
TS_AFTER = 1_792_000_000.0  # 2026-10-14, after the newest usage record


def _write_skill(
    root: Path,
    rel_dir: str,
    *,
    name: str | None = None,
    description: str = "Use when testing skill packs. Short description.",
    body: str = " Follow deterministic steps.\n",
    base_dir: str = "skills",
    extra_fm: str = "",
    mtime: float | None = TS_INSIDE,
) -> Path:
    pkg = root / base_dir / rel_dir
    pkg.mkdir(parents=True, exist_ok=True)
    skill_name = name or pkg.name
    md = pkg / "SKILL.md"
    md.write_text(
        f"---\nname: {skill_name}\ndescription: \"{description}\"\n{extra_fm}---\n{body}",
        encoding="utf-8",
    )
    if mtime is not None:
        os.utime(md, (mtime, mtime))
    return md


def _write_raw_skill(root: Path, rel_dir: str, frontmatter: str) -> Path:
    pkg = root / "skills" / rel_dir
    pkg.mkdir(parents=True, exist_ok=True)
    md = pkg / "SKILL.md"
    md.write_text("---\n" + frontmatter + "\n---\nbody\n", encoding="utf-8")
    os.utime(md, (TS_INSIDE, TS_INSIDE))
    return md


def _usage(root: Path, records: dict, *, anchor: bool = True) -> None:
    data = dict(records)
    if anchor:
        # Two neutral anchor records fix the usage window independently of the skills under test.
        data.setdefault("zz-anchor-first", {"use_count": 0, "created_at": USAGE_FIRST})
        data.setdefault("zz-anchor-last", {"use_count": 0, "created_at": USAGE_LAST})
    (root / "skills").mkdir(parents=True, exist_ok=True)
    (root / "skills/.usage.json").write_text(json.dumps(data), encoding="utf-8")


def build_render_fixture(home: Path) -> None:
    """Fixture whose rendered index length was measured with Hermes's own renderer (see test below)."""
    _write_raw_skill(home, "alpha", "name: alpha\ndescription: Top level alpha skill.")
    _write_raw_skill(
        home, "beta",
        "name: beta\ndescription: Top level beta skill used for a long description that must be clipped somewhere.",
    )
    _write_raw_skill(home, "cat/gamma", "name: gamma\ndescription: Nested gamma.")
    _write_raw_skill(home, "cat/delta", "name: delta\ndescription: >\n  Folded multi\n  line description.")
    _write_raw_skill(home, "deep/sub/eps", "name: eps\ndescription: Deep.")
    _write_raw_skill(home, "maconly", "name: maconly\ndescription: Mac only.\nplatforms: [macos]")
    _write_raw_skill(home, "broken", "name: broken\ndescription: has: colon: [unclosed")
    _write_raw_skill(home, "ops/kanban-only", "name: kanban-only\ndescription: Kanban lane.\nenvironments: [kanban]")
    _write_raw_skill(home, "ops/odd-env", "name: odd-env\ndescription: Unknown env tag.\nenvironments: [mars]")
    _write_raw_skill(
        home, "ops/tool-gated",
        "name: tool-gated\ndescription: Needs a toolset.\nmetadata:\n  hermes:\n    requires_toolsets: [web]",
    )


# Measured by calling Hermes's agent.prompt_builder.build_skills_system_prompt on a copy of
# build_render_fixture() on Linux (default variant: no compact categories, not one-shot).
HERMES_RENDERED_CHARS_LINUX = 1489


def _snapshot_tree(root: Path) -> list[tuple[str, str, int, int, bytes]]:
    records: list[tuple[str, str, int, int, bytes]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        for entry_name in (*dirnames, *filenames):
            full = Path(dirpath) / entry_name
            rel = full.relative_to(root).as_posix()
            st = full.lstat()
            if full.is_symlink():
                records.append((rel, "symlink", st.st_mode, st.st_mtime_ns, os.readlink(full).encode("utf-8")))
            elif full.is_dir():
                records.append((rel, "dir", st.st_mode, st.st_mtime_ns, b""))
            elif full.is_file():
                records.append((rel, "file", st.st_mode, st.st_size, hashlib.sha256(full.read_bytes()).digest()))
    records.sort(key=lambda item: item[0])
    return records


def test_rendered_index_matches_hermes_renderer(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    build_render_fixture(tmp_path)
    res = mod.audit_skill_packs(tmp_path, host_platform="linux")
    idx = res["skill_packs"]["index"]
    # Hermes lists the malformed-YAML skill via its key:value fallback, drops the macOS-only skill on Linux and
    # the kanban-only skill outside a kanban session, and lists unknown-environment and tool-gated skills.
    assert idx["discovered_skills"] == 10
    assert idx["platform_excluded_count"] == 2
    assert idx["loadable_skills"] == 8
    assert idx["runtime_gated_count"] == 2
    assert idx["index_chars"] == HERMES_RENDERED_CHARS_LINUX
    assert idx["estimated_tokens"] == HERMES_RENDERED_CHARS_LINUX // 4
    assert idx["name_chars"] == len("alpha" "beta" "broken" "delta" "gamma" "eps" "odd-env" "tool-gated")
    clipped_beta = mod.clip_skill_description(
        "Top level beta skill used for a long description that must be clipped somewhere."
    )
    assert clipped_beta == "Top level beta skill used for a long description that..."
    assert idx["description_chars"] == sum(len(d) for d in (
        "Top level alpha skill.", clipped_beta, "has: colon: [unclosed",
        "Folded multi line description.", "Nested gamma.", "Deep.", "Unknown env tag.", "Needs a toolset.",
    ))
    # Same tree on macOS lists the macOS-only skill too.
    res_mac = mod.audit_skill_packs(tmp_path, host_platform="darwin")
    assert res_mac["skill_packs"]["index"]["platform_excluded_count"] == 1
    assert res_mac["skill_packs"]["index"]["loadable_skills"] == 9
    assert res_mac["skill_packs"]["index"]["index_chars"] == HERMES_RENDERED_CHARS_LINUX + len("\n  - maconly: Mac only.")


def test_index_cost_disabled_snapshot_and_finding(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    long_desc = (
        "Use when converting complex multi-layer vector documents into responsive web components "
        "with strict token budgets and accessibility."
    )
    _write_skill(tmp_path, "autonomous-ai-agents/hermes-agent", name="hermes-agent", description="Use Hermes Agent.")
    _write_skill(tmp_path, "creative/long-desc", name="long-desc", description=long_desc)
    _write_skill(tmp_path, "creative/disabled-one", name="disabled-one", description="Should be excluded when disabled.")

    def snap_entry(folder, cat):
        return {"skill_name": folder, "category": cat, "frontmatter_name": folder, "description": "Short."}

    ghosts = [snap_entry(f"ghost-{i:02d}", "gone") for i in range(15)]
    snapshot = {
        "version": 3,
        "manifest": {},
        "skills": [snap_entry("hermes-agent", "autonomous-ai-agents"), snap_entry("long-desc", "creative"), *ghosts],
    }
    (tmp_path / ".skills_prompt_snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")
    _usage(tmp_path, {"hermes-agent": {"use_count": 5, "last_used_at": "2026-09-30T00:00:00+00:00"}})

    # Disabling hermes-agent is ignored (ESSENTIAL_SKILLS); disabled-one is excluded.
    res = mod.audit_skill_packs(tmp_path, disabled_skills=["disabled-one", "hermes-agent"], host_platform="linux")
    sec = res["skill_packs"]
    idx = sec["index"]
    assert idx["discovered_skills"] == 3
    assert idx["disabled_skills_count"] == 1
    assert idx["loadable_skills"] == 2
    clipped_long = mod.clip_skill_description(long_desc)
    assert len(clipped_long) <= 60 and clipped_long.endswith("...")
    assert idx["name_chars"] == len("hermes-agent") + len("long-desc")
    assert idx["description_chars"] == len("Use Hermes Agent.") + len(clipped_long)
    assert idx["index_chars"] > idx["name_chars"] + idx["description_chars"]
    snap = idx["snapshot"]
    assert snap["present"] is True and snap["version"] == 3 and snap["skills_count"] == 17
    assert snap["stale_count"] == 15
    assert "stale_entries" not in snap  # stale entries have no file on disk: counted, never named
    ids = {f["id"] for f in res["findings"]}
    assert "skill_packs.stale_index_snapshot" in ids
    assert "skill_packs.index_cost" not in ids

    for i in range(155):
        _write_skill(tmp_path, f"pack/skill-{i:03d}", name=f"skill-{i:03d}",
                     description="Pack skill description that adds characters to every prompt index.")
    res_big = mod.audit_skill_packs(tmp_path, disabled_skills=["disabled-one"], host_platform="linux")
    f_idx = next(f for f in res_big["findings"] if f["id"] == "skill_packs.index_cost")
    assert f_idx["classification"] == "review_suggested"
    n_skills = res_big["skill_packs"]["index"]["loadable_skills"]
    n_chars = res_big["skill_packs"]["index"]["index_chars"]
    assert n_skills == 157
    assert f_idx["evidence"] == {"skills": n_skills, "chars": n_chars, "estimated_tokens": n_chars // 4,
                                 "runtime_gated_count": 0, "platform_excluded_count": 0}
    # Fixed sentence: the numbers live in evidence only (persistence keeps only exact fixed sentences).
    assert f_idx["consequence"] == mod.FINDING_CONSEQUENCES["skill_packs.index_cost"]
    assert str(n_skills) not in f_idx["consequence"] and str(n_chars) not in f_idx["consequence"]
    assert "about" in f_idx["consequence"] and "upper bound" in f_idx["consequence"]


def test_every_consequence_is_a_fixed_sentence(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    for rule_id, text in mod.FINDING_CONSEQUENCES.items():
        assert rule_id.startswith("skill_packs.")
        assert "{" not in text and "}" not in text, rule_id
        low = f" {text.lower()} "
        for banned in (" you ", " your ", "indicat", "suggest", "unpruned", "abandon"):
            assert banned not in low, (rule_id, banned)


def test_usage_window_never_used_and_missing_usage_file(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    for i in range(25):
        _write_skill(tmp_path, f"pack/s-{i:02d}", name=f"s-{i:02d}")

    res_missing = mod.audit_skill_packs(tmp_path)
    u0 = res_missing["skill_packs"]["usage"]
    assert res_missing["coverage"] == "could_not_verify"
    assert u0["coverage"] == "could_not_verify" and u0["reason"] == "usage_file_missing"
    assert u0["zero_use_count"] is None
    missing = {f["id"]: f for f in res_missing["findings"]}
    assert missing["skill_packs.could_not_verify"]["classification"] == "info"
    assert "skill_packs.never_used" not in missing

    usage_data = {
        "s-00": {"use_count": 50, "last_used_at": "2026-09-25T00:00:00+00:00"},  # 6 days before newest
        "s-01": {"use_count": 40, "last_used_at": "2026-09-10T00:00:00+00:00"},  # 21 days
        "s-02": {"use_count": 30, "last_used_at": "2026-08-15T00:00:00+00:00"},  # 47 days
        "s-03": {"use_count": 20, "last_used_at": "2026-07-15T00:00:00+00:00"},  # 78 days
        "s-04": {"use_count": 10, "last_used_at": "2026-05-01T00:00:00+00:00"},  # 153 days
        "s-05": {"use_count": 0, "last_used_at": None},
        "historical-deleted": {"use_count": 99, "last_used_at": USAGE_LAST},
    }
    _usage(tmp_path, usage_data)
    res = mod.audit_skill_packs(tmp_path)
    u = res["skill_packs"]["usage"]
    assert u["coverage"] == "verified"
    # Year-month as an integer YYYYMM: numbers survive the report serializer unchanged.
    assert u["recording_since"] == 202605 and u["recording_until"] == 202610
    assert u["skills_evaluated"] == 25
    assert u["zero_use_count"] == 20
    assert u["zero_use_unverifiable_count"] == 0
    assert u["never_used_share"] == 0.8
    # Absolute path of the existing skill folder; a usage record with no skill on disk has path None.
    assert u["top_used_counts"][:6] == [
        {"path": None, "use_count": 99},
        *({"path": os.path.realpath(tmp_path / f"skills/pack/s-{i:02d}"), "use_count": c}
          for i, c in enumerate((50, 40, 30, 20, 10)))]
    assert u["days_since_last_use"] == {
        "never": 20, "gt_90_days": 1, "days_30_to_90": 2, "lt_30_days": 2, "unverifiable": 0}
    f_nu = next(f for f in res["findings"] if f["id"] == "skill_packs.never_used")
    assert f_nu["classification"] == "review_suggested"
    assert f_nu["evidence"] == {"skills": 25, "zero_use_count": 20, "never_used_share": 0.8, "unverifiable_count": 0}


def test_skills_outside_the_usage_window_are_not_called_never_used(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    for i in range(10):
        _write_skill(tmp_path, f"pack/in-{i:02d}", mtime=TS_INSIDE)
    for i in range(10):
        _write_skill(tmp_path, f"pack/old-{i:02d}", mtime=TS_BEFORE)  # predates the first usage record
    for i in range(10):
        _write_skill(tmp_path, f"pack/new-{i:02d}", mtime=TS_AFTER)  # newer than the newest usage record
    # A skill outside the window that HAS its own (zero-use) record is observed since that record.
    _write_skill(tmp_path, "pack/seeded", mtime=TS_BEFORE)
    _usage(tmp_path, {"seeded": {"use_count": 0, "created_at": "2026-09-05T00:00:00+00:00"}})
    res = mod.audit_skill_packs(tmp_path)
    u = res["skill_packs"]["usage"]
    assert u["coverage"] == "verified"
    assert u["zero_use_count"] == 11
    assert u["zero_use_unverifiable_count"] == 20
    assert u["non_stock_skills_evaluated"] == 11
    assert u["days_since_last_use"]["unverifiable"] == 20
    assert u["days_since_last_use"]["never"] == 11
    # 11 evaluated non-stock skills < NEVER_USED_MIN_SKILLS (20): no never_used finding.
    assert "skill_packs.never_used" not in {f["id"] for f in res["findings"]}

    # A usage file with no parseable timestamps has no usable window: could_not_verify.
    _usage(tmp_path, {"in-00": {"use_count": 0}}, anchor=False)
    res2 = mod.audit_skill_packs(tmp_path)
    assert res2["skill_packs"]["usage"]["coverage"] == "could_not_verify"
    assert res2["skill_packs"]["usage"]["reason"] == "usage_file_no_timestamps"
    assert res2["skill_packs"]["usage"]["zero_use_count"] is None


def test_output_is_deterministic_across_now_and_clock(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    for i in range(22):
        _write_skill(tmp_path, f"pack/d-{i:02d}")
    _usage(tmp_path, {"d-00": {"use_count": 3, "last_used_at": "2026-09-02T00:00:00+00:00"}})

    def ticking(start: float, step: float):
        state = {"t": start}

        def clock() -> float:
            state["t"] += step
            return state["t"]
        return clock

    a = mod.audit_skill_packs(tmp_path, now="2026-10-02T00:00:00+00:00", clock=ticking(5.0, 0.001))
    b = mod.audit_skill_packs(tmp_path, now="2027-03-30T00:00:00+00:00", clock=ticking(5.0 + 9 * 86400, 0.002))
    c = mod.audit_skill_packs(tmp_path)
    for other in (b, c):
        assert json.dumps(a["skill_packs"], sort_keys=True) == json.dumps(other["skill_packs"], sort_keys=True)
        assert json.dumps(a["findings"], sort_keys=True) == json.dumps(other["findings"], sort_keys=True)
        assert a["coverage"] == other["coverage"]
    # Run-dependent figures live only in the top-level run_metrics sibling, never in the section.
    assert "run_metrics" not in a["skill_packs"]
    assert set(a["run_metrics"]) == {"elapsed_ms", "time_budget_hit"}
    assert a["run_metrics"]["elapsed_ms"] != b["run_metrics"]["elapsed_ms"]
    assert a["run_metrics"]["time_budget_hit"] is False
    assert "elapsed" not in json.dumps(a["skill_packs"])
    # The not-measured path carries the same sibling.
    assert set(mod.audit_skill_packs(tmp_path / "nope")["run_metrics"]) == {"elapsed_ms", "time_budget_hit"}


def test_bulk_install_signals_and_mtime_signal_never_above_info(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")

    lic_home = tmp_path / "lic_home"
    for i in range(55):
        md = _write_skill(lic_home, f"lic/l-{i:02d}", name=f"l-{i:02d}", mtime=TS_INSIDE + i * 1000)
        (md.parent / "LICENSE").write_text("MIT License Text Shared Across Pack\n", encoding="utf-8")
    _usage(lic_home, {"l-00": {"use_count": 3, "last_used_at": USAGE_LAST},
                      "l-01": {"use_count": 1, "last_used_at": USAGE_LAST}})
    res_lic = mod.audit_skill_packs(lic_home)
    bi_lic = res_lic["skill_packs"]["bulk_installs"]
    assert bi_lic["group_count"] == 1
    assert bi_lic["groups"][0] == {"signal": "license_hash", "weak_signal": False, "skills_count": 55,
                                   "used_skills_count": 2, "used_share": round(2 / 55, 4)}
    f_bulk_lic = next(f for f in res_lic["findings"] if f["id"] == "skill_packs.bulk_install")
    assert f_bulk_lic["classification"] == "review_suggested"
    f_lc = next(f for f in res_lic["findings"] if f["id"] == "skill_packs.license_copies")
    assert f_lc["evidence"] == {"count": 55, "distinct_texts": 1, "bytes": 55 * 36}

    hub_home = tmp_path / "hub_home"
    installed = {}
    for i in range(22):
        sname = f"hub-{i:02d}"
        _write_skill(hub_home, f"hub/{sname}", name=sname, mtime=TS_INSIDE + i * 1000)
        installed[sname] = {"source": "clawhub", "identifier": f"@pack/{sname}", "install_path": f"hub/{sname}",
                            "content_hash": "sha256:0123456789abcdef"}
    (hub_home / "skills/.hub").mkdir(parents=True, exist_ok=True)
    (hub_home / "skills/.hub/lock.json").write_text(json.dumps({"version": 1, "installed": installed}), encoding="utf-8")
    _usage(hub_home, {"hub-00": {"use_count": 5, "last_used_at": USAGE_LAST}})
    res_hub = mod.audit_skill_packs(hub_home)
    g = res_hub["skill_packs"]["bulk_installs"]["groups"][0]
    assert (g["signal"], g["weak_signal"], g["skills_count"], g["used_skills_count"]) == ("hub_lock_source", False, 22, 1)
    assert next(f for f in res_hub["findings"] if f["id"] == "skill_packs.bulk_install")["classification"] == "info"

    # 60 skills sharing only SKILL.md times within 2 minutes, none used: weak signal, stays info.
    mt_home = tmp_path / "mt_home"
    for i in range(60):
        _write_skill(mt_home, f"mtime/m-{i:02d}", name=f"m-{i:02d}", mtime=TS_INSIDE + i * 1.5)
    _usage(mt_home, {})
    res_mt = mod.audit_skill_packs(mt_home)
    gm = res_mt["skill_packs"]["bulk_installs"]["groups"][0]
    assert (gm["signal"], gm["weak_signal"], gm["skills_count"], gm["used_skills_count"]) == ("mtime_window_2m", True, 60, 0)
    f_mt = next(f for f in res_mt["findings"] if f["id"] == "skill_packs.bulk_install")
    assert f_mt["classification"] == "info"
    assert f_mt["evidence"]["weak_signal"] is True
    # Without verified usage the used counts are absent from the evidence rather than null.
    (mt_home / "skills/.usage.json").unlink()
    f_nouse = next(f for f in mod.audit_skill_packs(mt_home)["findings"] if f["id"] == "skill_packs.bulk_install")
    assert f_nouse["evidence"] == {"signal": "mtime_window_2m", "weak_signal": True, "skills": 60}


def test_dead_weight_licenses_and_large_non_text_payload_classes(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    texts = ["License variant A\n", "License variant B\n", "License variant C\n"]
    for i in range(54):
        md = _write_skill(tmp_path, f"pack/dw-{i:02d}", name=f"dw-{i:02d}")
        (md.parent / ("LICENSE" if i % 2 == 0 else "NOTICE.txt")).write_text(texts[i % 3], encoding="utf-8")
    assets = tmp_path / "skills/pack/dw-00/assets"
    assets.mkdir(parents=True, exist_ok=True)
    big = 1024 * 1024 + 100
    payloads = {
        "banner.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * big,
        "clip.mp4": b"\x00\x00\x00\x18ftypmp42" + b"\x00" * big,
        "song.mp3": b"ID3" + b"\x00" * big,
        "pack.zip": b"PK\x03\x04" + b"\x00" * big,
        "weights.gguf": b"GGUF" + b"\x00" * big,
        "tool.so": b"\x7fELF" + b"\x00" * big,
        "guide.pdf": b"%PDF-1.7\n" + b"\x00" * big,
        "blob.weirdext": b"\x00\x01\x02" * (big // 3 + 1),
        "data.sqlite": b"SQLite format 3\x00" + b"\x00" * big,
    }
    for fname, data in payloads.items():
        (assets / fname).write_bytes(data)
    (assets / "huge_doc.md").write_text("# Docs\n" + ("word " * 220_000), encoding="utf-8")
    _usage(tmp_path, {})
    res = mod.audit_skill_packs(tmp_path)
    dw = res["skill_packs"]["dead_weight"]
    assert dw["license_files_count"] == 54
    assert dw["distinct_license_texts"] == 3
    assert dw["identical_license_copies"] == 54
    assert dw["license_bytes"] == 54 * len("License variant A\n")
    assert dw["non_text_over_1mb_count"] == len(payloads)
    by = dw["non_text_over_1mb_by_type"]
    assert set(by) <= set(mod.NON_TEXT_CLASSES)
    assert {k: v["count"] for k, v in by.items()} == {
        "image": 1, "video": 1, "audio": 1, "archive": 1, "model_weights": 1,
        "executable_file": 1, "document": 1, "other": 2,
    }
    assert mod.NON_TEXT_CLASSES == (
        "image", "video", "audio", "archive", "model_weights", "executable_file", "document", "other")
    f_lic = next(f for f in res["findings"] if f["id"] == "skill_packs.license_copies")
    assert f_lic["classification"] == "info"


def test_always_on_skills_and_loaded_size_distribution(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    _write_skill(tmp_path, "stock-one", name="stock-one", description="Normal stock skill.", body="x" * 9000)
    (tmp_path / "skills/.bundled_manifest").write_text("stock-one:0123456789abcdef0123456789abcdef\n", encoding="utf-8")
    _write_skill(tmp_path, "team-rules", name="team-rules", description="Use in every session. Team rules.",
                 body="Rule body.\n" * 400, base_dir="shared/skills")
    _write_skill(tmp_path, "body-only-cue", name="body-only-cue", description="Use when debugging network routes.",
                 body="Always load this in every session before anything.\n" * 50)
    _write_skill(tmp_path, "pinned-helper", name="pinned-helper", description="Use when formatting reports.",
                 body="Helper body.\n" * 100)
    _usage(tmp_path, {})
    res = mod.audit_skill_packs(tmp_path, auto_load_skills=["stock-one", "pinned-helper"],
                                external_dirs=["shared/skills"])
    ao = res["skill_packs"]["always_on"]
    assert ao == {"count": 3, "auto_loaded_count": 2, "description_cue_count": 1, "non_stock_count": 2,
                  "paths": sorted([os.path.realpath(tmp_path / "skills/pinned-helper"),
                                   os.path.realpath(tmp_path / "shared/skills/team-rules")])}
    f_ao = next(f for f in res["findings"] if f["id"] == "skill_packs.always_on_skills")
    assert f_ao["classification"] == "review_suggested"
    # Names stay in the section (always_on.non_stock_skills); finding evidence carries counts only.
    assert f_ao["evidence"] == {"count": 2, "auto_loaded_count": 1, "description_cue_count": 1}
    ls = res["skill_packs"]["loaded_sizes"]
    assert [item["path"] for item in ls["top_10_largest"]] == [
        os.path.realpath(tmp_path / p) for p in ("shared/skills/team-rules", "skills/body-only-cue",
                                                 "skills/pinned-helper")]
    assert ls["max_chars"] == ls["top_10_largest"][0]["chars"]
    assert ls["median_chars"] == ls["top_10_largest"][1]["chars"]


def test_do_not_flag_normal_stock_and_handful_of_hub_installs(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    manifest_lines = []
    for i in range(55):
        sname = "hermes-agent" if i == 0 else f"stock-{i:02d}"
        md = _write_skill(tmp_path, f"cat-{i % 5}/{sname}", name=sname,
                          description="Use when working on standard tasks with Hermes.",
                          body="Standard stock guidance.\n" * 80, mtime=TS_INSIDE)
        if i == 0:
            refs = md.parent / "references"
            refs.mkdir()
            (refs / "big-guide.md").write_text("guide " * 250_000, encoding="utf-8")
        manifest_lines.append(f"{sname}:{'a' * 32}")
    (tmp_path / "skills/.bundled_manifest").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    hub_installed = {}
    for i in range(3):
        sname = f"hub-extra-{i}"
        md = _write_skill(tmp_path, sname, name=sname, description="Use when running optional helper.")
        (md.parent / "LICENSE.txt").write_text("Apache 2.0\n", encoding="utf-8")
        hub_installed[sname] = {"source": "github", "identifier": f"org/repo/{sname}", "install_path": sname,
                                "content_hash": "sha256:1234567890abcdef"}
    (tmp_path / "skills/.hub").mkdir(parents=True, exist_ok=True)
    (tmp_path / "skills/.hub/lock.json").write_text(json.dumps({"version": 1, "installed": hub_installed}),
                                                     encoding="utf-8")
    _usage(tmp_path, {
        "hermes-agent": {"use_count": 99, "last_used_at": USAGE_LAST},
        "stock-01": {"use_count": 5, "last_used_at": USAGE_LAST},
        "hub-extra-0": {"use_count": 3, "last_used_at": USAGE_LAST},
    })
    disabled = [f"stock-{i:02d}" for i in range(47, 55)]
    res = mod.audit_skill_packs(tmp_path, disabled_skills=disabled, auto_load_skills=["hermes-agent"])
    assert res["coverage"] == "verified"
    assert res["findings"] == []
    assert res["skill_packs"]["index"]["loadable_skills"] == 50
    assert res["skill_packs"]["index"]["disabled_skills_count"] == 8
    assert res["skill_packs"]["bulk_installs"]["group_count"] == 0


def _upstream_skills_tree() -> Path | None:
    """The stock skills folder of the Hermes Agent source the tests import (not imported here)."""
    import importlib.util

    spec = importlib.util.find_spec("hermes_constants")
    if spec is None or not spec.origin:
        return None
    cand = Path(spec.origin).resolve().parent / "skills"
    if (cand / "autonomous-ai-agents").is_dir():
        return cand
    return None


def test_plain_upstream_stock_install_raises_nothing_above_info(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    upstream = _upstream_skills_tree()
    if upstream is None:
        pytest.skip("upstream Hermes skills tree not present")
    home = tmp_path / "stock"
    shutil.copytree(upstream, home / "skills", symlinks=True,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
    names = []
    for md in sorted((home / "skills").rglob("SKILL.md")):
        names.append(md.parent.name)
    (home / "skills/.bundled_manifest").write_text("".join(f"{n}:{'b' * 32}\n" for n in names), encoding="utf-8")
    _usage(home, {"hermes-agent": {"use_count": 4, "last_used_at": USAGE_LAST}})
    res = mod.audit_skill_packs(home, host_platform="linux")
    idx = res["skill_packs"]["index"]
    assert 30 <= idx["loadable_skills"] <= 80  # 39 listed on Linux at the pinned source
    assert idx["index_chars"] < mod.INDEX_CHARS_THRESHOLD
    above_info = [f for f in res["findings"] if f["classification"] != "info"]
    assert above_info == []


def test_caps_truncation_paths(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.skill_packs")
    for i in range(6):
        md = _write_skill(tmp_path, f"cat/s-{i}", name=f"s-{i}")
        (md.parent / "LICENSE").write_text(f"License {i}\n", encoding="utf-8")
        (md.parent / "extra.txt").write_text("extra\n", encoding="utf-8")
    _usage(tmp_path, {f"s-{i}": {"use_count": i, "last_used_at": USAGE_LAST} for i in range(6)})
    for attr, val, expected_trunc in (
        ("MAX_TREE_ENTRIES", 3, "max_entries"),
        ("MAX_DEPTH", 1, "max_depth"),
        ("MAX_SKILLS", 2, "max_skills"),
        ("MAX_FILES_PER_SKILL", 1, "max_files_per_skill"),
        ("MAX_FILE_BYTES", 8, "max_file_bytes"),
        ("MAX_LICENSE_FILES", 2, "max_license_files"),
        ("MAX_TOTAL_BYTES", 30, "max_total_bytes"),
        ("MAX_USAGE_ROWS", 2, "max_usage_rows"),
    ):
        with monkeypatch.context() as m:
            m.setattr(mod, attr, val)
            res = mod.audit_skill_packs(tmp_path)
            assert res["coverage"] == "could_not_verify", attr
            assert res["skill_packs"]["limits"]["cuts"] > 0, attr
            assert res["skill_packs"]["truncated_by"] == expected_trunc, attr
            cnv = [f for f in res["findings"] if f["id"] == "skill_packs.could_not_verify"]
            assert cnv and all(f["classification"] == "info" for f in cnv), attr
    ticks = iter([0.0, 0.1, 25.0, 26.0, 27.0])
    res_time = mod.audit_skill_packs(tmp_path, clock=lambda: next(ticks, 30.0))
    assert res_time["coverage"] == "could_not_verify"
    assert res_time["skill_packs"]["truncated_by"] == "time_budget"
    assert res_time["skill_packs"]["limits"]["cuts"] > 0


def test_symlinks_credentials_read_only_and_canary_privacy(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.skill_packs")
    profile = tmp_path / "profile"
    outside = tmp_path / "outside_target"
    outside.mkdir()
    (outside / "SKILL.md").write_text("---\nname: outside\n---\nCANARY_OUTSIDE_TEXT\n", encoding="utf-8")
    md = _write_skill(profile, "pack/safe-skill", name="safe-skill",
                      description="Use in every session. CANARY_DESC_SECRET_991 host-203.0.113.7.",
                      body="Body text with CANARY_BODY_SECRET_992 and /home/user/workspace.\n")
    _write_skill(profile, "pack/other-skill", name="other-skill",
                 description="CANARY_DESC_TWO_981 " + "long words " * 20)
    (md.parent / "LICENSE").write_text("CANARY_LICENSE_TEXT_993\n", encoding="utf-8")
    deep_dir = md.parent / "assets" / "CANARY_DEEP_PATH_994" / "CANARY_SUBDIR_995"
    deep_dir.mkdir(parents=True)
    (deep_dir / "CANARY_FILE_996.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * (1024 * 1024 + 64))
    (deep_dir / "CANARY_FILE_997.canaryext").write_bytes(b"\x00\x01" * (600 * 1024))
    forbidden_files = [
        profile / ".env", profile / ".env.bak-1", profile / "auth.json", md.parent / "auth.json",
        md.parent / "LICENSE.key", md.parent / "id_ed25519", md.parent / "secrets.yaml",
        profile / "skills/mcp-tokens/x.json", md.parent / ".env",
    ]
    for fp in forbidden_files:
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text("CANARY_CRED_998\n", encoding="utf-8")
    (profile / "memories").mkdir(parents=True)
    (profile / "memories/MEMORY.md").write_text("CANARY_MEMORY_TEXT_1000\n", encoding="utf-8")
    (profile / "skills/linked-skill").symlink_to(outside)
    (profile / "skills/loop").symlink_to(profile / "skills")
    (md.parent / "LICENSE-link").symlink_to(outside / "SKILL.md")
    snapshot = {"version": 5, "manifest": {}, "skills": [
        {"skill_name": "gone", "category": "pack", "frontmatter_name": "gone", "rel": "pack/gone/SKILL.md",
         "description": "CANARY_SNAPSHOT_DESC_982"}]}
    (profile / ".skills_prompt_snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")
    _usage(profile, {"safe-skill": {"use_count": 2, "last_used_at": USAGE_LAST, "note": "CANARY_USAGE_983"}})
    (profile / "skills/.hub").mkdir(parents=True)
    (profile / "skills/.hub/lock.json").write_text(json.dumps({"installed": {"safe-skill": {
        "source": "CANARY_SOURCE_984", "identifier": "CANARY_IDENT_985", "install_path": "pack/safe-skill"}}}),
        encoding="utf-8")
    before_snapshot = _snapshot_tree(profile)

    opened_paths: list[str] = []
    real_open, real_io_open, real_os_open = builtins.open, io.open, os.open

    def track_open(file, *args, **kwargs):
        if isinstance(file, (str, os.PathLike)):
            opened_paths.append(os.fspath(file))
        return real_open(file, *args, **kwargs)

    def track_io_open(file, *args, **kwargs):
        if isinstance(file, (str, os.PathLike)):
            opened_paths.append(os.fspath(file))
        return real_io_open(file, *args, **kwargs)

    def track_os_open(path, flags, mode=0o777, *, dir_fd=None):
        opened_paths.append(os.fsdecode(path))
        return real_os_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(builtins, "open", track_open)
    monkeypatch.setattr(io, "open", track_io_open)
    monkeypatch.setattr(os, "open", track_os_open)
    res = mod.audit_skill_packs(profile)
    monkeypatch.undo()
    assert _snapshot_tree(profile) == before_snapshot
    for forbidden in (".env", "LICENSE.key", "auth.json", "id_ed25519", "secrets.yaml", "x.json",
                      "outside_target", "LICENSE-link", "MEMORY.md"):
        assert not any(Path(p).name.startswith(forbidden) or forbidden in Path(p).parts for p in opened_paths), (
            forbidden, opened_paths)
    assert res["skill_packs"]["limits"]["symlinks_skipped"] >= 3
    assert res["skill_packs"]["limits"]["credentials_skipped"] >= 2
    assert res["coverage"] == "could_not_verify"
    serialized = json.dumps(res)
    assert "CANARY" not in serialized
    assert "203.0.113" not in serialized
    # Absolute paths appear only as existing skill folders inside the profile (kept by the report serializer).
    assert str(outside) not in serialized
    assert "/home/user" not in serialized


def test_read_only_on_0555_tree(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    home = tmp_path / "ro"
    for i in range(3):
        _write_skill(home, f"pack/r-{i}")
    _usage(home, {"r-0": {"use_count": 1, "last_used_at": USAGE_LAST}})
    dirs = [Path(d) for d, _, _ in os.walk(home)]
    try:
        for d in dirs:
            d.chmod(0o555)
        before = _snapshot_tree(home)
        res = mod.audit_skill_packs(home)
        assert res["skill_packs"]["index"]["loadable_skills"] == 3
        assert _snapshot_tree(home) == before
    finally:
        for d in dirs:
            d.chmod(0o755)


def test_output_keys_and_consequence_wording(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    _write_skill(tmp_path, "pack/k-0")
    _usage(tmp_path, {})
    sec = mod.audit_skill_packs(tmp_path)["skill_packs"]
    assert set(sec) == {"status", "coverage", "reason", "truncated_by", "index", "usage", "bulk_installs",
                        "dead_weight", "always_on", "loaded_sizes", "limits", "thresholds"}
    assert set(sec["index"]) == {
        "loadable_skills", "discovered_skills", "stock_skills", "non_stock_skills", "disabled_skills_count",
        "shadowed_skills_count", "platform_excluded_count", "runtime_gated_count", "index_chars", "name_chars",
        "description_chars", "estimated_tokens", "snapshot"}
    assert set(sec["index"]["snapshot"]) == {"present", "coverage", "version", "skills_count", "description_chars",
                                             "stale_count"}
    assert set(sec["usage"]) == {
        "present", "coverage", "reason", "recording_since", "recording_until", "skills_evaluated", "zero_use_count",
        "never_used_share", "zero_use_unverifiable_count", "non_stock_skills_evaluated", "non_stock_zero_use_count",
        "non_stock_never_used_share", "top_used_counts", "days_since_last_use"}
    assert set(sec["bulk_installs"]) == {"group_count", "groups", "hub_lock_present", "hub_lock_entries",
                                         "hub_lock_missing_on_disk"}
    assert set(sec["always_on"]) == {"count", "auto_loaded_count", "description_cue_count", "non_stock_count",
                                     "paths"}
    assert set(sec["loaded_sizes"]) == {"median_chars", "p90_chars", "max_chars", "top_10_largest"}
    for text in mod.FINDING_CONSEQUENCES.values():
        low = text.lower()
        for banned in ("suggest", "indicat", "uncurated", "often means", "scratchpad", "likely"):
            assert banned not in low, (banned, text)
    # The not-measured section exposes the same key layout.
    empty = mod.audit_skill_packs(tmp_path / "nope")["skill_packs"]
    assert set(empty) == set(sec)
    for key, val in sec.items():
        if isinstance(val, dict):
            assert set(empty[key]) == set(val), key
    assert set(empty["index"]["snapshot"]) == set(sec["index"]["snapshot"])


def test_missing_empty_and_malformed_inputs(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    missing_res = mod.audit_skill_packs(tmp_path / "does_not_exist")
    assert missing_res["skill_packs"]["status"] == "not_measured"
    assert missing_res["coverage"] == "could_not_verify"
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    empty_res = mod.audit_skill_packs(empty_dir)
    assert empty_res["skill_packs"]["status"] == "not_measured"
    file_home = tmp_path / "a_file"
    file_home.write_text("x", encoding="utf-8")
    assert mod.audit_skill_packs(file_home)["skill_packs"]["status"] == "not_measured"

    bad = tmp_path / "malformed"
    _write_skill(bad, "good-skill", name="good-skill")
    bad_skill = bad / "skills/broken-skill"
    bad_skill.mkdir(parents=True)
    (bad_skill / "SKILL.md").write_bytes(b"---\nname: [unclosed\n---\n\x00\xff\xfe")
    binary_skill = bad / "skills/binary-skill"
    binary_skill.mkdir(parents=True)
    (binary_skill / "SKILL.md").write_bytes(b"\xff\xfe\x00junk" * 40)
    (bad / "skills/.usage.json").write_text("{broken json", encoding="utf-8")
    (bad / "skills/.bundled_manifest").write_text("not_a_valid_line_without_colon_or_hash:xyz\n", encoding="utf-8")
    (bad / "skills/.hub").mkdir(parents=True)
    (bad / "skills/.hub/lock.json").write_text('["wrong_root_type"]', encoding="utf-8")
    (bad / ".skills_prompt_snapshot.json").write_text('{"version": 3, "skills": "not_a_list"}', encoding="utf-8")
    os.mkfifo(bad / "skills/a-fifo")
    try:
        (bad / "skills" / os.fsdecode(b"bad-\xff-name")).mkdir()
    except (OSError, UnicodeEncodeError):
        pass
    res_bad = mod.audit_skill_packs(
        bad,
        disabled_skills=12345,  # type: ignore[arg-type]
        auto_load_skills={"bad": True},  # type: ignore[arg-type]
        external_dirs=["../outside_escape"],
        host_platform=42,  # type: ignore[arg-type]
    )
    assert res_bad["coverage"] == "could_not_verify"
    assert res_bad["skill_packs"]["limits"]["cuts"] > 0
    assert any(f["id"] == "skill_packs.could_not_verify" and f["classification"] == "info"
               for f in res_bad["findings"])
    # Hermes still lists a skill whose SKILL.md cannot be decoded (empty frontmatter, folder name).
    assert res_bad["skill_packs"]["index"]["discovered_skills"] == 3
    # Usage file with wrong types and huge values does not raise.
    _usage(bad, {"good-skill": {"use_count": "x" * 10_000, "last_used_at": 12}, "y": [1, 2]}, anchor=False)
    assert mod.audit_skill_packs(bad)["skill_packs"]["usage"]["coverage"] == "could_not_verify"


def test_config_derived_inputs_are_read_from_profile_config(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    _write_skill(tmp_path, "pack/kept", name="kept")
    _write_skill(tmp_path, "pack/retired", name="retired")
    _write_skill(tmp_path, "pinned", name="pinned", base_dir="shared/skills")
    _usage(tmp_path, {})
    (tmp_path / "config.yaml").write_text(
        "model: some-model\nskills:\n  disabled: [retired, hermes-agent]\n  auto_load: '[\"pinned\"]'\n"
        "  external_dirs: shared/skills\n", encoding="utf-8")
    res = mod.audit_skill_packs(tmp_path)
    sec = res["skill_packs"]
    assert res["coverage"] == "verified", sec["limits"]
    assert sec["index"]["discovered_skills"] == 3
    assert sec["index"]["disabled_skills_count"] == 1
    assert sec["index"]["loadable_skills"] == 2
    assert sec["always_on"]["auto_loaded_count"] == 1
    # An explicit value (also an empty one) overrides the config.
    res_explicit = mod.audit_skill_packs(tmp_path, disabled_skills=(), auto_load_skills=(), external_dirs=())
    assert res_explicit["skill_packs"]["index"]["discovered_skills"] == 2
    assert res_explicit["skill_packs"]["index"]["disabled_skills_count"] == 0
    assert res_explicit["skill_packs"]["always_on"]["auto_loaded_count"] == 0
    # Unparseable config, a non-mapping skills block, or an environment reference: a cut, never silent defaults.
    for bad_cfg in ("skills: [unclosed\n", "skills: just-a-string\n", "skills:\n  disabled: ${DISABLED}\n",
                    "skills:\n  disabled: [a]\nskills:\n  disabled: [b]\n"):
        (tmp_path / "config.yaml").write_text(bad_cfg, encoding="utf-8")
        bad = mod.audit_skill_packs(tmp_path)
        assert bad["coverage"] == "could_not_verify", bad_cfg
        assert bad["skill_packs"]["limits"]["cuts"] > 0, bad_cfg
    # Missing config: no cut.
    (tmp_path / "config.yaml").unlink()
    assert mod.audit_skill_packs(tmp_path)["coverage"] == "verified"


def test_envelope_shape_and_adapter_keeps_section_and_run_metrics(tmp_path: Path) -> None:
    mod = load_submodule("audit.skill_packs")
    contract = load_submodule("audit.contract")
    for i in range(3):
        _write_skill(tmp_path, f"pack/e-{i}")
    res = mod.audit_skill_packs(tmp_path)  # no usage file: could_not_verify finding
    # make_component_envelope adds ok/error/classification; adapt_component_result ignores or recomputes them.
    assert set(res) == {"skill_packs", "findings", "run_metrics", "status", "coverage", "ok", "error",
                        "classification"}
    adapted = contract.adapt_component_result(res, component_id="skill_packs", affected_identities=["default"])
    assert adapted["skill_packs"] == res["skill_packs"]
    assert adapted["run_metrics"] == res["run_metrics"]
    assert adapted["coverage"] == "could_not_verify"
    assert [f["id"] for f in adapted["findings"]] == ["skill_packs.could_not_verify"]
    assert all(f["id"].startswith("skill_packs.") for f in adapted["findings"])


# ---------------------------------------------------------------------------------------------------------------
# Wiring sheet (audit/wiring/skill_packs.json) and sealing through the report serializer and persistence.

WIRING_PATH = Path(__file__).resolve().parents[1] / "audit" / "wiring" / "skill_packs.json"
_FINDING_FIELDS = {"id", "classification", "coverage", "affected_identities", "source_paths", "evidence",
                   "consequence", "limitations", "proposed_cleanup_id", "severity", "detail", "fix"}


def _wiring() -> dict:
    return json.loads(WIRING_PATH.read_text(encoding="utf-8"))


def _all_branch_envelopes(base: Path, monkeypatch) -> list[dict]:
    """Synthetic homes that reach every status, reason, truncated_by, signal, bucket, class and rule."""
    mod = load_submodule("audit.skill_packs")
    out: list[dict] = []

    big = base / "big"
    build_render_fixture(big)
    for i in range(155):
        _write_skill(big, f"pack/skill-{i:03d}", name=f"skill-{i:03d}",
                     description="Pack skill description that adds characters to every prompt index.")
    ghosts = [{"skill_name": f"ghost-{i:02d}", "category": "gone", "frontmatter_name": f"ghost-{i:02d}",
               "description": "Short."} for i in range(12)]
    (big / ".skills_prompt_snapshot.json").write_text(
        json.dumps({"version": 3, "manifest": {}, "skills": ghosts}), encoding="utf-8")
    _usage(big, {"skill-000": {"use_count": 4, "last_used_at": "2026-09-25T00:00:00+00:00"},
                 "skill-001": {"use_count": 2, "last_used_at": "2026-08-15T00:00:00+00:00"},
                 "skill-002": {"use_count": 1, "last_used_at": "2026-05-01T00:00:00+00:00"}})
    out.append(mod.audit_skill_packs(big, host_platform="linux"))

    lic = base / "lic"
    for i in range(55):
        md = _write_skill(lic, f"lic/l-{i:02d}", name=f"l-{i:02d}", mtime=TS_INSIDE + i * 1000)
        (md.parent / "LICENSE").write_text("Shared licence text\n", encoding="utf-8")
    for i in range(22):
        sname = f"hub-{i:02d}"
        _write_skill(lic, f"hub/{sname}", name=sname, mtime=TS_INSIDE + 200_000 + i * 1000)
    (lic / "skills/.hub").mkdir(parents=True, exist_ok=True)
    (lic / "skills/.hub/lock.json").write_text(json.dumps({"version": 1, "installed": {
        f"hub-{i:02d}": {"source": "github", "install_path": f"hub/hub-{i:02d}"} for i in range(22)}}),
        encoding="utf-8")
    for i in range(21):
        _write_skill(lic, f"mtime/m-{i:02d}", name=f"m-{i:02d}", mtime=TS_INSIDE + 500_000 + i)
    _usage(lic, {"l-00": {"use_count": 1, "last_used_at": USAGE_LAST}})
    out.append(mod.audit_skill_packs(lic))
    # Same tree without a usage file: bulk groups without used counts, usage_file_missing.
    (lic / "skills/.usage.json").unlink()
    out.append(mod.audit_skill_packs(lic))

    nu = base / "never_used"
    for i in range(25):
        _write_skill(nu, f"pack/s-{i:02d}", name=f"s-{i:02d}")
    _usage(nu, {"s-00": {"use_count": 3, "last_used_at": "2026-09-25T00:00:00+00:00"},
                "s-01": {"use_count": 2, "last_used_at": "2026-07-15T00:00:00+00:00"},
                "gone-skill": {"use_count": 9, "last_used_at": USAGE_LAST}})
    out.append(mod.audit_skill_packs(nu))

    dw = base / "dead_weight"
    md = _write_skill(dw, "pack/dw-00", name="dw-00")
    assets = md.parent / "assets"
    assets.mkdir()
    big_n = 1024 * 1024 + 16
    for fname, data in {"a.png": b"\x89PNG\r\n\x1a\n", "b.mp4": b"\x00\x00\x00\x18ftypmp42", "c.mp3": b"ID3",
                        "d.zip": b"PK\x03\x04", "e.gguf": b"GGUF", "f.so": b"\x7fELF", "g.pdf": b"%PDF-1.7\n",
                        "h.bin": b"\x00\x01"}.items():
        (assets / fname).write_bytes(data + b"\x00" * big_n)
    _write_skill(dw, "pinned", name="pinned", description="Use when formatting.", base_dir="shared/skills")
    _write_skill(dw, "pack/cue", name="cue", description="Load first in every session.")
    (dw / "config.yaml").write_text("skills:\n  auto_load: [pinned]\n  external_dirs: [shared/skills]\n",
                                    encoding="utf-8")
    _usage(dw, {})
    out.append(mod.audit_skill_packs(dw))

    out.append(mod.audit_skill_packs(base / "does-not-exist"))  # not_measured, no finding
    a_file = base / "a_file"
    a_file.write_text("x", encoding="utf-8")
    out.append(mod.audit_skill_packs(a_file))  # not_measured with a could_not_verify finding

    bad = base / "malformed"
    _write_skill(bad, "good", name="good")
    (bad / "skills/.usage.json").write_text("{broken", encoding="utf-8")
    (bad / ".skills_prompt_snapshot.json").write_text('{"version": 3, "skills": "x"}', encoding="utf-8")
    out.append(mod.audit_skill_packs(bad))
    _usage(bad, {"good": {"use_count": 0}}, anchor=False)  # no timestamps
    out.append(mod.audit_skill_packs(bad))

    linked = base / "linked"
    _write_skill(linked, "pack/real", name="real")
    (linked / "skills/pack/alias").symlink_to(linked / "skills/pack/real")
    _usage(linked, {"real": {"use_count": 1, "last_used_at": USAGE_LAST}})
    out.append(mod.audit_skill_packs(linked))  # a cut without a truncation reason: unverified_inputs

    caps = base / "caps"
    for i in range(6):
        md = _write_skill(caps, f"cat/s-{i}", name=f"s-{i}")
        (md.parent / "LICENSE").write_text(f"License {i}\n", encoding="utf-8")
        (md.parent / "extra.txt").write_text("extra\n", encoding="utf-8")
    _usage(caps, {f"s-{i}": {"use_count": i, "last_used_at": USAGE_LAST} for i in range(6)})
    for attr, val in (("MAX_TREE_ENTRIES", 3), ("MAX_DEPTH", 1), ("MAX_SKILLS", 2), ("MAX_FILES_PER_SKILL", 1),
                      ("MAX_FILE_BYTES", 8), ("MAX_LICENSE_FILES", 2), ("MAX_TOTAL_BYTES", 30),
                      ("MAX_USAGE_ROWS", 2)):
        with monkeypatch.context() as m:
            m.setattr(mod, attr, val)
            out.append(mod.audit_skill_packs(caps))
    ticks = iter([0.0, 0.1, 25.0, 26.0, 27.0])
    out.append(mod.audit_skill_packs(caps, clock=lambda: next(ticks, 30.0)))
    return out


def _walk_section(value, key, schema_keys, vocabulary, free_keys, seen_keys, seen_vocab, path="skill_packs"):
    if isinstance(value, dict):
        for k, v in value.items():
            assert k in schema_keys, f"key {k!r} at {path} missing from wiring schema_keys"
            seen_keys.add(k)
            _walk_section(v, k, schema_keys, vocabulary, free_keys, seen_keys, seen_vocab, f"{path}.{k}")
    elif isinstance(value, list):
        for item in value:
            _walk_section(item, key, schema_keys, vocabulary, free_keys, seen_keys, seen_vocab, path + "[]")
    elif isinstance(value, str):
        if key in free_keys:
            return
        assert value in vocabulary, f"string {value!r} at {path} is neither vocabulary nor a free string"
        seen_vocab.add(value)
    else:
        assert value is None or type(value) in (bool, int, float), (path, type(value))


def test_wiring_json_is_complete_for_every_reachable_branch(tmp_path: Path, monkeypatch) -> None:
    w = _wiring()
    assert set(w) == {"section", "entry", "kwargs", "schema_keys", "vocabulary", "numeric_evidence_keys",
                      "vocab_evidence_keys", "rule_ids", "classifications", "consequences", "free_strings",
                      "run_metrics_keys", "notes"}
    mod = load_submodule("audit.skill_packs")
    assert w["section"] == "skill_packs" and w["entry"] == "audit.skill_packs.audit_skill_packs"
    import inspect
    assert set(w["kwargs"]) == set(inspect.signature(mod.audit_skill_packs).parameters)
    assert w["schema_keys"] == sorted(set(w["schema_keys"])) and w["vocabulary"] == sorted(set(w["vocabulary"]))
    assert w["consequences"] == mod.FINDING_CONSEQUENCES
    assert sorted(w["rule_ids"]) == sorted(mod.FINDING_CONSEQUENCES) == sorted(w["classifications"])
    schema_keys, vocabulary = set(w["schema_keys"]), set(w["vocabulary"])
    numeric, vocab_ev = set(w["numeric_evidence_keys"]), set(w["vocab_evidence_keys"])
    free_keys = {f["key"] for f in w["free_strings"]}
    assert all(set(f) == {"key", "what", "example", "why_safe"} for f in w["free_strings"])
    seen_keys: set[str] = set()
    seen_vocab: set[str] = set()
    seen_classes: dict[str, set[str]] = {}
    seen_ev_keys: set[str] = set()
    for env in _all_branch_envelopes(tmp_path, monkeypatch):
        seen_keys.add("skill_packs")
        _walk_section(env["skill_packs"], "skill_packs", schema_keys, vocabulary, free_keys, seen_keys, seen_vocab)
        assert set(env["run_metrics"]) == set(w["run_metrics_keys"])
        assert all(type(v) in (int, bool) for v in env["run_metrics"].values())
        for f in env["findings"]:
            assert set(f) == _FINDING_FIELDS
            assert f["id"] in w["rule_ids"]
            assert f["classification"] in w["classifications"][f["id"]]
            seen_classes.setdefault(f["id"], set()).add(f["classification"])
            assert f["consequence"] == f["detail"] == w["consequences"][f["id"]]
            assert f["limitations"] == "" and f["fix"] is None and f["proposed_cleanup_id"] is None
            for ident in f["affected_identities"]:
                assert ident in vocabulary
                seen_vocab.add(ident)
            for sp in f["source_paths"]:
                assert sp["path"] in vocabulary and sp["start_line"] is None and sp["end_line"] is None
            for k, v in f["evidence"].items():
                assert k in schema_keys, k
                seen_ev_keys.add(k)
                if k in numeric:
                    assert type(v) in (int, float, bool), (f["id"], k, v)
                else:
                    assert k in vocab_ev and isinstance(v, str) and v in vocabulary, (f["id"], k, v)
                    seen_vocab.add(v)
            seen_vocab.update({f["classification"]})
    # Every declared key, value, evidence key and classification is reached by some branch (no padding).
    assert seen_keys | seen_ev_keys == schema_keys, sorted(schema_keys - seen_keys - seen_ev_keys)
    assert seen_vocab == vocabulary, sorted(vocabulary - seen_vocab)
    assert seen_ev_keys == numeric | vocab_ev, sorted((numeric | vocab_ev) ^ seen_ev_keys)
    assert {k: sorted(v) for k, v in seen_classes.items()} == {k: sorted(v) for k, v in w["classifications"].items()}


def _patch_sealing_sets(monkeypatch, w: dict) -> None:
    evidence = load_submodule("audit.evidence")
    persistence = load_submodule("audit.persistence")
    constants = load_submodule("audit.evidence_constants")
    consequences = {**constants.FINDING_CONSEQUENCES, **w["consequences"]}
    allowed = frozenset({*constants.ALLOWED_FINDING_CONSEQUENCES, *w["consequences"].values()})
    rule_ids = frozenset({*constants.RULE_IDS, *w["rule_ids"]})
    vocab = frozenset({*evidence.VOCABULARY, *w["vocabulary"], *w["rule_ids"], *w["consequences"].values()})
    monkeypatch.setattr(evidence, "SCHEMA_KEYS", frozenset({*evidence.SCHEMA_KEYS, *w["schema_keys"]}))
    monkeypatch.setattr(evidence, "VOCABULARY", vocab)
    monkeypatch.setattr(evidence, "RULE_IDS", rule_ids)
    monkeypatch.setattr(persistence, "VOCABULARY", vocab)
    monkeypatch.setattr(persistence, "ALLOWED_FINDING_CONSEQUENCES", allowed)
    monkeypatch.setattr(persistence, "FINDING_CONSEQUENCES", consequences)
    monkeypatch.setattr(persistence, "_EVIDENCE_NUMERIC_KEYS",
                        frozenset({*persistence._EVIDENCE_NUMERIC_KEYS, *w["numeric_evidence_keys"]}))
    monkeypatch.setattr(persistence, "_EVIDENCE_VOCAB_KEYS",
                        frozenset({*persistence._EVIDENCE_VOCAB_KEYS, *w["vocab_evidence_keys"]}))
    monkeypatch.setattr(constants, "RULE_IDS", rule_ids)
    monkeypatch.setattr(constants, "FINDING_CONSEQUENCES", consequences)
    monkeypatch.setattr(constants, "ALLOWED_FINDING_CONSEQUENCES", allowed)


def _compare_sealed(orig, sealed, key, free_keys, vocab, outcomes, path="skill_packs"):
    if isinstance(orig, dict):
        assert isinstance(sealed, dict) and set(sealed) == set(orig), (path, sorted(set(orig) ^ set(sealed)))
        for k, v in orig.items():
            _compare_sealed(v, sealed[k], k, free_keys, vocab, outcomes, f"{path}.{k}")
    elif isinstance(orig, list):
        assert isinstance(sealed, list) and len(sealed) == len(orig), path
        for o, s_item in zip(orig, sealed):
            _compare_sealed(o, s_item, key, free_keys, vocab, outcomes, path + "[]")
    else:
        assert sealed == orig and type(sealed) is type(orig), (path, orig, sealed)
        if isinstance(orig, str) and key in free_keys:
            outcomes.setdefault(key, set()).add("kept")


def test_sealing_keeps_every_measurement(tmp_path: Path, monkeypatch) -> None:
    w = _wiring()
    envelopes = _all_branch_envelopes(tmp_path, monkeypatch)
    contract = load_submodule("audit.contract")
    evidence = load_submodule("audit.evidence")
    persistence = load_submodule("audit.persistence")
    _patch_sealing_sets(monkeypatch, w)
    free_keys = {f["key"] for f in w["free_strings"]}
    vocab = evidence.VOCABULARY
    outcomes: dict[str, set[str]] = {}
    n_findings = 0
    for env in envelopes:
        adapted = contract.adapt_component_result(env, component_id="skill_packs", affected_identities=["default"])
        assert adapted["skill_packs"] == env["skill_packs"] and adapted["run_metrics"] == env["run_metrics"]
        sealed = evidence.serialize_evidence({"skill_packs": adapted["skill_packs"]})
        assert set(sealed) == {"skill_packs"}
        _compare_sealed(env["skill_packs"], sealed["skill_packs"], "skill_packs", free_keys, vocab, outcomes)
        for f in adapted["findings"]:
            n_findings += 1
            # Findings reach the report as persistence DTOs (store.finalize_run), which are then serialized again.
            dto = persistence.finding_dto(f)
            _compare_sealed(dto, evidence.serialize_evidence(dto), None, set(), vocab, outcomes, f["id"])
            for field in ("id", "classification", "coverage", "severity", "affected_identities", "source_paths",
                          "consequence"):
                assert dto[field] == f[field], (f["id"], field, dto[field])
            assert dto["consequence"] == w["consequences"][f["id"]]
            assert {k: v for k, v in dto["evidence"].items() if k != "source_digest"} == f["evidence"], f["id"]
    assert n_findings > 20
    # Every free string is an absolute path to an existing skill folder, kept unchanged by the serializer.
    assert outcomes == {"path": {"kept"}, "paths": {"kept"}}


def test_canary_inputs_never_reach_sealed_output(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.skill_packs")
    contract = load_submodule("audit.contract")
    evidence = load_submodule("audit.evidence")
    persistence = load_submodule("audit.persistence")
    w = _wiring()
    home = tmp_path / "canary_home"
    md = _write_skill(home, "CANARYFOLDER01/CANARYSKILL02", name="CANARYNAME03",
                      description="Use in every session. CANARYDESC04", body="CANARYBODY05\n")
    (md.parent / "LICENSE").write_text("CANARYLICENSE06\n", encoding="utf-8")
    (md.parent / "CANARYFILE07.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * (1024 * 1024 + 8))
    _write_skill(home, "pack/url-named", name="https://canary-host08.example/x", description="Load first.")
    _write_skill(home, "pack/plain", name="plain", body="p" * 4000)
    (home / ".skills_prompt_snapshot.json").write_text(json.dumps({"version": 4, "manifest": {"CANARYMAN09": 1},
        "skills": [{"skill_name": "CANARYSNAP10", "category": "CANARYCAT11", "frontmatter_name": "CANARYSNAP10",
                    "rel": "CANARYCAT11/CANARYSNAP10/SKILL.md", "description": "CANARYSNAPDESC12"}]}),
        encoding="utf-8")
    _usage(home, {"CANARYUSAGE13": {"use_count": 7, "last_used_at": USAGE_LAST, "note": "CANARYUSAGENOTE14"}})
    (home / "skills/.hub").mkdir(parents=True, exist_ok=True)
    (home / "skills/.hub/lock.json").write_text(json.dumps({"installed": {"CANARYHUB15": {
        "source": "CANARYSRC16", "identifier": "CANARYID17", "install_path": "CANARYPATH18"}}}), encoding="utf-8")
    (home / "skills/.bundled_manifest").write_text("CANARYSTOCK19:" + "c" * 32 + "\n", encoding="utf-8")
    (home / "config.yaml").write_text(
        "model: CANARYMODEL20\nskills:\n  disabled: [CANARYDISABLED21]\n  auto_load: [CANARYNAME03]\n"
        "  external_dirs: [CANARYEXT22]\n", encoding="utf-8")
    env = mod.audit_skill_packs(home)
    free_keys = {f["key"] for f in w["free_strings"]}

    home_real = os.path.realpath(home)

    def canary_walk(value, key, path):
        """A canary may appear only inside a kept absolute path to an existing folder of the audited home."""
        if isinstance(value, dict):
            assert not ("hmac" in value and "kind" in value), path
            for k, v in value.items():
                assert "CANARY" not in k, path
                canary_walk(v, k, f"{path}.{k}")
        elif isinstance(value, list):
            for item in value:
                canary_walk(item, key, path + "[]")
        elif isinstance(value, str) and "CANARY" in value:
            assert key in free_keys, (path, value)
            assert value.startswith(home_real + os.sep) and os.path.isdir(value), (path, value)
            assert "CANARYFOLDER01/CANARYSKILL02" in value, (path, value)

    canary_walk(env["skill_packs"], "skill_packs", "skill_packs")
    canary_walk(env["findings"], "findings", "findings")
    canary_walk(env["run_metrics"], "run_metrics", "run_metrics")
    assert env["skill_packs"]["always_on"]["paths"] == sorted(
        os.path.realpath(home / "skills" / p) for p in ("CANARYFOLDER01/CANARYSKILL02", "pack/url-named"))
    _patch_sealing_sets(monkeypatch, w)
    adapted = contract.adapt_component_result(env, component_id="skill_packs")
    sealed = evidence.serialize_evidence({"skill_packs": adapted["skill_packs"]})
    sealed_findings = [evidence.serialize_evidence(persistence.finding_dto(f)) for f in adapted["findings"]]
    canary_walk(json.loads(json.dumps(sealed)), "sealed", "sealed")
    canary_walk(json.loads(json.dumps(sealed_findings)), "findings", "sealed_findings")
    dumped = json.dumps([sealed, sealed_findings])
    assert '"kind": "url"' not in dumped and "canary-host08" not in dumped and "hmac" not in dumped


def _sealed_run(home: Path, monkeypatch, w: dict) -> str:
    mod = load_submodule("audit.skill_packs")
    contract = load_submodule("audit.contract")
    evidence = load_submodule("audit.evidence")
    persistence = load_submodule("audit.persistence")
    with monkeypatch.context() as m:
        _patch_sealing_sets(m, w)
        adapted = contract.adapt_component_result(mod.audit_skill_packs(home), component_id="skill_packs")
        # A fresh serializer per run, like one redaction scope per audit (its HMAC key is random per instance).
        serializer = evidence.EvidenceSerializer()
        sealed = serializer.serialize({"skill_packs": adapted["skill_packs"]})
        dtos = serializer.serialize([persistence.finding_dto(f) for f in adapted["findings"]])
        for dto in dtos:
            dto["evidence"].pop("source_digest", None)  # keyed digest handle, outside the section by design
        return json.dumps([sealed, dtos], sort_keys=True)


def test_two_runs_give_identical_sealed_output_and_no_hashed_tokens(tmp_path: Path, monkeypatch) -> None:
    w = _wiring()
    envelopes = _all_branch_envelopes(tmp_path, monkeypatch)
    homes = [tmp_path / n for n in ("big", "lic", "never_used", "dead_weight", "malformed", "linked", "caps")]
    for home in homes:
        first, second = _sealed_run(home, monkeypatch, w), _sealed_run(home, monkeypatch, w)
        assert first == second, home.name
        assert "hmac" not in first, home.name
    # No dict with an `hmac` field anywhere in any sealed branch output.
    evidence = load_submodule("audit.evidence")
    persistence = load_submodule("audit.persistence")
    contract = load_submodule("audit.contract")
    _patch_sealing_sets(monkeypatch, w)

    def no_hmac(value, path):
        if isinstance(value, dict):
            assert "hmac" not in value, path
            for k, v in value.items():
                no_hmac(v, f"{path}.{k}")
        elif isinstance(value, list):
            for item in value:
                no_hmac(item, path + "[]")

    for env in envelopes:
        adapted = contract.adapt_component_result(env, component_id="skill_packs")
        no_hmac(json.loads(json.dumps(evidence.serialize_evidence({"skill_packs": adapted["skill_packs"]}))), "sec")
        for f in adapted["findings"]:
            dto = json.loads(json.dumps(evidence.serialize_evidence(persistence.finding_dto(f))))
            dto["evidence"].pop("source_digest", None)
            no_hmac(dto, f["id"])


def test_doc_page_matches_code_and_wiring():
    from tests.test_audit_dead_stores import _doc_contains, _doc_rule_rows, _doc_words, _doc_bullets
    mod = load_submodule("audit.skill_packs")
    w = _wiring()
    doc = (Path(__file__).resolve().parents[1] / "docs/audit-sections/skill_packs.md").read_text(encoding="utf-8")
    rows = _doc_rule_rows(doc, mod.FINDING_CONSEQUENCES)
    for rule_id, classes in w["classifications"].items():
        for cls in classes:
            _doc_contains(rows[rule_id]['classification'], cls)
    sentences = _doc_bullets(doc)
    for rule_id, sentence in mod.FINDING_CONSEQUENCES.items():
        assert _doc_words(sentences[rule_id]) == _doc_words(sentence), rule_id
    for key in w["schema_keys"]:
        _doc_contains(doc, key)
    for cls in mod.NON_TEXT_CLASSES:
        _doc_contains(doc, cls)
    for token in w["vocabulary"]:
        _doc_contains(doc, token)
    _doc_contains(doc, "upper bound")
    assert "about" in mod.FINDING_CONSEQUENCES["skill_packs.index_cost"]
