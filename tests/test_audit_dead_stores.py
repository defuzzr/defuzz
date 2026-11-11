"""Dead stores and caches audit tests; synthetic homes only."""
from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import re
from pathlib import Path

import pytest

from tests.conftest import load_submodule


def _tree_snapshot(root: Path) -> str:
    """Hash every entry's relative path, mode, size, mtime_ns, link target, and regular-file bytes."""
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        st_dir = os.lstat(dirpath)
        h.update(f"D:{rel_dir}:{st_dir.st_mode}:{st_dir.st_size}\n".encode("utf-8", "surrogateescape"))
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            st = os.lstat(p)
            if os.path.islink(p):
                h.update(f"L:{rel}:{os.readlink(p)}\n".encode("utf-8", "surrogateescape"))
            elif os.path.isfile(p):
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
                h.update(f"F:{rel}:{st.st_mode}:{st.st_size}:{st.st_mtime_ns}:{digest}\n".encode("utf-8", "surrogateescape"))
    return h.hexdigest()


def test_exports_and_archives_and_bursts(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    exports = tmp_path / "profile-exports"
    exports.mkdir()
    base_t = 1790836378.0
    sizes = [25 * 1024 * 1024, 15 * 1024 * 1024, 12 * 1024 * 1024, 5 * 1024 * 1024]
    for idx, sz in enumerate(sizes):
        f = exports / f"prof{idx}-20261001-02320{idx}.tar.gz"
        f.write_bytes(b"z" * sz)
        os.utime(f, (base_t + idx * 10, base_t + idx * 10))

    top_zip = tmp_path / "full-backup.zip"
    top_zip.write_bytes(b"z" * (11 * 1024 * 1024))
    os.utime(top_zip, (base_t + 500, base_t + 500))

    res = mod.audit_dead_stores(
        tmp_path,
        enabled_plugins=[],
        external_skill_dirs=[],
        pet_enabled=True,
        now=base_t + 3600,
    )
    sec = res["dead_stores"]
    assert res["coverage"] == "verified"
    assert sec["status"] == "completed"
    exp = sec["exports_and_archives"]
    assert exp["profile_exports_count"] == 4
    assert exp["profile_exports_bytes"] == sum(sizes)
    assert exp["large_archives_count"] == 1
    assert exp["large_archives_bytes"] == 11 * 1024 * 1024
    assert exp["total_bytes"] == sum(sizes) + 11 * 1024 * 1024
    assert exp["burst_count"] == 4
    ids = {f["id"] for f in res["findings"]}
    assert "dead_stores.profile_exports" in ids
    f_exp = next(f for f in res["findings"] if f["id"] == "dead_stores.profile_exports")
    assert f_exp["classification"] == "review_suggested"
    assert f_exp["evidence"]["profile_exports_bytes"] == sum(sizes)
    assert f_exp["evidence"]["burst_count"] == 4


def test_plugins_parked_disabled_hooks_residue_and_missing_enabled(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    plugins = tmp_path / "plugins"
    dplugins = tmp_path / "desktop-plugins"
    plugins.mkdir()
    dplugins.mkdir()

    # 1. Parked plugin copy under plugins/ and desktop-plugins/
    parked = plugins / "sample.parked-20260903"
    parked.mkdir()
    (parked / "plugin.yaml").write_text("name: sample\n", encoding="utf-8")
    (parked / "weights.bin").write_bytes(b"p" * 200_000)
    dparked = dplugins / "sample.parked-20260903"
    dparked.mkdir()
    (dparked / "plugin.js").write_text("// parked desktop half\n", encoding="utf-8")

    # 2. Disabled plugin on disk > 5 MiB (no hooks) and disabled plugin declaring 10 hooks
    disabled_big = plugins / "large-disabled"
    disabled_big.mkdir()
    (disabled_big / "plugin.yaml").write_text(
        "name: large-disabled\nkind: model-provider\n", encoding="utf-8"
    )
    (disabled_big / "bundle.bin").write_bytes(b"d" * (6 * 1024 * 1024))

    disabled_hooks = plugins / "status-hooks"
    disabled_hooks.mkdir()
    hooks_list = [
        "on_session_start",
        "pre_llm_call",
        "post_llm_call",
        "pre_tool_call",
        "post_tool_call",
        "pre_approval_request",
        "post_approval_response",
        "on_session_end",
        "on_session_finalize",
        "on_session_reset",
    ]
    (disabled_hooks / "plugin.yaml").write_text(
        "name: status-hooks\nprovides_hooks:\n" + "".join(f"  - {h}\n" for h in hooks_list),
        encoding="utf-8",
    )
    (disabled_hooks / "__init__.py").write_text("def register(ctx): pass\n", encoding="utf-8")

    # 3. Enabled plugin on disk with .git, __pycache__, tests, node_modules
    active = plugins / "active-plugin"
    active.mkdir()
    (active / "plugin.yaml").write_text("name: active-plugin\n", encoding="utf-8")
    (active / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    for sub, sz in ((".git", 40_000), ("__pycache__", 10_000), ("tests", 20_000), ("node_modules", 30_000)):
        sd = active / sub
        sd.mkdir()
        (sd / "blob").write_bytes(b"r" * sz)

    # 4. Enabled plugin with empty folder and enabled plugin with no manifest
    (plugins / "empty-enabled").mkdir()
    no_manifest = plugins / "manifestless-enabled"
    no_manifest.mkdir()
    (no_manifest / "code.py").write_text("y = 2\n", encoding="utf-8")

    res = mod.audit_dead_stores(
        tmp_path,
        enabled_plugins=[
            "active-plugin",
            "disk-cleanup",  # bundled: must NOT be flagged missing
            "platforms/discord",  # bundled category key: must NOT be flagged missing
            "a2a-platform",  # bundled manifest name: must NOT be flagged missing
            "missing-nonbundled",
            "empty-enabled",
            "manifestless-enabled",
        ],
        external_skill_dirs=[],
        pet_enabled=True,
        now=1800000000.0,
    )
    sec = res["dead_stores"]
    psec = sec["plugins"]
    assert psec["parked_count"] == 2
    assert psec["disabled_count"] == 2
    assert psec["disabled_hooks_declared"] == 10
    assert psec["dev_residue"]["git_bytes"] == 40_000
    assert psec["dev_residue"]["pycache_bytes"] == 10_000
    assert psec["dev_residue"]["tests_bytes"] == 20_000
    assert psec["dev_residue"]["node_modules_bytes"] == 30_000

    # Names from config are never emitted; existing folders are reported by absolute path.
    real = Path(os.path.realpath(tmp_path))
    missing = sorted((m["reason"], m["path"]) for m in psec["enabled_missing"])
    assert missing == sorted([
        ("no_folder", None),
        ("empty_folder", str(real / "plugins" / "empty-enabled")),
        ("no_manifest", str(real / "plugins" / "manifestless-enabled")),
    ])

    f_parked = next(f for f in res["findings"] if f["id"] == "dead_stores.parked_or_disabled_plugins")
    assert f_parked["classification"] == "review_suggested"
    assert f_parked["evidence"]["hooks_declared"] == 10
    assert f_parked["evidence"]["parked_count"] == 2
    assert f_parked["evidence"]["disabled_count"] == 2

    f_missing = next(f for f in res["findings"] if f["id"] == "dead_stores.enabled_plugin_missing")
    # Entry-point plugins (hermes_cli/plugins_discovery.py:72-95) are invisible to a file walk,
    # so a missing folder is never certain: review_suggested, not warning.
    assert f_missing["classification"] == "review_suggested"
    assert f_missing["evidence"]["missing_count"] == 3


def test_orphan_plugin_data_and_regenerable_caches(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    # Installed plugin 'installed-one', orphan 'hermes-achievements'
    inst = tmp_path / "plugins" / "installed-one"
    inst.mkdir(parents=True)
    (inst / "plugin.yaml").write_text("name: installed-one\n", encoding="utf-8")

    pdata_ok = tmp_path / "plugin-data" / "installed-one"
    pdata_ok.mkdir(parents=True)
    (pdata_ok / "state.json").write_bytes(b"{}" * 500)

    pdata_orphan = tmp_path / "plugin-data" / "hermes-achievements"
    pdata_orphan.mkdir(parents=True)
    (pdata_orphan / "state.json").write_bytes(b"a" * 50_000)

    # Regenerable caches > 20 MiB
    hub_cache = tmp_path / "skills" / ".hub" / "index-cache"
    hub_cache.mkdir(parents=True)
    (hub_cache / "hermes-index.json").write_bytes(b"i" * (12 * 1024 * 1024))

    prof_hub = tmp_path / "profiles" / "worker1" / "skills" / ".hub" / "index-cache"
    prof_hub.mkdir(parents=True)
    (prof_hub / "hermes-index.json").write_bytes(b"i" * (4 * 1024 * 1024))

    (tmp_path / "models_dev_cache.json").write_bytes(b"m" * (2 * 1024 * 1024))
    (tmp_path / "provider_models_cache.json").write_bytes(b"p" * 4000)

    img_cache = tmp_path / "image_cache"
    img_cache.mkdir()
    (img_cache / "pic.png").write_bytes(b"g" * 100_000)

    aud_cache = tmp_path / "audio_cache"
    aud_cache.mkdir()
    (aud_cache / "clip.mp3").write_bytes(b"u" * 200_000)

    tool_cache = tmp_path / "tools" / "browser-tool" / "cache"
    tool_cache.mkdir(parents=True)
    (tool_cache / "browser.bin").write_bytes(b"b" * (2 * 1024 * 1024))
    tool_dl = tmp_path / "tools" / "browser-tool" / "dl"
    tool_dl.mkdir(parents=True)
    (tool_dl / "browser.tar.xz").write_bytes(b"t" * (1 * 1024 * 1024))

    # Top-level ELF installer binary hermes-setup vs non-binary hermes-setup.txt
    (tmp_path / "hermes-setup").write_bytes(b"\x7fELF" + b"\x00" * (2 * 1024 * 1024 - 4))
    (tmp_path / "hermes-setup-notes.txt").write_text("plain text notes, not a binary\n", encoding="utf-8")

    res = mod.audit_dead_stores(
        tmp_path,
        enabled_plugins=["installed-one"],
        external_skill_dirs=[],
        pet_enabled=True,
        now=1800000000.0,
    )
    sec = res["dead_stores"]
    assert sec["orphan_plugin_data"]["count"] == 1
    assert sec["orphan_plugin_data"]["total_bytes"] == 50_000
    assert sec["orphan_plugin_data"]["orphans"][0]["path"] == os.path.join(
        os.path.realpath(tmp_path), "plugin-data", "hermes-achievements")

    rc = sec["regenerable_caches"]
    assert rc["hub_index_cache_count"] == 2
    assert rc["hub_index_cache_bytes"] == 16 * 1024 * 1024
    assert rc["models_dev_cache_bytes"] == 2 * 1024 * 1024
    assert rc["provider_models_cache_bytes"] == 4000
    assert rc["image_cache_bytes"] == 100_000
    assert rc["audio_cache_bytes"] == 200_000
    assert rc["tool_cache_bytes"] == 3 * 1024 * 1024
    assert rc["installer_binaries_count"] == 1
    assert rc["installer_binaries_bytes"] == 2 * 1024 * 1024
    assert rc["total_bytes"] > 20 * 1024 * 1024

    ids = {f["id"] for f in res["findings"]}
    assert "dead_stores.orphan_plugin_data" in ids
    assert "dead_stores.regenerable_caches" in ids
    f_orphan = next(f for f in res["findings"] if f["id"] == "dead_stores.orphan_plugin_data")
    assert f_orphan["classification"] == "info"
    f_cache = next(f for f in res["findings"] if f["id"] == "dead_stores.regenerable_caches")
    assert f_cache["classification"] == "info"


def test_growing_piles_locks_clones_and_feature_off_assets(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    now = 1800000000.0

    # 1. Request dumps (> 10)
    sess = tmp_path / "sessions"
    sess.mkdir()
    for i in range(12):
        (sess / f"request_dump_sid{i}_20261001_12000{i}.json").write_bytes(b"e" * 10_000)

    # 2. Unrotated log > 500 KiB vs rotated log > 500 KiB
    dc = tmp_path / "disk-cleanup"
    dc.mkdir()
    (dc / "cleanup.log").write_bytes(b"l" * (600 * 1024))
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "agent.log").write_bytes(b"a" * (1024 * 1024))
    (logs / "agent.log.1").write_bytes(b"a" * (1024 * 1024))

    # 3. Attachments and composer-pastes with oldest year-month
    att = tmp_path / "attachments"
    att.mkdir()
    a_file = att / "doc.pdf"
    a_file.write_bytes(b"p" * 5000)
    # 2026-08-15 UTC = 1786752000
    os.utime(a_file, (1786752000.0, 1786752000.0))

    cp = tmp_path / "composer-pastes"
    cp.mkdir()
    c_file = cp / "pasted_content_1.txt"
    c_file.write_bytes(b"t" * 3000)
    # 2026-09-20 UTC = 1789862400
    os.utime(c_file, (1789862400.0, 1789862400.0))

    # 4. Backup-style files (> 20), including credential-looking names and config backup burst
    cfg_bak_dir = tmp_path / "backups" / "config"
    cfg_bak_dir.mkdir(parents=True)
    for i in range(4):
        bf = cfg_bak_dir / f"config.yaml.good.20261001-23472{i}"
        bf.write_bytes(b"c" * 1000)
        os.utime(bf, (now - 100 + i, now - 100 + i))

    for i in range(16):
        (tmp_path / f"notes_{i}.md.bak").write_bytes(b"n" * 500)
    (tmp_path / ".env.bak-20260903").write_bytes(b"s" * 2000)
    (tmp_path / "auth.json.orig").write_bytes(b"s" * 3000)
    (tmp_path / "slack_tokens.json~").write_bytes(b"s" * 1500)

    # 5. Stale zero-byte locks (> 10 older than 24h) + young lock + non-empty lock
    locks_dir = tmp_path / "locks"
    locks_dir.mkdir()
    for i in range(11):
        lf = locks_dir / f"job_{i}.lock"
        lf.write_bytes(b"")
        os.utime(lf, (now - 90_000, now - 90_000))
    young = locks_dir / "fresh.lock"
    young.write_bytes(b"")
    os.utime(young, (now - 3600, now - 3600))
    nonempty = locks_dir / "held.lock"
    nonempty.write_bytes(b"12345")
    os.utime(nonempty, (now - 90_000, now - 90_000))
    # Lock age is measured against the newest mtime in the home, not the wall clock.
    newest = tmp_path / "newest.txt"
    newest.write_bytes(b"n")
    os.utime(newest, (now, now))

    # 6. Unreferenced skill clones under vendor-skills/
    vs_unref = tmp_path / "vendor-skills" / "unreferenced-repo"
    vs_unref.mkdir(parents=True)
    (vs_unref / "SKILL.md").write_bytes(b"v" * 25_000)
    vs_ref = tmp_path / "vendor-skills" / "referenced-repo"
    vs_ref.mkdir(parents=True)
    (vs_ref / "SKILL.md").write_bytes(b"v" * 15_000)

    # 7. Feature-off assets (pets/ when pet_enabled=False)
    pets = tmp_path / "pets" / "sample-pet"
    pets.mkdir(parents=True)
    (pets / "sprite.png").write_bytes(b"x" * 40_000)

    res = mod.audit_dead_stores(
        tmp_path,
        enabled_plugins=[],
        external_skill_dirs=[str(vs_ref)],
        pet_enabled=False,
        now=now,
    )
    sec = res["dead_stores"]
    gp = sec["growing_piles"]
    assert gp["request_dumps"] == {"count": 12, "bytes": 120_000}
    assert gp["unrotated_logs"]["count"] == 1
    assert gp["unrotated_logs"]["bytes"] == 600 * 1024
    # Oldest month as integers: a "YYYY-MM" string is not a sealed vocabulary value.
    assert gp["attachments"] == {"count": 1, "bytes": 5000, "oldest_year": 2026, "oldest_month": 8}
    assert gp["composer_pastes"] == {"count": 1, "bytes": 3000, "oldest_year": 2026, "oldest_month": 9}

    bf_info = gp["backup_files"]
    assert bf_info["count"] == 23
    assert bf_info["cred_named_count"] == 3
    assert bf_info["cred_named_bytes"] == 6500
    assert bf_info["config_backup_count"] == 4
    assert bf_info["config_backup_burst_count"] == 4

    assert sec["stale_locks"]["count"] == 11
    assert sec["unreferenced_skill_clones"]["count"] == 1
    assert sec["unreferenced_skill_clones"]["total_bytes"] == 25_000
    assert sec["feature_off_assets"]["total_bytes"] == 40_000

    ids = {f["id"] for f in res["findings"]}
    assert {
        "dead_stores.request_dumps",
        "dead_stores.unrotated_logs",
        "dead_stores.backup_file_pile",
        "dead_stores.stale_locks",
        "dead_stores.unreferenced_skill_clones",
        "dead_stores.feature_off_assets",
        "dead_stores.summary",
    } <= ids


def test_do_not_flag_normal_cases(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    now = 1800000000.0

    # 1. cron/output (capped at 50 per job by Hermes cron/jobs.py:3323)
    cron_out = tmp_path / "cron" / "output" / "daily-job"
    cron_out.mkdir(parents=True)
    for i in range(50):
        (cron_out / f"2026-10-01_00-00-{i:02d}.md").write_bytes(b"o" * 20_000)

    # 2. Rotated *.log.N files and active agent.log with agent.log.1 sibling
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "agent.log").write_bytes(b"a" * (2 * 1024 * 1024))
    (logs / "agent.log.1").write_bytes(b"a" * (5 * 1024 * 1024))
    (logs / "agent.log.2").write_bytes(b"a" * (5 * 1024 * 1024))

    # 3. .lock files younger than 24 h
    for i in range(15):
        lf = tmp_path / f"recent_{i}.lock"
        lf.write_bytes(b"")
        os.utime(lf, (now - 1000, now - 1000))

    # 4. One bin/ with tool binaries
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "rg").write_bytes(b"\x7fELF" + b"b" * (5 * 1024 * 1024))

    # 5. A single config backup
    cfg_bak = tmp_path / "backups" / "config"
    cfg_bak.mkdir(parents=True)
    (cfg_bak / "config.yaml.good.20261001-120000").write_bytes(b"c" * 5000)

    # 6. models_dev_cache.json alone under 20 MiB
    (tmp_path / "models_dev_cache.json").write_bytes(b"m" * (5 * 1024 * 1024))

    # 7. Enabled plugins that are BUNDLED with Hermes (no folder in profile)
    res = mod.audit_dead_stores(
        tmp_path,
        enabled_plugins=["disk-cleanup", "security-guidance", "a2a-platform", "platforms/discord", "web/tavily"],
        external_skill_dirs=[],
        pet_enabled=True,
        now=now,
    )
    assert res["coverage"] == "verified"
    ids = {f["id"] for f in res["findings"]}
    # Only dead_stores.summary (info) may appear; no warning or review_suggested or specific rule flags
    assert ids <= {"dead_stores.summary"}
    for f in res["findings"]:
        assert f["classification"] == "info"


def test_none_parameters_report_could_not_verify(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    (tmp_path / "config.yaml").write_text("{}\n", encoding="utf-8")
    (tmp_path / "pets").mkdir()
    (tmp_path / "pets" / "cat.png").write_bytes(b"p" * 1000)
    (tmp_path / "vendor-skills" / "some-repo").mkdir(parents=True)
    (tmp_path / "vendor-skills" / "some-repo" / "SKILL.md").write_bytes(b"s" * 1000)

    res = mod.audit_dead_stores(
        tmp_path,
        enabled_plugins=None,
        external_skill_dirs=None,
        pet_enabled=None,
        now=1800000000.0,
    )
    assert res["coverage"] == "could_not_verify"
    sec = res["dead_stores"]
    assert sec["coverage"] == "could_not_verify"
    assert sec["plugins"]["coverage"] == "could_not_verify"
    assert sec["unreferenced_skill_clones"]["coverage"] == "could_not_verify"
    assert sec["feature_off_assets"]["coverage"] == "could_not_verify"
    ids = {f["id"] for f in res["findings"]}
    assert "dead_stores.could_not_verify" in ids
    assert "dead_stores.feature_off_assets" not in ids
    assert "dead_stores.unreferenced_skill_clones" not in ids


def test_caps_and_truncation_paths(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.dead_stores")
    for i in range(10):
        (tmp_path / f"f_{i}.txt").write_bytes(b"x" * 100)

    # 1. Entry budget cap
    monkeypatch.setattr(mod, "MAX_ENTRIES", 4)
    res_entries = mod.audit_dead_stores(
        tmp_path, enabled_plugins=[], external_skill_dirs=[], pet_enabled=False, now=1800000000.0
    )
    assert res_entries["coverage"] == "could_not_verify"
    assert res_entries["dead_stores"]["truncated_by"] == "entry_budget"
    assert res_entries["dead_stores"]["limits"]["cuts"] >= 1
    assert "dead_stores.could_not_verify" in {f["id"] for f in res_entries["findings"]}
    monkeypatch.undo()

    # 2. Time budget cap via injectable clock
    ticks = iter([0.0, 0.1, 25.0, 26.0, 27.0])
    res_time = mod.audit_dead_stores(
        tmp_path,
        enabled_plugins=[],
        external_skill_dirs=[],
        pet_enabled=False,
        now=1800000000.0,
        clock=lambda: next(ticks, 30.0),
    )
    assert res_time["coverage"] == "could_not_verify"
    assert res_time["dead_stores"]["truncated_by"] == "time_budget"
    assert res_time["dead_stores"]["limits"]["cuts"] >= 1

    # 3. Depth budget cap
    deep = tmp_path / "a" / "b" / "c" / "d"
    deep.mkdir(parents=True)
    (deep / "leaf.txt").write_bytes(b"x")
    monkeypatch.setattr(mod, "MAX_DEPTH", 2)
    res_depth = mod.audit_dead_stores(
        tmp_path, enabled_plugins=[], external_skill_dirs=[], pet_enabled=False, now=1800000000.0
    )
    assert res_depth["coverage"] == "could_not_verify"
    assert res_depth["dead_stores"]["truncated_by"] == "depth_budget"
    monkeypatch.undo()

    # 4. Metadata byte cap (oversized plugin.yaml on disabled plugin)
    pdir = tmp_path / "plugins" / "huge-manifest"
    pdir.mkdir(parents=True)
    (pdir / "plugin.yaml").write_bytes(b"# " + b"x" * (300 * 1024))
    res_mbytes = mod.audit_dead_stores(
        tmp_path, enabled_plugins=[], external_skill_dirs=[], pet_enabled=False, now=1800000000.0
    )
    assert res_mbytes["coverage"] == "could_not_verify"
    assert res_mbytes["dead_stores"]["truncated_by"] == "metadata_byte_budget"

    # 5. Metadata read count cap
    (pdir / "plugin.yaml").write_text("name: huge-manifest\n", encoding="utf-8")
    monkeypatch.setattr(mod, "MAX_METADATA_READS", 0)
    res_mreads = mod.audit_dead_stores(
        tmp_path, enabled_plugins=[], external_skill_dirs=[], pet_enabled=False, now=1800000000.0
    )
    assert res_mreads["coverage"] == "could_not_verify"
    assert res_mreads["dead_stores"]["truncated_by"] == "metadata_read_budget"
    monkeypatch.undo()


def test_symlink_refusal(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret_archive.tar.gz").write_bytes(b"s" * (60 * 1024 * 1024))

    home = tmp_path / "home"
    home.mkdir()
    (home / "config.yaml").write_text("{}\n", encoding="utf-8")
    exports = home / "profile-exports"
    exports.mkdir()
    (exports / "linked_export.tar.gz").symlink_to(outside / "secret_archive.tar.gz")
    (home / "plugins").mkdir()
    (home / "plugins" / "linked-plugin").symlink_to(outside)

    # Also a symlinked profile root itself
    linked_root = tmp_path / "linked_home"
    linked_root.symlink_to(home)
    res_root = mod.audit_dead_stores(
        linked_root, enabled_plugins=[], external_skill_dirs=[], pet_enabled=False, now=1800000000.0
    )
    assert res_root["coverage"] == "could_not_verify"
    assert res_root["dead_stores"]["status"] == "not_measured"
    assert res_root["dead_stores"]["reason"] == "symlink_root"

    # Inside home, symlinks are skipped and never followed
    res = mod.audit_dead_stores(
        home, enabled_plugins=[], external_skill_dirs=[], pet_enabled=False, now=1800000000.0
    )
    sec = res["dead_stores"]
    assert sec["exports_and_archives"]["profile_exports_bytes"] == 0
    assert sec["limits"]["symlinks_skipped"] >= 2


def test_credential_files_never_opened_and_home_unchanged(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.dead_stores")
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-secret\n", encoding="utf-8")
    (tmp_path / ".env.bak-20261001").write_text("OPENAI_API_KEY=sk-old\n", encoding="utf-8")
    (tmp_path / "auth.json").write_text('{"token": "secret"}\n', encoding="utf-8")
    (tmp_path / "auth.json.bak").write_text('{"token": "old"}\n', encoding="utf-8")
    (tmp_path / "hermes-setup-token.key").write_bytes(b"\x7fELF" + b"secret")
    for sub in ("mcp-tokens", "pairing", "vault"):
        d = tmp_path / sub
        d.mkdir()
        (d / "secret.bak").write_text("secret", encoding="utf-8")

    pdir = tmp_path / "plugins" / "disabled-one"
    pdir.mkdir(parents=True)
    (pdir / "plugin.yaml").write_text("name: disabled-one\nprovides_hooks:\n  - pre_tool_call\n", encoding="utf-8")

    before_hash = _tree_snapshot(tmp_path)

    opened_paths: list[str] = []
    real_builtins_open = builtins.open
    real_io_open = io.open
    real_os_open = os.open

    def wrap_open(file, *args, **kwargs):
        if not isinstance(file, int):
            opened_paths.append(os.fsdecode(file))
        return real_builtins_open(file, *args, **kwargs)

    def wrap_io_open(file, *args, **kwargs):
        if not isinstance(file, int):
            opened_paths.append(os.fsdecode(file))
        return real_io_open(file, *args, **kwargs)

    def wrap_os_open(path, flags, mode=0o777, *, dir_fd=None):
        opened_paths.append(os.fsdecode(path))
        return real_os_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(builtins, "open", wrap_open)
    monkeypatch.setattr(io, "open", wrap_io_open)
    monkeypatch.setattr(os, "open", wrap_os_open)

    res = mod.audit_dead_stores(
        tmp_path, enabled_plugins=[], external_skill_dirs=[], pet_enabled=False, now=1800000000.0
    )
    monkeypatch.undo()

    after_hash = _tree_snapshot(tmp_path)
    assert before_hash == after_hash

    for p in opened_paths:
        low = p.lower()
        assert not any(
            bad in low for bad in (".env", "auth.json", "token", "secret", "vault", "pairing", ".key", ".pem")
        ), f"Credential path was opened: {p}"
    assert res["dead_stores"]["growing_piles"]["backup_files"]["cred_named_count"] >= 2


def test_canary_privacy_and_missing_empty_malformed_inputs(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")

    # 1. Missing home
    res_missing = mod.audit_dead_stores(tmp_path / "does_not_exist")
    assert res_missing["coverage"] == "could_not_verify"
    assert res_missing["dead_stores"]["status"] == "not_measured"
    assert res_missing["dead_stores"]["reason"] == "missing"

    # 2. Empty home
    empty_home = tmp_path / "empty_home"
    empty_home.mkdir()
    res_empty = mod.audit_dead_stores(empty_home)
    assert res_empty["dead_stores"]["status"] == "not_measured"
    assert res_empty["dead_stores"]["reason"] == "empty_home"

    # 3. Canary privacy + malformed inputs
    home = tmp_path / "canary_home"
    home.mkdir()
    mem = home / "memories"
    mem.mkdir()
    (mem / "MEMORY.md").write_text("CANARY_MEMORY_TEXT_SECRET_881\n", encoding="utf-8")

    sess = home / "sessions"
    sess.mkdir()
    (sess / "request_dump_CANARY_SESSION_ID_882_20261001.json").write_text(
        '{"prompt": "CANARY_PROMPT_883"}', encoding="utf-8"
    )

    deep_log = home / "plans" / "work" / "CANARY_DEEP_PATH_884" / "sub"
    deep_log.mkdir(parents=True)
    (deep_log / "CANARY_FILE_885.log").write_bytes(b"CANARY_LOG_CONTENT_886\n" * 30_000)

    bad_plugin = home / "plugins" / "broken-plugin"
    bad_plugin.mkdir(parents=True)
    (bad_plugin / "plugin.yaml").write_bytes(b"\xff\xfe:\x00:bad yaml CANARY_YAML_887 [[[")

    res_canary = mod.audit_dead_stores(
        home,
        enabled_plugins="not-a-list",  # type: ignore[arg-type]
        external_skill_dirs=12345,  # type: ignore[arg-type]
        pet_enabled="not-a-bool",  # type: ignore[arg-type]
        now="not-a-timestamp",  # type: ignore[arg-type]
    )
    dumped = json.dumps(res_canary)
    assert "CANARY" not in dumped
    assert res_canary["coverage"] == "could_not_verify"


_KIB = 1024
_MIB = 1024 * 1024


def _run(mod, home: Path, **kw):
    kw.setdefault("enabled_plugins", [])
    kw.setdefault("external_skill_dirs", [])
    kw.setdefault("pet_enabled", True)
    return mod.audit_dead_stores(home, **kw)


def test_unrotated_logs_limited_to_hermes_log_locations(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    logs = tmp_path / "logs"
    logs.mkdir()
    # Appended without rotation by Hermes: counted.
    (logs / "mcp-stderr.log").write_bytes(b"m" * (600 * _KIB))  # tools/mcp_tool_config.py:39
    (logs / "update.log").write_bytes(b"u" * (700 * _KIB))  # hermes_cli/main_dashboard.py:546
    # Rotation-managed by Hermes (below their cap no sibling exists yet): not counted.
    (logs / "gui.log").write_bytes(b"g" * (2 * _MIB))
    (logs / "desktop.log").write_bytes(b"d" * (1 * _MIB))
    (logs / "errors.log").write_bytes(b"e" * (1 * _MIB))
    prof_logs = tmp_path / "profiles" / "worker" / "logs"
    prof_logs.mkdir(parents=True)
    (prof_logs / "agent.log").write_bytes(b"a" * (1 * _MIB))
    (prof_logs / "mcp-stderr.log").write_bytes(b"m" * (800 * _KIB))  # counted
    (tmp_path / "disk-cleanup").mkdir()
    (tmp_path / "disk-cleanup" / "cleanup.log").write_bytes(b"c" * (900 * _KIB))  # counted
    plug = tmp_path / "plugins" / "noisy" / "state"
    plug.mkdir(parents=True)
    (plug / "run.log").write_bytes(b"r" * (550 * _KIB))  # plugin log under plugin folder: counted
    # Work output outside Hermes log locations: not counted, only tallied as out of scope.
    work = tmp_path / "plans" / "work-a" / "deep"
    work.mkdir(parents=True)
    (work / "trace.log").write_bytes(b"w" * (3 * _MIB))
    (tmp_path / "tmp").mkdir()
    (tmp_path / "tmp" / "build.log").write_bytes(b"t" * (600 * _KIB))

    res = _run(mod, tmp_path)
    ul = res["dead_stores"]["growing_piles"]["unrotated_logs"]
    assert ul["count"] == 5
    assert ul["bytes"] == (600 + 700 + 800 + 900 + 550) * _KIB
    # Files are reported by fixed location label, never by a name taken from disk.
    assert sorted((f["log_location"], f["in_named_profile"], f["bytes"]) for f in ul["files"]) == sorted([
        ("logs_folder", False, 600 * _KIB), ("logs_folder", False, 700 * _KIB),
        ("logs_folder", True, 800 * _KIB), ("disk_cleanup_log", False, 900 * _KIB),
        ("plugin_folder", False, 550 * _KIB),
    ])
    assert all(set(f) == {"log_location", "in_named_profile", "bytes"} for f in ul["files"])
    assert ul["rotation_managed_skipped_count"] == 4
    assert ul["outside_hermes_log_locations_count"] == 2
    assert ul["outside_hermes_log_locations_bytes"] == 3 * _MIB + 600 * _KIB
    assert res["dead_stores"]["dead_weight_by_class"]["unrotated_logs"] == ul["bytes"]


def test_enabled_plugin_symlinked_left_core_and_review_classification(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    outside = tmp_path / "outside-plugin"
    outside.mkdir()
    (outside / "plugin.yaml").write_text("name: linked\n", encoding="utf-8")
    home = tmp_path / "home"
    (home / "plugins").mkdir(parents=True)
    (home / "plugins" / "linked").symlink_to(outside, target_is_directory=True)
    (home / "plugin-data" / "linked").mkdir(parents=True)
    (home / "plugin-data" / "linked" / "s.json").write_bytes(b"{}")
    (home / "plugin-data" / "gone").mkdir(parents=True)
    (home / "plugin-data" / "gone" / "s.json").write_bytes(b"{}")

    res = _run(mod, home, enabled_plugins=["linked", "langfuse", "gone", "disk-cleanup", "a2a-platform"])
    p = res["dead_stores"]["plugins"]
    assert p["enabled_missing"] == [{"reason": "no_folder", "path": None}]
    assert "enabled_symlinked" not in p  # count only: a symlink path would resolve outside the home
    assert p["enabled_symlinked_count"] == 1
    assert p["enabled_moved_out_of_core"] == ["langfuse"]
    assert p["enabled_moved_out_of_core_count"] == 1
    f = next(f for f in res["findings"] if f["id"] == "dead_stores.enabled_plugin_missing")
    assert f["classification"] == "review_suggested"
    assert f["evidence"]["missing_count"] == 1
    assert f["evidence"]["symlinked_count"] == 1
    # plugin-data of an enabled name (even one with no folder) or of a symlinked plugin is not orphaned.
    assert res["dead_stores"]["orphan_plugin_data"]["count"] == 0
    assert not any(f["classification"] == "warning" for f in res["findings"])


def test_only_symlinked_enabled_plugin_emits_no_missing_finding(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    target = tmp_path / "t"
    target.mkdir()
    home = tmp_path / "home"
    (home / "plugins").mkdir(parents=True)
    (home / "plugins" / "linked-tool").symlink_to(target, target_is_directory=True)
    res = _run(mod, home, enabled_plugins=["linked-tool"])
    assert "dead_stores.enabled_plugin_missing" not in {f["id"] for f in res["findings"]}
    assert res["dead_stores"]["plugins"]["enabled_symlinked_count"] == 1


# Bundled by newer Hermes sources, not by the v0.23.1 release (checked against its tree).
_BUNDLED_IN_SOME_RELEASES_ONLY = frozenset({"platforms/yuanbao", "yuanbao-platform"})


def test_bundled_names_match_hermes_source_tree() -> None:
    mod = load_submodule("audit.dead_stores")
    try:
        import hermes_cli  # noqa: PLC0415  (on PYTHONPATH in the runner)
    except ImportError:
        pytest.skip("Hermes source tree not importable")
    src = Path(hermes_cli.__file__).resolve().parent.parent / "plugins"
    if not src.is_dir():
        pytest.skip("bundled plugins dir not found")
    keys: set[str] = set()
    names: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".git", "tests", "node_modules")]
        rel = Path(dirpath).relative_to(src).as_posix()
        if "plugin.yaml" in filenames or "plugin.yml" in filenames:
            keys.add(rel)
            fn = "plugin.yaml" if "plugin.yaml" in filenames else "plugin.yml"
            m = re.search(r"(?m)^name:\s*['\"]?([^'\"\n#]+?)['\"]?\s*$",
                          (Path(dirpath) / fn).read_text(encoding="utf-8", errors="replace"))
            if m:
                names.add(m.group(1).strip())
        if Path(dirpath).name == "dashboard" and "manifest.json" in filenames:
            keys.add(Path(rel).parent.as_posix())
    bundled = keys | names
    # The list covers every supported Hermes release, so it may hold names that only some
    # releases bundle: nothing the running source bundles may be missing, and any extra
    # must be one of these known, version-dependent names (a stale or misspelt one fails).
    assert bundled - set(mod.BUNDLED_PLUGIN_NAMES) == set()
    assert set(mod.BUNDLED_PLUGIN_NAMES) - bundled <= _BUNDLED_IN_SOME_RELEASES_ONLY


def test_stale_locks_relative_to_newest_mtime_and_deterministic(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    t_newest = 1790000000.0
    newest = tmp_path / "state.txt"
    newest.write_bytes(b"s")
    os.utime(newest, (t_newest, t_newest))
    ld = tmp_path / "locks"
    ld.mkdir()
    for i in range(12):
        lf = ld / f"old_{i}.lock"
        lf.write_bytes(b"")
        os.utime(lf, (t_newest - 2 * 86_400, t_newest - 2 * 86_400))
    for i in range(3):
        lf = ld / f"recent_{i}.lock"
        lf.write_bytes(b"")
        os.utime(lf, (t_newest - 3600, t_newest - 3600))
    ticks_a = iter(x * 0.001 for x in range(100_000))
    ticks_b = iter(x * 0.37 for x in range(100_000))
    res_a = _run(mod, tmp_path, now=t_newest + 1.0, clock=lambda: next(ticks_a))
    res_b = _run(mod, tmp_path, now=t_newest + 40 * 86_400.0, clock=lambda: next(ticks_b))
    res_c = _run(mod, tmp_path)  # no now at all
    for r in (res_a, res_b, res_c):
        sl = r["dead_stores"]["stale_locks"]
        assert sl["count"] == 12
        assert sl["reference"] == "newest_mtime_in_home"
        assert sl["coverage"] == "verified"
    # run_metrics is a top-level sibling of the section, never inside it (digest safety).
    for r in (res_a, res_b, res_c):
        assert "run_metrics" not in r["dead_stores"]
    assert res_a["run_metrics"]["stale_locks_vs_now_count"] == 12
    assert res_b["run_metrics"]["stale_locks_vs_now_count"] == 15
    assert res_c["run_metrics"]["stale_locks_vs_now_count"] is None
    dump = lambda r: json.dumps(r["dead_stores"], sort_keys=True)
    assert dump(res_a) == dump(res_b) == dump(res_c)
    assert json.dumps(res_a["findings"], sort_keys=True) == json.dumps(res_b["findings"], sort_keys=True)
    assert json.dumps(res_a["findings"], sort_keys=True) == json.dumps(res_c["findings"], sort_keys=True)


def test_overlap_note_and_tool_cache_label(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    tc = tmp_path / "tools" / "sometool" / "cache"
    tc.mkdir(parents=True)
    (tc / "blob.bin").write_bytes(b"b" * (21 * _MIB))
    res = _run(mod, tmp_path)
    sec = res["dead_stores"]
    assert sec["overlaps_other_sections"] is True
    rc = sec["regenerable_caches"]
    assert rc["tool_cache_bytes"] == 21 * _MIB
    assert rc["tool_cache_label"] == "cache_in_work_folder"
    summary = next(f for f in res["findings"] if f["id"] == "dead_stores.summary")
    assert "must not be added" in summary["consequence"]
    empty = mod.audit_dead_stores(tmp_path / "nope")
    assert empty["dead_stores"]["overlaps_other_sections"] is True


def test_request_dumps_only_counted_in_sessions(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    (tmp_path / "sessions").mkdir()
    (tmp_path / "profiles" / "w" / "sessions").mkdir(parents=True)
    for i in range(6):
        (tmp_path / "sessions" / f"request_dump_s{i}_20261001_120000_000001.json").write_bytes(b"x" * 10)
        (tmp_path / "profiles" / "w" / "sessions" / f"request_dump_p{i}_20261001_120000_000001.json").write_bytes(b"x" * 10)
    (tmp_path / "plans").mkdir()
    for i in range(20):
        (tmp_path / "plans" / f"request_dump_copy{i}.json").write_bytes(b"x" * 10)
    res = _run(mod, tmp_path)
    assert res["dead_stores"]["growing_piles"]["request_dumps"] == {"count": 12, "bytes": 120}


def test_credential_named_backups_counted_by_name_only(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.dead_stores")
    cred_names = [".env.bak-CANARYENV1", "auth.json.bak", "slack_token.json.orig", "id_ed25519.bak",
                  "secrets.yaml.bak", "credentials.json~"]
    for d in (tmp_path, tmp_path / "profiles" / "p1", tmp_path / "plugins" / "x"):
        d.mkdir(parents=True, exist_ok=True)
        for n in cred_names:
            (d / n).write_bytes(b"CANARY_SECRET_VALUE_991")
    (tmp_path / "mcp-tokens").mkdir()
    (tmp_path / "mcp-tokens" / "x.json.bak").write_bytes(b"CANARY_SECRET_VALUE_991")
    (tmp_path / "hermes-setup.bak").write_bytes(b"\x7fELF")
    opened: list[str] = []
    ro, rio, roo = builtins.open, io.open, os.open
    monkeypatch.setattr(builtins, "open", lambda f, *a, **k: (opened.append(os.fsdecode(f)), ro(f, *a, **k))[1])
    monkeypatch.setattr(io, "open", lambda f, *a, **k: (opened.append(os.fsdecode(f)), rio(f, *a, **k))[1])
    monkeypatch.setattr(os, "open", lambda p, fl, m=0o777, *, dir_fd=None: (opened.append(os.fsdecode(p)), roo(p, fl, m, dir_fd=dir_fd))[1])
    res = _run(mod, tmp_path)
    monkeypatch.undo()
    names_lower = [n.lower() for n in cred_names] + ["x.json.bak"]
    assert not [p for p in opened if Path(p).name.lower() in names_lower]
    # Only directory descriptors (root, no file below a credential tree) may have been opened.
    assert all(Path(p).name not in cred_names for p in opened)
    bf = res["dead_stores"]["growing_piles"]["backup_files"]
    assert bf["cred_named_count"] >= 18
    dumped = json.dumps(res)
    assert "CANARY" not in dumped
    for n in cred_names:
        assert n not in dumped


def test_hostile_tree_readonly_dirs_loops_fifo_and_bad_names(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    home = tmp_path / "home"
    (home / "logs").mkdir(parents=True)
    (home / "logs" / "mcp-stderr.log").write_bytes(b"m" * (600 * _KIB))
    (home / "loop").symlink_to(home / "loop")
    (home / "up").symlink_to(tmp_path, target_is_directory=True)
    os.mkfifo(home / "pipe.lock")
    os.mkfifo(home / "hermes-setup")
    (home / "plugins").mkdir()
    (home / "plugins" / "zero").mkdir()
    (home / "plugins" / "zero" / "plugin.yaml").write_bytes(b"")
    try:
        (home / os.fsdecode(b"bad\xffname.bak")).write_bytes(b"x")
    except (OSError, UnicodeError):
        pass
    (tmp_path / "zzexternal.log").write_bytes(b"o" * (900 * _KIB))
    before = _tree_snapshot(home)
    dirs = [Path(dp) for dp, _dn, _fn in os.walk(home)]
    for d in dirs:
        os.chmod(d, 0o555)
    try:
        res = _run(mod, home, enabled_plugins=["zero"])
    finally:
        for d in dirs:
            os.chmod(d, 0o755)
    assert _tree_snapshot(home) == before
    sec = res["dead_stores"]
    assert sec["status"] == "completed"
    assert sec["growing_piles"]["unrotated_logs"]["count"] == 1
    assert sec["limits"]["symlinks_skipped"] >= 2
    assert sec["regenerable_caches"]["installer_binaries_count"] == 0
    assert "zzexternal" not in json.dumps(res)
    assert str(tmp_path) not in json.dumps(res)


_BANNED_WORDS = re.compile(r"(?i)\b(?:you|your|indicates?|suggests?|unpruned|abandoned)\b")


def test_consequences_are_fixed_measurement_sentences() -> None:
    mod = load_submodule("audit.dead_stores")
    for rule_id, sentence in mod.FINDING_CONSEQUENCES.items():
        assert rule_id.startswith("dead_stores.")
        assert "{" not in sentence and "%" not in sentence, rule_id
        assert not _BANNED_WORDS.search(sentence), rule_id
        assert sentence.endswith("."), rule_id


def test_name_patterns_not_in_hermes_source_are_labelled(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    parked = tmp_path / "plugins" / "sample.parked-20260101"
    parked.mkdir(parents=True)
    (parked / "plugin.yaml").write_text("name: sample\n", encoding="utf-8")
    for i in range(21):
        (tmp_path / f"note_{i}.md.bak").write_bytes(b"n")
    res = _run(mod, tmp_path)
    sec = res["dead_stores"]
    label = mod.NAME_PATTERN_LABEL
    assert label == "name_pattern_not_in_hermes_source"
    assert sec["plugins"]["parked_name_label"] == label
    assert sec["growing_piles"]["backup_files"]["name_pattern_label"] == label
    by_id = {f["id"]: f for f in res["findings"]}
    for rid in ("dead_stores.parked_or_disabled_plugins", "dead_stores.backup_file_pile"):
        assert by_id[rid]["evidence"]["name_pattern_label"] == label
        assert "not defined by the Hermes source" in by_id[rid]["consequence"]
    empty = mod.audit_dead_stores(tmp_path / "nope")["dead_stores"]
    assert empty["plugins"]["parked_name_label"] == label
    assert empty["growing_piles"]["backup_files"]["name_pattern_label"] == label


_ENVELOPE_KEYS = {"dead_stores", "findings", "run_metrics", "status", "coverage"}


def test_envelope_shape_and_adapter_keeps_run_metrics(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    contract = load_submodule("audit.contract")
    (tmp_path / "x.lock").write_bytes(b"")
    homes = [tmp_path, tmp_path / "missing", tmp_path / "empty"]
    (tmp_path / "empty").mkdir()
    for home in homes:
        env = mod.audit_dead_stores(home, now=1800000000.0)
        assert set(env) == _ENVELOPE_KEYS
        assert "run_metrics" not in env["dead_stores"]
        assert set(env["run_metrics"]) == {"stale_locks_vs_now_count"}
        adapted = contract.adapt_component_result(env, component_id="dead_stores", affected_identities=["default"])
        assert adapted["dead_stores"] == env["dead_stores"]
        assert adapted["run_metrics"] == env["run_metrics"]
        assert adapted["coverage"] == env["coverage"]
        assert adapted["operational_error"] is None
        assert [f["id"] for f in adapted["findings"]] == [f["id"] for f in env["findings"]]


def test_two_runs_days_apart_are_byte_identical(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "update.log").write_bytes(b"u" * (600 * _KIB))
    for i in range(12):
        lf = tmp_path / f"l{i}.lock"
        lf.write_bytes(b"")
        os.utime(lf, (1789990000.0, 1789990000.0))  # fresh vs run A's now, stale vs run B's now
    (tmp_path / "attachments").mkdir()
    (tmp_path / "attachments" / "a.txt").write_bytes(b"a")
    os.utime(tmp_path / "attachments" / "a.txt", (1790000000.0, 1790000000.0))
    a = mod.audit_dead_stores(tmp_path, now=1790000000.0)
    b = mod.audit_dead_stores(tmp_path, now=1790000000.0 + 9 * 86_400)
    assert json.dumps(a["dead_stores"], sort_keys=True) == json.dumps(b["dead_stores"], sort_keys=True)
    assert json.dumps(a["findings"], sort_keys=True) == json.dumps(b["findings"], sort_keys=True)
    assert a["run_metrics"] != b["run_metrics"]  # the wall-clock count lives outside the section


def _cfg(home: Path, text: str) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(text, encoding="utf-8")


def test_reads_its_own_config_when_kwargs_omitted(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    home = tmp_path / "home"
    _cfg(home, (
        "plugins:\n  enabled:\n    - kept\n    - dropped\n    - gone\n  disabled:\n    - dropped\n"
        "skills:\n  external_dirs:\n    - vendor-skills/ref\n"
        "display:\n  pet:\n    enabled: false\n"
    ))
    for name in ("kept", "dropped"):
        (home / "plugins" / name).mkdir(parents=True)
        (home / "plugins" / name / "plugin.yaml").write_text(f"name: {name}\n", encoding="utf-8")
    for repo in ("ref", "unref"):
        (home / "vendor-skills" / repo).mkdir(parents=True)
        (home / "vendor-skills" / repo / "SKILL.md").write_bytes(b"s" * 100)
    (home / "pets" / "p").mkdir(parents=True)
    (home / "pets" / "p" / "s.png").write_bytes(b"x" * 10)
    res = mod.audit_dead_stores(home)
    sec = res["dead_stores"]
    assert sec["unverified_checks"] == []
    assert res["coverage"] == "verified"
    assert sec["plugins"]["enabled_missing"] == [{"reason": "no_folder", "path": None}]
    assert [d["path"] for d in sec["plugins"]["disabled_on_disk"]] == [
        os.path.join(os.path.realpath(home), "plugins", "dropped")]
    assert sec["unreferenced_skill_clones"]["count"] == 1
    assert sec["feature_off_assets"]["pet_enabled"] is False
    assert sec["feature_off_assets"]["total_bytes"] == 10
    # Explicit keyword arguments still win over the file.
    res2 = mod.audit_dead_stores(home, enabled_plugins=["kept", "dropped"], disabled_plugins=[], pet_enabled=True)
    assert res2["dead_stores"]["plugins"]["enabled_missing"] == []
    assert res2["dead_stores"]["plugins"]["disabled_on_disk"] == []
    assert res2["dead_stores"]["feature_off_assets"]["pet_enabled"] is True


def test_missing_config_means_hermes_defaults(tmp_path: Path) -> None:
    mod = load_submodule("audit.dead_stores")
    (tmp_path / "pets" / "p").mkdir(parents=True)
    (tmp_path / "pets" / "p" / "s.png").write_bytes(b"x" * 10)
    res = mod.audit_dead_stores(tmp_path)
    sec = res["dead_stores"]
    assert sec["unverified_checks"] == []
    assert sec["feature_off_assets"]["pet_enabled"] is False  # display.pet.enabled defaults to False
    assert sec["plugins"]["coverage"] == "verified"
    assert sec["unreferenced_skill_clones"]["coverage"] == "verified"


@pytest.mark.parametrize("text, expect", [
    ("plugins: [unclosed\n", {"config_unreadable", "enabled_plugins", "external_skill_dirs", "pet_enabled"}),
    ("plugins:\n  enabled: 7\n", {"enabled_plugins"}),
    ("plugins:\n  disabled: oops\n", {"enabled_plugins"}),
    ("skills:\n  external_dirs:\n    - ${SHARED}/skills\n", {"external_skill_dirs"}),
    ("display:\n  pet:\n    enabled: 'yes'\n", {"pet_enabled"}),
    ("display: 3\n", {"pet_enabled"}),
    ("a: 1\na: 2\n", {"config_unreadable", "enabled_plugins", "external_skill_dirs", "pet_enabled"}),
])
def test_unusable_config_values_are_unverified(tmp_path: Path, text: str, expect: set) -> None:
    mod = load_submodule("audit.dead_stores")
    _cfg(tmp_path, text)
    res = mod.audit_dead_stores(tmp_path)
    assert set(res["dead_stores"]["unverified_checks"]) == expect
    assert res["coverage"] == "could_not_verify"


def test_oversized_config_and_managed_overlay_are_unverified(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.dead_stores")
    home = tmp_path / "home"
    _cfg(home, "# " + "x" * (mod.MAX_CONFIG_BYTES + 10) + "\n")
    assert "config_unreadable" in mod.audit_dead_stores(home)["dead_stores"]["unverified_checks"]
    _cfg(home, "plugins:\n  enabled: []\n")
    managed = tmp_path / "managed"
    managed.mkdir()
    res = mod.audit_dead_stores(home, managed_dir=managed)
    assert set(res["dead_stores"]["unverified_checks"]) == {
        "managed_config_overlay", "enabled_plugins", "external_skill_dirs", "pet_enabled"}



# --- Wiring sheet (audit/wiring/dead_stores.json) and sealing ---------------------------------

_WIRING_PATH = Path(__file__).resolve().parent.parent / "audit" / "wiring" / "dead_stores.json"
_FINDING_TEXT_FIELDS = ("consequence", "detail", "limitations")


def _wiring() -> dict:
    return json.loads(_WIRING_PATH.read_text(encoding="utf-8"))


def _rich_home(root: Path, tag: str = "") -> Path:
    """A synthetic home reaching every rule and most branches; ``tag`` is planted in user-controlled input."""
    t = tag
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.yaml").write_text(
        "plugins:\n  enabled:\n"
        f"    - kept{t}\n    - dropped{t}\n    - gone{t}\n    - linked{t}\n    - langfuse\n"
        f"    - empty{t}\n    - nomanifest{t}\n    - disk-cleanup\n"
        f"  disabled:\n    - dropped{t}\n"
        f"skills:\n  external_dirs:\n    - vendor-skills/ref{t}\n"
        f"display:\n  pet:\n    enabled: false\n    slug: pet{t}\n"
        f"note: value{t}\n",
        encoding="utf-8",
    )
    pl = root / "plugins"
    for name, size in ((f"kept{t}", 10), (f"dropped{t}", 6 * _MIB)):
        (pl / name).mkdir(parents=True)
        (pl / name / "plugin.yaml").write_text(f"name: {name}\n", encoding="utf-8")
        (pl / name / "blob.bin").write_bytes(b"k" * size)
    (pl / f"kept{t}" / ".git").mkdir()
    (pl / f"kept{t}" / ".git" / f"obj{t}").write_bytes(b"g" * 100)
    (pl / f"hooks{t}").mkdir()
    (pl / f"hooks{t}" / "plugin.yaml").write_text(
        f"name: hooks{t}\nprovides_hooks:\n  - pre_tool_call\n  - h{t}\n", encoding="utf-8")
    (pl / f"bad{t}").mkdir()
    (pl / f"bad{t}" / "plugin.yaml").write_bytes(b"\xff\xfe [[[ " + t.encode())
    (pl / f"sample{t}.parked-20260101").mkdir()
    (pl / f"sample{t}.parked-20260101" / "plugin.yaml").write_text(f"name: s{t}\n", encoding="utf-8")
    (pl / f"empty{t}").mkdir()
    (pl / f"nomanifest{t}").mkdir()
    (pl / f"nomanifest{t}" / "code.py").write_text(f"# {t}\n", encoding="utf-8")
    (pl / "memory" / f"mem{t}").mkdir(parents=True)
    (pl / "memory" / f"mem{t}" / "plugin.yaml").write_text("name: m\n", encoding="utf-8")
    outside = root.parent / f"outside{t}"
    outside.mkdir(exist_ok=True)
    (pl / f"linked{t}").symlink_to(outside, target_is_directory=True)
    (pl / f"symyaml{t}").mkdir()
    (pl / f"symyaml{t}" / "plugin.yaml").symlink_to(outside / "nope.yaml")
    (pl / f"symyaml{t}" / "x.py").write_text("x", encoding="utf-8")
    dp = root / "desktop-plugins" / f"desk{t}"
    (dp / "node_modules").mkdir(parents=True)
    (dp / "plugin.js").write_text("//\n", encoding="utf-8")
    (dp / "node_modules" / "m.js").write_bytes(b"n" * 50)
    (root / "plugin-data" / f"orphan{t}").mkdir(parents=True)
    (root / "plugin-data" / f"orphan{t}" / f"s{t}.json").write_bytes(b"o" * 70)
    exp = root / "profile-exports"
    exp.mkdir()
    for i in range(3):
        f = exp / f"p{t}{i}.tar.gz"
        f.write_bytes(b"z" * (20 * _MIB))
        os.utime(f, (1790000000.0 + i, 1790000000.0 + i))
    (root / "backups").mkdir()
    (root / "backups" / f"full{t}.zip").write_bytes(b"z" * (11 * _MIB))
    hub = root / "skills" / ".hub" / "index-cache"
    hub.mkdir(parents=True)
    (hub / "hermes-index.json").write_bytes(b"i" * (21 * _MIB))
    (root / "skills" / ".hub" / "audit.log").write_bytes(b"a" * (600 * _KIB))
    (root / "models_dev_cache.json").write_bytes(b"m" * 10)
    (root / "provider_models_cache.json").write_bytes(b"p" * 10)
    for d in ("image_cache", "audio_cache", "document_cache", "video_cache"):
        (root / d).mkdir()
        (root / d / f"f{t}").write_bytes(b"c" * 10)
    (root / "tools" / f"tool{t}" / "cache").mkdir(parents=True)
    (root / "tools" / f"tool{t}" / "cache" / f"c{t}").write_bytes(b"t" * 10)
    (root / "hermes-setup").write_bytes(b"\x7fELF" + b"\x00" * 100)
    sess = root / "sessions"
    sess.mkdir()
    for i in range(11):
        (sess / f"request_dump_{t}{i}_20261001.json").write_text(f'{{"p": "{t}"}}', encoding="utf-8")
    logs = root / "logs"
    logs.mkdir()
    (logs / f"own{t}.log").write_bytes((t or "x").encode() * (600 * _KIB // max(1, len(t or "x")) + 1))
    (logs / "agent.log").write_bytes(b"a" * (600 * _KIB))
    (logs / "update.log").write_bytes(b"u" * (600 * _KIB))
    (logs / "update.log.1").write_bytes(b"u")
    (root / "disk-cleanup").mkdir()
    (root / "disk-cleanup" / "cleanup.log").write_bytes(b"c" * (600 * _KIB))
    (root / "plugin-data" / f"orphan{t}" / "run.log").write_bytes(b"r" * (600 * _KIB))
    (root / "work" / f"w{t}").mkdir(parents=True)
    (root / "work" / f"w{t}" / f"out{t}.log").write_bytes(b"w" * (600 * _KIB))
    prof = root / "profiles" / f"prof{t}"
    (prof / "logs").mkdir(parents=True)
    (prof / "logs" / "mcp-stderr.log").write_bytes(b"m" * (600 * _KIB))
    (root / "profiles" / f"emptyprof{t}").mkdir()
    (root / "profiles" / ".deleted" / f"gone{t}").mkdir(parents=True)
    for d, n in (("attachments", f"a{t}.pdf"), ("composer-pastes", f"c{t}.txt")):
        (root / d).mkdir()
        (root / d / n).write_text(t or "x", encoding="utf-8")
        os.utime(root / d / n, (1786752000.0, 1786752000.0))
    (root / "backups" / "config").mkdir()
    for i in range(4):
        f = root / "backups" / "config" / f"config.yaml.good{t}.2026100{i}"
        f.write_bytes(b"c")
        os.utime(f, (1790000100.0 + i, 1790000100.0 + i))
    for i in range(18):
        (root / f"n{t}{i}.md.bak").write_bytes(b"n")
    (root / f".env.bak-{t}").write_bytes(b"s")
    (root / "locks").mkdir()
    for i in range(11):
        f = root / "locks" / f"l{t}{i}.lock"
        f.write_bytes(b"")
        os.utime(f, (1780000000.0, 1780000000.0))
    (root / "locks" / "held.lock").write_bytes(b"1")
    for repo in (f"ref{t}", f"unref{t}"):
        (root / "vendor-skills" / repo).mkdir(parents=True)
        (root / "vendor-skills" / repo / "SKILL.md").write_text(f"# {t}\n", encoding="utf-8")
    (root / "pets" / f"pet{t}").mkdir(parents=True)
    (root / "pets" / f"pet{t}" / "s.png").write_bytes(b"x" * 10)
    newest = root / "newest.txt"
    newest.write_bytes(b"n")
    os.utime(newest, (1790100000.0, 1790100000.0))
    return root


def _scenario_envelopes(tmp_path: Path, mod, monkeypatch) -> list[dict]:
    envs = [mod.audit_dead_stores(_rich_home(tmp_path / "rich"), now=1790100000.0)]
    envs.append(mod.audit_dead_stores(tmp_path / "rich", enabled_plugins=None, external_skill_dirs=None,
                                      pet_enabled=None))
    envs.append(mod.audit_dead_stores(tmp_path / "missing"))
    (tmp_path / "empty").mkdir()
    envs.append(mod.audit_dead_stores(tmp_path / "empty", enabled_plugins=None))
    (tmp_path / "link").symlink_to(tmp_path / "empty", target_is_directory=True)
    envs.append(mod.audit_dead_stores(tmp_path / "link"))
    (tmp_path / "afile").write_bytes(b"x")
    envs.append(mod.audit_dead_stores(tmp_path / "afile"))
    badcfg = tmp_path / "badcfg"
    _cfg(badcfg, "a: [\n")
    envs.append(mod.audit_dead_stores(badcfg))
    managed = tmp_path / "managed"
    managed.mkdir()
    envs.append(mod.audit_dead_stores(badcfg, managed_dir=managed))
    for attr, value in (("MAX_ENTRIES", 3), ("MAX_DEPTH", 1), ("MAX_METADATA_READS", 0),
                        ("MAX_METADATA_FILE_BYTES", 4)):
        monkeypatch.setattr(mod, attr, value)
        envs.append(mod.audit_dead_stores(tmp_path / "rich"))
        monkeypatch.undo()
    ticks = iter([0.0, 0.1] + [100.0] * 10_000)
    envs.append(mod.audit_dead_stores(tmp_path / "rich", clock=lambda: next(ticks)))
    return envs


def _walk(value, path, on_key, on_str):
    if isinstance(value, dict):
        for k, v in value.items():
            on_key(k, path)
            _walk(v, f"{path}.{k}" if path else k, on_key, on_str)
    elif isinstance(value, list):
        for item in value:
            _walk(item, f"{path}[]", on_key, on_str)
    elif isinstance(value, str):
        on_str(value, path)
    else:
        assert value is None or type(value) in (bool, int, float), (path, type(value))


def _check_envelope(env: dict, w: dict, seen_keys: set, seen_vocab: set) -> None:
    schema, vocab = set(w["schema_keys"]), set(w["vocabulary"])
    free = {f["key"] for f in w["free_strings"]}

    def on_key(k, path):
        assert k in schema, f"key {k!r} at {path!r} missing from schema_keys"
        seen_keys.add(k)

    def on_str(v, path):
        if path in free:
            return
        assert v in vocab, f"string {v!r} at {path!r} is neither vocabulary nor a free_strings key"
        seen_vocab.add(v)

    assert set(env) == {"dead_stores", "findings", "run_metrics", "status", "coverage"}
    assert set(env["run_metrics"]) == set(w["run_metrics_keys"])
    _walk(env["dead_stores"], "", on_key, on_str)
    for f in env["findings"]:
        rid = f["id"]
        assert rid in w["rule_ids"]
        assert f["classification"] in w["classifications"][rid]
        assert f["consequence"] == f["detail"] == w["consequences"][rid]
        assert f["limitations"] == ""
        for ident in f["affected_identities"]:
            assert ident in vocab
            seen_vocab.add(ident)
        for sp in f["source_paths"]:
            assert sp["path"] in vocab
        assert f["severity"] in vocab and f["coverage"] in vocab
        for k, v in f["evidence"].items():
            on_key(k, "evidence")
            if type(v) in (int, float, bool):
                assert k in w["numeric_evidence_keys"], k
            else:
                assert k in w["vocab_evidence_keys"] and v in vocab, (k, v)
                seen_vocab.add(v)


def test_wiring_sheet_is_consistent_with_module() -> None:
    mod = load_submodule("audit.dead_stores")
    w = _wiring()
    assert set(w) == {"section", "entry", "kwargs", "schema_keys", "vocabulary", "numeric_evidence_keys",
                      "vocab_evidence_keys", "rule_ids", "classifications", "consequences", "free_strings",
                      "run_metrics_keys", "notes"}
    assert w["section"] == "dead_stores"
    assert w["entry"] == "audit.dead_stores.audit_dead_stores"
    assert "profile_path" in w["kwargs"]
    for name in ("schema_keys", "vocabulary", "numeric_evidence_keys", "vocab_evidence_keys"):
        assert w[name] == sorted(set(w[name])), name
    assert w["consequences"] == mod.FINDING_CONSEQUENCES
    assert sorted(w["rule_ids"]) == sorted(mod.FINDING_CONSEQUENCES) == sorted(w["classifications"])
    vocab = set(w["vocabulary"])
    fixed = {mod.TOOL_CACHE_LABEL, mod.STALE_LOCK_REFERENCE, mod.NAME_PATTERN_LABEL,
             *mod.LOG_LOCATION_LABELS, *mod.LEFT_CORE_PLUGIN_NAMES}
    assert fixed <= vocab
    assert set(mod.DEAD_WEIGHT_CLASSES) <= set(w["schema_keys"])
    for item in w["free_strings"]:
        assert set(item) == {"key", "what", "example", "why_safe"}
    assert set(w["numeric_evidence_keys"]) | set(w["vocab_evidence_keys"]) <= set(w["schema_keys"])


def test_wiring_sheet_covers_every_emitted_key_and_string(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.dead_stores")
    w = _wiring()
    seen_keys: set = set()
    seen_vocab: set = set()
    envs = _scenario_envelopes(tmp_path, mod, monkeypatch)
    rich_ids = {f["id"] for f in envs[0]["findings"]}
    assert rich_ids == set(w["rule_ids"])  # the rich home reaches all 13 rules
    for env in envs:
        _check_envelope(env, w, seen_keys, seen_vocab)
    # The sheet lists no key that cannot be emitted.
    assert seen_keys | {w["section"]} == set(w["schema_keys"])
    truncations = {e["dead_stores"]["truncated_by"] for e in envs}
    assert {"entry_budget", "depth_budget", "metadata_read_budget", "metadata_byte_budget",
            "time_budget"} <= truncations
    reasons = {e["dead_stores"]["reason"] for e in envs}
    assert {"missing", "symlink_root", "not_directory", "empty_home"} <= reasons


def _patch_sealing_sets(monkeypatch, w: dict):
    ev = load_submodule("audit.evidence")
    per = load_submodule("audit.persistence")
    const = load_submodule("audit.evidence_constants")
    cons = dict(w["consequences"])
    rule_ids = frozenset(w["rule_ids"])
    vocab = ev.VOCABULARY | frozenset(w["vocabulary"]) | rule_ids | frozenset(cons.values())
    monkeypatch.setattr(ev, "SCHEMA_KEYS", ev.SCHEMA_KEYS | frozenset(w["schema_keys"]))
    monkeypatch.setattr(ev, "VOCABULARY", vocab)
    monkeypatch.setattr(per, "VOCABULARY", vocab)
    monkeypatch.setattr(per, "ALLOWED_FINDING_CONSEQUENCES", per.ALLOWED_FINDING_CONSEQUENCES | frozenset(cons.values()))
    monkeypatch.setattr(per, "FINDING_CONSEQUENCES", {**per.FINDING_CONSEQUENCES, **cons})
    monkeypatch.setattr(per, "_EVIDENCE_NUMERIC_KEYS", per._EVIDENCE_NUMERIC_KEYS | frozenset(w["numeric_evidence_keys"]))
    monkeypatch.setattr(per, "_EVIDENCE_VOCAB_KEYS", per._EVIDENCE_VOCAB_KEYS | frozenset(w["vocab_evidence_keys"]))
    monkeypatch.setattr(const, "RULE_IDS", const.RULE_IDS | rule_ids)
    monkeypatch.setattr(const, "FINDING_CONSEQUENCES", {**const.FINDING_CONSEQUENCES, **cons})
    monkeypatch.setattr(const, "ALLOWED_FINDING_CONSEQUENCES",
                        const.ALLOWED_FINDING_CONSEQUENCES | frozenset(cons.values()))
    return ev, per


def _seal(env: dict, ev, per) -> tuple[dict, list, dict]:
    contract = load_submodule("audit.contract")
    adapted = contract.adapt_component_result(env, component_id="dead_stores", affected_identities=["default"])
    assert adapted["run_metrics"] == env["run_metrics"]
    # Report path: store.finalize_run puts the section in the payload and serializes the whole payload.
    sealed_section = ev.serialize_evidence({"dead_stores": adapted["dead_stores"]})["dead_stores"]
    # Findings path: store persists component_dto -> sort_findings -> serialize_evidence.
    safe_comp = per.component_dto(adapted)
    stored = ev.serialize_evidence(contract.sort_findings(safe_comp["findings"]))
    return sealed_section, stored, adapted


def _is_text_token(v) -> bool:
    return (isinstance(v, dict) and set(v) == {"kind", "hmac", "location"} and v["kind"] == "text"
            and re.fullmatch(r"[0-9a-f]{64}", v["hmac"]) is not None
            and v["location"] == {"path": None, "line": None})


def _compare(raw, sealed, path, free, fates):
    if path in free and isinstance(raw, str):
        fates.setdefault(path, set()).add("hashed" if _is_text_token(sealed) else
                                          "kept" if sealed == raw else f"altered:{sealed!r}")
        return
    if isinstance(raw, dict):
        assert isinstance(sealed, dict) and set(sealed) == set(raw), (path, set(raw) ^ set(sealed))
        for k in raw:
            _compare(raw[k], sealed[k], f"{path}.{k}" if path else k, free, fates)
    elif isinstance(raw, list):
        assert isinstance(sealed, list) and len(sealed) == len(raw), path
        for a, b in zip(raw, sealed):
            _compare(a, b, f"{path}[]", free, fates)
    else:
        assert sealed == raw and type(sealed) is type(raw), (path, raw, sealed)


def test_sealing_keeps_every_key_number_label_and_consequence(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.dead_stores")
    w = _wiring()
    envs = _scenario_envelopes(tmp_path, mod, monkeypatch)
    ev, per = _patch_sealing_sets(monkeypatch, w)
    free = {f["key"] for f in w["free_strings"]}
    fates: dict[str, set] = {}
    for env in envs:
        sealed_section, stored, _adapted = _seal(env, ev, per)
        _compare(json.loads(json.dumps(env["dead_stores"])), sealed_section, "", free, fates)
        raw_by_id = {f["id"]: f for f in env["findings"]}
        assert sorted(raw_by_id) == sorted(f["id"] for f in stored)
        for f in stored:
            raw = raw_by_id[f["id"]]
            for k in ("classification", "coverage", "severity", "affected_identities"):
                assert f[k] == raw[k], (f["id"], k)
            assert [sp["path"] for sp in f["source_paths"]] == [sp["path"] for sp in raw["source_paths"]]
            assert f["consequence"] == f["detail"] == w["consequences"][f["id"]]
            ev_out = {k: v for k, v in f["evidence"].items() if k != "source_digest"}
            assert ev_out == raw["evidence"], f["id"]
    # Every free string is an absolute path to an existing item and is kept unchanged by the serializer.
    assert fates == {k: {"kept"} for k in free}


def test_canary_only_under_free_string_keys_and_never_sealed(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.dead_stores")
    w = _wiring()
    canary = "QZCANARY7"
    home = _rich_home(tmp_path / "canary", tag=canary)
    env = mod.audit_dead_stores(home, now=1790100000.0)
    free = {f["key"] for f in w["free_strings"]}
    hits: set[str] = set()
    _walk(env["dead_stores"], "", lambda k, p: None,
          lambda v, p: hits.add(p) if canary in v else None)
    assert hits and hits <= free, hits - free
    assert canary not in json.dumps(env["findings"])
    assert canary not in json.dumps(env["run_metrics"])
    real_home = os.path.realpath(home)
    for item in w["free_strings"]:
        assert item["key"].endswith(".path")
    ev, per = _patch_sealing_sets(monkeypatch, w)
    sealed_section, stored, _adapted = _seal(env, ev, per)
    sealed_hits: set[str] = set()

    def on_sealed(v, p):
        if canary in v:
            sealed_hits.add(p)
            assert v.startswith(real_home + os.sep), (p, v)  # only kept absolute paths inside the home

    _walk(sealed_section, "", lambda k, p: None, on_sealed)
    assert sealed_hits and sealed_hits <= free
    assert canary not in json.dumps(stored)
    # Config-only names (enabled names without a folder, hook names, manifest names, pet slug) never appear.
    for name in (f"gone{canary}", f"linked{canary}", f"h{canary}", f"pet{canary}", f"value{canary}"):
        assert name not in json.dumps(sealed_section)


def _no_hmac(value) -> bool:
    if isinstance(value, dict):
        return "hmac" not in value and all(_no_hmac(v) for v in value.values()) and not any(
            isinstance(k, str) and k.startswith("hmac:") for k in value)
    if isinstance(value, list):
        return all(_no_hmac(v) for v in value)
    return True


def test_sealed_output_contains_no_hashed_token(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.dead_stores")
    w = _wiring()
    envs = _scenario_envelopes(tmp_path, mod, monkeypatch)
    canary_env = mod.audit_dead_stores(_rich_home(tmp_path / "canary", tag="QZCANARY7"))
    ev, per = _patch_sealing_sets(monkeypatch, w)
    for env in [*envs, canary_env]:
        sealed_section, stored, adapted = _seal(env, ev, per)
        assert _no_hmac(sealed_section)
        assert _no_hmac({k: v for f in stored for k, v in f.items() if k != "evidence"})
        assert _no_hmac([{k: v for k, v in f["evidence"].items() if k != "source_digest"} for f in stored])
        assert _no_hmac(adapted["run_metrics"])


def test_two_runs_give_identical_sealed_section_and_findings(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.dead_stores")
    w = _wiring()
    home = _rich_home(tmp_path / "rich", tag="QZCANARY7")
    ev, per = _patch_sealing_sets(monkeypatch, w)
    runs = []
    for now in (1790100000.0, 1790100000.0 + 30 * 86_400):
        env = mod.audit_dead_stores(home, now=now)
        sealed_section, stored, _adapted = _seal(env, ev, per)  # each call uses a fresh serializer key
        strip = [{k: v for k, v in f.items() if k != "evidence"}
                 | {"evidence": {k: v for k, v in f["evidence"].items() if k != "source_digest"}} for f in stored]
        runs.append((json.dumps(sealed_section, sort_keys=True), json.dumps(strip, sort_keys=True)))
    assert runs[0] == runs[1]



def test_walker_and_sealing_checks_are_strict(tmp_path: Path, monkeypatch) -> None:
    mod = load_submodule("audit.dead_stores")
    w = _wiring()
    env = mod.audit_dead_stores(_rich_home(tmp_path / "rich"))
    for field, drop in (("schema_keys", "parked_name_label"), ("vocabulary", "logs_folder"),
                        ("numeric_evidence_keys", "orphan_count"), ("vocab_evidence_keys", "name_pattern_label")):
        broken = {**w, field: [x for x in w[field] if x != drop]}
        with pytest.raises(AssertionError):
            _check_envelope(env, broken, set(), set())
    broken_free = {**w, "free_strings": w["free_strings"][1:]}
    with pytest.raises(AssertionError):
        _check_envelope(env, broken_free, set(), set())
    # The live (unpatched) sealing sets now include the sheet: the section survives unchanged.
    ev = load_submodule("audit.evidence")
    per = load_submodule("audit.persistence")
    sealed, _stored, _a = _seal(env, ev, per)
    _compare(json.loads(json.dumps(env["dead_stores"])), sealed, "",
             {f["key"] for f in w["free_strings"]}, {})



def _doc_words(text):
    """Ignore Markdown typography and wrapping, not words (including negation)."""
    import re
    return " ".join(re.findall(r"\w+", text.casefold()))


def _doc_contains(doc, expected):
    words = _doc_words(expected)
    if not words:
        assert f"`{expected}`" in doc, expected
    else:
        assert f" {words} " in f" {_doc_words(doc)} ", expected


def _doc_tables(doc):
    """Read named Markdown columns; permit extra/reordered columns and reflow."""
    import re
    header = None
    previous = None
    pending = ""
    rows = []
    for line in doc.splitlines():
        line = line.strip()
        if not line:
            header = previous = None
            continue
        if not pending and not line.startswith("|"):
            continue
        pending = f"{pending} {line}".strip()
        if not line.endswith("|"):
            continue
        cells = [c.strip().strip("`") for c in pending.strip("|").split("|")]
        pending = ""
        if all(re.fullmatch(r":?-+:?", c.replace(" ", "")) for c in cells):
            assert previous is not None, "table separator has no header"
            header = [_doc_words(c) for c in previous]
        elif header is not None:
            assert len(cells) == len(header), cells
            rows.append(dict(zip(header, cells)))
        previous = cells
    return rows


def _doc_rule_rows(doc, ids, required_column=None):
    rows = {}
    for row in _doc_tables(doc):
        if required_column is not None and required_column not in row:
            continue
        rid = next((value for value in row.values() if value in ids), None)
        if rid is not None:
            if rid in rows:
                # Some pages repeat the rule table with a separate evidence view.
                for key in rows[rid].keys() & row.keys():
                    assert _doc_words(rows[rid][key]) == _doc_words(row[key]), (rid, key)
                rows[rid].update(row)
            else:
                rows[rid] = row
    assert set(rows) == set(ids)
    return rows


def _doc_bullets(doc):
    """Return rule-labelled blocks without pinning list markers or quote style."""
    import re
    blocks = re.split(r"(?m)^\s*(?:[-*+]\s+|#{1,6}\s+)", doc)
    result = {}
    for block in blocks:
        match = re.match(r"`?([a-z_]+\.[a-z_]+)`?\s*:\s*(.*)", block, re.S)
        if match:
            assert match[1] not in result, match[1]
            result[match[1]] = match[2].split("\n\n", 1)[0]
    return result


def test_doc_reference_parser_accepts_reflow_and_column_reordering():
    doc = ('|Consequence|Extra|Class|Rule id|\n|---|---|---|---|\n'
           '|“Targets are not\n followed.”|note|`info`|`example.rule`|\n')
    rows = _doc_rule_rows(doc, {'example.rule'})
    assert _doc_words(rows['example.rule']['consequence']) == _doc_words('Targets are not followed.')
    assert rows['example.rule']['class'] == 'info'
    bullets = _doc_bullets('* example.rule: “Targets are not\n  followed.”\n')
    assert _doc_words(bullets['example.rule']) == _doc_words('Targets are not followed.')


def test_doc_reference_parser_preserves_negation_and_values():
    assert _doc_words('Targets are not followed.') != _doc_words('Targets are followed.')
    assert _doc_words('At least 80%') != _doc_words('At least 8%')
    with pytest.raises(AssertionError):
        _doc_contains('Targets are followed.', 'Targets are not followed.')
    with pytest.raises(AssertionError):
        _doc_rule_rows('|Rule|Class|\n|---|---|\n|example.other|info|', {'example.rule'})
    with pytest.raises(AssertionError):
        _doc_rule_rows('|Rule|Class|\n|---|---|\n|example.rule|info|\n'
                       '|example.rule|review_suggested|', {'example.rule'})


def test_doc_page_matches_wiring_sheet():
    w = _wiring()
    doc = (Path(__file__).resolve().parents[1] / "docs/audit-sections/dead_stores.md").read_text(encoding="utf-8")
    rows = _doc_rule_rows(doc, w["rule_ids"])
    for rid, row in rows.items():
        classification = row.get("classification", row.get("class"))
        assert _doc_words(classification) == _doc_words(w["classifications"][rid][0]), rid
        consequence = next(value for key, value in row.items() if key.startswith("consequence"))
        assert _doc_words(consequence) == _doc_words(w["consequences"][rid]), rid
    for key in w["schema_keys"]:
        _doc_contains(doc, key)
    for value in w["vocabulary"]:
        _doc_contains(doc, value)
    for item in w["free_strings"]:
        _doc_contains(doc, item["key"])
    _doc_contains(doc, "Sizes are file sizes")
