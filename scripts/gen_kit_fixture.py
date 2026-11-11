#!/usr/bin/env python3
"""Regenerate (or check) the recorded kit fixture from the companion plugin's real kit commands.

Usage:
    python3 scripts/gen_kit_fixture.py --source <defuzz-componentize folder> [--check] [--out <dir>]

The source may also come from the DEFUZZ_COMPONENTIZE_SOURCE environment variable.
The companion's `kit list --json` and `kit show <id> --json` (plus `kit apply/check`
for the contract kit, when it exists) run in a subprocess with a temporary HOME and
working directory. Only the temporary folder's absolute path is normalised (to /ROOT).

Exit codes: 0 ok / up to date, 1 fixture out of date (--check), 2 usage or source error.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "tests" / "fixtures" / "kit_contract"
ENV_VAR = "DEFUZZ_COMPONENTIZE_SOURCE"
PLUGIN_NAME = "defuzz-componentize"
# The kit whose show/apply/check outputs are kept as the single-kit contract samples.
CONTRACT_KIT = "video-production"
SHOWS_DIR = "shows"

# Runs inside a subprocess so the companion package never loads into the caller.
_WORKER = r'''
import importlib, importlib.util, json, sys, tempfile
from pathlib import Path
src = Path(sys.argv[1]); contract = sys.argv[2]
name = "defuzz_componentize_fixture_gen"
spec = importlib.util.spec_from_file_location(name, src / "__init__.py", submodule_search_locations=[str(src)])
mod = importlib.util.module_from_spec(spec); sys.modules[name] = mod; spec.loader.exec_module(mod)
kit = importlib.import_module(name + ".kit_commands")
out = {"calls": []}
with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp).resolve(); home = base / "home"; work = base / "work"
    home.mkdir(); work.mkdir()
    def call(argv):
        res = kit.run(argv, cwd=str(work), home=str(home))
        text = res.get("stdout", "")
        out["calls"].append({"argv": argv, "exit": res.get("exit"), "stderr": res.get("stderr", ""),
                             "stdout": text.replace(str(work / "contract-kit"), "/ROOT").replace(str(base), "/ROOT")})
        return res
    res = call(["list", "--json"])
    if res.get("exit") == 0:
        ids = [k["id"] for k in json.loads(res["stdout"])["kits"]]
        for kid in ids:
            call(["show", kid, "--json"])
        if contract in ids:
            target = str(work / "contract-kit")
            call(["apply", contract, target, "--json"])
            call(["check", contract, target, "--json"])
print(json.dumps(out))
'''


class GenError(Exception):
    pass


def _canon(data) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def validate_source(source: Path) -> Path:
    source = source.expanduser().resolve()
    if not source.is_dir():
        raise GenError(f"companion plugin folder not found: {source}")
    manifest = source / "plugin.yaml"
    if not manifest.is_file() or not (source / "kit_commands.py").is_file():
        raise GenError(f"not the {PLUGIN_NAME} plugin (missing plugin.yaml or kit_commands.py): {source}")
    names = [ln.split(":", 1)[1].strip().strip("'\"") for ln in manifest.read_text(encoding="utf-8").splitlines()
             if ln.startswith("name:")]
    if names != [PLUGIN_NAME]:
        raise GenError(f"not the {PLUGIN_NAME} plugin (plugin.yaml name is {names[0] if names else 'missing'!r}): {source}")
    return source


def generate(source: Path) -> Dict[str, str]:
    """Return {relative fixture path: file text} produced by the companion right now."""
    source = validate_source(source)
    with tempfile.TemporaryDirectory() as tmp:
        env = {k: v for k, v in os.environ.items() if not k.startswith("HERMES")}
        env.update(HOME=tmp, PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run([sys.executable, "-B", "-c", _WORKER, str(source), CONTRACT_KIT],
                              cwd=tmp, env=env, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise GenError(f"loading the companion's kit commands failed:\n{proc.stderr.strip()}")
    calls = json.loads(proc.stdout)["calls"]
    files: Dict[str, str] = {}
    for c in calls:
        label = "kit " + " ".join(c["argv"])
        if c["exit"] != 0 or c["stderr"]:
            raise GenError(f"{label} failed (exit {c['exit']}): {c['stderr'].strip() or c['stdout'][:300]}")
        try:
            data = json.loads(c["stdout"])
        except ValueError as exc:
            raise GenError(f"{label} did not print JSON: {exc}") from None
        cmd = c["argv"][0]
        if cmd == "list":
            files["list.json"] = _canon(data)
        elif cmd == "show":
            files[f"{SHOWS_DIR}/{c['argv'][1]}.json"] = _canon(data)
            if c["argv"][1] == CONTRACT_KIT:
                files["show.json"] = _canon(data)
        else:
            files[f"{cmd}.json"] = _canon(data)
    return files


def _field_diff(old: str, new: str, path: str) -> List[str]:
    try:
        a, b = json.loads(old), json.loads(new)
    except ValueError:
        return [f"{path}: not valid JSON"]
    if path == "list.json":
        ka = {k.get("id"): k for k in a.get("kits", [])}
        kb = {k.get("id"): k for k in b.get("kits", [])}
        out = [f"kit {i}: added" for i in sorted(set(kb) - set(ka))]
        out += [f"kit {i}: removed" for i in sorted(set(ka) - set(kb))]
        for i in sorted(set(ka) & set(kb)):
            fields = sorted(f for f in set(ka[i]) | set(kb[i]) if ka[i].get(f) != kb[i].get(f))
            if fields:
                out.append(f"kit {i}: {', '.join(fields)} changed")
        other = sorted(f for f in set(a) | set(b) if f != "kits" and a.get(f) != b.get(f))
        if other:
            out.append(f"list.json: {', '.join(other)} changed")
        return out or ["list.json: formatting differs"]
    fields = sorted(f for f in set(a) | set(b) if a.get(f) != b.get(f))
    return [f"{path}: {', '.join(fields) or 'formatting'} changed"]


def compare(out_dir: Path, files: Dict[str, str]) -> List[str]:
    problems: List[str] = []
    for rel, text in sorted(files.items()):
        p = out_dir / rel
        if not p.is_file():
            problems.append(f"{rel}: missing from the committed fixture")
        elif p.read_text(encoding="utf-8") != text:
            problems.extend(_field_diff(p.read_text(encoding="utf-8"), text, rel))
    shows = out_dir / SHOWS_DIR
    if shows.is_dir():
        for p in sorted(shows.glob("*.json")):
            rel = f"{SHOWS_DIR}/{p.name}"
            if rel not in files:
                problems.append(f"{rel}: kit no longer exists in the companion")
    return problems


def write(out_dir: Path, files: Dict[str, str]) -> None:
    shows = out_dir / SHOWS_DIR
    shows.mkdir(parents=True, exist_ok=True)
    for p in shows.glob("*.json"):
        if f"{SHOWS_DIR}/{p.name}" not in files:
            p.unlink()
    for rel, text in sorted(files.items()):
        (out_dir / rel).write_text(text, encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Regenerate or check the recorded kit fixture.")
    ap.add_argument("--source", help=f"companion plugin folder (default: ${ENV_VAR})")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="fixture folder to write or check")
    ap.add_argument("--check", action="store_true", help="write nothing; exit 1 if the fixture is out of date")
    args = ap.parse_args(argv)
    raw = args.source or os.environ.get(ENV_VAR)
    if not raw:
        print(f"error: no companion plugin folder: pass --source or set {ENV_VAR}", file=sys.stderr)
        return 2
    try:
        files = generate(Path(raw))
    except GenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out_dir = Path(args.out)
    if args.check:
        problems = compare(out_dir, files)
        if problems:
            print("kit fixture is out of date; regenerate with: python3 scripts/gen_kit_fixture.py --source <folder>")
            for line in problems:
                print(f"  {line}")
            return 1
        print(f"kit fixture is up to date ({len(files)} files)")
        return 0
    write(out_dir, files)
    print(f"wrote {len(files)} files to {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
