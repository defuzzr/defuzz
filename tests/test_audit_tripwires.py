"""Forbidden-call tripwire tests and import-time safety checks for the audit sweep (§1, §11).

Verifies:
- Sweep forbidden-call tripwires: network (`socket`, `urllib.request`, `http.client`),
  subprocess (`subprocess.Popen`, `subprocess.run`, `os.system`, `os.popen`, `os.exec*`),
  extension/plugin loading, hook/MCP invocation, installs, and writes outside the plugin DB
  fail immediately when invoked, and are NEVER invoked during audit module import or a full
  read-only sweep.
- Audit package modules use only the Python standard library (plus the plugin's own `safety.py`).
"""

from __future__ import annotations

import ast
import builtins
import http.client
import importlib
import io
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

from tests import ensure_test_package

ensure_test_package()

REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = REPO_ROOT / "audit"


class TripwireTriggeredError(AssertionError):
    """Raised when a forbidden operation is attempted during an audit sweep or import."""


@contextmanager
def sweep_forbidden_call_tripwires(
    *,
    allowed_write_root: Path | None = None,
) -> Iterator[None]:
    """Install strict runtime tripwires for network, subprocess, dynamic extension loading, and outside writes (§11)."""
    real_open = builtins.open
    real_os_open = os.open
    real_mkdir = os.mkdir
    real_makedirs = os.makedirs
    real_unlink = os.unlink
    real_remove = os.remove
    real_rename = os.rename
    real_replace = os.replace
    real_sqlite_connect = sqlite3.connect

    allowed_abs = (
        Path(os.path.abspath(os.path.expanduser(os.fspath(allowed_write_root))))
        if allowed_write_root is not None
        else None
    )

    def _is_allowed_write_path(target: Any) -> bool:
        if allowed_abs is None or isinstance(target, int):
            return False
        try:
            p = Path(os.path.abspath(os.path.expanduser(os.fspath(target))))
            p.relative_to(allowed_abs)
            return True
        except Exception:
            return False

    def _forbid(label: str) -> Any:
        def _raiser(*args: Any, **kwargs: Any) -> Any:
            raise TripwireTriggeredError(f"Forbidden call during audit sweep: {label} args={args!r}")
        return _raiser

    def _guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if any(m in mode for m in ("w", "a", "x", "+")):
            if not _is_allowed_write_path(file):
                raise TripwireTriggeredError(
                    f"Forbidden file write via builtins.open({file!r}, mode={mode!r}) outside plugin DB"
                )
        return real_open(file, mode, *args, **kwargs)

    def _guarded_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        write_mask = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        if (flags & write_mask) != 0:
            if kwargs.get("dir_fd") is not None or not _is_allowed_write_path(path):
                raise TripwireTriggeredError(
                    f"Forbidden file write via os.open({path!r}, flags={flags:#x}) outside plugin DB"
                )
        return real_os_open(path, flags, *args, **kwargs)

    def _guarded_mkdir(path: Any, *args: Any, **kwargs: Any) -> None:
        if not _is_allowed_write_path(path):
            raise TripwireTriggeredError(f"Forbidden os.mkdir({path!r}) outside plugin DB")
        return real_mkdir(path, *args, **kwargs)

    def _guarded_makedirs(name: Any, *args: Any, **kwargs: Any) -> None:
        if not _is_allowed_write_path(name):
            raise TripwireTriggeredError(f"Forbidden os.makedirs({name!r}) outside plugin DB")
        return real_makedirs(name, *args, **kwargs)

    def _guarded_sqlite_connect(database: Any, *args: Any, **kwargs: Any) -> sqlite3.Connection:
        db_str = str(database)
        is_uri = bool(kwargs.get("uri"))
        if is_uri and "mode=ro" in db_str:
            return real_sqlite_connect(database, *args, **kwargs)
        if not _is_allowed_write_path(db_str):
            raise TripwireTriggeredError(
                f"Forbidden writable sqlite3.connect({database!r}) outside plugin DB"
            )
        return real_sqlite_connect(database, *args, **kwargs)

    with contextlib.ExitStack() as stack:
        # 1. Subprocess & command execution tripwires
        stack.enter_context(mock.patch.object(subprocess, "Popen", side_effect=_forbid("subprocess.Popen")))
        stack.enter_context(mock.patch.object(subprocess, "run", side_effect=_forbid("subprocess.run")))
        stack.enter_context(mock.patch.object(subprocess, "call", side_effect=_forbid("subprocess.call")))
        stack.enter_context(mock.patch.object(subprocess, "check_call", side_effect=_forbid("subprocess.check_call")))
        stack.enter_context(mock.patch.object(subprocess, "check_output", side_effect=_forbid("subprocess.check_output")))
        stack.enter_context(mock.patch.object(os, "system", side_effect=_forbid("os.system")))
        stack.enter_context(mock.patch.object(os, "popen", side_effect=_forbid("os.popen")))

        # 2. Network tripwires
        stack.enter_context(mock.patch.object(socket, "socket", side_effect=_forbid("socket.socket")))
        stack.enter_context(mock.patch.object(socket, "create_connection", side_effect=_forbid("socket.create_connection")))
        stack.enter_context(mock.patch.object(socket, "getaddrinfo", side_effect=_forbid("socket.getaddrinfo")))
        stack.enter_context(mock.patch.object(urllib.request, "urlopen", side_effect=_forbid("urllib.request.urlopen")))
        stack.enter_context(mock.patch.object(http.client.HTTPConnection, "connect", side_effect=_forbid("HTTPConnection.connect")))
        stack.enter_context(mock.patch.object(http.client.HTTPSConnection, "connect", side_effect=_forbid("HTTPSConnection.connect")))

        # 3. Write / mutation tripwires outside allowed_write_root
        stack.enter_context(mock.patch.object(builtins, "open", side_effect=_guarded_open))
        stack.enter_context(mock.patch.object(io, "open", side_effect=_guarded_open))
        stack.enter_context(mock.patch.object(os, "open", side_effect=_guarded_os_open))
        stack.enter_context(mock.patch.object(os, "mkdir", side_effect=_guarded_mkdir))
        stack.enter_context(mock.patch.object(os, "makedirs", side_effect=_guarded_makedirs))
        stack.enter_context(mock.patch.object(os, "unlink", side_effect=_forbid("os.unlink")))
        stack.enter_context(mock.patch.object(os, "remove", side_effect=_forbid("os.remove")))
        stack.enter_context(mock.patch.object(os, "rename", side_effect=_forbid("os.rename")))
        stack.enter_context(mock.patch.object(os, "replace", side_effect=_forbid("os.replace")))
        stack.enter_context(mock.patch.object(shutil, "rmtree", side_effect=_forbid("shutil.rmtree")))
        stack.enter_context(mock.patch.object(shutil, "copy2", side_effect=_forbid("shutil.copy2")))
        stack.enter_context(mock.patch.object(sqlite3, "connect", side_effect=_guarded_sqlite_connect))

        yield


import contextlib  # noqa: E402


class TestAuditTripwires(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_tripwires_fail_immediately_on_forbidden_calls(self) -> None:
        plugin_db_dir = self.tmp_root / "plugin_db"
        outside_file = self.tmp_root / "outside.txt"

        with sweep_forbidden_call_tripwires(allowed_write_root=plugin_db_dir):
            with self.assertRaises(TripwireTriggeredError):
                subprocess.run(["echo", "hi"], check=False)
            with self.assertRaises(TripwireTriggeredError):
                socket.create_connection(("127.0.0.1", 80))
            with self.assertRaises(TripwireTriggeredError):
                urllib.request.urlopen("http://127.0.0.1")
            with self.assertRaises(TripwireTriggeredError):
                outside_file.write_text("forbidden", encoding="utf-8")
            with self.assertRaises(TripwireTriggeredError):
                sqlite3.connect(str(self.tmp_root / "foreign_state.db"))

    def test_import_time_tripwires_on_all_audit_modules(self) -> None:
        """Importing/reloading every `audit.*` and `audit.vendor.*` module under strict tripwires must succeed with zero side effects."""
        pkg_prefix = "hermes_plugins.defuzz.audit"
        discovered_submodules: list[str] = [""]
        for py_file in sorted(AUDIT_DIR.glob("**/*.py")):
            rel_parts = list(py_file.relative_to(AUDIT_DIR).with_suffix("").parts)
            if rel_parts[-1] == "__init__":
                rel_parts = rel_parts[:-1]
            sub = ".".join(rel_parts)
            if sub not in discovered_submodules:
                discovered_submodules.append(sub)

        def _audit_names() -> list[str]:
            return [n for n in sys.modules if n == pkg_prefix or n.startswith(pkg_prefix + ".")]

        # A reload rebinds module globals to NEW objects (for example the redaction
        # scope's ContextVar), while modules that did `from .x import name` earlier keep
        # the old ones; reloading again cannot undo that split, and later audits then run
        # partly outside their per-run scope (two runs gave the same digest). So restore
        # every audit module's original namespace, and re-import the ones first imported here.
        saved = {n: (sys.modules[n], dict(vars(sys.modules[n]))) for n in _audit_names()}
        try:
            with sweep_forbidden_call_tripwires(allowed_write_root=None):
                for sub in discovered_submodules:
                    full_name = f"{pkg_prefix}.{sub}" if sub else pkg_prefix
                    if full_name in sys.modules:
                        importlib.reload(sys.modules[full_name])
                    else:
                        importlib.import_module(full_name)
        finally:
            for name in _audit_names():
                if name not in saved:
                    del sys.modules[name]
            for name, (module, namespace) in saved.items():
                vars(module).clear()
                vars(module).update(namespace)
                sys.modules[name] = module
            # Leave every audit module imported, as before, but with the real os functions
            # (an import under the tripwires sees wrapped ones).
            for sub in discovered_submodules:
                importlib.import_module(f"{pkg_prefix}.{sub}" if sub else pkg_prefix)

    def test_vendored_components_public_functions_under_tripwires(self) -> None:
        """Every module under `audit/vendor/` must import and execute its public entrypoint on an empty fixture under strict tripwires."""
        import inspect

        vendor_dir = AUDIT_DIR / "vendor"
        if not vendor_dir.is_dir():
            return

        vendor_files = [
            p for p in sorted(vendor_dir.glob("**/*.py")) if p.name != "__init__.py"
        ]
        self.assertGreaterEqual(len(vendor_files), 1)

        def _invoke_vendored_module(mod: Any) -> Any:
            if hasattr(mod, "run") and callable(mod.run):
                empty_in = getattr(mod, "EMPTY_INPUT", {})
                return mod.run(empty_in)
            for fn_name in (
                "audit_cross_checks",
                "audit_executable_inventory",
                "audit_profile_context",
                "audit_profile_memory",
                "audit_template_drift",
                "audit_static_code",
            ):
                fn = getattr(mod, fn_name, None)
                if callable(fn):
                    break
            else:
                fn = None
                for attr_name in getattr(mod, "__all__", ()):
                    cand = getattr(mod, attr_name, None)
                    if callable(cand) and not inspect.isclass(cand) and attr_name.startswith(("audit_", "check_", "run")):
                        fn = cand
                        break
            self.assertIsNotNone(fn, f"No public audit function found in {mod.__name__}")
            assert fn is not None
            sig = inspect.signature(fn)
            kwargs: dict[str, Any] = {}
            pos_args: list[Any] = []
            for pname, param in sig.parameters.items():
                if param.default is not inspect.Parameter.empty:
                    continue
                if param.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
                    if param.kind == inspect.Parameter.POSITIONAL_ONLY:
                        pos_args.append({})
                    elif pname in ("profile_name", "name"):
                        kwargs[pname] = "default"
                    elif pname in ("profile_facts",):
                        kwargs[pname] = {"name": "default", "path": "/tmp/empty_profile"}
                    else:
                        kwargs[pname] = {}
                elif param.kind == inspect.Parameter.KEYWORD_ONLY:
                    if pname in ("profile_name", "name"):
                        kwargs[pname] = "default"
                    elif pname in ("profile_facts",):
                        kwargs[pname] = {"name": "default", "path": "/tmp/empty_profile"}
                    else:
                        kwargs[pname] = {}
            return fn(*pos_args, **kwargs)

        with sweep_forbidden_call_tripwires(allowed_write_root=None):
            for vf in vendor_files:
                rel_parts = list(vf.relative_to(AUDIT_DIR).with_suffix("").parts)
                mod_name = "hermes_plugins.defuzz.audit." + ".".join(rel_parts)
                mod = importlib.import_module(mod_name)
                result = _invoke_vendored_module(mod)
                self.assertIsInstance(result, dict, f"{mod_name} did not return a dict")
                self.assertIn("ok", result)
                self.assertIn("status", result)
                self.assertIn("findings", result)
                self.assertIn("coverage", result)
                self.assertIn("classification", result)

    def test_full_sweep_and_plugin_db_store_under_tripwires(self) -> None:
        """Running a full system inventory + fingerprint sweep + plugin DB commit triggers zero tripwires and leaves source trees untouched."""
        from hermes_plugins.defuzz.audit import (
            AuditStore,
            collect_system_inventory_facts,
        )

        # Build isolated fixture profiles and a registered project
        hermes_root = self.tmp_root / "hermes_home"
        default_dir = hermes_root
        named_dir = hermes_root / "profiles" / "coder"
        (default_dir / "memories").mkdir(parents=True)
        (default_dir / "skills" / "demo-skill").mkdir(parents=True)
        (named_dir / "memories").mkdir(parents=True)
        (named_dir / "skills").mkdir(parents=True)

        (default_dir / "config.yaml").write_text("model: test-model\n", encoding="utf-8")
        (default_dir / "SOUL.md").write_text("Be direct.\n", encoding="utf-8")
        (default_dir / "memories" / "MEMORY.md").write_text("Entry A\n§\nEntry B\n", encoding="utf-8")
        (default_dir / "skills" / "demo-skill" / "SKILL.md").write_text(
            "---\nname: demo-skill\ndescription: Demo skill\n---\nBody\n",
            encoding="utf-8",
        )
        (named_dir / "config.yaml").write_text("model: coder-model\n", encoding="utf-8")
        (named_dir / "memories" / "MEMORY.md").write_text("Coder note\n", encoding="utf-8")

        # Create a read-only source state.db in default_dir
        src_db = default_dir / "state.db"
        with contextlib.closing(sqlite3.connect(str(src_db))) as conn:
            with conn:
                conn.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY, started_at REAL, source TEXT, title TEXT)")
                conn.execute("INSERT INTO sessions VALUES ('s1', 1700000000.0, 'cli', 'Test session')")
        src_db_bytes_before = src_db.read_bytes()

        plugin_db_dir = self.tmp_root / "active_plugin_store"
        plugin_db_path = plugin_db_dir / "state.db"

        def _list_names() -> list[str]:
            return ["default", "coder"]

        def _get_dir(name: str) -> Path:
            return default_dir if name == "default" else (hermes_root / "profiles" / name)

        from hermes_plugins.defuzz.audit.key import key_scope
        # Durable-key provisioning is a plugin-store write, not source capture.
        with key_scope(plugin_db_path), sweep_forbidden_call_tripwires(allowed_write_root=plugin_db_dir):
            inv = collect_system_inventory_facts(
                as_of=1700500000,
                list_profile_names_fn=_list_names,
                get_profile_dir_fn=_get_dir,
                active_profile="default",
            )
            store = AuditStore(db_path=plugin_db_path)
            run = store.create_run(
                as_of=1700500000,
                active_profile="default",
                inventory={"profiles": [p["name"] for p in inv["profile_units"]]},
                planned_units=[
                    {"unit_kind": "profile", "unit_id": p["name"]}
                    for p in inv["profile_units"]
                ],
            )
            for idx, p_unit in enumerate(inv["profile_units"]):
                store.commit_unit_result(
                    run_id=run["run_id"],
                    unit_kind="profile",
                    unit_id=p_unit["name"],
                    manifest=p_unit["fingerprint_manifest"],
                    evidence=p_unit,
                    sort_order=idx,
                )
            final = store.finalize_run(run["run_id"], extra_findings=inv["findings"])

        self.assertEqual(final["status"], "completed")
        self.assertEqual(src_db.read_bytes(), src_db_bytes_before)
        # Ensure named_dir/state.db and named_dir/plugin-data/defuzz/state.db were NEVER created!
        self.assertFalse((named_dir / "state.db").exists())
        self.assertFalse((named_dir / "plugin-data" / "defuzz" / "state.db").exists())
        self.assertFalse((default_dir / "plugin-data" / "defuzz" / "state.db").exists())

    def test_audit_package_ast_uses_stdlib_only(self) -> None:
        """Static AST check: `audit/**/*.py` never imports subprocess, socket, requests, httpx, or non-stdlib packages."""
        forbidden_imports = {
            "subprocess",
            "socket",
            "urllib.request",
            "http",
            "requests",
            "httpx",
            "aiohttp",
            "tiktoken",
        }
        py_files = sorted(AUDIT_DIR.glob("**/*.py"))
        self.assertGreaterEqual(len(py_files), 6)
        # One exception, pinned below: the time-budget worker
        # (audit/bounded_call.py) starts a fresh copy of this same Python
        # interpreter running the audit's own code, so a stuck component can be
        # killed. It never runs another program; see
        # test_bounded_call_launches_only_this_interpreter.
        allowed_imports = {"bounded_call.py": {"subprocess"}}

        for py_file in py_files:
            rel_label = str(py_file.relative_to(AUDIT_DIR))
            forbidden_here = forbidden_imports - allowed_imports.get(rel_label, set())
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        self.assertNotIn(
                            alias.name,
                            forbidden_here,
                            f"{rel_label} imports forbidden module {alias.name!r}",
                        )
                        if top != "urllib" or alias.name != "urllib.parse":
                            self.assertNotIn(
                                top,
                                forbidden_here,
                                f"{rel_label} imports forbidden module {alias.name!r}",
                            )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    top = node.module.split(".")[0]
                    self.assertNotIn(
                        node.module,
                        forbidden_here,
                        f"{rel_label} imports from forbidden module {node.module!r}",
                    )
                    if top != "urllib" or node.module != "urllib.parse":
                        self.assertNotIn(
                            top,
                            forbidden_here,
                            f"{rel_label} imports from forbidden module {node.module!r}",
                        )

    def test_bounded_call_launches_only_this_interpreter(self) -> None:
        """The subprocess allowance above: one Popen of [sys.executable, '-c', <constant>], no shell."""
        path = AUDIT_DIR / "bounded_call.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        constants = {
            target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
            for target in node.targets if isinstance(target, ast.Name)
        }
        uses = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "subprocess"
        ]
        self.assertEqual({node.attr for node in uses}, {"Popen", "PIPE", "TimeoutExpired"})
        calls = [
            node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "Popen"
        ]
        self.assertEqual(len(calls), 1)
        (call,) = calls
        argv = call.args[0]
        self.assertIsInstance(argv, ast.List)
        self.assertEqual(ast.unparse(argv), "[sys.executable, '-c', _BOOT]")
        self.assertIsInstance(constants["_BOOT"], ast.Constant)
        self.assertIsInstance(constants["_BOOT"].value, str)
        self.assertEqual(len(call.args), 1)
        self.assertFalse({kw.arg for kw in call.keywords} & {"shell", "executable", "args", "env", "preexec_fn"})
        for name in ("os.system", "os.popen", "os.exec", "os.spawn", "os.posix_spawn"):
            self.assertNotIn(name, path.read_text(encoding="utf-8"))
        imported = {
            alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertNotIn("multiprocessing", imported)


if __name__ == "__main__":
    unittest.main()
