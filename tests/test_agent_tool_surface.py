"""Agent tool surface: only declared schema properties reach the engine; user-only switches stay CLI-only."""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, List

import pytest

from tests import ensure_test_package

plugin_init = ensure_test_package()

from hermes_plugins.defuzz import desktop_registration  # noqa: E402

PLUGIN_ROOT = Path(plugin_init.__file__).resolve().parent


class _Ctx:
    def __init__(self) -> None:
        self.tools: Dict[str, Dict[str, Any]] = {}
        self.llm = None
        self.dispatched: List[Any] = []
        self.dispatch_result: Any = json.dumps({"ok": True})

    def get_config(self, key: str, default: Any = None) -> Any:
        return default

    def register_tool(self, name: str, toolset: str, schema: Dict[str, Any], handler: Callable) -> None:
        self.tools[name] = {"schema": schema, "handler": handler}

    def register_hook(self, *a: Any, **k: Any) -> None:
        pass

    def register_cli_command(self, *a: Any, **k: Any) -> None:
        pass

    def register_command(self, *a: Any, **k: Any) -> None:
        pass

    def dispatch_tool(self, tool_name: str, args: dict, **kwargs: Any) -> str:
        self.dispatched.append((tool_name, args, kwargs))
        if isinstance(self.dispatch_result, Exception):
            raise self.dispatch_result
        return self.dispatch_result


@pytest.fixture()
def ctx(monkeypatch):
    c = _Ctx()
    plugin_init.register(c)
    yield c
    desktop_registration.bind_context(None)


def _source(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("hi\n")
    (src / ".env").write_text("TOKEN=x\n")
    return src


def test_agent_cannot_enable_include_secret_files(ctx, tmp_path):
    src = _source(tmp_path)
    copy = tmp_path / "copy"
    out = json.loads(ctx.tools["defuzz_project"]["handler"](
        {"action": "scan", "copy_path": str(copy), "source_path": str(src),
         "staging_path": str(tmp_path / "stage"), "include_secret_files": True}))
    assert not (copy / ".env").exists()
    assert out["ok"] is False
    assert "--include-secret-files" in out["error"]


def test_default_scan_still_leaves_secret_behind(ctx, tmp_path):
    src = _source(tmp_path)
    copy = tmp_path / "copy"
    out = json.loads(ctx.tools["defuzz_project"]["handler"](
        {"action": "scan", "copy_path": str(copy), "source_path": str(src),
         "staging_path": str(tmp_path / "stage")}))
    assert out.get("ok") is not False, out
    assert (copy / "README.md").exists() and not (copy / ".env").exists()


TOOLS = ["defuzz_project", "defuzz_place", "defuzz_audit"]


@pytest.mark.parametrize("name", TOOLS)
def test_undeclared_argument_rejected_for_every_tool(ctx, name):
    out = json.loads(ctx.tools[name]["handler"]({"action": "scan", "copy_path": "/nonexistent", "zz_undeclared": 1}))
    assert out["ok"] is False and "zz_undeclared" in out["error"]


def _engine_keys(func: Callable) -> set:
    src = inspect.getsource(func)
    return set(re.findall(r"""(?:args|payload)(?:\.get\(|\[)\s*["']([a-z_]+)["']""", src))


def test_engine_reads_only_declared_or_guarded_keys(ctx):
    from hermes_plugins.defuzz import audit_surface, cli
    cases = {
        "defuzz_project": cli.execute_defuzz_project,
        "defuzz_place": cli.execute_defuzz_place,
        "defuzz_audit": audit_surface.execute_audit,
    }
    for name, func in cases.items():
        declared = set(ctx.tools[name]["schema"]["parameters"]["properties"])
        read = _engine_keys(func)
        # include_secret_files is read by the engine but the tool boundary rejects it (CLI-only).
        assert read - declared <= {"include_secret_files"}, (name, read - declared)


def test_desktop_registration_goes_through_ctx_dispatch_tool(ctx, monkeypatch):
    from tools.registry import registry
    monkeypatch.setattr(registry, "get_entry", lambda *a, **k: object())
    monkeypatch.setattr(registry, "dispatch", lambda *a, **k: pytest.fail("direct registry dispatch"))
    assert desktop_registration.create_project("n", "/p") == json.dumps({"ok": True})
    assert ctx.dispatched == [("desktop_project", {"action": "create", "name": "n", "path": "/p"}, {})]


def test_desktop_registration_dict_result_and_failure_unchanged(ctx, monkeypatch):
    from tools.registry import registry
    monkeypatch.setattr(registry, "get_entry", lambda *a, **k: object())
    ctx.dispatch_result = {"ok": False}
    assert desktop_registration.create_project("n", "/p") == json.dumps({"ok": False})
    ctx.dispatch_result = RuntimeError("boom")
    with pytest.raises(RuntimeError, match="boom"):
        desktop_registration.create_project("n", "/p")
    monkeypatch.setattr(registry, "get_entry", lambda *a, **k: None)
    monkeypatch.setattr("tools.registry.discover_builtin_tools", lambda: None)
    with pytest.raises(desktop_registration.RegistrationUnavailable):
        desktop_registration.create_project("n", "/p")


def test_desktop_registration_without_ctx_falls_back_to_registry(monkeypatch):
    from tools.registry import registry
    desktop_registration.bind_context(None)
    calls = []
    monkeypatch.setattr(registry, "get_entry", lambda *a, **k: object())
    monkeypatch.setattr(registry, "dispatch", lambda *a, **k: calls.append(a) or "{}")
    assert desktop_registration.create_project("n", "/p") == "{}"
    assert calls == [("desktop_project", {"action": "create", "name": "n", "path": "/p"})]
