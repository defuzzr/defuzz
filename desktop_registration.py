"""Desktop project registration through core's public tool boundary.

CLI plugin commands need not import model_tools (chat normally does discovery).
Use the same public discovery entry point, only when the tool is absent. This
also works in dashboard/desktop processes without replacing their registered
handlers or callbacks. Do not import implementation modules or write projects.db.
Discovery imports approximately 43 core tool modules (observed 0.5-0.85s) and
writes $HERMES_HOME/cache/tool_discovery_cache.json. Core project_create also
sets the active Desktop project (tools/project_tools.py:117-118).

Core contracts: tools/registry.py:121 (discovery), :972 (dispatch),
model_tools.py:150 (normal startup discovery), hermes_cli/plugins.py:677
(PluginContext.dispatch_tool delegates to this same registry). Desktop reads
hermes_cli.projects_db via tui_gateway/methods_projects.py:20-24,81-83.
"""
import json
import logging


def failure_notice(repo: dict) -> str:
    """Format recovery guidance without writing to any presentation channel."""
    manual_args = json.dumps({"action": "create", "name": repo["registration_name"], "path": repo["path"]})
    return (
        f"Desktop registration failed: {json.dumps(repo['registration_result']['reason'])}; "
        f"project created at {json.dumps(repo['path'])}. "
        f"Register manually with desktop_project {manual_args}."
    )


class RegistrationUnavailable(RuntimeError):
    """Core cannot expose the Desktop registration tool in this process."""


_CTX = None


def bind_context(ctx) -> None:
    """Remember the PluginContext from register() so dispatch uses ctx.dispatch_tool.

    ctx.dispatch_tool (Hermes >=0.21, below requires_hermes 0.23.0) adds the plugin's
    registry scope and the parent agent; without a bound ctx (direct library use or tests)
    the same public registry call is made.
    """
    global _CTX
    _CTX = ctx


def create_project(name: str, path: str) -> str:
    try:
        from tools.registry import registry
        if registry.get_entry("desktop_project") is None:
            from tools.registry import discover_builtin_tools
            discover_builtin_tools()
        if registry.get_entry("desktop_project") is None:
            raise RegistrationUnavailable("desktop_project unavailable: public tool is not registered after discovery")
    except RegistrationUnavailable:
        raise
    except Exception as exc:
        logging.getLogger(__name__).debug("Desktop tool discovery failed: %s", exc, exc_info=True)
        raise RegistrationUnavailable(f"project_create unavailable: {exc}") from exc
    args = {"action": "create", "name": name, "path": path}
    dispatch_tool = getattr(_CTX, "dispatch_tool", None)
    if callable(dispatch_tool):
        result = dispatch_tool("desktop_project", args)
    else:
        result = registry.dispatch("desktop_project", args)
    return result if isinstance(result, str) else json.dumps(result)
