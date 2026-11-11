"""Shared environment policy for child processes spawned by the Defuzz plugin.

Two consumers:

* componentize child (``componentize_bridge._child_env``): drops exactly
  ``COMPONENTIZE_STRIPPED_NAMES`` and names starting with
  ``COMPONENTIZE_STRIPPED_PREFIXES``; everything else (including ``HERMES_HOME``
  and ``HERMES_PROFILE``) is passed, because that child is Hermes itself.
* template check commands (``stripped_child_env``): project code run by
  ``uv``/``pnpm``/``cargo``/``go``/``dotnet``/``cmake``.  These get the
  componentize strip list plus every ``HERMES_*`` / ``_HERMES_*`` variable (no
  keep-list: a template build must not find the user's Hermes home or profile),
  ``SUDO_PASSWORD`` and every ``*ASKPASS`` helper, and every variable whose name
  looks like a credential (``SECRET_NAME_RE``).  There is no credential
  keep-list: a private registry token (e.g. ``CARGO_REGISTRIES_<NAME>_TOKEN``,
  ``npm_config__authToken``) is NOT passed, and a check that needs one fails.

Everything else is passed unchanged, notably PATH, HOME, LANG/LC_*, TMPDIR,
TERM, proxy variables (HTTP_PROXY/HTTPS_PROXY/NO_PROXY, any case), and
toolchain variables (CARGO_HOME, RUSTUP_HOME, GOPATH, GOMODCACHE, GOFLAGS,
DOTNET_*, NUGET_PACKAGES, UV_*, PNPM_HOME, npm_config_* without a secret-looking
name, NODE_OPTIONS, JAVA_HOME, CC, CXX, CMAKE_*, XDG_*).
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping

# Environment variables that alter Hermes approval, YOLO/auto-approve, interactivity,
# unattended/cron/gateway mode, or session/worker inheritance in a child process.
# HERMES_DESKTOP is intentionally NOT stripped for componentize: hermes_cli/process_identity.py:389-399
# requires HERMES_DASHBOARD_SESSION_TOKEN (stripped below) or SSH argv to grant desktop
# backend ownership, so HERMES_DESKTOP alone does not alter what componentize may do.
COMPONENTIZE_STRIPPED_NAMES = frozenset({
    'HERMES_YOLO_MODE',
    'HERMES_EXEC_ASK',
    'HERMES_INTERACTIVE',
    'HERMES_NONINTERACTIVE',  # hermes_cli/setup.py:284: skips prompt_yes_no and returns default=True; stdin=DEVNULL already handles EOF without advertising dashboard-spawned action context.
    'HERMES_QUIET',
    'HERMES_SPINNER_PAUSE',
    'HERMES_SINGLE_QUERY_SESSION',
    'HERMES_CRON_SESSION',
    'HERMES_GATEWAY_SESSION',
    '_HERMES_GATEWAY',
    'HERMES_ACP_AUTO_APPROVE',
    'HERMES_DELEGATED_CHILD_CONTEXT',
    'HERMES_UI_SESSION_ID',
    'HERMES_KANBAN_TASK',
    'HERMES_KANBAN_RUN_ID',
    'HERMES_KANBAN_CLAIM_LOCK',
    'HERMES_KANBAN_GOAL_MODE',
    'HERMES_KANBAN_GOAL_MAX_TURNS',
    'HERMES_ACCEPT_HOOKS',  # agent/shell_hooks.py:820: auto-approves unseen shell hooks.
    'HERMES_DASHBOARD_SESSION_TOKEN',  # hermes_cli/process_identity.py:398: per-spawn desktop backend credential.
    'HERMES_PLATFORM',  # tools/write_approval.py:216: platform override affecting write-approval staging surface.
    '_HERMES_CRON_EXTERNAL_WORKER',  # cron/scheduler.py:2816: external cron worker execution ownership marker.
    'HERMES_KANBAN_BOARD',  # hermes_cli/kanban_db.py:445: pins active kanban board slug.
    'HERMES_KANBAN_DB',  # hermes_cli/kanban_db.py:566: pins kanban.db file path across boards.
    'HERMES_KANBAN_HOME',  # hermes_cli/kanban_db.py:405: overrides root kanban directory.
    'SUDO_PASSWORD',  # tools/approval_detection.py:360: privileged-password variable / stdin guard bypass.
    'HERMES_ALLOW_PRIVATE_URLS',  # tools/url_safety.py:159: disables private-IP / localhost URL blocking.
})
COMPONENTIZE_STRIPPED_PREFIXES = (
    'HERMES_SESSION_',
    'HERMES_CRON_AUTO_DELIVER_',
)

# Template checks: every Hermes variable goes (no keep-list), plus privilege and askpass helpers.
CHECK_STRIPPED_PREFIXES = ('HERMES_', '_HERMES_')
CHECK_KEPT_HERMES_NAMES: frozenset[str] = frozenset()
CHECK_STRIPPED_NAMES = COMPONENTIZE_STRIPPED_NAMES | {'SUDO_PASSWORD', 'SUDO_ASKPASS', 'SSH_ASKPASS'}
CHECK_STRIPPED_SUFFIXES = ('ASKPASS',)
SECRET_NAME_RE = re.compile(r'(?i)(api[_-]?key|token|secret|password|passwd|credential|auth)')

CREDENTIALS_NOT_PASSED_NOTE = (
    "Note: template checks run without HERMES_* variables, privilege and askpass helpers, and "
    "variables whose names look like API keys, tokens, passwords, secrets, credentials or auth, "
    "so a check that needs a private-registry token from such a variable fails here. "
    "Credentials stored in tool configuration files on disk (for example a user-level npm or "
    "pip configuration) are not affected."
)


def _check_drops(name: str) -> bool:
    if name in CHECK_STRIPPED_NAMES:
        return True
    if name.startswith(COMPONENTIZE_STRIPPED_PREFIXES):
        return True
    if name.startswith(CHECK_STRIPPED_PREFIXES) and name not in CHECK_KEPT_HERMES_NAMES:
        return True
    if name.upper().endswith(CHECK_STRIPPED_SUFFIXES):
        return True
    return bool(SECRET_NAME_RE.search(name))


def stripped_child_env(
    base: Mapping[str, str] | None = None,
    *,
    extra_drop: Iterable[str] = (),
) -> dict[str, str]:
    """Return a copy of ``base`` (default ``os.environ``) safe for template check commands."""
    src = os.environ if base is None else base
    extra = frozenset(extra_drop)
    return {k: v for k, v in src.items() if k not in extra and not _check_drops(k)}
