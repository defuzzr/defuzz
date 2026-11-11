"""Bounded, read-only file listing for explicitly opened existing projects.

This is deliberately narrower than a general file browser:

* A project must already be a registration in the active Hermes profile.
* The root must pass :func:`defuzz.safety.assert_safe_root`, must not be a
  symlink and must not change identity while the registration is verified.
* Traversal is descriptor-relative with ``O_NOFOLLOW | O_DIRECTORY``, so no
  component below the root can be a symlink and nothing outside the root is
  reachable.  Symlinks, special files, credential paths and dependency/cache
  directories are omitted.
* Only names are returned.  File content is never opened, read, hashed or
  keyed, and no state file is written.
* Resource use is bounded: at most ``MAX_RETURNED`` files are returned, at
  most ``MAX_SCANNED`` directory entries are inspected and directories deeper
  than ``MAX_DEPTH`` are not entered.  A cut is reported through
  ``truncated``/``omitted``; an I/O or containment failure degrades
  ``coverage`` to ``could_not_verify`` instead of looking like a clean empty
  tree.
"""
from __future__ import annotations

import os
import stat
from typing import Any

from .audit import policy
from .audit.fingerprint import (
    ContainmentUnsupportedError,
    _open_root_dir_fd,
    _require_containment_support,
)
from .audit.readonly_db import read_profile_registrations_readonly
from .safety import SafetyError, assert_safe_root

__all__ = ["list_project_files", "MAX_RETURNED", "MAX_SCANNED", "MAX_DEPTH"]

MAX_RETURNED = 1000
MAX_SCANNED = 5000
MAX_DEPTH = 12

# Names that hold installed third-party packages, VCS metadata or regenerable
# build/tool output rather than the project's own files.  Compared casefolded.
_EXCLUDED_DIRECTORIES = frozenset(name.casefold() for name in {
    ".git", ".hg", ".svn", ".bzr",
    "node_modules", "bower_components", "jspm_packages", "vendor",
    "site-packages", "__pycache__",
    ".venv", "venv", "virtualenv", ".tox", ".nox", ".eggs",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".pyre", ".pytype", ".hypothesis",
    ".cache", ".next", ".nuxt", ".svelte-kit", ".parcel-cache", ".turbo",
    "target", "dist", "build", "coverage", "htmlcov", ".coverage",
    ".gradle", ".terraform", "cmake-build-debug", "cmake-build-release",
})


def _validated_root(project: Any) -> tuple[str, os.stat_result]:
    """Validate a literal absolute project folder and return (canonical, lstat)."""
    if not isinstance(project, (str, os.PathLike)):
        raise SafetyError("project must be a string path")
    try:
        raw = os.fspath(project)
    except TypeError as exc:
        raise SafetyError("project must be a string path") from exc
    if not isinstance(raw, str) or not raw.strip():
        raise SafetyError("project must be a non-empty string path")
    if "\x00" in raw:
        raise SafetyError("project path must not contain NUL")
    if not os.path.isabs(raw):
        raise SafetyError(f"project path must be absolute: {raw!r}")

    assert_safe_root(raw, role="workspace tree root")
    # Check the spelling supplied by the caller before resolving anything: a
    # symlink at the root is refused even when its target is registered.
    try:
        supplied = os.lstat(raw)
    except FileNotFoundError as exc:
        raise SafetyError(f"project is not an existing directory: {raw}") from exc
    except OSError as exc:
        raise SafetyError(f"project cannot be inspected: {raw}") from exc
    if stat.S_ISLNK(supplied.st_mode):
        raise SafetyError(f"project root must not be a symlink: {raw}")
    if not stat.S_ISDIR(supplied.st_mode):
        raise SafetyError(f"project root is not a directory: {raw}")

    canonical = os.path.realpath(raw)
    try:
        info = os.lstat(canonical)
    except OSError as exc:
        raise SafetyError(f"project cannot be inspected: {raw}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise SafetyError(f"project root must not be a symlink: {raw}")
    if not stat.S_ISDIR(info.st_mode):
        raise SafetyError(f"project root is not a directory: {raw}")
    if _identity(info) != _identity(supplied):
        raise SafetyError("Project changed while its root was validated")
    return canonical, info


def _identity(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _assert_active_registration(canonical: str, before: os.stat_result) -> None:
    """Require a verified, unchanged active-profile registration for ``canonical``."""
    try:
        from hermes_constants import get_hermes_home

        snapshot = read_profile_registrations_readonly("active", get_hermes_home())
    except Exception as exc:
        raise SafetyError("Active-profile registrations could not be verified") from exc

    if getattr(snapshot, "coverage", None) != "verified" or getattr(
        snapshot, "changed_during_read", True
    ):
        raise SafetyError("Active-profile registrations could not be verified")
    records = getattr(snapshot, "records", None) or ()
    registered = {
        record.get("canonical_path")
        for record in records
        if isinstance(record, dict)
    }
    if canonical not in registered:
        raise SafetyError(f"Project is not registered in the active profile: {canonical}")

    try:
        after = os.lstat(canonical)
    except OSError as exc:
        raise SafetyError("Project changed while its registration was verified") from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISDIR(after.st_mode)
        or _identity(after) != _identity(before)
    ):
        raise SafetyError("Project changed while its registration was verified")


def list_project_files(project: Any) -> dict[str, Any]:
    """List regular file names under one registered project folder.

    ``files`` holds sorted POSIX-style relative paths.  ``truncated`` is true
    when a bound, depth cut or I/O/containment failure means the listing is not
    complete.  ``omitted`` counts safe regular files found after ``MAX_RETURNED``
    within the scan budget.  ``coverage`` is ``verified`` only when traversal
    completed without an unresolved I/O or containment failure.
    """
    canonical, before = _validated_root(project)
    _assert_active_registration(canonical, before)
    if policy.credential_path(canonical):
        raise SafetyError("project root is a credential path")

    files: list[str] = []
    scanned = 0
    omitted = 0
    truncated = False
    coverage = "verified"

    def degrade() -> None:
        nonlocal coverage, truncated
        coverage = "could_not_verify"
        truncated = True

    try:
        o_nofollow, o_nonblock, o_directory = _require_containment_support()

        def walk(dir_fd: int, parts: tuple[str, ...], depth: int) -> None:
            nonlocal scanned, omitted, truncated
            try:
                with os.scandir(dir_fd) as entries:
                    batch = []
                    for entry in entries:
                        if scanned >= MAX_SCANNED:
                            truncated = True
                            break
                        scanned += 1
                        batch.append(entry)
                    ordered = sorted(batch, key=lambda entry: entry.name)
            except OSError:
                degrade()
                return

            for entry in ordered:
                name = entry.name
                try:
                    name.encode("utf-8")
                except UnicodeEncodeError:
                    degrade()
                    continue
                if not name or "/" in name or "\\" in name:
                    degrade()
                    continue
                child = parts + (name,)
                full_path = os.path.join(canonical, *child)

                # Same read boundary as the audit: path names only, no content.
                try:
                    if policy.credential_path(full_path):
                        continue
                except Exception:
                    degrade()
                    continue

                try:
                    info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                except OSError:
                    degrade()
                    continue

                if stat.S_ISLNK(info.st_mode):
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if name.casefold() in _EXCLUDED_DIRECTORIES:
                        continue
                    if depth + 1 >= MAX_DEPTH or scanned >= MAX_SCANNED:
                        truncated = True
                        continue
                    try:
                        sub_fd = os.open(
                            name,
                            os.O_RDONLY | o_nofollow | o_nonblock | o_directory,
                            dir_fd=dir_fd,
                        )
                    except OSError:
                        degrade()
                        continue
                    try:
                        opened = os.fstat(sub_fd)
                        if (
                            not stat.S_ISDIR(opened.st_mode)
                            or _identity(opened) != _identity(info)
                        ):
                            degrade()
                            continue
                        walk(sub_fd, child, depth + 1)
                    finally:
                        os.close(sub_fd)
                elif stat.S_ISREG(info.st_mode):
                    if len(files) < MAX_RETURNED:
                        files.append("/".join(child))
                    else:
                        omitted += 1
                        truncated = True
                # FIFOs, sockets and devices are never opened or returned.

        with _open_root_dir_fd(canonical) as (root_fd, _, _):
            opened = os.fstat(root_fd)
            if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(before):
                degrade()
            else:
                walk(root_fd, (), 0)
    except (ContainmentUnsupportedError, OSError):
        degrade()

    files.sort()
    return {
        "project": canonical,
        "files": files,
        "truncated": truncated,
        "coverage": coverage,
        "omitted": omitted,
    }
