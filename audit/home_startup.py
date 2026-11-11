"""Bounded discovery of implicit inputs in the audited HOME, never process HOME."""
import os
import re

from .file_types import SHELL_STARTUP_FILES


def discover(home, directory_fd, issue, *, unbounded=False):
    remaining = None if unbounded else 10000

    def entries(root):
        nonlocal remaining
        try:
            with directory_fd(root) as fd:
                with os.scandir(fd) as rows:
                    for row in rows:
                        if remaining is not None:
                            if remaining <= 0:
                                issue('entry_limit_exceeded: ' + str(root))
                                return
                            remaining -= 1
                        yield row.name
        except FileNotFoundError:
            pass
        except OSError:
            issue('home_startup_discovery_failed: ' + str(root))

    for name in (*SHELL_STARTUP_FILES, '.npmrc',
                 '.cargo/config.toml', '.pythonrc', '.netrc', '.pgpass',
                 '.git-credentials', '.docker/config.json',
                 '.config/pip/pip.conf', '.pip/pip.conf',
                 'Library/Application Support/pip/pip.conf'):
        yield home / name
    # Systemd unit drop-ins and wants links are visited under the normal tree
    # budgets. No other .config directories are implicitly authorized.
    yield home / '.config/systemd/user'
    root = home / '.config/autostart'
    for name in entries(root):
        if name.endswith('.desktop'):
            yield root / name
    lib = home / '.local/lib'
    for version in entries(lib):
        if not re.fullmatch(r'python\d+\.\d+[a-z]*', version):
            continue
        site = lib / version / 'site-packages'
        for name in entries(site):
            if name in {'sitecustomize.py', 'usercustomize.py'} or name.endswith('.pth'):
                yield site / name
    # macOS framework Python keeps the user site in ~/Library/Python/X.Y.
    lib = home / 'Library/Python'
    for version in entries(lib):
        if not re.fullmatch(r'\d+\.\d+', version):
            continue
        site = lib / version / 'lib/python/site-packages'
        for name in entries(site):
            if name in {'sitecustomize.py', 'usercustomize.py'} or name.endswith('.pth'):
                yield site / name
