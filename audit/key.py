"""Private durable audit key; never part of evidence or a database DTO."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat

from .evidence import generated_digest

_CURRENT_KEY_PATH: ContextVar[Path | None] = ContextVar('audit_key_path', default=None)
_CURRENT_KEY_BYTES: ContextVar[bytes | None] = ContextVar('audit_key_bytes', default=None)


class AuditKeyUnavailable(OSError):
    """Closed key failure: never expose underlying path or error text."""


def key_path(db_path):
    return Path(db_path).parent / 'audit.key'


@contextmanager
def key_scope(db_path):
    path = key_path(db_path).absolute()
    if _CURRENT_KEY_PATH.get() == path and _CURRENT_KEY_BYTES.get() is not None:
        yield
        return
    token, key_token = _CURRENT_KEY_PATH.set(path), _CURRENT_KEY_BYTES.set(None)
    try:
        _CURRENT_KEY_BYTES.set(_load_key())
        yield
    finally:
        _CURRENT_KEY_BYTES.reset(key_token)
        _CURRENT_KEY_PATH.reset(token)


@contextmanager
def key_location_scope(db_path):
    """Point key lookups at this store's key WITHOUT loading it.

    The key is read (or created) only if a digest is actually computed inside the
    scope, so opening a store never fails just because its key is unavailable.
    """
    path = key_path(db_path).absolute()
    if _CURRENT_KEY_PATH.get() == path:
        yield
        return
    token, key_token = _CURRENT_KEY_PATH.set(path), _CURRENT_KEY_BYTES.set(None)
    try:
        yield
    finally:
        _CURRENT_KEY_BYTES.reset(key_token)
        _CURRENT_KEY_PATH.reset(token)


def using_store_key(fn):
    @wraps(fn)
    def wrapped(store, *args, **kwargs):
        with key_scope(store.db_path):
            return fn(store, *args, **kwargs)
    return wrapped


def private_paths():
    path = _CURRENT_KEY_PATH.get()
    if path is None:
        from hermes_constants import get_hermes_home
        path = Path(get_hermes_home()) / 'plugin-data' / 'defuzz' / 'audit.key'
    return (path.absolute(), Path(f'{path.absolute()}.lock'))


def _load_key():
    try:
        return _read_or_create_key()
    except OSError:
        raise AuditKeyUnavailable('audit_key_unavailable') from None


def _read_existing_key(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AuditKeyUnavailable('audit_key_unavailable')
        value = os.read(fd, 33)
        if len(value) == 32:
            os.fchmod(fd, 0o600)
            return value
    finally:
        os.close(fd)
    path.unlink()
    return None


def _read_or_create_key():
    if (cached := _CURRENT_KEY_BYTES.get()) is not None:
        return cached
    path, lock_path = private_paths()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if (existing := _read_existing_key(path)) is not None:
            return existing
        value = secrets.token_bytes(32)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, value)
            os.fsync(fd)
        finally:
            os.close(fd)
        return value
    finally:
        os.close(lock_fd)


def keyed_digest(value, *, domain):
    message = domain.encode('ascii') + b'\0' + value.encode('utf-8', errors='surrogatepass')
    return generated_digest(hmac.new(_load_key(), message, hashlib.sha256).hexdigest())


def content_digest(sha256):
    """Domain-separated HMAC of a content SHA-256, stable within this profile."""
    return keyed_digest(sha256, domain='content')
