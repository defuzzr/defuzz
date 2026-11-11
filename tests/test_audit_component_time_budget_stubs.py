"""Component stubs run inside the bounded child by the time-budget tests.

Kept free of tests.conftest and other test imports: the child imports this
module by name, and nothing here may need the test session's set-up. Secret
values are obviously synthetic and assembled at run time.
"""
from __future__ import annotations

import os
import signal
import time
from pathlib import Path


def secret(tag: str = 'RAISE') -> str:
    return 'INERT' + '-TB-' + tag


def spin(**kwargs):
    while True:
        pass


def regex(**kwargs):
    import re
    # Catastrophic backtracking. Built here so the pattern is not a product constant.
    re.match('(?:' + 'a+' + ')+' + '$', 'a' * 40 + '!')


def sleep(**kwargs):
    time.sleep(30)


def _name_me(token):
    import ctypes
    ctypes.CDLL(None).prctl(15, token.encode(), 0, 0, 0)  # PR_SET_NAME


def grandchildren(token, **kwargs):
    # One grandchild stays in the group; one leaves it with setsid and forks again.
    if os.fork() == 0:
        _name_me(token)
        time.sleep(60)
        os._exit(0)
    if os.fork() == 0:
        os.setsid()
        if os.fork() == 0:
            _name_me(token)
            time.sleep(60)
            os._exit(0)
        _name_me(token)
        time.sleep(60)
        os._exit(0)
    time.sleep(60)


def daemon_then_return(token, **kwargs):
    if os.fork() == 0:
        os.setsid()
        _name_me(token)
        time.sleep(60)
        os._exit(0)
    return {'findings': [], 'coverage': 'verified', 'status': 'pass'}


def exit_late_on_term(**kwargs):
    # Asks for the grace period: exits with a known code a little after SIGTERM.
    def handler(*_args):
        time.sleep(0.03)
        os._exit(7)
    signal.signal(signal.SIGTERM, handler)
    time.sleep(30)


def _sleeper(token, detach):
    if os.fork() == 0:
        if detach:
            os.setsid()
        _name_me(token)
        time.sleep(60)
        os._exit(0)


def group_child(token, **kwargs):
    _sleeper(token, detach=False)
    time.sleep(30)


def setsid_child(token, **kwargs):
    _sleeper(token, detach=True)
    time.sleep(30)


def stubborn_tree(token, **kwargs):
    # Everything ignores SIGTERM, so the whole tree is still in place when the
    # parent walks it: one child in the group, one that left it and forked again.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    _sleeper(token, detach=False)
    if os.fork() == 0:
        os.setsid()
        _sleeper(token, detach=False)
        _name_me(token)
        time.sleep(60)
        os._exit(0)
    time.sleep(30)


def huge(**kwargs):
    return {'blob': b'x' * (200 * 1024 * 1024)}


def signalled(**kwargs):
    os.kill(os.getpid(), signal.SIGKILL)


def exit_nonzero(**kwargs):
    os._exit(3)


def system_exit_secret(**kwargs):
    raise SystemExit(secret())


class Opaque:
    pass


def unreadable(**kwargs):
    return {'value': Opaque()}


def raise_secret(**kwargs):
    raise RuntimeError(secret())


def write_file(target, **kwargs):
    Path(target).write_text('written')
    return {'findings': [], 'coverage': 'verified', 'status': 'pass'}


def echo(**kwargs):
    return {'findings': [], 'coverage': 'verified', 'status': 'pass', 'marker': kwargs.get('marker', 'ok')}


# ----- state-crossing probes

def is_credential(path):
    from hermes_plugins.defuzz.audit.policy import credential_path
    return {'credential': credential_path(path)}


def declare(path, skipped):
    from hermes_plugins.defuzz.audit.policy import declare_credential, note_credential_skip
    from hermes_plugins.defuzz.audit.redaction import observe_value
    declare_credential(path)
    note_credential_skip(skipped)
    observe_value({'api_key': secret('CHILD-7f3a9c')})
    return {'ok': True}


def forget(path):
    from hermes_plugins.defuzz.audit.redaction import _CURRENT
    _CURRENT.get().credential_paths.discard(os.path.abspath(path))
    return {'ok': True}


def seal(value):
    from hermes_plugins.defuzz.audit.evidence import serialize_evidence
    return serialize_evidence({'provider': value})


def taint_values():
    from hermes_plugins.defuzz.audit.redaction import _CURRENT
    state = _CURRENT.get()
    return None if state is None else sorted(state.values)


def key_bytes():
    from hermes_plugins.defuzz.audit.key import _CURRENT_KEY_BYTES
    return _CURRENT_KEY_BYTES.get()


def session_limit():
    from hermes_plugins.defuzz.audit import session_contamination
    return session_contamination.MAX_MESSAGES


def _memory_finding(observe):
    from hermes_plugins.defuzz.audit.contract import make_component_envelope, make_finding
    from hermes_plugins.defuzz.audit.redaction import observe_value
    value = secret('SEAL-7f3a9c')
    memory_file = str(Path(os.environ['HERMES_HOME']) / 'memories' / 'MEMORY.md')
    if observe:
        # A credential-shaped assignment whose value is also a reported path:
        # the parent's sealing must treat that path as tainted.
        observe_value({'api_key': value, 'token': memory_file})
    finding = make_finding(rule_id='memory.unverified', classification='review_suggested',
                           coverage='could_not_verify', affected_identities=['default'],
                           source_paths=[memory_file],
                           consequence='Profile memory check could not be verified.',
                           evidence={'note': f'value {value} seen', 'path': memory_file})
    return make_component_envelope(coverage='could_not_verify', findings=[finding])


def memory_observing(**kwargs):
    return _memory_finding(True)


def memory_not_observing(**kwargs):
    return _memory_finding(False)


def forged_length(**kwargs):
    # A hostile child: announce a 1 TiB reply straight on every pipe it holds,
    # bypassing the worker's own size check, then stall.
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd <= 2:
            continue
        try:
            if os.readlink(f'/proc/self/fd/{fd}').startswith('pipe:'):
                os.write(fd, (1 << 40).to_bytes(8, 'big'))
        except OSError:
            continue
    time.sleep(30)


def environment(name):
    return {'value': os.environ.get(name), 'cwd': os.getcwd()}


def bound_name():
    from hermes_plugins.defuzz.audit import context_load
    return context_load.unverified_context_load.__name__
