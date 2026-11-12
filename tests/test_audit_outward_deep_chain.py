"""The outward walk measures deep folder chains without running out of call stack.

A folder chain deeper than Python's recursion limit used to raise RecursionError out
of ``collect_outward(..., unbounded=True)`` (491 nested folders were enough) and crash
the whole audit. Unbounded mode must walk such a chain to its leaf; bounded mode still
stops at MAX_DEPTH and reports ``depth_limit_exceeded``. The same holds for a chain of
followed edges (each folder links or refers to the next one): a few hundred hops used
to crash too. An interrupt that lands while the walk is suspended deep in such a chain
must unwind it at once, closing every folder descriptor before the exception is seen.

The chain is built, audited and removed in a child interpreter with a hard timeout:
the suite's real-home tripwire resolves every audited path with ``realpath``, which
costs time quadratic in the chain depth, and the chain's paths pass PATH_MAX. The
child loads the package from this checkout without importing the test package, so it
runs without that hook; HOME and friends are the isolated test values it inherits.
"""
import json
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPTH = 3000
# The unbounded audit of the deep chain takes about 90 s on an idle machine: the
# per-entry credential check (audit/policy.py credential_verdict) builds every parent
# path of every entry, which is cubic in the chain depth. The timeout leaves room for
# a loaded test machine; it guards against a hang, not against that cost.
HARD_TIMEOUT_S = 600

_CHILD = textwrap.dedent(
    """
    import importlib
    import importlib.util
    import json
    import os
    import sys
    import types
    from pathlib import Path

    repo, work, depth = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
    namespace = types.ModuleType('hermes_plugins')
    namespace.__path__ = []
    sys.modules['hermes_plugins'] = namespace
    spec = importlib.util.spec_from_file_location(
        'hermes_plugins.defuzz', repo / '__init__.py', submodule_search_locations=[str(repo)])
    package = importlib.util.module_from_spec(spec)
    sys.modules['hermes_plugins.defuzz'] = package
    spec.loader.exec_module(package)
    outward = importlib.import_module('hermes_plugins.defuzz.audit.outward')

    def chain(root, depth):
        # root/.git (parent-context boundary), root/d/d/.../d/leaf.txt through descriptors.
        (root / '.git').mkdir(parents=True)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for _ in range(depth):
                os.mkdir('d', dir_fd=fd)
                child = os.open('d', os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = child
            leaf = os.open('leaf.txt', os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=fd)
            os.write(leaf, b'plain notes\\n')
            os.close(leaf)
        finally:
            os.close(fd)

    def remove_chain(root):
        fds = [os.open(root, os.O_RDONLY | os.O_DIRECTORY)]
        try:
            while True:
                try:
                    fds.append(os.open('d', os.O_RDONLY | os.O_DIRECTORY, dir_fd=fds[-1]))
                except FileNotFoundError:
                    break
            for name in os.listdir(fds[-1]):
                os.unlink(name, dir_fd=fds[-1])
            while len(fds) > 1:
                os.close(fds.pop())
                os.rmdir('d', dir_fd=fds[-1])
        finally:
            for fd in fds:
                os.close(fd)

    profile = work / 'home' / '.hermes'
    profile.mkdir(parents=True)
    deep, shallow = work / 'deep', work / 'shallow'
    report = {'recursion_limit': sys.getrecursionlimit(), 'max_depth': outward.MAX_DEPTH}
    try:
        chain(deep, depth)
        chain(shallow, 0)
        for mode in (True, False):
            for name, project in (('deep', deep), ('shallow', shallow)):
                result = outward.collect_outward(profile, [str(project)], unbounded=mode)
                budget = result['limits']['regions'][str(project)]
                report[('unbounded ' if mode else 'bounded ') + name] = {
                    'entries_inspected': budget['entries_inspected'],
                    'bytes_read': budget['bytes_read'],
                    'stream_hashed_files': budget['stream_hashed_files'],
                    'max_depth': result['limits']['max_depth'],
                    'coverage': result['regions']['project_tree']['coverage'],
                    'codes': sorted(d['code'] for d in result['regions']['project_tree'].get('reason_details', [])),
                }
    finally:
        remove_chain(deep)
    print(json.dumps(report))
    """
)


def _audit_chains(tmp_path):
    completed = subprocess.run(
        [sys.executable, '-B', '-c', _CHILD, str(REPO_ROOT), str(tmp_path), str(DEPTH)],
        capture_output=True, text=True, timeout=HARD_TIMEOUT_S)
    assert completed.returncode == 0, completed.stderr[-3000:]
    return json.loads(completed.stdout)


def test_deep_folder_chain_is_walked_whole_unbounded_and_cut_at_max_depth_bounded(tmp_path):
    report = _audit_chains(tmp_path)
    assert report['recursion_limit'] < DEPTH

    deep, twin = report['unbounded deep'], report['unbounded shallow']
    # Every chain folder was measured, and the leaf file at the bottom was read.
    assert deep['entries_inspected'] - twin['entries_inspected'] == DEPTH
    assert deep['bytes_read'] == twin['bytes_read']
    assert deep['stream_hashed_files'] == twin['stream_hashed_files']
    assert deep['max_depth'] is None
    assert deep['codes'] == twin['codes']
    assert 'depth_limit_exceeded' not in deep['codes']

    deep, twin = report['bounded deep'], report['bounded shallow']
    # The project folder and MAX_DEPTH chain folders; the leaf is never reached.
    assert deep['entries_inspected'] - twin['entries_inspected'] == report['max_depth'] - 1
    assert deep['stream_hashed_files'] == twin['stream_hashed_files'] - 1
    assert deep['max_depth'] == report['max_depth']
    assert 'depth_limit_exceeded' in deep['codes']
    assert 'depth_limit_exceeded' not in twin['codes']
    assert deep['coverage'] == 'could_not_verify'


# Followed-edge chains: every hop is a top-level folder, so the per-entry credential
# check stays cheap and these chains take a few seconds; the timeout guards a hang.
HOPS = 2500
EDGE_TIMEOUT_S = 300
# The walk driver's functions in audit/outward.py: an interrupt is injected on the Nth
# line they run, which is where an asynchronous KeyboardInterrupt can land outside any visit.
DRIVER_FUNCTIONS = ('visit', 'resume')

_LOADER = _CHILD.split("def chain(root, depth):")[0]

_EDGE_CHILD = _LOADER + textwrap.dedent(
    """
    def symlink_hops(root, hops):
        for i in range(hops + 1):
            (root / ('h%d' % i)).mkdir(parents=True)
        for i in range(hops):
            (root / ('h%d' % i) / 'next').symlink_to(root / ('h%d' % (i + 1)), target_is_directory=True)
        (root / ('h%d' % hops) / 'end.txt').write_text('end notes\\n')
        return root / 'h0'

    def reference_hops(root, hops):
        for i in range(hops + 1):
            (root / ('r%d' % i)).mkdir(parents=True)
            dependencies = {'next': 'file:../r%d' % (i + 1)} if i < hops else {}
            (root / ('r%d' % i) / 'package.json').write_text(json.dumps({'name': 'r%d' % i, 'dependencies': dependencies}))
        (root / ('r%d' % hops) / 'end.txt').write_text('end notes\\n')
        return root / 'r0'

    profile = work / 'home' / '.hermes'
    profile.mkdir(parents=True)
    report = {'recursion_limit': sys.getrecursionlimit(), 'max_depth': outward.MAX_DEPTH}
    for kind, build in (('symlink', symlink_hops), ('reference', reference_hops)):
        for name, hops in (('deep', depth), ('shallow', 0)):
            project = work / kind / name / 'project'
            (project / '.git').mkdir(parents=True)
            first = build(work / kind / name / 'hops', hops)
            if kind == 'symlink':
                (project / 'tohops').symlink_to(first, target_is_directory=True)
            else:
                (project / 'package.json').write_text(json.dumps({'name': 'p', 'dependencies': {'first': 'file:' + str(first)}}))
            last = str(first.parent / (first.name[0] + str(hops)))
            for mode in (True, False):
                result = outward.collect_outward(profile, [str(project)], unbounded=mode)
                budget = result['limits']['regions'][str(project)]
                report['%s %s %s' % (kind, 'unbounded' if mode else 'bounded', name)] = {
                    'entries_inspected': budget['entries_inspected'],
                    'bytes_read': budget['bytes_read'],
                    'stream_hashed_files': budget['stream_hashed_files'],
                    'last_reached': any(e['target'] == last for e in result['blending']),
                    'codes': sorted({d['code'] for region in result['regions'].values()
                                     for d in region.get('reason_details', [])}),
                }
    print(json.dumps(report))
    """
)


def test_deep_followed_edge_chains_are_walked_whole_unbounded(tmp_path):
    completed = subprocess.run(
        [sys.executable, '-B', '-c', _EDGE_CHILD, str(REPO_ROOT), str(tmp_path), str(HOPS)],
        capture_output=True, text=True, timeout=EDGE_TIMEOUT_S)
    assert completed.returncode == 0, completed.stderr[-3000:]
    report = json.loads(completed.stdout)
    assert report['recursion_limit'] < HOPS

    for kind, per_hop in (('symlink', 2), ('reference', 2)):
        deep, twin = report[kind + ' unbounded deep'], report[kind + ' unbounded shallow']
        # Every hop's folder (and its link or manifest) was measured, and the last hop was reached.
        assert deep['entries_inspected'] - twin['entries_inspected'] == per_hop * HOPS, kind
        assert deep['last_reached'] and twin['last_reached'], kind
        assert 'depth_limit_exceeded' not in deep['codes'], kind

        deep = report[kind + ' bounded deep']
        # Bounded mode still stops the chain at MAX_DEPTH.
        assert not deep['last_reached'], kind
        assert 'depth_limit_exceeded' in deep['codes'], kind


_INTERRUPT_CHILD = _LOADER + textwrap.dedent(
    """
    import gc

    root = work / 'project'
    (root / '.git').mkdir(parents=True)
    folder = root
    for _ in range(depth):
        folder = folder / 'd'
    folder.mkdir(parents=True)
    (folder / 'leaf.txt').write_text('plain notes\\n')
    hops = work / 'hops'
    for i in range(depth + 1):
        (hops / ('h%d' % i)).mkdir(parents=True)
    for i in range(depth):
        (hops / ('h%d' % i) / 'next').symlink_to(hops / ('h%d' % (i + 1)), target_is_directory=True)
    (root / 'tohops').symlink_to(hops / 'h0', target_is_directory=True)
    profile = work / 'home' / '.hermes'
    profile.mkdir(parents=True)
    source = os.path.abspath(outward.__file__)
    driver = set(sys.argv[6].split(','))

    def open_fds():
        return len(os.listdir('/proc/self/fd'))

    def suspended():
        return sum(1 for o in gc.get_objects() if type(o).__name__ == 'generator'
                   and o.gi_code.co_filename == source and o.gi_frame is not None)

    outcomes = []
    for target in range(int(sys.argv[4]), int(sys.argv[5])):
        hits, landed = [0], []

        def local(frame, event, arg):
            # Interrupt lands on the Nth line the walk driver runs, wherever that is.
            if event == 'line':
                hits[0] += 1
                if hits[0] == target:
                    landed.append(frame.f_code.co_name)
                    raise KeyboardInterrupt('injected')
            return local

        def trace(frame, event, arg):
            if frame.f_code.co_name in driver and frame.f_code.co_filename == source:
                return local
            return None

        before = open_fds()
        sys.settrace(trace)
        try:
            outward.collect_outward(profile, [str(root)], unbounded=True)
            outcome = {'target': target, 'raised': False}
        except KeyboardInterrupt as exc:
            sys.settrace(None)
            # Still holding the exception (and with it the walk's frames): nothing may be open.
            outcome = {'target': target, 'raised': True, 'landed': landed, 'type': type(exc).__name__, 'message': str(exc),
                       'cause': repr(exc.__cause__), 'context': repr(exc.__context__),
                       'open_fds': open_fds() - before, 'suspended_generators': suspended()}
        finally:
            sys.settrace(None)
        outcomes.append(outcome)
    print(json.dumps(outcomes))
    """
)


def _interrupt_outcomes(child, tmp_path, first, last):
    completed = subprocess.run(
        [sys.executable, '-B', '-c', child, str(REPO_ROOT), str(tmp_path), '40', str(first), str(last),
         ','.join(DRIVER_FUNCTIONS)],
        capture_output=True, text=True, timeout=EDGE_TIMEOUT_S)
    assert completed.returncode == 0, completed.stderr[-3000:]
    outcomes = json.loads(completed.stdout)
    assert len(outcomes) == last - first
    # Configuration sanity: the interrupts landed in the walk driver at all.
    assert any(outcome.get('landed') for outcome in outcomes)
    return outcomes


def test_interrupt_in_walk_driver_closes_every_suspended_folder_at_once(tmp_path):
    for outcome in _interrupt_outcomes(_INTERRUPT_CHILD, tmp_path, 300, 340):
        # Still holding the interrupt: every folder descriptor is closed, no visit is left
        # suspended, and the interrupt is the one injected, unchanged.
        assert outcome['raised'], outcome
        assert (outcome['type'], outcome['message'], outcome['cause']) == ('KeyboardInterrupt', 'injected', 'None'), outcome
        assert (outcome['open_fds'], outcome['suspended_generators']) == (0, 0), outcome


# Every folder listing's close raises once armed, as a suspended visit's cleanup might
# while it unwinds (a second interrupt, a failing close). The interrupt is armed at the
# same moment, so the driver has to close every suspended visit despite those failures.
def _patched(text, *replacements):
    for old, new in replacements:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    return text


_CLOSE_RAISES_CHILD = _patched(
    _INTERRUPT_CHILD,
    ("\noutcomes = []\n", textwrap.dedent(
        """
        armed, close_failures = [False], [0]
        real_os = outward.os

        class FailingClose:
            def __init__(self, fd):
                self.entries = real_os.scandir(fd)

            def __enter__(self):
                self.entries.__enter__()
                return self

            def __iter__(self):
                return iter(self.entries)

            def __exit__(self, *exc_info):
                self.entries.__exit__(*exc_info)
                if armed[0]:
                    close_failures[0] += 1
                    raise RuntimeError('close-fail')

        failing_os = types.ModuleType('failing_os')
        failing_os.__dict__.update(real_os.__dict__)
        failing_os.scandir = FailingClose
        outward.os = failing_os
        outcomes = []
        """)),
    ("landed.append(frame.f_code.co_name)\n", "landed.append(frame.f_code.co_name)\n                armed[0] = True\n"),
    # Whatever propagates is reported, so a close failure replacing the interrupt shows.
    ("except KeyboardInterrupt as exc:", "except BaseException as exc:"),
    ("    outcomes.append(outcome)\n",
     "    armed[0] = False\n    outcome['close_failures'], close_failures[0] = close_failures[0], 0\n    outcomes.append(outcome)\n"),
)


def test_interrupt_in_walk_driver_closes_every_suspended_folder_even_when_closes_raise(tmp_path):
    outcomes = _interrupt_outcomes(_CLOSE_RAISES_CHILD, tmp_path, 300, 340)
    # Several suspended listings failed to close each time, so later closes had to go on.
    assert all(outcome['close_failures'] > 1 for outcome in outcomes), outcomes
    for outcome in outcomes:
        # The interrupt still propagates unchanged, and nothing stays open behind it.
        assert outcome['raised'], outcome
        assert (outcome['type'], outcome['message'], outcome['cause']) == ('KeyboardInterrupt', 'injected', 'None'), outcome
        assert (outcome['open_fds'], outcome['suspended_generators']) == (0, 0), outcome
