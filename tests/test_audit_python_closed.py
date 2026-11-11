"""Synthetic inputs only: the classifier must never execute source."""
import importlib.util
from pathlib import Path

import pytest


def analyze(data):
    path = Path(__file__).parents[1] / 'audit' / 'outward_python.py'
    assert path.exists(), 'Python fail-closed classifier is missing'
    spec = importlib.util.spec_from_file_location('closed_python', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.analyze_python(data)


@pytest.mark.parametrize('source', [
    'import os\nos.execv("x", [])',
    'import os\nos.spawnlp(0, "x", "x")',
    'import os\nos.posix_spawn("x", [], {})',
    'import os\ngetattr(os, "system")("x")',
    'import pty\npty.spawn("x")',
    'import runpy\nrunpy.run_path("x")',
    'import ctypes\nctypes.CDLL(None).system("x")',
    'import multiprocessing\nmultiprocessing.Process(target=f)',
    'compile("x", "x", "exec")',
    'open("/other/config.yaml").read()',
])
def test_dangerous_calls(source):
    findings = analyze(source.encode())
    assert findings
    assert all(kind.endswith('_unresolved') and line > 0 for kind, line in findings)


@pytest.mark.parametrize('source', [
    'import os\nlen([1]); print("ok"); os.path.join("a", "b")',
    'import os.path as p\np.exists("x")',
    'from os import path\npath.basename("x")',
    'import os, json, re, typing, dataclasses\njson.loads("{}"); re.compile("x"); typing.cast(str, "x"); dataclasses.field()',
    'import os\nfrom pathlib import Path\np = Path("x")\np.read_text(); p.exists(); p.joinpath("y").read_bytes()',
])
def test_allowlisted_calls(source):
    assert analyze(source.encode()) == []


@pytest.mark.parametrize('source', [
    'f = eval\nf("x")',
    'import os as o\nf = o.system\nf("x")',
    'import os\nunknown()',
    'os.system("x")',
    'import os\nlist(map(os.system, ["x"]))',
    'f = eval\nlist(map(f, ["x"]))',
    'import os\nmatch thing:\n case {"x": len}:\n  len("x")',
    'import os\nlen = os.system\nlen("x")',
    'import os\ndef f(len):\n len("x")',
    'import os, json\njson.loads = os.system\njson.loads("x")',
    'import os\nfrom json import *\nloads("x")',
    'import cffi\nf = cffi.FFI()\nf.dlopen(None)',
    'import importlib\nimportlib.import_module("x")',
    'import arbitrary_plugin',
    'import os, re\nre.sub("x", os.system, "x")',
    'import os, re\nre.sub(pattern="x", repl=os.system, string="x")',
    'import os, dataclasses\ndataclasses.field(default_factory=os.system)',
])
def test_aliases_and_uncertain_calls(source):
    assert analyze(source.encode())


def test_parse_failure_and_encoding_are_closed():
    assert analyze(b'import os\n(') == [('python_parse_unresolved', 1)]
    assert analyze(b'\xff') == [('python_parse_unresolved', 1)]


def test_prefilter_skips_ast(monkeypatch):
    import ast
    def forbidden(*args, **kwargs):
        raise AssertionError('AST used for token-free text')
    monkeypatch.setattr(ast, 'parse', forbidden)
    assert analyze(b'x = 1\nprint(x)') == []


def test_results_are_deduplicated_ordered_and_do_not_retain_secrets():
    assert analyze(b'import os\nos.system("SECRET"); os.execv("SECRET", [])\nf()') == [
        ('python_call_unresolved', 2), ('python_call_unresolved', 3)]
