"""Command contracts established by real-tool failures in the matrix."""
from ..conftest import load_submodule


def test_real_output_argv_regressions(tmp_path):
    tools = load_submodule('lint_tools')
    specs = {s.name: s for s in tools.TOOLS}
    go = tools.argv(specs['golangci-lint'], 'post', tmp_path, ['main.go'])
    assert '--show-stats=false' in go  # Otherwise v2.15 appends text to JSON stdout.
    lua = tools.argv(specs['selene'], 'post', tmp_path, ['sample.lua'])
    assert lua[lua.index('--display-style') + 1].lower() == 'json2'
    assert '--no-summary' in lua  # Parser expects typed Diagnostic/Summary objects.
    ps = tools.argv(specs['pwsh-parse'], 'pre', tmp_path, ['sample.ps1'])[-1]
    assert ps.index('$e=$null') < ps.index('[ref]$e')
