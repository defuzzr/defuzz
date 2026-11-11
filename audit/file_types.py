"""Pure file-type gate. Classification is not execution or safety approval."""
from pathlib import Path
import re

from .outward_structured import classification

_ASSET_SUFFIXES = frozenset('''
.png .jpg .jpeg .gif .webp .ico .bmp .tif .tiff .avif .woff .woff2 .ttf .otf
.mp3 .wav .ogg .flac .mp4 .webm .mov .pdf .glb .gltf
'''.split())
_DOCUMENT_SUFFIXES = frozenset({'.md', '.mdc', '.rst', '.txt', '.adoc', '.csv', '.tsv', '.tmpl', '.css', '.scss', '.sass', '.svg'})
_DATA_NAMES = frozenset({'cargo.lock', 'uv.lock', 'poetry.lock', 'yarn.lock',
                         'gemfile.lock', 'pipfile.lock', 'composer.lock', 'bun.lock',
                         '.gitignore', '.gitattributes', '.editorconfig', '.worktreeinclude',
                         'codeowners', 'py.typed', '.nvmrc', '.python-version', '.node-version',
                         '.tool-versions', 'pyvenv.cfg', 'rust-toolchain.toml', 'rustfmt.toml', 'clippy.toml'})
_EXECUTABLE_MAGIC = (b'\x7fELF', b'MZ', b'\x00asm', b'\xfe\xed\xfa\xce',
                     b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
                     b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe')
_ENCODING_COOKIE = re.compile(br'^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)')

_CODE_SUFFIXES = frozenset('''
.py .pyw .pyi .js .jsx .mjs .cjs .ts .tsx .mts .cts .rs .go .c .h
.cc .cpp .cxx .hpp .hxx .m .mm .java .rb .sh .bash .zsh .fish .ps1
.psm1 .bat .cmd .php .lua .swift .kt .kts .cs .fs .fsx .vb .pl .pm
.ex .exs .erl .hrl .scala .sc .hs .lhs .clj .cljs .cljc .edn .vue
.svelte .sql .r .jl .dart .groovy .gradle .cmake .bzl .asm .s .v .sv
.vhd .vhdl .lisp .el .scm .rkt .tcl .awk .sed .html .htm .wasm
'''.split())


_LEGACY_CREDENTIAL_KINDS = {
    '.netrc': 'netrc',
    '.pgpass': 'pgpass',
    '.git-credentials': 'git',
    '.npmrc': 'npm',
    'pip.conf': 'pip',
}


def credential_file_kind(path: Path) -> str | None:
    """Path-only credential-store classification; never authorizes content reads."""
    from pathlib import PurePath
    from .secret_file_copies import (
        EXPECTED_SECRET_FILENAMES,
        HERMES_NON_SECRET_FILES,
        NON_STORE_SUFFIXES,
        _BACKUP_SUFFIX_RE,
        _STEM_BACKUP_INFIX_RE,
        _classify_lower_name,
        _is_excluded_example_or_public,
        _name_words,
    )

    p = PurePath(str(path))
    if not p.name:
        return None
    parts_low = tuple(part.lower() for part in p.parts)
    if any(len(parts_low) >= len(sub) and parts_low[-len(sub):] == sub for sub in HERMES_NON_SECRET_FILES):
        return None
    if len(parts_low) >= 2 and parts_low[-2:] == ('.docker', 'config.json'):
        return 'docker'
    if len(parts_low) >= 2 and parts_low[-2:] == ('webapp', 'session-token'):
        return 'platform_token_stores'

    low = p.name.lower()
    if low.startswith('._') and len(low) > 2:
        low = low[2:]
    if _is_excluded_example_or_public(low):
        return None
    legacy = _LEGACY_CREDENTIAL_KINDS.get(low)
    if legacy is not None:
        return legacy

    expected_names = frozenset(EXPECTED_SECRET_FILENAMES) | {'feishu_comment_pairing.json', 'nous_auth.json'}
    if low in expected_names:
        return EXPECTED_SECRET_FILENAMES.get(low, 'credential_store')
    if not low.endswith('.lock'):
        for exp_name in expected_names:
            if low.startswith(exp_name) and len(low) > len(exp_name):
                rest = low[len(exp_name):]
                if rest.startswith(('.', '~')) or _BACKUP_SUFFIX_RE.match(rest):
                    return EXPECTED_SECRET_FILENAMES.get(exp_name, 'credential_store')
            if '.' in exp_name and not exp_name.startswith('.'):
                stem, ext = exp_name.rsplit('.', 1)
                dot_ext = '.' + ext
                if low.startswith(stem) and low.endswith(dot_ext) and len(low) > len(stem) + len(dot_ext):
                    if _STEM_BACKUP_INFIX_RE.match(low[len(stem):-len(dot_ext)]):
                        return EXPECTED_SECRET_FILENAMES.get(exp_name, 'credential_store')

    cls = _classify_lower_name(low)
    if cls is not None:
        return cls
    if low.endswith(NON_STORE_SUFFIXES):
        return None
    if low.endswith('.json') and ('firebase-adminsdk' in low or 'firebase_adminsdk' in low):
        return 'firebase'
    if low in {'kubeconfig', '.kubeconfig'} or low.endswith('.kubeconfig') or low.startswith('kubeconfig.'):
        return 'kubeconfig'
    if low.endswith(('.tfvars', '.tfvars.json', '.tfstate')) or '.tfstate.' in low:
        return 'tfvars'
    if low.endswith('.key') and any(w in {'license', 'licence'} for w in _name_words(low[:-4])):
        return 'key'
    if low == 'token':
        return 'token'
    if low.startswith('id_') and '.' not in low:
        return 'ssh-key'
    if low.startswith('.env') and '.' not in low[1:] and not low.startswith('.envoy'):
        return 'dotenv'
    return None


# Shell startup files read from the audited HOME. One list for discovery
# (home_startup.py) and for the trigger below. zsh reads .zshenv in every shell,
# then .zprofile, .zshrc, .zlogin and, at exit, .zlogout; bash reads the first of
# .bash_profile, .bash_login, .profile, then .bashrc and, at exit, .bash_logout.
SHELL_STARTUP_FILES = ('.bashrc', '.profile', '.zshrc', '.bash_profile', '.zshenv',
                       '.zprofile', '.zlogin', '.zlogout', '.bash_login', '.bash_logout')


def execution_trigger(path: Path) -> str:
    """Return a descriptive path-based trigger, or an empty string.

    A trigger records how a surface may be consumed, not whether it is safe
    or whether execution will actually occur. No filesystem access is used.
    """
    name = path.name.lower()
    parts = tuple(part.lower() for part in path.parts)
    if name in SHELL_STARTUP_FILES or name == '.pythonrc':
        return 'user interpreter startup'
    if path.suffix.lower() == '.desktop' and 'autostart' in parts:
        return 'desktop autostart'
    if name in {'makefile', 'gnumakefile', 'cmakelists.txt', 'build', 'build.bazel',
                'rakefile', 'gemfile', 'vagrantfile', 'justfile', 'procfile',
                'setup.py', 'build.rs', 'noxfile.py', 'tox.ini', 'pyproject.toml',
                'cargo.toml', 'package.json', 'setup.cfg', 'entry_points.txt',
                '.justfile', 'containerfile', 'meson.build', 'meson_options.txt',
                'build.gradle', 'build.gradle.kts', 'settings.gradle', 'go.mod'} or name.startswith('dockerfile'):
        return 'build, install, or task runner'
    if name.startswith('requirements') and name.endswith('.txt'):
        return 'dependency installation'
    if name in {'.npmrc', '.env', '.envrc'} or name.startswith('.env.'):
        return 'environment or package-manager startup'
    if path.suffix.lower() == '.pth' or name in {'sitecustomize.py', 'usercustomize.py'}:
        return 'Python interpreter startup'
    if (('.github', 'workflows') in tuple(zip(parts, parts[1:])) or
            '.circleci' in parts or name in {'.gitlab-ci.yml', '.gitlab-ci.yaml',
                'jenkinsfile', '.travis.yml', 'azure-pipelines.yml'}):
        return 'CI workflow'
    if name in {'.pre-commit-config.yaml', '.pre-commit-config.yml',
                '.pre-commit-hooks.yaml', '.pre-commit-hooks.yml'} or (
            ('.git', 'hooks') in tuple(zip(parts, parts[1:]))):
        return 'version-control hook'
    if path.suffix.lower() == '.ipynb':
        return 'notebook kernel execution'
    if path.suffix.lower() == '.code-workspace':
        return 'editor workspace tasks or debugger launch'
    if '.vscode' in parts and name in {'tasks.json', 'launch.json'}:
        return 'editor task or debugger launch'
    if name in {'crontab', 'jobs.json'} or any(part in {
            'cron.d', 'cron.hourly', 'cron.daily', 'cron.weekly', 'cron.monthly'
            } for part in parts):
        return 'scheduled job'
    if name in {'hook.yaml', 'hook.yml'}:
        return 'registered hook'
    if '.cargo' in parts and name in {'config', 'config.toml'}:
        return 'Cargo aliases and toolchain configuration'
    if name in {'config.yaml', 'config.yml', 'config.json', 'plugin.yaml', 'plugin.yml',
                'plugin.json', 'manifest.json', 'hooks.json', 'settings.json', 'mcp.json',
                'pnpm-workspace.yaml'}:
        return 'application configuration load'
    if path.suffix.lower() in {'.service', '.timer', '.socket'}:
        return 'service manager activation'
    if 'hooks' in parts and path.suffix.lower() in {'.py', '.sh', '.js', '.ts'}:
        return 'hook handler load'
    if 'plugins' in parts and name == '__init__.py':
        return 'plugin import'
    return ''


def classify_file(path: Path, data: bytes) -> str:
    """Identify a file without filesystem reads or behavior analysis.

    Executable signatures win over data names. Unsupported text encodings
    fail closed; recognized binary assets and executables need not be UTF-8.
    Structured extensions alone never establish that a file is data.
    """
    suffix = path.suffix.lower()
    trigger = execution_trigger(path)
    if data.startswith(_EXECUTABLE_MAGIC):
        return 'execution_surface' if trigger else 'program_code'
    for line in data.split(b'\n', 2)[:2]:
        cookie = _ENCODING_COOKIE.match(line)
        if cookie and cookie[1].lower().replace(b'_', b'-') not in {
                b'utf-8', b'utf8', b'ascii', b'us-ascii'}:
            return 'unknown'
    text_signature = data.startswith((b'#!', b'<?php'))
    if suffix in _ASSET_SUFFIXES and not text_signature and not trigger:
        return 'data'
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        return 'unknown'
    if b'\x00' in data:
        return 'unknown'
    if trigger:
        return 'execution_surface'
    if text_signature or suffix in _CODE_SUFFIXES:
        return 'program_code'
    if classification(path) in {'data', 'fixture_data', 'jsonc_data', 'jsonc_config'}:
        return 'data'
    name = path.name.lower()
    if suffix in _DOCUMENT_SUFFIXES or name in _DATA_NAMES:
        return 'data'
    if name in {'readme', 'license', 'licence', 'copying', 'notice', 'authors',
                'changelog'} or name.startswith(('license-', 'licence-')):
        return 'data'
    return 'unknown'
