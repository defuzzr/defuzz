"""The type gate identifies surfaces, never approves their behavior."""
from pathlib import Path

import pytest

from tests.conftest import load_submodule

file_types = load_submodule('audit.file_types')


@pytest.mark.parametrize('name', ['main.py', 'main.js', 'main.ts', 'main.rs', 'main.go',
    'main.c', 'main.cpp', 'main.h', 'main.java', 'main.rb', 'main.sh', 'main.ps1',
    'main.php', 'main.lua', 'main.swift', 'main.kt', 'main.cs', 'main.pl', 'main.ex',
    'main.scala', 'main.hs', 'main.clj', 'main.vue', 'main.svelte', 'main.sql'])
def test_known_languages_are_code(name):
    assert file_types.classify_file(Path(name), b'') == 'program_code'


@pytest.mark.parametrize('name', ['mystery', 'file.unrecognized', 'unknown.json',
    'settings.yaml', 'settings.toml', 'template.yaml', 'template.yml'])
def test_unrecognized_names_fail_closed(name):
    assert file_types.classify_file(Path(name), b'{}') == 'unknown'


@pytest.mark.parametrize('name', [
    'Makefile', 'CMakeLists.txt', 'BUILD', 'BUILD.bazel', 'Rakefile', 'Gemfile',
    'Vagrantfile', 'Dockerfile', 'Dockerfile.dev', 'Justfile', 'Procfile', 'crontab',
    'setup.py', 'build.rs', 'noxfile.py', 'tox.ini', 'pyproject.toml', 'Cargo.toml',
    'package.json', 'requirements.txt', 'requirements-dev.txt', '.npmrc', '.env',
    '.env.local', '.envrc', 'startup.pth', 'sitecustomize.py', 'usercustomize.py',
    '.github/workflows/check.yml', '.gitlab-ci.yml', '.circleci/config.yml',
    '.pre-commit-config.yaml', '.vscode/tasks.json', '.vscode/launch.json',
    'cron/jobs.json', 'hooks/HOOK.yaml', 'plugins/sample/__init__.py',
    '/etc/cron.d/backup', '/etc/cron.daily/backup', '.git/hooks/pre-commit',
])
def test_execution_surfaces_have_path_only_trigger(name):
    path = Path(name)
    assert file_types.classify_file(path, b'') == 'execution_surface'
    assert file_types.execution_trigger(path)
    assert file_types.execution_trigger(path) == file_types.execution_trigger(path)


@pytest.mark.parametrize('name', ['ordinary.py', 'README.md', 'unknown',
    'tasks.json', 'notplugins/a/__init__.py'])
def test_non_surface_has_no_trigger(name):
    assert file_types.execution_trigger(Path(name)) == ''


@pytest.mark.parametrize('name', ['README', 'LICENSE', 'LICENSE-MIT', 'COPYING',
    'NOTICE', 'guide.md', 'guide.rst', 'notes.txt', 'image.png', 'photo.jpg',
    'font.woff2', 'audio.mp3', 'Cargo.lock', 'uv.lock', 'yarn.lock',
    'package-lock.json', 'pnpm-lock.yaml', 'provenance.json',
    'tsconfig.json', 'biome.jsonc', '.gitignore', '.editorconfig', 'py.typed',
    '.worktreeinclude', 'CODEOWNERS', 'component.py.tmpl', '.nvmrc',
    'rustfmt.toml', 'clippy.toml', 'rust-toolchain.toml'])
def test_known_data_names(name):
    assert file_types.classify_file(Path(name), b'{}') == 'data'


@pytest.mark.parametrize('data', [b'#!/usr/bin/env python3\nprint(1)',
    b'#!/bin/sh\necho hi', b'\x7fELF\x00\xff', b'MZ\x90\x00',
    b'\x00asm\x01\x00\x00\x00', b'\xcf\xfa\xed\xfe\x00', b'<?php echo 1;'])
@pytest.mark.parametrize('name', ['unknown', 'image.png', 'README.md'])
def test_code_signatures_override_data_names(name, data):
    assert file_types.classify_file(Path(name), data) == 'program_code'


@pytest.mark.parametrize('data', [b'\xff', b'\x00text',
    b'# coding: utf-7\nprint(1)', b'# coding=latin-1\n',
    b'#!/usr/bin/python\n# coding: utf_7\n'])
@pytest.mark.parametrize('name', ['main.py', 'README.md', 'package.json', 'unknown'])
def test_unsupported_text_encoding_fails_closed(name, data):
    assert file_types.classify_file(Path(name), data) == 'unknown'


def test_binary_asset_is_data():
    assert file_types.classify_file(Path('image.png'), b'\x89PNG\r\n\x1a\n\xff') == 'data'


def test_utf8_cookie_is_supported():
    assert file_types.classify_file(Path('main.py'), b'# coding: utf-8\n') == 'program_code'


def test_workspace_can_contain_tasks():
    assert file_types.classify_file(Path('dev.code-workspace'), b'{}') == 'execution_surface'


def test_classification_never_reads_or_executes_path(tmp_path):
    path = tmp_path / 'main.py'
    assert not path.exists()
    assert file_types.classify_file(path, b'raise RuntimeError()') == 'program_code'
    assert not path.exists()
