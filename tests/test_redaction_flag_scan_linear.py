"""The command-flag scan that feeds secret redaction runs in linear time on large texts."""

from __future__ import annotations

import shlex
import time

import pytest

from tests.conftest import load_submodule

SECRET = 'hunter2-CANARY-value'


def _state():
    redaction = load_submodule('audit.redaction')
    return redaction, redaction.Taint()


def _captured(text):
    _, state = _state()
    state.observe_text(text)
    return state.values


@pytest.mark.parametrize('text', [
    'run --password ' + SECRET + ' now',
    'curl -u ' + SECRET + ' https://example.invalid',
    'tool --api-key=' + SECRET,
    'x "unclosed --password ' + SECRET,
    'a\nb --token ' + SECRET + '\nc',
])
def test_small_texts_split_exactly_as_before(text):
    redaction = load_submodule('audit.redaction')
    try:
        expected = [shlex.split(text)]
    except ValueError:
        expected = [[]]
    assert redaction._flag_word_groups(text) == expected


def test_large_text_with_an_unclosed_quote_is_fast_and_still_captures_flag_values():
    filler = 'log line with an apostrophe: it\'s fine and "never closed\n' + 'plain words here\n' * 60000
    text = filler + 'deploy --password ' + SECRET + ' --verbose\n' + 'more words\n' * 60000
    assert len(text) > 1_500_000
    started = time.monotonic()
    values = _captured(text)
    assert time.monotonic() - started < 5.0
    assert SECRET in values


def test_large_balanced_text_captures_flag_values_on_any_line():
    text = 'alpha beta gamma\n' * 30000 + 'mysql -u ' + SECRET + ' -h host\n' + 'delta\n' * 30000
    assert SECRET in _captured(text)


def test_large_text_backslash_continuation_and_equals_form():
    text = 'word\n' * 40000 + 'cmd --secret-key \\\n  ' + SECRET + '\n' + 'tool --auth-token=' + SECRET + 'B\n' + 'word\n' * 40000
    values = _captured(text)
    assert SECRET in values and SECRET + 'B' in values


def test_very_long_single_line_is_linear():
    line = ('{"k": "v it\'s"} ' * 200000) + '--password ' + SECRET
    started = time.monotonic()
    values = _captured(line)
    assert time.monotonic() - started < 5.0
    assert SECRET in values


def _big(prefix_lines=5000):
    return '# filler line with it\'s apostrophe\n' * prefix_lines


def test_large_text_flag_at_end_of_line_takes_value_from_next_line():
    text = _big() + 'cmd --password\n' + SECRET + '\nrest\n' + _big()
    assert len(text) > 64 * 1024
    assert SECRET in _captured(text)


def test_large_text_very_long_line_before_a_flag_is_still_scanned():
    text = _big() + 'x' * 16500 + ' --token ' + SECRET + '\n' + _big()
    assert SECRET in _captured(text)


def test_large_text_quoted_value_spanning_lines_is_joined():
    text = _big() + 'tool --secret "first part\nsecond ' + SECRET + ' part" --verbose\n' + _big()
    values = _captured(text)
    assert any(SECRET in value for value in values)


def test_large_text_long_backslash_run_then_flag():
    text = _big() + ('part \\\n' * 3000) + 'end --api-key ' + SECRET + '\n'
    assert SECRET in _captured(text)


def test_large_text_crlf_and_tabs():
    text = _big().replace('\n', '\r\n') + 'cmd\t--password\t' + SECRET + '\r\n' + 'next --token\r\n' + SECRET + 'B\r\n'
    values = _captured(text)
    assert SECRET in values and SECRET + 'B' in values


def test_large_adversarial_inputs_stay_linear():
    for text in ('"' + 'a b c\n' * 400000, 'x "' + 'y' * 3_000_000, ('--password \\\n' * 200000),
                 "it's a -p key line\n" * 300000):
        started = time.monotonic()
        _captured(text)
        assert time.monotonic() - started < 15.0
