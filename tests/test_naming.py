"""Unit tests for naming.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.naming import (  # noqa: E402
    PrefixForms,
    forms_from_placeholder,
    forms_from_slug,
    is_binary,
    rename_path_parts,
    rename_text,
    slugify,
)


class TestNaming(unittest.TestCase):
    def test_slugify_basic_and_whitespace(self) -> None:
        self.assertEqual(slugify("My Game!"), "my-game")
        self.assertEqual(slugify("  Space  Shooter 2 "), "space-shooter-2")
        self.assertEqual(slugify("Hello___World---App"), "hello-world-app")
        self.assertEqual(slugify("A"), "a")
        self.assertEqual(slugify("  --Leading_Symbols_a1-- "), "leading-symbols-a1")

    def test_slugify_invalid_inputs_raise_value_error(self) -> None:
        for bad in ("", "   ", "!!!", "---", "123abc", "9-lives", "  42  "):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    slugify(bad)

    def test_forms_from_slug_exact_values(self) -> None:
        forms = forms_from_slug("my-game")
        self.assertEqual(
            forms,
            PrefixForms(
                kebab="my-game",
                snake="my_game",
                screaming="MY_GAME",
                pascal="MyGame",
            ),
        )
        forms2 = forms_from_slug("space-shooter-2")
        self.assertEqual(
            forms2,
            PrefixForms(
                kebab="space-shooter-2",
                snake="space_shooter_2",
                screaming="SPACE_SHOOTER_2",
                pascal="SpaceShooter2",
            ),
        )

    def test_forms_from_placeholder_exact_values(self) -> None:
        forms = forms_from_placeholder("tmpl_prefix")
        self.assertEqual(
            forms,
            PrefixForms(
                kebab="tmpl-prefix",
                snake="tmpl_prefix",
                screaming="TMPL_PREFIX",
                pascal="TmplPrefix",
            ),
        )
        self.assertEqual(
            forms_from_placeholder("tmpl__prefix"),
            PrefixForms(
                kebab="tmpl--prefix",
                snake="tmpl__prefix",
                screaming="TMPL__PREFIX",
                pascal="TmplPrefix",
            ),
        )
        self.assertEqual(
            forms_from_placeholder("tmpl_"),
            PrefixForms(
                kebab="tmpl-",
                snake="tmpl_",
                screaming="TMPL_",
                pascal="Tmpl",
            ),
        )

    def test_forms_reject_invalid_inputs(self) -> None:
        with self.assertRaises(ValueError):
            forms_from_slug("")
        with self.assertRaises(ValueError):
            forms_from_slug("123-bad")
        with self.assertRaises(ValueError):
            forms_from_slug("my-game\n")
        with self.assertRaises(ValueError):
            forms_from_placeholder("")
        with self.assertRaises(ValueError):
            forms_from_placeholder("123_bad")
        with self.assertRaises(ValueError):
            forms_from_placeholder("Bad-Snake")
        with self.assertRaises(ValueError):
            forms_from_placeholder("tmpl_prefix\n")

    def test_rename_text_replaces_all_four_forms_in_one_pass(self) -> None:
        src = forms_from_placeholder("tmpl_prefix")
        dst = forms_from_slug("my-game")
        text = (
            "crate: tmpl_prefix\n"
            "pkg: tmpl-prefix\n"
            "const: TMPL_PREFIX_VERSION\n"
            "type: TmplPrefixApp\n"
            "sub: tmpl_prefix_core\n"
        )
        expected = (
            "crate: my_game\n"
            "pkg: my-game\n"
            "const: MY_GAME_VERSION\n"
            "type: MyGameApp\n"
            "sub: my_game_core\n"
        )
        self.assertEqual(rename_text(text, src, dst), expected)

    def test_rename_text_no_double_replacement_or_prefix_corruption(self) -> None:
        # Destination contains source substring or overlapping tokens; single-pass prevents re-replacing.
        src = forms_from_placeholder("tmpl_prefix")
        dst = forms_from_slug("tmpl-prefix-ext")
        text = "tmpl_prefix and tmpl-prefix and TMPL_PREFIX and TmplPrefix"
        expected = "tmpl_prefix_ext and tmpl-prefix-ext and TMPL_PREFIX_EXT and TmplPrefixExt"
        self.assertEqual(rename_text(text, src, dst), expected)

        # Single-word placeholder where pascal/kebab/snake could share prefix characteristics
        src_single = forms_from_placeholder("app")
        dst_single = forms_from_slug("super-game")
        self.assertEqual(
            rename_text("app APP App app_core", src_single, dst_single),
            "super_game SUPER_GAME SuperGame super_game_core",
        )

        # Custom PrefixForms where one form is a strict prefix of another form
        src_prefix = PrefixForms(
            kebab="foo",
            snake="foo_bar",
            screaming="FOO_BAR",
            pascal="FooBar",
        )
        dst_prefix = PrefixForms(
            kebab="baz-qux",
            snake="baz_qux",
            screaming="BAZ_QUX",
            pascal="BazQux",
        )
        self.assertEqual(
            rename_text("foo_bar and foo and FooBar and FOO_BAR", src_prefix, dst_prefix),
            "baz_qux and baz-qux and BazQux and BAZ_QUX",
        )

    def test_rename_path_parts(self) -> None:
        src = forms_from_placeholder("tmpl_prefix")
        dst = forms_from_slug("my-game")
        self.assertEqual(
            rename_path_parts("tmpl_prefix_core/TmplPrefix.rs", src, dst),
            "my_game_core/MyGame.rs",
        )
        self.assertEqual(
            rename_path_parts("crates/tmpl-prefix/src/TMPL_PREFIX.txt", src, dst),
            "crates/my-game/src/MY_GAME.txt",
        )

    def test_is_binary(self) -> None:
        self.assertFalse(is_binary(b""))
        self.assertFalse(is_binary(b"hello world\nutf-8 text \xc3\xa9"))
        self.assertTrue(is_binary(b"\x00"))
        self.assertTrue(is_binary(b"header\x00binary"))
        # NUL within first 8 KiB -> True
        self.assertTrue(is_binary(b"a" * 8191 + b"\x00"))
        # NUL only after first 8 KiB -> False
        self.assertFalse(is_binary(b"a" * 8192 + b"\x00"))


if __name__ == "__main__":
    unittest.main()
