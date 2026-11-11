"""Non-ASCII project names: folder keeps letters of any script, identifier stays ASCII."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import unicodedata
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.naming import (  # noqa: E402
    MAX_FOLDER_BYTES,
    MAX_NAME_LENGTH,
    folder_name,
    forms_from_slug,
    is_ascii_folder,
    slugify,
)

_SLUG_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


def _fallback(name: str) -> str:
    digest = hashlib.sha256(folder_name(name).encode("utf-8")).hexdigest()[:8]
    return f"project-{digest}"


# (name, expected folder, expected identifier slug)
CASES = [
    ("Café Ünïcode", "café-ünïcode", "cafe-unicode"),
    ("Café", "café", "cafe"),
    ("Crème Brûlée", "crème-brûlée", "creme-brulee"),
    ("Straße", "straße", "strasse"),
    ("Smørrebrød", "smørrebrød", "smorrebrod"),
    ("Łódź App", "łódź-app", "lodz-app"),
    ("Ærø Œuvre", "ærø-œuvre", "aero-oeuvre"),
    ("Þing", "þing", "thing"),
    ("İstanbul", "i̇stanbul", "istanbul"),
    ("Ñandú", "ñandú", "nandu"),
    ("Ελληνικά", "ελληνικά", None),
    ("Привет Мир", "привет-мир", None),
    ("日本語サイト", "日本語サイト", None),
    ("中文项目", "中文项目", None),
    ("한국어 앱", "한국어-앱", None),
    ("עברית", "עברית", None),
    ("العربية", "العربية", None),
    ("हिन्दी", "हिन्दी", None),
    ("தமிழ்", "தமிழ்", None),
    ("ไทย", "ไทย", None),
    ("Tokyo 東京", "tokyo-東京", "tokyo"),
    ("東京 Tokyo", "東京-tokyo", "tokyo"),
    ("Game 🎮 Night", "game-night", "game-night"),
    ("🎮 Ελλάδα", "ελλάδα", None),
    ("Cafe\u0301", "café", "cafe"),  # combining acute, NFC-composed in the folder
    ("e\u0301clair", "éclair", "eclair"),
    ("\u202eevil\u202c Café", "evil-café", "evil-cafe"),  # bidi override removed
    ("Zero\u200bWidth Café", "zerowidth-café", "zerowidth-cafe"),  # ZWSP removed
    ("tab\tCafé", "tab-café", "tab-cafe"),
    ("..Café", "café", "cafe"),
    ("--Café--", "café", "cafe"),
    ("Café/../Résumé", "café-résumé", "cafe-resume"),
    ("Ünïcode_Ärger", "ünïcode-ärger", "unicode-arger"),
    ("ＦＵＬＬ ｗｉｄｔｈ", "full-width", "full-width"),  # compatibility forms normalised (NFKC)
    ("Ÿ", "ÿ", "y"),
    ("Ωmega", "ωmega", "mega"),
    ("café٣", "café٣", "cafe"),
    ("Résumé 2", "résumé-2", "resume-2"),
    ("Mañana-Proyecto", "mañana-proyecto", "manana-proyecto"),
    ("Ünïcode Ünïcode", "ünïcode-ünïcode", "unicode-unicode"),
]

# ASCII expectations from before the change; results must be byte-identical.
OLD_ASCII = [
    ("My Game!", "my-game"),
    ("  Space  Shooter 2 ", "space-shooter-2"),
    ("Hello___World---App", "hello-world-app"),
    ("A", "a"),
    ("  --Leading_Symbols_a1-- ", "leading-symbols-a1"),
    ("new project", "new-project"),
    ("con", "con"),
    ("x" * MAX_NAME_LENGTH, "x" * MAX_NAME_LENGTH),
]
OLD_ASCII_BAD = ["", "   ", "!!!", "---", "123abc", "9-lives", "  42  ", "x" * (MAX_NAME_LENGTH + 1)]


class TestUnicodeNaming(unittest.TestCase):
    def test_at_least_forty_names(self) -> None:
        self.assertGreaterEqual(len(CASES), 40)

    def test_folder_and_identifier(self) -> None:
        for name, folder, ident in CASES:
            with self.subTest(name=name):
                got_folder = folder_name(name)
                self.assertEqual(got_folder, unicodedata.normalize("NFC", folder))
                self.assertEqual(unicodedata.normalize("NFC", got_folder), got_folder)
                self.assertLessEqual(len(got_folder.encode("utf-8")), MAX_FOLDER_BYTES)
                self.assertNotIn("/", got_folder)
                self.assertFalse(got_folder.startswith((".", "-")))
                for ch in got_folder:
                    self.assertNotIn(unicodedata.category(ch), ("Cc", "Cf", "Zs"))
                slug = slugify(name)
                self.assertEqual(slug, ident if ident is not None else _fallback(name))
                self.assertTrue(slug.isascii() and _SLUG_RE.fullmatch(slug), slug)
                forms_from_slug(slug)  # valid for every template language

    def test_fallback_is_deterministic_and_distinct(self) -> None:
        self.assertEqual(slugify("日本語サイト"), slugify("日本語サイト"))
        self.assertNotEqual(slugify("日本語サイト"), slugify("中文项目"))
        self.assertEqual(slugify("Ελλάδα"), slugify(unicodedata.normalize("NFD", "Ελλάδα")))
        self.assertEqual(slugify("Ελλάδα"), slugify("ΕΛΛΆΔΑ"))

    def test_ascii_results_byte_identical(self) -> None:
        for name, expected in OLD_ASCII:
            with self.subTest(name=name):
                self.assertEqual(slugify(name), expected)
                self.assertEqual(folder_name(name), expected)
        for bad in OLD_ASCII_BAD:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    slugify(bad)
                with self.assertRaises(ValueError):
                    folder_name(bad)

    def test_empty_or_punctuation_only_refused_with_one_line(self) -> None:
        for bad in ("🎮🎮", "¿¡…!", "\u202e\u202c", "\u200b", "・・・", "1日本", "٣café"):
            with self.subTest(bad=bad):
                for fn in (folder_name, slugify):
                    with self.assertRaises(ValueError) as ctx:
                        fn(bad)
                    self.assertNotIn("\n", str(ctx.exception))

    def test_length_measured_in_bytes(self) -> None:
        # 300 bytes of Japanese (100 three-byte letters) is refused, not cut.
        with self.assertRaises(ValueError) as ctx:
            folder_name("日" * 100)
        self.assertIn("bytes", str(ctx.exception))
        # 64 four-byte letters = 256 bytes: within the character limit, over the byte limit.
        with self.assertRaises(ValueError):
            folder_name("\U00020000" * MAX_NAME_LENGTH)
        ok = folder_name("日" * MAX_NAME_LENGTH)
        self.assertEqual(len(ok.encode("utf-8")), 3 * MAX_NAME_LENGTH)
        with self.assertRaises(ValueError):
            folder_name("é" * (MAX_NAME_LENGTH + 1))

    def test_normalisation_collisions_map_to_same_folder(self) -> None:
        pairs = [
            ("Café", "Cafe\u0301"),
            ("Café", "CAFÉ"),
            ("Café!", "café"),
            ("Ünïcode", "U\u0308ni\u0308code"),
        ]
        for a, b in pairs:
            with self.subTest(a=a, b=b):
                self.assertEqual(folder_name(a), folder_name(b))

    def test_case_variants_collide_on_case_sensitive_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / folder_name("Ünïcode")
            first.mkdir()
            second = root / folder_name("ÜNÏCODE")
            self.assertTrue(os.path.lexists(second))  # caller reports "already exists"
            self.assertEqual(sorted(p.name for p in root.iterdir()), [folder_name("ünïcode")])


# Compatibility forms (full-width, half-width, ligatures, superscripts) fold to ordinary forms.
COMPAT_CASES = [
    ("ＦＵＬＬ ｗｉｄｔｈ", "full-width"),
    ("ｶﾀｶﾅ App", "カタカナ-app"),
    ("ﬁle Café", "file-café"),
    ("Ⅻ Café", "xii-café"),
    ("x² Café", "x2-café"),
    ("Ｃａｆé", "café"),
    ("㍿ Tokyo", "株式会社-tokyo"),
]

# Names that only look like path syntax once normalised: neutralised to a plain folder name.
PATH_NEUTRALISED = [
    ("．．／ｅｔｃ", "etc"),
    ("．．／．．／Café", "café"),
    ("ａ／ｂ", "a-b"),
    ("Café＼Résumé", "café-résumé"),
    ("．ｈｉｄｄｅｎ", "hidden"),
    (".Café", "café"),
    ("Café．", "café"),
    ("Café. . ", "café"),
    ("Café\u3000", "café"),  # trailing ideographic space
    ("Café\u00a0", "café"),  # trailing no-break space
    ("Café∕Résumé", "café-résumé"),  # division slash
    ("Café⁄x", "café-x"),  # fraction slash
]

# Non-ASCII names that normalise to a Windows device name (with or without extension): refused.
RESERVED_REFUSED = [
    "ｃｏｎ", "ＣＯＮ", "ｎｕｌ", "Ａｕｘ", "ｐｒｎ", "com¹", "ｌｐｔ９", "ＣＯＭ１",
    "ＮＵＬ．ｔｘｔ", "ｃｏｎ．ｔａｒ．ｇｚ", "con．café", "con\u3000", "con\u200b", "nul\u202e",
    "aux．", "ｃｏｎ ", "．ｃｏｎ", "ｃｏｎ\u00a0",
]

# Close to a reserved name but not one: allowed.
NOT_RESERVED = [("cön", "cön"), ("con café", "con-café"), ("ｃｏｎｓｏｌｅ", "console"), ("ｃｏｍ１０", "com10")]


class TestUnicodeNormalisation(unittest.TestCase):
    def test_compatibility_forms_folded(self) -> None:
        for name, folder in COMPAT_CASES:
            with self.subTest(name=name):
                self.assertEqual(folder_name(name), unicodedata.normalize("NFC", folder))

    def test_compatibility_only_variant_equals_ascii(self) -> None:
        # A full-width spelling of an ASCII name gives the ASCII name's folder and identifier.
        for wide, plain in (("ＦＵＬＬ ｗｉｄｔｈ", "FULL width"), ("Ｍｙ Ｇａｍｅ！", "My Game!"), ("ｓｐａｃｅ－２", "space-2")):
            with self.subTest(wide=wide):
                self.assertEqual(folder_name(wide), folder_name(plain))
                self.assertEqual(slugify(wide), slugify(plain))
                self.assertTrue(is_ascii_folder(folder_name(wide)))

    def test_variants_map_to_same_folder(self) -> None:
        groups = [
            ["Café Ünïcode", "CAFÉ ÜNÏCODE", "Cafe\u0301 U\u0308ni\u0308code", "ｃａｆé ünïcode", "café  ünïcode!"],
            ["Привет Мир", "ПРИВЕТ МИР", "привет мир"],
            ["Ελληνικά", "ΕΛΛΗΝΙΚΆ", unicodedata.normalize("NFD", "Ελληνικά")],
            ["Tokyo 東京", "ＴＯＫＹＯ　東京", "tokyo-東京"],
            ["カタカナ", "ｶﾀｶﾅ"],
            ["Résumé", unicodedata.normalize("NFD", "RÉSUMÉ")],
        ]
        for group in groups:
            with self.subTest(group=group[0]):
                self.assertEqual({folder_name(n) for n in group}, {folder_name(group[0])})

    def test_idempotent_and_nfc(self) -> None:
        names = [n for n, _, _ in CASES] + [n for n, _ in COMPAT_CASES + PATH_NEUTRALISED + NOT_RESERVED]
        for name in names:
            with self.subTest(name=name):
                folder = folder_name(name)
                self.assertEqual(folder_name(folder), folder)
                self.assertEqual(unicodedata.normalize("NFC", folder), folder)
                self.assertEqual(unicodedata.normalize("NFKC", folder), folder)

    def test_path_confusables_neutralised(self) -> None:
        for name, folder in PATH_NEUTRALISED:
            with self.subTest(name=name):
                got = folder_name(name)
                self.assertEqual(got, unicodedata.normalize("NFC", folder))
                self.assertNotIn("/", got)
                self.assertNotIn("\\", got)
                self.assertNotIn(".", got)
                self.assertEqual(got, got.strip(" .-"))
                self.assertEqual(len(Path(got).parts), 1)

    def test_reserved_device_names_refused_with_one_line(self) -> None:
        for bad in RESERVED_REFUSED:
            with self.subTest(bad=bad):
                for fn in (folder_name, slugify):
                    with self.assertRaises(ValueError) as ctx:
                        fn(bad)
                    message = str(ctx.exception)
                    self.assertNotIn("\n", message)
                    self.assertIn("reserved", message)

    def test_near_reserved_allowed(self) -> None:
        for name, folder in NOT_RESERVED:
            with self.subTest(name=name):
                self.assertEqual(folder_name(name), folder)

    def test_ascii_reserved_unchanged(self) -> None:
        # ASCII names keep their old result byte for byte (Linux and macOS accept them).
        for name in ("con", "nul", "aux", "com1", "con.txt"):
            with self.subTest(name=name):
                self.assertEqual(folder_name(name), slugify(name))

    def test_is_ascii_folder(self) -> None:
        self.assertTrue(is_ascii_folder(folder_name("My Game")))
        self.assertTrue(is_ascii_folder(folder_name("ＦＵＬＬ ｗｉｄｔｈ")))
        self.assertTrue(is_ascii_folder(folder_name("Game 🎮 Night")))
        for name in ("Café", "日本語サイト", "привет мир", "Tokyo 東京", "e\u0301clair"):
            with self.subTest(name=name):
                self.assertFalse(is_ascii_folder(folder_name(name)))
        self.assertFalse(is_ascii_folder(""))


if __name__ == "__main__":
    unittest.main()
