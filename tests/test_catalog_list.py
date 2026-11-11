"""Unit tests for catalog_list.py (the one project pick-list: build, order, suggest, find, render)."""

from __future__ import annotations

import json
import random
import subprocess
import sys
import tempfile
import textwrap
import unicodedata
import unittest
from pathlib import Path
from types import SimpleNamespace

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import catalog_list  # noqa: E402
from hermes_plugins.defuzz.catalog_list import (  # noqa: E402
    build_catalog,
    find_entry,
    load_picker_text,
    render_text,
    suggested_ids,
    to_json,
)
from hermes_plugins.defuzz.matcher import KitInfo, KitMatch, Match  # noqa: E402
from hermes_plugins.defuzz.templates import load_templates  # noqa: E402
from tests.fake_kit_bridge import load_list_fixture  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "catalog_list" / "picker.json"
MODULE_FILE = Path(catalog_list.__file__).resolve()
ENTRY_KEYS = {"kind", "id", "title", "line", "group", "group_title", "flag"}


def _t(tid, name="A template", summary="Does things."):
    return SimpleNamespace(id=tid, name=name, summary=summary)


def _k(kid, name="A kit", summary="Holds things."):
    return SimpleNamespace(id=kid, name=name, summary=summary)


def _real_templates():
    return load_templates()


def _real_kits():
    return [KitInfo.from_dict(k) for k in load_list_fixture()["kits"]]


def _picker():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _tm(template, score=5):
    return Match(template=template, score=score, reasons=[], needs=[])


def _km(kit, score=5, **kw):
    return KitMatch(kit=kit, score=score, reasons=[], **kw)


def _keys(entries):
    return [f"{e['kind']}:{e['id']}" for e in entries]


def _cols(s):
    return sum(
        0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in "WF" else 1
        for c in s
    )


class TestLoadPickerText(unittest.TestCase):
    def test_fixture_loads(self):
        self.assertEqual(load_picker_text(FIXTURE), _picker())

    def test_missing_empty_malformed_never_raise(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            self.assertEqual(load_picker_text(base / "absent.json"), {})
            self.assertEqual(load_picker_text(base), {})  # a folder
            for name, data in [
                ("empty.json", b""),
                ("bad.json", b"{not json"),
                ("list.json", b"[1, 2]"),
                ("str.json", b'"text"'),
                ("bin.json", b"\xff\xfe\x00garbage"),
                ("deep.json", b"[" * 100000),
            ]:
                p = base / name
                p.write_bytes(data)
                self.assertEqual(load_picker_text(p), {}, name)

    def test_default_path_is_beside_module(self):
        self.assertIsInstance(load_picker_text(), dict)
        self.assertEqual(Path(catalog_list.PICKER_TEXT_PATH).resolve(), MODULE_FILE.with_name("picker_text.json"))


class TestBuildCatalog(unittest.TestCase):
    def test_entry_shape_and_flags(self):
        entries = build_catalog([_t("tpl")], [_k("kit-a")], picker={})
        self.assertEqual(len(entries), 2)
        for e in entries:
            self.assertEqual(set(e), ENTRY_KEYS)
            for v in e.values():
                self.assertIsInstance(v, str)
        tpl = [e for e in entries if e["kind"] == "template"][0]
        kit = [e for e in entries if e["kind"] == "kit"][0]
        self.assertEqual(tpl["flag"], "--template tpl")
        self.assertEqual(kit["flag"], "--kit kit-a")
        self.assertEqual(tpl["group"], "code")
        self.assertEqual(kit["group"], "workspace")
        self.assertEqual(tpl["title"], "A template")
        self.assertEqual(tpl["line"], "Does things")

    def test_order_and_grouping_with_picker(self):
        entries = build_catalog(_real_templates(), _real_kits(), picker=_picker())
        keys = _keys(entries)
        kits_rest = sorted(
            f"kit:{k.id}" for k in _real_kits()
            if k.id not in {"research-writing", "client-job", "video-production"}
        )
        self.assertEqual(
            keys,
            ["kit:research-writing", "kit:client-job", "kit:video-production"]
            + kits_rest
            + ["template:python-golden", "template:rust-golden", "template:cpp-golden",
               "template:dotnet-golden", "template:go-golden", "template:ts-node-golden",
               "template:web-golden"],
        )
        groups = [e["group"] for e in entries]
        self.assertEqual(groups, ["workspace"] * len(_real_kits()) + ["code"] * 7)
        self.assertEqual(entries[0]["group_title"], "Workspaces for creative work")
        self.assertEqual(entries[0]["title"], "Research and writing")
        self.assertEqual(entries[-1]["group_title"], "Code projects")
        # picker ids that name nothing are not entries
        self.assertNotIn("kit:does-not-exist", keys)
        self.assertNotIn("template:not-a-template", keys)

    def test_order_without_picker_is_templates_then_kits_by_id(self):
        entries = build_catalog([_t("b"), _t("a")], [_k("z"), _k("c")], picker={})
        self.assertEqual(_keys(entries), ["template:a", "template:b", "kit:c", "kit:z"])
        self.assertEqual(entries[0]["group_title"], "Code projects")
        self.assertEqual(entries[-1]["group_title"], "Workspace kits")

    def test_bad_picker_shapes_fall_back(self):
        for picker in [
            {}, {"groups": "x", "entries": []}, {"groups": [1, None, {"id": 3}], "entries": {"kit:a": 7}},
            {"entries": {"kit:a": {"title": 5, "line": None, "order": "first", "group": 9}}},
            {"entries": {"kit:a": {"order": True}}}, "not a dict", None,
        ]:
            with self.subTest(picker=picker):
                p = picker if isinstance(picker, dict) else {}
                entries = build_catalog([], [_k("a", "Kit A", "Holds A. More.")], picker=p)
                self.assertEqual(len(entries), 1)
                self.assertEqual(entries[0]["title"], "Kit A")
                self.assertEqual(entries[0]["line"], "Holds A")
                self.assertEqual(entries[0]["group"], "workspace")

    def test_non_dict_picker_argument_tolerated(self):
        entries = build_catalog([_t("a")], [], picker=["nonsense"])
        self.assertEqual(_keys(entries), ["template:a"])

    def test_described_sort_before_undescribed(self):
        picker = {"entries": {"kit:zz": {"title": "Zed", "line": "Last by id, first by text"}}}
        entries = build_catalog([], [_k("aa"), _k("zz")], picker=picker)
        self.assertEqual(_keys(entries), ["kit:zz", "kit:aa"])
        self.assertEqual(entries[0]["title"], "Zed")

    def test_partial_picker_text_fills_from_manifest(self):
        picker = {"entries": {"kit:a": {"title": "Short title"}}}
        e = build_catalog([], [_k("a", "Name", "First. Second.")], picker=picker)[0]
        self.assertEqual((e["title"], e["line"]), ("Short title", "First"))

    def test_picker_text_over_limits_is_cut(self):
        picker = {"entries": {"kit:a": {"title": "word " * 20, "line": "word " * 40}}}
        e = build_catalog([], [_k("a")], picker=picker)[0]
        self.assertLessEqual(len(e["title"]), 40)
        self.assertLessEqual(len(e["line"]), 100)
        self.assertFalse(e["title"].endswith(" "))

    def test_zero_kits_zero_templates_and_nothing(self):
        self.assertEqual(_keys(build_catalog(_real_templates(), [], picker={}))[0], "template:cpp-golden")
        self.assertEqual(len(build_catalog([], _real_kits(), picker={})), len(_real_kits()))
        self.assertEqual(build_catalog([], [], picker={}), [])
        self.assertEqual(build_catalog((), (), picker=_picker()), [])

    def test_duplicate_ids_across_kinds_are_two_entries(self):
        entries = build_catalog([_t("same")], [_k("same")], picker={})
        self.assertEqual(_keys(entries), ["template:same", "kit:same"])

    def test_duplicate_ids_within_kind_keep_first(self):
        entries = build_catalog([_t("x", "First"), _t("x", "Second")], [], picker={})
        self.assertEqual([e["title"] for e in entries], ["First"])

    def test_invalid_items_skipped_and_mappings_accepted(self):
        entries = build_catalog(
            [None, SimpleNamespace(id="", name="n", summary="s"), SimpleNamespace(name="no id")],
            [{"id": "m", "name": "Mapped", "summary": "From a dict."}, 42],
            picker={},
        )
        self.assertEqual(_keys(entries), ["kit:m"])
        self.assertEqual(entries[0]["title"], "Mapped")

    def test_title_cut_and_colon_not_doubled(self):
        e = build_catalog([], [_k("g", "Game workspace: Unreal + Blender + Houdini", "x.")], picker={})[0]
        self.assertEqual(e["title"], "Game workspace: Unreal + Blender...")
        e2 = build_catalog([], [_k("c", "Ends in colon:", "Line.")], picker={})
        self.assertEqual(render_text(e2).splitlines()[1:], ["  1. Ends in colon:  [--kit c]", "     Line"])

    def test_missing_name_or_summary(self):
        e = build_catalog([], [SimpleNamespace(id="k", name=None, summary=None)], picker={})[0]
        self.assertEqual(e["title"], "k")
        self.assertEqual(e["line"], "")

    def test_picker_none_reads_default_file(self):
        entries = build_catalog([_t("a")], [_k("b")])
        self.assertEqual(set(_keys(entries)), {"template:a", "kit:b"})


class TestFallbackLine(unittest.TestCase):
    def line(self, summary, name="N"):
        return build_catalog([], [_k("a", name, summary)], picker={})[0]["line"]

    def test_first_sentence(self):
        self.assertEqual(self.line("One thing. Another thing."), "One thing")
        self.assertEqual(self.line("Ends with period."), "Ends with period")
        self.assertEqual(self.line("Question? Next."), "Question?")
        self.assertEqual(self.line("Uses .NET and v1.2 libs. Then more."), "Uses .NET and v1.2 libs")

    def test_no_doubled_punctuation(self):
        self.assertEqual(self.line("Trailing dots..."), "Trailing dots")
        self.assertEqual(self.line("Colon at end:"), "Colon at end")
        long = "alpha " * 30 + "end."
        out = self.line(long)
        self.assertLessEqual(len(out), 100)
        self.assertTrue(out.endswith("..."))
        self.assertFalse(out.endswith("...."))
        self.assertNotIn(" ...", out)
        long2 = ("word, " * 30).strip()
        out2 = self.line(long2)
        self.assertFalse(out2.endswith(",..."))

    def test_word_boundary_cut(self):
        summary = " ".join(["abcdefgh"] * 20)
        out = self.line(summary)
        self.assertLessEqual(len(out), 100)
        self.assertTrue(out.endswith("abcdefgh..."))

    def test_single_huge_word_is_hard_cut(self):
        out = self.line("x" * 300)
        self.assertLessEqual(len(out), 100)

    def test_whitespace_collapsed(self):
        self.assertEqual(self.line("  spread\n\tover   lines  "), "spread over lines")

    def test_real_summaries(self):
        for e in build_catalog(_real_templates(), _real_kits(), picker={}):
            self.assertLessEqual(len(e["line"]), 100)
            self.assertLessEqual(len(e["title"]), 40)
            self.assertTrue(e["line"])
            self.assertFalse(e["line"].endswith((".", ",", ";", ":")) and not e["line"].endswith("..."))


class TestEscaping(unittest.TestCase):
    def test_control_and_bidi_escaped_in_entries_and_text(self):
        evil = "Evil\u202ename\x1b[31m\u200b\x00"
        entries = build_catalog([], [_k("e", evil, "Sum\u2066mary\x07 here.")], picker={})
        e = entries[0]
        for field in ("title", "line"):
            for ch in e[field]:
                self.assertNotIn(unicodedata.category(ch), ("Cc", "Cf"), (field, repr(e[field])))
        self.assertIn("\\u202e", e["title"])
        self.assertIn("\\x1b", e["title"])
        text = render_text(entries, notice="note\u202e\x1b")
        for ch in text:
            self.assertTrue(ch == "\n" or unicodedata.category(ch) not in ("Cc", "Cf", "Zl", "Zp"), repr(ch))
        self.assertIn("\\u2066", text)

    def test_picker_text_escaped_too(self):
        picker = {"entries": {"kit:e": {"title": "T\u202e", "line": "L\x1b"}},
                  "groups": [{"id": "workspace", "title": "G\u2028"}]}
        e = build_catalog([], [_k("e")], picker=picker)[0]
        self.assertEqual(e["title"], "T\\u202e")
        self.assertEqual(e["line"], "L\\x1b")
        self.assertEqual(e["group_title"], "G\\u2028")

    def test_render_escapes_handmade_entries(self):
        entry = {"kind": "kit", "id": "x\u202e", "title": "a\x1b", "line": "b",
                 "group": "g", "group_title": "G\x07", "flag": "--kit x\u202e"}
        text = render_text([entry])
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertNotIn("\x07", text)


class TestSuggestedIds(unittest.TestCase):
    def setUp(self):
        self.templates = _real_templates()
        self.kits = _real_kits()
        self.entries = build_catalog(self.templates, self.kits, picker={})
        self.tby = {t.id: t for t in self.templates}
        self.kby = {k.id: k for k in self.kits}

    def test_none_with_no_matches(self):
        self.assertEqual(suggested_ids(self.entries, [], [], "none"), [])
        self.assertEqual(suggested_ids(self.entries, [], [], "template"), [])
        self.assertEqual(suggested_ids([], [], [], None), [])

    def test_preferred_kind_first(self):
        tm = [_tm(self.tby["rust-golden"], 6)]
        km = [_km(self.kby["video-production"], 9)]
        self.assertEqual(suggested_ids(self.entries, tm, km, "template"),
                         ["template:rust-golden", "kit:video-production"])
        self.assertEqual(suggested_ids(self.entries, tm, km, "kit"),
                         ["kit:video-production", "template:rust-golden"])

    def test_none_with_matches_orders_by_score(self):
        tm = [_tm(self.tby["rust-golden"], 6)]
        km = [_km(self.kby["video-production"], 9), _km(self.kby["client-job"], 6)]
        self.assertEqual(suggested_ids(self.entries, tm, km, "none"),
                         ["kit:video-production", "template:rust-golden", "kit:client-job"])

    def test_never_more_than_three(self):
        tm = [_tm(t, 5) for t in self.templates]
        km = [_km(k, 5) for k in self.kits]
        for pref in ("template", "kit", "none", None, "bogus"):
            out = suggested_ids(self.entries, tm, km, pref)
            self.assertLessEqual(len(out), 3)
            self.assertEqual(len(out), 3)
            self.assertEqual(len(set(out)), len(out))

    def test_only_ids_in_list(self):
        ghost_t = _tm(SimpleNamespace(id="ghost", name="g", summary="g"), 99)
        ghost_k = _km(KitInfo(id="ghost-kit", name="g", summary="g", tags=(), version=1), 99)
        km = [ghost_k, _km(self.kby["homelab"], 4)]
        out = suggested_ids(self.entries, [ghost_t], km, "kit")
        self.assertEqual(out, ["kit:homelab"])
        only_templates = build_catalog(self.templates, [], picker={})
        self.assertEqual(suggested_ids(only_templates, [], km, "kit"), [])

    def test_disqualified_and_junk_matches_ignored(self):
        km = [_km(self.kby["homelab"], 9, disqualified=True), None, "kit:homelab", 3]
        self.assertEqual(suggested_ids(self.entries, [None, object()], km, "kit"), [])

    def test_duplicates_collapsed(self):
        tm = [_tm(self.tby["go-golden"]), _tm(self.tby["go-golden"])]
        self.assertEqual(suggested_ids(self.entries, tm, [], "template"), ["template:go-golden"])

    def test_same_id_both_kinds(self):
        entries = build_catalog([_t("same")], [_k("same")], picker={})
        tm = [_tm(SimpleNamespace(id="same"), 3)]
        km = [_km(KitInfo(id="same", name="s", summary="s", tags=(), version=1), 3)]
        self.assertEqual(suggested_ids(entries, tm, km, "kit"), ["kit:same", "template:same"])


class TestFindEntry(unittest.TestCase):
    def setUp(self):
        self.entries = build_catalog([_t("web-golden"), _t("same")],
                                     [_k("web-app"), _k("same"), _k("mixed-case")], picker={})

    def key(self, token):
        e = find_entry(self.entries, token)
        return None if e is None else f"{e['kind']}:{e['id']}"

    def test_by_id_kind_and_number(self):
        self.assertEqual(self.key("web-golden"), "template:web-golden")
        self.assertEqual(self.key("web-app"), "kit:web-app")
        self.assertEqual(self.key("kit:web-app"), "kit:web-app")
        self.assertEqual(self.key("template:web-golden"), "template:web-golden")
        self.assertEqual(self.key("1"), _keys(self.entries)[0])
        self.assertEqual(self.key("5"), _keys(self.entries)[4])
        self.assertEqual(self.key(" 2 "), _keys(self.entries)[1])
        self.assertIs(find_entry(self.entries, "3"), self.entries[2])

    def test_none_cases(self):
        for token in ["0", "-1", "6", "99", "", "   ", "web", "web-gold", "kit:web-golden",
                      "template:web-app", "kit:", ":web-app", "1.0", "+1", "\u0663", "１",
                      "same", None, 3, "web-goldenx", "web golden"]:
            with self.subTest(token=token):
                self.assertIsNone(find_entry(self.entries, token))

    def test_case_insensitive_exact_allowed_prefix_not(self):
        self.assertEqual(self.key("WEB-GOLDEN"), "template:web-golden")
        self.assertEqual(self.key("MIXED-Case"), "kit:mixed-case")
        self.assertEqual(self.key("Kit:WEB-APP"), "kit:web-app")
        self.assertIsNone(find_entry(self.entries, "WEB-"))
        self.assertIsNone(find_entry(self.entries, "mixed"))

    def test_ambiguous_bare_id_needs_kind(self):
        self.assertIsNone(find_entry(self.entries, "same"))
        self.assertEqual(self.key("kit:same"), "kit:same")
        self.assertEqual(self.key("template:same"), "template:same")

    def test_empty_list(self):
        self.assertIsNone(find_entry([], "1"))
        self.assertIsNone(find_entry([], "web-app"))

    def test_number_matches_render(self):
        entries = build_catalog(_real_templates(), _real_kits(), picker=_picker())
        blocks = TestRenderText._blocks(None, render_text(entries))
        for n in (1, 7, 14, 15, 21):
            self.assertIn(f"[{find_entry(entries, str(n))['flag']}]", blocks[n])


class TestRenderText(unittest.TestCase):
    def setUp(self):
        self.entries = build_catalog(_real_templates(), _real_kits(), picker=None)
        self.fixture_entries = build_catalog(_real_templates(), _real_kits(), picker=_picker())

    def _blocks(self, text):
        """Map row number -> full text of that row (row line plus continuation lines)."""
        blocks, cur = {}, None
        for ln in text.splitlines():
            head = ln.lstrip()
            num = head.split(".", 1)[0]
            if ln.startswith(" ") and num.isdigit() and head[len(num):len(num) + 2] == ". ":
                cur = int(num)
                blocks[cur] = ln
            elif cur is not None and ln.startswith("     "):
                blocks[cur] += " " + ln.strip()
            else:
                cur = None
        return blocks

    def test_real_list_shape(self):
        for entries in (self.entries, self.fixture_entries):
            suggested = [_keys(entries)[3], _keys(entries)[20]]
            text = render_text(entries, suggested=suggested, notice="A notice line.")
            for ln in text.splitlines():
                self.assertLessEqual(_cols(ln), 100, ln)
                for ch in ln:
                    self.assertNotIn(unicodedata.category(ch), ("Cc", "Cf"))
            self.assertNotIn("\x1b", text)
            blocks = self._blocks(text)
            self.assertEqual(sorted(blocks), list(range(1, len(entries) + 1)))
            order = [int(ln.lstrip().split(".", 1)[0]) for ln in text.splitlines()
                     if ln.startswith(" ") and ln.lstrip().split(".", 1)[0].isdigit()]
            self.assertEqual(order, list(range(1, len(entries) + 1)))
            for n, block in blocks.items():
                self.assertEqual("(suggested)" in block, n in (4, 21), block)
                if entries[n - 1].get("coming_soon"):
                    self.assertIn("  [coming soon]", block)
                    self.assertNotIn(f"[{entries[n - 1]['flag']}]", block)
                else:
                    self.assertIn(f"[{entries[n - 1]['flag']}]", block)
            self.assertEqual(text.count("(suggested)"), 2)
            self.assertEqual(text.rstrip("\n").splitlines()[-1], "A notice line.")
            titles = {e["group_title"] for e in entries}
            for t in titles:
                self.assertIn(t, text.splitlines())

    def test_row_format(self):
        entries = build_catalog([_t("tpl", "Tiny", "Small thing.")], [], picker={})
        text = render_text(entries, suggested=["template:tpl"])
        self.assertEqual(text.splitlines(),
                         ["Code projects", "  1. Tiny  [--template tpl]  (suggested)", "     Small thing"])
        self.assertEqual(render_text(entries), "Code projects\n  1. Tiny  [--template tpl]\n     Small thing\n")

    def test_empty_line_prints_first_line_only(self):
        entries = build_catalog([], [SimpleNamespace(id="k", name="Kit", summary=None)], picker={})
        self.assertEqual(render_text(entries), "Workspace kits\n  1. Kit  [--kit k]\n")

    def test_title_40_and_line_100(self):
        title, line = "T" * 40, " ".join(["abcdefghi"] * 10)[:100]
        picker = {"entries": {"kit:k": {"title": title, "line": line}}}
        entries = build_catalog([], [_k("k")], picker=picker)
        self.assertEqual(entries[0]["line"], line)
        lines = render_text(entries, suggested=["kit:k"]).splitlines()
        self.assertEqual(lines[1], "  1. " + title + "  [--kit k]  (suggested)")
        self.assertEqual(lines[2], "     " + " ".join(["abcdefghi"] * 9))
        self.assertEqual(lines[3], "     abcdefghi")
        for ln in lines:
            self.assertLessEqual(_cols(ln), 100)

    def test_very_long_title_moves_flag_to_own_line(self):
        entry = {"kind": "kit", "id": "k", "title": "word " * 25, "line": "L",
                 "group": "g", "group_title": "G", "flag": "--kit k"}
        lines = render_text([entry], suggested=["kit:k"]).splitlines()
        self.assertTrue(lines[1].startswith("  1. word"))
        self.assertNotIn("[", lines[1])
        self.assertIn("     [--kit k]  (suggested)", lines)
        self.assertEqual(lines[-1], "     L")
        for ln in lines:
            self.assertLessEqual(_cols(ln), 100)

    def test_number_alignment_9_vs_10(self):
        nine = build_catalog([], [_k(f"k{i}") for i in range(9)], picker={})
        ten = build_catalog([], [_k(f"k{i:02d}") for i in range(10)], picker={})
        rows9 = [ln for ln in render_text(nine).splitlines() if "[--kit" in ln]
        rows10 = [ln for ln in render_text(ten).splitlines() if "[--kit" in ln]
        self.assertTrue(rows9[0].startswith("  1. A kit"))
        self.assertTrue(rows9[8].startswith("  9. A kit"))
        self.assertTrue(rows10[0].startswith("  1. A kit"))
        self.assertTrue(rows10[9].startswith(" 10. A kit"))
        for ln in rows9 + rows10:
            self.assertEqual(ln.index("A kit"), 5)

    def test_real_catalog_layout(self):
        text = render_text(self.fixture_entries)
        lines = text.splitlines()
        rows = [ln for ln in lines if ln[:4].strip().rstrip(".").isdigit() and ln[3] == "."]
        self.assertEqual(len(rows), 7 + len(_real_kits()))
        self.assertTrue(rows[0].startswith("  1. "))
        self.assertTrue(rows[-1].startswith(f" {len(rows)}. "))
        titles = {e["title"] for e in self.fixture_entries}
        for n, (row, e) in enumerate(zip(rows, self.fixture_entries), start=1):
            self.assertEqual(row, f"{n:>3}. {e['title']}  [{e['flag']}]")
            self.assertIn(e["title"], titles)
        for ln in lines:
            self.assertTrue(ln == "" or not ln.startswith(" ") or ln.startswith("     ") or ln in rows, ln)
            self.assertLessEqual(_cols(ln), 100)
        groups = [ln for ln in lines if ln and not ln.startswith(" ")]
        self.assertEqual(len(groups), 2)
        self.assertEqual(lines.count(""), 1)
        self.assertEqual(lines[lines.index("") + 1], groups[1])

    def test_long_rows_wrap_and_keep_flag_whole(self):
        picker = {"entries": {"kit:k": {"title": "W" * 40, "line": ("long " * 20).strip()}}}
        entries = build_catalog([], [_k("k" * 30)], picker={})
        entries += build_catalog([], [_k("k")], picker=picker)
        text = render_text(entries, suggested=["kit:k"])
        for ln in text.splitlines():
            self.assertLessEqual(_cols(ln), 100)
        self.assertIn("[--kit k]", text)
        self.assertIn("[--kit " + "k" * 30 + "]", text)

    def test_wide_characters_counted_as_two_columns(self):
        picker = {"entries": {"kit:k": {"title": "漢字" * 10, "line": "字 " * 49}}}
        text = render_text(build_catalog([], [_k("k")], picker=picker))
        for ln in text.splitlines():
            self.assertLessEqual(_cols(ln), 100)

    def test_empty_and_notice_only(self):
        self.assertEqual(render_text([]), "")
        self.assertEqual(render_text([], notice="Kits are missing."), "Kits are missing.\n")
        long_notice = "Install the companion plugin to get the workspace kits. " * 4
        text = render_text(build_catalog([_t("a")], [], picker={}), notice=long_notice)
        for ln in text.splitlines():
            self.assertLessEqual(_cols(ln), 100)
        self.assertIn("\n\n", text)

    def test_suggested_unknown_keys_ignored(self):
        entries = build_catalog([_t("a")], [], picker={})
        self.assertNotIn("(suggested)", render_text(entries, suggested=["kit:a", "a", None, 5]))

    def test_unsorted_subset_repeats_no_numbers(self):
        entries = list(reversed(self.fixture_entries[10:18]))
        blocks = self._blocks(render_text(entries))
        self.assertEqual(sorted(blocks), list(range(1, 9)))


class TestToJson(unittest.TestCase):
    def test_shape_serialisable_stable(self):
        a = build_catalog(_real_templates(), _real_kits(), picker=_picker())
        b = build_catalog(_real_templates(), _real_kits(), picker=_picker())
        sug = ["kit:homelab", "template:go-golden", "kit:ghost", "kit:homelab"]
        ja = to_json(a, suggested=sug, notice="n")
        jb = to_json(b, suggested=sug, notice="n")
        self.assertEqual(set(ja), {"entries", "suggested", "notice"})
        self.assertEqual(ja["suggested"], ["kit:homelab", "template:go-golden"])
        self.assertEqual(ja["notice"], "n")
        self.assertEqual(len(ja["entries"]), 7 + len(_real_kits()))
        for e in ja["entries"]:
            self.assertEqual(set(e), ENTRY_KEYS)
        self.assertEqual(json.dumps(ja), json.dumps(jb))
        self.assertEqual(json.dumps(ja, ensure_ascii=False).encode(), json.dumps(jb, ensure_ascii=False).encode())
        self.assertEqual(json.loads(json.dumps(ja)), ja)

    def test_does_not_alias_entries(self):
        a = build_catalog([_t("a")], [], picker={})
        j = to_json(a)
        j["entries"][0]["title"] = "changed"
        self.assertNotEqual(a[0]["title"], "changed")
        self.assertEqual(to_json([]), {"entries": [], "suggested": [], "notice": ""})

    def test_notice_escaped(self):
        self.assertEqual(to_json([], notice="x\x1by")["notice"], "x\\x1by")


class TestDeterministicOrder(unittest.TestCase):
    def test_random_subsets_and_orderings(self):
        rng = random.Random(20261111)
        templates = list(_real_templates()) + [_t("same", "Same T"), _t("zz-undescribed")]
        kits = list(_real_kits()) + [_k("same", "Same K")]
        picker = _picker()
        picker["entries"]["kit:same"] = {"title": "Same", "line": "x", "group": "code", "order": 20}
        picker["entries"]["template:same"] = {"title": "Same", "line": "x", "group": "code", "order": 20}
        full = _keys(build_catalog(templates, kits, picker=picker))
        self.assertEqual(full.index("kit:same"), full.index("template:same") + 1)
        for _ in range(200):
            ts = rng.sample(templates, rng.randint(0, len(templates)))
            ks = rng.sample(kits, rng.randint(0, len(kits)))
            out = _keys(build_catalog(ts, ks, picker=picker))
            expected = [k for k in full if k in {f"template:{t.id}" for t in ts} | {f"kit:{k.id}" for k in ks}]
            self.assertEqual(out, expected)


class TestImportIsSideEffectFree(unittest.TestCase):
    def test_import_reads_no_file_and_no_network(self):
        script = textwrap.dedent(
            """
            import importlib.util, sys
            path = sys.argv[1]
            events = []
            def hook(event, args):
                if event == "open" and args and str(args[0]) != path:
                    events.append(("open", str(args[0])))
                if event.startswith("socket."):
                    events.append((event, None))
            spec = importlib.util.spec_from_file_location("catalog_list_probe", path)
            mod = importlib.util.module_from_spec(spec)
            sys.addaudithook(hook)
            spec.loader.exec_module(mod)
            bad = [e for e in events if not e[1] or not e[1].endswith((".py", ".pyc", ".so")) or "picker" in e[1]]
            print(repr(bad))
            """
        )
        out = subprocess.run([sys.executable, "-c", script, str(MODULE_FILE)],
                             capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), "[]", out.stderr)

    def test_standard_library_only(self):
        import ast

        tree = ast.parse(MODULE_FILE.read_text(encoding="utf-8"))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "no relative imports needed")
                names.add((node.module or "").split(".")[0])
        stdlib = set(sys.stdlib_module_names) | {"__future__"}
        self.assertTrue(names <= stdlib, names - stdlib)


if __name__ == "__main__":
    unittest.main()


class KitsNoticeLineTests(unittest.TestCase):
    CASES = [
        ("unavailable", "componentize CLI is unavailable",
         "Kits need the defuzz-componentize plugin. Install it, then run `hermes defuzz kits`."),
        ("absent", "", "Kits need the defuzz-componentize plugin. Install it, then run `hermes defuzz kits`."),
        ("error", "Project kits check TIMED OUT: secret-raw",
         "The kit list did not answer in time. Try again, or run `hermes defuzz kits`."),
        ("error", "componentize settings error: /tmp/x secret-raw",
         "Kits could not be listed: componentize settings are invalid. Run `hermes defuzz kits`."),
        ("error", "boom secret-raw", "Kits are unavailable right now. Run `hermes defuzz kits` for details."),
        ("error", "", "Kits are unavailable right now. Run `hermes defuzz kits` for details."),
    ]

    def test_each_case(self) -> None:
        for status, notice, expected in self.CASES:
            line = catalog_list.kits_notice_line(status, notice)
            self.assertEqual(line, expected)
            self.assertLessEqual(len(line), 100)
            self.assertNotIn("\n", line)
            self.assertNotIn("secret-raw", line)
            self.assertNotIn("/tmp", line)

    def test_ok_is_empty(self) -> None:
        self.assertEqual(catalog_list.kits_notice_line("ok", "anything"), "")


# --------------------------------------------------------------- skipped kits
from hermes_plugins.defuzz import catalog_list as _cl  # noqa: E402


class KitsSkippedNoticeTests(unittest.TestCase):
    def test_lines(self) -> None:
        self.assertEqual(_cl.kits_notice_line("ok", ""), "")
        self.assertEqual(_cl.kits_notice_line("ok", "", 0), "")
        one = _cl.kits_notice_line("ok", "", 1)
        three = _cl.kits_notice_line("ok", "", 3)
        self.assertEqual(one, "1 kit was skipped because its description is not valid. Run `hermes defuzz kits`.")
        self.assertEqual(three, "3 kits were skipped because their descriptions are not valid. Run `hermes defuzz kits`.")
        self.assertLessEqual(len(_cl.kits_notice_line("ok", "", 10**12)), 100)

    def test_error_status_wins_over_skipped(self) -> None:
        self.assertEqual(_cl.kits_notice_line("unavailable", "", 5), _cl.KITS_MISSING_NOTICE)

    def test_entries_dropped_by_the_bridge_are_counted(self) -> None:
        from hermes_plugins.defuzz import matcher as _m
        reply = {"status": "ok", "data": {"kits": [], "skipped_kits": 3}}
        res = _m.parse_kit_list_detailed(reply)
        self.assertEqual(res.skipped, 3)
        self.assertEqual(_cl.kits_notice_line(res.status, res.notice, res.skipped),
                         "3 kits were skipped because their descriptions are not valid. Run `hermes defuzz kits`.")
        for bad in (True, -2, "3", 2.0, None):
            r = _m.parse_kit_list_detailed({"status": "ok", "data": {"kits": [], "skipped_kits": bad}})
            self.assertEqual(r.skipped, 0)
        huge = _m.parse_kit_list_detailed({"status": "ok", "data": {"kits": [], "skipped_kits": 10**30}})
        self.assertLessEqual(huge.skipped, 100_000)


# ------------------------------------------------- hostile ids, caps, escaping
_BAD_IDS = [
    "--yes", "../../etc/passwd", "a b; rm -rf ~", "id\x1b[31mred", "id\u202ertl", "3", "9lives",
    "Mixed", "a--b", "-a", "a-", "a_b", "a.b", "template:python-cli", "a" * 65, "", "   ", "a\n",
    "\u0430bc",  # Cyrillic a
]
_GOOD_IDS = ["a", "a1", "web-app", "x2-y3", "a" * 64]


class SafeIdTests(unittest.TestCase):
    def test_bad_ids_are_dropped_and_counted(self) -> None:
        for kind in ("template", "kit"):
            with self.subTest(kind=kind):
                items = [_t(i) for i in _BAD_IDS + _GOOD_IDS]
                tpls, kits = (items, []) if kind == "template" else ([], items)
                entries, skipped = catalog_list.build_catalog_counted(tpls, kits, picker={})
                self.assertEqual(sorted(e["id"] for e in entries), sorted(_GOOD_IDS))
                # "" and "   " were never entries; every other bad id is counted
                self.assertEqual(skipped[kind], len(_BAD_IDS) - 2)
                self.assertEqual(skipped["template" if kind == "kit" else "kit"], 0)
                self.assertEqual(build_catalog(tpls, kits, picker={}), entries)

    def test_rule_matches_bridge_rule_for_good_ids(self) -> None:
        import re
        bridge = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
        for i in _GOOD_IDS + [k["id"] for k in load_list_fixture()["kits"]]:
            self.assertTrue(catalog_list.is_safe_id(i), i)
            self.assertTrue(bridge.fullmatch(i), i)
        for i in _BAD_IDS + [None, 3, b"a"]:
            self.assertFalse(catalog_list.is_safe_id(i), repr(i))

    def test_real_templates_and_kits_all_pass(self) -> None:
        entries, skipped = catalog_list.build_catalog_counted(_real_templates(), _real_kits(), picker={})
        self.assertEqual(skipped, {"template": 0, "kit": 0})
        self.assertEqual(len(entries), 7 + len(_real_kits()))

    def test_flag_never_holds_a_bad_id(self) -> None:
        entries = build_catalog([_t(i) for i in _BAD_IDS], [_k(i) for i in _BAD_IDS], picker={})
        self.assertEqual(entries, [])
        self.assertEqual(render_text(entries), "")


class CapTests(unittest.TestCase):
    def test_at_most_200_kits_and_100_templates(self) -> None:
        tpls = [_t(f"t{i:04d}") for i in range(150)]
        kits = [_k(f"k{i:04d}") for i in range(250)]
        entries, skipped = catalog_list.build_catalog_counted(tpls, kits, picker={})
        self.assertEqual(sum(e["kind"] == "template" for e in entries), catalog_list.MAX_TEMPLATES)
        self.assertEqual(sum(e["kind"] == "kit" for e in entries), catalog_list.MAX_KITS)
        self.assertEqual((catalog_list.MAX_TEMPLATES, catalog_list.MAX_KITS), (100, 200))
        self.assertEqual(skipped, {"template": 50, "kit": 50})
        # the first ones in list order are kept
        self.assertEqual([e["id"] for e in entries if e["kind"] == "kit"][:2], ["k0000", "k0001"])

    def test_huge_input_is_fast(self) -> None:
        import time
        big = "\x1b[2J" * 50000
        kits = [_k(f"k{i}", name=big, summary=big) for i in range(2000)]
        start = time.monotonic()
        entries, skipped = catalog_list.build_catalog_counted([], kits, picker={})
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(skipped["kit"], 1800)


class LimitsAfterEscapingTests(unittest.TestCase):
    def test_title_and_line_within_limits(self) -> None:
        nasty = "\x1b\u202e\u2066\x07\u200b\u2028" * 200
        for name, summary in ((nasty, nasty), ("a" * 500, "b" * 5000), ("\x1b x " * 99, "\u202e. " * 999)):
            with self.subTest(name=name[:10]):
                (entry,) = build_catalog([], [_k("k", name=name, summary=summary)], picker={})
                self.assertLessEqual(len(entry["title"]), catalog_list.TITLE_MAX)
                self.assertLessEqual(len(entry["line"]), catalog_list.LINE_MAX)
                for text in (entry["title"], entry["line"]):
                    self.assertFalse(any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in text))


class CleanFieldTests(unittest.TestCase):
    def test_escapes_and_newlines_shown_as_escapes(self) -> None:
        out = catalog_list.clean_field("a\x1b]8;;http://e\x07X\nnext\r\tline\u202eY\u2028Z", 300)
        self.assertEqual(out, "a\\x1b]8;;http://e\\x07X\\nnext\\r\\tline\\u202eY\\u2028Z")
        self.assertNotIn("\n", out)

    def test_capped_after_escaping(self) -> None:
        for limit in (300, 600):
            out = catalog_list.clean_field("\x1b" * 1000, limit)
            self.assertLessEqual(len(out), limit)
            out = catalog_list.clean_field("word " * 1000, limit)
            self.assertLessEqual(len(out), limit)
            self.assertTrue(out.endswith("..."))

    def test_non_strings(self) -> None:
        self.assertEqual(catalog_list.clean_field(None, 10), "")
        self.assertEqual(catalog_list.clean_field(12, 10), "12")

    def test_escape_text_keeps_lines_and_spaces(self) -> None:
        text = "  1. Title  [--kit x]\n     line\x1b[2J\u202e\x00"
        self.assertEqual(catalog_list.escape_text(text),
                         "  1. Title  [--kit x]\n     line\\x1b[2J\\u202e\\x00")


class SkippedTemplatesNoticeTests(unittest.TestCase):
    def test_templates_line(self) -> None:
        one = _cl.kits_notice_line("ok", "", 0, templates_skipped=1)
        many = _cl.kits_notice_line("ok", "", 0, templates_skipped=4)
        self.assertEqual(one, "1 template was skipped because its id is not valid. Run `hermes defuzz templates`.")
        self.assertEqual(many, "4 templates were skipped because their ids are not valid. Run `hermes defuzz templates`.")
        # kits come first; a kit error still wins
        self.assertEqual(_cl.kits_notice_line("ok", "", 2, templates_skipped=4), _cl.kits_notice_line("ok", "", 2))
        self.assertEqual(_cl.kits_notice_line("unavailable", "", 0, templates_skipped=4), _cl.KITS_MISSING_NOTICE)
        self.assertLessEqual(len(_cl.kits_notice_line("ok", "", 0, templates_skipped=10**12)), 100)
