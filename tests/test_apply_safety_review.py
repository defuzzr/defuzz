import os
import tempfile
import unittest
from pathlib import Path

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz.applier import apply_rules_to_copy
from hermes_plugins.defuzz.cli import execute_defuzz_project
from hermes_plugins.defuzz.rules import build_deterministic_fallback_rules
from hermes_plugins.defuzz.safety import SafetyError, assert_disjoint_roots, copy_tree_nofollow
from hermes_plugins.defuzz.scanner import scan_folder


class ApplySafetyReviewTests(unittest.TestCase):
    def test_runtime_symlinks_are_classified_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, copy = root / 'source', root / 'copy'
            source.mkdir()
            (source / '.worktrees').symlink_to(root / 'external')
            (source / '.hermes').symlink_to(root / 'external')
            copy_tree_nofollow(source, copy)
            inv = scan_folder(copy, source_root=source)
            apply_rules_to_copy(copy, inv, build_deterministic_fallback_rules(inv), db_path=root / 'state.db')
            self.assertTrue((copy / '.worktrees').is_symlink())
            self.assertTrue((copy / '.hermes').is_symlink())
            self.assertFalse((root / 'external').exists())

    def test_leaf_alias_overlap_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'source').mkdir()
            (root / 'alias').symlink_to(root / 'source')
            with self.assertRaises(SafetyError):
                assert_disjoint_roots(source=root / 'source', staging=root / 'alias')

    def test_report_and_rules_outputs_refused_inside_source_or_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, copy = root / 'source', root / 'copy'
            source.mkdir()
            (source / 'hello.txt').write_text('hello')
            copy_tree_nofollow(source, copy)
            inv = scan_folder(copy, source_root=source)
            for target in [source / 'output.json', copy / 'output.json']:
                with self.subTest(target=target):
                    with self.assertRaises(SafetyError):
                        apply_rules_to_copy(copy, inv, build_deterministic_fallback_rules(inv), report_out_path=target, db_path=root / 'state.db')
                    with self.assertRaises(SafetyError):
                        execute_defuzz_project({'action': 'propose_rules', 'source_path': str(source), 'copy_path': str(copy), 'rules_path': str(target), 'use_fallback_rules': True})
                    self.assertFalse(target.exists())
            self.assertFalse((copy / '.git').exists())

    def test_runtime_nested_git_collapsed_archived_and_binary_guide_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, copy = root / 'source', root / 'copy'
            source.mkdir()
            for name in ['.worktrees/work/payload', '.hermes/scratch/payload', 'vendor/.git/config']:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'runtime bytes')
            (source / 'AGENTS.md').write_bytes(b'old guide\xff\xfe\x00')
            copy_tree_nofollow(source, copy)
            inv = scan_folder(copy, source_root=source)
            self.assertFalse(any(f['path'].startswith('.worktrees/') for f in inv['files']))
            apply_rules_to_copy(copy, inv, build_deterministic_fallback_rules(inv), db_path=root / 'state.db')
            for name in ['.worktrees/work/payload', '.hermes/scratch/payload', 'vendor/.git/config']:
                self.assertEqual((copy / '_archive' / name).read_bytes(), b'runtime bytes')
                self.assertFalse((copy / name).exists())
            self.assertEqual((copy / '_archive/AGENTS.pre-adopt.md').read_bytes(), b'old guide\xff\xfe\x00')
