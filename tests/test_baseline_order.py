import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import ensure_test_package

ensure_test_package()

from hermes_plugins.defuzz import applier
from hermes_plugins.defuzz.rules import build_deterministic_fallback_rules
from hermes_plugins.defuzz.safety import copy_tree_nofollow, run_git_hardened
from hermes_plugins.defuzz.scanner import scan_folder


class BaselineOrderTests(unittest.TestCase):
    def exercise(self, existing_git=False, include_secret_files=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, copy = root / 'source', root / 'copy'
            source.mkdir()
            for i in range(6):
                (source / f'doc{i}.md').write_text(f'unique documentation {i}\n')
            (source / '.env').write_text('PRIVATE=value\n')
            (source / 'latest').symlink_to(source / 'doc0.md')
            if existing_git:
                for args in [['init'], ['config', 'user.name', 'Test'], ['config', 'user.email', 'test@example.org'], ['add', '.'], ['commit', '-m', 'original']]:
                    self.assertEqual(run_git_hardened(source, args).returncode, 0)
            copy_tree_nofollow(source, copy, include_secret_files=include_secret_files)
            inv = scan_folder(copy, source_root=source)
            calls = []
            def git(repo, args, **kwargs):
                calls.append(args)
                return run_git_hardened(repo, args, **kwargs)
            with patch.object(applier, 'run_git_hardened', side_effect=git):
                report = applier.apply_rules_to_copy(copy, inv, build_deterministic_fallback_rules(inv), db_path=root / 'state.db')
            commits = [i for i, args in enumerate(calls) if args[0] == 'commit']
            moves = [i for i, args in enumerate(calls) if args[0] == 'mv']
            self.assertTrue(moves, 'structural moves must use git mv')
            self.assertLess(commits[0], moves[0])
            baseline, adopted = report['baseline_commit_sha'], report['adopted_commit_sha']
            self.assertEqual(run_git_hardened(copy, ['rev-parse', adopted + '^']).stdout.decode().strip(), baseline)
            tree = run_git_hardened(copy, ['ls-tree', '-r', '--name-only', baseline]).stdout.decode().splitlines()
            self.assertIn('doc0.md', tree)
            self.assertEqual(run_git_hardened(copy, ['show', baseline + ':latest']).stdout, b'doc0.md')
            self.assertNotIn('.env', tree)
            self.assertNotIn('.env', run_git_hardened(copy, ['ls-files']).stdout.decode().splitlines())
            self.assertEqual((copy / '.env').exists(), include_secret_files)
            self.assertTrue((source / '.env').exists())
            stat = run_git_hardened(copy, ['show', '--stat', adopted]).stdout.decode()
            self.assertIn('=> docs/doc0.md', stat)
            log = run_git_hardened(copy, ['log', '-2', '--format=%s']).stdout.decode()
            self.assertIn('baseline snapshot before structural moves', log)
            self.assertEqual(report['counts']['links_rewritten'], 1)
            self.assertEqual(report['schema_version'], 1)
            self.assertEqual(json.loads((copy / '.adopt/rules.json').read_text())['schema_version'], 1)

    def test_new_repo_baseline_precedes_git_mv(self):
        self.exercise()

    def test_tracked_secret_removed_from_index_not_false_leak(self):
        self.exercise(True)
        self.exercise(True, include_secret_files=True)
