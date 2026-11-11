"""Local hardening regressions; no sibling source checkout needed."""
import hashlib
import json
from pathlib import Path
import unittest
from tests import ensure_test_package
ensure_test_package()
from hermes_plugins.defuzz.audit.vendor.executable_inventory import redact_arg_or_url


class VendorReleaseTests(unittest.TestCase):
    def test_vendor_live_walkers_never_open_credentials(self):
        import tempfile
        from unittest.mock import patch
        from hermes_plugins.defuzz.audit.vendor import static_code, template_drift
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'auth.json').write_text('CANARY')
            original = os.open
            def tripwire(path, *args, **kwargs):
                if str(path) == 'auth.json':
                    raise AssertionError('credential opened')
                return original(path, *args, **kwargs)
            self.assertIn(os.open, os.supports_dir_fd)
            flags = (os.O_NOFOLLOW, os.O_NONBLOCK, os.O_DIRECTORY)
            with patch('os.open', side_effect=tripwire):
                for component in (static_code, template_drift):
                    with patch.object(component, '_require_containment_flags', return_value=flags):
                        files, coverage, issues = component._safe_walk_directory(root)
                    self.assertNotIn('auth.json', files)

    def test_short_secret_and_url_fragment_redacted(self):
        for text, secret in [('password=abc', 'abc'), ('https://example.test/#opaqueCanary', 'opaqueCanary'),
                             ('https://example.test/?custom=opaqueCanary', 'opaqueCanary')]:
            with self.subTest(text=text):
                result, changed = redact_arg_or_url(text)
                self.assertTrue(changed)
                self.assertNotIn(secret, result)

    def test_packaged_inventory_digests_and_honest_provenance(self):
        root = Path(__file__).resolve().parents[1] / 'audit' / 'vendor'
        manifest = json.loads((root / 'provenance.json').read_text())
        self.assertEqual(set(manifest['files']), {p.name for p in root.glob('*.py')})
        for name, info in manifest['files'].items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), info['sha256'])
        self.assertIsNone(manifest['upstream_revision'])
        self.assertEqual(manifest['files']['executable_inventory.py']['local_patch'],
                         'credential-redaction-v2; approved-yaml-parser-v1; uncaptured-manifest-v1; linear-redaction-regex-v1')
        self.assertEqual(manifest['files']['static_code.py']['local_patch'],
                         'shared-credential-read-policy-v2; golden-template-registry-v1; linear-source-scan-v1; web-golden-registry-v1; pnpm-config-document-v1; dev-scope-import-mapping-v1; open-handle-credential-check-v1')
        self.assertEqual(manifest['files']['template_drift.py']['local_patch'],
                         'shared-credential-read-policy-v2; golden-template-registry-v1; web-golden-registry-v1; open-handle-credential-check-v1')
        self.assertIn('all seven golden templates', manifest['note'])
        self.assertNotIn('all six golden templates', manifest['note'])

    def test_provenance_check_rejects_mutated_vendor_code(self):
        import shutil
        import tempfile
        from tests.vendor_provenance import assert_packaged_vendor
        src = Path(__file__).resolve().parents[1] / 'audit' / 'vendor'
        with tempfile.TemporaryDirectory() as tmp:
            copy_dir = Path(tmp) / 'vendor'
            shutil.copytree(src, copy_dir)
            assert_packaged_vendor(self, ['memory.py'], vendor=copy_dir)
            target = copy_dir / 'memory.py'
            data = bytearray(target.read_bytes())
            data[-1] ^= 0x01
            target.write_bytes(bytes(data))
            with self.assertRaises(AssertionError):
                assert_packaged_vendor(self, ['memory.py'], vendor=copy_dir)
