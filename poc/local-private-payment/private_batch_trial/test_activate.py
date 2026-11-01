"""Public CLI controls for the Testnet research activation split."""
from pathlib import Path
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
SPEC = importlib.util.spec_from_file_location(
    'private_batch_trial_activate', HERE / 'activate.py')
activate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(activate)


class ActivateCliControls(unittest.TestCase):
    def test_cli_requires_preflight_not_future_terminal_rehearsal(self):
        result = subprocess.run(
            [sys.executable, '-B', str(HERE / 'activate.py'), '--help'],
            capture_output=True, text=True, check=True)
        self.assertIn('--preflight PREFLIGHT', result.stdout)
        self.assertIn('--preflight-sha256 PREFLIGHT_SHA256', result.stdout)
        self.assertNotIn('--rehearsal ', result.stdout)

    def test_preflight_evidence_record_is_one_shot_but_not_authority(self):
        with tempfile.TemporaryDirectory(prefix='kpb-activation-registry-') as root:
            registry = Path(root) / 'registry'
            preflight = hashlib.sha256(b'preflight').hexdigest()
            identity = hashlib.sha256(b'identity').hexdigest()
            first = activate.record_preflight_evidence(
                '11111111-1111-4111-8111-111111111111', preflight,
                identity, registry=registry)
            self.assertEqual(first['preflight_receipt_sha256'], preflight)
            self.assertFalse(first['terminal_complete_or_readiness_claimed'])
            retained = json.loads((registry / preflight).read_text())
            self.assertEqual(retained, first)
            with self.assertRaises(ValueError):
                activate.record_preflight_evidence(
                    '11111111-1111-4111-8111-111111111111', preflight,
                    identity, registry=registry)

    def test_preflight_registry_must_be_private_owned_directory(self):
        with tempfile.TemporaryDirectory(prefix='kpb-activation-registry-') as root:
            registry = Path(root) / 'registry'; registry.mkdir(mode=0o777)
            registry.chmod(0o777)
            with self.assertRaisesRegex(ValueError,
                                        'activation-preflight-registry-mode'):
                activate.record_preflight_evidence(
                    '11111111-1111-4111-8111-111111111111',
                    hashlib.sha256(b'preflight').hexdigest(),
                    hashlib.sha256(b'identity').hexdigest(),
                    registry=registry)

    def test_execute_refuses_before_root_guard_or_filesystem_access(self):
        args = SimpleNamespace(execute=True)
        with patch('runpy.run_path', side_effect=AssertionError('guard touched')):
            with self.assertRaisesRegex(
                    ValueError, 'live-parent-authority-conjunction-required'):
                activate.run(args)


if __name__ == '__main__':
    unittest.main()
