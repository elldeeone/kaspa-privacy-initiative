"""Controls for the parent-only Testnet network boundary."""
from pathlib import Path
import json
import importlib.util
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch


HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'private_batch_trial_funding_network', HERE / 'funding_network.py')
funding_network = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(funding_network)


class FundingNetworkAuthorityControls(unittest.TestCase):
    def test_standalone_execute_refuses_before_filesystem_or_network_access(self):
        args = SimpleNamespace(execute=True)
        with patch.object(
                funding_network.runpy, 'run_path',
                side_effect=AssertionError('root guard touched')):
            with self.assertRaisesRegex(
                    ValueError,
                    'parent-live-activation-authority-required'):
                funding_network.run(args)

    def test_source_only_stage_persists_no_replayable_network_plan(self):
        with tempfile.TemporaryDirectory(prefix='kpb-funding-network-source-only-') as temporary:
            root = Path(temporary)
            identity = root / 'IDENTITY.json'
            identity.write_bytes(b'identity fixture')
            output = root / 'output'
            args = SimpleNamespace(
                execute=False,
                operation='anchor',
                identity=identity,
                identity_sha256='11' * 32,
                output=output,
                case_mode='genesis',
                owner_component=None,
            )
            admitted = {'trial_id': '7abaee02-63ab-4b1e-817e-28bc7e63d169'}
            with patch.object(
                    funding_network.runpy, 'run_path',
                    return_value={'read': lambda path, pin=None: Path(path).read_bytes()}), \
                    patch.object(funding_network, 'parse', return_value={}), \
                    patch.object(funding_network, 'validate_identity', return_value=admitted):
                result = funding_network.run(args)

            self.assertEqual(result['status'], 'SOURCE_ONLY_NETWORK_DISABLED')
            self.assertEqual([path.name for path in output.iterdir()], ['LAUNCH.json'])
            receipt = json.loads((output / 'LAUNCH.json').read_text())
            self.assertFalse(receipt['network_invoked'])
            self.assertFalse(receipt['executable_network_plan_persisted'])
            self.assertFalse(receipt['child_job_persisted'])
            self.assertFalse(receipt['network_activation_configured'])
            self.assertNotIn('command', json.dumps(receipt))

    def test_miner_child_refuses_configured0_before_reading_mounted_inputs(self):
        child = HERE / 'funding_network_miner.mjs'
        result = subprocess.run(
            [shutil.which('node'), str(child), '--mode', 'plan'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin'},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            b'PARENT_LIVE_NETWORK_ACTIVATION_NOT_CONFIGURED',
            result.stderr,
        )
        self.assertNotIn(b'ENOENT', result.stderr)


if __name__ == '__main__':
    unittest.main()
