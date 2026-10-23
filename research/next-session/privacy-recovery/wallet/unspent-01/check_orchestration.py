"""Public mocked ordering controls; not cryptographic or network evidence."""
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

archive = Path(__file__).resolve().parents[1] / 'network-01/source/poc/independent-recovery'
sys.path.insert(0, str(archive))
spec = importlib.util.spec_from_file_location('cold_orchestration', Path(__file__).with_name('client.py'))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
wallet = client.wallet


def case(request, *, no_claim=False, missing_public=False):
    events = []
    claims = [] if no_claim else [SimpleNamespace(position=7, owner_action_available=False),
        SimpleNamespace(position=5, owner_action_available=True),
        SimpleNamespace(position=2, owner_action_available=True)]
    with ExitStack() as stack:
        def wrapped(name, value):
            def call(*args, **kwargs):
                events.append(name)
                if name == 'prepare':
                    assert args[0]['position'] == 2
                if name == 'complete-public' and missing_public:
                    raise wallet.Invalid('missing-current-head')
                return value
            return call
        functions = {
            'runtime_crypto': ('crypto-pin', Path('/public-crypto')),
            'descriptor_identity': ('descriptor-pin', '00' * 32),
            'snapshot_from_replay': ('complete-public', None),
            'load_backup': ('backup-read', b'public-do-not-fund-placeholder'),
            'recognize': ('recognize', ({}, object(), SimpleNamespace(owned=claims), object(), object())),
            'prepare_reveal': ('prepare', {'status': 'MOCK_NO_SIGNATURE'}),
        }
        for name, (event, value) in functions.items():
            stack.enter_context(patch.object(wallet, name, wrapped(event, value)))
        stack.enter_context(patch.object(client, 'replay', wrapped('replay-public', {})))
        try:
            return client.run(request), events
        except wallet.Invalid as error:
            return {'error': str(error)}, events


with TemporaryDirectory() as temporary:
    descriptor = Path(temporary, 'descriptor.json')
    fetched = Path(temporary, 'fetch.json')
    descriptor.write_text('{}')
    fetched.write_text('{}')
    base = {'op': 'recover', 'backup_path': '/never-open-this-backup',
            'descriptor_path': str(descriptor), 'fetch_path': str(fetched),
            'expected_descriptor_sha256': '00' * 32, 'crypto_path': '/public-crypto'}
    sign = dict(base, op='prepare-reveal', disclosure_consent=wallet.DISCLOSURE_CONSENT,
                native_helper_path='/native', fee_rate_sompi_per_mass=100,
                output_dir='/private/prepared')
    result, events = case(base)
    assert result['recognized_actionable_positions'] == [2, 5]
    assert events == ['crypto-pin', 'descriptor-pin', 'replay-public', 'complete-public',
                      'backup-read', 'recognize']
    result, events = case(sign)
    assert result['position_selected_from_recognized_claims'] == 2
    assert events.count('backup-read') == 1 and events[-1] == 'prepare'
    result, events = case(dict(sign, disclosure_consent='unaccepted'))
    assert result['error'] == 'explicit-reveal-consent-required' and not events
    result, events = case(base, missing_public=True)
    assert result['error'] == 'missing-current-head' and 'backup-read' not in events
    result, events = case(dict(base, expected_descriptor_sha256='01' * 32))
    assert result['error'] == 'user-selected-descriptor-pin-mismatch' and 'backup-read' not in events
    result, events = case(sign, no_claim=True)
    assert result['error'] == 'recognized-unspent-claim-required' and 'prepare' not in events
    result, events = case(dict(sign, position=99))
    assert result['error'] == 'cold-request-fields' and not events

print(json.dumps({'passed': True, 'public_mocked_ordering_controls': 7,
                  'actual_seed_reads': 0, 'actual_signatures': 0,
                  'cryptographic_or_network_evidence': False}))
