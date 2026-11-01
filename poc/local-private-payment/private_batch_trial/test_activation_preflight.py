"""Controls for the non-circular Testnet research-launch boundary."""
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest

import activation_preflight as preflight
import private_worker
import wallet_history


def digest(label):
    return hashlib.sha256(label.encode()).hexdigest()


class MemoryReader:
    def __init__(self):
        self.rows = {}

    def add(self, name, value):
        raw = value if type(value) is bytes else private_worker.encoded(value)
        path = Path('/public-activation-preflight-controls') / name
        pin = hashlib.sha256(raw).hexdigest()
        self.rows[str(path)] = raw
        return {'path': str(path), 'sha256': pin}

    def __call__(self, path, expected=None):
        raw = self.rows[str(path)]
        if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('control-pin')
        return raw


class ActivationPreflightControls(unittest.TestCase):
    def setUp(self):
        self.reader = MemoryReader()
        self.trial = self.reader.add('TRIAL.json', {
            'trial_id': '11111111-1111-4111-8111-111111111111',
        })
        self.source = self.reader.add('SOURCE.json', {'source': 'exact'})
        self.history = self.reader.add('HISTORY.json', {'history': 'two-round'})
        self.cases = [self.reader.add(name + '.json', {'case': name})
                      for name in ('genesis', 'round-1', 'round-2')]
        self.value = {
            'schema': preflight.RECEIPT_SCHEMA,
            'scope': wallet_history.SCOPE,
            'bootstrap_trial_id': '11111111-1111-4111-8111-111111111111',
            'bootstrap_trial': self.trial,
            'funding_identity_sha256': digest('funding identity'),
            'component_profile_sha256': digest('component profile'),
            'tail_sha256': digest('tail'),
            'source_contract': self.source,
            'history': self.history,
            'cases': [
                {'kind': kind, **record}
                for kind, record in zip(('genesis', 'payment', 'payment'),
                                        self.cases)
            ],
            'privacy_acceptance_sha256': digest('privacy acceptance'),
            'registered_driver_result_sha256': [
                digest('registered round 1'), digest('registered round 2')],
            'launch_authorized': False,
            'authority_admitted': False,
            'serialized_receipt_is_authority': False,
            'complete_terminal_lifecycle_observed': False,
            'testnet_trial_readiness_claimed': False,
            'mainnet_or_production_authorized': False,
        }
        self.args = SimpleNamespace(
            trial=self.trial['path'], trial_sha256=self.trial['sha256'],
            identity_sha256=digest('funding identity'),
            component_profile_sha256=digest('component profile'),
            tail_sha256=digest('tail'))

    def test_exact_receipt_is_audit_evidence_only(self):
        actual = preflight.validate_audit_receipt(
            self.value, self.args, self.reader)
        self.assertEqual(actual['bootstrap_trial_id'],
                         '11111111-1111-4111-8111-111111111111')
        self.assertFalse(actual['launch_authorized'])
        self.assertFalse(actual['authority_admitted'])
        self.assertFalse(actual['serialized_receipt_is_authority'])
        self.assertFalse(actual['testnet_trial_readiness_claimed'])

    def test_terminal_or_production_claim_and_cross_trial_reuse_refuse(self):
        mutations = []
        for name in ('complete_terminal_lifecycle_observed',
                     'testnet_trial_readiness_claimed',
                     'mainnet_or_production_authorized',
                     'launch_authorized', 'authority_admitted',
                     'serialized_receipt_is_authority'):
            changed = copy.deepcopy(self.value); changed[name] = True
            mutations.append(changed)
        changed = copy.deepcopy(self.value)
        changed['bootstrap_trial_id'] = (
            '22222222-2222-4222-8222-222222222222')
        mutations.append(changed)
        changed = copy.deepcopy(self.value)
        changed['cases'][2]['path'] = changed['cases'][1]['path']
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                preflight.validate_audit_receipt(changed, self.args,
                                                 self.reader)

    def test_receipt_cannot_bypass_missing_registered_driver_authority(self):
        with self.assertRaisesRegex(ValueError,
                'activation-preflight-registered-driver-completion-receipt-not-implemented'):
            preflight.verify_audit_receipt(self.value, self.args, self.reader)


if __name__ == '__main__':
    unittest.main()
