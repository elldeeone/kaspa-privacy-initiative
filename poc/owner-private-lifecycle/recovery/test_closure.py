#!/usr/bin/env python3
"""Public synthetic dependency and handoff controls; no wallet or network IO."""
from copy import deepcopy
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

import closure


def fixture():
    contents = {role: ('PUBLIC SYNTHETIC OBJECT: ' + role + '\n').encode()
                for role in closure.REQUIRED_ROLES}
    contents['history-page-0'] = b'PUBLIC SYNTHETIC HISTORY PAGE, NOT CHAIN EVIDENCE\n'
    contents['wallet-library'] = b'PUBLIC SYNTHETIC WALLET LIBRARY, NOT EXECUTABLE\n'
    providers = [{'id': name,
        'reported_infrastructure': name + '-infrastructure',
        'reported_administration': 'same-unverified-administrator',
        'reported_deletion_control': 'same-unverified-administrator',
        'allowed_hosts': [name + '.invalid'],
        'reported_retention_until_utc': None,
        'reported_policy_sha256': None} for name in ('issuer', 'replica', 'third')]
    selection = {
        'schema': 'four-wallet-public-recovery-selection/v1',
        'profile_reference_sha256': closure.digest(contents['profile']),
        'providers': providers,
        'assets': [{'id': identifier, 'kind': 'other_public_metadata',
            'bytes': len(raw), 'sha256': closure.digest(raw),
            'replicas': [{'provider_id': name,
                'url': 'https://' + name + '.invalid/' + identifier}
                for name in ('issuer', 'replica', 'third')]}
            for identifier, raw in sorted(contents.items())],
    }
    dependencies = {identifier: [] for identifier in contents}
    dependencies['accepted-history-index'] = ['history-page-0']
    dependencies['wallet-software'] = ['wallet-library']
    for family in ('spend', 'output', 'exit'):
        dependencies[family + '-manifest'] = [
            family + '-proving-key', family + '-verification-key']
    manifest = {
        'schema': 'owner-private-lifecycle-public-closure/v1',
        'domain_hex32': closure.LIFECYCLE_DOMAIN,
        'profile_reference_sha256': selection['profile_reference_sha256'],
        'transport_selection_sha256': closure.digest(closure.encoded(selection)),
        'required_roles': {role: role for role in sorted(closure.REQUIRED_ROLES)},
        'dependencies': dependencies,
    }
    return manifest, selection, contents


class SyntheticFetcher:
    def __init__(self, contents, bad=()):
        self.contents = contents
        self.bad = set(bad)
        self.calls = []

    def __call__(self, replica, asset, hosts, output):
        self.calls.append((replica['provider_id'], asset['id'], hosts))
        raw = self.contents[asset['id']]
        if (replica['provider_id'], asset['id']) in self.bad:
            raw = b'X' + raw[1:]
        output.write_bytes(raw)
        return {'transport': 'SYNTHETIC_PUBLIC_BYTES_NOT_HTTPS_OR_CHAIN_EVIDENCE'}


class ClosureControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='public-lifecycle-recovery-')
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'restored'
        self.manifest, self.selection, self.contents = fixture()

    def check(self, manifest=None, selection=None):
        manifest = deepcopy(self.manifest if manifest is None else manifest)
        selection_raw = closure.encoded(self.selection if selection is None else selection)
        manifest['transport_selection_sha256'] = closure.digest(selection_raw)
        raw = closure.encoded(manifest)
        return closure.validate(raw, closure.digest(raw), selection_raw)

    def restore(self, fetch=None, **kwargs):
        raw = closure.encoded(self.manifest)
        return closure.restore(raw, closure.digest(raw),
            closure.encoded(self.selection), self.output,
            excluded=kwargs.pop('excluded', ('issuer',)),
            denied_hosts=kwargs.pop('denied_hosts', ('issuer.invalid',)),
            fetch=fetch or SyntheticFetcher(self.contents),
            observed_at='2026-10-24T00:00:00Z', **kwargs)

    def test_valid_complete_declared_closure_has_no_financial_authority(self):
        fetch = SyntheticFetcher(self.contents)
        handoff = self.restore(fetch)
        self.assertEqual(handoff['status'], 'DECLARED_CLOSURE_RESTORED')
        self.assertEqual(handoff['restored_objects'], len(self.contents))
        self.assertEqual(set(handoff['roles']), closure.REQUIRED_ROLES)
        self.assertEqual({call[0] for call in fetch.calls}, {'replica'})
        self.assertTrue(all('issuer.invalid' not in call[2] for call in fetch.calls))
        self.assertFalse(handoff['control_assessment']['independent_administration_demonstrated'])
        self.assertFalse(handoff['control_assessment']['retention_guarantee_demonstrated'])
        self.assertFalse(handoff['accepted_history_replayed_or_current_chain_reconciled'])
        self.assertFalse(handoff['restored_software_executed_or_parameters_loaded'])
        self.assertFalse(handoff['wallet_backup_seed_witness_or_owner_map_read'])
        self.assertFalse(handoff['financial_authority_setup_honesty_or_spend_readiness'])
        raw = (self.output / 'HANDOFF.json').read_bytes()
        self.assertEqual(closure.digest(raw), handoff['handoff_sha256'])
        self.assertNotIn('handoff_sha256', json.loads(raw))
        self.assertEqual((self.output / 'HANDOFF.json').stat().st_mode & 0o777, 0o400)

    def test_missing_exit_key_role_refuses_before_any_fetch_or_output(self):
        self.manifest['required_roles'].pop('exit-proving-key')
        fetch = SyntheticFetcher(self.contents)
        with self.assertRaisesRegex(closure.Refused, 'complete-lifecycle-role-set'):
            self.restore(fetch)
        self.assertEqual(fetch.calls, [])
        self.assertFalse(self.output.exists())

    def test_missing_role_object_refuses(self):
        self.manifest['required_roles']['exit-proving-key'] = 'missing'
        with self.assertRaisesRegex(closure.Refused, 'required-role-object-missing'):
            self.check()

    def test_missing_history_dependency_refuses(self):
        self.manifest['dependencies']['accepted-history-index'] = ['missing-page']
        with self.assertRaisesRegex(closure.Refused, 'canonical-dependency-edges'):
            self.check()

    def test_extra_unreachable_selected_payload_refuses(self):
        self.manifest['dependencies']['wallet-software'] = []
        with self.assertRaisesRegex(closure.Refused, 'unreachable-extra-object'):
            self.check()

    def test_cycle_refuses(self):
        self.manifest['dependencies']['history-page-0'] = ['accepted-history-index']
        with self.assertRaisesRegex(closure.Refused, 'dependency-cycle'):
            self.check()

    def test_duplicate_dependency_refuses(self):
        self.manifest['dependencies']['wallet-software'] = ['wallet-library'] * 2
        with self.assertRaisesRegex(closure.Refused, 'canonical-dependency-edges'):
            self.check()

    def test_dependency_map_must_cover_every_selected_object(self):
        self.manifest['dependencies'].pop('wallet-library')
        with self.assertRaisesRegex(closure.Refused, 'exact-dependency-object-set'):
            self.check()

    def test_changed_external_closure_refuses(self):
        raw = closure.encoded(self.manifest)
        with self.assertRaisesRegex(closure.Refused, 'external-closure-pin'):
            closure.validate(raw + b' ', closure.digest(raw), closure.encoded(self.selection))

    def test_changed_transport_selection_refuses(self):
        raw = closure.encoded(self.manifest)
        with self.assertRaisesRegex(closure.Refused, 'external-publication-selection-pin'):
            closure.validate(raw, closure.digest(raw), closure.encoded(self.selection) + b' ')

    def test_other_profile_reference_refuses(self):
        self.manifest['profile_reference_sha256'] = 'f' * 64
        with self.assertRaisesRegex(closure.Refused, 'closure-selection-profile'):
            self.check()

    def test_foreign_domain_refuses(self):
        self.manifest['domain_hex32'] = 'f' * 64
        with self.assertRaisesRegex(closure.Refused, 'selected-lifecycle-domain'):
            self.check()

    def test_profile_role_cannot_name_an_unrelated_selected_object(self):
        # Keep all objects reachable so that the exact profile join is exercised.
        self.manifest['required_roles']['profile'] = 'wallet-library'
        self.manifest['dependencies']['wallet-library'] = ['profile']
        with self.assertRaisesRegex(closure.Refused, 'profile-object-pin'):
            self.check()

    def test_issuer_exclusion_is_required(self):
        with self.assertRaisesRegex(closure.Refused, 'issuer-exclusion-required'):
            self.restore(excluded=())
        self.assertFalse(self.output.exists())

    def test_every_issuer_host_must_be_denied(self):
        with self.assertRaisesRegex(closure.Refused, 'all-excluded-provider-hosts-denied'):
            self.restore(denied_hosts=())
        self.assertFalse(self.output.exists())

    def test_corrupt_replica_uses_another_authentic_replica(self):
        fetch = SyntheticFetcher(self.contents, {('replica', 'exit-proving-key')})
        handoff = self.restore(fetch)
        self.assertEqual(handoff['status'], 'DECLARED_CLOSURE_RESTORED')
        self.assertIn(('third', 'exit-proving-key'), [(p, a) for p, a, _ in fetch.calls])

    def test_all_replicas_missing_one_key_yields_no_owner_handoff_roles(self):
        bad = {(name, 'exit-proving-key') for name in ('replica', 'third')}
        handoff = self.restore(SyntheticFetcher(self.contents, bad))
        self.assertEqual(handoff['status'], 'INCOMPLETE')
        self.assertEqual(handoff['roles'], {})
        self.assertFalse(handoff['financial_authority_setup_honesty_or_spend_readiness'])

    def test_existing_output_is_preserved_and_refused(self):
        self.output.mkdir()
        sentinel = self.output / 'keep'
        sentinel.write_bytes(b'EXISTING PUBLIC BYTES')
        with self.assertRaisesRegex(closure.Refused, 'fresh-output-required'):
            self.restore()
        self.assertEqual(sentinel.read_bytes(), b'EXISTING PUBLIC BYTES')

    def test_duplicate_json_key_refuses(self):
        raw = closure.encoded(self.manifest).replace(
            b'"schema":', b'"schema":"ignored","schema":', 1)
        with self.assertRaisesRegex(closure.Refused, 'duplicate-json-key'):
            closure.validate(raw, closure.digest(raw), closure.encoded(self.selection))

    def test_a_shared_dependency_is_valid(self):
        self.manifest['dependencies']['relation-prover'] = ['wallet-library']
        self.check()

    def test_post_transport_final_mutation_prevents_owner_handoff(self):
        storage = closure.storage_module()
        original = storage.restore

        def mutate_after_transport(*args, **kwargs):
            result = original(*args, **kwargs)
            selected = next(item for item in result['restored_objects']
                            if item['asset_id'] == 'exit-proving-key')
            path = self.output / selected['relative_path']
            raw = path.read_bytes()
            path.write_bytes(b'X' + raw[1:])
            return result

        storage.restore = mutate_after_transport
        with patch.object(closure, 'storage_module', return_value=storage):
            handoff = self.restore()
        self.assertEqual(handoff['status'], 'INCOMPLETE')
        self.assertEqual(handoff['roles'], {})
        self.assertEqual(handoff['handoff_reauthentication_error'],
                         'whole-public-object-integrity')
        # The earlier transport receipt remains historical evidence; the
        # enclosing handoff explicitly refuses to promote it after mutation.
        transport = json.loads((self.output / 'RESULT.json').read_bytes())
        self.assertEqual(transport['status'], 'ALL_SELECTED_BYTES_RESTORED')


if __name__ == '__main__':
    unittest.main()
