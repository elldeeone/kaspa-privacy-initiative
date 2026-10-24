#!/usr/bin/env python3
"""Small PUBLIC selection/exclusion controls; no external network or wallet IO."""
from pathlib import Path
from copy import deepcopy
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import restore


PUBLIC = {'role': b'PUBLIC_SYNTHETIC_ROLE_ONLY\n',
          'parameters': b'PUBLIC_SYNTHETIC_NOT_A_PROVING_KEY\n',
          'history': b'PUBLIC_SYNTHETIC_NOT_ACCEPTED_HISTORY\n'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fixture():
    providers = []
    for identifier in ('issuer', 'mirror', 'third'):
        providers.append({'id': identifier,
            'reported_infrastructure': identifier + '-infra',
            'reported_administration': identifier + '-admin',
            'reported_deletion_control': identifier + '-delete',
            'allowed_hosts': [identifier + '.invalid'],
            'reported_retention_until_utc': '2030-01-01T00:00:00Z',
            'reported_policy_sha256': restore.digest(b'UNVERIFIED_PUBLIC_POLICY_CLAIM')})
    kinds = {'role': 'parameter_manifest', 'parameters': 'public_parameters',
             'history': 'public_history'}
    assets = [{'id': name, 'kind': kinds[name], 'bytes': len(raw),
               'sha256': restore.digest(raw), 'replicas': [
                   {'provider_id': p, 'url': 'https://' + p + '.invalid/' + name}
                   for p in ('issuer', 'mirror', 'third')]}
              for name, raw in PUBLIC.items()]
    return {'schema': 'four-wallet-public-recovery-selection/v1',
            'profile_reference_sha256': restore.digest(b'UNFUNDED_SYNTHETIC_PROFILE_REFERENCE'),
            'providers': providers, 'assets': assets}


class PublicFixtureFetch:
    def __init__(self, behavior=None):
        self.calls = []
        self.behavior = behavior or {}

    def __call__(self, replica, asset, hosts, output):
        identifier = replica['provider_id']
        self.calls.append((identifier, asset['id'], frozenset(hosts)))
        operation = self.behavior.get(identifier, 'good')
        raw = PUBLIC[asset['id']]
        if operation == 'missing':
            raise restore.Refused('synthetic-provider-missing')
        if operation == 'corrupt':
            raw = b'X' + raw[1:]
        if operation == 'short':
            raw = raw[:-1]
        if operation == 'long':
            raw = raw + b'X'
        if callable(operation):
            operation(output)
        else:
            output.write_bytes(raw)
        return {'transport': 'SYNTHETIC_PUBLIC_BYTES_NOT_TLS_OR_INDEPENDENT_OPERATOR'}


class StorageControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='four-wallet-storage-controls-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_restore(self, value=None, fetch=None, **kwargs):
        raw = encoded(fixture() if value is None else value)
        result = restore.restore(raw, restore.digest(raw), self.root / 'out',
            excluded=('issuer',), denied_hosts=('issuer.invalid',),
            fetch=fetch or PublicFixtureFetch(), observed_at='2026-10-24T00:00:00Z', **kwargs)
        return result

    def assert_objects(self, result):
        self.assertEqual(result['status'], 'ALL_SELECTED_BYTES_RESTORED')
        self.assertEqual(len(result['restored_objects']), len(PUBLIC))
        for item in result['restored_objects']:
            self.assertEqual((self.root / 'out' / item['relative_path']).read_bytes(),
                             PUBLIC[item['asset_id']])
        self.assertFalse(result['control_assessment']['independent_administration_demonstrated'])
        self.assertFalse(result['control_assessment']['retention_guarantee_demonstrated'])
        self.assertFalse(result['financial_authority_setup_honesty_backing_currentness_or_spend_readiness'])

    def test_primary_excluded_all_exact_public_objects_restore_from_mirror(self):
        fetch = PublicFixtureFetch()
        result = self.run_restore(fetch=fetch)
        self.assert_objects(result)
        self.assertEqual([p for p, _, _ in fetch.calls], ['mirror'] * len(PUBLIC))

    def test_unverified_future_retention_is_never_a_guarantee(self):
        result = self.run_restore()
        self.assert_objects(result)
        self.assertEqual(result['control_assessment']['provider_reports'][0]
                         ['retention_claim_status'], 'UNVERIFIED_FUTURE_CLAIM')

    def test_expired_retention_does_not_block_authentic_recovery(self):
        value = fixture()
        value['providers'][1]['reported_retention_until_utc'] = '2020-01-01T00:00:00Z'
        result = self.run_restore(value)
        self.assert_objects(result)
        self.assertEqual(result['control_assessment']['provider_reports'][0]
                         ['retention_claim_status'], 'UNVERIFIED_EXPIRED_CLAIM')

    def test_no_retention_claim_does_not_become_an_empty_balance(self):
        value = fixture()
        value['providers'][1]['reported_retention_until_utc'] = None
        value['providers'][1]['reported_policy_sha256'] = None
        result = self.run_restore(value)
        self.assert_objects(result)
        self.assertEqual(result['control_assessment']['provider_reports'][0]
                         ['retention_claim_status'], 'NO_CLAIM')

    def test_malformed_retention_claim_does_not_block_authentic_recovery(self):
        value = fixture()
        value['providers'][1]['reported_retention_until_utc'] = '2026-02-30T00:00:00Z'
        result = self.run_restore(value)
        self.assert_objects(result)
        report = result['control_assessment']['provider_reports'][0]
        self.assertEqual(report['retention_claim_status'], 'MALFORMED_UNVERIFIED_CLAIM')
        self.assertIsNone(report['reported_retention_until_utc'])

    def test_malformed_policy_digest_does_not_block_authentic_recovery(self):
        value = fixture()
        value['providers'][1]['reported_policy_sha256'] = 'NOT_A_CANONICAL_DIGEST'
        result = self.run_restore(value)
        self.assert_objects(result)
        self.assertEqual(result['control_assessment']['provider_reports'][0]
                         ['reported_policy_pin_status'], 'MALFORMED_UNVERIFIED_CLAIM')

    def test_different_provider_names_do_not_hide_same_administrator(self):
        value = fixture()
        value['providers'][1]['reported_administration'] = 'issuer-admin'
        value['providers'][1]['reported_deletion_control'] = 'issuer-delete'
        result = self.run_restore(value)
        self.assert_objects(result)
        report = result['control_assessment']['provider_reports'][0]
        self.assertTrue(report['same_reported_administration_as_excluded'])
        self.assertTrue(report['same_reported_deletion_control_as_excluded'])

    def test_all_allowed_replicas_missing_remains_incomplete(self):
        fetch = PublicFixtureFetch({'mirror': 'missing', 'third': 'missing'})
        result = self.run_restore(fetch=fetch)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['restored_objects'], [])
        self.assertEqual([p for p, _, _ in fetch.calls], ['mirror', 'third'])

    def test_corrupt_mirror_uses_exact_third_replica(self):
        fetch = PublicFixtureFetch({'mirror': 'corrupt'})
        result = self.run_restore(fetch=fetch)
        self.assert_objects(result)
        self.assertEqual([p for p, _, _ in fetch.calls], ['mirror', 'third'] * len(PUBLIC))

    def test_truncated_mirror_uses_exact_third_replica(self):
        result = self.run_restore(fetch=PublicFixtureFetch({'mirror': 'short'}))
        self.assert_objects(result)

    def test_oversized_mirror_uses_exact_third_replica(self):
        result = self.run_restore(fetch=PublicFixtureFetch({'mirror': 'long'}))
        self.assert_objects(result)

    def test_denied_issuer_removed_from_other_provider_redirect_allowlist(self):
        value = fixture()
        value['providers'][1]['allowed_hosts'].append('issuer.invalid')
        fetch = PublicFixtureFetch()
        result = self.run_restore(value, fetch)
        self.assert_objects(result)
        self.assertTrue(all('issuer.invalid' not in hosts for _, _, hosts in fetch.calls))

    def test_other_provider_cannot_route_origin_back_to_denied_issuer(self):
        value = fixture()
        value['providers'][1]['allowed_hosts'].append('issuer.invalid')
        for item in value['assets']:
            item['replicas'] = [item['replicas'][0],
                {'provider_id': 'mirror', 'url': 'https://issuer.invalid/' + item['id']}]
        fetch = PublicFixtureFetch()
        result = self.run_restore(value, fetch)
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(fetch.calls, [])
        self.assertEqual(result['attempts'][0]['status'], 'DENIED_HOST_NO_REQUEST')

    def test_wrong_external_root_refuses_before_fetch_or_output(self):
        raw = encoded(fixture())
        fetch = PublicFixtureFetch()
        with self.assertRaisesRegex(restore.Refused, 'external-publication-selection-pin'):
            restore.restore(raw, '0' * 64, self.root / 'out', fetch=fetch)
        self.assertEqual(fetch.calls, [])
        self.assertFalse((self.root / 'out').exists())

    def test_malformed_selection_refuses_before_fetch_or_output(self):
        variants = []
        for field, bad in [('bytes', True), ('bytes', -1), ('kind', []),
                           ('sha256', '0' * 63), ('id', '../outside')]:
            value = fixture()
            value['assets'][0][field] = bad
            variants.append(value)
        value = fixture(); value['assets'].append(deepcopy(value['assets'][0])); variants.append(value)
        value = fixture(); value['assets'][0]['replicas'][0]['provider_id'] = 'unknown'; variants.append(value)
        value = fixture(); value['assets'][0]['replicas'][0]['url'] += '?token=unpublished'; variants.append(value)
        value = fixture(); value['assets'][0]['replicas'][0]['url'] += '\n'; variants.append(value)
        value = fixture(); value['providers'][1]['allowed_hosts'] = ['MIRROR.invalid']; variants.append(value)
        for value in variants:
            with self.subTest(value=value):
                raw = encoded(value); fetch = PublicFixtureFetch()
                with self.assertRaises(restore.Refused):
                    restore.restore(raw, restore.digest(raw), self.root / 'out', fetch=fetch)
                self.assertEqual(fetch.calls, [])
                self.assertFalse((self.root / 'out').exists())

    def test_duplicate_json_and_fractional_byte_count_refuse(self):
        originals = (b'{"schema":1,"schema":2}', encoded(fixture()).replace(
            b'"bytes":', b'"bytes":1.5,"old_bytes":', 1))
        for raw in originals:
            with self.assertRaises(restore.Refused):
                restore.restore(raw, restore.digest(raw), self.root / 'out', fetch=PublicFixtureFetch())
        self.assertFalse((self.root / 'out').exists())

    def test_dotdot_output_refuses_before_creation(self):
        raw = encoded(fixture())
        with self.assertRaisesRegex(restore.Refused, 'canonical-output-path'):
            restore.restore(raw, restore.digest(raw), self.root / 'not-created' / '..' / 'out',
                            fetch=PublicFixtureFetch())
        self.assertFalse((self.root / 'not-created').exists())

    def test_existing_output_is_never_clobbered(self):
        (self.root / 'out').mkdir()
        (self.root / 'out' / 'sentinel').write_bytes(b'PUBLIC_EXISTING_SENTINEL')
        with self.assertRaisesRegex(restore.Refused, 'fresh-output-required'):
            self.run_restore()
        self.assertEqual((self.root / 'out' / 'sentinel').read_bytes(), b'PUBLIC_EXISTING_SENTINEL')

    def test_symlink_parent_refuses_before_fetch(self):
        (self.root / 'real').mkdir()
        (self.root / 'alias').symlink_to(self.root / 'real', target_is_directory=True)
        raw = encoded(fixture()); fetch = PublicFixtureFetch()
        with self.assertRaisesRegex(restore.Refused, 'output-parent-symlink'):
            restore.restore(raw, restore.digest(raw), self.root / 'alias' / 'out', fetch=fetch)
        self.assertEqual(fetch.calls, [])

    def test_symlink_candidate_is_not_opened_and_remains_incomplete(self):
        sentinel = self.root / 'public-sentinel'
        sentinel.write_bytes(PUBLIC['role'])
        def symlink(path): path.symlink_to(sentinel)
        value = fixture()
        for item in value['assets']:
            item['replicas'] = item['replicas'][:2]
        with patch.object(restore.os, 'open', side_effect=AssertionError('candidate opened')) as opened:
            result = self.run_restore(value, PublicFixtureFetch({'mirror': symlink}))
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(opened.call_count, 0)

    def test_hardlink_candidate_payload_is_not_read(self):
        sentinel = self.root / 'public-sentinel'
        sentinel.write_bytes(PUBLIC['role'])
        def hardlink(path): os.link(sentinel, path)
        value = fixture()
        for item in value['assets']:
            item['replicas'] = item['replicas'][:2]
        with patch.object(restore.os, 'fdopen', side_effect=AssertionError('candidate payload read')) as read:
            result = self.run_restore(value, PublicFixtureFetch({'mirror': hardlink}))
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(read.call_count, 0)

    def test_replaced_candidate_cannot_be_exported_as_verified(self):
        original_link = restore.os.link
        def swap(source, target, **kwargs):
            source = Path(source)
            replacement = source.with_suffix('.public-swap')
            raw = source.read_bytes()
            replacement.write_bytes(b'X' + raw[1:])
            restore.os.replace(replacement, source)
            return original_link(source, target, **kwargs)
        with patch.object(restore.os, 'link', side_effect=swap):
            result = self.run_restore()
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['restored_objects'], [])
        self.assertTrue(all(attempt['reason'] == 'final-public-object-inode-binding'
                            for attempt in result['attempts']))
        self.assertEqual(len(list((self.root / 'out' / 'objects').glob('*--' +
                             restore.digest(PUBLIC['role'])))), 0)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(StorageControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({'schema': 'four-wallet-storage-public-controls/v1',
        'tests_run': result.testsRun, 'failures': len(result.failures),
        'errors': len(result.errors), 'external_network_TLS_actual_provider_or_retention_exercised': False,
        'PK_backup_seed_witness_or_financial_runtime_read': False}, sort_keys=True))
    raise SystemExit(not result.wasSuccessful())
