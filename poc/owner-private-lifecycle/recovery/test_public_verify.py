"""Synthetic public metadata/path controls; no RPC, owner or parameter reads."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('public_verify', Path(__file__).with_name('public_verify.py'))
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)
closed = verify.module('poc/owner-private-lifecycle/recovery/replay_closed.py')


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def fixture():
    ids = [f'{i + 1:064x}' for i in range(12)]
    rows = []
    for name in sorted(verify.ROLES | verify.CASES | {'terminal-prefix-page-00000'}):
        size, pin = verify.STATIC.get(name, (1, hashlib.sha256(name.encode()).hexdigest()))
        rows.append({'id': name, 'kind': 'public_history', 'bytes': size or 1, 'sha256': pin,
            'placement': 'objects/' + name, 'release_filename': name + '.json',
            'public_urls': [verify.RELEASE + name + '.json']})
    index = {'schema': 'kpx8-terminal-public-evidence-index/v1', 'domain_hex32': verify.DOMAIN,
        'financial_profile_sha256': verify.PROFILE, 'trial_id': 'synthetic-public-metadata',
        'accepted_pool_transaction_ids': ids,
        'accepted_cases': [{'transaction_id': value, 'kind': 'genesis' if i == 0 else 'batch' if i < 3 else 'exit',
            'objects': {k: f'accepted-case-{i:02d}-{k}' for k in ('case', 'validation', 'metrics')}}
            for i, value in enumerate(ids)],
        'checkpoint_sha256': '11' * 32, 'initial_R2_inventory_sha256': '22' * 32,
        'initial_R2_snapshot_changed': False, 'owner_client_associations_selected': False,
        'financial_verifier_or_consensus_claimed_by_packager': False,
        'availability_claimed_by_manifest': False, 'objects': rows}
    return index


def transport(index):
    raw = encoded(index)
    assets = [{'id': r['id'], 'kind': r['kind'], 'bytes': r['bytes'], 'sha256': r['sha256'],
               'replicas': [{'provider_id': 'github-release', 'url': u} for u in r['public_urls']]}
              for r in index['objects']]
    assets.append({'id': 'terminal-verification-manifest', 'kind': 'other_public_metadata', **identity(raw),
                   'replicas': [{'provider_id': 'github-release', 'url': verify.RELEASE + 'INDEX.json'}]})
    return raw, {'assets': assets}, identity(raw)


class Controls(unittest.TestCase):
    def test_pending_config_has_no_future_pins_and_enabled_requires_whole_identities(self):
        pending = {'schema': 'kpx8-public-verification-config/v1', 'enabled': False, 'reason': 'Not published'}
        self.assertEqual(verify.config(encoded(pending), closed), pending)
        pending['transport_selection'] = None
        with self.assertRaises(ValueError):
            verify.config(encoded(pending), closed)
        value = {'schema': 'kpx8-public-verification-config/v1', 'enabled': True,
            'transport_selection': {'url': verify.RELEASE + 'selection.json', 'bytes': 1, 'sha256': '11' * 32},
            'terminal_index': {'bytes': 1, 'sha256': '22' * 32}}
        self.assertTrue(verify.config(encoded(value), closed)['enabled'])
        for key, bad in [('bytes', True), ('sha256', 'pending')]:
            changed = copy.deepcopy(value); changed['terminal_index'][key] = bad
            with self.assertRaises(ValueError):
                verify.config(encoded(changed), closed)

    def test_duplicate_JSON_keys_rejected(self):
        with self.assertRaises(ValueError):
            verify.config(b'{"enabled":false,"enabled":true}', closed)

    def test_complete_twelve_case_index_matches_external_selection(self):
        value = fixture(); raw, selected, expected = transport(value)
        parsed, objects = verify.index(raw, selected, expected, closed)
        self.assertEqual(parsed, value)
        self.assertEqual(len(objects), len(verify.ROLES) + 36 + 1)

    def test_wrong_whole_index_pin_rejected(self):
        raw, selected, expected = transport(fixture()); expected['sha256'] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'external-index-identity'):
            verify.index(raw, selected, expected, closed)

    def test_traversal_duplicate_and_parent_placements_rejected(self):
        for mode in ('traversal', 'duplicate', 'parent'):
            value = fixture()
            if mode == 'traversal':
                value['objects'][0]['placement'] = '../outside'
            elif mode == 'duplicate':
                value['objects'][1]['placement'] = value['objects'][0]['placement']
            else:
                value['objects'][0]['placement'] = 'parent'
                value['objects'][1]['placement'] = 'parent/child'
            raw, selected, expected = transport(value)
            with self.assertRaises(ValueError, msg=mode):
                verify.index(raw, selected, expected, closed)

    def test_unselected_PK_or_thirteenth_case_role_rejected(self):
        for identifier in ('spend-pk', 'accepted-case-12-case'):
            value = fixture(); extra = copy.deepcopy(value['objects'][0]); extra['id'] = identifier
            extra['placement'] = identifier; value['objects'].append(extra)
            raw, selected, expected = transport(value)
            with self.assertRaisesRegex(ValueError, 'public-verification-role'):
                verify.index(raw, selected, expected, closed)

    def test_missing_case_wrong_role_or_selection_identity_rejected(self):
        for mode in ('missing', 'role', 'identity'):
            value = fixture()
            if mode == 'missing':
                value['objects'] = [r for r in value['objects'] if r['id'] != 'accepted-case-11-case']
            elif mode == 'role':
                value['accepted_cases'][0]['objects']['case'] = 'accepted-case-01-case'
            raw, selected, expected = transport(value)
            if mode == 'identity':
                selected['assets'][0]['sha256'] = '00' * 32
            with self.assertRaises(ValueError, msg=mode):
                verify.index(raw, selected, expected, closed)

    def test_public_read_rejects_symlink_hardlink_and_wrong_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); original = base / 'public'
            original.write_bytes(b'public synthetic fixture')
            symbolic = base / 'symbolic'; symbolic.symlink_to(original)
            with self.assertRaises(ValueError):
                verify.read(symbolic)
            alias = base / 'alias'; os.link(original, alias)
            with self.assertRaises(ValueError):
                verify.read(alias)
            alias.unlink()
            with self.assertRaisesRegex(ValueError, 'whole-public-identity'):
                verify.read(original, '00' * 32)

    def test_same_ID_different_witness_budget_or_context_fails_complete_byte_comparison(self):
        for changed in ('signatureScript', 'computeBudget', 'entries'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); objects = {}
                for name, filename in [('terminal-history', 'HISTORY.json'), ('terminal-checkpoint', 'CHECKPOINT.json')]:
                    raw = encoded({'public': name}); (root / filename).write_bytes(raw); objects[name] = identity(raw)
                case = {'transaction': {'id': '44' * 32, 'inputs': [{'signatureScript': 'aa', 'computeBudget': 1800}]}, 'entries': []}
                for i in range(12):
                    path = root / f'native-{i:04d}/case.json'; path.parent.mkdir()
                    raw = encoded(case); path.write_bytes(raw); objects[f'accepted-case-{i:02d}-case'] = identity(raw)
                verify.compare_outputs(root, objects)
                altered = copy.deepcopy(case)
                if changed == 'entries':
                    altered['entries'] = [{'amount': 1}]
                else:
                    altered['transaction']['inputs'][0][changed] = 'bb' if changed == 'signatureScript' else 1799
                self.assertEqual(altered['transaction']['id'], case['transaction']['id'])
                (root / 'native-0005/case.json').write_bytes(encoded(altered))
                with self.assertRaisesRegex(ValueError, 'whole-public-identity'):
                    verify.compare_outputs(root, objects)

    def test_failure_does_not_write_into_existing_unselected_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); destination = base / 'existing'; destination.mkdir()
            value = {'schema': 'kpx8-public-verification-config/v1', 'enabled': True,
                'transport_selection': {'url': verify.RELEASE + 'selection.json', 'bytes': 1, 'sha256': '11' * 32},
                'terminal_index': {'bytes': 1, 'sha256': '22' * 32}}
            selected = base / 'config.json'; selected.write_bytes(encoded(value))
            args = ['public_verify.py', '--config', str(selected), '--execute', '--output', str(destination)]
            with (patch.object(verify, 'module', return_value=closed),
                  patch.object(verify, 'run', side_effect=ValueError('fresh-verification-output')),
                  patch('sys.argv', args), contextlib.redirect_stdout(io.StringIO())):
                with self.assertRaises(SystemExit) as stopped:
                    verify.main()
            self.assertEqual(stopped.exception.code, 2)
            self.assertEqual(list(destination.iterdir()), [])

    def test_failed_command_retains_bounded_actual_stdout_and_stderr(self):
        result = subprocess.CompletedProcess(['omitted'], 2,
            b'public prefix' + b'x' * 9000, b'loader: missing-library\xff\n')
        with patch.object(verify.subprocess, 'run', return_value=result):
            with self.assertRaises(verify.PublicCommandFailure) as failure:
                verify.command('isolated-public-runtime', ['not-recorded'])
        detail = failure.exception.detail
        self.assertEqual(detail['returncode'], 2)
        self.assertEqual(detail['stdout']['bytes'], len(result.stdout))
        self.assertTrue(detail['stdout']['truncated'])
        self.assertEqual(len(detail['stdout']['tail']), verify.DIAGNOSTIC_TAIL_BYTES)
        self.assertIn('missing-library', detail['stderr']['tail'])
        self.assertNotIn('not-recorded', json.dumps(detail))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('replay/stage/software', 'replay/stage/data', 'replay/public/replayed'):
                (root / name).mkdir(parents=True)
            for name in ('selection', 'descriptor', 'fetch'):
                (root / 'replay/public/replayed' / (name + '.json')).write_bytes(b'{}')
            packet = {'inputs': {name: {'sha256': str(i) * 64}
                                for i, name in enumerate(('selection', 'descriptor', 'fetch'), 1)}}
            with patch.object(verify.subprocess, 'run', return_value=result) as invoked:
                probe = verify.diagnostic_probe(root, packet, closed)
            self.assertFalse(probe['financial_acceptance'])
            self.assertEqual(probe['stage'], 'SDK')
            self.assertIn('missing-library', probe['stderr']['tail'])
            args, kwargs = invoked.call_args
            self.assertIn('--unshare-all', args[0]); self.assertIn('--clearenv', args[0])
            self.assertEqual(kwargs['env'], verify.CLEAN)
            self.assertEqual(args[0][-9:], ['/out/replayed/selection.json', '1' * 64,
                '/out/replayed/descriptor.json', '2' * 64, '/out/replayed/fetch.json', '3' * 64,
                '/data', '/diagnostic/SDK-VERIFICATION.json', '/work/sdk/kaspa'])
            (root / 'replay/public/replayed/SDK-VERIFICATION.json').write_bytes(b'{}')
            with patch.object(verify.subprocess, 'run') as not_invoked:
                self.assertEqual(verify.diagnostic_probe(root, packet, closed)['status'], 'SDK-report-already-exists')
            not_invoked.assert_not_called()

    def test_diagnostics_select_known_bounded_public_logs_and_reject_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); replay = root / 'replay'; replay.mkdir()
            stderr = replay / 'stderr.log'
            stderr.write_bytes(b'prefix' + b'e' * 9000 + b'actual nested failure')
            unselected = replay / 'unselected.log'; unselected.write_bytes(b'unselected')
            stdout = replay / 'stdout.log'; stdout.symlink_to(unselected)
            native = replay / 'public/replayed/native-0000/native'; native.mkdir(parents=True)
            metrics = native / 'metrics.json'; os.link(unselected, metrics)
            result = verify.retained_diagnostics(root)
            self.assertEqual(set(result), {'replay/stderr.log', 'replay/stdout.log',
                'replay/public/replayed/native-0000/native/metrics.json'})
            self.assertTrue(result['replay/stderr.log']['truncated'])
            self.assertTrue(result['replay/stderr.log']['tail'].endswith('actual nested failure'))
            self.assertEqual(result['replay/stdout.log'], {'unavailable': 'ValueError'})
            self.assertEqual(result['replay/public/replayed/native-0000/native/metrics.json'],
                             {'unavailable': 'ValueError'})

    def test_actual_failure_details_and_nested_logs_reach_small_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); destination = root / 'new'
            selected = root / 'config.json'
            selected.write_bytes(encoded({'schema': 'kpx8-public-verification-config/v1', 'enabled': True,
                'transport_selection': {'url': verify.RELEASE + 'selection.json', 'bytes': 1, 'sha256': '11' * 32},
                'terminal_index': {'bytes': 1, 'sha256': '22' * 32}}))

            def failed_run(value, output, closed_module, report):
                output.mkdir(); (output / 'replay').mkdir()
                (output / 'replay/stderr.log').write_bytes(b'public nested SDK traceback')
                report.update(fresh_output_created=True, phase='unchanged-complete-financial-replay',
                    diagnostic_probe={'status': 'diagnostic-only', 'returncode': 0, 'financial_acceptance': False})
                raise verify.PublicCommandFailure('unchanged-replay',
                    subprocess.CompletedProcess(['omitted'], 2, b'', b'outer real stderr'))

            with (patch.object(verify, 'module', return_value=closed),
                  patch.object(verify, 'run', side_effect=failed_run),
                  patch('sys.argv', ['public_verify.py', '--config', str(selected), '--execute', '--output', str(destination)]),
                  contextlib.redirect_stdout(io.StringIO())):
                with self.assertRaises(SystemExit) as stopped:
                    verify.main()
            self.assertEqual(stopped.exception.code, 2)
            report = json.loads((destination / 'RESULT.json').read_bytes())
            diagnostic = json.loads((destination / 'DIAGNOSTICS.json').read_bytes())
            self.assertEqual(report['status'], 'INCOMPLETE')
            self.assertEqual(report['failure_detail']['stderr']['tail'], 'outer real stderr')
            self.assertEqual(diagnostic['public_output_tails']['replay/stderr.log']['tail'],
                             'public nested SDK traceback')
            self.assertFalse(report['diagnostic_probe']['financial_acceptance'])

    def test_loader_diagnostics_authenticate_only_fixed_runtime_roles_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.CompletedProcess(['omitted'], 1, b'CXXABI version missing', b'')
            with (patch.object(verify, 'read', return_value=b'public authenticated ELF') as checked,
                  patch.object(verify.subprocess, 'run', return_value=result) as invoked):
                diagnostics = verify.loader_diagnostics(root)
            self.assertEqual(set(diagnostics), set(verify.STAGED_EXECUTABLES))
            self.assertEqual([row.args[1] for row in checked.call_args_list], list(verify.STAGED_EXECUTABLES.values()))
            self.assertEqual(invoked.call_count, 4)
            for row in invoked.call_args_list:
                self.assertEqual(row.args[0][0], '/usr/bin/ldd')
                self.assertEqual(row.kwargs['env'], verify.CLEAN)
            with (patch.object(verify, 'read', side_effect=ValueError('whole-public-identity')),
                  patch.object(verify.subprocess, 'run') as rejected):
                verify.loader_diagnostics(root)
            rejected.assert_not_called()


if __name__ == '__main__':
    unittest.main()
