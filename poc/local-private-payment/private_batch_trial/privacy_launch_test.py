"""Public fixture end-to-end launcher controls; no actual Original or truth."""
import copy
import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

import privacy_codec as codec
import privacy_launch as launch
import privacy_observer as observer
import privacy_owner
import privacy_test as model


def digest(raw): return hashlib.sha256(raw).hexdigest()


class LauncherControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real_read = staticmethod(runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'])
        cls.source_cache = {}
        for name in (*launch.CORE_PINS, 'privacy_launch.py'):
            path = launch.HERE / name; cls.source_cache[path] = cls.real_read(path)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kpb-public-privacy-launcher-fixture-')
        self.base = Path(self.tmp.name)
        self.private_base = self.base / 'fixture-private-route'
        self.bootstrap = self.base / 'public-bootstrap'
        self.lifecycle = self.base / 'public-lifecycle'
        self.label = 'public-launcher-fixture'
        self.private = self.private_base / self.label
        for component in codec.OWNERS: (self.private / ('owner-' + str(component))).mkdir(parents=True)
        self.method = self.base / 'PUBLIC-METHOD.txt'; self.method.write_bytes(b'PUBLIC FIXTURE METHOD')
        self.run_selection = self.base / 'PUBLIC-RUN.txt'; self.run_selection.write_bytes(b'PUBLIC FIXTURE RUN')
        self.bound = {**model.BOUND, 'method_sha256': digest(self.method.read_bytes()),
                      'selection_sha256': digest(self.run_selection.read_bytes())}
        self.read_paths = []; self.cache = dict(self.source_cache)
        def public_read(path, expected=None):
            path = Path(path); self.read_paths.append(path)
            self.assertFalse(path.is_relative_to(self.private_base), 'controller attempted a private-body read/hash')
            if path not in self.cache: self.cache[path] = self.real_read(path)
            raw = self.cache[path]
            if expected is not None: self.assertEqual(digest(raw), expected)
            return raw
        self.public_read = public_read
        self.patches = [patch.object(launch, 'PRIVATE', self.private_base),
            patch.object(launch, 'BOOTSTRAP_PUBLIC', self.bootstrap),
            patch.object(launch, 'LIFECYCLE_PUBLIC', self.lifecycle), patch.object(launch, 'METHOD', self.method),
            patch.object(launch.runpy, 'run_path', return_value={'read': public_read})]
        for value in self.patches: value.start()
        self.addCleanup(self.tmp.cleanup)
        for value in reversed(self.patches): self.addCleanup(value.stop)

    def save(self, path, value, mode=0o400):
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = value if type(value) is bytes else codec.encoded(value)
        path.write_bytes(raw); path.chmod(mode)
        return {'path': str(path), 'sha256': digest(raw)}

    def fixture(self, with_server=True):
        trial = {'schema': 'kpb-fresh-unfunded-private-original-trial/v1', 'trial_id': self.bound['trial_id'],
            'label': self.label, 'network_id': 'testnet-10', 'domain_hex32': launch.DOMAIN,
            'profile_id_hex32': launch.PROFILE, 'owner_count': 3,
            'private_original_parent': str(self.private), 'controller_read_or_hashed_private_bodies': False}
        trial_ref = self.save(self.bootstrap / self.label / 'TRIAL.json', trial)
        rounds = []
        for r in (1, 2):
            raw = bytearray(10685); raw[:8] = b'KPBAFX01'; raw[193:201] = b'KPBAEF01'
            raw[201:477] = bytes([r]) * 276
            for index, nf in enumerate(model.public(r)['nfs_hex32']):
                raw[193 + 404 + index * 96:193 + 436 + index * 96] = bytes.fromhex(nf)
            for index in range(6): raw[193 + 692 + index * 520:193 + 692 + (index + 1) * 520] = model.row(r, index)
            projection = self.save(self.base / ('PUBLIC-PROJECTION-' + str(r) + '.bin'), bytes(raw))
            batch = observer.batch_from_projection(r, bytes(raw))
            results = {}
            for operation in ('invoice', 'pay'):
                op_label = 'public-' + operation + '-r' + str(r); owners = []
                for component in codec.OWNERS:
                    own = self.private / 'operations' / op_label / ('owner-' + str(component)); own.mkdir(parents=True)
                    public = self.lifecycle / op_label / ('owner-' + str(component))
                    status = {'schema': 'kpb-original-lifecycle-operation/v1', 'operation': operation,
                        'private_original_or_witness_exported': False, 'accepted_backing_or_native_settlement': False}
                    self.save(public / 'PUBLIC.json', status)
                    owners.append({'owner_component': component, 'private_output_directory': str(own),
                        'public_receipt': str(public / 'PUBLIC.json'), 'status': status})
                    if operation == 'pay':
                        truth = codec.truth_record(self.bound, component, r, batch['context_sha256'],
                            bytes.fromhex(batch['nfs_hex32'][model.TRUTH_INPUTS[r - 1].index(component)]),
                            [model.row(r, index) for index, creator in enumerate(model.TRUTH_CREATORS[r - 1]) if creator == component])
                        salt = bytes([r + component + 1]) * 32
                        self.save(own / 'PRIVACY-TRUTH.json', {'schema': 'kpb-salted-owner-truth/v1',
                            'salt_hex32': salt.hex(), 'truth': truth}, 0o600)
                        self.save(public / 'PRIVACY-COMMITMENT.json', {'schema': 'kpb-owner-truth-commitment/v1',
                            'binding': self.bound, 'owner_component': component, 'round': r,
                            'salted_commitment_sha256': digest(privacy_owner.TRUTH_TAG + salt + codec.encoded(truth)),
                            'truth_or_identifiers_exported': False})
                        if component == 1:
                            self.save(own / 'COLLUDER-CONSTRAINTS.json', {'schema': 'kpb-private-colluder-constraints/v1',
                                'binding': self.bound, 'round': r, 'context_sha256': batch['context_sha256'],
                                'constraints': model.colluder_constraints(r)}, 0o600)
                value = {'schema': 'kpb-original-lifecycle-controller-result/v1', 'operation': operation,
                    'operation_id': op_label, 'bootstrap_trial_id': self.bound['trial_id'], 'round': r, 'owners': owners,
                    'controller_read_or_hashed_private_bodies': False, 'native_settlement_or_privacy_qualification': False}
                ref = self.save(self.lifecycle / op_label / 'RESULT.json', value); results[operation] = (ref, value)
            for component in codec.OWNERS:
                target = (component + r) % 3
                route = {'schema': 'kpb-observed-invoice-route/v1', 'round': r, 'source_owner_component': component,
                    'target_owner_component': target, 'invoice_leaf_path': results['invoice'][1]['owners'][target]['private_output_directory'] + '/INVOICE208.bin',
                    'source_operation_id': results['pay'][1]['operation_id'], 'target_invoice_operation_id': results['invoice'][1]['operation_id'],
                    'launch_monotonic_ns': 100, 'complete_monotonic_ns': 200, 'worker_returncode': 0}
                public = Path(results['pay'][1]['owners'][component]['public_receipt']).parent
                self.save(public / 'OBSERVED-INVOICE-ROUTE.json', route)
            extras = []
            if r == 1:
                failed = {**route, 'source_owner_component': 2, 'worker_returncode': 2,
                          'source_operation_id': 'public-failed-attempt'}
                ref = self.save(self.lifecycle / 'public-failed-attempt' / 'owner-2' / 'OBSERVED-INVOICE-ROUTE.json', failed)
                extras.append({'kind': 'invoice-route', **ref, 'route_owner': 2})
            rounds.append({'round': r, 'invoice_result': results['invoice'][0], 'pay_result': results['pay'][0],
                           'projection': projection, 'dispatcher_artifacts': extras})
        capture = None
        if with_server:
            root = self.private / 'diagnostics' / launch.DIAGNOSTIC / 'corrupt-server-1'
            self.save(root / 'PUBLIC-FIXTURE-RAW.json', {'opaque_public_model_bytes': True}, 0o600)
            capture = {'owner_component': 1, 'root': str(root), 'relative_leaves': ['PUBLIC-FIXTURE-RAW.json']}
        selected = {'schema': 'kpb-private-diagnostic-launch-selection/v1', 'binding': self.bound,
            'run_selection': {'path': str(self.run_selection), 'sha256': self.bound['selection_sha256']},
            'bootstrap_trial': trial_ref, 'source_members': [{'name': name, 'sha256': digest(raw)}
                for name, raw in ((path.name, raw) for path, raw in self.source_cache.items())],
            'rounds': rounds, 'corrupt_server_view': capture}
        return selected, self.save(self.base / 'PUBLIC-LAUNCH-SELECTION.json', selected)

    def test_actual_launcher_full_public_fixture_and_fixed_repeat_refusal(self):
        _, ref = self.fixture()
        plan = launch.run('observe', ref['path'], ref['sha256'])
        self.assertFalse(plan['executed'])
        with self.assertRaises((OSError, ValueError)):
            launch.run('score', ref['path'], ref['sha256'], 0, True)
        self.assertFalse((self.private / 'owner-0/diagnostics/private-batch-privacy/LAUNCH-CLOSED').exists())
        observed = launch.run('observe', ref['path'], ref['sha256'], execute=True)
        public = self.bootstrap / self.label / 'privacy-diagnostics'
        self.assertTrue((public / 'observe' / 'BARRIER.json').is_file())
        self.assertFalse(observed['private_bodies_read_or_hashed'])
        for component in codec.OWNERS:
            result = launch.run('score', ref['path'], ref['sha256'], component, True)
            self.assertFalse(result['private_bodies_read_or_hashed'])
        measured = launch.run('aggregate', ref['path'], ref['sha256'], execute=True)
        result = codec.parse(self.public_read(measured['public_result'], measured['public_result_sha256']))
        self.assertEqual([part['view'] for part in result['views']], list(codec.VIEWS))
        union = result['views'][-1]
        self.assertEqual([part['strict_H1_status'] for part in union['rounds']], ['FAIL', 'FAIL'])
        self.assertEqual(union['combined_terminal_status'], 'UNQUALIFIED')
        self.assertFalse(result['private_records_masks_or_per_owner_counts_exported'])
        with self.assertRaises(ValueError): launch.run('score', ref['path'], ref['sha256'], 0, True)
        with self.assertRaises(ValueError): launch.run('observe', ref['path'], ref['sha256'], execute=True)
        self.assertFalse(any(path.is_relative_to(self.private_base) for path in self.read_paths))

    def test_observer_cannot_select_honest_truth_or_wrong_corrupt_server(self):
        selected, _ = self.fixture()
        wrong = copy.deepcopy(selected)
        wrong['rounds'][0]['dispatcher_artifacts'] = [{'kind': 'dispatcher-metadata',
            'path': str(self.private / 'operations/public-pay-r1/owner-0/PRIVACY-TRUTH.json'),
            'sha256': None, 'route_owner': None}]
        ref = self.save(self.base / 'PUBLIC-WRONG-CAPTURE.json', wrong)
        with self.assertRaises(ValueError): launch.run('observe', ref['path'], ref['sha256'])
        wrong = copy.deepcopy(selected); wrong['corrupt_server_view']['owner_component'] = 0
        ref = self.save(self.base / 'PUBLIC-WRONG-SERVER.json', wrong)
        with self.assertRaises(ValueError): launch.run('observe', ref['path'], ref['sha256'])

    def test_wrong_bootstrap_owner_route_or_changed_core_source_refuses(self):
        selected, _ = self.fixture(with_server=False)
        for mutation in ('trial', 'source'):
            wrong = copy.deepcopy(selected)
            if mutation == 'trial': wrong['binding']['trial_id'] = 'a951be59-207b-487f-8b50-7145b70481ef'
            else: wrong['source_members'][0]['sha256'] = '00' * 32
            ref = self.save(self.base / ('PUBLIC-WRONG-' + mutation + '.json'), wrong)
            with self.assertRaises(ValueError): launch.run('observe', ref['path'], ref['sha256'])


if __name__ == '__main__': unittest.main()
