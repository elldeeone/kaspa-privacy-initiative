"""Public synthetic host controls; no actual private role or generation runs.

Closed-role subprocesses are fixture adapters. They consume only host-created
config objects already in memory and write known public fixture capsules/seals.
The host reader refuses every contact/capsule/state/log body. Bootstrap controls
separately check real byte/hash ordering with harmless public study source.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

import payout_linkage_measure as host

METHOD = 'dc5026741ccc3bf8d19105a1528257d6934ed76877ec1fc3fe19e3e2b586834d'


class Fixture:
    def __init__(self, root):
        self.root = root; self.events = []; self.written = {}; self.commands = []; self.bad_seal = None
        self.private_root = root / 'admitted-root'
        self.fixed = self.private_root / 'diagnostics/private-payout-linkage-02'
        self.sha = 'ab' * 32; self.label('first')
        paths = [(host.HERE / 'payout_linkage_observe.py', host.OBSERVER_SHA),
                 (host.HERE / 'payout_privacy_attack.py', host.MATCHER_SHA),
                 (host.HERE / 'exit_wire.py', host.EXIT_SHA),
                 (host.HERE.parent / 'verification/wire.py', 'cd' * 32)]
        self.sources = {}
        for i, (path, pin) in enumerate(paths):
            leaf = root / ('public-source-fixture-' + str(i)); leaf.write_bytes(b'PUBLIC FIXTURE SOURCE ADMISSION ORACLE\n')
            self.sources[str(path)] = {'path': path, 'snapshot': leaf, 'sha256': pin, 'raw': b''}
        self.study = SimpleNamespace(METHOD_SHA=METHOD)

    def public(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = host.encoded(value); path.write_bytes(raw)
        return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

    def label(self, label):
        self.selected = {'trial_id': 'PUBLIC-TRIAL', 'attempt_id': label, 'label': label,
            'original_parent': str(self.private_root), 'private': str(self.fixed / label),
            'public': str(self.root / ('public-' + label))}
        self.selected['trial'] = self.public(self.root / 'TRIAL.json',
            {'trial_id': 'PUBLIC-TRIAL', 'private_original_parent': str(self.private_root)})
        contact = self.fixed / label / 'contact-owner-1/CONTACT.json'
        contact.parent.mkdir(parents=True, exist_ok=True); contact.write_bytes(b'PUBLIC FIXTURE: HOST MUST NOT OPEN\n'); contact.chmod(0o600)
        bound = {'method_sha256': METHOD, 'selection_sha256': self.sha,
                 'trial_id': 'PUBLIC-TRIAL', 'phase': 'private-payout-linkage-02', 'attempt_id': label}
        exits = {'schema': 'kpb-method02-unlabelled-exits/v1', 'binding': bound,
                 'arms': {arm: [{'exit_id': hashlib.sha256((arm + str(i)).encode()).hexdigest()}
                                for i in range(3)] for arm in ('A', 'B')}}
        output = Path(self.selected['public'])
        self.dispatcher = self.public(output / 'DISPATCHER.json', {'PUBLIC_FIXTURE_LABELS': True})
        self.catalog = {'schema': 'kpb-method02-generated-artifact-catalog/v1', 'selection_sha256': self.sha,
            'method_sha256': METHOD, 'trial_id': 'PUBLIC-TRIAL', 'controller_private_body_read_or_hash': False,
            'contact_private_leaf': str(contact), 'unlabelled_exits': self.public(output / 'EXITS.json', exits),
            'dispatcher': self.dispatcher, 'native_verification': None}
        self.catalog_ref = self.public(output / 'GENERATION.json', self.catalog)

    def read(self, path, pin=None):
        path = Path(path); self.events.append(('read', str(path)))
        if path.is_relative_to(self.private_root):
            raise AssertionError('HOST ATTEMPTED PRIVATE FIXTURE BODY READ')
        raw = path.read_bytes()
        if pin is not None: host.need(hashlib.sha256(raw).hexdigest() == pin, 'PUBLIC_FIXTURE_HASH')
        return raw

    def write(self, original, path, value, mode=0o400):
        self.written[str(path)] = copy.deepcopy(value)
        return original(path, value, mode)

    def run(self, argv, **kwargs):
        binds = {argv[i + 2]: (argv[i], Path(argv[i + 1]))
                 for i, value in enumerate(argv) if value in ('--ro-bind', '--bind')}
        operation = argv[-1]; self.events.append(('role', operation)); self.commands.append((operation, binds, argv))
        config = self.written[str(binds['/CONFIG.json'][1])]
        output = binds['/out'][1]
        if operation == 'postseal-score':
            result = {'schema': 'kpb-method02-public-paired-linkage-result/v1', 'binding': config['binding'],
                'all_predictions_sealed_before_truth': True, 'all_models_bound_to_exact_selected_exit_universes': True,
                'same_position_cross_arm_linkage_included': True, 'private_contacts_salts_models_or_keys_exported': False,
                'overall_crypto_dispatcher_or_terminal_privacy_qualified': False, 'status': 'UNQUALIFIED'}
            host.write_new(output / 'RESULT.json', result)
        else:
            view = operation.split('-')[0].upper()
            capsule = binds['/private-output'][1] / 'PREDICTIONS.json'
            capsule.write_bytes(b'PUBLIC FIXTURE CAPSULE: HOST MUST NOT OPEN\n'); capsule.chmod(0o400)
            seal = {'schema': 'kpb-method02-public-prediction-seal/v1', 'binding': config['binding'], 'view': view,
                'commitment_sha256': 'ab' * 32, 'exits_sha256': config['exits_sha256'],
                'predictions_frozen_before_truth': True, 'private_contact_or_prediction_records_exported': False}
            if self.bad_seal == view: seal['view'] = 'WRONG'
            host.write_new(output / 'SEAL.json', seal)
        return SimpleNamespace(returncode=0)


class HostControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='method02-public-host-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name)); original_write = host.write_new
        self.patches = [patch.object(host, 'load_runtime', side_effect=lambda *_: (self.f.read, self.f.study, self.f.selected, self.f.sources)),
            patch.object(host, 'write_new', side_effect=lambda p, v, mode=0o400: self.f.write(original_write, p, v, mode)),
            patch.object(host.subprocess, 'run', side_effect=self.f.run)]
        for p in self.patches: p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patches)])

    def measure(self):
        return host.measure('/PUBLIC-SELECTED-FIXTURE.json', self.f.sha,
                            self.f.catalog_ref['path'], self.f.catalog_ref['sha256'])

    def test_contact_guarded_seal_precedes_labels_and_all_seals_precede_score(self):
        row = self.measure(); events = self.f.events
        contact = str(Path(self.f.selected['public']) / 'measurement/CONTACT/SEAL.json')
        self.assertLess(events.index(('read', contact)), events.index(('read', self.f.dispatcher['path'])))
        score = events.index(('role', 'postseal-score'))
        for view in host.VIEWS:
            path = str(Path(self.f.selected['public']) / 'measurement' / view / 'SEAL.json')
            self.assertLess(events.index(('read', path)), score)
        self.assertEqual([c[0] for c in self.f.commands],
                         ['contact-observe', 'dispatcher-observe', 'union-observe', 'postseal-score'])
        result = json.loads(Path(row['path']).read_bytes())
        self.assertFalse(result['native_verification_complete'])
        self.assertFalse(result['overall_privacy_qualified'])
        score_file = Path(result['public_result']['path'])
        self.assertEqual(json.loads(score_file.read_bytes())['status'], 'UNQUALIFIED')
        self.assertFalse(any(Path(p).is_relative_to(self.f.private_root) for action, p in events if action == 'read'))

    def test_private_input_mounts_are_finite_leaves_without_original_runtime_or_pk(self):
        self.measure()
        for operation, binds, _ in self.f.commands:
            self.assertEqual(len([p for mode, p in binds.values() if p.name.startswith('public-source-fixture-')]), 4)
            for alias, (mode, path) in binds.items():
                self.assertFalse(alias.startswith(('/original', '/runtime', '/parameters', '/truth')))
                if mode == '--ro-bind' and alias != '/usr': self.assertTrue(path.is_file(), (alias, path))
                if mode == '--bind': self.assertIn(alias, ('/state', '/out', '/private-output'))
            self.assertEqual('/contact/CONTACT.json' in binds, operation in ('contact-observe', 'union-observe'))
            self.assertEqual('/public/DISPATCHER.json' in binds, operation != 'contact-observe')
            if operation == 'postseal-score':
                self.assertEqual(len([a for a in binds if a.startswith('/predictions/')]), 3)
                self.assertEqual(len([a for a in binds if a.startswith('/seals/')]), 3)

    def test_wrong_contact_seal_stops_before_any_dispatcher_read_or_mount(self):
        self.f.bad_seal = 'CONTACT'
        with self.assertRaises(ValueError): self.measure()
        self.assertNotIn(('read', self.f.dispatcher['path']), self.f.events)
        self.assertEqual([c[0] for c in self.f.commands], ['contact-observe'])

    def test_wrong_later_seal_prevents_score_launch(self):
        self.f.bad_seal = 'UNION'
        with self.assertRaises(ValueError): self.measure()
        self.assertNotIn(('role', 'postseal-score'), self.f.events)

    def test_new_labels_cannot_reset_same_admitted_original_state(self):
        self.measure(); first_count = len(self.f.commands)
        self.f.sha = 'cd' * 32; self.f.label('new-label-and-selection')
        with self.assertRaises(FileExistsError): self.measure()
        self.assertEqual(len(self.f.commands), first_count)
        self.assertTrue((self.f.fixed / 'observe-CONTACT/HOST-RESERVED.json').exists())


class BootstrapControls(unittest.TestCase):
    def test_external_bootstrap_then_all_snapshot_and_canonical_admission_before_study_exec(self):
        with tempfile.TemporaryDirectory(prefix='method02-public-bootstrap-fixture-') as directory:
            root = Path(directory); events = []; docs = {}
            study_path = host.HERE / 'payout_linkage_original.py'; guard_path = host.HERE / 'payout_linkage_guard.py'
            paths = [study_path, Path(host.__file__).absolute(), guard_path]
            selected = {'public': str(root), 'source_members': []}
            body = b'def load_selection(path,pin,read):\n    return {"PUBLIC_STUDY_EXECUTED":True}\n'
            for i, path in enumerate(paths):
                raw = body if path == study_path else ('PUBLIC-SOURCE-' + str(i)).encode()
                pin = hashlib.sha256(raw).hexdigest()
                selected['source_members'].append({'path': str(path), 'index': i, 'sha256': pin})
                docs[str(path)] = raw; docs[str(root / 'selected-public' / ('source-' + str(i)))] = raw
            selection_path = root / 'SELECTION.json'; raw = host.encoded(selected)
            docs[str(selection_path)] = raw; selection_sha = hashlib.sha256(raw).hexdigest()
            def read(path, pin=None):
                events.append(('read', str(path))); raw = docs[str(path)]
                host.need(pin is None or hashlib.sha256(raw).hexdigest() == pin, 'PUBLIC_BOOTSTRAP_HASH')
                return raw
            def load_guard(): events.append(('load_guard', None)); return {'read': read}
            def exec_bootstrap(module): events.append(('external_bootstrap', None)); module.load_guard = load_guard
            spec = SimpleNamespace(loader=SimpleNamespace(exec_module=exec_bootstrap))
            real_compile = compile
            def compile_study(raw, filename, mode):
                events.append(('study_compile', filename)); return real_compile(raw, filename, mode)
            with (
                patch.object(host.importlib.util, 'spec_from_file_location', return_value=spec),
                patch.object(host.importlib.util, 'module_from_spec', side_effect=lambda _: ModuleType('PUBLIC_BOOTSTRAP')),
                patch('runpy.run_path', side_effect=AssertionError('UNEXTENDED09_MUST_NOT_RUN_FIRST')),
                patch.object(host, 'compile', side_effect=compile_study, create=True),
            ):
                result = host.load_runtime(str(selection_path), selection_sha)
                self.assertEqual(result[2], {'PUBLIC_STUDY_EXECUTED': True})
                compiled = events.index(('study_compile', str(study_path)))
                self.assertEqual(events[:2], [('external_bootstrap', None), ('load_guard', None)])
                for path in paths: self.assertLess(events.index(('read', str(path))), compiled)
                events.clear(); docs[str(paths[1])] = b'CHANGED PUBLIC CANONICAL SOURCE'
                with self.assertRaises(ValueError): host.load_runtime(str(selection_path), selection_sha)
                self.assertFalse(any(action == 'study_compile' for action, _ in events))


if __name__ == '__main__':
    unittest.main()
