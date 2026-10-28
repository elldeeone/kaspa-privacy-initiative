"""Public source/fixture controls; no Original, proof, capture or network call."""
import ast
import copy
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
import types
import unittest
from unittest import mock


IDENTITY = [bytes.fromhex(value) for value in (
    'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
    'd68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf',
    'ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700',
    'a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0',
    'ce821210834e870b6eebe3851b0b003b1b33cf343b1a17a996987f35dda514b5')]


def run_public_controls(admitted_sources):
    """Caller supplies guard-admitted PUBLIC source bytes, never private data."""
    source = admitted_sources['method03_generation.py'].decode()
    tree = ast.parse(source)
    names = {'need', 'checked', 'candidate_metadata', 'append_metadata', 'save', 'reference', 'run_role',
             'validate_parameters', 'bootstrap_command'}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {'Path': Path, 'os': os, 'stat': stat, 'json': json,
        'genesis': types.SimpleNamespace(EXPECTED_IDENTITY=tuple(IDENTITY)),
        'PHASE': 'private-exit-route-03', 'ARMS': {'A': {'index': 11, 'origin': 'controller'},
            'B': {'index': 13, 'origin': 'owner-pipe'}}, 'METHOD02_LABEL': 'new-profile-original-01',
        'DRAFT_SHA': '0b4f01b0cc38963d9117248fa9ee3449928b4a36f00b0aa9e8cf4cd7d77694a6',
        'HERE': Path('/public-fixture/finite-source')}
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<admitted-public-functions>', 'exec'), namespace)

    class Controls(unittest.TestCase):
        def selected(self):
            return {'schema': 'kpb-method03-wallet-source-selection/v1', 'phase': namespace['PHASE'],
                'arms': copy.deepcopy(namespace['ARMS']), 'value_sompi': 200_000_000,
                'fee_sompi': 1, 'reserve_sompi': 6_000_000_000,
                'identity': [word.hex() for word in IDENTITY], 'profile_hex32': IDENTITY[2].hex(),
                'domain_hex32': IDENTITY[3].hex(), 'bootstrap': {'label': 'method03-public-fixture',
                    'existing_trial_input_allowed': False, 'new_Original_count': 3},
                'status': 'UNSELECTED_SOURCE_ONLY', 'budget': {'policy': 'UNSELECTED'},
                'method': {'sha256': namespace['DRAFT_SHA']}, 'public': '/public-fixture/output',
                'source_members': [{'path': '/public-fixture/finite-source/method03_entry.py', 'index': 7}]}

        def test_source_candidate_never_grants_execution(self):
            selected = self.selected()
            self.assertIs(namespace['validate_parameters'](selected), selected)
            with self.assertRaisesRegex(ValueError, 'freeze-required'):
                namespace['validate_parameters'](selected, execution=True)

        def test_fixed_economics_reject_bool_and_retuning(self):
            for key, bad in [('fee_sompi', True), ('value_sompi', 199_999_999),
                             ('reserve_sompi', 5_000_000_000)]:
                selected = self.selected(); selected[key] = bad
                with self.assertRaises(ValueError): namespace['validate_parameters'](selected)

        def test_no_caller_profile_or_old_Original_set(self):
            for change in ('domain', 'profile', 'identity', 'old', 'existing'):
                selected = self.selected()
                if change == 'domain': selected['domain_hex32'] = '11' * 32
                if change == 'profile': selected['profile_hex32'] = '22' * 32
                if change == 'identity': selected['identity'][0] = '33' * 32
                if change == 'old': selected['bootstrap']['label'] = namespace['METHOD02_LABEL']
                if change == 'existing': selected['bootstrap']['existing_trial_input_allowed'] = True
                with self.assertRaises(ValueError): namespace['validate_parameters'](selected)

        def test_bootstrap_command_has_no_seed_or_existing_trial_argument(self):
            command = namespace['bootstrap_command'](self.selected(), 'ab' * 32, '/public-fixture/FINAL.json')
            self.assertEqual(command[-2:], ['--program', 'bootstrap'])
            self.assertEqual(command[command.index('--selection') + 1], '/public-fixture/FINAL.json')
            self.assertNotIn('--recipient', command); self.assertNotIn('--seed', command)
            self.assertNotIn('--bootstrap-trial', command)

        def test_candidate_lookup_is_metadata_only(self):
            with tempfile.TemporaryDirectory(prefix='public-method03-metadata-') as directory:
                path = Path(directory) / 'PUBLIC-KNOWN-FAKE-CANDIDATE.json'
                path.write_bytes(b'public known fake fixture only'); path.chmod(0o600)
                with mock.patch('builtins.open', side_effect=AssertionError('body opened')), \
                     mock.patch.object(os, 'open', side_effect=AssertionError('body opened')):
                    result = namespace['candidate_metadata'](path)
                self.assertEqual(result['bytes'], 30); self.assertEqual(result['nlink'], 1)
                self.assertNotIn('sha256', result)

        def test_candidate_aliases_and_broad_modes_refuse(self):
            with tempfile.TemporaryDirectory(prefix='public-method03-alias-') as directory:
                path = Path(directory) / 'PUBLIC-FAKE'; path.write_bytes(b'public'); path.chmod(0o644)
                with self.assertRaises(ValueError): namespace['candidate_metadata'](path)
                path.chmod(0o600); alias = Path(directory) / 'PUBLIC-HARDLINK'; os.link(path, alias)
                with self.assertRaises(ValueError): namespace['candidate_metadata'](path)

        def test_journal_retains_concurrent_records_and_partial_writes(self):
            with tempfile.TemporaryDirectory(prefix='public-method03-journal-') as directory:
                fd = os.open(Path(directory) / 'PUBLIC-JOURNAL.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                real_write = os.write
                def short_write(target, raw): return real_write(target, raw[:3])
                lock = threading.Lock()
                try:
                    with mock.patch.object(os, 'write', side_effect=short_write):
                        threads = [threading.Thread(target=namespace['append_metadata'],
                            args=(fd, {'public_event': value}, lock)) for value in range(12)]
                        for thread in threads: thread.start()
                        for thread in threads: thread.join()
                finally: os.close(fd)
                values = [json.loads(line)['public_event'] for line in
                          (Path(directory) / 'PUBLIC-JOURNAL.jsonl').read_text().splitlines()]
                self.assertEqual(sorted(values), list(range(12)))

        def test_receiver_requires_consumed_record_before_Original_read(self):
            worker = ast.parse(admitted_sources['method03_worker.py'])
            receiver = next(node for node in worker.body if isinstance(node, ast.FunctionDef) and node.name == 'receiver')
            text = ast.unparse(receiver)
            self.assertLess(text.index('/budget/ORIGINAL.json'), text.index('load_backup'))
            self.assertIn('invoice(4294967295)', text)
            prove = next(node for node in worker.body if isinstance(node, ast.FunctionDef) and node.name == 'prove')
            text = ast.unparse(prove)
            self.assertIn('fresh_payout(context, claim.nf, action)', text)
            self.assertNotIn('native_pk', text)
            self.assertNotIn("arm == 'A'", text)

        def test_no_hidden_publication_order_or_old_profile_authorizer(self):
            worker = admitted_sources['method03_worker.py'].decode()
            self.assertNotIn('PUBLICATION-ORDER', worker)
            self.assertNotIn('baseline_wallet', worker)
            self.assertNotIn('def publish(', worker)
            self.assertIn("('A', 11), ('B', 13)", worker)

        def test_runtime_entry_refuses_source_only_before_bootstrap(self):
            entry = admitted_sources['method03_entry.py'].decode()
            self.assertLess(entry.index('METHOD03-runtime-source-and-budget-not-frozen'),
                            entry.index("programs ="))
            self.assertIn('METHOD03-production-budget-not-selected', entry)
            self.assertIn('METHOD03-bootstrap-arguments-are-frozen', entry)

        def test_guard_reuses_all_eight_functions_and_adds_only_seventh_root(self):
            old = ast.parse(admitted_sources['payout_linkage_guard.py'])
            new = ast.parse(admitted_sources['method03_guard.py'])
            a = {n.name: ast.dump(n, include_attributes=False) for n in old.body if isinstance(n, ast.FunctionDef)}
            b = {n.name: ast.dump(n, include_attributes=False) for n in new.body if isinstance(n, ast.FunctionDef)}
            self.assertEqual(a, b)
            self.assertIn('/assets/ingress-runtime/tor-state', admitted_sources['method03_guard.py'].decode())

        def test_root_policy_refusal_precedes_Original_bootstrap(self):
            function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'execute')
            text = ast.unparse(function)
            self.assertLess(text.index('production-budget-policy-and-registry-not-selected'),
                            text.index('subprocess.run'))

        def test_actual_early_controller_clock_precedes_bootstrap(self):
            function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'execute')
            text = ast.unparse(function)
            self.assertLess(text.index("clock_snapshot('controller')"), text.index('subprocess.run'))
            self.assertIn('early_controller_clock_ref=early_ref', text)

        def test_transport_receives_guard_context_not_bare_read_function(self):
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute)]
            getter = next(node for node in calls if node.func.attr == 'selected_transport_source_pins')
            self.assertIsInstance(getter.args[0], ast.Dict)
            opened = next(node for node in calls if node.func.attr == 'open_vector')
            guard = next(item.value for item in opened.keywords if item.arg == 'guard')
            self.assertIsInstance(guard, ast.Dict)
            self.assertIn("'read': read", ast.unparse(guard))

        def test_owner_launcher_uses_callable_read_without_private_inputs(self):
            import hashlib
            import sys
            with tempfile.TemporaryDirectory(prefix='public-method03-launch-') as directory:
                root = Path(directory); shared = root / 'public/selected-public'; shared.mkdir(parents=True)
                runtime = root / 'PUBLIC-FAKE-RUNTIME'; runtime.write_bytes(b'known public fixture')
                own, output = root / 'PUBLIC-FAKE-OWN', root / 'PUBLIC-FAKE-OUT'
                admitted = []
                def read(path, expected=None):
                    path = Path(path); admitted.append(str(path)); return path.read_bytes()
                def fake_run(argv, **kwargs):
                    self.assertIn(str(runtime), admitted)
                    (output / 'PUBLIC.json').write_text('{"public_fixture":true}\n')
                    return types.SimpleNamespace(returncode=0)
                selected = self.selected()
                selected.update(public=str(root / 'public'), attempt_id='public-fixture', trial_id='public-fixture',
                    domain_hex32=IDENTITY[3].hex(), profile_hex32=IDENTITY[2].hex(), binary_sha256='01'*32,
                    output_manifest_sha256='02'*32, exit_manifest_sha256='03'*32, js_leaf_map_sha256='04'*32,
                    tail_sha256='05'*32, _budget_claim=object(), source_members=[],
                    runtime_members=[{'path':'/runtime/PUBLIC-FAKE','host_path':str(runtime),'sha256':'06'*32}])
                fake_budget = types.SimpleNamespace(describe_claim=lambda claim:
                    {'source_sha256':'07'*32,'slot_grammar_sha256':'08'*32,'spec_sha256':'09'*32})
                context = dict(namespace, guard=lambda:{'read':read}, hashlib=hashlib, time=time,
                    boundary=types.SimpleNamespace(encoded=lambda x:(json.dumps(x)+'\n').encode()),
                    bootstrap=types.SimpleNamespace(JS_ROOT=root/'PUBLIC-JS', PARAMETERS=root/'PUBLIC-PARAMETERS',CLEAN={}),
                    lifecycle=types.SimpleNamespace(EXIT_PARAMETERS=root/'PUBLIC-EXIT-PARAMETERS'),
                    subprocess=types.SimpleNamespace(run=fake_run))
                fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_role')
                exec(compile(ast.Module(body=[fn], type_ignores=[]), '<admitted-owner-launcher>', 'exec'), context)
                # Helper functions need this detached fixture namespace as globals too.
                for key in ('save','reference'):
                    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == key)
                    exec(compile(ast.Module(body=[node], type_ignores=[]), '<public-launch-helper>', 'exec'), context)
                with mock.patch.dict(sys.modules, {'method03_budget':fake_budget}):
                    result = context['run_role'](selected,'0a'*32,'feed','PUBLIC-FAKE-ROLE',own,output,[])
                self.assertEqual(result['path'], str(output/'PUBLIC.json'))
                self.assertTrue((output/'ROUTE.json').exists())

        def test_public_export_translation_never_reads_or_hashes_body(self):
            native = ast.parse(admitted_sources['method03_native_host.py'])
            body = [n for n in native.body if isinstance(n, ast.FunctionDef)
                    and n.name in ('need', 'checked', 'translate_ref')]
            scope = {'Path': Path, 'os': os, 'stat': stat}
            exec(compile(ast.Module(body=body, type_ignores=[]), '<public-native-ref-functions>', 'exec'), scope)
            with tempfile.TemporaryDirectory(prefix='public-method03-export-') as directory:
                root = Path(directory); (root / 'result').mkdir()
                (root / 'result/EXITS.json').write_bytes(b'PUBLIC KNOWN FIXTURE; NOT A CAPTURE')
                ref = {'path': '/public-output/result/EXITS.json', 'sha256': '01' * 32}
                with mock.patch('builtins.open', side_effect=AssertionError('body read')), \
                     mock.patch.object(os, 'open', side_effect=AssertionError('body read')):
                    result = scope['translate_ref'](ref, '/public-output', root)
                self.assertEqual(result['sha256'], ref['sha256'])
                with self.assertRaises(ValueError):
                    scope['translate_ref']({'path': '/native/result/INDEX.json', 'sha256': '01' * 32},
                                           '/public-output', root)

        def test_host_calls_stateful_permits_before_view_and_truth_mounts(self):
            host = ast.parse(admitted_sources['method03_measure.py'])
            function = next(n for n in host.body if isinstance(n, ast.FunctionDef) and n.name == 'measure')
            text = ast.unparse(function)
            self.assertLess(text.index('claim_view_intake_once'), text.index('run_role(operation'))
            self.assertLess(text.index('claim_view_intake_once'), text.index('owner_role(selected'))
            self.assertIn("primary_permit if label == 'PRIMARY'", text)
            self.assertLess(text.index('mark_views_sealed'), text.index('claim_truth_once'))
            self.assertLess(text.index('claim_truth_once'), text.index("'/truth/'"))
            self.assertLess(text.index('claim_aggregate_once'), text.index("run_role('aggregate'"))
            self.assertNotIn('read_bytes', text)

    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
    return {'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
            'passed': result.wasSuccessful(), 'public_fixture_only': True,
            'Original_note_proof_capture_or_network_execution': False, 'details': stream.getvalue()}
