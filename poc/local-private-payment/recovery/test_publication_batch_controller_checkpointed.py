"""Public model only: no Original stat/read, namespace, producer, or network.

The exact frozen core performs the real schema/hash/context/invocation joins.
Only public artifact I/O and producer/preparer/worker execution are fixture
adapters. Real fsync and fresh output writes exercise the checkpoint ordering.
"""
import copy
import errno
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import publication_batch_controller_checkpointed as checkpointed
import test_publication_batch_audit as model


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controller = checkpointed.Controller()

    def setUp(self):
        self.k = self.controller
        self.a, self.c = self.k.a, self.k.c
        self.temp = tempfile.TemporaryDirectory(prefix='checkpoint-public-fixture-', dir=checkpointed.OUTPUT_ROOT)
        self.root = Path(self.temp.name)
        self.patches = [patch.object(checkpointed, 'OUTPUT_ROOT', self.root),
                        patch.object(model, 'PREPARED', checkpointed.PREPARED_SHA),
                        patch.object(model, 'a', self.a)]
        for p in self.patches:
            p.start()
        self.f = model.fixture()
        # The old generic fixture predates the fixed producer path identity.
        self.f['batches'][0]['producer_preparation']['result']['archive'] = {
            'path': 'data.tar', **self.f['index']['archive'],
            'members': sum(c['path'].startswith('members/') for c in self.f['index']['candidates'])}
        self.docs = {}
        self.value = {'index': {'path': '/known-public/INDEX.json', 'sha256': self.f['index_sha']},
            'batch_plan': {'path': '/known-public/PLAN.json', 'sha256': self.f['plan_sha']},
            'launcher': {'path': '/known-public/c465.py', 'sha256': self.a.LAUNCHER},
            'prepared_launcher': {'path': '/known-public/prepared.py', 'sha256': checkpointed.PREPARED_SHA},
            'producer': {'path': '/known-public/producer.py', 'sha256': self.a.PRODUCER},
            'canary_assets': self.f['canary_assets'], 'originals': self.f['originals'], 'run_label': 'model-plan'}
        self.plan_row = self.doc('/known-public/EXECUTION.json', self.value)
        self.doc(self.value['index']['path'], self.f['index'])
        self.doc(self.value['batch_plan']['path'], self.f['plan'])
        for record in self.f['batches']:
            self.register_record(record)
        self.io = [patch.object(self.k, 'read', side_effect=self.read),
                   patch.object(self.k, 'fresh_guard', side_effect=self.fixture_guard),
                   patch.object(self.a, 'guarded', side_effect=lambda row: self.read(row['path'], row['sha256'])),
                   patch.object(self.c, 'load_plan', return_value=(self.value, self.f['index'], self.f['plan'],
                                                                 self.f['contexts'], self.f['coverage']))]
        for p in self.io:
            p.start()

    def fixture_guard(self):
        return {'read': self.read, 'refresh': lambda: None,
                'm': SimpleNamespace(GUARD=SimpleNamespace(metadata=lambda p: (Path(p), Path(p).lstat())))}

    def tearDown(self):
        for p in reversed(self.io + self.patches):
            p.stop()
        self.temp.cleanup()

    def read(self, path, expected=None):
        path = str(path)
        if path in self.docs:
            raw = self.docs[path]
        else:
            # The fixture refuses every non-model path, including Originals.
            self.assertTrue(Path(path).is_relative_to(self.root), path)
            raw = Path(path).read_bytes()
        if expected is not None:
            self.a.need(self.a.sha(raw) == expected, 'fixture-public-identity')
        return raw

    def doc(self, path, value):
        raw = self.a.encoded(value); self.docs[str(path)] = raw
        return {'path': str(path), 'sha256': self.a.sha(raw)}

    def register_record(self, record):
        self.doc(record['descriptor_row']['path'], record['descriptor'])
        for release in record['releases'].values():
            self.doc(release['row']['path'], release['release'])

    def pair(self, output, label, original, record):
        bid = record['descriptor']['batch_id']; oid = original['original_id']
        envelope = model.invocation(original, record, self.f['contexts'], self.f['index_sha'], self.f['plan_sha'])
        self.a.save(output / 'local-invocations' / bid / (oid + '.json'), envelope)
        job = self.root / ('prepared-' + label + '-' + bid.lower()) / ('audit-' + label + '-' + bid.lower() + '-' + oid.lower())
        for kind in ('literal', 'derived'):
            schema = ('kpx8-new-owner-seed-export-allowlist/v1' if kind == 'literal'
                      else 'kpxa-derived-export-candidates/v1')
            self.a.save(job / (kind + '-ALLOWLIST.json'),
                        {'schema': schema, 'files': self.a.candidate_manifest(record['descriptor']['files'])})
            self.a.save(job / (kind + '-out') / 'RESULTS.json', envelope['workers'][kind])
        return envelope

    def durable(self, number, label='old', count=9):
        output = self.root / ('stage-' + label); output.mkdir(exist_ok=True)
        record = copy.deepcopy(self.f['batches'][number])
        wrapped = self.k.wrapper(self.plan_row, label, output, record)
        row = self.k.save(output / 'local-batches' / record['descriptor']['batch_id'] / 'RECORD.json', wrapped)
        for original in self.value['originals'][:count]:
            self.pair(output, label, original, record)
        return row, wrapped

    def selected(self, resume, label='new'):
        return self.doc('/known-public/SELECTOR-' + label + '.json',
            {'schema': 'kpxa-publication-checkpointed-run/v1', 'execution_plan': self.plan_row,
             'stage_label': label, 'resume': resume})

    def load_records(self, rows):
        return self.k.load(self.selected({'batch_records': rows}))

    def test_exact_completed_prefix_and_reconstruction_without_checkpoint(self):
        rows = [self.durable(0)[0], self.durable(1)[0]]
        loaded = self.load_records(rows)
        self.assertEqual(len(loaded[6]), 2)
        self.assertEqual(len(loaded[7]), 18)
        prefix = {'schema': 'kpxa-publication-completed-prefix/v1', 'sources': self.k.identities(),
                  'execution_plan': self.plan_row, 'completed_batches': 2, 'batch_records': rows}
        ref = self.k.save(self.root / 'prefix.json', prefix)
        loaded_again = self.k.load(self.selected({'checkpoint': ref}, 'another'))
        self.assertEqual(loaded_again[6:9], loaded[6:9])

    def test_wrong_missing_or_nonprefix_record_refuses(self):
        cases = ('missing-record', 'missing-pair', 'wrong-record-SHA', 'wrong-source',
                 'wrong-plan', 'wrong-preparation-SHA', 'wrong-prefix', 'wrong-worker-bytes',
                 'wrong-allowlist', 'changed-context')
        for case in cases:
            with self.subTest(case=case):
                # Each case has an independent retained public model stage.
                label = 'case' + str(cases.index(case))
                row, wrapped = self.durable(0, label)
                output = Path(wrapped['stage_output'])
                bid = wrapped['batch_record']['descriptor']['batch_id']
                if case == 'missing-record':
                    row = {'path': str(self.root / 'absent.json'), 'sha256': 'ab' * 32}
                elif case == 'missing-pair':
                    (output / 'local-invocations' / bid / 'O09.json').unlink()
                elif case == 'wrong-record-SHA':
                    row = dict(row, sha256='ab' * 32)
                elif case in ('wrong-source', 'wrong-plan'):
                    changed = copy.deepcopy(wrapped)
                    if case == 'wrong-source': changed['sources']['core_sha256'] = 'ab' * 32
                    else: changed['execution_plan']['sha256'] = 'ab' * 32
                    row = self.doc(row['path'], changed)
                elif case == 'wrong-preparation-SHA':
                    path = output / 'local-invocations' / bid / 'O04.json'
                    value = json.loads(path.read_bytes()); value['public_preparation_sha256'] = 'ab' * 32
                    self.docs[str(path)] = self.a.encoded(value)
                elif case == 'wrong-prefix':
                    row = self.durable(1, label + 'd')[0]
                elif case == 'wrong-worker-bytes':
                    path = self.root / ('prepared-' + label + '-base') / ('audit-' + label + '-base-o01') / 'literal-out/RESULTS.json'
                    self.docs[str(path)] = b'changed public result\n'
                elif case == 'wrong-allowlist':
                    path = self.root / ('prepared-' + label + '-base') / ('audit-' + label + '-base-o01') / 'literal-ALLOWLIST.json'
                    self.docs[str(path)] = b'changed public allowlist\n'
                elif case == 'changed-context':
                    changed = copy.deepcopy(wrapped)
                    changed['batch_record']['preparation']['provenance']['context_releases']['creation'] = 'ab' * 32
                    row = self.doc(row['path'], changed)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.load_records([row])

    def test_checkpoint_source_count_and_stage_reuse_refuse(self):
        row, _ = self.durable(0)
        prefix = {'schema': 'kpxa-publication-completed-prefix/v1', 'sources': self.k.identities(),
                  'execution_plan': self.plan_row, 'completed_batches': 1, 'batch_records': [row]}
        for change in ('source', 'count', 'stage'):
            with self.subTest(change=change):
                value = copy.deepcopy(prefix)
                if change == 'source': value['sources']['checkpoint_controller_sha256'] = 'ab' * 32
                if change == 'count': value['completed_batches'] = 2
                ref = self.doc(self.root / ('prefix-' + change + '.json'), value)
                with self.assertRaises(ValueError):
                    self.k.load(self.selected({'checkpoint': ref}, 'old' if change == 'stage' else 'new'))

    def execution_adapters(self, stop_after=None, events=None):
        calls = [] if events is None else events
        producer = SimpleNamespace(pinned_preimage=lambda: {'SHM_OUTPUT_BASE': str(self.root / 'shm')})
        (self.root / 'shm').mkdir(exist_ok=True)
        def materialize(_, ix, pl, batch, temporary):
            temporary.mkdir()
            record = copy.deepcopy(next(r for r in self.f['batches'] if r['descriptor']['batch_id'] == batch['batch_id']))
            record['descriptor']['files'][0]['source'] = str(temporary / 'public-candidate.bin')
            record['descriptor_row'] = self.a.save(Path(ix['path']).parent / (batch['batch_id'] + '-BATCH.json'), record['descriptor'])
            record['materialization']['descriptor'] = record['descriptor_row']
            return record['materialization']
        def prepare(value, descriptor, releases, _):
            provenance = model.preparation(descriptor['files'], releases)
            provenance['provenance']['public_admission_wall_seconds'] = 2.5
            return SimpleNamespace(close=lambda: calls.append(('close', descriptor['batch_id']))), provenance
        def audit_one(value, original, descriptor, descriptor_row, release, context, output, prepared, preparation):
            bid = descriptor['batch_id']
            # The fully encoded record must already exist before modeled intake.
            record_path = output / 'local-batches' / bid / 'RECORD.json'
            wrapped = json.loads(record_path.read_bytes())
            self.assertEqual(wrapped['batch_record']['preparation'], preparation)
            calls.append((bid, original['original_id']))
            if stop_after is not None and len([v for v in calls if v[0] == bid]) > stop_after:
                raise RuntimeError('PUBLIC_MODEL_INTERRUPTED_BATCH')
            return self.pair(output, value['run_label'], original, wrapped['batch_record'])
        return calls, [patch.object(self.c, 'selected_module', side_effect=lambda row, _: producer if row['sha256'] == self.a.PRODUCER else object()),
                       patch.object(self.c, 'materialize', side_effect=materialize),
                       patch.object(self.c, 'prepare_snapshot', side_effect=prepare),
                       patch.object(self.c, 'audit_one', side_effect=audit_one)]

    def test_completed_prefix_skipped_and_interrupted_tail_restarted_in_full(self):
        row, _ = self.durable(0)
        # A different old tail preparation has four successful model pairs only.
        partial_row, partial = self.durable(1, 'interrupted', 4)
        with self.assertRaises(FileNotFoundError):
            self.load_records([row, partial_row])
        calls, patches = self.execution_adapters()
        for p in patches: p.start()
        try:
            result = self.k.execute(self.selected({'batch_records': [row]}, 'fresh-tail'), self.root / 'fresh-output')
        finally:
            for p in reversed(patches): p.stop()
        self.assertTrue(result['primary_checks_complete'])
        jobs = [x for x in calls if x[0] != 'close']
        self.assertEqual([x[0] for x in jobs], ['D000001'] * 9 + ['D000002'] * 9)
        self.assertTrue(Path(partial_row['path']).exists())
        self.assertTrue((self.root / 'fresh-output/LOCAL-UNPUBLISHED-PRIMARY-JOURNAL.json').exists())
        completed = json.loads((self.root / 'fresh-output/local-batches/D000001/RECORD.json').read_bytes())
        self.assertNotEqual(completed['batch_record']['preparation'], partial['batch_record']['preparation'])

    def test_durable_record_failure_prevents_modeled_owner_intake(self):
        calls, patches = self.execution_adapters()
        authority = self.f['batches'][0]['producer_preparation']
        original_save = self.k.save
        def fail_record(path, value):
            if Path(path).name == 'RECORD.json': raise OSError('PUBLIC_MODEL_DISK_FULL')
            return original_save(path, value)
        patches += [patch.object(self.k, 'base_authority', return_value=authority),
                    patch.object(self.k, 'save', side_effect=fail_record)]
        for p in patches: p.start()
        try:
            with self.assertRaises(OSError):
                self.k.execute(self.selected(None, 'no-intake'), self.root / 'failed-record-output')
        finally:
            for p in reversed(patches): p.stop()
        self.assertEqual([x for x in calls if x[0] != 'close'], [])
        self.assertEqual(calls, [('close', 'BASE')])

    def test_completed_batch_survives_final_checkpoint_write_failure(self):
        calls, patches = self.execution_adapters()
        authority = self.f['batches'][0]['producer_preparation']
        original_save = self.k.save
        def fail_checkpoint(path, value):
            if Path(path).name.startswith('PREFIX-'): raise OSError('PUBLIC_MODEL_CHECKPOINT_DISK_FULL')
            return original_save(path, value)
        patches += [patch.object(self.k, 'base_authority', return_value=authority),
                    patch.object(self.k, 'save', side_effect=fail_checkpoint)]
        for p in patches: p.start()
        output = self.root / 'checkpoint-failure-output'
        try:
            with self.assertRaises(OSError): self.k.execute(self.selected(None, 'checkpoint-fail'), output)
        finally:
            for p in reversed(patches): p.stop()
        self.assertEqual(len([x for x in calls if x[0] != 'close']), 9)
        path = output / 'local-batches/BASE/RECORD.json'; raw = path.read_bytes()
        loaded = self.k.load(self.selected({'batch_records': [{'path': str(path), 'sha256': self.a.sha(raw)}]}, 'recovered'))
        self.assertEqual(len(loaded[6]), 1)
        self.assertEqual(len(loaded[7]), 9)

    def test_ENOSPC_retains_partial_and_waits_before_atomic_no_replace_publish(self):
        original = self.k._write_attempt; attempts = []
        def write(path, value):
            attempts.append(Path(path))
            if len(attempts) == 1:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(b'PUBLIC_MODEL_PARTIAL')
                raise OSError(errno.ENOSPC, 'PUBLIC_MODEL_DISK_FULL')
            return original(path, value)
        path = self.root / 'atomic/RECORD.json'
        with patch.object(self.k, '_write_attempt', side_effect=write), \
             patch.object(checkpointed.time, 'sleep') as sleep:
            row = self.k.save(path, {'public_model': True})
        sleep.assert_called_once_with(5)
        self.assertEqual(attempts[0].read_bytes(), b'PUBLIC_MODEL_PARTIAL')
        self.assertEqual(row['sha256'], self.a.sha(path.read_bytes()))
        self.assertFalse(attempts[1].exists())  # Same complete inode was renamed.
        with self.assertRaises(FileExistsError):
            self.k.save(path, {'different': True})
        self.assertEqual(json.loads(path.read_bytes()), {'public_model': True})

    def test_prepare_resource_hook_exceptions_are_not_acceptance_gates(self):
        self.k.prepare_phase = lambda *_: (_ for _ in ()).throw(OSError('PUBLIC_MODEL_TELEMETRY_FULL'))
        try:
            self.k.phase('PUBLIC_ADMISSION', 'BASE')
            self.k.phase('SCANNERS', 'BASE')
        finally:
            self.k.prepare_phase = None

    def test_new_public_reads_use_a_fresh_unchanged_helper_each_time(self):
        calls = []
        def fresh():
            token = len(calls)
            calls.append(token)
            return {'read': lambda path, expected=None: (token, path, expected)}
        with patch.object(checkpointed.runpy, 'run_path', side_effect=lambda path: fresh() if path == checkpointed.GUARD else self.fail(path)), \
             patch.object(self.k, 'fresh_guard', wraps=checkpointed.Controller.fresh_guard.__get__(self.k)):
            self.assertEqual(self.k.new_public_read('/public-one', 'ab' * 32), (0, '/public-one', 'ab' * 32))
            self.assertEqual(self.k.new_public_read('/public-two', 'cd' * 32), (1, '/public-two', 'cd' * 32))
        self.assertEqual(calls, [0, 1])

    def test_directory_sync_ENOSPC_waits_and_retries_without_bypass(self):
        path = self.root / 'directory-sync'; path.mkdir()
        real = checkpointed.os.fsync; calls = []
        def sync(fd):
            calls.append(fd)
            if len(calls) == 1: raise OSError(errno.ENOSPC, 'PUBLIC_MODEL_DIRECTORY_SYNC_FULL')
            return real(fd)
        with patch.object(checkpointed.os, 'fsync', side_effect=sync), \
             patch.object(checkpointed.time, 'sleep') as sleep:
            self.k.sync_directories(path)
        sleep.assert_called_once_with(5)
        self.assertGreater(len(calls), 1)

    def test_prefix_cannot_publish_before_finite_runtime_receipts_are_durable(self):
        calls, patches = self.execution_adapters()
        authority = self.f['batches'][0]['producer_preparation']
        original_sync = self.k.sync_public_leaves
        def fail_runtime(paths):
            paths = list(paths)
            if any('/prepared-' in str(p) for p in paths):
                raise OSError(errno.EIO, 'PUBLIC_MODEL_RECEIPT_DURABILITY_FAILURE')
            return original_sync(paths)
        patches += [patch.object(self.k, 'base_authority', return_value=authority),
                    patch.object(self.k, 'sync_public_leaves', side_effect=fail_runtime),
                    patch.object(self.k, 'pairs_checked', side_effect=AssertionError('FRESH_PATH_MUST_USE_CHECKED_RETURNS'))]
        for p in patches: p.start()
        output = self.root / 'runtime-sync-failure'
        try:
            with self.assertRaises(OSError): self.k.execute(self.selected(None, 'durability-fail'), output)
        finally:
            for p in reversed(patches): p.stop()
        self.assertEqual(len([x for x in calls if x[0] != 'close']), 9)
        self.assertTrue((output / 'local-batches/BASE/RECORD.json').exists())
        self.assertFalse((output / 'local-checkpoints').exists())

    def test_full_record_waits_for_exact_current_stage_reference_closure(self):
        row, _ = self.durable(0)
        calls, patches = self.execution_adapters()
        output = self.root / 'reference-sync-failure'
        expected = {output / 'materialization-inputs/D000001-BATCH.json',
                    *[output / directory / 'D000001' / (cohort + '.json')
                      for directory in ('local-releases', 'local-scopes')
                      for cohort in ('creation', 'actual02')]}
        real = self.k.sync_public_leaves; observed = []
        def fail_references(paths):
            paths = list(paths)
            if any(Path(p).is_relative_to(output) for p in paths):
                self.assertEqual(set(map(Path, paths)), expected)
                observed.append(paths)
                raise OSError(errno.EIO, 'PUBLIC_MODEL_REFERENCE_DURABILITY_FAILURE')
            return real(paths)
        patches += [patch.object(self.k, 'sync_public_leaves', side_effect=fail_references)]
        for p in patches: p.start()
        try:
            with self.assertRaises(OSError):
                self.k.execute(self.selected({'batch_records': [row]}, 'refs-fail'), output)
        finally:
            for p in reversed(patches): p.stop()
        self.assertEqual(len(observed), 1)
        self.assertEqual([x for x in calls if x[0] != 'close'], [])
        self.assertFalse((output / 'local-batches/D000001/RECORD.json').exists())


if __name__ == '__main__':
    unittest.main()
