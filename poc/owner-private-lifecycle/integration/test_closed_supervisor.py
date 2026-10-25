"""Run inside an empty-root namespace: no foreign backup fixtures exist."""
import json
import os
from itertools import permutations
from pathlib import Path
import unittest
from unittest.mock import patch

from closed_exits import ClosedStageRunner, PRIVATE, private_order, consume_owner
from codec import canonical_json, sha


class ClosedSupervisorTests(unittest.TestCase):
    def test_portable_source_auth_and_persistent_private_inode_exclusion(self):
        for trial in ('kpi-four-wallet-local-rehearsal-01', 'kpi-four-wallet-live-01'):
            self.assertFalse((Path('/var/tmp') / trial).exists())
        self.assertFalse(Path('/home/luke').exists())
        PRIVATE.mkdir(parents=True)
        # Same namespace tmpfs permits a real rename while the public path
        # remains outside the declared private parent.
        public = Path('/var/tmp/closed-supervisor-public')
        public.mkdir()
        source = Path(__file__).with_name('closed_exits.py')
        source_raw = source.read_bytes()
        manifest = canonical_json({'schema': 'kpx8-lifecycle-source-selection/v1', 'files': [
            {'path': str(source), 'sha256': sha(source_raw), 'bytes': len(source_raw)}]})
        selected = public / 'SOURCE.json'
        selected.write_bytes(manifest)
        runner = ClosedStageRunner(PRIVATE / 'client', public / 'runtime', [PRIVATE],
                                   [str(selected), sha(manifest)])
        runner.initialize_directories()
        self.assertEqual(len(list((PRIVATE / 'client').glob('party-*/owner'))), 3)
        original = PRIVATE / 'synthetic-private-inode'
        original.write_bytes(b'{"synthetic":"known-public-test-content"}\n')
        runner.ingress.refresh()
        producer = public / 'moved-producer'
        runner.ingress.register(producer, 'scan')
        producer.mkdir()
        os.rename(original, producer / 'PUBLIC.json')
        with self.assertRaises(ValueError):
            runner.ingress.promote(producer, public / 'must-not-exist', lambda raw, kind: True)
        self.assertFalse((public / 'must-not-exist').exists())
        producer = public / 'honest-producer'
        runner.ingress.register(producer, 'scan')
        producer.mkdir()
        (producer / 'PUBLIC.json').write_bytes(canonical_json({'schema': 'public-synthetic/v1'}))
        value, _ = runner.ingress.promote(producer, public / 'PROMOTED.json',
            lambda raw, kind: json.loads(raw) if json.loads(raw) == {'schema': 'public-synthetic/v1'}
            else self.fail('unexpected public producer'))
        self.assertEqual(value, {'schema': 'public-synthetic/v1'})
        (PRIVATE / 'link').symlink_to(public, target_is_directory=True)
        with self.assertRaises(ValueError):
            ClosedStageRunner(PRIVATE / 'link/client', public / 'other', [PRIVATE],
                              [str(selected), sha(manifest)])
        for number, order in enumerate(permutations(range(3))):
            with patch('closed_exits.secrets.SystemRandom') as random:
                random.return_value.sample.return_value = list(order)
                self.assertEqual(private_order(runner, 'synthetic-case-%d' % number), list(order))
                random.return_value.sample.assert_called_once_with(range(3), 3)
            self.assertTrue((runner.private / 'controller' /
                             ('synthetic-case-%d-private-order.json' % number)).is_file())
        self.assertFalse(list(public.rglob('*private-order*')))
        for valid in (True, False):
            label = 'associated-success' if valid else 'associated-refusal'
            producer = public / label
            runner.ingress.register(producer, 'exit-ready')
            producer.mkdir()
            (producer / 'PUBLIC.json').write_bytes(canonical_json({
                'schema': 'synthetic-owner-export/v1', 'participant_id_hex32': '33' * 32}))
            (producer / 'ISOLATION.json').write_bytes(canonical_json({'synthetic': True}))
            def validate(raw, kind):
                if not valid: raise ValueError('synthetic validation refusal')
                return True
            if valid:
                self.assertIs(consume_owner(runner, producer, label, validate), True)
            else:
                with self.assertRaises(ValueError): consume_owner(runner, producer, label, validate)
            self.assertFalse(producer.exists())
            self.assertFalse((public / (label + '-associated-result.json')).exists())
            self.assertTrue((runner.private / 'controller' /
                             (label + '-associated-outputs/PUBLIC.json')).is_file())


if __name__ == '__main__': unittest.main()
