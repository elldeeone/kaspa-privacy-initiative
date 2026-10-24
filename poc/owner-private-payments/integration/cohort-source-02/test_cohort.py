"""Synthetic controller controls. No real wallet, proof engine, MPC or truth."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import sys
import unittest
from unittest.mock import patch

import cohort


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        old = [root / ('old-%d' % i) for i in range(2)]
        for tree in old:
            for role in 'ABCD':
                owner = tree / 'owners' / role; owner.mkdir(parents=True)
                (owner / 'backup.json').write_bytes(b'SYNTHETIC PRIVATE FIXTURE')
        self.c = cohort.Cohort.__new__(cohort.Cohort)
        self.c.args = SimpleNamespace(exclude_private_root=list(map(str, old)), execute=False, spec_sha256='a' * 64)
        retained = root / 'retained'; retained.mkdir()
        self.c.retained = [retained]; self.c.parties = []; self.c.controllers = []
        self.c.forbidden = set(); self.c.approved_jobs = set()
        self.root = root

    def test_all_world_private_aliases_and_moved_inodes_rejected_before_read(self):
        party = self.root / 'fresh-party'; party.mkdir()
        self.c.parties.append(party)
        secret = party / 'PRIVATE'; secret.write_bytes(b'NOT A PUBLIC INPUT')
        self.c.guard()  # Metadata snapshot only.
        moved = self.root / 'looks-public'; secret.rename(moved)
        with self.assertRaisesRegex(ValueError, 'public-aliases-original-private'):
            self.c.guard().read(moved, '0' * 64)
        previous = self.c.retained[0] / 'OTHER'; previous.write_bytes(b'PRIVATE')
        alias = self.root / 'alias'; os.link(previous, alias)
        with self.assertRaises(ValueError):
            self.c.guard().metadata(alias)
        link = self.root / 'symlink'; link.symlink_to(previous)
        with self.assertRaises(ValueError):
            self.c.guard().metadata(link)

    def test_registered_typed_public_promotion_and_no_private_field_export(self):
        controller = self.root / 'controller-private'; controller.mkdir()
        self.c.controllers.append(controller)
        job = controller / 'init-0'; (job / 'public').mkdir(parents=True)
        self.c.approved_jobs.add(job)
        value = {'schema': 'kpx7-unfunded-owner-public/v1', 'domain_hex32': cohort.wire.DOMAIN.hex(),
                 'participant_id_hex32': '1' * 64, 'initial_cm_hex32': '2' * 64,
                 'initial_position': 0, 'admission_sompi': 2_000_000_000}
        leaf = job / 'public/PUBLIC.json'; leaf.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            self.c.guard().metadata(leaf)  # Whole controller branch is protected generically.
        target = self.root / 'PROMOTED.json'
        self.assertEqual(self.c.promote(job, target, 'init', 0), value)
        target.unlink(); value['seed_hex32'] = '3' * 64; leaf.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'exact-public-owner-init-export'):
            self.c.promote(job, target, 'init', 0)
        self.assertFalse(target.exists())
        with self.assertRaisesRegex(ValueError, 'only-selected-producer-job'):
            self.c.promote(controller / 'unselected', target, 'init', 0)

    def test_default_preflight_never_creates_world_or_invokes_children(self):
        self.c.output = self.root / 'not-created'
        with patch.object(self.c, 'run_world', side_effect=AssertionError('must not run')):
            result = self.c.run()
        self.assertEqual(result['owner_init_count'], 0)
        self.assertFalse(self.c.output.exists())

    def test_phase_failure_keeps_all_registered_worlds_without_replacement(self):
        self.c.output = self.root / 'cohort'; self.c.args.execute = True
        self.c.assets = {}; self.c.spec = {'world_ids': ['world-%02d' % i for i in range(1, 17)]}
        called = []
        def world(name):
            called.append(name); (self.c.output / name / 'public').mkdir(parents=True)
            if name == 'world-04':
                raise ValueError('selected-phase-incomplete:outputs')
            return {'status': 'COMPLETE', 'candidate_failed': False, 'S': 0, 'K': 3, 'reason': 'synthetic'}
        with patch.object(self.c, 'run_world', side_effect=world), patch('builtins.print'):
            result = self.c.run()
        self.assertEqual(called, self.c.spec['world_ids'])
        self.assertEqual(result['status'], 'INCOMPLETE'); self.assertIsNone(result['tail'])
        failure = json.loads((self.c.output / 'world-04/public/WORLD-RESULT.json').read_text())
        self.assertEqual(failure['reason'], 'selected-phase-incomplete:outputs')
        self.assertEqual(len(list(self.c.output.glob('world-*/public/WORLD-RESULT.json'))), 16)

    def test_own_engine_result_mode_change_is_metadata_only(self):
        self.c.current = []
        for i in range(3):
            p = self.root / ('party-%d' % i); result = p / 'mpc/mpc-private-fixture/OWN-MPC-PROJECTION.json'
            result.parent.mkdir(parents=True); result.write_bytes(b'NEVER HOST-OPEN THIS FIXTURE')
            result.chmod(0o644); self.c.current.append(p)
        with patch.object(Path, 'open', side_effect=AssertionError('private bytes must not open')):
            selectors = self.c.own_reports()
        self.assertEqual(selectors, ['mpc-private-fixture/OWN-MPC-PROJECTION.json'] * 3)
        for p in self.c.current:
            self.assertEqual((p / 'mpc' / selectors[0]).stat().st_mode & 0o777, 0o400)

    def test_unknown_MPC_cleanup_halts_operations_but_retains_sixteen_slots(self):
        self.c.output = self.root / 'cohort'; self.c.args.execute = True
        self.c.assets = {}; self.c.spec = {'world_ids': ['world-%02d' % i for i in range(1, 17)]}
        called = []
        def failure(name):
            called.append(name); (self.c.output / name / 'public').mkdir(parents=True)
            self.c.last_stage = 'mpc-mixed'
            raise ValueError('selected-phase-incomplete:mpc-mixed')
        with patch.object(self.c, 'run_world', side_effect=failure), patch('builtins.print'):
            result = self.c.run()
        self.assertEqual(called, ['world-01']); self.assertEqual(result['attempted_worlds'], 1)
        self.assertEqual(result['incomplete_worlds'], 16); self.assertIsNone(result['tail'])
        self.assertEqual(len(list(self.c.output.glob('world-*/public/WORLD-RESULT.json'))), 16)

    def test_candidate_failure_never_stops_later_registered_worlds(self):
        self.c.output = self.root / 'cohort'; self.c.args.execute = True
        self.c.assets = {}; self.c.spec = {'world_ids': ['world-%02d' % i for i in range(1, 17)]}
        called = []
        def world(name):
            called.append(name); (self.c.output / name / 'public').mkdir(parents=True)
            return {'status': 'CANDIDATE_FAIL', 'candidate_failed': True, 'S': None, 'K': 1,
                    'reason': 'synthetic-unique-grouping'}
        with patch.object(self.c, 'run_world', side_effect=world), patch('builtins.print'):
            result = self.c.run()
        self.assertEqual(called, self.c.spec['world_ids'])
        self.assertEqual(result['status'], 'CANDIDATE_FAIL'); self.assertIsNone(result['tail'])

    def test_actual_diagnostic_command_builder_matches_selected_launcher_parser(self):
        # Exercise the real builder and real argparse schema together, with no
        # owner directory/file, source staging, scorer run or truth comparison.
        with patch.object(sys, 'path', [str(cohort.HERE.parent / 'wallet'), *sys.path]):
            import run_score
        self.c.public = self.root / 'public'; self.c.public.mkdir()
        self.c.controller = self.root / 'controller-private'; self.c.controller.mkdir()
        self.c.current = [self.root / ('OPAQUE-PARTY-%d' % i) for i in range(3)]
        parsed = []
        def stage(label, commands):
            for command in commands:
                self.assertEqual(command[:3], ['/usr/bin/python3', '-B',
                    str(cohort.HERE.parent / 'wallet/run_score.py')])
                value = run_score.parser().parse_args(command[3:]); parsed.append(value)
                self.assertEqual(value.experiment_sha256, cohort.EXPERIMENT)
                self.assertEqual(value.session_sha256, 'b' * 64)
                self.assertEqual(value.projection_sha256, 'c' * 64)
                if value.operation in ('observe', 'score'):
                    self.assertEqual(value.assets, Path('/PUBLIC/ASSETS.json'))
                    self.assertEqual(value.assets_sha256, 'a' * 64)
                    self.assertEqual(value.session, Path('/PUBLIC/SESSION.json'))
                    self.assertEqual(value.projection, Path('/PUBLIC/PROJECTION.bin'))
                if value.operation == 'observe':
                    self.assertEqual(value.registry, Path('/PUBLIC/OWNERS.json'))
                    self.assertEqual(value.registry_sha256, 'd' * 64)
                if value.operation == 'score':
                    self.assertEqual(value.capsule, self.c.current[0] / 'owner/diagnostics/OBSERVER-CAPSULE.bin')
                if value.operation == 'aggregate':
                    self.assertEqual(len(value.count_file), 3)
                    self.assertIsNone(value.owner_directory)
        def promote(job, target, kind):
            return {'capsule_seal_sha256': 'f' * 64} if kind == 'observe' else {}
        with patch.object(self.c, 'stage', side_effect=stage), \
             patch.object(self.c, 'selector', side_effect=lambda p: [str(p), 'e' * 64]), \
             patch.object(self.c, 'promote', side_effect=promote), \
             patch.object(run_score, 'run', side_effect=AssertionError('parser control must never execute')), \
             patch.object(cohort, 'world_event', return_value={'status': 'SYNTHETIC_PARSER_ONLY'}):
            result = self.c.diagnostics(['/PUBLIC/SESSION.json', 'b' * 64],
                ['/PUBLIC/PROJECTION.bin', 'c' * 64], ['/PUBLIC/OWNERS.json', 'd' * 64],
                ['/PUBLIC/ASSETS.json', 'a' * 64])
        self.assertEqual([p.operation for p in parsed], ['observe', 'score', 'score', 'score', 'aggregate'])
        self.assertEqual(result['status'], 'SYNTHETIC_PARSER_ONLY')
        self.assertTrue(all(not p.exists() for p in self.c.current))

    def test_error_codes_never_echo_paths_or_payloads(self):
        self.assertEqual(cohort.safe_reason(ValueError('selected-phase-incomplete:spends')),
                         'selected-phase-incomplete:spends')
        self.assertEqual(cohort.safe_reason(ValueError('/private/OWNER.json seed=123')), 'unexpected-runtime-failure')
        self.assertEqual(cohort.safe_reason(FileNotFoundError('/private/TRUTH')), 'unexpected-runtime-failure')


if __name__ == '__main__':
    unittest.main()
