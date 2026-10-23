"""Publication boundaries reject private and unrecognized driver filenames."""
from pathlib import Path
import unittest

from publish_evidence import GENERATED_SOURCE_PATHS, STAGES, public_driver_member


class PublicDriverBoundaryTests(unittest.TestCase):
    def test_all_six_stage_names_are_recognized(self):
        for directory in ('bodies', 'observations'):
            for stage in STAGES:
                with self.subTest(directory=directory, stage=stage):
                    self.assertTrue(public_driver_member(Path(directory) / (stage + '.json')))

    def test_actual_phase_verdict_boundaries(self):
        nonce = 'a' * 32
        for phase in (3, 4, 5):
            directory = Path(f'phase-{phase}-{nonce}')
            for filename in ('archive.json', 'current.json', 'charlie-recovery.json'):
                self.assertTrue(public_driver_member(directory / filename))
            self.assertEqual(public_driver_member(directory / 'bob-recovery.json'), phase != 4)

    def test_private_unknown_and_nested_members_reject(self):
        phase = 'phase-3-' + 'a' * 32
        denied = ['bodies/profile.json', 'observations/funding.key.json',
                  phase + '/profile.json', phase + '/backups.json', phase + '/private-fixture.json',
                  phase + '/private-rho.json', phase + '/unknown.json',
                  phase + '/nested/archive.json', phase + '/archive.json/extra',
                  'phase-2-' + 'a' * 32 + '/archive.json',
                  'phase-3-not-a-uuid/archive.json', 'bodies/private.json.bak',
                  '/bodies/private.json', 'private.json']
        for name in denied:
            with self.subTest(name=name):
                self.assertFalse(public_driver_member(Path(name)))

    def test_generated_sources_are_exact_finite_nonsecret_paths(self):
        self.assertEqual(len(GENERATED_SOURCE_PATHS), 16)
        for name in GENERATED_SOURCE_PATHS:
            self.assertFalse(Path(name).is_absolute())
            self.assertNotIn('..', Path(name).parts)
        for name in ('profile.json', 'backups/bob.json', 'private-fixture.json',
                     'poc/future-testnet/profile.json', 'poc/future-private-payment/private-rho.json'):
            self.assertNotIn(name, GENERATED_SOURCE_PATHS)


if __name__ == '__main__':
    unittest.main()
