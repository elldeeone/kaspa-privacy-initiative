"""Synthetic transport/private-metadata boundary controls; no real wallets."""
from pathlib import Path
import tempfile
import unittest

from construction.codec import DOMAIN, Q, canonical_json, owner_input, session, sha
from ingress import Ingress


def specification(domain=DOMAIN):
    return {'schema': 'kpx8-private-construction-session/v1', 'session_id': '11' * 32,
        'domain_hex': domain, 'prior_state_digest': '22' * 32, 'circuit_profile_sha256': '33' * 32,
        'public_effects_context_sha256': '44' * 32, 'roster': ['55' * 32, '66' * 32, '77' * 32],
        'program_source_sha256': '88' * 32, 'tuple_bytes': 520, 'outputs_per_party': 2, 'mpc_prime': str(Q)}


class ConstructionTests(unittest.TestCase):
    def test_new_domain_accepted_and_old_domain_rejected(self):
        selected = specification()
        self.assertEqual(session(canonical_json(selected), '88' * 32)[0], selected)
        for domain in ('00' * 32, '32b4f31a58cc52d22862c20a923c59cdd0127785e9998f632eae2b3bb319919d'):
            with self.assertRaises(ValueError):
                session(canonical_json(specification(domain)), '88' * 32)

    def test_fixed_private_shape_zero_and_large_scalar(self):
        for beta in (0, Q - 1):
            raw = owner_input([bytes(520), bytes([255]) * 520], beta)
            self.assertEqual(len(raw), 2695)
        with self.assertRaises(ValueError):
            owner_input([bytes(520), bytes(520)], Q)

    def test_stock_mpc_program_bytes_are_unchanged(self):
        here = Path(__file__).resolve().parent
        old = here.parents[1] / 'owner-private-payments/construction/kpx7_mix.mpc'
        self.assertEqual((here / 'construction/kpx7_mix.mpc').read_bytes(), old.read_bytes())


class IngressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.private = self.root / 'private'
        self.private.mkdir()
        self.originals = [self.root / name for name in ('old-local', 'old-live')]
        for directory in self.originals:
            for role in 'ABCD':
                target = directory / 'owners' / role
                target.mkdir(parents=True)
                (target / 'backup.json').write_bytes(b'PUBLIC SYNTHETIC CANARY')
        self.ingress = Ingress(self.originals, [self.private], self.private)

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_public_promotion_outside_private(self):
        output = self.root / 'producer'
        self.ingress.register(output, 'prepare')
        output.mkdir()
        raw = b'{"synthetic":true}\n'
        (output / 'PUBLIC.json').write_bytes(raw)
        target = self.root / 'promoted.json'
        value, selected = self.ingress.promote(output, target,
            lambda data, kind: (kind, data == raw))
        self.assertEqual(value, ('prepare', True))
        self.assertEqual(selected['sha256'], sha(raw))
        self.assertEqual(target.read_bytes(), raw)

    def test_private_output_registration_and_unregistered_promotion_rejected(self):
        with self.assertRaises(ValueError):
            self.ingress.register(self.private / 'producer', 'prepare')
        with self.assertRaises(ValueError):
            self.ingress.promote(self.root / 'unregistered', self.root / 'target', lambda *_: None)

    def test_previously_private_inode_renamed_to_public_export_is_rejected(self):
        secret = self.private / 'private-plan'
        secret.write_bytes(b'PUBLIC SYNTHETIC PRIVATE CANARY')
        self.ingress.refresh()
        output = self.root / 'producer'
        self.ingress.register(output, 'prepare')
        output.mkdir()
        secret.rename(output / 'PUBLIC.json')
        with self.assertRaises(ValueError):
            self.ingress.promote(output, self.root / 'bad.json', lambda *_: self.fail('must not parse'))

    def test_new_private_hardlink_in_public_leaf_rejected_before_validator(self):
        output = self.root / 'producer'
        self.ingress.register(output, 'prepare')
        output.mkdir()
        source = self.private / 'fresh-plan'
        source.write_bytes(b'PUBLIC SYNTHETIC PRIVATE CANARY')
        (output / 'PUBLIC.json').hardlink_to(source)
        with self.assertRaises(ValueError):
            self.ingress.promote(output, self.root / 'bad.json', lambda *_: self.fail('must not parse'))


if __name__ == '__main__':
    unittest.main()
