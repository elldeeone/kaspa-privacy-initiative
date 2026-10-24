"""Public unsafe sentinels only: no original wallet, PK, VM or proof execution."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import paths
import run_owner
import support
import worker


class PublicCrypto:
    """Deterministic NONCRYPTOGRAPHIC source-control adapter, never fundable."""
    def xonly(self, secret):
        return bytes.fromhex(paths.digest(b'PUBLIC-UNSAFE-xonly' + secret))

    def delivery_public(self, secret):
        return bytes.fromhex(paths.digest(b'PUBLIC-UNSAFE-delivery' + secret))


def load_public(relative, name):
    spec = importlib.util.spec_from_file_location(name, paths.ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


class Boundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kpx7-public-unsafe-controls-')
        self.root = Path(self.temp.name)
        self.old = [self.root / ('old-' + str(i)) for i in range(2)]
        for root in self.old:
            for role in 'ABCD':
                directory = root / 'owners' / role
                directory.mkdir(parents=True)
                paths.write_new(directory / 'backup.json', b'PUBLIC UNSAFE SENTINEL, NO KEY\n')
        self.new = [self.root / ('party-' + str(i)) for i in range(3)]
        for root in self.new:
            root.mkdir(mode=0o700)
            (root / 'owner').mkdir(mode=0o700)
            (root / 'mpc').mkdir(mode=0o700)
        self.a = SimpleNamespace(owner=self.new[0] / 'owner', mpc=self.new[0] / 'mpc')

    def tearDown(self):
        self.temp.cleanup()

    def test_metadata_collection_opens_no_private_leaf(self):
        sentinel = self.new[1] / 'owner' / 'GENERIC.bin'
        paths.write_new(sentinel, b'PUBLIC UNSAFE PRIVATE-TREE SENTINEL')
        with patch.object(paths.os, 'open', side_effect=AssertionError('metadata opened bytes')):
            policy = paths.HostPolicy(self.old, self.new)
        self.assertIn((sentinel.stat().st_dev, sentinel.stat().st_ino), policy.identities)
        with self.assertRaisesRegex(ValueError, 'inside-private-tree'):
            policy.read(sentinel)

    def test_private_hardlink_alias_fails_before_read(self):
        sentinel = self.new[2] / 'mpc' / 'GENERIC.bin'
        paths.write_new(sentinel, b'PUBLIC UNSAFE SENTINEL')
        policy = paths.HostPolicy(self.old, self.new)
        alias = self.root / 'public-alias.bin'; os.link(sentinel, alias)
        with patch.object(paths.os, 'open', side_effect=AssertionError('alias opened bytes')):
            with self.assertRaisesRegex(ValueError, 'private-alias'):
                policy.read(alias)
        with self.assertRaisesRegex(ValueError, 'hardlink'):
            paths.HostPolicy(self.old, self.new)

    def test_tls_symlinks_are_metadata_only_and_public_paths_stay_strict(self):
        scratch = self.new[0] / 'mpc' / 'mpc-private-publicsentinel'
        scratch.mkdir(mode=0o700)
        paths.write_new(scratch / 'certificate.pem', b'PUBLIC CERTIFICATE SENTINEL')
        (scratch / '1234abcd.0').symlink_to('certificate.pem')
        (scratch / 'opaque-directory-link').symlink_to(self.new[2], target_is_directory=True)
        with patch.object(paths.os, 'open', side_effect=AssertionError('metadata opened bytes')):
            policy = paths.HostPolicy(self.old, self.new)
        alias = self.root / 'public-symlink'; alias.symlink_to(scratch / 'certificate.pem')
        with self.assertRaisesRegex(ValueError, 'symlink-path'):
            policy.read(alias)

    def test_descriptor_swap_refused_before_first_byte(self):
        selected = self.root / 'public.bin'; paths.write_new(selected, b'ORIGINAL PUBLIC')
        replacement = self.root / 'replacement.bin'; paths.write_new(replacement, b'CHANGED PUBLIC')
        policy = paths.HostPolicy(self.old, self.new)
        actual_open = paths.os.open
        def replace_before_open(path, flags, *args, **kwargs):
            if Path(path) == selected:
                os.replace(replacement, selected)
            return actual_open(path, flags, *args, **kwargs)
        with patch.object(paths.os, 'open', side_effect=replace_before_open), \
             patch.object(paths.os, 'fdopen', side_effect=AssertionError('swapped bytes read')):
            with self.assertRaisesRegex(ValueError, 'before-first-byte'):
                policy.read(selected)

    def test_post_auth_barrier_precedes_assets_and_old_map_reads(self):
        attempt = self.a.owner / 'attempts' / '000001'
        attempt.mkdir(parents=True, mode=0o700)
        paths.write_new(attempt / 'DISCLOSURE-CLOSED', b'', 0o400)
        with patch.object(worker, 'private_json', side_effect=AssertionError('old map reopened')), \
             patch.object(worker, 'load_assets', side_effect=AssertionError('assets opened')):
            for operation in (worker.prepare, worker.authorize):
                with self.assertRaisesRegex(ValueError, 'reconciliation-required'):
                    operation(self.a)

    def test_pre_auth_rotation_moves_original_input_only_inside_owner(self):
        attempt = self.a.owner / 'attempts' / '000001'
        attempt.mkdir(parents=True, mode=0o700)
        original = self.a.mpc / 'Input-P0-0'
        paths.write_new(original, b'0' * 2695, 0o400); before = original.stat()
        worker.private_save(attempt / 'STATE.json', {
            'input_device_hex8': before.st_dev.to_bytes(8, 'little').hex(),
            'input_inode_hex8': before.st_ino.to_bytes(8, 'little').hex()})
        worker.archive_pre_authorization_input(self.a, [attempt], original)
        self.assertFalse(original.exists())
        self.assertEqual((attempt / 'MPC-INPUT.bin').stat().st_ino, before.st_ino)
        paths.write_new(attempt / 'DISCLOSURE-CLOSED', b'', 0o400)
        with patch.object(worker, 'private_json', side_effect=AssertionError('post-auth state read')):
            with self.assertRaisesRegex(ValueError, 'reconciliation-required'):
                worker.archive_pre_authorization_input(self.a, [attempt], original)

    def test_participant_bound_invoice_rejects_directory_permutation(self):
        receiver = support.recipient().Receiver(bytes([7]) * 32, support.DOMAIN, PublicCrypto())
        roster = [bytes([i + 10]) * 32 for i in range(3)]
        session = {'roster': [p.hex() for p in roster]}
        raw = roster[1] + receiver.invoice(1).encode()
        self.assertEqual(worker.private_peer_invoice(raw, session, 1, 0), receiver.invoice(1))
        for candidate, destination, sender in ((raw, 2, 0), (raw, 1, 1), (raw[32:], 1, 0)):
            with self.assertRaises(ValueError):
                worker.private_peer_invoice(candidate, session, destination, sender)

    def test_original_nf_stays_stable_and_owner_position_rejects_upper_bits(self):
        v2 = support.recipient()
        receiver = v2.Receiver(bytes([9]) * 32, support.DOMAIN, PublicCrypto())
        receipt = v2.Receipt.for_invoice(receiver.invoice(0), support.MIN_NOTE * 3, bytes([8]) * 32)
        nf = receiver.nullifier(receipt, 1)
        # Attempt/session/blinds never enter the original NF derivation.
        for public_attempt in range(3):
            self.assertEqual(receiver.nullifier(receipt, 1), nf)
        changed_domain = v2.Receiver(bytes([9]) * 32, bytes([3]) * 32, PublicCrypto())
        changed_receipt = v2.Receipt.for_invoice(changed_domain.invoice(0), receipt.value_sompi, bytes([8]) * 32)
        self.assertNotEqual(changed_domain.nullifier(changed_receipt, 1), nf)
        value = {'schema': 'kpx7-unfunded-owner-state/v1', 'domain_hex32': support.DOMAIN.hex(),
            'participant_id_hex32': bytes([1]).hex() * 32, 'seed_hex32': bytes([9]).hex() * 32,
            'initial_position': 65537, 'input_receipt_hex216': receipt.encode().hex()}
        with patch.object(worker, 'private_json', return_value=value):
            with self.assertRaisesRegex(ValueError, 'position'):
                worker.owner_state(self.a)

    def test_fixed_transport_and_strict_amount_scalar_boundaries(self):
        codec = load_public('poc/owner-private-payments/construction/codec.py', '_kpx7_public_codec_controls')
        for beta in (0, support.Q - 1):
            packed = codec.owner_input([bytes(520), bytes([255]) * 520], beta)
            self.assertEqual(len(packed), 2695)
            self.assertTrue(all(len(line) == 76 for line in packed.splitlines()))
        for invalid in (-1, support.Q, True):
            with self.assertRaises(ValueError):
                codec.owner_input([bytes(520), bytes(520)], invalid)
        for value in (support.MIN_NOTE, support.MAX_VALUE):
            self.assertEqual(support.amount(value), value)
        for value in (support.MIN_NOTE - 1, support.MAX_VALUE + 1, True, '60000000'):
            with self.assertRaises(ValueError):
                support.amount(value)
        with self.assertRaises(ValueError):
            support.scalar(support.Q.to_bytes(32, 'little'))

    def test_staged_namespace_has_one_owner_and_only_peer_invoice_leaves(self):
        crypto = self.root / 'unsafe-public-ELF'; paths.write_new(crypto, b'\x7fELF PUBLIC UNSAFE NO EXECUTION', 0o500)
        out = self.root / 'staged'
        a = SimpleNamespace(operation='init', owner_directory=self.a.owner, mpc_directory=self.a.mpc,
            peer_owner_directory=[p / 'owner' for p in self.new], exclude_old_trial=self.old,
            exclude_new_private_directory=self.new, output=out, crypto=crypto,
            participant_id=bytes([1]).hex() * 32, position=0, admission_sompi=support.MIN_NOTE * 3,
            assets=None, assets_sha256=None, session=None, session_sha256=None, context=None,
            context_sha256=None, projection=None, projection_sha256=None, own_mpc_result=None,
            party=None, execute=False)
        with patch.object(run_owner, 'CRYPTO_SHA', paths.digest(crypto.read_bytes())):
            self.assertEqual(run_owner.run(a), {'operation': 'init', 'staged': True, 'executed': False})
        command = paths.parse((out / 'PRIVATE-PLAN.json').read_bytes())['command']
        self.assertIn('--unshare-all', command)
        self.assertNotIn('--share-net', command)
        self.assertNotIn('/var/run/docker.sock', command)
        for excluded in (*self.old, *self.new[1:]):
            self.assertFalse(any(str(excluded) in arg for arg in command))
        self.assertFalse((self.a.owner / 'OWNER.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
