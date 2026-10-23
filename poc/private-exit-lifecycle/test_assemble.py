"""Cheap semantic boundary tests; no setup, proof, native VM or network."""
import unittest
from pathlib import Path

import assemble as a


BRIDGE = Path('/home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto')


class ActionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto = a.Crypto(BRIDGE)
        cls.wallets = a.wallets(cls.crypto)
        cls.destination = b'\0\0\x20' + cls.crypto.xonly(a.public_seed('BoundaryDestination')) + b'\xac'
        cls.dummy = [(a.h(b'dummy-key', bytes([i])), a.h(b'dummy-seed', bytes([i]))) for i in range(2)]

    def receipt(self, owner, index, value, position):
        return a.make_receipt(self.wallets[owner], index, value, position, self.crypto,
                              a.h(b'BOUNDARY_RHO', a.u32(position)))

    def test_terminal_preserves_cm_tree_and_zeros_every_inactive_field(self):
        note, record = self.receipt('Bob', 0, 60_000_000, 0)
        before = a.Snapshot([record], [a.NFEntry(a.ZERO, a.ZERO, 0)])
        after, fixture, vector = a.action(before, [(0, self.wallets['Bob'], 0), None], [],
            bytes(36), 60_000_000, 20_000_000, 40_000_000, self.destination, self.dummy)
        auth = bytes.fromhex(fixture['auth_hex528'])
        self.assertEqual(len(auth), 528)
        self.assertEqual(auth[268:332], bytes(64))
        self.assertEqual(auth[332:364], a.h(bytes(528)))
        self.assertEqual(auth[364+40:364+76], a.state(before)[40:76])
        self.assertEqual(auth[476:484], bytes(8))
        self.assertEqual(len(after.deliveries), 1)
        self.assertEqual(len(after.nullifiers), 3)
        self.assertEqual(bytes.fromhex(vector['cipher_hex']), bytes(528))
        self.assertEqual(bytes.fromhex(vector['public_witness_hex'])[-1024:], bytes(1024))
        self.assertEqual([row['note_hex168'] for row in fixture['outputs']], [bytes(168).hex()] * 2)

    def test_continuing_owner_full_exit_preserves_other_users_value(self):
        _, first = self.receipt('Bob', 0, 100_000_000, 0)
        _, second = self.receipt('Charlie', 0, 100_000_000, 1)
        before = a.Snapshot([first, second], [a.NFEntry(a.ZERO, a.ZERO, 0)])
        outputs = [a.dummy_output(2+i, a.h(b'OUT_RHO', bytes([i])),
                                 a.opaque_dummy_ciphertext(self.crypto)) for i in range(2)]
        after, fixture, vector = a.action(before, [(0, self.wallets['Bob'], 0), None], outputs,
            bytes(36), 200_000_000, 20_000_000, 80_000_000, self.destination, self.dummy)
        auth = bytes.fromhex(fixture['auth_hex528'])
        self.assertEqual(int.from_bytes(auth[476:484], 'little'), 100_000_000)
        self.assertEqual(len(after.deliveries), 4)
        recovered = a.recover(self.wallets['Charlie'], after.pin(a.DOMAIN), after)
        self.assertEqual(recovered.all_owned_unspent_sompi, 100_000_000)
        self.assertNotEqual(bytes.fromhex(vector['public_witness_hex'])[-1024:], bytes(1024))

    def test_exact_consumed_emergency_key_reuse_rejected(self):
        note, record = self.receipt('Bob', 0, 60_000_000, 0)
        before = a.Snapshot([record], [a.NFEntry(a.ZERO, a.ZERO, 0)])
        destination = b'\0\0\x20' + note.native_pk + b'\xac'
        with self.assertRaisesRegex(ValueError, 'emergency key'):
            a.action(before, [(0, self.wallets['Bob'], 0), None], [], bytes(36),
                     60_000_000, 20_000_000, 40_000_000, destination, self.dummy)

    def test_duplicate_real_position_rejected(self):
        note, record = self.receipt('Bob', 0, 60_000_000, 0)
        before = a.Snapshot([record], [a.NFEntry(a.ZERO, a.ZERO, 0)])
        with self.assertRaisesRegex(ValueError, 'duplicate real position'):
            a.action(before, [(0, self.wallets['Bob'], 0)] * 2, [], bytes(36),
                     120_000_000, 20_000_000, 100_000_000, self.destination, self.dummy)

    def test_terminal_private_output_is_not_silently_discarded(self):
        note, record = self.receipt('Bob', 0, 60_000_000, 0)
        before = a.Snapshot([record], [a.NFEntry(a.ZERO, a.ZERO, 0)])
        with self.assertRaisesRegex(ValueError, 'terminal has private output'):
            a.action(before, [(0, self.wallets['Bob'], 0), None], [(note.note_bytes(), record)],
                     bytes(36), 60_000_000, 20_000_000, 40_000_000, self.destination, self.dummy)

    def test_noncanonical_destination_and_p0_destination_rejected(self):
        note, record = self.receipt('Bob', 0, 60_000_000, 0)
        before = a.Snapshot([record], [a.NFEntry(a.ZERO, a.ZERO, 0)])
        with self.assertRaisesRegex(ValueError, 'canonical payout'):
            a.action(before, [(0, self.wallets['Bob'], 0), None], [], bytes(36),
                     60_000_000, 20_000_000, 40_000_000, bytes(36), self.dummy)
        with self.assertRaisesRegex(ValueError, 'P0 destination'):
            a.action(before, [(0, self.wallets['Bob'], 0), None], [], bytes(36),
                     60_000_000, 20_000_000, 0, self.destination, self.dummy)

    def test_spent_nf_fixture_is_explicitly_rejected_only(self):
        _, record = self.receipt('Bob', 0, 60_000_000, 0)
        before = a.Snapshot([record], [a.NFEntry(a.ZERO, a.ZERO, 0)])
        note = self.wallets['Bob'].open(record.ciphertext)
        nf = self.wallets['Bob'].nullifier(note, 0)
        spent, _ = a.insert(before, nf)
        with self.assertRaisesRegex(ValueError, 'spent or zero nullifier'):
            a.action(spent, [(0, self.wallets['Bob'], 0), None], [], bytes(36),
                     60_000_000, 20_000_000, 40_000_000, self.destination, self.dummy)
        _, fixture, vector = a.action(spent, [(0, self.wallets['Bob'], 0), None], [], bytes(36),
            60_000_000, 20_000_000, 40_000_000, self.destination, self.dummy,
            expected_spent_rejection=True)
        auth = bytes.fromhex(fixture['auth_hex528'])
        witness = bytes.fromhex(vector['public_witness_hex'])
        self.assertEqual(auth[204:236], nf)
        self.assertEqual(witness[4:36], nf, 'strict predecessor<NF must fail at the authentic equal leaf')
        self.assertEqual(auth[76:188], a.state(spent))

    def test_dummy_ciphertext_uses_real_cryptobox_prefix_and_fresh_padding(self):
        ciphers = [a.opaque_dummy_ciphertext(self.crypto) for _ in range(2)]
        self.assertNotEqual(*ciphers)
        for cipher in ciphers:
            self.assertEqual(len(cipher), 264)
            self.assertEqual(cipher[31] & 0x80, 0, 'canonical X25519 ephemeral prefix')
        snapshot = a.Snapshot([a.dummy_output(index, a.h(b'PAD_RHO', bytes([index])), cipher)[1]
                               for index, cipher in enumerate(ciphers)], [a.NFEntry(a.ZERO, a.ZERO, 0)])
        for wallet in self.wallets.values():
            self.assertEqual(a.recover(wallet, snapshot.pin(a.DOMAIN), snapshot).all_owned_unspent_sompi, 0)


if __name__ == '__main__':
    unittest.main()
