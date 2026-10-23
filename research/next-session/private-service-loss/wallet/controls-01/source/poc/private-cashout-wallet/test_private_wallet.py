"""Public unfunded controls; no actual backup, PK, setup or prover is used."""
from copy import deepcopy
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from owner_rules import Invalid, canonical, digest, parse
from owner_runtime import SEALS, SealedExecutable
from private_action import material, payout_key, p2sh, state
import private_wallet as wallet
from receiver_tools import Crypto, recipient

ROOT = Path(__file__).resolve().parents[2]
CRYPTO = ROOT.parent / 'recipient-target/debug/kpi-future-recipient-crypto'
CRYPTO_SHA = '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
DOMAIN = hashlib.sha256(b'KPX3/OWNER-CONTROLS/PUBLIC-DO-NOT-FUND/v1').digest()


def old_public_decoder():
    path = ROOT / 'poc/independent-recovery/replay.py'
    raw = path.read_bytes()
    assert digest(raw) == 'f8be03c47008dd3b06ef601bd6da67ba42be47dec3f7c43a0d28dfe68e9b773d'
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location('_kpx3_public_test_decoder', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(path.parent))


class OwnerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executable = SealedExecutable(CRYPTO, CRYPTO_SHA)
        cls.crypto = Crypto(cls.executable)
        cls.v2 = recipient()
        cls.decoder = old_public_decoder()

    @classmethod
    def tearDownClass(cls):
        cls.executable.close()

    def fixture(self, continuing=True, duplicate=False):
        v2 = self.v2
        seed = hashlib.sha256(b'PUBLIC-DO-NOT-FUND/OWNER-A').digest()
        receiver = v2.Receiver(seed, DOMAIN, self.crypto)
        note = v2.Receipt.for_invoice(receiver.invoice(7), 60_000_000, hashlib.sha256(b'public-rho0').digest())
        cipher = self.crypto.seal(receiver.invoice(7).delivery_pk, note.encode())
        notes, ciphers = [note], [cipher]
        if continuing:
            other = receiver if duplicate else v2.Receiver(hashlib.sha256(b'PUBLIC-DO-NOT-FUND/OWNER-B').digest(), DOMAIN, self.crypto)
            second = v2.Receipt.for_invoice(other.invoice(7), 60_000_000, hashlib.sha256(b'public-rho1').digest())
            notes.append(second)
            ciphers.append(self.crypto.seal(other.invoice(7).delivery_pk, second.encode()))
        snapshot = v2.Snapshot([v2.Delivery(i, n.commitment(), ciphers[i]) for i, n in enumerate(notes)], v2.nf_entries([]))
        expected = snapshot.pin(DOMAIN)
        recovered = v2.recover(receiver, expected, snapshot)
        initial = b'\x4c\x70' + state(snapshot, DOMAIN) + bytes(24303)
        descriptor = {'domain_hex32': DOMAIN.hex(), 'genesis_hash_hex': wallet.GENESIS,
                      'founding_outpoint': {'transactionId': '11' * 32, 'index': 0},
                      'initial_redeem_hex': initial.hex(), 'vk_hex328': bytes(328).hex()}
        outpoint = {'transactionId': '22' * 32, 'index': 0}
        head = {'outpoint': outpoint, 'reserve_sompi': 60_000_000 * len(notes),
                'current_redeem_hex': initial.hex(), 'state_hex112': state(snapshot, DOMAIN).hex(),
                'current_utxo': {'outpoint': outpoint, 'amount_sompi': 60_000_000 * len(notes),
                    'script_public_key': p2sh(initial), 'block_daa_score': '1', 'is_coinbase': False, 'covenant_id': None}}
        claim = recovered.owned[0]
        secret, public, _ = payout_key(seed, descriptor, claim, self.crypto)
        self.assertEqual(self.crypto.xonly(secret), public)
        action = material(descriptor, head, receiver, claim, snapshot, expected, b'\0\0\x20' + public + b'\xac')
        return seed, receiver, notes, ciphers, snapshot, expected, recovered, descriptor, head, action

    def independent_updates(self, notes, ciphers, action):
        decoder = self.decoder
        current = decoder.State(DOMAIN, notes[0].note_bytes(), ciphers[0])
        for note, cipher in zip(notes[1:], ciphers[1:]):
            current.append(note.commitment(), cipher, current.cm.path(len(current.deliveries)))
        self.assertEqual(current.encoded(), action.before)
        for i in range(2):
            current.insert(action.nfs[i], action.public_witness[i * 1160:(i + 1) * 1160])
        if action.remaining:
            for i in range(2):
                current.append(action.commitments[i], action.ciphertexts[i * 264:(i + 1) * 264],
                               action.public_witness[2320 + i * 512:2832 + i * 512])
        current.counts()
        self.assertEqual(current.encoded(), action.after)
        return current

    def test_continuing_fullclaim_paths_and_real_sealed_dummies(self):
        _, _, notes, ciphers, _, _, _, _, _, action = self.fixture()
        auth, private, public = action.build(20_000_000)
        current = self.independent_updates(notes, ciphers, action)
        self.assertEqual((len(auth), len(action.public_witness), len(action.ciphertexts)), (528, 3344, 528))
        self.assertEqual((int.from_bytes(auth[484:492], 'little'), action.remaining), (40_000_000, 60_000_000))
        self.assertEqual((len(current.deliveries), len(current.entries)), (4, 3))
        self.assertNotEqual(action.commitments[0], action.commitments[1])
        for i, note in enumerate(action.outputs):
            self.assertEqual(note[:72] + note[104:], bytes(136))
            self.assertEqual(action.ciphertexts[i * 264 + 31] & 128, 0)
        self.assertEqual(private['schema'], 'kpx3-private-action-witness/v1')
        self.assertEqual(public['proof_hex128'], bytes(128).hex())

    def test_terminal_skips_all_cm_appends_and_complete_inactive_fields_are_zero(self):
        _, _, notes, ciphers, _, _, _, _, _, action = self.fixture(False)
        auth, private, _ = action.build(20_000_000)
        current = self.independent_updates(notes, ciphers, action)
        self.assertEqual((len(current.deliveries), len(current.entries)), (1, 3))
        self.assertEqual(auth[268:332], bytes(64))
        self.assertEqual(action.ciphertexts, bytes(528))
        self.assertEqual(action.public_witness[2320:], bytes(1024))
        self.assertEqual([row['note_hex168'] for row in private['outputs']], [bytes(168).hex()] * 2)
        self.assertEqual(auth[332:364], hashlib.sha256(bytes(528)).digest())

    def test_stale_second_nf_witness_and_changed_path_are_rejected(self):
        _, _, notes, ciphers, _, _, _, _, _, action = self.fixture(False)
        current = self.decoder.State(DOMAIN, notes[0].note_bytes(), ciphers[0])
        with self.assertRaises(self.decoder.Invalid):
            current.insert(action.nfs[1], action.public_witness[1160:2320])
        current = self.decoder.State(DOMAIN, notes[0].note_bytes(), ciphers[0])
        bad = bytearray(action.public_witness[:1160]);bad[72] ^= 1
        with self.assertRaises(self.decoder.Invalid):
            current.insert(action.nfs[0], bytes(bad))

    def test_original_nullifier_cannot_spend_twice(self):
        _, _, notes, ciphers, _, _, _, _, _, action = self.fixture(False)
        current = self.decoder.State(DOMAIN, notes[0].note_bytes(), ciphers[0])
        current.insert(action.nfs[0], action.public_witness[:1160])
        with self.assertRaisesRegex(self.decoder.Invalid, 'double-spend'):
            current.insert(action.nfs[0], action.public_witness[:1160])

    def test_duplicate_invoice_keeps_both_positive_claims_actionable(self):
        *_, recovered, _, _, action = self.fixture(duplicate=True)
        self.assertEqual(recovered.all_owned_unspent_sompi, 120_000_000)
        self.assertTrue(all(c.owner_action_available and c.privacy_contaminated for c in recovered.owned))
        # The unchanged V2 policy quarantines the duplicate credit, retaining
        # the first credit while keeping both positive claims actionable.
        self.assertEqual(recovered.normal_credit_sompi, 60_000_000)
        action.build(20_000_000)

    def test_fee_payout_boundaries(self):
        *_, action = self.fixture(False)
        for fee in (0, -1, 50_000_001, True, '01'):
            with self.assertRaises(Invalid):action.build(fee)
        auth, _, _ = action.build(50_000_000)
        self.assertEqual(int.from_bytes(auth[484:492], 'little'), 10_000_000)

    def test_payout_hmac_exact_vector_and_context_separation(self):
        seed = bytes(range(32))
        class Receipt:
            native_pk = bytes(32)
            def commitment(self):return bytes(range(96, 128))
        claim = SimpleNamespace(receipt=Receipt(), position=9)
        descriptor = {'domain_hex32': bytes(range(32, 64)).hex(),
                      'founding_outpoint': {'transactionId': bytes(range(64, 96)).hex(), 'index': 7}}
        secret, public, retry = payout_key(seed, descriptor, claim, self.crypto)
        self.assertEqual(secret.hex(), '982ad90d8cb00c4b830b7e5c6a01ba1661b92f43854268fa1ddbbde3a2cbf4e6')
        self.assertEqual(retry, 0)
        variants = []
        changed = deepcopy(descriptor);changed['domain_hex32'] = ('ff' * 32);variants.append((changed, claim))
        changed = deepcopy(descriptor);changed['founding_outpoint']['index'] = 8;variants.append((changed, claim))
        variants.append((descriptor, SimpleNamespace(receipt=Receipt(), position=10)))
        for changed, note in variants:
            self.assertNotEqual(payout_key(seed, changed, note, self.crypto)[1], public)

    def test_invalid_scalar_and_note_key_equality_retry(self):
        seed, _, _, _, _, _, recovered, descriptor, _, _ = self.fixture(False)
        claim = recovered.owned[0]
        class RetryCrypto:
            def __init__(self):self.calls = 0
            def xonly(self, secret):
                self.calls += 1
                if self.calls == 1:raise recipient().Invalid('crypto-scalar')
                if self.calls == 2:return claim.receipt.native_pk
                return bytes([3]) * 32
        crypto = RetryCrypto()
        _, public, retry = payout_key(seed, descriptor, claim, crypto)
        self.assertEqual((crypto.calls, retry, public), (3, 2, bytes([3]) * 32))

    def test_historical_spent_note_recovers_current_default_native_payout(self):
        seed, _, _, _, _, _, recovered, descriptor, _, _ = self.fixture(False)
        recovered.owned[0].spent = True
        secret, public, _ = payout_key(seed, descriptor, recovered.owned[0], self.crypto)
        del secret
        point = {'transactionId': 'ab' * 32, 'index': 0};script = (b'\0\0\x20' + public + b'\xac').hex()
        row = {'script_public_key': script, 'amount_sompi': 40_000_000, 'outpoint': point, 'queried': True,
               'current_utxo': {'outpoint': point, 'amount_sompi': 40_000_000, 'script_public_key': script,
                                'is_coinbase': False, 'covenant_id': None}}
        result = wallet.owned_native_payouts(seed, descriptor, recovered, self.crypto, {'payouts': [row]})
        self.assertEqual(result['current_owned_default_private_payouts_sompi'], 40_000_000)
        self.assertFalse(any(word in canonical(result).decode() for word in ('position', 'secret', 'native_pk')))
        row['current_utxo'] = None
        result = wallet.owned_native_payouts(seed, descriptor, recovered, self.crypto, {'payouts': [row]})
        self.assertEqual(result['historical_owned_default_private_payouts_sompi'], 40_000_000)
        self.assertEqual(result['current_owned_default_private_payouts_sompi'], 0)
        row['queried'] = False
        with self.assertRaisesRegex(Invalid, 'current-query'):
            wallet.owned_native_payouts(seed, descriptor, recovered, self.crypto, {'payouts': [row]})

    def test_unselected_software_rejects_before_backup_or_network(self):
        request = dict.fromkeys({'schema', 'op', 'backup_path', 'descriptor_path', 'expected_descriptor_sha256',
             'public_manifest_path', 'fetch_path', 'crypto_path', 'output_dir'}, '/never-read')
        request.update(schema='kpx3-private-owner-request/v1', op='recover')
        with patch.object(wallet, 'backup') as backup, patch.object(wallet, 'network_replay') as replay:
            with self.assertRaisesRegex(Invalid, 'selection-required'):wallet.execute(request)
            backup.assert_not_called();replay.assert_not_called()

    def test_parameters_ready_exact_schema_and_identity_gate(self):
        ready = {'event': 'parameters-ready', 'parameter_manifest_sha256': None,
                 'domain_hex32': None, 'vk_sha256': None, 'compiled_build_identity_sha256': None}
        # No selected release exists in this public control; use explicit public
        # mock identities only to exercise the event gate without a real PK.
        with patch.multiple(wallet.selection, PARAMETER_MANIFEST_SHA256='11' * 32,
                DOMAIN_HEX32='22' * 32, VK_SHA256='33' * 32, COMPILED_BUILD_IDENTITY_SHA256='44' * 32):
            with self.assertRaisesRegex(Invalid, 'ready-identity'):
                wallet.ready(SimpleNamespace(stdout=io.StringIO(json.dumps(ready) + '\n')))
            ready.update(parameter_manifest_sha256='11' * 32, domain_hex32='22' * 32,
                         vk_sha256='33' * 32, compiled_build_identity_sha256='44' * 32)
            wallet.ready(SimpleNamespace(stdout=io.StringIO(json.dumps(ready) + '\n')))
            ready['private_witness'] = 'forbidden'
            with self.assertRaisesRegex(Invalid, 'ready-schema'):
                wallet.ready(SimpleNamespace(stdout=io.StringIO(json.dumps(ready) + '\n')))

    def test_duplicate_json_and_request_position_injection_reject(self):
        with self.assertRaisesRegex(Invalid, 'duplicate-json-field'):parse('{"op":1,"op":2}')
        with self.assertRaisesRegex(Invalid, 'request-fields'):
            wallet.execute({'schema': 'kpx3-private-owner-request/v1', 'op': 'prepare-private-exit', 'position': 1})


class RuntimeControls(unittest.TestCase):
    def test_sealed_payload_ignores_source_overwrite_and_replacement(self):
        raw = Path('/usr/bin/true').read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'selected');path.write_bytes(raw)
            with SealedExecutable(path, digest(raw)) as executable:
                self.assertEqual(fcntl.fcntl(executable.fd, fcntl.F_GET_SEALS), SEALS)
                with self.assertRaises(OSError):os.pwrite(executable.fd, b'bad', 0)
                path.write_bytes(b'inplace mutation')
                path.unlink();path.write_bytes(b'new inode')
                self.assertEqual(executable.run().returncode, 0)

    def test_selected_hash_and_elf_checks(self):
        with self.assertRaisesRegex(Invalid, 'identity'):SealedExecutable('/usr/bin/true', '00' * 32)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'script');path.write_bytes(b'#!/bin/sh\nexit 0\n')
            with self.assertRaisesRegex(Invalid, 'elf-required'):SealedExecutable(path, digest(path.read_bytes()))

    def test_clean_child_environment_and_explicit_witness_fd(self):
        # Ubuntu's env/cat names are multicall wrappers which intentionally
        # reject an alternate /proc/self/exe. Use installed standalone GNU ELFs.
        raw = Path('/usr/bin/gnuenv').read_bytes()
        with SealedExecutable('/usr/bin/gnuenv', digest(raw)) as executable:
            result = executable.run()
            self.assertEqual(result.returncode, 0)
            environment = dict(line.split('=', 1) for line in result.stdout.splitlines())
            self.assertEqual(environment, {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
        raw = Path('/usr/bin/gnucat').read_bytes()
        with SealedExecutable('/usr/bin/gnucat', digest(raw)) as executable:
            read_fd, write_fd = os.pipe()
            try:
                process = executable.popen([f'/proc/self/fd/{read_fd}'], extra_fds=(read_fd,))
                os.write(write_fd, b'PUBLIC-ONLY-FD-CONTROL')
                os.close(write_fd);write_fd = None
                stdout, _ = process.communicate()
                self.assertEqual((process.returncode, stdout), (0, 'PUBLIC-ONLY-FD-CONTROL'))
            finally:
                os.close(read_fd)
                if write_fd is not None:os.close(write_fd)


if __name__ == '__main__':
    unittest.main()
