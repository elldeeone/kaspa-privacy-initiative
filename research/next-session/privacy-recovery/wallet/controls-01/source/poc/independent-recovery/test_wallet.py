"""Public synthetic wallet component controls; never an accepted-chain claim."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import wallet


class WalletControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2 = wallet.recipient_module()
        cls.crypto = wallet.runtime_crypto(wallet.DEFAULT_CRYPTO)
        cls.domain = bytes.fromhex('9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c')
        cls.seed = bytes([0x31]) * 32  # PUBLIC_SYNTHETIC_DO_NOT_FUND.
        cls.receiver = cls.v2.Receiver(cls.seed, cls.domain, cls.crypto)
        raw = json.loads((wallet.ROOT / 'research/next-session/private-integration/lifecycle/execution-01/private/transaction.json').read_bytes())
        cls.template = bytes.fromhex(raw['inputs'][0]['signatureScript'])[199:]
        cls.vk = (wallet.ROOT / 'research/next-session/private-integration/lifecycle/setup-01/verification-key.bin').read_bytes()

    def state(self, snapshot):
        cm, nf = snapshot.roots()
        return b'KPX2ST01' + self.domain + cm.root + self.v2.u32(len(snapshot.deliveries)) + nf.root + self.v2.u32(len(snapshot.nullifiers))

    def fixture(self, duplicate=False, spent=False):
        v2 = self.v2
        own = v2.deliver(self.crypto, self.receiver.invoice(0), 100_000_000, bytes([0x41]) * 32, 0)
        other = self.receiver if duplicate else v2.Receiver(bytes([0x32]) * 32, self.domain, self.crypto)
        second = v2.deliver(self.crypto, other.invoice(0), 80_000_000, bytes([0x42]) * 32, 1)
        nf = self.receiver.nullifier(self.receiver.open(own.ciphertext), 0)
        nullifiers = v2.nf_entries([nf] if spent else [])
        snapshot = v2.Snapshot([own, second], nullifiers)
        initial = v2.Snapshot([own], v2.nf_entries([]))
        initial_redeem = self.template[:2] + self.state(initial) + self.template[114:]
        current_redeem = self.template[:2] + self.state(snapshot) + self.template[114:]
        descriptor = {'schema': 'kpx2-recovery-descriptor/v1', 'network_id': 'testnet-10',
            'genesis_hash_hex': wallet.GENESIS, 'domain_hex32': self.domain.hex(),
            'founding_outpoint': {'transactionId': 'aa' * 32, 'index': 0},
            'birth_start_hash': 'bb' * 32, 'initial_redeem_hex': initial_redeem.hex(),
            'immutable_policy_sha256': hashlib.sha256(initial_redeem[114:]).hexdigest(),
            'vk_hex328': self.vk.hex()}
        reserve = 80_000_000 if spent else 180_000_000
        outpoint = {'transactionId': 'cc' * 32, 'index': 0}
        public = {'schema': 'kpx2-independent-replay/v1',
            'descriptor_sha256': wallet.digest(wallet.canonical(descriptor)),
            'network_id': descriptor['network_id'], 'genesis_hash_hex': wallet.GENESIS,
            'domain_hex32': self.domain.hex(), 'deliveries': [d.public() for d in snapshot.deliveries],
            'nullifiers': [{'value': n.value.hex(), 'next_value': n.next_value.hex(), 'next_index': n.next_index}
                           for n in snapshot.nullifiers],
            'head': {'outpoint': outpoint, 'state_hex112': self.state(snapshot).hex(),
                'reserve_sompi': reserve, 'current_redeem_hex': current_redeem.hex(),
                'current_utxo': {'outpoint': outpoint, 'amount_sompi': str(reserve),
                    'script_public_key': wallet.p2sh(current_redeem), 'is_coinbase': False,
                    'covenant_id': None, 'block_daa_score': '0'}},
            'payouts': [], 'completeness': {'complete': True, 'terminal': False,
                'acceptance_trust': 'LOCAL_UNPROVED_PUBLIC_UNIT_FIXTURE'}}
        return descriptor, public

    def run_recovery(self, descriptor, public, seed=None):
        return wallet.recognize(descriptor, public, self.seed if seed is None else seed, self.crypto)

    def test_recognized_receipt_and_current_witness(self):
        descriptor, public = self.fixture()
        result, *_ = self.run_recovery(descriptor, public)
        self.assertEqual((result['recognized_receipts'], result['recognized_owned_unspent_sompi'],
                          result['current_witnesses_constructible']), (1, 100_000_000, 1))
        self.assertFalse(result['operator_snapshot_or_expected_payment_map_used'])
        self.assertFalse(result['independent_consensus_verified'])

    def test_wrong_seed_no_universal_zero_claim(self):
        result, *_ = self.run_recovery(*self.fixture(), seed=bytes([0x44]) * 32)
        self.assertEqual(result['recognized_receipts'], 0)
        self.assertTrue(result['recognized_valid_receipts_only'])
        self.assertFalse(result['no_recognized_receipt_proves_absence_of_all_owned_claims'])

    def test_duplicate_does_not_freeze_original_or_positive_liability(self):
        result, *_ = self.run_recovery(*self.fixture(duplicate=True))
        self.assertEqual(result['recognized_owned_unspent_sompi'], 180_000_000)
        self.assertEqual(result['recognized_normal_credit_sompi'], 100_000_000)
        self.assertEqual(result['current_witnesses_constructible'], 2)
        self.assertEqual(result['recognized_privacy_contaminated_claims'], 2)

    def test_current_nf_marks_original_position_spent(self):
        result, *_ = self.run_recovery(*self.fixture(spent=True))
        self.assertEqual(result['recognized_spent_receipts'], 1)
        self.assertEqual(result['recognized_owned_unspent_sompi'], 0)
        self.assertEqual(result['current_witnesses_constructible'], 0)

    def payout_fixture(self, still_unspent=True):
        descriptor, public = self.fixture(spent=True)
        receipt = self.receiver.open(bytes.fromhex(public['deliveries'][0]['ciphertext']))
        point = {'transactionId': 'dd' * 32, 'index': 1}
        spk = (b'\0\0\x20' + receipt.native_pk + b'\xac').hex()
        public['payouts'] = [{'transaction_id': point['transactionId'], 'outpoint': point,
            'amount_sompi': 95_000_000, 'script_public_key': spk,
            'cm': receipt.commitment().hex(), 'position': 0,
            'note_hex168': receipt.note_bytes().hex(), 'queried': True,
            'current_utxo': {'outpoint': point, 'amount_sompi': '95000000',
                'script_public_key': spk, 'is_coinbase': False, 'covenant_id': None}
                if still_unspent else None}]
        return descriptor, public

    def test_historical_and_current_native_payouts(self):
        result, *_ = self.run_recovery(*self.payout_fixture())
        self.assertEqual(result['historical_owned_payouts_sompi'], 95_000_000)
        self.assertEqual(result['current_owned_pool_payouts_sompi'], 95_000_000)
        self.assertEqual(result['current_owned_pool_payout_utxos'], 1)

    def test_legitimate_later_native_spend_is_not_missing_pool_payment(self):
        result, *_ = self.run_recovery(*self.payout_fixture(still_unspent=False))
        self.assertEqual(result['historical_owned_payouts_sompi'], 95_000_000)
        self.assertEqual(result['current_owned_pool_payouts_sompi'], 0)

    def test_unqueried_owned_payout_rejects(self):
        descriptor, public = self.payout_fixture()
        public['payouts'][0]['queried'] = False
        with self.assertRaisesRegex(wallet.Invalid, 'owned-payout-current-query-missing'):
            self.run_recovery(descriptor, public)

    def test_wrong_owned_native_payout_value_rejects(self):
        descriptor, public = self.payout_fixture()
        public['payouts'][0]['current_utxo']['amount_sompi'] = '95000001'
        with self.assertRaisesRegex(wallet.Invalid, 'owned-payout-current-utxo'):
            self.run_recovery(descriptor, public)

    def test_duplicate_payout_cannot_double_native_balance(self):
        descriptor, public = self.payout_fixture()
        public['payouts'].append(copy.deepcopy(public['payouts'][0]))
        with self.assertRaisesRegex(wallet.Invalid, 'duplicate-owned-payout'):
            self.run_recovery(descriptor, public)

    def test_incomplete_history_never_empty_balance(self):
        descriptor, public = self.fixture()
        public['completeness']['complete'] = False
        with self.assertRaisesRegex(wallet.Invalid, 'incomplete-public-history'):
            self.run_recovery(descriptor, public)

    def test_missing_ciphertext_never_empty_balance(self):
        descriptor, public = self.fixture()
        public['deliveries'][0]['ciphertext'] = None
        with self.assertRaises(wallet.Invalid):
            self.run_recovery(descriptor, public)

    def test_current_root_corruption_rejects(self):
        descriptor, public = self.fixture()
        public['head']['state_hex112'] = public['head']['state_hex112'][:-2] + 'ff'
        with self.assertRaisesRegex(wallet.Invalid, 'replayed-current-state'):
            self.run_recovery(descriptor, public)

    def test_missing_live_reserve_rejects(self):
        descriptor, public = self.fixture()
        public['head']['current_utxo'] = None
        with self.assertRaisesRegex(wallet.Invalid, 'current-reserve-utxo'):
            self.run_recovery(descriptor, public)

    def test_policy_mutation_rejects(self):
        descriptor, public = self.fixture()
        raw = bytearray.fromhex(public['head']['current_redeem_hex']); raw[-1] ^= 1
        public['head']['current_redeem_hex'] = raw.hex()
        with self.assertRaisesRegex(wallet.Invalid, 'current-immutable-policy'):
            self.run_recovery(descriptor, public)

    def test_descriptor_domain_replay_rejects(self):
        descriptor, public = self.fixture()
        public['domain_hex32'] = '11' * 32
        with self.assertRaisesRegex(wallet.Invalid, 'replay-network-domain'):
            self.run_recovery(descriptor, public)

    def test_report_does_not_expose_secret_or_opening(self):
        result, *_ = self.run_recovery(*self.fixture())
        raw = json.dumps(result)
        keys = self.receiver.keys(0)
        for value in (self.seed, keys.owner_secret, keys.nf_secret, keys.native_secret):
            self.assertNotIn(value.hex(), raw)
        self.assertNotIn('note_hex168', result)

    def test_explicit_consent_required_before_files_or_helper(self):
        with patch.object(wallet, 'runtime_crypto', side_effect=AssertionError('no helper access')):
            with self.assertRaisesRegex(wallet.Invalid, 'explicit-reveal-consent-required'):
                wallet.execute({'op': 'prepare-reveal'})

    def test_user_descriptor_pin_mismatch_precedes_seed_read(self):
        descriptor, _ = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'descriptor.json'; path.write_text(json.dumps(descriptor))
            with patch.object(wallet, 'load_backup', side_effect=AssertionError('seed must not be read')):
                with self.assertRaisesRegex(wallet.Invalid, 'user-selected-descriptor-pin-mismatch'):
                    wallet.execute({'op': 'recover', 'descriptor_path': str(path),
                        'expected_descriptor_sha256': '11' * 32,
                        'backup_path': '/no-backup', 'fetch_path': '/no-fetch'})

    def test_payload_exact_note_current_nf_and_fee(self):
        descriptor, public = self.fixture()
        _, receiver, recovered, expected, snapshot = self.run_recovery(descriptor, public)
        payload = wallet.reveal_payload(receiver, recovered.owned[0], expected, snapshot, 5_000_000)
        self.assertEqual(len(payload), 2029)
        self.assertEqual(payload[:9], b'KPX2RV01\x01')
        self.assertEqual(payload[1917:1949], recovered.owned[0].nf)
        self.assertEqual(int.from_bytes(payload[2013:2021], 'little'), 5_000_000)
        self.assertEqual(int.from_bytes(payload[2021:2029], 'little'), 95_000_000)

    def test_spent_cannot_construct_exit(self):
        descriptor, public = self.fixture(spent=True)
        _, receiver, recovered, expected, snapshot = self.run_recovery(descriptor, public)
        with self.assertRaisesRegex(self.v2.Invalid, 'already-spent'):
            wallet.reveal_payload(receiver, recovered.owned[0], expected, snapshot, 1)

    def test_boolean_amount_rejected(self):
        with self.assertRaisesRegex(wallet.Invalid, 'integer-sompi'):
            wallet.amount(True)

    def test_duplicate_consent_field_rejected(self):
        with self.assertRaisesRegex(wallet.Invalid, 'duplicate-json-field'):
            wallet.parse_json('{"disclosure_consent":false,"disclosure_consent":"yes"}')

    def test_nested_duplicate_descriptor_field_rejected(self):
        with self.assertRaisesRegex(wallet.Invalid, 'duplicate-json-field'):
            wallet.parse_json('{"founding_outpoint":{"index":0,"index":1}}')

    def test_crypto_pin_rejects_untrusted_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / 'untrusted'; executable.write_text('#!/bin/sh\nexit 0\n'); executable.chmod(0o700)
            with self.assertRaisesRegex(wallet.Invalid, 'crypto-software-identity'):
                wallet.runtime_crypto(executable)

    def test_backup_regular_private_file_and_identity(self):
        descriptor, _ = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / 'backup.json'
            value = {'schema': 'kpx2-tn10-seed-backup/v1', 'network_id': 'testnet-10',
                'genesis_hash_hex': wallet.GENESIS, 'domain_hex32': self.domain.hex(),
                'seed_hex32': self.seed.hex()}
            backup.write_text(json.dumps(value)); backup.chmod(0o600)
            self.assertEqual(wallet.load_backup(backup, descriptor), self.seed)
            backup.chmod(0o644)
            with self.assertRaisesRegex(wallet.Invalid, 'backup-permissions'):
                wallet.load_backup(backup, descriptor)

    def test_existing_backup_in_another_git_worktree_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp) / 'other'; repository.mkdir()
            subprocess.run(['git', 'init', '-q', str(repository)], check=True)
            backup = repository / 'backup.json'; backup.write_text('{}'); backup.chmod(0o600)
            with self.assertRaisesRegex(wallet.Invalid, 'private-material-inside-git'):
                wallet.outside_git(backup)

    def test_dotdot_alias_to_git_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp) / 'other'; repository.mkdir()
            subprocess.run(['git', 'init', '-q', str(repository)], check=True)
            inner = repository / 'inner'; inner.mkdir()
            backup = repository / 'backup.json'; backup.write_text('{}'); backup.chmod(0o600)
            with self.assertRaisesRegex(wallet.Invalid, 'private-material-inside-git'):
                wallet.outside_git(inner / '..' / 'backup.json')

    def test_symlink_backup_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / 'backup.json'; backup.write_text('{}'); backup.chmod(0o600)
            alias = Path(tmp) / 'alias.json'; alias.symlink_to(backup)
            with self.assertRaisesRegex(wallet.Invalid, 'symlink-path'):
                wallet.outside_git(alias)


if __name__ == '__main__':
    unittest.main()
