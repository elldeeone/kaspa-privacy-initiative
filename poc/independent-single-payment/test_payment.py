"""Public deterministic development controls, never proof/native/privacy evidence."""
import copy
import hashlib
import json
import unittest

from payment import (Request, REQUEST_SCHEMA, STANDALONE, VIRTUAL,
                     prepare_payment, public_component)
from reuse import load


class Entropy:
    def __init__(self, label):
        self.seed = label
        self.counter = 0

    def __call__(self, width):
        out = b''
        while len(out) < width:
            out += hashlib.sha256(self.seed + self.counter.to_bytes(8, 'little')).digest()
            self.counter += 1
        return out[:width]


class PaymentControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = load()
        cls.p = cls.c.primitives
        cls.crypto = cls.c.receiver.Crypto()
        cls.v2 = cls.c.receiver.module()
        cls.domain = cls.c.native_runtime.DOMAIN
        cls.seeds = [cls.p.h(b'PUBLIC_UNSAFE_SINGLE_INVOICE_DO_NOT_FUND_TEST', bytes([i]))
                     for i in range(3)]
        cls.wallets = [cls.v2.Receiver(seed, cls.domain, cls.crypto) for seed in cls.seeds]
        cls.invoices = [wallet.invoice(0) for wallet in cls.wallets]
        note = cls.v2.Receipt.for_invoice(cls.invoices[0], 1_000_000_000,
                                        cls.p.h(b'PUBLIC_UNSAFE_SINGLE_INVOICE_RHO'))
        cipher = cls.crypto.seal(cls.invoices[0].delivery_pk, note.encode())
        cls.initial = cls.p.singleton(cls.domain, note.note_bytes(), cipher)
        cls.point = {'transactionId': '11' * 32, 'index': 0}
        cls.fee = 18_826_500  # Recorded compact P0 shape; actual quote still required.
        cls.credit = cls.c.owner.minimum_shape_fee(2, 23575, 100)
        assert cls.fee == 18_826_500 and cls.credit == 18_867_700

    def request(self, invoice=None, net=200_000_000, credit=None):
        value = {'schema': REQUEST_SCHEMA, 'domain_hex32': self.domain.hex(),
                 'recipient_invoice_hex208': (invoice or self.invoices[1]).encode().hex(),
                 'net_principal_sompi': net,
                 'recipient_exit_credit_sompi': self.credit if credit is None else credit}
        return Request.parse(json.dumps(value), self.domain)

    def recognized(self, wallet, snapshot):
        recovered = self.c.receiver.recover(wallet, snapshot, snapshot.state(self.domain))
        current = [item for item in recovered.owned if item.owner_action_available]
        return recovered, current

    def payment(self, *, seed_label=b'PUBLIC_ACTION_1', request=None, snapshot=None, point=None,
                context=STANDALONE, fee=None):
        snapshot = snapshot or self.initial
        wallet = self.v2.Receiver(self.seeds[0], self.domain, self.crypto)
        recovered, available = self.recognized(wallet, snapshot)
        self.assertEqual(len(available), 1)
        return prepare_payment(wallet, snapshot, available[0], point or self.point,
            1_000_000_000 if snapshot is self.initial else self._reserve(snapshot),
            self.fee if fee is None else fee, request or self.request(), recovered.owned,
            expected_exit_credit_sompi=self.credit, fee_context=context,
            entropy=Entropy(seed_label))

    def _reserve(self, snapshot):
        return sum(item.receipt.value_sompi
                   for wallet in self.wallets
                   for item in self.recognized(wallet, snapshot)[1])

    def test_one_invoice_gross_fee_change_and_original_backup_recovery(self):
        prepared = self.payment()
        candidate = prepared.candidate
        self.assertEqual((candidate.role, candidate.mode, candidate.payout), ('compact2', 2, 0))
        self.assertEqual(prepared.recipient_gross_sompi, 218_867_700)
        self.assertEqual(prepared.sender_change_sompi, 762_305_800)
        self.assertEqual(candidate.reserve_after, 981_173_500)
        self.assertEqual(len(candidate.payload()), 3920)
        restored_sender = self.v2.Receiver(self.seeds[0], self.domain, self.crypto)
        restored_payee = self.v2.Receiver(self.seeds[1], self.domain, self.crypto)
        history, own = self.recognized(restored_sender, candidate.after)
        _, payee = self.recognized(restored_payee, candidate.after)
        self.assertEqual((len(history.owned), sum(item.spent for item in history.owned)), (2, 1))
        self.assertEqual([item.receipt.value_sompi for item in own], [prepared.sender_change_sompi])
        self.assertEqual([item.receipt.value_sompi for item in payee], [prepared.recipient_gross_sompi])
        self.assertNotEqual(own[0].receipt.index, 0)
        self.assertEqual({own[0].position, payee[0].position}, {2, 3})
        self.assertEqual(candidate.auth[268:300], self.p.h(candidate.cm_list))

    def test_both_output_slots_are_possible_without_fixed_recipient_change_role(self):
        positions = set()
        for label in (b'PUBLIC_PERM_0', b'PUBLIC_PERM_1', b'PUBLIC_PERM_2', b'PUBLIC_PERM_3',
                      b'PUBLIC_PERM_4', b'PUBLIC_PERM_5', b'PUBLIC_PERM_6', b'PUBLIC_PERM_7'):
            prepared = self.payment(seed_label=label)
            _, claims = self.recognized(self.wallets[1], prepared.candidate.after)
            positions.add(claims[0].position)
        self.assertEqual(positions, {2, 3})

    def test_reentrant_second_invoice_then_three_own_cashouts_reconcile(self):
        first = self.payment()
        second_point = {'transactionId': '22' * 32, 'index': 0}
        second = self.payment(seed_label=b'PUBLIC_SECOND_INVOICE',
            request=self.request(self.invoices[2], 100_000_000),
            snapshot=first.candidate.after, point=second_point)
        snapshot, reserve = second.candidate.after, second.candidate.reserve_after
        self.assertEqual(second.sender_change_sompi, 624_611_600)
        self.assertEqual(reserve, 962_347_000)
        self.assertEqual(snapshot.cm_cursor, 6)
        fees = first.candidate.fee + second.candidate.fee
        payouts = []
        for ordinal in (1, 2, 0):
            wallet = self.v2.Receiver(self.seeds[ordinal], self.domain, self.crypto)
            _, claims = self.recognized(wallet, snapshot)
            self.assertEqual(len(claims), 1)
            claim = claims[0]
            mode = 0 if claim.receipt.value_sompi == reserve else 2
            fee = self.c.owner.minimum_shape_fee(mode, 23575, 100)
            selected = self.c.actions.cashout(self.seeds[ordinal], wallet, snapshot, claim,
                second_point, self.point, reserve, fee, Entropy(bytes([ordinal])))
            snapshot, reserve = selected.after, selected.reserve_after
            payouts.append(selected.payout)
            fees += fee
        self.assertEqual(payouts[:2], [200_000_000, 100_000_000])
        self.assertEqual((reserve, len(snapshot.nullifiers)), (0, 11))
        self.assertEqual(1_000_000_000, sum(payouts) + fees)
        for wallet in self.wallets:
            _, claims = self.recognized(wallet, snapshot)
            self.assertEqual(claims, [])

    def test_wrong_domain_extra_fields_list_and_noninteger_requests_reject(self):
        invoice = self.invoices[1].encode().hex()
        base = {'schema': REQUEST_SCHEMA, 'domain_hex32': self.domain.hex(),
                'recipient_invoice_hex208': invoice, 'net_principal_sompi': 200_000_000,
                'recipient_exit_credit_sompi': self.credit}
        bad = []
        for name, value in [('domain_hex32', '00' * 32),
                            ('recipient_invoice_hex208', [invoice]),
                            ('net_principal_sompi', True),
                            ('net_principal_sompi', -1),
                            ('net_principal_sompi', self.p.MAX),
                            ('recipient_exit_credit_sompi', 0)]:
            item = dict(base)
            item[name] = value
            bad.append(item)
        bad.append(dict(base, second_invoice=invoice))
        for item in bad:
            with self.subTest(keys=list(item)):
                with self.assertRaises((ValueError, TypeError)):
                    Request.parse(json.dumps(item), self.domain)
        with self.assertRaisesRegex(ValueError, 'duplicate-JSON-field'):
            Request.parse('{"schema":0,"schema":1}', self.domain)

    def test_self_historical_receive_fields_insufficient_dust_and_credit_reject(self):
        for invoice in (self.invoices[0], self.wallets[0].invoice(999)):
            with self.assertRaisesRegex(ValueError, 'recipient-is-sender'):
                self.payment(request=self.request(invoice))
        for net in (1_000_000_000, 903_000_000):
            with self.assertRaisesRegex(ValueError, 'positive-change-floor-or-insufficient-value'):
                self.payment(request=self.request(net=net))
        with self.assertRaisesRegex(ValueError, 'exact-requested-exit-credit'):
            self.payment(request=self.request(credit=self.credit + 1))
        with self.assertRaisesRegex(ValueError, 'explicit-fee-settlement-context'):
            self.payment(context='IMPLICIT_APPROVED')
        with self.assertRaisesRegex(ValueError, 'positive-authorized-fee'):
            self.payment(fee=0)

    def test_spent_original_claim_rejects_even_with_new_change_available(self):
        prepared = self.payment()
        recovered, claims = self.recognized(self.wallets[0], self.initial)
        with self.assertRaisesRegex(ValueError, 'selected-claim-already-spent'):
            prepare_payment(self.wallets[0], prepared.candidate.after, claims[0], self.point,
                prepared.candidate.reserve_after, self.fee, self.request(), recovered.owned,
                expected_exit_credit_sompi=self.credit, fee_context=STANDALONE,
                entropy=Entropy(b'PUBLIC_REPLAY'))

    def case(self, prepared, proof):
        candidate = prepared.candidate
        # Deliberately fake public program/ID, never Native/proof evidence.
        redeem = b'\x4c\x70' + candidate.auth[76:188] + b'PUBLIC_NOT_NATIVE_TEMPLATE' + bytes(300)
        next_redeem = b'\x4c\x70' + candidate.auth[364:476] + redeem[114:]
        signature = (self.c.native_runtime.push(bytes(65))
            + self.c.native_runtime.push(proof) + self.c.native_runtime.push(redeem))
        body = self.c.native_runtime.tx(self.point,
            [(candidate.reserve_after, self.c.native_runtime.p2sh(next_redeem))],
            candidate.payload(), signature, 1600)
        contexts = [self.c.native_runtime.context(1_000_000_000, redeem)]
        return self.c.native_runtime.public_case(body, contexts)

    def test_only_public_wire_component_is_copied_with_explicit_unverified_context(self):
        prepared = self.payment(context=VIRTUAL)
        proof = bytes([42]) * 128  # fake; export must never call this genuine.
        case = self.case(prepared, proof)
        public = public_component(prepared, proof, case)
        self.assertEqual(set(public), {'schema', 'classification', 'role', 'fee_context',
                                      'auth_hex528', 'payload_hex', 'proof_hex128', 'public_case'})
        self.assertEqual(public['classification'],
                         'UNVERIFIED_COMPONENT_EXTERNAL_SETTLEMENT_POLICY_REQUIRED')
        self.assertEqual(public['fee_context'], VIRTUAL)
        encoded = json.dumps(public)
        for private_key in ('s_hex32', 'k_hex32', 'note_hex168', 'seed_hex32', 'sender_change_sompi'):
            self.assertNotIn(private_key, encoded)
        case['transaction']['outputs'][0]['value'] = 1
        self.assertEqual(public['public_case']['transaction']['outputs'][0]['value'],
                         prepared.candidate.reserve_after)

    def test_changed_public_fee_point_payload_proof_context_or_header_rejects(self):
        prepared = self.payment()
        proof = bytes([42]) * 128
        base = self.case(prepared, proof)
        mutations = [
            lambda c: c['transaction']['outputs'][0].update(value=1),
            lambda c: c['transaction']['inputs'][0]['previousOutpoint'].update(index=1),
            lambda c: c['transaction'].update(payload='00' * 3920),
            lambda c: c['transaction']['inputs'][0].update(signatureScript='00'),
            lambda c: c['entries'][0].update(amount=999_999_999),
            lambda c: c['entries'][0].update(isCoinbase=True),
            lambda c: c['transaction'].update(version=True),
            lambda c: c.update(hidden_owner_map={}),
        ]
        for mutate in mutations:
            case = copy.deepcopy(base)
            mutate(case)
            with self.assertRaises(ValueError):
                public_component(prepared, proof, case)
        with self.assertRaisesRegex(ValueError, 'exact-public-proof-frame'):
            public_component(prepared, bytes([43]) * 128, base)


if __name__ == '__main__':
    unittest.main()

