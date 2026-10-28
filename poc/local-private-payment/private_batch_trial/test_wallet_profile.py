"""Real mature-crypto controls over public unfunded seeds; no native trial."""
from dataclasses import replace
import hashlib
from pathlib import Path
import unittest

import wallet_profile as wallet

NODE=Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node')
CRYPTO=Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto')
JS_ROOT=Path('/var/tmp/kpi-signature-predicate-tools-20261026-01')
LEAF_MAP=Path('/run/user/1000/kpi-nativeauthspend-resume-20261028-03/JS-INSTALLED-LEAF-MAP.json')
LEAF_MAP_SHA='00b536cab3799984c2a2f9895329bc410daa0f11f5093f10aa48d92f3abdca50'
# These seeds are deliberately public synthetic vectors, never funded wallets.
SEEDS=tuple(bytes(range(start,start+32)) for start in (0,32,64))
PROFILE=wallet.Profile(bytes([0xa6])*32,hashlib.sha256(b'ADR0074 unfunded wallet component profile v1').digest())


class WalletProfileControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        modules=wallet.authenticate_js(LEAF_MAP,LEAF_MAP_SHA,JS_ROOT)
        cls.authority=wallet.Authority(NODE,modules)
        cls.crypto=wallet.Crypto(CRYPTO)
        cls.receivers=[wallet.Receiver(seed,PROFILE,cls.crypto,cls.authority) for seed in SEEDS]

    @classmethod
    def tearDownClass(cls):
        cls.authority.close()

    def restored(self,owner=0,profile=PROFILE):
        return wallet.Receiver(SEEDS[owner],profile,self.crypto,self.authority)

    def deliveries(self):
        a,b=self.receivers[:2]
        # The wallet receives no source/payer/change classification or map.
        return [wallet.deliver(self.crypto,b.invoice(41),100_000_000,bytes([1])*32,0),
            wallet.deliver(self.crypto,a.invoice(3),200_000_000,bytes([2])*32,1),
            wallet.deliver(self.crypto,a.invoice(99),300_000_000,bytes([3])*32,2)]

    def root(self,deliveries):
        return wallet.legacy.Tree(wallet.legacy.CM_DEPTH,[d.cm for d in deliveries],
            wallet.legacy.CM_NODE,wallet.legacy.CM_EMPTY).root

    def test_roles_and_profile_are_separated(self):
        a=self.receivers[0]
        material=a.keys(3)
        self.assertEqual(len({material.signing_seed,material.nf_secret,material.native_secret,material.delivery_secret}),4)
        self.assertNotEqual(a.invoice(3).owner,a.invoice(4).owner)
        other=wallet.Profile(PROFILE.domain,hashlib.sha256(b'other unfunded profile').digest())
        self.assertNotEqual(a.invoice(3),self.restored(profile=other).invoice(3))
        self.assertNotIn(material.signing_seed.hex(),repr(material))

    def test_new_invoice_and_receipt_versions(self):
        invoice=self.receivers[0].invoice(3)
        self.assertEqual(len(invoice.encode()),208)
        self.assertEqual(wallet.Invoice.parse(invoice.encode()),invoice)
        with self.assertRaises(wallet.Invalid):
            wallet.legacy.Invoice.parse(invoice.encode())
        receipt=wallet.Receipt.for_invoice(invoice,200_000_000,bytes([4])*32)
        self.assertEqual(len(receipt.encode()),216)
        self.assertEqual(wallet.Receipt.parse(receipt.encode()),receipt)
        with self.assertRaises(wallet.Invalid):
            wallet.legacy.Receipt.parse(receipt.encode())

    def test_original_seed_recovers_received_and_change_without_partition(self):
        deliveries=self.deliveries();root=self.root(deliveries)
        before=wallet.recover_openings(self.receivers[0],deliveries,root,[])
        after=wallet.recover_openings(self.restored(),deliveries,root,[before[0].nf])
        self.assertEqual([c.receipt.value_sompi for c in after],[200_000_000,300_000_000])
        self.assertEqual([c.nf for c in after],[c.nf for c in before])
        self.assertEqual([c.spent for c in after],[True,False])
        self.assertTrue(all(c.kind=='unclassified' for c in after))
        self.assertEqual([c.receipt.index for c in after],[3,99])
        for claim in after:
            self.assertEqual(wallet.legacy.Tree(wallet.legacy.CM_DEPTH,[d.cm for d in deliveries],
                wallet.legacy.CM_NODE,wallet.legacy.CM_EMPTY).path(claim.position),list(claim.path))

    def test_wrong_seed_cannot_report_empty_success(self):
        deliveries=self.deliveries()
        with self.assertRaisesRegex(wallet.Invalid,'seed-not-in-authenticated-history-cohort'):
            wallet.recover_openings(self.restored(2),deliveries,self.root(deliveries),[])

    def test_wrong_profile_cannot_restore(self):
        deliveries=self.deliveries();other=wallet.Profile(PROFILE.domain,hashlib.sha256(b'wrong profile').digest())
        with self.assertRaises(wallet.Invalid):
            wallet.recover_openings(self.restored(profile=other),deliveries,self.root(deliveries),[])

    def test_poisoned_descriptor_rejects_after_real_decryption(self):
        expected=self.receivers[0].invoice(3)
        poisoned=replace(expected,incoming=bytes([99])*32)
        delivery=wallet.deliver(self.crypto,poisoned,200_000_000,bytes([4])*32,0)
        with self.assertRaisesRegex(wallet.Invalid,'receipt-descriptor'):
            self.restored().open(delivery.ciphertext)

    def test_ciphertext_commitment_and_complete_history_are_bound(self):
        deliveries=self.deliveries()
        changed=list(deliveries);changed[1]=replace(changed[1],cm=bytes([77])*32)
        with self.assertRaisesRegex(wallet.Invalid,'recovered-CM'):
            wallet.recover_openings(self.restored(),changed,self.root(changed),[])
        with self.assertRaisesRegex(wallet.Invalid,'authenticated-CM-root'):
            wallet.recover_openings(self.restored(),deliveries,self.root(deliveries[::-1]),[])
        with self.assertRaisesRegex(wallet.Invalid,'complete-ordered-deliveries'):
            wallet.recover_openings(self.restored(),deliveries[1:],self.root(deliveries),[])

    def test_same_note_nf_stable_and_high_position_refused(self):
        delivery=self.deliveries()[1];receipt=self.restored().open(delivery.ciphertext)
        self.assertEqual(self.restored().nullifier(receipt,1),self.restored().nullifier(receipt,1))
        self.assertNotEqual(self.restored().nullifier(receipt,1),self.restored().nullifier(receipt,2))
        with self.assertRaises(wallet.Invalid):
            self.restored().nullifier(receipt,1<<wallet.legacy.CM_DEPTH)

    def test_actual_exit_signature_binds_payout_fee_effects_and_domain(self):
        receiver=self.receivers[0];receipt=receiver.open(self.deliveries()[1].ciphertext)
        nf=receiver.nullifier(receipt,1);effects=hashlib.sha256(b'public unfunded supplied native effects').digest()
        statement=wallet.exit_statement(PROFILE,bytes([5])*32,nf,effects,199_000_000,1_000_000)
        signature=self.authority.sign(receiver.keys(receipt.index).signing_seed,statement)
        self.assertTrue(self.authority.verify(statement,signature))
        for at in (8,40,72,104,136,144):
            changed=bytearray(statement);changed[at]^=1
            self.assertFalse(self.authority.verify(bytes(changed),signature))
        inputs=self.authority.signature_inputs(statement,signature)
        self.assertEqual(len(inputs['ownerKeyBytes']),64)
        self.assertEqual(len(inputs['digestLimbs']),2)
        self.assertNotIn(receiver.keys(receipt.index).signing_seed.hex(),str(inputs))
        wrong=dict(signature,owner_key_hex64=self.receivers[1].keys(3).owner_key.hex())
        self.assertFalse(self.authority.verify(statement,wrong))

    def test_integer_sompi_and_cross_legacy_boundaries(self):
        for amount in (True,-1,59_999_999,wallet.legacy.MAX_SOMPI+1):
            with self.assertRaises(wallet.Invalid):
                wallet.deliver(self.crypto,self.receivers[0].invoice(3),amount,bytes([4])*32,0)
        for payout,fee in ((True,1),(10_000_000,True),(10_000_000,0),
                (wallet.legacy.MAX_SOMPI,1)):
            with self.assertRaises(wallet.Invalid):
                wallet.exit_statement(PROFILE,bytes([5])*32,bytes([6])*32,bytes([7])*32,payout,fee)
        with self.assertRaises(wallet.Invalid):
            wallet.Profile(bytes.fromhex('b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'),PROFILE.profile_id)


if __name__=='__main__':
    unittest.main()
