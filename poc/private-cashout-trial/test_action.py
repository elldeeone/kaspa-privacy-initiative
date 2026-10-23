"""PUBLIC_SYNTHETIC_DO_NOT_FUND semantic controls; no native VM or prover."""
import hashlib
import hmac
import unittest

import action as a
import prepare as p
import trial


class FourBodyRelation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, cls.crypto, _ = trial.runtime(trial.DEFAULT_BRIDGE, trial.DEFAULT_SDK)
        cls.domain = a.h(b'PUBLIC_SYNTHETIC_DO_NOT_FUND/private-cashout-trial-tests')
        cls.seeds = {name: a.h(b'PUBLIC_TEST_SEED', name.encode()) for name in ('alice','bob','charlie')}
        cls.wallets = {name: cls.module.Receiver(seed, cls.domain, cls.crypto) for name,seed in cls.seeds.items()}
        cls.founding = a.h(b'PUBLIC_TEST_FOUNDING_OUTPOINT') + a.u32(0)

    @classmethod
    def tearDownClass(cls):
        cls.crypto.close()

    def dummy(self, label):
        return [(a.h(label,b'key',bytes([i])),a.h(label,b'seed',bytes([i]))) for i in range(2)]

    def payout(self, owner, snapshot, position):
        note=self.wallets[owner].open(snapshot.deliveries[position].ciphertext)
        return a.payout_secret(self.seeds[owner],self.domain,self.founding,
            snapshot.deliveries[position].cm,position,self.crypto,[note.native_pk])

    def prefix(self):
        f=18_958_700
        _,alice=a.receipt(self.module,self.wallets['alice'],120_000_000+f,0,a.h(b'PUBLIC_RHO',b'a'))
        before=self.module.Snapshot([alice],[self.module.NFEntry(a.ZERO,a.ZERO,0)])
        outputs=[a.receipt(self.module,self.wallets[name],60_000_000,pos,a.h(b'PUBLIC_RHO',name.encode()))
                 for name,pos in [('bob',1),('charlie',2)]]
        return a.action(self.module,self.domain,before,[(0,self.wallets['alice']),None],outputs,
            self.founding,120_000_000+f,f,0,bytes(36),self.dummy(b'P0'))

    def test_full_three_action_private_lifecycle_and_terminal_zeros(self):
        after,spend,_=self.prefix()
        self.assertEqual(spend['schema'],'kpx3-private-action-witness/v1')
        self.assertEqual((len(after.deliveries),len(after.nullifiers)),(3,3))
        _,dest=self.payout('bob',after,1)
        pads=[a.dummy_output(self.module,self.domain,3+i,a.h(b'PAD_RHO',bytes([i])),
              a.sealed_dummy(self.crypto,a.h(b'PAD_DELIVERY',bytes([i])),bytes([i+1])*216)) for i in range(2)]
        middle,_,_=a.action(self.module,self.domain,after,[(1,self.wallets['bob']),None],pads,
            a.h(b'P0ID')+a.u32(0),120_000_000,18_999_900,41_000_100,dest,self.dummy(b'BOB'))
        self.assertEqual((len(middle.deliveries),len(middle.nullifiers)),(5,5))
        _,dest=self.payout('charlie',middle,2)
        terminal,fixture,public=a.action(self.module,self.domain,middle,[(2,self.wallets['charlie']),None],[],
            a.h(b'BOBID')+a.u32(0),60_000_000,18_957_600,41_042_400,dest,self.dummy(b'CHARLIE'))
        auth=bytes.fromhex(public['auth_hex528'])
        self.assertEqual((len(terminal.deliveries),len(terminal.nullifiers)),(5,7))
        self.assertEqual(auth[268:332],bytes(64))
        self.assertEqual(auth[332:364],hashlib.sha256(bytes(528)).digest())
        self.assertEqual(auth[476:484],bytes(8))
        self.assertEqual(bytes.fromhex(public['cipher_hex528']),bytes(528))
        self.assertEqual(bytes.fromhex(public['public_witness_hex3344'])[-1024:],bytes(1024))
        self.assertEqual([r['note_hex168'] for r in fixture['outputs']],[bytes(168).hex()]*2)
        for wallet in self.wallets.values():
            self.assertEqual(self.module.recover(wallet,terminal.pin(self.domain),terminal).all_owned_unspent_sompi,0)

    def test_payout_derivation_exact_hmac_and_recoverable(self):
        snapshot,_,_=self.prefix(); key,spk=self.payout('bob',snapshot,1)
        expected=hmac.digest(self.seeds['bob'],b'KPX3PAY\0'+self.domain+self.founding
            +snapshot.deliveries[1].cm+a.u32(1)+a.u32(0),'sha256')
        self.assertEqual(key,expected)
        self.assertEqual(spk,b'\0\0\x20'+self.crypto.xonly(expected)+b'\xac')
        self.assertEqual((key,spk),self.payout('bob',snapshot,1))

    def test_private_payout_cannot_reuse_consumed_emergency_key(self):
        snapshot,_,_=self.prefix(); note=self.wallets['bob'].open(snapshot.deliveries[1].ciphertext)
        with self.assertRaisesRegex(ValueError,'emergency-key-reuse'):
            a.action(self.module,self.domain,snapshot,[(1,self.wallets['bob']),None],[],
                self.founding,60_000_000,18_957_600,41_042_400,
                b'\0\0\x20'+note.native_pk+b'\xac',self.dummy(b'REUSE'))

    def test_occupied_original_nf_cannot_be_inserted_again(self):
        snapshot,_,_=self.prefix(); note=self.wallets['bob'].open(snapshot.deliveries[1].ciphertext)
        nf=self.wallets['bob'].nullifier(note,1)
        spent,_=a.insert(self.module,snapshot,nf)
        with self.assertRaisesRegex(ValueError,'unseen-nonzero-NF'):
            a.insert(self.module,spent,nf)

    def test_both_private_recipient_slot_permutations_recognize_correctly(self):
        ctx=object.__new__(p.Context)
        ctx.module,ctx.crypto,ctx.domain=self.module,self.crypto,self.domain
        ctx.seeds,ctx.wallets=self.seeds,self.wallets
        for order in (['bob','charlie'],['charlie','bob']):
            with self.subTest(public_synthetic_permutation=tuple(order)):
                recipe={'recipient_order':order,
                    'rho':[a.h(b'PUBLIC_PERM_RHO',bytes([i])).hex() for i in range(5)],
                    'dummy_inputs':[[a.h(b'PUBLIC_PERM_KEY',bytes([i])).hex(),
                        a.h(b'PUBLIC_PERM_SEED',bytes([i])).hex()] for i in range(6)]}
                _,_,_,after,fixture,_=ctx.payment(20_000_000,recipe,self.founding)
                self.assertEqual(ctx.own_claim('bob',after).position,order.index('bob')+1)
                self.assertEqual(ctx.own_claim('charlie',after).position,order.index('charlie')+1)
                for position,owner in enumerate(order,1):
                    claim=ctx.own_claim(owner,after)
                    self.assertEqual(claim.receipt.commitment(),after.deliveries[position].cm)
                    self.assertEqual(fixture['outputs'][position-1]['note_hex168'],claim.receipt.note_bytes().hex())
                # Sender proof contains Alice's ownership fields only.
                self.assertEqual(fixture['inputs'][0]['s_hex32'],self.wallets['alice'].keys(0).owner_secret.hex())


if __name__=='__main__':unittest.main()
