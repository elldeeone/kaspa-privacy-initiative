"""Exact new native-exit framing and owner approval with real mature crypto."""
from dataclasses import replace
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

import exit_wire as wire
import wallet_profile as wallet
from test_wallet_profile import NODE,CRYPTO,JS_ROOT,LEAF_MAP,LEAF_MAP_SHA,SEEDS,PROFILE

spec=importlib.util.spec_from_file_location('_kpb_retained_tree',Path(__file__).resolve().parents[1]/'integration/trees.py')
trees=importlib.util.module_from_spec(spec);sys.modules[spec.name]=trees;spec.loader.exec_module(trees)


class ExitWireControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority=wallet.Authority(NODE,wallet.authenticate_js(LEAF_MAP,LEAF_MAP_SHA,JS_ROOT))
        cls.crypto=wallet.Crypto(CRYPTO)
        cls.receiver=wallet.Receiver(SEEDS[0],PROFILE,cls.crypto,cls.authority)

    @classmethod
    def tearDownClass(cls):
        cls.authority.close()

    def fixture(self,terminal=False):
        delivery=wallet.deliver(self.crypto,self.receiver.invoice(7),200_000_000,bytes([11])*32,0)
        cms=[delivery.cm] if terminal else [delivery.cm,hashlib.sha256(b'other public synthetic commitment').digest()]
        state=trees.PublicState(cms)
        context=wire.HeadContext(bytes([1])*32,bytes([2])*32,PROFILE.profile_id,PROFILE.domain,bytes([3])*32,
            bytes([4])*32+bytes(4),state.cm.root(),state.nf.root(),len(cms),1,200_000_000 if terminal else 500_000_000)
        receipt=self.receiver.open(delivery.ciphertext)
        claim=wallet.RecoveredOpening(0,receipt,self.receiver.nullifier(receipt,0),tuple(state.cm.path(0)[at:at+32] for at in range(0,512,32)),False)
        witness=state.insert(claim.nf)
        raw=wire.body(context,bytes([5])*32,state.nf.root(),len(state.entries),0 if terminal else 300_000_000,
            1_000_000,199_000_000,b'\0\0\x20'+receipt.native_pk+b'\xac',claim.nf,witness)
        tail=b'public synthetic policy bytes; no native execution claim'
        return context,claim,raw,wire.projection(raw,tail),tail

    def test_continuing_and_terminal_exact_native_shapes(self):
        for terminal in (False,True):
            context,claim,body,projection,tail=self.fixture(terminal)
            self.assertEqual(len(body),1604)
            self.assertEqual(len(projection),1604+(192 if terminal else 240))
            self.assertEqual(wire.HeadContext.parse(context.encode()),context)
            self.assertEqual(len(wire.statement(projection)),152)
            self.assertEqual(wire.require_current_head(projection,context,tail).nf,claim.nf)
            with self.assertRaises(ValueError):
                wire.old.parse_exit_projection(projection)

    def test_real_owner_authorization_has_no_service_dependency(self):
        context,claim,_,projection,tail=self.fixture()
        authorization=wallet.authorize_exit(self.receiver,claim,projection,context,tail,approved_fee_sompi=1_000_000)
        self.assertTrue(self.authority.verify(authorization.statement,authorization.authorization))
        self.assertEqual(authorization.private_request['statement_hex'],wire.statement(projection).hex())
        self.assertNotIn(self.receiver.keys(7).signing_seed.hex(),str(authorization.private_request))
        self.assertNotIn('journal',authorization.private_request)

    def test_payout_redirection_and_amount_change_require_new_owner_consent(self):
        context,claim,raw,projection,tail=self.fixture()
        original=wallet.authorize_exit(self.receiver,claim,projection,context,tail,approved_fee_sompi=1_000_000)
        changed=bytearray(raw);changed[379]^=1
        diverted=wire.projection(bytes(changed),tail)
        self.assertFalse(self.authority.verify(wire.statement(diverted),original.authorization))
        with self.assertRaisesRegex(wallet.Invalid,'exit-owner-selected-native-destination'):
            wallet.authorize_exit(self.receiver,claim,diverted,context,tail,approved_fee_sompi=1_000_000)
        changed=bytearray(raw)
        changed[360:368]=(1_000_001).to_bytes(8,'little');changed[368:376]=(198_999_999).to_bytes(8,'little')
        repriced=wire.projection(bytes(changed),tail)
        self.assertFalse(self.authority.verify(wire.statement(repriced),original.authorization))
        with self.assertRaisesRegex(wallet.Invalid,'owner-approved-fee'):
            wallet.authorize_exit(self.receiver,claim,repriced,context,tail,approved_fee_sompi=1_000_000)

    def test_stale_head_wrong_policy_and_spent_claim_refuse(self):
        context,claim,_,projection,tail=self.fixture()
        with self.assertRaisesRegex(ValueError,'exact-selected-head'):
            wire.require_current_head(projection,replace(context,point=bytes([99])*36),tail)
        with self.assertRaisesRegex(ValueError,'input-policy'):
            wire.require_current_head(projection,context,tail+b'changed')
        with self.assertRaisesRegex(wallet.Invalid,'claim-spent'):
            wallet.authorize_exit(self.receiver,replace(claim,spent=True),projection,context,tail,approved_fee_sompi=1_000_000)

    def test_actual_indexed_NF_mutation_and_native_amount_mismatch_reject(self):
        context,_,raw,projection,tail=self.fixture()
        changed=bytearray(raw);changed[444+72]^=1
        with self.assertRaises(ValueError):
            wire.projection(bytes(changed),tail)
        changed=bytearray(projection);changed[56]^=1
        with self.assertRaisesRegex(ValueError,'native-header'):
            wire.validate_public(bytes(changed))
        changed=bytearray(raw);changed[368:376]=(199_000_001).to_bytes(8,'little')
        with self.assertRaisesRegex(ValueError,'conservation'):
            wire.parse_body(bytes(changed))


if __name__=='__main__':
    unittest.main()
