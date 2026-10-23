"""Unfunded public controls. No real backup, PK, setup, proof or RPC is used."""
from copy import deepcopy
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

import change_action as action
import change_wallet as wallet
from owner_rules import Invalid, canonical, digest, input_metadata, parse
from owner_runtime import SelectedExecutable
from receiver_tools import Crypto, recipient

ROOT = Path(__file__).resolve().parents[2]
DOMAIN = hashlib.sha256(b'KPX3/PRIVATE-CHANGE/PUBLIC-DO-NOT-FUND').digest()
CRYPTO = ROOT.parent / 'private-wallet-controls-release-01/crypto'
CRYPTO_SHA = '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'


class Entropy:
    def __init__(self, slots=(0, 0), indices=(), label=b'public-action'):
        self.slots, self.indices = list(slots), list(indices)
        self.count, self.label = 0, label

    def __call__(self, width):
        self.count += 1
        if width == 1 and self.slots:
            return bytes([self.slots.pop(0)])
        if width == 8 and self.indices:
            return self.indices.pop(0).to_bytes(8, 'little')
        out = b''
        while len(out) < width:
            out += hashlib.sha256(self.label + self.count.to_bytes(8, 'little')
                                  + len(out).to_bytes(4, 'little')).digest()
        return out[:width]


class MockOwnerProver:
    """Data-pipe orchestration mock. No parameter blob or proving code runs."""
    sha256 = 'cd' * 32

    def __init__(self, ready, vk, *, mismatch=False):
        self.event, self.vk, self.mismatch = ready, vk, mismatch
        self.seen, self.returncode = None, None

    def popen(self, argv, *, extra_fds):
        self.reader = os.dup(extra_fds[0])
        self.output = Path(argv[-1])
        message = dict(self.event)
        if self.mismatch: message['domain_hex32'] = '99' * 32
        self.stdout = io.StringIO(json.dumps(message) + '\n')
        return self

    def communicate(self):
        if self.returncode is not None:
            os.close(self.reader)
            return '', ''
        raw = b''
        while True:
            chunk = os.read(self.reader, 65536)
            if not chunk: break
            raw += chunk
        os.close(self.reader)
        self.seen = json.loads(raw)
        self.output.mkdir(mode=0o700)
        (self.output/'proof128.bin').write_bytes(b'\x01' * 128)
        (self.output/'authorization528.bin').write_bytes(bytes.fromhex(self.seen['auth_hex528']))
        (self.output/'verification-key.bin').write_bytes(self.vk)
        self.returncode = 0
        return '', ''

    def poll(self): return self.returncode
    def terminate(self): self.returncode = -15


def decoder():
    path = ROOT / 'poc/independent-recovery/replay.py'
    raw = path.read_bytes()
    assert digest(raw) == 'f8be03c47008dd3b06ef601bd6da67ba42be47dec3f7c43a0d28dfe68e9b773d'
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location('_change_public_decoder', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(path.parent))


def mock_quote(request, mass=200_000):
    """Mock serialization only; NOT an official SDK/native quote or validation."""
    auth = bytes.fromhex(request['auth_hex528'])
    remaining = int.from_bytes(auth[476:484], 'little')
    payout = int.from_bytes(auth[484:492], 'little')
    fee = int.from_bytes(auth[196:204], 'little')
    redeem = bytes.fromhex(request['current_redeem_hex'])
    outputs = []
    if remaining:
        successor = redeem[:2] + auth[364:476] + redeem[114:]
        outputs.append({'value': remaining, 'scriptPublicKey': action.p2sh(successor)})
    if payout:
        outputs.append({'value': payout, 'scriptPublicKey': auth[492:528].hex()})
    body = {'version': 1, 'lockTime': '0', 'gas': '0', 'subnetworkId': bytes(20).hex(),
            'payload': auth.hex() + request['cipher_hex528'] + request['public_witness_hex3344'],
            'inputs': [{'previousOutpoint': request['previous_outpoint'],
                        'sequence': str((1 << 64) - 1), 'computeBudget': 1600,
                        'signatureScript': (b'\x41' + bytes(65) + b'\x4c\x80' + bytes(128)
                            + b'\x4d' + len(redeem).to_bytes(2, 'little') + redeem).hex()}],
            'outputs': outputs}
    body['id'] = digest(canonical(body))
    return {'schema': 'kpx3-public-native-result/v1', 'transaction': body,
            'transaction_id': body['id'], 'supplied_context': [request['supplied_utxo']],
            'fee_sompi': str(fee), 'mining_mass': str(mass),
            'required_fee_sompi': str(mass * int(request['fee_rate_sompi_per_mass'])),
            'quote_id': digest(canonical(body)), 'verified': False,
            'public_checks_reached_G16': True,
            'successor_state_hex112': auth[364:476].hex() if remaining else None}


class ChangeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executable = SelectedExecutable(CRYPTO, CRYPTO_SHA)
        cls.crypto, cls.v2, cls.decoder = Crypto(cls.executable), recipient(), decoder()

    @classmethod
    def tearDownClass(cls):
        cls.executable.close()

    def fixture(self, value=1_000_000_000, extras=(), duplicate=False):
        v2 = self.v2
        seed = hashlib.sha256(b'PUBLIC-DO-NOT-FUND/CHANGE-OWNER').digest()
        receiver = v2.Receiver(seed, DOMAIN, self.crypto)
        other = v2.Receiver(hashlib.sha256(b'PUBLIC-DO-NOT-FUND/RECIPIENT').digest(), DOMAIN, self.crypto)
        notes = [v2.Receipt.for_invoice(receiver.invoice(7), value, digest(b'rho0').encode()[:32])]
        for i, amount in enumerate(extras):
            owner = receiver if duplicate else other
            notes.append(v2.Receipt.for_invoice(owner.invoice(7), amount,
                         hashlib.sha256(b'extra' + bytes([i])).digest()))
        ciphers = [self.crypto.seal((receiver if i == 0 or duplicate else other).invoice(7).delivery_pk,
                                   note.encode()) for i, note in enumerate(notes)]
        snapshot = v2.Snapshot([v2.Delivery(i, n.commitment(), ciphers[i])
                               for i, n in enumerate(notes)], v2.nf_entries([]))
        expected = snapshot.pin(DOMAIN)
        initial = b'\x4c\x70' + action.state(snapshot, DOMAIN) + bytes(24303)
        descriptor = {'domain_hex32': DOMAIN.hex(), 'genesis_hash_hex': wallet.GENESIS,
                      'founding_outpoint': {'transactionId': '11' * 32, 'index': 0},
                      'initial_redeem_hex': initial.hex(), 'vk_hex328': bytes(328).hex()}
        head = self.head(descriptor, snapshot, sum(n.value_sompi for n in notes))
        recovered = v2.recover(receiver, expected, snapshot)
        return SimpleNamespace(seed=seed, receiver=receiver, other=other, notes=notes,
            ciphers=ciphers, snapshot=snapshot, expected=expected, descriptor=descriptor,
            head=head, recovered=recovered)

    def head(self, descriptor, snapshot, reserve, number=0x22):
        encoded = action.state(snapshot, DOMAIN)
        redeem = b'\x4c\x70' + encoded + bytes.fromhex(descriptor['initial_redeem_hex'])[114:]
        outpoint = {'transactionId': f'{number:02x}' * 32, 'index': 0}
        return {'outpoint': outpoint, 'reserve_sompi': reserve,
                'current_redeem_hex': redeem.hex(), 'state_hex112': encoded.hex(),
                'current_utxo': {'outpoint': outpoint, 'amount_sompi': reserve,
                    'script_public_key': action.p2sh(redeem), 'block_daa_score': '1',
                    'is_coinbase': False, 'covenant_id': None}}

    def template(self, f, operation='prepare-partial-cashout', amount=400_000_000,
                 slots=(0, 0), indices=(), invoice=None, label=b'public-action'):
        claim = action.select_claim(f.recovered)
        if operation == 'prepare-private-payment':
            invoice = invoice or f.other.invoice(9)
            destination = bytes(36)
        else:
            _, pk, _ = action.payout_key(f.seed, f.descriptor, claim, self.crypto)
            destination = b'\0\0\x20' + pk + b'\xac'
        return action.material(f.descriptor, f.head, f.receiver, claim, f.recovered.owned,
            f.snapshot, f.expected, destination, action.Intent(operation, amount, invoice),
            entropy=Entropy(slots, indices, label))

    def apply(self, f, candidate):
        d = self.decoder
        current = d.State(DOMAIN, f.notes[0].note_bytes(), f.ciphers[0])
        for note, cipher in zip(f.notes[1:], f.ciphers[1:]):
            current.append(note.commitment(), cipher, current.cm.path(len(current.deliveries)))
        # For later snapshots initialize the independent tree exactly from its
        # existing public ordered deliveries/NF entries, not a wallet shortcut.
        if len(f.snapshot.nullifiers) > 1:
            current = self.independent_from_snapshot(f.snapshot)
        self.assertEqual(current.encoded(), candidate.before)
        for i in range(2):
            current.insert(candidate.auth[204 + i * 32:236 + i * 32],
                           candidate.public_witness[i * 1160:(i + 1) * 1160])
        if candidate.remaining:
            for i in range(2):
                current.append(candidate.auth[268 + i * 32:300 + i * 32],
                    candidate.ciphertexts[i * 264:(i + 1) * 264],
                    candidate.public_witness[2320 + i * 512:2832 + i * 512])
        current.counts()
        self.assertEqual(current.encoded(), candidate.after)
        v2 = self.v2
        return v2.Snapshot([v2.Delivery(r['position'], bytes.fromhex(r['cm']), bytes.fromhex(r['ciphertext']))
                            for r in current.deliveries],
                           [v2.NFEntry(e['value'], e['next_value'], e['next_index']) for e in current.entries])

    def independent_from_snapshot(self, snapshot):
        d = self.decoder
        current = d.State.__new__(d.State)
        current.domain = DOMAIN
        current.cm = d.SparseTree(16, d.CM_NODE, d.CM_EMPTY)
        current.nf = d.SparseTree(17, d.NF_NODE, d.NF_EMPTY)
        current.deliveries = []
        for row in snapshot.deliveries:
            current.cm.set(row.position, row.cm)
            current.deliveries.append({'position': row.position, 'cm': row.cm.hex(),
                                       'ciphertext': row.ciphertext.hex()})
        current.entries = [{'value': e.value, 'next_value': e.next_value, 'next_index': e.next_index}
                           for e in snapshot.nullifiers]
        current.nf_positions = {e['value']: i for i, e in enumerate(current.entries)}
        for i, e in enumerate(current.entries): current.nf.set(i, d.nf_leaf(e))
        return current

    def restored(self, f, snapshot, reserve, number):
        receiver = self.v2.Receiver(f.seed, DOMAIN, self.crypto)
        expected = snapshot.pin(DOMAIN)
        return SimpleNamespace(**dict(vars(f), receiver=receiver, snapshot=snapshot,
            expected=expected, recovered=self.v2.recover(receiver, expected, snapshot),
            head=self.head(f.descriptor, snapshot, reserve, number)))

    def test_partial_exact_requested_payout_change_and_seed_only_restore(self):
        f = self.fixture()
        t = self.template(f, indices=((1 << 64) - 1,))
        c = t.actual(20_000_000)
        self.assertEqual((c.payout, c.remaining), (400_000_000, 580_000_000))
        self.assertEqual(sum(int.from_bytes(n[64:72], 'little') for n in c.notes), 580_000_000)
        snapshot = self.apply(f, c)
        restored = self.restored(f, snapshot, c.remaining, 0x33)
        self.assertEqual(restored.recovered.all_owned_unspent_sompi, 580_000_000)
        self.assertEqual(len(restored.recovered.owned), 2)
        self.assertEqual(action.select_claim(restored.recovered).receipt.index, (1 << 64) - 1)
        self.assertEqual(restored.recovered.owned[0].spent, True)

    def test_both_input_and_output_permutations_match_independent_updates(self):
        for real_slot in (0, 1):
            for output_slot in (0, 1):
                with self.subTest(real_slot=real_slot, output_slot=output_slot):
                    f = self.fixture()
                    t = self.template(f, slots=(real_slot, output_slot), indices=(42,))
                    c = t.actual(20_000_000)
                    self.assertTrue(c.inputs[real_slot]['real'])
                    dummy = c.inputs[1 - real_slot]
                    expected = __import__('hmac').digest(bytes.fromhex(dummy['dummy_key_hex32']),
                        b'KPX2DMY\0' + DOMAIN + bytes.fromhex(dummy['dummy_seed_hex32'])
                        + bytes([1 - real_slot]), 'sha256')
                    self.assertEqual(c.auth[204 + (1-real_slot)*32:236 + (1-real_slot)*32], expected)
                    self.assertEqual(int.from_bytes(c.notes[output_slot][64:72], 'little'), 580_000_000)
                    self.apply(f, c)

    def test_fee_rebuild_preserves_invoice_rho_slots_but_changes_cm_cipher_state(self):
        f = self.fixture();t = self.template(f, slots=(1, 1), indices=(123,))
        a, b = t.actual(19_000_000), t.actual(20_000_000)
        self.assertEqual(a.inputs, b.inputs)
        self.assertEqual(a.notes[1][72:104], b.notes[1][72:104])
        self.assertEqual(a.notes[1][:64] + a.notes[1][104:], b.notes[1][:64] + b.notes[1][104:])
        self.assertNotEqual(a.auth[268:332], b.auth[268:332])
        self.assertNotEqual(a.ciphertexts, b.ciphertexts)
        self.assertNotEqual(a.after, b.after)
        self.apply(f, a);self.apply(f, b)

    def test_change_index_resamples_recognized_history_including_spent(self):
        f = self.fixture();t = self.template(f, indices=(7, 0))
        c = t.actual(20_000_000)
        self.assertEqual(t.change_invoice.index, 0)
        new = self.restored(f, self.apply(f, c), c.remaining, 0x33)
        again = self.template(new, amount=10_000_000, indices=(7, 0, 1234))
        again.actual(20_000_000)
        self.assertEqual(again.change_invoice.index, 1234)

    def test_new_prepare_resamples_change_without_map_or_counter(self):
        f = self.fixture()
        one = self.template(f, indices=(10,), label=b'first')
        two = self.template(f, indices=(99,), label=b'second')
        a,b = one.actual(20_000_000), two.actual(20_000_000)
        self.assertNotEqual(one.change_invoice.index, two.change_invoice.index)
        self.assertNotEqual(a.auth[268:332], b.auth[268:332])

    def test_self_payment_child_resamples_current_recipient_tuple(self):
        f=self.fixture(200_000_000)
        t=self.template(f,'prepare-private-payment',60_000_000,
                        invoice=f.receiver.invoice(123),indices=(123,456))
        c=t.actual(20_000_000)
        self.assertEqual(t.change_invoice.index,456)
        restored=self.restored(f,self.apply(f,c),c.remaining,0x33)
        self.assertEqual(restored.recovered.all_owned_unspent_sompi,180_000_000)
        self.assertEqual(sorted(claim.receipt.index for claim in restored.recovered.owned),[7,123,456])
        self.assertTrue(all(a!=b for a,b in zip(action.receive_tuple(t.change_invoice),
                                               action.receive_tuple(f.recovered.owned[0].receipt))))

    def test_payment_permutations_deliver_correct_amounts_to_both_original_seeds(self):
        for input_slot in (0,1):
            for output_slot in (0,1):
                f=self.fixture(200_000_000)
                c=self.template(f,'prepare-private-payment',60_000_000,
                    slots=(input_slot,output_slot),indices=(42,)).actual(20_000_000)
                snapshot=self.apply(f,c)
                own=self.v2.recover(self.v2.Receiver(f.seed,DOMAIN,self.crypto),snapshot.pin(DOMAIN),snapshot)
                other=self.v2.recover(f.other,snapshot.pin(DOMAIN),snapshot)
                self.assertEqual((own.all_owned_unspent_sompi,other.all_owned_unspent_sompi),
                                 (120_000_000,60_000_000))
                self.assertEqual(int.from_bytes(c.notes[output_slot][64:72],'little'),60_000_000)

    def test_recovered_change_pays_recipient_then_both_branches_exit(self):
        f = self.fixture();partial = self.template(f, indices=(2**64-1,)).actual(20_000_000)
        a = self.restored(f, self.apply(f, partial), partial.remaining, 0x33)
        pay = self.template(a, 'prepare-private-payment', 300_000_000,
                            slots=(1,1), indices=(1001,), label=b'pay').actual(20_000_000)
        snapshot = self.apply(a, pay)
        b = self.restored(a, snapshot, pay.remaining, 0x44)
        self.assertEqual(b.recovered.all_owned_unspent_sompi, 260_000_000)
        recipient_restored = self.v2.Receiver(hashlib.sha256(b'PUBLIC-DO-NOT-FUND/RECIPIENT').digest(),DOMAIN,self.crypto)
        theirs = self.v2.recover(recipient_restored, snapshot.pin(DOMAIN), snapshot)
        self.assertEqual(theirs.all_owned_unspent_sompi, 300_000_000)
        full = self.template(b, 'prepare-full-cashout', 0, label=b'full').actual(20_000_000)
        after_full = self.apply(b, full)
        their_f = SimpleNamespace(**dict(vars(b), seed=hashlib.sha256(b'PUBLIC-DO-NOT-FUND/RECIPIENT').digest(),
            receiver=recipient_restored, snapshot=after_full, expected=after_full.pin(DOMAIN),
            recovered=self.v2.recover(recipient_restored, after_full.pin(DOMAIN), after_full),
            head=self.head(f.descriptor, after_full, full.remaining, 0x55)))
        terminal = self.template(their_f, 'prepare-full-cashout', 0, label=b'terminal').actual(20_000_000)
        final = self.apply(their_f, terminal)
        self.assertEqual((terminal.remaining, terminal.payout), (0, 280_000_000))
        self.assertEqual(terminal.ciphertexts, bytes(528))
        self.assertEqual(terminal.notes, (bytes(168), bytes(168)))
        self.assertEqual(terminal.public_witness[2320:], bytes(1024))
        self.assertEqual(len(final.deliveries), 7)
        self.assertEqual(len(final.nullifiers), 9)

    def test_sizing_is_not_a_private_witness_and_can_precede_subfloor_candidate(self):
        f=self.fixture(70_000_000)
        t=self.template(f,'prepare-private-payment',60_000_000)
        size=t.sizing(1)
        self.assertIs(type(size),action.PublicSizingCandidate)
        self.assertFalse(hasattr(size,'private_witness'))
        self.assertFalse(hasattr(size,'inputs'))
        self.assertFalse(hasattr(size,'notes'))
        with self.assertRaisesRegex(Invalid,'actual-private-material-required'):
            action.ActualCandidate.private_witness(size)
        self.apply(f,size)
        with self.assertRaisesRegex(Invalid,'private-change-note-floor'): t.actual(1)

    def test_zero_change_payment_uses_sizing_then_exact_actual_quote(self):
        f=self.fixture(80_000_000);t=self.template(f,'prepare-private-payment',60_000_000)
        phases=[]
        def quote(native,request,diagnostic=None):
            phases.append(diagnostic.name)
            return mock_quote(request)
        with tempfile.TemporaryDirectory() as tmp, patch.object(wallet,'native_call',side_effect=quote):
            c,q,m=wallet.quote_action(t,None,100,Path(tmp))
        self.assertEqual(c.fee,20_000_000)
        self.assertEqual(sorted(int.from_bytes(n[64:72],'little') for n in c.notes),[0,60_000_000])
        self.assertEqual([('sizing' if 'sizing' in p else 'actual') for p in phases],['sizing','sizing','actual'])
        self.assertEqual(c.public_request['auth_hex528'],c.auth.hex())
        self.assertEqual(q['quote_id'],digest(canonical(q['transaction'])))
        self.apply(f,c)

    def test_subfloor_negative_or_fee_shift_cannot_serialize_private_witness(self):
        for value in (79_999_999,80_000_001):
            f=self.fixture(value,extras=(60_000_000,));t=self.template(f,'prepare-private-payment',60_000_000)
            with tempfile.TemporaryDirectory() as tmp,patch.object(wallet,'native_call',side_effect=lambda n,r,diagnostic=None:mock_quote(r)),patch.object(action.ActualCandidate,'private_witness',side_effect=AssertionError('must stay empty')) as serialize:
                with self.assertRaises(Invalid): wallet.quote_action(t,None,100,Path(tmp))
                serialize.assert_not_called()
        f=self.fixture(80_000_000,extras=(60_000_000,));t=self.template(f,'prepare-private-payment',60_000_000)
        def shift(n,r,diagnostic=None): return mock_quote(r,210_000 if 'actual' in diagnostic.name else 200_000)
        with tempfile.TemporaryDirectory() as tmp,patch.object(wallet,'native_call',side_effect=shift),patch.object(action.ActualCandidate,'private_witness',side_effect=AssertionError('must stay empty')) as serialize:
            with self.assertRaisesRegex(Invalid,'requested-value-exceeds'):wallet.quote_action(t,None,100,Path(tmp))
            serialize.assert_not_called()

    def test_actual_fee_shift_rebuilds_before_selection(self):
        f=self.fixture(200_000_000);t=self.template(f,'prepare-private-payment',60_000_000,indices=(999,))
        actuals=[]
        def shift(n,r,diagnostic=None):
            if 'actual' in diagnostic.name:actuals.append(bytes.fromhex(r['auth_hex528']))
            return mock_quote(r,210_000 if 'actual' in diagnostic.name else 200_000)
        with tempfile.TemporaryDirectory() as tmp,patch.object(wallet,'native_call',side_effect=shift):c,q,m=wallet.quote_action(t,None,100,Path(tmp))
        self.assertEqual(c.fee,21_000_000)
        self.assertEqual(len(actuals),2)
        self.assertNotEqual(actuals[0][268:332],actuals[1][268:332])
        self.assertEqual(c.auth,actuals[-1])
        self.assertEqual(c.private_witness()['auth_hex528'],actuals[-1].hex())

    def test_exact_private_and_payout_floors(self):
        f=self.fixture(90_000_000,extras=(60_000_000,));t=self.template(f,amount=10_000_000)
        c=t.actual(20_000_000)
        self.assertEqual(sum(int.from_bytes(n[64:72],'little') for n in c.notes),60_000_000)
        with self.assertRaisesRegex(Invalid,'private-change-note-floor'): t.actual(20_000_001)
        for amount in (0,9_999_999):
            with self.assertRaisesRegex(Invalid,'requested-payout-floor'):self.template(f,amount=amount)
        full=self.template(self.fixture(60_000_000),'prepare-full-cashout',0)
        self.assertEqual(full.actual(50_000_000).payout,10_000_000)
        for fee in (50_000_001,60_000_000):
            with self.assertRaisesRegex(Invalid,'private-fee-payout-floor'):full.actual(fee)

    def test_max_amount_ranges_and_no_float_or_boolean_amounts(self):
        maximum=2_870_000_000_000_000_000
        f=self.fixture(maximum);c=self.template(f,amount=10_000_000).actual(1)
        self.assertEqual(c.remaining,maximum-10_000_001)
        for value in (True,False,1.0,'10000000',-1,maximum+1):
            with self.assertRaises(Invalid): action.Intent('prepare-partial-cashout',value).validate(DOMAIN)

    def test_duplicate_owned_claims_remain_actionable_and_largest_selected(self):
        f=self.fixture(120_000_000,extras=(130_000_000,),duplicate=True)
        self.assertEqual(f.recovered.all_owned_unspent_sompi,250_000_000)
        self.assertEqual(action.select_claim(f.recovered).receipt.value_sompi,130_000_000)
        t=self.template(f,amount=10_000_000);c=t.actual(20_000_000)
        self.apply(f,c)
        self.assertTrue(all(claim.owner_action_available for claim in f.recovered.owned))

    def test_stale_nf_order_replay_and_membership_path_rejected(self):
        f=self.fixture();c=self.template(f,slots=(1,0)).actual(20_000_000)
        current=self.independent_from_snapshot(f.snapshot)
        with self.assertRaises(self.decoder.Invalid):current.insert(c.auth[236:268],c.public_witness[1160:2320])
        current.insert(c.auth[204:236],c.public_witness[:1160])
        with self.assertRaises(self.decoder.Invalid):current.insert(c.auth[204:236],c.public_witness[:1160])
        stale=deepcopy(f);stale.head['state_hex112']='00'*112
        with self.assertRaisesRegex(Invalid,'private-current-state'):self.template(stale)
        altered=deepcopy(f);altered.snapshot.deliveries[0]=self.v2.Delivery(0,bytes(32),f.ciphers[0])
        with self.assertRaises(self.v2.Invalid):self.template(altered)

    def test_cross_domain_or_wrong_current_context_rejected(self):
        f=self.fixture();wrong=deepcopy(f);wrong.descriptor['domain_hex32']='12'*32
        with self.assertRaises(Invalid):self.template(wrong)
        for field,value in [('amount_sompi',999),('script_public_key','00'),('outpoint',{'transactionId':'33'*32,'index':0})]:
            wrong=deepcopy(f);wrong.head['current_utxo'][field]=value
            with self.assertRaisesRegex(Invalid,'private-current-context'):self.template(wrong)

    def test_recipient_format_domain_nonzero_and_input_reuse_reject(self):
        f=self.fixture();raw=f.other.invoice(9).encode()
        for altered in (raw[:-1],b'BADMAGIC'+raw[8:],raw[:8]+bytes(32)+raw[40:],raw[:48]+bytes(32)+raw[80:]):
            with self.assertRaises(Invalid):action.parse_invoice(altered,DOMAIN)
        with self.assertRaisesRegex(Invalid,'recipient-reuses-input'):
            self.template(f,'prepare-private-payment',60_000_000,invoice=f.receiver.invoice(7))

    def test_self_change_roundtrip_failure_blocks_candidate(self):
        f=self.fixture();t=self.template(f)
        with patch.object(f.receiver,'open',side_effect=self.v2.Invalid('unseal')):
            with self.assertRaises(self.v2.Invalid):t.actual(20_000_000)

    def test_body_checker_rejects_wrong_payout_and_p0_extra_output(self):
        f=self.fixture();c=self.template(f).actual(20_000_000)
        request=dict(c.public_request,fee_rate_sompi_per_mass='100');q=mock_quote(request)
        wallet.check_body(q,f.descriptor,f.head,c,c.auth,bytes(128),c.fee)
        q['transaction']['outputs'][-1]['value']+=1
        with self.assertRaisesRegex(Invalid,'native-owned-payout'):wallet.check_body(q,f.descriptor,f.head,c,c.auth,bytes(128),c.fee)
        p=self.template(f,'prepare-private-payment',300_000_000).actual(20_000_000)
        q=mock_quote(dict(p.public_request,fee_rate_sompi_per_mass='100'))
        q['transaction']['outputs'].append({'value':1,'scriptPublicKey':'00'})
        with self.assertRaisesRegex(Invalid,'native-output-count'):wallet.check_body(q,f.descriptor,f.head,p,p.auth,bytes(128),p.fee)

    def test_original_body_under_new_head_and_cross_founding_payout_reject_or_separate(self):
        f=self.fixture();c=self.template(f).actual(20_000_000)
        q=mock_quote(dict(c.public_request,fee_rate_sompi_per_mass='100'))
        changed=deepcopy(f.head);changed['outpoint']['transactionId']='99'*32
        with self.assertRaisesRegex(Invalid,'native-current-input'):
            wallet.check_body(q,f.descriptor,changed,c,c.auth,bytes(128),c.fee)
        claim=action.select_claim(f.recovered)
        one=action.payout_key(f.seed,f.descriptor,claim,self.crypto)[1]
        descriptor=deepcopy(f.descriptor);descriptor['founding_outpoint']['index']=1
        two=action.payout_key(f.seed,descriptor,claim,self.crypto)[1]
        self.assertNotEqual(one,two)

    def orchestration(self, value, *, mismatch=False):
        f=self.fixture(value,extras=(60_000_000,))
        selected={'PARAMETER_MANIFEST_SHA256':'aa'*32,'DOMAIN_HEX32':DOMAIN.hex(),
                  'VK_SHA256':digest(bytes(328)),'COMPILED_BUILD_IDENTITY_SHA256':'bb'*32}
        event={'event':'parameters-ready','parameter_manifest_sha256':selected['PARAMETER_MANIFEST_SHA256'],
               'domain_hex32':DOMAIN.hex(),'vk_sha256':selected['VK_SHA256'],
               'compiled_build_identity_sha256':selected['COMPILED_BUILD_IDENTITY_SHA256']}
        prover=MockOwnerProver(event,bytes(328),mismatch=mismatch)
        intent=action.Intent('prepare-private-payment',60_000_000,f.other.invoice(9))
        public={'head':f.head,'payouts':[]}
        request={'backup_path':'/UNREAD-PUBLIC-FIXTURE-ALIAS','public_pk_path':'/NO-PK-OPENED',
                 'fee_rate_sompi_per_mass':100}
        native=SimpleNamespace(sha256='dc'*32)
        def quote(n,r,diagnostic=None):
            self.assertIsNone(prover.seen)
            q=mock_quote(r)
            if r['mode']=='verify':
                frame=bytearray.fromhex(q['transaction']['inputs'][0]['signatureScript'])
                frame[68:196]=bytes.fromhex(r['proof_hex128'])
                q['transaction']['inputs'][0]['signatureScript']=frame.hex()
                q['verified']=True
                q['native_validation']={'Full':{'accepted':True,'fee_sompi':int(q['fee_sompi'])},
                                        'all_input_engines_accepted':True}
                q['metrics']={'mock_only':True}
            return q
        return f,selected,prover,intent,public,request,native,quote

    def test_main_zero_change_only_writes_final_actual_witness_after_quotes(self):
        f,selected,prover,intent,public,request,native,quote=self.orchestration(80_000_000)
        def native_call(n,r,diagnostic=None):
            if r['mode']=='verify':
                seen=prover.seen;self.assertIsNotNone(seen)
                # The mock quote helper has no secret-note request fields.
                q=mock_quote(r)
                frame=bytearray.fromhex(q['transaction']['inputs'][0]['signatureScript'])
                frame[68:196]=bytes.fromhex(r['proof_hex128'])
                q['transaction']['inputs'][0]['signatureScript']=frame.hex()
                q.update(verified=True,native_validation={'Full':{'accepted':True,'fee_sompi':20_000_000},'all_input_engines_accepted':True},metrics={'mock_only':True})
                return q
            return quote(n,r,diagnostic)
        with tempfile.TemporaryDirectory() as tmp,patch.multiple(wallet.selection,**selected),patch.object(wallet,'backup',return_value=f.seed) as backup,patch.object(wallet,'snapshot_from_public',return_value=(f.snapshot,f.expected)),patch.object(wallet,'native_call',side_effect=native_call):
            result=wallet.prove_and_build(request,f.descriptor,public,{},Path(tmp),self.crypto,native,prover,intent)
            self.assertTrue(result['passed'])
            self.assertEqual(result['payout_sompi'],0)
            self.assertEqual(sorted(int.from_bytes(bytes.fromhex(n['note_hex168'])[64:72],'little') for n in prover.seen['outputs']),[0,60_000_000])
            final_quote=json.loads((Path(tmp)/'quote.json').read_text())
            self.assertTrue(final_quote['selected_actual_quote_only'])
            self.assertNotIn('attempts',final_quote)
            backup.assert_called_once()

    def test_main_invalid_change_or_ready_mismatch_leaves_witness_pipe_empty(self):
        for mismatch,value in ((False,80_000_001),(True,80_000_000)):
            f,selected,prover,intent,public,request,native,quote=self.orchestration(value,mismatch=mismatch)
            original_write=os.write
            witness_writes=[]
            def guard(fd,raw):
                if hasattr(prover,'reader'):
                    a,b=os.fstat(fd),os.fstat(prover.reader)
                    if (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino):
                        witness_writes.append(len(raw))
                        raise AssertionError('witness must remain empty')
                return original_write(fd,raw)
            with tempfile.TemporaryDirectory() as tmp,patch.multiple(wallet.selection,**selected),patch.object(wallet,'backup',return_value=f.seed) as backup,patch.object(wallet,'snapshot_from_public',return_value=(f.snapshot,f.expected)),patch.object(wallet,'native_call',side_effect=quote),patch.object(wallet.os,'write',side_effect=guard):
                with self.assertRaises(Invalid):wallet.prove_and_build(request,f.descriptor,public,{},Path(tmp),self.crypto,native,prover,intent)
                self.assertEqual(witness_writes,[])
                self.assertIsNone(prover.seen)
                self.assertFalse((Path(tmp)/'proof').exists())
                if mismatch:backup.assert_not_called()


class BoundaryControls(unittest.TestCase):
    def request(self,operation='prepare-partial-cashout'):
        r={'schema':'kpx3-private-change-owner-request/v1','op':operation,
           'backup_path':'/backup','descriptor_path':'/descriptor','expected_descriptor_sha256':'00'*32,
           'public_manifest_path':'/manifest','fetch_path':'/fetch','crypto_path':'/crypto','output_dir':'/private/output'}
        if operation!='recover':r.update(public_pk_path='/pk',local_prover_path='/prover',native_helper_path='/native',fee_rate_sompi_per_mass=100)
        if operation=='prepare-partial-cashout':r['payout_sompi']=10_000_000
        if operation=='prepare-private-payment':r.update(payment_sompi=60_000_000,recipient_invoice_path='/invoice')
        return r

    def test_strict_request_amount_and_field_sets(self):
        for op in ('recover','prepare-partial-cashout','prepare-private-payment','prepare-full-cashout'):
            self.assertEqual(wallet.validate_request(self.request(op)),op!='recover')
        for bad in (True,False,1.0,'10000000',-1):
            r=self.request();r['payout_sompi']=bad
            with self.assertRaises(Invalid):wallet.validate_request(r)
        for field in ('position','private_witness','operator_archive','change_index','recipient_seed'):
            r=self.request();r[field]='forbidden'
            with self.assertRaisesRegex(Invalid,'private-owner-request-fields'):wallet.validate_request(r)
        with self.assertRaises(Invalid):parse('{"op":"recover","op":"prepare-full-cashout"}')
        for value in (None,True,123,'','bad\0path'):
            r=self.request();r['descriptor_path']=value
            with self.assertRaisesRegex(Invalid,'private-owner-request-paths'):wallet.validate_request(r)

    def test_public_exports_reject_private_values_paths_maps_and_slots(self):
        result={key:False for key in wallet.PUBLIC_PREPARED_FIELDS}
        result['status']='PROVED_NATIVE_FULL_VALID_UNBROADCAST'
        result['schema']='kpx3-private-change-owner-result/v1'
        wallet.public_export(result)
        for field in ('payment_sompi','change_sompi','recipient_invoice_path','input_cm','position','receive_index','input_slot','output_slot','private_witness_sha256','output_dir'):
            with self.assertRaisesRegex(Invalid,'public-result-allowlist'):wallet.public_export(dict(result,**{field:1}))

    def test_all_caller_public_paths_cannot_alias_backup_before_read(self):
        fields=('descriptor_path','public_manifest_path','fetch_path','recipient_invoice_path','public_pk_path','crypto_path','local_prover_path','native_helper_path')
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);backup=d/'backup';backup.write_bytes(b'PUBLIC CANARY ONLY');backup.chmod(0o600)
            r=self.request('prepare-private-payment');r['backup_path']=str(backup)
            for i,name in enumerate(fields):
                p=d/str(i);p.write_bytes(bytes(208));r[name]=str(p)
            for name in fields:
                hard=d/'hard';os.link(backup,hard)
                changed=dict(r);changed[name]=str(hard)
                with patch.object(Path,'read_bytes',side_effect=AssertionError('no public or seed reads')):
                    with self.assertRaisesRegex(Invalid,'backup-public-path-alias'):input_metadata(changed)
                hard.unlink()
            link=d/'link';link.symlink_to(backup)
            changed=dict(r,descriptor_path=str(link))
            with self.assertRaisesRegex(Invalid,'symlink-path'):input_metadata(changed)

    def test_unselected_release_stops_before_any_request_file_read(self):
        with patch.object(Path,'read_bytes',side_effect=AssertionError('must not read')),patch.object(wallet,'input_metadata') as metadata:
            with self.assertRaisesRegex(Invalid,'trusted-software-selection-required'):wallet.execute(self.request())
            metadata.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)
