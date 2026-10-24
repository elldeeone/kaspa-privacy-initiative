"""Public-only controls: no actor backups, PK, prover, native Full or broadcasts."""
import copy
from dataclasses import replace
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import no_append as a
import owner
import paths
import recovery
import run_owner
import selected as s
from reuse import core, public

C = core(); P = C.primitives
POINT = {'transactionId': '31' * 32, 'index': 0}
SEED = hashlib.sha256(b'UNSAFE_PUBLIC_WALLET_CONTROL_DO_NOT_FUND').digest()


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2 = C.receiver.module()
        raw = C.receiver.CRYPTO.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == C.receiver.CRYPTO_SHA
        cls.crypto = cls.v2.Crypto(C.receiver.CRYPTO)
        cls.wallet = cls.v2.Receiver(SEED, s.DOMAIN, cls.crypto)
        cls.notes = tuple(cls.v2.Receipt.for_invoice(cls.wallet.invoice(i), 120_000_000,
            hashlib.sha256(b'public-rho' + bytes([i])).digest()) for i in (3, 9))
        cls.snapshot = P.Snapshot(3, tuple(P.Delivery(i, note.commitment(),
            cls.crypto.seal(cls.wallet.invoice(note.index).delivery_pk, note.encode()))
            for i, note in enumerate(cls.notes)) +
            (P.Delivery(2, P.h(b'opaque-foreign-CM'), bytes(264)),), (P.NFEntry(P.ZERO, P.ZERO, 0),)).verify()
        cls.rec = C.receiver.recover(cls.wallet, cls.snapshot, cls.snapshot.state(s.DOMAIN))

    def material(self, slot=0, claims=None, snapshot=None, recovered=None, reserve=300_000_000):
        return a.prepare(SEED, self.wallet, snapshot or self.snapshot, recovered or self.rec,
            self.rec.owned if claims is None else claims, POINT, POINT, reserve,
            entropy=lambda width: bytes([slot]) * width)

    def test_two_real_permutations_rebuild_ordered_nf_paths(self):
        materials = [self.material(i) for i in (0, 1)]
        self.assertEqual(materials[0].destination, materials[1].destination)
        self.assertEqual(materials[0].nfs, tuple(reversed(materials[1].nfs)))
        for m in materials:
            after, w0 = P.insert_nf(self.snapshot, m.nfs[0]);after, w1 = P.insert_nf(after, m.nfs[1])
            self.assertEqual(m.paths, w0 + w1);self.assertEqual(after, m.after)
            self.assertEqual(len(m.after.nullifiers), 3)
            self.assertEqual(m.after.roots()[0].root, self.snapshot.roots()[0].root)
            self.assertTrue(all(row['real'] and row['dummy_key_hex32'] == P.ZERO.hex()
                and row['dummy_seed_hex32'] == P.ZERO.hex() for row in m.inputs))

    def test_noappend_conservation_and_floors(self):
        m = self.material();candidate = m.candidate(20_000_000)
        self.assertEqual((candidate.payout, candidate.reserve_after), (220_000_000, 60_000_000))
        self.assertEqual(candidate.payload()[528:], m.paths)
        self.assertEqual(len(candidate.payload()), 2848)
        self.assertEqual(candidate.notes, (bytes(168), bytes(168)))
        self.assertEqual(candidate.ciphertexts, bytes(528))
        self.assertEqual(candidate.auth[268:332], bytes(64))
        self.assertEqual(candidate.auth[332:364], P.h(bytes(528)))
        self.assertEqual(self.material(reserve=240_000_000).candidate(230_000_000).payout, 10_000_000)
        for bad in (0, -1, True, 1.0, '1', 230_000_001, P.MAX + 1):
            with self.subTest(bad=bad), self.assertRaises(ValueError):m.candidate(bad)
        with self.assertRaises(ValueError):self.material(reserve=299_999_999).candidate(1)
        with self.assertRaises(ValueError):self.material(reserve=239_999_999)

    def test_both_real_membership_and_original_nf(self):
        m = self.material()
        for row, nf in zip(m.inputs, m.nfs):
            note = bytes.fromhex(row['note_hex168']);cm = P.note_cm(s.DOMAIN, note)
            self.assertEqual(P.fold_path(cm, row['position'], [bytes.fromhex(x) for x in row['cm_path_hex']],
                b'KPX1CMN\0'), self.snapshot.roots()[0].root)
            self.assertEqual(nf, P.real_nf(s.DOMAIN, bytes.fromhex(row['k_hex32']), cm, row['position']))

    def test_min_anchor_and_one_real_existing_recipe(self):
        claim = self.rec.owned[0]
        expected = self.crypto.xonly(hmac.digest(SEED, b'KPX3PAY\0' + s.DOMAIN +
            C.actions.point_bytes(POINT) + claim.receipt.commitment() + P.u32(claim.position) + P.u32(0), 'sha256'))
        self.assertEqual(a.default_key(SEED, self.wallet, POINT, [claim]), expected)
        self.assertEqual(a.default_key(SEED, self.wallet, POINT, self.rec.owned),
                         a.default_key(SEED, self.wallet, POINT, list(reversed(self.rec.owned))))
        for slot in (0, 1):
            m = self.material(slot, [claim]);dummy = next(i for i, row in enumerate(m.inputs) if not row['real'])
            row = m.inputs[dummy]
            self.assertEqual(m.nfs[dummy], P.dummy_nf(s.DOMAIN, bytes.fromhex(row['dummy_key_hex32']),
                bytes.fromhex(row['dummy_seed_hex32']), dummy))

    def test_payout_retry_rejects_either_input_key_and_scalar(self):
        answers = [self.v2.Invalid('crypto-scalar'), self.rec.owned[0].receipt.native_pk,
                   self.rec.owned[1].receipt.native_pk, b'\x53' * 32]
        with patch.object(self.crypto, 'xonly', side_effect=answers) as call:
            self.assertEqual(a.default_key(SEED, self.wallet, POINT, self.rec.owned), b'\x53' * 32)
            self.assertEqual(call.call_count, 4)
        with patch.object(self.crypto, 'xonly', side_effect=self.v2.Invalid('crypto-adapter')):
            with self.assertRaisesRegex(ValueError, 'adapter'):a.default_key(SEED, self.wallet, POINT, self.rec.owned)

    def test_duplicates_actionable_foreign_spent_and_replay_reject(self):
        claim = self.rec.owned[0]
        duplicate = copy.deepcopy(claim);duplicate.duplicate_invoice = True;duplicate.privacy_contaminated = True
        self.assertEqual(a.available(SimpleNamespace(owned=[duplicate])), [duplicate])
        self.assertEqual(duplicate.normal_credit_sompi, 0)
        with self.assertRaises(ValueError):self.material(claims=[claim, claim])
        foreign = copy.deepcopy(claim);foreign.position = 2
        with self.assertRaises(ValueError):self.material(claims=[foreign])
        spent = copy.deepcopy(claim);spent.spent = True
        with self.assertRaises(ValueError):self.material(claims=[spent])
        after, _ = P.insert_nf(self.snapshot, claim.nf)
        with self.assertRaises(ValueError):self.material(claims=[claim], snapshot=after)
        stale = replace(self.snapshot, deliveries=(replace(self.snapshot.deliveries[0], cm=P.ZERO),
            *self.snapshot.deliveries[1:]))
        with self.assertRaises(ValueError):self.material(snapshot=stale)

    def test_cross_state_domain_outpoint_and_nf_order_reject(self):
        m = self.material();candidate = m.candidate(20_000_000)
        after, f = recovery.advance(self.snapshot, 300_000_000, POINT, candidate.payload())
        self.assertEqual(after, m.after);self.assertEqual(f['remaining'], 60_000_000)
        for snap, point, reserve in ((m.after, POINT, 300_000_000), (self.snapshot,
            {'transactionId':'42'*32,'index':0},300_000_000), (self.snapshot,POINT,300_000_001)):
            with self.assertRaises(ValueError):recovery.advance(snap, reserve, point, candidate.payload())
        broken = candidate.auth + m.paths[1160:] + m.paths[:1160]
        with self.assertRaises(ValueError):recovery.advance(self.snapshot,300_000_000,POINT,broken)
        with patch.object(self.wallet, 'domain', b'\x11'*32):
            with self.assertRaises(ValueError):self.material()
        with self.assertRaises(ValueError):a.prepare(SEED,self.wallet,self.snapshot,self.rec,
            self.rec.owned,{'transactionId':'31'*32,'index':True},POINT,300_000_000)

    def test_all_spent_receipts_recover_two_real_payout(self):
        m = self.material();candidate = m.candidate(20_000_000)
        restored = C.receiver.recover(self.wallet,m.after,m.after.state(s.DOMAIN))
        self.assertEqual(sum(c.spent for c in restored.owned),2)
        payouts = [{'auth_hex528':candidate.auth.hex(),'script_public_key':m.destination.hex(),
                    'amount_sompi':candidate.payout}]
        summary = a.controlled_payouts(SEED,self.wallet,restored,POINT,payouts)
        self.assertEqual(summary['bounded_two_real_group_reconstruction_count'],1)
        self.assertEqual(summary['historical_native_payout_key_control_match_count'],1)
        self.assertFalse(summary['native_current_UTXO_or_spendability_verified'])

    def test_one_match_only_exact_key_control_no_arity_or_missing_key_guess(self):
        claim=self.rec.owned[0];m=self.material(claims=[claim]);candidate=m.candidate(20_000_000)
        payouts=[{'auth_hex528':candidate.auth.hex(),'script_public_key':m.destination.hex(),
                  'amount_sompi':candidate.payout}]
        out=a.controlled_payouts(SEED,self.wallet,self.rec,POINT,payouts)
        self.assertEqual(out['one_known_NF_exact_key_matches_without_arity_claim'],1)
        self.assertEqual(out['bounded_two_real_group_reconstruction_count'],0)
        payouts[0]['script_public_key']=(b'\0\0\x20'+b'\x75'*32+b'\xac').hex()
        out=a.controlled_payouts(SEED,self.wallet,self.rec,POINT,payouts)
        self.assertEqual(out['historical_native_payout_key_control_match_count'],0)
        self.assertEqual(out['unresolved_owned_NF_payout_records'],1)

    def test_snapshot_missing_duplicate_physical_and_malformed_records_reject(self):
        record=recovery.snapshot_record(self.snapshot)
        self.assertEqual(recovery.snapshot_input(record),self.snapshot)
        for variant in ('missing','duplicate','reorder','unknown'):
            broken=copy.deepcopy(record)
            if variant=='missing':del broken['deliveries'][0]['cipher_hex264']
            if variant=='duplicate':broken['deliveries'].append(broken['deliveries'][0])
            if variant=='reorder':broken['deliveries'].reverse()
            if variant=='unknown':broken['nullifiers'][0]['success']=True
            with self.subTest(variant=variant), self.assertRaises(ValueError):recovery.snapshot_input(broken)

    def test_metadata_alias_parent_symlink_and_other_git_reject_before_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);backup=root/'backup';backup.write_bytes(b'PUBLIC SENTINEL');backup.chmod(0o600)
            alias=root/'hardlink';alias.hardlink_to(backup)
            with patch.object(Path,'read_bytes',side_effect=AssertionError('no content read')):
                with self.assertRaisesRegex(ValueError,'alias'):paths.guard(backup,(p for p in [alias]),root/'new')
            with self.assertRaisesRegex(ValueError,'parent'):paths.checked(root/'a/../bad')
            symlink=root/'link';symlink.symlink_to(backup)
            with self.assertRaisesRegex(ValueError,'symlink'):paths.checked(symlink)
            repo=root/'other-repo';repo.mkdir();subprocess.run(['/usr/bin/git','init','-q',str(repo)],check=True)
            existing=repo/'backup';existing.write_bytes(b'PUBLIC');existing.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'Git'):paths.outside_git(existing)

    def test_ready_mismatch_does_not_read_seed_or_write_witness(self):
        fake=SimpleNamespace(stdout=SimpleNamespace(readline=lambda:json.dumps({'event':'wrong'})))
        worker=object.__new__(owner.Worker);worker.process=fake
        with patch.object(C.receiver,'backup',side_effect=AssertionError('seed')), \
             patch.object(owner.Worker,'prove',side_effect=AssertionError('witness')):
            with self.assertRaisesRegex(ValueError,'READY'):worker.ready()

    def test_invalid_quote_does_not_serialize_private_witness(self):
        m=self.material()
        with patch.object(C.actions.Candidate,'private_witness',side_effect=AssertionError('witness')):
            with self.assertRaises(ValueError):m.candidate(240_000_000)

    def test_immutable_material_copies_point_and_public_projection_excludes_maps(self):
        point=dict(POINT);m=a.prepare(SEED,self.wallet,self.snapshot,self.rec,self.rec.owned,point,POINT,300_000_000)
        point['index']=9;self.assertEqual(m.previous,POINT)
        summary=a.controlled_payouts(SEED,self.wallet,self.rec,POINT,[])
        self.assertFalse(any(word in summary for word in ('seed','s','k','note','position','index','CM','witness_sha256')))
        self.assertFalse(any(value in json.dumps(summary) for value in
            (SEED.hex(),self.notes[0].commitment().hex(),self.notes[1].commitment().hex())))

class LauncherControls(unittest.TestCase):
    def fixture(self,root):
        backup=root/'backup';backup.write_bytes(b'PUBLIC BACKUP SENTINEL');backup.chmod(0o600)
        tree=root/'tree';tree.mkdir();rows=[]
        for relative in run_owner.mapping():
            path=tree/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'public')
            rows.append({'kind':'selected-executable' if relative.startswith('runtime/') else 'runtime-source',
                'path':relative,'bytes':6,'sha256':hashlib.sha256(b'public').hexdigest()})
        inventory=root/'inventory.json';inventory.write_text(json.dumps({'schema':'kpx4-public-software-bundle/v1',
            'classification':'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY','files':rows}))
        info=backup.stat()
        return SimpleNamespace(inventory=inventory,inventory_sha256=run_owner.digest(inventory.read_bytes()),
            software_root=tree), (info.st_dev,info.st_ino),backup

    def test_complete_runtime_metadata_before_any_listed_content(self):
        with tempfile.TemporaryDirectory() as temp:
            args,forbidden,backup=self.fixture(Path(temp))
            path=args.software_root/list(run_owner.mapping())[-1];path.unlink();path.hardlink_to(backup)
            original=Path.read_bytes;reads=[]
            def read(path):
                reads.append(path)
                return original(path)
            with patch.object(Path,'read_bytes',read),self.assertRaisesRegex(ValueError,'alias'):
                run_owner.verified_entries(args,forbidden)
            self.assertEqual(reads,[args.inventory])

    def test_inventory_duplicate_traversal_wrong_root_and_missing_closure(self):
        with tempfile.TemporaryDirectory() as temp:
            args,forbidden,_=self.fixture(Path(temp));original=json.loads(args.inventory.read_bytes())
            for kind in ('duplicate','traversal','missing','wrong-pin'):
                value=copy.deepcopy(original)
                if kind=='duplicate':value['files'].append(value['files'][0])
                if kind=='traversal':value['files'][0]['path']='runtime-source/../escape'
                if kind=='missing':value['files'].pop()
                args.inventory.write_text(json.dumps(value));args.inventory_sha256=run_owner.digest(args.inventory.read_bytes())
                if kind=='wrong-pin':args.inventory_sha256='00'*32
                with self.subTest(kind=kind),self.assertRaises(ValueError):run_owner.verified_entries(args,forbidden)

    def test_fixed_mounts_exclude_tests_controller_other_backup_and_unlisted_files(self):
        mounts=run_owner.mapping()
        self.assertEqual(len(mounts),24)
        self.assertTrue(all('test_wallet' not in path and 'run_owner' not in path for path in mounts))
        self.assertFalse(any(any(x in path for x in ('original-backups','actor-','public_fixture','OWNER')) for path in mounts))
        self.assertTrue(all('/work/' in path or path in run_owner.RUNTIME_DEST.values() or path.startswith(run_owner.SDK_DEST)
            for path in mounts.values()))

if __name__=='__main__':unittest.main(verbosity=2)
