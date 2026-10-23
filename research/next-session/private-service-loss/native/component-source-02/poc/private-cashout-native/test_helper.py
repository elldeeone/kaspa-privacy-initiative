#!/usr/bin/env python3
"""New native API controls using old PUBLIC AA proofs; no old PK/setup/prover."""
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=ROOT/'research/next-session/private-service-loss/native/component-fixtures-01/REQUESTS.json'
BINARY_SHA='f6139cea85a30f092447efe199796f62c540b0399d63e949845423678d4bdc44'
LOADER=Path('/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2')
LOADER_SHA='bda779ea9e9ad234f60315477d7cfd0bdde861cd8ddd9df8cdaf62f18c4cec14'


class HelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=json.loads(FIXTURE.read_bytes())
        raw=Path(os.environ['KPI_PUBLIC_NATIVE_BINARY']).read_bytes()
        assert hashlib.sha256(raw).hexdigest()==BINARY_SHA
        assert hashlib.sha256(LOADER.read_bytes()).hexdigest()==LOADER_SHA
        cls.fd=os.memfd_create('kpx3-public-native-test',os.MFD_ALLOW_SEALING)
        with os.fdopen(os.dup(cls.fd),'wb') as file:file.write(raw)
        seals=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK
        fcntl.fcntl(cls.fd,fcntl.F_ADD_SEALS,seals)
        assert fcntl.fcntl(cls.fd,fcntl.F_GET_SEALS)&seals==seals
        assert hashlib.sha256(os.pread(cls.fd,len(raw),0)).hexdigest()==BINARY_SHA

    @classmethod
    def tearDownClass(cls):os.close(cls.fd)

    def call(self,request,error=None):
        raw=request if isinstance(request,str) else json.dumps(request,separators=(',',':'))
        p=subprocess.run([str(LOADER),f'/proc/self/fd/{self.fd}'],pass_fds=(self.fd,),
            input=raw,text=True,capture_output=True,env={'PATH':'/usr/bin:/bin'})
        if error:
            self.assertEqual(p.returncode,1);self.assertEqual(p.stdout,'');self.assertEqual(p.stderr,error+'\n');return
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(p.stderr,'')
        return json.loads(p.stdout)

    def quote(self):return deepcopy(self.data['cases']['bob-partial']['quote'])
    def verify(self):return deepcopy(self.data['cases']['bob-partial']['verify'])

    def test_quote_then_actual_full_all_four_public_shapes(self):
        for stage,case in self.data['cases'].items():
            with self.subTest(stage=stage):
                q=self.call(case['quote']);v=self.call(case['verify'])
                self.assertEqual(q['quote_id'],case['expected_quote_id']);self.assertEqual(v['quote_id'],q['quote_id'])
                self.assertEqual(q['transaction'],case['expected_zero_proof_transaction'])
                self.assertEqual(v['transaction'],case['expected_transaction'])
                self.assertEqual(q['transaction_id'],v['transaction_id'])
                self.assertFalse(q['verified']);self.assertFalse(q['native_validation']['Full']['accepted'])
                self.assertTrue(v['verified']);self.assertTrue(v['native_validation']['Full']['accepted'])
                self.assertTrue(v['native_validation']['all_input_engines_accepted'])
                self.assertEqual(q['metrics'],case['expected_metrics'])
                self.assertFalse(v['accepted_chain_backing_proved_here'])
                self.assertFalse(v['network_contacted'])

    def test_genesis_actual_runtime_domain(self):
        request=self.data['genesis_fresh_public_domain'];r=self.call(request)
        note=bytes.fromhex(request['note_hex168']);d=bytes.fromhex(request['domain_hex32'])
        cm=hashlib.sha256(b'KPX1NOT\0'+d+note).digest()
        self.assertEqual(r['note_cm_hex32'],cm.hex())
        self.assertEqual(bytes.fromhex(r['state_hex112'])[8:40],d)
        self.assertEqual(bytes.fromhex(r['payload_hex536'])[8:40],d)
        self.assertEqual(len(bytes.fromhex(r['redeem_hex'])),24417)

    def test_strict_root_nested_maps_duplicates_and_unknown_secrets(self):
        self.call([], 'INVALID_REQUEST')
        for field in ('previous_outpoint','supplied_utxo'):
            r=self.quote();r[field]=list(r[field].values());self.call(r,'INVALID_REQUEST')
        r=self.quote();r['native_secret_hex32']='00'*32;self.call(r,'INVALID_REQUEST')
        raw=json.dumps(self.quote());self.call(raw.replace('{','{"mode":"quote",',1),'INVALID_REQUEST')
        r=self.quote();r.pop('supplied_utxo');self.call(r,'INVALID_REQUEST')
        r=self.quote();r['supplied_utxo'].pop('covenant_id');self.call(r,'INVALID_REQUEST')
        r=self.quote();r['expected_quote_id']=None;self.call(r,'INVALID_REQUEST')

    def test_exact_profile_program_domain_vk_and_actual_utxo(self):
        for field,value,error in (('domain_hex32','22'*32,'STATE_DOMAIN'),('vk_hex328','00'*328,'CURRENT_PROGRAM_NOT_APPROVED'),
            ('network_id','mainnet','TN10_SCHEMA_REQUIRED')):
            r=self.quote();r[field]=value;self.call(r,error)
        r=self.quote();raw=bytearray.fromhex(r['current_redeem_hex']);raw[-1]^=1;r['current_redeem_hex']=raw.hex()
        r['supplied_utxo']['script_public_key']='0000aa20'+hashlib.blake2b(raw,digest_size=32).hexdigest()+'87'
        self.call(r,'CURRENT_PROGRAM_NOT_APPROVED')
        for field,value in (('amount_sompi','1'),('script_public_key','0000'),('is_coinbase',True),('covenant_id','01'*32)):
            r=self.quote();r['supplied_utxo'][field]=value;self.call(r,'ACTUAL_UTXO_CONTEXT')

    def test_checked_canonical_rates_and_mode(self):
        for rate,error in (('0','POSITIVE_FEE_RATE'),('0100','UNSIGNED_DECIMAL_REQUIRED'),('18446744073709551615','FEE_PRODUCT_OVERFLOW')):
            r=self.quote();r['fee_rate_sompi_per_mass']=rate;self.call(r,error)
        r=self.quote();r['proof_hex128']=self.verify()['proof_hex128'];self.call(r,'PROOF_MODE')
        r=self.verify();r['proof_hex128']='00'*128;self.call(r,'PROOF_MODE')
        r=self.quote();r['expected_quote_id']='00'*32;self.call(r,'QUOTE_ID_MODE')
        q=self.quote();q['fee_rate_sompi_per_mass']='200';quoted=self.call(q)
        self.assertGreater(int(quoted['required_fee_sompi']),int(quoted['fee_sompi']))
        v={**q,'mode':'verify','proof_hex128':self.verify()['proof_hex128'],'expected_quote_id':quoted['quote_id']}
        self.call(v,'FEE_BELOW_REQUIRED')

    def test_quote_binds_entire_actual_context_and_rate(self):
        r=self.verify();r['supplied_utxo']['block_daa_score']='1';self.call(r,'QUOTE_ID_MISMATCH')
        r=self.verify();r['fee_rate_sompi_per_mass']='200';self.call(r,'QUOTE_ID_MISMATCH')
        r=self.verify();r['expected_quote_id']='00'*32;self.call(r,'QUOTE_ID_MISMATCH')

    def test_same_v1id_corrupted_proof_still_requires_native_full(self):
        r=self.verify();proof=bytearray.fromhex(r['proof_hex128']);proof[2]^=1;r['proof_hex128']=proof.hex()
        self.call(r,'NATIVE_FULL_REJECTED')

    def test_public_nf_and_terminal_checks_before_zero_proof_seam(self):
        r=self.quote();w=bytearray.fromhex(r['public_witness_hex3344']);w[72]^=1;r['public_witness_hex3344']=w.hex()
        self.call(r,'PUBLIC_CHECKS_DID_NOT_REACH_G16')
        for field,offset in (('cipher_hex528',0),('public_witness_hex3344',3343),('auth_hex528',268)):
            r=deepcopy(self.data['cases']['charlie-terminal']['quote']);raw=bytearray.fromhex(r[field]);raw[offset]^=1;r[field]=raw.hex()
            self.call(r,'PUBLIC_CHECKS_DID_NOT_REACH_G16')

    def test_coherent_other_destination_quote_is_not_original_authorization(self):
        q=self.quote();a=bytearray.fromhex(q['auth_hex528']);a[495]^=1;q['auth_hex528']=a.hex()
        fresh=self.call(q)
        self.assertNotEqual(fresh['quote_id'],self.verify()['expected_quote_id'])
        v={**q,'mode':'verify','proof_hex128':self.verify()['proof_hex128'],'expected_quote_id':fresh['quote_id']}
        self.call(v,'NATIVE_FULL_REJECTED')


if __name__=='__main__':unittest.main(verbosity=2)
