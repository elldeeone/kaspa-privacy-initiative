#!/usr/bin/env python3
"""Stdlib-only fixed public Borsh/body/full-hash/mass recount; no native run."""
from hashlib import sha256,blake2b
from pathlib import Path
import json
from native_budget_recount import transaction_bytes,h

BASE=Path('/home/luke/projects/kpi-intensive-2026-10-22')
EVIDENCE=BASE/'research/poc/public-state-native-check/evidence/historical-state-native-01'

class Reader:
    def __init__(self,raw):self.raw=raw;self.at=0
    def take(self,n):
        assert n>=0 and self.at+n<=len(self.raw)
        value=self.raw[self.at:self.at+n];self.at+=n;return value
    def num(self,n):return int.from_bytes(self.take(n),'little')
    def blob(self):return self.take(self.num(4))

def main():
    body=(EVIDENCE/'transaction.native-borsh.bin').read_bytes()
    assert len(body)==2910 and sha256(body).hexdigest()=='8cb44d28e488eab9e59f540b47016394dd8cf440313332e0cac48e827ac18c97'
    r=Reader(body);tx={'version':r.num(2),'inputs':[],'outputs':[]}
    assert tx['version']==1 and r.num(4)==1
    point={'transactionId':r.take(32).hex(),'index':r.num(4)}
    signature=r.blob();sequence=r.num(8)
    assert r.num(1)==1  # Borsh ComputeCommit::ComputeBudget enum variant.
    budget=r.num(2)
    tx['inputs'].append({'previousOutpoint':point,'signatureScript':signature.hex(),'sequence':sequence,'computeBudget':budget})
    assert r.num(4)==1
    value=r.num(8);version=r.num(2);script=r.blob();assert r.num(1)==0
    tx['outputs'].append({'value':value,'scriptPublicKey':version.to_bytes(2,'big').hex()+script.hex(),'covenant':None})
    tx['lockTime']=r.num(8);tx['subnetworkId']=r.take(20).hex();tx['gas']=r.num(8)
    payload=r.blob();tx['payload']=payload.hex();tx['storageMass']=r.num(8);cached_id=r.take(32).hex()
    assert r.at==len(body)
    assert cached_id=='b79c32deebb2d8800672ec07d4b9996688569750050ebb0de18d94798a6f6b97'
    full_hash=h('TransactionHash',transaction_bytes(tx)).hex()
    assert full_hash=='056636101fadbf4eb400104e59031fec9499615028713a85c5f3ae078d6af2ed'
    old=(EVIDENCE/'previous-redeem.bin').read_bytes();new=(EVIDENCE/'successor-redeem.bin').read_bytes();j=(EVIDENCE/'reconstructed-journal.bin').read_bytes()
    assert signature[:2]==bytes([0x4c,128]) and signature[130:133]==b'\x4d'+len(old).to_bytes(2,'little') and signature[133:]==old
    assert len(old)==len(new)==1383 and old[36:141]==j[110:215] and new[36:141]==j[215:320]
    assert old[:36]==new[:36] and old[141:]==new[141:]
    expected_spk=b'\xaa\x20'+blake2b(new,digest_size=32).digest()+b'\x87'
    assert version==0 and script==expected_spk
    assert payload==(EVIDENCE/'payload.bin').read_bytes() and len(payload)==1203
    reserve=int.from_bytes(j[320:328],'little');next_value=int.from_bytes(j[328:336],'little')
    assert reserve==1700000000 and value==next_value==1620000000
    assert budget==1600 and sequence==2**64-1 and tx['lockTime']==tx['gas']==0
    # Native deterministic mass-size estimator, not Borsh or P2P wire length.
    estimated=2+8+(36+8+len(signature)+8+2)+8+(8+2+8+len(script))+8+20+8+32+8+len(payload)
    compute=estimated+10*(2+len(script))+100*budget;transient=estimated*4
    storage=max(0,10**12//value-10**12//reserve) # Both standard P2SH UTXOs have plurality1.
    assert estimated==2920 and compute==163290 and transient==11680 and storage==tx['storageMass']==29
    print(json.dumps({'scope':'Independent fixed public Borsh decode/full-hash/immutable-policy and mass arithmetic; no native execution',
        'body_bytes':len(body),'borsh_exactly_consumed':r.at==len(body),'body_sha256':sha256(body).hexdigest(),
        'independent_full_hash':full_hash,'cached_transaction_id':cached_id,'cached_id_recomputed_in_python':False,
        'proof_and_redeem_bytes_preserved':True,'successor_spk_independently_reconstructed':True,'same_immutable_policy_outside_state':True,
        'estimated_mass_bytes':estimated,'compute_mass':compute,'transient_mass':transient,'storage_mass':storage,
        'fee_sompi':reserve-value,'default_relay_floor_sompi':compute*100,'rate500_fee_floor_sompi':compute*500,
        'rate500_fixed_fee_deficit_sompi':compute*500-(reserve-value)},indent=2))

if __name__=='__main__':main()
