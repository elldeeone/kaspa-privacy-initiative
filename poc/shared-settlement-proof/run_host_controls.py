#!/usr/bin/env python3
"""Public byte/crypto backend differentials; no R0, setup, PK or owner witness."""
from pathlib import Path
import argparse,copy,hashlib,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'poc/shared-settlement-verifier'))
from public_native import normalize
from capacity_g16 import verify as reference

def sha(raw):return hashlib.sha256(raw).hexdigest()
def run(binary,output):
    output.mkdir(parents=True,exist_ok=False,mode=0o700);rows=[]
    def command(args,expected):
        r=subprocess.run([str(binary),*map(str,args)],capture_output=True,text=True,check=False)
        assert (r.returncode==0) is expected
        return {'args':list(map(str,args)),'exit_code':r.returncode,
                'stdout':r.stdout,'stderr':r.stderr}
    key=command(['key-check'],True);key['case']='selected-key';rows.append(key)
    base=Path('/home/luke/projects/kpi-intensive-2026-10-22/capacity-exit-genuine-01')
    pairs=[]
    for label in ['first','terminal','current-occupied-NF']:
        a=(base/('proof-'+label)/'authorization528.bin').read_bytes()
        p=(base/('proof-'+label)/'proof128.bin').read_bytes()
        assert reference('compact2',a,p)['verified']
        r=command(['crypto-check',base/('proof-'+label)/'authorization528.bin',base/('proof-'+label)/'proof128.bin'],True)
        r['case']='genuine-backend-differential-'+label;rows.append(r);pairs.append((a,p))
    a,p=pairs[0];bad=bytearray(a);bad[196:204]=(int.from_bytes(a[196:204],'little')+1).to_bytes(8,'little');bad[476:484]=(int.from_bytes(a[476:484],'little')-1).to_bytes(8,'little')
    for label,auth,proof in [('coherent-fee-reserve',bytes(bad),p),('trailing-proof',a,p+b'\x00')]:
        d=output/label;d.mkdir();(d/'auth.bin').write_bytes(auth);(d/'proof.bin').write_bytes(proof)
        assert reference('compact2',auth,proof)['verified'] is False
        r=command(['crypto-check',d/'auth.bin',d/'proof.bin'],False);r['case']=label;rows.append(r)
    # HASH-CODEC-ONLY: deliberately invalid payment payload derived from a known
    # public cashout. No private predicate or VM is claimed for this body.
    case=json.loads((base/'native-first/case.json').read_bytes());profile=json.loads((ROOT/'poc/shared-settlement-proof/child-profile.json').read_bytes())
    payload=bytes.fromhex(case['transaction']['payload'])+bytes(3920-2848)
    auth=payload[:528];tail=bytes.fromhex(profile['child_template_tail_hex'])
    def spk(state):return (b'\x00\x00\xaa\x20'+hashlib.blake2b(b'\x4c\x70'+state+tail,digest_size=32).digest()+b'\x87').hex()
    case['transaction']['payload']=payload.hex();case['transaction']['outputs']=[{'value':int.from_bytes(auth[476:484],'little'),'scriptPublicKey':spk(auth[364:476]),'covenant':None}]
    normalized=normalize(case);assert normalized['native_VM_executed'] is False
    path=output/'HASH-CODEC-ONLY-PUBLIC-INVALID-PAYMENT.bin';path.write_bytes(payload)
    r=command(['virtual-id',path],True);actual=json.loads(r['stdout'])['canonical_virtual_id'];assert actual==normalized['transaction']['id']
    r.update(case='native-keyed-BLAKE3-virtual-ID-differential',official_txid=actual,
             classification='HASH_CODEC_ONLY_INTENTIONALLY_INVALID_PAYMENT_NO_VM_NO_PROOF_QUALIFICATION');rows.append(r)
    summary={'schema':'kpx5-public-host-backend-controls/v1','classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND_NO_MAIN_DATA',
        'all_expected_outcomes':True,'cases':rows,'host_elf_sha256':sha(binary.read_bytes()),
        'R0_execution_or_proof_or_native_VM_or_PK_or_owner_witness':False,
        'compatible_two_P0_settlement_qualification':False,
        'actual_new_host_crypto_calls':5,'actual_cap_reference_crypto_calls':4,
        'reference_width_rejection_before_Rust':1,'actual_official_ID_normalizations':1,
        'source_sha256':sha(Path(__file__).read_bytes())}
    (output/'RESULTS.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n');print(json.dumps({'all_expected_outcomes':True,'cases':len(rows),'host_elf_sha256':summary['host_elf_sha256']}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path);p.add_argument('output',type=Path);a=p.parse_args();run(a.binary,a.output)
