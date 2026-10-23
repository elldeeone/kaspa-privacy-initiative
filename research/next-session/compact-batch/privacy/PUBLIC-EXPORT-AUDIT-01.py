"""Post-barrier public export and local exact-secret leak audit. No model reruns."""
import argparse
import base64
import collections
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

FREEZE='8d39e45d0b7d93c497641999f71dfa302e781bbf6d960d41d491276e32a81166'
RELEASE='fcdd3d7321393f5b774096111d528c5d864ea7eea76357372b58c7f6c5df240f'
ORDER=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

def need(ok):
    if not ok:raise ValueError('post-barrier-public-audit')

def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(path.read_bytes())
def dump(path,obj):path.write_text(json.dumps(obj,sort_keys=True,indent=2)+'\n')
def safe(relative):
    p=Path(relative);need(not p.is_absolute() and '..' not in p.parts);return p

def collect(args):
    runtime=Path(args.runtime).resolve();repo=Path(args.repo).resolve();public=Path(args.public).resolve()
    need(not public.exists())
    # This check precedes EVERY private-material/truth read below.
    barrier=read(runtime/'PREDICTION-BARRIER.json')
    need(barrier['prediction_count']==96 and len(barrier['predictions'])==96 and
         barrier['all_predictions_before_any_scorer'] is True and barrier['source_freeze_sha256']==FREEZE)
    result=read(runtime/'RESULTS.json');need(result['scores']==96)
    method=repo/'research/next-session/compact-batch/privacy'
    freeze_raw=(method/'SOURCE-PROPOSED-03.json').read_bytes();release_raw=(method/'STUDY-SELECTION-02.json').read_bytes()
    need(sha(freeze_raw)==FREEZE and sha(release_raw)==RELEASE)
    freeze=json.loads(freeze_raw);public.mkdir(mode=0o700)
    manifest=[]
    def copy(source,relative):
        relative=safe(relative);need(source.is_file() and not source.is_symlink());raw=source.read_bytes()
        target=public/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o444)
        manifest.append({'path':relative.as_posix(),'bytes':len(raw),'sha256':sha(raw)})
        return raw
    for row in freeze['files']:
        source=runtime/'software'/safe(row['path']);raw=source.read_bytes()
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256']);copy(source,'software/'+row['path'])
    copy(method/'SOURCE-PROPOSED-03.json','SOURCE-PROPOSED-03.json')
    copy(method/'STUDY-SELECTION-02.json','STUDY-SELECTION-02.json')
    for name in ('WORKLOAD-COMMITMENTS.json','PUBLIC-QUERY-BOUND.json','PREDICTION-BARRIER.json','RESULTS.json'):
        copy(runtime/name,name)
    sys.path.insert(0,str(runtime/'software/poc/payment-linkage'))
    from schema import decode,digest
    from prediction import validate_prediction
    seen=set();counts=collections.Counter();scores=[]
    for row in barrier['predictions']:
        key=(row['case'],row['horizon'],row['profile']);need(key not in seen);seen.add(key)
        need(row['case'] in {f'case-{i:03}' for i in range(16)} and row['horizon'] in ('payment','drain') and row['profile'] in ('C','C+1','C+8'))
        input_relative=safe(row['public_relative']);pred_relative=safe(row['prediction_file'])
        need(input_relative.parts[0]==row['case'] and len(input_relative.parts)==2 and len(pred_relative.parts)==1)
        source=runtime/'generator-output/cases'/input_relative;raw=source.read_bytes();need(sha(raw)==row['public_sha256'])
        prediction_raw=(runtime/'predictions'/pred_relative).read_bytes();need(sha(prediction_raw)==row['prediction_sha256'])
        pub=json.loads(raw);pred=json.loads(prediction_raw);ledger=decode(pub)
        need(pub['known_wallet_policy']=='one_real_full_cashout_wide_positive_varied_future_wallet')
        need(pred['status']==row['status'] and pred['public_sha256']==digest(pub));counts[pred['status']]+=1
        need(pred['status'] in ('COMPLETE','INCOMPLETE'))
        if pred['status']=='COMPLETE':validate_prediction(ledger,pred)
        score=read(runtime/'scores'/pred_relative)
        need(score['true_history_independently_validated'] is True and score['public_sha256']==sha(raw)
             and score['prediction_sha256']==digest(pred) and score['prediction_status']==pred['status']
             and score['complete']==(pred['status']=='COMPLETE'))
        scores.append(score)
        copy(source,'public-inputs/'+input_relative.as_posix())
        copy(runtime/'predictions'/pred_relative,'predictions/'+pred_relative.as_posix())
        copy(runtime/'scores'/pred_relative,'scores/'+pred_relative.as_posix())
    need(len(seen)==96 and counts['COMPLETE']==result['complete_score_cells'])
    need(len({(s['cluster'],s['timing'],s['arm'],s['profile'],s['horizon']) for s in scores})==96)
    # Keys and truth are used ONLY for the local leak scan, never copied.
    secrets_set=secret_material(runtime)
    return public,manifest,counts,secrets_set

def secret_material(runtime):
    # Already protected by collect()'s global barrier before this function runs.
    material=read(runtime/'PRIVATE-MATERIAL.json');secrets_set=set()
    need(set(material)=={'schema','workload_hex32','material_hex32'} and material['schema']=='kpx3-linkage-study-material/v1')
    for name in ('workload_hex32','material_hex32'):
        need(type(material[name]) is list and len(material[name])==4 and
             all(type(v) is str and len(v)==64 and v==v.lower() and len(bytes.fromhex(v))==32 for v in material[name]))
    commitments=read(runtime/'WORKLOAD-COMMITMENTS.json')
    need(commitments['schema']=='kpx3-linkage-sampling-commitments/v1' and
         commitments['crypto_material_key_seed_or_private_input_hashes_published'] is False and
         commitments['commitments']==[sha(b'KPI/LINKAGE/WORKLOAD-COMMIT/v1\0'+bytes.fromhex(v)) for v in material['workload_hex32']])
    for name in ('workload_hex32','material_hex32'):
        for value in material[name]:secrets_set.add(bytes.fromhex(value))
    sys.path.insert(0,str(runtime/'software/poc/payment-linkage'))
    from generate import Stream,load_receiver,CRYPTO_SHA
    v2=load_receiver()
    crypto_path=Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto')
    need(sha(crypto_path.read_bytes())==CRYPTO_SHA);crypto=v2.Crypto(crypto_path)
    def add(value,*,delivery=False,native=False):
        need(type(value) is bytes and len(value)==32);secrets_set.add(value)
        if delivery:
            clamped=bytearray(value);clamped[0]&=248;clamped[31]&=127;clamped[31]|=64;secrets_set.add(bytes(clamped))
        if native:
            number=int.from_bytes(value,'big');need(0<number<ORDER);secrets_set.add((ORDER-number).to_bytes(32,'big'))
    class Capture(Stream):
        def __init__(self,*a):super().__init__(*a);self.public=False
        def block(self):
            value=super().block()
            if not self.public:add(value)
            return value
        def exposed(self):
            self.public=True
            try:return self.block()
            finally:self.public=False
    private_index=read(runtime/'generator-output/cases/PRIVATE-CASES.json')
    need(private_index['schema']=='kpx3-linkage-private-case-index/v1' and len(private_index['cases'])==16)
    need({c['case'] for c in private_index['cases']}=={f'case-{i:03}' for i in range(16)})
    need(len({(c['cluster'],c['timing'],c['arm']) for c in private_index['cases']})==16)
    for c in private_index['cases']:
        need(type(c['cluster']) is int and c['cluster'] in range(4) and
             c['timing'] in ('overlap','staggered') and c['arm'] in ('wide32','compact2'))
    for case in private_index['cases']:
        truth=read(runtime/'generator-output/cases'/case['case']/'truth.json')
        # Only reconstruct derivable key material and stream positions. No note,
        # ciphertext, workload, public input, prediction or score is regenerated.
        stream=Capture(bytes.fromhex(material['material_hex32'][case['cluster']]),
                       f"{case['cluster']}/{case['timing']}/{case['arm']}/material")
        domain=hashlib.sha256(b'KPI/LINKAGE/MODEL/DO_NOT_FUND/v1\0'+stream.block()).digest()
        owner_seeds=[stream.block() for _ in range(34)]
        sample=read(runtime/'generator-output/cases'/case['case']/'drain-C.json')
        need(domain.hex()==sample['domain_hex32'])
        notes=truth['notes'];per_owner=collections.defaultdict(list)
        for note in notes:
            if note['value']:per_owner[note['owner']].append(note)
        for owner,seed in enumerate(owner_seeds):
            add(v2.derive(seed,domain,b'DELIVERY',0),delivery=True)
            owned=sorted(per_owner[owner],key=lambda n:(n['birth'],n['position']))
            for index,note in enumerate(owned):
                opening=bytes.fromhex(note['opening']);s=v2.derive(seed,domain,b'OWNSEC\0\0',index)
                k=v2.derive(seed,domain,b'KSECRET\0',index);incoming=v2.derive(seed,domain,b'INCOMING',index)
                need(incoming==opening[32:64] and v2.h(v2.OWNER_TAG,domain,s,incoming)==opening[:32]
                     and v2.h(v2.KEY_TAG,domain,k)==opening[104:136]);add(s);add(k)
                retry=0
                while True:
                    native=v2.derive(seed,domain,b'NATIVE\0\0',index,retry)
                    if 0<int.from_bytes(native,'big')<ORDER:break
                    retry+=1
                add(native,native=True);need(crypto.xonly(native)==opening[136:168])
        for event in sample['events']:
            born=[n for n in notes if n['birth']==event['ordinal']]
            if event['kind']=='ingress':
                need(len(born)==1 and born[0]['value']>0)
                need(stream.exposed()==bytes.fromhex(born[0]['opening'])[72:104])
            else:
                # Creation order: economic then self-change for mode2 P0;
                # all-positive for wide; all-zero for continuing cashout.
                ordered=sorted(born,key=lambda n:(0 if n['purpose']=='economic' else 1,n['obligation'] if n['obligation'] is not None else -1))
                actual_rhos=[];expected_rhos=[]
                for note in ordered:
                    actual_rhos.append(stream.block());expected_rhos.append(bytes.fromhex(note['opening'])[72:104])
                    if not note['value']:
                        add(stream.block(),delivery=True);stream.block()
                need(collections.Counter(actual_rhos)==collections.Counter(expected_rhos))
            need(stream.exposed().hex()==event['tx_id'])
            if event['kind']=='private':
                real_slot=stream.below(2);key=stream.block();dummy_seed=stream.block()
                import hmac
                dummy=hmac.digest(key,b'KPX2DMY\0'+domain+dummy_seed+bytes([1-real_slot]),'sha256').hex()
                need(dummy==event['nfs'][1-real_slot])
                for index in range(len(born)-1,0,-1):stream.below(index+1)
                if event['payout_sompi']:
                    native=stream.block();add(native,native=True)
                    need(event['payout_spk_hex36']=='000020'+crypto.xonly(native).hex()+'ac')
    return secrets_set

def scan(public,manifest,secrets_set,args_rg,archive=None):
    files=[public/safe(row['path']) for row in manifest]
    if archive is not None:files.append(archive)
    encodings=set()
    for value in secrets_set:
        encodings.update((value.hex().encode(),value.hex().upper().encode(),base64.b64encode(value),
            base64.b64encode(value).rstrip(b'='),base64.urlsafe_b64encode(value),base64.urlsafe_b64encode(value).rstrip(b'='),
            str(int.from_bytes(value,'big')).encode(),str(int.from_bytes(value,'little')).encode(),
            json.dumps(list(value),separators=(',',':')).encode(),json.dumps(list(value)).encode(),repr(value).encode()))
    # Pattern files are private, ephemeral, never hashed or exported. rg stdout
    # (possible file joins) and stderr are captured and never emitted.
    with tempfile.TemporaryDirectory(prefix='local-secret-audit-',dir=public.parent) as private:
        directory=Path(private);directory.chmod(0o700);text=directory/'patterns';raw=directory/'raw-patterns'
        text.write_bytes(b'\n'.join(sorted(encodings))+b'\n');text.chmod(0o600)
        raw.write_text('\n'.join(''.join('\\x%02x'%b for b in value) for value in sorted(secrets_set))+'\n');raw.chmod(0o600)
        common=[str(args_rg),'--files-with-matches','--text','--no-messages','--threads','4','--regex-size-limit','1G']
        outputs=[]
        for pattern,extra in ((text,['--fixed-strings']),(raw,['--no-unicode','--multiline'])):
            process=subprocess.run(common+extra+['--file',str(pattern),'--']+[str(f) for f in files],capture_output=True)
            need(process.returncode in (0,1));outputs.append(process.stdout)
        hits=set(line for output in outputs for line in output.splitlines());need(not hits)
    return {'result':'PASS','secret_values_checked':len(secrets_set),'text_encodings_checked':len(encodings),
            'public_files_checked':len(files),'matches':0}

def main(args):
    public,manifest,counts,secret_values=collect(args)
    result=scan(public,manifest,secret_values,args.rg)
    dump(public/'FILES.json',{'schema':'kpx3-public-linkage-export-files/v1','files':sorted(manifest,key=lambda r:r['path']),
        'private_truth_key_seed_values_case_index_and_actual_study_runtime_prefix_included':False})
    # Final exact finite payload list includes the small manifest itself.
    m=public/'FILES.json';manifest.append({'path':'FILES.json','bytes':m.stat().st_size,'sha256':sha(m.read_bytes())})
    archive=Path(args.archive).resolve();need(not archive.exists() and not archive.is_relative_to(public))
    command=['tar','--sort=name','--mtime=@0','--owner=0','--group=0','--numeric-owner','-C',str(public),'-cf','-','.']
    tar=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    compressed=subprocess.run(['zstd','-T4','-15','--long=27','-q','-o',str(archive)],stdin=tar.stdout,capture_output=True)
    tar.stdout.close();tar.wait();tar_error=tar.stderr.read();tar.stderr.close();need(tar.returncode==0 and compressed.returncode==0)
    # Verify actual archive members against the scanned allowlist before claiming
    # that the compressed artifact contains only the audited public payload.
    expected={row['path']:row for row in manifest};seen=set()
    decoder=subprocess.Popen(['zstd','-dc',str(archive)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    with tarfile.open(fileobj=decoder.stdout,mode='r|') as packed:
        for member in packed:
            if member.isdir():continue
            need(member.isfile());name=Path(member.name).as_posix().removeprefix('./');need(name in expected and name not in seen)
            data=packed.extractfile(member).read();row=expected[name]
            need(len(data)==row['bytes'] and sha(data)==row['sha256']);seen.add(name)
    decoder.stdout.close();decoder.wait();decoder.stderr.read();decoder.stderr.close();need(decoder.returncode==0 and seen==set(expected))
    result=scan(public,manifest,secret_values,args.rg,archive)
    report=Path(args.report);report.mkdir(parents=True,exist_ok=True)
    dump(report/'LEAK-SCAN-01.json',result)
    dump(report/'PUBLIC-EXPORT-01.json',{'schema':'kpx3-finite-public-linkage-export/v1','source_freeze_sha256':FREEZE,
        'root_release_sha256':RELEASE,'files':sorted(manifest,key=lambda r:r['path']),
        'uncompressed_payload_bytes':sum(row['bytes'] for row in manifest),'archive_bytes':archive.stat().st_size,
        'archive_sha256':sha(archive.read_bytes()),'prediction_status_counts':dict(counts),
        'all_archive_members_equal_scanned_allowlist':True,'privacy_or_security_qualification':False,
        'private_material_truth_and_raw_runtime_paths_exported':False,'external_upload_performed':False})
    print(json.dumps(result),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',required=True);parser.add_argument('--repo',required=True)
    parser.add_argument('--public',required=True);parser.add_argument('--archive',required=True);parser.add_argument('--report',required=True);parser.add_argument('--rg',required=True)
    try:main(parser.parse_args())
    except Exception:
        print(json.dumps({'result':'FAIL','matches':None}),flush=True);raise SystemExit(1)
