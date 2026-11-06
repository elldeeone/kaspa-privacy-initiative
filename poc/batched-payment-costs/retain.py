#!/usr/bin/env python3
"""Retain a finite reviewed allowlist of public evidence. No external publishing."""
from pathlib import Path
import hashlib
import json
import shutil
import sys

ROOT=Path(__file__).resolve().parents[2]
PROOF_FILES=['input.bin','expected-journal.bin','candidate-succinct.bin','candidate-compressed.bin','native-proof.bin','proof-report.json','REUSED.json']
def copy(src,dst,optional=False):
    assert 'private' not in src.parts and src.name not in ['wallets.json','proving-parameters.bin']
    if not src.exists():
        if optional:return
        raise FileNotFoundError(src)
    dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    core,extras,analysis,out=map(lambda s:Path(s).resolve(),sys.argv[1:5]);out.mkdir()
    copy(core.with_name(core.name+'-monitor')/'guest.program.bin',out/'program.bin')
    for amount in ['30-kas','75-kas']:
        for name in ['initial-public-state.json','private-payment-operations.json','wallet-resources.json','deposit.json']:
            copy(core/amount/name,out/'core'/amount/name,optional=(amount=='75-kas' and name=='deposit.json'))
    for name in ['30-kas/named','30-kas/named-batched','30-kas/batched','75-kas/batched']:
        src=core/name;dst=out/'core'/name;copy(src/'world.json',dst/'world.json')
        for kind,count in [('payment',3 if name.endswith('/named') else 1),('withdraw',3 if name.endswith('/named') else 1)]:
            for i in range(count):
                copy(src/f'{kind}-{i}-native.json',dst/f'{kind}-{i}-native.json')
                for f in PROOF_FILES:copy(src/f'{kind}-{i}'/f,dst/f'{kind}-{i}'/f,optional=f=='REUSED.json')
        for f in ['registration.json','registration-controls.json','registration-resources.json']:copy(src/f,dst/f,optional=name.endswith('/named') or name.endswith('/named-batched'))
    extra_files=['abort-registration.json','abort.json','retry-registration.json','retry.json','negative-controls.json','solo.json','refund.json']
    extra_files += [f'solo-{i}-{suffix}.json' for i in range(3) for suffix in ['native','nf-replay']]
    for f in extra_files:copy(extras/f,out/'extras'/f)
    for d in ['retry-proof','solo-0','solo-1','solo-2','refund-proof']:
        for f in PROOF_FILES:copy(extras/d/f,out/'extras'/d/f,optional=f=='REUSED.json')
    # Metadata from all retained preflights/failures and completed campaigns.
    retained_ids=['8bb9ce05-39ff-452e-b370-bb6e445115aa','82ab253d-fd6a-425d-b65f-e410596d8130','5b6110dd-2c21-42b3-8594-6ac330489843',core.name,extras.name]
    monitors=[core.parent/(identity+'-monitor') for identity in retained_ids]
    assert all((m/'RESOURCES.json').exists() for m in monitors)
    for m in monitors:
        for f in ['FREEZE.json','RESOURCES.json','INVOCATION.json','TIMING-ANCHOR.json','STOP-REASON.json','stdout.log','stderr.log','resource-samples.jsonl']:
            copy(m/f,out/'monitors'/m.name/f,optional=f in ['INVOCATION.json','TIMING-ANCHOR.json','STOP-REASON.json'])
        archived_documents={}
        for p in sorted((m/'source').rglob('*')):
            if p.is_file():
                assert p.suffix in ['.rs','.py','.toml','.lock','.md']
                dest=out/'monitors'/m.name/'source'/p.relative_to(m/'source')
                if p.suffix=='.md':
                    dest=dest.with_suffix('.md.txt')
                    archived_documents[str(p.relative_to(m/'source'))]=str(dest.relative_to(out/'monitors'/m.name))
                copy(p,dest)
        with (out/'monitors'/m.name/'FROZEN-DOCUMENT-PATHS.json').open('x') as f:json.dump(archived_documents,f,indent=2,sort_keys=True)
    for d in ['views','scores','replay','extra-replay','costs']:
        for p in sorted((analysis/d).rglob('*')):
            if p.is_file():copy(p,out/d/p.relative_to(analysis/d))
    for p in sorted(analysis.glob('*FREEZE*.json')):copy(p,out/p.name)
    copy(analysis/'ATTEMPTS.json',out/'ATTEMPTS.json')
    expected=['program.bin','costs/COSTS.json','scores/VALIDATION.json','replay/public-replay.json','extra-replay/extra-public-replay.json']
    for f in expected:assert (out/f).exists(),f
    files={str(p.relative_to(out)):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(out.rglob('*')) if p.is_file()}
    with (out/'MANIFEST.json').open('x') as f:json.dump({'schema':'batched-payment-public-evidence-v1','coreRun':core.name,'extraRun':extras.name,'privateRuntimeFilesExcluded':True,'noExternalPublication':True,'files':files},f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps({'files':len(files),'bytes':sum(v['bytes'] for v in files.values()),'output':str(out)}))
if __name__=='__main__':main()
