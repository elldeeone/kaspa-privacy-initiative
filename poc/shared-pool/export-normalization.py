#!/usr/bin/env python3
"""Allowlisted H12 public evidence; never export private unused fallbacks."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


h=module('h12','normalized-deposits.py'); c=h.c
guard=module('guard','fresh-proof.py')


def forbidden(root,execution):
    secrets,proofs,auths=set(),set(),set()
    preparations=[root/'native/native-runtime/prepared'/case for case in ('sparse-00','burst-00')]
    preparations += [Path(execution[role])/'prepared' for role in ('recorder_failure','rehearsal','trial')]
    for prepared in preparations:
        private=c.read(prepared/'wallets.json')
        for w in private['wallets']:
            secrets.update(bytes(w[k]) for k in ('spending','viewing','native'))
        secrets.update(bytes(k) for k in private['funding_keys'])
        secrets.update(bytes(n['rho']) for _,n in private['notes'])
        old=c.read(prepared/'saved-request.json')['bundles'];new=c.read(prepared/'fresh-request.json')['bundles']
        for a,b in zip(old,new,strict=True):
            proofs.add(bytes.fromhex(a['proof']))
            if a['authorization']!=b['authorization']:auths.add(bytes.fromhex(a['authorization']))
    funding=Path(execution['funding_wallet'])
    secrets.add(bytes.fromhex((funding/'funding.key').read_text().strip()))
    # Also scan actual source-wallet secrets used to recycle ordinary payouts.
    origins=set()
    for directory in execution['funding']:
        consolidation=Path(directory);plan=c.read(consolidation/'plan.json')
        for i in range(plan['steps']):
            for u in c.read(consolidation/f'{i:04}/inputs.json'):
                if 'origin' in u:origins.add(Path(u['origin']['root']))
    for origin in origins:
        for i in range(4):
            candidates=[origin/f'wallet{i}.json',origin/f'wallet{i}/wallet.json']
            for file in candidates:
                if not file.exists():continue
                data=c.read(file)
                w=data.get('wallet',{})
                secrets.update(bytes(w[k]) for k in ('spending','viewing','native') if k in w)
                if isinstance(data.get('funding_key'),list):secrets.add(bytes(data['funding_key']))
                if data.get('initial_note'):secrets.add(bytes(data['initial_note']['rho']))
    return secrets,proofs,auths


def export(root,destination):
    execution=c.read(root/'execution.json')
    for role in ('recorder_failure','rehearsal','trial'):
        if not c.read(Path(execution[role])/'result.json')['complete']:
            raise ValueError('incomplete live validation')
    if not c.read(root/'summary.json')['both_inference_screens_pass']:
        raise ValueError('inference gate not passed')
    secrets,proofs,auths=forbidden(root,execution); denied=secrets|proofs|auths
    injections=0
    for value in denied:
        for encoded in (value.hex(),list(value)):
            try:guard.check_bytes(json.dumps({'injection':encoded}).encode(),denied)
            except ValueError:injections+=1
            else:raise ValueError('injection guard failed')
    destination.mkdir(parents=True,exist_ok=False);manifest={}

    def put(name,raw):
        guard.check_bytes(raw,denied)
        target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);manifest[name]=c.sha(raw)

    def obj(name,value):put(name,(json.dumps(value,indent=2)+'\n').encode())
    def copy(file,name):put(name,file.read_bytes())
    for name in ('freeze.json','source-pins.json','summary.json'):
        copy(root/name,name)
    if (root/'verification.json').exists():copy(root/'verification.json','verification.json')
    scores=c.read(root/'scores.json');table={};projections=[];observations=[];isolation={}
    for name,*_ in h.cases():
        table[name]={}
        for policy in h.POLICIES:
            row=scores[name][policy]
            table[name][policy]={'deposit':{h:{k:v for k,v in r.items() if k!='rows'} for h,r in row['deposit'].items()},
                'source':{h:{a:{k:v for k,v in r.items() if k!='rows'} for a,r in attacks.items()} for h,attacks in row['source'].items()}}
            base=root/'model'/name/policy
            projections.append({'case':name,'policy':policy,'projection':c.read(base/'input.json')})
            observations.append({'case':name,'policy':policy,'observer':c.read(base/'output/result.json')})
            isolation[f'{name}/{policy}']=c.read(base/'isolation.json')
    obj('ledger-scores.json',table);obj('model/isolation.json',isolation)
    for name,rows in [('projections.jsonl',projections),('observations.jsonl',observations)]:
        # Scan each JSON object too; a JSONL container is not one JSON value.
        for row in rows:guard.check_bytes(json.dumps(row).encode(),denied)
        put('model/'+name,(''.join(json.dumps(row,separators=(',',':'))+'\n' for row in rows)).encode())
    native=root/'native'
    copy(native/'native-summary.json','native/calibration-summary.json')
    copy(native/'native-runtime/binary.json','native/calibration-binary.json')
    for case in ('sparse-00','burst-00'):
        for arm in ('saved','fresh'):
            for name in ('settlement-isolation.json','observer-isolation.json','settled/result.json','calibration.json'):
                copy(native/'native-analysis'/case/arm/name,f'native/{case}/{arm}/{name}')
        for name in ('settled/chain.json','settled/metrics.json','observer/result.json'):
            copy(native/'native-analysis'/case/'fresh'/name,f'native/{case}/fresh/{name}')
    offline=c.read(Path(execution['offline'])/'offline-result.json')
    obj('native/adapter-offline.json',{**offline,'arms':{arm:{k:v for k,v in r.items() if k!='receipts'} for arm,r in offline['arms'].items()}})
    for role in ('recorder_failure','rehearsal','trial'):
        run=Path(execution[role]);result=c.read(run/'result.json')
        obj(f'tn10/{role}/result.json',{k:v for k,v in result.items() if k!='exitReceipts'})
        for name in ('chain.json','chain-confirmed.json','prover-stopped.json','observer/result.json',
                     'observer/isolation.json','observer/calibration.json','prepared/preparation.json','prepared/parameters.json'):
            copy(run/name,f'tn10/{role}/{name}')
        receipts=[]
        for index in range(result['claims']):
            base=run/f'tn10-fresh-{index:04}'
            # Isolation plus numeric/selected-file hashes, without duplicate
            # transaction copies or any other wallet's capability.
            receipts.append({'claim':index,'isolation':c.read(base/'isolation.json'),
                'process':c.read(base/'process-exit.json'),
                'selected_sha256':c.read(base/'result.json')['savedSha256'],
                'submission':c.read(base/'exit/submission.json'),'confirmation':c.read(base/'exit/confirmed.json')})
        obj(f'tn10/{role}/exit-receipts.json',receipts)
    for sequence,directory in enumerate(execution['funding']):
        funding=Path(directory);plan=c.read(funding/'result.json');obj(f'funding/{sequence}/result.json',plan)
        rows=[]
        for index in range(plan['steps']):
            base=funding/f'{index:04}'
            rows.append({'transaction':c.read(base/'transaction.json'),
                'inputs':[{k:v for k,v in u.items() if k!='origin'} for u in c.read(base/'inputs.json')],
                'validation':c.read(base/'validation.json'),'confirmation':c.read(base/'confirmed.json')})
        obj(f'funding/{sequence}/transactions.json',rows)
    tooling=['export-normalization.py','normalization-live-analysis.py','normalization-run.mjs',
        'normalization-client.mjs','normalization-reconcile.mjs','normalization-funding.mjs','src/compact/normalization.rs',
        'src/compact/study.rs','src/bin/kpi-normalized-deposits.rs','src/bin/kpi-compact-funding.rs',
        'test_normalization.py','privacy-study-native.py']
    obj('tooling-pins.json',{name:c.sha((HERE/name).read_bytes()) for name in tooling})
    obj('export.json',{'allowlist_only':True,'files_sha256':dict(manifest),
        'secret_values_scanned':len(secrets),'unused_saved_proofs_scanned':len(proofs),
        'distinct_old_authorizations_scanned':len(auths),'injection_controls_passed':injections,
        'private_material_matches':0,'omitted':['wallets','note openings','seed draws/truth','pending capabilities','native saved arms']})
    for file in destination.rglob('*'):
        if file.is_file():guard.check_bytes(file.read_bytes(),denied)
    print(json.dumps({'exported_files':len(manifest),'private_material_matches':0,'injection_controls':injections}))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('destination',type=Path);a=p.parse_args()
    export(a.root.resolve(),a.destination.resolve())
