#!/usr/bin/env python3
"""Export drained-trial evidence; omit keys, private witnesses and proving parameters.

Ground truth contains synthetic commitment/value/owner-public-hash labels only.
It is disclosed here AFTER blind inference and scoring, never to the observer.
"""
import argparse
import hashlib
import json
import shutil
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('trial',type=Path);p.add_argument('destination',type=Path)
p.add_argument('--observer-dir',default='blind-observer')
p.add_argument('--score-file',default='scored-final.json')
p.add_argument('--amounts-dir',default='blind-amounts');a=p.parse_args()
r=a.trial;d=a.destination
read=lambda f:json.loads(f.read_text())
hashfile=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
prepared=read(r/'prepared.json');result=read(r/'live/result.json');scored=read(r/a.score_file);retrieved=read(r/'chain-retrieval.json')
assert result['terminalReserveSpent'] and result['fourWalletsIndependentlyProvedAndDrained']
assert result['confirmedTransactions']==retrieved['exactBodyAndFullHashMatches']==prepared['lastStep']+1
assert scored['truth_sha256']==prepared['groundTruthSha256']==hashfile(r/'private-truth.json')
assert scored['observer_sha256']==hashfile(r/a.observer_dir/'observer.json')
assert scored['amounts_sha256']==hashfile(r/a.amounts_dir/'amounts.json')
assert read(r/a.observer_dir/'observer.json')['chain_sha256']==hashfile(r/'chain-confirmed.json')
assert read(r/a.amounts_dir/'amounts.json')['chain_sha256']==hashfile(r/'chain-confirmed.json')
for horizon in scored['supplement']['joint_history'].values():
    assert horizon['true_joint_history_satisfies_model']
for groups in scored['horizons'].values():
    for group in groups.values():assert group['truth_in_all_candidates']
truth=read(r/'private-truth.json')
assert set(truth)=={'arm','initial','events','firstWithdrawalHorizon'}
assert set(truth['initial'])=={'cm','value','wallet'}
for event in truth['events']:
    assert set(event)=={'step','mode','spent_cm','input_value','outputs','wallet','kind'}
    for note in event['outputs']:assert set(note)=={'cm','value','owner'}
d.mkdir(parents=True,exist_ok=False)
def save(name,value):(d/name).write_text(json.dumps(value,indent=2)+'\n')
def copy(src,name):shutil.copyfile(r/src,d/name)
for folder in ['transactions','metrics','live','wallets']:(d/folder).mkdir()
for step in range(prepared['lastStep']+1):
    label=f'{step:04}'
    assert hashfile(r/f'public/{label}.json')==prepared['transactions'][label]
    copy(f'public/{label}.json',f'transactions/{label}.json')
    copy(f'public/{label}.metrics.json',f'metrics/{label}.json')
    for suffix in ['submission.json','response.json','confirmed.json','inputs.json','-validation.stdout.json']:
        filename=label+suffix if suffix.startswith('-') else label+'.'+suffix
        copy('live/'+filename,'live/'+filename)
copy('live/result.json','result.json');copy('chain-confirmed.json','chain-confirmed.json');copy('chain-retrieval.json','chain-retrieval.json')
copy('logs/native-controls.stdout.json','native-controls.json')
copy(a.observer_dir+'/observer.json','observer.json');copy(a.score_file,'scored.json')
copy(a.amounts_dir+'/amounts.json','amounts.json')
copy('private-truth.json','scoring-ground-truth.json')
for i in range(4):
    namespace=read(r/f'wallet{i}-isolated/namespace.json');ready=read(r/f'wallet{i}-isolated/ready.json')
    assert namespace['privateInputCount']==1 and not namespace['otherWalletsMounted'] and namespace['networkUnshared'] and namespace['pidNamespaceUnshared']
    save(f'wallets/{i}.json',{'namespace':{k:v for k,v in namespace.items() if k!='mounts'},'originalNamespaceSha256':hashfile(r/f'wallet{i}-isolated/namespace.json'),'startup':ready})
for source,name in [(a.observer_dir,'observer-isolation.json'),(a.amounts_dir,'amount-isolation.json')]:
    namespace=read(r/source/'namespace.json');assert namespace['privateTruthMounted'] is False
    save(name,{k:v for k,v in namespace.items() if k!='mounts'})
save('prepared.json',{k:v for k,v in prepared.items() if k!='root'})
node=read(r/'live/node.json');node['endpoint']='owner TN10 node; LAN endpoint omitted';save('node.json',node)
save('export.json',{'trialIdentity':r.name,'sourcePreparedSha256':hashfile(r/'prepared.json'),'sourceConfirmedChainSha256':hashfile(r/'chain-confirmed.json'),'scope':'synthetic TN10 results; scoring ground truth disclosed only after blind output; no keys, note randomness or proving parameters exported','omitted':['LAN endpoint','private host mount paths','wallet files','note witnesses','proving parameters'],'nodeViewOnly':True})
# Check all known scalar secrets and genesis randomness against exported bytes.
secrets=[]
for i in range(4):
    w=read(r/f'wallet{i}/wallet.json')
    for field in ['spending','viewing','native']:secrets.append(bytes(w['wallet'][field]))
    if w['genesis_note']:secrets.append(bytes(w['genesis_note']['rho']))
for f in d.rglob('*'):
    if not f.is_file():continue
    data=f.read_bytes()
    for secret in secrets:
        assert secret not in data and secret.hex().encode() not in data, 'secret material in exported file'
        assert json.dumps(list(secret)).encode() not in data,'secret array in exported file'
manifest={str(f.relative_to(d)):hashfile(f) for f in sorted(d.rglob('*')) if f.is_file()}
save('sha256.json',manifest)
print(json.dumps({'exported':str(d),'files':len(manifest)+1,'knownSecretScan':'passed'}))
