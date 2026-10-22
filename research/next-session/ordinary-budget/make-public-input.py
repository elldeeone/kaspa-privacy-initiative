#!/usr/bin/env python3
"""Read only the exact retained, intentionally public fixture/evidence files."""
import hashlib,json,pathlib,sys
root=pathlib.Path(__file__).resolve().parents[3]
seen=[]
def raw(path):
 p=root/path;b=p.read_bytes();seen.append({'source':str(p),'relative_source':path,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()});return b
def js(path):return json.loads(raw(path))
a='artifacts/initial-four-public-fixture-20261022T1415/public/'
f='artifacts/finalize-initial-native-20261022T1431/public/'
s='research/intensive-2026-10-22/s7-native-policy/ordinary-spend-native-02/execution/results/'
p='research/intensive-2026-10-22/s7-native-policy/pair-native-01/'
u=js(f+'pre-pair-utxo.json')
packet={'policy':js(f+'policy.json'),'profile':js(f+'profile.json'),'selected_tuple':js(p+'inputs/selected-profile.json'),'initial_state':js(a+'initial-state.json'),'prior_state':js(f+'pre-pair-state.json'),'prior_utxo':u}
for name in ('bootstrap','admit'):
 packet[name]={'bundle':js(a+name+'.json'),'transaction':js(f+name+'.json'),'utxos':js(f+name+'-spent-utxos.json')}
packet['spends']=[{'bundle':js(a+f'bundle-{i}.json'),'transaction':js(s+f'fork-{i}-transaction.json'),'utxos':[u]}for i in range(2)]
packet['paired']={'projection':raw(p+'inputs/P.bin').hex(),'next_state':raw(p+'inputs/next-state.bin').hex(),'proof':raw(p+'inputs/proof.compressed.bin').hex(),'transaction':js(p+'execution/results/transaction.json')}
packet['provenance']={'format':'retained-public-ordinary1600-input-v1','source_files':seen,'private_inputs_read':False,'new_setup_or_proving':False,'actual_prefix_scope':'supplied retained offline context; no accepted chain or native backing assertion'}
out=pathlib.Path(sys.argv[1]);out.parent.mkdir(parents=True,exist_ok=True)
if out.exists():raise SystemExit('refusing existing output')
b=(json.dumps(packet,indent=2)+'\n').encode();out.write_bytes(b);print(hashlib.sha256(b).hexdigest(),len(b),out)
