#!/usr/bin/env python3
"""Independent boundary mutants on an existing public synthetic adapter fixture.
Fake proofs and fabricated accepted statuses are not native financial authority.
"""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import sys
import types
ROOT=Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
READ=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
PINS={
 'poc/local-private-payment/privacy/economic_linkage.py':'f861537240593dfda94fccd499ab802f2f3bbe23a52d6d4c4219e81b97d60641',
 'poc/local-private-payment/privacy/economic_ledger_adapter.py':'47a1b4878fa9556ff4305cb6435a02297c3f380bcc78b4837e96a8fef0e7e315',
 'poc/local-private-payment/verification/wire.py':'6727e00a143596dbd31abf06c7fd5a2ceafa07082d6e3e6de47fa389a826def8',
 'poc/local-private-payment/integration/trees.py':'4936a7b571187469755b9aafae275c61ac589eb70ecd6a8efbced862d8c3bd3b',
 'poc/local-private-payment/privacy/test_economic_ledger_adapter.py':'556dee24d0a84cc97091b63838e20544ac39bc2b263b66edaeed5293856bc7f0',
}
raw={p:READ(str(ROOT/p),sha) for p,sha in PINS.items()}
def load(name,path):
 m=types.ModuleType(name);m.__file__=str(ROOT/path);sys.modules[name]=m
 exec(compile(raw[path],m.__file__,'exec'),m.__dict__);return m
observer=load('economic_linkage','poc/local-private-payment/privacy/economic_linkage.py')
wire=load('_independent_adapter_wire','poc/local-private-payment/verification/wire.py')
trees=load('_independent_adapter_trees','poc/local-private-payment/integration/trees.py')
adapter=load('economic_ledger_adapter','poc/local-private-payment/privacy/economic_ledger_adapter.py')
def public_word(s):return hashlib.sha256(('INDEPENDENT PUBLIC TOY/'+s).encode()).hexdigest()
def base_fixture():
 return {'schema':'kpxa-public-economic-ledger/v1','terminal':True,'terminal_reserve_sompi':0,
  'genesis':[{'cm_hex32':public_word('g'+str(i)),'position':i,'value_sompi':2_000_000_000} for i in range(3)],
  'payments':[{'action_id_hex32':public_word('a'+str(i)),'event_index':i,'nf_hex32':public_word('n'+str(i)),
    'fee_sompi':1000,'outputs':[{'cm_hex32':public_word('c'+str(i)+str(j)),'position':3+2*i+j} for j in range(2)]} for i in range(6)],
  'exits':[{'action_id_hex32':public_word('e'+str(i)),'event_index':6+i,'nf_hex32':public_word('en'+str(i)),
    'payout_sompi':666_665_000,'fee_sompi':1000} for i in range(9)]}
fixture_path='poc/local-private-payment/privacy/test_economic_ledger_adapter.py'
# Extract only the preexisting fixture definitions; never execute its file loader.
body=ast.parse(raw[fixture_path],str(ROOT/fixture_path))
selected=[n for n in body.body if isinstance(n,ast.FunctionDef) and n.name in
 {'toy_transaction','output','entry','input_at','row','synthetic_final'}]
env={'wire':wire,'trees':trees,'adapter':adapter,'symmetric_public_fixture':base_fixture}
exec(compile(ast.Module(body=selected,type_ignores=[]),str(ROOT/fixture_path),'exec'),env)
history,accounting,cases,expected=env['synthetic_final']()
assert adapter.derive(history,accounting,cases,wire,observer)==expected
mutants=['fee-even-if-report-adjusted','payout-outpoint','payout-SPK','ordinary-to-GEN3-lineage',
 'duplicate-ID','exit-proof','GEN3-CM-root','trial-UUID','nonterminal-status','floating-native-metrics']
rejections=[]
for name in mutants:
 h,a,c=deepcopy((history,accounting,cases))
 if name=='fee-even-if-report-adjusted':
  c[4]['entries'][0]['amount']+=1;a['actual_native_Full_reports'][4]['fee_sompi']+=1
  a['actual_native_Full_reports'][4]['metrics']['actual_fee_sompi']+=1
 elif name=='payout-outpoint': a['native_payouts'][0]['outpoint_hex36']='11'*36
 elif name=='payout-SPK': a['native_payouts'][0]['script_public_key']='11'*36
 elif name=='ordinary-to-GEN3-lineage':
  c[0]['transaction']['id']='11'*32;a['actual_native_Full_reports'][0]['transaction_id']='11'*32
 elif name=='duplicate-ID':
  c[4]['transaction']['id']=c[3]['transaction']['id'];a['actual_native_Full_reports'][4]['transaction_id']=c[3]['transaction']['id']
 elif name=='exit-proof': h['transitions'][6]['proof_hex128']='00'*128
 elif name=='GEN3-CM-root':
  x=bytearray.fromhex(h['genesis']['outputs_hex520'][0]);x[0]^=1;h['genesis']['outputs_hex520'][0]=x.hex()
  y=bytearray.fromhex(c[3]['transaction']['payload']);y[88:608]=x;c[3]['transaction']['payload']=y.hex()
 elif name=='trial-UUID':a['trial_id']='22222222-2222-2222-2222-222222222222'
 elif name=='nonterminal-status':a['status']='SYNTHETIC_NOT_ACCEPTED'
 else:a['actual_native_Full_reports'][4]['metrics']['actual_fee_sompi']=float(a['actual_native_Full_reports'][4]['fee_sompi'])
 try:adapter.derive(h,a,c,wire,observer)
 except ValueError as exc:rejections.append({'name':name,'reason':str(exc)})
 else:raise AssertionError(name)
for name,payload in [('duplicate-JSON',b'{"a":1,"a":1}'),('nonfinite-JSON',b'{"a":NaN}')]:
 try:adapter.parse(payload)
 except ValueError as exc:rejections.append({'name':name,'reason':str(exc)})
 else:raise AssertionError(name)
report={'schema':'kpxa-economic-adapter-independent-controls/v1','status':'PASS','source_files':PINS,
 'existing_synthetic_fixture_used_with_independent_public_labels':True,
 'fixture_loader_bypassed_to_use_guard_authenticated_in_memory_modules':True,
 'native_or_chain_qualification_from_fake_fixture':False,
 'independent_boundary_mutants_rejected':rejections,
 'actual_live_public_ledger_or_payout_inputs_read':False,'private_or_owner_input_read':False,
 'required_external_authority':'Root-selected final19case native accounting plus same HISTORY/case byte pins; adapter is consistency derivation only'}
out=ROOT/'research/next-session/local-private-payment/review/ECONOMIC-ADAPTER-INDEPENDENT-CONTROLS-01.json'
with out.open('x') as f:json.dump(report,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps(report,sort_keys=True))
