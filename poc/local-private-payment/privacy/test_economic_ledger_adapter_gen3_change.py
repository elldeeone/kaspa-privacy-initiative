#!/usr/bin/env python3
"""Public helper controls only: no observer/ledger derivation, Native or network."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import sys
import types

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
BASE = Path('/var/tmp/kpi-local-private-payment-01/trials/local-pay-testnet-02/final-accounting-01')
read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
adapter_path = ROOT / 'poc/local-private-payment/privacy/economic_ledger_adapter_gen3_change.py'
adapter_raw = read(str(adapter_path), 'bc9e7bf649c6217f6a54efe3df6e76feed541dfe9db1199c93b1badc809bb811')
adapter = types.ModuleType('_public_gen3_change_controls')
adapter.__file__ = str(adapter_path)
sys.modules[adapter.__name__] = adapter
exec(compile(adapter_raw, str(adapter_path), 'exec'), adapter.__dict__)
wire_path = ROOT / 'poc/local-private-payment/verification/wire.py'
wire_raw = read(str(wire_path), '6727e00a143596dbd31abf06c7fd5a2ceafa07082d6e3e6de47fa389a826def8')
wire = adapter.selected_module('_public_gen3_change_control_wire', wire_raw, wire_path)
accounting = json.loads(read(str(BASE / 'RESULTS.json'), '2047d18602a6355d6a76c4e4bd69ce4ba310411b40228c9ea4c9ae2b8302d623'))
rows = accounting['actual_native_Full_reports']
def selected(index):
    row = next(r for r in rows if r['kind'] == 'pool' and r['index'] == index)
    return json.loads(read(row['case_path'], row['case_sha256']))
case, next_case = selected(0), selected(1)
history = json.loads(read('/var/tmp/kpi-local-private-payment-01/campaign/trial-02/run/action-0015/confirmation-1793059440809697374/pool-replay/result/HISTORY.json', '7e78910c6ff714edc5f7779a4b764fa1f2405df1278b3eea8df8814a05e54717'))
first = history['genesis']
reserve_script = next_case['entries'][0]['scriptPublicKey']
fee = accounting['genesis_fee_sompi']
checks = []
def accept(name, fn):
    fn(); checks.append({'name': name, 'expected': 'ACCEPT', 'status': 'PASS'})
def reject(name, fn, expected):
    try: fn()
    except ValueError as error:
        assert str(error) == expected, (name, str(error), expected)
        checks.append({'name': name, 'expected': 'REJECT', 'category': str(error), 'status': 'PASS'})
    else: raise AssertionError('invalid public helper assignment accepted: '+name)
def layout(c=case, f=first, total=fee, spk=reserve_script):
    return adapter.genesis_native_layout(c, f, total, spk)
accept('actual_four_output_GEN3', lambda: (layout() == [1203359095,1203359095,912118742]) or (_ for _ in ()).throw(AssertionError('actual changes')))
for count in (0,1,2):
    c=copy.deepcopy(case); c['transaction']['outputs']=c['transaction']['outputs'][:1]+c['transaction']['outputs'][1:1+count]
    shares=[fee//3,fee//3,fee-2*(fee//3)]
    for i,e in enumerate(c['entries']): e['amount']=first['deposit_sompi']+shares[i]+(case['transaction']['outputs'][i+1]['value'] if i<count else 0)
    accept('synthetic_'+str(1+count)+'_output_optional_changes', lambda c=c: layout(c))
f=copy.deepcopy(first);f['outpoint_hex36']='00'*36
reject('wrong_reserve_outpoint',lambda:layout(f=f),'actual-GEN3-reserve-outpoint-and-next-input-policy')
c=copy.deepcopy(case);c['transaction']['outputs'][0]['value']+=1
reject('wrong_reserve_amount',lambda:layout(c),'actual-GEN3-reserve-outpoint-and-next-input-policy')
c=copy.deepcopy(case);s=bytearray.fromhex(reserve_script);s[4]^=1;c['transaction']['outputs'][0]['scriptPublicKey']=s.hex()
reject('wrong_reserve_script',lambda:layout(c),'actual-GEN3-reserve-outpoint-and-next-input-policy')
c=copy.deepcopy(case);c['transaction']['outputs'].append(copy.deepcopy(c['transaction']['outputs'][0]))
reject('extra_reserve_credit',lambda:layout(c),'GEN3-native-reserve-and-at-most-three-changes')
c=copy.deepcopy(case);c['transaction']['outputs'][1]['scriptPublicKey']='000020'+'01'*32+'ac'
reject('foreign_change_script',lambda:layout(c),'GEN3-no-foreign-or-reserve-change')
c=copy.deepcopy(case);c['transaction']['outputs'][2]['scriptPublicKey']=c['transaction']['outputs'][1]['scriptPublicKey']
reject('duplicate_owner_change',lambda:layout(c),'GEN3-change-order-or-duplicate')
c=copy.deepcopy(case);c['transaction']['outputs'][1:3]=list(reversed(c['transaction']['outputs'][1:3]))
reject('reordered_owner_changes',lambda:layout(c),'GEN3-change-order-or-duplicate')
c=copy.deepcopy(case);c['transaction']['outputs'][1]['value']-=1;c['transaction']['outputs'][2]['value']+=1
reject('wrong_owner_allocation_same_total_fee',lambda:layout(c),'GEN3-exact-deposit-own-change-and-fee-share')
reject('wrong_selected_GEN3_fee',lambda:layout(total=fee+1),'GEN3-exact-full-CASE-fee')
c=copy.deepcopy(case);c['transaction']['outputs'][1]['value']=0
reject('zero_change_output',lambda:layout(c),'GEN3-positive-native-output-without-covenant')
c=copy.deepcopy(case);c['transaction']['outputs'][1]['value']=True
reject('boolean_change_amount',lambda:layout(c),'canonical-integer-sompi-or-index')
c=copy.deepcopy(case);c['transaction']['outputs'][1]['covenant']='00'
reject('change_covenant',lambda:layout(c),'GEN3-positive-native-output-without-covenant')
c=copy.deepcopy(case);c['transaction']['outputs'][1]=copy.deepcopy(c['transaction']['outputs'][0])
reject('reserve_disguised_as_change',lambda:layout(c),'canonical-public-hex')
genesis_rows=[bytes.fromhex(x) for x in first['outputs_hex520']]
accept('actual_three_note_prefix_root',lambda:adapter.genesis_state(first,genesis_rows,wire))
f=copy.deepcopy(first);state=wire.parse_state(bytes.fromhex(f['state_hex112']));cm=bytearray(state.cm_root);cm[0]^=1;f['state_hex112']=wire.encode_state(bytes(cm),state.cm_count,state.nf_root,state.nf_count).hex()
reject('wrong_CM_root',lambda:adapter.genesis_state(f,genesis_rows,wire),'complete-public-GEN3-CM-prefix-and-NF-sentinel')
f=copy.deepcopy(first);state=wire.parse_state(bytes.fromhex(f['state_hex112']));nf=bytearray(state.nf_root);nf[0]^=1;f['state_hex112']=wire.encode_state(state.cm_root,state.cm_count,bytes(nf),state.nf_count).hex()
reject('wrong_NF_root',lambda:adapter.genesis_state(f,genesis_rows,wire),'complete-public-GEN3-CM-prefix-and-NF-sentinel')
reject('extra_note_double_credit',lambda:adapter.genesis_state(first,genesis_rows+[genesis_rows[0]],wire),'complete-public-GEN3-CM-prefix-and-NF-sentinel')
assert len(checks)==21
print(json.dumps({'schema':'kpxa-GEN3-change-adapter-helper-controls/v1','status':'PASS','checks':checks,'count':len(checks),'source_sha256':hashlib.sha256(adapter_raw).hexdigest(),'actual_accounting_sha256':'2047d18602a6355d6a76c4e4bd69ce4ba310411b40228c9ea4c9ae2b8302d623','actual_GEN3_case_sha256':'bba117f9bb5727b1b21d94a4a249a9e676814a41790b8ea0464e619c47be0aeb','scope':'PUBLIC_GEN3_LAYOUT_AND_EXISTING_ROOT_HELPERS_ONLY_NOT_FULL_LEDGER_OR_OBSERVER_RERUN','native_or_network_or_private_action':False}))
