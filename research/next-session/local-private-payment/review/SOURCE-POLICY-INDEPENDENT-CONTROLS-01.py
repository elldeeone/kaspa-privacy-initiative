#!/usr/bin/env python3
"""Independent public arithmetic/queue oracle; no live or owner data input."""
import collections
import hashlib
import itertools
import json
from pathlib import Path
import runpy
import sys
import types

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
READ = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
PINS = {
    'poc/local-private-payment/privacy/economic_linkage.py': 'f861537240593dfda94fccd499ab802f2f3bbe23a52d6d4c4219e81b97d60641',
    'poc/local-private-payment/privacy/source_policy_prediction.py': 'b05e413b5b328795c5d9f7be56608f74cd31168284528bc17ee9da68fbb5838b',
    'research/next-session/local-private-payment/assessment/SOURCE-POLICY-PREDICTION-01.json': 'ae95c9a4c058069298aeef1030dcc4d8392a469148949e95340bd6c7aed1c709',
}
raws = {p: READ(str(ROOT / p), h) for p,h in PINS.items()}

def load(name, path):
    m=types.ModuleType(name); m.__file__=str(ROOT/path); sys.modules[name]=m
    exec(compile(raws[path],m.__file__,'exec'),m.__dict__); return m

observer=load('economic_linkage','poc/local-private-payment/privacy/economic_linkage.py')
source=load('source_policy_prediction','poc/local-private-payment/privacy/source_policy_prediction.py')
CAP=50_000_000; FLOOR=60_000_000

def forward(first,second,direction,fees):
    # Values and asset-origin labels evolve by actual note selection/subtraction.
    notes=[[(2_000_000_000,'initial',i)] for i in range(3)]
    for rnd,order in enumerate((first,second)):
        amount=(500_000_000,200_000_000)[rnd]
        for at,owner in enumerate(order):
            fee=fees[3*rnd+at]
            candidates=[n for n in notes[owner] if n[0]>=amount+fee+FLOOR]
            if rnd:
                if owner==1: candidates=[n for n in candidates if n[1]=='change']
                else:
                    received=[n for n in candidates if n[1]=='received']
                    candidates=received or [n for n in candidates if n[1]=='change']
            selected=max(candidates)
            assert selected[1]==('initial' if not rnd else 'change' if owner==1 else 'received')
            notes[owner].remove(selected)
            notes[owner].append((selected[0]-amount-fee,'change',selected[2]))
            notes[(owner+direction)%3].append((amount,'received',selected[2]))
    assert all(len(n)==3 for n in notes)
    assert sum(n[0] for ns in notes for n in ns)+sum(fees)==6_000_000_000
    actor1={n[0]:n for n in notes[1]}
    retained=actor1[500_000_000]
    changed=[n for n in notes[1] if 1_200_000_000<=n[0]<1_300_000_000]
    assert len(changed)==1 and retained[2]!=changed[0][2] and changed[0][2]==1
    queues=tuple(tuple(sorted((n[0] for n in ns),reverse=True)) for ns in notes)
    assert source.gross_bands([n[0] for ns in notes for n in ns])
    return queues

endpoint_count=0
for fees in itertools.product((1,CAP),repeat=6):
    known=set()
    for first in itertools.permutations(range(3)):
        for second in itertools.permutations(range(3)):
            for direction in (1,2):
                known.add(forward(first,second,direction,fees)); endpoint_count+=1
    assert known==source.queue_profiles(fees)

# Direct enumeration groups the entire actor-interleaving language by gross word.
fees=(1,12_345_679,CAP,23_456_789,2,49_999_999)
queues=forward((2,0,1),(1,2,0),2,fees)
grouped=collections.defaultdict(set); interleaving_count=0
for a in itertools.combinations(range(9),3):
    remaining=[i for i in range(9) if i not in a]
    for b in itertools.combinations(remaining,3):
        actors=[0 if i in a else 1 if i in b else 2 for i in range(9)]
        count=[0,0,0]; word=[]; mask=0
        for i,owner in enumerate(actors):
            word.append(queues[owner][count[owner]]); count[owner]+=1
            if owner==1: mask|=1<<i
        grouped[tuple(word)].add(mask); interleaving_count+=1
assert interleaving_count==1680
for word,masks in grouped.items():
    assert source.actor1_masks(queues,word)==masks

# A separate strict public ledger assembly tests the analyze boundary and fields.
def word(label): return hashlib.sha256(('INDEPENDENT PUBLIC SYNTHETIC/'+label).encode()).hexdigest()
gross=next(iter(grouped))
ledger={'schema':'kpxa-public-economic-ledger/v1','terminal':True,'terminal_reserve_sompi':0,
    'genesis':[{'cm_hex32':word('g'+str(i)),'position':i,'value_sompi':2_000_000_000} for i in range(3)],
    'payments':[{'action_id_hex32':word('a'+str(i)),'event_index':i,'nf_hex32':word('n'+str(i)),
      'fee_sompi':fees[i],'outputs':[{'cm_hex32':word('c'+str(i)+str(j)),'position':3+2*i+j} for j in range(2)]} for i in range(6)],
    'exits':[{'action_id_hex32':word('e'+str(i)),'event_index':6+i,'nf_hex32':word('en'+str(i)),
      'payout_sompi':v-1000,'fee_sompi':1000} for i,v in enumerate(gross)]}
result=source.analyze(ledger)
assert result['status']=='SOURCE_POLICY_PREDICTION_SUPPORTED'
pair={result['predicted_actor1_unique_gross500M_exit_index'],result['predicted_actor1_unique_change_band_exit_index']}
assert len(pair)==2 and pair<=set(result['must_actor1_exit_indices'])
assert result['selected_source_honest_execution_is_an_assumption']
assert not result['funding_mapping_independently_verified_by_this_analysis']
assert not result['contemporaneous_activation_argv_receipt_independently_verified']
assert not result['received500M_claim_and_original_change_same_asset_root_claimed']
assert not result['owner_verified_accuracy_or_probability_claim']
assert result['privacy_PASS_verdict']=='NOT_DEFINED'

bad=list(fees);bad[0]=CAP+1
rejected=source.predict(bad,list(gross))
assert rejected['status']=='SOURCE_POLICY_ASSUMPTIONS_NOT_QUALIFIED' and not rejected['must_actor1_exit_indices']
assert rejected['predicted_actor1_unique_gross500M_exit_index'] is None
badgross=list(gross);a=badgross.index(500_000_000);b=next(i for i,v in enumerate(badgross) if 1_200_000_000<=v<1_300_000_000)
badgross[a],badgross[b]=badgross[b],badgross[a]
rejected=source.predict(fees,badgross)
assert rejected['status']=='INCONSISTENT_SOURCE_POLICY_MODEL_OR_INPUT' and not rejected['must_actor1_exit_indices']
assert not rejected['predicted_pair_supported_by_every_consistent_source_model']
negative_count=0
for change in ('private-field','bool-fee','duplicate-nf','early-exit'):
    value=json.loads(json.dumps(ledger))
    if change=='private-field': value['private_PLAN']='SYNTHETIC_FORBIDDEN'
    elif change=='bool-fee': value['payments'][0]['fee_sompi']=True
    elif change=='duplicate-nf': value['exits'][0]['nf_hex32']=value['payments'][0]['nf_hex32']
    else:
        value['payments'][0]['event_index']=6
        value['exits'][0]['event_index']=0
    try: source.analyze(value)
    except ValueError: negative_count+=1
    else: raise AssertionError(change)
assert negative_count==4
report={'schema':'kpxa-source-policy-independent-controls/v1','status':'PASS',
    'source_files':PINS,'endpoint_fee_vectors':64,'forward_schedule_checks':endpoint_count,
    'independently_enumerated_exit_interleavings':interleaving_count,
    'distinct_gross_words_compared_to_queue_DP':len(grouped),'extra_strict_boundary_mutants_rejected':negative_count,
    'fee_cap_and_zero_support_controls':'PASS','conditional_scope_and_no_accuracy_claim_controls':'PASS',
    'asset_ancestry_common_ownership_separation':'PASS',
    'actual_live_public_ledger_or_payout_inputs_read':False,'private_or_owner_input_read':False,
    'native_financial_crypto_or_general_privacy_qualification':False}
out=ROOT/'research/next-session/local-private-payment/review/SOURCE-POLICY-INDEPENDENT-CONTROLS-01.json'
with out.open('x') as f: json.dump(report,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps(report,sort_keys=True))
