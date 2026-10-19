#!/usr/bin/env python3
"""Score a completed blind observer output. Ground truth is never sent to it."""
import argparse
import hashlib
import json
from pathlib import Path
from statistics import mean


def score(truth,observed):
    origin={truth['initial']['cm']:truth['initial']['cm']}
    born={truth['initial']['cm']:1}
    actual={}
    for event in truth['events']:
        if event['mode']==0:
            for note in event['outputs']:origin[note['cm']]=note['cm'];born[note['cm']]=event['step']
        else:
            root=origin[event['spent_cm']];actual[event['step']]={'cm':event['spent_cm'],'origin':root,'wallet':event['wallet'],'born':born[event['spent_cm']]}
            for note in event['outputs']:origin[note['cm']]=root;born[note['cm']]=event['step']
    result={}
    for name,h in observed['horizons'].items():
        groups={'all_spends':h['events'],'withdrawals':[e for e in h['events'] if e['mode']>=2],
                'first_four_withdrawals':[e for e in h['events'] if e['mode']>=2 and e['step']<=truth['firstWithdrawalHorizon']],
                'private_transfers':[e for e in h['events'] if e['mode']==1]}
        result[name]={}
        for group,events in groups.items():
            if not events:continue
            for e in events:
                a=actual[e['step']]
                assert a['cm'] in e['consumed_commitment_candidates'],f'true note excluded at {e["step"]}'
                assert a['origin'] in e['deposit_origin_candidates'],f'true origin excluded at {e["step"]}'
                assert a['born'] in e['source_transaction_candidates'],f'true creating transaction excluded at {e["step"]}'
            nt=[len(e['source_transaction_candidates']) for e in events]
            nc=[len(e['consumed_commitment_candidates']) for e in events];nr=[len(e['deposit_origin_candidates']) for e in events]
            called=[e for e in events if len(e['recency_candidates'])==1]
            result[name][group]={'count':len(events),'truth_in_all_candidates':True,'source_transaction_candidates':nt,'mean_source_transaction_candidates':mean(nt),'source_transaction_singletons':nt.count(1),'commitment_candidates':nc,'mean_commitment_candidates':mean(nc),'commitment_singletons':nc.count(1),'origin_candidates':nr,'mean_origin_candidates':mean(nr),'origin_singletons':nr.count(1),'recency_unique_calls':len(called),'recency_correct_calls':sum(actual[e['step']]['cm']==e['recency_candidates'][0] for e in called),'recency_ties':len(events)-len(called),'rows':[{'step':e['step'],'wallet':actual[e['step']]['wallet'],'candidate_transactions':len(e['source_transaction_candidates']),'candidate_commitments':len(e['consumed_commitment_candidates']),'candidate_origins':len(e['deposit_origin_candidates']),'whole_note_value_public':e['exact_input_value_sompi'] is not None} for e in events]}
    return {'arm':truth['arm'],'scope':'ground-truth scoring after blind inference; synthetic wallets are not independent people','horizons':result}


def validate_joint_and_amounts(truth,observed,amounts,chain):
    import z3
    from observe import Model,decode
    initial,events=decode(chain)
    replay={}
    for name,h in observed['horizons'].items():
        model=Model(initial,[e for e in events if e['step']<=h['through']])
        values={truth['initial']['cm']:int(truth['initial']['value'])}
        for e in truth['events']:
            if e['step']<=h['through']:
                for n in e['outputs']:values[n['cm']]=int(n['value'])
        indices={n['cm']:i for i,n in enumerate(model.notes)}
        assert set(values)==set(indices)
        for n in model.notes:model.s.add(n['v']==values[n['cm']])
        for e in truth['events']:
            if e['step'] in model.choices:model.s.add(model.choices[e['step']]==indices[e['spent_cm']])
        assert model.s.check()==z3.sat,'actual joint history violates public model'
        replay[name]={'true_joint_history_satisfies_model':True}
    true_inputs={e['step']:e['input_value'] for e in truth['events'] if e['mode']!=0}
    scores={}
    for name,h in amounts['horizons'].items():
        forced=[e for e in h['first_four'] if e['forced_sompi'] is not None]
        for e in forced:assert e['forced_sompi']==true_inputs[e['step']],'incorrect forced amount'
        scores[name]={'tested':len(h['first_four']),'uniquely_inferred_inputs':len(forced),'correct_inferences':len(forced),'non_unique_inputs':len(h['first_four'])-len(forced),'directly_visible_inputs':sum(e['direct'] for e in h['first_four'])}
    return {'joint_history':replay,'amounts':scores}


def main():
    p=argparse.ArgumentParser();p.add_argument('truth',type=Path);p.add_argument('observed',type=Path);p.add_argument('output',type=Path);p.add_argument('--chain',type=Path);p.add_argument('--amounts',type=Path);a=p.parse_args()
    truth_bytes=a.truth.read_bytes();ob=a.observed.read_bytes();result=score(json.loads(truth_bytes),json.loads(ob));result['truth_sha256']=hashlib.sha256(truth_bytes).hexdigest();result['observer_sha256']=hashlib.sha256(ob).hexdigest()
    if a.chain or a.amounts:
        assert a.chain and a.amounts
        chain_raw=a.chain.read_bytes();amount_raw=a.amounts.read_bytes();amounts=json.loads(amount_raw)
        assert hashlib.sha256(chain_raw).hexdigest()==json.loads(ob)['chain_sha256']==amounts['chain_sha256']
        result['supplement']=validate_joint_and_amounts(json.loads(truth_bytes),json.loads(ob),amounts,json.loads(chain_raw))
        result['amounts_sha256']=hashlib.sha256(amount_raw).hexdigest()
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
