#!/usr/bin/env python3
"""Supplement the frozen graph attack with exact-amount uniqueness checks.

A hidden input amount is inferred only if every feasible history gives the same
integer value. Two examples establish non-uniqueness, not the size of its range.
"""
import argparse
import hashlib
import json
import time
from pathlib import Path
import z3
from observe import Model,decode


def infer_input(model,event):
    direct=event['payout']+event['fee'] if event['mode'] in (2,3) else None
    if direct is not None:return {'forced_sompi':str(direct),'possible_examples_sompi':[str(direct)],'direct':True}
    choice=model.choices[event['step']]
    expr=z3.Sum([z3.If(choice==i,n['v'],0) for i,n in enumerate(model.notes)])
    model.s.push()
    try:
        assert model.s.check()==z3.sat
        value=model.s.model().eval(expr).as_long()
        model.s.add(expr!=value)
        alternative=model.s.check()
        if alternative==z3.unsat:return {'forced_sompi':str(value),'possible_examples_sompi':[str(value)],'direct':False}
        if alternative!=z3.sat:raise ValueError('unknown amount inference is not privacy')
        other=model.s.model().eval(expr).as_long();assert other!=value
        return {'forced_sompi':None,'possible_examples_sompi':[str(value),str(other)],'direct':False}
    finally:model.s.pop()


def analyze(chain):
    initial,events=decode(chain);withdrawals=[e for e in events if e['mode']>=2];cutoff=withdrawals[3]['step']
    out={}
    for name,through in [('first_four_withdrawals',cutoff),('fully_drained',events[-1]['step'])]:
        start=time.monotonic();model=Model(initial,[e for e in events if e['step']<=through])
        out[name]={'through':through,'seconds':0,'first_four':[{'step':e['step'],**infer_input(model,e)} for e in withdrawals[:4]]};out[name]['seconds']=time.monotonic()-start
    return {'method':'check for a second distinct consumed-note amount under the same public constraints','limitation':'examples are not bounds, probabilities or real-world anonymity','horizons':out}


def main():
    p=argparse.ArgumentParser();p.add_argument('chain',type=Path);p.add_argument('output',type=Path);a=p.parse_args();raw=a.chain.read_bytes();result=analyze(json.loads(raw));result['chain_sha256']=hashlib.sha256(raw).hexdigest()
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'output':str(a.output),'horizons':{n:{'through':h['through'],'seconds':h['seconds']} for n,h in result['horizons'].items()}}))
if __name__=='__main__':main()
