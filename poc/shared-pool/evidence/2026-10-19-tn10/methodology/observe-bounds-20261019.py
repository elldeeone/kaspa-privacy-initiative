#!/usr/bin/env python3
"""Chain-only feasible-history attack. No wallets, manifest, labels or truth input.

Candidates are logically possible under the modeled public constraints, not
posterior probabilities or an anonymity guarantee. No fee/timing distribution is
assumed. Chronology uses the reserve's spend order, not local RPC arrival time.
"""
import argparse
import hashlib
import json
import time
from pathlib import Path
import z3
CAP=24
STATE_LEN=3+64*CAP
CIPHER_START=9+STATE_LEN
MAX_SOMPI=2_900_000_000_000_000_000


def state(raw):
    assert len(raw)==STATE_LEN and raw[0]==2
    nc,nn=raw[1:3]
    assert 1<=nc<=CAP and nn<=nc
    cm=[raw[3+i*32:35+i*32].hex() for i in range(nc)]
    nf=[raw[3+32*CAP+i*32:35+32*CAP+i*32].hex() for i in range(nn)]
    assert len(set(cm))==nc and len(set(nf))==nn
    assert not any(raw[3+32*nc:3+32*CAP])
    assert not any(raw[3+32*CAP+32*nn:])
    return cm,nf


def decode(chain):
    assert set(chain)=={'schema','network','transactions'}
    assert chain['schema']=='kpi-shared-pool-chain-v2' and chain['network']=='testnet-10'
    rows=chain['transactions'];assert len(rows)>2
    events=[];previous=None;domain=None;initial=None
    ledger={}
    for row in rows:
        assert set(row)=={'step','tx','inputs'}
        step=row['step'];tx=row['tx'];ins=row['inputs']
        assert step==len(events)+2 if step>=2 else step in (0,1)
        assert set(tx)=={'version','id','inputs','outputs','lockTime','subnetworkId','gas','payload','storageMass'}
        assert len(ins)==len(tx['inputs'])
        for inp,ctx in zip(tx['inputs'],ins):
            assert set(ctx)=={'txid','index','amount','spk','daa','is_coinbase'}
            assert inp['previousOutpoint']=={'transactionId':ctx['txid'],'index':ctx['index']}
            key=(ctx['txid'],ctx['index'])
            if step==0:ledger[key]=(int(ctx['amount']),ctx['spk'])
            assert ledger.pop(key)==(int(ctx['amount']),ctx['spk'])
        for i,o in enumerate(tx['outputs']):
            assert o['covenant'] is None and 0<int(o['value'])<=MAX_SOMPI
            ledger[(tx['id'],i)]=(int(o['value']),o['scriptPublicKey'])
        fee=sum(int(x['amount']) for x in ins)-sum(int(x['value']) for x in tx['outputs'])
        assert fee>0
        if step<2:
            assert tx['payload']==''
            if step==1: previous=(tx['id'],0)
            continue
        payload=bytes.fromhex(tx['payload']);witness=bytes.fromhex(tx['inputs'][0]['signatureScript'])
        assert len(payload)==CIPHER_START+370 and payload[:8]==b'KPISP02\0'
        assert len(witness)==4229 and witness[:2]==bytes([0x4c,128]) and witness[130:133]==bytes([0x4d,0,16])
        redeem=witness[133:];d=redeem[1:33]
        old_cm,old_nf=state(redeem[37:37+STATE_LEN]);cm,nf=state(payload[9:CIPHER_START]);mode=payload[8]
        assert mode in range(5)
        assert (ins[0]['txid'],ins[0]['index'])==previous
        if initial is None:
            assert len(old_cm)==1 and len(old_nf)==0 and mode==1
            domain=d;initial={'cm':old_cm[0],'value':int(ins[0]['amount']),'born':1,'origin':old_cm[0]}
        else:
            assert d==domain and old_cm==events[-1]['state_cm'] and old_nf==events[-1]['state_nf']
        count=2 if mode==1 else 1 if mode in (0,4) else 0
        assert cm[:len(old_cm)]==old_cm and len(cm)==len(old_cm)+count
        assert nf[:len(old_nf)]==old_nf and len(nf)==len(old_nf)+(mode!=0)
        assert len(ins)==(2 if mode==0 else 1)
        assert len(tx['outputs'])==(2 if mode in (2,4) else 1)
        payout=int(tx['outputs'][0 if mode==3 else 1]['value']) if mode>=2 else 0
        reserve_out=0 if mode==3 else int(tx['outputs'][0]['value'])
        deposit=int(ins[1]['amount']) if mode==0 else 0
        assert int(ins[0]['amount'])+deposit==reserve_out+payout+fee
        events.append({'step':step,'mode':mode,'fee':fee,'payout':payout,'deposit':deposit,'reserve_out':reserve_out,'new_cm':cm[len(old_cm):],'state_cm':cm,'state_nf':nf})
        previous=None if mode==3 else (tx['id'],0)
    return initial,events


class Model:
    def __init__(self,initial,events):
        self.s=z3.Solver();self.notes=[];self.events=events;self.choices={};self.roots=[]
        self.add_note(initial['cm'],1,int(initial['value']),0)
        self.roots.append(initial['cm'])
        spent=[]
        for e in events:
            step=e['step'];mode=e['mode']
            prior=list(self.notes)
            if mode==0:
                root=len(self.roots);self.roots.append(e['new_cm'][0])
                self.add_note(e['new_cm'][0],step,e['deposit']-e['fee'],root)
            else:
                ch=z3.Int(f'input_{step}');self.choices[step]=ch
                self.s.add(z3.Or([ch==i for i in range(len(prior))]))
                for previous in spent:self.s.add(ch!=previous)
                spent.append(ch)
                # Redundant interval bound: every child is at most the largest
                # possible parent minus the public fee/payout and one unit
                # for each positive sibling. This preserves all histories
                # while making impossible large-value candidates cheap.
                upper=max(n['upper'] for n in prior)-e['payout']-e['fee']-max(0,len(e['new_cm'])-1)
                new=[self.add_note(cm,step,upper=upper) for cm in e['new_cm']]
                total=sum((x['v'] for x in new),z3.IntVal(e['payout']+e['fee']))
                for i,n in enumerate(prior):
                    self.s.add(z3.Implies(ch==i,n['v']==total))
                    for out in new:self.s.add(z3.Implies(ch==i,out['root']==n['root']))
            # Native reserve is the sum of remaining private claims. This is
            # derivable from genesis and every value-conserving transition.
            remaining=[z3.If(z3.And([c!=i for c in spent]),n['v'],0) for i,n in enumerate(self.notes)]
            self.s.add(z3.Sum(remaining)==e['reserve_out'])
        self.base=self.s.check()
        if self.base!=z3.sat:raise ValueError(f'public history is {self.base}, not a candidate set')

    def add_note(self,cm,born,value=None,root=None,upper=MAX_SOMPI):
        i=len(self.notes);assert all(n['cm']!=cm for n in self.notes)
        n={'cm':cm,'born':born,'v':z3.Int(f'value_{i}'),'root':z3.Int(f'root_{i}'),'upper':value if value is not None else upper}
        self.s.add(n['v']>=1,n['v']<=MAX_SOMPI,n['v']<=n['upper'])
        if value is not None:self.s.add(n['v']==value)
        if root is not None:self.s.add(n['root']==root)
        self.notes.append(n);return n

    def possible(self,condition):
        self.s.push();self.s.add(condition);result=self.s.check();self.s.pop()
        if result==z3.unknown:raise ValueError('solver unknown; do not count as privacy')
        return result==z3.sat

    def attacks(self):
        out=[]
        for e in self.events:
            if e['mode']==0:continue
            ch=self.choices[e['step']]
            candidates=[i for i,n in enumerate(self.notes) if n['born']<e['step'] and self.possible(ch==i)]
            roots=[root for root in range(len(self.roots)) if self.possible(z3.Or([z3.And(ch==i,self.notes[i]['root']==root) for i in candidates]))]
            assert candidates and roots
            latest=max(self.notes[i]['born'] for i in candidates)
            recent=[self.notes[i]['cm'] for i in candidates if self.notes[i]['born']==latest]
            out.append({'step':e['step'],'mode':e['mode'],'payout_sompi':str(e['payout']),
                        'consumed_commitment_candidates':[self.notes[i]['cm'] for i in candidates],
                        'deposit_origin_candidates':[self.roots[r] for r in roots],
                        'source_transaction_candidates':sorted({self.notes[i]['born'] for i in candidates}),
                        'recency_candidates':recent,
                        'exact_input_value_sompi':str(e['payout']+e['fee']) if e['mode'] in (2,3) else None})
        return out


def analyze(chain):
    initial,events=decode(chain)
    withdrawals=[e['step'] for e in events if e['mode']>=2]
    assert len(withdrawals)>=4
    first=withdrawals[3]
    horizons={'bootstrap':2,'first_four_withdrawals':first,'fully_drained':events[-1]['step']}
    assert events[-1]['mode']==3
    results={}
    for name,through in horizons.items():
        started=time.monotonic();model=Model(initial,[e for e in events if e['step']<=through]);attacks=model.attacks()
        results[name]={'through':through,'seconds':time.monotonic()-started,'events':attacks}
    return {'method':'integer conservation and temporal marginal candidates; recency tie set',
            'assumptions':['valid accepted protocol transitions','positive u64 note values within native range','one private input per non-deposit transition','public reserve spend order only','no private schedule, ownership, wallet policy, RPC clients or traffic distribution'],
            'limitations':['candidate counts are not probabilities or real-user anonymity','does not exploit cryptographic implementation flaws','no mempool arrival times, network/RPC observation, or external identity data'],
            'solver':z3.get_version_string(),'horizons':results}


def main():
    p=argparse.ArgumentParser();p.add_argument('chain',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    raw=a.chain.read_bytes();result=analyze(json.loads(raw));result['chain_sha256']=hashlib.sha256(raw).hexdigest()
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'output':str(a.output),'horizons':{n:{'through':h['through'],'seconds':h['seconds']} for n,h in result['horizons'].items()}}))
if __name__=='__main__':main()
