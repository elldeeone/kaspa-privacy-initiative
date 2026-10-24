"""Public-only finite-control observer. No truth/owner map, file or key input."""
import json
import sys
import z3
from ledger import decode,parse,digest,check,MAX,FLOOR

TIMEOUT_MS=300_000
MEMORY_MB=4096

class Model:
    def __init__(self,ledger,backend=None):
        self.l=ledger;self.backend=backend;self.s=z3.Solver();self.s.set(timeout=TIMEOUT_MS,max_memory=MEMORY_MB,threads=1,random_seed=0)
        self.v={p:z3.Int('v'+str(p)) for p in ledger.notes};self.select={};self.used={p:[] for p in ledger.notes};self.certs={};self.calls=0;self.unknown=False
        same={};liability=z3.IntVal(0)
        for p,n in ledger.notes.items():
            self.s.add(self.v[p]<=MAX,z3.Or(self.v[p]==0,self.v[p]>=FLOOR))
            if n.value is not None:self.s.add(self.v[p]==n.value)
            if n.cm in same:self.s.add(self.v[p]==self.v[same[n.cm]])
            else:same[n.cm]=p
        for e in ledger.events:
            outputs=[self.v[o['position']] for o in e['outputs']];total_out=z3.Sum(outputs) if outputs else z3.IntVal(0)
            if e['kind']=='ingress':liability+=total_out
            else:
                ss={p:z3.Bool(f"s{e['ordinal']}_{p}") for p,n in ledger.notes.items() if n.birth<e['ordinal']};self.select[e['ordinal']]=ss
                self.s.add(z3.PbGe([(s,1) for s in ss.values()],1),z3.PbLe([(s,1) for s in ss.values()],ledger.public['max_real_inputs']))
                for p,selected in ss.items():self.s.add(z3.Implies(selected,self.v[p]>=FLOOR));self.used[p].append(selected)
                amount=z3.Sum([z3.If(selected,self.v[p],0) for p,selected in ss.items()])
                self.s.add(amount<=MAX,amount<=e['reserve_before'],amount==total_out+e['payout']+e['fee'])
                if not e['payout']:self.s.add(z3.Or([v>0 for v in outputs]))
                if e['mode']==32 and ledger.public['wallet_policy']=='wide32-single-issuer':self.s.add(*[v>=FLOOR for v in outputs])
                if e['mode']==2 and not e['payout'] and ledger.public['wallet_policy']=='one-invoice-positive-change':self.s.add(*[v>=FLOOR for v in outputs])
                liability+=total_out-amount
            self.s.add(liability==e['reserve_after'])
        for rows in self.used.values():
            if rows:self.s.add(z3.PbLe([(r,1) for r in rows],1))
        for r in ledger.records:
            p=r['position'];self.s.add(self.v[p]==r['value']);expected=ledger.nf_spends[p]
            for i,ss in self.select.items():
                if p in ss:self.s.add(ss[p] if i==expected else z3.Not(ss[p]))
        for r in ledger.public['outgoing_invoices']:self.s.add(self.v[r['position']]==r['value'])
        # No counterparty-to-origin, hidden owner or source-map constraints.

    def solve(self,predicate=None,query=None):
        if self.unknown:return {'status':'UNKNOWN','reason':'NOT_EVALUATED_AFTER_FIRST_UNKNOWN'}
        self.calls+=1;self.s.push()
        try:
            if predicate is not None:self.s.add(predicate)
            try:status=self.backend(self.s) if self.backend else self.s.check()
            except z3.Z3Exception as error:
                if not any(w in str(error).lower() for w in ('out of memory','max. memory exceeded')):raise
                self.unknown=True;return {'status':'UNKNOWN','reason':'solver-memory-limit'}
            if status==z3.unsat:return {'status':'UNSAT'}
            if status!=z3.sat:
                self.unknown=True;return {'status':'UNKNOWN','reason':self.s.reason_unknown()}
            m=self.s.model();cert={'values':[{'position':p,'value':m.eval(self.v[p],model_completion=True).as_long()} for p in sorted(self.v)],
                'inputs':[{'event':i,'positions':[p for p,b in ss.items() if z3.is_true(m.eval(b,model_completion=True))]} for i,ss in self.select.items()]}
            checked=check(self.l,cert);query=query or {'kind':'baseline'}
            if query['kind']=='select':assert query['position'] in checked['inputs'][query['event']]
            elif query['kind']=='exclude':assert query['position'] not in checked['inputs'][query['event']]
            else:assert query['kind']=='baseline'
            key=digest(cert);self.certs.setdefault(key,cert)
            return {'status':'SAT','certificate':key,'query':query}
        finally:self.s.pop()

    def run(self):
        base=self.solve();result={'baseline':base,'event_results':[]}
        if base['status']!='SAT':return dict(result,status='INCONSISTENT' if base['status']=='UNSAT' else 'INCOMPLETE',queries=self.calls,certificates=self.certs)
        for e in self.l.events:
            if e['kind']!='action':continue
            rows=[]
            for p in self.select[e['ordinal']]:
                yes=self.solve(self.select[e['ordinal']][p],{'kind':'select','event':e['ordinal'],'position':p})
                no=self.solve(z3.Not(self.select[e['ordinal']][p]),{'kind':'exclude','event':e['ordinal'],'position':p})
                rows.append({'position':p,'selected':yes,'excluded':no})
            result['event_results'].append({'event':e['ordinal'],'inputs':rows})
        complete=not self.unknown
        directory={f['source_id']:f['known_bootstrap_owner_role'] for f in self.l.public['funders']}
        changes={p:{directory[n.source]} for p,n in self.l.notes.items() if n.source is not None and directory[n.source] is not None}
        for r in self.l.records:changes.setdefault(r['position'],set()).add(self.l.public['participant_role'])
        for r in self.l.public['outgoing_invoices']:changes.setdefault(r['position'],set()).add(r['recipient_role'])
        if self.l.public['wallet_policy'] in ('one-invoice-sender-change','one-invoice-positive-change'):
            for r in self.l.records:
                birth=self.l.events[self.l.notes[r['position']].birth]
                if r['invoice_payer_role'] is not None and birth['kind']=='action' and birth['mode']==2 and not birth['payout']:
                    sibling=next(o['position'] for o in birth['outputs'] if o['position']!=r['position'])
                    changes.setdefault(sibling,set()).add(r['invoice_payer_role'])
        for row in result['event_results']:
            mandatory=[r['position'] for r in row['inputs'] if r['selected']['status']=='SAT' and r['excluded']['status']=='UNSAT'] if complete else []
            role_sets=[changes[p] for p in mandatory if p in changes and len(changes[p])==1]
            labels=set().union(*role_sets) if role_sets else set()
            possible=[r['position'] for r in row['inputs'] if r['selected']['status']=='SAT']
            if complete and not labels and possible and all(p in changes and len(changes[p])==1 for p in possible):labels=set().union(*(changes[p] for p in possible))
            row['mandatory_input_positions']=mandatory
            row['conditional_wallet_payer_role']=next(iter(labels)) if complete and len(labels)==1 and self.l.public['wallet_policy'] in ('one-invoice-sender-change','one-invoice-positive-change') else None
            row['role_inference_scope']='known one-payer wallet + positive sender change; NOT protocol/human identity'
        return dict(result,status='COMPLETE' if complete else 'INCOMPLETE',queries=self.calls,certificates=self.certs,
                    known_input_owner_facts=[{'position':p,'roles':sorted(r),'conditional_on_positive':True} for p,r in sorted(changes.items())])

def analyze(public,backend=None):
    ledger=decode(public);result=Model(ledger,backend).run()
    return dict(result,schema='independent-payment-public-analysis/v1',public_sha256=digest(public),
        classification='SYMBOLIC_INTEGER_CONTROL_NOT_CRYPTO_OR_NATIVE',privacy_qualification=False,
        owner_identity='NOT_MODELLED',one_or_two_real_inputs=public['max_real_inputs'],
        partial_native_outputs_permitted=True,source_role_equivalence_assumed=False)

if __name__=='__main__':
    try:print(json.dumps(analyze(parse(sys.stdin.buffer.read())),sort_keys=True,separators=(',',':')))
    except (ValueError,KeyError,TypeError) as error:
        print(json.dumps({'status':'REJECTED_INPUT','reason':str(error)}));raise SystemExit(2)
