"""Independent incremental integer solver for the H14 public relation."""
import z3


class Z3Model:
    def __init__(self,data,floor=60_000_000,payout_floor=10_000_000,relaxed=False):
        # The framing parser is shared; the relation is independently encoded.
        from two_input_privacy_observer import decode, reverse_bounds
        self.births,self.upper=decode(data,floor,payout_floor)
        self.upper=reverse_bounds(data,self.births,self.upper)
        self.data=data;self.solver=z3.Solver();self.queries=0
        sort=z3.Real if relaxed else z3.Int
        self.values=[sort(f'v{p}') for p in range(len(self.upper))]
        self.select={};uses=[[] for _ in self.values]
        for v,ub in zip(self.values,self.upper,strict=True):
            self.solver.add(v<=ub,z3.Or(v==0,v>=floor))
        self.solver.add(self.values[0]==data['initial']['value'])
        for i,e in enumerate(data['events']):
            output=z3.Sum([self.values[p] for p in e['new']])
            if e['mode']==0:self.solver.add(output==e['deposit']-e['fee']);continue
            selected=[z3.Bool(f's{i}_{p}') for p in range(e['anchor_count'])];self.select[i]=selected
            self.solver.add(z3.PbGe([(s,1) for s in selected],1),z3.PbLe([(s,1) for s in selected],2))
            for p,s in enumerate(selected):
                self.solver.add(z3.Implies(s,self.values[p]>=floor));uses[p].append(s)
            self.solver.add(z3.Sum([z3.If(s,self.values[p],0) for p,s in enumerate(selected)])==output+e['payout']+e['fee'])
        for p,choices in enumerate(uses):
            if choices:self.solver.add(z3.PbLe([(s,1) for s in choices],1))
            if data['events'][-1]['reserve_out']==0:
                self.solver.add((self.values[p]>0)==z3.Or(choices))


        # Redundant public conservation cuts: two sibling notes can be consumed
        # by at most two later transactions, or remain in the final reserve.
        # Historical counts include whole output pairs. Each bucket's budget
        # overestimates what this pair alone could contribute, so these are
        # upper bounds implied by the original integer relation, not new policy.
        totals={}
        for i in reversed(range(len(data['events']))):
            e=data['events'][i]
            if not e['new']:
                totals[i]=0
                continue
            budgets=[data['events'][-1]['reserve_out']]
            for j,f in enumerate(data['events']):
                if j>i and f['mode']!=0 and f['anchor_count']>e['new'][0]:
                    budgets.append(totals[j]+f['payout']+f['fee'])
            totals[i]=min(sum(self.upper[p] for p in e['new']),sum(sorted(budgets,reverse=True)[:2]))
            self.solver.add(z3.Sum([self.values[p] for p in e['new']])<=totals[i])
        # The transaction equations imply these identities, but writing them
        # explicitly avoids expensive rediscovery after intermediate exits.
        for cut,e in enumerate(data['events']):
            remaining=[]
            for p in range(e['count_before']+len(e['new'])):
                used=z3.Or([ss[p] for i,ss in self.select.items() if i<=cut and p<len(ss)])
                remaining.append(z3.If(used,0,self.values[p]))
            self.solver.add(z3.Sum(remaining)==e['reserve_out'])

    def check(self,target=None,combo=None):
        from two_input_privacy_observer import need
        assumptions=[]
        if target is not None:
            need(1<=len(combo)<=2 and len(set(combo))==len(combo) and all(0<=p<len(self.select[target]) for p in combo),'selection framing')
            assumptions=[s if p in combo else z3.Not(s) for p,s in enumerate(self.select[target])]
        status=self.solver.check(*assumptions);self.queries+=1
        need(status in (z3.sat,z3.unsat),f'non-conclusive Z3 status {status}')
        return status==z3.sat

    def candidates(self,target,allowed=None):
        from two_input_privacy_observer import possibilities
        return [c for c in (possibilities(self.data['events'][target]) if allowed is None else allowed) if self.check(target,c)]
