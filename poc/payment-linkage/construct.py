"""Public-only SAT witness search, never an extra model/ownership constraint.

A successful assignment is checked against the unsimplified integer ledger.
This deliberately incomplete two-chain template may FAIL to find a witness;
that failure says nothing about satisfiability and always falls back to SMT.
No generator, truth, role-owner map, keys, seeds, files or randomness are inputs.
"""
import itertools
import math
from certificate import check,BadCertificate
from schema import FLOOR

class Search:
    def __init__(self,ledger):
        self.l=ledger;self.parts={};self.cache={}
        self.roots=sorted((n for n in ledger.notes.values() if n.value is not None),key=lambda n:n.birth)
        self.p0=[e for e in ledger.events if e.kind=='private' and not e.payout]
        self.native=[e for e in ledger.events if e.payout];self.by_e={e.ordinal:e for e in self.native}
        self.groups=[];self.wide=False;self.closed=ledger.events[-1].reserve==0
        if not 1<=len(self.roots)<=2:return
        count=len(self.roots)
        if len(self.p0)==count and (not self.closed or sum(len(e.notes) for e in self.p0)==len(self.native)):
            self.groups=[[e] for e in self.p0];self.wide=True
        elif self.p0 and all(e.mode==2 for e in self.p0) and (not self.closed or len(self.p0)==len(self.native)) and len(self.p0)%count==0:
            width=len(self.p0)//count;self.groups=[self.p0[i*width:(i+1)*width] for i in range(count)]
        if any(g[0].ordinal<e.ordinal<g[-1].ordinal for g in self.groups for e in self.native):self.groups=[]
        self.position_group={p:g for g,events in enumerate(self.groups) for e in events for p in e.notes}
        self.anchor={r['position']:ledger.nf_spends[r['position']] for r in ledger.participants}
        if any(p not in self.position_group or self.closed and e is None or e is not None and e not in self.by_e
               for p,e in self.anchor.items()):self.groups=[]

    def _subset(self,items,count,target):
        if count==0:return [] if target==0 else None
        if count<0 or count>len(items) or target<0:return None
        if count==len(items):return [i for i,_ in items] if sum(v for _,v in items)==target else None
        # Equal-cardinality credit subtraction gives a compact exact sum domain.
        credit=self.l.public['exit_credit_sompi'];weights=[v-credit for _,v in items];target-=count*credit
        if min(weights)<0 or target<0:return None
        unit=math.gcd(target,*weights)
        if unit==0:return [i for i,_ in items[:count]]
        target//=unit;weights=[v//unit for v in weights]
        if target>1_000_000:return None # Search bound, never UNSAT or a scope rejection.
        if (len(items)+1)*(count+1)*(target+1)>1_000_000_000:return None # Bound DP history bits.
        mask=(1<<(target+1))-1;dp=[1]+[0]*count;history=[tuple(dp)]
        for weight in weights:
            # Masking AFTER an enormous shift does not bound its temporary size.
            # A nonnegative weight above target can never occur in a solution.
            if weight<=target:
                for k in range(count,0,-1):dp[k]|=(dp[k-1]<<weight)&mask
            history.append(tuple(dp))
        if not (dp[count]>>target)&1:return None
        chosen=[];k=count;remaining=target
        for i in range(len(items)-1,-1,-1):
            if (history[i][k]>>remaining)&1:continue
            w=weights[i]
            if remaining<w or not (history[i][k-1]>>(remaining-w))&1:return None
            chosen.append(items[i][0]);remaining-=w;k-=1
            if not k:break
        return chosen if k==0 and remaining==0 else None

    def build(self,force=None,root_order=None):
        key=(force,root_order)
        if key in self.cache:return self.cache[key]
        self.cache[key]=None
        if not self.groups:return None
        if not self.closed:
            found=self._open_build(force,root_order);self.cache[key]=found;return found
        if root_order is None:
            for order in itertools.permutations(range(len(self.roots))):
                found=self.build(force,order)
                if found is not None:self.cache[key]=found;return found
            return None
        if any(self.roots[root_order[g]].birth>=events[0].ordinal for g,events in enumerate(self.groups)):return None
        anchors=dict(self.anchor)
        if force is not None:
            event,position=force
            if position not in self.position_group or event not in self.by_e:return None
            if position in anchors and anchors[position]!=event:return None
            if event in anchors.values() and next(p for p,e in anchors.items() if e==event)!=position:return None
            anchors[position]=event
        required=[set() for _ in self.groups]
        for p,e in anchors.items():required[self.position_group[p]].add(e)
        for e in self.native:
            allowed=[g for g,events in enumerate(self.groups) if events[-1].ordinal<e.ordinal]
            if not allowed:return None
            if len(allowed)==1:required[allowed[0]].add(e.ordinal)
        if len(required)==2 and required[0]&required[1]:return None
        capacities=[len(events[0].notes) if self.wide else len(events) for events in self.groups]
        if any(len(required[g])>capacities[g] for g in range(len(self.groups))):return None
        targets=[self.roots[root_order[g]].value-sum(e.fee for e in events) for g,events in enumerate(self.groups)]
        values={e.ordinal:e.payout+e.fee for e in self.native}
        partkey=(root_order,tuple(tuple(sorted(x)) for x in required))
        if partkey in self.parts:parts=self.parts[partkey]
        else:
            if len(self.groups)==1:
                part=set(values);parts=[part] if len(part)==capacities[0] and sum(values.values())==targets[0] else None
            else:
                unused=[(e,values[e]) for e in sorted(values) if e not in required[0] and e not in required[1]]
                chosen=self._subset(unused,capacities[0]-len(required[0]),targets[0]-sum(values[e] for e in required[0]))
                parts=None
                if chosen is not None:
                    a=required[0]|set(chosen);b=set(values)-a
                    if len(b)==capacities[1] and sum(values[e] for e in b)==targets[1]:parts=[a,b]
            self.parts[partkey]=parts
        if parts is None:return None
        output_values={p:0 for p in self.l.notes};choices={};native_choice={}
        for root in self.roots:output_values[root.position]=root.value
        for g,events in enumerate(self.groups):
            root=self.roots[root_order[g]];remaining=set(parts[g]);local={p:e for p,e in anchors.items() if self.position_group[p]==g}
            if self.wide:
                choices[events[0].ordinal]=root.position
                for p,e in local.items():
                    if e not in remaining:return None
                    output_values[p]=values[e];native_choice[e]=p;remaining.remove(e)
                free=[p for p in events[0].notes if p not in local]
                if len(free)!=len(remaining):return None
                for p,e in zip(free,sorted(remaining),strict=True):output_values[p]=values[e];native_choice[e]=p
            else:
                current=root.position;reserved=set(local.values())
                for index,event in enumerate(events):
                    own=[p for p in event.notes if p in local]
                    if len(own)>1:return None
                    leaf=own[0] if own else event.notes[0]
                    change=next(p for p in event.notes if p!=leaf)
                    if own:e=local[leaf]
                    else:
                        free=sorted(remaining-reserved)
                        if not free:return None
                        e=free[0]
                    if e not in remaining or event.ordinal>=e:return None
                    choices[event.ordinal]=current;output_values[leaf]=values[e]
                    output_values[change]=output_values[current]-event.fee-values[e]
                    if output_values[change]<0 or (output_values[change] and output_values[change]<FLOOR):return None
                    if index<len(events)-1 and output_values[change]<FLOOR:return None
                    native_choice[e]=leaf;remaining.remove(e);reserved.discard(e);current=change
                if remaining or output_values[current]!=0:return None
        choices.update(native_choice)
        cert={'values':[{'position':p,'value_sompi':output_values[p]} for p in sorted(output_values)],
              'selected_positions':[{'event':e.ordinal,'position':choices[e.ordinal]} for e in self.l.events if e.kind=='private']}
        try:check(self.l,cert)
        except (BadCertificate,KeyError):return None
        if force is not None and choices[force[0]]!=force[1]:return None
        self.cache[key]=cert;return cert

    def _open_build(self,force,root_order):
        # One legal public arithmetic assignment for an open prefix, with unknown
        # outputs filled from available public slack. No claim of completeness.
        if root_order is None:
            for order in itertools.permutations(range(len(self.roots))):
                found=self._open_build(force,order)
                if found is not None:return found
            return None
        if any(self.roots[root_order[g]].birth>=events[0].ordinal for g,events in enumerate(self.groups)):return None
        participant={r['position']:r for r in self.l.participants}
        anchors={p:e for p,e in self.anchor.items() if e is not None}
        if force is not None:
            event,position=force
            if position not in self.position_group or event not in self.by_e:return None
            if position in participant and self.anchor[position]!=event:return None
            if event in anchors.values() and next(p for p,e in anchors.items() if e==event)!=position:return None
            anchors[position]=event
        values={p:0 for p in self.l.notes};choices={};native_choice={}
        for r in self.roots:values[r.position]=r.value
        groups_native=[[] for _ in self.groups]
        for e in self.native:
            fixed=next((self.position_group[p] for p,v in anchors.items() if v==e.ordinal),None)
            allowed=[g for g,events in enumerate(self.groups) if events[-1].ordinal<e.ordinal]
            if fixed is not None:
                if fixed not in allowed:return None
                g=fixed
            elif allowed:g=allowed[0]
            else:return None
            groups_native[g].append(e.ordinal)
        for g,events in enumerate(self.groups):
            root=self.roots[root_order[g]];target=root.value-sum(e.fee for e in events)
            available=list(groups_native[g]);leaf_positions=[];leaf_event={};fixed_values={}
            if self.wide:leaf_positions=list(events[0].notes)
            else:
                for event in events:
                    known=[p for p in event.notes if p in participant or p in anchors]
                    if len(known)>1:return None
                    p=known[0] if known else event.notes[0]
                    leaf_positions.append(p);leaf_event[p]=event
            for p in leaf_positions:
                if p in participant:fixed_values[p]=participant[p]['value_sompi']
                if p in anchors:
                    e=anchors[p]
                    if e not in available:return None
                    v=self.by_e[e].payout+self.by_e[e].fee
                    if p in fixed_values and fixed_values[p]!=v:return None
                    fixed_values[p]=v;native_choice[e]=p;available.remove(e)
            free=[p for p in leaf_positions if p not in fixed_values]
            for e in available:
                if not free:return None
                p=free.pop(0);fixed_values[p]=self.by_e[e].payout+self.by_e[e].fee;native_choice[e]=p
            remaining=target-sum(fixed_values.values())
            if free:
                if remaining<len(free)*FLOOR:return None
                for p in free:fixed_values[p]=FLOOR
                fixed_values[free[-1]]+=remaining-len(free)*FLOOR
            elif remaining!=0:return None
            if self.wide:
                choices[events[0].ordinal]=root.position
                for p in leaf_positions:values[p]=fixed_values[p]
            else:
                current=root.position
                for event,p in zip(events,leaf_positions,strict=True):
                    change=next(q for q in event.notes if q!=p)
                    choices[event.ordinal]=current;values[p]=fixed_values[p]
                    values[change]=values[current]-event.fee-values[p]
                    if values[change]<0 or values[change] and values[change]<FLOOR:return None
                    if event!=events[-1] and values[change]<FLOOR:return None
                    current=change
                if values[current]!=0:return None
        choices.update(native_choice)
        try:
            cert={'values':[{'position':p,'value_sompi':values[p]} for p in sorted(values)],
                  'selected_positions':[{'event':e.ordinal,'position':choices[e.ordinal]} for e in self.l.events if e.kind=='private']}
            check(self.l,cert)
        except (BadCertificate,KeyError):return None
        if force is not None and choices[force[0]]!=force[1]:return None
        return cert

    def with_changed_value(self,position,baseline):
        for order in itertools.permutations(range(len(self.roots))):
            cert=self.build(root_order=order)
            if cert is not None:
                info=check(self.l,cert)
                if info['values'][position]!=baseline:return cert
                changed=self._change_serial_leaf_assignment(cert,position,baseline)
                if changed is not None:return changed
        return None

    def _change_serial_leaf_assignment(self,cert,position,baseline):
        # A second PUBLIC arithmetic certificate can permute unanchored native
        # values among serial leaves and recompute the intervening change. This
        # is a SAT-only incomplete template, never a claim that all worlds fit it.
        if self.wide or not self.closed:return None
        info=check(self.l,cert);native_by_position={info['choices'][e.ordinal]:e.ordinal for e in self.native}
        protected=set(self.anchor)
        for events in self.groups:
            leaves=[p for event in events for p in event.notes if p in native_by_position and p not in protected]
            for a,b in itertools.combinations(leaves,2):
                if info['values'][a]==info['values'][b]:continue
                values=dict(info['values']);choices=dict(info['choices'])
                values[a],values[b]=values[b],values[a]
                choices[native_by_position[a]],choices[native_by_position[b]]=b,a
                valid=True
                for event in events:
                    leaf=next((p for p in event.notes if p in native_by_position),None)
                    if leaf is None:valid=False;break
                    change=next(p for p in event.notes if p!=leaf)
                    values[change]=values[choices[event.ordinal]]-event.fee-values[leaf]
                    if values[change]<0 or values[change] and values[change]<FLOOR:valid=False;break
                if not valid or values[position]==baseline:continue
                alternative={'values':[{'position':p,'value_sompi':values[p]} for p in sorted(values)],
                    'selected_positions':[{'event':e.ordinal,'position':choices[e.ordinal]} for e in self.l.events if e.kind=='private']}
                try:check(self.l,alternative)
                except (BadCertificate,KeyError):continue
                return alternative
        return None

    def with_source(self,event,source):
        for order in itertools.permutations(range(len(self.roots))):
            for g,events in enumerate(self.groups):
                if self.roots[order[g]].source!=source:continue
                for p in events[0].notes if self.wide else [p for e in events for p in e.notes]:
                    c=self.build((event,p),order)
                    if c is not None:return c
        return None
