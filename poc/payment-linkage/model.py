"""Exact conditional integer relation. SAT is not cryptographic anonymity."""
import copy
import z3
from schema import MAX,FLOOR,digest
from certificate import check,swap
from construct import Search

TIMEOUT_MS=120_000
MEMORY_MB=2048 # Per-view operational bound returns UNKNOWN, never privacy success.
MAX_QUERIES=300_000

def total(items):return z3.Sum(items) if items else z3.IntVal(0)

class Model:
    def __init__(self,ledger,*,group=True,backend=None):
        self.ledger=ledger;self.search=Search(ledger);self.solver=z3.Solver();self.solver.set(timeout=TIMEOUT_MS,random_seed=0,threads=1,max_memory=MEMORY_MB)
        self.queries=0;self.blocked_unknown=False;self.certificates={};self.backend=backend;self.groups=[];self.select={};self.inputs={};self.source={}
        self.values={p:z3.Int('value_'+str(p)) for p in ledger.notes}
        self.origins={p:z3.Int('origin_'+str(p)) for p in ledger.notes}
        self.grouping_enabled=group and not ledger.repeated_cm
        uses={p:[] for p in ledger.notes};same_cm={};liability=z3.IntVal(0)
        for p,n in ledger.notes.items():
            v=self.values[p];self.solver.add(v<=MAX,z3.Or(v==0,v>=FLOOR))
            if n.value is not None:self.solver.add(v==n.value)
            if n.cm in same_cm:self.solver.add(v==self.values[same_cm[n.cm]])
            else:same_cm[n.cm]=p
        for e in ledger.events:
            outs=total([self.values[p] for p in e.notes])
            if e.kind=='ingress':
                self.solver.add(outs==e.ingress)
                self.solver.add(self.origins[e.notes[0]]==e.source)
                liability=liability+outs
                self.solver.add(liability==e.reserve)
                continue
            prior=[p for p,n in ledger.notes.items() if n.birth<e.ordinal]
            ss={p:z3.Bool(f'select_{e.ordinal}_{p}') for p in prior};self.select[e.ordinal]=ss
            self.solver.add(z3.PbEq([(s,1) for s in ss.values()],1))
            for p,s in ss.items():
                self.solver.add(z3.Implies(s,self.values[p]>=FLOOR));uses[p].append(s)
            consumed=total([z3.If(ss[p],self.values[p],0) for p in prior])
            origin=total([z3.If(ss[p],self.origins[p],0) for p in prior])
            self.inputs[e.ordinal]=consumed;self.source[e.ordinal]=origin
            self.solver.add(consumed==outs+e.payout+e.fee,consumed<=MAX,
                            consumed<=ledger.public['events'][e.ordinal]['prior_reserve_sompi'])
            if e.payout:
                for p in e.notes:self.solver.add(self.values[p]==0)
                # Entailed by exactly one selector, consumed equality and zero
                # private outputs; expose this cut for public-value propagation.
                for p,selected in ss.items():self.solver.add(z3.Implies(selected,self.values[p]==e.payout+e.fee))
            else:
                self.solver.add(z3.Or([self.values[p]>0 for p in e.notes]))
                policy=ledger.public['known_wallet_policy']
                if e.mode==32 and policy!='one_real_input_full_native_cashout':
                    for p in e.notes:self.solver.add(self.values[p]>=FLOOR)
                    if policy=='one_real_full_cashout_wide_positive_equal_current_demo':
                        for p in e.notes[1:]:self.solver.add(self.values[p]==self.values[e.notes[0]])
            for p in e.notes:self.solver.add(self.origins[p]==z3.If(self.values[p]>0,origin,-1))
            liability=liability+outs-consumed
            self.solver.add(liability==e.reserve)
        for selected in uses.values():
            if selected:self.solver.add(z3.PbLe([(s,1) for s in selected],1))
        for row in ledger.participants:
            p=row['position'];self.solver.add(self.values[p]==row['value_sompi'])
            expected=ledger.nf_spends[p]
            for ordinal,ss in self.select.items():
                if p in ss:self.solver.add(ss[p] if expected==ordinal else z3.Not(ss[p]))
            # A business counterparty is NOT an original funding source equation.
        self.public_lemmas=[]
        if ledger.events[-1].reserve==0:
            for p,v in self.values.items():
                selected=uses[p]
                self.solver.add(z3.Implies(v>0,z3.Or(selected) if selected else z3.BoolVal(False)))
            # Entailed only for this complete one-real/full-cashout relation:
            # every positive note is spent exactly once before terminal R0.
            p0=[e for e in ledger.events if e.kind=='private' and not e.payout]
            private=[e for e in ledger.events if e.kind=='private']
            ingress=[n for n in ledger.notes.values() if n.value is not None]
            p0_positions=[p for e in p0 for p in e.notes]
            needed=len(private)-len(ingress)
            self.solver.add(total([z3.If(self.values[p]>0,1,0) for p in p0_positions])==needed)
            if needed==len(p0_positions):
                for p in p0_positions:self.solver.add(self.values[p]>=FLOOR)
            native=[e for e in ledger.events if e.payout]
            roots=[n.position for n in ingress if not any(e.ordinal>n.birth and
                       e.payout+e.fee==n.value for e in native)]
            for p in roots:
                choices=[self.select[e.ordinal][p] for e in p0 if p in self.select[e.ordinal]]
                self.solver.add(z3.Or(choices) if choices else z3.BoolVal(False))
            all_p0_are_roots=len(roots)==len(p0)
            if len(roots)>len(p0):self.solver.add(z3.BoolVal(False))
            if all_p0_are_roots:
                for e in p0:
                    for p,selected in self.select[e.ordinal].items():
                        if p not in roots:self.solver.add(z3.Not(selected))
            last_p0=max((e.ordinal for e in p0),default=-1)
            finite=[]
            for p,n in ledger.notes.items():
                if n.birth>=last_p0 or all_p0_are_roots and p not in roots:
                    possibilities={0}|{e.payout+e.fee for e in native if e.ordinal>n.birth}
                    self.solver.add(z3.Or([self.values[p]==v for v in sorted(possibilities)]))
                    finite.append(p)
            self.public_lemmas=[{'kind':'terminal-positive-note-count','private_positive_count':needed},
                {'kind':'ingress-incompatible-with-native-must-P0','positions':roots},
                {'kind':'terminal-native-finite-values','positions':finite}]
        participant_positions={r['position'] for r in ledger.participants}
        grouped={}
        for p,n in ledger.notes.items():
            # A non-participant class has identical constraints except opaque labels.
            # Repeated hashes disable grouping globally; participant rows are singleton.
            flags=(not any(bytes.fromhex(n.ciphertext)),bool(bytes.fromhex(n.ciphertext)[31]&128))
            key=(n.birth,n.value,n.source,flags)
            if not self.grouping_enabled or p in participant_positions:key=('singleton',p)
            grouped.setdefault(key,[]).append(p)
        self.groups=list(grouped.values())

    def _record(self,cert):
        check(self.ledger,cert);key=digest(cert)
        self.certificates.setdefault(key,cert)
        return key

    def sat(self,cert,query=None):
        info=check(self.ledger,cert);query=query or {'kind':'baseline'}
        kind=query['kind']
        if kind=='select':assert info['choices'][query['event']]==query['position']
        elif kind=='source':assert info['native_sources'][query['event']]==query['source_id']
        elif kind=='note_value':assert info['values'][query['position']]!=query['baseline_value']
        elif kind=='input_value':assert info['values'][info['choices'][query['event']]]!=query['baseline_value']
        elif kind=='no_native':assert all(info['choices'][e.ordinal]!=query['position'] for e in self.ledger.events if e.payout)
        else:assert kind=='baseline'
        return {'status':'SAT','certificate_id':self._record(cert),'swap':None,
                'public_constructive_witness':True,'query':query}

    def solve(self,predicate=None,query=None):
        if self.blocked_unknown:return {'status':'UNKNOWN','reason':'NOT_EVALUATED_AFTER_FIRST_UNKNOWN'}
        self.queries+=1
        if self.queries>MAX_QUERIES:
            self.blocked_unknown=True;return {'status':'UNKNOWN','reason':'query-bound'}
        self.solver.push()
        try:
            if predicate is not None:self.solver.add(predicate)
            try:result=self.backend(self.solver) if self.backend is not None else self.solver.check()
            except z3.Z3Exception as error:
                if not any(text in str(error).lower() for text in ('out of memory','max. memory exceeded')):raise
                self.blocked_unknown=True
                return {'status':'UNKNOWN','reason':'per-view-solver-memory-limit'}
            if result==z3.unsat:return {'status':'UNSAT'}
            if result!=z3.sat:
                self.blocked_unknown=True
                return {'status':'UNKNOWN','reason':self.solver.reason_unknown() if result==z3.unknown else 'backend-status'}
            m=self.solver.model()
            cert={'values':[{'position':p,'value_sompi':m.eval(self.values[p],model_completion=True).as_long()}
                            for p in sorted(self.ledger.notes)],
                  'selected_positions':[{'event':ordinal,'position':next(p for p,s in ss.items()
                           if z3.is_true(m.eval(s,model_completion=True)))} for ordinal,ss in self.select.items()]}
            row=self.sat(cert,query);row['public_constructive_witness']=False;return row
        finally:self.solver.pop()

    def lifted(self,result,representative,member):
        row=dict(result)
        if result['status']=='SAT' and representative!=member:
            cert=swap(self.ledger,self.certificates[result['certificate_id']],representative,member)
            # Verify every actual lifted assignment, then store only the exact swap
            # recipe to avoid quadratic copies of the same public certificate.
            query=copy.deepcopy(result.get('query',{'kind':'baseline'}))
            if 'position' in query and query['position']==representative:query['position']=member
            self.sat(cert,query);row['query']=query;row['swap']=[representative,member]
        return row

    def candidate_rows(self,event):
        rows=[]
        for members in self.groups:
            eligible=[p for p in members if self.ledger.notes[p].birth<event.ordinal]
            if not eligible:continue
            representative=eligible[0]
            cert=None if self.blocked_unknown else self.search.build((event.ordinal,representative))
            query={'kind':'select','event':event.ordinal,'position':representative}
            result=self.sat(cert,query) if cert is not None else self.solve(self.select[event.ordinal][representative],query)
            for p in eligible:rows.append(dict(position=p,**self.lifted(result,representative,p)))
        return sorted(rows,key=lambda r:r['position'])

    def no_native_rows(self):
        native=[e for e in self.ledger.events if e.payout]
        result={}
        for members in self.groups:
            rep=members[0]
            uses=[self.select[e.ordinal][rep] for e in native if rep in self.select[e.ordinal]]
            native_used={self.base_checked['choices'][e.ordinal] for e in native}
            cert=None
            if not self.blocked_unknown:
                if rep not in native_used:cert=self.certificates[self.base['certificate_id']]
                else:
                    other=next((p for p in members if p not in native_used),None)
                    if other is not None:cert=swap(self.ledger,self.certificates[self.base['certificate_id']],rep,other)
            query={'kind':'no_native','position':rep}
            row=self.sat(cert,query) if cert is not None else self.solve(z3.Not(z3.Or(uses)) if uses else z3.BoolVal(True),query)
            for p in members:result[p]=self.lifted(row,rep,p)
        return result

    def value_rows(self):
        result={}
        for members in self.groups:
            rep=members[0];base=self.base_checked['values'][rep]
            other=next((p for p in members if self.base_checked['values'][p]!=base),None)
            cert=None if other is None or self.blocked_unknown else swap(self.ledger,self.certificates[self.base['certificate_id']],rep,other)
            if cert is None and not self.blocked_unknown:cert=self.search.with_changed_value(rep,base)
            query={'kind':'note_value','position':rep,'baseline_value':base}
            row=self.sat(cert,query) if cert is not None else self.solve(self.values[rep]!=base,query)
            for p in members:
                # Blocking the representative baseline is not a complete test for a
                # different member whose baseline value happens to differ. Such a
                # member already has a checked swapped counterexample without SMT.
                own=self.base_checked['values'][p]
                if p!=rep and own!=base and not self.blocked_unknown:
                    cert=swap(self.ledger,self.certificates[self.base['certificate_id']],rep,p)
                    result[p]=dict(self.sat(cert,{'kind':'note_value','position':p,'baseline_value':own}),
                                   baseline_value_sompi=own)
                else:result[p]=dict(self.lifted(row,rep,p),baseline_value_sompi=own)
        return result

    def run(self):
        cert=None if self.backend is not None else self.search.build()
        self.base=self.sat(cert) if cert is not None else self.solve()
        if self.base['status']!='SAT':return {'status':'INCONSISTENT' if self.base['status']=='UNSAT' else 'INCOMPLETE',
                                            'baseline':self.base,'queries':self.queries,'certificates':self.certificates}
        self.base_checked=check(self.ledger,self.certificates[self.base['certificate_id']])
        values=self.value_rows();no_native=self.no_native_rows();native=[]
        for e in self.ledger.events:
            if not e.payout:continue
            candidates=self.candidate_rows(e)
            sources=[]
            for source in self.ledger.source_ids:
                cert=None
                if not self.blocked_unknown:
                    cert=(self.certificates[self.base['certificate_id']] if self.base_checked['native_sources'][e.ordinal]==source
                          else self.search.with_source(e.ordinal,source))
                if cert is not None:
                    assert check(self.ledger,cert)['native_sources'][e.ordinal]==source
                query={'kind':'source','event':e.ordinal,'source_id':source}
                row=self.sat(cert,query) if cert is not None else self.solve(self.source[e.ordinal]==source,query)
                sources.append(dict(source_id=source,**row))
            baseline_value=self.base_checked['values'][self.base_checked['choices'][e.ordinal]]
            input_value=self.solve(self.inputs[e.ordinal]!=baseline_value,
                 {'kind':'input_value','event':e.ordinal,'baseline_value':baseline_value})
            sat=[r['position'] for r in candidates if r['status']=='SAT']
            unknown=any(r['status']=='UNKNOWN' for r in candidates)
            native.append({'event':e.ordinal,'candidates':candidates,'forced_input_position':sat[0]
                           if len(sat)==1 and not unknown else None,'source_candidates':sources,
                           'input_value_alternative':dict(input_value,baseline_value_sompi=baseline_value)})
        notes=[]
        for p,n in sorted(self.ledger.notes.items()):
            candidates=[]
            for row in native:
                match=next((r for r in row['candidates'] if r['position']==p),None)
                if match is not None:candidates.append(dict(event=row['event'],**match))
            positive=[r['event'] for r in candidates if r['status']=='SAT']
            unknown=any(r['status']=='UNKNOWN' for r in candidates) or no_native[p]['status']=='UNKNOWN'
            forced=positive[0] if len(positive)==1 and not unknown and no_native[p]['status']=='UNSAT' else None
            notes.append({'position':p,'cm':n.cm,'birth':n.birth,'private_born':self.ledger.events[n.birth].kind=='private',
                          'amount_alternative':values[p],'cashout_candidates':candidates,
                          'no_direct_cashout':no_native[p],'forced_cashout_event':forced})
        complete=not any(row['status']=='UNKNOWN' for row in values.values())
        complete=complete and not any(row['status']=='UNKNOWN' for row in no_native.values())
        complete=complete and not any(r['status']=='UNKNOWN' for row in native
                         for r in row['candidates']+row['source_candidates']+[row['input_value_alternative']])
        return {'status':'COMPLETE' if complete else 'INCOMPLETE','baseline':self.base,'queries':self.queries,
                'symmetry_grouping_enabled':self.grouping_enabled,'symmetry_classes':self.groups,
                'entailed_public_lemmas':self.public_lemmas,
                'note_results':notes,'cashout_results':native,'certificates':self.certificates}
