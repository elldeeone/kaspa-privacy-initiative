"""Fixed public/participant attacks. No generator, keys, truth, fitting or files.

Equality of an opened Note168 is a fact. Arithmetic/timing guesses below are
never described as logically forced, valid hash witnesses or posteriors.
"""
import hashlib
import itertools
import json

VARIANTS = ('prior','opening','residual','cash_inverse')
FLOOR, S = 60_000_000, 100_000_000


def digest(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def need(c,m):
    if not c: raise ValueError(m)


def choice(roles, event, field):
    need(bool(roles),'nonempty public candidates')
    return min(roles,key=lambda r:(digest([event,field,r]),r))


def analyze(public,view,only_last=False):
    need(set(public) == {'schema','classification','arm','regime','rate','roles','active_roles',
        'events','ordinary_funding','crypto_model','invoice_model','wallet_freshness'},'public fields')
    need(public['schema'] == 'kpx3-population-arithmetic-public/v1'
         and public['classification'] == 'SYNTHETIC_CONSTRAINT_MODEL','model identity')
    need(set(view) == {'schema','members','authored','owned'},'participant fields')
    need(view['schema'] == 'kpx3-population-participant-view/v1','view identity')
    events, roles = public['events'], public['roles']
    need(roles == list(range(32)),'32 declared roles')
    known, births, cms, selected = {}, {}, {}, {}
    native_owners={coin['tx']:funding['owner'] for funding in public['ordinary_funding']
                   for coin in funding.get('sources',[])}
    position = 0
    for i,e in enumerate(events):
        need(set(e) == {'ordinal','tx','minute','mode','fee','payout','payout_spk','reserve','n','m',
            'nf','cm','ciphertext','prior_n','prior_m','prior_reserve','opening','funding_owner',
            'public_deposit','terminal','reveal_key'},'public event fields')
        need(e['ordinal'] == i and e['prior_n'] == position,'public sequence/count')
        for cm,cipher in zip(e['cm'],e['ciphertext'],strict=True):
            need(len(bytes.fromhex(cipher)) == 264,'full public cipher264')
            births[position],cms[position] = i,cm
            position += 1
        need(e['n'] == position,'append count')
        if e['opening']:
            n = dict(e['opening'])
            prior_owner=known.get(n['position'],{}).get('owner')
            n['owner'] = e['funding_owner'] if e['funding_owner'] is not None else (
                native_owners.get(e['tx'],prior_owner))
            known[n['position']] = n
    def merge(n):
        p=n['position'];need(cms[p] == n['cm'],'known opening CM')
        if p in known:
            need(known[p]['value'] == n['value'],'consistent known value')
            old_owner=known[p].get('owner')
            need(old_owner is None or n.get('owner') is None or old_owner == n['owner'],'known owner')
            n=dict(n,owner=old_owner if old_owner is not None else n.get('owner'))
        known[p]=n
    for n in view['owned']: merge(n)
    for authored in view['authored']:
        selected[authored['event']] = authored
        for n in authored['outputs']: merge(n)
    # Complete declared owned records legitimately know their positioned NF.
    by_nf={n['nf']:n['position'] for n in view['owned']}
    consumed={}
    for i,e in enumerate(events):
        ps=[by_nf[nf] for nf in e['nf'] if nf in by_nf]
        if e['mode'] == 'reveal': ps=[e['opening']['position']]
        if i in selected: ps=selected[i]['inputs']
        consumed[i]=ps
    targets=[i for i,e in enumerate(events) if e['mode'] == 'private' and e['payout'] == 0]
    if only_last:
        need(targets and targets[-1] == len(events)-1,'current public P0 target')
        targets=targets[-1:]
    rows=[]
    for target in targets:
        e=events[target]
        first=e['prior_n'];second=first+1
        sender=choice(roles,e['tx'],'sender')
        recipient=choice([r for r in roles if r != sender],e['tx'],'recipient')
        prior=dict(sender=sender,recipient=recipient,amount=45*S,rank=[0,0,0])
        guesses={v:dict(prior) for v in VARIANTS}
        facts=dict(note_value_opened=first in known,
                   exact_note_value=known[first]['value'] if first in known else None,
                   owner_known=known.get(first,{}).get('owner') is not None)
        if first in known:
            guesses['opening']['amount']=known[first]['value']
            guesses['opening']['rank']=[3,1,-target]
        if known.get(first,{}).get('owner') is not None:
            guesses['opening']['recipient']=known[first]['owner']
        if target in selected:
            guesses['opening']['sender']=selected[target]['owner']
        for v in ('residual','cash_inverse'):
            guesses[v]=dict(guesses['opening'])
        # Opened change value plus a known one/two-note input sum gives a
        # falsifiable amount guess. Unobserved inputs are never silently zero.
        earlier=[p for p in known if p < first and known[p]['value'] >= FLOOR]
        if second in known:
            candidates=[]
            for size in (1,2):
                for ps in itertools.combinations(earlier,size):
                    owners={known[p].get('owner') for p in ps}
                    if len(owners) > 1 and None not in owners: continue
                    value=sum(known[p]['value'] for p in ps)-known[second]['value']-e['fee']
                    if not 10*S <= value <= 50*S: continue
                    # Prefer public temporal proximity; position tuple breaks ties.
                    rank=(min(target-births[p] for p in ps),len(ps),ps)
                    owner=next((known[p]['owner'] for p in ps if known[p].get('owner') is not None),None)
                    candidates.append((rank,value,owner))
            if candidates:
                _,value,owner=min(candidates)
                guesses['residual'].update(amount=value,rank=[2,1,-target])
                if owner is not None: guesses['residual']['sender']=owner
        # Every later payout remains visible, including full drainage. This is
        # a fixed nearest-time invoice-value guess; it assumes neither hidden
        # positive-output arity nor whole-note private EXIT behavior.
        later=[f for f in events[target+1:] if f['payout'] and 10*S <= f['payout']+f['fee'] <= 50*S]
        if first not in known and later:
            f=min(later,key=lambda f:(f['minute']-e['minute'],f['ordinal']))
            guesses['cash_inverse'].update(amount=f['payout']+f['fee'],rank=[1,1,-f['ordinal']])
        # Public fixed tags are a guessed join, never automatic knowledge.
        for v in VARIANTS[1:]:
            for role in range(8):
                if guesses[v]['amount'] in (20*S+(role+1)*1000,20*S+(role+1)*1000+1):
                    guesses[v]['sender']=role
            if guesses[v]['sender'] == guesses[v]['recipient']:
                guesses[v]['recipient']=choice([r for r in roles if r != guesses[v]['sender']],e['tx'],'nonself')
        rows.append(dict(event=target,guesses=guesses,public_opening_facts=facts))
    return dict(schema='kpx3-population-prediction/v1',public_sha256=digest(public),
                view_sha256=digest(view),variants=list(VARIANTS),rows=rows)


if __name__ == '__main__':
    import sys
    # Streaming requires one prediction response before the controller sends a
    # later prefix. Each horizon uses a NEW process, so no future data persists.
    for line in sys.stdin:
        request=json.loads(line)
        need(set(request) == {'public','view','only_last'},'request fields')
        print(json.dumps(analyze(request['public'],request['view'],request['only_last']),
                         sort_keys=True,separators=(',',':')),flush=True)
