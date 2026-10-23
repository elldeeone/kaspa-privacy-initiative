"""Public known-answer controls, no held-out data or generation seed access."""
import copy
from population_attack import analyze
from population_fees import Fees,FeeUnavailable,validate_published_profile


def controls():
    checked=validate_published_profile()
    boundaries=[]
    for rate in (100,200,500):
        old=Fees('rerandomize_reveal',rate)
        try:
            fee0=old.private(120_000_000)
            assert 60_000_000-fee0 < 60_000_000
        except FeeUnavailable:
            pass
        new=Fees('private_exit',rate)
        try:
            fee=new.private(120_000_000,10_000_000)
            payout=60_000_000-fee
            supported=payout>=10_000_000
        except FeeUnavailable:
            fee=None;payout=None;supported=False
        assert supported == (rate in (100,200))
        boundaries.append(dict(rate=rate,old60M_rerandomization_possible=False,
            new60M_private_supported=supported,private_fee=fee,private_payout=payout))
    # Shape-only observer control; these openings/CMs/ciphers are constructed,
    # NOT a valid native/Groth16 trace. The actual model validator is separate.
    z='00'*32;a='11'*32;b='22'*32;c='33'*32
    opening=dict(position=0,cm=a,value=2_000_000_000,O=a,incoming=a,rho=a,K=a,nativePK=a)
    def event(i,mode,prior_n,n,cm,opened=None,payout=0):
        return dict(ordinal=i,tx=f'{i+1:064x}',minute=i,mode=mode,fee=5_000_000,
            payout=payout,payout_spk=None,reserve=1_000_000_000,n=n,m=i+1,nf=[],cm=cm,
            ciphertext=['00'*264 for _ in cm],prior_n=prior_n,prior_m=i,
            prior_reserve=1_000_000_000,opening=opened,
            funding_owner=8 if mode=='genesis' else None,public_deposit=0,
            terminal=False,reveal_key=z if mode=='reveal' else None)
    e0=event(0,'genesis',0,1,[a],opening)
    e1=event(1,'private',1,3,[b,c])
    note=dict(opening,position=1,cm=b,value=1_000_000_000,nativePK=b)
    e2=event(2,'reveal',3,3,[],note,995_000_000)
    public=dict(schema='kpx3-population-arithmetic-public/v1',classification='SYNTHETIC_CONSTRAINT_MODEL',
        arm='direct_reveal',regime='control',rate=100,roles=list(range(32)),active_roles=list(range(8)),
        events=[e0,e1],ordinary_funding=[],crypto_model='shape-only control',
        invoice_model='fresh V2 fields',wallet_freshness='control')
    view=dict(schema='kpx3-population-participant-view/v1',members=[],authored=[],owned=[])
    before=analyze(public,view,True)['rows'][0]
    assert not before['public_opening_facts']['note_value_opened']
    public['events'].append(e2)
    after=analyze(public,view)['rows'][0]
    assert after['public_opening_facts']['note_value_opened']
    assert after['guesses']['opening']['amount']==1_000_000_000
    assert not after['public_opening_facts']['owner_known']
    bad=copy.deepcopy(public);bad['hidden_owner']=8
    try: analyze(bad,view)
    except ValueError: pass
    else: raise AssertionError('metadata leakage control not rejected')
    return dict(passed=True,published_actual_metrics_checked=checked,
        known_answer_opening=True,no_fresh_invoice_owner_gift=True,
        metadata_rejection=True,boundary_controls=boundaries,
        scope='PUBLIC_DEVELOPMENT_CONTROLS_NOT_POPULATION_SAMPLES')


def development(crypto):
    """One PUBLIC DO_NOT_FUND fixture plus independent negative trace controls."""
    from population_model import plan,replay
    from population_score import validate
    ledger,error=replay(plan(bytes(range(32)),'overlap-independent'),
        bytes(reversed(range(32))),'private_exit',crypto,'overlap-independent',100)
    if error: raise ValueError('public development replay failed: '+error)
    baseline=validate(ledger)
    fields=('work','notes','events','hidden','cashout_end','funding','costs','payouts',
        'external_coins','earmarked','audit','payment_index','arm','regime','rate','reserve')
    original={k:copy.deepcopy(getattr(ledger,k)) for k in fields}
    from types import SimpleNamespace
    def changed(): return SimpleNamespace(**copy.deepcopy(original))
    cases=[]
    q=changed();q.events[32]['fee']+=1;cases.append(('fee-substitution',q))
    q=changed();q.notes[0]['value']+=1;cases.append(('inflated-note-value',q))
    q=changed();q.events[32]['prior_reserve']+=1;cases.append(('stale-context',q))
    q=changed();q.audit[7]['urgent_completed']=False;cases.append(('urgent-exit-failure-hidden',q))
    q=changed();q.costs[0]-=1;cases.append(('hidden-cost',q))
    i=next(i for i,e in enumerate(ledger.events) if e['mode']=='private' and e['payout'])
    q=changed();p=q.hidden[i]['inputs'][0]
    q.events[i]['payout_spk']='000020'+q.notes[p]['opening']['nativePK']+'ac'
    cases.append(('reused-note-native-destination',q))
    j=next(i for i,e in enumerate(ledger.events) if e['terminal'])
    q=changed();q.events[j]['cm']=['11'*32];cases.append(('terminal-phantom-output',q))
    q=changed();nf=q.events[32]['nf'][0]
    j=next(i for i in range(33,len(q.events)) if q.events[i]['nf'])
    q.events[j]['nf'][0]=nf;cases.append(('duplicate-nullifier',q))
    for name,q in cases:
        try: validate(q)
        except ValueError: pass
        else: raise AssertionError('negative control accepted: '+name)
    return dict(passed=True,private_model_development_only=True,
        baseline_validation=baseline,negative_cases=[name for name,_ in cases],
        public_seed_hex=bytes(range(32)).hex(),public_opaque_hex=bytes(reversed(range(32))).hex())
