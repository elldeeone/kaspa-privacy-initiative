"""Strict public control ledger and independent integer certificate checker.

This symbolic model is not a native transcript, cryptographic ownership world,
or accepted-chain verifier. It never reads a seed, owner map or hidden truth.
"""
from dataclasses import dataclass
import hashlib
import json

MAX=2_870_000_000_000_000_000
FLOOR=60_000_000
NATIVE_FLOOR=10_000_000
ROOT={'schema','classification','profile','max_real_inputs','wallet_policy','funders','participant_role','participant_records','outgoing_invoices','events'}
EVENT={'ordinal','kind','time','reserve_before','reserve_after','fee','payout','payout_spk','n_before','n_after','m_before','m_after','mode','append_start','source_id','ingress_value','outputs','nfs'}
NOTE={'position','cm','cipher'}
RECORD={'position','cm','value','original_nf','invoice_payer_role'}
OUTGOING={'position','cm','value','recipient_role'}

class Invalid(ValueError):pass
class BadCertificate(ValueError):pass

def need(test,reason):
    if not test:raise Invalid(reason)

def integer(v,maximum=MAX):
    need(type(v) is int and 0<=v<=maximum,'integer');return v

def hx(v,size):
    need(type(v) is str and len(v)==size*2 and all(c in '0123456789abcdef' for c in v),'hex');return bytes.fromhex(v)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()

def parse(raw):
    def pairs(rows):
        out={}
        for k,v in rows:need(k not in out,'duplicate-key');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Invalid('nonfinite')))

@dataclass(frozen=True)
class Note:
    position:int
    birth:int
    cm:str
    value:int|None
    source:int|None

@dataclass(frozen=True)
class Ledger:
    public:dict
    events:tuple
    notes:dict
    records:tuple
    nf_spends:dict


def decode(public):
    need(type(public) is dict and set(public)==ROOT,'root-fields')
    need(public['schema']=='independent-payment-public-control/v1' and public['classification'] in
         ('PUBLIC_SYMBOLIC_NO_CRYPTO_NO_NATIVE','PUBLIC_CRYPTO_CANARY_NO_PROOF_NO_NATIVE'),'identity')
    need(public['profile'] in ('legacy','prospective-noappend-full'),'profile')
    need(type(public['max_real_inputs']) is int and public['max_real_inputs'] in (1,2),'input-policy')
    need(public['wallet_policy'] in ('generic','one-invoice-sender-change','one-invoice-positive-change','wide32-single-issuer'),'wallet-policy')
    need(type(public['funders']) is list and bool(public['funders']),'funders')
    source_ids=[]
    for f in public['funders']:
        need(type(f) is dict and set(f)=={'source_id','known_bootstrap_owner_role'},'funder-fields')
        source_ids.append(integer(f['source_id'],255));need(f['known_bootstrap_owner_role'] is None or type(f['known_bootstrap_owner_role']) is int and 0<=f['known_bootstrap_owner_role']<=255,'bootstrap-owner-fact')
    need(len(set(source_ids))==len(source_ids),'duplicate-funder')
    participant=public['participant_role']
    need(participant is None or type(participant) is int and 0<=participant<=255,'participant-role')
    rows=public['events'];need(type(rows) is list and 1<=len(rows)<=260,'events')
    notes={};seen_nf=set();events=[];reserve=0;n=0;m=1;time=0;seen_sources=set();ended=False
    for i,e in enumerate(rows):
        need(type(e) is dict and set(e)==EVENT,'event-fields')
        need(integer(e['ordinal'],259)==i and not ended,'event-order')
        need(integer(e['time'],10**9)>=time,'time-order');time=e['time']
        need(integer(e['reserve_before'])==reserve and integer(e['n_before'],65535)==n and
             integer(e['m_before'],131071)==m,'public-predecessor')
        after=integer(e['reserve_after']);fee=integer(e['fee']);payout=integer(e['payout']);integer(e['append_start'],65535)
        need(type(e['outputs']) is list and type(e['nfs']) is list,'array-fields')
        if e['kind']=='ingress':
            value=integer(e['ingress_value']);source=integer(e['source_id'],255)
            need(source in source_ids and source not in seen_sources and value>=FLOOR,'ingress-source-value')
            seen_sources.add(source)
            need(e['mode'] is None and payout==0 and e['payout_spk'] is None and not e['nfs'] and
                 len(e['outputs'])==1 and after==reserve+value and e['append_start']==n,'ingress-effect')
            start=n
        else:
            need(e['kind']=='action' and e['source_id'] is None and e['ingress_value'] is None,'action-kind')
            need(fee>0 and payout+fee<=reserve and after==reserve-payout-fee,'native-conservation')
            need(e['mode'] in (0,2,32) and type(e['mode']) is int and len(e['nfs'])==2,'action-mode')
            need(payout==0 or payout>=NATIVE_FLOOR,'native-floor')
            if payout:
                spk=hx(e['payout_spk'],36);need(spk[:3]==bytes.fromhex('000020') and spk[-1]==0xac,'payout-framing')
            else:need(e['payout_spk'] is None,'p0-spk')
            need(e['mode']!=32 or payout==0,'wide-only-p0')
            if e['mode']==0:
                need(payout>0 and not e['outputs'] and e['append_start']==0,'noappend-shape')
                need(public['profile']=='prospective-noappend-full' or after==0,'legacy-terminal-only')
                start=0;ended=after==0
            else:
                start=((n+e['mode']-1)//e['mode'])*e['mode']
                need(e['append_start']==start and len(e['outputs'])==e['mode'] and start+e['mode']<=65535,'append-shape')
                need(after>=FLOOR,'continuing-reserve')
            for nf in e['nfs']:
                hx(nf,32);need(nf!='00'*32 and nf not in seen_nf,'nf-replay');seen_nf.add(nf)
            m+=2;value=source=None
        for j,o in enumerate(e['outputs']):
            need(type(o) is dict and set(o)==NOTE,'note-fields');p=integer(o['position'],65534)
            hx(o['cm'],32);hx(o['cipher'],264)
            need(p==start+j and p not in notes,'physical-position')
            notes[p]=Note(p,i,o['cm'],value,source)
        if e['mode']!=0:n=start+len(e['outputs'])
        need(integer(e['n_after'],65535)==n and integer(e['m_after'],131071)==m,'public-next-counts')
        reserve=after;events.append(e)
    need(len(notes)<=512,'note-bound')
    records=public['participant_records'];need(type(records) is list,'records');positions=set();record_nfs=set();nf_spends={}
    for r in records:
        need(type(r) is dict and set(r)==RECORD,'record-fields');p=integer(r['position'],65534)
        need(p in notes and p not in positions and notes[p].cm==r['cm'],'record-position');positions.add(p)
        need(integer(r['value'])>=FLOOR,'record-value');hx(r['original_nf'],32)
        need(r['invoice_payer_role'] is None or type(r['invoice_payer_role']) is int and 0<=r['invoice_payer_role']<=255,'invoice-payer-role')
        need(r['original_nf']!='00'*32 and r['original_nf'] not in record_nfs,'record-nf-identity');record_nfs.add(r['original_nf'])
        matches=[e['ordinal'] for e in events if r['original_nf'] in e['nfs']]
        need(len(matches)<=1 and (not matches or notes[p].birth<matches[0]),'record-nf-order')
        nf_spends[p]=matches[0] if matches else None
    outgoing=public['outgoing_invoices'];need(type(outgoing) is list,'outgoing-invoices');seen_outgoing=set()
    for r in outgoing:
        need(type(r) is dict and set(r)==OUTGOING,'outgoing-fields');p=integer(r['position'],65534)
        need(p in notes and notes[p].cm==r['cm'] and p not in seen_outgoing,'outgoing-position');seen_outgoing.add(p)
        need(integer(r['value'])>=FLOOR,'outgoing-value');integer(r['recipient_role'],255)
    need(participant is not None or not records and not outgoing,'anonymous-profile-facts')
    return Ledger(public,tuple(events),notes,tuple(records),nf_spends)


def check(ledger,certificate):
    """No solver imports. Full chronology, ranges, conservation and spentness."""
    def ok(test,why):
        if not test:raise BadCertificate(why)
    ok(type(certificate) is dict and set(certificate)=={'values','inputs'},'certificate-fields')
    rows=certificate['values'];actions=[e for e in ledger.events if e['kind']=='action']
    ok(type(rows) is list and len(rows)==len(ledger.notes),'values-count');values={}
    for p,r in zip(sorted(ledger.notes),rows,strict=True):
        ok(type(r) is dict and set(r)=={'position','value'} and type(r['position']) is int and r['position']==p,'value-position')
        v=r['value'];ok(type(v) is int and 0<=v<=MAX and (v==0 or v>=FLOOR),'value-range')
        ok(ledger.notes[p].value is None or v==ledger.notes[p].value,'known-value');values[p]=v
    ins=certificate['inputs'];ok(type(ins) is list and len(ins)==len(actions),'input-count');selected={}
    for e,r in zip(actions,ins,strict=True):
        ok(type(r) is dict and set(r)=={'event','positions'} and type(r['event']) is int and r['event']==e['ordinal'],'input-event')
        ps=r['positions'];ok(type(ps) is list and 1<=len(ps)<=ledger.public['max_real_inputs'] and
                           all(type(p) is int for p in ps) and len(set(ps))==len(ps) and ps==sorted(ps),'input-slots')
        selected[e['ordinal']]=ps
    same_cm={};unspent={};ancestors={};native_support={}
    for p,note in ledger.notes.items():
        if note.cm in same_cm:ok(values[p]==same_cm[note.cm],'same-cm-value')
        same_cm[note.cm]=values[p]
    for e in ledger.events:
        i=e['ordinal'];outs=[o['position'] for o in e['outputs']]
        if e['kind']=='ingress':support={e['source_id']};ok(values[outs[0]]==e['ingress_value'],'ingress-value')
        else:
            ps=selected[i]
            ok(all(p in unspent and values[p]>=FLOOR and ledger.notes[p].birth<i for p in ps),'spent-future-zero-gap')
            total=sum(unspent.pop(p) for p in ps);support=set().union(*(ancestors[p] for p in ps))
            ok(total<=MAX and total<=e['reserve_before'] and total==sum(values[p] for p in outs)+e['payout']+e['fee'],'conservation')
            ok(e['payout']>0 or any(values[p]>0 for p in outs),'all-dummy-p0')
            if e['mode']==32 and ledger.public['wallet_policy']=='wide32-single-issuer':ok(all(values[p]>0 for p in outs),'wide-positive')
            if e['mode']==2 and not e['payout'] and ledger.public['wallet_policy']=='one-invoice-positive-change':ok(all(values[p]>=FLOOR for p in outs),'known-positive-change')
            if e['payout']:native_support[i]=support
        for p in outs:unspent[p]=values[p];ancestors[p]=support if values[p] else set()
        ok(sum(unspent.values())==e['reserve_after'],'prefix-backing')
    for r in ledger.public['outgoing_invoices']:ok(values[r['position']]==r['value'],'outgoing-known-value')
    for r in ledger.records:
        p=r['position'];ok(values[p]==r['value'],'participant-value')
        actual=[i for i,ps in selected.items() if p in ps]
        ok(actual==([] if ledger.nf_spends[p] is None else [ledger.nf_spends[p]]),'participant-original-nf')
    return {'values':values,'inputs':selected,'ancestors':ancestors,'native_causal_support':native_support,
            'causal_support_is_not_a_multi_source_value_allocation_or_human_identity':True}


def verify_analysis(ledger,result):
    """Independent COMPLETE coverage/predicate/derived-field validation."""
    def ok(test,why):
        if not test:raise BadCertificate(why)
    ok(result['public_sha256']==digest(ledger.public),'analysis-public-binding')
    certs=result['certificates'];checked={}
    for key,cert in certs.items():ok(key==digest(cert),'certificate-identity');checked[key]=check(ledger,cert)
    baseline=result['baseline'];ok(baseline['status']=='SAT' and baseline['certificate'] in checked,'baseline')
    base=checked[baseline['certificate']]
    if result['status']!='COMPLETE':
        ok(result['status']=='INCOMPLETE','analysis-status')
        ok(all(not r.get('mandatory_input_positions') and r.get('conditional_wallet_payer_role') is None for r in result['event_results']),'unknown-forcedness')
        return
    events=[e for e in ledger.events if e['kind']=='action'];rows=result['event_results']
    ok(len(rows)==len(events),'event-coverage')
    directory={f['source_id']:f['known_bootstrap_owner_role'] for f in ledger.public['funders']}
    changes={p:{directory[n.source]} for p,n in ledger.notes.items() if n.source is not None and directory[n.source] is not None}
    for r in ledger.records:changes.setdefault(r['position'],set()).add(ledger.public['participant_role'])
    for r in ledger.public['outgoing_invoices']:changes.setdefault(r['position'],set()).add(r['recipient_role'])
    if ledger.public['wallet_policy'] in ('one-invoice-sender-change','one-invoice-positive-change'):
        for r in ledger.records:
            e=ledger.events[ledger.notes[r['position']].birth]
            if r['invoice_payer_role'] is not None and e['kind']=='action' and e['mode']==2 and not e['payout']:
                sibling=next(o['position'] for o in e['outputs'] if o['position']!=r['position'])
                changes.setdefault(sibling,set()).add(r['invoice_payer_role'])
    for e,row in zip(events,rows,strict=True):
        ok(row['event']==e['ordinal'],'event-order');expected=[p for p,n in ledger.notes.items() if n.birth<e['ordinal']]
        ok([r['position'] for r in row['inputs']]==expected,'complete-candidate-coverage')
        mandatory=[]
        for r in row['inputs']:
            p=r['position']
            for name,present in (('selected',True),('excluded',False)):
                q=r[name];ok(q['status'] in ('SAT','UNSAT'),'complete-status')
                holds=(p in base['inputs'][e['ordinal']])==present
                if holds:ok(q['status']=='SAT','UNSAT-contradicts-public-baseline')
                if q['status']=='SAT':
                    ok(q['certificate'] in checked,'missing-query-certificate')
                    info=checked[q['certificate']];ok((p in info['inputs'][e['ordinal']])==present,'wrong-query-predicate')
            if r['selected']['status']=='SAT' and r['excluded']['status']=='UNSAT':mandatory.append(p)
        ok(row['mandatory_input_positions']==mandatory,'mandatory-summary')
        labels=set().union(*(changes[p] for p in mandatory if p in changes and len(changes[p])==1)) if mandatory else set()
        possible=[r['position'] for r in row['inputs'] if r['selected']['status']=='SAT']
        if not labels and possible and all(p in changes and len(changes[p])==1 for p in possible):labels=set().union(*(changes[p] for p in possible))
        role=next(iter(labels)) if len(labels)==1 and ledger.public['wallet_policy'] in ('one-invoice-sender-change','one-invoice-positive-change') else None
        ok(row['conditional_wallet_payer_role']==role,'role-summary')
