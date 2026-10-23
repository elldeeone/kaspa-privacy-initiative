"""Strict public-only input for the conditional batch arithmetic observer."""
from dataclasses import dataclass
import hashlib
import json

MAX = 2_870_000_000_000_000_000
FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
ROOT = {'schema','classification','known_wallet_policy','profile','rate_sompi_per_mass',
        'exit_credit_sompi','domain_hex32','funding_directory','participant_roles',
        'participant_records','events'}
EVENT = {'ordinal','tx_id','minute','kind','prior_reserve_sompi','reserve_sompi',
         'fee_sompi','payout_sompi','payout_spk_hex36','prior_cm_cursor','cm_cursor',
         'prior_nf_count','nf_count','mode','append_start','notes','nfs',
         'ingress_value_sompi','ingress_source_id','public_ingress_note_hex168'}
PARTICIPANT = {'participant_role','position','cm','value_sompi','original_nf',
               'invoice_counterparty_role'}

class Invalid(ValueError): pass
class ScopeLimit(ValueError): pass

def need(condition, text):
    if not condition: raise Invalid(text)

def integer(value, maximum=MAX):
    need(type(value) is int and 0 <= value <= maximum,'noncanonical-integer')
    return value

def hx(value, width):
    need(type(value) is str and len(value)==2*width
         and all(c in '0123456789abcdef' for c in value),'canonical-hex')
    return bytes.fromhex(value)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(value): return hashlib.sha256(canonical(value)).hexdigest()

def parse(raw):
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'duplicate-json-key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Invalid('nonfinite-json')))

@dataclass(frozen=True)
class Note:
    position: int
    cm: str
    birth: int
    value: int | None
    source: int | None
    ciphertext: str

@dataclass(frozen=True)
class Event:
    ordinal: int
    kind: str
    minute: int
    fee: int
    payout: int
    reserve: int
    mode: int | None
    notes: tuple
    ingress: int | None
    source: int | None
    nfs: tuple

@dataclass(frozen=True)
class Ledger:
    public: dict
    notes: dict
    events: tuple
    participants: tuple
    source_ids: tuple
    nf_spends: dict
    repeated_cm: bool

def decode(public):
    need(type(public) is dict and set(public)==ROOT,'public-root-fields')
    need(public['schema']=='kpx3-payment-linkage-public/v1'
         and public['classification']=='PUBLIC_SYNTHETIC_DO_NOT_FUND_ARITHMETIC_MODEL'
         and public['known_wallet_policy'] in ('one_real_input_full_native_cashout',
             'one_real_full_cashout_wide_positive_varied_future_wallet',
             'one_real_full_cashout_wide_positive_equal_current_demo'),
         'public-model-identity')
    role_sets={'C':[],'C+1':[2],'C+8':list(range(2,10))}
    need(public['profile'] in role_sets and type(public['participant_roles']) is list
         and all(type(r) is int for r in public['participant_roles'])
         and public['participant_roles']==role_sets[public['profile']],
         'predeclared-participant-profile')
    need(integer(public['rate_sompi_per_mass'])==100,'selected-rate')
    integer(public['exit_credit_sompi']);domain=hx(public['domain_hex32'],32)
    directory=public['funding_directory'];need(type(directory) is list and 1<=len(directory)<=8,'funding-directory')
    source_ids=[];payer_roles=[]
    for row in directory:
        need(type(row) is dict and set(row)=={'source_id','payer_role'},'funding-directory-fields')
        source_ids.append(integer(row['source_id'],7));payer_roles.append(integer(row['payer_role'],255))
    need(source_ids==list(range(len(source_ids))) and len(set(payer_roles))==len(payer_roles),
         'funding-directory-identity')
    rows=public['events'];need(type(rows) is list and bool(rows),'public-events')
    if len(rows)>260: raise ScopeLimit('event-bound')
    notes={};events=[];seen_tx=set();seen_nf=set();reserve=0;cursor=0;nf_count=1
    ended=False;private_count=0;previous_minute=0;seen_sources=set();all_cm=[]
    for ordinal,row in enumerate(rows):
        need(type(row) is dict and set(row)==EVENT,'event-fields')
        need(integer(row['ordinal'],259)==ordinal and not ended,'event-order')
        minute=integer(row['minute'],10**9);need(minute>=previous_minute,'time-order');previous_minute=minute
        tx=hx(row['tx_id'],32);need(tx not in seen_tx,'tx-replay');seen_tx.add(tx)
        need(integer(row['prior_reserve_sompi'])==reserve
             and integer(row['prior_cm_cursor'],65535)==cursor
             and integer(row['prior_nf_count'],131071)==nf_count,'previous-public-state')
        after=integer(row['reserve_sompi']);fee=integer(row['fee_sompi']);payout=integer(row['payout_sompi'])
        new_notes=row['notes'];nfs=row['nfs'];need(type(new_notes) is list and type(nfs) is list,'public-array-fields')
        for nf in nfs:
            raw=hx(nf,32);need(raw!=bytes(32) and nf not in seen_nf,'nf-replay-or-zero');seen_nf.add(nf)
        if row['kind']=='ingress':
            value=integer(row['ingress_value_sompi']);source=integer(row['ingress_source_id'],7)
            need(source in source_ids and source not in seen_sources,'ingress-source')
            seen_sources.add(source)
            opening=hx(row['public_ingress_note_hex168'],168)
            need(value>=FLOOR and int.from_bytes(opening[64:72],'little')==value
                 and payout==0 and row['payout_spk_hex36'] is None and not nfs
                 and row['mode'] is None and integer(row['append_start'],65535)==cursor
                 and len(new_notes)==1 and after==reserve+value,'ingress-effects')
            mode=None;start=cursor
        elif row['kind']=='private':
            private_count+=1
            if private_count>256: raise ScopeLimit('private-action-bound')
            value=source=None;mode=integer(row['mode'],32)
            need(row['ingress_value_sompi'] is None and row['ingress_source_id'] is None
                 and row['public_ingress_note_hex168'] is None and mode in (0,2,32)
                 and fee>0 and len(nfs)==2 and payout<=reserve and fee<=reserve-payout
                 and after==reserve-payout-fee,'private-effects')
            need(payout==0 or payout>=PAYOUT_FLOOR,'payout-floor')
            if payout:
                spk=hx(row['payout_spk_hex36'],36)
                need(spk[:3]==bytes.fromhex('000020') and spk[-1]==0xac,'payout-spk')
            else: need(row['payout_spk_hex36'] is None,'p0-destination')
            need(mode!=32 or payout==0,'wide-p0-only')
            if mode==0:
                need(after==0 and payout>0 and not new_notes and integer(row['append_start'],65535)==0,'terminal-effects')
                ended=True;start=0
            else:
                need(after>=FLOOR and len(new_notes)==mode,'continuing-effects')
                start=((cursor+mode-1)//mode)*mode
                need(integer(row['append_start'],65535)==start and start+mode<=65535,'aligned-position')
        else: raise Invalid('event-kind')
        positions=[];event_cms=[]
        for offset,note in enumerate(new_notes):
            need(type(note) is dict and set(note)=={'position','cm','ciphertext_hex264'},'public-note-fields')
            pos=integer(note['position'],65534);cm=hx(note['cm'],32);hx(note['ciphertext_hex264'],264)
            need(pos==start+offset and pos not in notes,'physical-note-position')
            if row['kind']=='ingress':
                need(hashlib.sha256(b'KPX1NOT\0'+domain+opening).digest()==cm,'ingress-cm-opening')
            notes[pos]=Note(pos,note['cm'],ordinal,value,source,note['ciphertext_hex264'])
            positions.append(pos);event_cms.append(note['cm']);all_cm.append(note['cm'])
        need(len(event_cms)==len(set(event_cms)),'same-event-cm-duplicate')
        if len(notes)>512: raise ScopeLimit('note-bound')
        cursor=cursor if mode==0 else start+len(new_notes)
        nf_count+=len(nfs)
        need(integer(row['cm_cursor'],65535)==cursor and integer(row['nf_count'],131071)==nf_count,
             'new-public-counts')
        reserve=after;events.append(Event(ordinal,row['kind'],minute,fee,payout,after,mode,
                                        tuple(positions),value,source,tuple(nfs)))
    records=public['participant_records'];need(type(records) is list,'participant-records')
    participants=[];seen_participant_pos=set();nf_spends={}
    for row in records:
        need(type(row) is dict and set(row)==PARTICIPANT,'participant-fields')
        role=integer(row['participant_role'],255);pos=integer(row['position'],65534)
        need(role in public['participant_roles'] and pos in notes and pos not in seen_participant_pos,
             'participant-own-record-scope')
        seen_participant_pos.add(pos);need(notes[pos].cm==row['cm'],'participant-cm')
        integer(row['value_sompi']);need(row['value_sompi']>=FLOOR,'participant-positive-receipt')
        nf=hx(row['original_nf'],32);need(nf!=bytes(32),'participant-nf')
        counterparty=row['invoice_counterparty_role']
        need(counterparty is None or type(counterparty) is int and counterparty in payer_roles,
             'participant-counterparty-role')
        matches=[e.ordinal for e in events if row['original_nf'] in e.nfs]
        need(len(matches)<=1 and (not matches or notes[pos].birth<matches[0]),'participant-spend-chronology')
        nf_spends[pos]=matches[0] if matches else None
        participants.append(row)
    return Ledger(public,notes,tuple(events),tuple(participants),tuple(source_ids),nf_spends,
                  len(all_cm)!=len(set(all_cm)))
