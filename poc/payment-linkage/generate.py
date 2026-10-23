"""Source-restricted synthetic model producer; root must release heldout use.

This module never generates on import. Only a fresh experiment seed bundle is
read; no existing wallet/profile/PK is a source. Output is NOT a native trace.
"""
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys

from schema import canonical,decode,digest,MAX,FLOOR

ROOT=Path(__file__).resolve().parents[2]
RECEIVER=ROOT/'poc/future-recipient/v2/recipient.py'
RECEIVER_SHA='93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
CRYPTO_SHA='6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
FEE_PROFILE=ROOT/'research/next-session/private-change/fees/WHOLE-EMITTED-COSTS-01.json'
# Byte-checked old emitted/native fee dimensions, not matched financial proof fees.
FEES={'entry':258_500,'admit':5_098_200,'wide':19_701_700,'compact':18_826_500,
      'cashout':18_867_700,'terminal':18_718_200}
SOMPI=100_000_000
FEE_PROFILE_SHA='c4f7043c4f0cdd3c4509a3d93a02558b506e731aead243fc67a431f9db2d8d82'

def verify_profile():
    raw=FEE_PROFILE.read_bytes();assert hashlib.sha256(raw).hexdigest()==FEE_PROFILE_SHA
    p=json.loads(raw);shapes={r['shape']:r['normalized_mass'] for r in p['native_wire_shapes']}
    assert p['common_redeem_bytes']==23575 and shapes=={'terminal':187182,'continuing':188677,
        'compact_P0':188265,'wide_P0':197017}
    assert FEES['entry']==100*p['direct_entry_mass_ceiling']
    assert FEES['admit']==next(r['fee_at100_before_any_larger_storage'] for r in p['retained_additional_routes']
                               if r['route']=='ADMIT-with-change')
    return p

class Stream:
    def __init__(self,key,label):self.key=key;self.label=label.encode();self.index=0
    def block(self):
        out=hashlib.shake_256(b'KPI/LINKAGE/SAMPLER/v1\0'+self.key+len(self.label).to_bytes(4,'little')+
                             self.label+self.index.to_bytes(8,'little')).digest(32)
        self.index+=1;return out
    def below(self,bound):
        assert type(bound) is int and 0<bound<2**256
        cap=2**256-2**256%bound
        while True:
            v=int.from_bytes(self.block(),'big')
            if v<cap:return v%bound
    def shuffle(self,values):
        result=list(values)
        for i in range(len(result)-1,0,-1):
            j=self.below(i+1);result[i],result[j]=result[j],result[i]
        return result

def load_receiver():
    raw=RECEIVER.read_bytes();assert hashlib.sha256(raw).hexdigest()==RECEIVER_SHA
    name='_kpi_linkage_pinned_receiver'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,RECEIVER);module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module;exec(compile(raw,str(RECEIVER),'exec'),module.__dict__)
    return sys.modules[name]

def workload(seed):
    amounts=Stream(seed,'principal');people=Stream(seed,'payees');withdraw=Stream(seed,'withdrawal')
    rows=[]
    for payer in (0,1):
        for recipient in people.shuffle(range(2,34)):
            principal=([10,20,25,40,50][amounts.below(5)]*SOMPI if amounts.below(100)<60
                       else 10*SOMPI+amounts.below(4001)*1_000_000)
            rows.append({'obligation':len(rows),'payer':payer,'recipient':recipient,'principal_sompi':principal})
    early=withdraw.shuffle(range(2,34))[:16]
    late=[r for r in range(2,34) for _ in range(2-(r in early))]
    return {'payments':rows,'early_roles':early,'late_roles':withdraw.shuffle(late)}

def storage(inputs,outputs):
    assert all(type(v) is int and 0<v<=MAX for v in inputs+outputs)
    return max(0,sum(10**12//v for v in outputs)-sum(10**12//v for v in inputs))

class Trace:
    def __init__(self,material,cluster,timing,arm,crypto_path):
        assert timing in ('overlap','staggered') and arm in ('wide32','compact2')
        assert hashlib.sha256(Path(crypto_path).read_bytes()).hexdigest()==CRYPTO_SHA
        self.v2=load_receiver();self.crypto=self.v2.Crypto(crypto_path)
        self.stream=Stream(material,f'{cluster}/{timing}/{arm}/material')
        self.domain=hashlib.sha256(b'KPI/LINKAGE/MODEL/DO_NOT_FUND/v1\0'+self.stream.block()).digest()
        self.receivers={r:self.v2.Receiver(self.stream.block(),self.domain,self.crypto) for r in range(34)}
        self.index={r:0 for r in range(34)};self.notes={};self.events=[];self.private_rows=[]
        self.cursor=0;self.nf_count=1;self.reserve=0;self.used_nf=set();self.used_cm=set();self.seen_tx=set()
        self.ordinary_sources=[];self.fee_audit=[];self.cluster=cluster;self.timing=timing;self.arm=arm

    def label(self):
        value=self.stream.block().hex();assert value!='00'*32;return value

    def new_note(self,owner,value,purpose,obligation=None,payer=None):
        if value:
            idx=self.index[owner];self.index[owner]+=1
            invoice=self.receivers[owner].invoice(idx)
            receipt=self.v2.Receipt.for_invoice(invoice,value,self.stream.block())
            opening=receipt.note_bytes();cipher=self.crypto.seal(invoice.delivery_pk,receipt.encode())
            assert self.receivers[owner].open(cipher)==receipt
            cm=receipt.commitment().hex()
        else:
            receipt=None;opening=bytes(72)+self.stream.block()+bytes(64)
            secret=self.stream.block();public=self.crypto.delivery_public(secret);plain=self.stream.block()*7
            plain=plain[:216];cipher=self.crypto.seal(public,plain)
            assert self.crypto.unseal(secret,cipher)==plain
            cm=hashlib.sha256(b'KPX1NOT\0'+self.domain+opening).hexdigest()
        assert len(cipher)==264 and not cipher[31]&128 and any(cipher) and cm not in self.used_cm
        self.used_cm.add(cm)
        return {'value':value,'owner':owner,'purpose':purpose,'obligation':obligation,'payer':payer,
                'opening':opening.hex(),'cipher':cipher.hex(),'cm':cm,'receipt':receipt,
                'birth':None,'position':None,'nf':None,'spent':False,'consumer':None}

    def append(self,records,start):
        public=[]
        for offset,note in enumerate(records):
            pos=start+offset;assert pos not in self.notes
            note['position']=pos;note['birth']=len(self.events)
            if note['value']:
                note['nf']=self.receivers[note['owner']].nullifier(note['receipt'],pos).hex()
                assert note['nf']!='00'*32
            self.notes[pos]=note
            public.append({'position':pos,'cm':note['cm'],'ciphertext_hex264':note['cipher']})
        return public

    def header(self,kind,minute,fee,payout=0):
        tx=self.label();assert tx not in self.seen_tx;self.seen_tx.add(tx)
        return {'ordinal':len(self.events),'tx_id':tx,'minute':minute,'kind':kind,
            'prior_reserve_sompi':self.reserve,'reserve_sompi':self.reserve,
            'fee_sompi':fee,'payout_sompi':payout,'payout_spk_hex36':None,
            'prior_cm_cursor':self.cursor,'cm_cursor':self.cursor,'prior_nf_count':self.nf_count,
            'nf_count':self.nf_count,'mode':None,'append_start':self.cursor,'notes':[],'nfs':[],
            'ingress_value_sompi':None,'ingress_source_id':None,'public_ingress_note_hex168':None}

    def ingress(self,payer,value,minute):
        before=self.reserve;fee=FEES['entry' if not self.events else 'admit']
        note=self.new_note(payer,value,'bootstrap',payer=payer)
        row=self.header('ingress',minute,fee);row.update(ingress_value_sompi=value,
            ingress_source_id=payer,public_ingress_note_hex168=note['opening'])
        row['notes']=self.append([note],self.cursor);self.cursor+=1;self.reserve+=value
        row.update(cm_cursor=self.cursor,reserve_sompi=self.reserve)
        change=100*SOMPI;external=value+change+fee
        inputs=[external] if not self.events else [before,external]
        outputs=[self.reserve,change]
        assert storage(inputs,outputs)<=fee//100
        self.fee_audit.append({'event':len(self.events),'inputs':inputs,'outputs':outputs,'fee':fee,
                               'modeled_mass_ceiling':fee//100,'storage':storage(inputs,outputs)})
        self.ordinary_sources.append({'payer':payer,'external_source_sompi':external,'ordinary_change_sompi':change})
        self.events.append(row)

    def selected(self,owner):
        available=[n for n in self.notes.values() if n['value'] and n['owner']==owner and not n['spent']]
        assert available,'source cannot meet demand'
        return min(available,key=lambda n:(-n['value'],n['position']))

    def private(self,owner,minute,records,fee,payout=0,mode=None):
        selected=self.selected(owner);total=sum(n['value'] for n in records)
        assert selected['value']==total+payout+fee and selected['value']<=self.reserve
        before=self.reserve;after=before-payout-fee
        mode=0 if after==0 else (mode if mode is not None else 2)
        assert mode in (0,2,32) and (not payout or all(n['value']==0 for n in records))
        if mode==0:assert payout>0 and not total;records=[]
        assert len(records)==mode
        row=self.header('private',minute,fee,payout);row['mode']=mode
        source_nf=selected['nf'];assert source_nf not in self.used_nf
        real_slot=self.stream.below(2);dummy_slot=1-real_slot
        dummy=hmac.digest(self.stream.block(),b'KPX2DMY\0'+self.domain+self.stream.block()+bytes([dummy_slot]),'sha256').hex()
        assert dummy!='00'*32 and dummy not in self.used_nf and dummy!=source_nf
        row['nfs']=[None,None];row['nfs'][real_slot]=source_nf;row['nfs'][dummy_slot]=dummy
        self.used_nf.update(row['nfs'])
        selected['spent']=True;selected['consumer']=len(self.events)
        start=((self.cursor+mode-1)//mode)*mode if mode else 0
        row['append_start']=start;row['notes']=self.append(self.stream.shuffle(records),start)
        if mode:self.cursor=start+mode
        self.nf_count+=2;self.reserve=after
        row.update(cm_cursor=self.cursor,nf_count=self.nf_count,reserve_sompi=after)
        if payout:
            secret=self.stream.block();pk=self.crypto.xonly(secret)
            assert pk.hex()!=selected['opening'][-64:]
            row['payout_spk_hex36']='000020'+pk.hex()+'ac'
        outputs=([after] if after else [])+([payout] if payout else [])
        assert sum(outputs)+fee==before and storage([before],outputs)<=fee//100
        self.fee_audit.append({'event':len(self.events),'inputs':[before],'outputs':outputs,'fee':fee,
                             'modeled_mass_ceiling':fee//100,'storage':storage([before],outputs)})
        self.private_rows.append({'event':len(self.events),'selected_position':selected['position'],'owner':owner})
        self.events.append(row)

    def deliveries(self,payer,payments,minute):
        payfee=FEES['wide' if self.arm=='wide32' else 'compact'];credit=FEES['cashout']
        if self.arm=='wide32':
            records=[self.new_note(p['recipient'],p['principal_sompi']+credit,'economic',p['obligation'],payer)
                     for p in payments]
            self.private(payer,minute,records,payfee,mode=32)
        else:
            for payment in payments:
                selected=self.selected(payer);value=payment['principal_sompi']+credit
                change=selected['value']-value-payfee
                assert change==0 or change>=FLOOR
                records=[self.new_note(payment['recipient'],value,'economic',payment['obligation'],payer),
                         self.new_note(payer if change else None,change,'change' if change else 'dummy',payer=payer)]
                self.private(payer,minute,records,payfee,mode=2)

    def cashout(self,owner,minute):
        note=self.selected(owner);terminal=note['value']==self.reserve
        fee=FEES['terminal' if terminal else 'cashout'];payout=note['value']-fee
        assert payout>=10_000_000
        records=[] if terminal else [self.new_note(None,0,'dummy'),self.new_note(None,0,'dummy')]
        self.private(owner,minute,records,fee,payout=payout)

    def views(self,work):
        final=len(self.events);payment_end=max(e['ordinal'] for e in self.events if e['kind']=='private' and not e['payout_sompi'])+1
        outputs={}
        for horizon,end in [('payment',payment_end),('drain',final)]:
            events=self.events[:end];present={r['ingress_source_id'] for r in events if r['kind']=='ingress'}
            for profile,roles in [('C',[]),('C+1',[2]),('C+8',list(range(2,10)))]:
                records=[]
                for note in self.notes.values():
                    if note['birth']>=end or not note['value'] or note['owner'] not in roles:continue
                    records.append({'participant_role':note['owner'],'position':note['position'],
                        'cm':note['cm'],'value_sompi':note['value'],'original_nf':note['nf'],
                        'invoice_counterparty_role':note['payer'] if note['purpose']=='economic' else None})
                pub={'schema':'kpx3-payment-linkage-public/v1',
                    'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND_ARITHMETIC_MODEL',
                    'known_wallet_policy':'one_real_full_cashout_wide_positive_varied_future_wallet','profile':profile,
                    'rate_sompi_per_mass':100,'exit_credit_sompi':FEES['cashout'],
                    'domain_hex32':self.domain.hex(),
                    'funding_directory':[{'source_id':p,'payer_role':p} for p in sorted(present)],
                    'participant_roles':roles,'participant_records':records,'events':events}
                decode(pub);outputs[horizon+'/'+profile]=pub
        truth={'schema':'kpx3-payment-linkage-model-truth/v1','classification':'DISPOSABLE_SYNTHETIC_LABELS_NOT_LIVE_WALLET_DATA',
            'cluster':self.cluster,'timing':self.timing,'arm':self.arm,'obligations':work['payments'],
            'notes':[{k:n[k] for k in ('position','cm','value','owner','purpose','obligation','payer','opening','cipher','birth','nf','consumer')}
                     for n in self.notes.values()],
            'private_inputs':self.private_rows,'ordinary_sources':self.ordinary_sources,'fee_audit':self.fee_audit,
            'end_reserve_sompi':self.reserve,'truth_crypto_bridge_roundtrips_checked':True,
            'horizon_ends':{'payment':payment_end,'drain':final}}
        assert self.reserve==0 and all(n['spent'] for n in self.notes.values() if n['value'])
        assert sum(s['external_source_sompi'] for s in self.ordinary_sources)==sum(s['ordinary_change_sompi'] for s in self.ordinary_sources)+sum(e['payout_sompi'] for e in self.events)+sum(e['fee_sompi'] for e in self.events)
        return outputs,truth

def build_case(work,material,cluster,timing,arm,crypto):
    verify_profile();t=Trace(material,cluster,timing,arm,crypto);payfee=FEES['wide' if arm=='wide32' else 'compact']
    sizes={p:sum(r['principal_sompi']+FEES['cashout'] for r in work['payments'] if r['payer']==p)+
               payfee*(1 if arm=='wide32' else 32) for p in (0,1)}
    t.ingress(0,sizes[0],0)
    if timing=='overlap':t.ingress(1,sizes[1],0)
    t.deliveries(0,[p for p in work['payments'] if p['payer']==0],1)
    if timing=='staggered':
        for role in work['early_roles']:t.cashout(role,10)
        t.ingress(1,sizes[1],1440)
    t.deliveries(1,[p for p in work['payments'] if p['payer']==1],1441 if timing=='staggered' else 1)
    if timing=='overlap':
        for role in work['early_roles']:t.cashout(role,10)
    for i,role in enumerate(work['late_roles']):t.cashout(role,(1450 if timing=='staggered' else 20)+i)
    return t.views(work)
