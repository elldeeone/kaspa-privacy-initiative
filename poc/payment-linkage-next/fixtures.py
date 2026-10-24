"""Fixed reviewable PUBLIC symbolic controls. Never heldout/native/crypto data.

Labels and idealized NF correspondence are public to control reviewers. The
observer receives only public(); no inference of real-world anonymity follows.
"""
import copy
from dataclasses import dataclass
import hashlib
from ledger import decode,check,canonical,digest,FLOOR

S=100_000_000
F=20_000_000
BOX=(bytes([9])*264).hex() # shape-only: NOT genuine encryption
SPK='000020'+'11'*32+'ac'

def h(label):return hashlib.sha256(label.encode()).hexdigest()

@dataclass
class Fixture:
    public:dict
    certificate:dict
    notes:dict
    actors:dict

    def verify(self):
        ledger=decode(self.public);info=check(ledger,self.certificate)
        role=self.public['participant_role']
        for r in ledger.records:
            n=self.notes[r['position']]
            assert n['owner']==role and n['value']==r['value'] and n['nf']==r['original_nf']
            assert r['invoice_payer_role']==(n['issuer'] if n['purpose']=='economic' else None)
        for r in self.public['outgoing_invoices']:
            n=self.notes[r['position']];assert n['purpose']=='economic' and n['issuer']==role and n['owner']==r['recipient_role'] and n['value']==r['value']
        directory={f['source_id']:f['known_bootstrap_owner_role'] for f in self.public['funders']}
        for e in ledger.events:
            if e['kind']=='ingress':
                assert self.notes[e['outputs'][0]['position']]['owner']==directory[e['source_id']]
                continue
            chosen=info['inputs'][e['ordinal']]
            assert all(self.notes[p]['nf'] in e['nfs'] for p in chosen)
            if e['mode']==32:
                actor=self.actors[e['ordinal']];outs=[self.notes[o['position']] for o in e['outputs']]
                assert len(outs)==32 and len({n['invoice'] for n in outs})==32 and all(n['purpose']=='economic' and n['issuer']==actor and n['owner']!=actor for n in outs)
            if self.public['wallet_policy'] in ('one-invoice-sender-change','one-invoice-positive-change') and not e['payout']:
                actor=self.actors[e['ordinal']];outs=[self.notes[o['position']] for o in e['outputs']]
                economic=[n for n in outs if n['purpose']=='economic']
                assert len(economic)==1 and economic[0]['issuer']==actor and economic[0]['owner']!=actor
                assert all(self.notes[p]['owner']==actor for p in chosen)
                assert all(n['purpose']=='economic' or n['owner']==(actor if n['value'] else None) for n in outs)
        return ledger,info

class Builder:
    def __init__(self,label,policy='one-invoice-positive-change',maximum=2,profile='legacy'):
        self.label=label;self.policy=policy;self.maximum=maximum;self.profile=profile
        self.events=[];self.notes={};self.inputs={};self.actors={};self.funders=[];self.reserve=0;self.n=0;self.m=1
    def note(self,p,value,owner,purpose,issuer=None,invoice=None):
        cm=h(f'{self.label}/CM/{p}');self.notes[p]={'position':p,'value':value,'owner':owner,'purpose':purpose,'issuer':issuer,'invoice':invoice,'nf':h(f'{self.label}/idealized-private-NF/{p}'),'birth':len(self.events),'cm':cm}
        return {'position':p,'cm':cm,'cipher':BOX}
    def add(self,kind,outputs,*,inputs=(),payout=0,source=None,owner=None,mode=2,actor=None,time=None):
        i=len(self.events);before=self.reserve;nb=self.n;mb=self.m
        if kind=='ingress':
            assert source not in [x['source_id'] for x in self.funders]
            self.funders.append({'source_id':source,'known_bootstrap_owner_role':owner});start=self.n
            self.reserve+=outputs[0][0];nfs=[];selected=[];selected_value=None
        else:
            assert 1<=len(inputs)<=self.maximum and len(set(inputs))==len(inputs)
            selected_value=sum(self.notes[p]['value'] for p in inputs)
            assert selected_value==sum(x[0] for x in outputs)+payout+F
            self.reserve-=payout+F;start=((self.n+mode-1)//mode)*mode if mode else 0
            nfs=[self.notes[p]['nf'] for p in inputs]
            if len(nfs)==1:nfs.append(h(f'{self.label}/dummy-NF/{i}'))
            self.m+=2;selected=sorted(inputs);self.inputs[i]=selected;self.actors[i]=actor
        rows=[]
        for j,row in enumerate(outputs):
            value,recipient,purpose,issuer,invoice=row
            rows.append(self.note(start+j,value,recipient,purpose,issuer,invoice))
        if mode or kind=='ingress':self.n=start+len(rows)
        e={'ordinal':i,'kind':kind,'time':i if time is None else time,'reserve_before':before,'reserve_after':self.reserve,'fee':F,'payout':payout,'payout_spk':SPK if payout else None,'n_before':nb,'n_after':self.n,'m_before':mb,'m_after':self.m,'mode':None if kind=='ingress' else mode,'append_start':start,'source_id':source if kind=='ingress' else None,'ingress_value':outputs[0][0] if kind=='ingress' else None,'outputs':rows,'nfs':nfs}
        self.events.append(e);return [r['position'] for r in rows]
    def deposit(self,source,value,owner=None,time=None):
        owner=source if owner is None else owner
        return self.add('ingress',[(value,owner,'bootstrap',None,None)],source=source,owner=owner,time=time)[0]
    def payment(self,selected,recipient,principal,*,actor,invoice,time=None):
        gross=principal+F;change=sum(self.notes[p]['value'] for p in selected)-gross-F
        assert change==0 or change>=FLOOR
        return self.add('action',[(gross,recipient,'economic',actor,invoice),(change,actor if change else None,'change' if change else 'dummy',None,None)],inputs=selected,actor=actor,time=time)
    def fixture(self,participant=None,count=None):
        events=copy.deepcopy(self.events if count is None else self.events[:count]);end=len(events)
        notes={p:copy.deepcopy(n) for p,n in self.notes.items() if n['birth']<end}
        records=[];outgoing=[]
        for p,n in notes.items():
            if n['value'] and participant is not None and n['owner']==participant:
                records.append({'position':p,'cm':n['cm'],'value':n['value'],'original_nf':n['nf'],'invoice_payer_role':n['issuer'] if n['purpose']=='economic' else None})
            if participant is not None and n['purpose']=='economic' and n['issuer']==participant:
                outgoing.append({'position':p,'cm':n['cm'],'value':n['value'],'recipient_role':n['owner']})
        sources={e['source_id'] for e in events if e['kind']=='ingress'}
        public={'schema':'independent-payment-public-control/v1','classification':'PUBLIC_SYMBOLIC_NO_CRYPTO_NO_NATIVE','profile':self.profile,'max_real_inputs':self.maximum,'wallet_policy':self.policy,'funders':[f for f in self.funders if f['source_id'] in sources],'participant_role':participant,'participant_records':records,'outgoing_invoices':outgoing,'events':events}
        cert={'values':[{'position':p,'value':n['value']} for p,n in sorted(notes.items())], 'inputs':[{'event':i,'positions':ps} for i,ps in self.inputs.items() if i<end]}
        return Fixture(public,cert,notes,{i:a for i,a in self.actors.items() if i<end})

def sparse(maximum=2,policy='one-invoice-positive-change',extra=False,zero=False,generic=False):
    if generic:policy='generic'
    if zero:policy='one-invoice-sender-change'
    b=Builder(f'sparse/{maximum}/{policy}/{extra}/{zero}/{generic}',policy,maximum)
    root=b.deposit(0,30*S+2*F if zero else 100*S)
    other=b.deposit(1,100*S) if extra else None
    first=b.payment([root],2,30*S,actor=0,invoice='invoice-B')
    if generic:
        # Same two-output capability, but the sibling is a second recipient,
        # not sender change. This private fact must NOT be gifted publicly.
        b.notes[first[1]].update(owner=4,purpose='economic',issuer=0,invoice='invoice-D')
    if zero:other=b.deposit(1,100*S)
    selected=other if other is not None else first[1]
    actor=1 if other is not None else 4 if generic else 0
    second=b.payment([selected],3,20*S,actor=actor,invoice='invoice-C')
    return b.fixture(2),first[1],b.events[-1]['ordinal'],second

def forwarded_origin():
    b=Builder('forwarded-origin');a=b.deposit(0,100*S);bb=b.deposit(1,80*S)
    incoming,unused=b.payment([bb],0,40*S,actor=1,invoice='B-to-A')
    paid,change=b.payment([incoming],2,10*S,actor=0,invoice='A-to-Bob')
    return b.fixture(0),b.events[-1]['ordinal']

def singleton(maximum=2,split=False,noappend=False,future=False):
    b=Builder(f'singleton/{maximum}/{split}/{noappend}/{future}','generic',maximum,'prospective-noappend-full' if noappend else 'legacy')
    boot=b.deposit(0,100*S);selected=[boot]
    if split:
        assert maximum==2
        selected=b.add('action',[(40*S,0,'control-self-split',None,None),(60*S-F,0,'control-self-split',None,None)],inputs=[boot],actor=0)
    total=sum(b.notes[p]['value'] for p in selected)
    if noappend:
        chosen=[selected[0]];payout=b.notes[chosen[0]]['value']-F
        b.add('action',[],inputs=chosen,payout=payout,mode=0,actor=0)
    else:
        payout=40*S;remaining=total-payout-F
        b.add('action',[(remaining,0,'change',None,None),(0,None,'dummy',None,None)],inputs=selected,payout=payout,actor=0)
    target=b.events[-1]['ordinal']
    if future:
        later=b.deposit(1,80*S,time=1440)
        b.payment([later],4,10*S,actor=1,invoice='future-real-demand',time=1441)
    return b.fixture(),target

def partial_two_sources():
    b=Builder('partial-two-sources','generic',2);a=b.deposit(0,10*S);bb=b.deposit(1,20*S,owner=0)
    b.add('action',[(15*S-F,0,'change',None,None),(0,None,'dummy',None,None)],inputs=[a,bb],payout=15*S,actor=0)
    return b.fixture()

def breadth(wide):
    b=Builder('breadth/'+str(wide),'wide32-single-issuer' if wide else 'one-invoice-sender-change',1)
    principals=[50*S if i%2==0 else (10,20,25,40)[(i//2)%4]*S for i in range(32)]
    gross=[v+F for v in principals];roots=[b.deposit(p,sum(gross)+(F if wide else 32*F)) for p in (0,1)]
    economic=[]
    for payer in (0,1):
        if wide:
            ps=b.add('action',[(gross[i],i+2,'economic',payer,f'{payer}/{i}') for i in range(32)],inputs=[roots[payer]],mode=32,actor=payer)
            economic.extend(ps)
        else:
            current=roots[payer]
            for i in range(32):
                leaf,current=b.payment([current],i+2,principals[i],actor=payer,invoice=f'{payer}/{i}')
                economic.append(leaf)
    # Full drainage: refunds and every pool-paid fee are retained. Zero tails
    # and self-change are never extra economic obligations.
    for index,p in enumerate(economic):
        payout=b.notes[p]['value']-F;terminal=index==len(economic)-1
        b.add('action',[] if terminal else [(0,None,'dummy',None,None)]*2,inputs=[p],payout=payout,mode=0 if terminal else 2,actor=b.notes[p]['owner'])
    return b.fixture(2)
