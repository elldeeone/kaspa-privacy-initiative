"""Decode public v6 bytes for H14 calibration; not a proof/consensus verifier."""
import hashlib
from two_input_privacy_observer import decode, integer, need


def decimal(s):
    need(isinstance(s,str) and s.isascii() and s.isdecimal() and str(int(s))==s,'canonical decimal')
    return integer(int(s))


def p2sh(redeem):
    return (b'\0\0\xaa\x20'+hashlib.blake2b(redeem,digest_size=32).digest()+b'\x87').hex()


def project(raw):
    need(set(raw)=={'schema','initial','interval_minutes','transactions'} and raw['schema']=='kpi-h14-native-v1','native schema')
    u=raw['initial'];balance=decimal(u['amount']);interval=integer(raw['interval_minutes'],1)
    initial=dict(id=u['txid'],value=balance,funding_group=u['txid'])
    expected=dict(transactionId=u['txid'],index=u['index']);expected_spk=u['spk']
    events=[];roots={};nfs=set();cms=set();old_state=None;suffix=None;domain=None;count=1;nfcount=0
    for step,tx in enumerate(raw['transactions']):
        need(tx['version']==1 and tx['lockTime']=='0' and tx['gas']=='0' and tx['subnetworkId']=='0'*40,'native envelope')
        payload=bytes.fromhex(tx['payload'])
        need(len(payload)==5228 and payload[:8]==b'KPICR06\0','v6 payload')
        a=payload[8:385];cipher=payload[385:755];state=payload[755:860]
        need(a[:8]==b'KPICU06\0' and hashlib.sha256(cipher).digest()==a[345:377],'auth/cipher binding')
        mode=a[204];need(mode in (0,1,2),'mode')
        need(len(tx['inputs'])==(2 if mode==0 else 1),'input count')
        inp=tx['inputs'][0]
        need(inp['previousOutpoint']==expected,'reserve ancestry')
        need(inp['computeBudget']==3000 and inp['sequence']==str(2**64-1),'reserve input metadata')
        sig=bytes.fromhex(inp['signatureScript'])
        need(len(sig)==24709 and sig[:2]==b'\x4c\x80' and sig[130:133]==b'\x4d\x00\x60','v6 proof/redeem framing')
        redeem=sig[133:];old=redeem[36:141]
        need(p2sh(redeem)==expected_spk,'reserve script commitment')
        if old_state is None:
            domain=redeem[1:33];suffix=redeem[141:];roots[1]=old[9:41]
        else:
            need(old==old_state and redeem[1:33]==domain and redeem[141:]==suffix,'covenant continuity')
        need(old[0]==6 and int.from_bytes(old[1:5],'little')==count and int.from_bytes(old[5:9],'little')==nfcount,'old state counts')
        need(a[8:40]==domain,'domain')
        anchor=int.from_bytes(a[40:44],'little')
        if mode==0:
            need(step>0 and a[40:140]==bytes(100),'admission authorization shape')
        else:
            need(anchor in roots and a[44:76]==roots[anchor],'historical anchor')
            for nf in (a[76:108],a[108:140]):
                need(any(nf) and nf not in nfs,'zero/reused nullifier');nfs.add(nf);nfcount+=1
        fee=int.from_bytes(a[213:221],'little');payout=int.from_bytes(a[205:213],'little')
        deposit=int.from_bytes(a[257:265],'little');bootstrap=int.from_bytes(a[337:345],'little')
        need(bootstrap==(initial['value'] if step==0 else 0),'bootstrap binding')
        if mode==0:
            f=tx['inputs'][1]['previousOutpoint']
            need(bytes.fromhex(f['transactionId'])+integer(f['index'],0,2**32-1).to_bytes(4,'little')==a[265:301],'funding outpoint')
            need(deposit>0 and payout==0 and a[221:257]==bytes(36),'admission value/destination')
        else:
            need(deposit==0 and a[265:337]==bytes(72),'spend funding fields')
        if payout==0:need(a[221:257]==bytes(36),'zero payout destination')
        new=[] if mode==2 else [count,count+1]
        if new:
            for cm in (a[140:172],a[172:204]):
                need(any(cm) and cm not in cms,'projection assumes distinct output commitments');cms.add(cm)
        else:
            need(a[140:204]==bytes(64) and cipher==bytes(370),'drain output padding')
        balance+=deposit-payout-fee;need(balance>=0,'backing underflow')
        terminal=balance==0
        need(not terminal or mode==2,'terminal drain')
        need(len(tx['outputs'])==int(not terminal)+int(payout>0),'native output count')
        need(sum(decimal(o['value']) for o in tx['outputs'])==balance+payout,'native accounting')
        if payout:
            need(decimal(tx['outputs'][-1]['value'])==payout and tx['outputs'][-1]['scriptPublicKey']==a[221:257].hex(),'payout binding')
        before=count;count+=len(new)
        if terminal:
            need(state==bytes(105),'terminal state')
        else:
            need(state[0]==6 and int.from_bytes(state[1:5],'little')==count and int.from_bytes(state[5:9],'little')==nfcount,'new counts')
            need(decimal(tx['outputs'][0]['value'])==balance and tx['outputs'][0]['scriptPublicKey']==p2sh(redeem[:36]+state+suffix),'successor binding')
            if mode==2:need(state[9:41]==old[9:41],'drain commitment root')
            roots[count]=state[9:41]
            expected_spk=tx['outputs'][0]['scriptPublicKey']
        need(all(o.get('covenant') is None for o in tx['outputs']),'output metadata')
        events.append(dict(id=tx['id'],minute=step*interval,mode=mode,anchor_count=anchor,
            count_before=before,new=new,fee=fee,deposit=deposit,payout=payout,reserve_out=balance,
            destination=a[221:257].hex() if payout else None,
            funding_group=a[265:297].hex() if mode==0 else None))
        old_state=state;expected=dict(transactionId=tx['id'],index=0)
    data=dict(schema='kpi-h14-public-v1',initial=initial,events=events);decode(data)
    return data


def normalized(data):
    # Opaque labels differ between real proofs and the economic model. Preserve
    # equality, order, public monetary fields and all event structure exactly.
    import copy
    out=copy.deepcopy(data);funds={};dests={}
    def number(table,value):
        if value not in table:table[value]=len(table)
        return table[value]
    out['initial']['id']='genesis'
    out['initial']['funding_group']=number(funds,out['initial']['funding_group'])
    for i,e in enumerate(out['events']):
        e['id']=f'tx{i}'
        if e['funding_group'] is not None:e['funding_group']=number(funds,e['funding_group'])
        if e['destination'] is not None:e['destination']=number(dests,e['destination'])
    return out
