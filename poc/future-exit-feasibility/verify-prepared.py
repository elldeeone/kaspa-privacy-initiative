#!/usr/bin/env python3
"""Independent standard-library wire/tree/whole-note oracle, never native Full."""
import hashlib, hmac, json, pathlib, sys
base = pathlib.Path(sys.argv[1])
def sha(*p): return hashlib.sha256(b''.join(p)).digest()
def u(b): return int.from_bytes(b,'little')
def fold(h,path,index,tag):
    for j in range(len(path)//32):
        sibling=path[32*j:32*j+32]
        h=sha(tag,sibling,h) if index&1 else sha(tag,h,sibling)
        index >>= 1
    assert index==0
    return h
def nfl(v,n,i): return sha(b'KPX1NFL\0',v,n,i.to_bytes(4,'little'))
def spk(redeem): return '0000aa20'+hashlib.blake2b(redeem,digest_size=32).hexdigest()+'87'
def parse(tx):
    sig=bytes.fromhex(tx['inputs'][0]['signatureScript'])
    assert sig[0]==65 and sig[66]==0x4d and u(sig[67:69])==len(sig)-69
    r=sig[69:];assert r[:2]==bytes([0x4c,112]) and r[114]==0x75
    return r,r[2:114],bytes.fromhex(tx['payload'])
def reserve(name):
    if name.startswith('agility-'):name=name[len('agility-'):]
    if name.startswith('terminal-singleton-'):return 60_000_000
    if name.startswith('continuing-remainder20M-'):return 80_000_000
    if name.startswith('continuing-remainder10M-'):return 70_000_000
    return 120_000_000
context={}; positive=0; equality=0
for file in sorted(base.glob('*.transaction.json')):
    name=file.name.removesuffix('.transaction.json');tx=json.loads(file.read_text());r,s,p=parse(tx)
    context[file.name]=[{'outpoint':i['previousOutpoint'],'amount_sompi':reserve(name),'script_public_key':spk(bytes.fromhex(i['signatureScript'])[69:]),'block_daa_score':0,'is_coinbase':False} for i in tx['inputs']]
    if name.startswith('negative-'):
        if name=='negative-current-authenticated-spent-NF-equality':
            assert p[761:793]==p[1917:1949]
            assert fold(nfl(p[761:793],p[793:825],u(p[825:829])),p[829:1373],u(p[757:761]),b'KPX1NFN\0')==s[76:108]
            equality+=1
        continue
    assert s[:8]==b'KPX1ST01' and p[:9]==b'KPX1RV01\1' and len(p)==2029
    d=s[8:40];n=u(s[72:76]);m=u(s[108:112]);pos=u(p[177:181]);index=u(p[757:761]);ni=u(p[825:829]);V=u(p[73:81]);F=u(p[2013:2021]);P=u(p[2021:2029]);R=reserve(name)
    assert 1<=m<=n<=65536 and pos<n and index<m and ni<m
    K=sha(b'KPX1KEY\0',d,p[113:145]);assert K==p[181:213]
    CM=sha(b'KPX1NOT\0',d,p[9:41],p[41:73],p[73:81],p[81:113],K,p[145:177]);assert CM==p[213:245]
    assert fold(CM,p[245:757],pos,b'KPX1CMN\0')==s[40:72]
    NF=hmac.new(p[113:145],b'KPX1NF\0\0'+d+CM+p[177:181],hashlib.sha256).digest();assert NF==p[1917:1949]
    pv=p[761:793];pn=p[793:825]
    assert u(pv)<u(NF) and (u(pn)==0 or u(NF)<u(pn))
    assert fold(nfl(pv,pn,ni),p[829:1373],index,b'KPX1NFN\0')==s[76:108]
    mid=fold(nfl(pv,NF,m),p[829:1373],index,b'KPX1NFN\0');assert mid==p[1949:1981]
    assert fold(sha(b'KPX1NFE\0'),p[1373:1917],m,b'KPX1NFN\0')==mid
    nr=fold(nfl(NF,pn,ni),p[1373:1917],m,b'KPX1NFN\0');assert nr==p[1981:2013]
    assert V==P+F and 10_000_000<=P and R>=V and R-sum(o['value'] for o in tx['outputs'])==F
    payout=tx['outputs'][-1];assert payout['value']==P and payout['scriptPublicKey']=='000020'+p[145:177].hex()+'ac'
    if R==V:assert len(tx['outputs'])==1
    else:
        assert len(tx['outputs'])==2 and tx['outputs'][0]['value']==R-V
        next_state=s[:76]+nr+(m+1).to_bytes(4,'little')
        assert tx['outputs'][0]['scriptPublicKey']==spk(r[:2]+next_state+r[114:])
    positive+=1
assert positive==60 and equality==1
(base/'supplied-contexts.json').write_text(json.dumps(context,indent=2)+'\n')
print(json.dumps({'public_positive_wire_tree_accounting_checks':positive,'current_spent_NF_membership_equality_control':equality,'supplied_contexts':len(context),'official_VM_or_Full_executed':False},indent=2))
