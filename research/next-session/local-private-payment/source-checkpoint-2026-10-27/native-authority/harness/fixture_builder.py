"""SOURCE ONLY: deterministic public fixture builder, never imported/run in preparation.
All input JSON is helper09-admitted by the future closed runner. No private paths.
"""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import research_wire as w

class Sparse:
    def __init__(self,depth,empty,node):
        self.depth,self.node=depth,node
        self.empty=[empty]
        for _ in range(depth): self.empty.append(w.sha(node,self.empty[-1],self.empty[-1]))
        self.nodes=[{} for _ in range(depth+1)]
    def set(self,index,leaf):
        w.integer(index,0,(1<<self.depth)-1,'tree-index');self.nodes[0][index]=leaf
        for level in range(self.depth):
            parent=index>>1;left=self.nodes[level].get(parent*2,self.empty[level]);right=self.nodes[level].get(parent*2+1,self.empty[level])
            self.nodes[level+1][parent]=w.sha(self.node,left,right);index=parent
    def path(self,index):
        w.integer(index,0,(1<<self.depth)-1,'tree-index');p=[]
        for level in range(self.depth):p.append(self.nodes[level].get(index^1,self.empty[level]));index>>=1
        return b''.join(p)
    def root(self):return self.nodes[self.depth].get(0,self.empty[self.depth])

def hx(v,n):
    w.need(type(v)is str and len(v)==2*n and all(c in '0123456789abcdef' for c in v),'hex')
    return bytes.fromhex(v)

def build(derived,variant):
    w.need(derived['schema']=='kpi-nativeauth-derived-public-fixture/v1' and variant in ('base','coordinator'),'fixture-schema')
    oldcm=Sparse(16,w.CM_EMPTY,b'KPX1CMN\0')
    for i,n in enumerate(derived['prior']):oldcm.set(i,hx(n['cmHex'],32))
    oldcm.set(3,hx(derived['input']['cmHex'],32));input_path=oldcm.path(3);old_cm_root=oldcm.root()
    nf=hx(derived['nfHex'],32);nft=Sparse(17,w.NF_EMPTY,b'KPX1NFN\0');nft.set(0,w.nf_leaf(w.ZERO,w.ZERO,0));old_nf_root=nft.root();pred=nft.path(0)
    nft.set(0,w.nf_leaf(w.ZERO,nf,1));append=nft.path(1);nft.set(1,w.nf_leaf(nf,w.ZERO,0));new_nf_root=nft.root()
    nf_witness=(0).to_bytes(4,'little')+w.ZERO+w.ZERO+(0).to_bytes(4,'little')+pred+append
    selected=[derived['coordinatorOutput'] if variant=='coordinator' else derived['outputs'][0],derived['outputs'][1]]
    cfs=[bytes([0xad if variant=='coordinator' else 0xab])*264,bytes([0xac])*264]
    outputs=[w.build_output(hx(n['cmHex'],32),hx(n['cvHex'],64),cf,bytes(128))for n,cf in zip(selected,cfs)]
    paths=[]
    for i,n in enumerate(selected):paths.append(oldcm.path(4+i));oldcm.set(4+i,hx(n['cmHex'],32))
    old=w.encode_state(old_cm_root,4,old_nf_root,1);new=w.encode_state(oldcm.root(),6,new_nf_root,2)
    point=bytes([0x81])*32+bytes(4);tail=bytes([0x5a])*64
    core=w.build_body_core(action_id=bytes([0x80])*32,point=point,old_state=old,new_state=new,old_reserve=9000000000,new_reserve=8980000000,fee=20000000,delta=hx(derived['deltaHex'],32),nf=nf,cv=hx(derived['input']['cvHex'],64),outputs=outputs,nf_witness=nf_witness,cm_paths=paths)
    packet=w.build_projection(core+bytes(128),tail)
    # These mandatory public checks are separate from the actual joined R1CS.
    # No returned boolean is copied into a circuit or claimed current-chain truth.
    w.validate_public(packet);w.require_current_head(packet,old,point,9000000000,tail)
    inp=derived['input']
    native_input={'noteHex':inp['noteHex'],'kHex':inp['kHex'],'position':3,'pathHex':[input_path[i*32:(i+1)*32].hex()for i in range(16)],'blindHex':inp['blindHex'],'ownerKeyHex':derived['ownerKeys'][0]}
    return {'schema':'kpi-nativeauth-public-fixture-bundle/v1','variant':variant,'packetHex':packet.hex(),'nativeInput':native_input,'referenceOutputs':[{'noteHex':n['noteHex'],'blindHex':n['blindHex']}for n in selected],'head':{'stateHex':old.hex(),'pointHex':point.hex(),'reserveSompi':9000000000,'tailHex':tail.hex()},'scope':'PUBLIC_SYNTHETIC_UNFUNDED_OPAQUE_ZERO_PROOFS_DUMMY_CF_NO_DELIVERY'}

def revalidate(bundle):
    w.need(bundle['schema']=='kpi-nativeauth-public-fixture-bundle/v1','bundle-schema');p=hx(bundle['packetHex'],4077);head=bundle['head']
    w.validate_public(p);w.require_current_head(p,hx(head['stateHex'],112),hx(head['pointHex'],36),head['reserveSompi'],hx(head['tailHex'],64));return p

if __name__=='__main__':
    request=json.load(sys.stdin)
    if request['mode']=='build':result=build(request['derived'],request['variant'])
    elif request['mode']=='revalidate':revalidate(request['bundle']);result={'status':'PUBLIC_REFERENCE_REVALIDATED_NOT_NATIVE_ACCEPTANCE'}
    else:raise ValueError('mode')
    json.dump(result,sys.stdout,sort_keys=True,separators=(',',':'));sys.stdout.write('\n')
