"""Unfunded public native statements; no notes, owner witnesses or proofs.

Public cases are supposed to fail at G16. They are never financial positives.
The two proof-only/inductive-premise controls intentionally reach the same seam.
"""
import hashlib
import json
import subprocess

DOMAIN=hashlib.sha256(b'KPX4/DO_NOT_FUND/COMPACT_NATIVE_WHOLE/v1\0').digest()
MAX_SEQUENCE='18446744073709551615'
PK=bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
PAYOUT_SPK=b'\0\0\x20'+PK+b'\xac'
INPUT=100_000_000_000
FEE=50_000_000
def h(*values):return hashlib.sha256(b''.join(values)).digest()
def u(value,width):return value.to_bytes(width,'little')
def spk(redeem):return (b'\0\0\xaa\x20'+hashlib.blake2b(redeem,digest_size=32).digest()+b'\x87').hex()

class Tree:
    def __init__(self,depth,empty_tag,node_tag):
        self.depth=depth;self.tag=node_tag;self.nodes={};self.empty=[h(empty_tag)]
        for _ in range(depth):self.empty.append(h(node_tag,self.empty[-1],self.empty[-1]))
    def node(self,height,index):return self.nodes.get((height,index),self.empty[height])
    @property
    def root(self):return self.node(self.depth,0)
    def path(self,index,level=0):
        return [self.node(height,(index >> (height-level))^1) for height in range(level,self.depth)]
    def set(self,index,value):
        assert type(index) is int and 0<=index<1<<self.depth and len(value)==32
        self.nodes[(0,index)]=value
        for height in range(self.depth):
            self.nodes[(height+1,index//2)]=h(self.tag,self.node(height,index&~1),self.node(height,index|1));index//=2

def cm_tree():
    tree=Tree(16,b'KPX1CME\0',b'KPX1CMN\0');tree.set(0,h(b'PUBLIC_SYNTHETIC_NOT_A_NOTE'));return tree
def nf_leaf(value,next_value,next_index):return h(b'KPX1NFL\0',value,next_value,u(next_index,4))
def nf_transition():
    tree=Tree(17,b'KPX1NFE\0',b'KPX1NFN\0');zero=bytes(32)
    tree.set(0,nf_leaf(zero,zero,0));old=tree.root;rows=[];leaves={0:(zero,zero,0)}
    for append,value in enumerate((u(1,32),u(2,32)),1):
        pred=append-1;pv,pn,pni=leaves[pred];pp=tree.path(pred)
        tree.set(pred,nf_leaf(pv,value,append));ap=tree.path(append)
        witness=u(pred,4)+pv+pn+u(pni,4)+b''.join(pp)+b''.join(ap)
        assert len(witness)==1160
        rows.append((value,witness));leaves[pred]=(pv,value,append);leaves[append]=(value,pn,pni)
        tree.set(append,nf_leaf(value,pn,pni))
    return old,tree.root,rows

def state(cmroot,n,nfroot,m):return b'KPX2ST01'+DOMAIN+cmroot+u(n,4)+nfroot+u(m,4)

def emit(binary,state_bytes,compact,wide,operation='emit-new-do-not-fund'):
    request={'operation':operation,'state_hex112':state_bytes.hex(),
             'compact_vk_hex328':compact.hex(),'wide_vk_hex328':wide.hex()}
    result=subprocess.run([str(binary)],input=json.dumps(request),capture_output=True,text=True,
                          env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'})
    if result.returncode:raise ValueError('public-source-emitter-failed: '+result.stderr)
    answer=json.loads(result.stdout);redeem=bytes.fromhex(answer['redeem_hex'])
    if len(redeem)!=answer['redeem_bytes'] or h(redeem).hex()!=answer['redeem_sha256']:
        raise ValueError('public-source-emitter-integrity')
    return redeem,answer

def fixture(binary,compact,wide,mode,fault='none'):
    assert mode in (0,2,32)
    cm=cm_tree();nf_old,nf_new,nfs=nf_transition();old_n=1
    # Deliberately violates the inductive prior suffix invariant, outside the
    # authenticated target block; it must never be labelled a native rejection.
    if fault=='occupied-skipped-gap':cm.set(1,h(b'PUBLIC_OCCUPIED_GAP'))
    start=((old_n+mode-1)//mode)*mode if mode else 0
    if fault=='occupied-target':cm.set(start,h(b'PUBLIC_OCCUPIED_TARGET'))
    old=state(cm.root,old_n,nf_old,1)
    cms=[h(b'PUBLIC_OUTPUT_CM',u(i,4)) for i in range(mode)]
    if fault=='duplicate-CM-proof-obligation' and mode:cms[-1]=cms[0]
    boxes=b''.join(h(b'PUBLIC_NOT_A_RECEIPT',u(i,4),u(j,4)) for i in range(mode) for j in range(9))[:264*mode]
    path=cm.path(start//mode,mode.bit_length()-1) if mode else []
    for i,value in enumerate(cms):cm.set(start+i,value)
    new=state(cm.root,start+mode,nf_new,3) if mode else state(cm.root,old_n,nf_new,3)
    payout=0 if mode==32 or fault=='compact-P0' else INPUT-FEE if mode==0 else 1_000_000_000
    reserve=INPUT-FEE-payout;point=h(b'PUBLIC_SYNTHETIC_PREVIOUS_TX').hex()
    auth=bytearray(b'KPX4AU01'+DOMAIN+bytes.fromhex(point)+u(0,4)+old+u(INPUT,8)+u(FEE,8)
                   +nfs[0][0]+nfs[1][0]+(h(*cms) if mode else bytes(32))
                   +bytes([mode])+bytes(3)+u(start,4)+bytes(24)
                   +(h(boxes) if mode else h(bytes(528)))+new+u(reserve,8)+u(payout,8)
                   +(PAYOUT_SPK if payout else bytes(36)))
    assert len(auth)==528
    payload=auth+nfs[0][1]+nfs[1][1]+b''.join(cms)+boxes+b''.join(path)
    assert len(payload)=={0:2848,2:3920,32:12672}[mode]
    if fault=='array-digest':payload[268]^=1
    elif fault=='cipher-digest':payload[332]^=1
    elif fault=='alignment':payload[304]^=1
    elif fault=='count':payload[436]^=1
    elif fault=='reserved':payload[308]=1
    elif fault=='mode':payload[300]=3
    elif fault=='NF-path':payload[528+72]^=1
    elif fault=='NF-duplicate':payload[236:268]=payload[204:236]
    elif fault=='state-root':payload[76+40]^=1
    elif fault=='terminal-carry':payload[404]^=1
    elif fault=='terminal-cipher-sentinel':payload[332:364]=bytes(32)
    elif fault=='conservation':payload[196]^=1
    elif fault=='wrong-outpoint':payload[40]^=1
    elif fault=='truncated':payload=payload[:-1]
    elif fault=='trailing':payload+=b'\0'
    redeem,inspection=emit(binary,old,compact,wide)
    successor,_=emit(binary,new,compact,wide)
    outputs=[]
    if reserve:outputs.append({'value':reserve,'scriptPublicKey':spk(successor),'covenant':None})
    if payout:outputs.append({'value':payout,'scriptPublicKey':PAYOUT_SPK.hex(),'covenant':None})
    if fault=='payout':outputs[-1]['value']-=1
    if fault=='successor':outputs[0]['scriptPublicKey']='0000aa20'+h(b'WRONG_SUCCESSOR').hex()+'87'
    storage=max(0,sum(1_000_000_000_000//row['value'] for row in outputs)-1_000_000_000_000//INPUT)
    witness=bytes.fromhex(inspection['zero_signature_zero_proof_witness_hex'])
    case={'transaction':{'version':1,'id':'00'*32,'inputs':[{'previousOutpoint':{'transactionId':point,'index':0},
            'signatureScript':witness.hex(),'sequence':MAX_SEQUENCE,'computeBudget':1600}],
            'outputs':outputs,'lockTime':0,'subnetworkId':'00'*20,'gas':0,'payload':payload.hex(),'mass':storage},
          'entries':[{'amount':INPUT,'scriptPublicKey':spk(redeem),'blockDaaScore':0,'isCoinbase':False,'covenantId':None}]}
    seam=fault in ('none','compact-P0','occupied-skipped-gap','duplicate-CM-proof-obligation')
    return case,{'mode':mode,'fault':fault,'expected_final_G16_seam':seam,
        'classification':'PUBLIC_UNFUNDED_NO_MATCHED_CIRCUIT_NO_FINANCIAL_POSITIVE',
        'redeem_bytes':len(redeem),'payload_bytes':len(payload),'CM_start':start,'new_n':start+mode if mode else old_n,
        'native_pairwise_CM_distinctness':False,
        'prior_empty_suffix_invariant_assumed':fault!='occupied-skipped-gap',
        'fabricated_prior_empty_suffix_premise_violated':fault=='occupied-skipped-gap',
        'selected_VK_role_source_checked':'wide' if mode==32 else 'compact',
        'selected_VK_sha256':h(wide if mode==32 else compact).hex(),
        'private_ownership_and_conservation_proved':False,'G16_proof':'ZERO128_INVALID',
        'input_sompi':INPUT,'reserve_sompi':reserve,'payout_sompi':payout,'fee_sompi':FEE,
        'contextual_storage_mass':storage}
