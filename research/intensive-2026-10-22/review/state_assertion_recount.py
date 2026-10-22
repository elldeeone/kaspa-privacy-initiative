#!/usr/bin/env python3
"""Independent stdlib recount of NONFUNDABLE S7/J336 public state fixtures.

Reads only frozen public bytes. Does not import the architecture oracle or state
core and does not perform proof verification. Reconstructs indexed NF links from
the complete indexed value set after each insertion, rather than trusting the
previous witness's successor pointers. A recursively indexed sparse tree gives
an independent path/root implementation.
"""
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
import json
import struct

BASE = Path('/home/luke/projects/kpi-intensive-2026-10-22')
PUBLIC = BASE/'observer/artifacts/public-v6-fixture-production-20261022T124051Z/public'
FIXTURES = BASE/'observer/poc/two-v6-state/public-fixtures'
MANIFEST_SHA = '3dec202e797fd714547de6ef77e76489c557188f4e4e38b2d01c0618c495f9c6'
PAIR_SHA = '7771a2e610d37fdb12b1d668b8e229bd3cd1e5fe83c5993847daa0fef8c93b36'
ZERO = bytes(32)
MAX = 2_900_000_000_000_000_000

def h(raw): return sha256(raw).digest()
def u32(n): return struct.pack('<I', n)
def u64(n): return struct.pack('<Q', n)
def parent(a,b): return h(b'\x01'+a+b)
def cm(c): return h(b'\x00'+c)
def historical(n,r): return h(b'\x03'+u32(n)+r)
def nfd(raw): return h(b'\x02'+raw)

class Sparse:
    def __init__(self, leaves, depth):
        self.leaves = dict(enumerate(leaves))
        self.depth = depth
        self.empty = [ZERO]
        for _ in range(depth): self.empty.append(parent(self.empty[-1],self.empty[-1]))
        @lru_cache(None)
        def at(height, index):
            lo, hi = index << height, (index+1) << height
            if not any(lo <= pos < hi for pos in self.leaves): return self.empty[height]
            if height == 0: return self.leaves.get(index,ZERO)
            return parent(at(height-1,index*2),at(height-1,index*2+1))
        self.at = at
    def root(self): return self.at(self.depth,0)
    def path(self, index):
        assert 0 <= index < 1 << self.depth
        return [self.at(level,(index>>level)^1) for level in range(self.depth)]

def fold(leaf,index,path):
    for sibling in path:
        leaf = parent(sibling,leaf) if index & 1 else parent(leaf,sibling)
        index >>= 1
    assert index == 0
    return leaf

def links(values):
    """Leaves indexed by insertion order, links derived from numeric ordering."""
    assert values[0] == ZERO and len(set(values)) == len(values)
    sorted_indices = sorted(range(len(values)),key=lambda i: values[i][::-1])
    assert sorted_indices[0] == 0
    following = dict(zip(sorted_indices,sorted_indices[1:]))
    return [v+u32(following.get(i,0))+values[following.get(i,0)]
            for i,v in enumerate(values)]

def state(cms,values,history):
    n,m = len(cms),len(values)-1
    assert 0<n<65536 and n%2==1 and 2<=m<=2*n and m%2==0
    assert len(history)==(n+1)//2 and history[-1]==Sparse(list(map(cm,cms)),16).root()
    return (b'\x07'+u32(n)+u32(m)+history[-1]
            +Sparse(list(map(nfd,links(values))),17).root()
            +Sparse([historical(2*i+1,r) for i,r in enumerate(history)],16).root())

def reconstruct(case,pair,base_cms):
    p=pair[:1088]
    assert p[:12]==b'KPI2V6P1\x01\x00\x02\x00'
    nfs=[p[92+32*i:124+32*i] for i in range(4)]
    records=[p[220+217*i:437+217*i] for i in range(4)]
    assert nfs==sorted(set(nfs)) and records==sorted(records)
    assert sorted(nfs,key=lambda b:b[::-1])!=nfs
    contexts=[pair[1088+875*i+40:1088+875*i+76] for i in range(2)]
    assert contexts[0]==contexts[1]
    a=int.from_bytes(contexts[0][:4],'little');anchor=contexts[0][4:]
    cms=list(base_cms)
    if case=='historical-anchor':
        cms += [h(b'KPI/public-two-v6-state/DO-NOT-FUND/extra-cm/'+str(i).encode()) for i in range(2)]
        outpoint=b'\x55'*32+u32(2)
    else:
        assert case=='current-anchor'
        outpoint=b'\x33'*32+u32(1)
    values=[ZERO,u32(1)+bytes(28),u32(2)+bytes(28)]
    history=[Sparse(list(map(cm,cms[:i])),16).root() for i in range(1,len(cms)+1,2)]
    before=state(cms,values,history);n=len(cms)
    assert a%2==1 and 1<=a<=n and history[(a-1)//2]==anchor
    history_tree=Sparse([historical(2*i+1,r) for i,r in enumerate(history)],16)
    anchor_path=history_tree.path((a-1)//2)
    assert fold(historical(a,anchor),(a-1)//2,anchor_path)==before[73:105]
    nf_wires=[]; steps=[]
    for nf in nfs:
        assert nf!=ZERO and nf not in values
        numeric=lambda v:v[::-1]
        pred=max((i for i,v in enumerate(values) if numeric(v)<numeric(nf)),key=lambda i:numeric(values[i]))
        old=links(values);oldraw=old[pred];index=len(values)
        first=Sparse(list(map(nfd,old)),17)
        path=first.path(pred)
        assert fold(nfd(oldraw),pred,path)==first.root()
        modified=list(old);modified[pred]=values[pred]+u32(index)+nf
        interim=Sparse(list(map(nfd,modified)),17)
        assert fold(nfd(modified[pred]),pred,path)==interim.root()
        append_path=interim.path(index)
        assert fold(ZERO,index,append_path)==interim.root()
        values.append(nf)
        finalraw=links(values)
        assert finalraw[pred]==modified[pred]
        assert finalraw[index]==nf+oldraw[32:]
        final=Sparse(list(map(nfd,finalraw)),17)
        assert fold(nfd(finalraw[index]),index,append_path)==final.root()
        nf_wires.append(u32(pred)+oldraw+b''.join(path+append_path))
        steps.append({'pred_index':pred,'append_index':index,'before':first.root().hex(),
                      'after_predecessor':interim.root().hex(),'after':final.root().hex()})
    cm_paths=[];prefixes=[]
    for i,r in enumerate(records):
        pos=len(cms);tree=Sparse(list(map(cm,cms)),16);path=tree.path(pos)
        assert fold(ZERO,pos,path)==tree.root()
        cms.append(r[:32]);after=Sparse(list(map(cm,cms)),16).root()
        assert fold(cm(r[:32]),pos,path)==after
        cm_paths.append(b''.join(path))
        if i%2:prefixes.append((len(cms),after))
    hist_paths=[]
    for count,root in prefixes:
        index=len(history);tree=Sparse([historical(2*i+1,r) for i,r in enumerate(history)],16)
        path=tree.path(index)
        assert index==(count-1)//2 and fold(ZERO,index,path)==tree.root()
        history.append(root)
        assert fold(historical(count,root),index,path)==Sparse([historical(2*i+1,r) for i,r in enumerate(history)],16).root()
        hist_paths.append(b''.join(path))
    after=state(cms,values,history)
    reserve=1_700_000_000;fee=int.from_bytes(p[76:92],'little')
    assert p[84:92]==bytes(8) and 0<fee<reserve<=MAX
    remaining=reserve-fee
    inp=pair+outpoint+before+u64(reserve)+b''.join(anchor_path)+b''.join(nf_wires+cm_paths+hist_paths)
    journal=b'KPI2V6S1'+b'\x01\x00'+h(p)+h(b'KPI/public-two-v6-state/DO-NOT-FUND/v1')+outpoint+before+after+u64(reserve)+u64(remaining)
    assert len(inp)==11219 and len(journal)==336 and len(after)==105
    derived={'input.bin':inp,'expected-prior-state.bin':before,'expected-next-state.bin':after,'expected-journal.bin':journal}
    for name,raw in derived.items():assert (FIXTURES/case/name).read_bytes()==raw,(case,name)
    return {'case':case,'prior_n':n,'next_n':len(cms),'prior_m':2,'next_m':len(values)-1,
            'anchor_count':a,'anchor_is_historical':a<n,'fee_sompi':fee,'reserve_sompi':reserve,'remaining_sompi':remaining,
            'files':{name:{'bytes':len(raw),'sha256':h(raw).hex()} for name,raw in derived.items()},'nf_steps':steps}

def main():
    raw_manifest=(FIXTURES/'manifest.json').read_bytes()
    assert h(raw_manifest).hex()==MANIFEST_SHA
    pair=(PUBLIC/'expected-input.bin').read_bytes();assert len(pair)==2846 and h(pair).hex()==PAIR_SHA
    base=json.loads((PUBLIC/'manifest.json').read_bytes())['common_membership_context']['commitments']
    cms=list(map(bytes.fromhex,base));assert len(cms)==3
    results=[reconstruct(case,pair,cms) for case in ['current-anchor','historical-anchor']]
    print(json.dumps({'scope':'Independent public synthetic S7 state/wire recount; no cryptographic verification or native acceptance',
                      'manifest_sha256':MANIFEST_SHA,'state_version':7,'proof_verification':False,'builds':False,'contexts':results},indent=2))

if __name__=='__main__':main()
