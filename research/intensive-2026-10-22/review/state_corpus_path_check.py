#!/usr/bin/env python3
"""Check frozen public positives with independent stdlib path folds.

No architecture-module import, Rust invocation or cryptographic verifier. The
pair prefix must be the exact already-verified genuine public pair; this is a
state/path and complete-journal check only, not new proof-validity evidence.
"""
import json
from pathlib import Path
from state_assertion_recount import h, u32, u64, ZERO, MAX, cm, historical, nfd, fold, PUBLIC

ROOT=Path('/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/public-state-correctness-corpus-20261022T132924Z/public-corpus')
MANIFEST='19fc246c682a9545da41bec205535a6c76b6207dd05fdbf98ccf2fe1c9a74e6f'

def chunks(raw):
    assert len(raw)%32==0
    return [raw[i:i+32] for i in range(0,len(raw),32)]

def evaluate(raw, pair):
    assert len(raw)==11219 and raw[:2846]==pair
    s=raw[2882:2987]
    assert s[0]==7
    n=int.from_bytes(s[1:5],'little');m=int.from_bytes(s[5:9],'little')
    assert n%2==1 and 1<=n and n+4<65536
    assert 2<=m and m%2==0 and m<=2*n and m+4<131071
    r=int.from_bytes(raw[2987:2995],'little');f=int.from_bytes(pair[76:92],'little')
    assert 0<f<r<=MAX
    a=int.from_bytes(pair[1128:1132],'little');anchor=pair[1132:1164]
    assert a%2==1 and 1<=a<=n
    assert fold(historical(a,anchor),(a-1)//2,chunks(raw[2995:3507]))==s[73:105]
    assert a!=n or anchor==s[9:41]
    root=s[41:73];nf_steps=[]
    for i in range(4):
        w=raw[3507+1160*i:4667+1160*i]
        pred=int.from_bytes(w[:4],'little');value=w[4:36]
        nxt=int.from_bytes(w[36:40],'little');next_value=w[40:72]
        index=m+i+1;target=pair[92+32*i:124+32*i]
        assert pred<index and (pred==0)==(value==ZERO)
        assert value[::-1]<target[::-1]
        assert next_value==ZERO or target[::-1]<next_value[::-1]
        assert (next_value==ZERO and nxt==0) or (next_value!=ZERO and 0<nxt<index)
        path=chunks(w[72:616]);empty=chunks(w[616:])
        assert fold(nfd(w[4:72]),pred,path)==root
        mid=fold(nfd(value+u32(index)+target),pred,path)
        assert fold(ZERO,index,empty)==mid
        root=fold(nfd(target+w[36:72]),index,empty)
        nf_steps.append(root.hex())
    cm_root=s[9:41];cm_steps=[]
    for i in range(4):
        path=chunks(raw[8147+512*i:8659+512*i])
        assert fold(ZERO,n+i,path)==cm_root
        cm_root=fold(cm(pair[220+217*i:252+217*i]),n+i,path)
        cm_steps.append(cm_root.hex())
    hist_root=s[73:105];hist_steps=[]
    for i,prefix in enumerate([bytes.fromhex(cm_steps[1]),cm_root]):
        index=(n+1)//2+i;path=chunks(raw[10195+512*i:10707+512*i])
        assert fold(ZERO,index,path)==hist_root
        hist_root=fold(historical(n+2*(i+1),prefix),index,path)
        hist_steps.append(hist_root.hex())
    nxt=b'\x07'+u32(n+4)+u32(m+4)+cm_root+root+hist_root
    j=(b'KPI2V6S1\x01\x00'+h(pair[:1088])+h(b'KPI/public-two-v6-state/DO-NOT-FUND/v1')
       +raw[2846:2882]+s+nxt+u64(r)+u64(r-f))
    assert len(j)==336
    return nxt,j,nf_steps,cm_steps,hist_steps

def main():
    source=(ROOT/'manifest.json').read_bytes();assert h(source).hex()==MANIFEST
    manifest=json.loads(source);pair=(PUBLIC/'expected-input.bin').read_bytes()
    results=[]
    for case in manifest['positives']:
        raw=(ROOT/case['id']/'input.bin').read_bytes()
        assert h(raw).hex()==case['input_sha256']
        nxt,j,nf_steps,cm_steps,hist_steps=evaluate(raw,pair)
        assert nxt.hex()==case['next_state']
        assert j==(ROOT/case['id']/'expected-journal.bin').read_bytes()
        assert h(j).hex()==case['journal_sha256']
        assert nf_steps==[x['after_root'] for x in case['nf_steps']]
        assert cm_steps==case['intermediate_cm_roots']
        assert hist_steps==case['intermediate_history_roots']
        results.append({'id':case['id'],'journal_sha256':h(j).hex(),'next_state_sha256':h(nxt).hex()})
    for case in manifest['negatives']:
        raw=(ROOT/'negative'/case['id']/'input.bin').read_bytes()
        assert h(raw).hex()==case['input_sha256'] and len(raw)==case['input_bytes']
    print(json.dumps({'scope':'Independent public path-fold and exact-J336 recount only; no proof/native/Rust execution',
                      'manifest_sha256':MANIFEST,'positive_exact_matches':len(results),'negative_file_identities_checked':len(manifest['negatives']),
                      'negative_expectation_source_review':'One retained pre-Rust label defect: nf-equality-wire actual sentinel-link guard precedes numeric-order guard.',
                      'results':results},indent=2))

if __name__=='__main__':main()
