#!/usr/bin/env python3
"""Independent diagnostic decoder; no proof verification or native acceptance."""
import hashlib,json,struct,sys
from pathlib import Path

BASE=int('40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001',16)
SCALAR=int('40000000000000000000000000000000224698fc094cf91b992d30ed00000001',16)

class Reader:
    def __init__(self,data): self.data=data;self.i=0;self.nodes=0;self.selectors=0;self.layout=None
    def take(self,n):
        if n<0 or self.i+n>len(self.data): raise ValueError('truncated capsule')
        v=self.data[self.i:self.i+n];self.i+=n;return v
    def integer(self,n,signed=False): return int.from_bytes(self.take(n),'little',signed=signed)
    def count(self):
        n=self.integer(4)
        if n>1_000_000: raise ValueError('count limit')
        return n
    def field(self):
        n=self.integer(32)
        if n>=SCALAR: raise ValueError('noncanonical scalar')
        return n
    def point(self):
        raw=self.take(32);n=int.from_bytes(raw,'little');x=n&((1<<255)-1);sign=n>>255
        if x>=BASE: raise ValueError('noncanonical Vesta x')
        if x==0 and sign==0: return raw
        y2=(pow(x,3,BASE)+5)%BASE
        if pow(y2,(BASE-1)//2,BASE)!=1: raise ValueError('point not on Vesta')
        return raw
    def vector(self,f): return [f() for _ in range(self.count())]
    def expr(self,depth=0):
        self.nodes+=1
        if depth>256 or self.nodes>100_000: raise ValueError('expression bound')
        tag=self.integer(1)
        if tag==0: self.field();return 0
        if tag==1:
            self.count();assert self.integer(1) in (0,1);self.selectors+=1;return 1
        if tag in (2,3,4):
            qi,ci,rot=self.count(),self.count(),self.integer(4,True)
            kind={2:'fixed',3:'advice',4:'instance'}[tag]
            assert self.layout[kind][qi]==[ci,rot]
            return 1
        if tag==5:return self.expr(depth+1)
        if tag in (6,7):
            a,b=self.expr(depth+1),self.expr(depth+1)
            return max(a,b) if tag==6 else a+b
        if tag==8:self.field();return self.expr(depth+1)
        raise ValueError('unknown expression tag')

def parse(data,description):
    r=Reader(data);assert r.take(8)==b'KASPVK01';assert [r.integer(2) for _ in range(4)]==[1,1,1,1]
    assert r.integer(32)==BASE and r.integer(32)==SCALAR
    root,delta,zeta=r.field(),r.field(),r.field()
    assert pow(root,1<<32,SCALAR)==1 and pow(root,1<<31,SCALAR)!=1
    assert delta==pow(5,1<<32,SCALAR) and pow(zeta,3,SCALAR)==1 and zeta!=1
    params=r.take(r.count());pr=Reader(params);k=pr.count();assert k==11;n=1<<k
    for _ in range(2*n+2):pr.point()
    assert pr.i==len(params)==4+32*(2*n+2)
    assert r.count()==k;extended_k=r.count();omega,extended_omega,coset=r.field(),r.field(),r.field()
    quotient_degree,degree,blinding,minimum_rows=[r.count() for _ in range(4)]
    assert omega==pow(root,1<<(32-k),SCALAR)
    assert extended_omega==pow(root,1<<(32-extended_k),SCALAR) and coset==zeta
    expected_k=k
    while (1<<expected_k)<n*quotient_degree:expected_k+=1
    assert expected_k==extended_k and quotient_degree==degree-1 and minimum_rows==blinding+3
    transcript_offset=r.i;transcript=r.field()
    desc=description.encode();full=hashlib.blake2b(struct.pack('<Q',len(desc))+desc,person=b'Halo2-Verify-Key',digest_size=64).digest()
    assert int.from_bytes(full,'little')%SCALAR==transcript
    fixed,advice,instance,selectors=[r.count() for _ in range(4)]
    advice_counts=r.vector(r.count);assert len(advice_counts)==advice
    optional=r.integer(1);assert optional in (0,1);minimum_degree=r.count() if optional else None
    constants=r.vector(r.count);assert all(c<fixed for c in constants)
    layouts={}
    for kind,limit in [('advice',advice),('fixed',fixed),('instance',instance)]:
        layouts[kind]=r.vector(lambda:[r.count(),r.integer(4,True)])
        assert all(c<limit for c,rot in layouts[kind])
        assert len({tuple(v) for v in layouts[kind]})==len(layouts[kind])
    assert advice_counts==[sum(c==i for c,rot in layouts['advice']) for i in range(advice)]
    assert blinding==max(3,max(advice_counts,default=1))+2
    r.layout=layouts
    gates=r.vector(lambda:r.vector(r.expr))
    lookups=r.vector(lambda:[r.vector(r.expr),r.vector(r.expr)])
    assert all(len(a)==len(b) for a,b in lookups)
    assert r.selectors==0,'post-compression selector remained'
    lookup_degree=max([max(4,2+max([1]+a)+max([1]+b)) for a,b in lookups],default=1)
    assert degree==max([3,minimum_degree or 1,lookup_degree]+[d for g in gates for d in g])
    permutation=r.vector(lambda:[r.integer(1),r.count()]);limits=[advice,fixed,instance]
    assert all(t<3 and c<limits[t] for t,c in permutation)
    assert len(set(map(tuple,permutation)))==len(permutation)
    fixed_points=r.vector(r.point);permutation_points=r.vector(r.point)
    assert len(fixed_points)==fixed and len(permutation_points)==len(permutation)
    assert r.i==len(data),'trailing bytes'
    return {'schema':'KASPVK01/1','curve':'Vesta','fixed_circuit':'FixedPostNu6_2',
      'capsule_bytes':len(data),'capsule_sha256':hashlib.sha256(data).hexdigest(),
      'params_bytes':len(params),'params_sha256':hashlib.sha256(params).hexdigest(),
      'compatibility_transcript_scalar_le32':transcript.to_bytes(32,'little').hex(),
      'compatibility_transcript_scalar_offset':transcript_offset,
      'domain':{'k':k,'n':n,'extended_k':extended_k,'quotient_degree':quotient_degree,'omega_le32':omega.to_bytes(32,'little').hex()},
      'cs':{'degree':degree,'blinding_factors':blinding,'minimum_rows':minimum_rows,'fixed_columns':fixed,'advice_columns':advice,'instance_columns':instance,'selectors_before_compression':selectors,'minimum_degree':minimum_degree,'constant_column_indices':constants,'advice_query_counts_per_column':advice_counts,'query_layouts':layouts,'permutation_column_layout':permutation,'gate_groups':len(gates),'gate_polynomials':sum(map(len,gates)),'lookup_arguments':len(lookups),'query_counts':{k:len(v) for k,v in layouts.items()},'permutation_columns':len(permutation),'permutation_chunk_len':degree-2,'expression_nodes':r.nodes},
      'checks':{'canonical_complete_decode':True,'field_and_curve_encodings':True,'domain_query_ast_degree_consistency':True,'upstream_compatibility_scalar_provenance':True},
      'limitations':'not an independent Halo2 verifier, constraint soundness proof, native key import or activation'}

if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('run conformance checks without Python optimization')
    folder = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parents[1] / 'artifacts'
    data = (folder / 'fixed-post-nu6-2.vk-capsule.bin').read_bytes()
    if hashlib.sha256(data).hexdigest() != '743fa19c541fa2c7881c4ed0e3340c82d88780dbbc549cc2f3bfd982c2e517e0':
        raise ValueError('capsule is not the fixed native research key')
    description = (folder / 'upstream-pinned-key-description.txt').read_bytes().decode('utf-8')
    report = parse(data, description)
    expected = json.loads((folder / 'portable-key-manifest.json').read_text())
    if report != expected:
        raise ValueError('portable manifest differs from decoded key')
    print('Portable key: 206564 canonical bytes, fixed identity, field/curve/query/AST/domain checks and compatibility scalar provenance OK. No native import or independent Halo2 verification.')
