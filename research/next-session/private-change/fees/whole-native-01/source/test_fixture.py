import unittest
import fixture as f

def root(leaf,path,index,tag):
    for sibling in path:
        leaf=f.h(tag,sibling,leaf) if index&1 else f.h(tag,leaf,sibling);index//=2
    return leaf

class PublicFixtureControls(unittest.TestCase):
    def test_CM_boundary_matches_dense_independent_tree(self):
        for count in (2,32):
            tree=f.cm_tree();start=count;level=count.bit_length()-1
            boundary=tree.path(start//count,level);empty=tree.empty[level]
            self.assertEqual(root(empty,boundary,start//count,tree.tag),tree.root)
            leaves=[f.h(b'INDEPENDENT',f.u(i,4)) for i in range(count)]
            dense=leaves[:]
            while len(dense)>1:dense=[f.h(tree.tag,dense[i],dense[i+1]) for i in range(0,len(dense),2)]
            for i,leaf in enumerate(leaves):tree.set(start+i,leaf)
            self.assertEqual(root(dense[0],boundary,start//count,tree.tag),tree.root)
            self.assertNotEqual(root(f.h(b'BAD'),boundary,start//count,tree.tag),tree.root)

    def test_two_NF_witnesses_authenticate_sequential_absence_and_updates(self):
        old,expected,rows=f.nf_transition();current=old;zero=bytes(32)
        empty=f.h(b'KPX1NFE\0');tag=b'KPX1NFN\0'
        for append,(nf,w) in enumerate(rows,1):
            pi=int.from_bytes(w[:4],'little');pv,pn=w[4:36],w[36:68];pni=int.from_bytes(w[68:72],'little')
            pp=[w[i:i+32] for i in range(72,616,32)];ap=[w[i:i+32] for i in range(616,1160,32)]
            self.assertEqual(root(f.nf_leaf(pv,pn,pni),pp,pi,tag),current)
            repaired=root(f.nf_leaf(pv,nf,append),pp,pi,tag)
            self.assertEqual(root(empty,ap,append,tag),repaired)
            current=root(f.nf_leaf(nf,pn,pni),ap,append,tag)
            self.assertLess(int.from_bytes(pv,'little'),int.from_bytes(nf,'little'))
            self.assertTrue(pn==zero or int.from_bytes(nf,'little')<int.from_bytes(pn,'little'))
        self.assertEqual(current,expected)
        # A second insertion witness cannot be replayed against the original root.
        nf,w=rows[1];pp=[w[i:i+32] for i in range(72,616,32)]
        self.assertNotEqual(root(f.nf_leaf(w[4:36],w[36:68],int.from_bytes(w[68:72],'little')),pp,1,tag),old)

    def test_caps_and_serialized_widths(self):
        for n in (0,2,32):
            size=2848 if n==0 else 2848+296*n+32*(16-(n.bit_length()-1))
            self.assertEqual(size,{0:2848,2:3920,32:12672}[n])
        self.assertEqual(len(f.state(bytes(32),65535,bytes(32),131071)),112)
        self.assertEqual(len(f.PAYOUT_SPK),36)

if __name__=='__main__':unittest.main()
