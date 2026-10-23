"""Independent dense-tree fixture oracle and canonical-encoding controls, no VM."""
import hashlib
import unittest

import kernel


def dense_root(leaves):
    nodes=[hashlib.sha256(b'KPX1CME\0').digest()]*(1<<16)
    for index,leaf in leaves.items():nodes[index]=leaf
    while len(nodes)>1:
        nodes=[hashlib.sha256(b'KPX1CMN\0'+nodes[i]+nodes[i+1]).digest() for i in range(0,len(nodes),2)]
    return nodes[0]


class KernelControls(unittest.TestCase):
    def test_same_root_against_dense_oracle(self):
        leaves={i:hashlib.sha256(b'KPX/FEE/PUBLIC/PREFIX/'+i.to_bytes(4,'little')).digest() for i in range(32)}
        old=dense_root(leaves)
        for n in (4,8,16,32):
            updated=dict(leaves,**{})
            updated.update({32+i:hashlib.sha256(b'KPX/FEE/PUBLIC/NEW/'+i.to_bytes(4,'little')).digest() for i in range(n)})
            new=dense_root(updated)
            for mode in ('baseline','subtree'):
                case,meta=kernel.fixture(n,mode)
                self.assertEqual(meta['old_root'],old.hex());self.assertEqual(meta['new_root'],new.hex())
                self.assertEqual(case['transaction']['inputs'][0]['sequence'],'18446744073709551615')

    def test_native_signed_integer_and_data_encoding_boundaries(self):
        self.assertEqual(kernel.number(0),b'\0');self.assertEqual(kernel.number(16),b'\x60')
        self.assertEqual(kernel.number(128),b'\x02\x80\0')
        self.assertEqual(kernel.push(b'x'*256)[:3],b'\x4d\0\x01')
        self.assertEqual(kernel.push(b'x'*65536)[:5],b'\x4e\0\0\x01\0')

    def test_occupied_target_has_authentic_different_old_root(self):
        for n in (4,8,16,32):
            for mode in ('baseline','subtree'):
                _,good=kernel.fixture(n,mode);_,bad=kernel.fixture(n,mode,'occupied')
                self.assertNotEqual(good['old_root'],bad['old_root'])
                self.assertEqual(good['new_root'],bad['new_root'])
                self.assertFalse(bad['expected_native_acceptance'])


if __name__=='__main__':unittest.main()
