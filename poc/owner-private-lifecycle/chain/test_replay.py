"""Public accepted-boundary controls; no RPC, proof or original wallet access."""
import copy
from pathlib import Path
import unittest

from replay import bundle_public_paths, decimals, native_case


class ReplayBoundary(unittest.TestCase):
    def test_integer_sompi_conversion_is_exact_above_javascript_safe_integer(self):
        for value in (0,2**53+1,2_870_000_000_000_000_000,2**64-1):
            self.assertEqual(decimals(str(value)),value)
        for value in (True,False,1,1.0,'','01','+1','-1','1.0',' 1','１',str(2**64)):
            with self.subTest(value=value),self.assertRaises(ValueError):decimals(value)

    def test_populated_native_context_conversion_and_exact_outpoint(self):
        point={'transactionId':'11'*32,'index':0xffffffff}
        row={'transaction':{'version':1,'id':'22'*32,'inputs':[{'previousOutpoint':point,
            'signatureScript':'41'+'00'*64+'01','sequence':str(2**64-1),'computeBudget':1800}],
            'outputs':[{'value':str(2**53+1),'scriptPublicKey':'000020'+'33'*32+'ac','covenant':None}],
            'lockTime':'0','subnetworkId':'00'*20,'gas':'0','payload':'','storageMass':'123'},
            'accepted_input_contexts':[{'outpoint':point,'amount_sompi':str(2**53+2),
                'script_public_key':'0000aa20'+'44'*32+'87','block_daa_score':'605000000',
                'is_coinbase':False,'covenant_id':None}]}
        converted=native_case(row)
        self.assertEqual(converted['entries'][0]['amount'],2**53+2)
        self.assertEqual(converted['transaction']['outputs'][0]['value'],2**53+1)
        self.assertEqual(converted['transaction']['mass'],123)
        self.assertEqual(converted['transaction']['inputs'][0]['sequence'],2**64-1)
        for change in ('point','amount','count'):
            bad=copy.deepcopy(row)
            if change=='point':bad['accepted_input_contexts'][0]['outpoint']={**point,'index':1}
            elif change=='amount':bad['accepted_input_contexts'][0]['amount_sompi']=2**53+2
            else:bad['accepted_input_contexts']=[]
            with self.subTest(change=change),self.assertRaises(ValueError):native_case(bad)

    def test_page_metadata_is_enumerated_without_reading_or_decompressing(self):
        value={'pages':[{'path':'attempt-001/pages/00000.json.gz'}],
               'current_view':{'post_query_delta':{'pages':[{'path':'attempt-001/post-query/pages/00000.json.gz'}]}}}
        root=Path('/nonexistent-public-fixture')
        self.assertEqual(bundle_public_paths(value,root),(root/'attempt-001/pages/00000.json.gz',
                         root/'attempt-001/post-query/pages/00000.json.gz'))
        for bad_path in ('../BACKUP.json','/private/BACKUP.json','','a/../b','a//b','./a'):
            wrong=copy.deepcopy(value);wrong['pages'][0]['path']=bad_path
            with self.subTest(path=bad_path),self.assertRaises(ValueError):bundle_public_paths(wrong,root)
        duplicate=copy.deepcopy(value)
        duplicate['current_view']['post_query_delta']['pages']=copy.deepcopy(value['pages'])
        with self.assertRaises(ValueError):bundle_public_paths(duplicate,root)


if __name__=='__main__':unittest.main()
