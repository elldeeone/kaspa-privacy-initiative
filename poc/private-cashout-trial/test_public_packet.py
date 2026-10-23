"""Public nested-canary rejection; no private paths, witness, VM or prover."""
import copy
from pathlib import Path
import unittest

import prepare as p
import public_packet as export
import trial as t


class PublicPacketBoundaries(unittest.TestCase):
    def fixture(self,index=1):
        base=t.ROOT/'research/next-session/private-service-loss/trial/preparation-public-01'/f'case-{index:04d}'
        return [p.read(base/name) for name in ('transaction.json','supplied-context.json',
                                             'validation-case.json','metrics.json')]

    def test_all_four_public_cases_remain_eligible(self):
        for index in range(4):
            export.checked_public_case(*self.fixture(index),index>0)

    def test_nested_private_canaries_rejected(self):
        for slot in ('context','input','output','entry','payload'):
            body,contexts,case,metrics=copy.deepcopy(self.fixture())
            if slot=='payload':
                body['payload']={'private_canary':{'seed_hex32':'PUBLIC_CANARY_DO_NOT_EXPORT'}}
            else:
                target={'context':contexts[0],'input':body['inputs'][0],
                        'output':body['outputs'][0],'entry':case['entries'][0]}[slot]
                target['private_canary']={'seed_hex32':'PUBLIC_CANARY_DO_NOT_EXPORT'}
            if slot in ('input','output','payload'):case['transaction']=body
            with self.subTest(slot=slot),self.assertRaises(ValueError):
                export.checked_public_case(body,contexts,case,metrics,True)

    def test_native_entry_must_equal_actual_public_context(self):
        body,contexts,case,metrics=copy.deepcopy(self.fixture())
        case['entries'][0]['amount']+=1
        with self.assertRaisesRegex(ValueError,'entry-context-binding'):
            export.checked_public_case(body,contexts,case,metrics,True)


if __name__=='__main__':unittest.main()
