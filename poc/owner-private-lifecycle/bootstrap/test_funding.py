"""Public ordinary funding boundary controls; no private wallet reads."""
import copy
import unittest
import uuid

from fund_worker import DOMAIN,sources
from run_miner import reserve_mining_attempt


def fixture():
    spk='000020'+'12'*32+'ac'
    value={'schema':'kpx8-own-mature-coinbase-observation/v1','network_id':'testnet-10',
      'genesis_hash_hex':'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
      'domain_hex32':DOMAIN.hex(),'trial_id':'2a93ba31-0220-47d8-a845-369adadd0c95',
      'participant_id_hex32':'34'*32,'funding_script_public_key':spk,'virtual_daa_score':'1010',
      'sources':[{'outpoint':{'transactionId':'56'*32,'index':0},'entry':{'amount':'3000000000',
        'scriptPublicKey':spk,'blockDaaScore':'10','isCoinbase':True,'covenantId':None}}]}
    return value,spk


class FundingBoundary(unittest.TestCase):
    def test_mining_attempt_is_consumed_across_controller_restarts(self):
        trial=str(uuid.uuid4())
        reserve_mining_attempt(trial,0,'11'*32,'22'*32)
        with self.assertRaises(FileExistsError):reserve_mining_attempt(trial,0,'11'*32,'22'*32)
        # Other fresh parties in this trial retain independent mining attempts.
        reserve_mining_attempt(trial,1,'11'*32,'22'*32)
    def test_exact_maturity_and_decimal_conversion_leave_source_unchanged(self):
        value,spk=fixture();before=copy.deepcopy(value)
        rows,total=sources(value,spk)
        self.assertEqual(total,3_000_000_000);self.assertEqual(rows[0]['entry']['amount'],3_000_000_000)
        self.assertEqual(value,before)

    def test_immature_wrong_owner_duplicate_and_malformed_amount_reject(self):
        value,spk=fixture()
        for change in ('immature','owner','duplicate','float','bool','leading-zero','wrong-domain','coinbase'):
            bad=copy.deepcopy(value)
            if change=='immature':bad['virtual_daa_score']='1009'
            elif change=='owner':bad['sources'][0]['entry']['scriptPublicKey']='000020'+'78'*32+'ac'
            elif change=='duplicate':bad['sources'].append(copy.deepcopy(bad['sources'][0]))
            elif change=='float':bad['sources'][0]['entry']['amount']=3e9
            elif change=='bool':bad['sources'][0]['entry']['blockDaaScore']=True
            elif change=='leading-zero':bad['sources'][0]['entry']['amount']='03000000000'
            elif change=='wrong-domain':bad['domain_hex32']='00'*32
            else:bad['sources'][0]['entry']['isCoinbase']=False
            with self.subTest(change=change),self.assertRaises(ValueError):sources(bad,spk)


if __name__=='__main__':unittest.main()
