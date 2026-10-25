"""Synthetic observation conversion controls; no proof, acceptance or network."""
import copy
from types import SimpleNamespace
import unittest

from confirm import derive_observation,point_key,typed_entry

H=lambda c:c*64
SPK='000020'+'44'*32+'ac'
SOURCE={'transactionId':H('1'),'index':0}
GENESIS={'transactionId':H('2'),'index':0}
HEAD={'transactionId':H('3'),'index':0}
PAID={'transactionId':H('3'),'index':1}
DAA='9007199254740993'


def entry(at,amount):
    return {'outpoint':at,'amount_sompi':str(amount),'script_public_key':SPK,
            'block_daa_score':DAA,'is_coinbase':False,'covenant_id':None}


def query(at,value=None):
    return {'outpoint':at,'queried':True,'entry':value}


def fixture(terminal=False):
    head={'outpoint_hex36':None if terminal else point_key(HEAD),
          'state_hex112':'00'*112,'reserve_sompi':0 if terminal else 90}
    paid={'transactionId':H('3'),'index':0 if terminal else 1}
    queries=[query(SOURCE),query(GENESIS),query(paid,entry(paid,9))]
    if not terminal:queries.append(query(HEAD,entry(HEAD,90)))
    fetch={'transactions':[{'transaction':{'id':H('2'),'inputs':[{'previousOutpoint':SOURCE}]}},
             {'transaction':{'id':H('3'),'inputs':[{'previousOutpoint':GENESIS}]}}],
           'current_view':{'queries':queries},'terminal_candidate_not_yet_replay_verified':terminal}
    history={'head':head}
    report={'current_checkpoint':head,'payouts':[{'transaction_id':H('3'),
             'output_index':paid['index'],'payout_sompi':9,'script_public_key':SPK}]}
    return copy.deepcopy((fetch,history,head,report))


class PublicContract:
    """Only the independent history/SPK boundary is mocked in these unit tests."""
    def current_entry_context(self,history,tail,current):
        assert tail=='51'
        assert point_key(current['outpoint'])==history['head']['outpoint_hex36']
        assert current['entry']['amount']==history['head']['reserve_sompi']
        assert current['entry']['scriptPublicKey']==SPK


def derive(values,expected=H('3')):
    return derive_observation(*values,SimpleNamespace(tail=b'\x51'),expected,PublicContract())


class Controls(unittest.TestCase):
    def test_fresh_queried_birth_DAA_and_all_payouts(self):
        current,payouts=derive(fixture())
        self.assertEqual(current['entry']['blockDaaScore'],9007199254740993)
        self.assertEqual(payouts[0]['entry']['amount'],9)
        self.assertEqual(current['outpoint'],HEAD)

    def test_expected_transaction_must_be_latest_accepted_transition(self):
        for expected in (H('2'),H('4')):
            with self.assertRaises(ValueError):derive(fixture(),expected)

    def test_missing_changed_or_duplicated_current_observation_rejects(self):
        for change in ('missing','amount','script','point','duplicate','coinbase','covenant','integer-DAA'):
            values=fixture();q=values[0]['current_view']['queries'][-1]
            if change=='missing':q['entry']=None
            elif change=='amount':q['entry']['amount_sompi']='89'
            elif change=='script':q['entry']['script_public_key']='000020'+'55'*32+'ac'
            elif change=='point':q['entry']['outpoint']=SOURCE
            elif change=='duplicate':values[0]['current_view']['queries'].append(copy.deepcopy(q))
            elif change=='coinbase':q['entry']['is_coinbase']=True
            elif change=='covenant':q['entry']['covenant_id']=H('5')
            else:q['entry']['block_daa_score']=9007199254740993
            with self.assertRaises((ValueError,AssertionError)):derive(values)

    def test_all_accepted_inputs_must_be_spent(self):
        values=fixture();values[0]['current_view']['queries'][1]['entry']=entry(GENESIS,100)
        with self.assertRaises(ValueError):derive(values)

    def test_missing_or_substituted_payout_rejects(self):
        for change in ('missing','amount','script','point'):
            values=fixture();q=values[0]['current_view']['queries'][2]
            if change=='missing':q['entry']=None
            elif change=='amount':q['entry']['amount_sompi']='8'
            elif change=='script':q['entry']['script_public_key']='000020'+'55'*32+'ac'
            else:q['entry']['outpoint']=SOURCE
            with self.assertRaises(ValueError):derive(values)

    def test_terminal_zero_has_no_current_reserve_and_keeps_actual_payout(self):
        current,payouts=derive(fixture(terminal=True))
        self.assertIsNone(current);self.assertEqual(payouts[0]['outpoint']['index'],0)
        values=fixture(terminal=True)
        for row in (values[1]['head'],values[2],values[3]['current_checkpoint']):row['reserve_sompi']=1
        with self.assertRaises(ValueError):derive(values)


if __name__=='__main__':unittest.main()
