#!/usr/bin/env python3
"""Analytic controls, independent of the four-wallet private schedule."""
import copy
import unittest
from observe import Model
from score import score
from amounts import infer_input


def event(step,mode,fee,payout,deposit,reserve,new):
    return {'step':step,'mode':mode,'fee':fee,'payout':payout,'deposit':deposit,'reserve_out':reserve,'new_cm':new}


def fixture():
    return {'cm':'g','value':100},[
        event(2,1,1,0,0,99,['a','b']),
        event(3,0,1,0,30,128,['d']),
        event(4,2,1,28,0,99,[]),
    ]


class ObserverControls(unittest.TestCase):
    def test_single_member_bootstrap(self):
        initial,events=fixture();rows=Model(initial,events[:1]).attacks()
        self.assertEqual(rows[0]['consumed_commitment_candidates'],['g'])
        self.assertEqual(rows[0]['deposit_origin_candidates'],['g'])

    def test_multiple_histories_not_just_recency(self):
        initial,events=fixture();row=Model(initial,events).attacks()[-1]
        self.assertEqual(set(row['consumed_commitment_candidates']),{'a','b','d'})
        self.assertEqual(set(row['deposit_origin_candidates']),{'g','d'})
        self.assertEqual(row['recency_candidates'],['d'])
        self.assertEqual(row['source_transaction_candidates'],[2,3])
        self.assertEqual(row['exact_input_value_sompi'],'29')

    def test_future_information_only_changes_later_snapshot(self):
        initial,events=fixture();before=Model(initial,events).attacks()[-1]
        # A later 89-unit note leaves a 10-unit sibling. Neither could have
        # supplied the earlier whole-note 29-unit exit, fixing its deposit.
        later=events+[event(5,2,1,88,0,10,[])]
        after=Model(initial,later).attacks()[1]
        self.assertEqual(len(before['consumed_commitment_candidates']),3)
        self.assertEqual(after['consumed_commitment_candidates'],['d'])
        self.assertEqual(after['deposit_origin_candidates'],['d'])
        self.assertEqual(len(Model(initial,events).attacks()[-1]['consumed_commitment_candidates']),3)

    def test_partial_does_not_directly_reveal_input_value(self):
        initial,events=fixture();events[-1]=event(4,4,1,9,0,118,['c'])
        model=Model(initial,events);row=model.attacks()[-1]
        self.assertIsNone(row['exact_input_value_sompi'])
        self.assertEqual(set(row['consumed_commitment_candidates']),{'a','b','d'})
        # The consumed genesis child can take different values consistently.
        import z3
        self.assertTrue(model.possible(z3.And(model.choices[4]==1,model.notes[1]['v']==20)))
        self.assertTrue(model.possible(z3.And(model.choices[4]==1,model.notes[1]['v']==30)))

    def test_partial_amount_revealed_only_by_later_drain(self):
        initial,events=fixture();events[-1]=event(4,4,1,9,0,118,['c'])
        before=infer_input(Model(initial,events),events[-1]);self.assertIsNone(before['forced_sompi'])
        later=events+[event(5,2,1,88,0,29,[]),event(6,2,1,9,0,19,[]),event(7,3,1,18,0,0,[])]
        after=infer_input(Model(initial,later),events[-1]);self.assertEqual(after['forced_sompi'],'29')
        self.assertFalse(after['direct'])

    def test_inconsistent_public_balance_is_not_anonymity(self):
        initial,events=fixture();events[-1]['reserve_out']+=1
        with self.assertRaises(ValueError):Model(initial,events)

    def test_commitment_label_permutation_invariant(self):
        initial,events=fixture();before=Model(initial,events).attacks()
        rename={'g':'z','a':'y','b':'x','d':'w'}
        changed=copy.deepcopy(events)
        for e in changed:e['new_cm']=[rename[c] for c in e['new_cm']]
        after=Model({'cm':'z','value':100},changed).attacks()
        for b,a in zip(before,after):
            self.assertEqual({rename[c] for c in b['consumed_commitment_candidates']},set(a['consumed_commitment_candidates']))
            self.assertEqual({rename[c] for c in b['deposit_origin_candidates']},set(a['deposit_origin_candidates']))

    def test_scoring_rejects_excluded_ground_truth(self):
        observed={'horizons':{'test':{'events':[{'step':2,'mode':2,'consumed_commitment_candidates':['wrong'],'deposit_origin_candidates':['g'],'recency_candidates':['wrong'],'exact_input_value_sompi':'100'}]}}}
        truth={'arm':'full','initial':{'cm':'g'},'firstWithdrawalHorizon':2,'events':[{'step':2,'mode':2,'spent_cm':'g','outputs':[],'wallet':0}]}
        with self.assertRaises(AssertionError):score(truth,observed)

if __name__=='__main__':unittest.main()
