"""Terminal acceptance gates must reject partial, reordered or nonzero histories."""
import copy
import unittest
import final


def fixture():
    checkpoint={'reserve_sompi':0,'outpoint_hex36':None,'state_hex112':'public-test-placeholder'}
    history={'head':checkpoint,'transitions':[{'kind':'payment'} for _ in range(6)]+[{'kind':'exit'} for _ in range(9)]}
    context={'checkpoint':checkpoint}
    handoff={'accepted_transactions':16,'terminal':True,'checkpoint':checkpoint,'native_payouts_observed':[{} for _ in range(9)]}
    return handoff,history,context


class TerminalGates(unittest.TestCase):
    def test_complete_shape_only_passes_structural_gate(self):
        a,b,c=fixture();self.assertIs(final.require_terminal(a,b,c),c['checkpoint'])
    def test_genesis_only_cannot_be_reported_as_terminal(self):
        a,b,c=fixture();a.update(accepted_transactions=1,terminal=False)
        with self.assertRaises(ValueError):final.require_terminal(a,b,c)
    def test_missing_exit_or_payout_rejected(self):
        for mutate in (lambda a,b,c:b['transitions'].pop(),lambda a,b,c:a['native_payouts_observed'].pop()):
            a,b,c=fixture();mutate(a,b,c)
            with self.assertRaises(ValueError):final.require_terminal(a,b,c)
    def test_reordered_or_extra_private_actions_rejected(self):
        a,b,c=fixture();b['transitions'][0]['kind']='exit';b['transitions'][6]['kind']='payment'
        with self.assertRaises(ValueError):final.require_terminal(a,b,c)
    def test_positive_remaining_reserve_rejected(self):
        a,b,c=fixture();c['checkpoint']['reserve_sompi']=1
        with self.assertRaises(ValueError):final.require_terminal(a,b,c)
    def test_boolean_or_negative_sompi_rejected(self):
        for value in (True,-1,1.5,'100'):
            with self.assertRaises(ValueError):final.integer(value)
    def test_fee_derived_from_whole_native_values(self):
        case={'entries':[{'amount':1000},{'amount':2000}],
              'transaction':{'outputs':[{'value':2993}]}}
        self.assertEqual(final.fee(case),7)
        case['transaction']['outputs'][0]['value']=3001
        with self.assertRaises(ValueError):final.fee(case)

if __name__=='__main__':unittest.main()
