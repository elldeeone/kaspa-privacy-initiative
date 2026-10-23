"""Public synthetic integer controls, without any cryptographic execution."""
import random
import unittest

import economics as e


class Accounting(unittest.TestCase):
    def fees(self, values=(20_000_000,) * 5):
        return dict(zip(e.FEE_NAMES, values))

    def test_three_payouts_and_both_ordinary_change_tails(self):
        result=e.reconcile(self.fees(),funding_input_sompi=1_200_000_000,
            funding_output_sompi=1_100_000_000,funding_fee_sompi=500_000,
            funding_change_sompi=99_500_000,founding_fee_sompi=1_000_000,
            founding_change_sompi=79_000_000)
        self.assertEqual(result['all_native_payouts_sompi'],920_000_000)
        self.assertEqual(result['all_fees_sompi'],101_500_000)
        self.assertEqual(result['all_ordinary_change_sompi'],178_500_000)

    def test_exact_note_and_payout_floor_then_one_sompi_below(self):
        fees=self.fees((1,120_000_000,120_000_000,50_000_000,290_000_000))
        flow=e.derive(fees)
        self.assertEqual(flow['actions'][2]['output_notes_sompi'],[60_000_000,300_000_000])
        self.assertEqual(flow['actions'][3]['payout_sompi'],10_000_000)
        self.assertEqual(flow['actions'][4]['payout_sompi'],10_000_000)
        for field,category in (('change-payment','payment-positive-change-floor'),
                               ('owner-full','owner-final-payout-floor'),
                               ('recipient-terminal','recipient-final-payout-floor')):
            altered=dict(fees);altered[field]+=1
            with self.assertRaisesRegex(ValueError,category):e.derive(altered)

    def test_non_integer_nonpositive_and_unknown_fee_fields(self):
        for value in (True,False,'1','01',1.0,0,-1,e.MAX_SOMPI+1):
            fees=self.fees();fees['partial-cashout']=value
            with self.assertRaises(ValueError):e.derive(fees)
        fees=self.fees();fees['ignored-change']=1
        with self.assertRaisesRegex(ValueError,'exact-five-private-fees'):e.derive(fees)

    def test_one_sompi_missing_from_either_source_tail_is_rejected(self):
        values=dict(funding_input_sompi=1_200_000_000,funding_output_sompi=1_100_000_000,
            funding_fee_sompi=500_000,funding_change_sompi=99_500_000,
            founding_fee_sompi=1_000_000,founding_change_sompi=79_000_000)
        for field in ('funding_change_sompi','founding_change_sompi'):
            wrong=dict(values);wrong[field]-=1
            with self.assertRaisesRegex(ValueError,'conservation'):e.reconcile(self.fees(),**wrong)

    def test_generated_fee_partitions_preserve_independent_liabilities(self):
        rng=random.Random(55)
        for _ in range(250):
            f1=rng.randint(1,120_000_000);f2=rng.randint(1,240_000_000-f1)
            second_change=300_000_000-f1-f2
            f3=rng.randint(1,second_change-10_000_000);f4=rng.randint(1,290_000_000)
            f0=rng.randint(1,30_000_000);flow=e.derive(self.fees((f0,f1,f2,f3,f4)))
            self.assertEqual(flow['actions'][2]['reserve_after_sompi'],second_change+300_000_000)
            self.assertEqual(flow['actions'][3]['reserve_after_sompi'],300_000_000)
            self.assertEqual(flow['native_payouts_sompi'],1_000_000_000-f1-f2-f3-f4)
            self.assertEqual(flow['actions'][-1]['output_notes_sompi'],[])
            self.assertEqual((flow['final_CM_count'],flow['final_NF_count']), (9,11))


if __name__=='__main__':unittest.main()
