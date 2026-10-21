"""Handmade development controls; no held-out sampling or privacy scoring."""
import copy
import unittest

import working_balance_model as m

SEED = bytes(range(32))


class ModelTests(unittest.TestCase):
    def ledger(self, arm="partial", amount=100*m.SOMPI):
        result = m.Ledger(SEED, "public-control", arm)
        result.admit_initial(8, amount)
        return result

    def test_integer_semantics(self):
        for value in (True, False, -1, 0.5, "1", m.MAX+1):
            with self.assertRaises(ValueError):
                m.integer(value)
        self.assertEqual(m.integer(m.MAX), m.MAX)

    def test_total_input_bound_even_when_each_output_fits(self):
        ledger = self.ledger(amount=m.MAX-m.FEE)
        ledger.admit_initial(8, m.FLOOR+m.FEE)
        # Both selected notes and proposed outputs fit individually, but their
        # input sum exceeds the v6 transition-wide bound.
        before = len(ledger.events)
        with self.assertRaises(ValueError):
            ledger.operation(8, "pay", [0, 2], 1, amount=m.MAX-m.FEE, recipient=9)
        self.assertEqual(len(ledger.events), before)
        self.assertEqual(ledger.available(8), [0, 2])
        # Two independently accounted admissions can total exactly MAX;
        # that boundary must remain accepted with floor-valid outputs.
        boundary = self.ledger(amount=m.MAX-m.FLOOR)
        boundary.admit_initial(8, m.FLOOR)
        boundary.operation(8, "pay", [0, 2], 1, amount=m.MAX-m.FEE-m.FLOOR,
                           recipient=9)
        self.assertEqual(boundary.hidden[-1]["outputs"][1]["value"], m.FLOOR)

    def test_zero_and_floor_change(self):
        for remainder in (0, m.FLOOR):
            ledger = self.ledger(amount=10*m.SOMPI+m.FEE+remainder)
            ledger.operation(8, "pay", [0], 1, amount=10*m.SOMPI, recipient=9, obligation=0)
            self.assertEqual(ledger.notes[3]["value"], remainder)
        ledger = self.ledger(amount=10*m.SOMPI+m.FEE+m.FLOOR-1)
        with self.assertRaises(ValueError):
            ledger.operation(8, "pay", [0], 1, amount=10*m.SOMPI, recipient=9)
        self.assertEqual(len(ledger.events), 1)

    def test_wrong_owner_duplicate_and_spent(self):
        ledger = self.ledger()
        for owner, ins in ((9, [0]), (8, [0, 0]), (8, [1])):
            with self.assertRaises(ValueError):
                ledger.operation(owner, "exit", ins, 1, amount=100*m.SOMPI-m.FEE)
        ledger.operation(8, "exit", [0], 1, amount=100*m.SOMPI-m.FEE)
        with self.assertRaises(ValueError):
            ledger.operation(8, "exit", [0], 2, amount=100*m.SOMPI-m.FEE)

    def test_partial_and_full_conserve(self):
        ledgers = []
        request = dict(request=0, owner=8, amount=20*m.SOMPI, minute=1, urgent=False)
        for arm in ("whole", "partial"):
            ledger = self.ledger(arm)
            ledger.cash(request)
            ledger.check_accounting()
            ledgers.append(ledger)
        self.assertEqual(ledgers[0].external(8), 100*m.SOMPI-m.FEE)
        self.assertEqual(ledgers[1].external(8), 20*m.SOMPI)
        self.assertEqual(ledgers[1].reserve, 80*m.SOMPI-m.FEE)

    def test_external_surplus_satisfies_next_cash(self):
        ledger = self.ledger("whole")
        ledger.cash(dict(request=0, owner=8, amount=20*m.SOMPI, minute=1, urgent=False))
        before = len(ledger.events)
        ledger.cash(dict(request=1, owner=8, amount=25*m.SOMPI, minute=2, urgent=False))
        self.assertEqual(len(ledger.events), before)
        self.assertEqual(ledger.earmarked[8], 45*m.SOMPI)

    def test_dust_goes_public_not_burned(self):
        ledger = self.ledger(amount=20*m.SOMPI+m.FEE+m.FLOOR-1)
        ledger.cash(dict(request=0, owner=8, amount=20*m.SOMPI, minute=1, urgent=False))
        self.assertEqual(ledger.events[-1]["mode"], 2)
        self.assertEqual(ledger.external(8), 20*m.SOMPI+m.FLOOR-1)
        self.assertEqual(ledger.reserve, 0)

    def test_shortage_below_payout_floor_is_overpaid(self):
        ledger = self.ledger("whole", amount=20*m.SOMPI+m.FEE+m.PAYOUT_FLOOR-1)
        ledger.admit_initial(8, 100*m.SOMPI)
        ledger.cash(dict(request=0, owner=8, amount=20*m.SOMPI, minute=1, urgent=False))
        ledger.arm = "partial"
        ledger.cash(dict(request=1, owner=8, amount=m.PAYOUT_FLOOR, minute=2, urgent=False))
        self.assertEqual(ledger.events[-1]["payout"], m.PAYOUT_FLOOR)
        self.assertEqual(ledger.surplus(8), m.PAYOUT_FLOOR-1)
        ledger.check_accounting()

    def test_urgent_drains_and_reentry_preserves_earmark(self):
        ledger = self.ledger()
        ledger.cash(dict(request=0, owner=8, amount=20*m.SOMPI, minute=1, urgent=True))
        self.assertEqual(ledger.available(8), [])
        self.assertTrue(ledger.reenter(8, 2, 0))
        bridge = ledger.events[-1]["bridge"]
        self.assertEqual(len(bridge["sources"]), 2)
        self.assertEqual(bridge["change"], 20*m.SOMPI)
        self.assertEqual(bridge["input_value"], bridge["deposit"]+bridge["fee"]+bridge["change"])
        self.assertEqual(ledger.external(8), ledger.earmarked[8])
        self.assertEqual(ledger.bridge_fees, m.BRIDGE_FEE)
        ledger.check_accounting()

    def test_reentry_cannot_consume_earmark(self):
        ledger = self.ledger(amount=20*m.SOMPI+m.FEE)
        ledger.cash(dict(request=0, owner=8, amount=20*m.SOMPI, minute=1, urgent=True))
        self.assertFalse(ledger.reenter(8, 2, 0))
        with self.assertRaises(ValueError):
            ledger.pay(dict(obligation=0, sender=8, recipient=9, amount=10*m.SOMPI, minute=2))
        self.assertEqual(ledger.external(8), 20*m.SOMPI)

    def test_repeated_bridge_change_edges(self):
        ledger = self.ledger()
        ledger.cash(dict(request=0, owner=8, amount=20*m.SOMPI, minute=1, urgent=True))
        ledger.reenter(8, 2, 0)
        prior_change = ledger.events[-1]["bridge"]["change_ref"]
        ledger.drain(8, 3, "urgent")
        ledger.reenter(8, 4, 1)
        self.assertIn(prior_change, [s["ref"] for s in ledger.events[-1]["bridge"]["sources"]])
        ledger.check_accounting()

    def test_partial_change_spent_in_later_pay(self):
        ledger = self.ledger()
        ledger.cash(dict(request=0, owner=8, amount=20*m.SOMPI, minute=1, urgent=False))
        ledger.pay(dict(obligation=0, sender=8, recipient=9, amount=10*m.SOMPI, minute=2))
        self.assertEqual(ledger.metrics["private_change_reused_by_pay"], 1)

    def test_cash_selector_matches_sum_then_count_then_position(self):
        ledger = self.ledger(amount=15*m.SOMPI)
        ledger.admit_initial(8, 5*m.SOMPI)
        ledger.admit_initial(8, 20*m.SOMPI)
        self.assertEqual(ledger.cash_selection(8, 20*m.SOMPI-m.FEE), [4])
        self.assertEqual(ledger.cash_selection(8, 40*m.SOMPI), [0, 4])

    def test_cash_request_can_need_multiple_two_input_operations(self):
        for arm in ("whole", "partial"):
            ledger = self.ledger(arm, amount=5*m.SOMPI)
            ledger.admit_initial(8, 5*m.SOMPI)
            ledger.admit_initial(8, 5*m.SOMPI)
            ledger.cash(dict(request=0, owner=8, amount=12*m.SOMPI, minute=1, urgent=False))
            self.assertEqual(len(ledger.events), 5)
            self.assertEqual([len(r["inputs"]) for r in ledger.hidden[-2:]], [2, 1])
            self.assertGreaterEqual(ledger.external(8), 12*m.SOMPI)
            self.assertEqual(ledger.earmarked[8], 12*m.SOMPI)
            ledger.check_accounting()

    def test_admission_has_zero_anchor_and_nullifiers(self):
        ledger = self.ledger()
        ledger.admit_initial(0, 100*m.SOMPI)
        self.assertEqual(ledger.events[-1]["count_before"], 2)
        self.assertEqual(ledger.events[-1]["anchor_count"], 0)
        self.assertEqual(ledger.events[-1]["nullifiers"], ["0"*64, "0"*64])

    def test_merge_to_meet_obligation(self):
        ledger = self.ledger(amount=10*m.SOMPI)
        ledger.admit_initial(8, 10*m.SOMPI)
        ledger.admit_initial(8, 10*m.SOMPI)
        ledger.pay(dict(obligation=0, sender=8, recipient=9, amount=25*m.SOMPI, minute=1))
        self.assertEqual(ledger.metrics["merges"], 1)
        self.assertEqual(ledger.events[-2]["mode"], 1)
        self.assertEqual(ledger.events[-2]["payout"], 0)
        self.assertEqual(ledger.hidden[-2]["outputs"][1]["value"], 0)

    def test_public_and_views_exclude_hidden_records(self):
        ledger = self.ledger()
        ledger.admit_initial(0, 100*m.SOMPI)
        ledger.pay(dict(obligation=0, sender=8, recipient=0, amount=10*m.SOMPI, minute=1))
        public, view = ledger.public(), ledger.view([0])
        self.assertEqual(set(public), {"schema", "roles", "adversaries", "events", "commitments"})
        forbidden = {"owner", "inputs", "outputs", "obligation", "request", "kind", "phase"}
        for event in public["events"]:
            self.assertFalse(forbidden & set(event))
        self.assertEqual(len(view["authored"]), 1)
        self.assertEqual(len(view["receipts"]), 2)
        self.assertEqual(ledger.view([])["receipts"], [])
        self.assertTrue(all(set(row) == {"event", "owner", "inputs", "outputs"} for row in view["authored"]))

    def test_final_drain_and_fee_exactness(self):
        ledger = self.ledger()
        ledger.cash(dict(request=0, owner=8, amount=20*m.SOMPI, minute=1, urgent=False))
        ledger.drain(8, 2, "final")
        self.assertEqual(ledger.reserve, 0)
        self.assertEqual(ledger.injected, ledger.external(8)+3*m.FEE)

    def test_complete_receipt_cashout_negative_control(self):
        for arm in ("whole", "partial"):
            ledger = self.ledger(arm)
            ledger.pay(dict(obligation=0, sender=8, recipient=9, amount=40*m.SOMPI, minute=1))
            ledger.cash(dict(request=0, owner=9, amount=40*m.SOMPI-m.FEE, minute=2, urgent=False))
            self.assertEqual(ledger.events[-1]["payout"]+ledger.events[-1]["fee"], 40*m.SOMPI)
            self.assertEqual(ledger.events[-1]["mode"], 2)

    def test_plan_distribution_and_matching(self):
        for cell in m.CELLS:
            work = m.plan(SEED, cell)
            self.assertEqual(len(work["payments"]), 64)
            self.assertEqual(len(work["cash_requests"]), 32)
            self.assertEqual(sum(work["activity"]), 64)
            self.assertEqual(sorted(work["activity"][8:]), [0]*4+[1]*8+[2]*8+[6]*4)
            self.assertEqual([r["request"] for r in work["cash_requests"] if r["urgent"]], [7, 23])
            if cell.endswith("correlated"):
                for row in work["cash_requests"]:
                    payment = work["payments"][row["after_payment"]]
                    self.assertEqual((row["owner"], row["amount"]), (payment["recipient"], payment["amount"]//2))
            else:
                self.assertEqual(sorted(r["owner"] for r in work["cash_requests"]), m.ROLES)
            arms = [m.replay(SEED, cell, arm, work) for arm in ("whole", "partial")]
            self.assertEqual(arms[0]["truth"]["plan"], arms[1]["truth"]["plan"])
            for bundle in arms:
                self.assertTrue(bundle["cost"]["all_payments_met"] and bundle["cost"]["all_cash_met"])
                self.assertEqual(bundle["cost"]["final_reserve"], 0)
                self.assertEqual(bundle["cost"]["earmarked_total"], sum(r["amount"] for r in work["cash_requests"]))

    def test_domain_separation_and_reproducibility(self):
        self.assertEqual(m.plan(SEED, m.CELLS[0]), m.plan(SEED, m.CELLS[0]))
        self.assertNotEqual(m.plan(SEED, m.CELLS[0]), m.plan(SEED, m.CELLS[1]))
        a, b = self.ledger("whole"), self.ledger("partial")
        self.assertNotEqual(a.events[0]["event_id"], b.events[0]["event_id"])


if __name__ == "__main__":
    unittest.main()
