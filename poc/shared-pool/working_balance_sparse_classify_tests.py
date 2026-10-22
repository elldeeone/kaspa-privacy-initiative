"""Public handmade controls for causal-support classification, never held-out truth."""
import copy
import unittest

import working_balance_sparse_classify as c


class Fixture:
    def __init__(self):
        self.public = {"events": []}
        self.truth = {"events": []}
        self.next_position = 0

    def add(self, kind, inputs=(), values=(), owner=8, payout=0, fee=1, bridge=None):
        index = len(self.public["events"])
        outputs = []
        for value, recipient in values:
            outputs.append(dict(position=self.next_position, value=value, recipient=recipient if value else None))
            self.next_position += 1
        self.public["events"].append(dict(event=index, event_id="event-" + str(index),
                                          payout=payout, fee=fee, bridge=bridge))
        self.truth["events"].append(dict(event=index, kind=kind, owner=owner,
                                         inputs=list(inputs), outputs=outputs))
        return index, [out["position"] for out in outputs]

    def graph(self):
        return c.Graph(self.public, self.truth)


def residue(value, events, coinput=None, owner=None):
    return dict(value=value, events=list(events), coinput=coinput, owner=owner, partial=len(events) > 1)


class ClosedFlowTests(unittest.TestCase):
    def test_whole_and_unrelated_equal_amount(self):
        f = Fixture()
        _, (a, b) = f.add("admit", values=((40, 8), (40, 9)))
        exit_a, _ = f.add("exit", (a,), owner=8, payout=39)
        exit_b, _ = f.add("exit", (b,), owner=9, payout=39)
        graph = f.graph()
        self.assertTrue(graph.closed(a, residue(40, [exit_a])))
        self.assertFalse(graph.closed(a, residue(40, [exit_b])))
        self.assertFalse(graph.follows(a, [exit_b]))

    def test_partial_chain_fees_and_missing_leg(self):
        f = Fixture()
        _, (a,) = f.add("admit", values=((40, 8),))
        first, (change,) = f.add("partial", (a,), ((19, 8),), payout=20)
        last, _ = f.add("exit", (change,), payout=18)
        graph = f.graph()
        self.assertTrue(graph.closed(a, residue(40, [first, last])))
        self.assertFalse(graph.closed(a, residue(39, [first, last])))
        self.assertFalse(graph.closed(a, residue(40, [first])))
        self.assertFalse(graph.closed(a, residue(40, [last])))
        f.public["events"][last]["fee"] = 2
        self.assertFalse(f.graph().closed(a, residue(40, [first, last])))

    def test_two_note_and_late_additional_note(self):
        f = Fixture()
        _, (a,) = f.add("admit", values=((40, 8),))
        first, (change,) = f.add("partial", (a,), ((19, 8),), payout=20)
        _, (extra,) = f.add("admit", values=((7, 8),))
        last, _ = f.add("exit", (change, extra), payout=25)
        graph = f.graph()
        self.assertTrue(graph.closed(a, residue(40, [first, last], extra)))
        self.assertFalse(graph.closed(a, residue(40, [first, last])))
        self.assertFalse(graph.closed(a, residue(40, [first, last], a)))

    def test_intervening_payment_is_ancestry_not_closed_flow(self):
        f = Fixture()
        _, (a, extra) = f.add("admit", values=((40, 8), (10, 8)))
        _, (recipient, change) = f.add("pay", (a, extra), ((20, 9), (29, 8)))
        out, _ = f.add("exit", (recipient,), owner=9, payout=19)
        graph = f.graph()
        self.assertTrue(graph.follows(a, [out], native=False))
        self.assertFalse(graph.closed(a, residue(40, [out], extra)))
        self.assertIn(extra, graph.all[change])
        self.assertIn(a, graph.all[recipient])

    def test_native_bridge_and_external_change_ancestry(self):
        f = Fixture()
        _, (a,) = f.add("admit", values=((40, 8),))
        out, _ = f.add("exit", (a,), payout=39)
        _, (reentered,) = f.add("admit", values=((29, 8),), bridge=dict(
            sources=[dict(ref="event-" + str(out), value=39)], change_ref="native-change"))
        _, (again,) = f.add("admit", values=((7, 8),), bridge=dict(
            sources=[dict(ref="native-change", value=9)], change_ref=""))
        out2, _ = f.add("exit", (reentered,), payout=28)
        out3, _ = f.add("exit", (again,), payout=6)
        graph = f.graph()
        self.assertTrue(graph.follows(a, [out2, out3]))
        self.assertFalse(graph.follows(a, [out2, out3], native=False))
        self.assertFalse(graph.closed(a, residue(40, [out2, out3])))

    def test_zero_change_requires_empty_legs(self):
        f = Fixture()
        _, (zero,) = f.add("admit", values=((0, None),))
        graph = f.graph()
        self.assertTrue(graph.closed(zero, residue(0, [])))
        self.assertFalse(graph.closed(zero, residue(1, [])))


class RouteTests(unittest.TestCase):
    def fixture(self):
        f = Fixture()
        _, (fund,) = f.add("admit", values=((100, 8),))
        event, (receipt, change) = f.add("pay", (fund,), ((40, 9), (59, 8)))
        r, _ = f.add("exit", (receipt,), owner=9, payout=39)
        t, _ = f.add("exit", (change,), owner=8, payout=58)
        _, (other,) = f.add("admit", values=((40, 10),), owner=10)
        wrong, _ = f.add("exit", (other,), owner=10, payout=39)
        target = dict(event=event, obligation=0, sender=8, recipient=9, amount=40)
        route = dict(input_positions=[fund], receipt=residue(40, [r]), tail=residue(59, [t]))
        guess = dict(sender=8, recipient=9, amount=40)
        trace = dict(event=event, full_book_verified=True, decompositions=[route], fallback=False,
                     guess=guess, prior=dict(sender=10, recipient=11, amount=45), selected_record=dict(supports=[{}]))
        return f.graph(), target, route, trace, wrong

    def test_all_and_some_constructions_not_truth_selected(self):
        graph, target, route, trace, wrong = self.fixture()
        self.assertEqual(c.classify_target(graph, target, trace)["support_class"], "all_both_closed")
        false_route = copy.deepcopy(route)
        false_route["receipt"] = residue(40, [wrong])
        trace["decompositions"].extend([false_route, copy.deepcopy(route)])
        result = c.classify_target(graph, target, trace)
        self.assertEqual(result["support_class"], "some_both_closed")
        self.assertEqual((result["offers"], result["unique_constructions"]), (3, 2))
        self.assertTrue(result["any"]["receipt_closed"])
        self.assertFalse(result["all"]["receipt_closed"])

    def test_correct_change_with_wrong_receipt_is_separate(self):
        graph, target, route, trace, wrong = self.fixture()
        route["receipt"] = residue(40, [wrong])
        result = c.classify_target(graph, target, trace)
        self.assertEqual(result["support_class"], "closed_value_path_only")
        self.assertTrue(result["any"]["input_change_closed"])
        self.assertFalse(result["any"]["receipt_closed"])

    def test_wrong_branch_not_wholly_unrelated(self):
        graph, target, route, trace, _ = self.fixture()
        route["receipt"], route["tail"] = route["tail"], route["receipt"]
        result = c.classify_target(graph, target, trace)
        self.assertEqual(result["support_class"], "wrong_branch_only")
        self.assertTrue(result["any"]["receipt_follows_change"])

    def test_two_input_hypothesis_is_a_set_not_insertion_order(self):
        f = Fixture()
        _, (a, b) = f.add("admit", values=((40, 8), (60, 8)))
        event, (receipt, change) = f.add("pay", (a, b), ((40, 9), (59, 8)))
        r, _ = f.add("exit", (receipt,), owner=9, payout=39)
        t, _ = f.add("exit", (change,), owner=8, payout=58)
        target = dict(event=event, obligation=0, sender=8, recipient=9, amount=40)
        route = dict(input_positions=[b, a], receipt=residue(40, [r]), tail=residue(59, [t]))
        self.assertTrue(c.construction(f.graph(), target, route)["both_closed"])
        route["input_positions"] = [a, a, b]
        self.assertFalse(c.construction(f.graph(), target, route)["inputs_match"])

    def test_fallback_has_no_support(self):
        graph, target, _, trace, _ = self.fixture()
        trace.update(fallback=True, decompositions=[], selected_record=None)
        result = c.classify_target(graph, target, trace)
        self.assertEqual(result["support_class"], "fallback")
        self.assertFalse(any(result["any"].values()))

    def test_accuracy_boundaries_and_net_gain(self):
        target = dict(sender=8, recipient=9, amount=100)
        guess = dict(sender=8, recipient=10, amount=90)
        result = c.outcomes(guess, target)
        self.assertTrue(result["amount_within_10pct"])
        self.assertFalse(result["amount_exact"])
        self.assertTrue(result["sender"])
        self.assertFalse(result["relationship"])
        guess["amount"] = 89
        self.assertFalse(c.outcomes(guess, target)["amount_within_10pct"])
        self.assertEqual(c.transitions([True, False, True, False], [True, True, False, False]),
                         dict(targets=4, before=2, after=2, both=1, gains=1, losses=1, neither=1))


if __name__ == "__main__":
    unittest.main()
