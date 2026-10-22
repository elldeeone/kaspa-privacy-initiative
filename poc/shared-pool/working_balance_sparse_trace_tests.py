"""Handmade public tracer controls; no held-out truth, seeds or privacy scoring."""

import copy
import json
import unittest

import working_balance_observer as frozen
from working_balance_observer_tests import Fixture
from working_balance_sparse_trace import normalized_book, trace_split_tail


S, F = frozen.SOMPI, frozen.FEE


def engine_for(fixture, view=None):
    values = frozen.prefix_inputs(fixture.public, fixture.directory,
                                  fixture.view if view is None else view)
    targets = [row["event"] for row in values[0]["events"] if row["mode"] == 1 and not row["payout"]]
    return frozen.Engine(*values, min(targets) if targets else len(values[0]["events"]))


def partial_fixture():
    fixture = Fixture()
    target = fixture.add(1)
    first = fixture.add(1, payout=20 * S)
    last = fixture.add(2, payout=19 * S + 20_000_000)
    change = fixture.add(2, payout=59 * S + 20_000_000)
    return fixture, target, first, last, change


def known_receipt_view(fixture, target):
    """A participant legitimately knows its own received amount/position."""
    position = fixture.public["events"][target]["new"][0]
    return dict(schema="kpi-working-balance-view-v1", members=list(range(8)), authored=[],
                receipts=[dict(position=position, value=40 * S, owner=7)])


class PublicTraceTests(unittest.TestCase):
    def test_fallback_has_no_invented_support(self):
        fixture = Fixture()
        target = fixture.add(1)
        result = trace_split_tail(engine_for(fixture), target)
        self.assertTrue(result["fallback"])
        self.assertEqual(result["guess"], result["prior"])
        self.assertEqual(result["decompositions"], [])
        self.assertIsNone(result["selected_record"])
        self.assertIsNone(result["selected_key"])
        self.assertEqual(result["book_key_count"], 0)
        self.assertEqual(result["book_sha256"], frozen.digest([]))

    def test_all_public_targets_and_base_guesses_match_both_profiles(self):
        fixture, _, _, _, _ = partial_fixture()
        pooled = dict(schema="kpi-working-balance-view-v1", members=list(range(8)), authored=[], receipts=[])
        for view in (fixture.view, pooled):
            observed = frozen.observe(fixture.public, fixture.directory, view)
            engine = engine_for(fixture, view)
            self.assertEqual(engine.targets, [row["event"] for row in observed["rows"]])
            for row in observed["rows"]:
                result = trace_split_tail(engine, row["event"], expected_guess=row["guesses"]["split_tail"])
                self.assertEqual(result["all_guesses"], {key: row["guesses"][key] for key in frozen.VARIANTS})
                self.assertEqual(result["event_id"], row["event_id"])
                self.assertTrue(result["full_book_verified"])
                self.assertEqual(result, json.loads(json.dumps(result, allow_nan=False)))

    def test_partial_tail_and_change_keep_partition_and_equation(self):
        fixture, target, first, last, change = partial_fixture()
        result = trace_split_tail(engine_for(fixture, known_receipt_view(fixture, target)), target)
        self.assertFalse(result["fallback"])
        self.assertEqual(result["guess"]["amount"], 40 * S)
        explanations = [row for row in result["decompositions"]
                        if row["receipt"]["events"] == [first, last] and row["tail"]["events"] == [change]]
        self.assertTrue(explanations)
        for row in explanations:
            self.assertTrue(row["receipt"]["partial"])
            self.assertEqual(row["receipt"]["value"], 40 * S)
            self.assertEqual(row["tail"]["value"], 59 * S + 60_000_000)
            self.assertEqual(row["receipt"]["value"] + row["tail"]["value"], row["input_total_after_fee"])
            self.assertEqual(row["union_events"], [first, last, change])
        self.assertEqual({tuple(row["union_events"]) for row in result["decompositions"]},
                         {tuple(row["events"]) for row in result["selected_record"]["supports"]})

    def test_eight_support_cap_preserves_first_eight_of_twelve(self):
        fixture = Fixture()
        target = fixture.add(1)
        receipts = [fixture.add(2, payout=40 * S - F) for _ in range(12)]
        change = fixture.add(2, payout=59 * S + 20_000_000)
        result = trace_split_tail(engine_for(fixture), target)
        self.assertEqual(result["guess"]["amount"], 40 * S)
        self.assertEqual(len(result["selected_record"]["supports"]), 8)
        self.assertEqual({tuple(row["events"]) for row in result["selected_record"]["supports"]},
                         {(event, change) for event in receipts[:8]})
        self.assertEqual({tuple(row["receipt"]["events"]) for row in result["decompositions"]},
                         {(event,) for event in receipts[:8]})

    def test_known_owner_outranks_earlier_anonymous_support(self):
        fixture = Fixture()
        target = fixture.add(1)
        for _ in range(12):
            fixture.add(2, payout=40 * S - F)
        received = fixture.add(1)
        position = fixture.public["events"][received]["new"][0]
        known = fixture.add(2, payout=40 * S - F)
        fixture.add(2, payout=59 * S + 20_000_000)
        view = dict(schema="kpi-working-balance-view-v1", members=list(range(8)),
                    receipts=[dict(position=position, value=40 * S, owner=1)],
                    authored=[dict(event=known, owner=1, inputs=[position], outputs=[])])
        result = trace_split_tail(engine_for(fixture, view), target)
        self.assertEqual(result["guess"]["recipient"], 1)
        self.assertEqual(result["guess"]["relationship_rank"][0], 2)
        self.assertTrue(all(row["receipt"]["events"] == [known] for row in result["decompositions"]))

    def test_deducted_coinput_is_retained_separately_from_union(self):
        fixture = Fixture()
        target = fixture.add(1)
        first = fixture.add(1, payout=20 * S)
        last = fixture.add(2, payout=119 * S + 20_000_000)
        fixture.add(2, payout=59 * S + 20_000_000)
        result = trace_split_tail(engine_for(fixture, known_receipt_view(fixture, target)), target)
        self.assertEqual(result["guess"]["amount"], 40 * S)
        self.assertTrue(result["decompositions"])
        for row in result["decompositions"]:
            self.assertEqual(row["receipt"]["events"], [first, last])
            self.assertIsNotNone(row["receipt"]["coinput"])
            self.assertNotIn(row["receipt"]["coinput"], row["input_positions"])
        self.assertTrue(all(row["coinput"] is None for row in result["selected_record"]["supports"]))

    def test_zero_change_keeps_explicit_empty_tail(self):
        fixture = Fixture()
        receipt = fixture.add(1)
        position = fixture.public["events"][receipt]["new"][0]
        target = fixture.add(1)
        fixture.add(2, payout=40 * S - F)
        view = dict(schema="kpi-working-balance-view-v1", members=list(range(8)), authored=[],
                    receipts=[dict(position=position, value=40 * S + F, owner=0)])
        result = trace_split_tail(engine_for(fixture, view), target)
        self.assertEqual(result["guess"]["amount"], 40 * S)
        self.assertTrue(result["decompositions"])
        self.assertTrue(all(row["tail"]["events"] == [] and row["tail"]["value"] == 0
                            for row in result["decompositions"]))

    def test_sealed_guess_mismatch_is_rejected(self):
        fixture, target, _, _, _ = partial_fixture()
        engine = engine_for(fixture)
        wrong = copy.deepcopy(engine.row(target)["guesses"]["split_tail"])
        wrong["amount"] += 1
        with self.assertRaisesRegex(ValueError, "sealed split_tail guess"):
            trace_split_tail(engine, target, expected_guess=wrong)

    def test_reference_book_drift_is_rejected(self):
        fixture, target, _, _, _ = partial_fixture()
        engine = engine_for(fixture)
        books = engine.books(target)
        key = next(iter(books["split_tail"]))
        record = books["split_tail"][key]
        record["rank"] = (record["rank"][0], record["rank"][1] + 1, record["rank"][2])
        engine.books = lambda _: books
        with self.assertRaisesRegex(ValueError, "full split_tail book drift"):
            trace_split_tail(engine, target)

    def test_normalized_book_includes_all_ranks_and_supports(self):
        fixture, target, _, _, _ = partial_fixture()
        engine = engine_for(fixture)
        expected = normalized_book(engine.books(target)["split_tail"])
        result = trace_split_tail(engine, target)
        self.assertEqual(result["book_key_count"], len(expected))
        self.assertEqual(result["book_sha256"], frozen.digest(expected))
        self.assertIn(result["selected_record"], expected)


if __name__ == "__main__":
    unittest.main()
