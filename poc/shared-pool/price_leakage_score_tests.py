"""Explicit public development controls; never open held-out attempts or seeds."""
import copy
import json
import math
import unittest
from fractions import Fraction

import price_leakage_score as score


def synthetic_case(n, public_hits, pooled_hits, price_hits, label="control"):
    """Count-only accounting-shaped fixture for aggregate/statistics controls.

    This is not passed off as an independently validated generated ledger.
    score_case() accounting controls below use the real independent validator.
    """
    vectors = {
        "public": [i < public_hits for i in range(n)],
        "pooled": [i < pooled_hits for i in range(n)],
        "price": [i < price_hits for i in range(n)],
    }
    profiles = {}
    for profile, hits in (("C+D", public_hits), ("pooled", pooled_hits)):
        strategies = {}
        for name in score.variants(profile):
            values = dict.fromkeys(score.METRICS, 0)
            if name in ("prior", "C_prior"):
                values["amount_within_10pct"] = price_hits
            if name == "split_tail":
                values["amount_within_10pct"] = hits
            if name == "C_split_tail":
                values["amount_within_10pct"] = public_hits
            strategies[name] = values
        profiles[profile] = {"variants": strategies}
    pairs = {}
    for name, left, right in (("public_minus_price", "public", "price"),
                              ("pooled_minus_price", "pooled", "price"),
                              ("pooled_minus_public", "pooled", "public")):
        pairs[name] = {"amount_within_10pct": score.paired(vectors[left], vectors[right]),
                       "amount_exact": score.paired([False]*n, [False]*n)}
    hashes = {"public": score.digest(label), "directory": "a"*64,
              "views": {profile: "b"*64 for profile in score.PROFILES},
              "predictions": {profile: "c"*64 for profile in score.PROFILES}}
    return dict(schema="kpi-price-leakage-case-v1", complete=True,
                cell="sparse-independent", arm="partial", eligible_targets=n,
                observable_targets=64, input_sha256=hashes,
                price_baseline={"amount_within_10pct": price_hits, "amount_exact": 0},
                profiles=profiles, paired=pairs,
                accounting={"complete": True, "cost_counters_agree": True, "final_private_reserve": 0})


class PriceAndStatsTests(unittest.TestCase):
    def test_prior_values_and_exact_metric_baseline(self):
        import working_balance_observer as observer
        self.assertEqual(observer.amount_prior(), (45*score.SOMPI, score.EXPECTED_WITHIN))
        support = [(amount*score.SOMPI, Fraction(3, 25)) for amount in (10, 20, 25, 40, 50)]
        support.extend((amount*1_000_000, Fraction(2, 5*4001)) for amount in range(1000, 5001))
        within = sum((weight for amount, weight in support
                      if score.amount_hits(score.PRICE_WITHIN, amount)["amount_within_10pct"]), Fraction())
        exact = sum((weight for amount, weight in support
                     if score.amount_hits(score.PRICE_EXACT, amount)["amount_exact"]), Fraction())
        self.assertEqual(within, score.EXPECTED_WITHIN)
        self.assertEqual(exact, score.EXPECTED_EXACT)
        self.assertGreater(within, Fraction(1, 5))
        self.assertFalse(score.amount_hits(score.PRICE_WITHIN, 40*score.SOMPI)["amount_exact"])

    def test_integer_ten_percent_boundaries(self):
        for guess in (90, 110):
            self.assertTrue(score.amount_hits(guess, 100)["amount_within_10pct"])
        for guess in (89, 111):
            self.assertFalse(score.amount_hits(guess, 100)["amount_within_10pct"])
        self.assertTrue(score.amount_hits(91, 101)["amount_within_10pct"])
        self.assertFalse(score.amount_hits(90, 101)["amount_within_10pct"])
        self.assertTrue(score.amount_hits(111, 101)["amount_within_10pct"])
        self.assertFalse(score.amount_hits(112, 101)["amount_within_10pct"])
        for value in (True, 1.0, "1", -1):
            with self.assertRaises(ValueError):
                score.amount_hits(value, 100)

    def test_exact_wealth_products(self):
        self.assertEqual(score.e_value([Fraction(1)]), Fraction(231, 160))
        self.assertEqual(score.e_value([Fraction(0)], Fraction(1, 20)), Fraction(3129, 3200))
        self.assertEqual(score.e_value([Fraction(0)], Fraction(1, 20), "minus"), Fraction(3271, 3200))
        for theta in (Fraction(), Fraction(1, 20)):
            for direction in ("plus", "minus"):
                self.assertEqual(score.e_value([theta]*13, theta, direction), Fraction(1))
        values = [Fraction(1, 3), Fraction(-1, 7), Fraction(2, 5)]
        expected = sum((math.prod(1+bet*value for value in values) for bet in score.BETS), Fraction())/4
        self.assertEqual(score.e_value(values), expected)
        self.assertEqual(score.e_value(values), score.e_value(list(reversed(values))))

    def test_exact_threshold_not_float_rounding(self):
        self.assertTrue(score.threshold_crossed(Fraction(180)))
        self.assertFalse(score.threshold_crossed(Fraction(180)-Fraction(1, 10**100)))
        self.assertTrue(score.threshold_crossed(Fraction(180)+Fraction(1, 10**100)))

    def test_small_null_enumeration_expectation_and_false_positive_bound(self):
        # Enumerate all outcome counts of 12 iid +/-1 ledgers, exactly.
        # At either null boundary the expected factor is exactly one.
        for theta, probability in ((Fraction(0), Fraction(1, 2)),
                                   (Fraction(1, 20), Fraction(21, 40))):
            for direction in ("plus", "minus"):
                mean_e, rejected_probability = Fraction(), Fraction()
                for positives in range(13):
                    weight = (math.comb(12, positives)*probability**positives*
                              (1-probability)**(12-positives))
                    value = score.e_value([Fraction(1)]*positives+[Fraction(-1)]*(12-positives),
                                          theta, direction)
                    mean_e += weight*value
                    if score.threshold_crossed(value):
                        rejected_probability += weight
                self.assertEqual(mean_e, 1)
                self.assertLessEqual(rejected_probability, Fraction(1, 180))

    def test_nine_hypotheses_and_family_allocation(self):
        cases = [synthetic_case(4, 1, 2, 1, label=str(i)) for i in range(2)]
        result = score.aggregate(cases, expected_ledgers=2)
        self.assertEqual(result["inference"]["tests"], 9)
        self.assertEqual(9*score.exact(result["inference"]["per_test_error_bound"]), Fraction(1, 20))
        hypotheses = [(contrast, name) for contrast in result["contrasts"]
                      for name in result["contrasts"][contrast]["metrics"]["amount_within_10pct"]["tests"]]
        self.assertEqual(len(hypotheses), 9)
        self.assertEqual(set(result["contrasts"]), set(score.CONTRASTS))
        self.assertFalse(result["qualification_pass"])
        self.assertTrue(result["development_only"])

    def test_ledger_weights_differ_from_pooled_payment_weights(self):
        cases = [synthetic_case(1, 0, 1, 0, label="one"),
                 synthetic_case(3, 0, 0, 0, label="three")]
        result = score.aggregate(cases, expected_ledgers=2)
        metrics = result["contrasts"]["pooled_minus_price"]["metrics"]["amount_within_10pct"]
        self.assertEqual(score.exact(metrics["equal_ledger_difference"]), Fraction(1, 2))
        self.assertEqual(score.exact(metrics["pooled_difference"]), Fraction(1, 4))
        expected = score.e_tests([Fraction(1), Fraction(0)])
        self.assertEqual(metrics["tests"], expected)

    def test_additive_identity_and_gains_losses(self):
        case = synthetic_case(6, 2, 5, 3)
        result = score.aggregate([case], expected_ledgers=1)
        contrasts = result["contrasts"]
        metric = "amount_within_10pct"
        self.assertEqual(score.exact(contrasts["pooled_minus_price"]["metrics"][metric]["equal_ledger_difference"]),
                         Fraction(1, 3))
        self.assertEqual(score.exact(contrasts["public_minus_price"]["metrics"][metric]["equal_ledger_difference"]),
                         Fraction(-1, 6))
        self.assertEqual(score.exact(contrasts["pooled_minus_public"]["metrics"][metric]["equal_ledger_difference"]),
                         Fraction(1, 2))
        self.assertEqual(case["paired"]["public_minus_price"][metric]["losses"], 1)
        self.assertEqual(case["paired"]["pooled_minus_price"][metric]["gains"], 2)

    def test_paired_controls_preserve_swaps(self):
        result = score.paired([True, False, True], [False, True, True])
        self.assertEqual((result["gains"], result["losses"]), (1, 1))
        self.assertEqual(score.exact(result["difference"]), 0)
        for left, right in (([], []), ([True], []), ([1], [False])):
            with self.assertRaises(ValueError):
                score.paired(left, right)

    def test_stats_reject_nonfractions_or_unfrozen_settings(self):
        for values in ([], [True], [0.1], [1], [Fraction(2)]):
            with self.assertRaises(ValueError):
                score.e_value(values)
        with self.assertRaises(ValueError):
            score.e_value([Fraction(0)], Fraction(1, 10))
        with self.assertRaises(ValueError):
            score.e_value([Fraction(0)], Fraction(0), "unknown")

    def test_terminal_batch_count_and_duplicates(self):
        case = synthetic_case(4, 1, 2, 1)
        with self.assertRaises(ValueError):
            score.aggregate([case])
        with self.assertRaises(ValueError):
            score.aggregate([case, copy.deepcopy(case)], expected_ledgers=2)
        with self.assertRaises(ValueError):
            score.aggregate([], expected_ledgers=0)
        broken = copy.deepcopy(case)
        broken["paired"]["pooled_minus_price"]["amount_within_10pct"]["gains"] += 1
        with self.assertRaises(ValueError):
            score.aggregate([broken], expected_ledgers=1)

    def test_full_size_exact_products_serialization_and_positive_unresolved_status(self):
        # A positive effect exactly at the five-point boundary is detectable
        # against zero while both strict five-point hypotheses stay unresolved.
        cases = [synthetic_case(20, 1, 1, 0, label="fixed-size-control-"+str(i))
                 for i in range(score.FINAL_LEDGERS)]
        result = score.aggregate(cases)
        self.assertFalse(result["development_only"])
        self.assertEqual(result["independent_ledgers"], 512)
        for name in ("public_minus_price", "pooled_minus_price"):
            contrast = result["contrasts"][name]
            tests = contrast["metrics"]["amount_within_10pct"]["tests"]
            self.assertTrue(tests["positive_advantage"]["crossed"])
            self.assertFalse(tests["above_five_points"]["crossed"])
            self.assertFalse(tests["below_five_points"]["crossed"])
            self.assertEqual(contrast["decision"], "positive-advantage-size-unresolved")
        self.assertEqual(json.loads(json.dumps(result)), result)

    def test_fraction_roundtrip_unbounded_denominator(self):
        value = Fraction(10**500+1, 10**700+3)
        self.assertEqual(score.exact(score.ratio(value)), value)
        for value in ({"numerator": True, "denominator": 1},
                      {"numerator": 2, "denominator": 4},
                      {"numerator": 1, "denominator": 0}):
            with self.assertRaises(ValueError):
                score.exact(value)


class CompletePublicFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import working_balance_model as model
        import working_balance_observer as observer
        # Explicit public development seed, not fresh held-out data.
        seed = bytes(range(32))
        work = model.plan(seed, "sparse-independent")
        cls.bundle = model.replay(seed, "sparse-independent", "partial", work)
        cls.predictions = {profile: observer.observe(cls.bundle["public"], cls.bundle["directory"],
                              cls.bundle["views"][profile]) for profile in score.PROFILES}

    def test_actual_accounting_scoring_and_no_input_mutation(self):
        before = score.digest({"bundle": self.bundle, "predictions": self.predictions})
        result = score.score_case(self.bundle, self.predictions)
        self.assertTrue(result["accounting"]["complete"])
        self.assertGreater(result["eligible_targets"], 0)
        self.assertEqual(result["observable_targets"], len(self.predictions["pooled"]["rows"]))
        self.assertEqual(before, score.digest({"bundle": self.bundle, "predictions": self.predictions}))
        score.validate_case(result)
        # Public score has no truth joins, target IDs, ownership vectors or amounts.
        serialized = str(result)
        for forbidden in ("obligation", "event_id", "recipient_positions", "cash_audit", "targets"):
            if forbidden != "targets":
                self.assertNotIn("'"+forbidden+"':", serialized)
        self.assertEqual(set(result["profiles"]["C+D"]["variants"]), set(score.BASE))
        self.assertEqual(len(result["profiles"]["pooled"]["variants"]), 26)

    def test_prediction_shape_type_hash_and_complete_target_controls(self):
        mutations = [
            lambda p: p["C+D"]["rows"].pop(),
            lambda p: p["C+D"]["rows"].__setitem__(1, copy.deepcopy(p["C+D"]["rows"][0])),
            lambda p: p["C+D"].__setitem__("public_sha256", "0"*64),
            lambda p: p["C+D"].__setitem__("directory_sha256", "0"*64),
            lambda p: p["C+D"].__setitem__("view_sha256", "0"*64),
            lambda p: p["C+D"].__setitem__("target_events_sha256", "0"*64),
            lambda p: p["C+D"].__setitem__("complete", 1),
            lambda p: p["C+D"].__setitem__("through_event", True),
            lambda p: p["C+D"]["rows"][0].__setitem__("event", True),
            lambda p: p["C+D"]["rows"][0].__setitem__("event_id", "forged"),
            lambda p: p["C+D"]["rows"][0]["guesses"].pop("prior"),
            lambda p: p["C+D"]["rows"][0]["guesses"]["split_tail"].__setitem__("sender", True),
            lambda p: p["C+D"]["rows"][0]["guesses"]["split_tail"].__setitem__("sender", 32),
            lambda p: p["C+D"]["rows"][0]["guesses"]["split_tail"].__setitem__("amount", 1.0),
            lambda p: p["C+D"]["rows"][0]["guesses"]["split_tail"].__setitem__("amount", -1),
            lambda p: p["C+D"]["rows"][0]["guesses"]["split_tail"].__setitem__("relationship_rank", [0, 0, 0]),
            lambda p: p["C+D"]["rows"][0]["guesses"]["split_tail"].__setitem__("relationship_rank", [True, 0, 0, 0]),
            lambda p: p["pooled"]["rows"][0]["guesses"]["C_split_tail"].__setitem__("amount", 1),
        ]
        for mutation in mutations:
            prediction = copy.deepcopy(self.predictions)
            mutation(prediction)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                score.score_case(self.bundle, prediction)

    def test_adversarial_targets_cannot_be_omitted(self):
        predictions = copy.deepcopy(self.predictions)
        # The first four public PAY targets are the declared colluder controls.
        self.assertEqual(self.bundle["truth"]["targets"][0]["sender"], 0)
        predictions["C+D"]["rows"] = predictions["C+D"]["rows"][4:]
        predictions["C+D"]["target_events_sha256"] = score.digest(
            [row["event"] for row in predictions["C+D"]["rows"]])
        with self.assertRaises(ValueError):
            score.score_case(self.bundle, predictions)

    def test_accounting_and_view_tamper_rejected(self):
        for part in ("truth", "cost", "views"):
            bundle = copy.deepcopy(self.bundle)
            if part == "truth":
                bundle["truth"]["targets"].pop()
            elif part == "cost":
                bundle["cost"]["final_reserve"] = 1
            else:
                bundle["views"]["pooled"]["receipts"].pop()
            with self.subTest(part=part), self.assertRaises(ValueError):
                score.score_case(bundle, self.predictions)

    def test_exact_scoring_uses_ten_not_fortyfive(self):
        result = score.score_case(self.bundle, self.predictions)
        eligible = [row for row in self.bundle["truth"]["targets"]
                    if row["sender"] >= 8 and row["recipient"] >= 8]
        self.assertEqual(result["price_baseline"]["amount_exact"],
                         sum(row["amount"] == 10*score.SOMPI for row in eligible))
        self.assertEqual(result["profiles"]["C+D"]["variants"]["prior"]["amount_exact"], 0)


if __name__ == "__main__":
    unittest.main()
