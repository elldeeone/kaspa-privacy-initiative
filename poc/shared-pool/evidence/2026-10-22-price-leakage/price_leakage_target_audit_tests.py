"""Public handmade schema controls; no fresh attempt or observer execution."""
import copy
from fractions import Fraction
import tempfile
from pathlib import Path
import unittest

import price_leakage_target_audit as a


def fixture():
    """Schema-shaped public facts; not a funded/accounting-valid ledger claim."""
    public = dict(events=[])
    truth = dict(schema="kpi-working-balance-truth-v1", cell="sparse-independent", arm="partial",
                 plan=dict(payments=[]), events=[], targets=[])
    # A private merge shares obligation0 but is an observable zero-payout target,
    # not an economic PAY. Positions and amounts below are public control data.
    public["events"].append(dict(event=0, event_id="merge", mode=1, payout=0, new=[0, 1], minute=0))
    truth["events"].append(dict(event=0, owner=0, kind="merge", phase="payment", obligation=0,
                                inputs=[], outputs=[dict(position=0, value=1, recipient=0), dict(position=1, value=0, recipient=None)]))
    predictions = {p: {} for p in a.PROFILES}
    for k in range(64):
        event = k+1; sender = k % 32; recipient = (sender+1) % 32
        amount = (1_000_000_000, 4_000_000_000, 5_000_000_000, 4_500_000_000)[k % 4]
        payment = dict(obligation=k, sender=sender, recipient=recipient, amount=amount, minute=event)
        truth["plan"]["payments"].append(payment)
        public["events"].append(dict(event=event, event_id="public-"+str(k), mode=1, payout=0, new=[2*event, 2*event+1], minute=event))
        truth["events"].append(dict(event=event, owner=sender, kind="pay", phase="payment", obligation=k, inputs=[],
                                    outputs=[dict(position=2*event, value=amount, recipient=recipient),
                                             dict(position=2*event+1, value=0, recipient=None)]))
        truth["targets"].append(dict(payment, event=event))
        del truth["targets"][-1]["minute"]
        for profile in a.PROFILES:
            guess = dict(sender=sender, recipient=recipient, amount=amount if profile == "pooled" else 1_000_000_000,
                         relationship_rank=[0, 0, 0, 0])
            predictions[profile][event] = dict(prior=dict(guess, amount=4_500_000_000), split_tail=guess)
    return public, truth, predictions


def saved_case(recount):
    return dict(schema="kpi-price-leakage-case-v1", complete=True, cell="sparse-independent", arm="partial",
                eligible_targets=recount["eligible_targets"], observable_targets=recount["observable_targets"],
                price_baseline=copy.deepcopy(recount["price_baseline"]), paired=copy.deepcopy(recount["paired"]),
                profiles={p: dict(variants=dict(split_tail=copy.deepcopy(recount["profiles"][p]))) for p in a.PROFILES})


def summary(recounts):
    count = len(recounts); n = sum(c["eligible_targets"] for c in recounts)
    def rates(values):
        return dict(correct=sum(values), eligible=n, pooled_rate=a.ratio(Fraction(sum(values), n)),
                    equal_ledger_rate=a.ratio(sum((Fraction(v, c["eligible_targets"]) for v, c in zip(values, recounts)), Fraction())/count))
    result = dict(complete=True, qualification_pass=False, inferential_attack="split_tail", independent_ledgers=count,
                  eligible_targets=n, observable_targets=sum(c["observable_targets"] for c in recounts),
                  price_baseline={m: rates([c["price_baseline"][m] for c in recounts]) for m in a.AMOUNTS},
                  profiles={p: dict(variants=dict(split_tail={m: rates([c["profiles"][p][m] for c in recounts]) for m in a.METRICS})) for p in a.PROFILES},
                  contrasts={})
    for name in a.CONTRASTS:
        result["contrasts"][name] = dict(metrics={})
        for metric in a.AMOUNTS:
            pairs = [c["paired"][name][metric] for c in recounts]
            gains, losses = sum(p["gains"] for p in pairs), sum(p["losses"] for p in pairs)
            result["contrasts"][name]["metrics"][metric] = dict(gains=gains, losses=losses, eligible=n,
                pooled_difference=a.ratio(Fraction(gains-losses, n)), equal_ledger_difference=a.ratio(sum((Fraction(p["difference"]["numerator"], p["difference"]["denominator"]) for p in pairs), Fraction())/count))
    return result


class TargetAuditControls(unittest.TestCase):
    def test_derives_economic_payments_and_excludes_merge_and_adversaries(self):
        public, truth, _ = fixture()
        targets = a.derived_targets(public, truth)
        self.assertEqual(len(targets), 46)
        self.assertTrue(all(t["event"] > 0 and min(t["sender"], t["recipient"]) >= 8 for t in targets))
        self.assertNotIn(0, {t["event"] for t in targets})

    def test_rejects_declared_target_and_obligation_substitution(self):
        mutations = [lambda t: t["targets"].pop(),
                     lambda t: t["events"][2].__setitem__("obligation", 0),
                     lambda t: t["events"][2].__setitem__("kind", "merge"),
                     lambda t: t["events"][2].__setitem__("owner", True),
                     lambda t: t["events"][2]["outputs"][0].__setitem__("value", 7),
                     lambda t: t["plan"]["payments"][1].__setitem__("recipient", True),
                     lambda t: t["plan"]["payments"][1].__setitem__("amount", 0)]
        for change in mutations:
            public, truth, _ = fixture(); change(truth)
            with self.subTest(change=change), self.assertRaises(ValueError):
                a.derived_targets(public, truth)

    def test_independent_baselines_metrics_and_same_target_pairs(self):
        public, truth, predictions = fixture()
        result = a.case_counts(public, truth, predictions)
        protected = [p for p in truth["plan"]["payments"] if min(p["sender"], p["recipient"]) >= 8]
        self.assertEqual(result["price_baseline"]["amount_exact"], sum(p["amount"] == 1_000_000_000 for p in protected))
        self.assertEqual(result["price_baseline"]["amount_within_10pct"], sum(p["amount"] in (4_500_000_000, 5_000_000_000) for p in protected))
        self.assertEqual(result["profiles"]["pooled"]["amount_exact"], 46)
        self.assertEqual(result["profiles"]["pooled"]["relationship"], 46)
        self.assertGreater(result["paired"]["public_minus_price"]["amount_within_10pct"]["gains"], 0)
        self.assertGreater(result["paired"]["public_minus_price"]["amount_within_10pct"]["losses"], 0)
        saved = saved_case(result); a.compare_case(result, saved)
        for key in ("eligible_targets", "observable_targets"):
            tampered = copy.deepcopy(saved); tampered[key] += 1
            with self.assertRaises(ValueError): a.compare_case(result, tampered)
        saved["paired"]["public_minus_price"]["amount_within_10pct"]["gains"] += 1
        with self.assertRaises(ValueError): a.compare_case(result, saved)

    def test_inclusive_integer_boundary_and_exact_baseline(self):
        target = dict(sender=8, recipient=9, amount=100)
        for value, hit in ((90, True), (110, True), (89, False), (111, False)):
            self.assertEqual(a.outcomes(dict(sender=8, recipient=9, amount=value), target)["amount_within_10pct"], hit)

    def test_full_roster_prediction_hash_type_and_observable_merge_controls(self):
        public, _, indexed = fixture()
        directory = dict(public="directory"); view = dict(public="view")
        guess = dict(sender=8, recipient=9, amount=4_500_000_000, relationship_rank=[0, 0, 0, 0])
        pred = dict(schema="kpi-working-balance-predictions-v1", complete=True, profile="C+D", through_event=64,
                    public_sha256=a.canonical(public), directory_sha256=a.canonical(directory), view_sha256=a.canonical(view),
                    target_events_sha256=a.canonical(list(range(65))), boundary=a.BOUNDARY,
                    rows=[dict(event=e["event"], event_id=e["event_id"], guesses={name: copy.deepcopy(guess) for name in a.BASE}) for e in public["events"]])
        checked, targets = a.check_prediction(pred, public, directory, view, "C+D")
        self.assertEqual(targets, list(range(65)))
        self.assertEqual(len(checked), 65)
        for mutation in (lambda p: p["rows"].pop(0), lambda p: p.__setitem__("public_sha256", "0"*64),
                         lambda p: p["rows"][1]["guesses"]["split_tail"].__setitem__("amount", True)):
            altered = copy.deepcopy(pred); mutation(altered)
            with self.assertRaises(ValueError): a.check_prediction(altered, public, directory, view, "C+D")

    def test_aggregate_rates_compare_exact_weights_and_pairs(self):
        public, truth, predictions = fixture()
        first = a.case_counts(public, truth, predictions)
        second = copy.deepcopy(first)
        recounts = [first, second]; saved = summary(recounts)
        self.assertEqual(a.compare_aggregate(recounts, saved), 92)
        saved["profiles"]["pooled"]["variants"]["split_tail"]["amount_exact"]["equal_ledger_rate"]["numerator"] += 1
        with self.assertRaises(ValueError): a.compare_aggregate(recounts, saved)

    def test_json_and_path_controls_never_access_seed_or_private_attempt(self):
        for text in ('{"x":1,"x":2}', '{"x":NaN}'):
            with self.assertRaises(ValueError): a.parse(text)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root/"public.json").write_text('{"public":true}')
            self.assertEqual(a.read(root, "public.json"), dict(public=True))
            for name in ("../seed.json", "/seed.json"):
                with self.assertRaises(ValueError): a.read(root, name)
            with self.assertRaises(ValueError): a.read(root, "public.json", "0"*64)


if __name__ == "__main__":
    unittest.main()
