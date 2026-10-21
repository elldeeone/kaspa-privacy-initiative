#!/usr/bin/env python3
"""Public handmade aggregate controls; never import frozen scoring or observers."""
import copy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import working_balance_result_audit as audit


CELLS = ("overlap-independent", "sparse-independent", "overlap-correlated", "sparse-correlated")
ARMS = ("whole", "partial")
PROFILES = ("C+D", "pooled")
HORIZONS = ("creation", "next_payout", "final")
VARIANTS = ("prior", "residual", "coinput", "split", "subset_nearest", "subset_supported",
            "partial_tail", "split_tail", "receipt_timing", "cash_inverse", "colluder_tags",
            "bridge_ancestry", "combined")
METRICS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
N = 20
FEE = 40_000_000


def ratio(numerator, denominator):
    value = Fraction(numerator, denominator)
    return {"numerator": value.numerator, "denominator": value.denominator}


def decision(whole, partial, primary):
    w, p = whole["family_max"], partial["family_max"]
    reduction = w["amount_within_10pct"] - p["amount_within_10pct"]
    advantage = p["amount_within_10pct"] - partial["prior"]["amount_within_10pct"]
    regression = {metric: p[metric] - w[metric] for metric in METRICS[:3]}
    checks = {
        "amount_reduction": not primary or reduction >= 1,
        "prior_advantage": not primary or advantage <= 1,
        "relationship_nonregression": all(value <= 1 for value in regression.values()),
    }
    return dict(checks, passed=all(checks.values()), amount_reduction_rate=ratio(reduction, N),
                partial_prior_advantage=ratio(advantage, N),
                identity_regression={metric: ratio(value, N) for metric, value in regression.items()})


def aggregate_fixture(amount_reduction=1):
    """Fixed counters and costs only: no target identities, guesses, or hidden data."""
    cases, decisions, validation = {}, {}, {}
    for cell in CELLS:
        arms, costs, fees = {}, {}, {}
        primary = cell.endswith("-independent")
        for arm in ARMS:
            arms[arm] = {}
            partial = arm == "partial"
            for profile in PROFILES:
                arms[arm][profile] = {}
                base = VARIANTS + tuple("C_" + name for name in VARIANTS) if profile == "pooled" else VARIANTS
                for offset, horizon in enumerate(HORIZONS):
                    counters = {}
                    for name in base:
                        strategy = name.removeprefix("C_")
                        amount = 12 + offset - (1 if strategy == "prior" else 0 if strategy == "residual" else 2)
                        if partial:
                            amount += -amount_reduction if primary else 1
                        counts = dict(sender=2 + partial, recipient=2 + partial, relationship=1 + partial,
                                      amount_within_10pct=amount, amount_exact=amount - 2)
                        counters[name] = {metric: dict(correct=value, eligible=N, rate=ratio(value, N))
                                          for metric, value in counts.items()}
                    if horizon == "final":
                        for earlier in HORIZONS[:2]:
                            for name, values in arms[arm][profile][earlier]["variants"].items():
                                counters[earlier + "__" + name] = copy.deepcopy(values)
                    strongest = {metric: max(row[metric]["correct"] for row in counters.values())
                                 for metric in METRICS}
                    prior = {metric: counters["prior"][metric]["correct"] for metric in METRICS}
                    arms[arm][profile][horizon] = dict(
                        targets=N, variants=counters, family_max=strongest, prior=prior,
                        absolute_target_exceedances={"sender": strongest["sender"] > 2,
                                                     "recipient": strongest["recipient"] > 2,
                                                     "amount_within_10pct": strongest["amount_within_10pct"] > 4})

            reentries, merges = (1, 1) if partial else (4, 2)
            operations = 32 + 64 + 32 + 32 + reentries + merges
            principal = 32 * 350 * 100_000_000
            injected = principal + 32 * FEE
            pool_fee, bridge_fee = operations * FEE, reentries * 100_000
            external = injected - pool_fee - bridge_fee
            earmarked = 32 * 10 * 100_000_000
            costs[arm] = dict(
                reentries=reentries, merges=merges, partial_payouts=32 if partial else 0,
                whole_payouts=32 if partial else 64, urgent_exit_operations=2, final_exit_operations=32,
                peak_external_surplus=external - earmarked, total_withdrawal_overshoot=0 if partial else 100_000_000,
                private_change_reused_by_pay=6 if partial else 5, tagged_receipts_spent_as_coinput=3,
                pool_operations=operations, pool_fees=pool_fee, bridge_fees=bridge_fee,
                ordinary_payment_fees=64 * FEE, payment_principal=64 * 20 * 100_000_000,
                initial_principal=principal, external_total=external, earmarked_total=earmarked,
                final_reserve=0, all_payments_met=True, all_cash_met=True,
                modeled_cash_delay_minutes=0, modeled_urgent_delay_minutes=0)
            validation[cell + "/" + arm] = dict(
                complete=True, initial_admissions=32, payment_obligations=64, cash_obligations=32,
                urgent_requests=2, pool_operations=operations, note_positions=2 * operations,
                consumed_positive_notes=2 * (operations - 32), native_coins_remaining=32,
                initial_injected_sompi=injected, final_external_sompi=external, earmarked_sompi=earmarked,
                surplus_sompi=external - earmarked, pool_fees_sompi=pool_fee, bridge_fees_sompi=bridge_fee,
                final_private_reserve=0, cost_counters_agree=True)
            fees[arm] = dict(original_invoices=64, ordinary_fee_above_1pct_invoices=64,
                             ordinary_fee_max_fraction=ratio(1, 50), lifecycle_fees_sompi=pool_fee + bridge_fee,
                             capital_normalized_lifecycle_fee_diagnostic=ratio(pool_fee + bridge_fee, injected),
                             per_payment_lifecycle_fee_qualification=False)

        paired, decisions[cell] = {}, {}
        for profile in PROFILES:
            paired[profile], decisions[cell][profile] = {}, {}
            for horizon in HORIZONS:
                whole, partial = (arms[arm][profile][horizon] for arm in ARMS)
                paired[profile][horizon] = {}
                for name, metrics in whole["variants"].items():
                    paired[profile][horizon][name] = {}
                    for metric, row in metrics.items():
                        change = partial["variants"][name][metric]["correct"] - row["correct"]
                        paired[profile][horizon][name][metric] = dict(eligible=N, gains=max(change, 0), losses=max(-change, 0))
                if horizon != "creation":
                    decisions[cell][profile][horizon] = decision(whole, partial, primary)
        cases[cell] = dict(arms=arms, paired=paired, cost=costs, fee_diagnostics=fees)
    passed = all(row["passed"] for cell in decisions.values() for profile in cell.values() for row in profile.values())
    return dict(schema="kpi-working-balance-score-v1", complete=True, directional_pass=passed,
                status="directional-screen-pass" if passed else "candidate-rejected-by-arithmetic-screen",
                qualification_pass=False, paired_histories=4, cases=cases, decisions=decisions, validation=validation,
                limits=["Public handmade aggregate control; no real workload or privacy evidence."])


def change_count(report, profile, horizon, variant, metric, value):
    case = report["cases"][CELLS[0]]
    counter = case["arms"]["whole"][profile][horizon]["variants"][variant][metric]
    counter.update(correct=value, rate=ratio(value, N))
    new = case["arms"]["partial"][profile][horizon]["variants"][variant][metric]["correct"]
    case["paired"][profile][horizon][variant][metric].update(gains=max(new - value, 0), losses=max(value - new, 0))


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AggregateAuditTests(unittest.TestCase):
    def test_complete_handmade_report_and_faithful_failed_decision_are_consistent(self):
        for reduction in (1, 0):
            with self.subTest(amount_reduction=reduction):
                report = aggregate_fixture(reduction)
                receipt = audit.audit_report(report)
                self.assertTrue(receipt["complete"])
                self.assertTrue(receipt["aggregate_consistent"])
                self.assertFalse(receipt["qualification_pass"])
                self.assertEqual(receipt["groups"], 48)
                self.assertEqual(receipt["decisions"], 16)
                self.assertEqual(receipt["variant_metric_rows"], 7800)
                self.assertEqual(report["directional_pass"], reduction == 1)

    def test_counter_summary_and_cost_arithmetic_mutations_reject(self):
        mutations = (
            ("rate", lambda r: r["cases"][CELLS[0]]["arms"]["whole"]["C+D"]["creation"]["variants"]["prior"]["sender"]["rate"].update(numerator=2)),
            ("boolean-count", lambda r: r["cases"][CELLS[0]]["arms"]["whole"]["C+D"]["creation"]["variants"]["prior"]["sender"].update(correct=True)),
            ("maximum", lambda r: r["cases"][CELLS[0]]["arms"]["whole"]["C+D"]["creation"]["family_max"].update(sender=3)),
            ("prior", lambda r: r["cases"][CELLS[0]]["arms"]["whole"]["C+D"]["creation"]["prior"].update(sender=3)),
            ("exceedance", lambda r: r["cases"][CELLS[0]]["arms"]["whole"]["C+D"]["creation"]["absolute_target_exceedances"].update(sender=True)),
            ("pool-fee", lambda r: r["cases"][CELLS[0]]["cost"]["whole"].update(pool_fees=1)),
            ("operation-partition", lambda r: r["cases"][CELLS[0]]["cost"]["whole"].update(merges=3)),
            ("paired-principal", lambda r: r["cases"][CELLS[0]]["cost"]["whole"].update(payment_principal=64 * 20 * 100_000_000 + 1)),
            ("capital-conservation", lambda r: r["validation"][CELLS[0] + "/whole"].update(initial_injected_sompi=1)),
            ("external-balance", lambda r: r["cases"][CELLS[0]]["cost"]["whole"].update(external_total=1)),
            ("fee-diagnostic", lambda r: r["cases"][CELLS[0]]["fee_diagnostics"]["whole"].update(lifecycle_fees_sompi=1)),
            ("fee-rate", lambda r: r["cases"][CELLS[0]]["fee_diagnostics"]["whole"].update(capital_normalized_lifecycle_fee_diagnostic=ratio(1, 2))),
            ("missing-profile", lambda r: r["cases"][CELLS[0]]["arms"]["whole"].pop("pooled")),
            ("unknown-variant", lambda r: r["cases"][CELLS[0]]["arms"]["whole"]["C+D"]["creation"]["variants"].update(unknown={})),
        )
        for label, mutate in mutations:
            with self.subTest(mutation=label):
                report = aggregate_fixture()
                mutate(report)
                with self.assertRaises(ValueError):
                    audit.audit_report(report)

        report = aggregate_fixture()
        metrics = report["cases"][CELLS[0]]["arms"]["whole"]["C+D"]["creation"]["variants"]["prior"]
        for metric in ("sender", "recipient"):
            metrics[metric].update(correct=N, rate=ratio(N, N))
        with self.assertRaisesRegex(ValueError, "joint identity lower bound"):
            audit.audit_report(report)

    def test_exact_five_point_decisions_and_stress_exemption_are_recomputed(self):
        report = aggregate_fixture()
        boundary = report["decisions"][CELLS[0]]["C+D"]["next_payout"]
        self.assertEqual(boundary["amount_reduction_rate"], ratio(1, 20))
        self.assertEqual(boundary["partial_prior_advantage"], ratio(1, 20))
        self.assertEqual(set(tuple(value.values()) for value in boundary["identity_regression"].values()), {(1, 20)})
        stress = report["decisions"][CELLS[2]]["C+D"]["next_payout"]
        self.assertEqual(stress["amount_reduction_rate"], ratio(-1, 20))
        self.assertTrue(stress["passed"])
        for field in ("amount_reduction", "prior_advantage", "relationship_nonregression", "passed",
                      "amount_reduction_rate", "partial_prior_advantage", "identity_regression"):
            with self.subTest(field=field):
                changed = copy.deepcopy(report)
                row = changed["decisions"][CELLS[0]]["C+D"]["next_payout"]
                row[field] = False if type(row[field]) is bool else {}
                with self.assertRaises(ValueError):
                    audit.audit_report(changed)
        for field, value in (("directional_pass", False), ("status", "candidate-rejected-by-arithmetic-screen"),
                             ("qualification_pass", True)):
            with self.subTest(field=field):
                changed = copy.deepcopy(report)
                changed[field] = value
                with self.assertRaises(ValueError):
                    audit.audit_report(changed)

    def test_paired_deltas_eligibility_and_feasibility_reject(self):
        for changes in (dict(gains=2), dict(eligible=N - 1), dict(gains=4, losses=3)):
            with self.subTest(changes=changes):
                report = aggregate_fixture()
                row = report["cases"][CELLS[0]]["paired"]["C+D"]["creation"]["prior"]["sender"]
                row.update(changes)
                with self.assertRaises(ValueError):
                    audit.audit_report(report)

    def test_pooled_public_and_final_carry_counts_are_retained(self):
        report = aggregate_fixture()
        # Adjust count, rate, and paired delta together; maxima remain unchanged.
        for horizon, name in (("creation", "C_prior"), ("final", "creation__C_prior")):
            change_count(report, "pooled", horizon, name, "amount_exact", 10)
        with self.assertRaises(ValueError):
            audit.audit_report(report)

        report = aggregate_fixture()
        # Preserve C_ equality while violating only the earlier-horizon carry.
        for profile, name in (("C+D", "creation__prior"), ("pooled", "creation__C_prior")):
            change_count(report, profile, "final", name, "amount_exact", 10)
        with self.assertRaises(ValueError):
            audit.audit_report(report)

        paired_mutations = (
            (("pooled", "creation", "C_prior"), ("pooled", "final", "creation__C_prior")),
            (("C+D", "final", "creation__prior"), ("pooled", "final", "creation__C_prior")),
        )
        for copies in paired_mutations:
            with self.subTest(paired_copies=copies):
                report = aggregate_fixture()
                for profile, horizon, name in copies:
                    pair = report["cases"][CELLS[0]]["paired"][profile][horizon][name]["sender"]
                    # Feasible and the same net delta, but a different pairing.
                    pair["gains"] += 1
                    pair["losses"] += 1
                with self.assertRaises(ValueError):
                    audit.audit_report(report)

    def test_completion_and_pins_are_checked_before_score_bytes(self):
        with tempfile.TemporaryDirectory(prefix="working-balance-public-result-audit-") as folder:
            root = Path(folder)
            score_path = root / "runs/score/result.json"
            report = aggregate_fixture()
            score_hash = write_json(score_path, report)
            freeze_hash = write_json(root / "freeze.json", {"public_handmade_marker": True})
            batch = dict(complete=True, freeze_sha256=freeze_hash)
            batch_hash = write_json(root / "prediction-batch.json", batch)
            completion = dict(complete=True, qualification_pass=False, freeze_sha256=freeze_hash,
                              prediction_batch_sha256=batch_hash, score_sha256=score_hash,
                              directional_pass=report["directional_pass"], status=report["status"])
            original_read = Path.read_bytes
            for state in ("missing", "incomplete", "unsealed", "freeze-drift", "batch-drift"):
                with self.subTest(state=state):
                    changed = dict(completion)
                    if state == "incomplete":
                        changed["complete"] = False
                    elif state == "freeze-drift":
                        changed["freeze_sha256"] = "0" * 64
                    elif state == "batch-drift":
                        changed["prediction_batch_sha256"] = "0" * 64
                    elif state == "unsealed":
                        changed["prediction_batch_sha256"] = write_json(root / "prediction-batch.json", dict(batch, complete=False))
                    if state != "missing":
                        write_json(root / "completion.json", changed)
                    reads = []

                    def observed_read(path):
                        reads.append(path)
                        return original_read(path)

                    error = FileNotFoundError if state == "missing" else ValueError
                    with mock.patch.object(Path, "read_bytes", observed_read), self.assertRaises(error):
                        audit.load_completed(root)
                    self.assertNotIn(score_path, reads)
                    write_json(root / "prediction-batch.json", batch)
            write_json(root / "completion.json", completion)
            loaded, pins = audit.load_completed(root)
            self.assertEqual(loaded, report)
            self.assertIn(score_hash, pins.values())
            write_json(score_path, {"public_mutation": True})
            with self.assertRaises(ValueError):
                audit.load_completed(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
