#!/usr/bin/env python3
"""Independent public aggregate arithmetic audit, after completion only.

Reads fixed public receipts and the aggregate score. Never reads seed, truth,
per-target predictions or private wallet records; imports no experiment code.
This checks report consistency, not correctness against hidden truth or privacy.
"""
import argparse
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
from pathlib import Path

CELLS = ("overlap-independent", "sparse-independent", "overlap-correlated", "sparse-correlated")
ARMS, PROFILES = ("whole", "partial"), ("C+D", "pooled")
HORIZONS = ("creation", "next_payout", "final")
METRICS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
BASE = ("prior", "residual", "coinput", "split", "subset_nearest", "subset_supported", "partial_tail",
        "split_tail", "receipt_timing", "cash_inverse", "colluder_tags", "bridge_ancestry", "combined")
FEE, BRIDGE_FEE = 40_000_000, 100_000


def require(ok, label):
    if not ok:
        raise ValueError(label)


def count(value, minimum=0):
    require(type(value) is int and value >= minimum, "aggregate integer")
    return value


def exact(value):
    require(type(value) is dict and set(value) == {"numerator", "denominator"}, "fraction fields")
    require(type(value["numerator"]) is int, "fraction numerator")
    denominator = count(value["denominator"], 1)
    result = Fraction(value["numerator"], denominator)
    require(result.numerator == value["numerator"] and result.denominator == denominator, "fraction not reduced")
    return result


def names(profile, horizon):
    base = BASE if profile == "C+D" else BASE+tuple("C_"+v for v in BASE)
    return base if horizon != "final" else base+tuple(h+"__"+v for h in ("creation", "next_payout") for v in base)


def audit_cost(report, validation, arm):
    cost, check, fees = report["cost"][arm], validation, report["fee_diagnostics"][arm]
    for key, value in cost.items():
        if key in ("all_payments_met", "all_cash_met"):
            require(value is True, "economic completion")
        else:
            count(value)
    require(check["complete"] is True and check["cost_counters_agree"] is True, "accounting completion")
    for key, expected in (("initial_admissions", 32), ("payment_obligations", 64), ("cash_obligations", 32), ("urgent_requests", 2)):
        require(count(check[key]) == expected, "obligation count")
    require(cost["pool_operations"] == count(check["pool_operations"])
            and cost["pool_fees"] == cost["pool_operations"]*FEE == count(check["pool_fees_sompi"]), "pool fee accounting")
    require(cost["pool_operations"] == 32+64+cost["reentries"]+cost["merges"]+cost["partial_payouts"]+cost["whole_payouts"],
            "pool operation partition")
    require(cost["bridge_fees"] == cost["reentries"]*BRIDGE_FEE == count(check["bridge_fees_sompi"]), "bridge fee accounting")
    require(cost["ordinary_payment_fees"] == 64*FEE, "ordinary payment fees")
    require(cost["initial_principal"]+32*FEE == count(check["initial_injected_sompi"]), "initial fee accounting")
    require(cost["external_total"] == count(check["final_external_sompi"])
            == check["initial_injected_sompi"]-cost["pool_fees"]-cost["bridge_fees"], "aggregate conservation")
    require(cost["earmarked_total"] == count(check["earmarked_sompi"])
            and cost["external_total"] == cost["earmarked_total"]+count(check["surplus_sompi"]), "external partition")
    require(cost["final_reserve"] == count(check["final_private_reserve"]) == 0, "final reserve")
    require(cost["modeled_cash_delay_minutes"] == cost["modeled_urgent_delay_minutes"] == 0, "modeled delay")
    require(count(fees["original_invoices"]) == 64 and count(fees["ordinary_fee_above_1pct_invoices"]) <= 64,
            "invoice fee denominator")
    require(exact(fees["ordinary_fee_max_fraction"]) > 0, "maximum invoice fee fraction")
    total_fees = cost["pool_fees"]+cost["bridge_fees"]
    require(count(fees["lifecycle_fees_sompi"]) == total_fees
            and exact(fees["capital_normalized_lifecycle_fee_diagnostic"]) == Fraction(total_fees, check["initial_injected_sompi"]),
            "capital fee diagnostic")
    require(fees["per_payment_lifecycle_fee_qualification"] is False, "fee qualification scope")


def audit_report(score):
    require(score["schema"] == "kpi-working-balance-score-v1" and score["complete"] is True
            and score["qualification_pass"] is False and count(score["paired_histories"]) == 4, "score scope")
    require(set(score["cases"]) == set(score["decisions"]) == set(CELLS), "case roster")
    require(set(score["validation"]) == {c+"/"+a for c in CELLS for a in ARMS}, "validation roster")
    groups = rows = decisions = 0
    all_passed = True
    for cell in CELLS:
        report = score["cases"][cell]
        require(set(report["arms"]) == set(report["cost"]) == set(report["fee_diagnostics"]) == set(ARMS), "arm roster")
        require(set(report["paired"]) == set(score["decisions"][cell]) == set(PROFILES), "comparison profile roster")
        require(all(report["cost"]["whole"][key] == report["cost"]["partial"][key]
                    for key in ("initial_principal", "payment_principal", "earmarked_total")), "paired economic totals")
        denominator = None
        for arm in ARMS:
            audit_cost(report, score["validation"][cell+"/"+arm], arm)
            profiles = report["arms"][arm]
            require(set(profiles) == set(PROFILES), "profile roster")
            for profile in PROFILES:
                require(set(profiles[profile]) == set(HORIZONS), "horizon roster")
                for horizon in HORIZONS:
                    group = profiles[profile][horizon]
                    n = count(group["targets"], 1)
                    if denominator is None:
                        denominator = n
                    require(n == denominator, "matched aggregate denominators")
                    roster = names(profile, horizon)
                    require(set(group["variants"]) == set(roster), "fixed strategy roster")
                    require(set(group["family_max"]) == set(group["prior"]) == set(METRICS), "metric roster")
                    maximum = {m: 0 for m in METRICS}
                    for variant in roster:
                        metrics = group["variants"][variant]
                        require(set(metrics) == set(METRICS), "strategy metric roster")
                        for metric, counter in metrics.items():
                            correct = count(counter["correct"])
                            require(count(counter["eligible"]) == n and correct <= n, "strategy denominator")
                            require(exact(counter["rate"]) == Fraction(correct, n), "strategy rate")
                            maximum[metric] = max(maximum[metric], correct)
                            rows += 1
                        require(metrics["relationship"]["correct"] <= min(metrics[m]["correct"] for m in ("sender", "recipient")),
                                "joint identity count")
                        require(metrics["relationship"]["correct"] >= metrics["sender"]["correct"]+metrics["recipient"]["correct"]-n,
                                "joint identity lower bound")
                        require(metrics["amount_exact"]["correct"] <= metrics["amount_within_10pct"]["correct"], "exact amount subset")
                    require(all(count(group["family_max"][m]) == maximum[m]
                                and count(group["prior"][m]) == group["variants"]["prior"][m]["correct"] for m in METRICS),
                            "aggregate fixed strategy maximum or prior")
                    caps = {"sender": Fraction(1, 10), "recipient": Fraction(1, 10), "amount_within_10pct": Fraction(1, 5)}
                    require(set(group["absolute_target_exceedances"]) == set(caps)
                            and all(group["absolute_target_exceedances"][m] is (Fraction(maximum[m], n) > cap) for m, cap in caps.items()),
                            "absolute threshold arithmetic")
                    if profile == "pooled":
                        public = profiles["C+D"][horizon]
                        for variant in names("C+D", horizon):
                            parts = variant.split("__")
                            pooled_name = "__".join(parts[:-1]+["C_"+parts[-1]])
                            require(group["variants"][pooled_name] == public["variants"][variant], "pooled public strategy copy")
                        require(all(maximum[m] >= public["family_max"][m] for m in METRICS), "pooled maximum dominance")
                    if horizon == "final":
                        for earlier in ("creation", "next_payout"):
                            previous = profiles[profile][earlier]
                            require(all(group["variants"][earlier+"__"+v] == counter for v, counter in previous["variants"].items()),
                                    "fixed carryforward copy")
                            require(all(maximum[m] >= previous["family_max"][m] for m in METRICS), "final maximum dominance")
                    groups += 1
        for profile in PROFILES:
            require(set(report["paired"][profile]) == set(HORIZONS)
                    and set(score["decisions"][cell][profile]) == {"next_payout", "final"}, "decision horizon roster")
            for horizon in HORIZONS:
                whole, partial = (report["arms"][a][profile][horizon] for a in ARMS)
                pairs = report["paired"][profile][horizon]
                require(set(pairs) == set(names(profile, horizon)), "paired strategy roster")
                if profile == "pooled":
                    for variant, pair in report["paired"]["C+D"][horizon].items():
                        parts = variant.split("__")
                        require(pairs["__".join(parts[:-1]+["C_"+parts[-1]])] == pair, "pooled paired strategy copy")
                if horizon == "final":
                    require(all(pairs[earlier+"__"+variant] == pair for earlier in ("creation", "next_payout")
                                for variant, pair in report["paired"][profile][earlier].items()), "paired carryforward copy")
                for variant, metrics in pairs.items():
                    require(set(metrics) == set(METRICS), "paired metric roster")
                    for metric, pair in metrics.items():
                        old, new = (g["variants"][variant][metric]["correct"] for g in (whole, partial))
                        gains, losses = count(pair["gains"]), count(pair["losses"])
                        require(count(pair["eligible"]) == denominator and gains-losses == new-old
                                and gains <= min(denominator-old, new) and losses <= min(old, denominator-new), "paired gain loss arithmetic")
                if horizon == "creation":
                    continue
                n = denominator
                reduction = Fraction(whole["family_max"]["amount_within_10pct"]-partial["family_max"]["amount_within_10pct"], n)
                advantage = Fraction(partial["family_max"]["amount_within_10pct"]-partial["prior"]["amount_within_10pct"], n)
                regressions = {m: Fraction(partial["family_max"][m]-whole["family_max"][m], n) for m in ("sender", "recipient", "relationship")}
                primary = cell.endswith("-independent")
                flags = dict(amount_reduction=not primary or reduction >= Fraction(1, 20),
                             prior_advantage=not primary or advantage <= Fraction(1, 20),
                             relationship_nonregression=all(r <= Fraction(1, 20) for r in regressions.values()))
                decision = score["decisions"][cell][profile][horizon]
                require(all(decision[k] is v for k, v in flags.items()) and decision["passed"] is all(flags.values()), "directional gate arithmetic")
                require(exact(decision["amount_reduction_rate"]) == reduction and exact(decision["partial_prior_advantage"]) == advantage
                        and set(decision["identity_regression"]) == set(regressions)
                        and all(exact(decision["identity_regression"][m]) == r for m, r in regressions.items()), "gate rate arithmetic")
                all_passed = all_passed and all(flags.values())
                decisions += 1
    require(score["directional_pass"] is all_passed and score["status"] == ("directional-screen-pass" if all_passed else "candidate-rejected-by-arithmetic-screen"),
            "overall decision arithmetic")
    return dict(complete=True, aggregate_consistent=True, groups=groups, decisions=decisions, variant_metric_rows=rows,
                accounting_bundles=8, qualification_pass=False,
                limits=["Public aggregate consistency only; no seed, truth or target-level evidence read.",
                        "Does not independently establish eligibility, correct guesses, paired target identities or native execution.",
                        "Per-invoice fee exceedances cannot be reconstructed from aggregate totals alone."])


def read_json(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), "symlink rejected")
    blob = path.read_bytes()
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, "duplicate JSON field")
            result[k] = v
        return result
    return json.loads(blob, object_pairs_hook=pairs), hashlib.sha256(blob).hexdigest()


def load_completed(root):
    root = Path(root)
    completion, completion_hash = read_json(root/"completion.json")
    require(completion["complete"] is True and completion["qualification_pass"] is False, "completion required before score")
    _, freeze_hash = read_json(root/"freeze.json")
    batch, batch_hash = read_json(root/"prediction-batch.json")
    require(freeze_hash == completion["freeze_sha256"] and batch_hash == completion["prediction_batch_sha256"]
            and batch["complete"] is True and batch["freeze_sha256"] == freeze_hash, "completed public seal pins")
    score, score_hash = read_json(root/"runs/score/result.json")
    require(score_hash == completion["score_sha256"], "completed score pin")
    require(score["directional_pass"] is completion["directional_pass"] and score["status"] == completion["status"], "completion outcome pin")
    return score, dict(completion_sha256=completion_hash, freeze_sha256=freeze_hash, prediction_batch_sha256=batch_hash, score_sha256=score_hash)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    score, pins = load_completed(args.root)
    tests = Path(__file__).with_name("working_balance_result_audit_tests.py")
    result = dict(schema="kpi-working-balance-public-result-audit-v1", audited_utc=datetime.now(timezone.utc).isoformat(),
                  source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  tests_sha256=hashlib.sha256(tests.read_bytes()).hexdigest() if tests.is_file() else None,
                  **pins, **audit_report(score))
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
