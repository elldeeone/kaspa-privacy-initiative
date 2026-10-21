#!/usr/bin/env python3
"""Independent stdlib-only count/statistics checker; never emits private rows.

Run `case PUBLIC VIEW PREDICTION TRUTH SCORE POLICY` only after the prediction
batch is sealed, with one isolated case mounted. `aggregate SCORES SUMMARY`
uses public scored counts only. This checks bookkeeping/statistics, not solver
soundness, seed independence, cryptographic privacy or native acceptance.
"""
import copy
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import sys

NAMES = ("prior", "cashout_residual", "split_balance", "tag_split")
GROUPS = ("primary", "all_undisclosed", "startup", "adversary_endpoint")
FACTS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
PERCENT = (5, 10, 25)
CAPS = {"sender": .10, "recipient": .10, "amount_within_10pct": .20}
POLICY_CHECK = dict(passed=True, complete=True, payments=128, startup_payments=16,
                    active_payments=32, full_drainage=True,
                    scope="exact policy/accounting check; no seed-randomness or cryptographic claim")


class CheckFailure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise CheckFailure(code)


def keys(value, expected, code):
    require(isinstance(value, dict) and set(value) == set(expected), code)


def number(value, low=0, high=2_900_000_000_000_000_000):
    require(type(value) is int and low <= value <= high, "canonical_integer")
    return value


def read(path):
    def object_pairs(pairs):
        require(len(dict(pairs)) == len(pairs), "duplicate_json_keys")
        return dict(pairs)
    def bad_constant(_):
        raise CheckFailure("nonfinite_json")
    return json.loads(Path(path).read_text(), object_pairs_hook=object_pairs, parse_constant=bad_constant)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def equal(actual, expected, code):
    """Compare whole structures; only numerical interval leaves allow rounding."""
    if isinstance(expected, dict):
        keys(actual, expected, code)
        for k in expected:
            equal(actual[k], expected[k], code)
    elif isinstance(expected, list):
        require(isinstance(actual, list) and len(actual) == len(expected), code)
        for a, e in zip(actual, expected):
            equal(a, e, code)
    elif type(expected) is float:
        require(type(actual) in (int, float) and math.isfinite(actual)
                and math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12), code)
    else:
        require(type(actual) is type(expected) and actual == expected, code)


def targets(public):
    return [i for i, event in enumerate(public["algebra"]["events"]) if i != 0 and event["mode"] == 1]


def validate_records(public, view, truth):
    """Rewalk concrete ownership/conservation, then rebuild complete pooled P."""
    keys(public, ("schema", "roles", "adversaries", "algebra", "commitments",
                  "funding_owners", "bootstrap_self", "modeled"), "public_shape")
    require(public["schema"] == "kpi-population-public-v1" and public["bootstrap_self"] is True,
            "public_schema")
    equal(public["roles"], list(range(32)), "roles")
    equal(public["adversaries"], list(range(8)), "adversaries")
    equal(view["members"], list(range(8)), "pooled_members")
    events, hidden = public["algebra"]["events"], truth["events"]
    values, owners, selected = truth["values"], truth["owners"], truth["inputs"]
    require(len(values) == len(owners) == len(public["commitments"])
            and len(events) == len(hidden), "truth_vector_shapes")
    require(set(selected) == {str(i) for i in range(len(events))}, "truth_input_coverage")
    for value, owner in zip(values, owners):
        number(value)
        require(owner is None if value == 0 else type(owner) is int and owner in public["roles"]
                and value >= 60_000_000, "truth_owner_value")
    initial = public["algebra"]["initial"]
    require(values[0] == initial["value"] and owners[0] == public["funding_owners"][initial["funding_group"]],
            "initial_truth")
    used, count, reserve = set(), 1, values[0]
    for i, (event, hidden_event) in enumerate(zip(events, hidden)):
        positions = selected[str(i)]
        require(isinstance(positions, list), "input_list")
        for p in positions:
            number(p, 0, count - 1)
        require(positions == sorted(set(positions)) and not used.intersection(positions), "input_single_use")
        sender = number(hidden_event["sender"], 0, 31)
        require(all(values[p] > 0 and owners[p] == sender for p in positions), "input_owner")
        mode = number(event["mode"], 0, 2)
        require(event["count_before"] == count, "note_count")
        equal(event["new"], [] if mode == 2 else [count, count + 1], "created_positions")
        require(event["fee"] == 40_000_000, "fee")
        if mode == 0:
            require(not positions and hidden_event["kind"] == "admit"
                    and public["funding_owners"][event["funding_group"]] == sender,
                    "admission_owner")
            require(owners[count] == sender and values[count + 1] == 0, "admission_outputs")
        else:
            require(1 <= len(positions) <= 2 and all(p < event["anchor_count"] for p in positions),
                    "input_cardinality_anchor")
        if mode == 1:
            require(event["payout"] == 0 and values[count] >= 60_000_000
                    and (values[count + 1] == 0 or owners[count + 1] == sender), "payment_shape")
            if i == 0:
                require(hidden_event["kind"] == "bootstrap" and positions == [0]
                        and owners[count] == owners[0] and values[count + 1] == 0, "self_bootstrap")
            else:
                require(hidden_event["kind"] == "payment" and hidden_event["amount"] == values[count]
                        and hidden_event["recipient"] == owners[count], "payment_truth_binding")
        require(sum(values[p] for p in positions) + event["deposit"] ==
                sum(values[p] for p in event["new"]) + event["payout"] + event["fee"], "conservation")
        reserve += event["deposit"] - event["payout"] - event["fee"]
        used.update(positions)
        count += len(event["new"])
        require(reserve == event["reserve_out"] == sum(values[p] for p in range(count) if p not in used),
                "reserve_liability")
    require(count == len(values) and reserve == 0, "full_drainage")
    expected = dict(schema="kpi-population-view-v1", public_sha256=digest(public), members=list(range(8)),
                    receipts=[], authored=[])
    for position, (value, owner) in enumerate(zip(values, owners)):
        if value and owner in expected["members"]:
            expected["receipts"].append(dict(owner=owner, position=position, value=value))
    for i, event in enumerate(events):
        if hidden[i]["sender"] in expected["members"]:
            expected["authored"].append(dict(owner=hidden[i]["sender"], event=i, inputs=selected[str(i)],
                outputs=[dict(position=p, value=values[p], recipient=owners[p]) for p in event["new"]]))
    equal(view, expected, "complete_participant_records")


def recompute_counts(public, view, prediction, truth):
    """Compute eligibility matrices first, independently of attack correctness."""
    events = public["algebra"]["events"]
    authors = {r["event"] for r in view["authored"]}
    receipts = {r["position"] for r in view["receipts"]}
    controlled = set(public["adversaries"])
    forbidden = controlled | set(view["members"])
    admitted = {public["funding_owners"][public["algebra"]["initial"]["funding_group"]]}
    eligibility, primary = {}, 0
    for i, event in enumerate(events):
        if event["mode"] == 0:
            admitted.add(public["funding_owners"][event["funding_group"]])
        if i not in targets(public):
            continue
        hidden = truth["events"][i]
        endpoints = {hidden["sender"], hidden["recipient"]}
        startup = admitted != set(public["roles"])
        involved = bool(endpoints & controlled)
        uninvolved = not startup and not endpoints.intersection(forbidden)
        primary += uninvolved
        unknown_sender = i not in authors
        unknown_receipt = i not in authors and event["new"][0] not in receipts
        unknown = dict(sender=unknown_sender, recipient=unknown_receipt,
                       relationship=unknown_sender or unknown_receipt,
                       amount_within_10pct=unknown_receipt, amount_exact=unknown_receipt)
        enabled = dict(primary=uninvolved, all_undisclosed=True, startup=startup,
                       adversary_endpoint=involved)
        eligibility[i] = {group: {fact: enabled[group] and unknown[fact] for fact in FACTS}
                          for group in GROUPS}
    records = {name: {group: [] for group in GROUPS} for name in NAMES}
    for row in prediction["rows"]:
        i, actual = row["event"], truth["events"][row["event"]]
        for name in NAMES:
            guess = row["guesses"][name]
            sender_ok = guess["sender"] == actual["sender"]
            recipient_ok = guess["recipient"] == actual["recipient"]
            correctness = dict(sender=sender_ok, recipient=recipient_ok,
                relationship=sender_ok and recipient_ok,
                amount_exact=guess["amount"] == actual["amount"],
                amount_within_10pct=9 * actual["amount"] <= 10 * guess["amount"] <= 11 * actual["amount"])
            for group in GROUPS:
                records[name][group].append((i, eligibility[i][group], correctness,
                                            tuple(guess["relationship_rank"])))
    answer = {}
    for name in NAMES:
        answer[name] = {}
        for group in GROUPS:
            rows = records[name][group]
            counts = {fact: dict(eligible=sum(mask[fact] for _, mask, _, _ in rows),
                                correct=sum(mask[fact] and success[fact] for _, mask, success, _ in rows))
                      for fact in FACTS}
            eligible = [row for row in rows if row[1]["relationship"]]
            eligible.sort(key=lambda row: (row[3], -row[0]), reverse=True)
            selection = {}
            for percent in PERCENT:
                n = (percent * len(eligible) + 99) // 100
                selection[str(percent)] = dict(eligible=n,
                    correct=sum(row[2]["relationship"] for row in eligible[:n]),
                    population=len(eligible), nominal_percent=percent,
                    realized_coverage=n / len(eligible) if eligible else None)
            counts["selective_relationship"] = selection
            answer[name][group] = counts
    return dict(tested_primary_targets=primary, variants=answer)


def check_case(public, view, prediction, truth, score, policy):
    validate_records(public, view, truth)
    keys(prediction, ("schema", "complete", "public_sha256", "view_sha256", "policy_sha256",
                      "horizon", "variants", "rows"), "prediction_shape")
    require(prediction["schema"] == "kpi-population-strong-predictions-v1"
            and prediction["complete"] is True and prediction["horizon"] == "final", "prediction_scope")
    equal(prediction["variants"], list(NAMES), "variant_roster")
    expected_targets = targets(public)
    require(len(expected_targets) == 128 and len(prediction["rows"]) == 128, "full_target_coverage")
    for i, row in zip(expected_targets, prediction["rows"]):
        keys(row, ("event", "guesses"), "row_shape")
        require(type(row["event"]) is int and row["event"] == i, "target_order")
        keys(row["guesses"], NAMES, "guess_variants")
        for name, guess in row["guesses"].items():
            keys(guess, ("sender", "recipient", "amount", "relationship_rank"), "guess_shape")
            number(guess["sender"], 0, 31)
            number(guess["recipient"], 0, 31)
            number(guess["amount"])
            require(isinstance(guess["relationship_rank"], list) and len(guess["relationship_rank"]) == 4,
                    "rank_shape")
            a, b, c, d = [number(x, -(2**63) + 1, 2**63 - 1) for x in guess["relationship_rank"]]
            require(0 <= a <= 2 and b >= 0 and c >= 0 and d <= 0, "rank_domains")
            require(name != "prior" or (a, b, c, d) == (0, 0, 0, 0), "prior_rank")
    for value, label in ((public, "public_sha256"), (view, "view_sha256"), (policy, "policy_sha256")):
        require(prediction[label] == digest(value) == score[label], "canonical_identity")
    require(score["prediction_sha256"] == digest(prediction), "prediction_score_identity")
    calculated = recompute_counts(public, view, prediction, truth)
    expected_score = dict(schema="kpi-population-strong-score-v1", complete=True,
        public_sha256=digest(public), view_sha256=digest(view), policy_sha256=digest(policy),
        prediction_sha256=digest(prediction), regime=truth["regime"], arm="persistent", horizon="final",
        targets=128, truth_consistency=dict(complete=True, cp_sat="SAT", z3="SAT"),
        policy_validation=POLICY_CHECK, qualification_pass=False, **calculated)
    equal(score, expected_score, "case_score_counts_or_metadata")
    return dict(schema="kpi-strong-independent-review-v1", mode="case", passed=True,
                ordinary_targets=128, primary_targets=calculated["tested_primary_targets"],
                field_counter_cells=80, selective_counter_cells=48,
                digests={"public": digest(public), "view": digest(view), "prediction": digest(prediction),
                         "score": digest(score), "policy": digest(policy)})


def fraction(counter):
    n = number(counter["eligible"], 0, 128)
    k = number(counter["correct"], 0, n)
    return Fraction(k, n) if n else None


def describe(counters):
    rates = [fraction(c) for c in counters]
    nonempty = [r for r in rates if r is not None]
    k, n = sum(c["correct"] for c in counters), sum(c["eligible"] for c in counters)
    return dict(correct=k, eligible=n, pooled_rate=k / n if n else None,
                total_histories=len(counters), defined_histories=len(nonempty),
                mean_history_rate=float(sum(nonempty) / len(nonempty)) if nonempty else None)


def bound(rates, paired=False):
    n = len(rates)
    count = sum(x is not None for x in rates)
    if count != n or n == 0:
        return dict(complete=False, histories=n, defined_histories=count, mean=None, lower=None, upper=None)
    mean = float(sum(rates) / n)
    lo, hi = (-1., 1.) if paired else (0., 1.)
    require(all(lo <= x <= hi for x in rates), "interval_domain")
    radius = (hi - lo) * math.sqrt(math.log(3960) / (2 * n))
    return dict(complete=True, histories=n, defined_histories=n, mean=mean,
                lower=max(lo, math.nextafter(mean - radius, -math.inf)),
                upper=min(hi, math.nextafter(mean + radius, math.inf)))


def check_aggregate(cases, summary):
    require(isinstance(cases, list) and len(cases) == 16, "sixteen_independent_units")
    unique_public, policies = set(), set()
    for index, case in enumerate(cases):
        keys(case, ("case", "regime", "score"), "aggregate_case_shape")
        regime = "overlap" if index < 8 else "sparse"
        require(case["case"] == f"set-{index + 1:02d}-persistent" and case["regime"] == regime
                and case["score"]["regime"] == regime, "ordered_history_roster")
        score = case["score"]
        require(score["complete"] is True and score["qualification_pass"] is False and score["targets"] == 128,
                "completed_history")
        unique_public.add(score["public_sha256"])
        policies.add(score["policy_sha256"])
    require(len(unique_public) == 16 and len(policies) == 1, "history_identity_independence_proxy")
    keys(summary, ("schema", "complete", "status", "qualification_pass", "scopes", "certified_breaches",
                   "descriptive_point_estimate_exceedances", "inference", "limits"), "summary_shape")
    require(summary["schema"] == "kpi-population-strong-summary-v1" and summary["qualification_pass"] is False,
            "summary_scope")
    keys(summary["scopes"], ("pooled", "overlap", "sparse"), "summary_scopes")
    inference = summary["inference"]
    for field, value in dict(method="Bonferroni simultaneous two-sided Hoeffding", family_intervals=99,
                            tails=198, family_alpha=.05, unit="independent history, equally weighted",
                            unit_range=[0, 1], paired_difference_range=[-1, 1]).items():
        equal(inference[field], value, "statistical_family")
    breaches, signals, complete, checked = [], [], True, 0
    for scope in ("pooled", "overlap", "sparse"):
        chosen = [c["score"] for c in cases if scope == "pooled" or c["regime"] == scope]
        published = summary["scopes"][scope]
        keys(published, ("histories", "variants", "paired_prior_advantages"), "scope_shape")
        require(published["histories"] == len(chosen), "history_weighting")
        keys(published["variants"], NAMES, "scope_variants")
        keys(published["paired_prior_advantages"], NAMES[1:], "scope_advantages")

        def verify_interval(actual, rates, cap, name, metric, kind, percent=None):
            nonlocal complete, checked
            expected = bound(rates, paired=kind == "paired_prior_advantage")
            checked += 1
            complete &= expected["complete"]
            certified = expected["complete"] and expected["lower"] > cap
            exploratory = expected["complete"] and expected["mean"] > cap
            for key, value in dict(cap=cap, certified_breach=certified,
                                   point_estimate_exceeds_cap=exploratory, **expected).items():
                equal(actual[key], value, "interval_or_cap_decision")
            metadata = dict(scope=scope, variant=name, metric=metric, cap=cap, kind=kind)
            if percent is not None:
                metadata["nominal_percent"] = percent
            if certified:
                breaches.append(dict(metadata, lower=expected["lower"]))
            if exploratory:
                signals.append(dict(metadata, mean=expected["mean"]))

        for name in NAMES:
            published_variant = published["variants"][name]
            keys(published_variant, ("descriptive", "absolute", "selective_relationship"), "variant_summary_shape")
            keys(published_variant["descriptive"], GROUPS, "descriptive_groups")
            for group in GROUPS:
                keys(published_variant["descriptive"][group], FACTS, "descriptive_metrics")
                for fact in FACTS:
                    counters = [s["variants"][name][group][fact] for s in chosen]
                    equal(published_variant["descriptive"][group][fact], describe(counters), "descriptive_counts")
            keys(published_variant["absolute"], CAPS, "absolute_metrics")
            for metric, cap in CAPS.items():
                rates = [fraction(s["variants"][name]["primary"][metric]) for s in chosen]
                verify_interval(published_variant["absolute"][metric], rates, cap, name, metric, "absolute")
            keys(published_variant["selective_relationship"], map(str, PERCENT), "selective_coverages")
            for percent in PERCENT:
                counters = [s["variants"][name]["primary"]["selective_relationship"][str(percent)] for s in chosen]
                result = published_variant["selective_relationship"][str(percent)]
                verify_interval(result, [fraction(c) for c in counters], .50, name,
                                "selective_relationship", "selective", percent)
                equal(result["descriptive"], describe(counters), "selective_descriptive")
                equal(result["realized_coverages"], [c["realized_coverage"] for c in counters], "actual_coverages")
        for name in NAMES[1:]:
            keys(published["paired_prior_advantages"][name], CAPS, "advantage_metrics")
            for metric in CAPS:
                differences = []
                for s in chosen:
                    a = fraction(s["variants"][name]["primary"][metric])
                    b = fraction(s["variants"]["prior"]["primary"][metric])
                    differences.append(None if a is None or b is None else a - b)
                result = published["paired_prior_advantages"][name][metric]
                require(result["baseline"] == "prior", "paired_baseline")
                verify_interval(result, differences, .05, name, metric, "paired_prior_advantage")
    require(checked == 99, "comparison_count")
    # Lists are semantic sets; sorting avoids relying on the scorer's loop order.
    order = lambda row: (row["scope"], row["variant"], row["kind"], row["metric"], row.get("nominal_percent", 0))
    equal(sorted(summary["certified_breaches"], key=order), sorted(breaches, key=order), "breach_roster")
    equal(sorted(summary["descriptive_point_estimate_exceedances"], key=order), sorted(signals, key=order), "signal_roster")
    status = "incomplete" if not complete else "evidence-valid cap-breach" if breaches else "bounded-screen-complete-no-certified-breach"
    require(summary["complete"] is bool(complete) and summary["status"] == status, "aggregate_decision")
    return dict(schema="kpi-strong-independent-review-v1", mode="aggregate", passed=True,
                histories=16, intervals=checked, tails=198, certified_breaches=len(breaches),
                exploratory_signals=len(signals), digests={"scores": digest(cases), "summary": digest(summary)})


def controls():
    # Four hand-written target facts: one unknown startup, one wholly known
    # author, one recipient-only record, one unknown all-admitted payment.
    events = [dict(mode=1, new=[1, 2]), dict(mode=1, new=[3, 4]),
              dict(mode=0, new=[5, 6], funding_group="fund2"),
              dict(mode=1, new=[7, 8]), dict(mode=1, new=[9, 10]), dict(mode=1, new=[11, 12])]
    public = dict(roles=[0, 1, 2], adversaries=[0], funding_owners={"fund0": 0, "fund2": 2},
                  algebra=dict(initial=dict(funding_group="fund0"), events=events))
    # Role1 must already be admitted before the startup test; the final new
    # admission brings role2 online. Use an explicit extra public admission.
    events.insert(1, dict(mode=0, new=[3, 4], funding_group="fund1"))
    public["funding_owners"]["fund1"] = 1
    hidden = [dict(kind="nonpayment") for _ in events]
    actual = {2: (1, 1, 100), 4: (0, 1, 100), 5: (1, 0, 100), 6: (1, 2, 100)}
    for i, (sender, recipient, amount) in actual.items():
        hidden[i] = dict(sender=sender, recipient=recipient, amount=amount, kind="payment")
    view = dict(members=[0], authored=[dict(event=4)], receipts=[dict(position=events[5]["new"][0])])
    rows = []
    for i in actual:
        sender, recipient, amount = actual[i]
        rows.append(dict(event=i, guesses={name: dict(sender=sender if i != 6 else 2,
            recipient=recipient, amount=110 if i != 6 else 111,
            relationship_rank=[1, 0, 0, -1]) for name in NAMES}))
    checked = recompute_counts(public, view, dict(rows=rows), dict(events=hidden))
    require(checked["tested_primary_targets"] == 1, "control_primary")
    result = checked["variants"]["prior"]
    equal(result["all_undisclosed"]["sender"], dict(correct=2, eligible=3), "control_sender_exclusions")
    equal(result["all_undisclosed"]["recipient"], dict(correct=2, eligible=2), "control_recipient_exclusions")
    equal(result["all_undisclosed"]["relationship"], dict(correct=2, eligible=3), "control_joint_exclusions")
    equal(result["all_undisclosed"]["amount_within_10pct"], dict(correct=1, eligible=2), "control_amount_boundary")
    equal(result["startup"]["sender"], dict(correct=1, eligible=1), "control_startup")
    require(result["all_undisclosed"]["selective_relationship"]["5"]["correct"] == 1,
            "control_rank_event_tie")
    weighted = describe([dict(correct=1, eligible=1), dict(correct=0, eligible=99)])
    require(weighted["mean_history_rate"] == .5 and weighted["pooled_rate"] == .01, "control_history_weights")
    require(not bound([Fraction(0), None])["complete"], "control_zero_cell")
    require(math.isclose(bound([Fraction(0)] * 16)["upper"], .508797581103, abs_tol=1e-10), "control_radius16")
    require(math.isclose(bound([Fraction(0)] * 8)["upper"], .719548439665, abs_tol=1e-9), "control_radius8")
    require(bound([Fraction(1)] * 16, paired=True)["lower"] < 0, "control_paired_width")
    try:
        equal(dict(correct=2, eligible=3), dict(correct=1, eligible=3), "mutated_counter")
    except CheckFailure:
        pass
    else:
        raise CheckFailure("control_mutated_counter")
    return dict(schema="kpi-strong-independent-review-v1", mode="controls", passed=True,
                controls=11, scope="hand-written public fixtures only")


def main():
    args = sys.argv[1:]
    if args == ["controls"]:
        return controls()
    if len(args) == 7 and args[0] == "case":
        return check_case(*(read(p) for p in args[1:]))
    if len(args) == 3 and args[0] == "aggregate":
        return check_aggregate(*(read(p) for p in args[1:]))
    raise CheckFailure("usage_case_six_files_or_aggregate_two_files_or_controls")


if __name__ == "__main__":
    try:
        result = main()
    except CheckFailure as error:
        print(json.dumps(dict(passed=False, check=str(error)), sort_keys=True))
        sys.exit(1)
    except Exception:
        # No traceback, exception details or loaded field contents can escape.
        print(json.dumps(dict(passed=False, check="unexpected_input_or_runtime_failure"), sort_keys=True))
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))
