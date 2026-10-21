#!/usr/bin/env python3
"""Exploratory explanation of sealed guesses; outside the frozen experiment.

Classification rules fixed in source before the first diagnostic execution:
* Primary is the original honest/honest, fully admitted target set (36 here).
* Immediate receipt exit means the very next pool operation consumes that exact
  receipt; classify its actual one/two-positive-note arity from private truth.
* Later intermediate, final drain and PAY consumption are separate outcomes.
* A residual support is true only if the indicated DRAIN's actual input set is
  exactly the target receipt plus the proposed known coinput (if any). Equal
  value without the correct receipt/input set is a collision, not a link.
* A split explanation additionally requires the actual PAY inputs and actual
  change-note drain (or actual zero change). Keep every support for the selected
  candidate; report mixed true/false support rather than choose using truth.
  Actual note-flow agreement does not certify a guessed recipient identity.
* Next-public-withdrawal classes use the original next-DRAIN cutoff, separately
  from the recipient's policy class and actual later receipt consumption.
* Final drainage starts at the declared last-payment minute plus 60. An
  immediate last-payment exit at the payment minute remains intermediate.
  This corrects the initial diagnostic's after-last-PAY ordinal label; its
  aggregate artifact is preserved and every non-phase result must agree.
  All target groups
  retain the original denominator; gains/losses compare paired sealed guesses.

The unchanged frozen observer is replayed ONLY to recover support for its
already sealed guesses, which must match exactly. No modified attack, ablation,
new history, proof or claimed mitigation. Output is aggregate counts only.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import types

EXPORTER_SHA = "5b281274b2237288ea9c8c3cc1b076eb80d31d12949a29bdbe700b118454d1a6"
RECOUNT_SHA = "ec99bf6291b20f891ff59b720fb95a990f8b84488f883e15d62e20139799adc5"
INITIAL_ARTIFACT_SHA = "26530a11c933b8e8ca1485732379557d31fbfc858ab1b2d682abacba88b976e6"
PROFILES = ("C", "pooled")
HORIZONS = ("creation", "cashout", "final")
VARIANTS = ("prior", "residual", "split", "native_graph")
LIFECYCLE = ("immediate_single_receipt_exit", "immediate_two_note_receipt_exit",
             "later_intermediate_receipt_exit", "final_receipt_exit", "receipt_consumed_by_pay", "unspent")
NEXT = ("own_receipt_single", "own_receipt_pair", "other_single", "other_pair")
SUPPORT = ("fallback", "true_receipt_only", "mixed_true_and_collision", "collision_only")
INVOICES = {n * 100_000_000 for n in (10, 20, 25, 40, 50)}


def need(value):
    if not value:
        raise ValueError("diagnostic invariant failed")


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def module(name, blob, path):
    result = types.ModuleType(name)
    result.__file__ = str(path)
    exec(compile(blob, str(path), "exec"), result.__dict__)
    return result


def hit(guess, actual, exact=False):
    return guess == actual if exact else 10 * abs(guess - actual) <= actual


def summarize(rows):
    result = dict(targets=len(rows))
    for metric in ("within", "exact"):
        result[metric + "_hits"] = sum(row[metric] for row in rows)
        result["prior_" + metric + "_hits"] = sum(row["prior_" + metric] for row in rows)
        result[metric + "_gains"] = sum(row[metric] and not row["prior_" + metric] for row in rows)
        result[metric + "_losses"] = sum(not row[metric] and row["prior_" + metric] for row in rows)
    result["same_amount_as_prior"] = sum(row["same_as_prior"] for row in rows)
    return result


def phase_boundary(timing, last_pay):
    minute = timing["events"][last_pay]["minute"]
    first = next(i for i in range(last_pay+1, len(timing["events"])) if timing["events"][i]["minute"] > minute)
    need(timing["events"][first]["minute"] == minute + 60)
    return first - 1


def classify(target, events, inputs, horizons, intermediate_end):
    receipt = events[target]["outputs"][0]["position"]
    consumers = [i for i in range(target+1, len(events)) if receipt in inputs[str(i)]]
    need(len(consumers) <= 1)
    consumer = consumers[0] if consumers else None
    if consumer is None:
        lifecycle = "unspent"
    elif events[consumer]["kind"] == "pay":
        lifecycle = "receipt_consumed_by_pay"
    elif consumer > intermediate_end:
        need(events[consumer]["kind"] == "exit")
        lifecycle = "final_receipt_exit"
    elif consumer == target + 1:
        lifecycle = "immediate_single_receipt_exit" if len(inputs[str(consumer)]) == 1 else "immediate_two_note_receipt_exit"
    else:
        lifecycle = "later_intermediate_receipt_exit"
    cutoff = horizons[target]["cashout"]
    need(events[cutoff]["kind"] == "exit" and len(inputs[str(cutoff)]) in (1, 2))
    owns = receipt in inputs[str(cutoff)]
    next_class = ("own_receipt_" if owns else "other_") + ("single" if len(inputs[str(cutoff)]) == 1 else "pair")
    return dict(lifecycle=lifecycle, next_class=next_class,
                recipient_mode=None, phase="final" if cutoff > intermediate_end else "intermediate")


def receipt_support(note, drain, coinput, inputs):
    expected = {note} if coinput is None else {note, coinput}
    return (coinput is None or coinput != note) and set(inputs[str(drain)]) == expected


def support_summary(target, evidences, truth, intermediate_end):
    receipt, change = [item["position"] for item in truth["events"][target]["outputs"]]
    facts, kinds = [], dict(whole_drain=0, known_note_subtraction=0, zero_change_split=0, positive_change_split=0)
    for evidence in evidences:
        if len(evidence) == 2:
            drain, coinput = evidence
            kinds["whole_drain" if coinput is None else "known_note_subtraction"] += 1
            good = receipt_support(receipt, drain, coinput, truth["inputs"])
            full = good
        else:
            need(len(evidence) == 5)
            selected, drain, coinput, change_drain, change_coinput = evidence
            kinds["zero_change_split" if change_drain is None else "positive_change_split"] += 1
            good = receipt_support(receipt, drain, coinput, truth["inputs"])
            change_good = (truth["values"][change] == 0 if change_drain is None else
                           receipt_support(change, change_drain, change_coinput, truth["inputs"]))
            full = good and change_good and set(selected) == set(truth["inputs"][str(target)])
        facts.append((good, full, drain > intermediate_end, len(truth["inputs"][str(drain)])))
    good = sum(row[0] for row in facts)
    category = ("fallback" if not facts else "true_receipt_only" if good == len(facts)
                else "mixed_true_and_collision" if good else "collision_only")
    return dict(category=category, evidence_count=len(facts), true_receipt_supports=good,
                actual_note_flow_explanations=sum(row[1] for row in facts), **kinds,
                final_drain_supports=sum(row[2] for row in facts),
                single_note_supports=sum(row[3] == 1 for row in facts),
                pair_note_supports=sum(row[3] == 2 for row in facts))


def trace(engine, target, sealed):
    baseline = engine.prior(target)
    books, graph = engine.candidates(target), engine.candidates(target, graph=True)
    merged = copy.deepcopy(graph["residual"])
    for key, value in graph["split"].items():
        if key not in merged:
            merged[key] = copy.deepcopy(value)
        else:
            merged[key]["rank"] = max(merged[key]["rank"], value["rank"])
            merged[key]["support"].update(value["support"])
    predicted = dict(prior=baseline, residual=engine.best(books["residual"], baseline),
                     split=engine.best(books["split"], baseline))
    predicted["native_graph"] = engine.best(merged, predicted["split"])
    need(canonical(predicted) == canonical(sealed))
    selected_books = dict(prior={}, residual=books["residual"], split=books["split"],
                          native_graph=merged if merged else books["split"])
    return {variant: selected_books[variant].get(
        (guess["sender"], guess["recipient"], guess["amount"]), {}).get("support", set())
        for variant, guess in sealed.items()}


def aggregate(rows):
    result = dict(overall=summarize(rows))
    for field, categories in (("lifecycle", LIFECYCLE), ("next_class", NEXT),
                              ("recipient_mode", ("prompt", "accumulated", "retain")),
                              ("phase", ("intermediate", "final")), ("support_class", SUPPORT)):
        result[field] = {category: summarize([row for row in rows if row[field] == category]) for category in categories}
    result["support_counts"] = {key: sum(row[key] for row in rows) for key in
        ("evidence_count", "true_receipt_supports", "actual_note_flow_explanations", "final_drain_supports",
         "single_note_supports", "pair_note_supports", "graph_tier_selected", "whole_drain",
         "known_note_subtraction", "zero_change_split", "positive_change_split")}
    result["exact_hit_support_classes"] = {category: sum(row["exact"] and row["support_class"] == category for row in rows)
                                           for category in SUPPORT}
    result["within_hit_support_classes"] = {category: sum(row["within"] and row["support_class"] == category for row in rows)
                                            for category in SUPPORT}
    result["collision_only_exact_invoice_hits"] = sum(row["exact"] and row["invoice"] and row["support_class"] == "collision_only" for row in rows)
    # Numerical equality is not evidence the heuristic used that withdrawal;
    # in particular creation and prior rows can match a then-future total.
    result["next_drain_total_numeric_matches"] = dict(
        guessed_total=sum(row["next_total_guess"] for row in rows),
        exact_own_receipt=sum(row["next_total_guess"] and row["exact"] and row["next_class"].startswith("own_") for row in rows),
        exact_other_receipt_collision=sum(row["next_total_guess"] and row["exact"] and row["next_class"].startswith("other_") for row in rows),
        within_only_other_receipt_collision=sum(row["next_total_guess"] and row["within"] and not row["exact"]
            and row["next_class"].startswith("other_") for row in rows))
    return result


def diagnose(reader, exporter, recount, observer, truth):
    raw, directory = reader.read("inputs/final/raw.json"), reader.read("inputs/final/directory.json")
    timing, policy = reader.read("inputs/final/timing.json"), reader.read("policy.json")
    public_events = observer.surface.surface.project(raw)["algebra"]["events"]
    transactions, targets, horizons, admitted, predictions = recount.prepare(raw, directory, truth, reader.read("predictions.json"))
    primary = [i for i in targets if admitted[i] and min(truth["events"][i]["owner"], truth["events"][i]["recipient"]) >= 8]
    need(len(primary) == 36)
    intermediate_end = phase_boundary(timing, targets[-1])
    classes = {i: classify(i, truth["events"], truth["inputs"], horizons, intermediate_end) for i in primary}
    for i in primary:
        classes[i]["recipient_mode"] = truth["schedule"]["modes"][truth["events"][i]["recipient"]]
    rows = {p: {h: {v: [] for v in VARIANTS} for h in HORIZONS} for p in PROFILES}
    transitions, graph_comparison = {}, {}
    modes = exporter.modes(raw)
    for profile in PROFILES:
        view = reader.read("native/private/views/" + profile + ".json")
        endpoints = sorted({horizons[i][h] for i in primary for h in HORIZONS})
        for end in endpoints:
            r, d, v, t = exporter.prefixes(raw, directory, timing, view, end, modes)
            engine = observer.Engine(observer.surface.project(r, d, v, t, policy))
            sealed_rows = {row["event"]: row["guesses"] for row in predictions[profile, end]["rows"]}
            for target in primary:
                relevant = [h for h in HORIZONS if horizons[target][h] == end]
                if not relevant:
                    continue
                sealed = sealed_rows[target]
                evidence = trace(engine, target, sealed)
                actual = truth["events"][target]["amount"]
                for horizon in relevant:
                    cutoff = horizons[target]["cashout"]
                    total = public_events[cutoff]["payout"] + public_events[cutoff]["fee"]
                    need(total == sum(truth["values"][p] for p in truth["inputs"][str(cutoff)]))
                    for variant in VARIANTS:
                        amount, prior = sealed[variant]["amount"], sealed["prior"]["amount"]
                        support = support_summary(target, evidence[variant], truth, intermediate_end)
                        rows[profile][horizon][variant].append(dict(**classes[target], within=hit(amount, actual),
                            exact=hit(amount, actual, True), prior_within=hit(prior, actual), prior_exact=hit(prior, actual, True),
                            same_as_prior=amount == prior, support_class=support.pop("category"), **support,
                            invoice=actual in INVOICES, next_total_guess=amount == total,
                            graph_tier_selected=int(sealed[variant]["relationship_rank"][1] in (4, 5))))
        transitions[profile], graph_comparison[profile] = {}, {}
        for variant in VARIANTS:
            counts = dict(targets=36, amount_changed=0, within_gains=0, within_losses=0, exact_gains=0, exact_losses=0)
            for i in primary:
                early = next(r for r in predictions[profile, horizons[i]["cashout"]]["rows"] if r["event"] == i)["guesses"][variant]["amount"]
                late = next(r for r in predictions[profile, horizons[i]["final"]]["rows"] if r["event"] == i)["guesses"][variant]["amount"]
                actual = truth["events"][i]["amount"]
                counts["amount_changed"] += int(early != late)
                for label, exact in (("within", False), ("exact", True)):
                    counts[label+"_gains"] += int(hit(late, actual, exact) and not hit(early, actual, exact))
                    counts[label+"_losses"] += int(hit(early, actual, exact) and not hit(late, actual, exact))
            transitions[profile][variant] = counts
        for horizon in HORIZONS:
            counts = dict(targets=36, same_as_residual=0, same_as_split=0, within_gains_over_residual=0,
                          within_losses_to_residual=0, within_gains_over_split=0, within_losses_to_split=0,
                          graph_tier_selected=0)
            for i in primary:
                guesses = next(r for r in predictions[profile, horizons[i][horizon]]["rows"] if r["event"] == i)["guesses"]
                amount, actual = guesses["native_graph"]["amount"], truth["events"][i]["amount"]
                counts["graph_tier_selected"] += int(guesses["native_graph"]["relationship_rank"][1] in (4, 5))
                for alternative in ("residual", "split"):
                    other = guesses[alternative]["amount"]
                    counts["same_as_"+alternative] += int(amount == other)
                    counts["within_gains_over_"+alternative] += int(hit(amount, actual) and not hit(other, actual))
                    counts["within_losses_to_"+alternative] += int(not hit(amount, actual) and hit(other, actual))
            graph_comparison[profile][horizon] = counts
    result = {p: {h: {v: aggregate(rows[p][h][v]) for v in VARIANTS} for h in HORIZONS} for p in PROFILES}
    # Match the already recounted published primary counts before explaining them.
    score = reader.read("runs/score/result.json")
    for p in PROFILES:
        for h in HORIZONS:
            for v in VARIANTS:
                public = score["profiles"][p][h]["variants"][v]["primary"]
                counted = result[p][h][v]["overall"]
                need(counted["targets"] == public["amount_exact"]["eligible"] == public["amount_within_10pct"]["eligible"] == 36)
                need(counted["exact_hits"] == public["amount_exact"]["correct"]
                     and counted["within_hits"] == public["amount_within_10pct"]["correct"])
    return dict(primary_targets=36, profiles_same_primary_set=True, replayed_target_horizons=216,
                replayed_variant_guesses=864, profiles=result, cashout_to_final=transitions,
                native_graph_amount_comparison=graph_comparison)


def without_phase_labels(value):
    if isinstance(value, dict):
        return {key: without_phase_labels(item) for key, item in value.items()
                if key not in ("lifecycle", "phase", "final_drain_supports")}
    if isinstance(value, list):
        return [without_phase_labels(item) for item in value]
    return value


def run(attempt, destination):
    source = Path(__file__).absolute()
    source_hash = sha(source.read_bytes())
    def helper(filename, expected):
        path = source.with_name(filename)
        blob = path.read_bytes()
        need(sha(blob) == expected)
        return module(filename[:-3], blob, path)
    exporter = helper("native_usage_export.py", EXPORTER_SHA)
    recount = helper("native_usage_recount.py", RECOUNT_SHA)
    reader = exporter.Reader(attempt)
    destination = Path(destination).absolute()
    need(not destination.exists() and not destination.is_symlink() and reader.root not in destination.parents)
    exporter.checked(destination.parent, directory=True)
    initial_blob = source.parent.joinpath("artifacts/native-usage-withdrawal-diagnosis-20261021-initial-label-version.json").read_bytes()
    need(sha(initial_blob) == INITIAL_ARTIFACT_SHA)
    initial = exporter.load(initial_blob)
    frozen, native, _, truth = recount.sealed_truth(reader, exporter)
    names = ("early_privacy_surface", "native_usage_surface", "native_usage_observer")
    previous = {name: sys.modules.get(name) for name in names}
    try:
        for name in names:
            filename = name + ".py"
            blob = reader.blob("code/"+filename)
            need(sha(blob) == frozen["sources"][filename])
            sys.modules[name] = module(name, blob, reader.root / "code" / filename)
        result = diagnose(reader, exporter, recount, sys.modules["native_usage_observer"], truth)
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
    del truth
    reader.unchanged()
    need(sha(source.read_bytes()) == source_hash)
    need(canonical(without_phase_labels(result)) == canonical(without_phase_labels({key: initial[key] for key in result})))
    output = dict(schema="kpi-native-usage-withdrawal-diagnosis-v1", complete=True,
                  exploratory_post_run=True, qualification_pass=False, new_attacks=False,
                  label_correction=dict(initial_artifact_sha256=INITIAL_ARTIFACT_SHA,
                    initial_source_sha256=initial["hashes"]["diagnostic_source"],
                    non_phase_aggregates_unchanged=True,
                    reason="Final drainage starts at the declared plus-60-minute phase, not immediately after the last PAY"),
                  hashes=dict(diagnostic_source=source_hash, verifier_source=EXPORTER_SHA, recount_source=RECOUNT_SHA,
                    freeze=reader.hash("freeze.json"), frozen_observer=frozen["sources"]["native_usage_observer.py"],
                    prediction_batch=reader.hash("prediction-batch.json"), predictions=reader.hash("predictions.json"),
                    truth=native["truth_sha256"], score=reader.hash("runs/score/result.json")),
                  **result, limits=["Post-run descriptive explanation of one seen dependent history; no mitigation evaluation.",
                    "Exact amount coincidence does not establish a receipt link or common owner.",
                    "Actual positive-note arity and receipt relationships use private ground truth, not publicly exposed labels.",
                    "Modeled minute distances affect frozen ranking; no timing ablation was performed.",
                    "Collusion supplies a superset of information; a worse fixed heuristic is not a privacy benefit."])
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(output, indent=2, allow_nan=False)+"\n")
    return dict(complete=True, primary_targets=36, replayed_variant_guesses=864,
                aggregate_output_sha256=sha(destination.read_bytes()), diagnostic_source_sha256=source_hash)


def controls():
    tests = []
    def check(ok, label):
        need(ok); tests.append(label)
    inputs = {"0": [], "1": [3], "2": [7, 8], "3": [4]}
    check(receipt_support(3, 1, None, inputs) and not receipt_support(4, 1, None, inputs), "exact-position-not-equal-value-link")
    check(receipt_support(7, 2, 8, inputs) and not receipt_support(7, 2, 4, inputs), "pair-coinput-must-actually-be-spent")
    truth = dict(events=[dict(outputs=[dict(position=3), dict(position=4)])], inputs={**inputs, "0": [0]}, values=[0]*9)
    mixed = support_summary(0, {(1, None), (3, None)}, truth, 2)
    check(mixed["category"] == "mixed_true_and_collision" and mixed["true_receipt_supports"] == 1
          and mixed["final_drain_supports"] == 1, "retain-all-supports-and-final-phase")
    check(support_summary(0, set(), truth, 2)["category"] == "fallback", "empty-book-fallback")
    check(support_summary(0, {((0,), 1, None, 3, None)}, truth, 2)["actual_note_flow_explanations"] == 1
          and support_summary(0, {((1,), 1, None, 3, None)}, truth, 2)["actual_note_flow_explanations"] == 0,
          "split-input-change-and-receipt-all-required")
    events = [dict(kind="pay", outputs=[dict(position=3)]), dict(kind="exit"), dict(kind="pay"), dict(kind="exit")]
    horizons = {0: dict(cashout=1)}
    check(classify(0, events, {"0": [], "1": [3], "2": [], "3": []}, horizons, 2)["lifecycle"] == "immediate_single_receipt_exit",
          "immediate-own-single-exit")
    check(classify(0, events, {"0": [], "1": [7], "2": [], "3": [3]}, horizons, 2)["next_class"] == "other_single"
          and classify(0, events, {"0": [], "1": [7], "2": [], "3": [3]}, horizons, 2)["lifecycle"] == "final_receipt_exit",
          "next-public-drain-not-recipient-drain")
    check(classify(0, events, {"0": [], "1": [7], "2": [3], "3": []}, horizons, 2)["lifecycle"] == "receipt_consumed_by_pay",
          "pay-consumption-distinct-from-exit")
    boundary = phase_boundary(dict(events=[dict(minute=n) for n in (10, 10, 70, 70)]), 0)
    check(boundary == 1 and classify(0, events, {"0": [], "1": [3], "2": [], "3": []}, horizons, boundary)["lifecycle"]
          == "immediate_single_receipt_exit", "last-pay-immediate-exit-precedes-final-phase")
    check(without_phase_labels(dict(overall=3, phase={"final": 1}, final_drain_supports=2)) == dict(overall=3),
          "label-correction-preserves-all-other-aggregates")
    check(hit(90, 100) and hit(110, 100) and not hit(111, 100), "inclusive-integer-ten-percent")
    rows = [dict(within=True, prior_within=False, exact=True, prior_exact=False, same_as_prior=False),
            dict(within=False, prior_within=True, exact=False, prior_exact=False, same_as_prior=False)]
    check(summarize(rows)["within_gains"] == summarize(rows)["within_losses"] == 1
          and summarize(rows)["exact_gains"] == 1, "paired-gains-losses-not-net-only")
    return dict(complete=True, passed=True, tests=tests, scope="Public handmade classification fixtures only")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("controls")
    command = sub.add_parser("diagnose")
    command.add_argument("attempt"); command.add_argument("new_result")
    args = parser.parse_args()
    try:
        result = controls() if args.command == "controls" else run(args.attempt, args.new_result)
    except Exception:
        print(json.dumps(dict(complete=False, error="withdrawal-diagnosis-rejected")))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
