#!/usr/bin/env python3
"""Post-run aggregate arithmetic audit; outside the frozen experiment.

The pinned public exporter verifies completion and ALL prediction seals before
this script reads exactly one private truth file. Arithmetic below uses only
stdlib and never imports the frozen scorer, observer, generator or solver.
No per-target facts, masks, correctness, values or identities are emitted.
This does not independently revalidate native proofs or qualify privacy.
"""
import argparse
import copy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import types

EXPORTER_SHA256 = "5b281274b2237288ea9c8c3cc1b076eb80d31d12949a29bdbe700b118454d1a6"
PROFILES = ("C", *(f"P{i}" for i in range(8)), "pooled")
HORIZONS = ("creation", "cashout", "final")
VARIANTS = ("prior", "residual", "split", "native_graph")
STRATA = ("primary", "all_undisclosed", "startup", "adversary_endpoint")
METRICS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
CAPS = {"sender": Fraction(1, 10), "recipient": Fraction(1, 10),
        "amount_within_10pct": Fraction(1, 5)}
COVERAGES = (5, 10, 25)


def require(condition):
    if not condition:
        raise ValueError("audit invariant failed")


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def ratio(numerator, denominator):
    if not denominator:
        return None
    value = Fraction(numerator, denominator)
    return dict(numerator=value.numerator, denominator=value.denominator)


def rate(counter):
    return Fraction(counter["correct"], counter["eligible"]) if counter["eligible"] else None


def count(outcomes):
    n, correct = len(outcomes), sum(outcomes)
    return dict(correct=correct, eligible=n, rate=ratio(correct, n))


def eligibility(ordinal, sender, recipient, members, all_admitted):
    # Knowledge from authored/received records exists at target creation.
    sender_known = sender in members or ordinal < 4
    recipient_known = sender in members or recipient in members
    amount_known = recipient_known or ordinal < 4
    known = dict(sender=sender_known, recipient=recipient_known,
                 relationship=sender_known and recipient_known,
                 amount_within_10pct=amount_known, amount_exact=amount_known)
    adversary = min(sender, recipient) < 8
    groups = {"all_undisclosed"}
    if all_admitted and not adversary:
        groups.add("primary")
    if not all_admitted:
        groups.add("startup")
    if adversary:
        groups.add("adversary_endpoint")
    return known, groups


def accuracy(guess, hidden):
    sender = guess["sender"] == hidden["owner"]
    recipient = guess["recipient"] == hidden["recipient"]
    amount = hidden["amount"]
    return dict(sender=sender, recipient=recipient, relationship=sender and recipient,
                amount_exact=guess["amount"] == amount,
                amount_within_10pct=10 * abs(guess["amount"] - amount) <= amount)


def selected(rows, percent):
    # Stable two-pass sorting makes the ascending ordinal tie break explicit.
    ordered = sorted(rows, key=lambda row: row[0])
    ordered.sort(key=lambda row: tuple(row[1]), reverse=True)
    n = (percent * len(ordered) + 99) // 100
    return dict(**count([row[2] for row in ordered[:n]]), population=len(rows),
                nominal_percent=percent, realized_coverage=ratio(n, len(rows)))


def group_scores(rows):
    """Rows are ephemeral private comparisons; only aggregate dictionaries return."""
    variants, warnings, diagnostics = {}, [], []
    exclusions = {metric: sum(row[1][metric] for row in rows) for metric in METRICS}
    for variant in VARIANTS:
        variants[variant] = {}
        for stratum in STRATA:
            eligible = [row for row in rows if stratum in row[2]]
            result = {metric: count([row[3][variant][metric] for row in eligible
                                    if not row[1][metric]]) for metric in METRICS}
            result["selective_relationship"] = {
                str(percent): selected([(row[0], row[4][variant], row[3][variant]["relationship"])
                                        for row in eligible if not row[1]["relationship"]], percent)
                for percent in COVERAGES}
            variants[variant][stratum] = result
            destination = warnings if stratum == "primary" else diagnostics
            for metric, cap in CAPS.items():
                value = rate(result[metric])
                if value is not None and value > cap:
                    destination.append(dict(variant=variant, stratum=stratum, metric=metric,
                                            kind="absolute", cap=ratio(cap.numerator, cap.denominator),
                                            rate=result[metric]["rate"]))
            for percent in COVERAGES:
                counter = result["selective_relationship"][str(percent)]
                value = rate(counter)
                if value is not None and value > Fraction(1, 2):
                    destination.append(dict(variant=variant, stratum=stratum,
                                            metric="selective_relationship", nominal_percent=percent,
                                            kind="selective", cap=ratio(1, 2), rate=counter["rate"]))
    advantages = {}
    for variant in VARIANTS[1:]:
        advantages[variant] = {}
        for metric in CAPS:
            counter = variants[variant]["primary"][metric]
            baseline = variants["prior"]["primary"][metric]
            require(counter["eligible"] == baseline["eligible"])
            delta = ratio(counter["correct"] - baseline["correct"], counter["eligible"])
            advantages[variant][metric] = dict(difference=delta, eligible=counter["eligible"], cap=ratio(1, 20))
            if delta is not None and Fraction(delta["numerator"], delta["denominator"]) > Fraction(1, 20):
                warnings.append(dict(variant=variant, stratum="primary", metric=metric,
                                     kind="prior_advantage", cap=ratio(1, 20), difference=delta))
    return dict(complete=all(variants["prior"]["primary"][m]["eligible"] for m in METRICS),
                targets=len(rows), known_exclusions=exclusions, variants=variants,
                primary_prior_advantages=advantages, observed_primary_warnings=warnings,
                diagnostic_exceedances=diagnostics)


def bridge_counts(prediction, bridges, event_ids):
    actual = {bridge["transaction_id"]: bridge for bridge in bridges}
    require(len(actual) == len(bridges) == len(prediction) == 4)
    require({row["transaction_id"] for row in prediction} == set(actual))
    counts = dict(edges=4, same_owner_true=0, cross_user_true=0, guesses=0, abstentions=0,
                  true_positive=0, false_positive=0, true_negative=0, false_negative=0,
                  source_owner_correct=0, source_owner_guesses=0)
    matrix = {(True, True): "true_positive", (True, False): "false_positive",
              (False, True): "false_negative", (False, False): "true_negative"}
    for row in prediction:
        truth = actual[row["transaction_id"]]
        require(event_ids[row["source_event"]] == truth["event_id"])
        same = truth["source_owner"] == truth["target_owner"]
        counts["same_owner_true" if same else "cross_user_true"] += 1
        guessed = row["same_owner_guess"]
        require(guessed is None or type(guessed) is bool)
        if guessed is None:
            counts["abstentions"] += 1
        else:
            counts["guesses"] += 1
            counts[matrix[guessed, same]] += 1
        if row["source_owner_guess"] is not None:
            counts["source_owner_guesses"] += 1
            counts["source_owner_correct"] += int(row["source_owner_guess"] == truth["source_owner"])
    require(counts["same_owner_true"] == counts["cross_user_true"] == 2)
    return counts


def prepare(raw, directory, truth, predictions):
    transactions = raw["lineage"][1:]
    payloads = [bytes.fromhex(tx["payload"]) for tx in transactions]
    require(all(len(p) == 5228 and p[:16] == b"KPICR06\0KPICU06\0" for p in payloads))
    modes = [p[212] for p in payloads]
    require(modes[0] == 1 and set(modes) <= {0, 1, 2})
    require(len(truth["events"]) == len(transactions))
    for i, (hidden, tx, mode) in enumerate(zip(truth["events"], transactions, modes, strict=True)):
        require(hidden["event"] == i and hidden["event_id"] == tx["id"])
        require(hidden["kind"] == ("bootstrap" if i == 0 else ("admit", "pay", "exit")[mode]))
        require(type(hidden["owner"]) is int and 0 <= hidden["owner"] < 32)
    targets = [i for i, mode in enumerate(modes) if i and mode == 1]
    require(len(targets) == 64)
    for ordinal, i in enumerate(targets):
        hidden = truth["events"][i]
        require(hidden["request_index"] == ordinal and type(hidden["recipient"]) is int
                and 0 <= hidden["recipient"] < 32 and type(hidden["amount"]) is int and hidden["amount"] > 0)
    # Initial admission coverage comes from public exact funding outpoints, not
    # private native-owner labels or the observation horizon's later state.
    directory_map = {(entry["transaction_id"], entry["index"]): entry["owner"] for entry in directory["entries"]}
    require(len(directory_map) == 32 and set(directory_map.values()) == set(range(32)))
    def owner(outpoint):
        return directory_map.get((outpoint["transactionId"], outpoint["index"]))
    first = owner(raw["lineage"][0]["inputs"][0]["previousOutpoint"])
    require(first is not None)
    admitted, admission_complete = {first}, []
    for tx, mode in zip(transactions, modes, strict=True):
        if mode == 0:
            identity = owner(tx["inputs"][1]["previousOutpoint"])
            if identity is not None:
                admitted.add(identity)
        admission_complete.append(len(admitted) == 32)
    final = len(modes) - 1
    drains = [i for i, mode in enumerate(modes) if mode == 2]
    horizons = {i: dict(creation=i, cashout=next((j for j in drains if j > i), final), final=final) for i in targets}
    points = {end for cutoffs in horizons.values() for end in cutoffs.values()}
    expected = {(profile, end) for profile in PROFILES for end in points}
    indexed = {}
    for entry in predictions:
        key = entry["profile"], entry["through_event"]
        require(key in expected and key not in indexed)
        prediction = entry["prediction"]
        require((prediction["profile"], prediction["through_event"]) == key and prediction["complete"] is True)
        visible = [i for i in targets if i <= key[1]]
        require([row["event"] for row in prediction["rows"]] == visible)
        for row in prediction["rows"]:
            require(row["event_id"] == transactions[row["event"]]["id"] and set(row["guesses"]) == set(VARIANTS))
        indexed[key] = prediction
    require(set(indexed) == expected)
    return transactions, targets, horizons, admission_complete, indexed


def recompute(raw, directory, truth, predictions):
    transactions, targets, horizons, admitted, indexed = prepare(raw, directory, truth, predictions)
    rows_at = {key: {row["event"]: row for row in value["rows"]} for key, value in indexed.items()}
    result, warnings = {}, []
    for profile in PROFILES:
        members = set() if profile == "C" else set(range(8)) if profile == "pooled" else {int(profile[1:])}
        result[profile] = {}
        for horizon in HORIZONS:
            rows = []
            for ordinal, i in enumerate(targets):
                hidden = truth["events"][i]
                known, groups = eligibility(ordinal, hidden["owner"], hidden["recipient"], members, admitted[i])
                guesses = rows_at[profile, horizons[i][horizon]][i]["guesses"]
                rows.append((i, known, groups, {v: accuracy(guesses[v], hidden) for v in VARIANTS},
                             {v: guesses[v]["relationship_rank"] for v in VARIANTS}))
            scored = group_scores(rows)
            result[profile][horizon] = scored
            warnings.extend(dict(profile=profile, horizon=horizon, **warning) for warning in scored["observed_primary_warnings"])
        result[profile]["native_boundary_final"] = bridge_counts(
            indexed[profile, len(transactions)-1]["boundary"], truth["bridges"], [tx["id"] for tx in transactions])
    return result, warnings


def compare(profiles, warnings, score):
    # Only static aggregate group labels can enter the public mismatch list.
    mismatches, comparisons = [], 0
    def check(label, actual, expected):
        nonlocal comparisons
        comparisons += 1
        if canonical(actual) != canonical(expected):
            mismatches.append(label)
    check("profile-roster", sorted(score["profiles"]), list(sorted(PROFILES)))
    for profile in PROFILES:
        for horizon in HORIZONS:
            actual, expected = score["profiles"][profile][horizon], profiles[profile][horizon]
            for field in ("complete", "targets", "known_exclusions", "variants", "primary_prior_advantages"):
                check(f"{profile}.{horizon}.{field}", actual[field], expected[field])
            for field in ("observed_primary_warnings", "diagnostic_exceedances"):
                check(f"{profile}.{horizon}.{field}", sorted(map(canonical, actual[field])), sorted(map(canonical, expected[field])))
        check(f"{profile}.native_boundary_final", score["profiles"][profile]["native_boundary_final"], profiles[profile]["native_boundary_final"])
    check("observed_primary_warnings", sorted(map(canonical, score["observed_primary_warnings"])), sorted(map(canonical, warnings)))
    check("qualification_pass", score["qualification_pass"], False)
    # Activity coverage was already validated against native provenance by the
    # public verifier. Recount metric completeness and its resulting status.
    complete = score["checked"]["required_activity"]["complete"] and all(
        profiles[p][h]["complete"] for p in PROFILES for h in HORIZONS)
    status = ("incomplete" if not complete else "observed-finite-case-cap-warning" if warnings
              else "completed-native-screen-no-observed-primary-warning")
    check("complete", score["complete"], complete)
    check("status", score["status"], status)
    return dict(agreement=not mismatches, comparison_groups=comparisons, mismatch_count=len(mismatches), mismatches=mismatches)


def sealed_truth(reader, exporter):
    frozen, native, points = exporter.verify(reader)
    reader.unchanged()
    # This is the sole private read. Never use a path supplied inside metadata.
    blob = exporter.checked(reader.root / "native/private/truth.json").read_bytes()
    require(digest(blob) == native["truth_sha256"])
    return frozen, native, points, exporter.load(blob)


def run(attempt, destination):
    source = Path(__file__).absolute()
    exporter_path = source.with_name("native_usage_export.py")
    exporter_bytes = exporter_path.read_bytes()
    require(digest(exporter_bytes) == EXPORTER_SHA256)
    exporter = types.ModuleType("audited_public_exporter")
    exporter.__file__ = str(exporter_path)
    exec(compile(exporter_bytes, str(exporter_path), "exec"), exporter.__dict__)
    reader = exporter.Reader(attempt)
    destination = Path(destination).absolute()
    require(not destination.exists() and not destination.is_symlink())
    exporter.checked(destination.parent, directory=True)
    require(reader.root not in destination.parents)
    source_hash = digest(source.read_bytes())
    frozen, native, points, truth = sealed_truth(reader, exporter)
    profiles, warnings = recompute(reader.read("inputs/final/raw.json"), reader.read("inputs/final/directory.json"),
                                  truth, reader.read("predictions.json"))
    compared = compare(profiles, warnings, reader.read("runs/score/result.json"))
    coverage = reader.read("runs/score/result.json")["checked"]
    for name, expected in (("observation_prefixes", len(points)),
                           ("predictions", len(reader.read("predictions.json"))), ("target_profile_horizons", 1920)):
        compared["comparison_groups"] += 1
        if coverage[name] != expected:
            compared["mismatches"].append("coverage." + name)
    compared["mismatch_count"] = len(compared["mismatches"])
    compared["agreement"] = not compared["mismatches"]
    del truth, profiles, warnings
    reader.unchanged()
    require(digest(source.read_bytes()) == source_hash and digest(exporter_path.read_bytes()) == EXPORTER_SHA256)
    output = dict(schema="kpi-native-usage-recount-v1", complete=True, **compared,
                  qualification_pass=False, independent_histories=1,
                  counts=dict(targets=64, profiles=10, horizons=3, target_profile_horizons=1920,
                              variants=4, selected_variant_guesses=7680, metric_counters=2400,
                              selective_counters=1440, paired_advantages=270, field_exclusions=150,
                              bridge_profiles=10, bridge_controls_per_profile=4, observation_prefixes=len(points)),
                  hashes=dict(recount_source=source_hash, public_verifier_source=EXPORTER_SHA256,
                              freeze=reader.hash("freeze.json"), frozen_sources=frozen["sources"],
                              prediction_batch=reader.hash("prediction-batch.json"), predictions=reader.hash("predictions.json"),
                              truth=native["truth_sha256"], score=reader.hash("runs/score/result.json"),
                              completion=reader.hash("completion.json")),
                  scope="Post-run independent aggregate arithmetic only; public seal verifier reused; no new attacks, proof validation, chain acceptance or privacy qualification")
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(output, indent=2, allow_nan=False) + "\n")
    return output


def public_fixture():
    """Small schema fixture: public made-up identities, no native proof claim."""
    directory = dict(entries=[dict(transaction_id=f"fund-{i}", index=0, owner=i) for i in range(32)])
    def point(i):
        return dict(previousOutpoint=dict(transactionId=f"fund-{i}", index=0))
    raw, truth = dict(lineage=[dict(inputs=[point(0)])]), dict(events=[], bridges=[])
    def event(mode, owner, ordinal=None):
        i = len(truth["events"])
        payload = bytearray(5228); payload[:16] = b"KPICR06\0KPICU06\0"; payload[212] = mode
        raw["lineage"].append(dict(id=f"event-{i}", payload=payload.hex(), inputs=[point(0), point(owner)]))
        truth["events"].append(dict(event=i, event_id=f"event-{i}", owner=owner,
            kind="bootstrap" if i == 0 else ("admit", "pay", "exit")[mode],
            recipient=9, amount=100, request_index=ordinal))
        return i
    event(1, 0)
    for owner in range(1, 32):
        event(0, owner)
    targets, drains = [], []
    for ordinal in range(64):
        targets.append(event(1, ordinal if ordinal < 4 else 8, ordinal))
        if ordinal % 16 == 15:
            drains.append(event(2, 9))
    final = len(truth["events"]) - 1
    for i, drain in enumerate(drains):
        truth["bridges"].append(dict(transaction_id=f"bridge-{i}", event_id=f"event-{drain}",
            source_owner=8+i, target_owner=8+i if i < 2 else 16+i))
    predictions = []
    for end in sorted(set(targets + drains)):
        for profile in PROFILES:
            amount = 200 if end == final else 110 if end in drains else 100
            rows = [dict(event=i, event_id=f"event-{i}", guesses={v: dict(sender=truth["events"][i]["owner"],
                recipient=9, amount=amount, relationship_rank=[0, 0, 0, 0]) for v in VARIANTS}) for i in targets if i <= end]
            boundary = [dict(transaction_id=f"bridge-{i}", source_event=drain, same_owner_guess=i < 2,
                source_owner_guess=8+i) for i, drain in enumerate(drains) if drain <= end]
            predictions.append(dict(profile=profile, through_event=end, prediction=dict(profile=profile,
                through_event=end, complete=True, rows=rows, boundary=boundary)))
    return raw, directory, truth, predictions


def controls():
    tests = []
    def check(condition, label):
        require(condition)
        tests.append(label)
    check(ratio(2, 20) == dict(numerator=1, denominator=10) and ratio(0, 0) is None, "reduced-rates-empty-undefined")
    check(Fraction(3, 20)-Fraction(1, 10) == Fraction(1, 20) and not Fraction(1, 20) > Fraction(1, 20), "strict-cap-paired-equality")
    known, groups = eligibility(0, 0, 8, set(), True)
    check(known == dict(sender=True, recipient=False, relationship=False, amount_within_10pct=True, amount_exact=True)
          and groups == {"all_undisclosed", "adversary_endpoint"}, "first-four-policy-fields-only")
    known, _ = eligibility(4, 8, 0, {0}, True)
    check(known == dict(sender=False, recipient=True, relationship=False, amount_within_10pct=True, amount_exact=True), "recipient-only-sender-stays-eligible")
    check(all(eligibility(4, 0, 8, {0}, True)[0].values()), "author-all-fields-known")
    check(eligibility(4, 8, 9, set(), False)[1] == {"all_undisclosed", "startup"}
          and eligibility(4, 8, 9, set(), True)[1] == {"all_undisclosed", "primary"}, "creation-admission-strata")
    hidden = dict(owner=8, recipient=9, amount=100)
    check(all(accuracy(dict(sender=8, recipient=9, amount=a), hidden)["amount_within_10pct"] for a in (90, 110))
          and not accuracy(dict(sender=8, recipient=9, amount=111), hidden)["amount_within_10pct"]
          and not accuracy(dict(sender=8, recipient=9, amount=110), hidden)["amount_exact"], "exact-ten-percent-integer-boundaries")
    ranked = [(2, [1, 0, 0, -1], True), (1, [1, 0, 0, -1], False)]
    check(selected(ranked, 5)["correct"] == 0 and selected(ranked, 5)["eligible"] == 1
          and selected([], 25)["rate"] is None, "rank-ordinal-ties-ceiling-empty")
    ranked.append((3, [2, 0, 0, -1], True))
    check(selected(ranked, 5)["correct"] == 1, "descending-rank-priority")
    bridges = [dict(transaction_id=str(i), event_id=str(i), source_owner=8+i,
                    target_owner=8+i if i < 2 else 16+i) for i in range(4)]
    guesses = [dict(transaction_id=str(i), source_event=i, same_owner_guess=[True, False, True, False][i],
                    source_owner_guess=[8, None, 11, 11][i]) for i in range(4)]
    boundary = bridge_counts(guesses, bridges, list(map(str, range(4))))
    check(all(boundary[k] == 1 for k in ("true_positive", "false_positive", "true_negative", "false_negative"))
          and boundary["source_owner_correct"] == 2, "four-confusion-cells-source-owner-separate")
    guesses[1]["same_owner_guess"] = None
    check(bridge_counts(guesses, bridges, list(map(str, range(4))))["abstentions"] == 1, "bridge-abstention")
    known, groups = eligibility(4, 8, 9, set(), True)
    rows = [(i, known, groups, {v: dict(sender=(i < (2 if v == "prior" else 3)), recipient=False,
             relationship=False, amount_within_10pct=False, amount_exact=False) for v in VARIANTS},
             {v: [0, 0, 0, 0] for v in VARIANTS}) for i in range(20)]
    scored = group_scores(rows)
    check(scored["primary_prior_advantages"]["residual"]["sender"]["difference"] == ratio(1, 20)
          and not any(w["kind"] == "prior_advantage" for w in scored["observed_primary_warnings"])
          and not any(w["variant"] == "prior" and w["metric"] == "sender" for w in scored["observed_primary_warnings"]), "group-absolute-and-paired-equality-no-warning")
    rows[3][3]["residual"]["sender"] = True
    scored = group_scores(rows)
    check(any(w["kind"] == "prior_advantage" for w in scored["observed_primary_warnings"]), "paired-exceedance-warning")
    profiles = {p: {**{h: copy.deepcopy(scored) for h in HORIZONS}, "native_boundary_final": boundary} for p in PROFILES}
    score = dict(profiles=copy.deepcopy(profiles), observed_primary_warnings=[], qualification_pass=False,
                 checked=dict(required_activity=dict(complete=True)), complete=True,
                 status="completed-native-screen-no-observed-primary-warning")
    check(compare(profiles, [], score)["agreement"], "aggregate-comparison-positive")
    score["profiles"]["C"]["final"]["variants"]["prior"]["primary"]["sender"]["correct"] += 1
    check(compare(profiles, [], score)["mismatches"] == ["C.final.variants"], "aggregate-mutation-static-label-only")
    raw, directory, truth, predictions = public_fixture()
    profiles, warnings = recompute(raw, directory, truth, predictions)
    c = profiles["C"]
    check(c["creation"]["known_exclusions"] == dict(sender=4, recipient=0, relationship=0,
          amount_within_10pct=4, amount_exact=4)
          and c["creation"]["variants"]["prior"]["primary"]["amount_exact"] == count([True]*60)
          and c["cashout"]["variants"]["prior"]["primary"]["amount_within_10pct"] == count([True]*44+[False]*16)
          and c["final"]["variants"]["prior"]["primary"]["amount_within_10pct"] == count([False]*60),
          "full-roster-public-drain-horizons-and-field-denominators")
    check(profiles["pooled"]["creation"]["known_exclusions"]["relationship"] == 4
          and len(profiles) == 10 and len(warnings) > 0, "pooled-authors-full-profile-coverage")
    score = dict(profiles=copy.deepcopy(profiles), observed_primary_warnings=warnings,
                 qualification_pass=False, checked=dict(required_activity=dict(complete=True)),
                 complete=True, status="observed-finite-case-cap-warning")
    check(compare(profiles, warnings, score)["agreement"], "full-roster-aggregate-comparison")
    score["status"] = "completed-native-screen-no-observed-primary-warning"
    check(compare(profiles, warnings, score)["mismatches"] == ["status"], "contradictory-status-rejected")
    # Failure in public verification must not even attempt a private open.
    touched = []
    def fail(_):
        raise ValueError("public fixture failure")
    fake = types.SimpleNamespace(verify=fail, checked=lambda _: touched.append(True))
    try:
        sealed_truth(types.SimpleNamespace(root=Path("/unused-public-control")), fake)
        require(False)
    except ValueError:
        pass
    check(not touched, "failed-sealed-batch-zero-truth-opens")
    return dict(complete=True, passed=True, tests=tests, scope="Public handmade arithmetic and ordering controls only")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("controls")
    audit = commands.add_parser("recount")
    audit.add_argument("attempt")
    audit.add_argument("new_result")
    args = parser.parse_args()
    try:
        result = controls() if args.command == "controls" else run(args.attempt, args.new_result)
    except Exception:
        # No exception text or traceback may reveal private facts or paths.
        print(json.dumps(dict(complete=False, error="aggregate-recount-rejected")))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result.get("agreement", result.get("passed", False)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
