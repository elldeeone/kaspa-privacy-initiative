"""H18 scoring. This module alone receives hidden claims after all predictions."""
import math
import random
import statistics

from common_payout_observer import origin_map
from scheduled_payout_observer import Q, ScheduledModel, source_code
from two_input_privacy_observer import decode, need


def eligible(private, event, participant):
    if participant is None:
        return True
    notes = {int(p): n for p, n in private["notes"].items()}
    record = private["records"][event]
    return all(notes[p]["owner"] != participant for p in record["inputs"]) and all(
        n["value"] == 0 or n["owner"] != participant for n in record["outputs"])


def score(public, private, prediction, participant, view):
    births, _ = decode(public)
    graph = {i: tuple(r["inputs"]) for i, r in enumerate(private["records"]) if r["inputs"]}
    origins = origin_map(public, graph, Q)
    result = {}
    for profile in ("untimed", "timed"):
        rows = {r["event"]: r for r in prediction[profile]["rows"]}
        expected = {i for i, e in enumerate(public["events"])
                    if e["mode"] == 2 or e["mode"] == 1 and (e["payout"] == Q or e["payout"] == 0)}
        need(len(rows) == len(prediction[profile]["rows"]) and set(rows) == expected,
             "prediction target set missing/duplicated")
        for i, row in rows.items():
            actual = origins[graph[i][0]] if row["kind"] == "cashout" else source_code(
                births[p] for p in graph[i])
            need(actual in row["candidates"], "true original source excluded")
            need(all(v in row["candidates"] for v in row["guesses"].values()),
                 "guess outside candidate set")
        ScheduledModel(public, view, profile == "timed").check_truth(private)
        claims = []
        for c in private["claims"]:
            if c["owner"] == participant:
                continue
            legs = [rows[i] for i in c["legs"]]
            need(all(eligible(private, i, participant) for i in c["legs"]), "claim eligibility")
            source = origins[c["original_position"]]
            need(all(origins[graph[i][0]] == source for i in c["legs"]), "claim source changed")
            claims.append(dict(claim=c["claim"], shaped=c["shaped"],
                               unique=any(len(r["candidates"]) == 1 for r in legs),
                               minimum_candidates=min(len(r["candidates"]) for r in legs),
                               leg_candidate_counts=[len(r["candidates"]) for r in legs],
                               correct={attack: any(r["guesses"][attack] == source for r in legs)
                                        for attack in legs[0]["guesses"]},
                               common_leg_counts=[len(rows[i]["candidates"]) for i in c["legs"]
                                                  if public["events"][i]["mode"] == 1]))
        payments = []
        for i in private["payments"]:
            if not eligible(private, i, participant):
                continue
            r = rows[i]
            actual = source_code(births[p] for p in graph[i])
            payments.append(dict(event=i, unique=len(r["candidates"]) == 1,
                                 candidates=len(r["candidates"]),
                                 correct={a: g == actual for a, g in r["guesses"].items()}))
        result[profile] = dict(claims=claims, payments=payments,
                               all_sources_survive=True, exact_original_graph_check=True)
    return result


def quantile(values, fraction):
    values = sorted(values)
    return values[max(0, math.ceil(fraction * len(values)) - 1)]


def family_summary(cases, config):
    """Resample entire paired ledgers, never claims or overlapping views."""
    attacks = config["attacks"]
    arrays = {arm: {a: [] for a in attacks} for arm in ("full", "scheduled")}
    totals, singletons, candidates = {}, {}, {}
    for arm in arrays:
        all_rows = [r for case in cases for r in case[arm]]
        totals[arm] = len(all_rows)
        singletons[arm] = sum(r["unique"] for r in all_rows)
        candidates[arm] = [r["minimum_candidates"] for r in all_rows]
        for case in cases:
            for a in attacks:
                arrays[arm][a].append(statistics.mean(r["correct"][a] for r in case[arm]))
    rates = {arm: {a: statistics.mean(values) for a, values in scores.items()}
             for arm, scores in arrays.items()}
    best = {arm: max(scores.values()) for arm, scores in rates.items()}
    rng = random.Random(config["statistics_seed"])
    improvements = []
    for _ in range(config["bootstrap_draws"]):
        sample = [rng.randrange(len(cases)) for _ in cases]
        sampled = {arm: max(statistics.mean(values[i] for i in sample) for values in scores.values())
                   for arm, scores in arrays.items()}
        improvements.append(sampled["full"] - sampled["scheduled"])
    ci = [quantile(improvements, 0.025), quantile(improvements, 0.975)]
    relative = 1 - best["scheduled"] / best["full"] if best["full"] else None
    return dict(ledgers=len(cases), targets=totals, attack_accuracy=rates,
                family_accuracy=best, relative_reduction=relative,
                paired_improvement_95ci=ci, unique_claims=singletons,
                candidate_counts={arm: dict(min=min(v), median=statistics.median(v), max=max(v))
                                  for arm, v in candidates.items()},
                passes=relative is not None and relative >= config["min_relative_improvement"]
                and ci[0] > 0)


def summarize(config, scores, costs):
    reports, regressions, monotonic = {}, [], 0
    for regime in config["regimes"]:
        reports[regime] = {}
        names = [f"{regime}-{i:02}" for i in range(config["cases_per_regime"])]
        for profile in ("chain", "participants"):
            pairs = []
            for name in names:
                observers = ["chain"] if profile == "chain" else [f"participant-{i}" for i in range(4)]
                pair = {}
                for arm in ("full", "scheduled"):
                    pair[arm] = [r for obs in observers
                                 for r in scores[name, arm, obs]["timed"]["claims"]]
                pairs.append(pair)
            reports[regime][profile] = family_summary(pairs, config)
        added = [r["added_minutes"] for name in names for r in costs[name]["delays"]]
        reports[regime]["cost"] = dict(
            p95_added_minutes=quantile(added, .95), maximum_added_minutes=max(added),
            max_extra_fee_fraction=max(costs[name]["extra_fee_fraction"] for name in names),
            fee_passes=all(costs[name]["extra_fee_fraction"] <= config["max_extra_fee_fraction"]
                           for name in names),
            delay_passes=quantile(added, .95) <= config["max_p95_added_minutes"])
        for name in names:
            for obs in ("chain", *[f"participant-{i}" for i in range(4)]):
                old = {r["event"]: r for r in scores[name, "full", obs]["timed"]["payments"]}
                new = {r["event"]: r for r in scores[name, "scheduled", obs]["timed"]["payments"]}
                need(old.keys() == new.keys(), "paired payment target mismatch")
                for i in old:
                    if new[i]["unique"] and not old[i]["unique"]:
                        regressions.append(dict(case=name, observer=obs, event=i))
    for report in scores.values():
        for kind, key in (("claims", "claim"), ("payments", "event")):
            old = {r[key]: r for r in report["untimed"][kind]}
            for r in report["timed"][kind]:
                count = "minimum_candidates" if kind == "claims" else "candidates"
                need(r[count] <= old[r[key]][count], "timing expanded candidates")
                monotonic += 1
    privacy = all(reports[r][p]["passes"] for r in config["regimes"]
                  for p in ("chain", "participants")) and not regressions
    fees = all(reports[r]["cost"]["fee_passes"] for r in config["regimes"])
    delay = all(reports[r]["cost"]["delay_passes"] for r in config["regimes"])
    return dict(regimes=reports, new_unique_payment_links=regressions,
                privacy_screen_passes=privacy, fee_screen_passes=fees, delay_screen_passes=delay,
                offline_gate_passes=privacy and fees and delay,
                all_truth_survives=True, exact_truth_checks=len(scores) * 2,
                narrowing_metric_checks=monotonic, observations=len(scores),
                actual_tkas_spent=0, real_world_anonymity_established=False)
