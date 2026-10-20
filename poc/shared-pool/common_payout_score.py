"""Controller-side H17 scoring. Private claim matching never reaches observers."""
from common_payout_generate import accounting
from common_payout_observer import CommonModel, origin_map
from participant_privacy_observer import prefix_view
from participant_privacy_view import eligible_targets, ledger
from two_input_privacy_observer import decode, need


def claim_metric(legs):
    """Never intersect legs using a hidden claim association."""
    counts = [len(leg["sources"]) for leg in legs]
    return dict(linked=any(n == 1 for n in counts), min_leg_candidates=min(counts),
                leg_candidate_counts=counts)


def score(plan, public, truth, claims, prediction, baseline, participant):
    births, _ = decode(public)
    graph = {int(i): tuple(t["inputs"]) for i, t in truth.items()}
    provenance = origin_map(public, graph)
    by_event = {}
    for row in baseline["rows"]:
        by_event[row["event"]] = next(h for h in row["joint"] if h["through"] == 18)
    results = {(r["event"], r["through"]): r for r in prediction["rows"]}
    need(len(results) == len(prediction["rows"]), "duplicate observer row")
    expected = {(i, end) for end in (15, 22)
                for i, e in enumerate(public["events"][:end+1])
                if e["mode"] == 2 or e["mode"] == 1
                and (e["payout"] == 200_000_000 or i > 0 and e["payout"] == 0)}
    need(results.keys() == expected, "missing observer target or horizon")
    # Check all targets, including owned ones omitted from published scoring.
    for row in prediction["rows"]:
        inputs = graph[row["event"]]
        if row["kind"] == "cashout":
            need(len(inputs) == 1 and provenance[inputs[0]] in row["sources"],
                 "cashout truth excluded")
        else:
            need(list(inputs) in row["input_sets"], "payment input truth excluded")
            need(sorted({births[p] for p in inputs}) in row["source_sets"],
                 "payment source truth excluded")
    eligible = set(graph) if participant is None else eligible_targets(plan, participant)
    cashouts, payments = [], []
    for claim in claims:
        if participant == claim["owner"]:
            continue
        old = by_event[claim["baseline_event"]]["source_sets"]
        need(all(len(s) == 1 for s in old), "baseline exit unexpectedly multi-source")
        base = [s[0] for s in old]
        legs = [results[i, 22] for i in claim["legs"]]
        need(all(i in eligible for i in claim["legs"]), "claim eligibility differs")
        cashouts.append(dict(claim=claim["index"], baseline_sources=base,
                             baseline_linked=len(base) == 1,
                             **claim_metric(legs), legs=legs,
                             before_drain=[results[i, 15] for i in claim["legs"] if i <= 15]))
    for i, record in truth.items():
        i = int(i)
        if record["category"] != "payment" or i not in eligible:
            continue
        new = results[i, 22]
        old = by_event[i]
        payments.append(dict(event=i, baseline_candidates=len(old["source_sets"]),
                             candidates=len(new["source_sets"]),
                             baseline_linked=len(old["source_sets"]) == 1,
                             linked=len(new["source_sets"]) == 1,
                             newly_linked=len(new["source_sets"]) == 1 and len(old["source_sets"]) > 1,
                             horizons=[results[i, h] for h in (15, 22)]))
    return dict(claims=cashouts, payments=payments, all_truth_survives=True,
                eligible_events=sorted(eligible))


def validate_truth(plan, public, views):
    """Post-observation check: exact hidden amounts and graph survive both horizons."""
    notes, records = ledger(plan)
    checked = 0
    for end in (15, 22):
        prefix = dict(public, events=public["events"][:end+1])
        graph = {i: tuple(r["inputs"]) for i, r in enumerate(records[:end+1])
                 if r["inputs"]}
        for view in [None, *views]:
            known = prefix_view(public, view, end) if view is not None else None
            model = CommonModel(prefix, known)
            for p, value in enumerate(model.integer.values):
                model.integer.model.add(value == notes[p]["value"])
            need(model.integer.check(fixed=graph), "actual integer ledger excluded")
            checked += 1
    return checked


def costs(original_plan, original, plan, public, claims):
    old, new = accounting(original_plan, original), accounting(plan, public)
    need(new["funding_sompi"] == old["funding_sompi"], "funding changed")
    for a, b in zip(old["wallet_payouts_sompi"], new["wallet_payouts_sompi"], strict=True):
        need(a-b == 40_000_000, "wallet did not bear exactly one extra fee")
    delays = []
    for claim in claims:
        before = original["events"][claim["baseline_event"]]["minute"]
        first = public["events"][claim["legs"][0]]["minute"]
        complete = public["events"][claim["legs"][-1]]["minute"]
        delays.append(dict(claim=claim["index"], first_delta_minutes=first-before,
                           completion_delta_minutes=complete-before))
    return dict(baseline=old, common=new, delays=delays,
                added_fee_sompi=new["fees_sompi"]-old["fees_sompi"],
                added_fee_fraction=(new["fees_sompi"]-old["fees_sompi"])/old["fees_sompi"],
                p95_added_completion_minutes=max(r["completion_delta_minutes"] for r in delays))
