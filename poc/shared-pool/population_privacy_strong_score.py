"""Scorer-only, aggregate-only failure screen for the frozen persistent workload.

The runner must seal ALL observer predictions before supplying any private truth.
This module cannot itself establish that ordering or independent seed generation.
It verifies the fixed policy/accounting and both original full relation encodings,
then discards target-level truth/correctness from its output. Guesses are never
called logically forced facts. No result qualifies useful privacy.

Statistical units are independent histories, not payments. A fixed family of 99
two-sided Hoeffding intervals covers three scopes, four variants, three absolute
metrics, three selective coverages, and three attacks versus the sole frozen
prior. Bonferroni includes BOTH tails. This intentionally conservative screen
may have insufficient power; absence of a certified breach is not a pass.
"""
import copy
import math

import population_privacy_model as full

VARIANTS = ("prior", "cashout_residual", "split_balance", "tag_split")
ATTACKS = VARIANTS[1:]
STRATA = ("primary", "all_undisclosed", "startup", "adversary_endpoint")
METRICS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
CAPS = {"sender": .10, "recipient": .10, "amount_within_10pct": .20}
COVERAGES = (5, 10, 25)
SCOPES = ("pooled", "overlap", "sparse")
ALPHA = .05
FAMILY_SIZE = len(SCOPES) * (len(VARIANTS) * (len(CAPS) + len(COVERAGES))
                            + len(ATTACKS) * len(CAPS))
SCORE_KEYS = {"schema", "complete", "public_sha256", "view_sha256", "prediction_sha256",
              "policy_sha256", "regime", "arm", "horizon", "targets", "truth_consistency",
              "policy_validation", "tested_primary_targets", "variants", "qualification_pass"}
POLICY_CHECK_KEYS = {"passed", "complete", "payments", "startup_payments", "active_payments",
                     "full_drainage", "scope"}


def within_10pct(guess, amount):
    return 10 * abs(guess - amount) <= amount


def _targets(public):
    return [i for i, event in enumerate(public["algebra"]["events"])
            if i and event["mode"] == 1]


def _check_prediction(public, view, prediction, policy_digest):
    full.fields(prediction, {"schema", "complete", "public_sha256", "view_sha256",
                            "policy_sha256", "horizon", "variants", "rows"}, "prediction")
    full.need(prediction["schema"] == "kpi-population-strong-predictions-v1"
              and prediction["complete"] is True and prediction["horizon"] == "final",
              "prediction schema/completion/horizon")
    full.need(prediction["public_sha256"] == full.digest(public)
              and prediction["view_sha256"] == full.digest(view)
              and prediction["policy_sha256"] == policy_digest, "prediction identity")
    full.need(prediction["variants"] == list(VARIANTS), "frozen variants")
    expected = _targets(public)
    full.need(isinstance(prediction["rows"], list) and len(prediction["rows"]) == len(expected),
              "complete target coverage")
    for event, row in zip(expected, prediction["rows"], strict=True):
        full.fields(row, {"event", "guesses"}, "prediction row")
        full.need(type(row["event"]) is int and row["event"] == event, "target order/identity")
        full.fields(row["guesses"], set(VARIANTS), "guesses")
        for name, guess in row["guesses"].items():
            full.fields(guess, {"sender", "recipient", "amount", "relationship_rank"}, "guess")
            for field in ("sender", "recipient"):
                full.need(type(guess[field]) is int and guess[field] in public["roles"], "role guess")
            full.integer(guess["amount"])
            rank = guess["relationship_rank"]
            full.need(isinstance(rank, list) and len(rank) == 4
                      and all(type(n) is int and -(2**63) < n < 2**63 for n in rank), "rank tuple")
            full.need(0 <= rank[0] <= 2 and rank[1] >= 0 and rank[2] >= 0 and rank[3] <= 0,
                      "rank domains")
            full.need(name != "prior" or rank == [0, 0, 0, 0], "prior rank")


def _counter():
    return dict(correct=0, eligible=0)


def _selected(rows, percent):
    """All eligible targets ranked by sealed public evidence; ordinal breaks ties."""
    ordered = sorted(rows, key=lambda row: (tuple(-x for x in row["rank"]), row["event"]))
    count = (len(ordered) * percent + 99) // 100
    chosen = ordered[:count]
    return dict(correct=sum(r["correct"] for r in chosen), eligible=count,
                population=len(ordered), nominal_percent=percent,
                realized_coverage=count / len(ordered) if ordered else None)


def _score_rows(public, view, prediction, truth):
    variants = {name: {stratum: {metric: _counter() for metric in METRICS}
                        for stratum in STRATA} for name in VARIANTS}
    ranks = {name: {stratum: [] for stratum in STRATA} for name in VARIANTS}
    authored = {r["event"] for r in view["authored"]}
    receipts = {r["position"] for r in view["receipts"]}
    adversaries = set(public["adversaries"])
    excluded = adversaries | set(view["members"])
    admitted = {public["funding_owners"][public["algebra"]["initial"]["funding_group"]]}
    admission_state = []
    for event in public["algebra"]["events"]:
        if event["mode"] == 0:
            admitted.add(public["funding_owners"][event["funding_group"]])
        admission_state.append(len(admitted) == len(public["roles"]))
    primary_count = 0
    for row in prediction["rows"]:
        i = row["event"]
        hidden, event = truth["events"][i], public["algebra"]["events"][i]
        full.need(hidden["kind"] == "payment", "ordinary payment truth")
        sender, recipient, amount = (hidden[k] for k in ("sender", "recipient", "amount"))
        endpoints = {sender, recipient}
        startup = not admission_state[i]
        primary = not startup and not endpoints.intersection(excluded)
        primary_count += int(primary)
        known_sender = i in authored
        known_recipient = known_sender or event["new"][0] in receipts
        known = dict(sender=known_sender, recipient=known_recipient,
                     relationship=known_sender and known_recipient,
                     amount_within_10pct=known_recipient, amount_exact=known_recipient)
        strata = dict(primary=primary, all_undisclosed=True, startup=startup,
                      adversary_endpoint=bool(endpoints & adversaries))
        for name, guess in row["guesses"].items():
            correct = dict(sender=guess["sender"] == sender, recipient=guess["recipient"] == recipient,
                           relationship=guess["sender"] == sender and guess["recipient"] == recipient,
                           amount_within_10pct=within_10pct(guess["amount"], amount),
                           amount_exact=guess["amount"] == amount)
            for stratum, included in strata.items():
                if not included:
                    continue
                for metric in METRICS:
                    if not known[metric]:
                        variants[name][stratum][metric]["eligible"] += 1
                        variants[name][stratum][metric]["correct"] += int(correct[metric])
                if not known["relationship"]:
                    ranks[name][stratum].append(dict(event=i, rank=guess["relationship_rank"],
                                                     correct=correct["relationship"]))
    for name in VARIANTS:
        for stratum in STRATA:
            variants[name][stratum]["selective_relationship"] = {
                str(percent): _selected(ranks[name][stratum], percent) for percent in COVERAGES}
    return dict(tested_primary_targets=primary_count, variants=variants)


def score(public, view, prediction, truth, policy):
    """Run only in scorer isolation after the entire prediction batch is sealed."""
    import population_privacy_strong_workload as workload
    full.validate(public, view)
    full.need(view["members"] == public["adversaries"], "pooled eight-member view required")
    full.need(policy == workload.public_policy(), "frozen workload policy")
    _check_prediction(public, view, prediction, full.digest(policy))
    full.need(len(_targets(public)) == 128, "128 ordinary payments required")
    policy_validation = workload.validate_generated(public, truth)
    _check_policy_validation(policy_validation)
    consistency = full.validate_truth(public, view, truth)
    full.need(consistency == dict(complete=True, cp_sat="SAT", z3="SAT"), "full relation excludes truth")
    return dict(schema="kpi-population-strong-score-v1", complete=True,
                public_sha256=full.digest(public), view_sha256=full.digest(view),
                prediction_sha256=full.digest(prediction), policy_sha256=prediction["policy_sha256"],
                regime=truth["regime"], arm="persistent", horizon="final", targets=128,
                truth_consistency=consistency, policy_validation=policy_validation,
                qualification_pass=False, **_score_rows(public, view, prediction, truth))


def _rate(counter):
    return counter["correct"] / counter["eligible"] if counter["eligible"] else None


def _descriptive(counters):
    correct = sum(c["correct"] for c in counters)
    eligible = sum(c["eligible"] for c in counters)
    rates = [_rate(c) for c in counters if c["eligible"]]
    return dict(correct=correct, eligible=eligible, pooled_rate=correct / eligible if eligible else None,
                defined_histories=len(rates), total_histories=len(counters),
                mean_history_rate=sum(rates) / len(rates) if rates else None)


def _interval(values, lower=0., upper=1.):
    if not values or any(value is None for value in values):
        return dict(complete=False, histories=len(values), defined_histories=sum(v is not None for v in values),
                    mean=None, lower=None, upper=None)
    full.need(all(lower <= value <= upper for value in values), "statistic outside bounded domain")
    mean = math.fsum(values) / len(values)
    radius = (upper - lower) * math.sqrt(math.log(2 * FAMILY_SIZE / ALPHA) / (2 * len(values)))
    return dict(complete=True, histories=len(values), defined_histories=len(values), mean=mean,
                lower=max(lower, math.nextafter(mean - radius, -math.inf)),
                upper=min(upper, math.nextafter(mean + radius, math.inf)))


def _check_policy_validation(result):
    full.fields(result, POLICY_CHECK_KEYS, "policy validation")
    full.need(result["complete"] is True and result["passed"] is True
              and result["full_drainage"] is True
              and result["payments"] == 128 and result["startup_payments"] == 16
              and result["active_payments"] == 32
              and result["scope"] == "exact policy/accounting check; no seed-randomness or cryptographic claim",
              "workload policy/accounting rejected")


def _validate_score(score):
    full.fields(score, SCORE_KEYS, "history score")
    full.need(score["schema"] == "kpi-population-strong-score-v1" and score["complete"] is True
              and score["qualification_pass"] is False and score["arm"] == "persistent"
              and score["horizon"] == "final" and score["targets"] == 128, "history score scope")
    for field in ("public_sha256", "view_sha256", "prediction_sha256", "policy_sha256"):
        value = score[field]
        full.need(isinstance(value, str) and len(value) == 64
                  and all(c in "0123456789abcdef" for c in value), "score digest")
    full.need(score["truth_consistency"] == dict(complete=True, cp_sat="SAT", z3="SAT"), "truth validation")
    _check_policy_validation(score["policy_validation"])
    full.integer(score["tested_primary_targets"], 0, 128)
    full.fields(score["variants"], set(VARIANTS), "score variants")
    for name in VARIANTS:
        full.fields(score["variants"][name], set(STRATA), "score strata")
        for stratum in STRATA:
            result = score["variants"][name][stratum]
            full.fields(result, set(METRICS) | {"selective_relationship"}, "stratum metrics")
            for metric in METRICS:
                c = result[metric]
                full.fields(c, {"correct", "eligible"}, "counter")
                full.integer(c["eligible"], 0, 128)
                full.integer(c["correct"], 0, c["eligible"])
                full.need(c["eligible"] == score["variants"]["prior"][stratum][metric]["eligible"],
                          "variant eligibility mismatch")
                if stratum == "primary":
                    full.need(c["eligible"] == score["tested_primary_targets"], "primary eligibility mismatch")
            full.fields(result["selective_relationship"], {str(x) for x in COVERAGES}, "selective coverages")
            full.need(result["amount_exact"]["eligible"] == result["amount_within_10pct"]["eligible"]
                      and result["amount_exact"]["correct"] <= result["amount_within_10pct"]["correct"],
                      "exact amount versus tolerance counters")
            if stratum == "primary":
                full.need(result["relationship"]["correct"] <= min(result[m]["correct"]
                                                                   for m in ("sender", "recipient")),
                          "joint relationship counters")
            for percent in COVERAGES:
                c = result["selective_relationship"][str(percent)]
                full.fields(c, {"correct", "eligible", "population", "nominal_percent", "realized_coverage"},
                            "selective counter")
                full.integer(c["population"], 0, 128)
                full.integer(c["eligible"], 0, c["population"])
                full.integer(c["correct"], 0, c["eligible"])
                full.need(c["population"] == result["relationship"]["eligible"]
                          and c["nominal_percent"] == percent
                          and c["eligible"] == (c["population"] * percent + 99) // 100
                          and c["realized_coverage"] == (c["eligible"] / c["population"]
                                                        if c["population"] else None), "selective denominator")
                total_correct = result["relationship"]["correct"]
                full.need(c["correct"] <= total_correct
                          and total_correct - c["correct"] <= c["population"] - c["eligible"],
                          "selective subset counters")


def aggregate(cases):
    """Fixed sixteen history units; no removal of inconvenient or empty histories."""
    full.need(isinstance(cases, list) and len(cases) == 16, "exact sixteen histories required")
    public_digests, policies = set(), set()
    for i, case in enumerate(cases):
        full.fields(case, {"case", "regime", "score"}, "case")
        regime = "overlap" if i < 8 else "sparse"
        full.need(case["case"] == f"set-{i + 1:02d}-persistent" and case["regime"] == regime,
                  "fixed case order/regimes")
        _validate_score(case["score"])
        full.need(case["score"]["regime"] == regime, "score regime")
        public_digests.add(case["score"]["public_sha256"])
        policies.add(case["score"]["policy_sha256"])
    full.need(len(public_digests) == 16 and len(policies) == 1, "duplicate history or differing policy")
    scopes, breaches, signals, complete, intervals = {}, [], [], True, 0
    for scope in SCOPES:
        selected = [c["score"] for c in cases if scope == "pooled" or c["regime"] == scope]
        variants, advantages = {}, {}
        for name in VARIANTS:
            descriptive = {stratum: {metric: _descriptive([s["variants"][name][stratum][metric]
                                                          for s in selected]) for metric in METRICS}
                           for stratum in STRATA}
            absolute, selective = {}, {}
            for metric, cap in CAPS.items():
                bound = _interval([_rate(s["variants"][name]["primary"][metric]) for s in selected])
                intervals += 1
                complete &= bound["complete"]
                breach = bound["complete"] and bound["lower"] > cap
                point_exceeds = bound["complete"] and bound["mean"] > cap
                absolute[metric] = dict(cap=cap, certified_breach=breach,
                                        point_estimate_exceeds_cap=point_exceeds, **bound)
                if point_exceeds:
                    signals.append(dict(scope=scope, variant=name, metric=metric, cap=cap,
                                        mean=bound["mean"], kind="absolute"))
                if breach:
                    breaches.append(dict(scope=scope, variant=name, metric=metric, cap=cap,
                                         lower=bound["lower"], kind="absolute"))
            for percent in COVERAGES:
                counters = [s["variants"][name]["primary"]["selective_relationship"][str(percent)]
                            for s in selected]
                bound = _interval([_rate(c) for c in counters])
                intervals += 1
                complete &= bound["complete"]
                breach = bound["complete"] and bound["lower"] > .50
                point_exceeds = bound["complete"] and bound["mean"] > .50
                selective[str(percent)] = dict(cap=.50, certified_breach=breach,
                    point_estimate_exceeds_cap=point_exceeds, **bound,
                    descriptive=_descriptive(counters),
                    realized_coverages=[c["realized_coverage"] for c in counters])
                if point_exceeds:
                    signals.append(dict(scope=scope, variant=name, metric="selective_relationship",
                                        nominal_percent=percent, cap=.50, mean=bound["mean"], kind="selective"))
                if breach:
                    breaches.append(dict(scope=scope, variant=name, metric="selective_relationship",
                                         nominal_percent=percent, cap=.50, lower=bound["lower"], kind="selective"))
            variants[name] = dict(descriptive=descriptive, absolute=absolute, selective_relationship=selective)
        for name in ATTACKS:
            advantages[name] = {}
            for metric in CAPS:
                pairs = [(_rate(s["variants"][name]["primary"][metric]),
                          _rate(s["variants"]["prior"]["primary"][metric])) for s in selected]
                differences = [None if a is None or b is None else a - b for a, b in pairs]
                bound = _interval(differences, -1., 1.)
                intervals += 1
                complete &= bound["complete"]
                breach = bound["complete"] and bound["lower"] > .05
                point_exceeds = bound["complete"] and bound["mean"] > .05
                advantages[name][metric] = dict(cap=.05, baseline="prior", certified_breach=breach,
                                                point_estimate_exceeds_cap=point_exceeds, **bound)
                if point_exceeds:
                    signals.append(dict(scope=scope, variant=name, metric=metric, cap=.05,
                                        mean=bound["mean"], kind="paired_prior_advantage"))
                if breach:
                    breaches.append(dict(scope=scope, variant=name, metric=metric, cap=.05,
                                         lower=bound["lower"], kind="paired_prior_advantage"))
        scopes[scope] = dict(histories=len(selected), variants=variants, paired_prior_advantages=advantages)
    full.need(intervals == FAMILY_SIZE, "multiplicity family changed")
    status = ("incomplete" if not complete else "evidence-valid cap-breach" if breaches
              else "bounded-screen-complete-no-certified-breach")
    return dict(schema="kpi-population-strong-summary-v1", complete=bool(complete), status=status,
                qualification_pass=False, scopes=scopes, certified_breaches=breaches,
                descriptive_point_estimate_exceedances=signals,
                inference=dict(method="Bonferroni simultaneous two-sided Hoeffding",
                    family_intervals=FAMILY_SIZE, tails=2 * FAMILY_SIZE, family_alpha=ALPHA,
                    unit="independent history, equally weighted", unit_range=[0, 1],
                    paired_difference_range=[-1, 1],
                    sampling_assumption="Runner independently sampled sixteen frozen-policy histories",
                    caps_scope="Primary only; other strata and exact amount are descriptive",
                    prior_limit="One frozen policy-aware prior; not proof it is strongest possible"),
                limits=["Finite synthetic workload, pooled final observation only; omitted native/provider surfaces remain open.",
                        "Guesses and uncalibrated rankings are not forced disclosures or posterior probabilities.",
                        "Wide intervals and no certified breach cannot establish useful privacy."])


def controls():
    """Small explicit scoring/statistics controls only; no hidden samples or files."""
    tests = []
    assert within_10pct(90, 100) and within_10pct(110, 100)
    assert not within_10pct(89, 100) and not within_10pct(111, 100)
    assert within_10pct(9, 10) and not within_10pct(8, 9)
    tests.append("integer-inclusive-ten-percent-boundaries")
    ranks = [dict(event=3, rank=[1, 0, 0, -1], correct=True),
             dict(event=1, rank=[1, 0, 0, -1], correct=False),
             dict(event=2, rank=[0, 9, 9, 0], correct=True)]
    assert _selected(ranks, 5) == dict(correct=0, eligible=1, population=3,
                                      nominal_percent=5, realized_coverage=1 / 3)
    assert _selected(ranks, 100)["correct"] == 2
    assert _selected([], 25)["realized_coverage"] is None
    tests.append("lexicographic-rank-ordinal-tie-ceiling-small-n-empty")
    assert FAMILY_SIZE == 99
    unit = _interval([1.] * 16)
    paired = _interval([1.] * 16, -1., 1.)
    assert unit["lower"] > .10 and unit["lower"] < .50
    assert paired["lower"] < .05
    assert _interval([0.] * 16)["lower"] == 0.
    assert not _interval([None] + [1.] * 15)["complete"]
    assert not _interval([])["complete"]
    assert _interval([1.] * 8)["lower"] < unit["lower"]
    tests.append("independent-history-multiplicity-two-tails-paired-range-empty")
    uneven = _descriptive([dict(correct=1, eligible=1), dict(correct=0, eligible=99)])
    assert uneven["pooled_rate"] == .01 and uneven["mean_history_rate"] == .5
    tests.append("pooled-payment-rate-not-substituted-for-equal-history-mean")
    # Three ordinary payments: known sender, received-only, wholly uninvolved.
    events = [dict(mode=1, new=[1, 2])] + [dict(mode=0, funding_group=f"f{i}") for i in range(1, 32)]
    events += [dict(mode=1, new=[65 + 2 * i, 66 + 2 * i]) for i in range(3)]
    public = dict(roles=list(range(32)), adversaries=list(range(8)),
                  funding_owners={f"f{i}": i for i in range(32)},
                  algebra=dict(initial=dict(funding_group="f0"), events=events))
    view = dict(members=list(range(8)), authored=[dict(event=32)], receipts=[dict(position=67)])
    hidden = [{} for _ in events]
    for i, (sender, recipient) in enumerate(((0, 8), (8, 0), (8, 9)), 32):
        hidden[i] = dict(kind="payment", sender=sender, recipient=recipient, amount=100)
    prediction = dict(rows=[dict(event=i, guesses={name: dict(sender=hidden[i]["sender"],
        recipient=hidden[i]["recipient"], amount=100, relationship_rank=[0, 0, 0, 0])
        for name in VARIANTS}) for i in range(32, 35)])
    scored = _score_rows(public, view, prediction, dict(events=hidden))
    result = scored["variants"]["prior"]
    assert scored["tested_primary_targets"] == 1
    assert result["all_undisclosed"]["sender"] == dict(correct=2, eligible=2)
    assert result["all_undisclosed"]["recipient"] == dict(correct=1, eligible=1)
    assert result["all_undisclosed"]["relationship"] == dict(correct=2, eligible=2)
    assert result["startup"]["sender"]["eligible"] == 0
    assert result["adversary_endpoint"]["sender"] == dict(correct=1, eligible=1)
    tests.append("known-authorship-versus-receipt-joint-exclusion-primary-strata")
    framed = dict(schema="kpi-population-strong-predictions-v1", complete=True,
                  public_sha256=full.digest(public), view_sha256=full.digest(view),
                  policy_sha256="4" * 64, horizon="final", variants=list(VARIANTS), **prediction)
    _check_prediction(public, view, framed, "4" * 64)
    for mutate in (
        lambda p: p["rows"].pop(),
        lambda p: p["rows"].reverse(),
        lambda p: p.__setitem__("public_sha256", "5" * 64),
        lambda p: p.__setitem__("policy_sha256", "5" * 64),
        lambda p: p.__setitem__("private_extra", {}),
        lambda p: p["rows"][0]["guesses"]["prior"].__setitem__("sender", True),
        lambda p: p["rows"][0]["guesses"]["prior"].__setitem__("relationship_rank", [0, 0, 0, True]),
        lambda p: p["rows"][0]["guesses"].__setitem__("after_score_oracle", {}),
    ):
        poisoned = copy.deepcopy(framed)
        mutate(poisoned)
        try:
            _check_prediction(public, view, poisoned, "4" * 64)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed or incomplete prediction accepted")
    tests.append("strict-schema-complete-targets-fixed-variants-digests-canonical-integers")
    assert "rows" not in scored and "events" not in scored
    base = dict(schema="kpi-population-strong-score-v1", complete=True,
        public_sha256="1" * 64, view_sha256="2" * 64, prediction_sha256="3" * 64,
        policy_sha256="4" * 64, regime="overlap", arm="persistent", horizon="final", targets=128,
        truth_consistency=dict(complete=True, cp_sat="SAT", z3="SAT"),
        policy_validation=dict(complete=True, passed=True, payments=128, startup_payments=16,
            active_payments=32, full_drainage=True,
            scope="exact policy/accounting check; no seed-randomness or cryptographic claim"),
        qualification_pass=False, **scored)
    cases = [dict(case=f"set-{i + 1:02d}-persistent", regime="overlap" if i < 8 else "sparse",
                  score=copy.deepcopy(base)) for i in range(16)]
    for i, case in enumerate(cases):
        case["score"]["regime"] = case["regime"]
        case["score"]["public_sha256"] = f"{i + 1:064x}"
    summary = aggregate(cases)
    assert summary["status"] == "evidence-valid cap-breach" and not summary["qualification_pass"]
    assert len(summary["certified_breaches"]) > 0
    assert "rows" not in base and "events" not in base
    tests.append("all-history-caps-aggregate-only-no-qualification")
    no_correct = copy.deepcopy(cases)
    for case in no_correct:
        for name in VARIANTS:
            for stratum in STRATA:
                result = case["score"]["variants"][name][stratum]
                for metric in METRICS:
                    result[metric]["correct"] = 0
                for counter in result["selective_relationship"].values():
                    counter["correct"] = 0
    zero = aggregate(no_correct)
    assert zero["status"] == "bounded-screen-complete-no-certified-breach"
    assert not zero["qualification_pass"] and not zero["certified_breaches"]
    assert zero["scopes"]["pooled"]["variants"]["prior"]["absolute"]["sender"]["upper"] > .10
    tests.append("zero-success-with-wide-bounds-is-not-a-privacy-pass")
    empty = copy.deepcopy(cases)
    empty[0]["score"]["tested_primary_targets"] = 0
    for name in VARIANTS:
        r = empty[0]["score"]["variants"][name]["primary"]
        for metric in METRICS:
            r[metric] = _counter()
        r["selective_relationship"] = {str(q): _selected([], q) for q in COVERAGES}
    assert aggregate(empty)["status"] == "incomplete"
    tests.append("empty-primary-not-silently-dropped")
    for bad in (cases[:-1], [cases[1], cases[0], *cases[2:]], copy.deepcopy(cases)):
        if len(bad) == 16 and bad[0]["case"] == cases[0]["case"]:
            bad[-1]["score"]["public_sha256"] = bad[0]["score"]["public_sha256"]
        try:
            aggregate(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid history roster accepted")
    tests.append("missing-reordered-duplicate-histories-rejected")
    return dict(passed=True, complete=True, tests=tests, family_intervals=FAMILY_SIZE,
                scope="Hand-built scoring and statistical controls; no held-out execution")
