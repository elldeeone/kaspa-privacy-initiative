"""Frozen price-versus-transcript score, with independent-ledger inference.

Pure functions only: callers provide authorized in-memory inputs after the
complete prediction barrier. No seed, filesystem, generation, or observer call
is used here. Public outputs contain counts, never truth-joined target rows.
This arithmetic experiment cannot qualify native or cryptographic privacy.
"""
import hashlib
import json
from fractions import Fraction

from working_balance_validate import validate_bundle

SOMPI = 100_000_000
PRICE_WITHIN = 45 * SOMPI
PRICE_EXACT = 10 * SOMPI
EXPECTED_WITHIN = Fraction(21103, 100025)
EXPECTED_EXACT = Fraction(3, 25) + Fraction(2, 5 * 4001)
PROFILES = ("C+D", "pooled")
BASE = ("prior", "residual", "coinput", "split", "subset_nearest",
        "subset_supported", "partial_tail", "split_tail", "receipt_timing",
        "cash_inverse", "colluder_tags", "bridge_ancestry", "combined")
METRICS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
AMOUNT_METRICS = ("amount_within_10pct", "amount_exact")
CONTRASTS = ("public_minus_price", "pooled_minus_price", "pooled_minus_public")
BETS = (Fraction(1, 8), Fraction(1, 4), Fraction(1, 2), Fraction(9, 10))
TESTS = (("positive_advantage", Fraction(0), "plus"),
         ("above_five_points", Fraction(1, 20), "plus"),
         ("below_five_points", Fraction(1, 20), "minus"))
E_THRESHOLD = 180
FINAL_LEDGERS = 512
BOUNDARY = "finite arithmetic hypotheses; not exhaustive inference or native evidence"


def need(condition, label):
    if not condition:
        raise ValueError("price-leakage-score: " + label)


def integer(value, low=0, high=2**64-1):
    need(type(value) is int and low <= value <= high, "integer/range")
    return value


def fields(value, names, label):
    need(type(value) is dict and set(value) == set(names), label)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def ratio(value):
    need(type(value) is Fraction, "exact fraction required")
    return {"numerator": value.numerator, "denominator": value.denominator}


def exact(value):
    fields(value, ("numerator", "denominator"), "fraction fields")
    need(type(value["numerator"]) is int, "fraction numerator")
    denominator = value["denominator"]
    need(type(denominator) is int and denominator > 0, "fraction denominator")
    result = Fraction(value["numerator"], denominator)
    need(ratio(result) == value, "reduced fraction required")
    return result


def variants(profile):
    need(profile in PROFILES, "profile")
    return BASE if profile == "C+D" else BASE + tuple("C_" + name for name in BASE)


def amount_hits(guess, actual):
    integer(guess)
    integer(actual, 1)
    return {"amount_within_10pct": 10 * abs(guess-actual) <= actual,
            "amount_exact": guess == actual}


def validate_views(truth, views):
    fields(views, PROFILES, "view roster")
    for profile in PROFILES:
        members = [] if profile == "C+D" else list(range(8))
        expected = dict(schema="kpi-working-balance-view-v1", members=members,
            authored=[{key: row[key] for key in ("event", "owner", "inputs", "outputs")}
                      for row in truth["events"] if row["owner"] in members],
            receipts=[dict(position=out["position"], value=out["value"], owner=out["recipient"])
                      for row in truth["events"] for out in row["outputs"]
                      if out["value"] > 0 and out["recipient"] in members])
        need(digest(views[profile]) == digest(expected), "permitted disclosure completeness")


def validate_prediction(prediction, public, directory, view, profile):
    """Check the complete final public roster before hidden target selection."""
    fields(prediction, ("schema", "complete", "profile", "through_event", "public_sha256",
                       "directory_sha256", "view_sha256", "target_events_sha256", "rows",
                       "boundary"), "prediction fields")
    need(prediction["schema"] == "kpi-working-balance-predictions-v1"
         and prediction["complete"] is True and prediction["profile"] == profile
         and type(prediction["through_event"]) is int
         and prediction["through_event"] == len(public["events"])-1
         and prediction["boundary"] == BOUNDARY, "prediction scope")
    for key, value in (("public_sha256", public), ("directory_sha256", directory),
                       ("view_sha256", view)):
        need(type(prediction[key]) is str and prediction[key] == digest(value), "prediction input hash")
    targets = [row["event"] for row in public["events"] if row["mode"] == 1 and not row["payout"]]
    need(prediction["target_events_sha256"] == digest(targets), "prediction target hash")
    rows = prediction["rows"]
    need(type(rows) is list and len(rows) == len(targets), "prediction target coverage")
    for row, target in zip(rows, targets, strict=True):
        fields(row, ("event", "event_id", "guesses"), "prediction row fields")
        need(type(row["event"]) is int and row["event"] == target
             and row["event_id"] == public["events"][target]["event_id"], "prediction target identity")
        fields(row["guesses"], variants(profile), "prediction strategy roster")
        for guess in row["guesses"].values():
            fields(guess, ("sender", "recipient", "amount", "relationship_rank"), "prediction guess fields")
            integer(guess["sender"], 0, 31)
            integer(guess["recipient"], 0, 31)
            integer(guess["amount"])
            rank = guess["relationship_rank"]
            need(type(rank) is list and len(rank) == 4, "prediction rank shape")
            for value in rank:
                integer(value, -(2**63)+1, 2**63-1)
    return {row["event"]: row["guesses"] for row in rows}


def paired(left, right):
    need(type(left) is list and type(right) is list and len(left) == len(right) > 0
         and all(type(value) is bool for value in left+right), "paired correctness vectors")
    gains = sum(a and not b for a, b in zip(left, right, strict=True))
    losses = sum(b and not a for a, b in zip(left, right, strict=True))
    need(gains-losses == sum(left)-sum(right), "paired difference identity")
    return dict(gains=gains, losses=losses, eligible=len(left),
                difference=ratio(Fraction(gains-losses, len(left))))


def score_case(bundle, predictions):
    """Return aggregate counts for one fully drained sparse partial ledger."""
    fields(bundle, ("public", "directory", "views", "truth", "cost"), "bundle fields")
    fields(predictions, PROFILES, "prediction profile roster")
    public, directory, truth = bundle["public"], bundle["directory"], bundle["truth"]
    need(truth["cell"] == "sparse-independent" and truth["arm"] == "partial", "fixed workload")
    accounting = validate_bundle(public, directory, truth, bundle["cost"])
    validate_views(truth, bundle["views"])
    indexed = {profile: validate_prediction(predictions[profile], public, directory,
                      bundle["views"][profile], profile) for profile in PROFILES}
    # C_ copies must retain the independently observed public predictions.
    for event, guesses in indexed["C+D"].items():
        for name in BASE:
            need(digest(guesses[name]) == digest(indexed["pooled"][event]["C_"+name]),
                 "pooled public prediction copy")
    targets = [row for row in truth["targets"] if row["sender"] >= 8 and row["recipient"] >= 8]
    need(bool(targets), "empty eligible ledger is an implementation error; never drop/resample")
    baselines = {metric: [] for metric in AMOUNT_METRICS}
    correctness = {profile: {name: {metric: [] for metric in METRICS}
                            for name in variants(profile)} for profile in PROFILES}
    for target in targets:
        baselines["amount_within_10pct"].append(amount_hits(PRICE_WITHIN, target["amount"])["amount_within_10pct"])
        baselines["amount_exact"].append(amount_hits(PRICE_EXACT, target["amount"])["amount_exact"])
        for profile in PROFILES:
            guesses = indexed[profile][target["event"]]
            need(guesses["prior"]["amount"] == PRICE_WITHIN,
                 "honest-target old prior must equal optimal price prior")
            for name, guess in guesses.items():
                sender, recipient = guess["sender"] == target["sender"], guess["recipient"] == target["recipient"]
                outcomes = dict(sender=sender, recipient=recipient, relationship=sender and recipient,
                                **amount_hits(guess["amount"], target["amount"]))
                for metric, outcome in outcomes.items():
                    correctness[profile][name][metric].append(outcome)
    counts = {profile: {"variants": {name: {metric: sum(values) for metric, values in metrics.items()}
                                   for name, metrics in strategies.items()}}
              for profile, strategies in correctness.items()}
    public_hits, pooled_hits = (correctness[profile]["split_tail"] for profile in PROFILES)
    comparisons = (("public_minus_price", public_hits, baselines),
                   ("pooled_minus_price", pooled_hits, baselines),
                   ("pooled_minus_public", pooled_hits, public_hits))
    pairs = {name: {metric: paired(left[metric], right[metric]) for metric in AMOUNT_METRICS}
             for name, left, right in comparisons}
    for metric in AMOUNT_METRICS:
        need(exact(pairs["pooled_minus_price"][metric]["difference"]) ==
             exact(pairs["public_minus_price"][metric]["difference"]) +
             exact(pairs["pooled_minus_public"][metric]["difference"]), "additive contrast identity")
    return dict(schema="kpi-price-leakage-case-v1", complete=True,
                cell="sparse-independent", arm="partial", eligible_targets=len(targets),
                observable_targets=len(indexed["C+D"]),
                input_sha256={"public": digest(public), "directory": digest(directory),
                              "views": {profile: digest(bundle["views"][profile]) for profile in PROFILES},
                              "predictions": {profile: digest(predictions[profile]) for profile in PROFILES}},
                price_baseline={metric: sum(values) for metric, values in baselines.items()},
                profiles=counts, paired=pairs, accounting=accounting)


def e_value(differences, theta=Fraction(0), direction="plus"):
    """Exact average of four fixed wealth products, one factor per ledger.

    For iid D in [-1,1], E[1+lambda(D-theta)] <= 1 under E[D] <= theta.
    The reverse sign tests E[D] >= theta. Independence makes each product's
    expectation <= 1; their fixed average retains this bound. Markov's bound
    and nine-test Bonferroni control require no normal approximation.
    """
    need(type(differences) in (list, tuple) and len(differences) > 0, "nonempty independent ledgers")
    need(theta in (Fraction(0), Fraction(1, 20)) and type(theta) is Fraction, "frozen e-test threshold")
    need(direction in ("plus", "minus"), "e-test direction")
    need(all(type(value) is Fraction and -1 <= value <= 1 for value in differences), "exact bounded ledger differences")
    products = []
    for bet in BETS:
        product = Fraction(1)
        for value in differences:
            factor = 1 + bet*(value-theta)*(1 if direction == "plus" else -1)
            need(factor > 0, "nonpositive wealth factor")
            product *= factor
        products.append(product)
    return sum(products, Fraction()) / len(BETS)


def threshold_crossed(value):
    need(type(value) is Fraction and value >= 0, "nonnegative exact e-value")
    return value >= E_THRESHOLD


def e_tests(differences):
    result = {}
    for name, theta, direction in TESTS:
        value = e_value(differences, theta, direction)
        result[name] = dict(theta=ratio(theta), direction=direction, e_value=ratio(value),
                            e_value_approx=float(value), threshold=E_THRESHOLD,
                            crossed=threshold_crossed(value))
    return result


def validate_case(case):
    fields(case, ("schema", "complete", "cell", "arm", "eligible_targets", "observable_targets",
                  "input_sha256", "price_baseline", "profiles", "paired", "accounting"), "case fields")
    need(case["schema"] == "kpi-price-leakage-case-v1" and case["complete"] is True
         and case["cell"] == "sparse-independent" and case["arm"] == "partial", "case scope")
    n = integer(case["eligible_targets"], 1, 48)
    integer(case["observable_targets"], 64, 65535)
    bindings = case["input_sha256"]
    fields(bindings, ("public", "directory", "views", "predictions"), "input binding fields")
    for key in ("views", "predictions"):
        fields(bindings[key], PROFILES, "input binding profile roster")
    for value in [bindings["public"], bindings["directory"], *bindings["views"].values(),
                  *bindings["predictions"].values()]:
        need(type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value), "input binding hash")
    fields(case["price_baseline"], AMOUNT_METRICS, "baseline metric roster")
    for value in case["price_baseline"].values():
        integer(value, 0, n)
    fields(case["profiles"], PROFILES, "case profile roster")
    for profile in PROFILES:
        fields(case["profiles"][profile], ("variants",), "profile fields")
        strategies = case["profiles"][profile]["variants"]
        fields(strategies, variants(profile), "case strategy roster")
        for metrics in strategies.values():
            fields(metrics, METRICS, "case metric roster")
            for value in metrics.values():
                integer(value, 0, n)
            need(metrics["relationship"] <= min(metrics["sender"], metrics["recipient"])
                 and metrics["relationship"] >= metrics["sender"]+metrics["recipient"]-n
                 and metrics["amount_exact"] <= metrics["amount_within_10pct"], "metric subset identities")
        need(strategies["prior"]["amount_within_10pct"] == case["price_baseline"]["amount_within_10pct"], "prior count identity")
    for name in BASE:
        need(case["profiles"]["C+D"]["variants"][name] == case["profiles"]["pooled"]["variants"]["C_"+name], "public-copy count identity")
    fields(case["paired"], CONTRASTS, "paired contrast roster")
    public = case["profiles"]["C+D"]["variants"]["split_tail"]
    pooled = case["profiles"]["pooled"]["variants"]["split_tail"]
    sources = ((public, case["price_baseline"]), (pooled, case["price_baseline"]), (pooled, public))
    for name, (left, right) in zip(CONTRASTS, sources, strict=True):
        fields(case["paired"][name], AMOUNT_METRICS, "paired metric roster")
        for metric in AMOUNT_METRICS:
            pair = case["paired"][name][metric]
            fields(pair, ("gains", "losses", "eligible", "difference"), "paired fields")
            gains, losses = integer(pair["gains"], 0, n), integer(pair["losses"], 0, n)
            need(type(pair["eligible"]) is int and pair["eligible"] == n
                 and gains-losses == left[metric]-right[metric]
                 and gains <= min(left[metric], n-right[metric])
                 and losses <= min(right[metric], n-left[metric])
                 and exact(pair["difference"]) == Fraction(gains-losses, n), "paired counts/difference")
    accounting = case["accounting"]
    need(type(accounting) is dict and accounting.get("complete") is True
         and accounting.get("cost_counters_agree") is True
         and type(accounting.get("final_private_reserve")) is int
         and accounting["final_private_reserve"] == 0, "completed accounting receipt")
    return n


def aggregate(cases, expected_ledgers=FINAL_LEDGERS):
    """One terminal result; an explicit non-512 size is public development only."""
    integer(expected_ledgers, 1, FINAL_LEDGERS)
    need(type(cases) is list and len(cases) == expected_ledgers, "fixed complete ledger count")
    denominators = [validate_case(case) for case in cases]
    need(len({case["input_sha256"]["public"] for case in cases}) == len(cases), "duplicate public ledger")
    ledgers, eligible = len(cases), sum(denominators)
    totals = {profile: {"variants": {name: {} for name in variants(profile)}} for profile in PROFILES}
    baseline = {}
    for metric in AMOUNT_METRICS:
        count = sum(case["price_baseline"][metric] for case in cases)
        baseline[metric] = dict(correct=count, eligible=eligible, pooled_rate=ratio(Fraction(count, eligible)),
             equal_ledger_rate=ratio(sum((Fraction(case["price_baseline"][metric], n)
                                         for case, n in zip(cases, denominators, strict=True)), Fraction())/ledgers))
    for profile in PROFILES:
        for name in variants(profile):
            for metric in METRICS:
                values = [case["profiles"][profile]["variants"][name][metric] for case in cases]
                count = sum(values)
                totals[profile]["variants"][name][metric] = dict(correct=count, eligible=eligible,
                    pooled_rate=ratio(Fraction(count, eligible)),
                    equal_ledger_rate=ratio(sum((Fraction(value, n) for value, n in
                                                zip(values, denominators, strict=True)), Fraction())/ledgers))
    comparisons = {}
    for name in CONTRASTS:
        metrics = {}
        for metric in AMOUNT_METRICS:
            pairs = [case["paired"][name][metric] for case in cases]
            differences = [exact(pair["difference"]) for pair in pairs]
            gains, losses = sum(pair["gains"] for pair in pairs), sum(pair["losses"] for pair in pairs)
            metrics[metric] = dict(gains=gains, losses=losses, eligible=eligible,
                pooled_difference=ratio(Fraction(gains-losses, eligible)),
                equal_ledger_difference=ratio(sum(differences, Fraction())/ledgers))
            if metric == "amount_within_10pct":
                metrics[metric]["tests"] = e_tests(differences)
        tests = metrics["amount_within_10pct"]["tests"]
        if tests["above_five_points"]["crossed"]:
            decision = "advantage-above-five-points-demonstrated"
        elif tests["below_five_points"]["crossed"]:
            decision = ("positive-advantage-below-five-points-demonstrated" if tests["positive_advantage"]["crossed"]
                        else "advantage-below-five-points-demonstrated")
        elif tests["positive_advantage"]["crossed"]:
            decision = "positive-advantage-size-unresolved"
        else:
            decision = "five-point-bound-unresolved"
        need(not (tests["above_five_points"]["crossed"] and tests["below_five_points"]["crossed"]),
             "opposing terminal tests both crossed")
        comparisons[name] = dict(metrics=metrics, decision=decision)
    for metric in AMOUNT_METRICS:
        need(exact(comparisons["pooled_minus_price"]["metrics"][metric]["equal_ledger_difference"]) ==
             exact(comparisons["public_minus_price"]["metrics"][metric]["equal_ledger_difference"]) +
             exact(comparisons["pooled_minus_public"]["metrics"][metric]["equal_ledger_difference"]),
             "aggregate additive identity")
    return dict(schema="kpi-price-leakage-summary-v1", complete=True,
        scope="held-out arithmetic incremental-information test; no native privacy qualification",
        development_only=expected_ledgers != FINAL_LEDGERS, independent_ledgers=ledgers,
        eligible_targets=eligible, observable_targets=sum(case["observable_targets"] for case in cases),
        inference_unit="independently seeded whole ledger; equal ledger weights",
        inferential_attack="split_tail", qualification_pass=False,
        price_priors={"within_10pct_guess_sompi": PRICE_WITHIN, "exact_guess_sompi": PRICE_EXACT,
                      "expected_within_10pct": ratio(EXPECTED_WITHIN), "expected_exact": ratio(EXPECTED_EXACT),
                      "absolute_amount_cap": ratio(Fraction(1, 5)),
                      "expected_price_prior_exceeds_absolute_cap": EXPECTED_WITHIN > Fraction(1, 5)},
        price_baseline=baseline, profiles=totals, contrasts=comparisons,
        inference={"tests": 9, "family_error_bound": ratio(Fraction(1, 20)),
                   "per_test_error_bound": ratio(Fraction(1, E_THRESHOLD)),
                   "e_threshold": E_THRESHOLD, "bets": [ratio(bet) for bet in BETS],
                   "exact_comparisons": True, "no_interim_selection": True},
        limits=["Known-price workload remains above the unchanged absolute privacy cap.",
                "Public-plus-colluder evidence is combined information; the added-record contrast measures this frozen heuristic only.",
                "Negative or unresolved results do not establish absence of transaction information or privacy.",
                "Cash demand and activity are declared synthetic assumptions, not measured user behavior.",
                "No native bytes/proofs, chain acceptance, cryptographic assurance, or real-user anonymity is tested."])
