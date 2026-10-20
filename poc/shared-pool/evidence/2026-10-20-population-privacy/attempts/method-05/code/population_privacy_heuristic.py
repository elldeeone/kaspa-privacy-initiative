"""Frozen public cashout guesses: measurements, never forced-disclosure claims.

No file access, generation, solver or truth input in analyze(). The separate
scorer checks concrete accounting and both original full-model encodings.
"""
import copy

import population_privacy_model as full

SOMPI = 100_000_000
LOW, HIGH, BASE_AMOUNT = 10 * SOMPI, 1000 * SOMPI, 100 * SOMPI
VARIANTS = ("baseline", "cashout_total", "cashout_half", "known_note_residual")
STRATA = ("primary", "all_undisclosed", "startup", "adversary_endpoint")
METRICS = ("sender", "recipient", "amount_within_10pct", "amount_exact")
GUESS_KEYS = {"sender", "recipient", "amount", "basis", "matched_drain", "seed_position"}


def _targets(public):
    events = public["algebra"]["events"]
    return [dict(event=i, through_event=len(events) - 1)
            for i, event in enumerate(events) if i and event["mode"] == 1]


def _admitted(public):
    owners = {public["funding_owners"][public["algebra"]["initial"]["funding_group"]]}
    result = {}
    for i, event in enumerate(public["algebra"]["events"]):
        if event["mode"] == 0:
            owners.add(public["funding_owners"][event["funding_group"]])
        result[i] = sorted(owners)
    return result


def _role(public, view, facts, admitted, event, field):
    authored = facts["authors"].get(event)
    if authored is not None:
        return authored["owner"] if field == "sender" else authored["outputs"][0]["recipient"]
    position = public["algebra"]["events"][event]["new"][0]
    if field == "recipient" and position in facts["receipts"]:
        return facts["receipts"][position]["owner"]
    candidates = sorted(set(admitted[event]) - set(view["members"]))
    full.need(bool(candidates), "no role candidate under declared complete records")
    seed = dict(domain="kpi-population-heuristic-role-v1", field=field,
                event_id=public["algebra"]["events"][event]["id"])
    return candidates[int(full.digest(seed), 16) % len(candidates)]


def _seeds(view):
    members = set(view["members"])
    return [dict(position=output["position"], value=output["value"],
                 owner=output["recipient"], born=row["event"])
            for row in view["authored"] for output in row["outputs"]
            if output["value"] > 0 and output["recipient"] not in members]


def _first_cashout(events, target, divisor):
    for i, event in enumerate(events):
        if i > target and event["mode"] == 2:
            guess = (event["payout"] + event["fee"]) // divisor
            if LOW <= guess <= HIGH:
                return i, guess
    return None


def _residual(events, target, payment_position, seeds, known_spent):
    candidates = []
    for i, event in enumerate(events):
        if i <= target or event["mode"] != 2:
            continue
        total = event["payout"] + event["fee"]
        for seed in seeds:
            p = seed["position"]
            if (p == payment_position or seed["born"] >= i
                    or known_spent.get(p, len(events)) < i):
                continue
            guess = total - seed["value"]
            if LOW <= guess <= HIGH:
                rank = (i - target, abs(seed["born"] - target), p)
                candidates.append((rank, i, guess, seed["owner"], p))
    return min(candidates) if candidates else None


def _analyze(public, view, tiny=False):
    facts = full.validate(public, view, tiny=tiny)
    events, admitted = public["algebra"]["events"], _admitted(public)
    seeds = _seeds(view)
    spent = {p: row["event"] for row in view["authored"] for p in row["inputs"]}
    targets, rows = _targets(public), []
    for target in targets:
        i = target["event"]
        baseline = dict(sender=_role(public, view, facts, admitted, i, "sender"),
                        recipient=_role(public, view, facts, admitted, i, "recipient"),
                        amount=BASE_AMOUNT, basis="baseline", matched_drain=None,
                        seed_position=None)
        guesses = {name: dict(baseline) for name in VARIANTS}
        for name, divisor in (("cashout_total", 1), ("cashout_half", 2)):
            match = _first_cashout(events, i, divisor)
            if match is not None:
                drain, amount = match
                guesses[name].update(amount=amount, basis=name, matched_drain=drain)
        match = _residual(events, i, events[i]["new"][0], seeds, spent)
        if match is not None:
            _, drain, amount, owner, position = match
            guesses["known_note_residual"].update(amount=amount, recipient=owner,
                basis="known_note_residual", matched_drain=drain, seed_position=position)
        rows.append(dict(**target, variants=guesses))
    return dict(schema="kpi-population-heuristic-predictions-v1", complete=True,
                public_sha256=full.digest(public), view_sha256=full.digest(view),
                requested_targets=targets, rows=rows,
                meaning="Deterministic guesses, not forced facts or probabilities",
                baseline_limit="Limited diagnostic prior; strongest-prior qualification remains open")


def analyze(public, view):
    return _analyze(public, view)


def within_10pct(guess, amount):
    return 10 * abs(guess - amount) <= amount


def _check_prediction(public, view, prediction):
    full.fields(prediction, {"schema", "complete", "public_sha256", "view_sha256",
        "requested_targets", "rows", "meaning", "baseline_limit"}, "prediction")
    full.need(prediction["schema"] == "kpi-population-heuristic-predictions-v1"
              and prediction["complete"] is True, "prediction completion/schema")
    full.need(prediction["public_sha256"] == full.digest(public)
              and prediction["view_sha256"] == full.digest(view), "prediction input identity")
    expected = _targets(public)
    full.need(prediction["requested_targets"] == expected
              and isinstance(prediction["rows"], list)
              and len(prediction["rows"]) == len(expected), "prediction target coverage")
    for target, row in zip(expected, prediction["rows"], strict=True):
        full.fields(row, {"event", "through_event", "variants"}, "prediction row")
        full.need({k: row[k] for k in target} == target, "prediction target order")
        full.fields(row["variants"], set(VARIANTS), "prediction variants")
        for guess in row["variants"].values():
            full.fields(guess, GUESS_KEYS, "guess")
            for field in ("sender", "recipient"):
                full.need(type(guess[field]) is int and guess[field] in public["roles"], "guess role")
            full.integer(guess["amount"], LOW, HIGH)
            full.need(guess["basis"] in VARIANTS, "guess basis")
            if guess["matched_drain"] is not None:
                d = full.integer(guess["matched_drain"], row["event"] + 1, row["through_event"])
                full.need(public["algebra"]["events"][d]["mode"] == 2, "matched drain")
            if guess["seed_position"] is not None:
                full.integer(guess["seed_position"], 0, len(public["commitments"]) - 1)


def _score_rows(public, view, prediction, truth):
    variants = {name: {stratum: {metric: dict(correct=0, eligible=0) for metric in METRICS}
                      for stratum in STRATA} for name in VARIANTS}
    admitted = _admitted(public)
    authors = {r["event"] for r in view["authored"]}
    received = {r["position"] for r in view["receipts"]}
    adversaries, members = set(public["adversaries"]), set(view["members"])
    rows = []
    for prediction_row in prediction["rows"]:
        i = prediction_row["event"]
        hidden, event = truth["events"][i], public["algebra"]["events"][i]
        full.need(hidden["kind"] == "payment", "nonpayment truth target")
        actual = {key: hidden[key] for key in ("sender", "recipient", "amount")}
        endpoints = {actual["sender"], actual["recipient"]}
        startup = len(admitted[i]) != len(public["roles"])
        primary = not startup and not endpoints.intersection(adversaries | members)
        known = dict(sender=i in authors, recipient=i in authors or event["new"][0] in received,
                     amount=i in authors or event["new"][0] in received)
        strata = dict(primary=primary, all_undisclosed=True, startup=startup,
                      adversary_endpoint=bool(endpoints & adversaries))
        correct = {}
        for name, guess in prediction_row["variants"].items():
            correct[name] = dict(sender=guess["sender"] == actual["sender"],
                                 recipient=guess["recipient"] == actual["recipient"],
                                 amount_within_10pct=within_10pct(guess["amount"], actual["amount"]),
                                 amount_exact=guess["amount"] == actual["amount"])
            for stratum, selected in strata.items():
                for metric in METRICS:
                    field = "amount" if metric.startswith("amount_") else metric
                    if selected and not known[field]:
                        counter = variants[name][stratum][metric]
                        counter["eligible"] += 1
                        counter["correct"] += int(correct[name][metric])
        rows.append(dict(event=i, through_event=prediction_row["through_event"],
                         primary_eligible=primary, directly_known=known,
                         startup=startup, adversary_endpoint=strata["adversary_endpoint"],
                         correct=correct))
    return dict(variants=variants, rows=rows,
                tested_primary_targets=sum(row["primary_eligible"] for row in rows))


def score(public, view, prediction, truth):
    """Called only by isolated scorer after the complete prediction batch is sealed."""
    import population_privacy_workload as workload
    full.validate(public, view)
    _check_prediction(public, view, prediction)
    full.need(workload.accounting(public, truth["values"], truth["owners"], truth["inputs"],
                                 truth["events"]) == truth["accounting"], "truth accounting changed")
    consistency = full.validate_truth(public, view, truth)
    full.need(consistency["complete"] and consistency["cp_sat"] == consistency["z3"] == "SAT",
              "truth excluded by original full model")
    return dict(complete=True, arm=truth["arm"], truth_consistency=consistency,
                qualification_pass=False, **_score_rows(public, view, prediction, truth),
                limit="Finite modeled guesses; four request sets and limited baselines cannot qualify privacy")


def controls():
    """Hand-chosen public fixtures; never generate or inspect held-out histories."""
    tests = []

    def drain(total):
        return dict(mode=2, payout=total - full.FEE, fee=full.FEE)

    events = [dict(mode=1), drain(19 * SOMPI), drain(40 * SOMPI)]
    assert _first_cashout(events, 0, 1) == (1, 19 * SOMPI)
    assert _first_cashout(events, 0, 2) == (2, 20 * SOMPI)
    assert _first_cashout([dict(mode=1), drain(21 * SOMPI + 1)], 0, 2) == (1, 1050000000)
    tests.append("independent-first-eligible-drain-and-odd-sompi-half")
    for amount in (LOW, HIGH):
        assert _first_cashout([dict(mode=1), drain(amount)], 0, 1) == (1, amount)
    for amount in (LOW - 1, HIGH + 1):
        assert _first_cashout([dict(mode=1), drain(amount)], 0, 1) is None
    assert within_10pct(110 * SOMPI, 100 * SOMPI) and within_10pct(90 * SOMPI, 100 * SOMPI)
    assert not within_10pct(110 * SOMPI + 1, 100 * SOMPI)
    assert not within_10pct(90 * SOMPI - 1, 100 * SOMPI)
    tests.append("inclusive-amount-and-exact-integer-tolerance-boundaries")
    events = [dict(mode=1), dict(mode=1), drain(1500 * SOMPI)]
    seed = dict(position=1, born=0, value=1200 * SOMPI, owner=9)
    assert _first_cashout(events, 1, 1) is None
    assert _first_cashout(events, 1, 2) == (2, 750 * SOMPI)
    assert _residual(events, 1, 5, [seed], {}) == ((1, 1, 1), 2, 300 * SOMPI, 9, 1)
    assert _residual(events, 1, 1, [seed], {}) is None
    assert _residual(events, 1, 5, [dict(seed, born=2)], {}) is None
    assert _residual(events, 1, 5, [seed], {1: 1}) is None
    assert _residual(events, 1, 5, [seed], {1: 2}) is not None
    tests.append("residual-range-chronology-target-exclusion-and-defensive-spend-boundary")
    tied = [dict(seed, position=3), dict(seed, position=2)]
    assert _residual(events, 1, 5, tied, {})[-1] == 2
    assert _residual(events, 1, 5, [dict(seed, value=1600 * SOMPI)], {}) is None
    tests.append("residual-tie-order-and-negative-residual")

    s, fee = SOMPI, full.FEE
    public, truth = full._fixture(100 * s + fee, [
        (1, 0, [0], [(0, 100 * s), (None, 0)]),
        (0, 1, [], [(1, 100 * s), (None, 0)]),
        (0, 2, [], [(2, 100 * s), (None, 0)]),
        (1, 0, [1], [(1, 30 * s), (0, 70 * s - fee)]),
        (1, 2, [5], [(1, 20 * s), (2, 80 * s - fee)]),
        (2, 1, [7, 9], [])], floor=full.FLOOR, fee=fee)
    public["adversaries"] = [0]
    public["modeled"]["payout_floor_sompi"] = full.PAYOUT_FLOOR
    view = full._view(public, truth, [0])
    predicted = _analyze(public, view, tiny=True)
    assert _analyze(public, view, tiny=True) == predicted
    assert _seeds(view) == [dict(position=7, value=30 * s, owner=1, born=3)]
    rows = {r["event"]: r for r in predicted["rows"]}
    guesses = rows[4]["variants"]
    assert guesses["cashout_total"]["amount"] == 50 * s
    assert guesses["cashout_half"]["amount"] == 25 * s
    assert guesses["known_note_residual"]["amount"] == 20 * s
    assert guesses["known_note_residual"]["recipient"] == 1
    assert rows[3]["variants"]["known_note_residual"]["basis"] == "baseline"
    prefix, prefix_view = full.prefix(public, view, 4)
    prefix_predictions = _analyze(prefix, prefix_view, tiny=True)
    assert all(g["basis"] == "baseline" for row in prefix_predictions["rows"]
               for g in row["variants"].values())
    tests.append("handchecked-total-half-residual-fallback-and-no-initial-admission-seeds")
    for poisoned in (dict(public, truth={}), dict(public, arm="persistent")):
        try:
            _analyze(poisoned, view, tiny=True)
        except ValueError:
            pass
        else:
            raise AssertionError("observer accepted private metadata")
    bad = copy.deepcopy(predicted)
    bad["rows"].pop()
    try:
        _check_prediction(public, view, bad)
    except ValueError:
        pass
    else:
        raise AssertionError("missing target accepted")
    tests.append("schema-poison-and-missing-coverage-rejected")
    # A 32-role, fully admitted explicit fixture exercises the complete scorer,
    # including original full CP/Z3 truth inclusion, without sampling requests.
    steps = [(1, 0, [0], [(0, 1000 * s), (None, 0)])]
    steps.extend((0, owner, [], [(owner, 1000 * s), (None, 0)]) for owner in range(1, 32))
    steps.extend([(1, 8, [17], [(9, 120 * s), (8, 880 * s - fee)]), (2, 9, [65], [])])
    p, t = full._fixture(1000 * s + fee, steps, roles=32, floor=full.FLOOR, fee=fee)
    p["modeled"]["payout_floor_sompi"] = full.PAYOUT_FLOOR
    t["events"] = [dict(sender=owner, kind="payment" if i == 32 else "control",
                        recipient=9 if i == 32 else None, amount=120 * s if i == 32 else None)
                   for i, (_, owner, _, _) in enumerate(steps)]
    t["arm"] = "development"
    import population_privacy_workload as workload
    t["accounting"] = workload.accounting(p, t["values"], t["owners"], t["inputs"], t["events"])
    v = full._view(p, t, [0])
    result = score(p, v, analyze(p, v), t)
    assert result["tested_primary_targets"] == 1 and result["qualification_pass"] is False
    assert result["variants"]["cashout_total"]["primary"]["amount_exact"] == dict(correct=1, eligible=1)
    assert result["variants"]["baseline"]["primary"]["amount_within_10pct"] == dict(correct=0, eligible=1)
    # Received-only knowledge excludes recipient/amount, never the hidden sender.
    private = dict(events=[dict(sender=truth["senders"][i], kind="payment" if i in (3, 4) else "control",
        recipient=truth["owners"][event["new"][0]] if i in (3, 4) else None,
        amount=truth["values"][event["new"][0]] if i in (3, 4) else None)
        for i, event in enumerate(public["algebra"]["events"])])
    received_view = full._view(public, truth, [1])
    scored = _score_rows(public, received_view, predicted, private)
    known = scored["rows"][1]["directly_known"]
    assert known == dict(sender=False, recipient=True, amount=True)
    tests.append("full-scorer-accounting-dual-truth-sat-and-field-specific-exclusions")
    return dict(passed=True, complete=True, controls=tests,
                scope="Explicit development fixtures only; no held-out data or privacy qualification")
