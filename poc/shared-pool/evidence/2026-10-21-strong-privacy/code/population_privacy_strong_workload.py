"""Four-round persistent population workload, with no generation on import.

The old Ledger, accounting, sampler, selector and disclosure code are reused
unchanged. This is a synthetic policy experiment: opaque, independently sampled
funding and payout labels model absence of the repaired native-script alias;
they do not demonstrate key separation, proof validity or chain acceptance.

Affordability does not require resampling. Follow each owner's original capital
note: a payment either leaves it alone or replaces it with sender change of at
least its previous value minus (1000 tKAS + fee). After k <= 4 own payments the
continuation is >= 5000 - k*1000.4 tKAS. Before the fourth payment it is >=1998.8,
so a single note covers every permitted request with safe change. Other incoming
notes cannot reduce that bound. Final drainage consumes every remaining positive
note once in one/two-note groups; each group covers the fee and payout floor.
"""
import copy
import itertools

import population_privacy_workload as old

SOMPI, FEE, FLOOR = old.SOMPI, old.FEE, old.FLOOR
ROLES, ADVERSARIES = tuple(old.ROLES), tuple(old.ADVERSARIES)
FIRST, SECOND = tuple(old.FIRST), tuple(old.SECOND)
ROUNDS = 4
PAYMENTS = len(ROLES) * ROUNDS
BALANCES = tuple(v * SOMPI for v in (5000, 10000, 20000, 40000))
MIN_AMOUNT, MAX_AMOUNT = 10 * SOMPI, 1000 * SOMPI
REGIMES = ("overlap", "sparse")
HISTORIES_PER_REGIME = 8
DEVELOPMENT_SEED = {"requests": bytes(range(32)).hex(),
                    "opaque": bytes(reversed(range(32))).hex()}
make_view, public_prefix = old.make_view, old.public_prefix
need = old.need


def tag_amount(role, round_number):
    need(type(role) is int and role in ADVERSARIES, "active role")
    old.integer(round_number, 0, ROUNDS - 1)
    return (round_number + 1) * 100 * SOMPI + (role + 1) * 1000


def public_policy():
    """Frozen policy available to observers from source, never private requests."""
    phases = [(FIRST, FIRST, 0), (SECOND, ROLES, 0)] + [
        (ROLES, ROLES, r) for r in range(1, ROUNDS)]
    offset, schedule = 0, []
    for senders, admitted, round_number in phases:
        schedule.append(dict(request_start=offset,
                             request_end_exclusive=offset + len(senders),
                             round=round_number, senders=list(senders),
                             admitted=list(admitted),
                             sparse_gap_before_minutes=60 if round_number else 0))
        offset += len(senders)
    return dict(schema="kpi-population-strong-policy-v1", histories=16,
                histories_per_regime=HISTORIES_PER_REGIME, regimes=list(REGIMES),
                arm="persistent", roles=list(ROLES), adversaries=list(ADVERSARIES),
                rounds=ROUNDS, payments=PAYMENTS, startup_payments=len(FIRST),
                starting_balances_sompi=list(BALANCES),
                honest_amount_min_sompi=MIN_AMOUNT,
                honest_amount_max_sompi=MAX_AMOUNT,
                honest_distribution="old.log_amount: uint64 log-uniform, Decimal80, half-even sompi",
                tag_amounts_sompi=[[tag_amount(r, n) for r in ADVERSARIES]
                                  for n in range(ROUNDS)],
                schedule=schedule,
                selector="least-excess-fewest-inputs-lexicographic",
                drain="hidden uniform role permutation, ascending positions in pairs",
                native_scripts="independent opaque labels; no funding/exit alias; synthetic assumption")


def _plan(request_seed, regime):
    need(regime in REGIMES, "strong regime")
    capital = old.Stream(request_seed, "strong/capital")
    ordering = old.Stream(request_seed, "strong/request-order")
    honest = old.Stream(request_seed, "strong/honest-requests")
    active = old.Stream(request_seed, "strong/nonadaptive-active-requests")
    drainage = old.Stream(request_seed, "strong/final-role-order")
    balances = [capital.choose(BALANCES) for _ in ROLES]
    requests, minute = [], 0
    for phase in public_policy()["schedule"]:
        if regime == "sparse":
            minute += phase["sparse_gap_before_minutes"]
        for sender in ordering.shuffle(phase["senders"]):
            minute += 1
            if sender in ADVERSARIES:
                recipient = active.choose([r for r in phase["admitted"] if r not in ADVERSARIES])
                amount = tag_amount(sender, phase["round"])
            else:
                recipient = honest.choose([r for r in phase["admitted"] if r != sender])
                amount = old.log_amount(honest)
            requests.append(dict(sender=sender, recipient=recipient, amount=amount,
                                 round=phase["round"], minute=minute))
    return balances, requests, drainage.shuffle(ROLES)


def generate(seed, regime):
    """Caller freezes first and preserves both private seeds before this call.

    Return the old paired-generator shape with only the persistent arm. Any
    failed prefix and every original request survive; no seed/request retry.
    """
    need(isinstance(seed, dict) and set(seed) == {"requests", "opaque"}, "seed bundle")
    request_seed, opaque_seed = old._seed(seed, "requests"), old._seed(seed, "opaque")
    need(request_seed != opaque_seed, "request and opaque seeds must be independent")
    balances, requests, drain_order = _plan(request_seed, regime)
    labels = old.Labels(opaque_seed, "strong-directory")
    funding = {r: labels.new() for r in ROLES}
    contacts = {labels.new(): r for r in ROLES}
    ledger = old.Ledger(balances, funding, contacts, opaque_seed, "strong-persistent")
    error = None
    try:
        ledger.bootstrap()
        for role in FIRST:
            if role != 0:
                ledger.admit(role, 0)
        for i, request in enumerate(requests):
            if i == len(FIRST):
                for role in SECOND:
                    ledger.admit(role, requests[i - 1]["minute"])
            ledger.pay(request, i, False)
        ledger.drain(drain_order, requests[-1]["minute"])
    except ValueError as failure:
        error = str(failure)
    public = copy.deepcopy(ledger.public())
    truth = copy.deepcopy(ledger.truth(requests, regime, "persistent"))
    if error is None:
        try:
            validate_generated(public, truth)
        except ValueError as failure:
            error = "generated-policy validation: " + str(failure)
    return {"persistent": dict(public=public, truth=truth, complete=error is None, error=error)}


def _checked_selection(values, owners, spent, sender, amount):
    """Independent policy checker; it does not call the generator's selector."""
    available = [p for p in range(len(values)) if p not in spent
                 and values[p] > 0 and owners[p] == sender]
    acceptable = []
    for positions in itertools.chain(((p,) for p in available), itertools.combinations(available, 2)):
        total = sum(values[p] for p in positions)
        change = total - amount - FEE
        if change == 0 or change >= FLOOR:
            acceptable.append((total, len(positions), positions))
    need(acceptable, "no policy-feasible input combination")
    return list(sorted(acceptable)[0][2])


def validate_generated(public, truth):
    """Scorer-side exact policy/accounting check, without a generator seed.

    Checks sampler support and schedule, not statistical randomness or seed
    independence; those belong to the frozen sampler and runner provenance.
    Does not run inference or claim truth inclusion in the two solver encodings.
    """
    import population_privacy_model as full
    need(set(public) == full.PUBLIC_KEYS, "strong public fields: no payout-owner side information")
    need(set(truth) == {"schema", "values", "owners", "inputs", "events", "requests",
                        "starting_balances", "regime", "arm", "accounting"}, "strong truth fields")
    need(truth["schema"] == old.TRUTH_SCHEMA and truth["arm"] == "persistent"
         and truth["regime"] in REGIMES, "strong truth identity")
    balances, requests = truth["starting_balances"], truth["requests"]
    need(len(balances) == len(ROLES) and all(type(v) is int and v in BALANCES for v in balances),
         "strong starting capital")
    need(len(requests) == PAYMENTS, "strong request count")
    minute = 0
    for phase in public_policy()["schedule"]:
        if truth["regime"] == "sparse":
            minute += phase["sparse_gap_before_minutes"]
        rows = requests[phase["request_start"]:phase["request_end_exclusive"]]
        need(sorted(r["sender"] for r in rows) == sorted(phase["senders"]), "strong phase senders")
        for request in rows:
            need(set(request) == {"sender", "recipient", "amount", "round", "minute"}, "request fields")
            minute += 1
            sender, recipient = request["sender"], request["recipient"]
            need(type(sender) is type(recipient) is int and sender != recipient
                 and recipient in phase["admitted"], "strong request identities")
            need(type(request["round"]) is int and request["round"] == phase["round"]
                 and type(request["minute"]) is int and request["minute"] == minute, "strong request chronology")
            old.integer(request["amount"], MIN_AMOUNT, MAX_AMOUNT)
            if sender in ADVERSARIES:
                need(recipient not in ADVERSARIES and request["amount"] == tag_amount(sender, phase["round"]),
                     "strong active policy")
    values, owners, inputs, hidden = (truth[k] for k in ("values", "owners", "inputs", "events"))
    need(all(set(row) == {"sender", "recipient", "kind", "request", "amount"} for row in hidden),
         "hidden event fields")
    need(isinstance(inputs, dict) and all(isinstance(row, list) and all(type(p) is int for p in row)
                                        for row in inputs.values()), "canonical selected positions")
    need(all(row["request"] is None if row["kind"] != "payment"
             else type(row["request"]) is int for row in hidden), "canonical payment request index")
    need(old.accounting(public, values, owners, inputs, hidden) == truth["accounting"], "strong accounting")
    full.validate(public, make_view(public, truth, []))
    need(public["algebra"]["initial"]["value"] == balances[0] + FEE and owners[0] == 0,
         "strong founding capital")
    events = public["algebra"]["events"]
    need(len({e["id"] for e in events}) == len(events)
         and len(set(public["commitments"])) == len(public["commitments"]), "opaque event/commitment identity")
    funding = set(public["funding_owners"])
    contacts = set(public["modeled"]["receive_contacts"])
    payouts = [e["destination"] for e in events if e["mode"] == 2]
    labels = funding | contacts | set(payouts) | {e["id"] for e in events} | {
        public["algebra"]["initial"]["id"]} | set(public["commitments"])
    need(all(isinstance(v, str) and len(v) == 64 and v != "0" * 64
             and all(c in "0123456789abcdef" for c in v) for v in labels), "canonical opaque labels")
    need(len(funding) == 32 and len(set(payouts)) == len(payouts)
         and not set(payouts).intersection(funding | contacts), "modeled destination alias")

    expected = [("bootstrap", 0, 0, None)] + [("admit", r, 0, None) for r in FIRST if r != 0]
    for i, request in enumerate(requests):
        if i == len(FIRST):
            expected.extend(("admit", r, requests[i - 1]["minute"], None) for r in SECOND)
        expected.append(("payment", request["sender"], request["minute"], i))
    need(len(events) > len(expected), "missing complete drainage")
    spent = set()
    for i, (kind, sender, when, request_index) in enumerate(expected):
        event, private = events[i], hidden[i]
        mode = 0 if kind == "admit" else 1
        need(private["kind"] == kind and private["sender"] == sender
             and private["request"] == request_index and event["mode"] == mode
             and event["minute"] == when, "strong event schedule")
        positions = inputs[str(i)]
        if kind == "bootstrap":
            need(positions == [0] and [values[p] for p in event["new"]] == [balances[0], 0]
                 and owners[event["new"][0]] == 0, "strong self bootstrap")
        elif kind == "admit":
            need(event["deposit"] == balances[sender] + FEE, "strong admission capital")
        else:
            request = requests[request_index]
            need(private["recipient"] == request["recipient"] and private["amount"] == request["amount"],
                 "strong request realization")
            before = event["count_before"]
            need(positions == _checked_selection(values[:before], owners[:before], spent,
                                                 sender, request["amount"]), "strong selected inputs")
        if kind != "payment":
            need(private["recipient"] is None and private["amount"] is None, "nonpayment truth metadata")
        spent.update(positions)
    drain_order, when = [], requests[-1]["minute"]
    for i in range(len(expected), len(events)):
        event, private = events[i], hidden[i]
        sender = private["sender"]
        if not drain_order or sender != drain_order[-1]:
            need(sender not in drain_order, "drain role revisit")
            if drain_order:
                need(not any(v and owners[p] == drain_order[-1] and p not in spent
                             for p, v in enumerate(values)), "drain role unfinished")
            drain_order.append(sender)
        remaining = [p for p, v in enumerate(values) if v and owners[p] == sender and p not in spent]
        when += 1
        need(event["mode"] == 2 and event["minute"] == when and private["kind"] == "final_exit"
             and private["request"] is None and private["recipient"] is None and private["amount"] is None
             and inputs[str(i)] == remaining[:2], "strong complete drainage policy")
        spent.update(inputs[str(i)])
    need(sorted(drain_order) == list(ROLES) and truth["accounting"]["remaining_reserve_sompi"] == 0,
         "strong terminal state")
    return dict(passed=True, complete=True, payments=PAYMENTS, startup_payments=len(FIRST),
                active_payments=len(ADVERSARIES) * ROUNDS, full_drainage=True,
                scope="exact policy/accounting check; no seed-randomness or cryptographic claim")


def controls():
    """Published development seeds only; no hidden seed creation or file reads."""
    tests = []
    policy = public_policy()
    need(policy["payments"] == 128 and policy["startup_payments"] == 16
         and sum(p["sparse_gap_before_minutes"] for p in policy["schedule"]) == 180,
         "policy constants")
    need(len({tag_amount(r, n) for r in ADVERSARIES for n in range(ROUNDS)}) == 32,
         "unique active tags")
    tests.append("fixed128-payments-32-tags-16-startup-three-sparse-gaps")
    # Explicit worst-case capital path with floor-sized and numerous incoming
    # fragments. Track original capital change, regardless of greedy selection.
    for fragments in ([], [FLOOR] * 12, [MAX_AMOUNT] * 5, [MAX_AMOUNT - FEE] * 4):
        values, owners, spent, capital = [BALANCES[0]] + fragments, [0] * (1 + len(fragments)), set(), 0
        for k in range(ROUNDS):
            need(values[capital] >= BALANCES[0] - k * (MAX_AMOUNT + FEE), "capital bound before")
            chosen = old.select_inputs(values, owners, spent, 0, MAX_AMOUNT)
            change = sum(values[p] for p in chosen) - MAX_AMOUNT - FEE
            spent.update(chosen)
            if capital in chosen:
                capital = len(values) + 1
            values.extend([MAX_AMOUNT, change])
            owners.extend([1, 0 if change else None])
            need(capital not in spent and values[capital] >= BALANCES[0] - (k + 1) * (MAX_AMOUNT + FEE),
                 "capital continuation")
        need(values[capital] >= 99_840_000_000, "four-payment boundary")
    tests.append("affordability-max-amount-capital-continuation-with-fragments")
    for values, amount, expected in (
        ([5000 * SOMPI, 11 * SOMPI, 12 * SOMPI], 2_260_000_000, [1, 2]),
        ([5000 * SOMPI, 11 * SOMPI, 12 * SOMPI, 23 * SOMPI, 23 * SOMPI], 2_260_000_000, [3]),
        ([1_040_000_000, 1_099_999_999, 1_100_000_000], 10 * SOMPI, [0]),
        ([1_099_999_999, 1_100_000_000], 10 * SOMPI, [1]),
    ):
        arguments = (values, [0] * len(values), set(), 0, amount)
        need(old.select_inputs(*arguments) == _checked_selection(*arguments) == expected,
             "hand-checked policy selector")
    tests.append("independent-selector-two-input-ties-and-zero-dust-floor-boundaries")
    histories = {regime: generate(DEVELOPMENT_SEED, regime)["persistent"] for regime in REGIMES}
    for history in histories.values():
        need(history["complete"], history["error"] or "development generation")
        validate_generated(history["public"], history["truth"])
    tests.append("published-development-seed-both-regimes-full-policy-and-accounting")
    overlap, sparse = (histories[r] for r in REGIMES)
    without_minute = lambda rows: [{k: v for k, v in r.items() if k != "minute"} for r in rows]
    need(without_minute(overlap["truth"]["requests"]) == without_minute(sparse["truth"]["requests"])
         and overlap["truth"]["values"] == sparse["truth"]["values"], "timing changed requests")
    tests.append("sparse-only-changes-declared-timing")
    changed_seed = dict(DEVELOPMENT_SEED, requests="a5" * 32)
    changed = generate(changed_seed, "overlap")["persistent"]
    need(changed["complete"], changed["error"] or "independent label control")
    p, t = overlap["public"], overlap["truth"]
    need(p["funding_owners"] == changed["public"]["funding_owners"]
         and p["modeled"]["receive_contacts"] == changed["public"]["modeled"]["receive_contacts"]
         and p["commitments"] == changed["public"]["commitments"]
         and t["requests"] != changed["truth"]["requests"], "labels depend on requests")
    tests.append("opaque-labels-independent-of-request-seed")
    for label, mutation in (
        ("changed-tag", lambda x: x["requests"][next(i for i, r in enumerate(x["requests"]) if r["sender"] == 0)].__setitem__("amount", 100 * SOMPI)),
        ("changed-round", lambda x: x["requests"][32].__setitem__("round", 0)),
        ("changed-time", lambda x: x["requests"][32].__setitem__("minute", 0)),
        ("changed-capital", lambda x: x["starting_balances"].__setitem__(0, 4999 * SOMPI)),
        ("missing-request", lambda x: x["requests"].pop()),
        ("boolean-input-position", lambda x: x["inputs"].__setitem__("0", [False])),
        ("boolean-request-index", lambda x: next(e for e in x["events"] if e["kind"] == "payment").__setitem__("request", False)),
    ):
        poisoned = copy.deepcopy(t)
        mutation(poisoned)
        try:
            validate_generated(p, poisoned)
        except ValueError:
            tests.append("reject-" + label)
        else:
            raise ValueError("accepted " + label)
    poisoned = copy.deepcopy(p)
    next(e for e in poisoned["algebra"]["events"] if e["mode"] == 2)["destination"] = next(iter(p["funding_owners"]))
    try:
        validate_generated(poisoned, t)
    except ValueError:
        tests.append("reject-modeled-funding-payout-alias")
    else:
        raise ValueError("accepted modeled alias")
    poisoned = copy.deepcopy(p)
    poisoned["payout_owners"] = {e["destination"]: t["events"][i]["sender"]
                                 for i, e in enumerate(p["algebra"]["events"]) if e["mode"] == 2}
    try:
        validate_generated(poisoned, t)
    except ValueError:
        tests.append("reject-added-payout-owner-side-information")
    else:
        raise ValueError("accepted payout-owner side information")
    truncated, prefix_truth = copy.deepcopy(p), copy.deepcopy(t)
    truncated["algebra"]["events"].pop()
    prefix_truth["events"].pop()
    del prefix_truth["inputs"][str(len(truncated["algebra"]["events"]))]
    prefix_truth["accounting"] = old.accounting(truncated, prefix_truth["values"], prefix_truth["owners"],
                                                prefix_truth["inputs"], prefix_truth["events"])
    need(prefix_truth["accounting"]["remaining_reserve_sompi"] > 0, "truncation fixture")
    try:
        validate_generated(truncated, prefix_truth)
    except ValueError:
        tests.append("reject-financially-consistent-incomplete-drainage")
    else:
        raise ValueError("accepted incomplete drainage")
    import population_privacy_model as full
    view = make_view(p, t, list(ADVERSARIES))
    full.validate(p, view)
    consistency = full.validate_truth(p, view, t)
    need(consistency["complete"] and consistency["cp_sat"] == consistency["z3"] == "SAT",
         "development full truth inclusion")
    tests.append("full-original-cp-sat-and-z3-pinned-development-truth")
    return dict(passed=True, complete=True, controls=tests, truth_consistency=consistency,
                development_seed=DEVELOPMENT_SEED,
                scope="published development fixtures only; no held-out seeds or predictions")
