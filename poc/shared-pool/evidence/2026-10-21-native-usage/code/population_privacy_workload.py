"""Modeled population workloads and participant records; no native transactions.

No workload is generated on import. Held-out callers must first freeze the spec,
source and dependencies, then preserve their private seed bundle and every arm,
including failed prefixes. Only controls() uses small explicit development data.
"""
import copy
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
import hashlib
import itertools
import json

SOMPI = 100_000_000
FEE = 40_000_000
FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
MAX = 2_900_000_000_000_000_000
TREE_LIMIT = 65_536
NULLIFIER_LIMIT = 131_072
ROLES = list(range(32))
ADVERSARIES = list(range(8))
FIRST = [0, 1, 2, 3] + list(range(8, 20))
SECOND = [r for r in ROLES if r not in FIRST]
BALANCES = [v * SOMPI for v in (2500, 5000, 10000, 20000)]
PUBLIC_SCHEMA = "kpi-population-public-v1"
VIEW_SCHEMA = "kpi-population-view-v1"
TRUTH_SCHEMA = "kpi-population-truth-v1"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, lower=0, upper=MAX):
    need(type(value) is int and lower <= value <= upper, "integer/range")
    return value


def public_digest(public):
    return hashlib.sha256(json.dumps(
        public, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Stream:
    """Specified private sampler: SHAKE256(domain || key || u64 counter).

    Each draw takes one 256-bit block. Bounded draws reject the high incomplete
    interval, and Fisher-Yates uses these unbiased bounded draws. Domains have a
    length prefix. This is deterministic experiment sampling, not wallet crypto.
    """
    def __init__(self, key, domain):
        need(isinstance(key, bytes) and len(key) == 32, "32-byte stream seed")
        label = domain.encode("ascii")
        self.prefix = b"kpi-population-sampler-v1" + len(label).to_bytes(2, "big") + label + key
        self.counter = 0

    def block(self):
        result = hashlib.shake_256(self.prefix + self.counter.to_bytes(8, "big")).digest(32)
        self.counter += 1
        return result

    def below(self, bound):
        integer(bound, 1, 2**256)
        limit = 2**256 - (2**256 % bound)
        while True:
            draw = int.from_bytes(self.block(), "big")
            if draw < limit:
                return draw % bound

    def shuffle(self, values):
        values = list(values)
        for i in range(len(values) - 1, 0, -1):
            j = self.below(i + 1)
            values[i], values[j] = values[j], values[i]
        return values

    def choose(self, values):
        need(bool(values), "empty choice")
        return values[self.below(len(values))]


class Labels:
    """Opaque labels use the independent opaque seed, never request RNG state."""
    def __init__(self, key, domain):
        self.stream = Stream(key, "opaque/" + domain)
        self.seen = set()

    def new(self):
        value = self.stream.block().hex()
        need(value != "00" * 32 and value not in self.seen, "opaque label collision")
        self.seen.add(value)
        return value


def log_amount(stream):
    """Round a 64-bit uniform log draw to sompi, with an explicit decimal rule.

    u = uint64/(2**64-1); value = 10 tKAS * exp(u*ln(100)).
    Decimal precision is 80; round once to integer sompi, ties to even.
    Endpoints are included. There is no denomination rounding or resampling.
    """
    draw = stream.below(2**64)
    with localcontext() as context:
        context.prec = 80
        context.rounding = ROUND_HALF_EVEN
        u = Decimal(draw) / Decimal(2**64 - 1)
        amount = Decimal(10 * SOMPI) * (u * Decimal(100).ln()).exp()
        result = int(amount.to_integral_value(rounding=ROUND_HALF_EVEN))
    return integer(result, 10 * SOMPI, 1000 * SOMPI)


def _plan(request_seed, regime):
    need(regime in ("overlap", "sparse"), "regime must be overlap or sparse")
    capital = Stream(request_seed, "capital")
    ordering = Stream(request_seed, "request-order")
    honest = Stream(request_seed, "honest-requests")
    active = Stream(request_seed, "nonadaptive-active-requests")
    drainage = Stream(request_seed, "final-role-order")
    balances = [capital.choose(BALANCES) for _ in ROLES]
    requests = []
    minute = 0
    for cohort, admitted, round_number in ((FIRST, FIRST, 0), (SECOND, ROLES, 0),
                                           (ROLES, ROLES, 1)):
        if round_number == 1 and regime == "sparse":
            minute += 60
        for sender in ordering.shuffle(cohort):
            minute += 1
            if sender in ADVERSARIES:
                recipient = active.choose([r for r in admitted if r not in ADVERSARIES])
                amount = (100 if round_number == 0 else 200) * SOMPI + (sender + 1) * 1000
            else:
                recipient = honest.choose([r for r in admitted if r != sender])
                amount = log_amount(honest)
            requests.append(dict(sender=sender, recipient=recipient, amount=amount,
                                 round=round_number, minute=minute))
    return balances, requests, drainage.shuffle(ROLES)


def select_inputs(values, owners, spent, sender, amount, fee=FEE, floor=FLOOR):
    """Declared modeled selector, not an implemented automatic wallet feature."""
    integer(amount, floor)
    available = [p for p, value in enumerate(values)
                 if owners[p] == sender and value > 0 and p not in spent]
    choices = []
    for size in (1, 2):
        for positions in itertools.combinations(available, size):
            excess = sum(values[p] for p in positions) - amount - fee
            if excess == 0 or excess >= floor:
                choices.append((excess, size, positions))
    need(bool(choices), "request cannot be funded by one or two owned notes")
    return list(min(choices)[2])


class Ledger:
    """Concrete bookkeeping model. Hidden ownership never enters public labels."""
    def __init__(self, balances, funding, contacts, opaque_seed, arm,
                 roles=ROLES, adversaries=ADVERSARIES):
        self.roles = list(roles)
        self.adversaries = list(adversaries)
        self.balances = list(balances)
        need(self.roles == list(range(len(self.roles))) and len(balances) == len(roles),
             "development/full population shape")
        need(set(adversaries) <= set(roles), "adversaries")
        for value in balances:
            integer(value, FLOOR, MAX - FEE)
        self.labels = Labels(opaque_seed, arm)
        self.funding = dict(funding)
        self.contacts = dict(contacts)
        need(set(funding) == set(roles) and set(contacts.values()) == set(roles),
             "directory population")
        need(len(set(funding.values())) == len(roles) and len(contacts) == len(roles),
             "distinct funding/contact identities")
        self.values = [balances[0] + FEE]
        self.owners = [0]
        self.spent = set()
        self.admitted = {0}
        self.commitments = [self.labels.new()]
        self.events = []
        self.hidden = []
        self.inputs = {}
        self.reserve = self.values[0]
        self.nf_count = 1
        self.history_count = 1
        self.initial = dict(id=self.labels.new(), value=self.reserve, funding_group=funding[0])

    def append(self, mode, sender, positions, outputs, minute, kind,
               request=None, amount=None):
        integer(sender, 0, len(self.roles) - 1)
        integer(minute)
        need(mode in (0, 1, 2) and self.reserve > 0, "mode/terminal")
        need(not self.events or minute >= self.events[-1]["minute"], "chronology")
        before = len(self.values)
        need(len(positions) == len(set(positions)), "duplicate input")
        for p in positions:
            integer(p, 0, before - 1)
            need(p not in self.spent and self.owners[p] == sender and self.values[p] >= FLOOR,
                 "spent/foreign/zero input")
        for value, owner in outputs:
            integer(value)
            need(value == 0 or value >= FLOOR, "output note floor")
            need((owner is None) == (value == 0), "zero ownership")
            if owner is not None:
                integer(owner, 0, len(self.roles) - 1)
                need(owner in self.admitted or (mode == 0 and owner == sender), "recipient admission")
        deposit = payout = 0
        total = sum(self.values[p] for p in positions)
        integer(total)
        nf_count, history_count = self.nf_count, self.history_count
        if mode == 0:
            need(bool(self.events) and not positions and sender not in self.admitted,
                 "admission context")
            need(outputs == [(self.balances[sender], sender), (0, None)], "admission shape")
            deposit = self.balances[sender] + FEE
            integer(self.reserve + deposit)  # Current wallet bounds the pre-fee input sum.
        else:
            need(1 <= len(positions) <= 2 and sender in self.admitted, "real input count")
            if mode == 1:
                need(len(outputs) == 2 and outputs[0][0] >= FLOOR, "payment outputs")
                need(outputs[1][0] == 0 or outputs[1][1] == sender, "sender change")
                need(total == sum(v for v, _ in outputs) + FEE, "private conservation")
            else:
                need(not outputs, "exit outputs")
                payout = total - FEE
                integer(payout, PAYOUT_FLOOR)
            nf_count += 2  # v6 has two positioned real-or-dummy nullifiers.
            need(nf_count <= NULLIFIER_LIMIT, "nullifier capacity")
        new = [] if mode == 2 else [before, before + 1]
        if mode != 2:
            need(len(outputs) == 2 and before + 2 < TREE_LIMIT, "commitment capacity")
            history_count += 1
            need(history_count <= TREE_LIMIT, "history capacity")
        reserve_out = self.reserve + deposit - payout - FEE
        integer(reserve_out)
        need(reserve_out > 0 or mode == 2, "terminal mode")
        need(sum(v for p, v in enumerate(self.values)
                 if p not in self.spent and p not in positions)
             + sum(v for v, _ in outputs) == reserve_out, "liabilities/native reserve mismatch")
        index = len(self.events)
        event = dict(id=self.labels.new(), minute=minute, mode=mode,
                     anchor_count=0 if mode == 0 else before, count_before=before,
                     new=new, fee=FEE, deposit=deposit, payout=payout,
                     reserve_out=reserve_out,
                     destination=self.labels.new() if payout else None,
                     funding_group=self.funding[sender] if mode == 0 else None)
        commitments = [self.labels.new() for _ in outputs]
        self.events.append(event)
        self.hidden.append(dict(sender=sender,
                                recipient=outputs[0][1] if kind == "payment" else None,
                                kind=kind, request=request, amount=amount))
        self.inputs[str(index)] = list(positions)
        self.spent.update(positions)
        if mode == 0:
            self.admitted.add(sender)
        self.nf_count, self.history_count = nf_count, history_count
        for value, owner in outputs:
            self.values.append(value)
            self.owners.append(owner)
        self.commitments.extend(commitments)
        self.reserve = reserve_out
        return new

    def bootstrap(self):
        self.append(1, 0, [0], [(self.balances[0], 0), (0, None)], 0, "bootstrap")

    def admit(self, role, minute):
        self.append(0, role, [], [(self.balances[role], role), (0, None)],
                    minute, "admit")

    def pay(self, request, request_index, prompt):
        sender, recipient, amount = (request[k] for k in ("sender", "recipient", "amount"))
        positions = select_inputs(self.values, self.owners, self.spent, sender, amount)
        change = sum(self.values[p] for p in positions) - amount - FEE
        new = self.append(1, sender, positions,
                          [(amount, recipient), (change, sender if change else None)],
                          request["minute"], "payment", request_index, amount)
        if prompt:
            self.append(2, recipient, [new[0]], [], request["minute"], "prompt_exit")

    def drain(self, order, minute):
        for role in order:
            remaining = [p for p, v in enumerate(self.values)
                         if v and self.owners[p] == role and p not in self.spent]
            for i in range(0, len(remaining), 2):
                minute += 1
                self.append(2, role, remaining[i:i + 2], [], minute, "final_exit")
        need(self.reserve == 0, "incomplete drainage")

    def public(self):
        observed = {self.initial["funding_group"]}
        observed.update(e["funding_group"] for e in self.events if e["mode"] == 0)
        return dict(
            schema=PUBLIC_SCHEMA, roles=self.roles, adversaries=self.adversaries,
            algebra=dict(schema="kpi-h14-public-v1", initial=self.initial, events=self.events),
            commitments=self.commitments,
            funding_owners={group: role for role, group in self.funding.items() if group in observed},
            bootstrap_self=True,
            modeled=dict(kind="synthetic-wallet-history", timing="modeled-minute-slots",
                         receive_contacts=self.contacts, floor_sompi=FLOOR,
                         payout_floor_sompi=PAYOUT_FLOOR, fee_sompi=FEE,
                         cryptographic_identifiers="independent-opaque-random-labels",
                         selection_policy="least-excess-fewest-inputs-lexicographic",
                         population=len(self.roles)))

    def truth(self, requests, regime, arm):
        return dict(schema=TRUTH_SCHEMA, values=self.values, owners=self.owners,
                    inputs=self.inputs, events=self.hidden, requests=requests,
                    starting_balances=self.balances, regime=regime, arm=arm,
                    accounting=accounting(self.public(), self.values, self.owners,
                                          self.inputs, self.hidden))


def accounting(public, values, owners, inputs, hidden):
    """Rewalk concrete truth independently of Ledger's incremental spent set."""
    events = public["algebra"]["events"]
    need(len(events) == len(hidden) and len(values) == len(owners) == len(public["commitments"]),
         "accounting shape")
    need(set(inputs) == {str(i) for i in range(len(events))}, "accounting input framing")
    for value, owner in zip(values, owners, strict=True):
        integer(value)
        need((value == 0 and owner is None) or
             (value >= FLOOR and type(owner) is int and owner in public["roles"]),
             "accounting value/owner domain")
    spent = set()
    before = 1
    reserve = public["algebra"]["initial"]["value"]
    need(values[0] == reserve and owners[0] ==
         public["funding_owners"][public["algebra"]["initial"]["funding_group"]],
         "accounting initial owner/value")
    funding = [0] * len(public["roles"])
    funding[public["funding_owners"][public["algebra"]["initial"]["funding_group"]]] = reserve
    payment_values = [0] * len(funding)
    operations = [0] * len(funding)
    payouts = [0] * len(funding)
    fees = 0
    for i, (event, private) in enumerate(zip(events, hidden, strict=True)):
        owner = private["sender"]
        need(type(owner) is int and owner in public["roles"], "accounting author")
        selected = inputs[str(i)]
        need(event["count_before"] == before, "accounting count")
        need(len(set(selected)) == len(selected), "accounting duplicate input")
        need(all(0 <= p < before and p not in spent and owners[p] == owner
                 and values[p] >= FLOOR for p in selected), "accounting invalid input")
        created = event["new"]
        need(created == ([] if event["mode"] == 2 else [before, before + 1]),
             "accounting output positions")
        if event["mode"] == 0:
            need(not selected and values[created[0]] == event["deposit"] - event["fee"]
                 and owners[created[0]] == owner and values[created[1]] == 0
                 and public["funding_owners"][event["funding_group"]] == owner,
                 "accounting admission")
            funding[owner] += event["deposit"]
        else:
            need(1 <= len(selected) <= 2, "accounting real inputs")
            need(sum(values[p] for p in selected) ==
                 sum(values[p] for p in created) + event["payout"] + event["fee"],
                 "accounting private conservation")
            if event["mode"] == 1:
                need(values[created[0]] >= FLOOR and
                     (values[created[1]] == 0 or owners[created[1]] == owner),
                     "accounting positive payment/sender change")
        spent.update(selected)
        before += len(created)
        reserve += event["deposit"] - event["payout"] - event["fee"]
        need(reserve == event["reserve_out"] ==
             sum(values[p] for p in range(before) if p not in spent), "accounting backing")
        fees += event["fee"]
        operations[owner] += 1
        payouts[owner] += event["payout"]
        if private["kind"] == "payment":
            need(private["amount"] == values[created[0]] and
                 private["recipient"] == owners[created[0]], "accounting payment truth")
            payment_values[owner] += private["amount"]
    need(before == len(values), "accounting extra positions")
    need(sum(funding) == sum(payouts) + fees + reserve, "accounting lifecycle")
    adversaries = public["adversaries"]

    def share(entries):
        return dict(adversary=sum(entries[r] for r in adversaries), total=sum(entries))

    return dict(native_funded_sompi=sum(funding), payouts_sompi=sum(payouts),
                pool_fees_sompi=fees, remaining_reserve_sompi=reserve,
                role_native_funding_sompi=funding, role_payment_value_sompi=payment_values,
                role_operations=operations, role_payouts_sompi=payouts,
                capital_share=share(funding), payment_value_share=share(payment_values),
                operation_share=share(operations))


def _seed(seed, name):
    value = seed[name]
    need(isinstance(value, str) and len(value) == 64, "private seed must be lowercase hex32")
    result = bytes.fromhex(value)
    need(result.hex() == value, "noncanonical private seed")
    return result


def generate(seed, regime):
    """Return paired histories; caller must privately preserve seed before calling.

    seed is {requests: hex32, opaque: independently sampled hex32}. Return
    {persistent: {public,truth,complete,error}, prompt: {...}}. An arm failure
    preserves its partial ledger and all unchanged requests, and never retries.
    """
    need(isinstance(seed, dict) and set(seed) == {"requests", "opaque"}, "seed bundle")
    request_seed, opaque_seed = _seed(seed, "requests"), _seed(seed, "opaque")
    need(request_seed != opaque_seed, "request and opaque seeds must be independent")
    balances, requests, drain_order = _plan(request_seed, regime)
    labels = Labels(opaque_seed, "directory")
    funding = {r: labels.new() for r in ROLES}
    contacts = {labels.new(): r for r in ROLES}
    arms = {}
    for arm in ("persistent", "prompt"):
        ledger = Ledger(balances, funding, contacts, opaque_seed, arm)
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
                ledger.pay(request, i, arm == "prompt")
            ledger.drain(drain_order, requests[-1]["minute"])
        except ValueError as failure:
            error = str(failure)
        arms[arm] = dict(public=copy.deepcopy(ledger.public()),
                         truth=copy.deepcopy(ledger.truth(requests, regime, arm)),
                         complete=error is None, error=error)
    return arms


def public_prefix(public, end):
    events = public["algebra"]["events"]
    integer(end, 0, len(events) - 1)
    result = copy.deepcopy(public)
    result["algebra"]["events"] = result["algebra"]["events"][:end + 1]
    last = events[end]
    result["commitments"] = result["commitments"][:last["count_before"] + len(last["new"])]
    groups = {public["algebra"]["initial"]["funding_group"]}
    groups.update(e["funding_group"] for e in events[:end + 1] if e["mode"] == 0)
    result["funding_owners"] = {k: v for k, v in public["funding_owners"].items() if k in groups}
    if "payout_owners" in result:
        destinations = {e["destination"] for e in events[:end + 1] if e["payout"]}
        result["payout_owners"] = {k: v for k, v in result["payout_owners"].items()
                                   if k in destinations}
    return result


def make_view(public, truth, members, end=None):
    """Complete participant records at a prefix; no counterparty sibling leaks."""
    need(isinstance(members, list) and len(set(members)) == len(members)
         and all(type(r) is int and r in public["roles"] for r in members), "view members")
    members = sorted(members)
    end = len(public["algebra"]["events"]) - 1 if end is None else end
    prefix = public_prefix(public, end)
    count = len(prefix["commitments"])
    receipts = [dict(owner=owner, position=p, value=truth["values"][p])
                for p, owner in enumerate(truth["owners"][:count])
                if owner in members and truth["values"][p] > 0]
    authored = []
    for i, private in enumerate(truth["events"][:end + 1]):
        if private["sender"] not in members:
            continue
        positions = prefix["algebra"]["events"][i]["new"]
        authored.append(dict(owner=private["sender"], event=i,
                             inputs=list(truth["inputs"][str(i)]),
                             outputs=[dict(position=p, value=truth["values"][p],
                                           recipient=truth["owners"][p]) for p in positions]))
    return dict(schema=VIEW_SCHEMA, public_sha256=public_digest(prefix),
                members=members, receipts=receipts, authored=authored)


def controls():
    """Explicit tiny development fixtures only; never calls held-out generate."""
    tests = []
    seed = bytes(range(32))
    labels = Labels(bytes(reversed(range(32))), "development-directory")
    roles = list(range(3))
    funding = {r: labels.new() for r in roles}
    contacts = {labels.new(): r for r in roles}
    ledger = Ledger([10 * SOMPI] * 3, funding, contacts, seed, "development",
                    roles=roles, adversaries=[0])
    ledger.bootstrap()
    ledger.admit(1, 0)
    ledger.admit(2, 0)
    request = dict(sender=0, recipient=1, amount=2 * SOMPI, round=0, minute=1)
    ledger.pay(request, 0, False)
    truth = ledger.truth([request], "development", "persistent")
    public = ledger.public()
    view = make_view(public, truth, [1])
    incoming = public["algebra"]["events"][3]["new"][0]
    need(any(r["position"] == incoming and r["value"] == 2 * SOMPI for r in view["receipts"])
         and all(a["event"] != 3 for a in view["authored"]), "recipient-only record")
    need(not any(r["position"] == incoming + 1 for r in view["receipts"]), "sibling leak")
    tests.append("recipient-only-not-author-or-sibling")
    early = make_view(public, truth, [1], 2)
    need(all(r["position"] < incoming for r in early["receipts"])
         and early["public_sha256"] == public_digest(public_prefix(public, 2)), "prefix leak")
    tests.append("prefix-disclosure-isolation")
    pooled = make_view(public, truth, roles)
    need(len(pooled["authored"]) == 4 and
         len(pooled["receipts"]) == sum(v > 0 for v in truth["values"]), "complete records")
    tests.append("complete-pooled-records")
    need(select_inputs([5 * SOMPI, 2 * SOMPI, 3 * SOMPI], [0, 0, 0], set(),
                       0, 460_000_000) == [0], "fewer-input tie")
    need(select_inputs([5 * SOMPI, 5 * SOMPI], [0, 0], set(),
                       0, 460_000_000) == [0], "lexicographic tie")
    need(select_inputs([5 * SOMPI, 6 * SOMPI], [0, 0], set(),
                       0, 470_000_000) == [1], "unsafe change")
    tests.append("least-excess-input-count-position-and-floor")
    try:
        select_inputs([SOMPI], [0], set(), 0, 2 * SOMPI)
    except ValueError:
        tests.append("unaffordable-request-rejected-without-resampling")
    else:
        raise ValueError("unaffordable request accepted")
    for name, sender, positions in (("foreign-input", 0, [incoming]),
                                    ("already-spent-input", 0, [0])):
        snapshot = copy.deepcopy(ledger.public())
        try:
            ledger.append(2, sender, positions, [], 2, "final_exit")
        except ValueError:
            need(ledger.public() == snapshot, "rejected input changed prefix")
            tests.append(name)
        else:
            raise ValueError("invalid input accepted")
    ledger.drain([2, 1, 0], 1)
    final = ledger.truth([request], "development", "persistent")
    need(final["accounting"]["remaining_reserve_sompi"] == 0 and
         any(len(p) == 2 for p in final["inputs"].values()), "two-input final exit")
    tests.append("two-input-exit-and-full-lifecycle-accounting")
    changed = copy.deepcopy(final["values"])
    changed[incoming] += 1
    try:
        accounting(ledger.public(), changed, final["owners"], final["inputs"], final["events"])
    except ValueError:
        tests.append("one-sompi-conservation-mutation")
    else:
        raise ValueError("conservation mutation accepted")

    class Endpoint:
        def __init__(self, value):
            self.value = value

        def below(self, bound):
            need(bound == 2**64, "amount sampler resolution")
            return self.value

    need(log_amount(Endpoint(0)) == 10 * SOMPI
         and log_amount(Endpoint(2**64 - 1)) == 1000 * SOMPI, "amount endpoints")
    tests.append("exact-decimal-sampler-endpoints")
    pair_requests = [request, dict(sender=1, recipient=2, amount=SOMPI, round=0, minute=2)]
    paired = {}
    for arm in ("persistent", "prompt"):
        instance = Ledger([10 * SOMPI] * 3, funding, contacts, seed, "development-" + arm,
                          roles=roles, adversaries=[0])
        instance.bootstrap()
        instance.admit(1, 0)
        instance.admit(2, 0)
        for i, item in enumerate(pair_requests):
            instance.pay(item, i, arm == "prompt")
        instance.drain([0, 1, 2], 2)
        paired[arm] = instance.truth(pair_requests, "development", arm)
    need(paired["persistent"]["requests"] == paired["prompt"]["requests"] and
         paired["persistent"]["starting_balances"] == paired["prompt"]["starting_balances"],
         "matched arms changed requests or capital")
    need(sum(e["kind"] == "prompt_exit" for e in paired["prompt"]["events"]) == 2 and
         all(v["accounting"]["remaining_reserve_sompi"] == 0 for v in paired.values()),
         "prompt receipts not exited or end reserve not drained")
    tests.append("matched-requests-capital-and-prompt-receipt-exits")
    before = copy.deepcopy(ledger.public())
    try:
        ledger.append(2, 0, [0], [], 100, "final_exit")
    except ValueError:
        need(ledger.public() == before, "failed transition changed public prefix")
        tests.append("failed-transition-preserves-prefix")
    else:
        raise ValueError("post-terminal spend accepted")
    boundary = Ledger([MAX - FLOOR, FLOOR, FLOOR], funding, contacts, seed,
                      "development-pre-fee-boundary", roles=roles, adversaries=[0])
    boundary.bootstrap()
    previous = copy.deepcopy(boundary.public())
    try:
        boundary.admit(1, 0)
    except ValueError:
        need(boundary.public() == previous, "over-range admission changed prefix")
        tests.append("pre-fee-native-input-range")
    else:
        raise ValueError("pre-fee input sum over MAX accepted")
    return dict(passed=True, controls=tests,
                scope="tiny explicit development fixtures only; no held-out request seed generated")
