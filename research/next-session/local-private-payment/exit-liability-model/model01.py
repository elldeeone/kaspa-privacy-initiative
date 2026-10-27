"""Offline finite accounting only. All symbols/data are public synthetic constants.

No file access, networking, wallet/proof/native imports or cryptography. Load
source only through unchanged root helper09; see RUN-01.md.
"""
from collections import deque
from dataclasses import dataclass, replace, asdict
from itertools import product

MAX = (1 << 64) - 1
VALUES = (3, 5, 7)
OWNERS = (0, 1, 0)
DOMAIN = ("SYNTHETIC-chain", "SYNTHETIC-pool", "withdrawal")
DIRECT_FEE = 2
ENVIRONMENTS = tuple(product((True, False), repeat=4))
ENVIRONMENTS = tuple((*bits, quote) for bits in ENVIRONMENTS for quote in (1, 2, 3))
AVAILABLE = (True, True, True, True, 1)
MUTANTS = ("omit-conversion-nf", "omit-funded-escrow", "drop-ticket",
           "double-settlement-fee", "global-only-fees", "omit-paid",
           "root-local-id", "historical-paid", "overwrite-paid",
           "wrong-destination", "wrong-gross", "service-dependent")


class Violation(Exception):
    pass


def require(condition, why):
    if not condition:
        raise Violation(why)


def uint(x):
    return type(x) is int and 0 <= x <= MAX


def add(*xs):
    if not all(uint(x) for x in xs):
        return None
    total = sum(xs)
    return total if total <= MAX else None


def sub(a, b):
    return a - b if uint(a) and uint(b) and b <= a else None


def change(xs, i, value):
    return xs[:i] + (value,) + xs[i + 1:]


def increment(xs, i, value):
    return change(xs, i, xs[i] + value)


@dataclass(frozen=True)
class Config:
    settlement: tuple
    claim_fee: int


def configurations():
    return tuple(Config(fs, fc) for fs in product((0, 1), repeat=2) for fc in (1, 2))


@dataclass(frozen=True)
class Finance:
    private: int = 15
    escrow: int = 0
    nf: int = 0
    # Records: economic ID, owner, gross, exact fee, accepted creation identity.
    tickets: tuple = (None, None)
    root: tuple = ()
    paid: frozenset = frozenset()
    private_point: tuple = ("private-genesis",)
    outbox_point: tuple = ()
    payouts: tuple = (0, 0, 0)
    owner_payouts: tuple = (0, 0)
    settlement_fees: tuple = (0, 0, 0)
    claim_fees: tuple = (0, 0, 0)
    direct_fees: tuple = (0, 0, 0)


@dataclass(frozen=True)
class Ghost:
    # 0 private, 1 unpaid entitlement, 2 paid entitlement, 3 direct paid.
    status: tuple = (0, 0, 0)
    payouts: tuple = (0, 0, 0)
    owner_payouts: tuple = (0, 0)
    settlement_fees: tuple = (0, 0, 0)
    claim_fees: tuple = (0, 0, 0)
    direct_fees: tuple = (0, 0, 0)


@dataclass(frozen=True)
class Node:
    money: Finance = Finance()
    rights: Ghost = Ghost()
    ancestors: tuple = ()
    rolled: bool = False
    observed_conversion: bool = False
    orphan_creations: frozenset = frozenset()


@dataclass(frozen=True)
class Action:
    kind: str
    index: int = -1
    ids: tuple = (0, 1)
    fees: tuple = ()
    amount: object = 0
    fee: object = 0
    actor: int = -1
    destination: int = -1
    private_point: tuple = ()
    outbox_point: tuple = ()
    root: tuple = ()
    paid_view: frozenset = frozenset()
    creation: tuple = ()
    domain: tuple = DOMAIN
    authentic: bool = True
    label: str = ""


def economic_id(i):
    return DOMAIN[:2] + (f"NF{i}",)


def claim_action(c, s, i):
    record = s.tickets[i]
    return Action("claim", i, amount=VALUES[i] - c.settlement[i], fee=c.claim_fee,
                  actor=OWNERS[i], destination=OWNERS[i], root=s.root,
                  outbox_point=s.outbox_point, paid_view=s.paid,
                  creation=record[4] if record else ())


def direct_action(s, i):
    return Action("direct", i, amount=VALUES[i], fee=DIRECT_FEE,
                  actor=OWNERS[i], destination=OWNERS[i], private_point=s.private_point)


def paid_key(s, i, mutant):
    # The deliberately broken variant rekeys the SAME right at every paid root.
    return (s.outbox_point, economic_id(i)) if mutant == "root-local-id" else economic_id(i)


def candidate(c, s, a, env=AVAILABLE, mutant="", branch=False):
    """Candidate acceptance never reads Ghost or independently derived rights."""
    service, public, retained, prover, quote = env
    if a.domain != DOMAIN or not a.authentic:
        return None
    if a.kind == "convert":
        if not service or not (public or retained) or a.private_point != s.private_point:
            return None
        if a.ids != (0, 1) or len(set(a.ids)) != 2 or len(a.fees) != 2:
            return None
        if any(s.nf & (1 << i) for i in a.ids):
            return None
        if not all(uint(f) and f < VALUES[i] for i, f in enumerate(a.fees)):
            return None
        consent = a.fees == c.settlement
        if mutant == "global-only-fees":
            consent = sum(a.fees) == sum(c.settlement)
        if not consent:
            return None
        gross = tuple(VALUES[i] - a.fees[i] for i in range(2))
        principal, fees = add(*gross), add(*a.fees)
        debit = add(VALUES[0], VALUES[1])
        if mutant == "double-settlement-fee":
            debit = add(debit, fees)
        remaining = sub(s.private, debit)
        funded = add(s.escrow, principal)
        if remaining is None or funded is None:
            return None
        point = (s.private_point, branch, "accepted-conversion")
        records = tuple((economic_id(i), OWNERS[i], gross[i], c.claim_fee, point)
                        for i in range(2))
        root = tuple(r[:4] for r in records)
        tickets = (None, records[1]) if mutant == "drop-ticket" else records
        return replace(s, private=remaining,
                       escrow=funded - (1 if mutant == "omit-funded-escrow" else 0),
                       nf=s.nf if mutant == "omit-conversion-nf" else s.nf | 3,
                       tickets=tickets, root=root, private_point=point,
                       outbox_point=(point, "outbox"),
                       settlement_fees=(a.fees[0], a.fees[1], 0))
    if a.kind == "direct":
        i = a.index
        if i not in range(3) or not (public or retained) or not prover:
            return None
        if a.private_point != s.private_point or s.nf & (1 << i):
            return None
        if a.actor != OWNERS[i] or a.destination != OWNERS[i]:
            return None
        if not uint(a.amount) or a.amount != VALUES[i] or not uint(a.fee):
            return None
        if a.fee != DIRECT_FEE or a.fee < quote or a.amount <= a.fee:
            return None
        remaining = sub(s.private, a.amount)
        if remaining is None:
            return None
        payout = a.amount - a.fee
        return replace(s, private=remaining, nf=s.nf | (1 << i),
                       private_point=(s.private_point, branch, "direct", i),
                       payouts=increment(s.payouts, i, payout),
                       owner_payouts=increment(s.owner_payouts, a.destination, payout),
                       direct_fees=increment(s.direct_fees, i, a.fee))
    if a.kind == "claim":
        i = a.index
        if i not in range(2) or not (public or retained):
            return None
        if mutant == "service-dependent" and not service:
            return None
        record = s.tickets[i]
        if record is None or a.root != s.root or a.creation != record[4]:
            return None
        if a.outbox_point != s.outbox_point or a.actor != record[1]:
            return None
        if a.paid_view != s.paid and mutant != "historical-paid":
            return None
        if a.destination != record[1] and mutant != "wrong-destination":
            return None
        if a.destination not in (0, 1):
            return None
        if not uint(a.amount) or (a.amount != record[2] and mutant != "wrong-gross"):
            return None
        if not uint(a.fee) or a.fee != record[3] or a.fee < quote or a.amount <= a.fee:
            return None
        key = paid_key(s, i, mutant)
        seen = a.paid_view if mutant == "historical-paid" else s.paid
        if key in seen and mutant != "omit-paid":
            return None
        remaining = sub(s.escrow, a.amount)
        if remaining is None:
            return None
        paid = s.paid | {key}
        if mutant == "omit-paid":
            paid = s.paid
        if mutant == "overwrite-paid":
            paid = frozenset({key})
        payout = a.amount - a.fee
        return replace(s, escrow=remaining, paid=frozenset(paid),
                       outbox_point=(s.outbox_point, branch, "claim", i),
                       payouts=increment(s.payouts, i, payout),
                       owner_payouts=increment(s.owner_payouts, a.destination, payout),
                       claim_fees=increment(s.claim_fees, i, a.fee))
    return None


def independent_advance(c, g, a):
    """Direct per-origin rights accounting, with no candidate helpers/state."""
    status = list(g.status)
    payout, owner = list(g.payouts), list(g.owner_payouts)
    settlement, claim, direct = list(g.settlement_fees), list(g.claim_fees), list(g.direct_fees)
    if a.kind == "convert":
        require(a.ids == (0, 1) and len(set(a.ids)) == 2, "duplicate-conversion-origin")
        require(a.fees == c.settlement, "unauthorized-per-owner-settlement-fee")
        for i in (0, 1):
            require(status[i] == 0, "same-note-consumed-twice")
            status[i] = 1
            settlement[i] = c.settlement[i]
    elif a.kind == "direct":
        i = a.index
        require(status[i] == 0, "direct-reuses-consumed-note")
        require(a.actor == OWNERS[i] and a.destination == OWNERS[i], "unauthorized-direct-payout")
        require(a.amount == VALUES[i] and a.fee == 2, "wrong-direct-value-or-fee")
        status[i] = 3
        payout[i] = VALUES[i] - 2
        owner[OWNERS[i]] += payout[i]
        direct[i] = 2
    elif a.kind == "claim":
        i = a.index
        require(status[i] == 1, "same-entitlement-paid-twice")
        gross = VALUES[i] - c.settlement[i]
        require(a.actor == OWNERS[i] and a.destination == OWNERS[i], "claim-recipient-substitution")
        require(a.amount == gross and a.fee == c.claim_fee, "claim-principal-or-fee-substitution")
        require(gross > c.claim_fee, "nonpositive-claim-payout")
        status[i] = 2
        payout[i] = gross - c.claim_fee
        owner[OWNERS[i]] += payout[i]
        claim[i] = c.claim_fee
    return Ghost(tuple(status), tuple(payout), tuple(owner), tuple(settlement), tuple(claim), tuple(direct))


def audit(c, s, g, mutant=""):
    amounts = (s.private, s.escrow, *s.payouts, *s.owner_payouts,
               *s.settlement_fees, *s.claim_fees, *s.direct_fees)
    require(all(type(x) is int and 0 <= x <= MAX for x in amounts), "invalid-native-integer")
    live = sum(VALUES[i] for i in range(3) if g.status[i] == 0)
    unpaid = sum(VALUES[i] - c.settlement[i] for i in range(2) if g.status[i] == 1)
    require(s.private == live, "private-reserve-does-not-match-private-rights")
    require(s.escrow == unpaid, "funded-escrow-does-not-match-unpaid-liabilities")
    for i in range(2):
        converted = g.status[i] in (1, 2)
        require((s.tickets[i] is not None) == converted, "missing-or-extra-economic-ticket")
        if converted:
            require(s.tickets[i][:4] == (DOMAIN[:2] + (f"NF{i}",), OWNERS[i],
                                        VALUES[i] - c.settlement[i], c.claim_fee),
                    "ticket-identity-owner-value-fee-changed")
    for name in ("payouts", "owner_payouts", "settlement_fees", "claim_fees", "direct_fees"):
        require(getattr(s, name) == getattr(g, name), "origin-or-recipient-" + name)
    fees = sum(g.settlement_fees) + sum(g.claim_fees) + sum(g.direct_fees)
    require(s.private + s.escrow + sum(s.payouts) + fees == 15, "total-native-conservation")
    for i in range(3):
        outstanding = VALUES[i] if g.status[i] == 0 else (
            VALUES[i] - c.settlement[i] if g.status[i] == 1 else 0)
        require(outstanding + g.payouts[i] + g.settlement_fees[i] +
                g.claim_fees[i] + g.direct_fees[i] == VALUES[i], "per-origin-conservation")
        if g.status[i] != 0:
            require(bool(s.nf & (1 << i)), "consumed-note-nf-still-unspent")
    for i in range(2):
        if g.status[i] == 2:
            require(paid_key(s, i, mutant) in s.paid, "paid-economic-id-redeemable-at-current-root")


def proposals(c, s, orphans=()):
    base = Action("convert", fees=c.settlement, private_point=s.private_point)
    yield base
    yield replace(base, ids=(0, 0), label="duplicate-NF")
    yield replace(base, private_point=("stale",), label="stale-private")
    yield replace(base, authentic=False, label="unproved-consent")
    yield replace(base, domain=("foreign",) + DOMAIN[1:], label="foreign-pool")
    if sum(c.settlement):
        moved = (sum(c.settlement), 0) if c.settlement[1] else (0, sum(c.settlement))
        if moved != c.settlement:
            yield replace(base, fees=moved, label="same-total-owner-fee-substitution")
    for i in range(3):
        a = direct_action(s, i)
        yield a
        yield replace(a, actor=1 - OWNERS[i], label="wrong-direct-signer")
        yield replace(a, private_point=("stale",), label="stale-direct-point")
    for i in range(2):
        a = claim_action(c, s, i)
        yield a
        yield replace(a, destination=1 - OWNERS[i], label="wrong-destination")
        yield replace(a, amount=a.amount + 1, label="wrong-gross")
        yield replace(a, fee=c.claim_fee + 1, label="changed-owner-fee")
        yield replace(a, actor=1 - OWNERS[i], label="wrong-claim-signer")
        yield replace(a, outbox_point=("stale",), label="stale-outbox-point")
        yield replace(a, root=tuple(reversed(s.root)) or ("foreign",), label="remapped-root")
        yield replace(a, paid_view=frozenset(), label="historical-paid-view")
        yield replace(a, domain=DOMAIN[:2] + ("private-spend",), label="wrong-role")
        for old in orphans:
            yield replace(a, creation=old, label="orphan-checkpoint")


def financial_successor(c, n, a, next_money):
    rights = independent_advance(c, n.rights, a)
    return Node(next_money, rights, n.ancestors + ((n.money, n.rights),), n.rolled,
                n.observed_conversion or a.kind == "convert", n.orphan_creations)


def rollbacks(n):
    if n.rolled:
        return
    for index, (money, rights) in enumerate(n.ancestors):
        removed = frozenset(r[4] for r in n.money.tickets if r is not None and
                            not any(t is not None and t[4] == r[4] for t in money.tickets))
        yield index, Node(money, rights, n.ancestors[:index], True,
                          n.observed_conversion, n.orphan_creations | removed)


def brief(n):
    s = n.money
    return {"private": s.private, "funded_escrow": s.escrow, "NF": s.nf,
            "rights": n.rights.status, "payouts": s.payouts,
            "settlement_fees": s.settlement_fees, "claim_fees": s.claim_fees,
            "direct_fees": s.direct_fees, "paid_ids": sorted(map(repr, s.paid)),
            "rolled": n.rolled, "observed_conversion": n.observed_conversion,
            "orphan_checkpoint_count": len(n.orphan_creations)}


def describe(a):
    return {"kind": a.kind, "index": a.index, "label": a.label,
            "fees": a.fees, "amount": a.amount, "fee": a.fee,
            "destination": a.destination}


def trace(parents, n):
    out = []
    while parents[n] is not None:
        previous, event = parents[n]
        out.append(event)
        n = previous
    return list(reversed(out))


def explore(c, mutant=""):
    start = Node()
    queue = deque([start])
    parents = {start: None}
    counts = {"financial_states": 0, "financial_edges": 0, "rollback_edges": 0,
              "environment_product_states": 0, "accepted_product_edges": 0,
              "rejected_product_proposals": 0, "rollback_environment_products": 0}
    witnesses = {}
    try:
        while queue:
            n = queue.popleft()
            counts["financial_states"] += 1
            audit(c, n.money, n.rights, mutant)
            actions = tuple(proposals(c, n.money, n.orphan_creations))
            for env in ENVIRONMENTS:
                counts["environment_product_states"] += 1
                service, public, retained, prover, quote = env
                for i, status in enumerate(n.rights.status):
                    if status == 1:
                        gross = VALUES[i] - c.settlement[i]
                        eligible = (public or retained) and c.claim_fee >= quote and gross > c.claim_fee
                        a = claim_action(c, n.money, i)
                        offered = candidate(c, n.money, a, env, mutant, n.rolled)
                        require(not eligible or offered is not None, "viable-accepted-ticket-service-dependence")
                        if not eligible:
                            reason = ("missing-data" if not (public or retained) else
                                      "nonpositive-payout" if gross <= c.claim_fee else "fee-rise")
                            witnesses.setdefault(reason, {"trace": trace(parents, n), "state": brief(n), "env": env, "ticket": i})
                    elif status == 0 and not service:
                        eligible = (public or retained) and prover and DIRECT_FEE >= quote
                        a = direct_action(n.money, i)
                        offered = candidate(c, n.money, a, env, mutant, n.rolled)
                        require(not eligible or offered is not None, "independent-direct-fallback-removed")
                        key = "preconversion-service-loss-direct-available" if eligible else "preconversion-fallback-blocked"
                        if n.rights.status[:2] == (0, 0):
                            witnesses.setdefault(key, {"trace": trace(parents, n), "state": brief(n), "env": env, "note": i})
                for a in actions:
                    next_money = candidate(c, n.money, a, env, mutant, n.rolled)
                    if next_money is None:
                        counts["rejected_product_proposals"] += 1
                        continue
                    counts["accepted_product_edges"] += 1
                    rights = independent_advance(c, n.rights, a)
                    audit(c, next_money, rights, mutant)
                    if env != AVAILABLE:
                        continue
                    nxt = financial_successor(c, n, a, next_money)
                    counts["financial_edges"] += 1
                    if nxt not in parents:
                        parents[nxt] = (n, describe(a))
                        queue.append(nxt)
            for index, nxt in rollbacks(n):
                require(nxt.observed_conversion == n.observed_conversion, "rollback-erases-observer-knowledge")
                audit(c, nxt.money, nxt.rights, mutant)
                counts["rollback_edges"] += 1
                counts["rollback_environment_products"] += len(ENVIRONMENTS)
                if n.observed_conversion and not any(nxt.money.tickets):
                    witnesses.setdefault("rollback-orphans-conversion", {"trace": trace(parents, n) + [{"rollback_to_ancestor": index}], "state": brief(nxt)})
                if nxt not in parents:
                    parents[nxt] = (n, {"rollback_to_ancestor": index})
                    queue.append(nxt)
        return {"complete": True, "config": asdict(c), "mutant": mutant,
                "counts": counts, "liveness_witnesses": witnesses}
    except Violation as error:
        return {"complete": False, "config": asdict(c), "mutant": mutant,
                "violation": str(error), "counts": counts,
                "trace": trace(parents, n), "state": brief(n),
                "attempt": describe(a) if "a" in locals() else None,
                "environment": env if "env" in locals() else None}


def directed_controls(c):
    n = Node()
    conversion = Action("convert", fees=c.settlement, private_point=n.money.private_point)
    made = candidate(c, n.money, conversion)
    require(made is not None, "directed-conversion-rejected")
    out = {}
    for order in ((0, 1), (1, 0)):
        current = financial_successor(c, n, conversion, made)
        events = [describe(conversion)]
        for i in order:
            a = claim_action(c, current.money, i)
            nxt = candidate(c, current.money, a, (False, True, False, False, 1))
            if VALUES[i] - c.settlement[i] <= c.claim_fee:
                require(nxt is None, "nonpositive-payout-accepted")
                events.append({"claim": i, "expected_liveness_failure": "nonpositive-payout"})
                continue
            require(nxt is not None, "claim-order-or-service-dependence")
            current = financial_successor(c, current, a, nxt)
            audit(c, current.money, current.rights)
            events.append(describe(a))
        a = direct_action(current.money, 2)
        nxt = candidate(c, current.money, a, (False, True, False, True, 1))
        require(nxt is not None, "third-private-note-stranded")
        current = financial_successor(c, current, a, nxt)
        audit(c, current.money, current.rights)
        out[str(order)] = {"trace": events + [describe(a)], "final": brief(current)}
    require(candidate(c, made, direct_action(made, 0)) is None, "conversion-then-direct-race")
    direct = candidate(c, n.money, direct_action(n.money, 0))
    require(candidate(c, direct, replace(conversion, private_point=direct.private_point)) is None,
            "direct-then-conversion-race")
    unrelated = Action("claim", 2, amount=VALUES[2], fee=c.claim_fee,
                       actor=OWNERS[2], destination=OWNERS[2], root=made.root,
                       outbox_point=made.outbox_point, creation=made.tickets[0][4])
    require(candidate(c, made, unrelated) is None, "still-private-NF2-claimed-as-ticket")
    converted_node = financial_successor(c, n, conversion, made)
    rollback_index, rolled = next(rollbacks(converted_node))
    require(rollback_index == 0 and rolled.observed_conversion,
            "directed-rollback-erases-observation")
    replacement_conversion = replace(conversion, private_point=rolled.money.private_point)
    replacement = candidate(c, rolled.money, replacement_conversion, branch=True)
    require(replacement is not None and replacement.tickets[0][0] == made.tickets[0][0],
            "economic-ticket-id-changes-across-fork")
    orphan = replace(claim_action(c, replacement, 0), creation=made.tickets[0][4])
    for env in ENVIRONMENTS:
        require(candidate(c, replacement, orphan, env) is None,
                "orphan-creation-authorizes-replacement-outbox")
    malformed = (False, True, -1, 0, MAX, MAX + 1, 1.0, "3", None)
    rejected = 0
    for value in malformed:
        a = replace(direct_action(n.money, 0), amount=value)
        require(candidate(c, n.money, a) is None, "invalid-amount-or-wrong-principal-accepted")
        rejected += 1
    require(uint(MAX) and not uint(MAX + 1) and not uint(True), "wire-range-guard")
    require(add(MAX, 0) == MAX and add(MAX, 1) is None and sub(0, 1) is None,
            "checked-arithmetic-boundaries")
    return {"claim_orders_and_third_note": out, "direct_conversion_orders_rejected": 2,
            "invalid_amount_or_wrong_principal_rejections": rejected,
            "valid_uint_MAX_rejected_as_wrong_principal": True,
            "still_private_NF2_claim_rejected": True,
            "replacement_fork_keeps_economic_id": True,
            "orphan_creation_rejections_across_environments": len(ENVIRONMENTS),
            "checked_u64_boundary_controls": True}


def run():
    """Exhaustive correct cases, then each frozen mutant to first counterexample."""
    correct = []
    for c in configurations():
        result = explore(c)
        correct.append(result)
        if not result["complete"]:
            return {"status": "STOP-correct-model-violation", "correct": correct}
    mutants = []
    for name in MUTANTS:
        examined = 0
        for c in configurations():
            examined += 1
            result = explore(c, name)
            if not result["complete"]:
                result["configurations_examined"] = examined
                mutants.append(result)
                break
        else:
            return {"status": "STOP-undetected-mutant", "name": name,
                    "correct": correct, "mutants": mutants}
    return {"status": "complete-bounded-model", "correct": correct, "mutants": mutants,
            "directed_controls": [directed_controls(c) for c in configurations()],
            "boundaries": "Ideal oracles only; no native/proof/fee/privacy/recovery qualification."}
