"""Independent per-origin rights ledger; candidate guards never read this module."""
from dataclasses import replace
from model import Ghost, pending


class Violation(Exception):
    pass


def checked(condition, why):
    if not condition:
        raise Violation(why)


def advance(c, g, a):
    # Lists intentionally use a direct origin-ledger interpretation, rather than
    # candidate reserve arithmetic or candidate NF/root/paid representations.
    live, owners, claims = list(g.live), list(g.owners), list(g.claims)
    fees, source_paid, receiver_paid = list(g.fees), list(g.paid_origin), list(g.paid_owner)
    paid = g.paid
    if a.kind in ("spend", "accept", "reveal"):
        for index, fee in zip(a.ids, a.fees):
            checked(live[index] > 0, "same-private-resource-consumed-twice")
            checked(0 <= fee < live[index], "unauthorized-or-exhaustive-source-fee")
            fees[index // 2] += fee
            if a.kind == "spend":
                checked(a.actor == owners[index], "copied-private-credential-theft")
                checked(index % 2 == 0 and live[index + 1] == 0, "replacement-collision")
                live[index + 1], owners[index + 1] = live[index] - fee, a.recipient
            elif a.kind == "accept":
                checked(claims[index] == 0, "duplicate-economic-entitlement")
                claims[index] = live[index] - fee
            else:
                checked(a.actor == owners[index] and a.recipient == owners[index], "reveal-redirect")
                source_paid[index // 2] += live[index] - fee
                receiver_paid[owners[index]] += live[index] - fee
            live[index] = 0
    elif a.kind == "claim":
        index, = a.ids
        fee, = a.fees
        checked(claims[index] > 0 and not paid & (1 << index), "same-entitlement-paid-twice")
        checked(a.recipient == owners[index] and a.actor == owners[index], "wrong-claim-recipient")
        checked(0 < fee < claims[index], "fee-exhausted-nonpositive-payout")
        paid |= 1 << index
        fees[index // 2] += fee
        source_paid[index // 2] += claims[index] - fee
        receiver_paid[owners[index]] += claims[index] - fee
    return Ghost(tuple(live), tuple(owners), tuple(claims), paid,
                 tuple(source_paid), tuple(receiver_paid), tuple(fees))


def audit(c, s, g, mutant=""):
    checked(all(x >= 0 for x in (s.reserve, s.escrow, *s.paid_origin, *s.paid_owner, *s.fees)),
            "negative-native-amount")
    for origin, initial in enumerate(c.values):
        outstanding = sum(g.live[2 * origin:2 * origin + 2])
        unpaid = sum(q for i, q in enumerate(g.claims) if i // 2 == origin and not g.paid & (1 << i))
        checked(outstanding + unpaid + g.paid_origin[origin] + g.fees[origin] == initial,
                "origin-value-partition")
    # Native liabilities arise independently from live origin rights and immutable
    # unpaid entitlements. Native P2PK outputs have already left the pool.
    unpaid = sum(q for i, q in enumerate(g.claims) if not g.paid & (1 << i))
    expected_reserve = sum(g.live) + (unpaid if c.mode == "shared-root" else 0)
    expected_escrow = unpaid if c.mode == "native-p2pk" else 0
    checked(s.reserve == expected_reserve, "lost-or-excess-shared-backing")
    checked(s.escrow == expected_escrow, "lost-or-excess-native-ticket-value")
    checked(s.paid_origin == g.paid_origin and s.paid_owner == g.paid_owner, "native-payout-identity-or-value")
    checked(s.fees == g.fees, "fee-double-debit-or-hidden-subsidy")
    checked(s.reserve + s.escrow + sum(s.paid_origin) + sum(s.fees) == sum(c.values),
            "native-conservation")
    offered_private = sum(v for i, v in enumerate(s.values) if not s.nf & (1 << i))
    offered_claims = sum(s.claims[i] for i in pending(c, s, mutant))
    checked(offered_private + (offered_claims if c.mode == "shared-root" else 0) <= s.reserve,
            "currently-spendable-liabilities-exceed-reserve")
    if c.mode == "native-p2pk":
        checked(offered_claims <= s.escrow, "native-output-still-redeemable-after-payment")
