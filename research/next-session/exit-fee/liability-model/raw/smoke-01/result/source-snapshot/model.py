"""Finite symbolic accounting experiment. No cryptographic/native implementation."""
from dataclasses import dataclass, replace
from itertools import combinations, product

AVAILABLE = (True, True, True)  # acceptance service, public data, retained witness
ENVIRONMENTS = tuple(sorted(product((False, True), repeat=3),
                            key=lambda e: (e != AVAILABLE, e != (False, True, True), e)))
MODES = ("native-p2pk", "shared-root")
MUTANTS = ("omit-accept-nf", "drop-pending-backing", "omit-paid", "root-local-id",
           "historical-paid", "service-dependent", "redirect", "fee-exhaustion",
           "retire-pending", "amount", "missing-entitlement")

@dataclass(frozen=True, slots=True)
class Config:
    id: int
    mode: str
    values: tuple
    owners: tuple

@dataclass(frozen=True, slots=True)
class State:
    values: tuple
    owners: tuple
    nf: int = 0
    claims: tuple = (0,) * 6
    roots: tuple = ()
    spent: tuple = ()
    reserve: int = 0
    escrow: int = 0
    paid_origin: tuple = (0, 0, 0)
    paid_owner: tuple = (0, 0, 0)
    fees: tuple = (0, 0, 0)
    quote: int = 1
    retired: bool = False

@dataclass(frozen=True, slots=True)
class Ghost:
    """Origin ledger, never consulted by candidate acceptance/authorization."""
    live: tuple
    owners: tuple
    claims: tuple = (0,) * 6
    paid: int = 0
    paid_origin: tuple = (0, 0, 0)
    paid_owner: tuple = (0, 0, 0)
    fees: tuple = (0, 0, 0)

@dataclass(frozen=True, slots=True)
class Action:
    kind: str
    ids: tuple = ()
    fees: tuple = ()
    recipient: int = -1
    root: int = 0
    fresh: bool = True
    authentic: bool = True
    historical_paid: bool = False
    actor: int = -1
    amount: int = -1


def configs():
    out = []
    for entries in product(tuple(product((2, 3), (0, 1))), repeat=3):
        for mode in MODES:
            out.append(Config(len(out), mode, tuple(v for v, _ in entries),
                              tuple(o for _, o in entries)))
    assert len(out) == 128
    return out


def initial(c):
    values = tuple(c.values[i // 2] if i % 2 == 0 else 0 for i in range(6))
    owners = tuple(c.owners[i // 2] if i % 2 == 0 else -1 for i in range(6))
    return State(values, owners, reserve=sum(c.values)), Ghost(values, owners)


def update(values, index, value):
    out = list(values)
    out[index] = value
    return tuple(out)


def plus(values, index, value):
    return update(values, index, values[index] + value)


def claim_key(c, s, i, root, mutant):
    if c.mode == "shared-root" and mutant == "root-local-id":
        # Accepted cumulative sorted roots can move the same entitlement's index.
        return root * 8 + sum(bool((root >> (3 * j)) & 7) for j in range(i))
    return i


def is_unpaid(c, s, i, root, mutant):
    return claim_key(c, s, i, root, mutant) not in s.spent


def pending(c, s, mutant):
    out = []
    for i, q in enumerate(s.claims):
        if not q:
            continue
        roots = s.roots if c.mode == "shared-root" else (0,)
        if any((c.mode == "native-p2pk" or ((root >> (3 * i)) & 7)) and is_unpaid(c, s, i, root, mutant) for root in roots):
            out.append(i)
    return tuple(out)


def availability(c, a, env, mutant):
    service, public, retained = env
    if a.kind in ("spend", "accept"):
        return service
    if a.kind == "claim":
        return (service or mutant != "service-dependent") and (
            c.mode == "native-p2pk" or public or retained)
    if a.kind == "reveal":
        return public or retained
    return True


def step(c, s, a, env=AVAILABLE, mutant="", leaked=0):
    """Candidate rules: only State, declared arguments and ideal auth/membership."""
    if not availability(c, a, env, mutant):
        return None
    if not a.fresh or not a.authentic:
        return None
    if a.kind == "quote":
        return replace(s, quote=2) if s.quote == 1 else None
    if a.kind == "spend":
        i, = a.ids
        f, = a.fees
        if i % 2 or not s.values[i] or s.nf & (1 << i):
            return None
        # Only the deliberately unsafe credential negative supplies leaked != 0.
        if a.actor != s.owners[i] and not (a.actor == 2 and leaked & (1 << s.owners[i])):
            return None
        q = s.values[i] - f
        if f not in (0, 1) or q <= 0 or a.recipient not in (0, 1, 2):
            return None
        return replace(s, values=update(s.values, i + 1, q),
                       owners=update(s.owners, i + 1, a.recipient), nf=s.nf | (1 << i),
                       reserve=s.reserve - f, fees=plus(s.fees, i // 2, f))
    if a.kind == "accept":
        if not 1 <= len(a.ids) <= 3 or len(set(a.ids)) != len(a.ids) or len(a.fees) != len(a.ids):
            return None
        if any(not s.values[i] or s.nf & (1 << i) or f not in (0, 1)
               or s.values[i] <= f for i, f in zip(a.ids, a.fees)):
            return None
        claims, fees, nf, removed, principal = s.claims, s.fees, s.nf, 0, 0
        for i, f in zip(a.ids, a.fees):
            q = s.values[i] - f
            claims = update(claims, i, q)
            fees = plus(fees, i // 2, f)
            if mutant != "omit-accept-nf":
                nf |= 1 << i
            removed += f
            principal += q
        root = sum((q + 4 * s.owners[i]) << (3 * i) for i, q in enumerate(claims) if q)
        # Cumulative sorted-by-stable-NF snapshots. Same economic leaf can shift index.
        roots = s.roots + (root,) if c.mode == "shared-root" else s.roots
        native = c.mode == "native-p2pk"
        debit = removed + (principal if native or mutant == "drop-pending-backing" else 0)
        if debit > s.reserve:
            return None
        if mutant == "missing-entitlement":
            claims = update(claims, a.ids[0], 0)
        return replace(s, nf=nf, claims=claims, roots=roots, fees=fees,
                       reserve=s.reserve - debit, escrow=s.escrow + (principal if native else 0))
    if a.kind == "claim":
        i, = a.ids
        f, = a.fees
        q = s.claims[i]
        if not q or (c.mode == "shared-root" and
                     (a.root not in s.roots or ((a.root >> (3 * i)) & 7) != q + 4 * s.owners[i])):
            return None
        if a.actor != s.owners[i]:
            return None
        if a.recipient != s.owners[i] and mutant != "redirect":
            return None
        if a.historical_paid and mutant != "historical-paid":
            return None
        if a.amount != q and mutant != "amount":
            return None
        q = a.amount
        spent = () if a.historical_paid else s.spent
        key = claim_key(c, s, i, a.root, mutant)
        if mutant != "omit-paid" and key in spent:
            return None
        if f != s.quote or (q <= f and mutant != "fee-exhaustion"):
            return None
        native = c.mode == "native-p2pk"
        if (s.escrow if native else s.reserve) < q:
            return None
        return replace(s, spent=s.spent if mutant == "omit-paid" else tuple(sorted(set(s.spent) | {key})),
                       reserve=s.reserve - (0 if native else q),
                       escrow=s.escrow - (q if native else 0),
                       paid_origin=plus(s.paid_origin, i // 2, q - f),
                       paid_owner=plus(s.paid_owner, a.recipient, q - f),
                       fees=plus(s.fees, i // 2, f))
    if a.kind == "reveal":
        i, = a.ids
        f, = a.fees
        if not s.values[i] or s.nf & (1 << i) or a.actor != s.owners[i] or a.recipient != s.owners[i]:
            return None
        if f != s.quote or s.values[i] <= f or s.reserve < s.values[i]:
            return None
        q = s.values[i]
        return replace(s, nf=s.nf | (1 << i), reserve=s.reserve - q,
                       paid_origin=plus(s.paid_origin, i // 2, q - f),
                       paid_owner=plus(s.paid_owner, a.recipient, q - f),
                       fees=plus(s.fees, i // 2, f))
    if a.kind == "retire":
        live = sum(v for i, v in enumerate(s.values) if not s.nf & (1 << i))
        unpaid = sum(s.claims[i] for i in pending(c, s, mutant)) if c.mode == "shared-root" else 0
        if s.retired or live or (unpaid and mutant != "retire-pending"):
            return None
        # Broken pending guard deliberately abandons reserve, never creates admin authority.
        return replace(s, retired=True, reserve=0)
    return None


def actions(c, s, conditional):
    created = [i for i, v in enumerate(s.values) if v]
    unspent = [i for i in created if not s.nf & (1 << i)]
    for i in unspent:
        if i % 2 == 0:
            for recipient, f in product((0, 1), (0, 1)):
                yield Action("spend", (i,), (f,), recipient, actor=s.owners[i])
        if conditional:
            yield Action("reveal", (i,), (s.quote,), s.owners[i], actor=s.owners[i])
    for size in range(1, min(3, len(unspent)) + 1):
        for ids in combinations(unspent, size):
            for fees in product((0, 1), repeat=size):
                yield Action("accept", ids, fees)
    for i, q in enumerate(s.claims):
        if not q:
            continue
        roots = s.roots if c.mode == "shared-root" else (0,)
        for root in roots:
            if c.mode == "shared-root" and not ((root >> (3 * i)) & 7):
                continue
            a = Action("claim", (i,), (s.quote,), s.owners[i], root, actor=s.owners[i], amount=q)
            yield a
            # Explicit invalid proposals, including paid records; no ghost/status filtering.
            yield replace(a, recipient=2)
            yield replace(a, amount=q + 1)
            yield replace(a, fresh=False)
            yield replace(a, authentic=False)
            yield replace(a, historical_paid=True)
        if c.mode == "shared-root":
            yield Action("claim", (i,), (s.quote,), s.owners[i], 1 << 18, actor=s.owners[i], amount=q)
    yield Action("retire")
    if s.quote == 1:
        yield Action("quote")
