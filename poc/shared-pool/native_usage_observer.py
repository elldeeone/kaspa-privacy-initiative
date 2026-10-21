"""Prefix-local native-byte guesses, never forced-disclosure certificates.

Every public event comes from the native adapter. Known notes are limited to
public wallet shape, the declared initial directory and the supplied participant
records. A transparent return edge supplies a fallible graph hypothesis only;
it never modifies the known note/owner registry. No hidden-history search,
generation, scoring, file access or private truth input occurs in observe().
"""
import copy
import hashlib
import itertools
import json
from collections import defaultdict
from fractions import Fraction

import native_usage_surface as surface

SOMPI = 100_000_000
FLOOR, FEE = 60_000_000, 40_000_000
LOW, HIGH, CENT = 10 * SOMPI, 50 * SOMPI, 1_000_000
INVOICES = (10, 20, 25, 40, 50)
VARIANTS = ("prior", "residual", "split", "native_graph")
SCHEMA = "kpi-native-usage-predictions-v1"
POLICY_SHA256 = "c6eb374ac28e7a8050fe3bfc7d54729b45ad523c690e337b31925529b7681471"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def optimal_amount_prior(support):
    """Exact weighted interval sweep; ties choose the smallest integer guess.

    For actual a, success means ceil(9a/10) <= guess <= floor(11a/10).
    Support consists of (integer sompi, exact Fraction weight), not a rounded
    approximation or an enumeration of possible guesses.
    """
    changes = defaultdict(Fraction)
    for amount, weight in support:
        need(type(amount) is int and amount > 0 and isinstance(weight, Fraction) and weight > 0,
             "positive exact prior support")
        changes[(9 * amount + 9) // 10] += weight
        changes[(11 * amount) // 10 + 1] -= weight
    need(bool(changes), "nonempty prior support")
    running, best, answer = Fraction(), Fraction(-1), None
    for guess, change in sorted(changes.items()):
        running += change
        if running > best:
            best, answer = running, guess
    return answer, best


def amount_prior():
    # This optimizes the declared honest-target mixture used by the primary
    # evaluation. It is not the unconditional honest/active request mixture,
    # nor a posterior conditioned on the whole public ledger.
    support = [(a * SOMPI, Fraction(3, 25)) for a in INVOICES]
    count = (HIGH - LOW) // CENT + 1
    support.extend((a, Fraction(2, 5 * count)) for a in range(LOW, HIGH + 1, CENT))
    return optimal_amount_prior(support)[0]


def _pick(roles, event_id, field):
    need(bool(roles), "empty prior candidate set")
    return min(roles, key=lambda r: (digest(dict(domain="kpi-native-usage-prior-v1",
                                               event_id=event_id, field=field, role=r)), r))


def _point(funding):
    return f'{funding["transaction_id"]}:{funding["index"]}'


class Engine:
    def __init__(self, facts):
        self.facts = facts
        self.events, self.notes, self.spent = facts["events"], {}, {0: 0}
        self.roles, self.members = facts["roles"], set(facts["members"])
        self.adversaries = set(facts["adversaries"])
        self.receipts, self.authors = facts["receipts"], facts["authors"]
        self.targets = [i for i, e in enumerate(self.events) if i and e["mode"] == 1]
        self.target_number = {i: n for n, i in enumerate(self.targets)}
        self.base_amount = amount_prior()
        self._registry()
        self.admitted = {}
        founder = facts["funding_owners"].get(_point(facts["projection"]["surface"]["funding"]))
        need(founder is not None, "known initial funding pseudonym")
        admitted = {founder}
        for i, row in enumerate(facts["projection"]["surface"]["events"]):
            if row["funding"]:
                owner = facts["funding_owners"].get(_point(row["funding"]))
                if owner is not None:
                    admitted.add(owner)
            self.admitted[i] = sorted(admitted)
        self.graph_owners = defaultdict(set)
        self.boundary = []
        for bridge in facts["bridges"]:
            owner = bridge["destination_owner"]
            self.boundary.append(dict(bridge, source_owner_guess=owner,
                                      same_owner_guess=True if owner is not None else None))
            if owner is not None:
                self.graph_owners[bridge["source_event"]].add(owner)

    def _add(self, p, value, owner):
        if p in self.notes:
            old = self.notes[p]
            need(old["value"] == value, "contradictory known value")
            need(old["owner"] is None or owner is None or old["owner"] == owner,
                 "contradictory known owner")
            if old["owner"] is None:
                old["owner"] = owner
            return
        self.notes[p] = dict(position=p, value=value, owner=owner, born=self.facts["births"][p])

    def _registry(self):
        projection = self.facts["projection"]
        initial = projection["algebra"]["initial"]["value"]
        founder = self.facts["funding_owners"].get(_point(projection["surface"]["funding"]))
        self._add(0, initial, founder)
        a, b = self.events[0]["new"]
        self._add(a, initial - self.events[0]["fee"], founder)
        self._add(b, 0, None)
        for i, e in enumerate(self.events):
            if e["mode"] == 0:
                funding = projection["surface"]["events"][i]["funding"]
                owner = self.facts["funding_owners"].get(_point(funding))
                a, b = e["new"]
                self._add(a, e["deposit"] - e["fee"], owner)
                self._add(b, 0, None)
        for row in self.receipts.values():
            self._add(row["position"], row["value"], row["owner"])
        for i, row in self.authors.items():
            for p in row["inputs"]:
                need(p not in self.spent or self.spent[p] == i, "contradictory disclosed spend")
                self.spent[p] = i
            for output in row["outputs"]:
                self._add(output["position"], output["value"], output["recipient"])
        # The first four tagged control requests and their senders are declared
        # public policy. Recipients remain hidden. These are not primary targets.
        for target, ordinal in self.target_number.items():
            if ordinal < 4:
                p = self.events[target]["new"][0]
                self._add(p, 20 * SOMPI + (ordinal + 1) * 1000, None)
        groups = defaultdict(list)
        for p, cm in enumerate(self.facts["commitments"]):
            groups[cm].append(p)
        for positions in groups.values():
            known = [self.notes[p] for p in positions if p in self.notes]
            if known:
                values = {n["value"] for n in known}
                owners = {n["owner"] for n in known if n["owner"] is not None}
                need(len(values) == 1 and len(owners) <= 1, "conflicting equal-note facts")
                for p in positions:
                    self._add(p, next(iter(values)), next(iter(owners)) if owners else None)

    def _known(self, target):
        author = self.authors.get(target)
        note = self.notes.get(self.events[target]["new"][0])
        known = dict(sender=author["owner"] if author is not None else None,
                     recipient=note["owner"] if note is not None else None,
                     amount=note["value"] if note is not None else None)
        ordinal = self.target_number[target]
        if ordinal < 4:
            need(known["sender"] in (None, ordinal), "public tagged-control sender")
            known["sender"] = ordinal
        return known

    def _allowed(self, target):
        known = self._known(target)
        senders = ([known["sender"]] if known["sender"] is not None else
                   [r for r in self.admitted[target] if r not in self.members])
        recipients = ([known["recipient"]] if known["recipient"] is not None else
                      [r for r in self.admitted[target] if r not in self.members])
        if self.target_number[target] < 4:
            recipients = [r for r in recipients if r not in self.adversaries]
        return senders, recipients

    def _amount_allowed(self, target, sender, amount):
        if sender not in self.adversaries:
            return LOW <= amount <= HIGH and amount % CENT == 0
        ordinal = self.target_number[target]
        if ordinal < 4:
            ordinals = [0] if sender == ordinal else []
        elif target in self.authors and self.authors[target]["owner"] == sender:
            ordinals = [sum(i < target and row["owner"] == sender and i in self.target_number
                            for i, row in self.authors.items())]
        else:
            # Active roles0..3 made their public first send in the four control
            # requests; others can be on either of their two hidden sends.
            ordinals = [1] if sender < 4 else [0, 1]
        return any(j in (0, 1) and amount == 20 * SOMPI + (sender + 1) * 1000 + j
                   for j in ordinals)

    def _roles(self, target, sender=None, recipient=None, amount=None):
        senders, recipients = self._allowed(target)
        if amount is not None:
            senders = [r for r in senders if self._amount_allowed(target, r, amount)]
        if sender is not None:
            if sender not in senders:
                return None
            senders = [sender]
        else:
            senders = [r for r in senders if r != recipient]
            # After the four controls, active roles0..3 have one send left;
            # roles4..7 have two. Honest identities have expected two under the
            # hidden activity-class permutation. Conditional unknown roles stay
            # exchangeable; this is not a full ledger posterior.
            if self.target_number[target] >= 4 and senders:
                weight = lambda r: 1 if r in range(4) else 2
                top = max(map(weight, senders))
                senders = [r for r in senders if weight(r) == top]
        if not senders:
            return None
        s = _pick(senders, self.events[target]["id"], "sender")
        if recipient is not None:
            if recipient not in recipients or recipient == s:
                return None
            recipients = [recipient]
        else:
            recipients = [r for r in recipients if r != s]
        if not recipients:
            return None
        return s, _pick(recipients, self.events[target]["id"], "recipient")

    def prior(self, target):
        known = self._known(target)
        pair = self._roles(target, known["sender"], known["recipient"])
        need(pair is not None, "no policy prior role pair")
        return dict(sender=pair[0], recipient=pair[1],
                    amount=self.base_amount if known["amount"] is None else known["amount"],
                    relationship_rank=[0, 0, 0, 0])

    def _can_spend(self, p, event):
        n = self.notes[p]
        return (n["value"] >= FLOOR and n["born"] < event
                and p < self.events[event]["anchor_count"]
                and (p not in self.spent or self.spent[p] == event))

    def residuals(self, graph=False):
        result = []
        for i, e in enumerate(self.events):
            if e["mode"] != 2 or i in self.authors:
                continue
            total = e["payout"] + e["fee"]
            guesses = sorted(self.graph_owners[i]) if graph and i in self.graph_owners else [None]
            for owner in guesses:
                if owner in self.members:
                    continue
                result.append((i, total, owner, None, owner is not None))
                for p, n in sorted(self.notes.items()):
                    if (n["owner"] in self.members or not self._can_spend(p, i)
                            or total - n["value"] < FLOOR
                            or (owner is not None and n["owner"] not in (None, owner))):
                        continue
                    result.append((i, total - n["value"],
                                   n["owner"] if owner is None else owner, p, owner is not None))
        return result

    def _residual_ok(self, target, residual, output, inputs=()):
        drain, value, owner, coinput, _ = residual
        if drain <= target or output >= self.events[drain]["anchor_count"]:
            return False
        if output in self.spent and self.spent[output] != drain:
            return False
        known = self.notes.get(output)
        if known is not None and (known["value"] != value
                                  or (owner is not None and known["owner"] not in (None, owner))):
            return False
        return coinput not in set(inputs) | set(self.events[target]["new"])

    def _inputs(self, target):
        author = self.authors.get(target)
        if author is not None:
            combos = [tuple(author["inputs"])]
        else:
            allowed, _ = self._allowed(target)
            eligible = [p for p, n in sorted(self.notes.items())
                        if n["owner"] in allowed and self._can_spend(p, target)]
            combos = [(p,) for p in eligible] + list(itertools.combinations(eligible, 2))
        return [(ins, self.notes[ins[0]]["owner"],
                 sum(self.notes[p]["value"] for p in ins) - self.events[target]["fee"])
                for ins in combos if all(p in self.notes and self._can_spend(p, target) for p in ins)
                and len({self.notes[p]["owner"] for p in ins}) == 1
                and self.notes[ins[0]]["owner"] is not None]

    def candidates(self, target, graph=False):
        books = {"residual": {}, "split": {}}
        known = self._known(target)

        def offer(kind, sender, recipient, amount, tier, distance, evidence):
            if not LOW <= amount <= HIGH or (known["amount"] is not None and known["amount"] != amount):
                return
            sender = known["sender"] if sender is None else sender
            recipient = known["recipient"] if recipient is None else recipient
            if ((known["sender"] is not None and known["sender"] != sender)
                    or (known["recipient"] is not None and known["recipient"] != recipient)):
                return
            pair = self._roles(target, sender, recipient, amount)
            if pair is None:
                return
            key = (pair[0], pair[1], amount)
            rank = (int(sender is not None) + int(recipient is not None), tier, -distance)
            if key not in books[kind]:
                books[kind][key] = dict(rank=rank, support=set())
            record = books[kind][key]
            record["rank"] = max(record["rank"], rank)
            record["support"].add(evidence)

        residuals = self.residuals(graph)
        by_value = defaultdict(list)
        for r in residuals:
            by_value[r[1]].append(r)
        payment, change = self.events[target]["new"]
        receipts = [r for r in residuals if LOW <= r[1] <= HIGH
                    and self._residual_ok(target, r, payment)]
        for r in receipts:
            drain, value, owner, coinput, edge = r
            offer("residual", None, owner, value, 4 if edge else 2 if owner is not None else 1,
                  self.events[drain]["minute"] - self.events[target]["minute"], (drain, coinput))
        for ins, sender, total in self._inputs(target):
            for receipt in receipts:
                if not self._residual_ok(target, receipt, payment, ins):
                    continue
                d1, amount, recipient, p1, edge1 = receipt
                value = total - amount
                if value > 0 and change in self.notes and self.notes[change]["owner"] not in (None, sender):
                    continue
                if value == 0:
                    if change in self.spent or (change in self.notes and self.notes[change]["value"] != 0):
                        continue
                    alternatives = [(None, 0, sender, None, False)]
                elif value >= FLOOR:
                    alternatives = by_value.get(value, ())
                else:
                    continue
                for d2, _, owner2, p2, edge2 in alternatives:
                    if d2 is not None and (d1 == d2 or (p1 is not None and p1 == p2)
                            or not self._residual_ok(target, (d2, value, owner2, p2, edge2), change, ins)
                            or owner2 not in (None, sender)):
                        continue
                    if recipient == sender:
                        continue
                    distance = self.events[d1]["minute"] - self.events[target]["minute"]
                    if d2 is not None:
                        distance += self.events[d2]["minute"] - self.events[target]["minute"]
                    offer("split", sender, recipient, amount, 5 if edge1 or edge2 else 3,
                          distance, (ins, d1, p1, d2, p2))
        return books

    @staticmethod
    def best(book, fallback):
        if not book:
            return copy.deepcopy(fallback)
        def rank(item):
            key, value = item
            endpoints, tier, recency = value["rank"]
            return (endpoints, tier, len(value["support"]), recency, -key[2], -key[0], -key[1])
        key, value = max(book.items(), key=rank)
        endpoints, tier, recency = value["rank"]
        return dict(sender=key[0], recipient=key[1], amount=key[2],
                    relationship_rank=[endpoints, tier, len(value["support"]), recency])

    def row(self, target):
        baseline = self.prior(target)
        books, graph = self.candidates(target), self.candidates(target, graph=True)
        guesses = dict(prior=baseline,
                       residual=self.best(books["residual"], baseline),
                       split=self.best(books["split"], baseline))
        # Graph variant competes both local residual and split explanations;
        # no graph guess is installed as a known note or spent-note fact.
        combined = copy.deepcopy(graph["residual"])
        for key, value in graph["split"].items():
            if key not in combined:
                combined[key] = value
            else:
                combined[key]["rank"] = max(combined[key]["rank"], value["rank"])
                combined[key]["support"].update(value["support"])
        guesses["native_graph"] = self.best(combined, guesses["split"])
        return dict(event=target, event_id=self.events[target]["id"], guesses=guesses)


def observe(raw, directory, view, timing, policy):
    need(digest(policy) == POLICY_SHA256, "frozen native usage policy")
    facts = surface.project(raw, directory, view, timing, policy)
    engine = Engine(facts)
    members = facts["members"]
    profile = "C" if not members else f"P{members[0]}" if len(members) == 1 else "pooled"
    return dict(schema=SCHEMA, complete=True, raw_sha256=digest(raw),
                directory_sha256=digest(directory), view_sha256=digest(view),
                timing_sha256=digest(timing), policy_sha256=digest(policy), profile=profile,
                through_event=len(engine.events) - 1,
                rows=[engine.row(i) for i in engine.targets], boundary=engine.boundary,
                diagnostics=facts["diagnostics"])


def prefix_inputs(raw, directory, view, timing, through_event):
    return surface.prefix_inputs(raw, directory, view, timing, through_event)


def observation_points(raw):
    return surface.observation_points(raw)


def native_relation(raw, directory):
    return surface.native_relation(raw, directory)


def controls():
    """Explicit development fixtures only; no native proof or held-out claim."""
    adapter = surface.controls()
    need(adapter["passed"] and adapter["complete"], "native adapter controls")
    results = []

    def check(name, ok):
        need(ok, "native observer control: " + name)
        results.append(dict(name=name, passed=True))

    def rejects(call):
        try:
            call()
        except (ValueError, KeyError):
            return True
        return False

    for support in [
            [(10, Fraction(1)), (20, Fraction(1)), (25, Fraction(1))],
            [(n, Fraction(2, 25)) for n in range(10, 51)] + [(40, Fraction(3)), (50, Fraction(3))],
            [(101, Fraction(3, 5)), (99, Fraction(2, 5))]]:
        guess, probability = optimal_amount_prior(support)
        scores = [(sum((w for a, w in support if 10 * abs(g - a) <= a), Fraction()), g)
                  for g in range(1, max(a for a, _ in support) * 2)]
        best = max(score for score, _ in scores)
        check("exact prior sweep matches exhaustive development support",
              probability == best and guess == min(g for score, g in scores if score == best))
    check("sompi-exact invoice prior is fixed and in support neighborhood",
          LOW <= amount_prior() <= HIGH and amount_prior() == amount_prior())

    facts, target, positions = _development_facts()
    engine = Engine(facts)
    candidate = (12, 9, 40 * SOMPI)
    check("known same-owner input split contains hand-ledger payment",
          candidate in engine.candidates(target)["split"])
    check("fixed public control tags do not disclose their recipients",
          engine._known(32) == dict(sender=0, recipient=None, amount=20 * SOMPI + 1000))
    check("unknown recurring sender prior uses declared activity mixture",
          engine.prior(target)["sender"] not in range(4)
          and engine.prior(target)["recipient"] != engine.prior(target)["sender"])
    check("honest local hypotheses honor exact cent support and bounds",
          engine._amount_allowed(target, 12, LOW)
          and engine._amount_allowed(target, 12, HIGH)
          and not engine._amount_allowed(target, 12, LOW - CENT)
          and not engine._amount_allowed(target, 12, HIGH + CENT)
          and not engine._amount_allowed(target, 12, 40 * SOMPI + 1))
    fractional, ftarget, _ = _development_facts(amount=40 * SOMPI + 1)
    check("plausible fractional split cannot label an honest sender",
          (12, 9, 40 * SOMPI + 1) not in Engine(fractional).candidates(ftarget)["split"])
    check("active exact tags restrict sender hypotheses without creating facts",
          engine._roles(target, amount=20 * SOMPI + 5000)[0] == 4
          and engine._roles(target, amount=20 * SOMPI + 5001)[0] == 4
          and engine._roles(target, sender=5, amount=20 * SOMPI + 5000) is None
          and engine._roles(target, amount=20 * SOMPI + 5002) is None
          and engine._known(target)["sender"] is None)
    check("public first control uses ordinal zero and later role0 uses ordinal one",
          engine._amount_allowed(32, 0, 20 * SOMPI + 1000)
          and not engine._amount_allowed(32, 0, 20 * SOMPI + 1001)
          and not engine._amount_allowed(target, 0, 20 * SOMPI + 1000)
          and engine._amount_allowed(target, 0, 20 * SOMPI + 1001))
    disclosed = Engine(facts)
    disclosed.authors = {target: {"owner": 4}}
    check("disclosed active send ordinal counts earlier authored PAYs only",
          disclosed._amount_allowed(target, 4, 20 * SOMPI + 5000)
          and not disclosed._amount_allowed(target, 4, 20 * SOMPI + 5001))
    disclosed.authors[34] = {"owner": 4}
    check("second disclosed active send uses ordinal one",
          disclosed._amount_allowed(target, 4, 20 * SOMPI + 5001)
          and not disclosed._amount_allowed(target, 4, 20 * SOMPI + 5000))
    check("no graph hypothesis is put in known-note registry",
          not engine.boundary and engine.notes[positions["receipt"]]["owner"] is None
          if positions["receipt"] in engine.notes else not engine.boundary)

    linked = copy.deepcopy(facts)
    linked["bridges"] = [dict(transaction_id="a" * 64, index=0, source_event=target + 1,
                             source_outpoint=dict(transaction_id=linked["events"][target + 1]["id"], index=1),
                             destination_owner=9)]
    self_return = Engine(linked)
    check("self-return graph supplies an explicit fallible owner hypothesis",
          self_return.boundary[0]["source_owner_guess"] == 9
          and self_return.boundary[0]["same_owner_guess"] is True
          and self_return.notes == engine.notes and self_return.spent == engine.spent)
    check("known self-return can strengthen a correct local recipient candidate",
          candidate in self_return.candidates(target, graph=True)["split"])
    cross = copy.deepcopy(linked)
    cross["bridges"][0]["destination_owner"] = 17
    cross_return = Engine(cross)
    check("cross-user native flow produces a deliberately wrong common-owner guess",
          cross_return.boundary[0]["source_owner_guess"] == 17
          and cross_return.boundary[0]["source_owner_guess"] != 9
          and cross_return.notes == engine.notes and cross_return.spent == engine.spent)
    check("wrong graph hypothesis remains a scored guess, not a forced assertion",
          cross_return.row(target)["guesses"]["native_graph"]["recipient"] != 9
          and set(cross_return.row(target)["guesses"]["native_graph"]) ==
          {"sender", "recipient", "amount", "relationship_rank"})
    unknown = copy.deepcopy(linked)
    unknown["bridges"][0]["destination_owner"] = None
    abstain = Engine(unknown)
    check("fresh unassociated funding script causes boundary abstention",
          abstain.boundary[0]["source_owner_guess"] is None
          and abstain.boundary[0]["same_owner_guess"] is None
          and not abstain.graph_owners)

    prefix = copy.deepcopy(facts)
    prefix["events"] = prefix["events"][:target + 1]
    prefix["projection"]["surface"]["events"] = prefix["projection"]["surface"]["events"][:target + 1]
    before_exit = Engine(prefix)
    check("creation prefix has no later-cashout matches",
          all(g == before_exit.prior(target) for g in before_exit.row(target)["guesses"].values()))
    p = positions["coinput"]
    engine.spent[p] = target + 2
    check("known later spend excludes a different earlier consumption",
          not engine._can_spend(p, target) and not engine._can_spend(p, target + 1)
          and engine._can_spend(p, target + 2))
    engine.spent.pop(p)
    r = (target + 1, 40 * SOMPI, 9, p, False)
    check("input and output positions cannot be reused as cashout coinputs",
          not engine._residual_ok(target, r, positions["receipt"], (p,))
          and not engine._residual_ok(target, (target + 1, 40 * SOMPI, 9,
                                                positions["receipt"], False), positions["receipt"]))
    engine.spent[positions["receipt"]] = target + 2
    check("later disclosed receipt spend rules out another exit",
          not engine._residual_ok(target, r, positions["receipt"]))
    engine.spent.pop(positions["receipt"])
    wrong_change = Engine(facts)
    wrong_change._add(positions["change"], 59 * SOMPI + FLOOR, 17)
    check("whole-cashout match cannot override known change owner",
          candidate not in wrong_change.candidates(target)["split"])
    check("hypotheses never mutate facts and repeated execution is deterministic",
          self_return.row(target) == self_return.row(target)
          and self_return.notes == Engine(linked).notes)

    positive = copy.deepcopy(facts)
    positive["members"] = [0]
    # This is an isolated knowledge-control map: a receipt alone provides no
    # sender. No accepted native history or full participant view is asserted.
    positive["receipts"] = {positions["receipt"]: dict(owner=0, position=positions["receipt"], value=40 * SOMPI)}
    recipient_only = Engine(positive)
    check("recipient-only record is not a sender record",
          recipient_only._known(target) == dict(sender=None, recipient=0, amount=40 * SOMPI))
    recipient_only._add(positions["receipt"], 40 * SOMPI, 0)
    check("conflicting private receipt assertions reject rather than rank",
          rejects(lambda: recipient_only._add(positions["receipt"], 41 * SOMPI, 0)))
    zero, ztarget, zp = _development_facts(amount=40 * SOMPI, zero_change=True)
    z = Engine(zero)
    check("zero change uses a single later residual",
          candidate in z.candidates(ztarget)["split"])
    z._add(zp["change"], FLOOR, 12)
    check("positive known change cannot be guessed zero",
          candidate not in z.candidates(ztarget)["split"])
    check("policy is exact-pinned and never accepts unrelated private fields",
          rejects(lambda: observe({}, {}, {}, {}, {"schema": "kpi-native-usage-policy-v1", "truth": []})))
    return dict(schema="kpi-native-usage-observer-controls-v1", complete=True, passed=True,
                adapter=adapter, controls=results, count=len(results),
                prior_amount_sompi=amount_prior(), candidate_truncation=False,
                native_proofs_generated=False, held_out_data_used=False)


def _development_facts(amount=40 * SOMPI, zero_change=False):
    """Hand-built concrete ledger projected to Engine inputs, not native bytes.

    Native parsing has separate adapter controls. These literals exercise local
    joins with 32 role labels and four public controls without fake proof claims.
    They are not samples from the forthcoming hidden workload.
    """
    events, rows, notes, births, spent = [], [], [(350 * SOMPI + FEE, 0)], [-1], set()
    funding, reserve, capitals = {"f0:0": 0}, 350 * SOMPI + FEE, {}

    def step(mode, sender, ins, outputs):
        nonlocal reserve
        i, count = len(events), len(notes)
        assert all(p not in spent and notes[p][1] == sender for p in ins)
        total = sum(notes[p][0] for p in ins)
        dep = sum(v for _, v in outputs) + FEE if mode == 0 else 0
        payout = total - FEE if mode == 2 else 0
        assert total + dep == sum(v for _, v in outputs) + payout + FEE
        reserve += dep - payout - FEE
        new = [] if mode == 2 else [count, count + 1]
        source = None
        if mode == 0:
            source = dict(transaction_id=f"f{sender}", index=0, amount_sompi=str(dep),
                          script_public_key=f"spk{sender}")
            funding[_point(source)] = sender
        event = dict(id=f"{i + 1:064x}", minute=i, mode=mode, count_before=count,
                     anchor_count=0 if mode == 0 else count, new=new, fee=FEE, deposit=dep,
                     payout=payout, reserve_out=reserve, funding_group=None if source is None else _point(source),
                     destination=f"exit{i}" if payout else None)
        events.append(event)
        rows.append(dict(ordinal=i, funding=source))
        notes.extend((v, who if v else None) for who, v in outputs)
        births.extend([i] * len(outputs))
        spent.update(ins)
        return new

    capitals[0] = step(1, 0, [0], [(0, 350 * SOMPI), (None, 0)])[0]
    for role in range(1, 32):
        value = (10 if role == 9 else 100 if role == 12 else 1000 + role) * SOMPI
        if role == 12 and zero_change:
            value = amount + FEE
        capitals[role] = step(0, role, [], [(role, value), (None, 0)])[0]
    for role in range(4):
        value = 20 * SOMPI + (role + 1) * 1000
        note = capitals[role]
        new = step(1, role, [note], [(8 + role, value), (role, notes[note][0] - value - FEE)])
        capitals[role] = new[1]
    target = len(events)
    receipt, change = step(1, 12, [capitals[12]],
                           [(9, amount), (12, notes[capitals[12]][0] - amount - FEE)])
    step(2, 9, [capitals[9], receipt], [])
    if not zero_change:
        step(2, 12, [change], [])
    projection = dict(algebra=dict(initial=dict(value=350 * SOMPI + FEE)),
                      surface=dict(funding=dict(transaction_id="f0", index=0), events=rows))
    facts = dict(projection=projection, events=events, births=births,
                 commitments=[f"{p + 1:064x}" for p in range(len(notes))],
                 roles=list(range(32)), adversaries=list(range(8)), members=[],
                 receipts={}, authors={}, funding_owners=funding, bridges=[], diagnostics={})
    return facts, target, dict(receipt=receipt, change=change, coinput=capitals[9])
