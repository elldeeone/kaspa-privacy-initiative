"""Frozen practical guesses over public history and one complete participant view.

No generation, truth, solver search or file access occurs in analyze(). Known
notes never include inferred notes. Exact local arithmetic matches are guesses:
they do not establish survival through intervening payments, a feasible global
history, or forced disclosure. The only supported observation horizon is final.
"""
import copy
import itertools
from collections import defaultdict

import population_privacy_model as full

SOMPI = 100_000_000
LOW, HIGH, BASE_AMOUNT = 10 * SOMPI, 1000 * SOMPI, 100 * SOMPI
VARIANTS = ("prior", "cashout_residual", "split_balance", "tag_split")
GUESS_KEYS = {"sender", "recipient", "amount", "relationship_rank"}


def policy():
    """Explicit observer policy, checked against the separately frozen policy.

    This intentionally does not import the generator or its seed/truth helpers.
    Controls compare this declaration with the generator's public-policy bytes.
    """
    roles, adversaries = list(range(32)), list(range(8))
    first = list(range(4)) + list(range(8, 20))
    second = [r for r in roles if r not in first]
    phases = [(first, first, 0), (second, roles, 0)] + [(roles, roles, n) for n in range(1, 4)]
    schedule, offset = [], 0
    for senders, admitted, n in phases:
        schedule.append(dict(request_start=offset, request_end_exclusive=offset + len(senders),
                             round=n, senders=senders, admitted=admitted,
                             sparse_gap_before_minutes=60 if n else 0))
        offset += len(senders)
    return dict(schema="kpi-population-strong-policy-v1", histories=16,
                histories_per_regime=8, regimes=["overlap", "sparse"], arm="persistent",
                roles=roles, adversaries=adversaries, rounds=4, payments=128,
                startup_payments=16,
                starting_balances_sompi=[v * SOMPI for v in (5000, 10000, 20000, 40000)],
                honest_amount_min_sompi=LOW, honest_amount_max_sompi=HIGH,
                honest_distribution="old.log_amount: uint64 log-uniform, Decimal80, half-even sompi",
                tag_amounts_sompi=[[(n + 1) * 100 * SOMPI + (r + 1) * 1000
                                   for r in adversaries] for n in range(4)],
                schedule=schedule, selector="least-excess-fewest-inputs-lexicographic",
                drain="hidden uniform role permutation, ascending positions in pairs",
                native_scripts="independent opaque labels; no funding/exit alias; synthetic assumption")


def _choice(candidates, event_id, field):
    """Uniform-prior ties only; the digest is not itself a behavioral prior."""
    full.need(bool(candidates), "empty public prior candidate set")
    return min(candidates, key=lambda r: (full.digest(dict(
        domain="kpi-population-strong-prior-v1", event_id=event_id, field=field, role=r)), r))


class Engine:
    def __init__(self, public, view, declared_policy, tiny=False):
        full.fields(public, full.PUBLIC_KEYS, "strong public")
        self.facts = full.validate(public, view, tiny=tiny)
        self.public, self.view, self.policy = public, view, declared_policy
        self.events = public["algebra"]["events"]
        self.members = set(view["members"])
        self.targets = [i for i, e in enumerate(self.events) if i and e["mode"] == 1]
        self.notes, self.spent = {}, {0: 0}
        self._registry()
        self.phases = {}
        for phase in declared_policy["schedule"]:
            phase_targets = self.targets[phase["request_start"]:phase["request_end_exclusive"]]
            full.need(len(phase_targets) == phase["request_end_exclusive"] - phase["request_start"],
                      "phase target coverage")
            known_authors = {self.facts["authors"][i]["owner"] for i in phase_targets
                             if i in self.facts["authors"]}
            full.need(known_authors <= set(phase["senders"]), "public phase author")
            for i in phase_targets:
                self.phases[i] = (phase, known_authors)
        full.need(set(self.phases) == set(self.targets), "complete public phase coverage")
        self.residuals = self._residuals()
        self.by_value = defaultdict(list)
        for residual in self.residuals:
            self.by_value[residual[1]].append(residual)

    def _add(self, position, value, owner, tag=False):
        if position in self.notes:
            previous = self.notes[position]
            full.need(previous["value"] == value and previous["owner"] == owner,
                      "inconsistent known note facts")
            previous["tag"] |= tag
            return
        self.notes[position] = dict(position=position, value=value, owner=owner,
                                    born=self.facts["births"][position], tag=tag)

    def _registry(self):
        data, funding = self.public["algebra"], self.public["funding_owners"]
        founder = funding[data["initial"]["funding_group"]]
        self._add(0, data["initial"]["value"], founder)
        a, b = self.events[0]["new"]
        self._add(a, data["initial"]["value"] - self.events[0]["fee"], founder)
        self._add(b, 0, None)
        for i, event in enumerate(self.events):
            if event["mode"] == 0:
                a, b = event["new"]
                self._add(a, event["deposit"] - event["fee"], funding[event["funding_group"]])
                self._add(b, 0, None)
        for row in self.view["receipts"]:
            self._add(row["position"], row["value"], row["owner"])
        for row in self.view["authored"]:
            for p in row["inputs"]:
                full.need(p not in self.spent or self.spent[p] == row["event"],
                          "conflicting known spend")
                self.spent[p] = row["event"]
            for output in row["outputs"]:
                # A tag is an actual positive participant-authored payment to an
                # honest role, never a synthetic guess or a change-to-self note.
                is_tag = (row["event"] > 0 and self.events[row["event"]]["mode"] == 1
                          and output["position"] == self.events[row["event"]]["new"][0]
                          and output["value"] > 0
                          and output["recipient"] not in self.public["adversaries"])
                self._add(output["position"], output["value"], output["recipient"], is_tag)
        # Equal commitments are full note equality in the adopted abstraction.
        groups = defaultdict(list)
        for p, cm in enumerate(self.public["commitments"]):
            groups[cm].append(p)
        for positions in groups.values():
            known = [self.notes[p] for p in positions if p in self.notes]
            if known:
                first = known[0]
                full.need(all((n["value"], n["owner"]) == (first["value"], first["owner"])
                              for n in known), "contradictory equal commitment facts")
                for p in positions:
                    # Equality reveals contents, not who authored this position.
                    self._add(p, first["value"], first["owner"])

    def _can_spend(self, p, event):
        note = self.notes[p]
        return (note["value"] >= full.FLOOR and note["born"] < event
                and p < self.events[event]["anchor_count"]
                and (p not in self.spent or self.spent[p] == event))

    def _residuals(self):
        """(drain, value, owner-or-None, coinput-or-None); no inferred facts.

        Disclosed DRAINs have fully known input sets. They cannot hide an
        unknown target note, so only undisclosed drains enter this attack.
        """
        result = []
        for i, e in enumerate(self.events):
            if e["mode"] != 2 or i in self.facts["authors"]:
                continue
            total = e["payout"] + e["fee"]
            result.append((i, total, None, None))
            for p, note in sorted(self.notes.items()):
                if (note["owner"] not in self.members and self._can_spend(p, i)
                        and total - note["value"] >= full.FLOOR):
                    result.append((i, total - note["value"], note["owner"], p))
        return result

    def _known(self, target):
        author = self.facts["authors"].get(target)
        receipt = self.notes.get(self.events[target]["new"][0])
        return dict(sender=None if author is None else author["owner"],
                    recipient=None if receipt is None else receipt["owner"],
                    amount=None if receipt is None else receipt["value"])

    def _allowed(self, target):
        phase, authors = self.phases[target]
        known = self._known(target)
        senders = ([known["sender"]] if known["sender"] is not None else
                   sorted(set(phase["senders"]) - authors - self.members))
        recipients = ([known["recipient"]] if known["recipient"] is not None else
                      sorted(set(phase["admitted"]) - self.members))
        return senders, recipients

    def _roles(self, target, sender=None, recipient=None):
        allowed_s, allowed_r = self._allowed(target)
        if sender is not None and sender not in allowed_s:
            return None
        if recipient is not None and recipient not in allowed_r:
            return None
        senders = [sender] if sender is not None else [r for r in allowed_s if r != recipient]
        if not senders:
            return None
        s = _choice(senders, self.events[target]["id"], "sender")
        recipients = ([recipient] if recipient is not None else [r for r in allowed_r if r != s])
        if not recipients or s in recipients and len(recipients) == 1:
            return None
        r = _choice([r for r in recipients if r != s], self.events[target]["id"], "recipient")
        return s, r

    def prior(self, target):
        known = self._known(target)
        roles = self._roles(target, known["sender"], known["recipient"])
        full.need(roles is not None, "no prior role pair")
        return dict(sender=roles[0], recipient=roles[1],
                    amount=BASE_AMOUNT if known["amount"] is None else known["amount"],
                    relationship_rank=[0, 0, 0, 0])

    def _residual_ok(self, target, residual, output, inputs=()):
        drain, value, owner, coinput = residual
        if drain <= target or output >= self.events[drain]["anchor_count"]:
            return False
        # A target output that has a disclosed later spend cannot also be spent
        # at this different guessed exit. A later disclosure is a final-horizon
        # fact, not evidence that the output was available before its birth.
        if output in self.spent and self.spent[output] != drain:
            return False
        known = self.notes.get(output)
        if known is not None and (known["value"] != value
                                  or (owner is not None and known["owner"] != owner)):
            return False
        return coinput not in set(inputs) | set(self.events[target]["new"])

    def _input_sets(self, target):
        author = self.facts["authors"].get(target)
        if author is not None:
            combinations = [tuple(author["inputs"])]
        else:
            eligible = [p for p, note in sorted(self.notes.items())
                        if note["owner"] in self._allowed(target)[0] and self._can_spend(p, target)]
            combinations = [(p,) for p in eligible] + list(itertools.combinations(eligible, 2))
        result = []
        for ins in combinations:
            if (all(p in self.notes and self._can_spend(p, target) for p in ins)
                    and len({self.notes[p]["owner"] for p in ins}) == 1):
                result.append((ins, self.notes[ins[0]]["owner"],
                               sum(self.notes[p]["value"] for p in ins) - self.events[target]["fee"],
                               any(self.notes[p]["tag"] for p in ins)))
        return result

    def candidates(self, target):
        """Exhaustive local joins, with no truncation and no state feedback."""
        books = {name: {} for name in VARIANTS[1:]}
        known = self._known(target)

        def offer(variant, sender, recipient, amount, tier, distance, evidence):
            if not LOW <= amount <= HIGH or (known["amount"] is not None and known["amount"] != amount):
                return
            sender = known["sender"] if sender is None else sender
            recipient = known["recipient"] if recipient is None else recipient
            if ((known["sender"] is not None and sender != known["sender"])
                    or (known["recipient"] is not None and recipient != known["recipient"])):
                return
            roles = self._roles(target, sender, recipient)
            if roles is None:
                return
            key = (roles[0], roles[1], amount)
            endpoints = int(sender is not None) + int(recipient is not None)
            book = books[variant]
            if key not in book:
                book[key] = dict(endpoints=endpoints, tier=tier, distance=distance, support=set())
            entry = book[key]
            entry["endpoints"] = max(entry["endpoints"], endpoints)
            entry["tier"] = max(entry["tier"], tier)
            entry["distance"] = min(entry["distance"], distance)
            entry["support"].add(evidence)

        payment, change = self.events[target]["new"]
        receipts = [r for r in self.residuals if LOW <= r[1] <= HIGH
                    and self._residual_ok(target, r, payment)]
        for receipt in receipts:
            drain, amount, owner, coinput = receipt
            offer("cashout_residual", None, owner, amount, 2 if owner is not None else 1,
                  self.events[drain]["minute"] - self.events[target]["minute"],
                  (drain, coinput))
        for ins, sender, total, tagged in self._input_sets(target):
            for receipt in receipts:
                if not self._residual_ok(target, receipt, payment, ins):
                    continue
                d1, amount, recipient, p1 = receipt
                change_value = total - amount
                if (change_value > 0 and change in self.notes
                        and self.notes[change]["owner"] != sender):
                    continue
                if change_value == 0:
                    if change in self.spent or (change in self.notes and self.notes[change]["value"] != 0):
                        continue
                    alternatives = [(None, 0, sender, None)]
                elif change_value >= full.FLOOR:
                    alternatives = self.by_value.get(change_value, ())
                else:
                    continue
                for other in alternatives:
                    d2, _, change_owner, p2 = other
                    if d2 is not None:
                        if (d1 == d2 or (p1 is not None and p1 == p2)
                                or not self._residual_ok(target, other, change, ins)
                                or (change_owner is not None and change_owner != sender)):
                            continue
                    if recipient is not None and recipient == sender:
                        continue
                    evidence = (ins, d1, p1, d2, p2)
                    distance = self.events[d1]["minute"] - self.events[target]["minute"]
                    if d2 is not None:
                        distance += self.events[d2]["minute"] - self.events[target]["minute"]
                    offer("split_balance", sender, recipient, amount, 3, distance, evidence)
                    if tagged:
                        offer("tag_split", sender, recipient, amount, 4, distance, evidence)
        return books

    def row(self, target):
        baseline, books = self.prior(target), self.candidates(target)
        guesses = {name: copy.deepcopy(baseline) for name in VARIANTS}
        for variant, candidates in books.items():
            if not candidates:
                continue
            def ranking(item):
                key, value = item
                rank = (value["endpoints"], value["tier"], len(value["support"]), -value["distance"])
                # Highest rank, then smallest amount/sender/recipient; every tie
                # uses only public candidate values, never actual correctness.
                return rank + (-key[2], -key[0], -key[1])
            key, selected = max(candidates.items(), key=ranking)
            guesses[variant] = dict(sender=key[0], recipient=key[1], amount=key[2],
                                   relationship_rank=[selected["endpoints"], selected["tier"],
                                                      len(selected["support"]), -selected["distance"]])
        return dict(event=target, guesses=guesses)


def analyze(public, view, declared_policy):
    full.need(declared_policy == policy(), "frozen strong policy")
    full.need(view["members"] == list(range(8)), "pooled eight-member final view required")
    engine = Engine(public, view, declared_policy)
    full.need(len(engine.targets) == 128 and engine.events[-1]["reserve_out"] == 0
              and engine.events[-1]["mode"] == 2, "complete 128-payment drain horizon")
    return dict(schema="kpi-population-strong-predictions-v1", complete=True,
                public_sha256=full.digest(public), view_sha256=full.digest(view),
                policy_sha256=full.digest(declared_policy), horizon="final",
                variants=list(VARIANTS), rows=[engine.row(i) for i in engine.targets])


def controls():
    """Explicit small development ledgers; no held-out generator or file reads."""
    return _controls()


def _controls():
    results = []

    def record(name, passed):
        full.need(passed, "strong control: " + name)
        results.append(dict(name=name, passed=True))

    def rejects(call):
        try:
            call()
        except (ValueError, KeyError):
            return True
        return False

    def fixture(amount=40 * SOMPI):
        # 100 to sender 0, 10 to recipient 9. PAY consumes 100 and
        # creates amount + (99.6-amount). Recipient drains its two notes.
        p, t = full._fixture(100 * SOMPI + full.FEE, [
            (1, 0, [0], [(0, 100 * SOMPI), (None, 0)]),
            (0, 9, [], [(9, 10 * SOMPI), (None, 0)]),
            (1, 0, [1], [(9, amount), (0, 100 * SOMPI - full.FEE - amount)]),
            (2, 9, [3, 5], []), (2, 0, [6], []),
        ], roles=32, floor=full.FLOOR, fee=full.FEE)
        p["modeled"]["payout_floor_sompi"] = full.PAYOUT_FLOOR
        v = full._view(p, t, [])
        pol = dict(schedule=[dict(request_start=0, request_end_exclusive=1,
                                 senders=[0], admitted=[0, 9])])
        return p, v, pol, t

    p, v, pol, t = fixture()
    e = Engine(p, v, pol)
    guess = e.row(2)["guesses"]["split_balance"]
    record("hand-checked same-owner split and residual cashouts",
           (guess["sender"], guess["recipient"], guess["amount"]) == (0, 9, 40 * SOMPI)
           and (0, 9, 40 * SOMPI) in e.candidates(2)["split_balance"])
    record("missing tag uses unchanged prior fallback",
           not e.candidates(2)["tag_split"]
           and e.row(2)["guesses"]["tag_split"] == e.prior(2))
    wrong_p, wrong_v, wrong_pol, wrong_t = fixture(49 * SOMPI + 60_000_000)
    wrong = Engine(wrong_p, wrong_v, wrong_pol).row(2)["guesses"]["split_balance"]
    record("plausible exact match can select the wrong payment",
           wrong["amount"] == 40 * SOMPI and wrong["amount"] != wrong_t["values"][5])
    record("known notes retain literal sompi without denomination rounding",
           e.notes[1]["value"] == 100 * SOMPI and e.notes[3]["value"] == 10 * SOMPI
           and 59 * SOMPI + 60_000_000 in e.by_value)
    record("later known spend excludes an earlier guessed consumption",
           e._can_spend(3, 2) and e._can_spend(3, 3))
    e.spent[3] = 4
    record("future-spend guard is exact event equality",
           not e._can_spend(3, 2) and not e._can_spend(3, 3) and e._can_spend(3, 4))
    e.spent.pop(3)
    record("no unborn note or target output reused as cashout coinput",
           not e._can_spend(3, 1)
           and not e._residual_ok(2, (3, 40 * SOMPI, 9, 5), 5)
           and not e._residual_ok(2, (3, 40 * SOMPI, 9, 3), 5, (3,)))
    e.spent[5] = 4
    record("disclosed future target spend rejects another exit",
           not e._residual_ok(2, (3, 40 * SOMPI, None, None), 5))
    e.spent.pop(5)
    record("two-note inputs must have one owner",
           all(ins != (1, 3) for ins, _, _, _ in e._input_sets(2)))
    record("no guessed-note feedback and deterministic ties",
           e.row(2) == e.row(2) and set(e.notes) == {0, 1, 2, 3, 4})
    # Isolated equality-fact controls, not claimed valid alternative histories.
    equal_p = copy.deepcopy(p)
    equal_p["commitments"][6] = equal_p["commitments"][1]
    equal_v = dict(v, public_sha256=full.digest(equal_p))
    equal = Engine(equal_p, equal_v, pol)
    record("equality-derived known change rejects contradicting residuals",
           equal.notes[6]["value"] == 100 * SOMPI
           and not equal._residual_ok(2, (4, 59 * SOMPI + 60_000_000, None, None), 6)
           and not equal.candidates(2)["split_balance"])
    wrong_owner = Engine(p, v, pol)
    wrong_owner._add(6, 59 * SOMPI + 60_000_000, 9)
    record("known change owner checked even for a whole cashout residual",
           not wrong_owner.candidates(2)["split_balance"])
    contaminated = copy.deepcopy(p)
    contaminated["payout_owners"] = {}
    record("extra payout-owner and truth fields rejected",
           rejects(lambda: Engine(contaminated, v, pol))
           and rejects(lambda: Engine(dict(p, truth=t), v, pol)))

    # A genuine disclosed participant sends a tag to role 8. Role 8 later
    # spends it; two distinct drains contain its receipt and change with
    # independently known admissions. Participant 0's own drain is excluded.
    tagged_p, tagged_t = full._fixture(100 * SOMPI + full.FEE, [
        (1, 0, [0], [(0, 100 * SOMPI), (None, 0)]),
        (0, 8, [], [(8, 10 * SOMPI), (None, 0)]),
        (0, 9, [], [(9, 10 * SOMPI), (None, 0)]),
        (1, 0, [1], [(8, 40 * SOMPI), (0, 59 * SOMPI + 60_000_000)]),
        (1, 8, [7], [(9, 10 * SOMPI), (8, 29 * SOMPI + 60_000_000)]),
        (2, 9, [5, 9], []), (2, 8, [3, 10], []), (2, 0, [8], []),
    ], roles=32, floor=full.FLOOR, fee=full.FEE)
    tagged_p["modeled"]["payout_floor_sompi"] = full.PAYOUT_FLOOR
    tagged_v = full._view(tagged_p, tagged_t, [0])
    tagged_pol = dict(schedule=[dict(request_start=0, request_end_exclusive=2,
                                    senders=[0, 8], admitted=[0, 8, 9])])
    tag = Engine(tagged_p, tagged_v, tagged_pol)
    tag_guess = tag.row(4)["guesses"]["tag_split"]
    record("participant tag split preserves change owner and output ordering",
           (tag_guess["sender"], tag_guess["recipient"], tag_guess["amount"]) == (8, 9, 10 * SOMPI)
           and tag_guess["relationship_rank"][:2] == [2, 4])
    record("participant complete records and phase sender prior",
           tag._allowed(4) == ([8], [8, 9])
           and all(r[0] != 7 for r in tag.residuals)
           and tag._known(3) == dict(sender=0, recipient=8, amount=40 * SOMPI))
    record("newer known coinput may be used only after its own birth",
           tag._can_spend(5, 5) and not tag._can_spend(5, 2))
    duplicate_p = copy.deepcopy(tagged_p)
    duplicate_p["commitments"][9] = duplicate_p["commitments"][7]
    duplicate_v = dict(tagged_v, public_sha256=full.digest(duplicate_p))
    duplicate = Engine(duplicate_p, duplicate_v, tagged_pol)
    record("equal contents do not transfer participant author provenance",
           duplicate.notes[7]["tag"] and not duplicate.notes[9]["tag"]
           and duplicate.notes[7]["value"] == duplicate.notes[9]["value"])
    bad_view = copy.deepcopy(tagged_v)
    bad_view["authored"][1]["outputs"][0]["value"] += 1
    # Arithmetic consistency is checked separately by the final truth scorer;
    # conflicting public/receipt facts must already fail this observer registry.
    bad_view["receipts"][0]["value"] += 1
    record("contradictory known facts rejected",
           rejects(lambda: Engine(tagged_p, bad_view, tagged_pol)))

    zero_p, zero_t = full._fixture(40 * SOMPI + 2 * full.FEE, [
        (1, 0, [0], [(0, 40 * SOMPI + full.FEE), (None, 0)]),
        (0, 9, [], [(9, 10 * SOMPI), (None, 0)]),
        (1, 0, [1], [(9, 40 * SOMPI), (None, 0)]),
        (2, 9, [3, 5], []),
    ], roles=32, floor=full.FLOOR, fee=full.FEE)
    zero_p["modeled"]["payout_floor_sompi"] = full.PAYOUT_FLOOR
    zero = Engine(zero_p, full._view(zero_p, zero_t, []), pol)
    record("zero change needs only a single later cashout residual",
           zero.row(2)["guesses"]["split_balance"]["amount"] == 40 * SOMPI)
    zero._add(6, 10 * SOMPI, 0)
    record("known positive change cannot be treated as zero",
           not zero.candidates(2)["split_balance"])
    # Add a direct single-note cashout positive; the literal public total is
    # enumerated even when another competing local hypothesis ranks higher.
    prompt_p, prompt_t = full._fixture(40 * SOMPI + 2 * full.FEE, [
        (1, 0, [0], [(0, 40 * SOMPI + full.FEE), (None, 0)]),
        (0, 9, [], [(9, 10 * SOMPI), (None, 0)]),
        (1, 0, [1], [(9, 40 * SOMPI), (None, 0)]),
        (2, 9, [5], []), (2, 9, [3], []),
    ], roles=32, floor=full.FLOOR, fee=full.FEE)
    prompt_p["modeled"]["payout_floor_sompi"] = full.PAYOUT_FLOOR
    prompt = Engine(prompt_p, full._view(prompt_p, prompt_t, []), pol)
    record("prompt single-note payout total is an explicit candidate",
           (0, 9, 40 * SOMPI) in prompt.candidates(2)["cashout_residual"])
    record("frozen policy and complete final batch required",
           rejects(lambda: analyze(p, v, dict(policy(), payments=1)))
           and rejects(lambda: analyze(p, v, policy())))
    return dict(schema="kpi-population-strong-controls-v1", passed=True,
                complete=True, controls=results, count=len(results),
                held_out_data_used=False, candidate_truncation=False)
