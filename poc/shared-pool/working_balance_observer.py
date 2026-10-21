"""Finite, prefix-local attacks for the working-balance arithmetic screen.

This is a deliberately bounded heuristic family, not an anonymity estimator or
an exhaustive search. No files, seed, hidden demands or truth enter observe().
Candidate ownership and note ancestry never become known-note facts. Public
labels are synthetic ideal-hiding objects, not proof or cryptographic evidence.
"""
import copy
import hashlib
import itertools
import json
from bisect import bisect_left, bisect_right
from collections import defaultdict
from fractions import Fraction

SOMPI = 100_000_000
FEE, FLOOR, CENT = 40_000_000, 60_000_000, 1_000_000
LOW, HIGH = 10 * SOMPI, 50 * SOMPI
VARIANTS = ("prior", "residual", "coinput", "split", "subset_nearest",
            "subset_supported", "partial_tail", "split_tail", "receipt_timing",
            "cash_inverse", "colluder_tags", "bridge_ancestry", "combined")
SPLIT_SUPPORT_LIMIT = 8
SCHEMA = "kpi-working-balance-predictions-v1"
PUBLIC_KEYS = {"schema", "roles", "adversaries", "events", "commitments"}
EVENT_KEYS = {"event", "event_id", "minute", "mode", "fee", "deposit", "payout",
              "reserve", "anchor_count", "count_before", "new", "nullifiers",
              "destination", "funding_group", "bridge"}
BRIDGE_KEYS = {"bridge_id", "sources", "input_value", "deposit", "fee", "change", "change_ref"}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def variants(profile):
    need(profile in ("C", "C+D", "pooled"), "declared observer profile")
    return VARIANTS + tuple("C_" + name for name in VARIANTS) if profile == "pooled" else VARIANTS


def amount_prior():
    """Exact weighted integer-interval sweep; smallest guess breaks ties."""
    changes = defaultdict(Fraction)
    support = [(amount * SOMPI, Fraction(3, 25)) for amount in (10, 20, 25, 40, 50)]
    support.extend((amount, Fraction(2, 5 * 4001)) for amount in range(LOW, HIGH + 1, CENT))
    for amount, weight in support:
        changes[(9 * amount + 9) // 10] += weight
        changes[(11 * amount) // 10 + 1] -= weight
    best, running, answer = Fraction(-1), Fraction(), None
    for guess, delta in sorted(changes.items()):
        running += delta
        if running > best:
            answer, best = guess, running
    return answer, best


def prefix_inputs(public, directory, view, through_event=None):
    """Validate the closed observer surface and remove all later information."""
    need(set(public) == PUBLIC_KEYS and public["schema"] == "kpi-working-balance-public-v1",
         "closed public schema")
    need(public["roles"] == list(range(32)) and public["adversaries"] == list(range(8)),
         "declared role universe")
    need(set(directory) == {"schema", "initial_funding_owners"}
         and directory["schema"] == "kpi-working-balance-directory-v1", "closed directory schema")
    need(set(view) == {"schema", "members", "authored", "receipts"}
         and view["schema"] == "kpi-working-balance-view-v1", "closed participant schema")
    need(view["members"] in ([], list(range(8))), "only C and all-eight pooled views")
    events = public["events"]
    need(isinstance(events, list) and events, "nonempty event history")
    if through_event is None:
        through_event = len(events) - 1
    need(integer(through_event) and through_event < len(events), "prefix bound")
    births, count, reserve = {}, 0, 0
    event_ids = set()
    for index, event in enumerate(events[:through_event + 1]):
        need(set(event) == EVENT_KEYS, "closed public event schema")
        need(event["event"] == index and event["mode"] in (0, 1, 2), "ordered event mode")
        need(all(integer(event[key]) for key in ("minute", "fee", "deposit", "payout", "reserve",
                                                  "anchor_count", "count_before")), "integer public values")
        need(event["fee"] == FEE and event["count_before"] == count
             and event["anchor_count"] <= count, "fee and anchor shape")
        need(isinstance(event["event_id"], str) and event["event_id"] not in event_ids,
             "unique opaque event ID")
        event_ids.add(event["event_id"])
        need(isinstance(event["nullifiers"], list) and len(event["nullifiers"]) == 2,
             "two opaque nullifiers")
        if event["mode"] == 2:
            need(event["new"] == [] and event["deposit"] == 0 and event["payout"] > 0,
                 "whole payout shape")
        else:
            need(event["new"] == [count, count + 1], "two new commitment positions")
            for position in event["new"]:
                births[position] = index
            count += 2
            if event["mode"] == 0:
                need(event["deposit"] > FEE and event["payout"] == 0, "admission shape")
            else:
                need(event["deposit"] == 0, "spend deposit zero")
        reserve += event["deposit"] - event["payout"] - event["fee"]
        need(reserve == event["reserve"] and reserve >= 0, "public reserve accounting")
        bridge = event["bridge"]
        if bridge is not None:
            need(set(bridge) == BRIDGE_KEYS and event["mode"] == 0, "closed bridge shape")
            need(all(integer(bridge[key]) for key in ("input_value", "deposit", "fee", "change")),
                 "integer bridge values")
            need(all(set(row) == {"ref", "value"} and isinstance(row["ref"], str)
                     and integer(row["value"], 1) for row in bridge["sources"]), "bridge source shape")
            need(sum(row["value"] for row in bridge["sources"]) == bridge["input_value"]
                 and bridge["input_value"] == bridge["deposit"] + bridge["fee"] + bridge["change"]
                 and bridge["deposit"] == event["deposit"], "bridge conservation")
    need(len(public["commitments"]) >= count, "commitment prefix available")
    truncated = copy.deepcopy(public)
    truncated["events"] = truncated["events"][:through_event + 1]
    truncated["commitments"] = truncated["commitments"][:count]
    owners = directory["initial_funding_owners"]
    need(isinstance(owners, dict) and all(isinstance(k, str) and integer(v) and v < 32
                                        for k, v in owners.items()), "initial owner directory")
    groups = {event["funding_group"] for event in truncated["events"] if event["mode"] == 0}
    trimmed_directory = dict(schema=directory["schema"], initial_funding_owners={
        group: owner for group, owner in owners.items() if group in groups})
    trimmed_view = dict(schema=view["schema"], members=list(view["members"]), authored=[], receipts=[])
    members = set(view["members"])
    for row in view["authored"]:
        need(set(row) == {"event", "owner", "inputs", "outputs"} and integer(row["event"]),
             "closed author record")
        need(row["owner"] in members, "only participant authored knowledge")
        if row["event"] > through_event:
            continue
        need(all(integer(position) and position in births and births[position] < row["event"]
                 for position in row["inputs"]), "authored input positions")
        need(all(set(output) == {"position", "value", "recipient"}
                 and integer(output["value"])
                 and ((output["value"] == 0 and output["recipient"] is None)
                      or (integer(output["recipient"]) and output["recipient"] < 32))
                 and output["position"] in births
                 and births[output["position"]] == row["event"] for output in row["outputs"]),
             "authored output records")
        trimmed_view["authored"].append(copy.deepcopy(row))
    for row in view["receipts"]:
        need(set(row) == {"position", "value", "owner"} and integer(row["position"])
             and integer(row["value"], FLOOR) and row["owner"] in members, "closed own positive receipt")
        if row["position"] in births:
            trimmed_view["receipts"].append(copy.deepcopy(row))
    need(members or (not view["authored"] and not view["receipts"]), "C has no participant records")
    return truncated, trimmed_directory, trimmed_view


class Engine:
    def __init__(self, public, directory, view, target_floor=None):
        self.events = public["events"]
        self.pick_cache, self.role_cache = {}, {}
        self.members = set(view["members"])
        self.authors = {row["event"]: row for row in view["authored"]}
        need(len(self.authors) == len(view["authored"]), "unique authored event records")
        self.births = {position: event["event"] for event in self.events for position in event["new"]}
        self.notes, self.spent = {}, {}
        self.targets = [event["event"] for event in self.events if event["mode"] == 1 and not event["payout"]]
        self.base_amount = amount_prior()[0]
        self.admitted, admitted = {}, set()
        for event in self.events:
            if event["mode"] == 0:
                owner = directory["initial_funding_owners"].get(event["funding_group"])
                self.add(event["new"][0], event["deposit"] - FEE, owner)
                self.add(event["new"][1], 0, None)
                if owner is not None:
                    admitted.add(owner)
            self.admitted[event["event"]] = sorted(admitted)
        for row in view["receipts"]:
            self.add(row["position"], row["value"], row["owner"])
        for event, row in self.authors.items():
            for position in row["inputs"]:
                need(position not in self.spent, "no contradictory disclosed double spend")
                self.spent[position] = event
            for output in row["outputs"]:
                self.add(output["position"], output["value"], output["recipient"])
        self.public_tag_senders = {}
        # The declared first four sends are public-policy controls. The
        # recipients and their private activity-class permutation stay hidden.
        for ordinal, target in enumerate(self.targets[:4]):
            self.public_tag_senders[target] = ordinal
            self.add(self.events[target]["new"][0], 20 * SOMPI + (ordinal + 1) * 1000, None)
        self.bridge_owners, self.bridge_roots = defaultdict(set), set()
        refs = {}
        for event in self.events:
            if event["payout"]:
                refs[event["event_id"]] = {event["event"]}
            bridge = event["bridge"]
            if bridge is not None:
                roots = set().union(*(refs.get(row["ref"], set()) for row in bridge["sources"]))
                self.bridge_roots.update(roots)
                owner = self.authors.get(event["event"], {}).get("owner")
                if owner is not None:
                    for source in roots:
                        self.bridge_owners[source].add(owner)
                if bridge["change_ref"]:
                    refs[bridge["change_ref"]] = roots
        self.payouts = [event["event"] for event in self.events if event["payout"]
                       and (target_floor is None or event["event"] > target_floor)]
        self.residuals = self.make_residuals()
        self.sums = self.make_sums()
        self.split_indices = {}

    def add(self, position, value, owner):
        need(position in self.births and integer(value), "known note birth and integer value")
        old = self.notes.get(position)
        if old is not None:
            need(old["value"] == value and (owner is None or old["owner"] in (None, owner)),
                 "consistent known note facts")
            if owner is not None:
                old["owner"] = owner
        else:
            self.notes[position] = dict(value=value, owner=owner, born=self.births[position])

    def known(self, target):
        note = self.notes.get(self.events[target]["new"][0], {})
        author = self.authors.get(target, {}).get("owner", self.public_tag_senders.get(target))
        need(target not in self.public_tag_senders or author == self.public_tag_senders[target],
             "public first-four sender policy")
        return dict(sender=author,
                    recipient=note.get("owner"), amount=note.get("value"))

    def pick(self, roles, target, field):
        key = (tuple(roles), target, field)
        if key not in self.pick_cache:
            self.pick_cache[key] = min(roles, key=lambda role: (digest(dict(domain="working-balance-prior-v1",
                event=self.events[target]["event_id"], role=role, field=field)), role))
        return self.pick_cache[key]

    def roles(self, target, sender=None, recipient=None):
        key = (target, sender, recipient)
        if key not in self.role_cache:
            self.role_cache[key] = self._roles(target, sender, recipient)
        return self.role_cache[key]

    def _roles(self, target, sender=None, recipient=None):
        known = self.known(target)
        if known["sender"] is not None and known["sender"] == known["recipient"]:
            if sender in (None, known["sender"]) and recipient in (None, known["recipient"]):
                return known["sender"], known["recipient"]
            return None
        if known["sender"] is not None:
            if sender not in (None, known["sender"]):
                return None
            sender = known["sender"]
        if known["recipient"] is not None:
            if recipient not in (None, known["recipient"]):
                return None
            recipient = known["recipient"]
        senders = [sender] if sender is not None else [r for r in self.admitted[target] if r not in self.members]
        recipients = [recipient] if recipient is not None else [r for r in self.admitted[target] if r not in self.members]
        senders = [r for r in senders if r != recipient]
        if not senders:
            return None
        sender = self.pick(senders, target, "sender")
        recipients = [r for r in recipients if r != sender]
        # Self-merges are public targets too. A disclosed self-merge may be
        # represented exactly; undisclosed ones retain the nonself prior.
        if not recipients:
            return None
        return sender, self.pick(recipients, target, "recipient")

    def prior(self, target):
        known = self.known(target)
        pair = self.roles(target)
        need(pair is not None, "nonempty prior role hypotheses")
        return dict(sender=pair[0], recipient=pair[1], amount=(self.base_amount if known["amount"] is None
                    else known["amount"]), relationship_rank=[0, 0, 0, 0])

    def can_spend(self, position, event):
        note = self.notes[position]
        return (note["value"] >= FLOOR and note["born"] < event
                and position < self.events[event]["anchor_count"]
                and self.spent.get(position, event) == event)

    def make_residuals(self):
        result = []
        for event in self.payouts:
            row = self.events[event]
            # A partial payout alone is not the input-note amount. The separate
            # receipt_timing and cash_inverse attacks test cash-demand signals.
            if row["mode"] != 2:
                continue
            total = row["payout"] + row["fee"]
            owner = self.authors.get(event, {}).get("owner")
            result.append(dict(value=total, events=(event,), owner=owner, coinput=None, partial=False))
            for position, note in self.notes.items():
                if self.can_spend(position, event) and total - note["value"] >= FLOOR:
                    if owner is not None and note["owner"] not in (None, owner):
                        continue
                    result.append(dict(value=total - note["value"], events=(event,),
                        owner=owner if owner is not None else note["owner"], coinput=position, partial=False))
        return result

    def make_sums(self):
        result = []
        note_values = sorted((note["value"], position) for position, note in self.notes.items()
                             if note["value"] >= FLOOR)
        values = [value for value, _ in note_values]
        by_owner = defaultdict(list)
        for note in self.notes.values():
            if note["owner"] is not None and note["value"] >= FLOOR:
                by_owner[note["owner"]].append(note["value"])
        intervals = [(LOW, HIGH)]
        for owned_values in by_owner.values():
            totals = set(owned_values)
            totals.update(a + b for a, b in itertools.combinations(owned_values, 2))
            intervals.extend((max(FLOOR, total - FEE - HIGH), total - FEE - LOW)
                             for total in totals if total - FEE - LOW >= FLOOR)
        merged = []
        for low, high in sorted(intervals):
            if merged and low <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(high, merged[-1][1]))
            else:
                merged.append((low, high))
        for size in (2, 3):
            for events in itertools.combinations(self.payouts, size):
                value = sum(self.events[event]["payout"] + FEE for event in events)
                # Subsets are hypotheses, not proven note descendants. A
                # policy-tail candidate additionally requires partial legs and
                # a final whole exit; there is no artificial maximum time gap.
                partial = (self.events[events[-1]]["mode"] == 2
                           and all(self.events[event]["mode"] == 1 for event in events[:-1]))
                owners = {self.authors[event]["owner"] for event in events if event in self.authors}
                if len(owners) > 1:
                    continue
                result.append(dict(value=value, events=events,
                    owner=next(iter(owners)) if owners else None, coinput=None, partial=partial))
                # Partial/full chains can consume a tagged or otherwise known
                # co-input. Restrict only by provably irrelevant value bounds:
                # useful residues are payment-sized, or a complement of some
                # known at-most-two-input payment. No time-window pruning.
                for low, high in merged:
                    start = bisect_left(values, value - high)
                    stop = bisect_right(values, value - low)
                    for note_value, position in note_values[start:stop]:
                        note = self.notes[position]
                        if (not any(self.can_spend(position, event) for event in events)
                                or (owners and note["owner"] not in (None, next(iter(owners))))):
                            continue
                        result.append(dict(value=value - note_value, events=events,
                            owner=next(iter(owners)) if owners else note["owner"],
                            coinput=position, partial=partial))
        return result

    def eligible(self, target, residue, position=None, inputs=()):
        position = self.events[target]["new"][0] if position is None else position
        if residue["events"][0] <= target or position >= self.events[residue["events"][0]]["anchor_count"]:
            return False
        if residue["coinput"] in set(inputs) | set(self.events[target]["new"]):
            return False
        if position in self.spent and self.spent[position] not in residue["events"]:
            return False
        note = self.notes.get(position)
        return note is None or (note["value"] == residue["value"]
            and (residue["owner"] is None or note["owner"] in (None, residue["owner"])))

    def inputs(self, target):
        if target in self.authors:
            combos = [tuple(self.authors[target]["inputs"])]
        else:
            eligible = [position for position, note in self.notes.items()
                        if note["owner"] is not None and self.can_spend(position, target)]
            combos = [(position,) for position in eligible] + list(itertools.combinations(eligible, 2))
        result = []
        for positions in combos:
            if not positions or any(position not in self.notes or not self.can_spend(position, target)
                                    for position in positions):
                continue
            owners = {self.notes[position]["owner"] for position in positions}
            if len(owners) != 1 or None in owners:
                continue
            result.append((positions, next(iter(owners)), sum(self.notes[p]["value"] for p in positions) - FEE))
        return result

    def books(self, target):
        books = {name: {} for name in VARIANTS if name != "prior"}
        known = self.known(target)

        def offer(kind, value, sender=None, recipient=None, support=(), tier=1, coinput=None):
            if not LOW <= value <= HIGH or (known["amount"] is not None and known["amount"] != value):
                return
            pair = self.roles(target, sender, recipient)
            if pair is None:
                return
            # Honest prices are cent aligned; non-cent values can only match
            # the declared exact adversarial tags. This restricts hypotheses,
            # never installs a guessed author as a fact.
            tags = [role for role in range(8) if value in
                    (20 * SOMPI + (role + 1) * 1000, 20 * SOMPI + (role + 1) * 1000 + 1)]
            if value % CENT:
                if not tags or sender not in (None, tags[0]):
                    return
                pair = self.roles(target, tags[0], recipient)
                if pair is None:
                    return
            support = tuple(support)
            distance = sum(self.events[event]["minute"] - self.events[target]["minute"] for event in support)
            rank = (int(sender is not None) + int(recipient is not None), tier, -distance)
            key = (pair[0], pair[1], value)
            record = books[kind].setdefault(key, dict(rank=rank, supports=set()))
            record["rank"] = max(record["rank"], rank)
            record["supports"].add((support, coinput))

        direct = [residue for residue in self.residuals if self.eligible(target, residue)]
        sums = [residue for residue in self.sums if self.eligible(target, residue)]
        for residue in direct:
            kind = "residual" if residue["coinput"] is None else "coinput"
            offer(kind, residue["value"], recipient=residue["owner"], support=residue["events"],
                  tier=2, coinput=residue["coinput"])
            co_note = self.notes.get(residue["coinput"], {})
            known_tag = any(co_note.get("value") in (20 * SOMPI + (role + 1) * 1000,
                            20 * SOMPI + (role + 1) * 1000 + 1) for role in range(8))
            if residue["coinput"] is not None and (co_note["owner"] in self.members or known_tag):
                offer("colluder_tags", residue["value"], recipient=residue["owner"],
                      support=residue["events"], tier=3, coinput=residue["coinput"])
            root = residue["events"][0]
            if root in self.bridge_roots:
                owners = sorted(self.bridge_owners[root]) or [residue["owner"]]
                for owner in owners:
                    offer("bridge_ancestry", residue["value"], recipient=owner,
                          support=residue["events"], tier=3, coinput=residue["coinput"])
        for residue in sums:
            for kind in ("subset_nearest", "subset_supported"):
                offer(kind, residue["value"], recipient=residue["owner"], support=residue["events"],
                      tier=1, coinput=residue["coinput"])
            if residue["partial"]:
                offer("partial_tail", residue["value"], recipient=residue["owner"],
                      support=residue["events"], tier=2, coinput=residue["coinput"])
        for event in self.payouts:
            if event <= target:
                continue
            amount = self.events[event]["payout"]
            owner = self.authors.get(event, {}).get("owner")
            offer("receipt_timing", amount, recipient=owner, support=(event,))
            # A half-cash request rounded down admits 2*payout and 2*payout+1.
            # Stable low-amount tie break chooses the former if both survive.
            for value in (2 * amount, 2 * amount + 1):
                offer("cash_inverse", value, recipient=owner, support=(event,), tier=2)
            tag_value = amount + FEE
            if any(tag_value in (20 * SOMPI + (role + 1) * 1000,
                                 20 * SOMPI + (role + 1) * 1000 + 1) for role in range(8)):
                offer("colluder_tags", tag_value, recipient=owner, support=(event,), tier=3)

        def split(kind, residues):
            payment, change = self.events[target]["new"]
            if kind not in self.split_indices:
                index = defaultdict(lambda: defaultdict(list))
                for residue in residues:
                    index[residue["value"]][len(residue["events"])].append(residue)
                def fixed_rank(residue):
                    events = residue["events"]
                    return (-int(residue["owner"] is not None), sum(self.events[e]["minute"] for e in events),
                            self.events[events[-1]]["minute"] - self.events[events[0]]["minute"], events,
                            -1 if residue["coinput"] is None else residue["coinput"],
                            -1 if residue["owner"] is None else residue["owner"])
                for lengths in index.values():
                    for rows in lengths.values():
                        rows.sort(key=fixed_rank)
                self.split_indices[kind] = index
            def bounded(position, receipt=False):
                def rank(residue):
                    events = residue["events"]
                    distance = sum(self.events[event]["minute"] - self.events[target]["minute"] for event in events)
                    span = self.events[events[-1]]["minute"] - self.events[events[0]]["minute"]
                    return (-int(residue["owner"] is not None), distance, span, events,
                            -1 if residue["coinput"] is None else residue["coinput"],
                            -1 if residue["owner"] is None else residue["owner"])
                # This explicit candidate cap is part of the attack, not a
                # solver timeout. Other subset attacks retain every support.
                result = {}
                for value, lengths in self.split_indices[kind].items():
                    if (receipt and not LOW <= value <= HIGH) or (position in self.notes and self.notes[position]["value"] != value):
                        continue
                    candidates = []
                    for rows in lengths.values():
                        accepted = 0
                        for residue in rows:
                            if self.eligible(target, residue, position):
                                candidates.append(residue)
                                accepted += 1
                                if accepted == SPLIT_SUPPORT_LIMIT:
                                    break
                    if candidates:
                        # At each fixed leg count the target-minute offset is
                        # constant, so its first eight valid rows contain all
                        # possible members of the exact overall first eight.
                        result[value] = sorted(candidates, key=rank)[:SPLIT_SUPPORT_LIMIT]
                return result
            by_value = bounded(change)
            receipts = [row for rows in bounded(payment, receipt=True).values() for row in rows]
            for positions, sender, total in self.inputs(target):
                for receipt in receipts:
                    if not self.eligible(target, receipt, payment, positions):
                        continue
                    remainder = total - receipt["value"]
                    if remainder == 0:
                        alternatives = [dict(value=0, events=(), owner=sender, coinput=None)]
                    else:
                        alternatives = by_value.get(remainder, ()) if remainder >= FLOOR else ()
                    for tail in alternatives:
                        if tail["events"] and (set(tail["events"]) & set(receipt["events"])
                                or not self.eligible(target, tail, change, positions)
                                or tail["owner"] not in (None, sender)):
                            continue
                        if tail["coinput"] is not None and tail["coinput"] == receipt["coinput"]:
                            continue
                        offer(kind, receipt["value"], sender, receipt["owner"],
                              tuple(sorted(receipt["events"] + tail["events"])), tier=4)
        split("split", self.residuals)
        split("split_tail", self.residuals + [row for row in self.sums if row["partial"]])
        # A fixed public rank combines hypotheses. Keep every constituent as a
        # separate strategy so a poor ensemble cannot look like extra privacy.
        for kind, book in list(books.items()):
            if kind == "combined":
                continue
            for key, record in book.items():
                dest = books["combined"].setdefault(key, dict(rank=record["rank"], supports=set()))
                dest["rank"] = max(dest["rank"], record["rank"])
                dest["supports"].update(record["supports"])
        return books

    @staticmethod
    def best(book, fallback, strategy):
        if not book:
            return copy.deepcopy(fallback)
        def rank(item):
            key, record = item
            endpoints, tier, recency = record["rank"]
            supports = len(record["supports"])
            if strategy in ("subset_nearest", "receipt_timing", "cash_inverse"):
                return (recency, endpoints, tier, supports, -key[2], -key[0], -key[1])
            return (endpoints, tier, supports, recency, -key[2], -key[0], -key[1])
        key, record = max(book.items(), key=rank)
        return dict(sender=key[0], recipient=key[1], amount=key[2],
                    relationship_rank=[record["rank"][0], record["rank"][1],
                                       len(record["supports"]), record["rank"][2]])

    def row(self, target):
        prior = self.prior(target)
        books = self.books(target)
        guesses = {"prior": prior}
        guesses.update((kind, self.best(books[kind], prior, kind)) for kind in VARIANTS if kind != "prior")
        return dict(event=target, event_id=self.events[target]["event_id"], guesses=guesses)


def observe(public, directory, view, through_event=None, target_events=None):
    public, directory, view = prefix_inputs(public, directory, view, through_event)
    all_targets = [event["event"] for event in public["events"] if event["mode"] == 1 and not event["payout"]]
    if target_events is None:
        target_events = all_targets
    need(isinstance(target_events, list) and target_events == sorted(set(target_events))
         and all(integer(target) and target in all_targets for target in target_events),
         "unique ordered public payment target subset")
    floor = min(target_events) if target_events else len(public["events"])
    engine = Engine(public, directory, view, floor)
    rows = [engine.row(target) for target in target_events]
    profile = "pooled" if view["members"] else "C+D"
    if profile == "pooled":
        empty = dict(schema="kpi-working-balance-view-v1", members=[], authored=[], receipts=[])
        public_engine = Engine(public, directory, empty, floor)
        for row in rows:
            guesses = public_engine.row(row["event"])["guesses"]
            row["guesses"].update(("C_" + name, guess) for name, guess in guesses.items())
    return dict(schema=SCHEMA, complete=True, profile=profile, through_event=len(public["events"]) - 1,
                public_sha256=digest(public), directory_sha256=digest(directory), view_sha256=digest(view),
                target_events_sha256=digest(target_events),
                rows=rows, boundary="finite arithmetic hypotheses; not exhaustive inference or native evidence")


def controls():
    # Import test fixtures only on an explicit development-control call.
    import working_balance_observer_tests
    return working_balance_observer_tests.controls()
