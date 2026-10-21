#!/usr/bin/env python3
"""Prospective arithmetic withdrawal comparison, never native transaction data.

No workload is generated on import. The runner freezes this module before
supplying a fresh private seed. All cryptographic identifiers below are opaque
model labels; their existence establishes no cryptographic or recovery property.
"""
import copy
import hashlib
import itertools
import json

SOMPI = 100_000_000
FEE = 40_000_000
FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
BRIDGE_FEE = 100_000
MAX = 2_900_000_000_000_000_000
ROLES = list(range(32))
ADVERSARIES = list(range(8))
CELLS = ("overlap-independent", "sparse-independent",
         "overlap-correlated", "sparse-correlated")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, low=0, high=MAX):
    need(type(value) is int and low <= value <= high, "integer/range")
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Stream:
    """Domain-separated SHAKE256 draws; experiment sampler, not wallet keys."""
    def __init__(self, key, domain):
        need(isinstance(key, bytes) and len(key) == 32, "32-byte experiment seed")
        label = domain.encode("ascii")
        self.prefix = b"kpi-working-balance-sampler-v1" + len(label).to_bytes(2, "big") + label + key
        self.counter = 0

    def block(self):
        result = hashlib.shake_256(self.prefix + self.counter.to_bytes(8, "big")).digest(32)
        self.counter += 1
        return result

    def below(self, bound):
        need(type(bound) is int and 0 < bound <= 2**256, "draw bound")
        limit = 2**256 - (2**256 % bound)
        while True:
            value = int.from_bytes(self.block(), "big")
            if value < limit:
                return value % bound

    def choose(self, values):
        need(bool(values), "empty selection")
        return values[self.below(len(values))]

    def shuffle(self, values):
        values = list(values)
        for i in range(len(values) - 1, 0, -1):
            j = self.below(i + 1)
            values[i], values[j] = values[j], values[i]
        return values


class Labels:
    def __init__(self, key, domain):
        self.stream = Stream(key, "opaque/" + domain)
        self.seen = set()

    def new(self):
        value = self.stream.block().hex()
        need(value != "0" * 64 and value not in self.seen, "opaque-label collision")
        self.seen.add(value)
        return value


def public_policy():
    return {
        "schema": "kpi-working-balance-policy-v1", "cells": list(CELLS),
        "roles": ROLES, "adversaries": ADVERSARIES, "payments": 64,
        "cash_requests": 32, "urgent_request_indices": [7, 23],
        "initial_net_capitals": [350*SOMPI, 700*SOMPI, 1400*SOMPI],
        "honest_send_counts": {"0": 4, "1": 8, "2": 8, "6": 4},
        "adversary_send_count": 2, "first_four": "roles0..3 to four six-send honest roles",
        "preferred_probability_percent": 70,
        "invoice_probability_percent": 60, "invoice_amounts": [x*SOMPI for x in (10, 20, 25, 40, 50)],
        "irregular_amounts": "uniform 4001 cent values 10 through 50 inclusive",
        "tag_formula": "20*SOMPI+(role+1)*1000+authored_ordinal",
        "payment_gaps": {"overlap": [1, 2, 3], "sparse": [60, 120, 180]},
        "cash_gap": 1, "final_gap": 60,
        "independent_cash_sizes": [10*SOMPI, 20*SOMPI, 25*SOMPI],
        "independent_cash_owners": "separate uniform permutation of all 32 roles, one each",
        "correlated_cash": "preceding recipient and floor-half payment amount",
        "fee": FEE, "floor": FLOOR, "payout_floor": PAYOUT_FLOOR, "bridge_fee": BRIDGE_FEE,
        "pay_selector": "largest then oldest other; reenter surplus; merge if needed",
        "cash_selector": "least adequate sum/fewest inputs/positions else greatest pair/positions",
        "cash_policy": "earmark cumulative external liquidity; external surplus first",
        "reentry": "all owner external coins; bridge change preserves earmark; all surplus admitted",
        "partial": "max(requested shortage,payout floor); floor-invalid change added to public payout",
        "partial_outputs": "change then dummy", "merge_outputs": "merged value then dummy",
        "final": "shared private role permutation; lowest-position pairs then singleton",
        "scope": "arithmetic model with opaque identifiers, not native transactions or proofs",
    }


def plan(seed, cell):
    need(cell in CELLS, "cell")
    activity = Stream(seed, cell + "/activity")
    invoices = Stream(seed, cell + "/invoices")
    cash = Stream(seed, cell + "/cash")
    timing = Stream(seed, cell + "/timing")
    capital = Stream(seed, cell + "/capital")
    final = Stream(seed, cell + "/final")
    honest = activity.shuffle(list(range(8, 32)))
    counts = [2]*8 + [0]*24
    for group, count in ((honest[4:12], 1), (honest[12:20], 2), (honest[20:], 6)):
        for owner in group:
            counts[owner] = count
    preferred = [activity.choose([r for r in ROLES if r != owner]) for owner in ROLES]
    remaining = [r for r in ROLES for _ in range(counts[r] - int(r < 4))]
    senders = list(range(4)) + activity.shuffle(remaining)
    cash_owners = cash.shuffle(ROLES)
    payments, requests, seen, minute = [], [], [0]*32, 0
    for ordinal, sender in enumerate(senders):
        recipient = honest[20+ordinal] if ordinal < 4 else (
            preferred[sender] if invoices.below(100) < 70 else
            invoices.choose([r for r in ROLES if r != sender]))
        if sender < 8:
            amount = 20*SOMPI + (sender+1)*1000 + seen[sender]
        elif invoices.below(100) < 60:
            amount = invoices.choose(public_policy()["invoice_amounts"])
        else:
            amount = 10*SOMPI + invoices.below(4001)*1_000_000
        seen[sender] += 1
        minute += timing.choose([1, 2, 3] if cell.startswith("overlap") else [60, 120, 180])
        payments.append(dict(obligation=ordinal, sender=sender, recipient=recipient,
                             amount=amount, minute=minute))
        if ordinal % 2:
            if cell.endswith("independent"):
                owner, wanted = cash_owners[len(requests)], cash.choose([10*SOMPI, 20*SOMPI, 25*SOMPI])
            else:
                owner, wanted = recipient, amount // 2
            minute += 1
            index = len(requests)
            requests.append(dict(request=index, owner=owner, amount=wanted, minute=minute,
                                 after_payment=ordinal, urgent=index in (7, 23)))
    return dict(capitals=[capital.choose(public_policy()["initial_net_capitals"]) for _ in ROLES],
                payments=payments, cash_requests=requests, final_order=final.shuffle(ROLES),
                final_minute=minute+60, activity=counts)


class Ledger:
    """Private arithmetic state. Only public()/view() may be observer inputs."""
    def __init__(self, seed, cell, arm):
        need(arm in ("whole", "partial"), "arm")
        self.cell, self.arm = cell, arm
        self.labels = Labels(seed, cell + "/" + arm)
        self.events, self.hidden, self.notes, self.commitments = [], [], [], []
        self.directory, self.targets, self.cash_audit = {}, [], []
        self.coins = [[] for _ in ROLES]
        self.earmarked = [0]*32
        self.injected = self.reserve = self.pool_fees = self.bridge_fees = 0
        self.partial_notes, self.tagged_notes = set(), set()
        self.metrics = dict(reentries=0, merges=0, partial_payouts=0, whole_payouts=0,
                            urgent_exit_operations=0, final_exit_operations=0,
                            peak_external_surplus=0, total_withdrawal_overshoot=0,
                            private_change_reused_by_pay=0, tagged_receipts_spent_as_coinput=0)

    def available(self, owner):
        integer(owner, 0, 31)
        return [p for p, n in enumerate(self.notes) if n["value"] and n["owner"] == owner and not n["spent"]]

    def external(self, owner):
        return sum(c["value"] for c in self.coins[owner])

    def surplus(self, owner):
        result = self.external(owner) - self.earmarked[owner]
        need(result >= 0, "earmarked external liquidity lost")
        return result

    def check_accounting(self):
        need(self.reserve == sum(n["value"] for n in self.notes if not n["spent"]), "reserve/liability mismatch")
        need(self.injected == self.reserve + sum(self.external(r) for r in ROLES)
             + self.pool_fees + self.bridge_fees, "native value not conserved")
        need(all(self.earmarked[r] <= self.external(r) for r in ROLES), "cash earmark consumed")
        for r in ROLES:
            self.metrics["peak_external_surplus"] = max(self.metrics["peak_external_surplus"], self.surplus(r))

    def operation(self, owner, kind, inputs, minute, *, amount=0, recipient=None,
                  obligation=None, request=None, phase="payment", bridge=None):
        integer(owner, 0, 31)
        integer(minute)
        integer(amount)
        need(kind in ("admit", "pay", "partial", "exit", "merge"), "kind")
        need(inputs == sorted(set(inputs)), "input positions canonical")
        need(len(inputs) == 0 if kind == "admit" else 1 <= len(inputs) <= 2, "input arity")
        for p in inputs:
            integer(p, 0, len(self.notes)-1)
            n = self.notes[p]
            need(n["value"] >= FLOOR and n["owner"] == owner and not n["spent"], "ownership/double spend")
        total = sum(self.notes[p]["value"] for p in inputs)
        deposit, payout = (amount if kind == "admit" else 0), 0
        integer(total + deposit)
        if kind == "admit":
            need(amount >= FEE + FLOOR, "admission floor")
            outputs, mode = [(amount-FEE, owner), (0, None)], 0
        elif kind == "pay":
            integer(recipient, 0, 31)
            need(amount >= FLOOR, "payment floor")
            outputs, mode = [(amount, recipient), (total-amount-FEE, owner)], 1
        elif kind == "partial":
            need(amount >= PAYOUT_FLOOR, "payout floor")
            payout = amount
            outputs, mode = [(total-payout-FEE, owner), (0, None)], 1
        elif kind == "merge":
            outputs, mode = [(total-FEE, owner), (0, None)], 1
        else:
            payout = total-FEE
            need(amount == payout and payout >= PAYOUT_FLOOR, "whole exit value/floor")
            outputs, mode = [], 2
        for value, target in outputs:
            integer(value)
            need(value == 0 or value >= FLOOR, "private output floor")
        need(total+deposit == sum(v for v, _ in outputs)+payout+FEE, "operation conservation")
        if self.events:
            need(minute >= self.events[-1]["minute"], "time order")
        before = len(self.notes)
        need(before + len(outputs) <= 65_536 and len(self.events) < 65_535, "v6 capacity")
        index, event_id = len(self.events), self.labels.new()
        new = list(range(before, before+len(outputs)))
        funding = self.labels.new() if mode == 0 else ""
        pub = dict(event=index, event_id=event_id, minute=minute, mode=mode, fee=FEE,
                   deposit=deposit, payout=payout, reserve=self.reserve+deposit-payout-FEE,
                   anchor_count=0 if mode == 0 else before, count_before=before, new=new,
                   nullifiers=["0"*64, "0"*64] if mode == 0 else [self.labels.new(), self.labels.new()],
                   destination=self.labels.new() if payout else "", funding_group=funding,
                   bridge=copy.deepcopy(bridge))
        outrows = [dict(position=p, value=value, recipient=target if value else None)
                   for p, (value, target) in zip(new, outputs)]
        hid = dict(event=index, owner=owner, kind=kind, inputs=list(inputs), outputs=outrows,
                   obligation=obligation, request=request, phase=phase)
        # No unvalidated event is accepted into either public or private state.
        self.events.append(pub)
        self.hidden.append(hid)
        for p in inputs:
            self.notes[p]["spent"] = True
        for value, target in outputs:
            self.notes.append(dict(value=value, owner=target if value else None, spent=False))
            self.commitments.append(self.labels.new())
        self.reserve = pub["reserve"]
        self.pool_fees += FEE
        if kind == "admit":
            if bridge is None:
                need(phase == "initial", "unbacked noninitial admission")
                self.injected += deposit
                self.directory[funding] = owner
            else:
                need(phase == "payment", "bridge outside payment need")
        if payout:
            self.coins[owner].append(dict(ref=event_id, value=payout))
        if kind == "partial":
            self.metrics["partial_payouts"] += 1
            self.partial_notes.add(new[0])
        if kind == "exit":
            self.metrics["whole_payouts"] += 1
            if phase in ("urgent", "final"):
                self.metrics[phase+"_exit_operations"] += 1
        if kind == "merge":
            self.metrics["merges"] += 1
        if kind == "pay":
            self.metrics["private_change_reused_by_pay"] += sum(p in self.partial_notes for p in inputs)
            self.metrics["tagged_receipts_spent_as_coinput"] += int(len(inputs) == 2 and any(p in self.tagged_notes for p in inputs))
            if owner in ADVERSARIES:
                self.tagged_notes.add(new[0])
            self.targets.append(dict(obligation=obligation, event=index, sender=owner,
                                     recipient=recipient, amount=amount))
        self.check_accounting()
        return index

    def admit_initial(self, owner, net):
        return self.operation(owner, "admit", [], 0, amount=integer(net, FLOOR)+FEE, phase="initial")

    def reenter(self, owner, minute, obligation):
        surplus = self.surplus(owner)
        if surplus < BRIDGE_FEE+FEE+FLOOR:
            return False
        sources = copy.deepcopy(self.coins[owner])
        total, deposit, change = self.external(owner), surplus-BRIDGE_FEE, self.earmarked[owner]
        bridge = dict(bridge_id=self.labels.new(), sources=sources, input_value=total,
                      deposit=deposit, fee=BRIDGE_FEE, change=change,
                      change_ref=self.labels.new() if change else "")
        need(total == deposit+BRIDGE_FEE+change, "bridge conservation")
        self.coins[owner] = ([dict(ref=bridge["change_ref"], value=change)] if change else [])
        self.bridge_fees += BRIDGE_FEE
        self.metrics["reentries"] += 1
        self.operation(owner, "admit", [], minute, amount=deposit, obligation=obligation,
                       phase="payment", bridge=bridge)
        return True

    def pay_selection(self, owner):
        available = self.available(owner)
        if not available:
            return []
        first = min(available, key=lambda p: (-self.notes[p]["value"], p))
        rest = [p for p in available if p != first]
        return sorted([first] + ([min(rest)] if rest else []))

    def pay(self, row):
        owner, amount, minute = row["sender"], row["amount"], row["minute"]
        reentered = False
        while True:
            selected = self.pay_selection(owner)
            total = sum(self.notes[p]["value"] for p in selected)
            remainder = total-amount-FEE
            if selected and (remainder == 0 or remainder >= FLOOR):
                return self.operation(owner, "pay", selected, minute, amount=amount,
                                      recipient=row["recipient"], obligation=row["obligation"])
            if not reentered:
                reentered = True
                if self.reenter(owner, minute, row["obligation"]):
                    continue
            need(len(selected) == 2 and len(self.available(owner)) > 2, "unfunded private obligation")
            self.operation(owner, "merge", selected, minute, obligation=row["obligation"])

    def cash_selection(self, owner, shortage):
        shortage = max(integer(shortage, 1), PAYOUT_FLOOR)
        available = self.available(owner)
        need(bool(available), "unfunded cash obligation")
        sets = [(p,) for p in available] + list(itertools.combinations(available, 2))
        adequate = [ps for ps in sets if sum(self.notes[p]["value"] for p in ps) >= shortage+FEE]
        if adequate:
            return list(min(adequate, key=lambda ps: (sum(self.notes[p]["value"] for p in ps), len(ps), ps)))
        pairs = [ps for ps in sets if len(ps) == min(2, len(available))]
        return list(min(pairs, key=lambda ps: (-sum(self.notes[p]["value"] for p in ps), ps)))

    def drain(self, owner, minute, phase, request=None):
        while self.available(owner):
            selected = self.available(owner)[:2]
            self.operation(owner, "exit", selected, minute,
                           amount=sum(self.notes[p]["value"] for p in selected)-FEE,
                           request=request, phase=phase)

    def cash(self, row):
        owner, wanted, minute, request = row["owner"], row["amount"], row["minute"], row["request"]
        before, old_earmark, start = self.external(owner), self.earmarked[owner], len(self.events)
        required = old_earmark+wanted
        while self.external(owner) < required:
            shortage = required-self.external(owner)
            selected = self.cash_selection(owner, shortage)
            total = sum(self.notes[p]["value"] for p in selected)
            payout = min(max(shortage, PAYOUT_FLOOR), total-FEE)
            change = total-payout-FEE
            if self.arm == "whole" or change < FLOOR:
                payout = total-FEE
                kind = "exit"
            else:
                kind = "partial"
            self.metrics["total_withdrawal_overshoot"] += max(0, payout-shortage)
            self.operation(owner, kind, selected, minute, amount=payout, request=request, phase="cash")
        self.earmarked[owner] = required
        if row["urgent"]:
            self.drain(owner, minute, "urgent", request)
        self.check_accounting()
        self.cash_audit.append(dict(request=request, owner=owner, amount=wanted,
                                   earmarked_before=old_earmark, earmarked_after=required,
                                   external_before=before, external_after=self.external(owner),
                                   event_start=start, event_end=len(self.events)-1,
                                   complete=self.external(owner) >= required, urgent=row["urgent"]))

    def public(self):
        return dict(schema="kpi-working-balance-public-v1", roles=ROLES.copy(),
                    adversaries=ADVERSARIES.copy(), events=copy.deepcopy(self.events),
                    commitments=self.commitments.copy())

    def view(self, members):
        need(members == sorted(set(members)) and set(members) <= set(ADVERSARIES), "view members")
        authored, receipts = [], []
        for row in self.hidden:
            if row["owner"] in members:
                authored.append({key: copy.deepcopy(row[key]) for key in ("event", "owner", "inputs", "outputs")})
            for out in row["outputs"]:
                if out["value"] and out["recipient"] in members:
                    receipts.append(dict(position=out["position"], value=out["value"], owner=out["recipient"]))
        return dict(schema="kpi-working-balance-view-v1", members=list(members), authored=authored, receipts=receipts)

    def bundle(self, work):
        self.check_accounting()
        private = [sum(self.notes[p]["value"] for p in self.available(r)) for r in ROLES]
        final = dict(external_values=[self.external(r) for r in ROLES], earmarked=self.earmarked.copy(),
                     surplus=[self.surplus(r) for r in ROLES], private_values=private,
                     reserve=self.reserve, injected=self.injected, pool_fees=self.pool_fees,
                     bridge_fees=self.bridge_fees)
        cost = dict(self.metrics, pool_operations=len(self.events), pool_fees=self.pool_fees,
                    bridge_fees=self.bridge_fees, ordinary_payment_fees=len(self.targets)*FEE,
                    payment_principal=sum(p["amount"] for p in work["payments"]),
                    initial_principal=sum(work["capitals"]), external_total=sum(final["external_values"]),
                    earmarked_total=sum(self.earmarked), final_reserve=self.reserve,
                    all_payments_met=len(self.targets) == len(work["payments"]),
                    all_cash_met=len(self.cash_audit) == len(work["cash_requests"]) and all(r["complete"] for r in self.cash_audit),
                    modeled_cash_delay_minutes=0, modeled_urgent_delay_minutes=0)
        return dict(public=self.public(),
                    directory=dict(schema="kpi-working-balance-directory-v1", initial_funding_owners=dict(self.directory)),
                    views={"C+D": self.view([]), "pooled": self.view(ADVERSARIES)},
                    truth=dict(schema="kpi-working-balance-truth-v1", cell=self.cell, arm=self.arm,
                               plan=copy.deepcopy(work), events=copy.deepcopy(self.hidden),
                               cash_audit=copy.deepcopy(self.cash_audit), targets=copy.deepcopy(self.targets), final=final),
                    cost=cost)


def replay(seed, cell, arm, work):
    ledger = Ledger(seed, cell, arm)
    for owner, net in enumerate(work["capitals"]):
        ledger.admit_initial(owner, net)
    requests = {r["after_payment"]: r for r in work["cash_requests"]}
    for row in work["payments"]:
        ledger.pay(row)
        if row["obligation"] in requests:
            ledger.cash(requests[row["obligation"]])
    for owner in work["final_order"]:
        ledger.drain(owner, work["final_minute"], "final")
    need(ledger.reserve == 0, "incomplete final drainage")
    return ledger.bundle(work)


def generate(seed):
    """Fresh caller-owned private seed only after the prospective freeze."""
    need(isinstance(seed, bytes) and len(seed) == 32, "32-byte experiment seed")
    result = {}
    for cell in CELLS:
        work = plan(seed, cell)
        result[cell] = {arm: replay(seed, cell, arm, work) for arm in ("whole", "partial")}
    return result


def controls():
    """Public handmade controls only; never creates a held-out seed."""
    import unittest
    from working_balance_model_tests import ModelTests
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ModelTests)
    outcome = unittest.TestResult()
    suite.run(outcome)
    need(outcome.wasSuccessful(), repr(outcome.errors + outcome.failures))
    return {"schema": "kpi-working-balance-model-controls-v1", "tests": outcome.testsRun,
            "passed": True, "scope": "public development fixtures, arithmetic only"}


if __name__ == "__main__":
    print(json.dumps(controls(), indent=2))
