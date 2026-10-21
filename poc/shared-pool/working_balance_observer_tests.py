"""Handmade public controls; no held-out histories or private seeds."""
import copy
import unittest
from fractions import Fraction

import working_balance_observer as observer

S = observer.SOMPI
F = observer.FEE


class Fixture:
    def __init__(self):
        self.public = dict(schema="kpi-working-balance-public-v1", roles=list(range(32)),
                           adversaries=list(range(8)), events=[], commitments=[])
        self.directory = dict(schema="kpi-working-balance-directory-v1", initial_funding_owners={})
        self.view = dict(schema="kpi-working-balance-view-v1", members=[], authored=[], receipts=[])
        for owner in range(32):
            event = self.add(0, deposit=100 * S + F, funding_group="funding-" + str(owner))
            self.directory["initial_funding_owners"][self.public["events"][event]["funding_group"]] = owner
        # Declared public first-four tagged sends precede all custom targets.
        for _ in range(4):
            self.add(1)

    def add(self, mode, payout=0, deposit=0, funding_group="", bridge=None):
        index = len(self.public["events"])
        count = len(self.public["commitments"])
        new = [] if mode == 2 else [count, count + 1]
        self.public["commitments"].extend("commitment-" + str(position) for position in new)
        reserve = self.public["events"][-1]["reserve"] if index else 0
        self.public["events"].append(dict(event=index, event_id="event-" + str(index), minute=index,
            mode=mode, fee=F, deposit=deposit, payout=payout, reserve=reserve + deposit - payout - F,
            anchor_count=count, count_before=count, new=new,
            nullifiers=["nf-" + str(index) + "-0", "nf-" + str(index) + "-1"],
            destination="destination-" + str(index) if payout else "", funding_group=funding_group,
            bridge=bridge))
        return index

    def observe(self, end=None, view=None):
        return observer.observe(self.public, self.directory, self.view if view is None else view, end)


def controls():
    checks = []

    def check(name, ok):
        observer.need(ok, "observer control: " + name)
        checks.append(dict(name=name, passed=True))

    def rejects(call):
        try:
            call()
        except (ValueError, KeyError, TypeError):
            return True
        return False

    amount, probability = observer.amount_prior()
    check("exact distribution-aware prior", amount == 45 * S and probability == Fraction(21103, 100025))

    tag_fixture = Fixture()
    tag_engine = observer.Engine(*observer.prefix_inputs(tag_fixture.public, tag_fixture.directory, tag_fixture.view))
    check("declared first four tags expose sender and amount but no recipient",
          all(tag_engine.known(32 + role) == dict(sender=role, recipient=None,
              amount=20 * S + (role + 1) * 1000) for role in range(4)))

    fixture = Fixture()
    target = fixture.add(1)
    fixture.add(2, payout=40 * S - F)
    row = fixture.observe()["rows"][-1]
    check("whole receipt cashout exposes its fee-adjusted amount", row["guesses"]["residual"]["amount"] == 40 * S)
    created = fixture.observe(target)
    check("creation has no future-payout inference", all(g["amount"] == 45 * S
          for g in created["rows"][-1]["guesses"].values()))
    check("positive-payout events are not private payment targets", len(fixture.observe()["rows"]) == 5)

    partial = Fixture()
    pt = partial.add(1)
    partial.add(1, payout=20 * S)
    partial.add(2, payout=19 * S + 20_000_000)
    guesses = partial.observe()["rows"][-1]["guesses"]
    check("partial plus complete tail reconstructs original receipt with both fees",
          guesses["partial_tail"]["amount"] == 40 * S)
    check("partial cash inverse tests receipt-correlated request rule",
          guesses["cash_inverse"]["amount"] == 40 * S)
    check("partial SPEND never becomes payment target", len(partial.observe()["rows"]) == 5)
    check("partial alone is not misclassified as whole input amount",
          partial.observe(pt + 1)["rows"][-1]["guesses"]["residual"]["amount"] == 45 * S)

    triple = Fixture()
    tt = triple.add(1)
    triple.add(1, payout=10 * S)
    triple.add(1, payout=10 * S)
    triple.add(2, payout=18 * S + 80_000_000)
    book = observer.Engine(*observer.prefix_inputs(triple.public, triple.directory, triple.view)).books(tt)
    check("three-payout subset includes hand-ledger amount", any(key[2] == 40 * S for key in book["partial_tail"]))

    coinput = Fixture()
    coinput.add(1)
    coinput.add(2, payout=140 * S - F)
    check("known coinput subtraction finds otherwise out-of-range amount",
          coinput.observe()["rows"][-1]["guesses"]["coinput"]["amount"] == 40 * S)
    co_tail = Fixture()
    co_tail.add(1)
    co_tail.add(1, payout=20 * S)
    co_tail.add(2, payout=119 * S + 20_000_000)
    check("partial-tail sum subtracts known eligible coinput",
          co_tail.observe()["rows"][-1]["guesses"]["partial_tail"]["amount"] == 40 * S)
    late_coin = Fixture()
    original = late_coin.add(1)
    late_coin.add(1, payout=10 * S)
    received = late_coin.add(1)
    late_coin.add(2, payout=49 * S + 20_000_000)
    late_view = dict(schema="kpi-working-balance-view-v1", members=list(range(8)), authored=[],
                     receipts=[dict(position=late_coin.public["events"][received]["new"][0], value=20 * S, owner=0)])
    late_engine = observer.Engine(*observer.prefix_inputs(late_coin.public, late_coin.directory, late_view))
    check("tail can subtract a known coinput born after first partial leg",
          any(key[2] == 40 * S for key in late_engine.books(original)["partial_tail"]))

    split = Fixture()
    split.add(1)
    split.add(2, payout=40 * S - F)
    split.add(2, payout=59 * S + 20_000_000)
    check("known input plus later receipt and change satisfies split equation",
          split.observe()["rows"][-1]["guesses"]["split"]["amount"] == 40 * S)

    pooled = dict(schema="kpi-working-balance-view-v1", members=list(range(8)), authored=[], receipts=[])
    public_result, pooled_result = partial.observe(), partial.observe(view=pooled)
    check("pooled includes every exact unchanged public strategy",
          all(pooled_row["guesses"]["C_" + name] == public_row["guesses"][name]
              for public_row, pooled_row in zip(public_result["rows"], pooled_result["rows"])
              for name in observer.VARIANTS))
    check("variant roster complete and stable", tuple(public_result["rows"][0]["guesses"]) == observer.variants("C")
          and set(pooled_result["rows"][0]["guesses"]) == set(observer.variants("pooled")))
    for profile in (partial.view, pooled):
        all_rows = partial.observe(view=profile)["rows"]
        selected = observer.observe(partial.public, partial.directory, profile, target_events=[pt])
        check("public target-subset optimization preserves exact selected row",
              selected["rows"] == [row for row in all_rows if row["event"] == pt]
              and selected["target_events_sha256"] == observer.digest([pt]))
    check("target selection cannot include a withdrawal",
          rejects(lambda: observer.observe(partial.public, partial.directory, partial.view, target_events=[pt + 1])))

    selfmerge = Fixture()
    merge = selfmerge.add(1)
    new = selfmerge.public["events"][merge]["new"]
    own = copy.deepcopy(pooled)
    own["authored"] = [dict(event=merge, owner=0, inputs=[0], outputs=[
        dict(position=new[0], value=100 * S - F, recipient=0), dict(position=new[1], value=0, recipient=None)])]
    self_result = selfmerge.observe(view=own)
    check("disclosed selfmerge remains an observable target with defined prior",
          len(self_result["rows"]) == 5 and self_result["rows"][-1]["guesses"]["prior"]["sender"] == 0
          and self_result["rows"][-1]["guesses"]["prior"]["recipient"] == 0)

    future = Fixture()
    early = future.add(1)
    future_event = future.add(1)
    future_view = copy.deepcopy(pooled)
    future_view["receipts"] = [dict(position=future.public["events"][future_event]["new"][0], value=40 * S, owner=0)]
    future_empty = future.observe(early, pooled)
    future_populated = future.observe(early, future_view)
    check("future participant receipts removed before engine construction", future_empty == future_populated)
    before = copy.deepcopy(future.public)
    before["events"][-1]["hidden_owner"] = 12
    check("future public fields cannot influence earlier prefix",
          observer.observe(before, future.directory, pooled, early) == future_empty)
    check("closed current prefix rejects hidden public owner field",
          rejects(lambda: observer.observe(before, future.directory, pooled)))

    malformed = copy.deepcopy(fixture.public)
    malformed["events"][target]["fee"] = True
    check("boolean amount rejected rather than accepted as integer",
          rejects(lambda: observer.observe(malformed, fixture.directory, fixture.view)))
    bad_view = copy.deepcopy(pooled)
    bad_view["truth"] = []
    check("closed participant surface rejects truth attachment",
          rejects(lambda: fixture.observe(view=bad_view)))
    bad_view = copy.deepcopy(pooled)
    bad_view["receipts"] = [dict(position=64, value=40 * S, owner=12)]
    check("honest receipt cannot enter pooled knowledge",
          rejects(lambda: fixture.observe(view=bad_view)))

    bridge = Fixture()
    bt = bridge.add(1)
    payout = bridge.add(2, payout=40 * S - F)
    source = bridge.public["events"][payout]
    deposit = 20 * S + F
    admit = bridge.add(0, deposit=deposit, funding_group="reentry", bridge=dict(bridge_id="bridge-0",
        sources=[dict(ref=source["event_id"], value=source["payout"])], input_value=source["payout"],
        deposit=deposit, fee=100_000, change=source["payout"] - deposit - 100_000, change_ref="bridge-change-0"))
    known_admit = copy.deepcopy(pooled)
    positions = bridge.public["events"][admit]["new"]
    known_admit["authored"] = [dict(event=admit, owner=0, inputs=[], outputs=[
        dict(position=positions[0], value=20 * S, recipient=0), dict(position=positions[1], value=0, recipient=0)])]
    engine = observer.Engine(*observer.prefix_inputs(bridge.public, bridge.directory, known_admit))
    check("native ancestry produces a fallible source-owner hypothesis", engine.bridge_owners[payout] == {0})
    check("native ancestry never installs guessed owner as payment fact", engine.known(bt)["recipient"] is None)
    return dict(passed=True, complete=True, checks=checks)


class ObserverControls(unittest.TestCase):
    def test_controls(self):
        result = controls()
        self.assertTrue(result["passed"])
        self.assertTrue(result["complete"])
        self.assertGreaterEqual(len(result["checks"]), 20)


if __name__ == "__main__":
    unittest.main()
