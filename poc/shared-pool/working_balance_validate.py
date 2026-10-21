"""Independent stdlib accounting validator for the working-balance screen.

Consumes an already authorized bundle in memory. No file access, generation,
observer import, policy selection search, or output of private identities.
"""
import json

SOMPI = 100_000_000
FEE, FLOOR, PAYOUT_FLOOR, BRIDGE_FEE = 40_000_000, 60_000_000, 10_000_000, 100_000
MAX = 2_900_000_000_000_000_000
CELLS = {"overlap-independent", "sparse-independent", "overlap-correlated", "sparse-correlated"}


def require(condition):
    if not condition:
        raise ValueError("working-balance-validation-rejected")


def integer(value, low=0, high=MAX):
    require(type(value) is int and low <= value <= high)
    return value


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def same(left, right):
    # Preserve integer/boolean distinctions, including inside nested records.
    require(json.dumps(left, sort_keys=True, allow_nan=False) ==
            json.dumps(right, sort_keys=True, allow_nan=False))


def validate_bundle(public, directory, truth, cost):
    fields(public, "schema roles adversaries events commitments")
    fields(directory, "schema initial_funding_owners")
    fields(truth, "schema cell arm plan events cash_audit targets final")
    require(public["schema"] == "kpi-working-balance-public-v1")
    require(directory["schema"] == "kpi-working-balance-directory-v1")
    require(truth["schema"] == "kpi-working-balance-truth-v1")
    same(public["roles"], list(range(32)))
    same(public["adversaries"], list(range(8)))
    require(truth["cell"] in CELLS and truth["arm"] in ("whole", "partial"))
    events, hidden, work = public["events"], truth["events"], truth["plan"]
    require(type(events) is list and 32 < len(events) < 65_535)
    require(type(hidden) is list and len(hidden) == len(events))
    require(type(public["commitments"]) is list and len(public["commitments"]) <= 65_536)
    require(type(truth["cash_audit"]) is list and len(truth["cash_audit"]) == 32)
    require(type(directory["initial_funding_owners"]) is dict)
    fields(work, "capitals payments cash_requests final_order final_minute activity")
    require(type(work["capitals"]) is list and len(work["capitals"]) == 32)
    for value in work["capitals"]:
        require(integer(value) in (350*SOMPI, 700*SOMPI, 1400*SOMPI))
    require(type(work["payments"]) is list and len(work["payments"]) == 64)
    require(type(work["cash_requests"]) is list and len(work["cash_requests"]) == 32)
    require(type(work["final_order"]) is list)
    for owner in work["final_order"]:
        integer(owner, 0, 31)
    require(sorted(work["final_order"]) == list(range(32)))
    sends, previous_minute = [0]*32, 0
    for k, payment in enumerate(work["payments"]):
        fields(payment, "obligation sender recipient amount minute")
        same(payment["obligation"], k)
        sender, recipient = integer(payment["sender"], 0, 31), integer(payment["recipient"], 0, 31)
        amount, minute = integer(payment["amount"], FLOOR), integer(payment["minute"])
        require(sender != recipient)
        require(minute-previous_minute in ((1, 2, 3) if truth["cell"].startswith("overlap") else (60, 120, 180)))
        if sender < 8:
            require(amount == 20*SOMPI+(sender+1)*1000+sends[sender])
        else:
            require(10*SOMPI <= amount <= 50*SOMPI and amount % 1_000_000 == 0)
        if k < 4:
            require(sender == k and recipient >= 8)
        sends[sender] += 1
        previous_minute = minute
        if k % 2:
            request = work["cash_requests"][k//2]
            fields(request, "request owner amount minute after_payment urgent")
            same(request["request"], k//2)
            same(request["after_payment"], k)
            same(request["urgent"], k//2 in (7, 23))
            owner, wanted = integer(request["owner"], 0, 31), integer(request["amount"], PAYOUT_FLOOR)
            require(integer(request["minute"]) == minute+1)
            if truth["cell"].endswith("correlated"):
                require((owner, wanted) == (recipient, amount//2))
            else:
                require(wanted in (10*SOMPI, 20*SOMPI, 25*SOMPI))
            previous_minute += 1
    require(sends[:8] == [2]*8 and sorted(sends[8:]) == [0]*4+[1]*8+[2]*8+[6]*4)
    require(len({p["recipient"] for p in work["payments"][:4]}) == 4)
    require(all(sends[p["recipient"]] == 6 for p in work["payments"][:4]))
    same(work["activity"], sends)
    require(integer(work["final_minute"]) == previous_minute+60)
    if truth["cell"].endswith("independent"):
        require(sorted(r["owner"] for r in work["cash_requests"]) == list(range(32)))

    notes, spent, labels, coins = [], set(), set(), {}
    earmarked, initial_directory, targets = [0]*32, {}, []
    partial_notes, tagged_notes = set(), set()
    reserve = injected = pool_fees = bridge_fees = cursor = last_minute = 0
    metrics = dict(reentries=0, merges=0, partial_payouts=0, whole_payouts=0,
                   urgent_exit_operations=0, final_exit_operations=0,
                   peak_external_surplus=0, total_withdrawal_overshoot=0,
                   private_change_reused_by_pay=0, tagged_receipts_spent_as_coinput=0)

    def label(value):
        require(type(value) is str and len(value) == 64 and value != "0"*64
                and all(c in "0123456789abcdef" for c in value) and value not in labels)
        labels.add(value)

    def external(owner):
        return sum(value for role, value in coins.values() if role == owner)

    def private(owner):
        return sum(value for p, (value, role) in enumerate(notes) if role == owner and p not in spent)

    def accounting():
        require(reserve == sum(value for p, (value, _) in enumerate(notes) if p not in spent))
        require(injected == reserve+sum(value for _, value in coins.values())+pool_fees+bridge_fees)
        for owner in range(32):
            surplus = external(owner)-earmarked[owner]
            require(surplus >= 0)
            metrics["peak_external_surplus"] = max(metrics["peak_external_surplus"], surplus)

    def consume(owner, phase, minute, allowed, obligation=None, request=None):
        nonlocal cursor, reserve, injected, pool_fees, bridge_fees, last_minute
        require(cursor < len(events))
        event, record = events[cursor], hidden[cursor]
        fields(event, "event event_id minute mode fee deposit payout reserve anchor_count count_before new nullifiers destination funding_group bridge")
        fields(record, "event owner kind inputs outputs obligation request phase")
        same(event["event"], cursor); same(record["event"], cursor)
        same(record["owner"], owner); same(record["obligation"], obligation)
        same(record["request"], request)
        require(record["phase"] == phase and record["kind"] in allowed)
        kind = record["kind"]
        require(integer(event["minute"]) == minute and minute >= last_minute)
        last_minute = minute
        mode = integer(event["mode"], 0, 2)
        require(mode == (0 if kind == "admit" else 2 if kind == "exit" else 1))
        require(integer(event["fee"]) == FEE)
        deposit, payout = integer(event["deposit"]), integer(event["payout"])
        require(payout == 0 or payout >= PAYOUT_FLOOR)
        label(event["event_id"])
        require(type(event["nullifiers"]) is list and len(event["nullifiers"]) == 2)
        if mode == 0:
            same(event["nullifiers"], ["0"*64, "0"*64])
            same(event["anchor_count"], 0)
        else:
            for nf in event["nullifiers"]:
                label(nf)
            same(event["anchor_count"], len(notes))
        if payout:
            label(event["destination"])
        else:
            require(event["destination"] == "")
        same(event["count_before"], len(notes))
        inputs = record["inputs"]
        require(type(inputs) is list)
        for p in inputs:
            integer(p, 0, len(notes)-1)
            require(p not in spent and notes[p][0] >= FLOOR and notes[p][1] == owner
                    and p < event["anchor_count"])
        require(inputs == sorted(set(inputs)))
        require(len(inputs) == 0 if mode == 0 else 1 <= len(inputs) <= 2)
        total = sum(notes[p][0] for p in inputs)
        integer(total+deposit)
        outputs = record["outputs"]
        require(type(outputs) is list and len(outputs) == (0 if mode == 2 else 2))
        positions = list(range(len(notes), len(notes)+len(outputs)))
        same(event["new"], positions)
        values, owners = [], []
        for position, output in zip(positions, outputs):
            fields(output, "position value recipient")
            same(output["position"], position)
            value = integer(output["value"])
            require(value == 0 or value >= FLOOR)
            recipient = output["recipient"]
            if value:
                integer(recipient, 0, 31)
            else:
                require(recipient is None)
            values.append(value); owners.append(recipient)
            require(position < len(public["commitments"]))
            label(public["commitments"][position])
        require(total+deposit == sum(values)+payout+FEE)
        if kind == "admit":
            require(deposit >= FEE+FLOOR and payout == 0)
            same(values, [deposit-FEE, 0]); same(owners, [owner, None])
            label(event["funding_group"])
            bridge = event["bridge"]
            if phase == "initial":
                require(bridge is None and deposit == work["capitals"][owner]+FEE)
                initial_directory[event["funding_group"]] = owner
                injected += deposit
            else:
                require(phase == "payment")
                fields(bridge, "bridge_id sources input_value deposit fee change change_ref")
                label(bridge["bridge_id"])
                require(type(bridge["sources"]) is list and bridge["sources"])
                expected = {ref: value for ref, (role, value) in coins.items() if role == owner}
                supplied = {}
                for source in bridge["sources"]:
                    fields(source, "ref value")
                    require(type(source["ref"]) is str and source["ref"] not in supplied)
                    supplied[source["ref"]] = integer(source["value"], 1)
                same(supplied, expected)
                require(integer(bridge["input_value"]) == sum(expected.values()))
                require(integer(bridge["deposit"]) == deposit and integer(bridge["fee"]) == BRIDGE_FEE)
                change = integer(bridge["change"])
                require(change == earmarked[owner] and sum(expected.values()) == deposit+BRIDGE_FEE+change)
                for ref in expected:
                    del coins[ref]
                if change:
                    label(bridge["change_ref"])
                    coins[bridge["change_ref"]] = (owner, change)
                else:
                    require(bridge["change_ref"] == "")
                bridge_fees += BRIDGE_FEE
                metrics["reentries"] += 1
        else:
            require(deposit == 0 and event["funding_group"] == "" and event["bridge"] is None)
            if kind == "pay":
                payment = work["payments"][obligation]
                require(payout == 0 and values[0] == payment["amount"] and owners[0] == payment["recipient"])
                require(owners[1] == (owner if values[1] else None))
                targets.append(dict(obligation=obligation, event=cursor, sender=owner,
                                    recipient=payment["recipient"], amount=payment["amount"]))
                metrics["private_change_reused_by_pay"] += sum(p in partial_notes for p in inputs)
                metrics["tagged_receipts_spent_as_coinput"] += int(len(inputs) == 2 and any(p in tagged_notes for p in inputs))
                if owner < 8:
                    tagged_notes.add(positions[0])
            elif kind in ("partial", "merge"):
                require(values[0] >= FLOOR and values[1] == 0 and owners == [owner, None])
                if kind == "partial":
                    require(payout >= PAYOUT_FLOOR and phase == "cash" and truth["arm"] == "partial")
                    partial_notes.add(positions[0]); metrics["partial_payouts"] += 1
                else:
                    require(payout == 0 and len(inputs) == 2 and phase == "payment")
                    metrics["merges"] += 1
            else:
                require(payout == total-FEE)
                metrics["whole_payouts"] += 1
                if phase in ("urgent", "final"):
                    metrics[phase+"_exit_operations"] += 1
        if phase == "cash":
            wanted = work["cash_requests"][request]["amount"]
            shortage = earmarked[owner]+wanted-external(owner)
            require(shortage > 0)
            expected_payout = min(max(shortage, PAYOUT_FLOOR), total-FEE)
            if truth["arm"] == "whole" or total-expected_payout-FEE < FLOOR:
                expected_payout = total-FEE
            require(payout == expected_payout)
            metrics["total_withdrawal_overshoot"] += max(0, payout-shortage)
        spent.update(inputs)
        notes.extend(zip(values, owners))
        reserve += deposit-payout-FEE
        require(integer(event["reserve"]) == reserve)
        pool_fees += FEE
        if payout:
            require(event["event_id"] not in coins)
            coins[event["event_id"]] = (owner, payout)
        cursor += 1
        accounting()

    # Walk economic obligations rather than trusting hidden event phase labels.
    for owner in range(32):
        consume(owner, "initial", 0, ("admit",))
    same(directory["initial_funding_owners"], initial_directory)
    for payment in work["payments"]:
        owner, k, minute = payment["sender"], payment["obligation"], payment["minute"]
        while cursor < len(hidden) and hidden[cursor]["kind"] in ("admit", "merge"):
            consume(owner, "payment", minute, ("admit", "merge"), obligation=k)
        consume(owner, "payment", minute, ("pay",), obligation=k)
        if not k % 2:
            continue
        index = k//2
        request, audit = work["cash_requests"][index], truth["cash_audit"][index]
        fields(audit, "request owner amount earmarked_before earmarked_after external_before external_after event_start event_end complete urgent")
        owner, wanted, minute = request["owner"], request["amount"], request["minute"]
        for key in ("request", "owner", "amount", "urgent"):
            same(audit[key], request[key])
        same(audit["event_start"], cursor)
        end = integer(audit["event_end"], cursor-1, len(events)-1)
        same(audit["external_before"], external(owner))
        same(audit["earmarked_before"], earmarked[owner])
        while cursor <= end and hidden[cursor]["phase"] == "cash":
            consume(owner, "cash", minute, ("partial", "exit"), request=index)
        require(external(owner) >= earmarked[owner]+wanted)
        earmarked[owner] += wanted
        if request["urgent"]:
            while cursor <= end:
                consume(owner, "urgent", minute, ("exit",), request=index)
            require(private(owner) == 0)
        require(cursor == end+1)
        same(audit["earmarked_after"], earmarked[owner])
        same(audit["external_after"], external(owner))
        same(audit["complete"], True)
        accounting()
    for owner in work["final_order"]:
        while cursor < len(hidden) and hidden[cursor]["owner"] == owner:
            consume(owner, "final", work["final_minute"], ("exit",))
        require(private(owner) == 0)
    require(cursor == len(events) and reserve == 0 and len(notes) == len(public["commitments"]))
    require(all(value == 0 or p in spent for p, (value, _) in enumerate(notes)))
    same(truth["targets"], targets)
    final = dict(external_values=[external(r) for r in range(32)], earmarked=earmarked,
                 surplus=[external(r)-earmarked[r] for r in range(32)],
                 private_values=[private(r) for r in range(32)], reserve=reserve,
                 injected=injected, pool_fees=pool_fees, bridge_fees=bridge_fees)
    same(truth["final"], final)
    expected_cost = dict(metrics, pool_operations=len(events), pool_fees=pool_fees,
        bridge_fees=bridge_fees, ordinary_payment_fees=64*FEE,
        payment_principal=sum(p["amount"] for p in work["payments"]),
        initial_principal=sum(work["capitals"]), external_total=sum(final["external_values"]),
        earmarked_total=sum(earmarked), final_reserve=reserve,
        all_payments_met=True, all_cash_met=True,
        modeled_cash_delay_minutes=0, modeled_urgent_delay_minutes=0)
    same(cost, expected_cost)
    return dict(complete=True, initial_admissions=32, payment_obligations=64,
                cash_obligations=32, urgent_requests=2, pool_operations=len(events),
                note_positions=len(notes), consumed_positive_notes=len(spent),
                native_coins_remaining=len(coins), initial_injected_sompi=injected,
                final_external_sompi=sum(final["external_values"]),
                earmarked_sompi=sum(earmarked), surplus_sompi=sum(final["surplus"]),
                pool_fees_sompi=pool_fees, bridge_fees_sompi=bridge_fees,
                final_private_reserve=0, cost_counters_agree=True)

