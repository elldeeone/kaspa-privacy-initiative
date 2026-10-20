"""Private H18 workload construction. Never mount this module in an observer."""
import copy
import hashlib
import heapq
import hmac
import random


def stream(master, label):
    return random.Random(int.from_bytes(hmac.digest(master, label.encode(), "sha256"), "big"))


def identifier(rng, size=32):
    return rng.getrandbits(size * 8).to_bytes(size, "big").hex()


def prefix(config, template, rng, singleton=False):
    fee, floor = config["fee_sompi"], config["note_floor_sompi"]
    deposits = [rng.randint(*config["deposit_units"]) * config["amount_unit_sompi"]
                for _ in range(4)]
    initial = dict(id=identifier(rng), value=deposits[0], funding_group=identifier(rng))
    notes = {0: dict(owner=0, value=deposits[0], born=1, source=-1)}
    named, spent = {"genesis:0": 0}, set()
    events, records, payments = [], [], []
    remaining = {"bootstrap"} if singleton else set(template["operations"])
    balance, count, minute = deposits[0], 1, 0
    while remaining:
        ready = sorted(label for label in remaining
                       if all(n in named for n in template["operations"][label].get("inputs", [])))
        label = "bootstrap" if not events else rng.choice(ready)
        op = template["operations"][label]
        admission = "depositor" in op
        inputs = [] if admission else sorted(named[n] for n in op["inputs"])
        assert not spent.intersection(inputs)
        owner = op["depositor"] if admission else notes[inputs[0]]["owner"]
        assert all(notes[p]["owner"] == owner for p in inputs)
        deposit = deposits[owner] if admission else 0
        available = deposit + sum(notes[p]["value"] for p in inputs) - fee
        payout = 0
        if label.startswith("W"):
            lo, hi = config["partial_percent"]
            payout = rng.randint(max(config["payout_floor_sompi"], available * lo // 100),
                                 min(available - floor, available * hi // 100))
            if payout == config["payout_sompi"]:
                payout += 1  # one exact public amount identifies the declared Q policy
            values = [available - payout, 0]
        elif admission:
            values = [available, 0]
        else:
            lo, hi = config["payment_percent"]
            if label == "bootstrap":
                first = available * rng.randint(lo, hi) // 100
            else:
                first = rng.randint(max(floor, available * lo // 100),
                                    min(available - floor, available * hi // 100))
            values = [first, available - first]
        assert all(v == 0 or v >= floor for v in values)
        balance += deposit - payout - fee
        minute += rng.randint(*config["prefix_gap_minutes"])
        index = len(events)
        events.append(dict(id=identifier(rng), minute=minute, mode=0 if admission else 1,
                           anchor_count=0 if admission else count, count_before=count,
                           new=[count, count + 1], fee=fee, deposit=deposit, payout=payout,
                           reserve_out=balance, destination=identifier(rng, 36) if payout else None,
                           funding_group=identifier(rng) if admission else None))
        outputs = []
        for slot, value in enumerate(values):
            position = count + slot
            note = dict(owner=op["owners"][slot], value=value, born=count + 2, source=index)
            notes[position] = note
            named[f"{label}:{slot}"] = position
            outputs.append(dict(position=position, **note))
        category = ("deposit" if admission else "partial" if payout else
                    "bootstrap" if label == "bootstrap" else "payment")
        records.append(dict(author=owner, inputs=inputs, outputs=outputs,
                            category=category, label=label))
        if category == "payment":
            payments.append(index)
        count += 2
        spent.update(inputs)
        remaining.remove(label)
    live = sorted(p for p, n in notes.items() if n["value"] and p not in spent)
    assert sum(notes[p]["value"] for p in live) == balance
    return dict(public=dict(schema="kpi-h14-public-v1", initial=initial, events=events),
                notes=notes, records=records, live=live, payments=payments)


def requests(config, base, regime, rng):
    positions = list(base["live"])
    start = base["public"]["events"][-1]["minute"]
    if regime == "sparse":
        rng.shuffle(positions)
        now = start + config["sparse_quiet_minutes"]
        arrivals = {}
        for p in positions:
            now += rng.randint(*config["sparse_gap_minutes"])
            arrivals[p] = now
    else:
        arrivals = {p: start + rng.randint(*config["overlap_request_minutes"])
                    for p in positions}
    selected = set()
    minimum = config["payout_sompi"] + config["fee_sompi"] + config["note_floor_sompi"]
    for owner in range(4):
        eligible = [p for p in positions
                    if base["notes"][p]["owner"] == owner and base["notes"][p]["value"] >= minimum]
        if eligible:
            selected.add(min(eligible))
    return [dict(claim=i, original_position=p, owner=base["notes"][p]["owner"],
                 request_minute=arrivals[p], split=p in selected,
                 delay=rng.choices(config["delay_minutes"], config["delay_weights"])[0],
                 first_ticket=rng.getrandbits(128), tail_ticket=rng.getrandbits(128))
            for i, p in enumerate(base["live"])]


def settle(config, base, intents, arm, rng, immediate=False):
    """Discrete local timers plus one serial pool; no other wallet is queried."""
    assert arm in ("full", "scheduled")
    public = copy.deepcopy(base["public"])
    notes, records = copy.deepcopy(base["notes"]), copy.deepcopy(base["records"])
    claims = copy.deepcopy(intents)
    count = len(notes)
    reserve = public["events"][-1]["reserve_out"]
    now = public["events"][-1]["minute"]
    heap = []
    for claim in claims:
        split = arm == "scheduled" and claim["split"] and not (immediate and claim["owner"] == 0)
        claim.update(legs=[], current_position=claim["original_position"], shaped=split)
        heapq.heappush(heap, (claim["request_minute"], claim["first_ticket"],
                             "partial" if split else "full", claim["claim"]))
    while heap:
        ready, _, kind, ci = heapq.heappop(heap)
        claim = claims[ci]
        now = max(now, ready) + config["service_minutes"]
        p = claim["current_position"]
        note = notes[p]
        owner, value = note["owner"], note["value"]
        partial = kind == "partial"
        payout = config["payout_sompi"] if partial else value - config["fee_sompi"]
        change = value - payout - config["fee_sompi"]
        assert (change >= config["note_floor_sompi"]) if partial else change == 0
        assert payout >= config["payout_floor_sompi"]
        event = len(public["events"])
        outputs = []
        if partial:
            for slot, v in enumerate((change, 0)):
                new_note = dict(owner=owner, value=v, born=count + 2, source=note["source"])
                notes[count + slot] = new_note
                outputs.append(dict(position=count + slot, **new_note))
            claim["current_position"] = count
            heapq.heappush(heap, (now + claim["delay"], claim["tail_ticket"], "full", ci))
        reserve -= payout + config["fee_sompi"]
        saved = immediate and owner == 0 and not partial
        public["events"].append(dict(
            id=identifier(rng), minute=now, mode=1 if partial else 2,
            anchor_count=note["born"] if saved else count, count_before=count,
            new=[count, count + 1] if partial else [], fee=config["fee_sompi"],
            deposit=0, payout=payout, reserve_out=reserve,
            destination=identifier(rng, 36), funding_group=None))
        records.append(dict(author=owner, inputs=[p], outputs=outputs, category="cashout",
                            label=f"{kind}-{ci}", saved=saved))
        claim["legs"].append(event)
        if partial:
            count += 2
    assert reserve == 0
    # Full history accounting also checks each intermediate available reserve.
    spent = set()
    for e, r in zip(public["events"], records, strict=True):
        assert not spent.intersection(r["inputs"])
        spent.update(r["inputs"])
        debit = sum(notes[p]["value"] for p in r["inputs"]) + e["deposit"]
        assert debit == sum(n["value"] for n in r["outputs"]) + e["payout"] + e["fee"]
    assert all(not n["value"] or p in spent for p, n in notes.items())
    return dict(public=public, private=dict(notes=notes, records=records, claims=claims,
                                           payments=list(base["payments"]),
                                           prefix_count=len(base["records"])))


def generate(config, template, master, name, regime, control=None):
    base = prefix(config, template, stream(master, f"{name}/prefix"), control == "singleton")
    intents = requests(config, base, regime, stream(master, f"{name}/requests"))
    paired = {arm: settle(config, base, intents, arm, stream(master, f"{name}/{arm}"),
                          control == "immediate") for arm in ("full", "scheduled")}
    assert paired["full"]["public"]["events"][:len(base["records"])] == \
        paired["scheduled"]["public"]["events"][:len(base["records"])]
    return paired


def project(private, participant, public_hash):
    notes = {int(p): n for p, n in private["notes"].items()}
    receipts = [dict(position=p, value=n["value"]) for p, n in notes.items()
                if n["owner"] == participant and n["value"]]
    handles, authored = {participant: 0}, []
    for i, record in enumerate(private["records"]):
        if record["author"] != participant:
            continue
        outputs = [dict(position=n["position"], value=n["value"],
                        recipient=handles.setdefault(n["owner"], len(handles)) if n["value"] else None)
                   for n in record["outputs"]]
        authored.append(dict(event=i, inputs=record["inputs"], outputs=outputs))
    return dict(schema="kpi-h16-participant-view-v1", public_sha256=public_hash,
                receipts=receipts, authored=authored)


def accounting(config, paired):
    totals = {}
    for arm, bundle in paired.items():
        public, private = bundle["public"], bundle["private"]
        events, records = public["events"], private["records"]
        funding = public["initial"]["value"] + sum(e["deposit"] for e in events)
        fees = sum(e["fee"] for e in events)
        payouts = sum(e["payout"] for e in events)
        assert funding == fees + payouts and events[-1]["reserve_out"] == 0
        totals[arm] = dict(funding_sompi=funding, fees_sompi=fees, payouts_sompi=payouts,
                           transactions=len(events), reserve_remaining=0,
                           wallet_payouts_sompi=[
                               sum(e["payout"] for e, r in zip(events, records, strict=True)
                                   if r["author"] == owner) for owner in range(4)])
    delays = []
    for old, new in zip(paired["full"]["private"]["claims"],
                        paired["scheduled"]["private"]["claims"], strict=True):
        assert old["original_position"] == new["original_position"]
        assert old["request_minute"] == new["request_minute"]
        ends = {arm: paired[arm]["public"]["events"][c["legs"][-1]]["minute"]
                for arm, c in (("full", old), ("scheduled", new))}
        delays.append(dict(claim=old["claim"], request_minute=old["request_minute"],
                           full_minutes=ends["full"] - old["request_minute"],
                           scheduled_minutes=ends["scheduled"] - old["request_minute"],
                           added_minutes=ends["scheduled"] - ends["full"],
                           shaped=new["shaped"]))
    totals.update(delays=delays, extra_fee_sompi=totals["scheduled"]["fees_sompi"] -
                  totals["full"]["fees_sompi"])
    totals["extra_fee_fraction"] = totals["extra_fee_sompi"] / totals["full"]["fees_sompi"]
    return totals
