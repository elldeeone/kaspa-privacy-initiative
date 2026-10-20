"""Private H17 transformation and economic matching. Never mounted in observers."""
import copy
import secrets

from participant_privacy_view import ledger


def build(plan, public, truth, config):
    plan, public = copy.deepcopy(plan), copy.deepcopy(public)
    original_drains = copy.deepcopy(plan["drains"])
    fee, payout, floor = (config[k] for k in
                          ("fee_sompi", "payout_sompi", "note_floor_sompi"))
    assert len(plan["steps"]) == config["prefix_operations"]
    events = public["events"][:len(plan["steps"])]
    truths = {str(i): copy.deepcopy(truth[str(i)]) for i in range(len(events))
              if str(i) in truth}
    notes, _ = ledger(plan)
    positions = {f"{s['label']}:{slot}": s["count_before"] + slot
                 for s in plan["steps"] for slot in (0, 1)}
    selected = [positions[label] for label in config["selected_notes"]]
    live = {n["position"] for n in original_drains}
    assert len(set(selected)) == 4 and set(selected) <= live
    count = events[-1]["count_before"] + 2
    reserve = events[-1]["reserve_out"]
    replacements, early_legs = {}, {}
    for owner, position in enumerate(selected):
        old = notes[position]
        assert old["owner"] == owner
        change = old["value"] - payout - fee
        if change < floor:
            raise ValueError("common payout would create a sub-floor remainder")
        reserve -= payout + fee
        step = dict(label=f"Q{owner}", mode=1, inputs=[position], owners=[owner, owner],
                    values=[change, 0], deposit=0, payout=payout, depositor=None,
                    count_before=count, reserve_out=reserve)
        plan["steps"].append(step)
        i = len(events)
        early_legs[position] = i
        truths[str(i)] = dict(inputs=[position], label=step["label"], category="common")
        events.append(dict(id=secrets.token_hex(32), minute=i*config["interval_minutes"],
                           mode=1, anchor_count=count, count_before=count,
                           new=[count, count+1], fee=fee, deposit=0, payout=payout,
                           reserve_out=reserve, destination=secrets.token_hex(36),
                           funding_group=None))
        replacements[position] = dict(position=count, owner=owner, value=change, born=count+2)
        count += 2
    plan["drains"] = [replacements.get(n["position"], n) for n in original_drains]
    claims = []
    for index, (old, note) in enumerate(zip(original_drains, plan["drains"], strict=True)):
        i = len(events)
        reserve -= note["value"]
        events.append(dict(id=secrets.token_hex(32), minute=i*config["interval_minutes"],
                           mode=2, anchor_count=count, count_before=count, new=[],
                           fee=fee, deposit=0, payout=note["value"]-fee,
                           reserve_out=reserve, destination=secrets.token_hex(36),
                           funding_group=None))
        truths[str(i)] = dict(inputs=[note["position"]], label="exit", category="exit")
        claims.append(dict(index=index, original_position=old["position"], owner=old["owner"],
                           baseline_event=config["prefix_operations"]+index,
                           legs=([early_legs[old["position"]]] if old["position"] in early_legs else [])+[i]))
    assert reserve == 0
    public["events"] = events
    return plan, public, truths, claims


def accounting(plan, public):
    """All native funding, every fee, and both early and final owner cashouts."""
    _, events = ledger(plan)
    payouts, fees = [0]*4, [0]*4
    for event, known in zip(public["events"], events, strict=True):
        payouts[known["author"]] += event["payout"]
        fees[known["author"]] += event["fee"]
    funding = plan["initial"] + sum(s["deposit"] for s in plan["steps"])
    assert funding == sum(payouts)+sum(fees)
    assert public["events"][-1]["reserve_out"] == 0
    return dict(funding_sompi=funding, payouts_sompi=sum(payouts), fees_sompi=sum(fees),
                wallet_payouts_sompi=payouts, wallet_fees_sompi=fees, reserve_remaining=0)
