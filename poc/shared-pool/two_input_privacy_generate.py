"""Private H14 workload builder. Never mounted in an observer sandbox."""
import copy
import secrets


def build(manifest, amount_row, schedule):
    row = manifest['amount_rows'][amount_row]
    fee = manifest['fee_sompi']
    notes = {'genesis:0': dict(position=0, owner=0, value=row['deposits'][0], born=1)}
    spent, steps, truth = set(), [], {}
    count, reserve = 1, row['deposits'][0]
    for label in manifest['schedules'][schedule]:
        op = manifest['operations'][label]
        admission = 'depositor' in op
        inputs = [] if admission else [notes[h] for h in op['inputs']]
        assert not any(n['position'] in spent for n in inputs)
        assert len({n['owner'] for n in inputs}) <= 1
        spent.update(n['position'] for n in inputs)
        deposit = row['deposits'][op['depositor']] if admission else 0
        payout = row[label] if label.startswith('W') else 0
        available = deposit + sum(n['value'] for n in inputs) - payout - fee
        first = (row['bootstrap_first'] if label == 'bootstrap' else
                 available if admission or payout else row[label])
        values = [first, available-first]
        assert all(v == 0 or v >= manifest['note_floor_sompi'] for v in values)
        reserve += deposit-payout-fee
        step = dict(label=label, mode=0 if admission else 1,
                    inputs=sorted(n['position'] for n in inputs), owners=op['owners'],
                    values=values, deposit=deposit, payout=payout,
                    depositor=op.get('depositor'), count_before=count,
                    reserve_out=reserve)
        steps.append(step)
        if not admission:
            truth[len(steps)-1] = dict(inputs=step['inputs'], label=label,
                                     category='partial' if payout else 'bootstrap' if label == 'bootstrap' else 'payment')
        count += 2
        for slot, (v, owner) in enumerate(zip(values, op['owners'], strict=True)):
            notes[f'{label}:{slot}'] = dict(position=count-2+slot, owner=owner, value=v, born=count)
    drains = list(manifest['drains'])
    if schedule == manifest['reverse_drain_for_schedule']:
        drains.reverse()
    live = {n['position'] for n in notes.values() if n['value'] and n['position'] not in spent}
    assert live == {notes[h]['position'] for h in drains}
    plan = dict(schema='kpi-h14-private-plan-v1', initial=row['deposits'][0], steps=steps,
                drains=[notes[h] for h in drains], interval_minutes=manifest['interval_minutes'])
    identifiers = [secrets.token_hex(32) for _ in range(1+len(steps)+len(drains))]
    funding = [secrets.token_hex(32) for _ in range(4)]
    destinations = [secrets.token_hex(36) for _ in range(2+len(drains))]
    paired = {}
    for arm in ('fresh', 'saved'):
        events, dest = [], 0
        for i, s in enumerate(steps):
            mode = s['mode']
            e = dict(id=identifiers[i+1], minute=i*manifest['interval_minutes'], mode=mode,
                anchor_count=0 if mode == 0 else s['count_before'], count_before=s['count_before'],
                new=[s['count_before'], s['count_before']+1], fee=fee, deposit=s['deposit'],
                payout=s['payout'], reserve_out=s['reserve_out'],
                destination=destinations[dest] if s['payout'] else None,
                funding_group=funding[s['depositor']] if mode == 0 else None)
            dest += bool(s['payout'])
            events.append(e)
        remaining = reserve
        for n in plan['drains']:
            i = len(events); payout = n['value']-fee; remaining -= n['value']
            events.append(dict(id=identifiers[i+1], minute=i*manifest['interval_minutes'], mode=2,
                anchor_count=count if arm == 'fresh' else n['born'], count_before=count,
                new=[], fee=fee, deposit=0, payout=payout, reserve_out=remaining,
                destination=destinations[dest], funding_group=None))
            truth[i] = dict(inputs=[n['position']], label='exit', category='exit')
            dest += 1
        assert remaining == 0
        paired[arm] = dict(schema='kpi-h14-public-v1',
            initial=dict(id=identifiers[0], value=plan['initial'], funding_group=funding[0]),
            events=events)
    return plan, paired, copy.deepcopy(truth)
