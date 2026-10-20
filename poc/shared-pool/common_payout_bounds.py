"""Entailed amount domains for a fully drained single-input cashout suffix.

No plans, participant IDs, workload labels or true note values are used.
This is a solver shortcut, not an extra wallet assumption.
"""
import z3


def suffix_domains(data, births, payout):
    """Return (start, domains), or None when the public suffix is unsuitable."""
    events = data["events"]
    if events[-1]["reserve_out"] != 0:
        return None
    start = len(events)
    while start:
        e = events[start-1]
        if e["mode"] == 2 or e["mode"] == 1 and e["payout"] == payout:
            start -= 1
        else:
            break
    commons = [i for i in range(start, len(events)) if events[i]["mode"] == 1]
    drains = [i for i in range(start, len(events)) if events[i]["mode"] == 2]
    if not drains:
        return None
    debits = {events[i]["payout"]+events[i]["fee"] for i in commons}
    if len(debits) > 1:
        return None  # varying fees need subset sums, outside this shortcut
    debit = next(iter(debits), 0)
    domains = []
    for born in births:
        candidates = {0}
        for end in drains:
            if end <= born:
                continue
            maximum = sum(born < i < end for i in commons)
            base = events[end]["payout"]+events[end]["fee"]
            candidates.update(base+k*debit for k in range(maximum+1))
        domains.append(sorted(candidates))
    return start, domains


def add_suffix_domains(smt, data, payout):
    derived = suffix_domains(data, smt.births, payout)
    if derived is None:
        return 0
    start, domains = derived
    for p, amounts in enumerate(domains):
        # A note already consumed before the cashout-only suffix is exempt.
        spent_before = z3.Or([ss[p] for i, ss in smt.select.items()
                              if i < start and p < len(ss)])
        smt.solver.add(z3.Or(spent_before, *[smt.values[p] == v for v in amounts]))
    return len(domains)
