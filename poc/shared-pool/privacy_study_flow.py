"""Exact specialization of the integer model for latest-root, drain-only exits.

Each note has one funding ancestor: the relation has splits but no aggregation.
Enumerate transfer source choices; then partition observed exit values among
funding trees. For a fixed tree, leaf values determine all internal values.
Unwithdrawn leaves may share the remaining integer value above their floor.
This is an exact feasibility reduction, not a heuristic or a new attack.
"""
from functools import lru_cache


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Flow:
    @staticmethod
    def supports(events):
        seen_exit = False
        for e in events:
            if e['kind'] == 'exit':
                seen_exit = True
                if e['anchor_count'] != e['count_before']:
                    return False
            elif seen_exit:
                return False
        return seen_exit

    def __init__(self, chain, events, notes, floor=60_000_000, structure=None):
        require(self.supports(events), 'unsupported flow specialization')
        self.events, self.notes, self.floor = events, notes, floor
        self.deposits = [chain['initial']['id']]+[e['id'] for e in events if e['kind']=='deposit']
        self.groups = [chain['initial']['funding_group']]+[e['funding_group'] for e in events if e['kind']=='deposit']
        self.budgets = [chain['initial']['value']]+[e['deposit']-e['fee'] for e in events if e['kind']=='deposit']
        self.source_positions = {}
        for i,n in enumerate(notes):self.source_positions.setdefault(n['source'],[]).append(i)
        self.structure = structure if structure is not None else self.topologies()
        self.results = None

    def topologies(self):
        # Pair outputs have identical eligibility and private-value constraints.
        # Choosing one representative when both are live quotients only this
        # label symmetry; candidate reporting expands the pair again.
        states = {((0,), (0,)*len(self.deposits))}
        for e in self.events:
            if e['kind']=='exit':break
            successors = set()
            for live,costs in states:
                if e['kind']=='deposit':
                    origin = self.deposits.index(e['id'])
                    successors.add((live+(origin,origin),costs))
                    continue
                representatives = {}
                for i,origin in enumerate(live):
                    if origin >= 0 and i < e['anchor_count']:
                        representatives.setdefault(self.notes[i]['source'],i)
                for position in representatives.values():
                    origin = live[position]
                    after = list(live);after[position] = -1;after.extend([origin,origin])
                    charged = list(costs);charged[origin] += e['fee']
                    if self.budgets[origin]-charged[origin] >= after.count(origin)*self.floor:
                        successors.add((tuple(after),tuple(charged)))
            require(successors,'no feasible transfer topology')
            states = successors
        return states

    def partitions(self, capacities, budgets, values):
        """All possible deposit assignments, without enumerating note permutations."""
        n = len(values); all_bits = (1<<n)-1
        sums = [0]*(1<<n)
        for mask in range(1,1<<n):
            bit = mask & -mask
            sums[mask] = sums[mask^bit]+values[bit.bit_length()-1]
        allowed = []
        for capacity,budget in zip(capacities,budgets,strict=True):
            allowed.append({mask for mask in range(1<<n)
                if mask.bit_count() <= capacity and
                (sums[mask] == budget if mask.bit_count()==capacity
                 else sums[mask]+(capacity-mask.bit_count())*self.floor <= budget)})
        order = sorted(range(len(allowed)),key=lambda i:len(allowed[i]))
        @lru_cache(None)
        def can(level,remaining):
            if level == len(order):return remaining==0
            choices = allowed[order[level]]
            if level == len(order)-1:return remaining in choices
            subset = remaining
            while True:
                if subset in choices and can(level+1,remaining^subset):return True
                if not subset:break
                subset = (subset-1)&remaining
            return False
        if not can(0,all_bits):return None
        possible = [0]*len(allowed)
        visited = set()
        def collect(level,remaining):
            if level == len(order) or (level,remaining) in visited:return
            visited.add((level,remaining))
            root = order[level]
            subset = remaining
            while True:
                if subset in allowed[root] and can(level+1,remaining^subset):
                    possible[root] |= subset
                    collect(level+1,remaining^subset)
                if not subset:break
                subset = (subset-1)&remaining
        collect(0,all_bits)
        return possible

    def solve(self):
        exits = [e for e in self.events if e['kind']=='exit']
        values = tuple(e['payout']+e['fee'] for e in exits)
        positions = [set() for _ in exits]; ancestors = [set() for _ in exits]
        cache = {}
        for live,costs in self.structure:
            capacities = tuple(live.count(i) for i in range(len(self.deposits)))
            budgets = tuple(v-f for v,f in zip(self.budgets,costs,strict=True))
            key = capacities,budgets
            if key not in cache:cache[key] = self.partitions(capacities,budgets,values)
            masks = cache[key]
            if masks is None:continue
            for position,origin in enumerate(live):
                if origin < 0:continue
                bits = masks[origin]
                while bits:
                    bit = bits & -bits; target = bit.bit_length()-1;bits ^= bit
                    positions[target].update(self.source_positions[self.notes[position]['source']])
                    ancestors[target].add(origin)
        require(all(positions) and all(ancestors),'inconsistent flow history')
        return {e['id']:(sorted(positions[j]),[self.deposits[i] for i in sorted(ancestors[j])],
                          sorted({self.groups[i] for i in ancestors[j]})) for j,e in enumerate(exits)}

    def candidates(self,event):
        if self.results is None:self.results = self.solve()
        return self.results[event['id']]
