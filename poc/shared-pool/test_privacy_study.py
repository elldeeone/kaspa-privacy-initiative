#!/usr/bin/env python3
"""Adversarial model checks, including a separate exhaustive small-value oracle."""
import copy
import itertools
import unittest
from privacy_study_generate import generate
from privacy_study_observer import Joint, Z3Joint, analyze, decode
from privacy_study_flow import Flow


class ModelChecks(unittest.TestCase):
    def test_singleton_and_fresh_pairing(self):
        data = generate(999, 'sparse', singleton=True)
        for arm in data['arms'].values():
            result = analyze(arm)
            self.assertTrue(result['drained'])
            for row in result['rows']:
                self.assertEqual(len(row['complete_drain']['joint']['sources']), 1)

    def test_malformed_counts_values_and_missing_history(self):
        good = generate(999, 'sparse', singleton=True)['arms']['fresh']
        for key in ['fee', 'payout', 'reserve_out', 'count_before', 'anchor_count']:
            bad = copy.deepcopy(good); bad['events'][-1][key] += 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                analyze(bad)
        for key in ['owner', 'seed', 'truth']:
            bad = copy.deepcopy(good); bad['events'][0][key] = 'private'
            with self.subTest(private=key), self.assertRaises(ValueError): decode(bad)
        bad = copy.deepcopy(good); del bad['events'][0]
        with self.assertRaises(ValueError): analyze(bad)

    @staticmethod
    def tiny():
        # Two equal admissions: three 2-unit exits cannot identify which of
        # the two equal-valued source pairs they consumed. One 3-unit exit.
        initial = {'id': 'gen', 'value': 6, 'minute': -1, 'funding_group': 'a'}
        events = []
        reserve = 6
        for i, (kind, anchor, count, added, pay, new) in enumerate([
            ('bootstrap', 1, 1, 0, 0, [1,2]), ('deposit', 1, 3, 5, 0, [3,4]),
            ('exit', 5, 5, 0, 1, []), ('exit', 5, 5, 0, 1, []),
            ('exit', 5, 5, 0, 1, []), ('exit', 5, 5, 0, 2, [])]):
            reserve += added-pay-1
            events.append({'id': str(i), 'minute': i, 'kind': kind, 'anchor_count': anchor,
                'count_before': count, 'fee': 1, 'payout': pay, 'deposit': added, 'new': new,
                'reserve_out': reserve, 'destination': str(i) if kind == 'exit' else None,
                'funding_group': 'b' if kind == 'deposit' else None})
        return {'schema': 'kpi-privacy-projection-v1', 'initial': initial, 'events': events}

    def test_independent_enumeration_and_joint_ancestry(self):
        chain = self.tiny(); events = chain['events']
        exact = [set() for _ in range(4)]
        # No symbolic solver, model helper or hidden generator choices here.
        for first in range(1,5):
            for second in range(1,4):
                values = [first, 5-first, second, 4-second]
                for order in itertools.permutations(range(4)):
                    if [values[i] for i in order] == [2,2,2,3]:
                        for j, pos in enumerate(order): exact[j].add(pos+1)
        model = Joint(chain, events, floor=1)
        reference = Z3Joint(chain, events, floor=1)
        for j, e in enumerate(events[2:]):
            positions, ancestors, groups = model.candidates(e)
            self.assertEqual((positions,ancestors,groups), reference.candidates(e))
            self.assertEqual(set(positions), exact[j])
            self.assertEqual(set(ancestors), {'gen' if p < 3 else '1' for p in exact[j]})
            self.assertEqual(set(groups), {'a' if p < 3 else 'b' for p in exact[j]})
        self.assertGreater(len(exact[0]), 1)

    def test_double_consumption_is_impossible(self):
        chain = self.tiny(); model = Joint(chain, chain['events'], floor=1)
        ids = [e['id'] for e in chain['events'] if e['kind'] == 'exit']
        self.assertFalse(model.possible(model.choices[ids[0]] == model.choices[ids[1]]))

    def test_flow_reduction_matches_both_solvers_at_every_prefix(self):
        chain=self.tiny();notes=decode(chain,floor=1)
        for end in range(3,len(chain['events'])+1):
            events=chain['events'][:end]
            flow=Flow(chain,events,notes,floor=1)
            cp=Joint(chain,events,floor=1);z3=Z3Joint(chain,events,floor=1)
            for e in events:
                if e['kind']=='exit':
                    self.assertEqual(flow.candidates(e),cp.candidates(e))
                    self.assertEqual(flow.candidates(e),z3.candidates(e))

    def test_flow_requires_current_roots_and_drain_only_phase(self):
        chain=self.tiny();self.assertTrue(Flow.supports(chain['events']))
        bad=copy.deepcopy(chain['events']);bad[-1]['anchor_count']=3
        self.assertFalse(Flow.supports(bad))
        self.assertFalse(Flow.supports(chain['events']+[chain['events'][1]]))

    def test_balanced_but_impossible_cross_deposit_payout(self):
        chain=self.tiny();chain['initial']['value']=21
        chain['events'][1]['deposit']=21
        for e,value in zip(chain['events'][2:],[34,2,2,2],strict=True):e['payout']=value-1
        reserve=21
        for e in chain['events']:
            reserve+=e['deposit']-e['payout']-e['fee'];e['reserve_out']=reserve
        notes=decode(chain,floor=1)
        self.assertEqual(reserve,0)  # Aggregate backing alone is not enough.
        with self.assertRaises(ValueError):Flow(chain,chain['events'],notes,floor=1).candidates(chain['events'][2])
        with self.assertRaises(ValueError):Joint(chain,chain['events'],floor=1)


if __name__ == '__main__':
    unittest.main()
