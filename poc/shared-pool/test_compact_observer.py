#!/usr/bin/env python3
"""Analytic and malformed-input controls for the Stage 2 observer."""
import copy
import itertools
import json
import unittest
from pathlib import Path
from compact_observer import decode, describe, matching_candidates, ValueModel


def bounds(values):
    return [{'step': i+1, 'anchor_count': value} for i, value in enumerate(values)]


def fixture():
    unit = 1_000_000
    events = []
    for mode, count, payout, remaining, new in [
        (1, 1, 0, 999, [1, 2]), (1, 3, 0, 998, [3, 4]),
        (2, 5, 399, 598, []), (2, 5, 198, 399, []), (2, 5, 398, 0, []),
    ]:
        step = len(events)+1
        events.append({'step': step, 'txid': f'tx{step}', 'mode': mode,
                       'anchor_count': count, 'current_count': count,
                       'fee': unit, 'payout': payout*unit,
                       'reserve_out': remaining*unit, 'new': new})
    notes = [{'position': 0, 'born': 0, 'source': 'funding'}]
    for e in events:
        notes.extend({'position': i, 'born': e['step'], 'source': e['txid']} for i in e['new'])
    return {'initial_value': 1000*unit, 'funding_txid': 'funding', 'notes': notes}, events


class Controls(unittest.TestCase):
    def test_singleton(self):
        e = bounds([1])
        self.assertEqual(matching_candidates(e, e[0]), [0])

    def test_hall_matching_against_brute_force(self):
        # All small nested-set systems, including conflicts, not chosen outputs.
        for count in range(1, 5):
            for limits in itertools.product(range(1, 5), repeat=count):
                e = bounds(limits)
                histories = [h for h in itertools.permutations(range(4), count)
                             if all(i < limit for i, limit in zip(h, limits))]
                for target in range(count):
                    expected = sorted({h[target] for h in histories})
                    if expected:
                        self.assertEqual(matching_candidates(e, e[target]), expected)
                    else:
                        with self.assertRaises(ValueError):
                            matching_candidates(e, e[target])

    def test_jointly_forced_spent_prefix(self):
        e = bounds([1, 3, 3, 5])
        self.assertEqual(matching_candidates(e, e[-1]), [3, 4])

    def test_frozen_anchor_excludes_future_notes(self):
        e = bounds([1, 3, 5, 7, 3])
        self.assertEqual(matching_candidates(e, e[-1]), [1, 2])

    def test_delay_without_new_information(self):
        d, e = fixture()
        before = ValueModel(d, e).candidates(e[2])
        later = copy.deepcopy(e)
        for event in later:
            event['untrusted_local_time'] = 999999
        self.assertEqual(before, ValueModel(d, later).candidates(later[2]))

    def test_multiple_joint_value_histories(self):
        d, e = fixture()
        candidates = ValueModel(d, e).candidates(e[2])
        self.assertEqual(candidates, [1, 2, 3, 4])
        self.assertEqual(describe(d, e[2], candidates)['source_candidate_count'], 2)

    def test_old_anchor_then_fresh_anchor(self):
        d, e = fixture()
        e[2]['anchor_count'] = 3
        self.assertEqual(ValueModel(d, e).candidates(e[2]), [1, 2])
        e[2]['anchor_count'] = 5
        self.assertEqual(ValueModel(d, e).candidates(e[2]), [1, 2, 3, 4])

    def test_note_labels_do_not_identify_people(self):
        d, e = fixture()
        candidates = ValueModel(d, e).candidates(e[2])
        for note in d['notes']:
            note['commitment'] = 'opaque replacement'
        self.assertEqual(candidates, ValueModel(d, e).candidates(e[2]))

    def test_wrong_native_balance_rejected(self):
        d, e = fixture()
        e[-1]['reserve_out'] = 1
        with self.assertRaises(ValueError):
            ValueModel(d, e)

    def test_insufficient_value_rejected(self):
        d, e = fixture()
        e[2]['payout'] = d['initial_value']
        with self.assertRaises(ValueError):
            ValueModel(d, e)

    def test_sat_witness_preserves_conservation(self):
        d, e = fixture()
        m = ValueModel(d, e)
        solution = m.s.model()
        values = [solution[v].as_long() for v in m.values]
        seen = set()
        for event in e:
            i = solution[m.choices[event['step']]].as_long()
            self.assertNotIn(i, seen)
            seen.add(i)
            self.assertEqual(values[i], sum(values[j] for j in event['new'])+event['fee']+event['payout'])

    def test_chain_parser_controls(self):
        source = Path(__file__).parent/'evidence/2026-10-19-compact/rehearsal/chain-confirmed.json'
        old = json.loads(source.read_text())
        chain = {'schema': 'kpi-compact-chain-observer-v1', 'network': 'testnet-10',
                 'records': [{'transaction': r['transaction'], 'header': r['acceptedHeader']} for r in old['transactions']]}
        expected = decode(chain)
        reordered = copy.deepcopy(chain)
        reordered['records'].reverse()
        self.assertEqual(expected, decode(reordered))
        for change in ['count', 'value', 'ancestry', 'metadata', 'duplicate']:
            bad = copy.deepcopy(chain)
            tx = bad['records'][1]['transaction']
            if change == 'count':
                raw = bytearray.fromhex(tx['payload']); raw[48:52] = (3).to_bytes(4, 'little')
                tx['payload'] = raw.hex()
            elif change == 'value':
                tx['outputs'][0]['value'] = str(int(tx['outputs'][0]['value'])+1)
            elif change == 'ancestry':
                tx['inputs'][0]['previousOutpoint']['index'] = 1
            elif change == 'metadata':
                bad['records'][1]['owner'] = 'scoring-only'
            else:
                bad['records'].append(bad['records'][-1])
            with self.subTest(change=change), self.assertRaises(ValueError):
                decode(bad)


if __name__ == '__main__':
    unittest.main()
