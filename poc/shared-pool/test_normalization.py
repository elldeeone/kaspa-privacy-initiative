import copy
import importlib.util
from pathlib import Path
import unittest

from normalization_generate import contributions, generate, POLICIES
from privacy_study_generate import FEES
from privacy_study_observer import analyze, decode

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('normalization_controller', HERE/'normalized-deposits.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


class NormalizationChecks(unittest.TestCase):
    def test_equalization_preserves_total_and_charges_exact_fee(self):
        fees = [FEES['bootstrap']]+[FEES['deposit']]*3
        for seed in range(50):
            values = contributions(seed)
            self.assertEqual(len({sum(x) for x in values.values()}), 1)
            self.assertEqual(len(set(values['gross'])), 1)
            self.assertEqual(len({v-f for v, f in zip(values['net'], fees, strict=True)}), 1)
            self.assertEqual((values['gross'][0]-fees[0])-(values['gross'][1]-fees[1]), 112000)

    def test_pairing_and_every_wallet_exit(self):
        for regime in ('sparse', 'burst'):
            data = generate(901, regime)
            truth = [d['truth'] for d in data['policies'].values()]
            self.assertEqual(truth[0], truth[1]); self.assertEqual(truth[1], truth[2])
            for policy in POLICIES:
                ledger = data['policies'][policy]; chain = ledger['arms']['fresh']
                decode(chain)
                exits = [e for e in chain['events'] if e['kind'] == 'exit']
                self.assertEqual({ledger['truth'][e['id']]['owner'] for e in exits}, set(range(4)))
                self.assertEqual(chain['events'][-1]['reserve_out'], 0)
                self.assertTrue(all(e['anchor_count'] == e['count_before'] for e in exits))

    def test_equal_net_root_symmetry_and_fee_fingerprint(self):
        data = generate(902, 'sparse')
        for policy in ('gross', 'net'):
            ledger = data['policies'][policy]; chain = ledger['arms']['fresh']
            observed = analyze(chain)
            c.c.score(ledger['truth'], observed)
            scored = c.deposit_scores(ledger['truth'], chain, observed)
            if policy == 'net':
                self.assertEqual(scored['complete_drain']['candidates'], 4)
                self.assertEqual(scored['complete_drain']['unique'], 0)
            else:
                self.assertGreater(scored['complete_drain']['unique'], 0)

    def test_no_cover_does_not_create_candidates(self):
        for control in ('singleton', 'early'):
            ledger = generate(903, 'sparse', control)['policies']['net']
            observed = analyze(ledger['arms']['fresh'])
            got = c.deposit_scores(ledger['truth'], ledger['arms']['fresh'], observed)
            self.assertEqual(got['at_withdrawal']['rows'][0]['candidates'], 1)

    def test_fake_normalization_breaks_accounting(self):
        chain = copy.deepcopy(generate(904, 'sparse')['policies']['gross']['arms']['fresh'])
        # Relabeling a public contribution without changing its backed value
        # must not make an apparently normalized valid trace.
        next(e for e in chain['events'] if e['kind'] == 'deposit')['deposit'] += 112000
        with self.assertRaises(ValueError):
            decode(chain)

    def test_public_labels_are_not_seed_derived(self):
        a, b = generate(905, 'sparse'), generate(905, 'sparse')
        self.assertEqual(a['contributions'], b['contributions'])
        self.assertEqual(a['policies']['net']['native_plan'], b['policies']['net']['native_plan'])
        self.assertNotEqual(a['policies']['net']['arms']['fresh']['initial']['id'],
                            b['policies']['net']['arms']['fresh']['initial']['id'])


if __name__ == '__main__':
    unittest.main()
