import hashlib
import importlib.util
from pathlib import Path
import random
import unittest

import privacy_public_state as state_check
from test_privacy_capture_model import projection


def _load_public_trees():
    source = Path(__file__).resolve().parents[1] / 'integration' / 'trees.py'
    spec = importlib.util.spec_from_file_location(
        'privacy_public_state_retained_trees', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TREES = _load_public_trees()


def _valid_projection(round_number=1, seed=9107):
    raw, _ = projection(round_number)
    prefix, body = raw[:193], bytearray(raw[193:])
    initial_cms = [hashlib.sha256(
        b'public-state-old-cm' + seed.to_bytes(4, 'little')
        + index.to_bytes(4, 'little')).digest() for index in range(3)]
    state = TREES.PublicState(initial_cms)
    body[204:236] = state.cm.root()
    body[236:268] = state.nf.root()
    body[268:272] = len(state.cms).to_bytes(4, 'little')
    body[272:276] = len(state.entries).to_bytes(4, 'little')

    rng = random.Random(seed)
    nfs = sorted((rng.getrandbits(256).to_bytes(32, 'little')
                  for _ in range(3)), key=lambda value: int.from_bytes(
                      value, 'little'))
    for index, nf in enumerate(nfs):
        body[404 + 96 * index:436 + 96 * index] = nf
        witness = state.insert(nf)
        body[3812 + 1160 * index:3812 + 1160 * (index + 1)] = witness
    body[316:348] = state.nf.root()
    body[352:356] = len(state.entries).to_bytes(4, 'little')

    for index in range(6):
        cm = hashlib.sha256(
            b'public-state-new-cm' + seed.to_bytes(4, 'little')
            + index.to_bytes(4, 'little')).digest()
        body[692 + 520 * index:724 + 520 * index] = cm
        path = state.append(cm)
        body[7292 + 512 * index:7292 + 512 * (index + 1)] = path
    body[284:316] = state.cm.root()
    body[348:352] = len(state.cms).to_bytes(4, 'little')
    return prefix + bytes(body)


def _flip(raw, at):
    changed = bytearray(raw)
    changed[at] ^= 1
    return bytes(changed)


class PublicStateTransitionTests(unittest.TestCase):
    def test_exact_three_nf_six_cm_transition_and_non_authority(self):
        raw = _valid_projection()
        receipt = state_check.verify_public_state_transition(raw)
        self.assertEqual((receipt['old_cm_count'], receipt['new_cm_count']),
                         (3, 9))
        self.assertEqual((receipt['old_nf_count'], receipt['new_nf_count']),
                         (1, 4))
        self.assertEqual((receipt['verified_nf_insertions'],
                          receipt['verified_cm_appends']), (3, 6))
        self.assertEqual(len(receipt['nf_interval_commitment_sha256']), 3)
        self.assertEqual(receipt['owner_label_fields'], 0)
        for claim in ('accepted_chain_currentness_proven',
                      'proof_validity_proven', 'native_acceptance_proven',
                      'privacy_proven', 'authorizes_selected_coverage'):
            self.assertIs(receipt[claim], False)

    def test_each_authenticated_root_and_path_component_is_required(self):
        raw = _valid_projection()
        body = 193
        mutations = {
            'old-nf-root': body + 236,
            'new-nf-root': body + 316,
            'first-nf-predecessor-path': body + 3812 + 72,
            'first-nf-append-path': body + 3812 + 616,
            'second-nf-predecessor-path': body + 3812 + 1160 + 72,
            'old-cm-root': body + 204,
            'new-cm-root': body + 284,
            'first-cm-path': body + 7292,
            'last-cm-path': body + 7292 + 5 * 512,
        }
        for label, at in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(state_check.PublicStateError):
                    state_check.verify_public_state_transition(_flip(raw, at))

    def test_sequential_nf_history_cannot_reuse_a_stale_witness(self):
        raw = _valid_projection()
        changed = bytearray(raw)
        body = 193
        first = changed[body + 3812:body + 3812 + 1160]
        changed[body + 3812 + 1160:body + 3812 + 2320] = first
        with self.assertRaises(state_check.PublicStateError):
            state_check.verify_public_state_transition(bytes(changed))

    def test_counts_intervals_order_and_commitments_refuse(self):
        raw = _valid_projection()
        body = 193
        cases = []
        changed = bytearray(raw)
        changed[body + 348:body + 352] = (8).to_bytes(4, 'little')
        cases.append(('wrong-new-cm-count', bytes(changed)))
        changed = bytearray(raw)
        changed[body + 352:body + 356] = (5).to_bytes(4, 'little')
        cases.append(('wrong-new-nf-count', bytes(changed)))
        changed = bytearray(raw)
        changed[body + 500:body + 532] = changed[body + 404:body + 436]
        cases.append(('duplicate-nf', bytes(changed)))
        changed = bytearray(raw)
        changed[body + 404:body + 436], changed[body + 500:body + 532] = \
            changed[body + 500:body + 532], changed[body + 404:body + 436]
        cases.append(('unsorted-nf', bytes(changed)))
        changed = bytearray(raw)
        changed[body + 692:body + 724] = bytes(32)
        cases.append(('zero-cm', bytes(changed)))
        changed = bytearray(raw)
        changed[body + 692 + 520:body + 724 + 520] = \
            changed[body + 692:body + 724]
        cases.append(('duplicate-cm', bytes(changed)))
        for label, changed in cases:
            with self.subTest(label=label):
                with self.assertRaises(state_check.PublicStateError):
                    state_check.verify_public_state_transition(changed)

    def test_random_valid_public_transitions_match_retained_tree_builder(self):
        for trial in range(16):
            with self.subTest(trial=trial):
                raw = _valid_projection(1 + trial % 2, 20_000 + trial)
                receipt = state_check.verify_public_state_transition(raw)
                self.assertEqual(receipt['projection_sha256'],
                                 hashlib.sha256(raw).hexdigest())

    def test_type_width_frame_and_effect_tag_are_exact(self):
        raw = _valid_projection()
        for malformed in (bytearray(raw), raw[:-1], raw + b'\0', None):
            with self.subTest(kind=type(malformed).__name__):
                with self.assertRaises(state_check.PublicStateError):
                    state_check.verify_public_state_transition(malformed)
        for at in (0, 193, 189):
            with self.subTest(at=at):
                with self.assertRaises(state_check.PublicStateError):
                    state_check.verify_public_state_transition(_flip(raw, at))


if __name__ == '__main__':
    unittest.main()
