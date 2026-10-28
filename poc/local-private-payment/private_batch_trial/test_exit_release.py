"""Public model controls for the explicit AuthExit release boundary."""
from dataclasses import replace
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

import exit_release as release
import exit_wire

spec = importlib.util.spec_from_file_location('_kpb_release_control_trees',
    Path(__file__).resolve().parents[1] / 'integration/trees.py')
trees = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = trees
spec.loader.exec_module(trees)


def fixture(terminal=False):
    state = trees.PublicState([bytes([11]) * 32, bytes([12]) * 32, bytes([13]) * 32])
    context = exit_wire.HeadContext(*(bytes([i]) * 32 for i in range(1, 6)),
        bytes([6]) * 32 + bytes(4), state.cm.root(), state.nf.root(), 3, 1,
        200_000_000 if terminal else 600_000_000)
    witness = state.insert(bytes([7]) * 32)
    body = exit_wire.body(context, bytes([8]) * 32, state.nf.root(), len(state.entries),
        0 if terminal else 400_000_000, 1_000_000, 199_000_000,
        b'\0\0\x20' + bytes([9]) * 32 + b'\xac', bytes([7]) * 32, witness)
    tail = b'PUBLIC_MODEL_POLICY_NO_NATIVE_OR_CRYPTOGRAPHIC_CLAIM'
    projection = exit_wire.projection(body, tail)
    candidate = {'schema': 'kpb-owner-prepared-independent-exit/v1', 'scope': release.SCOPE,
        'projection_hex': projection.hex(), 'statement_hex152': exit_wire.statement(projection).hex(),
        'proof_hex128': bytes([10]).hex() * 128, 'native_or_chain_acceptance': False}
    identity = tuple(bytes([i]) * 32 for i in range(1, 6))
    history = dict(zip(('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32'),
                       (word.hex() for word in identity)))
    history.update(schema='kpb-private-batch-public-history/v1', scope=release.SCOPE, genesis={}, transitions=[],
        head={'outpoint_hex36': context.point.hex(), 'state_hex112': context.state().hex(),
              'reserve_sompi': context.reserve})
    return context, tail, candidate, history, identity


class ReleaseControls(unittest.TestCase):
    def test_exact_continuing_and_terminal_public_export(self):
        for terminal in (False, True):
            context, tail, candidate, history, identity = fixture(terminal)
            self.assertEqual(release.selected_head(history, identity), context)
            checked = []
            def verify(statement, proof):
                checked.append((statement, proof))
                return True  # Explicit model callback; no proof validity claim.
            self.assertEqual(release.validate_candidate(candidate, context, tail, verify), candidate)
            self.assertEqual(checked, [(bytes.fromhex(candidate['statement_hex152']), bytes([10]) * 128)])

    def test_private_field_or_authority_upgrade_cannot_be_exported(self):
        context, tail, candidate, _, _ = fixture()
        mutations = [{'seed_hex32': '00' * 32}, {'accepted': True}, {'scope': 'ACCEPTED'},
                     {'native_or_chain_acceptance': True}, {'native_or_chain_acceptance': 0}]
        for change in mutations:
            with self.assertRaises(ValueError):
                release.validate_candidate({**candidate, **change}, context, tail, lambda *_: True)

    def test_wrong_statement_and_invalid_or_nonboolean_verifier_refuse(self):
        context, tail, candidate, _, _ = fixture()
        for verdict in (False, 1, 'true', None):
            with self.assertRaisesRegex(ValueError, 'genuine-AuthExit-proof'):
                release.validate_candidate(candidate, context, tail, lambda *_: verdict)
        with self.assertRaisesRegex(ValueError, 'exact-owner-statement'):
            release.validate_candidate({**candidate, 'statement_hex152': '00' * 152}, context, tail, lambda *_: True)

    def test_stale_cross_lane_and_wrong_policy_refuse(self):
        context, tail, candidate, _, _ = fixture()
        for name in ('chain', 'pool', 'profile', 'domain', 'service', 'point', 'cm_root', 'nf_root'):
            current = getattr(context, name)
            changed = replace(context, **{name: bytes([99]) * len(current)})
            with self.assertRaises(ValueError):
                release.validate_candidate(candidate, changed, tail, lambda *_: True)
        with self.assertRaisesRegex(ValueError, 'input-policy'):
            release.validate_candidate(candidate, context, tail + b'changed', lambda *_: True)

    def test_changed_nf_witness_and_noncanonical_proof_refuse(self):
        context, tail, candidate, _, _ = fixture()
        projection = bytearray.fromhex(candidate['projection_hex'])
        projection[-1160 + 72] ^= 1
        with self.assertRaises(ValueError):
            release.validate_candidate({**candidate, 'projection_hex': projection.hex()}, context, tail, lambda *_: True)
        for proof in ('AB' * 128, '00' * 127, '00' * 129, 'g0' * 128):
            with self.assertRaises(ValueError):
                release.validate_candidate({**candidate, 'proof_hex128': proof}, context, tail, lambda *_: True)

    def test_supplied_context_is_explicit_and_not_a_history_admission(self):
        _, _, _, history, identity = fixture()
        for change in ({'accepted': True}, {'scope': 'ACCEPTED_CHAIN'}):
            with self.assertRaises(ValueError):
                release.selected_head({**history, **change}, identity)
        for reserve in (True, '600000000', 0):
            with self.assertRaises(ValueError):
                release.selected_head({**history, 'head': {**history['head'], 'reserve_sompi': reserve}}, identity)
        with self.assertRaises(ValueError):
            release.selected_head(history, (bytes([99]) * 32,) + identity[1:])
        with self.assertRaises(ValueError):
            release.selected_head({**history, 'head': {**history['head'], 'outpoint_hex36': None}}, identity)

    def test_duplicate_json_and_private_leaf_aliases_refuse(self):
        with self.assertRaisesRegex(ValueError, 'duplicate-json-key'):
            release.parse(b'{"scope":"one","scope":"two"}')
        with tempfile.TemporaryDirectory(prefix='kpb-public-release-parser-') as name:
            root = Path(name)
            leaf = root / 'PUBLIC-MODEL-CANDIDATE.json'
            leaf.write_bytes(b'public model fixture')
            leaf.chmod(0o600)
            self.assertEqual(release.stable_read(leaf, private=True), b'public model fixture')
            leaf.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'private-mode'):
                release.stable_read(leaf, private=True)
            leaf.chmod(0o600)
            alias = root / 'ALIAS'
            alias.symlink_to(leaf)
            with self.assertRaises(ValueError):
                release.stable_read(alias, private=True)
            alias.unlink()
            os.link(leaf, alias)
            with self.assertRaisesRegex(ValueError, 'single-leaf'):
                release.stable_read(leaf, private=True)


if __name__ == '__main__':
    unittest.main()
