#!/usr/bin/env python3
"""Frozen, nonauthorizing Observer-v4 ABI and cross-language controls."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import privacy_measurement_output_abi as v3
import privacy_measurement_output_abi_v4 as v4


HERE = Path(__file__).resolve().parent


class ObserverV4AbiControls(unittest.TestCase):
    def test_registry_is_source_derived_and_family_requirements_stay_distinct(self):
        canonical = (json.dumps(
            v4.REGISTRY_PREIMAGE, sort_keys=True, separators=(',', ':'))
            + '\n').encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(),
                         v4.REGISTRY_IDENTITY)
        self.assertEqual(len(v4.FAMILY_ROWS), 12)
        by_name = {row['name']: row for row in v4.FAMILY_ROWS}
        self.assertEqual(len(by_name), 12)

        self.assertNotEqual(by_name['S4_OUTPUT_GROTH16'],
                            by_name['S12_AGGREGATE_GROTH16'])
        self.assertEqual(
            by_name['S5_AND_S6A_STRICT_CONJUNCTION']['prerequisites'],
            ['S5_CRYPTOBOX_CONFIDENTIALITY',
             'S6A_HIDDEN_DELIVERY_PRF'])
        self.assertEqual(
            by_name['JOINT_S6A_S7_HMAC']['mode'],
            'joint-same-source-game')
        self.assertEqual(
            by_name['JOINT_S6A_S7_HMAC']['prerequisites'],
            ['S6A_HIDDEN_DELIVERY_PRF', 'S7_NULLIFIER_HMAC_PRF'])
        self.assertEqual(
            by_name['NARROW_S14_AND_S12_CONJUNCTION']['prerequisites'],
            ['NARROW_S14_MPC_REALIZATION',
             'S12_AGGREGATE_GROTH16'])
        self.assertFalse(
            by_name['NARROW_S14_MPC_REALIZATION']['requirements'][
                'aggregate_groth16_included'])
        self.assertEqual(
            by_name['COUNTERFACTUAL_FULL_W1_CLOSE']['mode'],
            'atomic-same-instance')
        self.assertEqual(
            by_name['ALL_FRESH_TRIAL_HISTORY_DIRECT_EMPIRICAL']['mode'],
            'exhaustive-fresh-trial-history')
        self.assertTrue(all(
            row['applicability_status'] == 'MISSING_LIVE_AUTHORITY'
            and row['applicability_identity'] is None
            for row in v4.FAMILY_ROWS))

    def test_s12_binds_current_historical_equivalence_and_verifier_separately(self):
        self.assertEqual(v4.PINNED_S12['historical_setup_source'],
                         '3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829')
        self.assertEqual(v4.PINNED_S12['current_source'],
                         '04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7')
        self.assertEqual(v4.PINNED_S12['matrix_equivalence_receipt'],
                         '52ca327ac2d3dd2921c0aa913060f8a97f127d81c5d125c1892dc989853ac692')
        self.assertEqual(v4.PINNED_S12['independent_verifier'],
                         'c1805cfe7ae9b2db7d58fd58727b57e92a0fec866506cd720fbd59242359131f')
        self.assertEqual(len(set(v4.PINNED_S12.values())), 8)

    def test_section_and_descriptor_identities_are_independently_recomputable(self):
        self.assertEqual(len(v4.SECTION_BYTES), v4.SECTION_BYTES_COUNT)
        self.assertEqual(hashlib.sha256(v4.SECTION_BYTES).hexdigest(),
                         v4.SECTION_IDENTITY)
        canonical = (json.dumps(
            v4.SPEC_PREIMAGE, sort_keys=True, separators=(',', ':'))
            + '\n').encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(),
                         v4.OUTPUT_ABI_IDENTITY)
        self.assertEqual(v4.SECTION_BYTES[84:116],
                         bytes.fromhex(v4.OUTPUT_ABI_IDENTITY))
        ledger = (HERE.parents[2] / 'research' /
                  'combined-p1-c1-public-finite-assumption-ledger-2026-10-29.md')
        self.assertEqual(v4.MODEL_IDENTITY,
                         hashlib.sha256(ledger.read_bytes()).hexdigest())

    def test_python_validator_requires_exact_v3_prefix_section_and_padding(self):
        from test_privacy_measurement_output_abi import capsules
        prefix = v3.test_only_encode_observer_capsules_v3(
            capsules(full_workload=False))
        body = prefix + v4.SECTION_BYTES + bytes(
            v4.EXACT_BYTES - v4.USED_BYTES)
        v4.validate_observer_output_v4(body)
        for relative in (0, v4.SECTION_BYTES_COUNT - 1):
            changed = bytearray(body)
            changed[v4.SECTION_OFFSET + relative] ^= 1
            with self.assertRaises(ValueError):
                v4.validate_observer_output_v4(bytes(changed))
        changed = bytearray(body)
        changed[v4.USED_BYTES] = 1
        with self.assertRaises(ValueError):
            v4.validate_observer_output_v4(bytes(changed))
        with self.assertRaises(ValueError):
            v4.validate_observer_output_v4(body[:-1])

    def test_cpp_and_python_bytes_match_and_every_section_byte_is_guarded(self):
        with tempfile.TemporaryDirectory(prefix='kpb-observer-v4-') as raw:
            root = Path(raw)
            binary = root / 'control'
            body = root / 'body.bin'
            compiled = subprocess.run([
                'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-DKPB_MEASUREMENT_OUTPUT_ABI_TEST_SETUP',
                '-DKPB_MEASUREMENT_OUTPUT_ABI_V4_TEST_SETUP',
                '-I', str(HERE),
                str(HERE / 'privacy_measurement_output_abi_v4_control.cpp'),
                str(HERE / 'privacy_measurement_output_abi_v4.cpp'),
                str(HERE / 'privacy_measurement_output_abi.cpp'),
                '-o', str(binary)], text=True, capture_output=True,
                check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary), str(body)], text=True,
                                 capture_output=True, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            raw_body = body.read_bytes()
            self.assertEqual(
                raw_body[v4.SECTION_OFFSET:
                         v4.SECTION_OFFSET + v4.SECTION_BYTES_COUNT],
                v4.SECTION_BYTES)
            v4.validate_observer_output_v4(raw_body)

    def test_production_surface_has_no_encoder_or_authority_mint(self):
        self.assertFalse(hasattr(v4, 'encode_observer_output_v4'))
        self.assertFalse(hasattr(v4, 'mint'))
        with tempfile.TemporaryDirectory(prefix='kpb-observer-v4-nm-') as raw:
            obj = Path(raw) / 'v4.o'
            compiled = subprocess.run([
                'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-I', str(HERE), '-c',
                str(HERE / 'privacy_measurement_output_abi_v4.cpp'),
                '-o', str(obj)], text=True, capture_output=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            symbols = subprocess.run(
                ['nm', '-C', str(obj)], text=True, capture_output=True,
                check=True).stdout
            self.assertNotIn('test_only', symbols)
            self.assertNotIn('mint', symbols)


if __name__ == '__main__':
    unittest.main()
