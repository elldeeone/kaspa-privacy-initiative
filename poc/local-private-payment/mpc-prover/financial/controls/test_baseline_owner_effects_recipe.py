#!/usr/bin/env python3

import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


SOURCE = digest(b'selected relation source')
LAYOUT = digest(b'selected canonical owner layout')


def recipe(*, source=SOURCE, layout=LAYOUT, mutate=None):
    owners = []
    for owner, (nf_start, selector_start) in enumerate(
            [(10, 300), (500, 800), (1000, 1300)]):
        nfs = list(range(nf_start, nf_start + 256))
        selectors = [
            list(range(selector_start, selector_start + 6)),
            list(range(selector_start + 6, selector_start + 12)),
        ]
        owners.append([owner, nfs, selectors])
    if mutate:
        mutate(owners)
    out = bytearray(b'KPBOER01')
    out += struct.pack('<QQQQQQ', 2000, 3, 3, 256, 2, 6)
    out += bytes.fromhex(source) + bytes.fromhex(layout)
    for owner, nfs, selectors in owners:
        out += struct.pack('<Q', owner)
        out += b''.join(struct.pack('<Q', value) for value in nfs)
        for row in selectors:
            out += b''.join(struct.pack('<Q', value) for value in row)
    return bytes(out)


class BaselineOwnerEffectsRecipeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-baseline-owner-effects-')
        cls.root = Path(cls.temporary.name)
        cls.binary = cls.root / 'owner-effects'
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DKPI_REGISTERED_IDENTITY_UNFUNDED_SETUP',
            '-DKPI_REGISTERED_ATTEMPT_TEST_SETUP',
            '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
            str(HERE / 'baseline_owner_effects_recipe_test.cpp'),
            str(FINANCIAL / 'baseline_owner_effects_recipe.cpp'),
            str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
            str(FINANCIAL / 'registered_driver_bridge.cpp'),
            str(FINANCIAL / 'registered_capture_session.cpp'),
            str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
            str(FINANCIAL / 'registered_identity_registry.cpp'),
            str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
            str(FINANCIAL.parent.parent / 'private_batch_trial' /
                'privacy_capture_hook.cpp'),
            '-I', str(FINANCIAL), '-pthread', '-lcrypto', '-o', str(cls.binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_mode(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True,
                                text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    def run_recipe(self, name, body, source=SOURCE, layout=LAYOUT,
                   selected_hash=None, accepted=True):
        path = self.root / (name + '.bin')
        path.write_bytes(body)
        result = subprocess.run([
            str(self.binary), 'load', str(path), selected_hash or digest(body),
            source, layout, 'accept'], capture_output=True, text=True)
        if accepted:
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0,
                                'malformed recipe accepted: ' + name)

    def test_exact_selected_recipe_and_authority_partition(self):
        self.run_recipe('good', recipe())
        self.run_mode('authority-happy')

    def test_wrong_columns_identity_and_shape_refuse(self):
        cases = {
            'wrong-pin': (recipe(), {'selected_hash': '0' * 64}),
            'wrong-source': (recipe(source='1' * 64), {}),
            'wrong-layout': (recipe(layout='2' * 64), {}),
            'cross-owner': (recipe(mutate=lambda x: x[1][1].__setitem__(0, 10)), {}),
            'duplicate-column': (
                recipe(mutate=lambda x: x[0][2][0].__setitem__(1, x[0][2][0][0])), {}),
            'out-of-range': (recipe(mutate=lambda x: x[2][1].__setitem__(0, 2000)), {}),
            'truncated': (recipe()[:-1], {}),
            'trailing': (recipe() + b'x', {}),
        }
        for name, (body, kwargs) in cases.items():
            with self.subTest(name=name):
                self.run_recipe(name, body, accepted=False, **kwargs)

    def test_non_permutation_set_mismatch_and_replay_refuse(self):
        self.run_mode('authority-mutations')
        self.run_mode('authority-race')

    def test_production_surface_is_source_only_and_nonforgeable(self):
        self.run_mode('source')
        source = self.root / 'production-interface.cpp'
        source.write_text(r'''
#include "baseline_owner_effects_recipe.hpp"
#include <concepts>
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;
static_assert(!std::default_initializable<OwnerPrivateEffectsAuthority>);
static_assert(!std::constructible_from<OwnerPrivateEffectsAuthority,
                                       PublicOwnerPrivateEffects>);
static_assert(!std::default_initializable<PreparedBaselineOwnerEffects>);
int main() { return 0; }
''', encoding='utf-8')
        result = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-c', str(source), '-I', str(FINANCIAL),
            '-o', str(self.root / 'production-interface.o'),
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
