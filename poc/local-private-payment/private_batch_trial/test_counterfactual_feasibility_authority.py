#!/usr/bin/env python3
"""Hostile controls for the isolated counterfactual-feasibility authority."""

from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class CounterfactualFeasibilityAuthorityControls(unittest.TestCase):
    def compile(self, source):
        return subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-fsyntax-only', '-I', str(HERE), str(source),
        ], capture_output=True, text=True, check=False)

    def source(self, directory, name, value):
        path = Path(directory) / name
        path.write_text(value, encoding='utf-8')
        return path

    def test_precommit_source_identities_are_exact(self):
        root = HERE.parents[2]
        expected = {
            root / 'research/next-session/local-private-payment/'
                   'private-batch-2026-10-28/PRIVACY-WORKLOAD-FREEZE-2026-10-28.json':
                '7fedea9560e241b08521ec3d88c29dba4592f017b6e909092f530a97ee210170',
            root / 'research/next-session/local-private-payment/'
                   'private-batch-2026-10-28/UNFUNDED-REHEARSAL.json':
                '34b4d30dfdcb5d72c852c049a788400978571d09d21eb728eeb16f86833b9ed5',
            root / 'poc/local-private-payment/private-batch-relation/'
                   'src/circuit.rs':
                'bae649e1c80fa82f5f1a22446197be7bfaa3b367ea21875e2a6384b98567c022',
            root / 'poc/local-private-payment/private-batch-relation/'
                   'src/counterfactual_w1.rs':
                '3342f27468273ffd0492f704649444dda429815f34217f585429c97128fa6b07',
            root / 'poc/local-private-payment/private-batch-relation/'
                   'src/counterfactual_w1_bridge.rs':
                '4ebcc80a2c72cdcc407e5970e626cfac8cd84d27934ed4a8825004e2f7ff8b63',
            root / 'poc/local-private-payment/private-batch-relation/evidence/'
                   '2026-10-28-full-financial-source/'
                   'current-matrix-source-table-2026-10-29.json':
                '04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7',
            root / 'poc/local-private-payment/private-batch-relation/evidence/'
                   '2026-10-28-full-financial-source/'
                   'current-matrix-equivalence-2026-10-29.json':
                '52ca327ac2d3dd2921c0aa913060f8a97f127d81c5d125c1892dc989853ac692',
            HERE / 'privacy_observer.py':
                'aceadace4a5d6cbfaf20a3404e6690409bb15570f01a816914a0d7eb92cfc0eb',
            HERE / 'privacy_capture_model.py':
                '3e22997c8932709496c843929e4a0752b3bc7f001690c2119a6692b6388a645a',
            root / 'research/next-session/local-private-payment/'
                   'private-batch-2026-10-28/'
                   'PRIVACY-ACCEPTANCE-GATE-FREEZE-2026-10-28.md':
                'e59e003f6022a9a1bf3c9773de4f1ef5ab8614624d3eb1f75b370c291422eae3',
            root / 'docs/adr/0092-v3-one-use-hidden-invoice-keys.md':
                'df255f2d3238caf5298db344cae24fed79ba10e80af5c28a436d471c5acc0cff',
        }
        for path, identity in expected.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                                 identity)
        matrix = json.loads(next(path for path in expected
                                 if path.name ==
                                 'current-matrix-equivalence-2026-10-29.json')
                            .read_text(encoding='utf-8'))
        self.assertEqual(
            matrix['canonical_r1cs_fingerprint'],
            'c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab')

    def test_exact_rewire_and_hostile_controls(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-counterfactual-feasibility-') as directory:
            binary = Path(directory) / 'control'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread',
                '-DKPB_COUNTERFACTUAL_FEASIBILITY_TEST_SETUP',
                str(HERE / 'counterfactual_feasibility_authority_control.cpp'),
                str(HERE / 'counterfactual_feasibility_authority.cpp'),
                str(HERE / 'privacy_measurement_child_output_authority.cpp'),
                str(HERE / 'privacy_measurement_output_abi.cpp'),
                str(HERE / 'privacy_measurement_authority.cpp'),
                '-I', str(HERE), '-lcrypto', '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_surface_emits_no_values_keys_mapping_hash_or_boolean(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-counterfactual-surface-') as directory:
            source = self.source(directory, 'surface.cpp', r'''
#include "counterfactual_feasibility_authority.hpp"
#include <concepts>
#include <utility>
using namespace kpb::measurement::counterfactual_feasibility;
template<class T> concept HasReceipt = requires(const T& v) {
    v.public_receipt();
};
template<class T> concept HasValue = requires(const T& v) { v.value(); };
template<class T> concept HasKey = requires(const T& v) { v.key(); };
template<class T> concept HasMapping = requires(const T& v) { v.mapping(); };
template<class T> concept HasHash = requires(const T& v) { v.hash(); };
template<class T> concept HasBool = requires(const T& v) { v.passed(); };
static_assert(!HasReceipt<CounterfactualFeasibilityAuthority>);
static_assert(!HasValue<CounterfactualFeasibilityAuthority>);
static_assert(!HasKey<CounterfactualFeasibilityAuthority>);
static_assert(!HasMapping<CounterfactualFeasibilityAuthority>);
static_assert(!HasHash<CounterfactualFeasibilityAuthority>);
static_assert(!HasBool<CounterfactualFeasibilityAuthority>);
static_assert(!HasReceipt<LiveCounterfactualSourceInstanceAuthority>);
static_assert(!HasHash<LiveCounterfactualSourceInstanceAuthority>);
static_assert(!HasBool<LiveCounterfactualSourceInstanceAuthority>);
static_assert(!HasReceipt<FullW1WithCloseResidualAuthority>);
static_assert(!HasValue<FullW1WithCloseResidualAuthority>);
static_assert(!HasKey<FullW1WithCloseResidualAuthority>);
static_assert(!HasMapping<FullW1WithCloseResidualAuthority>);
static_assert(!HasHash<FullW1WithCloseResidualAuthority>);
static_assert(!HasBool<FullW1WithCloseResidualAuthority>);
static_assert(!HasReceipt<CounterfactualJointClosureAuthority>);
static_assert(!HasValue<CounterfactualJointClosureAuthority>);
static_assert(!HasKey<CounterfactualJointClosureAuthority>);
static_assert(!HasMapping<CounterfactualJointClosureAuthority>);
static_assert(!HasHash<CounterfactualJointClosureAuthority>);
static_assert(!HasBool<CounterfactualJointClosureAuthority>);
static_assert(!HasReceipt<CounterfactualFeasibilityTransfer>);
static_assert(!HasHash<CounterfactualFeasibilityTransfer>);
static_assert(!HasBool<CounterfactualFeasibilityTransfer>);
int main() {}
''')
            compiled = self.compile(source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_pinned_acceptance_bridge_definition_cannot_be_replaced_at_link(
            self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-counterfactual-acceptance-') as directory:
            malicious = self.source(directory, 'malicious.cpp', r'''
#include "counterfactual_feasibility_authority.hpp"
#include <cstdlib>
#include <utility>
namespace kpb::measurement::counterfactual_feasibility {
FullW1WithCloseResidualAuthority
CounterfactualFullW1WitnessBridge::construct_and_verify(
        LiveCounterfactualSourceInstanceAuthority&&) {
    std::abort();
}
CounterfactualJointClosureAuthority
CounterfactualRuntimeCloseBridge::close_descendants(
        FullW1WithCloseResidualAuthority&&) {
    std::abort();
}
}
namespace kpb::measurement::acceptance_v4 {
counterfactual_feasibility::CounterfactualFeasibilityTransfer
CounterfactualFeasibilityAcceptanceBridge::take(
        counterfactual_feasibility::CounterfactualFeasibilityAuthority&&
            supplied) {
    return std::move(supplied).transfer_for_acceptance();
}
}
''')
            main = self.source(directory, 'main.cpp', 'int main() {}\n')
            malicious_object = Path(directory) / 'malicious.o'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-c', str(malicious), '-I', str(HERE),
                '-o', str(malicious_object),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            binary = Path(directory) / 'hostile'
            linked = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread', str(main), str(malicious_object),
                str(HERE / 'counterfactual_feasibility_authority.cpp'),
                str(HERE / 'privacy_measurement_child_output_authority.cpp'),
                str(HERE / 'privacy_measurement_output_abi.cpp'),
                str(HERE / 'privacy_measurement_authority.cpp'),
                '-I', str(HERE), '-lcrypto', '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(
                linked.returncode, 0,
                'hostile acceptance bridge replacement unexpectedly linked')
            self.assertGreaterEqual(linked.stderr.count('multiple definition'),
                                    3, linked.stderr)

    def test_direct_raw_and_lookalike_construction_fail(self):
        hostile = {
            'direct.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
int main() {
    kpb::measurement::counterfactual_feasibility::
        CounterfactualFeasibilityAuthority authority;
}
''',
            'raw.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
#include <utility>
int main() {
    kpb::measurement::RunBinding binding{};
    (void)kpb::measurement::counterfactual_feasibility::
        CounterfactualFeasibilityBridge::verify_arithmetic_shape(
            std::move(binding), std::move(binding), std::move(binding));
}
''',
            'arithmetic-is-not-feasibility.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
#include <utility>
using namespace kpb::measurement::counterfactual_feasibility;
CounterfactualFeasibilityAuthority cheat(
        CounterfactualArithmeticShapeAuthority&& shape) {
    return std::move(shape);
}
int main() {}
''',
            'hash-enum-is-not-source-witness.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
#include <utility>
int main() {
    kpb::measurement::Digest source_hash{};
    auto result = kpb::measurement::counterfactual_feasibility::
        CounterfactualFeasibilityBridge::close_full_witness(
            std::move(source_hash), std::move(source_hash));
    (void)result;
}
''',
            'production-has-no-live-source-test-minter.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
int main() {
    kpb::measurement::RunBinding binding{};
    auto result = kpb::measurement::counterfactual_feasibility::
        CounterfactualFeasibilityBridge::test_only_live_source(
            binding, 0);
    (void)result;
}
''',
            'residual-is-not-joint-closure.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
using namespace kpb::measurement::counterfactual_feasibility;
CounterfactualFeasibilityAuthority cheat(
        CounterfactualArithmeticShapeAuthority&& shape,
        FullW1WithCloseResidualAuthority&& residual) {
    return CounterfactualFeasibilityBridge::close_full_witness(
        std::move(shape), std::move(residual));
}
int main() {}
''',
            'manifest-is-not-close-authority.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
#include <utility>
int main() {
    kpb::measurement::FiniteManifest manifest{};
    auto result = kpb::measurement::counterfactual_feasibility::
        CounterfactualRuntimeCloseBridge::close_descendants(
            std::move(manifest));
    (void)result;
}
''',
            'lookalike.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
namespace kpb::measurement::counterfactual_feasibility {
class CounterfactualFeasibilityResidualBridge final {};
}
int main() {}
''',
            'acceptance-bridge-exact-name-redefinition.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
namespace kpb::measurement::acceptance_v4 {
class CounterfactualFeasibilityAcceptanceBridge final {};
}
int main() {}
''',
            'direct-live-source.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
int main() {
    kpb::measurement::counterfactual_feasibility::
        LiveCounterfactualSourceInstanceAuthority source;
}
''',
            'direct-joint-closure.cpp': r'''
#include "counterfactual_feasibility_authority.hpp"
int main() {
    kpb::measurement::counterfactual_feasibility::
        CounterfactualJointClosureAuthority closure;
}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-counterfactual-hostile-') as directory:
            for name, value in hostile.items():
                with self.subTest(name=name):
                    compiled = self.compile(self.source(
                        directory, name, value))
                    self.assertNotEqual(
                        compiled.returncode, 0,
                        'hostile source unexpectedly compiled: ' + name)


if __name__ == '__main__':
    unittest.main()
