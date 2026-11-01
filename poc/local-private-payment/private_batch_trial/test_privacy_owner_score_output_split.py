#!/usr/bin/env python3
"""All-three sealed OwnerScore output split controls."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SOURCES = (
    'privacy_owner_score_output_split_control.cpp',
    'privacy_owner_score_output_split_authority.cpp',
    'privacy_owner_score_output_split_bridge.cpp',
    'privacy_owner_score_run_measurement.cpp',
    'privacy_measurement_runtime_bridge.cpp',
    'privacy_measurement_authority.cpp',
    'privacy_measurement_child_output_authority.cpp',
    'privacy_measurement_output_abi.cpp',
    'privacy_measurement_worker_capsule.cpp',
    'privacy_native_phase_scope_authority.cpp',
    'privacy_native_empirical_result_authority.cpp',
)


class OwnerScoreOutputSplitControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False, sanitize=False):
        command = [
            'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread', '-I', str(HERE),
        ]
        if test_setup:
            command.extend([
                '-DKPB_OWNER_SCORE_OUTPUT_SPLIT_TEST_SETUP',
                '-DKPB_MEASUREMENT_RUNTIME_BRIDGE_TEST_SETUP',
                '-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP',
                '-DKPB_MEASUREMENT_CHILD_OUTPUT_TEST_SETUP',
                '-DKPB_MEASUREMENT_OUTPUT_ABI_TEST_SETUP',
            ])
        if sanitize:
            command.extend([
                '-fsanitize=address,undefined',
                '-fno-omit-frame-pointer',
            ])
        command.extend(str(HERE / source) for source in sources)
        command.extend(['-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_all_three_split_is_atomic_exact_and_indivisible(self):
        with tempfile.TemporaryDirectory(prefix='kpb-score-split-') as raw:
            binary = Path(raw) / 'control'
            compiled = self.compile(binary, *SOURCES, test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_test_fault_api_is_absent_from_production(self):
        probes = {
            'split-fault': r'''
#include "privacy_owner_score_output_split_authority.hpp"
using namespace kpb::measurement::score_output_split;
int main() {
    auto* method = &OwnerScoreOutputSplitBridge::test_only_split;
    (void)method;
}
''',
            'retention-fault': r'''
#include "privacy_measurement_authority.hpp"
using namespace kpb::measurement;
int main() {
    auto* method = &RunMeasurement::test_only_accept_owner_score_split;
    (void)method;
}
''',
            'retention-inspection': r'''
#include "privacy_measurement_authority.hpp"
using namespace kpb::measurement;
int main() {
    auto* method = &RunMeasurement::test_only_has_owner_score_split;
    (void)method;
}
''',
        }
        with tempfile.TemporaryDirectory(prefix='kpb-score-split-prod-') as raw:
            root = Path(raw)
            for name, body in probes.items():
                with self.subTest(name=name):
                    source = root / f'{name}.cpp'
                    source.write_text(body, encoding='utf-8')
                    compiled = self.compile(root / name, source)
                    self.assertNotEqual(compiled.returncode, 0)

    def test_lineage_mint_and_outcome_inspection_are_absent_from_production(self):
        probes = {
            'lineage-mint': r'''
#include "privacy_owner_score_output_split_authority.hpp"
using namespace kpb::measurement::score_output_split;
int main() {
    auto* method = &OwnerScoreOutputLineageAuthority::test_only_mint;
    (void)method;
}
''',
            'outcome-inspection': r'''
#include "privacy_owner_score_output_split_authority.hpp"
using namespace kpb::measurement::score_output_split;
template<class T> concept Inspectable = requires(const T& value) {
    value.test_only_summary();
};
static_assert(Inspectable<OwnerScoreOutputSplitOutcomeAuthority>);
int main() {}
''',
        }
        with tempfile.TemporaryDirectory(prefix='kpb-score-split-opaque-') as raw:
            root = Path(raw)
            for name, body in probes.items():
                with self.subTest(name=name):
                    source = root / f'{name}.cpp'
                    source.write_text(body, encoding='utf-8')
                    compiled = self.compile(root / name, source)
                    self.assertNotEqual(compiled.returncode, 0)

    def test_legacy_run_measurement_score_accept_and_aggregate_issue_are_absent(self):
        probes = {
            'accept-score': r'''
#include "privacy_measurement_authority.hpp"
using namespace kpb::measurement;
int main() { auto* method = &RunMeasurement::accept_score; (void)method; }
''',
            'issue-aggregate': r'''
#include "privacy_measurement_authority.hpp"
using namespace kpb::measurement;
int main() { auto* method = &RunMeasurement::issue_aggregate; (void)method; }
''',
        }
        with tempfile.TemporaryDirectory(prefix='kpb-score-legacy-') as raw:
            root = Path(raw)
            for name, body in probes.items():
                with self.subTest(name=name):
                    source = root / f'{name}.cpp'
                    source.write_text(body, encoding='utf-8')
                    compiled = subprocess.run([
                        'c++', '-std=c++20', '-I', str(HERE),
                        '-fsyntax-only', str(source)], capture_output=True,
                        text=True, check=False)
                    self.assertNotEqual(compiled.returncode, 0)

    def test_run_measurement_requires_the_opaque_closed_sum(self):
        with tempfile.TemporaryDirectory(prefix='kpb-score-run-gate-') as raw:
            root = Path(raw)
            source = root / 'required.cpp'
            source.write_text(r'''
#include "privacy_measurement_authority.hpp"
#include "privacy_owner_score_output_split_authority.hpp"
using namespace kpb::measurement;
using namespace kpb::measurement::score_output_split;
template<class T> concept AcceptsClosedSum = requires(
        T& run, OwnerScoreOutputSplitOutcomeAuthority&& outcome) {
    run.accept_owner_score_split(std::move(outcome));
};
static_assert(AcceptsClosedSum<RunMeasurement>);
static_assert(kOwnerScoreOutputSplitSourceStatus.run_measurement_integrated);
static_assert(!kOwnerScoreOutputSplitSourceStatus
                  .mandatory_stop_sink_integrated);
static_assert(!kOwnerScoreOutputSplitSourceStatus
                  .aggregate_completion_retains_comparison);
int main() {}
''', encoding='utf-8')
            compiled = subprocess.run([
                'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-I', str(HERE), '-fsyntax-only', str(source),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_split_control_is_asan_ubsan_clean(self):
        with tempfile.TemporaryDirectory(prefix='kpb-score-split-san-') as raw:
            binary = Path(raw) / 'control'
            compiled = self.compile(
                binary, *SOURCES, test_setup=True, sanitize=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
                timeout=30,
                env={**__import__('os').environ,
                     'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1',
                     'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'})
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_exact_friend_name_cannot_be_defined_by_hostile_tu(self):
        probes = {}
        for header in (
                'privacy_owner_score_output_split_authority.hpp',
                'privacy_measurement_authority.hpp',
                'privacy_measurement_child_output_authority.hpp',
                'privacy_measurement_worker_capsule.hpp'):
            stem = header.removesuffix('.hpp')
            probes[f'{stem}_before'] = r'''
namespace kpb::measurement::score_output_split {
class OwnerScoreOutputSplitBridge final {};
}
''' + f'#include "{header}"\n'
            probes[f'{stem}_after'] = f'#include "{header}"\n' + r'''
namespace kpb::measurement::score_output_split {
class OwnerScoreOutputSplitBridge final {};
}
'''
        with tempfile.TemporaryDirectory(prefix='kpb-score-split-hostile-') as raw:
            root = Path(raw)
            for name, body in probes.items():
                with self.subTest(name=name):
                    source = root / f'{name}.cpp'
                    source.write_text(body + '\nint main() {}\n',
                                      encoding='utf-8')
                    compiled = subprocess.run([
                        'c++', '-std=c++20', '-I', str(HERE),
                        '-fsyntax-only', str(source)], capture_output=True,
                        text=True, check=False)
                    self.assertNotEqual(compiled.returncode, 0,
                                        'hostile exact friend compiled')


if __name__ == '__main__':
    unittest.main()
