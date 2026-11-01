#!/usr/bin/env python3
"""Contract controls for the missing score STOP/final consumer."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class OwnerScoreTerminalConsumerAuthorityControls(unittest.TestCase):
    def compile(self, output, source, *, link=False):
        command = [
            'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-I', str(HERE), str(source),
        ]
        if link:
            command.extend([
                str(HERE / 'privacy_owner_score_terminal_consumer_authority.cpp'),
                '-o', str(output),
            ])
        else:
            command.extend(['-c', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_all_terminal_capabilities_are_opaque_move_only(self):
        with tempfile.TemporaryDirectory(prefix='kpb-score-terminal-') as raw:
            root = Path(raw)
            source = root / 'surface.cpp'
            source.write_text(r'''
#include "privacy_owner_score_terminal_consumer_authority.hpp"
#include <concepts>
#include <type_traits>
using namespace kpb::measurement::score_terminal;
template<class T> concept HasReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasArm = requires(const T& value) { value.arm(); };
template<class T> concept HasTake = requires(T& value) { value.take(); };
template<class T> constexpr bool opaque_move_only =
    !std::default_initializable<T> && !std::copy_constructible<T> &&
    std::move_constructible<T> && !HasReceipt<T> && !HasArm<T> &&
    !HasTake<T>;
static_assert(opaque_move_only<
    RunMeasurementOwnerScoreOutcomeTransferAuthority>);
static_assert(opaque_move_only<OwnerScoreDurableStopSinkAuthority>);
static_assert(opaque_move_only<
    OwnerScoreAggregateComparisonConsumerAuthority>);
static_assert(opaque_move_only<OwnerScoreTerminalConsumeResultAuthority>);
static_assert(kOwnerScoreTerminalConsumerSourceStatus
                  .requires_preacquired_stop_and_success_consumers);
static_assert(kOwnerScoreTerminalConsumerSourceStatus
                  .no_public_arm_or_optional_residual);
static_assert(!kOwnerScoreTerminalConsumerSourceStatus
                   .run_measurement_transfer);
static_assert(!kOwnerScoreTerminalConsumerSourceStatus.durable_stop_sink);
static_assert(!kOwnerScoreTerminalConsumerSourceStatus
                   .aggregate_comparison_consumer);
static_assert(!kOwnerScoreTerminalConsumerSourceStatus
                   .closed_sum_consumer);
static_assert(!kOwnerScoreTerminalConsumerSourceStatus
                   .aggregate_completion_carries_comparison);
static_assert(!kOwnerScoreTerminalConsumerSourceStatus.final_privacy_pass);
static_assert(!kOwnerScoreTerminalConsumerSourceStatus.configured);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'surface', source, link=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(root / 'surface')], check=False)
            self.assertEqual(run.returncode, 0)

    def test_consumer_and_mints_are_mechanically_absent(self):
        probes = {
            'consume': r'''
#include "privacy_owner_score_terminal_consumer_authority.hpp"
using namespace kpb::measurement::score_terminal;
int main() {
    auto* method = &OwnerScoreTerminalConsumerBridge::consume;
    (void)method;
}
''',
            'transfer-mint': r'''
#include "privacy_owner_score_terminal_consumer_authority.hpp"
using namespace kpb::measurement::score_terminal;
int main() {
    auto value = RunMeasurementOwnerScoreOutcomeTransferAuthority::
        test_only_mint();
    (void)value;
}
''',
            'sink-mint': r'''
#include "privacy_owner_score_terminal_consumer_authority.hpp"
using namespace kpb::measurement::score_terminal;
int main() {
    auto value = OwnerScoreDurableStopSinkAuthority::test_only_mint();
    (void)value;
}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-score-terminal-absent-') as raw:
            root = Path(raw)
            for name, body in probes.items():
                with self.subTest(name=name):
                    source = root / f'{name}.cpp'
                    source.write_text(body, encoding='utf-8')
                    compiled = self.compile(root / f'{name}.o', source)
                    self.assertNotEqual(compiled.returncode, 0)

    def test_complete_bridge_name_cannot_be_forged(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-score-terminal-friend-') as raw:
            root = Path(raw)
            for order in ('before', 'after'):
                hostile = r'''
namespace kpb::measurement::score_terminal {
class OwnerScoreTerminalConsumerBridge final {};
}
'''
                include = (
                    '#include '
                    '"privacy_owner_score_terminal_consumer_authority.hpp"\n')
                source = root / f'{order}.cpp'
                source.write_text(
                    (hostile + include if order == 'before'
                     else include + hostile) + 'int main() {}\n',
                    encoding='utf-8')
                compiled = self.compile(root / f'{order}.o', source)
                self.assertNotEqual(compiled.returncode, 0)

    def test_contract_names_every_unclosed_dependency(self):
        header = (
            HERE / 'privacy_owner_score_terminal_consumer_authority.hpp'
        ).read_text(encoding='utf-8')
        for required in (
                'source-owned compact lineage',
                'durable STOP sink',
                'aggregate completion carrying all comparison residuals',
                'final aggregate-plus-comparison consumer'):
            self.assertIn(required, header)
        self.assertNotIn('test_only_mint', header)


if __name__ == '__main__':
    unittest.main()
