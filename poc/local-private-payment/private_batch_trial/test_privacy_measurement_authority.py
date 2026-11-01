#!/usr/bin/env python3
"""Controls for the source-only parent-owned measurement authority."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class MeasurementAuthorityControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.append('-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP')
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_linear_parent_authority_controls(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-authority-controls-') as directory:
            binary = Path(directory) / 'controls'
            compiled = self.compile(
                binary,
                HERE / 'privacy_measurement_authority_control.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_surface_is_move_only_and_has_no_public_minter(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-authority-production-') as directory:
            directory = Path(directory)
            source = directory / 'production_surface.cpp'
            source.write_text(r'''
#include "privacy_measurement_authority.hpp"
#include <type_traits>
using namespace kpb::measurement;
template<class T> concept HasRecordRoot = requires(T value) {
    value.record_root;
};
template<class T> concept HasEndFrameIdentity = requires(T value) {
    value.end_frame_identity;
};
template<class T> concept HasEofIdentity = requires(T value) {
    value.eof_identity;
};
template<class T> concept HasProducerReceipt = requires(T value) {
    value.producer_receipt;
};
template<class T> concept HasProducerIdentity = requires(T value) {
    value.producer_identity;
};
template<class T> concept HasProducerChildExit = requires(T value) {
    value.producer_child_exit;
};
template<class T> concept HasRecordCount = requires(T value) {
    value.record_count;
};
template<class T> concept HasPayloadBytes = requires(T value) {
    value.payload_bytes;
};
template<class T> concept HasRawWireBytes = requires(T value) {
    value.raw_wire_bytes;
};
static_assert(!HasRecordRoot<PublicStreamClosure>);
static_assert(!HasEndFrameIdentity<PublicStreamClosure>);
static_assert(!HasEofIdentity<PublicStreamClosure>);
static_assert(!HasRecordCount<PublicStreamClosure>);
static_assert(!HasPayloadBytes<PublicStreamClosure>);
static_assert(!HasRawWireBytes<PublicStreamClosure>);
static_assert(!HasProducerReceipt<PublicProducerClosure>);
static_assert(!HasProducerIdentity<PublicProducerClosure>);
static_assert(!HasProducerChildExit<PublicProducerClosure>);
static_assert(!HasProducerReceipt<PublicTrialCaptureCompletion>);
static_assert(!HasProducerIdentity<PublicTrialCaptureCompletion>);
static_assert(!HasProducerChildExit<PublicTrialCaptureCompletion>);
static_assert(!std::is_copy_constructible_v<PartyCompletionAuthority>);
static_assert(!std::is_copy_constructible_v<
    ParentManifestRecomputationAuthority>);
static_assert(!std::is_copy_constructible_v<ProducerClosureAuthority>);
static_assert(!std::is_copy_constructible_v<TrialCaptureCompletionAuthority>);
static_assert(!std::is_copy_constructible_v<
    runtime_bridge::ObserverAdmissionAuthority>);
static_assert(!std::is_copy_constructible_v<ObserverPermitAuthority>);
static_assert(!std::is_copy_constructible_v<
    ObserverExecutionPermitAuthority>);
static_assert(!std::is_copy_constructible_v<RunAggregateCompletionAuthority>);
static_assert(!std::is_copy_constructible_v<BatchPrivacyPassAuthority>);
static_assert(!std::is_constructible_v<
    PartyCompletionAuthority, PublicPartyCompletion>);
static_assert(!std::is_constructible_v<
    ParentManifestRecomputationAuthority,
    PublicParentManifestRecomputation>);
static_assert(!std::is_constructible_v<
    ProducerClosureAuthority, PublicProducerClosure,
    ProducerClosureEvidence>);
static_assert(!std::is_constructible_v<
    ObservationCompletionAuthority, PublicObservationCompletion>);
static_assert(!std::is_constructible_v<
    BarrierFreezeAuthority, PublicBarrierFreeze>);
static_assert(!std::is_constructible_v<
    OwnerScoreCompletionAuthority, PublicOwnerScoreCompletion>);
static_assert(!std::is_constructible_v<
    AggregateCompletionAuthority, PublicAggregateCompletion>);
static_assert(!std::is_constructible_v<
    ComparisonSelectionAuthority, PublicComparisonSelection>);
static_assert(!std::is_constructible_v<
    OwnerComparisonCompletionAuthority,
    PublicOwnerComparisonCompletion>);
static_assert(!std::is_constructible_v<
    BatchPrivacyPassAuthority, PublicBatchPrivacyPass>);
template<class T> concept HasReceiptOnlyProducerSubmit = requires(
        T& joiner, ProducerClosureAuthority&& producer) {
    joiner.submit(static_cast<ProducerClosureAuthority&&>(producer));
};
template<class T> concept HasTestExecutionBypass = requires(T&& permit) {
    static_cast<T&&>(permit).test_only_take_execution();
};
static_assert(!HasReceiptOnlyProducerSubmit<TrialCaptureJoiner>);
static_assert(!HasTestExecutionBypass<ObserverPermitAuthority>);
int main() { return kSourceStatus.configured ? 1 : 0; }
''', encoding='utf-8')
            binary = directory / 'production_surface'
            compiled = self.compile(
                binary, source, HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp')
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            symbols = subprocess.run(
                ['nm', '-C', str(binary)], capture_output=True, text=True,
                check=False, timeout=10)
            self.assertEqual(symbols.returncode, 0,
                             symbols.stdout + symbols.stderr)
            self.assertNotIn('test_only_mint', symbols.stdout)

    def test_test_mint_is_absent_from_production_build(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-authority-no-mint-') as directory:
            directory = Path(directory)
            source = directory / 'forbidden_mint.cpp'
            source.write_text(r'''
#include "privacy_measurement_authority.hpp"
using namespace kpb::measurement;
int main() {
    PublicPartyCompletion receipt{};
    auto authority = PartyCompletionAuthority::test_only_mint(receipt);
    (void)authority;
}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'forbidden_mint', source,
                HERE / 'privacy_measurement_authority.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp')
            self.assertNotEqual(compiled.returncode, 0,
                                'test-only mint unexpectedly compiled')
            self.assertIn('test_only_mint', compiled.stderr)

    def test_completion_and_producer_friend_names_cannot_be_forged(self):
        attacks = {
            'runtime-completion': r'''
#include "privacy_measurement_authority.hpp"
namespace kpb::measurement::runtime_bridge {
class RuntimeCompletionBridge final {
public:
    static auto observation() {
        return ObservationCompletionAuthority(PublicObservationCompletion{});
    }
    static auto observer_execution() {
        return ObserverExecutionPermitAuthority(PublicObserverPermit{});
    }
    static auto score_execution() {
        return OwnerScoreExecutionPermitAuthority(PublicOwnerScorePermit{});
    }
    static auto score() {
        return OwnerScoreCompletionAuthority(PublicOwnerScoreCompletion{});
    }
    static auto aggregate_permit() {
        return AggregatePermitAuthority(PublicAggregatePermit{});
    }
    static auto aggregate() {
        return AggregateCompletionAuthority(PublicAggregateCompletion{});
    }
    static auto comparison_permit() {
        return OwnerComparisonPermitAuthority(
            PublicOwnerComparisonPermit{});
    }
    static auto comparison() {
        return OwnerComparisonCompletionAuthority(
            PublicOwnerComparisonCompletion{});
    }
};
}
int main() { return 0; }
''',
            'producer-runtime': r'''
#include "privacy_measurement_authority.hpp"
namespace kpb::measurement::producer_runtime {
class ParentOwnedCaptureProducer final {
public:
    static auto forge() {
        return ProducerClosureAuthority(
            PublicProducerClosure{}, ProducerClosureEvidence{});
    }
};
}
int main() { return 0; }
''',
            'observer-capture': r'''
#include "privacy_measurement_authority.hpp"
namespace kpb::measurement::runtime_bridge {
class ObserverCaptureCapsuleBridge final {
public:
    static auto forge() {
        return ProducerClosureAuthority(
            PublicProducerClosure{}, ProducerClosureEvidence{});
    }
};
}
int main() { return 0; }
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-no-forward-friend-') as directory:
            directory = Path(directory)
            for name, body in attacks.items():
                source = directory / f'{name}.cpp'
                source.write_text(body, encoding='utf-8')
                compiled = subprocess.run([
                    'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-pedantic', '-pthread', '-I', str(HERE), '-c',
                    str(source), '-o', str(directory / f'{name}.o'),
                ], capture_output=True, text=True, check=False)
                self.assertNotEqual(
                    compiled.returncode, 0,
                    f'hostile definition {name} unexpectedly compiled')

    def test_registered_measurement_consumer_name_is_complete(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-registered-consumer-') as directory:
            directory = Path(directory)
            source = directory / 'hostile.cpp'
            source.write_text(r'''
#include "privacy_measurement_authority.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredMeasurementCaptureBridge final {};
}
int main() { return 0; }
''', encoding='utf-8')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread', '-I', str(HERE), '-c',
                str(source), '-o', str(directory / 'hostile.o'),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(
                compiled.returncode, 0,
                'registered measurement consumer friend name is forgeable')


if __name__ == '__main__':
    unittest.main()
