import subprocess
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
PRIVATE_BATCH = FINANCIAL.parent.parent / 'private_batch_trial'


class RegisteredCaptureSessionControls(unittest.TestCase):
    def test_single_writer_exact_projection_and_no_forged_route(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'registered-capture-session-controls'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread',
                '-DKPI_REGISTERED_IDENTITY_UNFUNDED_SETUP',
                '-DKPI_REGISTERED_ATTEMPT_TEST_SETUP',
                '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
                '-DKPI_REGISTERED_CAPTURE_SESSION_TEST_SETUP',
                str(HERE / 'registered_capture_session_test.cpp'),
                str(FINANCIAL / 'registered_capture_session.cpp'),
                str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
                str(FINANCIAL / 'registered_driver_bridge.cpp'),
                str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
                str(FINANCIAL / 'registered_identity_registry.cpp'),
                str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
                str(PRIVATE_BATCH / 'privacy_capture_hook.cpp'),
                '-I', str(FINANCIAL), '-lcrypto', '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_forward_declared_lookalikes_cannot_access_private_session(self):
        attacks = {
            'construction': '''
#include "registered_capture_session.hpp"
namespace kpi::mpc::financial {
class FinancialConstruction {
public:
    static void attack(registered_driver::RegisteredCaptureSession& value) {
        value.listeners_ready();
    }
};
}
''',
            'egress': '''
#include "registered_capture_session.hpp"
namespace kpi::mpc::history {
class EgressRelease {
public:
    static void attack(
        financial::registered_driver::RegisteredCaptureSession& value) {
        unsigned char byte = 0;
        value.released_projection({&byte, 1});
    }
};
}
''',
            'raw-baseline-export': '''
#include "registered_capture_session.hpp"
#include "baseline_public_effects_collector.hpp"
#include <utility>
using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;
void attack(RegisteredCaptureSession& session,
            PublicExplicitOwnerEffects caller_authored) {
    ExplicitOwnerPublicEffectsAuthority forged(std::move(caller_authored));
    RegisteredBaselineObserverCaptureBridge::explicit_owner_public_effects(
        session, std::move(forged));
}
''',
            'raw-terminal-mapping': '''
#include "baseline_public_effects_collector.hpp"
#include <utility>
using namespace kpi::mpc::financial::registered_driver::baseline_disclosure;
BaselineTerminalOwnerMappingAuthority attack(
        PublicExplicitOwnerEffects caller_authored) {
    return BaselineTerminalOwnerMappingAuthority(
        std::move(caller_authored));
}
''',
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, source in attacks.items():
                path = root / (name + '.cpp')
                path.write_text(source)
                compiled = subprocess.run([
                    'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-pedantic', '-fsyntax-only', '-I', str(FINANCIAL),
                    str(path),
                ], capture_output=True, text=True, check=False)
                self.assertNotEqual(compiled.returncode, 0, name)
                self.assertIn('private', compiled.stderr, compiled.stderr)


if __name__ == '__main__':
    unittest.main()
