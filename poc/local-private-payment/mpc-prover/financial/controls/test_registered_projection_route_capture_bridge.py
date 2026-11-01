#!/usr/bin/env python3
"""Genuine EGRESS-to-parent-route-to-capture-close integration controls."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
PRIVATE_BATCH = FINANCIAL.parent.parent / 'private_batch_trial'


class RegisteredProjectionRouteCaptureBridgeControls(unittest.TestCase):
    def test_exact_sequence_lineage_replay_and_transport_failures(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-route-capture-bridge-') as temporary:
            binary = Path(temporary) / 'route-capture-controls'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread',
                '-DKPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP',
                '-DKPI_REGISTERED_CAPTURE_SESSION_TEST_SETUP',
                '-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP',
                '-DKPI_REGISTERED_ATTEMPT_TEST_SETUP',
                '-DKPI_REGISTERED_IDENTITY_UNFUNDED_SETUP',
                str(HERE /
                    'registered_projection_route_capture_bridge_test.cpp'),
                str(FINANCIAL /
                    'registered_projection_route_capture_bridge.cpp'),
                str(FINANCIAL / 'registered_projection_route.cpp'),
                str(FINANCIAL / 'registered_capture_session.cpp'),
                str(FINANCIAL / 'baseline_public_effects_collector.cpp'),
                str(FINANCIAL / 'registered_driver_bridge.cpp'),
                str(FINANCIAL / 'registered_attempt_supervisor.cpp'),
                str(FINANCIAL / 'registered_identity_registry.cpp'),
                str(FINANCIAL / 'docker_monotonic_anchor_client.cpp'),
                str(PRIVATE_BATCH / 'privacy_capture_hook.cpp'),
                '-I', str(FINANCIAL), '-lcrypto',
                '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True,
                timeout=60, check=False)
            self.assertEqual(run.returncode, 0,
                             run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_surface_exposes_no_body_or_route_close_factory(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-route-capture-surface-') as temporary:
            root = Path(temporary)
            source = root / 'surface.cpp'
            source.write_text(r'''
#include "registered_projection_route_capture_bridge.hpp"
#include "registered_projection_route.hpp"
#include "registered_capture_session.hpp"
#include <concepts>
using namespace kpi::mpc::financial::registered_driver;
using namespace kpi::mpc::financial::registered_driver::projection_route;
template<class T> concept HasRouteClose = requires(
        T& session, Digest route, Digest projection) {
    session.close_after_projection_route(route, projection);
};
template<class T> concept HasRetainedBody = requires(T& session) {
    session.retained_projection_for_route();
};
template<class T> concept HasRawConsume = requires(
        T& session, Role0ProjectionRouteWriterAuthority&& writer,
        std::span<const std::byte> body) {
    RegisteredProjectionRouteCaptureBridge::consume(
        session, static_cast<Role0ProjectionRouteWriterAuthority&&>(writer),
        body);
};
static_assert(!HasRouteClose<RegisteredCaptureSession>);
static_assert(!HasRetainedBody<RegisteredCaptureSession>);
static_assert(!HasRawConsume<RegisteredCaptureSession>);
int main() { return 0; }
''', encoding='utf-8')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-fsyntax-only', '-I', str(FINANCIAL),
                str(source),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)


if __name__ == '__main__':
    unittest.main()
