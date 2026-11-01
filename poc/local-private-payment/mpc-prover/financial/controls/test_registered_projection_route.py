#!/usr/bin/env python3
"""Controls for the source-only registered public projection handoff."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent


def compile_cpp(source, output, *, test_setup=False):
    command = [
        'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
    ]
    if test_setup:
        command.append('-DKPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP')
    command.extend(source)
    command.extend(['-I', str(FINANCIAL), '-lcrypto', '-pthread',
                    '-o', str(output)])
    return subprocess.run(
        command, capture_output=True, text=True, check=False)


class RegisteredProjectionRouteControls(unittest.TestCase):
    def test_exact_route_runtime_and_adversarial_controls(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-registered-projection-route-') as temporary:
            binary = Path(temporary) / 'route-controls'
            compiled = compile_cpp([
                str(FINANCIAL / 'registered_projection_route.cpp'),
                str(FINANCIAL / 'registered_identity_registry.cpp'),
                str(HERE / 'registered_projection_route_test.cpp'),
            ], binary, test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True,
                timeout=30, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_wire_order_is_read_eof_ack_and_has_no_timeout_cap(self):
        source = (FINANCIAL / 'registered_projection_route.cpp').read_text(
            encoding='utf-8')
        receive = source[source.index(
            'RegisteredProjectionRoute::receive_and_retain_impl('):]
        ordered = [
            'auto first = receive_packet(fd, packet);',
            'auto second = receive_packet(fd, packet);',
            'auto eof = receive_packet(fd, packet);',
            'const auto ack = acknowledgment(',
            'send_packet(fd, ack);',
            '::shutdown(fd, SHUT_WR)',
        ]
        positions = [receive.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('first.pid == parent.expected_role0_pid_', receive)
        self.assertIn('received_ack.pid == writer.expected_parent_pid_',
                      source)
        self.assertIn('MSG_TRUNC | MSG_CTRUNC', source)
        self.assertIn('for (const int fd : sockets)', source)
        self.assertNotIn('SO_RCVTIMEO', source)
        self.assertNotIn('SO_SNDTIMEO', source)
        self.assertIn('::poll(&state, 1, 0)', source)
        self.assertNotRegex(source, r'::poll\(&state,\s*1,\s*[1-9]')

    def test_route_identity_precedes_and_excludes_projection_body(self):
        source = (FINANCIAL / 'registered_projection_route.cpp').read_text(
            encoding='utf-8')
        identity = source[
            source.index('Digest route_identity('):
            source.index('Digest fork_binding_identity(')]
        self.assertIn('fresh_nonce()', identity)
        self.assertNotIn('projection_identity', identity)
        self.assertNotIn('std::byte', identity)

        header = (FINANCIAL / 'registered_projection_route.hpp').read_text(
            encoding='utf-8')
        receipt = re.search(
            r'struct PublicRetainedProjectionReceipt \{(.*?)\n\};',
            header, re.DOTALL).group(1)
        self.assertNotIn('projection', receipt)
        self.assertNotIn('route', receipt)
        self.assertNotIn('pid', receipt.lower())
        self.assertIn('PUBLIC_PROJECTION_BYTES = 10685', header)
        self.assertIn('ROLE0_PROJECTION_ROUTE_FIXED_FD = 30', header)
        for false_status in (
                'candidate_egress_callsite = false',
                'baseline_post_disclosure_callsite = false',
                'parent_bootstrap_mint_integration = false',
                'dispatcher_close_integration = false',
                'native_terminal_retention_integration = false',
                'registered_driver_configured = false',
                'launch_authorized = false'):
            self.assertIn(false_status, source)

    def test_production_surface_has_no_raw_factory_or_private_body_accessor(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-projection-route-surface-') as temporary:
            root = Path(temporary)
            source = root / 'surface.cpp'
            source.write_text(r'''
#include "registered_projection_route.hpp"
#include <concepts>
#include <utility>
using namespace kpi::mpc::financial::registered_driver::projection_route;
template<class T> concept HasProjection = requires(const T& value) {
    value.projection();
};
template<class T> concept HasProjectionIdentity = requires(const T& value) {
    value.projection_identity();
};
template<class T> concept HasRouteIdentity = requires(const T& value) {
    value.route_identity();
};
template<class T> concept HasTerminalTransfer = requires(T value) {
    std::move(value).transfer_for_native_terminal();
};
template<class T> concept HasTestMint = requires(PublicProjectionRoutePlan p) {
    T::test_only_mint(p);
};
static_assert(!std::default_initializable<ProjectionRoutePlanAuthority>);
static_assert(!std::constructible_from<ProjectionRoutePlanAuthority,
                                       PublicProjectionRoutePlan>);
static_assert(!std::default_initializable<ProjectionDeliveryAuthority>);
static_assert(!std::constructible_from<ProjectionDeliveryAuthority,
    PublicProjectionRoutePlan,
    std::array<std::byte, PUBLIC_PROJECTION_BYTES>>);
static_assert(!HasProjection<ParentRetainedProjectionAuthority>);
static_assert(!HasProjectionIdentity<ParentRetainedProjectionAuthority>);
static_assert(!HasRouteIdentity<ParentRetainedProjectionAuthority>);
static_assert(!HasTerminalTransfer<ParentRetainedProjectionAuthority>);
static_assert(!HasProjection<NativeTerminalRetainedProjectionAuthority>);
static_assert(!HasTestMint<ProjectionRoutePlanAuthority>);
int main() { return 0; }
''', encoding='utf-8')
            compiled = compile_cpp(
                [str(source)], root / 'surface')
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_hostile_tu_cannot_construct_or_mint_authorities(self):
        attacks = {
            'plan-constructor': r'''
#include "registered_projection_route.hpp"
using namespace kpi::mpc::financial::registered_driver::projection_route;
void attack(PublicProjectionRoutePlan plan) {
    ProjectionRoutePlanAuthority forged(plan);
}
''',
            'delivery-constructor': r'''
#include "registered_projection_route.hpp"
using namespace kpi::mpc::financial::registered_driver::projection_route;
void attack(PublicProjectionRoutePlan plan) {
    std::array<std::byte, PUBLIC_PROJECTION_BYTES> body{};
    ProjectionDeliveryAuthority forged(plan, body);
}
''',
            'test-mint': r'''
#include "registered_projection_route.hpp"
using namespace kpi::mpc::financial::registered_driver::projection_route;
void attack(PublicProjectionRoutePlan plan) {
    (void)ProjectionRoutePlanAuthority::test_only_mint(plan);
}
''',
            'lookalike-fork-bridge': r'''
#include "registered_projection_route.hpp"
namespace kpi::mpc::financial::registered_driver::projection_route {
class RegisteredProjectionRouteForkBridge {
public:
    static void attack(Role0ProjectionRouteWriterAuthority& value) {
        value.fd_ = -1;
    }
};
}
''',
            'lookalike-parent-plan': r'''
#include "registered_projection_route.hpp"
namespace kpi::mpc::financial::registered_driver {
class ParentRoleForkPlanAuthority {};
}
''',
        }
        with tempfile.TemporaryDirectory(
                prefix='kpb-projection-route-hostile-') as temporary:
            root = Path(temporary)
            for name, text in attacks.items():
                source = root / f'{name}.cpp'
                source.write_text(text, encoding='utf-8')
                result = subprocess.run([
                    'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-pedantic', '-fsyntax-only', '-I', str(FINANCIAL),
                    str(source),
                ], capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertRegex(
                    result.stderr, r'private|not a member|redefinition', name)


if __name__ == '__main__':
    unittest.main()
