#!/usr/bin/env python3
"""Real-TLS controls for the immutable registered CryptoPlayer roster."""

from pathlib import Path
import os
import socket
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
ROOT = MPC.parents[2]
VENDOR = ROOT / '.local' / 'mpc-prover-softspoken-vendor'
MP_SPDZ = VENDOR / 'MP-SPDZ'
PREFIX = VENDOR / 'prefix' / 'usr'
MCL = VENDOR / 'mcl'


def run(command, cwd):
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)


class RegisteredRosterCryptoPlayerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-roster-player-')
        cls.root = Path(cls.temporary.name)
        cls.player_data = cls.root / 'Player-Data'
        cls.player_data.mkdir(mode=0o700)
        run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-days', '1', '-subj', '/CN=KPB Test CA',
            '-keyout', 'ca.key', '-out', 'ca.pem',
        ], cls.player_data)
        for role in range(3):
            name = f'P{role}'
            run([
                'openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
                '-subj', f'/CN={name}', '-keyout', f'{name}.key',
                '-out', f'{name}.csr',
            ], cls.player_data)
            run([
                'openssl', 'x509', '-req', '-days', '1',
                '-in', f'{name}.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                '-CAcreateserial', '-out', f'{name}.pem',
            ], cls.player_data)
        run(['c_rehash', '.'], cls.player_data)

        cls.binary = cls.root / 'controls'
        command = [
            'g++', '-std=c++20', '-march=native', '-Wall', '-Wextra',
            '-Werror', '-Wno-overloaded-virtual', '-pedantic',
            '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
            '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
            '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
            '-DKPI_REGISTERED_ROSTER_TEST_SETUP',
            str(HERE / 'registered_roster_crypto_player_test.cpp'),
            str(FINANCIAL / 'registered_roster_crypto_player.cpp'),
            str(MPC / 'history' / 'epoch_journal.cpp'),
            '-I', str(MPC), '-I', str(MP_SPDZ),
            '-I', str(MP_SPDZ / 'deps'),
            '-I', str(MP_SPDZ / 'local' / 'include'),
            '-I', str(PREFIX / 'include'),
            '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
            '-I', str(MCL / 'include'),
            '-L', str(MP_SPDZ), '-Wl,-rpath,' + str(MP_SPDZ),
            '-L', str(PREFIX / 'lib' / 'x86_64-linux-gnu'),
            '-Wl,-rpath,' + str(PREFIX / 'lib' / 'x86_64-linux-gnu'),
            '-L', str(MCL / 'lib'), '-lSPDZ', '-lmcl', '-lssl', '-lcrypto',
            '-lgmpxx', '-lgmp', '-pthread', '-o', str(cls.binary),
        ]
        compiled = subprocess.run(
            command, capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def free_port_base(self):
        for base in range(24000, 50000, 7):
            sockets = []
            try:
                for port in range(base - 1, base + 3):
                    current = socket.socket()
                    current.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    current.bind(('127.0.0.1', port))
                    sockets.append(current)
                return base
            except OSError:
                pass
            finally:
                for current in sockets:
                    current.close()
        self.fail('no four-port range available')

    def run_trio(self, scenario, expected):
        port = self.free_port_base()
        processes = [subprocess.Popen(
            [str(self.binary), str(role), str(port), scenario],
            cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True) for role in range(3)]
        results = []
        try:
            for process in processes:
                results.append(process.communicate(timeout=30))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        codes = [process.returncode for process in processes]
        self.assertEqual(codes, expected, '\n'.join(
            output + error for output, error in results))

    def test_live_tls_roster_and_binding_survive_fresh_fork(self):
        self.run_trio('valid', [0, 0, 0])

    def test_selected_child_adapter_owns_names_for_player_lifetime(self):
        self.run_trio('runtime', [0, 0, 0])

    def test_wrong_live_certificate_roster_refuses(self):
        self.run_trio('wrong-roster', [0, 0, 0])

    def test_wrong_live_certificate_authority_refuses(self):
        self.run_trio('wrong-ca', [0, 0, 0])

    def test_mixed_registered_binding_refuses(self):
        self.run_trio('mixed-binding', [0, 0, 0])

    def test_invalid_selection_is_rejected_before_network(self):
        for scenario in ('invalid-role', 'duplicate-roster',
                         'binding-roster-mismatch'):
            result = subprocess.run(
                [str(self.binary), scenario], cwd=self.root,
                capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)

    def test_authority_move_allocates_nothing_and_does_not_terminate(self):
        result = subprocess.run(
            [str(self.binary), 'noalloc-move'], cwd=self.root,
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)

    def test_production_surface_has_no_runtime_selection_factory(self):
        source = self.root / 'production-surface.cpp'
        source.write_text(r'''
#include "registered_roster_crypto_player.hpp"
#include <concepts>
using namespace kpi::mpc::financial;
template<class T> concept ArgvAdmit = requires(int argc, char** argv) {
    T::admit(argc, argv);
};
static_assert(!std::default_initializable<ImmutableRegisteredRosterAuthority>);
static_assert(!std::constructible_from<ImmutableRegisteredRosterAuthority,
                                       PublicImmutableRosterSelection>);
static_assert(!std::default_initializable<RegisteredRosterCryptoPlayer>);
static_assert(!ArgvAdmit<RegisteredRosterCryptoPlayer>);
int main() { return 0; }
''', encoding='utf-8')
        compiled = subprocess.run([
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
            '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
            '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
            '-c', str(source), '-I', str(FINANCIAL), '-I', str(MPC),
            '-I', str(MP_SPDZ),
            '-I', str(MP_SPDZ / 'deps'),
            '-I', str(MP_SPDZ / 'local' / 'include'),
            '-I', str(PREFIX / 'include'),
            '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
            '-I', str(MCL / 'include'),
            '-o', str(self.root / 'production-surface.o'),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)


if __name__ == '__main__':
    unittest.main()
