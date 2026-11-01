#!/usr/bin/env python3

import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
VENDOR = REPO / '.local/mpc-prover-softspoken-vendor'
MP = VENDOR / 'MP-SPDZ'
MCL = VENDOR / 'mcl'
PREFIX = VENDOR / 'prefix/usr'
CXX = Path('/usr/bin/x86_64-linux-gnu-g++-15')

FLAGS = [
    '-std=c++20', '-O1', '-g0', '-march=native', '-pthread',
    '-Wall', '-Wextra', '-Werror', '-Wno-overloaded-virtual',
    '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
    '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK', '-DMCL_FP_BIT=384',
    '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
]
INCLUDES = [
    ROOT, MP, MP / 'deps', MP / 'local/include', MCL / 'include',
    PREFIX / 'include', PREFIX / 'include/x86_64-linux-gnu',
]
WRAPS = [
    '-Wl,--wrap=_ZN4PRNG6ReSeedEv',
    '-Wl,--wrap=simplestot_randombytes',
    '-Wl,--wrap=_ZN9osuCrypto13sysRandomSeedEv',
]
OT_OBJECTS = [
    MP / 'OT' / name for name in (
        'BaseOT.o', 'OTExtension.o', 'OTExtensionWithMatrix.o',
        'BitDiagonal.o', 'OTTripleSetup.o', 'MascotParams.o')
]
STATIC = [
    MP / 'deps/SimplestOT_C/ref10/libSimplestOT.a',
    MCL / 'lib/libmcl.a', MP / 'local/lib/liblibOTe.a',
    MP / 'local/lib/libcoproto.a', MP / 'local/lib/libcryptoTools.a',
    MP / 'local/lib/libmacoro.a',
]


def compile_binary(output: Path) -> None:
    command = [str(CXX), *FLAGS,
               '-DKPI_P1_ENTROPY_STATE_HOOK_TEST_SETUP']
    for include in INCLUDES:
        command.extend(['-I', str(include)])
    command.extend([
        str(ROOT / 'p1_entropy_ingress_capture.cpp'),
        str(ROOT / 'controls/p1_entropy_ingress_capture_control.cpp'),
        *map(str, OT_OBJECTS), '-L' + str(MP), '-lSPDZ',
        *WRAPS, '-Wl,--start-group', *map(str, STATIC),
        '-Wl,--end-group',
        '-L' + str(PREFIX / 'lib/x86_64-linux-gnu'),
        '-Wl,-rpath,' + str(PREFIX / 'lib/x86_64-linux-gnu'),
        '-Wl,-rpath,' + str(MP), '-lgmpxx', '-lgmp', '-lsodium',
        '-lssl', '-lcrypto', '-lboost_filesystem', '-lboost_iostreams',
        '-lboost_thread', '-lrt', '-lz', '-ldl', '-z', 'noexecstack',
        '-o', str(output),
    ])
    subprocess.run(command, check=True, capture_output=True)


class P1EntropyIngressCaptureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.temp.name) / 'p1-entropy-control'
        compile_binary(cls.binary)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_mode(self, mode):
        def disable_core():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return subprocess.run(
            [self.binary, mode], capture_output=True,
            env={'PATH': '/usr/bin:/bin'}, timeout=30,
            preexec_fn=disable_core)

    def test_exact_entropy_and_source_order(self):
        result = self.run_mode('valid')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b'')

    def test_hook_failure_is_fail_stop(self):
        result = self.run_mode('failed-hook')
        self.assertEqual(result.returncode, -signal.SIGABRT)
        self.assertEqual(result.stdout, b'')

    def test_nonselected_simplest_ot_width_is_fail_stop(self):
        result = self.run_mode('wrong-width')
        self.assertEqual(result.returncode, -signal.SIGABRT)
        self.assertEqual(result.stdout, b'')

    def test_abandoned_guard_marks_unavailable(self):
        result = self.run_mode('abandoned')
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_worker_cannot_claim_reserved_root_epoch(self):
        result = self.run_mode('worker-first')
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_exact_selected_symbols_are_wrapped(self):
        symbols = subprocess.run(
            ['/usr/bin/nm', '-C', self.binary], check=True,
            capture_output=True, text=True).stdout
        self.assertIn(
            'EntropyIngressCapture::begin(std::unique_ptr<', symbols)
        self.assertIn('__wrap__ZN4PRNG6ReSeedEv', symbols)
        self.assertIn('__wrap_simplestot_randombytes', symbols)
        self.assertIn('__wrap__ZN9osuCrypto13sysRandomSeedEv', symbols)
        disassembly = subprocess.run(
            ['/usr/bin/objdump', '-d', '-C', self.binary], check=True,
            capture_output=True, text=True).stdout
        self.assertGreaterEqual(len(re.findall(
            r'call\s+[^\n]*<__wrap__ZN4PRNG6ReSeedEv>', disassembly)), 4)
        self.assertGreaterEqual(len(re.findall(
            r'call\s+[^\n]*<__wrap_simplestot_randombytes>',
            disassembly)), 2)
        self.assertGreaterEqual(len(re.findall(
            r'call\s+[^\n]*<__wrap__ZN9osuCrypto13sysRandomSeedEv>',
            disassembly)), 2)
        # Exactly one call per source reaches the pinned real implementation,
        # and that call is inside its wrapper. Every selected OT call is wrapped.
        self.assertEqual(len(re.findall(
            r'call\s+[^\n]*<PRNG::ReSeed\(\)@plt>', disassembly)), 1)
        self.assertEqual(len(re.findall(
            r'call\s+[^\n]*<simplestot_randombytes>', disassembly)), 1)
        self.assertEqual(len(re.findall(
            r'call\s+[^\n]*<osuCrypto::sysRandomSeed\(\)>',
            disassembly)), 1)

    def test_registered_build_closure_selects_wrappers(self):
        build = (ROOT / 'financial/build_registered_financial.py').read_text()
        self.assertIn("'p1_entropy_ingress_capture.cpp'", build)
        for flag in WRAPS:
            self.assertIn(repr(flag), build)
        self.assertIn("'link_flags': entropy_wrap_flags", build)

    def test_production_surface_has_no_fake_hook_or_raw_getter(self):
        source = (ROOT / 'p1_entropy_ingress_capture.hpp').read_text()
        hook = (ROOT / 'p1_entropy_state_hook.hpp').read_text()
        self.assertNotIn('test_only_begin', source.split(
            '#ifdef KPI_P1_ENTROPY_STATE_HOOK_TEST_SETUP')[0])
        for forbidden in ('raw_entropy()', 'entropy_bytes()', 'public_entropy'):
            self.assertNotIn(forbidden, source + hook)

    def test_hostile_hook_subclass_and_adapter_constructor_fail(self):
        hostile_hook = Path(self.temp.name) / 'hostile-hook.cpp'
        hostile_hook.write_text(r'''
#include "p1_entropy_state_hook.hpp"
using namespace kpi::mpc::p1_private_state;
class Fake final : public EntropyStateHook {
 public:
  bool record_entropy_ingress(const EntropyIngressView&) noexcept override {
    return true;
  }
  bool entropy_capture_terminal_noexcept() noexcept override { return true; }
  void entropy_unavailable_noexcept(EntropySource) noexcept override {}
};
int main() { Fake value; (void)value; }
''')
        command = [str(CXX), *FLAGS]
        for include in INCLUDES:
            command.extend(['-I', str(include)])
        result = subprocess.run([*command, '-fsyntax-only', hostile_hook],
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'private', result.stderr)

        hostile_recorder = Path(self.temp.name) / 'hostile-recorder.cpp'
        hostile_recorder.write_text(r'''
#include "p1_entropy_state_hook.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1CorruptStateRecorderAuthority {
 public:
  static P1EntropyStateAdapter steal() {
    return P1EntropyStateAdapter(nullptr);
  }
};
}
int main() { return 0; }
''')
        result = subprocess.run(
            [*command, '-fsyntax-only', hostile_recorder], capture_output=True)
        self.assertNotEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'private', result.stderr)

        hostile_bridge = Path(self.temp.name) / 'hostile-bridge.cpp'
        hostile_bridge.write_text(r'''
#include "p1_entropy_state_hook.hpp"
namespace kpb::measurement::p1_state_capsule {
class P1EntropyStateAdapterFactoryBridge final {};
}
int main() { return 0; }
''')
        result = subprocess.run(
            [*command, '-fsyntax-only', hostile_bridge], capture_output=True)
        self.assertNotEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'redefinition', result.stderr)


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    unittest.main()
