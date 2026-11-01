import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent.parent
ROOT = SOURCE.parents[2]


class OwnerDdnntControls(unittest.TestCase):
    def test_five_value_checks_strict_frames_and_old_width_refusal(self):
        vendor = Path(os.environ.get(
            'KPI_MPC_VENDOR', ROOT / '.local/mpc-prover-softspoken-vendor'))
        mp = vendor / 'MP-SPDZ'
        prefix = vendor / 'prefix/usr'
        lib = prefix / 'lib/x86_64-linux-gnu'
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'owner-ddnnt-controls'
            command = [
                'g++', '-std=c++20', '-O1', '-march=native', '-pthread',
                '-Wall', '-Wextra', '-Werror', '-Wno-overloaded-virtual',
                '-DNO_MIXED_CIRCUITS', '-DUSE_GF2N_LONG',
                '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
                '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
                '-I', str(SOURCE), '-I', str(mp), '-I', str(mp / 'deps'),
                '-I', str(mp / 'local/include'), '-I', str(vendor / 'mcl/include'),
                '-I', str(prefix / 'include'),
                '-I', str(prefix / 'include/x86_64-linux-gnu'),
                str(HERE / 'owner_input_ddnnt_test.cpp'),
                str(SOURCE / 'owner_input_ddnnt.cpp'),
                '-L' + str(mp), '-Wl,-rpath,' + str(mp), '-lSPDZ',
                '-L' + str(lib), '-Wl,-rpath,' + str(lib),
                '-lgmpxx', '-lgmp', '-lsodium', '-lssl', '-lcrypto',
                '-lboost_filesystem', '-lboost_iostreams', '-lboost_thread',
                '-lrt', '-lz', '-ldl', '-o', str(binary),
            ]
            compiled = subprocess.run(command, capture_output=True, text=True,
                                      check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))


if __name__ == '__main__':
    unittest.main()
