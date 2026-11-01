import subprocess
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class OwnerCohortIngressControls(unittest.TestCase):
    def test_all_arrival_orders_and_fixed_frames(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'owner-cohort-ingress-controls'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread',
                str(HERE / 'owner_cohort_ingress_test.cpp'),
                '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))


if __name__ == '__main__':
    unittest.main()
