import subprocess
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent


class HiddenCohortDispatcherControls(unittest.TestCase):
    def test_compiled_hidden_cohort_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'hidden-cohort-controls'
            compile_result = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                str(HERE / 'hidden_cohort_dispatcher_test.cpp'),
                str(FINANCIAL / 'hidden_cohort_dispatcher.cpp'),
                '-I', str(FINANCIAL), '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compile_result.returncode, 0,
                             compile_result.stdout + compile_result.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual(run.stdout, '')
            self.assertEqual(run.stderr, '')


if __name__ == '__main__':
    unittest.main()
