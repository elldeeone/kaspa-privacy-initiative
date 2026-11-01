import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import uuid


HERE = Path(__file__).resolve().parent


class BoundedSetupAuthorityControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='kpb-bounded-setup-build-')
        cls.root = Path(cls.build.name)
        common = [
            'g++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-DKPB_BOUNDED_SETUP_TEST_SETUP',
            '-DKPB_BOUNDED_SETUP_TEST_SMALL_OUTPUTS', '-I', str(HERE),
        ]
        cls.workers = []
        for behavior in range(9):
            target = cls.root / f'worker-{behavior}'
            subprocess.run(
                common + ['-static', '-s',
                          f'-DKPB_BOUNDED_SETUP_WORKER_BEHAVIOR={behavior}',
                          str(HERE / 'bounded_setup_test_worker.cpp'),
                          '-o', str(target)],
                check=True, cwd=HERE, capture_output=True, text=True)
            cls.workers.append(target)
        cls.control = cls.root / 'control'
        subprocess.run(
            common + [str(HERE / 'bounded_setup_authority_control.cpp'),
                      str(HERE / 'bounded_setup_authority.cpp'),
                      '-lcrypto', '-o', str(cls.control)],
            check=True, cwd=HERE, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def run_control(self, scoped=True, memory_max='2G'):
        output = self.root / f'outputs-{uuid.uuid4().hex}'
        output.mkdir(mode=0o700)
        command = [str(self.control), str(output),
                   *[str(path) for path in self.workers]]
        if scoped:
            command = [
                'systemd-run', '--user', '--scope', '--quiet',
                f'--unit=kpb-bounded-setup-{uuid.uuid4().hex}',
                '-p', 'MemorySwapMax=0', '-p', f'MemoryMax={memory_max}',
                *command,
            ]
        return subprocess.run(
            command, cwd=HERE, capture_output=True, text=True, timeout=90)

    def test_fd_only_supervisor_and_all_hostile_controls(self):
        result = self.run_control(scoped=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertFalse(Path('/tmp/kpb-bounded-setup-forbidden-output').exists())

    def test_ambient_swap_enabled_scope_is_refused(self):
        result = self.run_control(scoped=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bounded setup authority refused', result.stderr)

    def test_tiny_memory_scope_is_refused_by_execution_guard(self):
        result = self.run_control(scoped=True, memory_max='128M')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bounded setup authority refused', result.stderr)

    def test_production_surface_is_exact_and_unconfigured(self):
        header = (HERE / 'bounded_setup_authority.hpp').read_text()
        source = (HERE / 'bounded_setup_authority.cpp').read_text()
        wire = (HERE / 'bounded_setup_wire.hpp').read_text()
        chronology = (HERE / 'bounded_setup_chronology_contract.hpp').read_text()
        self.assertIn('dedicated_process_per_circuit = true', header)
        self.assertIn('source_owned_worker_selector = true', header)
        self.assertIn('source_closed_static_worker_required = true', header)
        self.assertIn('source_owned_plan_selector = false', header)
        self.assertIn('typed_w1_pre_setup_handoff = false', header)
        self.assertIn('typed_w1_post_setup_measured_key_join = false', header)
        self.assertIn('pre_setup_only_plan_abi = true', header)
        self.assertIn('post_setup_artifacts_excluded = true', header)
        self.assertIn('actual_fd_setup_worker = true', header)
        self.assertIn('full_output_setup_executed = false', header)
        self.assertIn('full_aggregate_setup_executed = false', header)
        self.assertIn('setup_honesty_or_erasure_proven = false', header)
        self.assertIn('s4_selected = false', header)
        self.assertIn('s12_selected = false', header)
        self.assertIn('configured = false', header)
        self.assertNotIn('seed', header.lower())
        plan = header.split('struct FrozenSetupPlanBinding final {', 1)[1]
        plan = plan.split('};', 1)[0]
        for post_setup_field in (
                'comparison_selection', 'run_selection',
                'round_capture_plans', 'projections',
                'finite_manifest_identity',
                'finite_manifest_parent_recomputation_identity'):
            self.assertNotIn(post_setup_field, plan)
        self.assertEqual(source.count(
            'ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e'), 1)
        self.assertEqual(source.count(
            'd8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31'), 1)
        self.assertEqual(source.count(
            '04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7'), 1)
        self.assertEqual(source.count(
            'c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab'), 1)
        self.assertIn('char* environment[]{nullptr}', source)
        self.assertIn('CLOSE_RANGE_CLOEXEC', source)
        self.assertIn('source_closed_static_elf(body)', source)
        self.assertIn('O_TMPFILE', source)
        self.assertIn('PLAN_BYTES = 424', wire)
        domain_body = wire.split('PRECOMMIT_DOMAIN{', 1)[1].split('};', 1)[0]
        domain_chars = re.findall(r"'((?:\\.|[^']))'", domain_body)
        domain = ''.join(bytes(char, 'utf-8').decode('unicode_escape')
                         for char in domain_chars)
        self.assertEqual(domain, 'KPB_BOUNDED_SETUP_PRECOMMIT_V1\n')
        self.assertNotIn('PLAN_PROJECTIONS_AT', wire)
        self.assertNotIn('PLAN_ROUND_CAPTURE_PLANS_AT', wire)
        self.assertNotIn('PLAN_FINITE_MANIFEST_AT', wire)
        self.assertIn('AGGREGATE_CONTEXT_FD = 43', wire)
        self.assertIn('AGGREGATE_SIGNATURE_FD = 44', wire)
        self.assertIn('MemorySwapMax=0', Path(__file__).read_text())
        self.assertIn('freeze(\n        ::kpb::measurement::counterfactual_feasibility::\n'
                      '            W1PreSetupTrialAuthority&&)', chronology)
        self.assertIn('join_measured_keys(\n        SetupCompletionAuthority&&,\n'
                      '        W1SetupBindingContinuationAuthority&&)', chronology)
        self.assertNotIn('Digest', chronology)
        self.assertNotIn('Public', chronology)

    def test_worker_binaries_are_distinct_and_no_full_setup_was_run(self):
        identities = {
            hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.workers
        }
        self.assertEqual(len(identities), len(self.workers))
        self.assertLess(sum(path.stat().st_size for path in self.workers),
                        16 * 1024 * 1024)


if __name__ == '__main__':
    unittest.main()
