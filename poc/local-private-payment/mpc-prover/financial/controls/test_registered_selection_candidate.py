#!/usr/bin/env python3
"""Public-only controls for the trial-03 configured-selection candidate."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


FINANCIAL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FINANCIAL))
import registered_selection_candidate as candidate  # noqa: E402


class RegisteredSelectionCandidateControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-registered-selection-controls-')
        cls.snapshot = Path(cls.temporary.name) / 'selection'
        cls.receipt = candidate.prepare_isolation_control_snapshot(
            candidate.REPOSITORY_ROOT /
            '.local/registered-financial-selection-05', cls.snapshot)
        cls.authority = Path(cls.temporary.name) / 'CONTROL-PIN.json'
        authority_raw = candidate.encoded({
            'schema': 'kpb-registered-isolation-control-pin/v1',
            'status': 'CONTROL_ONLY_UNCONFIGURED',
            'configuration_candidate_sha256':
                cls.receipt['configuration_candidate_sha256'],
            'selected_verifier_sha256':
                cls.receipt['selected_verifier_sha256'],
            'selected_runtime_closure_sha256':
                cls.receipt['selected_runtime_closure_sha256'],
            'registered_driver_configured': False,
            'launch_authorized': False,
        })
        cls.authority.write_bytes(authority_raw)
        cls.authority.chmod(0o400)
        cls.authority_sha256 = candidate.sha(authority_raw)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @staticmethod
    def replace(path, raw, mode=0o400):
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(mode)

    def test_exact_candidate_admits_but_never_configures_driver(self):
        admitted = candidate.admit_snapshot(self.snapshot)
        self.assertEqual(admitted.trial_id, candidate.TRIAL_ID)
        self.assertEqual(admitted.registration, candidate.REGISTRATION_SHA256)
        self.assertEqual(admitted.selection, candidate.TRIAL_SELECTION_SHA256)
        self.assertFalse(admitted.driver_configured)
        self.assertFalse(admitted.configured_build_admitted)
        self.assertEqual(
            admitted.state_initialization,
            '8024df3c3410786ba0fb0a41d65d7c535d7941a7e9cc64f90fe38d059d6c4196')
        self.assertEqual(
            admitted.trial_authority,
            '520b0983849b7cd777c266a4d706994d804836fb1612610c5dd9ec16ab1fd672')
        self.assertEqual(
            admitted.build_authority,
            '0931de42aaa401f20725b9b48fd3f63580d00b7a96fadfcc84b8be5276e47f74')
        self.assertNotEqual(admitted.trial_authority,
                            admitted.build_authority)
        self.assertFalse(admitted.durable_freshness_admitted)
        self.assertFalse(admitted.launch_authorized)
        self.assertEqual(
            self.receipt['status'], 'SOURCE_SNAPSHOT_CANDIDATE_UNCONFIGURED')
        self.assertTrue(self.receipt['control_only'])
        self.assertFalse(self.receipt['authority_admitted'])
        self.assertFalse(self.receipt['historical_base_receipt_reused'])
        self.assertFalse(self.receipt['network_owner_mpc_proof_or_broadcast'])
        self.assertEqual(self.receipt['trial_authority_sha256'],
                         admitted.trial_authority)
        self.assertEqual(self.receipt['unconfigured_build_authority_sha256'],
                         admitted.build_authority)

    def test_selected_verifier_is_hermetic_and_live_runtime_independent(self):
        hostile = Path(self.temporary.name) / 'hostile-runtime'
        hostile.mkdir()
        (hostile / 'libSPDZ.so').write_bytes(b'not an ELF object')
        inherited = {
            'LD_LIBRARY_PATH': str(hostile),
            'LD_PRELOAD': str(hostile / 'libSPDZ.so'),
            'PYTHONHOME': str(hostile),
            'PYTHONPATH': str(hostile),
        }
        previous = {name: os.environ.get(name) for name in inherited}
        os.environ.update(inherited)
        try:
            result = candidate.exercise_selected_verifier_control(
                self.snapshot, self.authority, self.authority_sha256)
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        self.assertEqual(result['status'], 'CONTROL_ONLY_UNCONFIGURED')
        self.assertFalse(result['authority_admitted'])
        self.assertTrue(result['selected_verifier_executed'])
        self.assertTrue(result['network_namespace_isolated'])
        self.assertTrue(result['pid_namespace_isolated'])
        self.assertTrue(result['ipc_namespace_isolated'])
        self.assertTrue(result['uts_namespace_isolated'])
        self.assertTrue(result['mount_namespace_isolated'])
        self.assertTrue(result['host_proc_hidden'])
        self.assertTrue(result['private_sentinel_hidden'])
        self.assertTrue(result['host_unix_socket_unreachable'])
        self.assertTrue(result['live_vendor_runtime_hidden'])
        self.assertTrue(result['fresh_pid_namespace_kernel_evidence'])
        self.assertTrue(result['loopback_only_network'])
        self.assertTrue(result['fixed_uts_hostname'])
        self.assertTrue(result['minimal_mount_root'])
        self.assertTrue(result['sealed_runtime_executed'])
        self.assertTrue(result['snapshot_only_runtime_objects'])
        self.assertEqual(result['inherited_environment_keys'], [])
        self.assertFalse(result['registered_driver_configured'])
        self.assertFalse(result['launch_authorized'])

    def test_selected_verifier_interpreter_and_runtime_drift_refuse(self):
        for relative, mode in (
                ('runtime/verifier/registered_selection_candidate.py', 0o400),
                ('runtime/bin/python3.14', 0o500),
                ('runtime/loader', 0o500),
                ('runtime/lib/libSPDZ.so', 0o400),
                ('runtime/python/lib/python314.zip', 0o400)):
            path = self.snapshot / relative
            original = path.read_bytes()
            try:
                self.replace(path, original + b'\n', mode)
                with self.assertRaises(ValueError):
                    candidate.exercise_selected_verifier_control(
                        self.snapshot, self.authority,
                        self.authority_sha256)
            finally:
                self.replace(path, original, mode)

    def test_external_control_pin_and_post_seal_replacement_refuse(self):
        original_authority = self.authority.read_bytes()
        try:
            self.replace(self.authority, original_authority + b'\n')
            with self.assertRaises(ValueError):
                candidate.exercise_selected_verifier_control(
                    self.snapshot, self.authority,
                    self.authority_sha256)
        finally:
            self.replace(self.authority, original_authority)

        verifier = self.snapshot / \
            'runtime/verifier/registered_selection_candidate.py'
        original_verifier = verifier.read_bytes()

        def replace_after_seal():
            self.replace(verifier, original_verifier + b'\n')

        try:
            with self.assertRaises(ValueError):
                candidate.exercise_selected_verifier_control(
                    self.snapshot, self.authority,
                    self.authority_sha256,
                    after_seal_hook=replace_after_seal)
        finally:
            self.replace(verifier, original_verifier)

    def test_direct_selected_child_mode_cannot_forge_admission(self):
        result = subprocess.run([
            sys.executable, str(FINANCIAL /
                'registered_selection_candidate.py'),
            '--verify-only', '--output', str(self.snapshot),
            '--selected-runtime-child', '--parent-netns',
            'attacker-controlled'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, env={})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'ADMITTED_UNCONFIGURED', result.stdout)

        forged = Path(self.temporary.name) / 'forged-child-capability.json'
        forged.write_bytes(candidate.encoded({
            'schema': 'kpb-selected-verifier-capability/v1',
            'nonce_hex': '11' * 32,
            'authority': json.loads(self.authority.read_bytes()),
            'parent_namespaces': {
                name: 'attacker-selected'
                for name in ('net', 'pid', 'ipc', 'uts', 'mnt')
            },
            'host_pid1_sha256': '22' * 32,
            'private_sentinel_path': '/attacker/missing-sentinel',
            'unix_socket_path': '/attacker/missing.sock',
        }))
        program = (
            "import sys; from pathlib import Path; "
            f"sys.path.insert(0, {str(FINANCIAL)!r}); "
            "import registered_selection_candidate as c; "
            f"c._selected_child_entry(Path('/selection'), {str(forged)!r})")
        imported = subprocess.run(
            [sys.executable, '-c', program], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, env={})
        self.assertNotEqual(imported.returncode, 0)
        self.assertNotIn(b'INTERNAL_CONTROL_EVIDENCE', imported.stdout)

    def test_production_authority_refuses_forged_caller_capability(self):
        descriptor = candidate._sealed_memfd(
            'forged-supervisor-capability', b'caller-controlled\n')
        try:
            with self.assertRaises(ValueError):
                candidate.run_selected_verifier(self.snapshot, descriptor)
        finally:
            os.close(descriptor)
        self.assertFalse(candidate.OUTER_SUPERVISOR_AUTHORITY_CONFIGURED)
        self.assertEqual(
            candidate.OUTER_SUPERVISOR_AUTHORITY_SHA256, '00' * 32)

    def test_wrong_trial_and_registration_refuse_even_if_manifest_is_rewritten(self):
        for relative, mutate in (
                ('trial/SELECTION-CANDIDATE.json',
                 lambda value: value.__setitem__(
                     'trial_id', '11111111-2222-4333-8444-555555555555')),
                ('trial/registration/REGISTRATION.json',
                 lambda value: value['registration'].__setitem__(
                     'registration_nonce_hex32', '11' * 32))):
            selected_path = self.snapshot / relative
            selected_original = selected_path.read_bytes()
            selected_changed = json.loads(selected_original)
            mutate(selected_changed)
            try:
                self.replace(selected_path, candidate.encoded(selected_changed))
                with self.assertRaises(ValueError):
                    candidate.admit_snapshot(self.snapshot)
            finally:
                self.replace(selected_path, selected_original)

        manifest_path = self.snapshot / 'CONFIGURATION-CANDIDATE.json'
        original = manifest_path.read_bytes()
        changed = json.loads(original)
        changed['authority']['trial_id'] = (
            '11111111-2222-4333-8444-555555555555')
        changed['authority']['registration_sha256'] = '11' * 32
        try:
            self.replace(manifest_path, candidate.encoded(changed))
            with self.assertRaises(ValueError):
                candidate.admit_snapshot(self.snapshot)
        finally:
            self.replace(manifest_path, original)

    def test_wrong_certificate_chain_refuses(self):
        certificate = self.snapshot / 'trial/certificates/P0.pem'
        original = certificate.read_bytes()
        wrong = self.snapshot / 'trial/certificates/P1.pem'
        try:
            self.replace(certificate, wrong.read_bytes())
            with self.assertRaises(ValueError):
                candidate.admit_snapshot(self.snapshot)
        finally:
            self.replace(certificate, original)

    def test_mutable_and_hardlinked_inputs_refuse(self):
        directory = self.snapshot / 'accepted-head'
        directory.chmod(0o700)
        try:
            with self.assertRaises(ValueError):
                candidate.admit_snapshot(self.snapshot)
        finally:
            directory.chmod(0o500)
        source = self.snapshot / 'accepted-head/accepted_head.cpp'
        source.chmod(0o600)
        try:
            with self.assertRaises(ValueError):
                candidate.admit_snapshot(self.snapshot)
        finally:
            source.chmod(0o400)
        alias = source.with_name('accepted_head.alias.cpp')
        source.parent.chmod(0o700)
        os.link(source, alias)
        source.parent.chmod(0o500)
        try:
            with self.assertRaises(ValueError):
                candidate.admit_snapshot(self.snapshot)
        finally:
            source.parent.chmod(0o700)
            alias.unlink()
            source.parent.chmod(0o500)

    def test_accepted_head_source_and_qualifier_build_drift_refuse(self):
        for relative in (
                'accepted-head/accepted_head.cpp',
                'trial/STATE-INITIALIZATION.txt',
                'qualifier/BUILD-RESULT.json',
                'qualifier/AUTHORITY-BUILD-RESULT.json',
                'qualifier/source/financial/registered_service.cpp',
                'qualifier/source/financial/registered_service_selection.hpp',
                'qualifier/dependencies/vendor/MP-SPDZ/BMR/AndJob.h',
                'qualifier/mpc-registered-financial-gate'):
            path = self.snapshot / relative
            original = path.read_bytes()
            try:
                self.replace(path, original + b'\n',
                             0o500 if relative.endswith('gate') else 0o400)
                with self.assertRaises(ValueError):
                    candidate.admit_snapshot(self.snapshot)
            finally:
                self.replace(path, original,
                             0o500 if relative.endswith('gate') else 0o400)

    def test_round1_round2_are_fresh_and_replay_refuses(self):
        admitted = candidate.admit_snapshot(self.snapshot)
        first = admitted.bind_fresh_head('ROUND1', '21' * 32)
        self.assertEqual(first, '21' * 32)
        with self.assertRaises(ValueError):
            admitted.bind_fresh_head('ROUND1', '21' * 32)
        with self.assertRaises(ValueError):
            admitted.bind_fresh_head('ROUND2', '21' * 32)
        self.assertEqual(
            admitted.bind_fresh_head('ROUND2', '22' * 32), '22' * 32)
        with self.assertRaises(ValueError):
            admitted.bind_fresh_head('ROUND3', '23' * 32)
        reopened = candidate.admit_snapshot(self.snapshot)
        self.assertFalse(reopened.durable_freshness_admitted)
        self.assertFalse(reopened.launch_authorized)

    def test_self_authored_or_other_trial_selection_refuses(self):
        manifest_path = self.snapshot / 'CONFIGURATION-CANDIDATE.json'
        original = manifest_path.read_bytes()
        changed = json.loads(original)
        changed['authority']['selection_sha256'] = '33' * 32
        changed['authority']['self_authorizing_manifest'] = True
        try:
            self.replace(manifest_path, candidate.encoded(changed))
            with self.assertRaises(ValueError):
                candidate.admit_snapshot(self.snapshot)
        finally:
            self.replace(manifest_path, original)

    def test_source05_retag_and_fixed_head_policy_refuse(self):
        manifest_path = self.snapshot / 'CONFIGURATION-CANDIDATE.json'
        original = manifest_path.read_bytes()
        changed = json.loads(original)
        changed['head_policy']['source05_retag_allowed'] = True
        changed['head_policy']['selection'] = 'FIXED_SOURCE05_HEAD'
        try:
            self.replace(manifest_path, candidate.encoded(changed))
            with self.assertRaises(ValueError):
                candidate.admit_snapshot(self.snapshot)
        finally:
            self.replace(manifest_path, original)

    def test_build_authority_forbids_object_reuse(self):
        output = Path(self.temporary.name) / 'forbidden-reuse-build'
        script = self.snapshot / \
            'qualifier/source/financial/build_registered_financial.py'
        result = subprocess.run([
            sys.executable, str(script), '--vendor-root',
            str(candidate.REPOSITORY_ROOT /
                '.local/mpc-prover-softspoken-vendor'),
            '--output', str(output), '--base-build',
            str(candidate.REPOSITORY_ROOT /
                '.local/registered-financial-gate-build-07')],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, env={})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Object reuse is forbidden', result.stderr)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
