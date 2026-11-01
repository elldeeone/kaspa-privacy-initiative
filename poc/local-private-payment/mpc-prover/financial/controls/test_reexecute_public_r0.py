#!/usr/bin/env python3
"""Controls for direct, selected-host public R0 re-execution."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

FINANCIAL = Path(__file__).resolve().parents[1]
LOCAL = FINANCIAL.parent.parent

qspec = importlib.util.spec_from_file_location(
    'qualify_public_release', FINANCIAL / 'qualify_public_release.py')
q = importlib.util.module_from_spec(qspec); qspec.loader.exec_module(q)
tspec = importlib.util.spec_from_file_location(
    'qualifier_controls', Path(__file__).with_name(
        'test_qualify_public_release.py'))
fixtures = importlib.util.module_from_spec(tspec); tspec.loader.exec_module(fixtures)
rspec = importlib.util.spec_from_file_location(
    'reexecute_public_r0', FINANCIAL / 'reexecute_public_r0.py')
r0 = importlib.util.module_from_spec(rspec); rspec.loader.exec_module(r0)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) +
            '\n').encode()


def put(path, raw, mode=0o400):
    path.write_bytes(raw if type(raw) is bytes else canonical(raw))
    path.chmod(mode)
    return {'path': str(path),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


class Fixture:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.profile_path = LOCAL / 'private-batch-public/component-profile.json'
        self.outer_path = LOCAL / 'private-batch-public/outer-selection.json'
        self.program_path = (LOCAL.parents[1] / '.local' /
            'private-batch-public-guest-real-roles-01/wrap/result/guest.program.bin')
        self.program = self.program_path.read_bytes()
        self.profile = json.loads(self.profile_path.read_text())
        self.tail = (LOCAL.parents[1] / '.local/mpc-prover-financial-runs/'
            'a86414d108d6886768f367a3384fd24de49d4fde7475d8469d92adee29c0e6ab/'
            'public/native-tail.bin').read_bytes()
        self.core = fixtures.make_core(self.profile)
        self.proof = bytes(range(q.PROOF_BYTES))
        old_spk = q.reserve_spk(q.FIXED_OLD_STATE, self.tail)
        self.projection = fixtures.make_projection(
            self.core, self.proof, self.tail)
        self.financial = fixtures.make_result(
            self.core, self.proof, self.projection)
        self.release = self.root / 'release'; self.release.mkdir()
        fixtures.dump(self.release / 'RESULT.json', self.financial)
        (self.release / 'released-core.bin').write_bytes(self.core)
        (self.release / 'released-proof.bin').write_bytes(self.proof)
        (self.release / 'released-projection.bin').write_bytes(
            self.projection)
        (self.release / 'native-tail.bin').write_bytes(self.tail)
        self.host = (LOCAL.parents[1] /
            '.local/private-batch-new-host-build-01/kpi-private-batch-public-host')
        with mock.patch.object(q, 'run_host', self.cross_check):
            q.qualify(self.release, self.profile_path, self.outer_path,
                      self.host, self.root / 'qualified')
        self.artifacts = self.root / 'qualified/ARTIFACTS.json'
        self.handoff = self.root / 'qualified/RESULT.json'
        artifacts = json.loads(self.artifacts.read_text())
        sealed = self.root / 'sealed-artifacts'; sealed.mkdir()
        for name, row in artifacts['artifacts'].items():
            raw = Path(row['path']).read_bytes()
            target = sealed / name; target.write_bytes(raw)
            target.chmod(0o500 if name in ('public_host', 'namespace_tool')
                         else 0o400)
            row['path'] = str(target)
        self.artifacts.chmod(0o600)
        self.artifacts.write_bytes(canonical(artifacts))
        self.artifacts.chmod(0o400)
        self.handoff.chmod(0o400)
        local = LOCAL.parents[1] / '.local'
        selected_outer_path = (local / 'private-batch-new-host-build-01/source/'
            'poc/local-private-payment/private-batch-public/outer-selection.json')
        self.selected_outer = put(self.root / 'selected-outer.json',
                                  selected_outer_path.read_bytes())
        self.program_ref = put(self.root / 'program.bin', self.program)
        def copied(name, source):
            return put(self.root / name, Path(source).read_bytes())
        self.host_admission = copied('host-admission.json',
            local / 'private-batch-new-host-build-01/HOST-ADMISSION.json')
        self.host_sources = copied('host-sources.json',
            local / 'private-batch-new-host-build-01/SOURCE.json')
        self.host_build = copied('host-build.json',
            local / 'private-batch-new-host-build-01/BUILD.json')
        guest = local / 'private-batch-public-guest-real-roles-01'
        self.guest_sources = copied('guest-sources.json',
                                    guest / 'SOURCE-BEFORE.json')
        self.guest_sources_after = copied('guest-sources-after.json',
                                          guest / 'SOURCE-AFTER.json')
        self.guest_plan = copied('guest-plan.json', guest / 'BUILD-PLAN.json')
        self.guest_build = copied('guest-build.json', guest / 'BUILD-RESULT.json')
        self.guest_elf = copied('guest-elf.json', guest / 'ELF-ADMISSION.json')
        self.guest_wrap = copied('guest-wrap.json',
                                 guest / 'wrap/WRAP-ADMISSION.json')
        self.native_parameters = copied('native-parameters.json',
            local / 'private-batch-public-native-final-parameters-01/PARAMETERS.json')
        self.runtime_root = self.root / 'sealed-runtime'
        r0.seal_runtime_closure(self.runtime_root)
        self.selection = {
            'schema': 'kpb-direct-public-r0-reexecution-selection/v1',
            'scope': q.SCOPE,
            'reexecutor_source_sha256': r0.source_sha256(),
            'financial_artifacts': put(
                self.root / 'artifacts-copy.json', self.artifacts.read_bytes()),
            'financial_result': put(
                self.root / 'result-copy.json', self.handoff.read_bytes()),
            'selected_outer_selection': self.selected_outer,
            'program': self.program_ref,
            'host_admission': self.host_admission,
            'host_source_manifest': self.host_sources,
            'host_build_result': self.host_build,
            'guest_source_before': self.guest_sources,
            'guest_source_after': self.guest_sources_after,
            'guest_source_root': str(LOCAL.parents[1]),
            'guest_build_plan': self.guest_plan,
            'guest_build_result': self.guest_build,
            'guest_elf_admission': self.guest_elf,
            'guest_wrap_admission': self.guest_wrap,
            'native_parameters': self.native_parameters,
            'runtime_root': str(self.runtime_root),
            'receipt': None,
        }
        self.selection_path = self.root / 'selection.json'
        self.write_selection()

    def cross_check(self, host, projection, profile, namespace):
        digest = q.sha(projection)
        journal = (b'KPBAJR01' + bytes.fromhex(profile['domain_hex32']) +
                   bytes.fromhex(q.PROFILE_SHA256) + bytes.fromhex(digest))
        return ({'aggregate_and_six_Output_G16_verified': True,
                 'independent_arkworks_reference_checked': True,
                 'public_state_and_global_balance_verified': True,
                 'projection_sha256': digest,
                 'journal_hex104': journal.hex(),
                 'journal_sha256': q.sha(journal),
                 'R0_or_native_VM_executed': False,
                 'accepted_chain_authority': False}, journal)

    def write_selection(self):
        self.selection_path.write_bytes(canonical(self.selection))
        self.selection_path.chmod(0o400)
        self.selection_sha = hashlib.sha256(
            self.selection_path.read_bytes()).hexdigest()

    def rewrite_selection(self):
        self.selection_path.chmod(0o600); self.write_selection()

    def run(self, output='r0'):
        return r0.reexecute(self.selection_path, self.selection_sha,
                            self.root / output)

    def seal_guest_sources(self):
        guest = (LOCAL.parents[1] /
            '.local/private-batch-public-guest-real-roles-01')
        sealed = self.root / 'sealed-guest-source'
        result = r0.seal_guest_source(guest / 'SOURCE-BEFORE.json',
                                      guest / 'SOURCE-AFTER.json', sealed)
        self.selection['guest_source_root'] = str(sealed)
        self.rewrite_selection()
        return sealed, result


class DirectPublicR0Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Fixture(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_runtime_sealer_materializes_exact_reviewed_ipc_closure(self):
        output = self.fixture.root / 'sealed-runtime-second'
        result = r0.seal_runtime_closure(output)
        self.assertEqual(result['schema'], 'kpb-direct-r0-runtime-seal/v1')
        self.assertEqual(len(result['rows']), 11)
        self.assertEqual(hashlib.sha256((output / 'SEAL.json').read_bytes()
                         ).hexdigest(), r0.PINNED_RUNTIME_SEAL_SHA256)
        self.assertEqual(output.stat().st_mode & 0o777, 0o500)
        self.assertTrue(all((path.stat().st_mode & 0o777) ==
                            (0o500 if row['executable'] else 0o400)
                            for row in result['rows']
                            for path in (output / row['relative_path'],)))

    def test_direct_report_contract_is_exact_but_mints_no_authority_token(self):
        digest = hashlib.sha256(self.fixture.projection).hexdigest()
        journal = (b'KPBAJR01' + bytes.fromhex(
            self.fixture.profile['domain_hex32']) + bytes.fromhex(
            r0.PINNED_PROFILE_SHA256) + bytes.fromhex(digest))
        report = {
            'genuine_seven_G16_public_guest_execution_passed': True,
            'image_id_hex32': r0.PINNED_IMAGE_ID,
            'projection_sha256': digest,
            'journal_sha256': hashlib.sha256(journal).hexdigest(),
            'cycles': 123, 'seconds': 1.25,
            'operational_session_cycle_limit': None,
            'proof_generation': False, 'native_VM_executed': False,
        }
        self.assertTrue(r0.admit_execute_evidence(
            report, journal, self.fixture.projection,
            self.fixture.profile['domain_hex32'],
            r0.PINNED_PROFILE_SHA256, r0.PINNED_IMAGE_ID))
        for name, value in (('image_id_hex32', '99' * 32),
                            ('cycles', 0), ('proof_generation', True)):
            changed = copy.deepcopy(report); changed[name] = value
            with self.assertRaises(ValueError):
                r0.admit_execute_evidence(changed, journal,
                    self.fixture.projection,
                    self.fixture.profile['domain_hex32'],
                    r0.PINNED_PROFILE_SHA256, r0.PINNED_IMAGE_ID)

    def test_mutable_guest_source_closure_refuses_before_subprocess(self):
        with mock.patch.object(r0.subprocess, 'run') as execute:
            with self.assertRaises(ValueError): self.fixture.run()
            execute.assert_not_called()
        self.assertFalse((self.fixture.root / 'r0/RESULT.json').exists())

    def test_sealed_reviewed_source_reaches_host_and_nonzero_refuses(self):
        sealed, result = self.fixture.seal_guest_sources()
        self.assertEqual(result['leaf_count'], 32)
        self.assertEqual(sealed.stat().st_mode & 0o777, 0o500)
        self.assertTrue(all((path.stat().st_mode & 0o777) == 0o400
                            for path in sealed.rglob('*') if path.is_file()))
        refused = mock.Mock(returncode=9, stdout=b'', stderr=b'host-refused')
        with mock.patch.object(r0.subprocess, 'run', return_value=refused) \
                as execute:
            with self.assertRaisesRegex(ValueError, 'host-execute-nonzero'):
                self.fixture.run('nonzero')
            execute.assert_called_once()
            command = execute.call_args.args[0]
            self.assertTrue(command[0].endswith(
                '/runtime/ld-linux-x86-64.so.2'))
            self.assertEqual(command[1], '--library-path')
            self.assertIn('/worker/r0vm', ' '.join(command))
            self.assertIn('/worker', command)
            self.assertIn('RISC0_SERVER_PATH', command)
        self.assertFalse((self.fixture.root / 'nonzero/RESULT.json').exists())

    def test_changed_projection_head_tail_or_image_refuses(self):
        mutations = ('projection', 'head', 'tail', 'image')
        for mutation in mutations:
            with self.subTest(mutation=mutation), \
                 tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                artifacts = json.loads(Path(
                    fixture.selection['financial_artifacts']['path']).read_text())
                if mutation == 'projection':
                    path = Path(artifacts['artifacts'][
                        'retained_projection']['path'])
                    path.chmod(0o600); path.write_bytes(
                        path.read_bytes()[:-1] + b'X')
                elif mutation == 'head':
                    artifacts['head']['state_hex112'] = '00' * 112
                    path = Path(fixture.selection[
                        'financial_artifacts']['path'])
                    path.chmod(0o600); path.write_bytes(canonical(artifacts))
                    fixture.selection['financial_artifacts']['sha256'] = \
                        hashlib.sha256(path.read_bytes()).hexdigest()
                    fixture.rewrite_selection()
                elif mutation == 'tail':
                    path = Path(artifacts['artifacts']['native_tail']['path'])
                    path.chmod(0o600); path.write_bytes(b'changed-tail')
                else:
                    outer = json.loads(Path(fixture.selected_outer['path']).read_text())
                    outer['image_id_hex32'] = '99' * 32
                    path = Path(fixture.selected_outer['path'])
                    path.chmod(0o600); path.write_bytes(canonical(outer))
                    fixture.selection['selected_outer_selection']['sha256'] = \
                        hashlib.sha256(path.read_bytes()).hexdigest()
                    fixture.rewrite_selection()
                with self.assertRaises(ValueError): fixture.run()

    def test_rehashed_handoff_metadata_cannot_redirect_r0_authority(self):
        mutations = ('outer-image', 'old-state-hash', 'effects')
        for mutation in mutations:
            with self.subTest(mutation=mutation), \
                 tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory); fixture.seal_guest_sources()
                result_path = Path(fixture.selection['financial_result']['path'])
                result = json.loads(result_path.read_text())
                if mutation == 'outer-image':
                    result['outer_image_id_hex32'] = '99' * 32
                elif mutation == 'old-state-hash':
                    result['fixed_old_state_sha256'] = '99' * 32
                else:
                    result['effects_sha256'] = '99' * 32
                    artifacts_path = Path(
                        fixture.selection['financial_artifacts']['path'])
                    artifacts = json.loads(artifacts_path.read_text())
                    artifacts['effects_sha256'] = '99' * 32
                    artifacts_path.chmod(0o600)
                    artifacts_path.write_bytes(canonical(artifacts))
                    artifacts_path.chmod(0o400)
                    fixture.selection['financial_artifacts']['sha256'] = \
                        hashlib.sha256(artifacts_path.read_bytes()).hexdigest()
                result_path.chmod(0o600)
                result_path.write_bytes(canonical(result)); result_path.chmod(0o400)
                fixture.selection['financial_result']['sha256'] = \
                    hashlib.sha256(result_path.read_bytes()).hexdigest()
                fixture.rewrite_selection()
                with mock.patch.object(r0.subprocess, 'run') as execute:
                    with self.assertRaisesRegex(
                            ValueError, 'qualified-handoff-cross-document-join'):
                        fixture.run('redirected-handoff')
                    execute.assert_not_called()

    def test_rehashed_host_cross_check_cannot_be_imported(self):
        self.fixture.seal_guest_sources()
        artifacts_path = Path(
            self.fixture.selection['financial_artifacts']['path'])
        artifacts = json.loads(artifacts_path.read_text())
        row = artifacts['artifacts']['host_cross_check']
        report_path = Path(row['path'])
        report = json.loads(report_path.read_text())
        report['projection_sha256'] = '99' * 32
        report_path.chmod(0o600); report_path.write_bytes(canonical(report))
        report_path.chmod(0o400)
        row['sha256'] = hashlib.sha256(report_path.read_bytes()).hexdigest()
        row['bytes'] = len(report_path.read_bytes())
        artifacts_path.chmod(0o600)
        artifacts_path.write_bytes(canonical(artifacts)); artifacts_path.chmod(0o400)
        self.fixture.selection['financial_artifacts']['sha256'] = \
            hashlib.sha256(artifacts_path.read_bytes()).hexdigest()
        self.fixture.rewrite_selection()
        with mock.patch.object(r0.subprocess, 'run') as execute:
            with self.assertRaisesRegex(ValueError,
                                        'exact-qualified-host-cross-check'):
                self.fixture.run('forged-cross-check')
            execute.assert_not_called()

    def test_host_drift_hardlink_and_injected_runner_refuse(self):
        artifacts = json.loads(Path(self.fixture.selection[
            'financial_artifacts']['path']).read_text())
        host = Path(artifacts['artifacts']['public_host']['path'])
        host.chmod(0o700); host.write_bytes(b'host-v2')
        with self.assertRaises(ValueError): self.fixture.run('host-drift')
        fixture = Fixture(self.fixture.root / 'fresh')
        alias = fixture.root / 'program-alias'
        os.link(fixture.program_ref['path'], alias)
        with self.assertRaises(ValueError): fixture.run('hardlink')
        alias.unlink()
        with self.assertRaises(TypeError):
            r0.reexecute(fixture.selection_path, fixture.selection_sha,
                         fixture.root / 'injected', lambda *a: None)

    def test_prewritten_output_cannot_become_completion(self):
        self.fixture.seal_guest_sources()
        output = self.fixture.root / 'occupied'; output.mkdir()
        (output / 'RESULT.json').write_text('{"forged":true}\n')
        with mock.patch.object(r0.subprocess, 'run') as execute:
            with self.assertRaisesRegex(ValueError, 'fresh-absolute-output'):
                self.fixture.run('occupied')
            execute.assert_not_called()

    def test_rehashed_wrong_old_head_refuses_before_subprocess(self):
        self.fixture.seal_guest_sources()
        path = Path(self.fixture.selection['financial_artifacts']['path'])
        artifacts = json.loads(path.read_text())
        artifacts['head']['state_hex112'] = '11' * 112
        path.chmod(0o600); path.write_bytes(canonical(artifacts)); path.chmod(0o400)
        self.fixture.selection['financial_artifacts']['sha256'] = \
            hashlib.sha256(path.read_bytes()).hexdigest()
        self.fixture.rewrite_selection()
        with mock.patch.object(r0.subprocess, 'run') as execute:
            with self.assertRaisesRegex(ValueError, 'fixed-old-head'):
                self.fixture.run('wrong-head')
            execute.assert_not_called()

    def test_writable_sealed_source_root_refuses_before_subprocess(self):
        sealed, _ = self.fixture.seal_guest_sources()
        sealed.chmod(0o700)
        with mock.patch.object(r0.subprocess, 'run') as execute:
            with self.assertRaisesRegex(ValueError,
                                        'owned-private-guest-source-root'):
                self.fixture.run('writable-seal')
            execute.assert_not_called()

    def test_writable_or_extra_sealed_source_directory_refuses(self):
        for mutation in ('writable', 'extra'):
            with self.subTest(mutation=mutation), \
                 tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                sealed, _ = fixture.seal_guest_sources()
                if mutation == 'writable':
                    next(path for path in sealed.rglob('*')
                         if path.is_dir()).chmod(0o700)
                else:
                    sealed.chmod(0o700)
                    (sealed / 'unselected-empty-directory').mkdir()
                    (sealed / 'unselected-empty-directory').chmod(0o500)
                    sealed.chmod(0o500)
                with mock.patch.object(r0.subprocess, 'run') as execute:
                    with self.assertRaisesRegex(
                            ValueError, '(sealed-guest-source-director|'
                                        'exact-sealed-guest-source-inventory)'):
                        fixture.run('directory-mutation')
                    execute.assert_not_called()

    def test_alternate_self_hashed_guest_refuses_before_subprocess(self):
        outer = json.loads(Path(self.fixture.selected_outer['path']).read_text())
        outer['image_id_hex32'] = '77' * 32
        alternate = Path(self.fixture.selected_outer['path'])
        alternate.chmod(0o600); alternate.write_bytes(canonical(outer))
        self.fixture.selection['selected_outer_selection']['sha256'] = \
            hashlib.sha256(alternate.read_bytes()).hexdigest()
        self.fixture.rewrite_selection()
        with mock.patch.object(r0.subprocess, 'run') as execute:
            with self.assertRaises(ValueError): self.fixture.run('alternate')
            execute.assert_not_called()

    def test_alternate_self_hashed_loader_refuses_before_subprocess(self):
        loader = self.fixture.runtime_root / 'runtime/ld-linux-x86-64.so.2'
        loader.chmod(0o600)
        loader.write_bytes(b'malicious-loader'); loader.chmod(0o400)
        with mock.patch.object(r0.subprocess, 'run') as execute:
            with self.assertRaises(ValueError): self.fixture.run('loader')
            execute.assert_not_called()

    def test_owner_writable_selected_runtime_refuses_before_subprocess(self):
        self.fixture.seal_guest_sources()
        runtime = self.fixture.runtime_root / 'runtime/libgcc_s.so.1'
        runtime.chmod(0o600)
        with mock.patch.object(r0.subprocess, 'run') as execute:
            with self.assertRaisesRegex(
                    ValueError, 'owned-single-link-readonly-bounded-leaf'):
                self.fixture.run('writable-runtime')
            execute.assert_not_called()

    def test_self_consistent_result_booleans_are_ignored(self):
        result = json.loads(Path(self.fixture.selection[
            'financial_result']['path']).read_text())
        for name in ('R0_or_native_VM_executed', 'R0_receipt_verified',
                     'full_native_candidate_validated'):
            result[name] = True
        path = Path(self.fixture.selection['financial_result']['path'])
        path.chmod(0o600); path.write_bytes(canonical(result))
        self.fixture.selection['financial_result']['sha256'] = \
            hashlib.sha256(path.read_bytes()).hexdigest()
        self.fixture.rewrite_selection()
        with self.assertRaises(ValueError): self.fixture.run()


if __name__ == '__main__':
    unittest.main()
