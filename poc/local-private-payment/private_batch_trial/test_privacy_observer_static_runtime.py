#!/usr/bin/env python3
"""Finite static-observer build and runtime closure controls."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_privacy_fd40_archive import ArchiveFixture


HERE = Path(__file__).resolve().parent
BUILD = HERE / 'privacy_observer_runtime_build'
BUILDER = BUILD / 'build_static_observer_runtime.py'
PYTHON = Path('/usr/bin/python3.14')
READELF = Path('/usr/bin/x86_64-linux-gnu-readelf')
STRACE = Path('/usr/bin/strace')
FORBIDDEN_SYSCALLS = (
    'open,openat,openat2,creat,socket,socketpair,connect,accept,accept4')


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output, *, environment=None):
    completed = subprocess.run(
        [str(PYTHON), str(BUILDER), '--output', str(output)],
        cwd=HERE, capture_output=True, text=True, check=False,
        env=environment)
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    return json.loads(completed.stdout)


def sealed_archive(value, *, readonly=True, sealed=True):
    writable = os.memfd_create(
        'kpb-static-observer-control', os.MFD_ALLOW_SEALING)
    os.write(writable, value)
    os.lseek(writable, 0, os.SEEK_SET)
    descriptor = (os.open('/proc/self/fd/' + str(writable), os.O_RDONLY)
                  if readonly else os.dup(writable))
    if sealed:
        fcntl.fcntl(writable, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    os.close(writable)
    return descriptor


def empty_output(*, readonly=False, size=0, sealed=False):
    parent = os.memfd_create(
        'kpb-static-observer-output-control', os.MFD_ALLOW_SEALING)
    if size:
        os.ftruncate(parent, size)
    descriptor = os.open(
        '/proc/self/fd/' + str(parent),
        os.O_RDONLY if readonly else os.O_WRONLY)
    if sealed:
        fcntl.fcntl(parent, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    return descriptor, parent


class FixedArchiveDescriptors:
    def __init__(self, capsule, source, assets, *, capsule_kwargs=None,
                 output_kwargs=None, **archive_kwargs):
        capsule_kwargs = {} if capsule_kwargs is None else capsule_kwargs
        output_kwargs = {} if output_kwargs is None else output_kwargs
        output, self.output_inspection = empty_output(**output_kwargs)
        self.values = (
            sealed_archive(capsule, **capsule_kwargs),
            sealed_archive(source, **archive_kwargs),
            sealed_archive(assets, **archive_kwargs),
            output,
        )
        self.saved = []
        self.output_size = None

    def __enter__(self):
        for target, descriptor in zip((40, 60, 61, 62), self.values):
            try:
                saved = os.dup(target)
            except OSError:
                saved = -1
            self.saved.append(saved)
            os.dup2(descriptor, target, inheritable=True)
            os.close(descriptor)
        return (40, 60, 61, 62)

    def __exit__(self, *_):
        self.output_size = os.fstat(self.output_inspection).st_size
        os.close(self.output_inspection)
        for target, saved in zip((40, 60, 61, 62), self.saved):
            if saved < 0:
                os.close(target)
            else:
                os.dup2(saved, target)
                os.close(saved)


class StaticObserverRuntimeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-static-observer-control-')
        cls.root = Path(cls.temporary.name)
        cls.first = cls.root / 'first'
        cls.second = cls.root / 'second'
        cls.capsule = ArchiveFixture(
            valid_public_state=True, repeat_ciphertext=True).value
        cls.first_receipt = build(cls.first)
        cls.second_receipt = build(cls.second)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def launch(self, source, assets, *, readonly=True, sealed=True,
               capsule_kwargs=None, output_kwargs=None, strace_log=None):
        executable = self.first / 'kpb-static-observer'
        command = [str(executable)]
        if strace_log is not None:
            command = [str(STRACE), '-f', '-qq', '-e',
                       'trace=' + FORBIDDEN_SYSCALLS,
                       '-e', 'inject=open:error=EPERM',
                       '-e', 'inject=openat:error=EPERM',
                       '-e', 'inject=openat2:error=EPERM',
                       '-e', 'inject=creat:error=EPERM',
                       '-e', 'inject=socket:error=EPERM',
                       '-e', 'inject=socketpair:error=EPERM',
                       '-e', 'inject=connect:error=EPERM',
                       '-e', 'inject=accept:error=EPERM',
                       '-e', 'inject=accept4:error=EPERM',
                       '-o', str(strace_log), *command]
        descriptors = FixedArchiveDescriptors(
                self.capsule, source, assets,
                readonly=readonly, sealed=sealed,
                capsule_kwargs=capsule_kwargs,
                output_kwargs=output_kwargs)
        with descriptors as passed:
            completed = subprocess.run(
                command, pass_fds=passed, close_fds=True, env={},
                capture_output=True, check=False)
        completed.kpb_output_size = descriptors.output_size
        return completed

    def test_two_independent_builds_are_byte_identical_and_static(self):
        self.assertEqual(self.first_receipt, self.second_receipt)
        for name in ('kpb-static-observer', 'observer-source.kpb',
                     'observer-assets.kpb'):
            self.assertEqual(sha256(self.first / name),
                             sha256(self.second / name))
        self.assertFalse(any(
            path.read_bytes()[:4] == b'\x7fELF'
            for path in BUILD.iterdir() if path.is_file()))
        readelf = subprocess.run(
            [str(READELF), '-l', '-d',
             str(self.first / 'kpb-static-observer')],
            capture_output=True, text=True, check=True)
        self.assertNotIn(' INTERP ', readelf.stdout)
        self.assertNotIn('(NEEDED)', readelf.stdout)
        self.assertFalse(self.first_receipt['configured'])
        self.assertFalse(
            self.first_receipt['selected_fd40_authority_consumer'])
        self.assertFalse(
            self.first_receipt['selected_fd62_output_authority'])
        self.assertTrue(self.first_receipt['runtime_loader_absent'])
        self.assertEqual(self.first_receipt['dynamic_runtime_dependencies'], [])
        self.assertEqual(
            self.first_receipt['transitive_dependency_count'], 338)

    def test_exact_sealed_archives_run_without_path_or_network_syscalls(self):
        source = (self.first / 'observer-source.kpb').read_bytes()
        assets = (self.first / 'observer-assets.kpb').read_bytes()
        trace = self.root / 'static-runtime.strace'
        completed = self.launch(source, assets, strace_log=trace)
        self.assertEqual(completed.returncode, 78,
                         completed.stderr.decode(errors='replace'))
        self.assertEqual(completed.stdout, b'')
        self.assertEqual(
            completed.stderr, b'KPB_OBSERVER_STATIC_STEP2_OPEN\n')
        self.assertEqual(completed.kpb_output_size, 0)
        calls = [line for line in trace.read_text().splitlines() if line]
        self.assertTrue(calls)
        self.assertTrue(all(
            'EPERM (Operation not permitted) (INJECTED)' in line
            for line in calls), '\n'.join(calls))

    def test_archive_substitution_writable_or_unsealed_descriptor_refuses(self):
        source = bytearray((self.first / 'observer-source.kpb').read_bytes())
        assets = (self.first / 'observer-assets.kpb').read_bytes()
        source[-1] ^= 1
        self.assertEqual(self.launch(bytes(source), assets).returncode, 71)
        source[-1] ^= 1
        self.assertEqual(self.launch(
            bytes(source), assets, sealed=False).returncode, 71)
        self.assertEqual(self.launch(
            bytes(source), assets, readonly=False).returncode, 71)

    def test_capsule_and_output_descriptor_substitution_refuses(self):
        source = (self.first / 'observer-source.kpb').read_bytes()
        assets = (self.first / 'observer-assets.kpb').read_bytes()
        for name, capsule, output in (
                ('capsule-unsealed', {'sealed': False}, None),
                ('capsule-writable', {'readonly': False}, None),
                ('output-readonly', None, {'readonly': True}),
                ('output-pre-sized', None, {'size': 1}),
                ('output-sealed', None, {'sealed': True})):
            with self.subTest(name=name):
                self.assertEqual(self.launch(
                    source, assets, capsule_kwargs=capsule,
                    output_kwargs=output).returncode, 71)

    def test_tool_path_environment_substitution_cannot_change_output(self):
        fake = self.root / 'fake-tools'
        fake.mkdir()
        for name in ('gcc', 'cc1', 'cc1plus', 'as', 'ld', 'collect2'):
            path = fake / name
            path.write_text('#!/bin/sh\nexit 99\n', encoding='ascii')
            path.chmod(0o755)
        third = self.root / 'hostile-environment'
        receipt = build(third, environment={
            'PATH': str(fake),
            'COMPILER_PATH': str(fake),
            'GCC_EXEC_PREFIX': str(fake) + '/',
            'LIBRARY_PATH': str(fake),
            'LD_LIBRARY_PATH': str(fake),
        })
        self.assertEqual(receipt, self.first_receipt)
        self.assertEqual(sha256(third / 'kpb-static-observer'),
                         sha256(self.first / 'kpb-static-observer'))

    def test_hostile_model_internal_import_cannot_enter_frozen_closure(self):
        manifest = json.loads((BUILD / 'frozen_modules.json').read_text())
        attack = BUILD / 'hostile_model_internal_mutation.py'
        manifest['entrypoint'] = {
            'module': 'hostile_model_internal_mutation', 'function': 'run'}
        manifest['modules'].append({
            'name': 'hostile_model_internal_mutation',
            'path': str(attack), 'is_package': False,
            'source_sha256': hashlib.sha256(attack.read_bytes()).hexdigest(),
        })
        copied = self.root / 'hostile-manifest.json'
        copied.write_text(json.dumps(manifest), encoding='utf-8')
        completed = subprocess.run(
            [str(PYTHON), str(BUILDER), '--output',
             str(self.root / 'hostile-build'), '--manifest', str(copied)],
            capture_output=True, text=True, check=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn('module-manifest-digest', completed.stderr)

    def test_one_byte_missing_and_extra_dependency_lock_inputs_refuse(self):
        original = json.loads(
            (BUILD / 'transitive_dependency_lock.json').read_text())
        changes = {}
        changed = json.loads(json.dumps(original))
        changed['identity_sha256'] = '1' + changed['identity_sha256'][1:]
        changes['one-byte'] = changed
        changed = json.loads(json.dumps(original))
        changed['dependency_groups']['usr-include'].pop()
        changes['missing'] = changed
        changed = json.loads(json.dumps(original))
        changed['dependency_groups']['usr-include'].append('hostile-extra.h')
        changes['extra'] = changed
        for name, value in changes.items():
            with self.subTest(name=name):
                path = self.root / ('dependencies-' + name + '.json')
                path.write_text(json.dumps(value), encoding='utf-8')
                completed = subprocess.run(
                    [str(PYTHON), str(BUILDER), '--output',
                     str(self.root / ('dependency-build-' + name)),
                     '--dependency-lock', str(path)],
                    capture_output=True, text=True, check=False)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn('input-digest:', completed.stderr)

    def test_assumption_selection_cannot_be_enabled_or_populated(self):
        manifest = json.loads((BUILD / 'frozen_modules.json').read_text())
        selection = json.loads(
            (BUILD / 'privacy_assumption_selection.json').read_text())
        for name, changed in (
                ('configured', {**selection, 'configured': True}),
                ('nonempty', {**selection,
                              'selected_assumptions': ['caller-choice']})):
            with self.subTest(name=name):
                path = self.root / ('assumptions-' + name + '.json')
                raw = (json.dumps(changed, sort_keys=True,
                                  separators=(',', ':')) + '\n').encode()
                path.write_bytes(raw)
                modified = json.loads(json.dumps(manifest))
                row = next(row for row in modified['assets']
                           if row['path'] ==
                           'privacy-assumption-selection.json')
                row['source'] = str(path)
                row['sha256'] = hashlib.sha256(raw).hexdigest()
                manifest_path = self.root / ('manifest-' + name + '.json')
                manifest_path.write_text(json.dumps(modified), encoding='utf-8')
                completed = subprocess.run(
                    [str(PYTHON), str(BUILDER), '--output',
                     str(self.root / ('assumption-build-' + name)),
                     '--manifest', str(manifest_path)],
                    capture_output=True, text=True, check=False)
                self.assertNotEqual(completed.returncode, 0)
                self.assertTrue(
                    'module-manifest-digest' in completed.stderr or
                    'assumption-selection' in completed.stderr)

    def test_superseded_v2_output_abi_asset_cannot_enter_selected_build(self):
        self.assertFalse((BUILD / 'observer_output_abi_v2.json').exists())
        old = {
            'schema': 'kpb-measurement-private-output-abi/v2',
            'configured': False,
            'role': 'observer',
            'version': 2,
            'magic': 'KPBOABI2',
            'used_bytes': 151193,
            'exact_bytes': 151552,
            'identity': (
                'b88103ce5c9474163c73963688bb756e0db50ed15f05a475c1e63'
                'c412d1246ef'),
            'phase_magic': 'KPBPHV01',
            'phase_offset': 151049,
            'phase_bytes': 144,
        }
        raw = (json.dumps(old, sort_keys=True, separators=(',', ':')) +
               '\n').encode()
        old_path = self.root / 'observer_output_abi_v2.json'
        old_path.write_bytes(raw)
        manifest = json.loads((BUILD / 'frozen_modules.json').read_text())
        row = next(row for row in manifest['assets']
                   if row['path'] == 'observer-output-abi-v3.json')
        row.update({
            'path': 'observer-output-abi-v2.json',
            'source': str(old_path),
            'sha256': hashlib.sha256(raw).hexdigest(),
        })
        manifest_path = self.root / 'old-v2-manifest.json'
        manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
        completed = subprocess.run(
            [str(PYTHON), str(BUILDER), '--output',
             str(self.root / 'old-v2-build'), '--manifest',
             str(manifest_path)],
            capture_output=True, text=True, check=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn('module-manifest-digest', completed.stderr)


if __name__ == '__main__':
    unittest.main()
