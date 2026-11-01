import hashlib
from pathlib import Path
import tempfile
import unittest

import privacy_source_closure as closure


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


class Fixture:
    def __init__(self, directory):
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        self.roots = {scope: root / scope
                      for scope in ('source', 'build', 'runtime')}
        for path in self.roots.values():
            path.mkdir()
        files = {
            ('source', 'src/main.py'): b'import helper\nimport subprocess\n',
            ('source', 'src/helper.py'): b'VALUE = 1\n',
            ('source', 'src/engine.cpp'): b'#include "engine.hpp"\n',
            ('source', 'src/engine.hpp'): b'#pragma once\n',
            ('source', 'src/worker.mjs'): b'import "./config.json";\n',
            ('source', 'src/config.json'): b'{"enabled":true}\n',
            ('source', 'src/disclosure.dat'): b'explicit-owner-effects\n',
            ('build', 'bin/launcher'): b'linked-launcher\n',
            ('build', 'receipts/build.json'): b'{"build":"selected"}\n',
            ('runtime', 'usr/bin/python'): b'pinned-python\n',
            ('runtime', 'usr/bin/bwrap'): b'pinned-bwrap\n',
            ('runtime', 'lib/ld.so'): b'pinned-loader\n',
            ('runtime', 'lib/libc.so'): b'pinned-libc\n',
            ('runtime', 'proc/kernel-id'): b'pinned-kernel\n',
        }
        kinds = {
            'src/main.py': 'python', 'src/helper.py': 'python',
            'src/engine.cpp': 'cpp', 'src/engine.hpp': 'cpp-header',
            'src/worker.mjs': 'javascript', 'src/config.json': 'json',
            'src/disclosure.dat': 'asset',
            'bin/launcher': 'launcher',
            'receipts/build.json': 'build-receipt',
            'usr/bin/python': 'interpreter',
            'usr/bin/bwrap': 'namespace-tool',
            'lib/ld.so': 'dynamic-loader',
            'lib/libc.so': 'shared-library',
            'proc/kernel-id': 'kernel-identity',
        }
        members = []
        for (scope, name), raw in files.items():
            path = self.roots[scope] / name
            write(path, raw)
            members.append({
                'id': scope + ':' + name, 'scope': scope, 'path': name,
                'kind': kinds[name], 'bytes': len(raw),
                'sha256': hashlib.sha256(raw).hexdigest(),
            })
        edges = [
            ('build:bin/launcher', 'build:receipts/build.json',
             'build-receipt'),
            ('build:bin/launcher', 'runtime:lib/ld.so', 'loader'),
            ('build:bin/launcher', 'runtime:lib/libc.so', 'shared-library'),
            ('build:bin/launcher', 'runtime:proc/kernel-id', 'kernel'),
            ('build:bin/launcher', 'runtime:usr/bin/python', 'interpreter'),
            ('build:bin/launcher', 'source:src/engine.cpp', 'compiled-from'),
            ('build:bin/launcher', 'source:src/main.py', 'compiled-from'),
            ('build:bin/launcher', 'source:src/worker.mjs', 'generated-from'),
            ('source:src/engine.cpp', 'source:src/engine.hpp', 'cpp-include'),
            ('source:src/main.py', 'runtime:usr/bin/bwrap',
             'subprocess-exec'),
            ('source:src/main.py', 'source:src/disclosure.dat', 'asset-read'),
            ('source:src/main.py', 'source:src/helper.py', 'python-import'),
            ('source:src/worker.mjs', 'source:src/config.json',
             'javascript-import'),
        ]
        self.value = {
            'schema': closure.ACTUAL_CLOSURE_SCHEMA,
            'source_search_roots': ['src'],
            'entrypoints': ['build:bin/launcher'],
            'members': sorted(members, key=lambda row: row['id']),
            'edges': [
                {'consumer': consumer, 'dependency': dependency, 'kind': kind}
                for consumer, dependency, kind in sorted(edges)],
        }
        self.seal()

    def seal(self):
        value = self.value
        sources = [row for row in value['members']
                   if row['scope'] == 'source']
        builds = [row for row in value['members']
                  if row['scope'] == 'build']
        runtimes = [row for row in value['members']
                    if row['scope'] == 'runtime']
        source_edges = [row for row in value['edges']
                        if row['consumer'].startswith('source:')]
        build_edges = [row for row in value['edges']
                       if row['consumer'].startswith('build:')]
        runtime_edges = [row for row in value['edges']
                         if row['consumer'].startswith('runtime:')
                         or row['dependency'].startswith('runtime:')]
        value['source_identity_sha256'] = closure._identity({
            'schema': closure.ACTUAL_CLOSURE_SCHEMA,
            'source_search_roots': value['source_search_roots'],
            'members': sources, 'edges': source_edges})
        value['build_identity_sha256'] = closure._identity({
            'schema': closure.ACTUAL_CLOSURE_SCHEMA,
            'source_identity_sha256': value['source_identity_sha256'],
            'members': builds, 'edges': build_edges})
        value['runtime_identity_sha256'] = closure._identity({
            'schema': closure.ACTUAL_CLOSURE_SCHEMA,
            'build_identity_sha256': value['build_identity_sha256'],
            'members': runtimes, 'edges': runtime_edges})
        value['closure_identity_sha256'] = closure._identity({
            name: value[name] for name in (
                'schema', 'source_search_roots', 'entrypoints', 'members',
                'edges', 'source_identity_sha256', 'build_identity_sha256',
                'runtime_identity_sha256')})
        self.expected = hashlib.sha256(closure.encoded(value)).hexdigest()

    def role_selection(self):
        new_files = {
            ('source', 'src/owner.py', 'python'): b'OWNER = 1\n',
            ('source', 'authority/outer.py', 'python'): b'OUTER = 1\n',
            ('source', 'authority/producer.py', 'python'): b'PRODUCER = 1\n',
            ('source', 'authority/actual.py', 'python'): b'ACTUAL = 1\n',
            ('source', 'authority/diagnostic.py', 'python'):
                b'DIAGNOSTIC = 1\n',
            ('source', 'authority/owner_compare.py', 'python'):
                b'COMPARE = 1\n',
            ('source', 'plans/financial.json', 'build-policy'): b'{}\n',
            ('source', 'plans/terminal.json', 'build-policy'): b'{}\n',
            ('source', 'plans/dispatcher.json', 'build-policy'): b'{}\n',
            ('source', 'plans/p1.json', 'build-policy'): b'{}\n',
            ('source', 'plans/c1.json', 'build-policy'): b'{}\n',
            ('build', 'bin/producer', 'launcher'): b'producer\n',
            ('build', 'bin/actual', 'launcher'): b'actual\n',
            ('build', 'bin/diagnostic', 'launcher'): b'diagnostic\n',
            ('build', 'bin/owner-compare', 'launcher'): b'comparison\n',
            ('build', 'bin/registered', 'executable'): b'registered\n',
            ('build', 'bin/terminal', 'executable'): b'terminal\n',
            ('build', 'bin/owner-c1', 'executable'): b'owner-c1\n',
        }
        for (scope, name, kind), raw in new_files.items():
            write(self.roots[scope] / name, raw)
            self.value['members'].append({
                'id': scope + ':' + name, 'scope': scope, 'path': name,
                'kind': kind, 'bytes': len(raw),
                'sha256': hashlib.sha256(raw).hexdigest(),
            })
        self.value['source_search_roots'] = ['authority', 'plans', 'src']
        extra_edges = []
        outer = 'build:bin/launcher'
        for target in (
                'build:bin/producer', 'build:bin/actual',
                'build:bin/diagnostic', 'build:bin/owner-compare',
                'build:bin/registered', 'build:bin/terminal',
                'build:bin/owner-c1'):
            extra_edges.append((outer, target, 'subprocess-exec'))
        authority_source_edges = {
            'build:bin/launcher': 'source:authority/outer.py',
            'build:bin/producer': 'source:authority/producer.py',
            'build:bin/actual': 'source:authority/actual.py',
            'build:bin/diagnostic': 'source:authority/diagnostic.py',
            'build:bin/owner-compare':
                'source:authority/owner_compare.py',
        }
        extra_edges.extend((build, source, 'generated-from')
                           for build, source in
                           authority_source_edges.items())
        plan_builds = {
            'financial': 'build:bin/registered',
            'terminal': 'build:bin/terminal',
            'dispatcher': 'build:bin/registered',
            'p1': 'build:bin/registered',
            'c1': 'build:bin/owner-c1',
        }
        for plan, role_build in plan_builds.items():
            extra_edges.append(
                (outer, 'source:plans/' + plan + '.json', 'asset-read'))
            extra_edges.append(
                ('source:plans/' + plan + '.json', role_build,
                 'launch-plan-for'))
        extra_edges.extend((
            ('build:bin/registered', 'source:src/engine.cpp',
             'compiled-from'),
            ('build:bin/registered', 'source:src/main.py',
             'generated-from'),
            ('build:bin/registered', 'source:src/helper.py',
             'generated-from'),
            ('build:bin/terminal', 'source:src/worker.mjs',
             'generated-from'),
            ('build:bin/owner-c1', 'source:src/owner.py',
             'generated-from'),
        ))
        self.value['members'].sort(key=lambda row: row['id'])
        self.value['edges'].extend({
            'consumer': consumer, 'dependency': dependency, 'kind': kind}
            for consumer, dependency, kind in extra_edges)
        self.value['edges'].sort(key=lambda row: (
            row['consumer'], row['dependency'], row['kind']))
        self.seal()
        authority = {
            'outer-supervisor': outer,
            'capture-producer': 'build:bin/producer',
            'actual-capture-worker': 'build:bin/actual',
            'diagnostic-launcher': 'build:bin/diagnostic',
            'owner-comparison-launcher': 'build:bin/owner-compare',
        }
        authority_sources = {
            'outer-supervisor': 'source:authority/outer.py',
            'capture-producer': 'source:authority/producer.py',
            'actual-capture-worker': 'source:authority/actual.py',
            'diagnostic-launcher': 'source:authority/diagnostic.py',
            'owner-comparison-launcher':
                'source:authority/owner_compare.py',
        }
        role_members = {
            'public-projection': (
                'financial-release', 'source:src/engine.cpp',
                'build:bin/registered', 'source:plans/financial.json'),
            'terminal-history': (
                'terminal-controller', 'source:src/worker.mjs',
                'build:bin/terminal', 'source:plans/terminal.json'),
            'dispatcher-capture': (
                'private-dispatcher', 'source:src/main.py',
                'build:bin/registered', 'source:plans/dispatcher.json'),
            'corrupt-server-capture': (
                'server-P1', 'source:src/helper.py',
                'build:bin/registered', 'source:plans/p1.json'),
            'colluder-wallet-capture': (
                'owner-C1', 'source:src/owner.py',
                'build:bin/owner-c1', 'source:plans/c1.json'),
        }
        roles = []
        for index, (round_number, kind) in enumerate(
                closure.ACTUAL_CHANNEL_ORDER):
            role, source, build, plan = role_members[kind]
            roles.append({
                'round': round_number, 'kind': kind, 'role': role,
                'fixed_fd': 20 + index, 'source_member': source,
                'build_member': build, 'launch_plan_member': plan,
            })
        selected = {
            'schema': closure.ACTUAL_ROLE_SELECTION_SCHEMA,
            'classification': 'ACTUAL_HIDDEN_MAPPING_CANDIDATE',
            'actual_closure_sha256': self.expected,
            'authority_entrypoints': authority,
            'authority_sources': authority_sources,
            'roles': roles,
        }
        selected['role_closure_identity_sha256'] = closure._identity(selected)
        return selected


class ActualClosureControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = Fixture(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_multilanguage_build_runtime_closure_recomputes_every_identity(self):
        self.assertIs(
            closure.validate_actual_closure(
                self.fixture.value, self.fixture.expected,
                self.fixture.roots),
            self.fixture.value)

    def test_runtime_byte_drift_refuses(self):
        (self.fixture.roots['runtime'] / 'lib/libc.so').write_bytes(
            b'changed-libc\n')
        with self.assertRaisesRegex(ValueError, 'actual-member-bytes'):
            closure.validate_actual_closure(
                self.fixture.value, self.fixture.expected,
                self.fixture.roots)

    def test_omitted_cpp_include_refuses_independent_scan(self):
        for row in self.fixture.value['edges']:
            if row['kind'] == 'cpp-include':
                row['kind'] = 'asset-read'
        self.fixture.seal()
        with self.assertRaisesRegex(
                ValueError,
                'actual-independent-static-dependency-closure'):
            closure.validate_actual_closure(
                self.fixture.value, self.fixture.expected,
                self.fixture.roots)

    def test_omitted_imported_file_and_edge_remain_visible_in_snapshot(self):
        self.fixture.value['members'] = [
            row for row in self.fixture.value['members']
            if row['id'] != 'source:src/helper.py']
        self.fixture.value['edges'] = [
            row for row in self.fixture.value['edges']
            if row['dependency'] != 'source:src/helper.py']
        self.fixture.seal()
        with self.assertRaisesRegex(
                ValueError,
                'actual-independent-static-dependency-closure'):
            closure.validate_actual_closure(
                self.fixture.value, self.fixture.expected,
                self.fixture.roots)

    def test_disconnected_runtime_or_caller_build_word_refuses(self):
        with self.subTest('disconnected-runtime'):
            value = self.fixture.value
            value['edges'] = [row for row in value['edges']
                              if row['kind'] != 'shared-library']
            self.fixture.seal()
            with self.assertRaisesRegex(ValueError,
                                        'actual-transitive-graph'):
                closure.validate_actual_closure(
                    value, self.fixture.expected, self.fixture.roots)
        self.fixture = Fixture(Path(self.temp.name) / 'second')
        with self.subTest('caller-build-word'):
            self.fixture.value['build_identity_sha256'] = 'ff' * 32
            expected = hashlib.sha256(
                closure.encoded(self.fixture.value)).hexdigest()
            with self.assertRaisesRegex(ValueError,
                                        'actual-recomputed-identities'):
                closure.validate_actual_closure(
                    self.fixture.value, expected, self.fixture.roots)

    def test_no_selected_actual_manifest_remains_a_hard_stop(self):
        with self.assertRaisesRegex(
                ValueError,
                'actual-multilanguage-build-runtime-selection-absent'):
            closure.require_selected_actual_closure()
        self.assertEqual(closure.actual_closure_source_status(), {
            'schema': 'kpb-actual-closure-source-status/v1',
            'status': 'CONFIGURED0_UNQUALIFIED',
            'manifest_bytes_and_static_graph_validated': True,
            'role_members_bound_without_caller_digest_words': True,
            'parent_sealed_snapshot_consumed_by_launch': False,
            'dynamic_import_asset_exec_dlopen_instrumented': False,
            'build_recipe_flags_outputs_verified': False,
            'elf_interpreter_and_runtime_graph_resolved': False,
            'running_kernel_identity_attested': False,
            'outer_supervisor_completion_authority': False,
            'actual_authority': False,
        })

    def test_role_selection_uses_verified_members_not_caller_digest_words(self):
        selected = self.fixture.role_selection()
        self.assertIs(closure.validate_actual_role_selection(
            selected, self.fixture.value, self.fixture.expected,
            self.fixture.roots), selected)
        selected['roles'][0]['source_sha256'] = 'ff' * 32
        with self.assertRaisesRegex(ValueError, 'actual-role-row-fields'):
            closure.validate_actual_role_selection(
                selected, self.fixture.value, self.fixture.expected,
                self.fixture.roots)

    def test_role_selection_cannot_reference_untyped_build_member(self):
        selected = self.fixture.role_selection()
        selected['roles'][0]['build_member'] = 'source:src/engine.cpp'
        selected['role_closure_identity_sha256'] = closure._identity({
            name: selected[name] for name in (
                'schema', 'classification', 'actual_closure_sha256',
                'authority_entrypoints', 'authority_sources', 'roles')})
        with self.assertRaisesRegex(ValueError,
                                    'actual-role-member-closure'):
            closure.validate_actual_role_selection(
                selected, self.fixture.value, self.fixture.expected,
                self.fixture.roots)

    def test_role_build_cannot_relabel_source_edge_as_asset(self):
        selected = self.fixture.role_selection()
        for row in self.fixture.value['edges']:
            if (row['consumer'], row['dependency']) == (
                    'build:bin/registered', 'source:src/engine.cpp'):
                row['kind'] = 'asset-read'
        self.fixture.value['edges'].sort(key=lambda row: (
            row['consumer'], row['dependency'], row['kind']))
        self.fixture.seal()
        selected['actual_closure_sha256'] = self.fixture.expected
        selected['role_closure_identity_sha256'] = closure._identity({
            name: selected[name] for name in (
                'schema', 'classification', 'actual_closure_sha256',
                'authority_entrypoints', 'authority_sources', 'roles')})
        with self.assertRaisesRegex(ValueError,
                                    'actual-role-member-closure'):
            closure.validate_actual_role_selection(
                selected, self.fixture.value, self.fixture.expected,
                self.fixture.roots)

    def test_role_launch_plan_must_select_its_exact_build(self):
        selected = self.fixture.role_selection()
        for row in self.fixture.value['edges']:
            if (row['consumer'], row['dependency'], row['kind']) == (
                    'source:plans/financial.json',
                    'build:bin/registered', 'launch-plan-for'):
                row['kind'] = 'asset-read'
        self.fixture.value['edges'].sort(key=lambda row: (
            row['consumer'], row['dependency'], row['kind']))
        self.fixture.seal()
        selected['actual_closure_sha256'] = self.fixture.expected
        selected['role_closure_identity_sha256'] = closure._identity({
            name: selected[name] for name in (
                'schema', 'classification', 'actual_closure_sha256',
                'authority_entrypoints', 'authority_sources', 'roles')})
        with self.assertRaisesRegex(ValueError,
                                    'actual-role-member-closure'):
            closure.validate_actual_role_selection(
                selected, self.fixture.value, self.fixture.expected,
                self.fixture.roots)

    def test_authority_build_must_have_its_exact_selected_source(self):
        for mutation in ('omitted', 'relabelled'):
            with self.subTest(mutation=mutation):
                fixture = Fixture(Path(self.temp.name) / mutation)
                selected = fixture.role_selection()
                if mutation == 'omitted':
                    fixture.value['members'] = [
                        row for row in fixture.value['members']
                        if row['id'] != 'source:authority/producer.py']
                    fixture.value['edges'] = [
                        row for row in fixture.value['edges']
                        if row['dependency'] !=
                            'source:authority/producer.py']
                else:
                    for row in fixture.value['edges']:
                        if (row['consumer'], row['dependency'], row['kind']) == (
                                'build:bin/producer',
                                'source:authority/producer.py',
                                'generated-from'):
                            row['kind'] = 'asset-read'
                fixture.value['members'].sort(key=lambda row: row['id'])
                fixture.value['edges'].sort(key=lambda row: (
                    row['consumer'], row['dependency'], row['kind']))
                fixture.seal()
                selected['actual_closure_sha256'] = fixture.expected
                selected['role_closure_identity_sha256'] = closure._identity({
                    name: selected[name] for name in (
                        'schema', 'classification',
                        'actual_closure_sha256', 'authority_entrypoints',
                        'authority_sources', 'roles')})
                with self.assertRaisesRegex(
                        ValueError,
                        'actual-authority-entrypoint-capture-producer'):
                    closure.validate_actual_role_selection(
                        selected, fixture.value, fixture.expected,
                        fixture.roots)


if __name__ == '__main__':
    unittest.main()
