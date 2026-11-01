#!/usr/bin/env python3
"""Source-owned raw-attempt/exact-run transfer controls."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import privacy_source_closure as source_closure


# This control exercises only the new source archive encoder. The shared
# observer manifest is concurrently gaining FD40 parser dependencies; do not
# make this isolated test own or weaken that transitive-closure work.
_manifest = source_closure.manifest
source_closure.manifest = lambda _role: {'members': []}
try:
    import privacy_launch as launch
finally:
    source_closure.manifest = _manifest


HERE = Path(__file__).resolve().parent


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class OwnerScoreLineageSourceAuthorityControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(
            prefix='kpb-score-lineage-source-control-')
        cls.root = Path(cls.temp.name)
        cls.control = cls.root / 'control'
        built = subprocess.run([
            'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-DKPB_OWNER_SCORE_LINEAGE_SOURCE_TEST_SETUP',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
            '-I', str(HERE),
            str(HERE / 'privacy_owner_score_lineage_source_control.cpp'),
            str(HERE / 'privacy_owner_score_lineage_source_authority.cpp'),
            '-o', str(cls.control),
        ], capture_output=True, text=True, check=False)
        if built.returncode != 0:
            raise AssertionError(built.stdout + built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @staticmethod
    def archive():
        run_raw = (
            b'{"schema":"kpb-source-owned-diagnostic-run/v1",'
            b'"selected":true}\n')
        bound = {
            'method_sha256': digest(b'frozen-method'),
            'selection_sha256': digest(run_raw),
            'trial_id': '22222222-2222-4222-8222-222222222222',
            'phase': 'private-batch-privacy',
            'attempt_id': 'actual-candidate-attempt-01',
        }
        selected = {
            'schema': 'kpb-private-diagnostic-launch-selection/v2',
            'binding': bound,
            'expected_classification':
                'ACTUAL_HIDDEN_MAPPING_CANDIDATE',
            'source_closure_sha256': {
                'diagnostic-launcher': '11' * 32,
            },
            'runtime_identity_sha256': digest(b'runtime-closure'),
        }
        outer = digest(b'exact-diagnostic-selection')
        return launch._owner_score_lineage_source_archive(
            selected, bound, run_raw, outer)

    def run_control(self, mode, archive=None):
        path = self.root / f'{mode}.bin'
        path.write_bytes(self.archive() if archive is None else archive)
        result = subprocess.run(
            [str(self.control), mode, str(path)],
            capture_output=True, text=True, check=False,
            env={
                **os.environ,
                'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1',
                'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1',
            })
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)

    def compile(self, output, source, *, link=False):
        command = [
            'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-I', str(HERE), str(source),
        ]
        if link:
            command.extend([
                str(HERE /
                    'privacy_owner_score_lineage_source_authority.cpp'),
                '-o', str(output),
            ])
        else:
            command.extend(['-c', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_source_archive_and_opaque_one_shot_transfer(self):
        archive = self.archive()
        self.assertEqual(archive[:8], b'KPBOSL02')
        self.assertEqual(int.from_bytes(archive[8:12], 'little'), 2)
        self.assertEqual(int.from_bytes(archive[12:16], 'little'), 416)
        self.assertEqual(int.from_bytes(archive[16:24], 'little'),
                         len(archive))
        attempt = b'actual-candidate-attempt-01'
        expected_measurement = hashlib.sha256(
            launch.OWNER_SCORE_MEASUREMENT_ATTEMPT_DOMAIN +
            len(attempt).to_bytes(2, 'little') + attempt).digest()
        self.assertEqual(archive[232:264], expected_measurement)
        self.assertEqual(archive[264:264 + len(attempt)], attempt)
        self.assertEqual(archive[416:],
                         b'{"schema":"kpb-source-owned-diagnostic-run/v1",'
                         b'"selected":true}\n')
        self.run_control('success', archive)

    def test_forge_cross_run_replay_and_preclaim_fault_refuse(self):
        for mode in ('forge', 'cross-run', 'replay', 'fault'):
            with self.subTest(mode=mode):
                self.run_control(mode)

    def test_production_surface_has_no_caller_mint_or_raw_getter(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-score-lineage-surface-') as raw:
            root = Path(raw)
            source = root / 'surface.cpp'
            source.write_text(r'''
#include "privacy_owner_score_lineage_source_authority.hpp"
#include <concepts>
#include <type_traits>
using namespace kpb::measurement::score_output_lineage_source;
template<class T> concept HasReceipt = requires(const T& value) {
    value.public_receipt();
};
template<class T> concept HasBytes = requires(const T& value) {
    value.bytes();
};
template<class T> concept HasDigest = requires(const T& value) {
    value.digest();
};
template<class T> concept HasAttempt = requires(const T& value) {
    value.attempt_id();
};
template<class T> concept HasTestMint = requires {
    &T::test_only_mint;
};
static_assert(!std::default_initializable<
    AuthenticatedPrivacyLaunchLineageSourceAuthority>);
static_assert(!std::copy_constructible<
    AuthenticatedPrivacyLaunchLineageSourceAuthority>);
static_assert(std::move_constructible<
    AuthenticatedPrivacyLaunchLineageSourceAuthority>);
static_assert(!std::default_initializable<
    SelectedOwnerScoreLineageSourceTransferAuthority>);
static_assert(!std::copy_constructible<
    SelectedOwnerScoreLineageSourceTransferAuthority>);
static_assert(std::move_constructible<
    SelectedOwnerScoreLineageSourceTransferAuthority>);
static_assert(!HasReceipt<SelectedOwnerScoreLineageSourceTransferAuthority>);
static_assert(!HasBytes<SelectedOwnerScoreLineageSourceTransferAuthority>);
static_assert(!HasDigest<SelectedOwnerScoreLineageSourceTransferAuthority>);
static_assert(!HasAttempt<SelectedOwnerScoreLineageSourceTransferAuthority>);
static_assert(!HasTestMint<AuthenticatedPrivacyLaunchLineageSourceAuthority>);
static_assert(kOwnerScoreLineageSourceStatus.python_source_parser_located);
static_assert(kOwnerScoreLineageSourceStatus.source_archive_encoder);
static_assert(kOwnerScoreLineageSourceStatus.cpp_archive_parser);
static_assert(kOwnerScoreLineageSourceStatus.opaque_one_shot_transfer);
static_assert(kOwnerScoreLineageSourceStatus.credentialed_receiver_transport_core);
static_assert(!kOwnerScoreLineageSourceStatus.authenticated_python_receiver);
static_assert(kOwnerScoreLineageSourceStatus.outer_attempt_source_join);
static_assert(!kOwnerScoreLineageSourceStatus.prelaunch_linear_residual);
static_assert(!kOwnerScoreLineageSourceStatus.trial_linear_residual);
static_assert(!kOwnerScoreLineageSourceStatus.output_lineage_minter);
static_assert(!kOwnerScoreLineageSourceStatus.selected_callsite);
static_assert(!kOwnerScoreLineageSourceStatus.configured);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(root / 'surface', source, link=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(root / 'surface')], check=False)
            self.assertEqual(run.returncode, 0)

    def test_complete_bridges_and_exact_admitted_boundary_are_pinned(self):
        bridges = (
            'PrivacyLaunchLineageSourceReceiverBridge',
            'SelectedOwnerScoreLineageAdmissionBridge',
            'RegisteredOwnerScoreLineageSourceBridge',
        )
        with tempfile.TemporaryDirectory(
                prefix='kpb-score-lineage-friend-') as raw:
            root = Path(raw)
            for bridge in bridges:
                for order in ('before', 'after'):
                    with self.subTest(bridge=bridge, order=order):
                        hostile = f'''namespace kpb::measurement::score_output_lineage_source {{
class {bridge} final {{}};
}}
'''
                        include = ('#include '
                                   '"privacy_owner_score_lineage_source_authority.hpp"\n')
                        body = (hostile + include if order == 'before'
                                else include + hostile)
                        source = root / f'{bridge}-{order}.cpp'
                        source.write_text(body + 'int main() {}\n',
                                          encoding='utf-8')
                        compiled = self.compile(
                            root / f'{bridge}-{order}.o', source)
                        self.assertNotEqual(compiled.returncode, 0)
        launch_source = (HERE / 'privacy_launch.py').read_text(
            encoding='utf-8')
        self.assertIn('def admitted_owner_score_lineage_source(',
                      launch_source)
        self.assertIn('_owner_score_lineage_source_archive(', launch_source)
        self.assertIn('lineage_sink(archive)', launch_source)


if __name__ == '__main__':
    unittest.main()
