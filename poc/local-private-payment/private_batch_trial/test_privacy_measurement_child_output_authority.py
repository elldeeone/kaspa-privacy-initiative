#!/usr/bin/env python3
"""Controls for the sealed, fixed-size measurement child output plane."""

from pathlib import Path
import subprocess
import tempfile
import unittest

import privacy_measurement_output_abi as output_abi
from test_privacy_measurement_output_abi import capsules, score_bundle


HERE = Path(__file__).resolve().parent


class MeasurementChildOutputAuthorityControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.append('-DKPB_MEASUREMENT_CHILD_OUTPUT_TEST_SETUP')
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_exact_output_is_sealed_read_only_and_one_shot(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-child-output-') as directory:
            binary = Path(directory) / 'control'
            compiled = self.compile(
                binary,
                HERE / 'privacy_measurement_child_output_authority_control.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            observer = Path(directory) / 'observer.bin'
            score = Path(directory) / 'score.bin'
            observer.write_bytes(
                output_abi.test_only_encode_observer_capsules_v3(
                capsules(full_workload=False)))
            score.write_bytes(output_abi.encode_owner_score_bundle(
                score_bundle()))
            run = subprocess.run([str(binary), str(observer), str(score)],
                                 capture_output=True,
                                 text=True, check=False, timeout=15)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual((run.stdout, run.stderr), ('', ''))

    def test_production_has_no_factory_fd_or_hash_surface(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-measurement-child-output-surface-') as directory:
            directory = Path(directory)
            source = directory / 'bypass.cpp'
            source.write_text(r'''
#include "privacy_measurement_child_output_authority.hpp"
#include <concepts>
using namespace kpb::measurement::runtime_bridge;
template<class T> concept HasTestBegin = requires(PrivateChildOutputOffer x) {
    T::test_only_begin(x);
};
template<class T> concept HasTakeFd = requires(T& x) {
    x.test_only_take_child_fd();
};
template<class T> concept HasTestMint = requires(PrivateChildOutputCompletion x) {
    T::test_only_mint(x);
};
template<class T> concept HasDuplicateFd = requires(const T& x) {
    x.test_only_duplicate_read_fd();
};
template<class T> concept HasPublicReceipt = requires(const T& x) {
    x.public_receipt();
};
template<class T> concept HasContentHash = requires(const T& x) {
    x.content_hash();
};
static_assert(!HasTestBegin<MeasurementChildOutputPlane>);
static_assert(!HasTakeFd<PendingChildOutputAuthority>);
static_assert(!HasTestMint<AuthenticatedChildOutputCompletionAuthority>);
static_assert(!HasDuplicateFd<SealedChildOutputAuthority>);
static_assert(!HasPublicReceipt<SealedChildOutputAuthority>);
static_assert(!HasContentHash<SealedChildOutputAuthority>);
int main() {}
''', encoding='utf-8')
            compiled = self.compile(directory / 'bypass', source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)


if __name__ == '__main__':
    unittest.main()
