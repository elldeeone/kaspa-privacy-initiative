#!/usr/bin/env python3
"""Controls for parent-owned finite-manifest artifact recomputation."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class ParentManifestControls(unittest.TestCase):
    def compile(self, output, *sources, test_setup=False):
        command = [
            'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-pthread',
        ]
        if test_setup:
            command.append('-DKPB_MEASUREMENT_PARENT_MANIFEST_TEST_SETUP')
        command.extend(str(source) for source in sources)
        command.extend(['-I', str(HERE), '-lcrypto', '-o', str(output)])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_exact_sealed_artifacts_are_one_shot(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-parent-manifest-') as directory:
            binary = Path(directory) / 'control'
            compiled = self.compile(
                binary,
                HERE / 'privacy_measurement_parent_manifest_control.cpp',
                HERE / 'privacy_measurement_parent_manifest.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_measurement_authority.cpp',
                test_setup=True)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_production_has_no_digest_list_mint_or_test_hooks(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-parent-manifest-surface-') as directory:
            directory = Path(directory)
            source = directory / 'surface.cpp'
            source.write_text(r'''
#include "privacy_measurement_parent_manifest.hpp"
#include <type_traits>
using namespace kpb::measurement;
static_assert(!std::is_copy_constructible_v<
    ParentManifestArtifactSelectionAuthority>);
static_assert(!std::is_constructible_v<
    ParentManifestArtifactSelectionAuthority,
    std::array<ManifestEntry, 10>>);
template<class Factory> concept HasDigestMint = requires(
    std::array<ManifestEntry, 10> entries, Digest process,
    Digest executable) {
    Factory::mint(entries, process, executable);
};
template<class Factory> concept HasEntropyHook = requires {
    Factory::test_only_force_entropy_failure(true);
    Factory::test_only_force_entropy_short_read(true);
};
template<class Selector> concept HasArbitraryFdSelection = requires(
    std::array<ParentManifestComponentArtifacts, 10> artifacts) {
    Selector::select(
        static_cast<std::array<ParentManifestComponentArtifacts, 10>&&>(
            artifacts));
};
static_assert(!HasDigestMint<ParentManifestRecomputationFactory>);
static_assert(!HasEntropyHook<ParentManifestRecomputationFactory>);
static_assert(!HasArbitraryFdSelection<ParentManifestArtifactSelector>);
static_assert(!kParentManifestSourceStatus.source_owned_artifact_selection);
static_assert(!kParentManifestSourceStatus.launch_consumes_selected_artifacts);
int main() { return kParentManifestSourceStatus.configured ? 1 : 0; }
''', encoding='utf-8')
            binary = directory / 'surface'
            compiled = self.compile(
                binary, source,
                HERE / 'privacy_measurement_parent_manifest.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_measurement_authority.cpp')
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            symbols = subprocess.run(
                ['nm', '-C', str(binary)], capture_output=True, text=True,
                check=False, timeout=10)
            self.assertEqual(symbols.returncode, 0,
                             symbols.stdout + symbols.stderr)
            self.assertNotIn('test_only_force_entropy', symbols.stdout)

    def test_factory_friend_name_is_complete(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-parent-manifest-friend-') as directory:
            directory = Path(directory)
            source = directory / 'hostile.cpp'
            source.write_text(r'''
#include "privacy_measurement_authority.hpp"
namespace kpb::measurement {
class ParentManifestRecomputationFactory final {};
}
int main() { return 0; }
''', encoding='utf-8')
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', '-pthread', '-I', str(HERE), '-c',
                str(source), '-o', str(directory / 'hostile.o'),
            ], capture_output=True, text=True, check=False)
            self.assertNotEqual(compiled.returncode, 0,
                                'factory friend name remained forgeable')

    def test_sixty_self_authored_blobs_cannot_select_production_manifest(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-parent-manifest-self-authored-') as directory:
            directory = Path(directory)
            source = directory / 'self_authored.cpp'
            source.write_text(r'''
#include "privacy_measurement_parent_manifest.hpp"
#include <array>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
using namespace kpb::measurement;
int main() {
    std::array<ParentManifestComponentArtifacts, 10> artifacts{};
    for (unsigned component = 0; component < artifacts.size(); ++component)
        for (unsigned field = 0; field < artifacts[component].fds.size();
             ++field) {
            const int fd = ::memfd_create(
                "attacker-selected", MFD_CLOEXEC | MFD_ALLOW_SEALING);
            std::array<unsigned char, 67> bytes{};
            bytes.fill(static_cast<unsigned char>(1 + component * 6 + field));
            (void)::write(fd, bytes.data(), bytes.size());
            (void)::fcntl(fd, F_ADD_SEALS,
                F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
            artifacts[component].fds[field] = fd;
        }
    auto selected = ParentManifestArtifactSelector::select(
        static_cast<decltype(artifacts)&&>(artifacts));
    auto authority = ParentManifestRecomputationFactory::recompute(
        static_cast<decltype(selected)&&>(selected));
    (void)authority;
}
''', encoding='utf-8')
            compiled = self.compile(
                directory / 'self_authored', source,
                HERE / 'privacy_measurement_parent_manifest.cpp',
                HERE / 'privacy_measurement_child_output_authority.cpp',
                HERE / 'privacy_measurement_output_abi.cpp',
                HERE / 'privacy_measurement_authority.cpp')
            self.assertNotEqual(
                compiled.returncode, 0,
                'self-authored sixty-blob manifest unexpectedly minted')
            self.assertIn('select', compiled.stderr)


if __name__ == '__main__':
    unittest.main()
