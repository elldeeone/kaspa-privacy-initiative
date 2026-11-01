#!/usr/bin/env python3
"""Diagnostic controls for race-free source-owned parent artifact launch."""

from hashlib import sha256
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
EXECUTABLE_COMPONENT = 6
EXECUTABLE_FIELD = 4


def cpp_digest(value):
    return "Digest{" + ",".join(f"0x{byte:02x}" for byte in value) + "}"


def cpp_string(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


class SelectedParentLauncherControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-selected-parent-launcher-")
        cls.directory = Path(cls.temporary.name)
        cls.worker = cls.directory / "fixture-worker"
        worker_compile = subprocess.run([
            "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic",
            str(HERE / "privacy_measurement_selected_parent_fixture_worker.cpp"),
            "-I", str(HERE), "-lcrypto", "-o", str(cls.worker),
        ], capture_output=True, text=True, check=False)
        if worker_compile.returncode:
            raise AssertionError(worker_compile.stdout + worker_compile.stderr)

        cls.paths = []
        cls.digests = []
        for component in range(10):
            component_paths = []
            component_digests = []
            for field in range(6):
                if (component, field) == (
                        EXECUTABLE_COMPONENT, EXECUTABLE_FIELD):
                    path = cls.worker
                else:
                    path = cls.directory / f"artifact-{component}-{field}.bin"
                    body = bytes(
                        (1 + component * 19 + field * 7 + index) & 0xff
                        for index in range(97 + component + field))
                    path.write_bytes(body)
                component_paths.append(path)
                component_digests.append(sha256(path.read_bytes()).digest())
            cls.paths.append(component_paths)
            cls.digests.append(component_digests)

        cls.swap_target = cls.paths[0][0]
        cls.swap_replacement = cls.directory / "artifact-0-0-replacement.bin"
        cls.swap_replacement.write_bytes(b"replacement-does-not-match-pin")
        cls.symlink = cls.directory / "artifact-0-0-symlink"
        cls.symlink.symlink_to(cls.swap_target)

        cls.table = cls.directory / "compiled_fixture_table.hpp"
        rows = []
        for component in range(10):
            fields = ",\n".join(
                "ArtifactSpec{" + cpp_string(cls.paths[component][field]) +
                ", " + cpp_digest(cls.digests[component][field]) + "}"
                for field in range(6))
            rows.append(
                "std::array<ArtifactSpec, 6>{{\n" + fields + "\n}}")
        cls.table.write_text(
            "#pragma once\n"
            "namespace kpb::measurement::selected_parent_fixture {\n"
            "inline constexpr std::array<std::array<ArtifactSpec, 6>, 10> "
            "kArtifacts{{\n" + ",\n".join(rows) + "\n}};\n"
            f"inline constexpr unsigned kExecutableComponent = "
            f"{EXECUTABLE_COMPONENT};\n"
            f"inline constexpr unsigned kExecutableField = "
            f"{EXECUTABLE_FIELD};\n"
            "inline constexpr std::string_view kSwapTargetPath = " +
            cpp_string(cls.swap_target) + ";\n"
            "inline constexpr std::string_view kSwapReplacementPath = " +
            cpp_string(cls.swap_replacement) + ";\n"
            "inline constexpr std::string_view kSymlinkPath = " +
            cpp_string(cls.symlink) + ";\n"
            "}\n",
            encoding="utf-8")

        cls.binary = cls.directory / "launcher-control"
        table_macro = (
            '-DKPB_MEASUREMENT_SELECTED_PARENT_FIXTURE_TABLE_HEADER=' +
            f'"{cls.table}"')
        compiled = subprocess.run([
            "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-pthread",
            "-DKPB_MEASUREMENT_SELECTED_PARENT_LAUNCHER_TEST_SETUP",
            table_macro,
            str(HERE / "privacy_measurement_selected_parent_launcher_control.cpp"),
            str(HERE / "privacy_measurement_selected_parent_launcher.cpp"),
            str(HERE / "privacy_measurement_parent_manifest.cpp"),
            str(HERE / "privacy_measurement_authority.cpp"),
            str(HERE / "privacy_measurement_child_output_authority.cpp"),
            str(HERE / "privacy_measurement_output_abi.cpp"),
            "-I", str(HERE), "-lcrypto", "-o", str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_exact_same_descriptors_reach_child_and_recomputation(self):
        environment = dict(os.environ)
        environment["PYTHONWARNINGS"] = "error::ResourceWarning"
        run = subprocess.run(
            [str(self.binary)], capture_output=True, text=True, check=False,
            timeout=20, env=environment)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual((run.stdout, run.stderr), ("", ""))

    def test_production_has_no_table_or_caller_path_fd_launch(self):
        source = self.directory / "production_surface.cpp"
        source.write_text(r'''
#include "privacy_measurement_parent_manifest.hpp"
#include <array>
#include <string_view>
using namespace kpb::measurement;
template<class Launcher> concept HasNoArgumentLaunch = requires {
    Launcher::launch();
};
template<class Launcher> concept HasCallerPaths = requires(
        std::array<std::string_view, 60> paths) {
    Launcher::launch(paths);
};
template<class Launcher> concept HasCallerFds = requires(
        std::array<ParentManifestComponentArtifacts, 10> fds) {
    Launcher::launch(static_cast<decltype(fds)&&>(fds));
};
template<class Launcher> concept HasFixtureLaunch = requires {
    Launcher::test_only_launch_compiled_fixture();
};
static_assert(!HasNoArgumentLaunch<SelectedParentArtifactLauncher>);
static_assert(!HasCallerPaths<SelectedParentArtifactLauncher>);
static_assert(!HasCallerFds<SelectedParentArtifactLauncher>);
static_assert(!HasFixtureLaunch<SelectedParentArtifactLauncher>);
static_assert(kParentManifestSourceStatus.diagnostic_launcher_mechanism);
static_assert(kParentManifestSourceStatus.production_artifact_table_missing);
static_assert(!kParentManifestSourceStatus.source_owned_artifact_selection);
static_assert(!kParentManifestSourceStatus.launch_consumes_selected_artifacts);
static_assert(!kParentManifestSourceStatus.selected_parent_callsite);
static_assert(!kParentManifestSourceStatus.configured);
int main() { return 0; }
''', encoding="utf-8")
        binary = self.directory / "production-surface"
        compiled = subprocess.run([
            "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-pthread", str(source),
            str(HERE / "privacy_measurement_selected_parent_launcher.cpp"),
            str(HERE / "privacy_measurement_parent_manifest.cpp"),
            str(HERE / "privacy_measurement_authority.cpp"),
            str(HERE / "privacy_measurement_child_output_authority.cpp"),
            str(HERE / "privacy_measurement_output_abi.cpp"),
            "-I", str(HERE), "-lcrypto", "-o", str(binary),
        ], capture_output=True, text=True, check=False)
        self.assertEqual(compiled.returncode, 0,
                         compiled.stdout + compiled.stderr)
        run = subprocess.run(
            [str(binary)], capture_output=True, text=True, check=False,
            timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
