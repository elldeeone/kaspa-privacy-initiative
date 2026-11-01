#!/usr/bin/env python3
"""Hostile controls for the unimplemented P1 capsule plan compiler contract."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
HEADER = HERE / "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"
SOURCE = HERE / "privacy_p1_state_capsule_prelaunch_compiler_contract.cpp"
CONTROL = (
    HERE / "privacy_p1_state_capsule_prelaunch_compiler_contract_control.cpp"
)


class P1StateCapsulePrelaunchCompilerContractControls(unittest.TestCase):
    def compile(self, inputs, output, *, sanitize=False, compile_only=False):
        command = [
            "c++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-I", str(HERE),
        ]
        if sanitize:
            command.extend([
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
            ])
        if compile_only:
            command.append("-c")
        command.extend(str(value) for value in inputs)
        command.extend(["-o", str(output)])
        return subprocess.run(
            command, capture_output=True, text=True, check=False,
        )

    def test_contract_is_dependency_neutral_and_status_is_false(self):
        with tempfile.TemporaryDirectory(
            prefix="kpb-p1-plan-contract-",
        ) as raw:
            binary = Path(raw) / "control"
            built = self.compile([CONTROL, SOURCE], binary)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_control_is_clean_under_asan_and_ubsan(self):
        with tempfile.TemporaryDirectory(
            prefix="kpb-p1-plan-contract-sanitize-",
        ) as raw:
            binary = Path(raw) / "control"
            built = self.compile([CONTROL, SOURCE], binary, sanitize=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            run = subprocess.run(
                [str(binary)], capture_output=True, text=True, check=False,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def hostile_compile_fails(self, body):
        with tempfile.TemporaryDirectory(
            prefix="kpb-p1-plan-contract-hostile-",
        ) as raw:
            root = Path(raw)
            source = root / "hostile.cpp"
            source.write_text(
                '#include "privacy_p1_state_capsule_prelaunch_compiler_contract.hpp"\n'
                + body,
                encoding="utf-8",
            )
            output = root / "hostile.o"
            built = self.compile([source], output, compile_only=True)
            self.assertNotEqual(built.returncode, 0, built.stdout + built.stderr)

    def test_raw_plan_digest_fd_and_event_compile_paths_are_absent(self):
        for body in (
            """
using namespace kpb::measurement::p1_state;
int main() {
  return P1StateCapsulePrelaunchCompilerBridge::compile(7, 8, 9, 10);
}
""",
            """
#include <array>
using namespace kpb::measurement::p1_state;
int main() {
  std::array<unsigned char, 32> digest{};
  return P1StateCapsulePrelaunchCompilerBridge::compile(digest);
}
""",
            """
using namespace kpb::measurement::p1_state;
int main() {
  P1HookSerializerManifestAuthority value;
  return value.fd();
}
""",
            """
using namespace kpb::measurement::p1_state;
int main() {
  P1AbortTerminalManifestAuthority value;
  return value.event_factory();
}
""",
        ):
            with self.subTest(body=body):
                self.hostile_compile_fails(body)

    def test_hostile_bridge_redefinition_is_rejected(self):
        self.hostile_compile_fails("""
namespace kpb::measurement::p1_state {
class P1StateCapsulePrelaunchCompilerBridge final {
public:
  static int compile(int) { return 1; }
};
}
int main() { return 0; }
""")

    def test_header_declares_no_callable_compiler_or_raw_authority_data(self):
        text = HEADER.read_text(encoding="utf-8")
        self.assertLess(
            text.index("class P1StateCapsulePrelaunchCompilerBridge final"),
            text.index("friend class P1StateCapsulePrelaunchCompilerBridge"),
        )
        self.assertNotIn("static P1StateCapsulePrelaunchSplit compile", text)
        self.assertNotIn("StaticStateCapsulePlan", text)
        self.assertNotIn("PolicyDigest", text)
        self.assertNotIn(" int fd", text)
        self.assertNotIn("std::span", text)
        self.assertNotIn("std::array", text)
        for required in (
            "RegisteredSelectedProducerPrelaunchBindingAuthority",
            "RegisteredPrelaunchPolicyDomainAuthority",
            "P1HookSerializerManifestAuthority",
            "P1AbortTerminalManifestAuthority",
            "P1CorruptStateCapsulePlanAuthority",
            "P1StateCapsulePrelaunchSplit",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
