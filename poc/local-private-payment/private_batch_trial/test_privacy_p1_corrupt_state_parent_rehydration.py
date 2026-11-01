#!/usr/bin/env python3
"""Compile controls for the CONFIGURED0 parent rehydration contract."""

from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class P1CorruptStateParentRehydrationControls(unittest.TestCase):
    def compile(self, output, source):
        return subprocess.run([
            "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", str(source),
            str(HERE / "privacy_p1_corrupt_state_parent_rehydration.cpp"),
            "-I", str(HERE), "-o", str(output),
        ], capture_output=True, text=True, check=False)

    def test_exact_conjunctive_surface_is_unmintable(self):
        with tempfile.TemporaryDirectory(prefix="kpb-p1-rehydrate-") as d:
            directory = Path(d)
            source = directory / "surface.cpp"
            source.write_text(r'''
#include "privacy_p1_corrupt_state_parent_rehydration.hpp"
#include <concepts>
using namespace kpb::measurement::p1_state_capsule;
template<class T> concept HasFd = requires(const T& value) { value.fd(); };
template<class T> concept HasPath = requires(const T& value) { value.path(); };
template<class T> concept HasHash = requires(const T& value) {
    value.archive_sha256();
};
template<class T> concept HasStatus = requires(const T& value) {
    value.complete();
};
static_assert(!std::default_initializable<
    P1AuthenticatedChildStateDispositionAuthority>);
static_assert(!std::default_initializable<
    P1ParentRehydratedStateCapsuleAuthority>);
static_assert(!std::copy_constructible<
    P1AuthenticatedChildStateDispositionAuthority>);
static_assert(!std::copy_constructible<
    P1ParentRehydratedStateCapsuleAuthority>);
static_assert(!HasFd<P1ParentRehydratedStateCapsuleAuthority>);
static_assert(!HasPath<P1ParentRehydratedStateCapsuleAuthority>);
static_assert(!HasHash<P1ParentRehydratedStateCapsuleAuthority>);
static_assert(!HasStatus<P1ParentRehydratedStateCapsuleAuthority>);
static_assert(kParentRehydrationSourceStatus.exact_conjunctive_type_contract);
static_assert(kParentRehydrationSourceStatus.raw_fd_or_path_overload_absent);
static_assert(kParentRehydrationSourceStatus.raw_digest_or_status_overload_absent);
static_assert(!kParentRehydrationSourceStatus.authenticated_child_disposition_source);
static_assert(!kParentRehydrationSourceStatus.topology_archive_residual_consumer);
static_assert(!kParentRehydrationSourceStatus.pidfd_completion_consumer);
static_assert(!kParentRehydrationSourceStatus.independent_archive_grammar_parser);
static_assert(!kParentRehydrationSourceStatus.independent_state_replay);
static_assert(!kParentRehydrationSourceStatus.exact_two_round_order_join);
static_assert(!kParentRehydrationSourceStatus.parent_rehydration_minter);
static_assert(!kParentRehydrationSourceStatus.configured);
int main() {}
''', encoding="utf-8")
            compiled = self.compile(directory / "surface", source)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)

    def test_complete_bridge_cannot_be_redefined(self):
        with tempfile.TemporaryDirectory(prefix="kpb-p1-rehydrate-friend-") as d:
            directory = Path(d)
            source = directory / "friend.cpp"
            source.write_text(r'''
#include "privacy_p1_corrupt_state_parent_rehydration.hpp"
namespace kpi::mpc::financial::registered_driver {
class RegisteredP1StateCapsuleParentRehydrationBridge final {
public: RegisteredP1StateCapsuleParentRehydrationBridge() = delete;
};
}
int main() {}
''', encoding="utf-8")
            compiled = self.compile(directory / "friend", source)
            self.assertNotEqual(compiled.returncode, 0)

    def test_contract_has_no_raw_reader_or_digest_signature(self):
        contract = (HERE / (
            "privacy_p1_corrupt_state_parent_rehydration_contract.hpp"
        )).read_text(encoding="utf-8")
        self.assertIn("FreshTrialP1StateArchiveResidual&&", contract)
        self.assertIn("PersistentRoleExitEvidence&&", contract)
        self.assertEqual(
            contract.count("P1AuthenticatedChildStateDispositionAuthority&&"),
            2)
        for forbidden in (
            "int fd", "int reader", "std::span", "std::vector",
            "Digest", "bool complete", "const char*", "std::string",
        ):
            self.assertNotIn(forbidden, contract)


if __name__ == "__main__":
    unittest.main()
