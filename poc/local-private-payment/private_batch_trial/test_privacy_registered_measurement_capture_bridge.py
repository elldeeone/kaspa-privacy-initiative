#!/usr/bin/env python3
"""Controls for the persistent registered-parent measurement conversion."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent / "mpc-prover" / "financial"


class RegisteredMeasurementCaptureBridgeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-registered-measurement-capture-")
        cls.binary = Path(cls.temporary.name) / "controls"
        sources = [
            HERE / "privacy_registered_measurement_capture_bridge_control.cpp",
            HERE / "privacy_registered_measurement_capture_bridge.cpp",
            HERE / "privacy_measurement_authority.cpp",
            HERE / "privacy_measurement_child_output_authority.cpp",
            HERE / "privacy_measurement_output_abi.cpp",
            FINANCIAL / "registered_parent_round_completion.cpp",
            FINANCIAL / "registered_party_completion_transport.cpp",
            FINANCIAL / "authenticated_baseline_owner_receiver.cpp",
            FINANCIAL / "registered_parent_role_fork.cpp",
            FINANCIAL / "registered_full_cohort_release_barrier.cpp",
            FINANCIAL / "registered_projection_route.cpp",
            FINANCIAL / "registered_parent_role_delivery_bridge.cpp",
            FINANCIAL / "registered_driver_bridge.cpp",
            FINANCIAL / "registered_capture_session.cpp",
            FINANCIAL / "baseline_public_effects_collector.cpp",
            FINANCIAL / "registered_attempt_supervisor.cpp",
            FINANCIAL / "registered_identity_registry.cpp",
            FINANCIAL / "docker_monotonic_anchor_client.cpp",
            HERE / "privacy_capture_hook.cpp",
        ]
        command = [
            "g++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-pthread",
            "-DKPI_REGISTERED_PARENT_FORK_TEST_SETUP",
            "-DKPI_REGISTERED_FULL_COHORT_RELEASE_BARRIER_TEST_SETUP",
            "-DKPI_REGISTERED_DRIVER_BRIDGE_TEST_SETUP",
            "-DKPI_REGISTERED_PARTY_COMPLETION_TRANSPORT_TEST_SETUP",
            "-DKPI_REGISTERED_PROJECTION_ROUTE_TEST_SETUP",
            "-DKPB_MEASUREMENT_AUTHORITY_TEST_SETUP",
            *map(str, sources), "-I", str(FINANCIAL), "-lcrypto",
            "-o", str(cls.binary),
        ]
        compiled = subprocess.run(
            command, capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_persistent_trial_is_consumed_once_and_exactly(self):
        environment = dict(os.environ)
        environment["PYTHONWARNINGS"] = "error::ResourceWarning"
        scenarios = (
            "hidden", "baseline", "missing-producer", "prepopulated",
            "missing-retention", "projection-process", "projection-exit",
            "dispatcher-process", "dispatcher-exit", "classification",
            "trial", "financial-run-1", "financial-run-2", "attempt-1",
            "attempt-2", "cohort-1", "cohort-2", "capture-plan-1",
            "capture-plan-2", "projection-1", "projection-2",
            "capture-source", "capture-build", "capture-launcher",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                run = subprocess.run(
                    [str(self.binary), scenario], capture_output=True,
                    text=True, check=False, timeout=30, env=environment)
                self.assertEqual(run.returncode, 0,
                                 run.stdout + run.stderr)
                self.assertEqual((run.stdout, run.stderr), ("", ""))

    def test_production_bridge_has_no_receipt_or_digest_overload(self):
        header = (
            FINANCIAL / "registered_measurement_capture_bridge_contract.hpp"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "RegisteredParentTrialCompletionAuthority&&", header)
        self.assertNotIn("PublicRegisteredParentTrialCompletion", header)
        self.assertNotIn("Digest", header)
        self.assertNotIn("test_only", header)


if __name__ == "__main__":
    unittest.main()
