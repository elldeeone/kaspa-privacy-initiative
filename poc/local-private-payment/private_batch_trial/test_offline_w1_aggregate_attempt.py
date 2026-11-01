#!/usr/bin/env python3
"""Hostile controls for the inert offline W1 aggregate attempt contract."""

from __future__ import annotations

import copy
import inspect
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

import offline_w1_aggregate_attempt as target


def healthy_resources():
    return {
        "memory_available_bytes": target.MINIMUM_MEMORY_AVAILABLE,
        "swap_total_bytes": 8 * 1024**3,
        "swap_free_bytes": 8 * 1024**3,
        "disk_free_bytes": target.MINIMUM_DISK_FREE,
        "effective_memory_swap_max": "0",
        "network_interfaces": ["lo"],
        "network_namespace_inode": 100,
        "init_network_namespace_inode": 200,
        "conflicting_processes": [],
        "core_soft_limit": 0,
        "core_hard_limit": 0,
    }


class AttemptCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-offline-w1-aggregate-attempt-controls-"
        )
        self.parent = Path(self.temporary.name) / "attempts"
        self.attempts = []

    def tearDown(self):
        for attempt in self.attempts:
            attempt.close()
        self.temporary.cleanup()

    def attempt(self):
        value = target._allocate_attempt(self.parent, str(uuid.uuid4()))
        self.attempts.append(value)
        return value

    def recover(self, root):
        value = target._recover_control_attempt(root)
        self.attempts.append(value)
        return value

    def child(self, attempt, phase, behavior):
        with mock.patch.object(target, "_oom_kill_count", side_effect=[4, 4]):
            return target._test_only_run_inert_child(attempt, phase, behavior)

    def prepare(self, attempt):
        child = self.child(attempt, "prepare", "prepare-ok")
        receipt = target._test_only_publish_prepare_control(attempt, child)
        return child, receipt

    @staticmethod
    def terminal(attempt):
        return json.loads((attempt.root / "TERMINAL.json").read_bytes())


class ResourceControls(unittest.TestCase):
    def test_exact_resource_shape_and_every_gate(self):
        target.admit_resources(healthy_resources())
        hostile = []
        for key, value in (
            ("memory_available_bytes", target.MINIMUM_MEMORY_AVAILABLE - 1),
            ("swap_free_bytes", 0),
            ("effective_memory_swap_max", "max"),
            ("disk_free_bytes", target.MINIMUM_DISK_FREE - 1),
            ("network_interfaces", ["eth0", "lo"]),
            ("network_namespace_inode", 200),
            ("init_network_namespace_inode", None),
            ("conflicting_processes", [{"pid": 7, "comm": "rustc"}]),
            ("core_soft_limit", -1),
            ("core_hard_limit", -1),
        ):
            selected = healthy_resources()
            selected[key] = value
            hostile.append(selected)
        malformed = healthy_resources()
        malformed["extra"] = True
        hostile.append(malformed)
        for value in hostile:
            with self.subTest(value=value), self.assertRaises(target.Refused):
                target.admit_resources(value)

    def test_source_status_is_narrow_and_go_is_impossible(self):
        status = target.SOURCE_STATUS
        self.assertTrue(status["descriptor_bound_control_output_core"])
        self.assertTrue(status["bounded_control_logs_core"])
        self.assertTrue(status["control_crash_recovery_core"])
        self.assertTrue(status["preallocated_fallback_terminal_core"])
        self.assertTrue(status["historical_reconstructed_nonfinal_source_bound"])
        for key in (
            "current_assignment_and_prover_source_bound",
            "source_owned_child_binary_present",
            "eligible_inner_prover_binary_present",
            "eligible_inner_prover_build_receipt_present",
            "source_owned_assignment_bridge_present",
            "production_relation_satisfaction_authority_present",
            "production_independent_verification_authority_present",
            "production_pk_open_path_present",
            "production_typed_pk_authority_present",
            "production_internal_osrng_enforced",
            "production_caller_randomness_entry_present",
            "production_prepare_enabled",
            "production_proof_enabled",
            "canonical_proof_writer_present",
            "canonical_stage_08_writer_present",
            "network_namespace_launch_path_present",
            "current_successful_memory_bound_present",
            "authorization",
        ):
            self.assertFalse(status[key], key)

    def test_no_import_mintable_authority_or_pk_open_seam_exists(self):
        forbidden = (
            "_CONTROL_AUTHORITY_TOKEN",
            "RelationSatisfiedAuthority",
            "IndependentVerificationAuthority",
            "_control_relation_authority",
            "_control_verification_authority",
            "_open_parameters_after_relation",
            "_publish_verified_proof",
        )
        for name in forbidden:
            self.assertFalse(hasattr(target, name), name)


class SourceBindingControls(unittest.TestCase):
    def test_current_diagnostics_report_exact_mode_and_all_live_drift(self):
        value = target.component_source_diagnostics()
        self.assertEqual(
            value["status"], "HISTORICAL_COMPONENT_SOURCE_BOUND_NONFINAL"
        )
        self.assertTrue(value["ready_for_exact_component_validation"])
        self.assertFalse(value["authorization"])
        self.assertFalse(any(value["actions_performed"].values()))
        self.assertEqual(value["fixture_source"]["mode_octal"], "0664")
        self.assertEqual(
            value["fixture_source"]["sha256"], target.FIXTURE_SOURCE_SHA256
        )
        self.assertEqual(value["sealed_plan"]["live_exact_members"], 76)
        self.assertEqual(
            value["retained_owner_aux_source_closure"]["live_exact_members"],
            34,
        )
        self.assertEqual(value["blockers"], [])
        codes = [item["code"] for item in value["live_path_diagnostics"]]
        self.assertEqual(
            codes,
            [
                "fixture-live-source-not-immutable-exact",
                "sealed-plan-live-source-member-drift",
                "retained-owner-aux-live-source-member-drift",
            ],
        )
        historical = value["historical_source_bundle"]
        self.assertTrue(historical["accepted_by_this_source"])
        self.assertTrue(historical["all_members_rehashed"])
        self.assertEqual(historical["manifest_sha256"], target.HISTORICAL_MANIFEST_SHA256)
        self.assertEqual(historical["receipt_sha256"], target.HISTORICAL_RECEIPT_SHA256)
        self.assertFalse(historical["current_source"])
        self.assertFalse(historical["build_reproduced"])
        plan_drift = {
            Path(item["path"]).relative_to(target.ROOT).as_posix(): item
            for item in value["sealed_plan"]["live_drift_members"]
        }
        self.assertEqual(set(plan_drift), set(target.HISTORICAL_RECONSTRUCTION_RECIPES))
        lock = plan_drift[
            "poc/local-private-payment/private-batch-relation/Cargo.lock"
        ]
        self.assertEqual(lock["expected"]["bytes"], 38_060)
        self.assertEqual(
            lock["expected"]["sha256"],
            "fe0af1b1ff77eba2acf57ea069b8942d0884b2b8e5ce728647373d5f768ec09f",
        )
        self.assertEqual(lock["observed"]["bytes"], 38_072)
        self.assertEqual(
            lock["observed"]["sha256"],
            "9b6c43f8a188d24de5e55b9c310bb094133ffa2a276dca4d8fda6f20985bea5e",
        )

    def test_missing_mutated_raced_symlink_and_extra_members_are_drift(self):
        expected = [
            {"path": "/source/a", "bytes": 3, "sha256": "aa" * 32},
            {"path": "/source/b", "bytes": 4, "sha256": "bb" * 32},
        ]

        def observed(path, size, digest):
            return {
                "path": path,
                "exists": True,
                "symlink": False,
                "regular": True,
                "owner_uid": os.getuid(),
                "link_count": 1,
                "mode_octal": "0400",
                "bytes": size,
                "sha256": digest,
                "stable_during_observation": True,
                "error": None,
            }

        healthy = [
            observed("/source/a", 3, "aa" * 32),
            observed("/source/b", 4, "bb" * 32),
        ]
        self.assertEqual(target._source_member_drift(expected, healthy), [])

        hostile = [copy.deepcopy(healthy[0])]
        hostile[0]["bytes"] = 2
        hostile[0]["sha256"] = "cc" * 32
        hostile[0]["stable_during_observation"] = False
        hostile[0]["symlink"] = True
        hostile.append(observed("/source/extra", 1, "dd" * 32))
        drift = target._source_member_drift(expected, hostile)
        by_path = {item["path"]: item["reasons"] for item in drift}
        self.assertIn("member-size-drift", by_path["/source/a"])
        self.assertIn("member-content-drift", by_path["/source/a"])
        self.assertIn("member-raced", by_path["/source/a"])
        self.assertIn("symlink-member", by_path["/source/a"])
        self.assertEqual(by_path["/source/b"], ["missing-member"])
        self.assertEqual(by_path["/source/extra"], ["unexpected-member"])

    def test_unreviewed_bundle_path_can_never_clear_historical_gate(self):
        with tempfile.TemporaryDirectory(prefix="w1-unbound-bundle-") as temporary:
            with mock.patch.object(
                target, "HISTORICAL_SOURCE_BUNDLE_ROOT", Path(temporary)
            ):
                value = target.component_source_diagnostics()
        bundle = value["historical_source_bundle"]
        self.assertTrue(bundle["exists"])
        self.assertTrue(bundle["directory"])
        self.assertEqual(
            bundle["receipt_sha256_bound_by_this_source"],
            target.HISTORICAL_RECEIPT_SHA256,
        )
        self.assertFalse(bundle["accepted_by_this_source"])
        self.assertFalse(value["ready_for_exact_component_validation"])
        self.assertIn(
            "immutable-historical-source-bundle-invalid",
            [item["code"] for item in value["blockers"]],
        )

    def test_invalid_historical_bundle_stops_before_component_reads(self):
        with mock.patch.object(
            target,
            "validate_historical_source_bundle",
            side_effect=target.Refused("forced-historical-refusal"),
        ), mock.patch.object(
            target,
            "validate_frozen_component_descriptors",
            side_effect=AssertionError("must-not-run"),
        ), mock.patch.object(
            target,
            "rerun_component_validator",
            side_effect=AssertionError("must-not-run"),
        ):
            value, exit_code = target.validate_components_report()
        self.assertEqual(exit_code, 1)
        self.assertEqual(value["status"], "COMPONENT_SOURCE_BINDING_BLOCKED")
        self.assertFalse(value["relation_satisfaction_checked"])
        self.assertFalse(value["pk_opened"])
        self.assertFalse(value["proof"])
        self.assertFalse(value["stage_08"])
        self.assertFalse(any(value["actions_performed"].values()))

    def test_exact_historical_bundle_and_component_content_validate_without_authority(self):
        value, exit_code = target.validate_components_report()
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            value["status"], "EXACT_COMPONENT_CONTENT_VALID_NO_PROOF_AUTHORITY"
        )
        self.assertTrue(value["validation"]["historical_source_bundle_validated"])
        self.assertFalse(value["validation"]["legacy_live_source_validator_run"])
        self.assertFalse(value["relation_satisfaction_checked"])
        self.assertFalse(value["pk_opened"])
        self.assertFalse(value["proof"])
        self.assertFalse(value["stage_08"])
        self.assertFalse(value["authorization"])

    def test_historical_receipt_semantic_mutation_refuses(self):
        root = target.HISTORICAL_SOURCE_BUNDLE_ROOT
        manifest = json.loads((root / "MANIFEST.json").read_bytes())
        receipt = json.loads((root / "TRANSFORMATION-RECEIPT.json").read_bytes())
        plan = json.loads((root / "PLAN.json").read_bytes())
        owner = json.loads((root / "OWNER-AUX-SOURCE-CLOSURE.json").read_bytes())
        target._validate_historical_documents(manifest, receipt, plan, owner)
        for mutation in ("current-source", "extra-field", "member-snapshot"):
            hostile_manifest = copy.deepcopy(manifest)
            hostile_receipt = copy.deepcopy(receipt)
            if mutation == "current-source":
                hostile_receipt["current_source"] = True
            elif mutation == "extra-field":
                hostile_receipt["unreviewed"] = True
            else:
                hostile_manifest["members"][0]["snapshot"]["sha256"] = "00" * 32
            with self.subTest(mutation=mutation), self.assertRaises(target.Refused):
                target._validate_historical_documents(
                    hostile_manifest, hostile_receipt, plan, owner
                )

    def test_validate_components_cli_returns_one_structured_success_record(self):
        result = subprocess.run(
            [sys.executable, str(Path(target.__file__)), "validate-components"],
            capture_output=True,
            text=True,
            check=False,
            env={"LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.strip().splitlines()), 1)
        value = json.loads(result.stdout)
        self.assertEqual(
            value["status"], "EXACT_COMPONENT_CONTENT_VALID_NO_PROOF_AUTHORITY"
        )
        self.assertFalse(any(value["actions_performed"].values()))
        self.assertFalse(value["authorization"])
        self.assertEqual(
            value["validation"]["historical_source_bundle_validated"], True
        )

    def test_source_closure_plan_is_complete_separate_and_inert(self):
        value = target.source_closure_plan()
        self.assertFalse(value["execution_enabled"])
        self.assertFalse(value["exact_command_ready"])
        self.assertFalse(value["authorization"])
        self.assertFalse(any(value["actions_performed"].values()))
        historical = value["historical_component_validation"]
        current = value["fresh_assignment_and_prover_source"]
        self.assertEqual(len(historical["source_members"]), 81)
        self.assertEqual(historical["complete_sealed_plan_member_bytes"], 143_536_017)
        self.assertTrue(historical["required_receipt_flags"]["historical_reconstructed_nonfinal"])
        self.assertFalse(historical["required_receipt_flags"]["current_source"])
        self.assertFalse(historical["required_receipt_flags"]["build_reproduced"])
        self.assertEqual(historical["receipt_sha256"], target.HISTORICAL_RECEIPT_SHA256)
        self.assertTrue(historical["accepted_by_current_source"])
        self.assertTrue(current["waiting_for_assignment_preparer_final_hash"])
        self.assertIsNone(current["assignment_preparer_final_sha256"])
        self.assertNotEqual(historical["bundle_root"], current["bundle_root"])
        self.assertIn(
            "rehash-same-snapshot-inodes-before-and-after-build",
            current["requirements"],
        )
        self.assertIn(
            "refuse-missing-extra-mutated-or-raced-members",
            current["requirements"],
        )
        self.assertTrue(
            all(not item["may_execute_now"] for item in value["planned_command_path"])
        )
        resources = value["resource_evidence"]
        self.assertEqual(resources["retained_component_total_wall_seconds"], 107.45)
        self.assertEqual(resources["retained_component_peak_rss_kib"], 157_104)
        self.assertFalse(resources["fresh_owner_aux_build_bound_present"])
        self.assertFalse(resources["proof_peak_rss_measured"])
        self.assertFalse(resources["wall_timeout_allowed"])


class SupervisorControls(AttemptCase):
    def test_private_create_new_plan_binds_exact_w1_without_authority(self):
        attempt_id = str(uuid.uuid4())
        attempt = target._allocate_attempt(self.parent, attempt_id)
        self.attempts.append(attempt)
        self.assertEqual(stat.S_IMODE(attempt.root.stat().st_mode), 0o700)
        plan_path = attempt.root / "ATTEMPT-PLAN.json"
        self.assertEqual(stat.S_IMODE(plan_path.stat().st_mode), 0o400)
        self.assertEqual(
            stat.S_IMODE((attempt.root / "TERMINAL.partial").stat().st_mode),
            0o600,
        )
        self.assertEqual(
            stat.S_IMODE(
                (attempt.root / "TERMINAL-FALLBACK.partial").stat().st_mode
            ),
            0o400,
        )
        plan = json.loads(plan_path.read_bytes())
        self.assertEqual(plan["selected_round"], 1)
        self.assertEqual(plan["sealed_preflight"]["sha256"], target.PREFLIGHT_SHA256)
        self.assertEqual(
            plan["w1_source"]["checkpoint_sha256"],
            [digest for _, digest in target.CHECKPOINTS],
        )
        self.assertEqual(
            plan["w1_source"]["source_closure_sha256"],
            target.W1_SOURCE_CLOSURE_SHA256,
        )
        self.assertEqual(
            plan["exact_relation"]["public_inputs_decimal"],
            list(target.ROUND_1_PUBLIC_INPUTS_DECIMAL),
        )
        self.assertEqual(
            plan["exact_relation"]["standard_r1cs_sha256"],
            target.STANDARD_R1CS_SHA256,
        )
        self.assertEqual(
            plan["historical_parameters"]["compressed_pk_sha256"],
            target.COMPRESSED_PK_SHA256,
        )
        self.assertFalse(plan["exact_relation"]["relation_satisfaction_checked"])
        self.assertFalse(plan["historical_parameters"]["pk_opened"])
        self.assertFalse(plan["candidate_prover"]["present"])
        self.assertFalse(plan["candidate_prover"]["typed_pk_authority_present"])
        self.assertFalse(plan["candidate_prover"]["internal_osrng_enforced"])
        self.assertFalse(plan["candidate_prover"]["caller_randomness_entry_present"])
        self.assertFalse(plan["source_owned_assignment_bridge_present"])
        self.assertFalse(any(plan["actions"].values()))
        self.assertFalse(plan["authorization"])
        with self.assertRaises(FileExistsError):
            target._allocate_attempt(self.parent, attempt_id)

    def test_self_consistent_plan_identity_mutations_all_refuse_recovery(self):
        mutations = (
            (("w1_source", "run_id"), "mutated-run"),
            (("w1_source", "source_instance_epoch_id"), str(uuid.uuid4())),
            (("w1_source", "selected_build_identity_sha256"), "11" * 32),
            (("exact_relation", "round_1_effects_sha256"), "22" * 32),
            (("exact_relation", "rows"), target.ROWS - 1),
            (("historical_parameters", "decoded_pk_sha256"), "33" * 32),
            (
                ("historical_parameters", "required_query_shape", "a_query"),
                target.QUERY_SHAPE["a_query"] - 1,
            ),
        )
        for path, replacement in mutations:
            with self.subTest(path=path):
                attempt = self.attempt()
                plan = json.loads(
                    (attempt.root / "ATTEMPT-PLAN.json").read_bytes()
                )
                mutated = copy.deepcopy(plan)
                selected = mutated
                for key in path[:-1]:
                    selected = selected[key]
                selected[path[-1]] = replacement
                mutated.pop("attempt_identity_sha256")
                mutated["attempt_identity_sha256"] = target._attempt_identity(
                    mutated
                )
                os.unlink("ATTEMPT-PLAN.json", dir_fd=attempt.directory_fd)
                target._create_sealed_at(
                    attempt.directory_fd,
                    "ATTEMPT-PLAN.json",
                    target.canonical(mutated),
                )
                root = attempt.root
                attempt.close()
                with self.assertRaises(target.Refused):
                    target._recover_control_attempt(root)

    def test_public_inputs_are_exact_effects_digest_limbs(self):
        digest = bytes.fromhex(target.ROUND_1_EFFECTS_SHA256)
        observed = (
            str(int.from_bytes(digest[:16], "little")),
            str(int.from_bytes(digest[16:], "little")),
        )
        self.assertEqual(observed, target.ROUND_1_PUBLIC_INPUTS_DECIMAL)

    def test_non_private_parent_and_symlink_parent_refuse(self):
        bad = Path(self.temporary.name) / "bad"
        bad.mkdir(mode=0o755)
        with self.assertRaises(target.Refused):
            target._allocate_attempt(bad, str(uuid.uuid4()))
        actual = Path(self.temporary.name) / "actual"
        actual.mkdir(mode=0o700)
        alias = Path(self.temporary.name) / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(target.Refused):
            target._allocate_attempt(alias, str(uuid.uuid4()))

    def test_child_api_has_no_command_path_name_digest_or_public_input(self):
        signature = inspect.signature(target._test_only_run_inert_child)
        self.assertEqual(list(signature.parameters), ["attempt", "phase", "behavior"])
        attempt = self.attempt()
        with self.assertRaises(TypeError):
            target._test_only_run_inert_child(
                attempt,
                "prepare",
                "prepare-ok",
                "/tmp/attacker",
            )
        with self.assertRaises(target.Refused):
            target._test_only_run_inert_child(attempt, "prepare", "../escape")

    def test_prepare_control_is_fsynced_read_only_and_one_use(self):
        attempt = self.attempt()
        child, receipt = self.prepare(attempt)
        for name in (
            "CONTROL-PREPARED-BYTES.bin",
            "CONTROL-PREPARE.stdout",
            "CONTROL-PREPARE.stderr",
            "CONTROL-PREPARE-RECEIPT.json",
        ):
            self.assertEqual(stat.S_IMODE((attempt.root / name).stat().st_mode), 0o400)
        self.assertFalse(receipt["relation_satisfaction_checked"])
        self.assertFalse(receipt["query_shape_checked"])
        self.assertFalse(receipt["pk_opened"])
        self.assertFalse(receipt["pk_decode"])
        self.assertFalse(receipt["production_resume_eligible"])
        self.assertFalse(receipt["receipt_is_authority"])
        self.assertFalse(receipt["proof"])
        self.assertFalse(child["production_artifact"])
        target._test_only_consume_prepare_control_once(attempt)
        self.assertFalse((attempt.root / "CONTROL-PREPARE-RECEIPT.json").exists())
        self.assertTrue(
            (attempt.root / "CONTROL-PREPARE-RECEIPT.CONSUMED.json").is_file()
        )
        ready = json.loads((attempt.root / "CONTROL-PROVE-READY.json").read_bytes())
        self.assertTrue(ready["control_only"])
        self.assertFalse(ready["ark_prover_entered"])
        with self.assertRaises(target.Refused):
            target._test_only_consume_prepare_control_once(attempt)

    def test_nonzero_signal_wrong_output_oom_log_overflow_and_exec_failure_quarantine(self):
        cases = (
            ("exit-nonzero", [4, 4], None),
            ("signal-term", [4, 4], None),
            ("wrong-output", [4, 4], None),
            ("prepare-ok", [4, 5], None),
            ("stdout-overflow", [4, 4], None),
            ("prepare-ok", [4], OSError("exec refused")),
        )
        for behavior, oom_values, run_error in cases:
            attempt = self.attempt()
            run_patch = (
                mock.patch.object(target.subprocess, "run", side_effect=run_error)
                if run_error is not None
                else mock.patch.object(target.subprocess, "run", wraps=subprocess.run)
            )
            with (
                self.subTest(behavior=behavior, run_error=run_error),
                mock.patch.object(target, "_oom_kill_count", side_effect=oom_values),
                run_patch,
                self.assertRaises(target.Refused),
            ):
                target._test_only_run_inert_child(attempt, "prepare", behavior)
            self.assertTrue(attempt.terminal)
            self.assertTrue((attempt.root / "TERMINAL.json").is_file())
            terminal = self.terminal(attempt)
            self.assertEqual(
                terminal["outcome"], "QUARANTINED_FRESH_ATTEMPT_REQUIRED"
            )
            self.assertFalse(terminal["canonical_proof_published"])
            self.assertFalse(terminal["canonical_stage_08_created"])
            self.assertFalse(terminal["ark_prover_entered"])
            self.assertFalse((attempt.root / "PROOF.bin").exists())
            if (attempt.root / "CONTROL-PREPARE.stdout").exists():
                self.assertLessEqual(
                    (attempt.root / "CONTROL-PREPARE.stdout").stat().st_size,
                    target.MAX_CONTROL_LOG_BYTES,
                )
            with self.assertRaises(target.Refused):
                target._test_only_run_inert_child(attempt, "prepare", "prepare-ok")

    def test_child_cannot_replace_output_by_relative_path(self):
        attempt = self.attempt()
        with (
            mock.patch.object(target, "_oom_kill_count", side_effect=[0, 0]),
            self.assertRaises(target.Refused),
        ):
            target._test_only_run_inert_child(attempt, "prepare", "path-attack")
        self.assertTrue(attempt.terminal)
        marker = json.loads(
            (attempt.root / "CONTROL-PREPARE-ENTERED.json").read_bytes()
        )
        self.assertFalse(marker["attempt_directory_fd_passed_to_child"])
        self.assertFalse(marker["cwd_is_attempt_directory"])
        self.assertTrue(marker["output_name_not_passed_to_child"])
        self.assertFalse((attempt.root / "CONTROL-PREPARED-BYTES.bin").exists())

    def test_canonical_control_collision_quarantines_without_overwrite(self):
        attempt = self.attempt()
        child = self.child(attempt, "prepare", "prepare-ok")
        target._create_sealed_at(
            attempt.directory_fd,
            "CONTROL-PREPARED-BYTES.bin",
            b"substitute",
        )
        with self.assertRaises(target.Refused):
            target._test_only_publish_prepare_control(attempt, child)
        self.assertTrue(attempt.terminal)
        self.assertEqual(
            (attempt.root / "CONTROL-PREPARED-BYTES.bin").read_bytes(),
            b"substitute",
        )
        self.assertEqual(self.terminal(attempt)["phase"], "prepare-publication")

    def test_post_child_fsync_or_reopen_failure_is_terminal(self):
        attempt = self.attempt()
        with (
            mock.patch.object(target, "_oom_kill_count", side_effect=[0, 0]),
            mock.patch.object(
                target,
                "_seal_control_fd",
                side_effect=OSError("injected-post-child-failure"),
            ),
            self.assertRaises(target.Refused),
        ):
            target._test_only_run_inert_child(attempt, "prepare", "prepare-ok")
        self.assertTrue(attempt.terminal)
        self.assertEqual(self.terminal(attempt)["phase"], "prepare-postprocess")

    def test_post_consume_marker_failure_is_durable_terminal(self):
        attempt = self.attempt()
        self.prepare(attempt)
        target._create_sealed_at(
            attempt.directory_fd,
            "CONTROL-PROVE-READY.json",
            b"collision",
        )
        with self.assertRaises(target.Refused):
            target._test_only_consume_prepare_control_once(attempt)
        self.assertTrue(attempt.terminal)
        self.assertFalse(attempt.prepare_consumed)
        self.assertTrue(
            (attempt.root / "CONTROL-PREPARE-RECEIPT.CONSUMED.json").is_file()
        )
        self.assertEqual(self.terminal(attempt)["phase"], "resume")
        root = attempt.root
        attempt.close()
        recovered = self.recover(root)
        self.assertTrue(recovered.terminal)

    def test_prepare_and_post_consume_states_recover_without_fake_mid_ark_resume(self):
        prepared = self.attempt()
        self.prepare(prepared)
        prepared_root = prepared.root
        prepared.close()
        resumed_prepare = self.recover(prepared_root)
        self.assertFalse(resumed_prepare.terminal)
        self.assertFalse(resumed_prepare.prepare_consumed)
        target._test_only_consume_prepare_control_once(resumed_prepare)
        resumed_prepare.close()
        resumed_prove = self.recover(prepared_root)
        self.assertFalse(resumed_prove.terminal)
        self.assertTrue(resumed_prove.prepare_consumed)
        self.assertFalse(
            json.loads(
                (prepared_root / "CONTROL-PROVE-READY.json").read_bytes()
            )["ark_prover_entered"]
        )

    def test_ambiguous_entered_state_crash_recovers_to_quarantine(self):
        attempt = self.attempt()
        target._create_sealed_at(
            attempt.directory_fd,
            "CONTROL-PREPARE-ENTERED.json",
            target.canonical(
                {
                    "schema": "injected-crash/v1",
                    "attempt_id": attempt.attempt_id,
                }
            ),
        )
        root = attempt.root
        attempt.close()
        recovered = self.recover(root)
        self.assertTrue(recovered.terminal)
        self.assertEqual(self.terminal(recovered)["phase"], "crash-recovery")

    def test_tampered_prepared_state_recovers_to_durable_quarantine(self):
        attempt = self.attempt()
        self.prepare(attempt)
        os.unlink("CONTROL-PREPARED-BYTES.bin", dir_fd=attempt.directory_fd)
        target._create_sealed_at(
            attempt.directory_fd,
            "CONTROL-PREPARED-BYTES.bin",
            b"tampered-control-bytes",
        )
        root = attempt.root
        attempt.close()
        recovered = self.recover(root)
        self.assertTrue(recovered.terminal)
        terminal = self.terminal(recovered)
        self.assertEqual(terminal["phase"], "crash-recovery")
        self.assertEqual(terminal["result"]["state"], "prepared")

    def test_written_terminal_partial_is_completed_during_recovery(self):
        attempt = self.attempt()
        record = {
            "schema": "kpb-offline-w1-aggregate-control-terminal/v2",
            "attempt_id": attempt.attempt_id,
            "outcome": "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
            "phase": "injected-recovery-control",
            "result": {"injected": True},
            "fresh_attempt_required": True,
            "mid_ark_resume_supported": False,
            "ark_prover_entered": False,
            "pk_opened": False,
            "canonical_proof_published": False,
            "canonical_stage_08_created": False,
            "authorization": False,
        }
        record["terminal_identity_sha256"] = target.sha256_bytes(
            target.canonical(record)
        )
        raw = target.canonical(record)
        target._write_all(attempt.terminal_fd, raw)
        os.fsync(attempt.terminal_fd)
        root = attempt.root
        attempt.close()
        recovered = self.recover(root)
        self.assertTrue(recovered.terminal)
        self.assertTrue((root / "TERMINAL.json").is_file())
        self.assertFalse((root / "TERMINAL.partial").exists())

    def test_terminal_dual_link_crash_window_completes_by_inode(self):
        attempt = self.attempt()
        record = target._terminal_value(
            attempt.attempt_id,
            "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
            "injected-dual-link-window",
            {"injected": True},
        )
        raw = target.canonical(record)
        target._write_all(attempt.terminal_fd, raw)
        os.fsync(attempt.terminal_fd)
        os.fchmod(attempt.terminal_fd, 0o400)
        os.fsync(attempt.terminal_fd)
        os.link(
            "TERMINAL.partial",
            "TERMINAL.json",
            src_dir_fd=attempt.directory_fd,
            dst_dir_fd=attempt.directory_fd,
            follow_symlinks=False,
        )
        target._fsync_directory(attempt.directory_fd)
        self.assertEqual((attempt.root / "TERMINAL.json").stat().st_nlink, 2)
        root = attempt.root
        attempt.close()
        recovered = self.recover(root)
        self.assertTrue(recovered.terminal)
        self.assertFalse((root / "TERMINAL.partial").exists())
        self.assertFalse((root / "TERMINAL-FALLBACK.partial").exists())
        self.assertEqual((root / "TERMINAL.json").stat().st_nlink, 1)

    def test_post_commit_primary_and_fallback_both_final_is_dominant_stop(self):
        attempt = self.attempt()
        original = target._publish_noreplace_at

        def commit_then_fail(directory_fd, partial, final):
            original(directory_fd, partial, final)
            if final == "TERMINAL.json":
                raise OSError("injected-after-primary-commit")

        with (
            mock.patch.object(
                target,
                "_publish_noreplace_at",
                side_effect=commit_then_fail,
            ),
            self.assertRaises(target.Refused),
        ):
            target._terminal(
                attempt,
                "CONTROL_COMPLETE_NO_PROOF",
                "injected-primary-success",
                {"injected": True},
            )
        self.assertTrue((attempt.root / "TERMINAL.json").is_file())
        self.assertTrue((attempt.root / "TERMINAL-FALLBACK.json").is_file())
        primary = json.loads((attempt.root / "TERMINAL.json").read_bytes())
        self.assertEqual(primary["outcome"], "CONTROL_COMPLETE_NO_PROOF")
        self.assertEqual(
            attempt.terminal_outcome,
            "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
        )
        root = attempt.root
        attempt.close()
        recovered = self.recover(root)
        self.assertEqual(
            recovered.terminal_outcome,
            "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
        )
        self.assertEqual(
            recovered.terminal_record_name,
            "TERMINAL-FALLBACK.json",
        )

    def test_invalid_primary_final_publishes_fallback_stop_and_is_retained(self):
        attempt = self.attempt()
        target._create_sealed_at(
            attempt.directory_fd,
            "TERMINAL.json",
            b"malformed-primary-terminal",
        )
        root = attempt.root
        attempt.close()
        recovered = self.recover(root)
        self.assertTrue(recovered.terminal)
        self.assertEqual(
            recovered.terminal_outcome,
            "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
        )
        self.assertEqual(
            recovered.terminal_record_name,
            "TERMINAL-FALLBACK.json",
        )
        self.assertEqual(
            (root / "TERMINAL.json").read_bytes(),
            b"malformed-primary-terminal",
        )
        self.assertTrue((root / "TERMINAL-FALLBACK.json").is_file())

    def test_terminal_publication_fault_windows_all_recover_to_fallback_stop(self):
        windows = (
            "post-link",
            "post-link-fsync",
            "post-unlink",
            "post-unlink-fsync",
            "post-reopen",
        )
        for window in windows:
            with self.subTest(window=window):
                attempt = self.attempt()
                target._arm_fallback_terminal(attempt)
                primary = target._terminal_value(
                    attempt.attempt_id,
                    "CONTROL_COMPLETE_NO_PROOF",
                    "injected-publication-window",
                    {"window": window},
                )
                raw = target.canonical(primary)
                target._write_all(attempt.terminal_fd, raw)
                os.fsync(attempt.terminal_fd)
                os.fchmod(attempt.terminal_fd, 0o400)
                os.fsync(attempt.terminal_fd)
                os.link(
                    "TERMINAL.partial",
                    "TERMINAL.json",
                    src_dir_fd=attempt.directory_fd,
                    dst_dir_fd=attempt.directory_fd,
                    follow_symlinks=False,
                )
                if window != "post-link":
                    target._fsync_directory(attempt.directory_fd)
                if window in (
                    "post-unlink",
                    "post-unlink-fsync",
                    "post-reopen",
                ):
                    os.unlink("TERMINAL.partial", dir_fd=attempt.directory_fd)
                if window in ("post-unlink-fsync", "post-reopen"):
                    target._fsync_directory(attempt.directory_fd)
                if window == "post-reopen":
                    fd = os.open(
                        "TERMINAL.json",
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=attempt.directory_fd,
                    )
                    os.close(fd)
                root = attempt.root
                attempt.close()
                recovered = self.recover(root)
                self.assertEqual(
                    recovered.terminal_outcome,
                    "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
                )
                self.assertEqual(
                    recovered.terminal_record_name,
                    "TERMINAL-FALLBACK.json",
                )

    def test_torn_primary_terminal_recovers_to_typed_fallback_quarantine(self):
        attempt = self.attempt()
        target._write_all(attempt.terminal_fd, b'{"torn":')
        os.fsync(attempt.terminal_fd)
        root = attempt.root
        attempt.close()
        recovered = self.recover(root)
        self.assertTrue(recovered.terminal)
        fallback_path = root / "TERMINAL-FALLBACK.json"
        self.assertTrue(fallback_path.is_file())
        fallback = json.loads(fallback_path.read_bytes())
        self.assertEqual(
            fallback["schema"],
            "kpb-offline-w1-aggregate-control-terminal/v2",
        )
        self.assertEqual(fallback["phase"], "preallocated-terminal-fallback")
        self.assertEqual(
            fallback["outcome"], "QUARANTINED_FRESH_ATTEMPT_REQUIRED"
        )
        self.assertFalse(fallback["canonical_proof_published"])
        self.assertFalse(fallback["canonical_stage_08_created"])

    def test_self_hashed_terminal_semantic_mutations_use_typed_fallback(self):
        mutations = (
            ("fresh-equation", lambda value: value.__setitem__(
                "fresh_attempt_required", False
            )),
            ("extra-key", lambda value: value.__setitem__("extra", False)),
            ("missing-key", lambda value: value.pop("pk_opened")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                attempt = self.attempt()
                record = target._terminal_value(
                    attempt.attempt_id,
                    "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
                    "mutated-terminal-control",
                    {"mutation": label},
                )
                mutate(record)
                record.pop("terminal_identity_sha256")
                record["terminal_identity_sha256"] = target.sha256_bytes(
                    target.canonical(record)
                )
                target._write_all(attempt.terminal_fd, target.canonical(record))
                os.fsync(attempt.terminal_fd)
                root = attempt.root
                attempt.close()
                recovered = self.recover(root)
                self.assertTrue(recovered.terminal)
                fallback = json.loads(
                    (root / "TERMINAL-FALLBACK.json").read_bytes()
                )
                self.assertEqual(
                    fallback["phase"], "preallocated-terminal-fallback"
                )
                self.assertEqual(
                    fallback["outcome"],
                    "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
                )

    def test_primary_terminal_write_or_fsync_failure_uses_typed_fallback(self):
        for failure in ("write", "fsync"):
            with self.subTest(failure=failure):
                attempt = self.attempt()
                if failure == "write":
                    original = target._write_all
                    calls = 0

                    def fail_once(fd, raw):
                        nonlocal calls
                        calls += 1
                        if calls == 1:
                            raise OSError("injected-primary-write-failure")
                        return original(fd, raw)

                    patcher = mock.patch.object(
                        target, "_write_all", side_effect=fail_once
                    )
                else:
                    original = target.os.fsync
                    calls = 0

                    def fail_once(fd):
                        nonlocal calls
                        calls += 1
                        if calls == 1:
                            raise OSError("injected-primary-fsync-failure")
                        return original(fd)

                    patcher = mock.patch.object(
                        target.os, "fsync", side_effect=fail_once
                    )
                with patcher, self.assertRaises(target.Refused):
                    target._quarantine(
                        attempt,
                        "injected-primary-terminal-failure",
                        {"failure": failure},
                    )
                self.assertTrue(attempt.terminal)
                fallback_path = attempt.root / "TERMINAL-FALLBACK.json"
                self.assertTrue(fallback_path.is_file())
                fallback = json.loads(fallback_path.read_bytes())
                self.assertEqual(
                    fallback["phase"], "preallocated-terminal-fallback"
                )
                self.assertEqual(
                    fallback["outcome"],
                    "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
                )
                self.assertFalse(fallback["canonical_proof_published"])

    def test_terminal_record_or_canonical_allocation_failure_uses_presealed_fallback(self):
        for failure in ("record", "canonical"):
            with self.subTest(failure=failure):
                attempt = self.attempt()
                if failure == "record":
                    patcher = mock.patch.object(
                        target,
                        "_terminal_value",
                        side_effect=MemoryError("injected-record-allocation"),
                    )
                else:
                    patcher = mock.patch.object(
                        target,
                        "canonical",
                        side_effect=MemoryError("injected-canonical-allocation"),
                    )
                with patcher, self.assertRaises(target.Refused):
                    target._terminal(
                        attempt,
                        "CONTROL_COMPLETE_NO_PROOF",
                        "injected-allocation-failure",
                        {"failure": failure},
                    )
                self.assertTrue(attempt.terminal)
                self.assertEqual(
                    attempt.terminal_outcome,
                    "QUARANTINED_FRESH_ATTEMPT_REQUIRED",
                )
                self.assertEqual(
                    attempt.terminal_record_name,
                    "TERMINAL-FALLBACK.json",
                )
                fallback = json.loads(
                    (attempt.root / "TERMINAL-FALLBACK.json").read_bytes()
                )
                self.assertEqual(
                    fallback,
                    target._preallocated_fallback_value(attempt.attempt_id),
                )

    def test_successful_control_never_publishes_proof_or_stage08(self):
        attempt = self.attempt()
        self.prepare(attempt)
        target._test_only_consume_prepare_control_once(attempt)
        child = self.child(attempt, "prove", "prove-ok")
        receipt = target._test_only_evaluate_verification_control(
            attempt, child, "accepted-valid-control"
        )
        self.assertTrue(attempt.terminal)
        self.assertTrue((attempt.root / "CONTROL-VERIFIED-BYTES.bin").is_file())
        self.assertTrue((attempt.root / "CONTROL-VERIFICATION-RESULT.json").is_file())
        self.assertFalse(receipt["production_independent_verification"])
        self.assertFalse(receipt["proof_generated"])
        self.assertFalse(receipt["canonical_proof_published"])
        self.assertFalse(receipt["canonical_stage_08_created"])
        for forbidden in (
            "PROOF.bin",
            "PROOF-RESULT.json",
            "PREPARE-RECEIPT.json",
            "ARK-PROVER-ENTERED.json",
        ):
            self.assertFalse((attempt.root / forbidden).exists(), forbidden)
        terminal = self.terminal(attempt)
        self.assertEqual(terminal["outcome"], "CONTROL_COMPLETE_NO_PROOF")
        self.assertFalse(terminal["canonical_proof_published"])
        self.assertFalse(terminal["canonical_stage_08_created"])

    def test_accepted_invalid_controls_are_fatal_and_publish_no_proof(self):
        for outcome in (
            "accepted-wrong-input-control",
            "accepted-mutated-control",
        ):
            attempt = self.attempt()
            self.prepare(attempt)
            target._test_only_consume_prepare_control_once(attempt)
            child = self.child(attempt, "prove", "prove-ok")
            with self.assertRaises(target.Refused):
                target._test_only_evaluate_verification_control(
                    attempt, child, outcome
                )
            self.assertTrue(attempt.terminal)
            terminal = self.terminal(attempt)
            self.assertEqual(terminal["phase"], "fatal-invalid-acceptance")
            self.assertFalse((attempt.root / "PROOF.bin").exists())
            self.assertFalse(
                (attempt.root / "CONTROL-VERIFICATION-RESULT.json").exists()
            )

    def test_rejected_control_quarantines_and_has_no_boolean_overload(self):
        attempt = self.attempt()
        self.prepare(attempt)
        target._test_only_consume_prepare_control_once(attempt)
        child = self.child(attempt, "prove", "prove-ok")
        with self.assertRaises(target.Refused):
            target._test_only_evaluate_verification_control(
                attempt, child, "rejected-control"
            )
        self.assertEqual(self.terminal(attempt)["phase"], "verification")
        self.assertFalse((attempt.root / "PROOF.bin").exists())
        other = self.attempt()
        self.prepare(other)
        target._test_only_consume_prepare_control_once(other)
        other_child = self.child(other, "prove", "prove-ok")
        with self.assertRaises(target.Refused):
            target._test_only_evaluate_verification_control(
                other, other_child, True
            )

    def test_cli_has_no_prepare_prove_setup_bridge_or_stage08_command(self):
        result = subprocess.run(
            [sys.executable, str(Path(target.__file__)), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("status", result.stdout)
        self.assertIn("validate-components", result.stdout)
        for forbidden in (
            "prepare",
            "prove",
            "setup",
            "bridge",
            "stage-08",
            "finalize",
        ):
            self.assertNotIn("{" + forbidden, result.stdout)


if __name__ == "__main__":
    unittest.main()
