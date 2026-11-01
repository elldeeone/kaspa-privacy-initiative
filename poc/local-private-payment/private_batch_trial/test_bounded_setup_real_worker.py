import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid


HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[2]
WORKER_ROOT = HERE / "bounded_setup_worker"
ARTIFACT = (WORKER_ROOT / "target/x86_64-unknown-linux-musl/release/"
            "kpb-bounded-setup-worker")
CONTEXT = (WORKSPACE / ".local/private-batch-full-matrix-probe-20261028-01/"
           "PUBLIC-CONTEXT-HISTORY.json")
SIGNATURE = (WORKSPACE / ".local/registered-financial-relation-candidate-20261029/"
             "SIGNATURE-MATRIX.json")


class RealBoundedSetupWorkerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="kpb-real-bounded-setup-")
        cls.root = Path(cls.temporary.name)
        verification = subprocess.run(
            ["python3", "verify_static_worker.py", "--build"],
            cwd=WORKER_ROOT, check=True, capture_output=True, text=True,
            timeout=180)
        cls.verification = json.loads(verification.stdout.strip())
        cls.control = cls.root / "preflight-control"
        subprocess.run([
            "g++", "-std=c++20", "-O2", "-Wall", "-Wextra", "-Werror",
            "-pedantic", "-I", str(HERE),
            str(HERE / "bounded_setup_preflight_control.cpp"),
            str(HERE / "bounded_setup_authority.cpp"), "-lcrypto",
            "-o", str(cls.control),
        ], cwd=HERE, check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def scoped_preflight(self, root, output):
        return subprocess.run([
            "systemd-run", "--user", "--scope", "--quiet",
            f"--unit=kpb-real-setup-{uuid.uuid4().hex}",
            "-p", "MemorySwapMax=0", "-p", "MemoryMax=2G",
            str(self.control), str(root), str(output),
        ], cwd=HERE, capture_output=True, text=True, timeout=45)

    def test_static_worker_build_and_source_owned_selector(self):
        self.assertEqual(
            self.verification["worker_identity"],
            "5754490a8649fe9f287d3e3f7f40d3abcdcbc515afb39e8122b8dd17e6adcd0d")
        self.assertTrue(self.verification["source_closed_static_worker"])
        self.assertFalse(self.verification["setup_executed"])
        self.assertEqual(self.verification["resolved_local_packages"], 5)
        self.assertEqual(self.verification["local_source_files"], 50)
        self.assertEqual(self.verification["local_build_scripts"], 0)
        self.assertEqual(
            self.verification["local_source_closure_identity"],
            "04a809da7e8efbaa62a55972b23676df0f8e64d9ab136b2a9212ee5e4c7536d0")
        output = self.root / "real-preflight-output"
        output.mkdir(mode=0o700)
        result = self.scoped_preflight(WORKSPACE, output)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["worker_bytes"], 1745168)
        self.assertTrue(receipt["filesystem_headroom"])
        self.assertFalse(receipt["memory_bounded"])
        self.assertFalse(receipt["memory_headroom"])
        self.assertFalse(receipt["production_plan_selected"])
        self.assertFalse(receipt["full_setup_ready"])
        self.assertEqual(list(output.iterdir()), [])

    def test_worker_and_aggregate_input_substitution_are_refused(self):
        fake = self.root / "fake-workspace"
        worker = (fake / "poc/local-private-payment/private_batch_trial/"
                  "bounded_setup_worker/target/x86_64-unknown-linux-musl/"
                  "release/kpb-bounded-setup-worker")
        context = (fake / ".local/private-batch-full-matrix-probe-20261028-01/"
                   "PUBLIC-CONTEXT-HISTORY.json")
        signature = (fake / ".local/registered-financial-relation-candidate-20261029/"
                     "SIGNATURE-MATRIX.json")
        for path in (worker, context, signature):
            path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ARTIFACT, worker)
        shutil.copyfile(CONTEXT, context)
        shutil.copyfile(SIGNATURE, signature)
        output = self.root / "substitution-output"
        output.mkdir(mode=0o700)

        cases = ((worker, ARTIFACT), (context, CONTEXT),
                 (signature, SIGNATURE))
        for target, original in cases:
            body = bytearray(original.read_bytes())
            body[len(body) // 2] ^= 1
            target.write_bytes(body)
            result = self.scoped_preflight(fake, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bounded setup preflight refused", result.stderr)
            self.assertEqual(list(output.iterdir()), [])
            shutil.copyfile(original, target)

        worker.unlink()
        worker.symlink_to(ARTIFACT)
        result = self.scoped_preflight(fake, output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bounded setup preflight refused", result.stderr)
        self.assertEqual(list(output.iterdir()), [])

    def test_machine_plan_blocker_matches_authoritative_missing_report(self):
        blocker = json.loads((HERE / "bounded_setup_plan_blocker.json").read_text())
        missing = json.loads((HERE /
            "privacy_measurement_selected_parent_artifact_missing.json").read_text())
        self.assertEqual(blocker["status"], "BLOCKED")
        self.assertEqual(blocker["authoritative_inputs"]
                         ["missing_parent_artifacts"], missing["missing_count"])
        self.assertEqual(missing["missing_count"], 60)
        self.assertFalse(blocker["chronology"]["selected_parent_rows"]
                         ["pre_setup_independence_proven"])
        self.assertEqual(
            {row["field"] for row in blocker["chronology"]
             ["excluded_from_pre_setup_plan"]},
            {"projections[2]", "round_capture_plans[2]",
             "finite_manifest_identity",
             "finite_manifest_parent_recomputation_identity",
             "comparison_selection", "run_selection"})
        self.assertEqual(blocker["required_pre_setup_plan_fields"], [
            "trial", "financial_runs[2]", "round_attempts[2]",
            "round_cohorts[2]"])
        self.assertEqual(blocker["precommit_derivation"]["root"], "trial")
        self.assertFalse(blocker["precommit_derivation"]
                         ["generated_crs_identity_allowed"])
        self.assertFalse(blocker["precommit_derivation"]
                         ["crs_or_setup_output_input_allowed"])
        self.assertFalse(blocker["precommit_derivation"]
                         ["proof_projection_observer_or_post_run_input_allowed"])
        self.assertFalse(blocker["precommit_derivation"]
                         ["production_trial_root_authority_present"])
        self.assertFalse(blocker["precommit_derivation"]
                         ["existing_financial_lineage_join_implemented"])
        chronology = blocker["typed_chronology_handoff"]
        self.assertFalse(chronology["raw_digest_or_receipt_overload"])
        self.assertFalse(chronology[
            "current_fresh_owner_trial_issuance_eligible_pre_setup"])
        self.assertFalse(chronology[
            "current_w1_historical_vk_pins_accept_fresh_setup"])
        self.assertFalse(chronology["pre_setup_minter_implemented"])
        self.assertFalse(chronology["setup_launcher_callsite_implemented"])
        self.assertFalse(chronology["post_setup_join_implemented"])
        self.assertFalse(chronology["full_w1_or_capture_consumer_implemented"])
        self.assertEqual(
            blocker["circuit_closure_semantics"]["post_setup_outputs_only"],
            ["generated proving-key identity",
             "generated verifying-key identity", "setup artifact bytes"])
        self.assertFalse(blocker["source_owned_plan_selector"])
        self.assertFalse(blocker["full_setup_ready"])
        self.assertFalse(blocker["s4_selected"])
        self.assertFalse(blocker["s12_selected"])
        self.assertFalse(blocker["configured"])

    def test_build_contract_and_worker_digest_are_stable(self):
        contract = json.loads((WORKER_ROOT / "build_contract.json").read_text())
        self.assertEqual(len(ARTIFACT.read_bytes()),
                         contract["selected_worker"]["bytes"])
        self.assertEqual(hashlib.sha256(ARTIFACT.read_bytes()).hexdigest(),
                         contract["selected_worker"]["sha256"])
        closure = json.loads((WORKER_ROOT / "source_closure.json").read_text())
        self.assertEqual(closure["file_count"], 50)
        self.assertEqual(len(closure["resolved_local_packages"]), 5)
        self.assertEqual(closure["local_build_scripts"], [])
        self.assertEqual(closure["closure_identity"],
                         contract["local_source_closure"]["closure_identity"])
        self.assertFalse(contract["full_output_setup_executed"])
        self.assertFalse(contract["full_aggregate_setup_executed"])
        self.assertFalse(contract["erasure_cryptographically_proven"])
        self.assertFalse(contract["setup_honesty_cryptographically_proven"])


if __name__ == "__main__":
    unittest.main()
