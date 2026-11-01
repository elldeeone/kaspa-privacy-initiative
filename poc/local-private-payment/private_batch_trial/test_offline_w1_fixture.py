import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

import c1_capture_supervisor as c1
import offline_w1_fixture as fixture


def fresh():
    return str(uuid.uuid4())


class OfflineW1FixtureControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def leaf(self, name, raw=b"fixture"):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o400)
        return path

    def plan(self):
        profile = self.leaf("profile.json", b"profile\n")
        rehearsal = self.leaf("rehearsal.json", b"rehearsal\n")
        source = self.leaf("source.py", b"source\n")
        build = {"schema": "test-build", "build_identity_sha256": "11" * 32}
        rounds = []
        for number in (1, 2):
            rounds.append({
                "round": number,
                "input_attempt_id": fresh(),
                "invoice_operation_id": fresh(),
                "payment_operation_id": fresh(),
                "scan_operation_id": fresh(),
                "c1_capture_attempt_id": fresh(),
                "c1_capture_identity_id": fresh(),
                "c1_cohort_hex32": uuid.uuid4().hex * 2,
                "c1_financial_run_hex32": uuid.uuid4().hex * 2,
                "aggregate_attempt_id": fresh(),
            })
        value = {
            "schema": fixture.PLAN_SCHEMA,
            "classification": fixture.CLASSIFICATION,
            "label": "test",
            "run_id": fresh(),
            "source_instance_epoch_id": fresh(),
            "source_instance_epoch_is_authority": False,
            "owner_generation_ids": [fresh(), fresh(), fresh()],
            "rounds": rounds,
            "selected_build": build,
            "source_members": [fixture.ref(source)],
            "source_closure_sha256": "",
            "source_closure_derivation": {
                "python": "recursive-local-imports-plus-explicit-dynamic-and-subprocess-inputs",
                "rust": "cargo-link-dep-info-plus-package-manifests-locks-and-build-scripts",
                "validation_recomputes_exact_current_path_set_and_content": True,
            },
            "profile": fixture.ref(profile),
            "rehearsal": fixture.ref(rehearsal),
            "fixed_rewire": fixture.fixed_rewire(),
            "workload": {
                "fee_sompi_each": fixture.FEE,
                "rounds": [{"round": n, **fixture.ROUND_VALUES[n]} for n in (1, 2)],
                "genuine_transfer_output_proofs": 12,
                "genuine_signature_witnesses": 6,
                "required_aggregate_proofs": 2,
            },
            "stage_order": list(fixture.STAGES),
            "boundaries": {
                "network_enabled": False,
                "funding_or_real_funds": False,
                "backing_or_chain_acceptance": False,
                "old_setup_privacy_assumption_eligible": False,
                "historical_binary_matches_current_source_proven": False,
                "fixture_possession_authorizes_v4": False,
                "future_atomic_minter_must_consume_live_w0_c1_close_sources": True,
                "caller_digest_is_common_origin_authority": False,
                "aggregate_checkpoint_enabled": True,
                "aggregate_checkpoint_requires_pinned_in_process_verifier": True,
                "aggregate_proof_generation_authorized": False,
                "aggregate_pk_content_read_during_plan_selection": False,
                "handoff_requires_two_pinned_verifier_receipts": True,
            },
        }
        value["source_closure_sha256"] = fixture.sha(fixture.canonical(value["source_members"]))
        return value, build, fixture.sha(profile.read_bytes()), fixture.sha(rehearsal.read_bytes())

    def valid_c1(self, plan, round_number=1):
        attempt = plan["rounds"][round_number - 1]
        creator = 0 if round_number == 1 else 2
        outgoing_target = (1 + round_number) % 3
        records = []
        for owner in range(3):
            outputs = []
            for output_index in range(2):
                row = bytearray([40 + owner * 4 + output_index]) * 520
                ciphertext = bytes([90 + owner * 4 + output_index]) * 264
                row[96:360] = ciphertext
                row[360:392] = bytes.fromhex(fixture.sha(ciphertext))
                note = bytearray([120 + owner * 4 + output_index]) * 168
                note[104:136] = bytes([150 + owner * 4 + output_index]) * 32
                outputs.append({
                    "tuple_hex520": bytes(row).hex(),
                    "note_hex168": bytes(note).hex(),
                })
            records.append({
                "input": {"nf_hex32": bytes([10 + owner] * 32).hex()},
                "outputs": outputs,
            })
        operations = [attempt[name] for name in (
            "invoice_operation_id", "payment_operation_id", "scan_operation_id")]
        contacts = [creator, outgoing_target, creator]
        incoming = bytes.fromhex(records[creator]["outputs"][0]["tuple_hex520"])
        outgoing = bytes.fromhex(records[1]["outputs"][0]["tuple_hex520"])
        change = bytes.fromhex(records[1]["outputs"][1]["tuple_hex520"])
        incoming_note = bytes.fromhex(records[creator]["outputs"][0]["note_hex168"])
        change_note = bytes.fromhex(records[1]["outputs"][1]["note_hex168"])
        invoices = []
        for index, kind in enumerate(("issued-incoming", "accepted-outgoing")):
            raw = bytes([180 + index + round_number]) * 208
            invoices.append({
                "kind": kind,
                "source_operation_id": (attempt["invoice_operation_id"]
                    if index == 0 else attempt["payment_operation_id"]),
                "invoice_operation_id": attempt["invoice_operation_id"],
                "source_owner": 1 if index == 0 else outgoing_target,
                "target_owner": creator if index == 0 else 1,
                "invoice_index": 2 * round_number - 1,
                "value_sompi": fixture.ROUND_VALUES[round_number]["payment"][
                    creator if index == 0 else 1],
                "invoice_hex208": raw.hex(),
                "invoice_sha256": fixture.sha(raw),
            })
        projection = bytes([round_number]) * 10_685
        value = {
            "schema": "kpb-offline-w1-c1-residual/v2",
            "round": round_number,
            "c1_owner": 1,
            "capture_attempt_id": attempt["c1_capture_attempt_id"],
            "capture_attempt_hex32": fixture.capture_attempt_word(
                attempt["c1_capture_attempt_id"]),
            "capture_identity_id": attempt["c1_capture_identity_id"],
            "c1_cohort_hex32": attempt["c1_cohort_hex32"],
            "c1_financial_run_hex32": attempt["c1_financial_run_hex32"],
            "contact_value_authority_preimage": {},
            "contact_value_authority_preimage_sha256": "00" * 32,
            "contact_value_authority_was_live": False,
            "stages": [
                {"stage": stage, "operation_id": operation,
                 "operation_hex32": fixture.operation_word(operation),
                 "contact_owner": contact, "stage_config": {},
                 "stage_config_hex32": "00" * 32}
                for stage, operation, contact in zip(
                    ("invoice", "pay", "scan"), operations, contacts)
            ],
            "original": {
                "source_operation_id": attempt["payment_operation_id"],
                "source_operation_hex32": fixture.operation_word(
                    attempt["payment_operation_id"]),
                "input_nf_hex32": records[1]["input"]["nf_hex32"],
                "input_value_sompi": fixture.ROUND_VALUES[round_number]["input"][1],
                "created": [
                    {"kind": "outgoing-payment", "tuple_sha256": fixture.sha(outgoing),
                     "cm_hex32": outgoing[:32].hex(), "value_sompi":
                        fixture.ROUND_VALUES[round_number]["payment"][1]},
                    {"kind": "own-change", "tuple_sha256": fixture.sha(change),
                     "cm_hex32": change[:32].hex(), "value_sompi":
                        fixture.ROUND_VALUES[round_number]["change"][1]},
                ],
            },
            "invoices": invoices,
            "receipts": [
                {"kind": "decrypted-incoming",
                 "source_operation_id": attempt["scan_operation_id"],
                 "receipt_index": 2 * round_number - 1, "creator_owner": creator,
                 "tuple_sha256": fixture.sha(incoming),
                 "cm_hex32": incoming[:32].hex(),
                 "note_sha256": fixture.sha(incoming_note),
                 "value_sompi": fixture.ROUND_VALUES[round_number]["payment"][creator]},
                {"kind": "decrypted-own-change",
                 "source_operation_id": attempt["scan_operation_id"],
                 "receipt_index": 2 * round_number, "creator_owner": 1,
                 "tuple_sha256": fixture.sha(change),
                 "cm_hex32": change[:32].hex(),
                 "note_sha256": fixture.sha(change_note),
                 "value_sompi": fixture.ROUND_VALUES[round_number]["change"][1]},
            ],
            "incoming_key_commitment_hex32": incoming_note[104:136].hex(),
            "incoming_ciphertext_hex264": incoming[96:360].hex(),
            "retry_history_closed": True,
            "retries": [],
            "lineage": {},
            "manifest_or_digest_is_authority": False,
        }
        precursor = fixture.expected_c1_authority_preimage(value, plan)
        authority = fixture.c1_authority_preimage_word(precursor)
        value["contact_value_authority_preimage"] = precursor
        value["contact_value_authority_preimage_sha256"] = authority
        for sequence, row in enumerate(value["stages"]):
            row["stage_config"] = fixture.expected_stage_config(
                value, plan, sequence, authority)
            row["stage_config_hex32"] = fixture.stage_config_word(
                row["stage_config"])
        value["lineage"] = fixture.expected_c1_lineage(value, plan, projection)
        return records, value, projection

    def test_atomic_leaf_refuses_overwrite(self):
        path = self.root / "immutable.json"
        fixture.write_new(path, {"a": 1})
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            fixture.write_new(path, {"a": 2})
        self.assertEqual(path.read_bytes(), before)

    def test_atomic_stage_publish_refuses_existing_target(self):
        source = self.root / "source"
        target = self.root / "target"
        source.mkdir()
        target.mkdir()
        (source / "new").write_bytes(b"new")
        (target / "kept").write_bytes(b"kept")
        with self.assertRaises(FileExistsError):
            fixture.rename_no_replace(source, target)
        self.assertTrue(source.is_dir())
        self.assertEqual((target / "kept").read_bytes(), b"kept")

    def test_source_closure_excludes_outputs_and_includes_rust_bins(self):
        paths = fixture.source_paths()
        parts = [set(path.parts) for path in paths]
        self.assertTrue(all(not ({"target", "evidence", ".git"} & row)
                            for row in parts))
        relative = {str(path.relative_to(fixture.ROOT)) for path in paths
                    if path.is_relative_to(fixture.ROOT)}
        self.assertIn(
            "poc/local-private-payment/private-batch-relation/src/bin/owner_aux.rs",
            relative,
        )
        self.assertIn(
            "poc/local-private-payment/private-batch-relation/src/bin/owner_file_fr32/mod.rs",
            relative,
        )
        self.assertIn(
            "poc/local-private-payment/private_batch_trial/c1_capture_supervisor.py",
            relative,
        )
        self.assertIn(
            "poc/local-private-payment/private_batch_trial/offline_w1_components.py",
            relative,
        )
        self.assertIn(
            "poc/local-private-payment/private-batch-relation/examples/qualify_joint_core.rs",
            relative,
        )
        self.assertIn(
            "poc/local-private-payment/private-batch-relation/examples/support/public_fixture.rs",
            relative,
        )
        self.assertIn(
            "poc/local-private-payment/private-batch-relation/src/counterfactual_w1/offline_verifier.rs",
            relative,
        )
        self.assertIn(
            "poc/local-private-payment/private-batch-relation/examples/verify_offline_w1_aggregate.rs",
            relative,
        )
        self.assertIn(
            "poc/local-private-payment/private_batch_trial/freeze_offline_w1_rust_build.py",
            relative,
        )
        self.assertIn(
            "poc/local-private-payment/private_batch_trial/freeze_offline_w1_verifier_build.py",
            relative,
        )

    def test_current_owner_aux_build_bundle_is_independently_rederived(self):
        bundle = fixture.owner_aux_build_bundle()
        self.assertEqual(bundle["binary"]["sha256"],
                         fixture.OWNER_AUX_SHA)
        self.assertEqual(bundle["dep_info"]["sha256"],
                         fixture.OWNER_AUX_DEP_INFO_SHA)
        self.assertEqual(bundle["source_members_identity_sha256"],
                         fixture.OWNER_AUX_SOURCE_MEMBERS_SHA)
        self.assertTrue(bundle["current_source_build_reverified"])

    def test_plan_selection_does_not_read_aggregate_proving_key(self):
        original = fixture.sha_file

        def guarded(path):
            if Path(path) == fixture.AGGREGATE_PARAMETERS / "AGGREGATE-PK.bin.gz":
                self.fail("aggregate proving key was read during PLAN selection")
            return original(path)

        with mock.patch.object(fixture, "sha_file", side_effect=guarded):
            selected = fixture.selected_build()
        aggregate = selected["aggregate_feasibility_only"]
        self.assertFalse(aggregate[
            "proving_key_gzip_content_rehashed_during_selection"])
        self.assertEqual(aggregate["proving_key_gzip"]["sha256"],
                         fixture.AGGREGATE_PK_GZ_SHA)

    def test_prior_aggregate_revalidates_identity_chain_and_semantics(self):
        plan, _, _, _ = self.plan()
        predecessor_stage = "round-2-close"
        aggregate_stage = "round-1-aggregate"
        predecessor_directory = fixture.stage_path(self.root,
                                                   predecessor_stage)
        predecessor_directory.mkdir()
        predecessor_path = predecessor_directory / "CHECKPOINT.json"
        predecessor_path.write_bytes(b"immutable predecessor\n")
        predecessor_path.chmod(0o400)

        aggregate_directory = fixture.stage_path(self.root, aggregate_stage)
        aggregate_directory.mkdir()
        artifact_path = aggregate_directory / "projection.bin"
        artifact_path.write_bytes(b"verified projection")
        artifact_path.chmod(0o400)
        checkpoint = {
            "schema": fixture.CHECKPOINT_SCHEMA,
            "classification": fixture.CLASSIFICATION,
            "run_id": plan["run_id"],
            "source_instance_epoch_id": plan["source_instance_epoch_id"],
            "stage": aggregate_stage,
            "ordinal": fixture.STAGES.index(aggregate_stage) + 1,
            "previous": fixture.ref(predecessor_path),
            "artifacts": {"projection.bin": fixture.ref(artifact_path)},
            "facts": {"aggregate_proof_verified": True},
            "fixture_possession_authorizes_v4": False,
        }
        checkpoint["checkpoint_identity_sha256"] = fixture.sha(
            fixture.canonical(checkpoint))
        checkpoint_path = aggregate_directory / "CHECKPOINT.json"
        checkpoint_path.write_bytes(fixture.canonical(checkpoint))
        checkpoint_path.chmod(0o400)

        with mock.patch.object(fixture, "validate_checkpoint_semantics") as validate:
            admitted = fixture.validated_checkpoint_from_root(
                self.root, aggregate_stage, plan)
        validate.assert_called_once_with(admitted, plan)

        changed = json.loads(checkpoint_path.read_text())
        changed["facts"]["aggregate_proof_verified"] = False
        checkpoint_path.chmod(0o600)
        checkpoint_path.write_bytes(fixture.canonical(changed))
        checkpoint_path.chmod(0o400)
        with self.assertRaisesRegex(
                fixture.Refused,
                "validated-prior-checkpoint-self-identity"):
            fixture.validated_checkpoint_from_root(
                self.root, aggregate_stage, plan)

    def test_normalized_signature_witness_substitution_is_refused(self):
        signature_inputs = {
            "digestLimbs": ["0", "0"],
            "ownerKeyBytes": ["0"] * 64,
            "sigR8": ["0", "0"],
            "sigS": "0",
            "preimageA": ["0", "0"],
            "preimageR8": ["0", "0"],
        }
        values = ["1"] + ["0"] * (fixture.SIGNATURE_VARIABLES - 1)
        witness = {
            "schema": "kpi-signature-normalized-witness/v1",
            "field": str(fixture.SIGNATURE_FIELD),
            "nVars": fixture.SIGNATURE_VARIABLES,
            "nInstances": fixture.SIGNATURE_INSTANCES,
            "nWitnesses": (fixture.SIGNATURE_VARIABLES
                           - fixture.SIGNATURE_INSTANCES),
            "mappingSha256": fixture.SIGNATURE_MAP_SHA,
            "normalizedMatrixSha256": fixture.SIGNATURE_MATRIX_SHA,
            "values": values,
        }
        zero = [[], [], []]
        rows = [zero for _ in range(fixture.SIGNATURE_ROWS)]
        rows[0] = [[(67, 1)], [(0, 1)], []]
        fixture.validate_signature_witness(
            rows, fixture.canonical(witness), signature_inputs)
        changed = copy.deepcopy(witness)
        changed["values"][67] = "1"
        with self.assertRaisesRegex(
                fixture.Refused, "signature-witness-all-rows-satisfied"):
            fixture.validate_signature_witness(
                rows, fixture.canonical(changed), signature_inputs)
        changed = copy.deepcopy(witness)
        changed["values"][1] = "1"
        with self.assertRaisesRegex(
                fixture.Refused,
                "signature-witness-exact-statement-key-prefix"):
            fixture.validate_signature_witness(
                rows, fixture.canonical(changed), signature_inputs)

    def test_close_replay_refuses_malformed_after_head(self):
        context = bytes([9]) * 276
        core = bytearray(10_364)
        core[:8] = b"KPBAEF01"
        core[8:284] = context
        projection = bytearray(10_685)
        projection[:8] = b"KPBAFX01"
        projection[193:10_557] = core
        successor = bytes([7]) * 36
        before = {
            **{name: name for name in (
                "chain_hex32", "pool_hex32", "profile_hex32",
                "domain_hex32", "service_hex32")},
            "genesis": {"outpoint_hex36": (bytes([6]) * 36).hex()},
            "transitions": [],
        }
        after = copy.deepcopy(before)
        after["transitions"] = [{
            "kind": "payment",
            "projection_hex": bytes(projection).hex(),
            "successor_outpoint_hex36": successor.hex(),
        }]
        good_before = SimpleNamespace(
            head=SimpleNamespace(encode=lambda: context))
        malformed_after = SimpleNamespace(
            head=SimpleNamespace(encode=lambda: bytes(276)))
        with mock.patch.object(fixture, "output_verifier_from_plan",
                               return_value=object()), \
             mock.patch.object(fixture, "replay_public_history",
                               side_effect=[good_before, malformed_after]):
            with self.assertRaisesRegex(
                    fixture.Refused,
                    "close-after-derived-head-state-reserve"):
                fixture.validate_public_history_pair(
                    before, after, context, bytes(projection), successor, {})

    def test_pinned_verifier_build_bundle_is_independently_rederived(self):
        bundle = fixture.verifier_build_bundle()
        self.assertEqual(bundle["binary"]["sha256"],
                         fixture.VERIFIER_BINARY_SHA)
        self.assertEqual(bundle["dep_info"]["sha256"],
                         fixture.VERIFIER_DEP_INFO_SHA)
        self.assertEqual(bundle["source_members_identity_sha256"],
                         fixture.VERIFIER_SOURCE_MEMBERS_SHA)
        self.assertFalse(
            bundle["offline_synthetic_provenance_enforced_by_binary"])

    def test_frozen_source_set_must_equal_current_closure(self):
        plan, build, profile_sha, rehearsal_sha = self.plan()
        current = copy.deepcopy(plan["source_members"])
        substituted = copy.deepcopy(current)
        substituted[0]["sha256"] = "ff" * 32
        plan["source_members"] = substituted
        plan["source_closure_sha256"] = fixture.sha(fixture.canonical(substituted))
        with mock.patch.object(fixture, "selected_build", return_value=build), \
             mock.patch.object(fixture, "PROFILE_SHA", profile_sha), \
             mock.patch.object(fixture, "REHEARSAL_SHA", rehearsal_sha), \
             mock.patch.object(fixture, "source_refs", return_value=current):
            with self.assertRaisesRegex(
                    fixture.Refused, "source-closure-current-exact-set-and-content"):
                fixture.validate_plan(plan)

    def test_caller_aggregate_receipt_cannot_advance_checkpoint(self):
        plan, _, _, _ = self.plan()
        with self.assertRaisesRegex(
                fixture.Refused,
                "aggregate-facts-not-caller-validity"):
            fixture.validate_aggregate({}, {"proof_verified": True}, plan, 1)

    def test_c1_defined_identities_match_production_source(self):
        operations = [fresh(), fresh(), fresh()]
        contacts = [0, 2, 0]
        route_source = "ab" * 32
        attempt = fresh()
        self.assertEqual(
            fixture.capture_attempt_word(attempt),
            fixture.sha(fixture.C1_CAPTURE_ATTEMPT_DOMAIN + attempt.encode()),
        )
        self.assertEqual(
            fixture.stage_plan_word(1, operations),
            c1._stage_plan_sha256(1, operations),
        )
        self.assertEqual(
            fixture.route_word(1, contacts, operations, route_source),
            c1._route_manifest_sha256(1, contacts, operations, route_source),
        )
        self.assertEqual(
            [fixture.operation_word(value) for value in operations],
            c1._operation_hashes(operations)[1],
        )

    def test_complete_c1_residual_rederives_all_bound_facts(self):
        plan, _, _, _ = self.plan()
        records, value, projection = self.valid_c1(plan)
        fixture.validate_c1(value, records, 1, plan["rounds"][0], plan,
                            projection)

    def test_c1_stage_config_substitution_is_refused(self):
        plan, _, _, _ = self.plan()
        records, value, projection = self.valid_c1(plan)
        value["stages"][1]["stage_config"]["contact_owner_component"] = 0
        with self.assertRaisesRegex(fixture.Refused, "c1-stage-config-lineage"):
            fixture.validate_c1(value, records, 1, plan["rounds"][0], plan,
                                projection)

    def test_c1_change_receipt_substitution_is_refused(self):
        plan, _, _, _ = self.plan()
        records, value, projection = self.valid_c1(plan)
        value["receipts"][1]["tuple_sha256"] = "ff" * 32
        with self.assertRaisesRegex(fixture.Refused, "c1-both-decrypted-receipts"):
            fixture.validate_c1(value, records, 1, plan["rounds"][0], plan,
                                projection)

    def test_c1_authority_preimage_substitution_is_refused(self):
        plan, _, _, _ = self.plan()
        records, value, projection = self.valid_c1(plan)
        value["contact_value_authority_preimage"]["process_sha256"] = "ee" * 32
        with self.assertRaisesRegex(
                fixture.Refused,
                "c1-contact-value-authority-production-preimage-equivalent"):
            fixture.validate_c1(value, records, 1, plan["rounds"][0], plan,
                                projection)

    def test_final_aggregate_projection_requires_fresh_c1_lineage(self):
        plan, _, _, _ = self.plan()
        records, value, projection = self.valid_c1(plan)
        final_projection = bytearray(projection)
        final_projection[-128:] = bytes([7]) * 128
        with self.assertRaisesRegex(fixture.Refused,
                                    "c1-full-lineage-rederived"):
            fixture.validate_c1(value, records, 1, plan["rounds"][0], plan,
                                bytes(final_projection))
        value["lineage"] = fixture.expected_c1_lineage(
            value, plan, bytes(final_projection))
        fixture.validate_c1(value, records, 1, plan["rounds"][0], plan,
                            bytes(final_projection))

    def test_final_round2_history_refuses_preproof_round1_prefix(self):
        component_before_1 = {"head": {"outpoint_hex36": "00" * 36},
                              "transitions": []}
        component_after_1 = copy.deepcopy(component_before_1)
        component_after_1["transitions"].append({
            "kind": "payment", "projection_hex": "00" * 10_685,
            "successor_outpoint_hex36": "11" * 36,
        })
        proof_projection_1 = bytes([1]) * 10_685
        _, final_after_1 = fixture.final_public_history_pair(
            1, component_before_1, component_after_1, None,
            proof_projection_1, bytes([17]) * 36)

        component_before_2 = copy.deepcopy(component_after_1)
        component_after_2 = copy.deepcopy(component_before_2)
        component_after_2["transitions"].append({
            "kind": "payment", "projection_hex": "00" * 10_685,
            "successor_outpoint_hex36": "22" * 36,
        })
        expected_before_2, expected_after_2 = fixture.final_public_history_pair(
            2, component_before_2, component_after_2, final_after_1,
            bytes([2]) * 10_685, bytes([34]) * 36)
        self.assertNotEqual(component_before_2, expected_before_2)
        with self.assertRaisesRegex(
                fixture.Refused,
                "aggregate-final-cross-round-public-history-lineage"):
            fixture.validate_final_public_history_chain(
                {1: (component_before_1, component_after_1),
                 2: (component_before_2, component_after_2)},
                {1: (component_before_1, final_after_1),
                 2: (component_before_2, component_after_2)},
                {1: proof_projection_1, 2: bytes([2]) * 10_685},
                {1: bytes([17]) * 36, 2: bytes([34]) * 36})
        fixture.validate_final_public_history_chain(
            {1: (component_before_1, component_after_1),
             2: (component_before_2, component_after_2)},
            {1: (component_before_1, final_after_1),
             2: (expected_before_2, expected_after_2)},
            {1: proof_projection_1, 2: bytes([2]) * 10_685},
            {1: bytes([17]) * 36, 2: bytes([34]) * 36})
        self.assertEqual(expected_before_2, final_after_1)
        self.assertEqual(fixture.canonical(expected_before_2),
                         fixture.canonical(final_after_1))
        self.assertEqual(expected_after_2["transitions"][:-1],
                         expected_before_2["transitions"])

    def test_content_substitution_is_detected(self):
        path = self.leaf("artifact.bin", b"one")
        selected = fixture.ref(path)
        path.chmod(0o600)
        path.write_bytes(b"two")
        path.chmod(0o400)
        with self.assertRaisesRegex(fixture.Refused, "artifact-content-substitution"):
            fixture.read_ref(selected)

    def test_duplicate_cross_round_attempt_is_replay(self):
        plan, build, profile_sha, rehearsal_sha = self.plan()
        plan["rounds"][1]["c1_capture_attempt_id"] = plan["rounds"][0]["c1_capture_attempt_id"]
        with mock.patch.object(fixture, "selected_build", return_value=build), \
             mock.patch.object(fixture, "PROFILE_SHA", profile_sha), \
             mock.patch.object(fixture, "REHEARSAL_SHA", rehearsal_sha), \
             mock.patch.object(fixture, "source_refs", return_value=plan["source_members"]):
            with self.assertRaisesRegex(fixture.Refused, "plan-replay-id"):
                fixture.validate_plan(plan)

    def test_mixed_equivalent_build_is_not_accepted(self):
        plan, _, profile_sha, rehearsal_sha = self.plan()
        other = {"schema": "test-build", "build_identity_sha256": "22" * 32}
        with mock.patch.object(fixture, "selected_build", return_value=other), \
             mock.patch.object(fixture, "PROFILE_SHA", profile_sha), \
             mock.patch.object(fixture, "REHEARSAL_SHA", rehearsal_sha), \
             mock.patch.object(fixture, "source_refs", return_value=plan["source_members"]):
            with self.assertRaisesRegex(fixture.Refused, "mixed-or-substituted-build"):
                fixture.validate_plan(plan)

    def test_cross_round_input_mix_is_refused(self):
        plan, _, _, _ = self.plan()
        artifacts = {}
        for owner in range(3):
            value = {
                "schema": "kpb-offline-w1-owner-input/v1",
                "round": 1,
                "logical_owner": owner,
                "input_attempt_id": plan["rounds"][0]["input_attempt_id"],
                "nf_hex32": (owner + 1).to_bytes(32, "little").hex(),
            }
            path = self.leaf(f"input-{owner}.json", fixture.canonical(value))
            artifacts[f"owner-{owner}-input.json"] = fixture.ref(path)
        facts = {"round": 2, "attempt": plan["rounds"][1], "input_count": 3}
        with self.assertRaisesRegex(fixture.Refused, "round-input-source-binding"):
            fixture.validate_round_inputs(artifacts, facts, plan, 2)

    def test_fixed_rewire_graph_is_rederived_from_core_and_records(self):
        core = bytearray(10_364)
        core[:8] = b"KPBAEF01"
        records = []
        input_slots = [2, 1, 0]
        payment_slots = [4, 2, 0]
        change_slots = [1, 3, 5]
        for owner in range(3):
            nf = bytes([10 + owner]) * 32
            cv = bytes([20 + owner]) * 64
            payment = bytes([30 + owner]) * 520
            change = bytes([40 + owner]) * 520
            at = input_slots[owner]
            core[404 + at * 96:500 + at * 96] = nf + cv
            core[692 + payment_slots[owner] * 520:1212 + payment_slots[owner] * 520] = payment
            core[692 + change_slots[owner] * 520:1212 + change_slots[owner] * 520] = change
            records.append({
                "input": {"nf_hex32": nf.hex(), "cv_hex64": cv.hex()},
                "outputs": [{"tuple_hex520": payment.hex()}, {"tuple_hex520": change.hex()}],
            })
        w0, w1 = fixture.derive_graph(records, bytes(core))
        self.assertEqual(w1, {
            "input": input_slots, "payment": payment_slots, "change": change_slots,
        })
        self.assertEqual(w0, {
            "input": [0, 1, 2], "payment": payment_slots, "change": [5, 3, 1],
        })
        duplicate = bytearray(core)
        duplicate[692 + 520:692 + 2 * 520] = duplicate[692:692 + 520]
        with self.assertRaisesRegex(
                fixture.Refused, "graph-exact-unique-input-output-sets"):
            fixture.derive_graph(records, bytes(duplicate))

    def test_c1_creator_and_attempt_cannot_be_replayed_across_rounds(self):
        plan, _, _, _ = self.plan()
        attempt = plan["rounds"][0]
        operations = [attempt[name] for name in (
            "invoice_operation_id", "payment_operation_id", "scan_operation_id")]
        value = {
            "schema": "kpb-offline-w1-c1-residual/v2",
            "round": 1,
            "c1_owner": 1,
            "capture_attempt_id": attempt["c1_capture_attempt_id"],
            "capture_attempt_hex32": fixture.capture_attempt_word(
                attempt["c1_capture_attempt_id"]),
            "capture_identity_id": attempt["c1_capture_identity_id"],
            "c1_cohort_hex32": attempt["c1_cohort_hex32"],
            "c1_financial_run_hex32": attempt["c1_financial_run_hex32"],
            "contact_value_authority_preimage": {},
            "contact_value_authority_preimage_sha256": "11" * 32,
            "contact_value_authority_was_live": False,
            "stages": [
                {"stage": stage, "operation_id": operation,
                 "operation_hex32": fixture.operation_word(operation),
                 "contact_owner": contact, "stage_config": {},
                 "stage_config_hex32": "22" * 32}
                for stage, operation, contact in zip(
                    ("invoice", "pay", "scan"), operations, (0, 2, 0))
            ],
            "original": {},
            "invoices": [],
            "receipts": [],
            "incoming_key_commitment_hex32": "33" * 32,
            "incoming_ciphertext_hex264": bytes(264).hex(),
            "retry_history_closed": True,
            "retries": [],
            "lineage": {},
            "manifest_or_digest_is_authority": False,
        }
        with self.assertRaisesRegex(fixture.Refused, "c1-exact-operation-contact-attempt-value"):
            fixture.validate_c1(value, [], 2, plan["rounds"][1], plan,
                                bytes(10_685))


if __name__ == "__main__":
    unittest.main()
