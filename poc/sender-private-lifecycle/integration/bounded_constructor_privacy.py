#!/usr/bin/env python3
"""Score one completed three-owner constructor run; do not capture new state.

This is a post-run trusted scorer, not part of the constructor or coordinator.
It reads the exact public/coordinator artifacts and all owners only to verify the
hidden truth.  Its output contains counts and hashes, never owner secrets or the
truth map.
"""
import argparse
from itertools import combinations, permutations
import os
from pathlib import Path
import stat
import sys


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "admission"))

from codec import (Q, authorization_input, canonical_json, owner_input, parse_json,
                   session as validate_session, sha, validate_admission,
                   validate_authorizations)
from public import finalized_projection


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def read(path):
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "regular-single-link-artifact")
    raw = path.read_bytes()
    need(len(raw) == info.st_size, "stable-artifact-size")
    return raw


def json_file(path, *, require_canonical=True):
    raw = read(path)
    value = parse_json(raw)
    if require_canonical:
        need(canonical_json(value) == raw, "canonical-json-artifact")
    return value, raw


def artifact(path):
    raw = read(path)
    return {"bytes": len(raw), "sha256": sha(raw)}


def selected_artifact(selector, expected_path):
    expected_path = Path(expected_path)
    need(type(selector) is list and len(selector) == 2 and
         Path(selector[0]) == expected_path and selector[1] == sha(read(expected_path)),
         "exact-selected-artifact-path-and-hash")


def output_assignments(outputs):
    """All owner-labelled partitions of six rows into three unordered pairs."""
    outputs = tuple(outputs)
    need(len(outputs) == 6 and len(set(outputs)) == 6, "six-distinct-output-identifiers")
    for first in combinations(outputs, 2):
        remaining = tuple(value for value in outputs if value not in first)
        for second in combinations(remaining, 2):
            third = tuple(value for value in remaining if value not in second)
            yield tuple(sorted(first)), tuple(sorted(second)), tuple(sorted(third))


def map_candidates(inputs, outputs, *, colluder_input=None, colluder_outputs=(), incoming_creators=()):
    """Enumerate maps consistent with public data and optional owner-0 facts."""
    inputs, outputs = tuple(inputs), tuple(outputs)
    need(len(inputs) == 3 and len(set(inputs)) == 3, "three-distinct-input-identifiers")
    pairs = tuple(output_assignments(outputs))
    if colluder_input is None:
        need(not colluder_outputs and not incoming_creators, "public-view-has-no-private-facts")
    else:
        need(colluder_input in inputs and len(colluder_outputs) == 2 and
             len(set(colluder_outputs)) == 2 and set(colluder_outputs) <= set(outputs),
             "exact-colluder-self-map")
        need(all(output in outputs and creator in (1, 2)
                 for output, creator in incoming_creators), "honest-incoming-creator-facts")
        if len({creator for _, creator in incoming_creators}) != len(incoming_creators):
            return
    for input_map in permutations(inputs):
        if colluder_input is not None and input_map[0] != colluder_input:
            continue
        for output_map in pairs:
            if colluder_input is not None and set(output_map[0]) != set(colluder_outputs):
                continue
            if any(output not in output_map[creator]
                   for output, creator in incoming_creators):
                continue
            yield input_map, output_map


def one_attempt(owner):
    attempts = sorted((owner / "attempts").iterdir())
    attempts = [path for path in attempts if path.is_dir() and path.name.isdigit()]
    need(len(attempts) == 1 and attempts[0].name == "000001", "one-fresh-owner-attempt")
    need((attempts[0] / "DISCLOSURE-CLOSED").is_file(), "owner-authorized-after-disclosure-barrier")
    return attempts[0]


def wallet_modules():
    sys.path.insert(0, str(HERE.parent / "wallet"))
    import history
    import support
    return history, support


def private_truth(private_root, session, inputs, outputs, authorizations,
                  expected_payment_sompi):
    _, support = wallet_modules()
    truth = []
    for owner in range(3):
        party_root = private_root / ("party-%d" % owner)
        root = party_root / "owner"
        attempt = one_attempt(root)
        state, _ = json_file(attempt / "STATE.json")
        authorization, _ = json_file(attempt / "AUTHORIZATION.json")
        need(state["party"] == owner and parse_json(read(attempt / "SESSION.json")) == session,
             "owner-session-and-party-binding")
        input_row = bytes.fromhex(state["nf_hex32"] + state["cv_hex64"])
        need(inputs.count(input_row) == 1, "owner-input-in-mixed-pool-once")
        rows = tuple(bytes.fromhex(item["tuple_hex520"]) for item in state["outputs"])
        need(len(rows) == 2 and len(set(rows)) == 2 and all(outputs.count(row) == 1 for row in rows),
             "owner-output-pair-in-mixed-pool-once")
        receipts = [support.recipient().Receipt.parse(bytes.fromhex(item["receipt_hex216"]))
                    for item in state["outputs"]]
        need(all(receipt.commitment() == row[:32] for receipt, row in zip(receipts, rows)),
             "private-receipts-bind-exact-MPC-output-commitments")
        need(receipts[0].value_sompi == expected_payment_sompi,
             "exact-selected-equal-payment-request")
        need(state["outputs"][0]["recipient_id_hex32"] != session["roster"][owner] and
             state["outputs"][1]["recipient_id_hex32"] == session["roster"][owner],
             "payment-then-own-change")
        auth_row = input_row + bytes.fromhex(authorization["proof_hex128"])
        need(authorizations.count(auth_row) == 1 and
             authorization["nf_hex32"] == state["nf_hex32"] and
             authorization["cv_hex64"] == state["cv_hex64"],
             "owner-authorization-in-independent-mixed-pool-once")
        beta = (int.from_bytes(bytes.fromhex(state["rin_hex32"]), "little") -
                sum(int.from_bytes(bytes.fromhex(item["blind_hex32"]), "little")
                    for item in state["outputs"])) % Q
        need(read(party_root / "mpc" / ("Input-P%d-0" % owner)) ==
             owner_input(input_row, list(rows), beta), "exact-owner-private-admission-stream")
        need(read(party_root / "authorization-mpc" / ("Input-P%d-0" % owner)) ==
             authorization_input(auth_row), "exact-owner-private-authorization-stream")
        truth.append({"root": root, "attempt": attempt, "input": input_row, "outputs": rows})
    need({row["input"] for row in truth} == set(inputs) and
         {output for row in truth for output in row["outputs"]} == set(outputs),
         "truth-is-exact-public-bijection")
    return truth


def colluder_incoming(colluder, assets, session_sha, outputs):
    history, support = wallet_modules()

    backup, _ = json_file(colluder["root"] / "BACKUP.json")
    wallet = support.recipient().Receiver(bytes.fromhex(backup["seed_hex32"]),
                                          support.DOMAIN,
                                          support.crypto(assets["crypto"]["path"]))
    own_outputs = set(colluder["outputs"])
    decrypted = []
    incoming = []
    for output_index, row in enumerate(outputs):
        try:
            receipt = wallet.open(row[96:360])
        except support.recipient().Invalid as error:
            need(str(error) == "crypto-unseal", "colluder-output-decryption-failure")
            continue
        need(receipt.commitment() == row[:32], "colluder-decrypted-output-commitment")
        decrypted.append(output_index)
        if row in own_outputs:
            need(row == colluder["outputs"][1], "only-own-change-decrypts-to-colluder")
            continue
        creators = [owner for owner in range(3)
                    if receipt.index == history.invoice_index(session_sha, owner, b"PAYMENT\0")]
        need(len(creators) == 1 and creators[0] in (1, 2),
             "incoming-receipt-identifies-one-honest-sender-slot")
        incoming.append((output_index, creators[0]))
    need(colluder["outputs"][1] in [outputs[index] for index in decrypted],
         "colluder-own-change-decrypted")
    need(len({output for output, _ in incoming}) == len(incoming) and
         len({creator for _, creator in incoming}) == len(incoming),
         "at-most-one-incoming-payment-per-honest-owner")
    return decrypted, incoming


def private_view_manifest(party_root):
    entries = []
    regular_files = symlinks = total_bytes = 0
    for path in sorted(party_root.rglob("*")):
        if path.is_symlink():
            target = os.readlink(path)
            need(not Path(target).is_absolute() and ".." not in Path(target).parts,
                 "private-view-local-certificate-alias-only")
            entries.append({"path": str(path.relative_to(party_root)), "symlink_target": target})
            symlinks += 1
            continue
        if not path.is_file():
            continue
        raw = read(path)
        entries.append({"path": str(path.relative_to(party_root)),
                        "bytes": len(raw), "sha256": sha(raw)})
        regular_files += 1
        total_bytes += len(raw)
    encoded = canonical_json(entries)
    return {"artifact_count": len(entries), "regular_file_count": regular_files,
            "local_certificate_symlink_count": symlinks, "regular_file_bytes": total_bytes,
            "manifest_sha256": sha(encoded)}


def coordinator_phase(round_root, phase, mixed, session, session_sha, effects):
    root = round_root / ("mpc-mixed-" + phase)
    packet, packet_raw = json_file(root / "COORDINATOR-PUBLIC-IPC.json")
    observer, observer_raw = json_file(root / "coordinator-public/OBSERVER.json")
    results, results_raw = json_file(root / "RESULTS.json")
    prepared, prepared_raw = json_file(round_root / ("mpc-prepared-" + phase) / "PREPARED.json")
    need(set(packet) == {"schema", "session", "session_sha256", "prepared_sha256", "phase",
                         "effects_digest_hex32", "party_projections"} and
         packet["schema"] == "kpx9-coordinator-public-ipc/v1" and packet["phase"] == phase and
         packet["session"] == session and packet["session_sha256"] == session_sha and
         packet["effects_digest_hex32"] == effects and packet["prepared_sha256"] == sha(prepared_raw) and
         prepared["session_sha256"] == session_sha and prepared["phase"] == phase and
         prepared["effects_digest_hex32"] == effects and
         len(packet["party_projections"]) == 3 and
         packet["party_projections"][0] == packet["party_projections"][1] ==
         packet["party_projections"][2] == mixed,
         "exact-three-identical-public-coordinator-projections")
    need(observer == {"schema": "kpx9-coordinator-observer-boundary/v1", "phase": phase,
         "public_ipc_only": True, "docker_socket_visible": False, "owner_paths_visible": False,
         "host_home_visible": False, "visible_network_interfaces": ["lo"],
         "execution_request_api": False, "per_owner_input_or_authorization_received": False,
         "party_projection_count": 3,
         "scope": "LOCAL_PROCESS_ISOLATION_NOT_HOST_ADMIN_OR_NETWORK_ANONYMITY"},
         "exact-coordinator-process-boundary")
    need(results["status"] == "COMPLETE" and results["phase"] == phase and
         results["session_sha256"] == session_sha and
         results["prepared_sha256"] == sha(prepared_raw) and
         results["mixed_sha256"] == sha(canonical_json(mixed)) and
         results["effects_digest_hex32"] == effects and
         results["party_success_count"] == 3 and results["host_owner_input_read_count"] == 0 and
         results["all_owned_containers_removed"] is True,
         "completed-three-party-MPC-with-zero-host-input-reads")
    return {"packet": {"bytes": len(packet_raw), "sha256": sha(packet_raw)},
            "boundary": {"bytes": len(observer_raw), "sha256": sha(observer_raw)},
            "result": {"bytes": len(results_raw), "sha256": sha(results_raw)},
            "wall_milliseconds": results["wall_milliseconds"]}


def neutral_owner_messages(round_root, session_sha, effects):
    for owner in range(3):
        ready, _ = json_file(round_root / ("READY-%d.json" % owner))
        need(set(ready) == {"schema", "session_sha256", "own_output_count", "mpc_input_written",
                            "financial_authorization"} and
             ready["schema"] == "kpx9-owner-input-ready/v1" and
             ready["session_sha256"] == session_sha and ready["own_output_count"] == 2 and
             ready["mpc_input_written"] is True and ready["financial_authorization"] is False,
             "neutral-owner-admission-readiness")
        authorized, _ = json_file(round_root / ("AUTHORIZATION-READY-%d.json" % owner))
        need(set(authorized) == {"schema", "session_sha256", "effects_digest_hex32",
                                 "authorization_input_written", "proof_publicly_exported"} and
             authorized["schema"] == "kpx9-owner-authorization-ready/v1" and
             authorized["session_sha256"] == session_sha and
             authorized["effects_digest_hex32"] == effects and
             authorized["authorization_input_written"] is True and
             authorized["proof_publicly_exported"] is False,
             "neutral-owner-authorization-readiness")


def assembler_observer(round_root, operation):
    root = round_root / ("core" if operation == "build" else "final-body")
    value, raw = json_file(root / "OBSERVER.json")
    need(value == {"schema": "kpx9-public-assembler-boundary/v1", "operation": operation,
         "public_stdin_only": True, "private_owner_directories_visible": False,
         "docker_socket_visible": False, "private_invocation_handles_received": False,
         "owner_labelled_inputs_or_proofs_received": False,
         "financial_proofs_verified": False, "accepted_chain_authority": False},
         "exact-public-assembler-process-boundary")
    return {"bytes": len(raw), "sha256": sha(raw)}


def public_assembler(round_root, history, session, session_sha, mixed, result,
                     final_projection, authorization_projection, authorizations):
    packet, packet_raw = json_file(round_root / "core/COORDINATOR-PUBLIC-IPC.json")
    need(set(packet) == {"schema", "operation", "history", "mixed_admission",
                         "session_sha256", "roster", "fee_sompi"} and
         packet["schema"] == "kpx9-public-assembly-ipc/v1" and
         packet["operation"] == "build" and packet["history"] == history and
         packet["mixed_admission"] == mixed and packet["session_sha256"] == session_sha and
         packet["roster"] == session["roster"] and packet["fee_sompi"] == result["fee_sompi"],
         "exact-public-constructor-inputs-from-selected-run")
    final_body = read(round_root / "final-body/PROJECTION.bin")
    pre_projection = read(round_root / "pre/PROJECTION.bin")
    need(final_body == final_projection ==
         finalized_projection(pre_projection, authorization_projection) and
         final_body[193:] == read(round_root / "final-body/BODY.bin"),
         "public-finalizer-output-is-selected-final-projection")
    # The authorization rows are independently mixed and occur in the final
    # projection only after the strict NF/CV bijection and proof verification.
    need(len(authorizations) == 3, "three-selected-final-authorizations")
    return {"build_packet": {"bytes": len(packet_raw), "sha256": sha(packet_raw)},
            "build_boundary": assembler_observer(round_root, "build"),
            "finalize_boundary": assembler_observer(round_root, "finalize")}


def score(public_root, private_root, assets_file, native_selection_file,
          expected_payment_sompi):
    need(type(expected_payment_sompi) is int and expected_payment_sompi > 0,
         "positive-selected-payment-request")
    round_root = public_root / "round-01"
    world, _ = json_file(public_root / "WORLD.json")
    result, _ = json_file(round_root / "ROUND.json")
    session, session_raw = json_file(round_root / "session/SESSION.json")
    admit, admit_raw = json_file(round_root / "mpc-mixed-admit/MIXED.json")
    authorize, authorize_raw = json_file(round_root / "mpc-mixed-authorize/MIXED.json")
    assets, _ = json_file(assets_file)
    native_selection, _ = json_file(native_selection_file)
    _, session_sha = validate_session(session_raw, assets["program_source_sha256"])
    need(session_sha == admit["session_sha256"] == authorize["session_sha256"],
         "one-session-across-both-MPC-phases")
    inputs, outputs, _ = validate_admission(admit, session_sha)
    effects = authorize["effects_digest_hex32"]
    authorizations = validate_authorizations(authorize, session_sha, effects)
    need({row[:96] for row in authorizations} == set(inputs),
         "authorization-to-input-bijection")

    selected_artifact(result["session"], round_root / "session/SESSION.json")
    selected_artifact(result["admission_projection"], round_root / "mpc-mixed-admit/MIXED.json")
    selected_artifact(result["authorization_projection"], round_root / "mpc-mixed-authorize/MIXED.json")
    selected_artifact(result["projection"], round_root / "final/PROJECTION.bin")
    selected_artifact(result["journal"], round_root / "final/JOURNAL.bin")
    selected_artifact(result["case"], round_root / "final/CASE.json")
    need(result["session"][1] == session_sha, "round-selector-session-binding")

    need(world["status"] == "COMPLETE" and world["label"] == public_root.name and
         len(world["rounds"]) == 1 and
         result["two_checked_MPC_stages_completed"] is True and
         result["nine_genuine_component_proofs_independently_verified"] is True and
         result["outer_receipt_native_Full_or_chain_acceptance"] is False,
         "complete-local-component-round-only")
    world_round = dict(world["rounds"][0])
    cpu_selector = world_round.pop("CPU_guest_report")
    need(world_round == result, "world-contains-exact-selected-round")
    cpu_path = public_root / "round-01-cpu-guest/report.json"
    selected_artifact(cpu_selector, cpu_path)

    neutral_owner_messages(round_root, session_sha, effects)
    phases = {
        "admit": coordinator_phase(round_root, "admit", admit, session, session_sha, "0" * 64),
        "authorize": coordinator_phase(round_root, "authorize", authorize, session, session_sha, effects),
    }

    history, _ = json_file(public_root / "SUPPLIED-HISTORY.json")
    final_projection = read(round_root / "final/PROJECTION.bin")
    assembler = public_assembler(round_root, history, session, session_sha, admit, result,
                                 final_projection, authorize, authorizations)

    truth = private_truth(private_root, session, inputs, outputs, authorizations,
                          expected_payment_sompi)
    input_ids = tuple(range(3))
    output_ids = tuple(range(6))
    truth_map = (tuple(inputs.index(row["input"]) for row in truth),
                 tuple(tuple(sorted(outputs.index(value) for value in row["outputs"])) for row in truth))
    public_maps = list(map_candidates(input_ids, output_ids))
    need(len(public_maps) == 540 and public_maps.count(truth_map) == 1,
         "public-map-space-contains-truth-once")

    colluder = truth[0]
    decrypted, incoming = colluder_incoming(colluder, assets, admit["session_sha256"], outputs)
    colluder_input = inputs.index(colluder["input"])
    colluder_outputs = tuple(outputs.index(value) for value in colluder["outputs"])
    colluder_maps = list(map_candidates(input_ids, output_ids, colluder_input=colluder_input,
                                        colluder_outputs=colluder_outputs,
                                        incoming_creators=incoming))
    need(len(colluder_maps) > 1 and colluder_maps.count(truth_map) == 1,
         "colluder-view-retains-nonunique-honest-map")

    financial, _ = json_file(round_root / "final-body/financial-check/report.json",
                             require_canonical=False)
    cpu, _ = json_file(cpu_path, require_canonical=False)
    journal = read(round_root / "final/JOURNAL.bin")
    need(financial["all_three_Spend_and_six_Output_G16_verified"] is True and
         financial["independent_arkworks_pairing_reference_checked"] is True and
         financial["public_state_native_effects_and_global_balance_verified"] is True and
         financial["input_sha256"] == sha(final_projection),
         "genuine-nine-proof-and-balance-check")
    need(cpu["genuine_nine_G16_public_guest_execution_passed"] is True and
         cpu["proof_generation"] is False and cpu["native_VM_executed"] is False and
         cpu["input_sha256"] == sha(final_projection) and cpu["journal_sha256"] == sha(journal) and
         cpu["image_id_hex32"] == native_selection["image_hex32"],
         "genuine-CPU-guest-check")

    return {
        "schema": "kpx9-bounded-constructor-privacy-observation/v1",
        "status": "COMPLETE",
        "scope": "ONE_LOCAL_THREE_OWNER_ADR0065_CONSTRUCTION",
        "observer_model": "PUBLIC_OR_COORDINATOR_PLUS_AT_MOST_OWNER_0_NOT_HOST_ADMIN_ONE_CORRUPT_PARTY_MASCOT_ASSUMED",
        "run": {"public_world": artifact(public_root / "WORLD.json"),
                "admission_projection": {"bytes": len(admit_raw), "sha256": sha(admit_raw)},
                "authorization_projection": {"bytes": len(authorize_raw), "sha256": sha(authorize_raw)},
                "coordinator_phases": phases,
                "public_assembler": assembler,
                "equal_payment_requests_sompi": expected_payment_sompi},
        "public_observation": {"roster_aliases": 3, "mixed_input_rows": 3,
            "mixed_complete_output_rows": 6, "mixed_authorization_rows": 3,
            "neutral_owner_ready_messages": 6,
            "explicit_owner_to_mixed_row_links_in_validated_protocol_schemas": 0,
            "owner_to_input_bijections": 6, "owner_to_output_pair_assignments": 90,
            "structural_full_owner_input_output_map_candidates": len(public_maps)},
        "coordinator_observation": {"public_ipc_only": True, "owner_paths_visible": False,
            "per_owner_input_or_authorization_received": False, "host_owner_input_read_count": 0,
            "explicit_owner_to_mixed_row_links_in_validated_protocol_schemas": 0,
            "structural_full_owner_input_output_map_candidates": len(public_maps)},
        "coordinator_plus_owner_0_observation": {
            "own_input_rows_known": 1, "own_created_output_rows_known": 2,
            "own_private_delta_and_Spend_proof_known": True,
            "own_MPC_party_private_view": private_view_manifest(private_root / "party-0"),
            "decryptable_output_rows": len(decrypted),
            "incoming_rows_with_sender_slot_known": len(incoming),
            "honest_owner_to_input_bijections": 2,
            "structural_full_maps_after_decoded_wallet_facts": len(colluder_maps),
            "opaque_MPC_transcript_interpretation": "ONE_CORRUPT_PARTY_MASCOT_PRIVACY_ASSUMPTION",
            "exact_honest_map_learned": False},
        "authorization_and_conservation": {"independent_authorization_shuffle_completed": True,
            "exact_NF_CV_authorization_bijection": True, "Spend_proofs_verified": 3,
            "Output_proofs_verified": 6, "independent_arkworks_reference_checked": True,
            "public_state_native_effects_and_global_balance_verified": True,
            "genuine_CPU_guest_execution_passed": True},
        "verdict": {"owner_labelled_plaintext_map_absent_from_declared_coordinator_boundary": True,
            "honest_map_structurally_nonunique_after_decoded_owner_0_facts": True,
            "colluder_result_depends_on_one_corrupt_party_MASCOT_privacy": True,
            "filtered_artifact_claim": False,
            "ADR0074_offline_W1_constructor_repaired": False,
            "testnet_or_chain_acceptance": False,
            "privacy_proof_or_active_retry_resistance": False},
        "limitations": ["trusted host administrator can read all local owner processes",
                        "two colluding owners identify the third by elimination",
                        "one-party MPC transcripts are covered by the selected MASCOT security assumption, not proven private by this scorer",
                        "active changed-cohort retry can intersect stable nullifiers",
                        "endpoint and timing anonymity are not measured",
                        "this executes ADR0065, not the newer restricted-intent ADR0074 path"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-root", required=True)
    parser.add_argument("--private-root", required=True)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--native-selection", required=True)
    parser.add_argument("--expected-payment-sompi", required=True, type=int)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    need(not output.exists(), "fresh-observation-output")
    value = score(Path(args.public_root), Path(args.private_root), Path(args.assets),
                  Path(args.native_selection), args.expected_payment_sompi)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical_json(value))
    output.chmod(0o400)
    print(canonical_json({"status": value["status"],
                          "coordinator_map_candidates":
                              value["coordinator_observation"]
                              ["structural_full_owner_input_output_map_candidates"],
                          "colluder_map_candidates": value["coordinator_plus_owner_0_observation"]
                              ["structural_full_maps_after_decoded_wallet_facts"]}).decode(), end="")


if __name__ == "__main__":
    os.umask(0o077)
    main()
