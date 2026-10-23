"""Fresh public network composition for ADR0053. Never reads an owner or PK.

The immutable offline semantic adapter remains offline/complete:false. This
module establishes a separate observed-network result from coverage/current
queries, actual SDK rehashing and newly executed generic native validation.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile

from pinned_dependencies import ROOT, adapter, old, native
from sealed_runtime import SealedExecutable

HERE = Path(__file__).resolve().parent
DESCRIPTOR_FIELDS = old.DESCRIPTOR_FIELDS | {"public_params_manifest_sha256"}
NATIVE_EXECUTABLE = ROOT.parent / "private-exit-native-target/selected-01/kpi-private-exit-native"
NATIVE_SHA256 = "077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061"
NODE_EXECUTABLE = Path("/home/luke/.nvm/versions/node/v24.15.0/bin/node.forge-original")
NODE_SHA256 = "d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c"


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        old.need(key not in result, "duplicate-json-field")
        result[key] = value
    return result


def read_json(path, *, canonical_manifest=False):
    raw = Path(path).read_bytes()
    value = json.loads(raw, object_pairs_hook=_unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("json-constant")))
    if canonical_manifest:
        old.need(raw == canonical_bytes(value), "manifest-canonical-bytes-no-newline")
    return value


def _exact(value, fields, code):
    old.need(type(value) is dict and set(value) == set(fields), code)


def descriptor_and_manifest(descriptor, public_manifest):
    _exact(descriptor, DESCRIPTOR_FIELDS, "private-network-descriptor-fields")
    old.need(descriptor["schema"] == "kpx3-private-network-descriptor/v1", "private-network-descriptor-schema")
    old.hx(descriptor["public_params_manifest_sha256"], 32)
    old.need(old.digest(public_manifest) == descriptor["public_params_manifest_sha256"], "public-manifest-digest")
    manifest_fields = {"schema", "trial_id", "network_id", "genesis_hash_hex", "domain_hex32", "format", "pk_bytes",
                       "pk_sha256", "vk_hex328", "vk_sha256", "core_source_identity", "compiled_build_identity_sha256",
                       "constraint_shape", "queries", "setup_provenance"}
    _exact(public_manifest, manifest_fields, "public-manifest-fields")
    old.need(public_manifest["schema"] == "kpx3-public-proving-parameters/v1"
             and public_manifest["format"] == "arkworks0.6-bn254-uncompressed"
             and type(public_manifest["trial_id"]) is str and bool(public_manifest["trial_id"]), "public-manifest-schema")
    for name in ("network_id", "genesis_hash_hex", "domain_hex32", "vk_hex328"):
        old.need(public_manifest[name] == descriptor[name], "public-manifest-descriptor-binding")
    for name in ("pk_sha256", "vk_sha256", "compiled_build_identity_sha256"):
        old.hx(public_manifest[name], 32)
    old.need(old.h(old.hx(public_manifest["vk_hex328"], 328)).hex() == public_manifest["vk_sha256"], "public-manifest-VK-hash")
    old.need(type(public_manifest["pk_bytes"]) is int and 0 < public_manifest["pk_bytes"] <= (1 << 53) - 1, "public-manifest-PK-length")
    _exact(public_manifest["core_source_identity"], {"lib_rs_sha256", "circuit_rs_sha256", "exact_sha256_rs_sha256",
           "request_rs_sha256", "parameters_rs_sha256", "main_rs_sha256", "setup_rs_sha256", "build_rs_sha256"}, "public-manifest-core-fields")
    _exact(public_manifest["setup_provenance"], {"executable_sha256", "source_freeze_sha256", "public_setup_report_sha256"},
           "public-manifest-setup-fields")
    for value in [*public_manifest["core_source_identity"].values(), *public_manifest["setup_provenance"].values()]:
        old.hx(value, 32)
    _exact(public_manifest["constraint_shape"], {"constraints", "witness_variables", "instances_including_one"}, "public-manifest-shape-fields")
    _exact(public_manifest["queries"], {"a", "b_g1", "b_g2", "l", "h", "instances_including_one"}, "public-manifest-query-fields")
    for value in [*public_manifest["constraint_shape"].values(), *public_manifest["queries"].values()]:
        old.need(type(value) is int and 0 < value <= (1 << 53) - 1, "public-manifest-query-integer")
    old.need(public_manifest["queries"]["instances_including_one"] == 3
             and public_manifest["constraint_shape"]["instances_including_one"] == 3, "public-manifest-instance-count")
    semantic = {key: value for key, value in descriptor.items() if key != "public_params_manifest_sha256"}
    semantic["schema"] = "kpx3-recovery-descriptor/v1"
    # Full template/domain/VK gate executes before projecting to old semantics.
    adapter.descriptor_check(semantic)
    return semantic


def _public_state(descriptor, bundle, public_manifest):
    """Pure public predicates, deliberately insufficient for a complete result."""
    semantic_descriptor = descriptor_and_manifest(descriptor, public_manifest)
    old.need(bundle["schema"] == "kpx3-private-network-fetch/v1"
             and bundle["network_id"] == "testnet-10" and bundle["genesis_hash_hex"] == old.GENESIS
             and bundle["descriptor_sha256"] == old.digest(descriptor)
             and bundle["descriptor"] == descriptor
             and bundle["public_params_manifest_sha256"] == descriptor["public_params_manifest_sha256"]
             and bundle["public_params_manifest"] == public_manifest
             and bundle["public_parameter_blob_read"] is False, "private-network-fetch-binding")
    coverage, frontier, anchor_score, frontier_score, sink_score, minimum, view = old.checked_network_coverage(descriptor, bundle)
    rows, entries_by_id = {}, {}
    for row in bundle["transactions"]:
        tx = old.canonical(row["transaction"])
        old.need(tx["id"] not in rows, "duplicate-accepted-transaction")
        entries, _ = old.context_entries(tx, row)
        old.confirmation(row)
        policy, header = row["confirmation_policy"], row["accepting_block_header"]
        old.need(anchor_score < old.integer(header["blueScore"], (1 << 64) - 1) <= frontier_score
                 and old.integer(policy["sink_blue_score"], (1 << 64) - 1) == sink_score
                 and old.integer(policy["min_confirmation_count"], (1 << 64) - 1) == minimum,
                 "acceptance-outside-fixed-frontier")
        rows[tx["id"]], entries_by_id[tx["id"]] = tx, entries
    supplied = {"schema": "kpx3-supplied-context/v1", "context": "OFFLINE_SUPPLIED_CONTEXT",
                "network_id": "testnet-10", "genesis_hash_hex": old.GENESIS,
                "descriptor_sha256": old.digest(semantic_descriptor),
                "transactions": [{"transaction": tx, "input_contexts": entries_by_id[txid]} for txid, tx in rows.items()]}
    # No ExistingNativeResults import or cache callback. Keep original output.
    semantic = adapter.replay(semantic_descriptor, supplied, native_validator=None)
    queries = {}
    for query in view["queries"]:
        at = old.point(query["outpoint"])
        old.need(at not in queries and query["queried"] is True, "duplicate-or-unqueried-current-point")
        old.spk(query["script_public_key"]); old.integer(query["amount_sompi"])
        if query["entry"] is not None:
            old.same_entry(query["entry"], {"outpoint": query["outpoint"], "amount_sompi": old.integer(query["amount_sompi"]),
                                           "script_public_key": query["script_public_key"]})
        queries[at] = query
    expected = {}
    consumed = set()
    for txid, tx in rows.items():
        for entry in entries_by_id[txid]:
            expected[old.point(entry["outpoint"])] = entry
            consumed.add(old.point(entry["outpoint"]))
        for index, output in enumerate(tx["outputs"]):
            point = old.outpoint(tx, index)
            expected[old.point(point)] = {"outpoint": point, "amount_sompi": output["value"], "script_public_key": output["scriptPublicKey"]}
    old.need(set(queries) == set(expected), "missing-or-extra-exact-current-query", incomplete=True)
    for at, value in expected.items():
        query = queries[at]
        old.need(query["script_public_key"] == value["script_public_key"]
                 and old.integer(query["amount_sompi"]) == old.integer(value["amount_sompi"]), "exact-current-query-substitution", incomplete=True)
        if at in consumed:
            old.need(query["entry"] is None, "consumed-input-not-observed-spent", incomplete=True)
    head = copy.deepcopy(semantic["head"])
    reserve = old.integer(head["reserve_sompi"])
    if reserve:
        query = queries.get(old.point(head["outpoint"]))
        old.need(query is not None, "current-head-not-queried", incomplete=True)
        old.same_entry(query["entry"], {"outpoint": head["outpoint"], "amount_sompi": reserve,
                                       "script_public_key": old.p2sh(old.hx(head["current_redeem_hex"]))})
        head["current_utxo"] = query["entry"]
    else:
        old.need(len(semantic["operations"]) > 1 and head["outpoint"] is None, "terminal-without-valid-transition")
        prior = old.point(semantic["operations"][-1]["prior_outpoint"])
        old.need(prior in consumed and queries[prior]["entry"] is None, "terminal-reserve-not-observed-spent", incomplete=True)
    payouts = copy.deepcopy(semantic["payouts"])
    for payout in payouts:
        query = queries.get(old.point(payout["outpoint"]))
        old.need(query is not None and query["script_public_key"] == payout["script_public_key"]
                 and old.integer(query["amount_sompi"]) == payout["amount_sompi"], "payout-not-queried", incomplete=True)
        payout.update(queried=True, current_utxo=query["entry"])
    watched = [old.point(value) for value in view["post_query_delta"]["watched_outpoints"]]
    live = {at for at, query in queries.items() if query["entry"] is not None}
    old.need(len(watched) == len(set(watched)) and set(watched) == live, "post-query-live-point-coverage", incomplete=True)
    head["observation_checkpoint"] = view["checkpoint"]
    head["accepting_block_header"] = bundle["transactions"][0]["accepting_block_header"]
    last = semantic["operations"][-1]["transaction_id"]
    head["accepting_block_header"] = next(row["accepting_block_header"] for row in bundle["transactions"] if row["transaction"]["id"] == last)
    return semantic, head, payouts, rows, entries_by_id


class FreshNativeValidator:
    """Fixed app-selected generic validator, executed anew on every body/context."""
    def __init__(self, output):
        self.output = Path(output); self.output.mkdir(mode=0o700)
        self.executable = SealedExecutable(NATIVE_EXECUTABLE, NATIVE_SHA256)
        self.reports = []

    def validate(self, transaction, entries):
        index = len(self.reports)
        case_path = self.output / f"{index:05d}-case.json"
        raw = canonical_bytes(native.native_case(transaction, entries)) + b"\n"
        case_path.write_bytes(raw)
        target = self.output / f"{index:05d}"
        process = self.executable.run(["validate-transaction", case_path, target])
        report_path = target / "native-validation.json"
        old.need(process.returncode == 0 and report_path.is_file(), "fresh-native-execution-failed", incomplete=True)
        report = read_json(report_path)
        old.need(report.get("isolation") == "PASS" and report.get("Full", {}).get("accepted") is True
                 and report.get("all_input_engines_accepted") is True
                 and len(report.get("per_input_ScriptEngine", [])) == len(transaction["inputs"])
                 and all(value.get("accepted") is True for value in report["per_input_ScriptEngine"]), "fresh-native-rejected")
        self.reports.append({"transaction_id": transaction["id"], "accepted": True,
                             "public_case_sha256": hashlib.sha256(raw).hexdigest(),
                             "native_report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                             "native_report_path": str(report_path)})

    def close(self):
        self.executable.close()


def replay(descriptor: dict, bundle: dict, public_manifest: dict, *, output_directory=None) -> dict:
    try:
        semantic, head, payouts, rows, entries = _public_state(descriptor, bundle, public_manifest)
        output = Path(output_directory) if output_directory is not None else Path(tempfile.mkdtemp(prefix="kpx3-public-replay-"))
        if output_directory is not None:
            old.need(not output.exists(), "fresh-public-validation-output-required")
            output.mkdir(mode=0o700, parents=True)
        paths = [output / "descriptor.json", output / "public-manifest.json", output / "network-bundle.json"]
        for path, value in zip(paths, (descriptor, public_manifest, bundle)):
            path.write_bytes(canonical_bytes(value))
        sdk_receipt_path = output / "sdk-verification.json"
        with SealedExecutable(NODE_EXECUTABLE, NODE_SHA256) as node:
            process = node.run([HERE / "verify_bundle.mjs", *paths, sdk_receipt_path])
            (output / "sdk-verification.log").write_text(process.stdout + process.stderr)
            old.need(process.returncode == 0 and sdk_receipt_path.is_file(), "fresh-sdk-verification-failed", incomplete=True)
            node_runtime = node.receipt()
        sdk = read_json(sdk_receipt_path)
        old.need(sdk["descriptor_sha256"] == old.digest(descriptor)
                 and sdk["canonical_bundle_sha256"] == old.digest(bundle)
                 and set(sdk["selected_transaction_ids"]) == set(rows)
                 and sdk["transaction_ids_recomputed"] is True and sdk["header_hashes_recomputed"] is True,
                 "fresh-sdk-receipt-binding")
        validator = FreshNativeValidator(output / "native")
        try:
            for txid in sorted(rows):
                validator.validate(rows[txid], entries[txid])
            native_runtime, reports = validator.executable.receipt(), validator.reports
        finally:
            validator.close()
        return {"schema": "kpx3-private-network-replay/v1", "context": "FRESH_NETWORK_PUBLIC_REPLAY",
                "descriptor_sha256": old.digest(descriptor), "public_params_manifest_sha256": old.digest(public_manifest),
                "network_id": descriptor["network_id"], "genesis_hash_hex": old.GENESIS,
                "domain_hex32": descriptor["domain_hex32"], "immutable_policy_sha256": descriptor["immutable_policy_sha256"],
                "deliveries": semantic["deliveries"], "nullifiers": semantic["nullifiers"],
                "operations": semantic["operations"], "payouts": payouts, "head": head,
                "offline_semantic_result": semantic,
                "completeness": {"complete": True, "public_replay_complete": True, "terminal": head["reserve_sompi"] == 0,
                                 "acceptance_trust": "SELECTED_VALIDATING_NODE", "accepted_chain_backing": True,
                                 "network_current_view_observed": True, "scan_anchor": bundle["coverage"]["start_hash"],
                                 "frontier": bundle["coverage"]["frontier"], "view_is_atomic": False,
                                 "independent_consensus": False, "durable_data_availability_proved": False,
                                 "orphan_disclosure_history_complete": False},
                "local_native_validation": True, "groth16_and_signatures": "FRESH_LOCALLY_EXECUTED_NATIVE_FULL",
                "sdk_transaction_id_validation": True, "sdk_header_hash_validation": True,
                "sdk_verification": sdk, "native_reports": reports,
                "runtime": {"node": node_runtime, "native": native_runtime},
                "public_parameter_manifest_authenticated": True, "public_parameter_blob_read": False,
                "accepted_membership_and_history_remain_selected_node_assumptions": True}
    except old.Invalid:
        raise
    except (KeyError, TypeError, ValueError, IndexError, OverflowError, OSError):
        raise old.Invalid("private-network-replay-unavailable-or-schema") from None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Public-only fresh network replay; no backup or parameter blob")
    parser.add_argument("descriptor"); parser.add_argument("public_manifest"); parser.add_argument("bundle"); parser.add_argument("new_output")
    args = parser.parse_args()
    try:
        result = replay(read_json(args.descriptor), read_json(args.bundle), read_json(args.public_manifest, canonical_manifest=True), output_directory=args.new_output)
        (Path(args.new_output) / "replay.json").write_bytes(canonical_bytes(result) + b"\n")
        print(json.dumps({"status": "PUBLIC_NETWORK_REPLAY_PASS", "reserve_sompi": result["head"]["reserve_sompi"],
                          "operations": len(result["operations"]), "complete": result["completeness"]["complete"]}))
    except old.Invalid as error:
        print(json.dumps({"status": "INCOMPLETE_OR_INVALID", "code": str(error), "balance_known": False}))
        raise SystemExit(2)
