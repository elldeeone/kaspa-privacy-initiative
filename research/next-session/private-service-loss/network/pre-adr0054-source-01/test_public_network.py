"""Synthetic public integration controls, not accepted-chain/native evidence.

Existing public Auth528 bodies and unrelated genuine headers are intentionally
combined into a synthetic provider view. Local SDK hashes can check identities;
they do not authenticate that invented acceptance assignment. No NativeValidator,
prover, backup, PK or RPC is invoked in this suite.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import network_replay as network
from network_replay import ROOT, old
from sealed_runtime import SealedExecutable


def fixture(length=None):
    source = ROOT / "research/next-session/privacy-recovery/compatibility/fixtures-01"
    descriptor = json.loads((source / "descriptor.json").read_bytes())
    supplied = json.loads((source / "supplied-public-bodies.json").read_bytes())
    actual = json.loads((ROOT / "research/next-session/privacy-recovery/fetch/vector-refetch-02/network-data/fetch.json").read_bytes())
    descriptor.update(schema="kpx3-private-network-descriptor/v1", birth_start_hash=actual["coverage"]["start_hash"])
    manifest = {"schema": "kpx3-public-proving-parameters/v1", "trial_id": "PUBLIC_SYNTHETIC_DO_NOT_FUND",
                "network_id": "testnet-10", "genesis_hash_hex": old.GENESIS,
                "domain_hex32": descriptor["domain_hex32"], "format": "arkworks0.6-bn254-uncompressed",
                "pk_bytes": 123, "pk_sha256": "11" * 32, "vk_hex328": descriptor["vk_hex328"],
                "vk_sha256": old.h(bytes.fromhex(descriptor["vk_hex328"])).hex(),
                "core_source_identity": {name + "_rs_sha256": "22" * 32 for name in
                    ("lib", "circuit", "exact_sha256", "request", "parameters", "main", "setup", "build")},
                "compiled_build_identity_sha256": "33" * 32,
                "constraint_shape": {"constraints": 1, "witness_variables": 1, "instances_including_one": 3},
                "queries": {"a": 1, "b_g1": 1, "b_g2": 1, "l": 1, "h": 1, "instances_including_one": 3},
                "setup_provenance": {name + "_sha256": "44" * 32 for name in
                    ("executable", "source_freeze", "public_setup_report")}}
    descriptor["public_params_manifest_sha256"] = old.digest(manifest)
    accepted = copy.deepcopy(actual["transactions"][-1]["accepting_block_header"])
    coverage = copy.deepcopy(actual["coverage"])
    sink_score = int(coverage["initial_sink"]["blueScore"])
    rows, expected, consumed = [], {}, set()
    for row in supplied["transactions"][:length]:
        tx = copy.deepcopy(row["transaction"])
        for key in ("lockTime", "gas", "storageMass"):
            tx[key] = str(tx[key])
        for input_ in tx["inputs"]:
            input_["sequence"] = str(input_["sequence"])
        for output in tx["outputs"]:
            output["value"] = str(output["value"])
        entries = copy.deepcopy(row["input_contexts"])
        for entry in entries:
            entry["amount_sompi"], entry["block_daa_score"] = str(entry["amount_sompi"]), str(entry["block_daa_score"])
            expected[old.point(entry["outpoint"])] = entry
            consumed.add(old.point(entry["outpoint"]))
        for index, output in enumerate(tx["outputs"]):
            point = old.outpoint(tx, index)
            expected[old.point(point)] = {"outpoint": point, "amount_sompi": output["value"], "script_public_key": output["scriptPublicKey"]}
        rows.append({"transaction": tx, "accepted_input_contexts": entries, "accepting_block_header": copy.deepcopy(accepted),
                     "confirmation_policy": {"min_confirmation_count": coverage["min_confirmation_count"],
                          "accepting_blue_score": accepted["blueScore"], "sink_blue_score": str(sink_score),
                          "actual_blue_score_distance": str(sink_score - int(accepted["blueScore"])), "passes": True},
                     "network_id": "testnet-10", "genesis_hash_hex": old.GENESIS,
                     "sdk_transaction_id_recomputed": False})
    queries = []
    for at, value in expected.items():
        entry = None if at in consumed else {**value, "block_daa_score": "1", "is_coinbase": False, "covenant_id": None}
        queries.append({**{key: value[key] for key in ("outpoint", "amount_sompi", "script_public_key")}, "queried": True, "entry": entry})
    view = copy.deepcopy(actual["current_view"]); view["queries"] = queries
    view["post_query_delta"]["watched_outpoints"] = [q["outpoint"] for q in queries if q["entry"] is not None]
    bundle = {"schema": "kpx3-private-network-fetch/v1", "network_id": "testnet-10", "genesis_hash_hex": old.GENESIS,
              "descriptor": descriptor, "descriptor_sha256": old.digest(descriptor), "transactions": rows,
              "coverage": coverage, "current_view": view,
              "public_params_manifest": manifest, "public_params_manifest_sha256": old.digest(manifest),
              "public_parameter_blob_read": False}
    return descriptor, bundle, manifest


class PublicNetworkTests(unittest.TestCase):
    def setUp(self):
        self.descriptor, self.bundle, self.manifest = fixture()

    def state(self):
        return network._public_state(self.descriptor, self.bundle, self.manifest)

    def test_semantics_remain_offline_and_incomplete(self):
        semantic, head, payouts, _, _ = self.state()
        self.assertFalse(semantic["completeness"]["complete"])
        self.assertFalse(semantic["completeness"]["accepted_chain_backing"])
        self.assertEqual(head["reserve_sompi"], 0)
        self.assertTrue(all(p["queried"] for p in payouts))

    def test_nonterminal_head_is_required_unspent(self):
        self.descriptor, self.bundle, self.manifest = fixture(6)
        _, head, _, _, _ = self.state()
        self.assertGreater(head["reserve_sompi"], 0)
        point = old.point(head["outpoint"])
        next(q for q in self.bundle["current_view"]["queries"] if old.point(q["outpoint"]) == point)["entry"] = None
        with self.assertRaises(old.Incomplete):
            self.state()

    def test_manifest_unknown_field_rejected(self):
        self.manifest["operator_archive"] = "forbidden"
        with self.assertRaises(old.Invalid): self.state()

    def test_manifest_VK_substitution_even_with_new_self_digest(self):
        self.manifest["vk_hex328"] = "11" * 328
        self.descriptor["public_params_manifest_sha256"] = old.digest(self.manifest)
        with self.assertRaises(old.Invalid): self.state()

    def test_tenth_field_is_mandatory(self):
        del self.descriptor["public_params_manifest_sha256"]
        with self.assertRaises(old.Invalid): self.state()

    def test_self_hash_cannot_approve_changed_program(self):
        raw = bytearray.fromhex(self.descriptor["initial_redeem_hex"]); raw[-1] ^= 1
        self.descriptor["initial_redeem_hex"] = raw.hex()
        self.descriptor["immutable_policy_sha256"] = old.h(raw[114:]).hex()
        with self.assertRaises(old.Invalid): self.state()

    def test_copied_manifest_must_match_separate_manifest(self):
        self.bundle["public_params_manifest"] = copy.deepcopy(self.manifest)
        self.bundle["public_params_manifest"]["trial_id"] = "another"
        with self.assertRaises(old.Invalid): self.state()

    def test_incomplete_or_truncated_scan_never_terminal_zero(self):
        for key, value in (("complete", False), ("pruned", True), ("missing", ["gap"]), ("end_cursor", "00" * 32)):
            saved = self.bundle["coverage"][key]; self.bundle["coverage"][key] = value
            with self.assertRaises(old.Incomplete): self.state()
            self.bundle["coverage"][key] = saved

    def test_accepted_row_outside_fixed_frontier(self):
        self.bundle["transactions"][0]["confirmation_policy"]["sink_blue_score"] = "999999999"
        with self.assertRaises(old.Invalid): self.state()

    def test_payout_query_cannot_be_missing(self):
        _, _, payouts, _, _ = self.state(); at = old.point(payouts[-1]["outpoint"])
        self.bundle["current_view"]["queries"] = [q for q in self.bundle["current_view"]["queries"] if old.point(q["outpoint"]) != at]
        with self.assertRaises(old.Incomplete): self.state()

    def test_consumed_head_cannot_appear_unspent(self):
        q = next(q for q in self.bundle["current_view"]["queries"] if q["entry"] is None)
        q["entry"] = {**{k: q[k] for k in ("outpoint", "amount_sompi", "script_public_key")},
                      "block_daa_score": "1", "is_coinbase": False, "covenant_id": None}
        with self.assertRaises(old.Incomplete): self.state()

    def test_postquery_must_watch_every_live_payout(self):
        self.bundle["current_view"]["post_query_delta"]["watched_outpoints"].pop()
        with self.assertRaises(old.Incomplete): self.state()

    def test_postquery_new_spend_or_removal_invalidates(self):
        for key in ("related_transactions", "removed_chain_block_hashes"):
            self.bundle["current_view"]["post_query_delta"][key] = ["aa" * 32]
            with self.assertRaises(old.Incomplete): self.state()
            self.bundle["current_view"]["post_query_delta"][key] = []

    def test_terminal_inactive_bytes_do_not_become_CM_append(self):
        payload = bytearray.fromhex(self.bundle["transactions"][-1]["transaction"]["payload"]); payload[268] = 1
        self.bundle["transactions"][-1]["transaction"]["payload"] = payload.hex()
        with self.assertRaises(old.Invalid): self.state()

    def test_manifest_file_requires_canonical_raw_no_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.json"; path.write_bytes(network.canonical_bytes(self.manifest) + b"\n")
            with self.assertRaises(old.Invalid): network.read_json(path, canonical_manifest=True)

    def test_duplicate_JSON_field_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.json"; path.write_text('{"schema":1,"schema":2}')
            with self.assertRaises(old.Invalid): network.read_json(path)

    def test_sdk_recomputes_real_body_header_hashes_and_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as directory, SealedExecutable(network.NODE_EXECUTABLE, network.NODE_SHA256) as node:
            directory = Path(directory); files = [directory / name for name in ("d.json", "m.json", "b.json")]
            for path, value in zip(files, (self.descriptor, self.manifest, self.bundle)):
                path.write_bytes(network.canonical_bytes(value))
            output = directory / "sdk.json"
            process = node.run([network.HERE / "verify_bundle.mjs", *files, output])
            self.assertEqual(process.returncode, 0, process.stderr)
            receipt = network.read_json(output)
            self.assertTrue(receipt["transaction_ids_recomputed"])
            self.assertTrue(receipt["header_hashes_recomputed"])
            self.assertFalse(receipt["chain_inclusion_or_pow_verified"])
            self.bundle["coverage"]["frontier"]["nonce"] = "1"
            files[2].write_bytes(network.canonical_bytes(self.bundle))
            self.assertNotEqual(node.run([network.HERE / "verify_bundle.mjs", *files, directory / "bad.json"]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
