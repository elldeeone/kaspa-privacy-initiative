"""Public replay controls. Retained actual records are LOCAL test inputs only."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random
import unittest

from replay import (Incomplete, Invalid, GENESIS, SparseTree, CM_NODE, CM_EMPTY,
                    descriptor_check, digest, h, replay)

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "research/next-session/testnet-rehearsal/accepted-01"


def fixture():
    """Adapt previously confirmed public records; this makes no fresh RPC claim."""
    def load(path):
        return json.loads(path.read_bytes())
    bodies = PUBLIC / "chain-public/bodies"
    observations = PUBLIC / "chain-public/observations"
    identity = load(PUBLIC / "public/identity.json")
    admit = load(bodies / "admit.json")
    initial = bytes.fromhex(admit["inputs"][0]["signatureScript"])[199:]
    birth = load(PUBLIC / "chain/founding.submission-intent.json")["start_hash"]
    descriptor = {"schema": "kpx2-recovery-descriptor/v1", "network_id": "testnet-10",
        "genesis_hash_hex": GENESIS, "domain_hex32": identity["domain_hex32"],
        "founding_outpoint": {"transactionId": load(bodies / "founding.json")["id"], "index": 0},
        "birth_start_hash": birth, "initial_redeem_hex": initial.hex(),
        "vk_hex328": (PUBLIC / "setup/verification-key.bin").read_bytes().hex(),
        "immutable_policy_sha256": h(initial[114:]).hex()}
    rows = []
    for name in ("founding", "admit", "private", "bob-reveal", "charlie-reveal"):
        observed = load(observations / (name + ".json"))
        rows.append({"transaction": load(bodies / (name + ".json")),
            "accepted_input_contexts": observed["accepted_input_contexts"],
            "accepting_block_header": observed["accepting_block_header"],
            "confirmation_policy": observed["confirmation_policy"],
            "sdk_transaction_id_recomputed": True,
            "network_id": "testnet-10", "genesis_hash_hex": GENESIS})
    final = load(next(PUBLIC.glob("chain-public/phase-5-*/current.json")))
    queries = {}
    for row in rows:
        for entry in row["accepted_input_contexts"]:
            key = (entry["outpoint"]["transactionId"], entry["outpoint"]["index"])
            queries[key] = {"outpoint": entry["outpoint"], "script_public_key": entry["script_public_key"],
                            "amount_sompi": entry["amount_sompi"], "queried": True, "entry": None}
    for record in final["observations"]:
        for entry in record["spent_inputs"]:
            key = (entry["outpoint"]["transactionId"], entry["outpoint"]["index"])
            queries[key].update(entry=None)
        for entry in record["current_outputs"]:
            key = (entry["outpoint"]["transactionId"], entry["outpoint"]["index"])
            queries[key] = {"outpoint": entry["outpoint"], "script_public_key": entry["script_public_key"],
                            "amount_sompi": entry["amount_sompi"], "queried": True, "entry": entry["utxo"]}
    last = final["observations"][-1]
    fixed_sink = {"hash": last["observed_sink"], "blueScore": last["confirmation_policy"]["sink_blue_score"]}
    boundary = rows[-1]["accepting_block_header"]
    for row in rows:
        row["confirmation_policy"]["sink_blue_score"] = fixed_sink["blueScore"]
        row["confirmation_policy"]["actual_blue_score_distance"] = str(
            int(fixed_sink["blueScore"]) - int(row["confirmation_policy"]["accepting_blue_score"]))
    bundle = {"schema": "kpx2-network-fetch/v1", "network_id": "testnet-10", "genesis_hash_hex": GENESIS,
        "descriptor_sha256": digest(descriptor), "transactions": rows,
        "source": {"classification": "LOCAL_RETAINED_ACTUAL_RECORD_CONTROL_NO_NEW_RPC"},
        "coverage": {"start_hash": birth, "anchor_header": {"hash": birth, "blueScore": "0"},
            "frontier": boundary, "initial_sink": fixed_sink, "min_confirmation_count": 20,
            "end_cursor": boundary["hash"], "complete": True,
            "frontier_seen": True, "removed_chain_block_hashes": [], "missing": [], "pruned": False},
        "current_view": {"checkpoint": final["checkpoint"], "queries": list(queries.values()),
            "observed_at": last["observed_at"], "post_query_delta": {
                "start_hash": boundary["hash"], "frontier": boundary, "completed": True,
                "removed_chain_block_hashes": [], "related_transactions": [],
                "checked_at": last["observed_at"]}},
        "verification": {"sdk_transaction_ids_recomputed": True}}
    return descriptor, bundle


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.descriptor, self.bundle = fixture()

    def result(self):
        return replay(self.descriptor, self.bundle)

    def test_real_public_lineage_reconstructs_without_snapshots_or_amounts(self):
        result = self.result()
        self.assertEqual(len(result["operations"]), 5)  # Genesis plus pool transitions, no funding-prep dependency.
        self.assertEqual(len(result["deliveries"]), 4)
        self.assertEqual(len(result["nullifiers"]), 5)
        self.assertEqual(result["head"]["reserve_sompi"], 0)
        self.assertIsNone(result["head"]["outpoint"])
        self.assertEqual([p["amount_sompi"] for p in result["payouts"]], [95_026_200, 95_036_800])
        self.assertFalse(result["local_native_validation"])
        self.assertEqual(result["groth16_and_signatures"], "TRUSTED_VALIDATING_NODE")

    def test_unordered_raw_rows_follow_actual_outpoints(self):
        self.bundle["transactions"].reverse()
        self.assertEqual(self.result()["head"]["reserve_sompi"], 0)

    def test_payout_later_spent_is_not_erased_historical_payment(self):
        for query in self.bundle["current_view"]["queries"]:
            query["entry"] = None
        result = self.result()
        self.assertEqual(sum(p["amount_sompi"] for p in result["payouts"]), 190_063_000)
        self.assertTrue(all(p["current_utxo"] is None for p in result["payouts"]))

    def test_missing_founding_is_incomplete(self):
        self.bundle["transactions"].pop(0)
        with self.assertRaisesRegex(Incomplete, "missing-founding"):
            self.result()

    def test_missing_middle_never_returns_zero(self):
        self.bundle["transactions"].pop(1)
        with self.assertRaises(Incomplete):
            self.result()

    def test_truncated_tail_never_returns_zero(self):
        self.bundle["transactions"].pop()
        with self.assertRaisesRegex(Incomplete, "current-utxo"):
            self.result()

    def test_duplicate_accepted_body_rejects(self):
        self.bundle["transactions"].append(deepcopy(self.bundle["transactions"][2]))
        with self.assertRaisesRegex(Invalid, "duplicate-accepted"):
            self.result()

    def test_competing_children_reject(self):
        fork = deepcopy(self.bundle["transactions"][2])
        fork["transaction"]["id"] = "ab" * 32
        self.bundle["transactions"].append(fork)
        with self.assertRaisesRegex(Invalid, "competing-accepted"):
            self.result()

    def test_corrupt_private_ciphertext_rejects(self):
        tx = self.bundle["transactions"][2]["transaction"]
        payload = bytearray.fromhex(tx["payload"]);payload[484] ^= 1;tx["payload"] = payload.hex()
        with self.assertRaisesRegex(Invalid, "ciphertext-binding"):
            self.result()

    def test_corrupt_nf_current_path_rejects(self):
        tx = self.bundle["transactions"][2]["transaction"]
        payload = bytearray.fromhex(tx["payload"]);payload[1012 + 72] ^= 1;tx["payload"] = payload.hex()
        with self.assertRaisesRegex(Invalid, "nf-current-path"):
            self.result()

    def test_corrupt_reveal_position_rejects(self):
        tx = self.bundle["transactions"][3]["transaction"]
        payload = bytearray.fromhex(tx["payload"]);payload[177:181] = (65534).to_bytes(4, "little")
        tx["payload"] = payload.hex()
        with self.assertRaisesRegex(Invalid, "reveal-position"):
            self.result()

    def test_wrong_input_context_rejects(self):
        self.bundle["transactions"][2]["accepted_input_contexts"][0]["amount_sompi"] = "1"
        with self.assertRaises(Invalid):
            self.result()

    def test_policy_mutation_even_with_matching_self_hash_rejects(self):
        raw = bytearray.fromhex(self.descriptor["initial_redeem_hex"]);raw[-1] ^= 1
        self.descriptor["initial_redeem_hex"] = raw.hex()
        self.descriptor["immutable_policy_sha256"] = h(raw[114:]).hex()
        self.bundle["descriptor_sha256"] = digest(self.descriptor)
        with self.assertRaisesRegex(Invalid, "unapproved-policy"):
            self.result()

    def test_wrong_genesis_state_rejects(self):
        raw = bytearray.fromhex(self.descriptor["initial_redeem_hex"]);raw[42] ^= 1
        self.descriptor["initial_redeem_hex"] = raw.hex()
        self.bundle["descriptor_sha256"] = digest(self.descriptor)
        with self.assertRaisesRegex(Invalid, "incoherent-founding"):
            self.result()

    def test_false_terminal_reserve_absence_rejects(self):
        query = self.bundle["current_view"]["queries"][1]
        # The consumed Bob reserve cannot be an unqueried/missing assertion.
        self.bundle["current_view"]["queries"] = [q for q in self.bundle["current_view"]["queries"]
            if q["outpoint"] != self.bundle["transactions"][-1]["transaction"]["inputs"][0]["previousOutpoint"]]
        with self.assertRaisesRegex(Incomplete, "consumed-input"):
            self.result()

    def test_terminal_query_for_unrelated_script_rejects(self):
        consumed = self.bundle["transactions"][-1]["transaction"]["inputs"][0]["previousOutpoint"]
        query = next(q for q in self.bundle["current_view"]["queries"] if q["outpoint"] == consumed)
        query["script_public_key"] = "000020" + "33" * 32 + "ac"
        with self.assertRaisesRegex(Incomplete, "consumed-input"):
            self.result()

    def test_consumed_predecessor_cannot_remain_unspent(self):
        old = self.bundle["transactions"][1]["accepted_input_contexts"][0]
        query = next(q for q in self.bundle["current_view"]["queries"] if q["outpoint"] == old["outpoint"])
        query["entry"] = deepcopy(old)
        with self.assertRaisesRegex(Incomplete, "consumed-input"):
            self.result()

    def test_per_row_false_depth_cannot_use_another_sink(self):
        row = self.bundle["transactions"][2]
        row["confirmation_policy"]["sink_blue_score"] = str(int(row["confirmation_policy"]["sink_blue_score"]) + 1)
        row["confirmation_policy"]["actual_blue_score_distance"] = str(int(row["confirmation_policy"]["actual_blue_score_distance"]) + 1)
        with self.assertRaisesRegex(Incomplete, "scan-frontier"):
            self.result()

    def test_removed_or_pruned_or_stale_scans_are_incomplete(self):
        for field, value in (("removed_chain_block_hashes", ["aa" * 32]), ("pruned", True),
                             ("frontier_seen", False), ("complete", False), ("missing", ["gap"])):
            with self.subTest(field=field):
                descriptor, bundle = fixture();bundle["coverage"][field] = value
                with self.assertRaises(Incomplete):
                    replay(descriptor, bundle)

    def test_new_related_spend_after_frontier_is_incomplete(self):
        self.bundle["current_view"]["post_query_delta"]["related_transactions"] = ["aa" * 32]
        with self.assertRaisesRegex(Incomplete, "stale-frontier"):
            self.result()

    def test_descriptor_has_no_operator_snapshot_escape(self):
        self.descriptor["snapshots"] = {}
        with self.assertRaisesRegex(Invalid, "descriptor-fields"):
            self.result()

    def test_bool_amount_cannot_be_integer(self):
        self.bundle["transactions"][0]["transaction"]["outputs"][0]["value"] = True
        with self.assertRaisesRegex(Invalid, "canonical-integer"):
            self.result()

    def synthetic(self):
        return {"schema": "kpx2-unproved-synthetic/v1", "context": "UNPROVED_SYNTHETIC",
            "network_id": "testnet-10", "genesis_hash_hex": GENESIS,
            "descriptor_sha256": digest(self.descriptor),
            "transactions": [{"transaction": row["transaction"],
                "input_contexts": row["accepted_input_contexts"]} for row in self.bundle["transactions"]],
            "declared_view": {"queries": self.bundle["current_view"]["queries"]}}

    def test_synthetic_context_has_no_accepted_node_claim(self):
        result = replay(self.descriptor, self.synthetic(), context="UNPROVED_SYNTHETIC")
        self.assertFalse(result["completeness"]["complete"])
        self.assertTrue(result["completeness"]["public_replay_complete"])
        self.assertEqual(result["groth16_and_signatures"], "UNCHECKED_SYNTHETIC")
        self.assertFalse(result["sdk_transaction_id_validation"])
        self.assertIsNone(result["head"]["accepting_block_header"])

    def test_synthetic_cannot_enter_default_network_api(self):
        with self.assertRaisesRegex(Invalid, "fetch-descriptor-binding"):
            replay(self.descriptor, self.synthetic())

    def test_synthetic_cannot_claim_local_native_validation(self):
        with self.assertRaisesRegex(Invalid, "synthetic-context"):
            replay(self.descriptor, self.synthetic(), lambda tx, entries: True,
                   context="UNPROVED_SYNTHETIC")

    def test_sparse_updates_match_independent_full_tree(self):
        import sys
        sys.path.insert(0, str(ROOT / "poc/future-recipient/v2"))
        from recipient import Tree
        rng = random.Random(7411)
        sparse = SparseTree(16, CM_NODE, CM_EMPTY)
        leaves = []
        for index in range(80):
            value = hashlib.sha256(rng.randbytes(32)).digest()
            sparse.set(index, value);leaves.append(value)
            reference = Tree(16, leaves, CM_NODE, CM_EMPTY)
            self.assertEqual(sparse.root, reference.root)
            self.assertEqual(sparse.path(index), b"".join(reference.path(index)))


if __name__ == "__main__":
    unittest.main()
