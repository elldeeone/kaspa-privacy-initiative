"""Offline controls over immutable six-body native evidence; never contacts RPC."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import recovery_check as check

ROOT = check.ROOT
BASE = ROOT / "research/next-session/private-integration/lifecycle"


def dump_snapshot(snapshot):
    return {"deliveries": [d.public() for d in snapshot.deliveries],
            "nullifiers": [{"value": e.value.hex(), "next_value": e.next_value.hex(),
                            "next_index": e.next_index} for e in snapshot.nullifiers]}


def native_paths():
    return [BASE / name / "transaction.json" for name in (
        "prefix-01/funding-prep", "prefix-01/founding", "prefix-01/admit",
        "execution-01/private", "execution-01/bob-reveal", "execution-01/charlie-reveal")]


def local_observation(body):
    outputs = []
    for index, row in enumerate(body["outputs"]):
        entry = {"outpoint": check.point(body, index), "amount_sompi": row["value"],
                 "script_public_key": row["scriptPublicKey"], "is_coinbase": False,
                 "covenant_id": None}
        outputs.append({"index": index, **entry, "utxo": dict(entry)})
    return {"transaction_id": body["id"], "accepted_body": body,
            "accepted_body_sha256": check.body_hash(body), "trust": check.LOCAL,
            "current_outputs": outputs,
            "spent_inputs": [{"outpoint": row["previousOutpoint"], "unspent": False}
                             for row in body["inputs"]]}


def fixture(prefix=6, label="bob"):
    bodies = [check.canonical(json.loads(path.read_bytes())) for path in native_paths()][:prefix]
    stored = json.loads((BASE / "materialized-01/records.json").read_bytes())
    final = check.parse_snapshot(json.loads((BASE / "execution-01/final-public-records.json").read_bytes()))
    # Independently recover the pre-terminal physical set from the immutable
    # terminal body's authenticated OLD predecessor record and final leaf list.
    last_payload = bytes.fromhex(json.loads(native_paths()[-1].read_bytes())["payload"])
    predecessor_index = int.from_bytes(last_payload[757:761], "little")
    entries = list(final.nullifiers[:-1])
    entries[predecessor_index] = check.NFEntry(last_payload[761:793], last_payload[793:825],
                                            int.from_bytes(last_payload[825:829], "little"))
    after_bob = check.Snapshot(list(final.deliveries), entries)
    snapshots = {"founding": stored["genesis"], "before-private": stored["before-private"],
                 "after-private": stored["after-private"], "after-bob": dump_snapshot(after_bob),
                 "terminal": dump_snapshot(final)}
    name = check.SNAPSHOTS[prefix - 1]
    snapshot = check.parse_snapshot(snapshots[name])
    reserve = 2_000_000_000 if prefix == 4 else 1_000_000_000 if prefix == 5 else 0
    old = [local_observation(body) for body in bodies]
    identity = {"trial_id": "OFFLINE_PUBLIC_SIX_BODY_CONTROL_ONLY", "domain_hex32": check.OLD_DOMAIN,
                "network_id": "testnet-10", "genesis_hash_hex": check.GENESIS,
                "classification": "PUBLIC_SYNTHETIC_DO_NOT_FUND"}
    backups = json.loads((BASE / "shape-01/PUBLIC-SYNTHETIC-backups.json").read_bytes())
    seed = backups["backups"][label.capitalize()]["seed32"]
    backup = {"schema": "kpx2-tn10-seed-backup/v1", "domain_hex32": check.OLD_DOMAIN,
              "network_id": "testnet-10", "genesis_hash_hex": check.GENESIS, "seed_hex32": seed}
    archive = {"schema": "kpx2-tn10-accepted-archive/v1", "oracle_stage": check.LOCAL,
               **{key: identity[key] for key in ("trial_id", "domain_hex32", "network_id", "genesis_hash_hex")},
               "operations": [{"kind": kind, "txid_raw_hex": body["id"]}
                              for kind, body in zip(check.KINDS, bodies)],
               "expected_payments_sompi": {"bob": 1_000_000_000, "charlie": 1_000_000_000},
               "snapshots": snapshots,
               "head": {"state_hex112": check.state(snapshot, bytes.fromhex(check.OLD_DOMAIN)).hex(),
                        "reserve_sompi": reserve, "outpoint": check.point(bodies[-1], 0) if reserve else None,
                        "accepted_operation_index": prefix - 1}}
    view = {"schema": "kpx2-tn10-current-view/v1", "trial_id": identity["trial_id"],
            "oracle_stage": check.LOCAL, "checkpoint": {"classification": check.LOCAL},
            "observations": old[-2:] if prefix == 6 else old[-1:]}
    return identity, backup, archive, view, bodies, old


class AcceptedRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto = check.Crypto(Path(os.environ.get("KPX_RECIPIENT_CRYPTO",
             ROOT.parent / "recipient-target/debug/kpi-future-recipient-crypto")))

    def run_case(self, data, label="bob"):
        return check.evaluate(*data, self.crypto, label, check.LOCAL)

    def test_01_two_seed_only_terminal_receivers_and_true_zero(self):
        for label in ("bob", "charlie"):
            result = self.run_case(fixture(label=label), label)
            self.assertEqual(result["reserve_sompi"], 0)
            self.assertEqual(result["owned_unspent_sompi"], 0)
            self.assertTrue(result["both_payout_utxos_reobserved"])
            self.assertFalse(result["confirmed_with_trusted_node"])
            self.assertFalse(result["prover_or_payer_secret_read"])

    def test_02_current_seed_only_recovery_without_authorization(self):
        for prefix, label in ((4, "bob"), (4, "charlie"), (5, "charlie")):
            result = self.run_case(fixture(prefix, label), label)
            self.assertEqual(result["owned_unspent_sompi"], 1_000_000_000)
            self.assertEqual(result["current_witnesses_constructible"], 1)
            self.assertFalse(result["terminal_zero"])

    def test_03_missing_public_receipt_data_rejects(self):
        data = fixture()
        data[2]["snapshots"]["after-private"]["deliveries"][2]["ciphertext"] = None
        with self.assertRaises(ValueError):
            self.run_case(data)

    def test_04_missing_current_reserve_rejects_stale_head(self):
        data = fixture(4)
        data[3]["observations"][0]["current_outputs"] = []
        with self.assertRaisesRegex(check.Invalid, "^stale-head-or-missing-payout$"):
            self.run_case(data)

    def test_05_archive_head_cannot_name_old_reserve(self):
        data = fixture()
        data[2]["head"]["outpoint"] = check.point(data[4][3], 0)
        with self.assertRaisesRegex(check.Invalid, "^archive-head$"):
            self.run_case(data)

    def test_06_competing_accepted_spend_is_rejected_before_updates(self):
        data = fixture()
        data[4][5]["inputs"][0]["previousOutpoint"] = copy.deepcopy(data[4][4]["inputs"][0]["previousOutpoint"])
        data[5][5] = local_observation(data[4][5])
        with self.assertRaisesRegex(check.Invalid, "^competing-accepted-spends$"):
            self.run_case(data)

    def test_07_second_nf_cannot_duplicate_first_nf(self):
        data = fixture()
        payload = bytearray.fromhex(data[4][3]["payload"])
        payload[236:268] = payload[204:236]
        data[4][3]["payload"] = payload.hex()
        data[5][3] = local_observation(data[4][3])
        with self.assertRaisesRegex(check.Invalid, "^double-spend-or-zero-nf$"):
            self.run_case(data)

    def test_08_body_substitution_rejects(self):
        data = fixture()
        data[5][3]["accepted_body"] = copy.deepcopy(data[4][3])
        data[5][3]["accepted_body"]["payload"] = "00"
        with self.assertRaisesRegex(check.Invalid, "^accepted-body-substitution$"):
            self.run_case(data)

    def test_09_actual_payout_substitution_cannot_pass(self):
        data = fixture()
        data[4][4]["outputs"][1]["value"] = str(int(data[4][4]["outputs"][1]["value"]) + 1)
        data[5][4] = local_observation(data[4][4])
        with self.assertRaisesRegex(check.Invalid, "^owned-native-payout$"):
            self.run_case(data)

    def test_10_both_current_payouts_required(self):
        data = fixture()
        data[3]["observations"] = data[3]["observations"][1:]
        with self.assertRaisesRegex(check.Invalid, "^missing-refreshed-observation$"):
            self.run_case(data)

    def test_11_payout_amount_and_spent_reserve_view_checked(self):
        data = fixture()
        data[3]["observations"][0]["current_outputs"][1]["utxo"]["amount_sompi"] = "1"
        with self.assertRaisesRegex(check.Invalid, "^current-utxo-mismatch$"):
            self.run_case(data)
        data = fixture()
        data[3]["observations"][1]["spent_inputs"][0]["unspent"] = True
        with self.assertRaisesRegex(check.Invalid, "^final-reserve-input-still-unspent$"):
            self.run_case(data)

    def test_12_wrong_backup_and_cross_trial_reject(self):
        data = fixture()
        data[1]["seed_hex32"] = bytes(32).hex()
        with self.assertRaisesRegex(check.Invalid, "^backup-does-not-recover-pilot-recipient$"):
            self.run_case(data)
        data = fixture()
        data[2]["trial_id"] = "OTHER_TRIAL"
        with self.assertRaisesRegex(check.Invalid, "^trial-identity$"):
            self.run_case(data)

    def test_13_local_control_cannot_be_upgraded_to_network_confirmation(self):
        data = fixture()
        data[2]["oracle_stage"] = check.NETWORK
        with self.assertRaises((check.Invalid, KeyError)):
            check.evaluate(*data, self.crypto, "bob", check.NETWORK)

    def test_14_refreshed_view_rejects_old_observation_but_allows_later_sink(self):
        # Mocked RPC metadata only, no live identity, seed or RPC is involved.
        view = {"checkpoint": {"network": "testnet-10", "expected_genesis": check.GENESIS,
                "start_hash": "11" * 32, "reference_sink": "22" * 32,
                "observed_at": "2026-10-23T03:00:00+00:00"},
                "observations": [{"observed_at": "2026-10-23T02:59:59+00:00", "observed_sink": "33" * 32}]}
        with self.assertRaisesRegex(check.Invalid, "^stale-current-observation$"):
            check.freshness(view, check.NETWORK)
        view["observations"][0]["observed_at"] = "2026-10-23T03:00:01+00:00"
        check.freshness(view, check.NETWORK)

    def test_15_removed_acceptance_and_wrong_node_network_reject(self):
        body = fixture()[4][0]
        observed = local_observation(body)
        observed.update(trust=check.TRUST, network="testnet-10", expected_genesis=check.GENESIS,
                        confirmation_policy={"min_confirmation_count": 20},
                        observed_sink="11" * 32, start_hash="22" * 32,
                        accepting_block_header={"hash": "33" * 32}, chain_delta_removed=["44" * 32])
        with self.assertRaisesRegex(check.Invalid, "^stale-or-removed-accepted-head$"):
            check.observation(observed, body, check.NETWORK)
        observed["chain_delta_removed"] = []
        observed["network"] = "mainnet"
        with self.assertRaisesRegex(check.Invalid, "^node-network-oracle$"):
            check.observation(observed, body, check.NETWORK)

    def test_16_pinned_artifact_refuses_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public-artifact.json"
            raw = b'{"public":"original"}'
            path.write_bytes(raw)
            sha = hashlib.sha256(raw).hexdigest()
            check.pinned_json(path.parent, path.name, sha)
            path.write_bytes(b'{"public":"substituted"}')
            with self.assertRaisesRegex(check.Invalid, "^artifact-hash$"):
                check.pinned_json(path.parent, path.name, sha)

    def test_17_declared_payment_cannot_relabel_actual_receipt_amount(self):
        data = fixture()
        data[2]["expected_payments_sompi"]["bob"] = 100_000_000
        with self.assertRaisesRegex(check.Invalid, "^backup-does-not-recover-pilot-recipient$"):
            self.run_case(data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
