"""Finite KPX2 TN10 accepted-record recovery checker; no network or signer.

Only the selected six-body pilot is supported. A refreshed validating-node
Full-history/UTXO observation is a trusted oracle, not an independent consensus
proof or durable public archive. The checker reads one seed-only backup, never
a payer profile, proving key, prover executable or another recipient's secret.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "poc/future-recipient/v2"))
from recipient import (Crypto, Delivery, ExpectedState, NFEntry, Receiver, Snapshot,
                       ZERO, CM_DEPTH, CM_NODE, CM_EMPTY, NF_DEPTH, NF_NODE, NF_EMPTY,
                       Tree, h, u32, u64, recover, exit_witness)

_spec = importlib.util.spec_from_file_location("kpx2_safe_native_body",
                ROOT / "poc/future-native-chain/native_safe.py")
_safe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_safe)

GENESIS = "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370"
OLD_DOMAIN = "9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c"
TRUST = "VALIDATING_NODE_AND_PUBLIC_ARCHIVE_ORACLE"
LOCAL = "LOCAL_SUPPLIED_CONTEXT"
NETWORK = "TRUSTED_TN10_ACCEPTED_NODE"
KINDS = ("fundingprep", "founding", "admit", "private", "bob-reveal", "charlie-reveal")
SNAPSHOTS = {1: "founding", 2: "before-private", 3: "after-private",
             4: "after-bob", 5: "terminal"}
MAX_SOMPI = 2_870_000_000_000_000_000


class Invalid(ValueError):
    """Secret-free stable failure category."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def exact(value, size=None):
    require(type(value) is str and re.fullmatch("(?:[0-9a-f]{2})*", value) is not None,
            "canonical-hex")
    raw = bytes.fromhex(value)
    require(size is None or len(raw) == size, "hex-width")
    return raw


def amount(value):
    require(type(value) is int or type(value) is str and re.fullmatch("0|[1-9][0-9]*", value),
            "integer-sompi")
    value = int(value)
    require(0 <= value <= MAX_SOMPI, "sompi-range")
    return value


def canonical(body):
    if "mass" in body:
        return _safe.body(body)
    require(set(body) == {"version", "id", "inputs", "outputs", "lockTime", "subnetworkId",
                          "gas", "payload", "storageMass"}, "canonical-body-fields")
    require(body["version"] == 1, "transaction-version")
    exact(body["id"], 32)
    exact(body["payload"])
    for output in body["outputs"]:
        require(set(output) == {"value", "scriptPublicKey", "covenant"}
                and output["covenant"] is None, "output-metadata")
        amount(output["value"])
        exact(output["scriptPublicKey"])
    return body


def body_hash(body):
    # Match adapter.mjs stringify(canonical(body)); insertion order is canonical.
    return hashlib.sha256(json.dumps(body, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def point(tx, index):
    return {"transactionId": tx["id"], "index": index}


def point_key(value):
    require(set(value) == {"transactionId", "index"}, "outpoint-fields")
    exact(value["transactionId"], 32)
    require(type(value["index"]) is int and 0 <= value["index"] < 1 << 32, "outpoint-index")
    return value["transactionId"], value["index"]


def pinned_json(base, path, sha):
    file = Path(path)
    file = file if file.is_absolute() else base / file
    raw = file.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == sha, "artifact-hash")
    return json.loads(raw)


def parse_snapshot(raw):
    require(set(raw) == {"deliveries", "nullifiers"}, "snapshot-fields")
    return Snapshot([Delivery(d["position"], exact(d["cm"], 32),
                    None if d["ciphertext"] is None else exact(d["ciphertext"], 264))
                    for d in raw["deliveries"]],
                    [NFEntry(exact(e["value"], 32), exact(e["next_value"], 32),
                             e["next_index"]) for e in raw["nullifiers"]])


def state(snapshot, domain):
    cm, nf = snapshot.roots()
    return (b"KPX2ST01" + domain + cm.root + u32(len(snapshot.deliveries))
            + nf.root + u32(len(snapshot.nullifiers)))


def same_snapshot(supplied, actual, domain):
    # This immutable-library pin checks mathematical roots/records only. Chain
    # authority is established separately from trusted node observations below.
    supplied.verify(supplied.pin(domain))
    require(supplied.deliveries == actual.deliveries and supplied.nullifiers == actual.nullifiers,
            "accepted-record-snapshot-mismatch")


def redeem(tx):
    sig = exact(tx["inputs"][0]["signatureScript"])
    require(len(sig) >= 199 and sig[:1] == b"\x41" and sig[66:68] == b"\x4c\x80"
            and sig[196:197] == b"\x4d", "pool-witness-frame")
    raw = sig[199:]
    require(len(raw) == int.from_bytes(sig[197:199], "little") and raw[:2] == b"\x4c\x70",
            "pool-redeem-frame")
    return raw


def p2sh(raw):
    return (b"\0\0\xaa\x20" + hashlib.blake2b(raw, digest_size=32).digest() + b"\x87").hex()


def check_successor(tx, old_redeem, snapshot, domain, reserve):
    if reserve == 0:
        require(len(tx["outputs"]) == 1, "terminal-reserve-output")
        return
    require(amount(tx["outputs"][0]["value"]) == reserve, "reserve-value")
    expected = old_redeem[:2] + state(snapshot, domain) + old_redeem[114:]
    require(tx["outputs"][0]["scriptPublicKey"] == p2sh(expected), "immutable-successor")


def insert(snapshot, value, witness):
    require(value != ZERO and not any(e.value == value for e in snapshot.nullifiers),
            "double-spend-or-zero-nf")
    require(len(witness) == 1160, "nf-witness-width")
    index = int.from_bytes(witness[:4], "little")
    require(index < len(snapshot.nullifiers), "nf-predecessor-index")
    entry = snapshot.nullifiers[index]
    require(witness[4:72] == entry.value + entry.next_value + u32(entry.next_index),
            "nf-predecessor-record")
    _, tree = snapshot.roots()
    require(witness[72:616] == b"".join(tree.path(index)), "nf-current-path")
    v = int.from_bytes(value, "little")
    require(int.from_bytes(entry.value, "little") < v and
            (entry.next_value == ZERO or v < int.from_bytes(entry.next_value, "little")),
            "nf-strict-absence")
    m = len(snapshot.nullifiers)
    updated = NFEntry(entry.value, value, m)
    intermediate = tree.with_leaf(index, updated.leaf())
    require(witness[616:] == b"".join(intermediate.path(m)), "nf-intermediate-append-path")
    entries = list(snapshot.nullifiers)
    entries[index] = updated
    entries.append(NFEntry(value, entry.next_value, entry.next_index))
    return Snapshot(list(snapshot.deliveries), entries), intermediate.root


def append(snapshot, cm, ciphertext, witness):
    require(ciphertext is not None and len(ciphertext) == 264, "missing-receipt-data")
    tree, _ = snapshot.roots()
    require(witness == b"".join(tree.path(len(snapshot.deliveries))), "cm-append-path")
    return Snapshot(snapshot.deliveries + [Delivery(len(snapshot.deliveries), cm, ciphertext)],
                    list(snapshot.nullifiers))


def record(payload, domain, expected_magic):
    require(payload[:8] == expected_magic and payload[8:40] == domain, "operation-domain")
    note, cm, cipher = payload[40:208], payload[208:240], payload[240:504]
    require(h(b"KPX1NOT\0", domain, note) == cm, "public-note-cm")
    require(h(cipher) == payload[504:536], "public-receipt-hash")
    value = int.from_bytes(note[64:72], "little")
    require(60_000_000 <= value <= MAX_SOMPI, "public-note-value")
    return note, Delivery(0, cm, cipher), value


def finite_trace(bodies, snapshots, domain):
    require(len(bodies) in (4, 5, 6), "finite-operation-prefix")
    spent, txids = set(), set()
    for tx in bodies:
        require(tx["id"] not in txids, "duplicate-accepted-transaction")
        txids.add(tx["id"])
        for input_ in tx["inputs"]:
            key = point_key(input_["previousOutpoint"])
            require(key not in spent, "competing-accepted-spends")
            spent.add(key)
    require(bodies[1]["inputs"][0]["previousOutpoint"] == point(bodies[0], 0),
            "founding-funding-link")
    require(bodies[2]["inputs"][1]["previousOutpoint"] == point(bodies[0], 1),
            "admission-funding-link")
    payload = exact(bodies[1]["payload"], 536)
    genesis_note, founding, reserve = record(payload, domain, b"KPX2GN01")
    current = Snapshot([founding], [NFEntry(ZERO, ZERO, 0)])
    require(amount(bodies[1]["outputs"][0]["value"]) == reserve, "founding-reserve")
    same_snapshot(parse_snapshot(snapshots["founding"]), current, domain)
    payouts, before_reveals = [], {}
    template = None
    for index in range(2, len(bodies)):
        tx, prior = bodies[index], bodies[index - 1]
        require(tx["inputs"][0]["previousOutpoint"] == point(prior, 0), "reserve-lineage")
        raw_redeem = redeem(tx)
        require(raw_redeem[2:114] == state(current, domain), "current-state")
        require(prior["outputs"][0]["scriptPublicKey"] == p2sh(raw_redeem), "current-p2sh")
        if template is None:
            template = raw_redeem[114:]
        require(raw_redeem[114:] == template, "policy-changed")
        payload = exact(tx["payload"])
        if index == 2:
            require(len(payload) == 1344 and len(tx["inputs"]) == 2, "admission-body")
            note, delivery, value = record(payload, domain, b"KPX2AD01")
            require(payload[1176:] == genesis_note, "first-admission-genesis")
            current = append(current, delivery.cm, delivery.ciphertext, payload[536:1048])
            reserve += value
            require(payload[1048:1160] == state(current, domain), "admission-next-state")
            check_successor(tx, raw_redeem, current, domain, reserve)
        elif index == 3:
            require(len(payload) == 4356 and len(tx["inputs"]) == len(tx["outputs"]) == 1,
                    "private-body")
            require(payload[:8] == b"KPX2AU01" and payload[8:40] == domain and
                    payload[76:188] == state(current, domain), "private-auth-state")
            require(payload[40:76] == exact(prior["id"], 32) + u32(0), "private-auth-outpoint")
            require(int.from_bytes(payload[188:196], "little") == reserve, "private-auth-reserve")
            require(h(payload[484:1012]) == payload[332:364], "private-delivery-binding")
            for slot in range(2):
                current, _ = insert(current, payload[204 + slot * 32:236 + slot * 32],
                                    payload[1012 + slot * 1160:2172 + slot * 1160])
            for slot in range(2):
                current = append(current, payload[268 + slot * 32:300 + slot * 32],
                                 payload[484 + slot * 264:748 + slot * 264],
                                 payload[3332 + slot * 512:3844 + slot * 512])
            fee = int.from_bytes(payload[196:204], "little")
            require(0 < fee < reserve, "private-fee")
            reserve -= fee
            require(payload[364:476] == state(current, domain) and
                    int.from_bytes(payload[476:484], "little") == reserve, "private-next-state")
            check_successor(tx, raw_redeem, current, domain, reserve)
        else:
            require(len(payload) == 2029 and payload[:9] == b"KPX2RV01\x01"
                    and len(tx["inputs"]) == 1, "revealing-body")
            position = int.from_bytes(payload[177:181], "little")
            require(position < len(current.deliveries), "revealing-position")
            opening = payload[9:113] + payload[181:213] + payload[145:177]
            cm = h(b"KPX1NOT\0", domain, opening)
            require(cm == payload[213:245] == current.deliveries[position].cm, "revealing-cm")
            key = payload[113:145]
            require(h(b"KPX1KEY\0", domain, key) == payload[181:213], "revealing-key")
            tree, _ = current.roots()
            require(payload[245:757] == b"".join(tree.path(position)), "revealing-current-cm-path")
            nf = hmac.digest(key, b"KPX1NF\0\0" + domain + cm + u32(position), "sha256")
            require(nf == payload[1917:1949], "revealing-nf")
            before_reveals[index] = current
            current, intermediate = insert(current, nf, payload[757:1917])
            require(intermediate == payload[1949:1981] and
                    current.roots()[1].root == payload[1981:2013], "revealing-next-root")
            value = int.from_bytes(payload[73:81], "little")
            fee, payout = (int.from_bytes(payload[o:o + 8], "little") for o in (2013, 2021))
            require(0 < fee <= MAX_SOMPI and payout >= 10_000_000 and value == fee + payout
                    and value <= reserve, "revealing-value")
            reserve -= value
            require(len(tx["outputs"]) == (2 if reserve else 1), "revealing-output-count")
            payout_index = 1 if reserve else 0
            output = tx["outputs"][payout_index]
            require(amount(output["value"]) == payout and
                    output["scriptPublicKey"] == (b"\0\0\x20" + payload[145:177] + b"\xac").hex(),
                    "owned-native-payout")
            payouts.append({"operation_index": index, "position": position, "cm": cm.hex(),
                            "outpoint": point(tx, payout_index), "amount_sompi": payout,
                            "script_public_key": output["scriptPublicKey"]})
            check_successor(tx, raw_redeem, current, domain, reserve)
        same_snapshot(parse_snapshot(snapshots[SNAPSHOTS[index]]), current, domain)
    return current, reserve, payouts, before_reveals


def observation(record, body, stage):
    actual = canonical(record["accepted_body"])
    require(actual == body and record["transaction_id"] == body["id"], "accepted-body-substitution")
    require(record["accepted_body_sha256"] == body_hash(actual), "accepted-body-digest")
    if stage == NETWORK:
        require(record["trust"] == TRUST and record["network"] == "testnet-10"
                and record["expected_genesis"] == GENESIS, "node-network-oracle")
        policy = record["confirmation_policy"]
        minimum = policy["min_confirmation_count"]
        require(type(minimum) is int and minimum >= 20,
                "insufficient-confirmation-policy")
        def score(raw):
            require(type(raw) is int or type(raw) is str and re.fullmatch("0|[1-9][0-9]*", raw),
                    "confirmation-score")
            result = int(raw)
            require(0 <= result < 1 << 64, "confirmation-score")
            return result
        accepted_score = score(policy["accepting_blue_score"])
        sink_score = score(policy["sink_blue_score"])
        require(policy["passes"] is True
                and policy["comparison"] == "sinkBlueScore-acceptingBlueScore > min"
                and sink_score >= accepted_score
                and score(policy["actual_blue_score_distance"]) == sink_score - accepted_score
                and sink_score - accepted_score > minimum
                and score(record["accepting_block_header"]["blueScore"]) == accepted_score,
                "confirmation-distance-inconsistent")
        exact(record["observed_sink"], 32)
        exact(record["start_hash"], 32)
        require(record["accepting_block_header"] and not record["chain_delta_removed"],
                "stale-or-removed-accepted-head")
    else:
        require(record.get("trust") == "LOCAL_SUPPLIED_CONTEXT", "local-oracle-label")


def current_output(record, expected):
    matches = [x for x in record["current_outputs"] if point_key(x["outpoint"]) == point_key(expected["outpoint"])]
    require(len(matches) == 1, "stale-head-or-missing-payout")
    row = matches[0]
    require(amount(row["amount_sompi"]) == expected["amount_sompi"]
            and row["script_public_key"] == expected["script_public_key"], "current-utxo-mismatch")
    utxo = row["utxo"]
    require(type(utxo) is dict and utxo["outpoint"] == expected["outpoint"]
            and amount(utxo["amount_sompi"]) == expected["amount_sompi"]
            and utxo["script_public_key"] == expected["script_public_key"]
            and utxo.get("is_coinbase") is False and utxo.get("covenant_id") is None,
            "current-utxo-mismatch")


def local_full_observation(body, native, checked, artifact_sha256):
    """Explicit supplied-output context, exclusively for unfunded LOCAL runs.

    It does not claim a UTXO exists on any network. NETWORK never uses this
    adapter and still requires the actual validating-node observation files.
    """
    require(native["Full"]["accepted"] is True and native["isolation"] == "PASS"
            and native["all_input_engines_accepted"] is True
            and checked["native_full_accepted"] is True
            and checked["all_input_engines_accepted"] is True
            and checked["transaction_id"] == body["id"]
            and checked["body_sha256"] == artifact_sha256, "local-full-context")
    outputs = []
    for index, value in enumerate(body["outputs"]):
        entry = {"outpoint": point(body, index), "amount_sompi": value["value"],
                 "script_public_key": value["scriptPublicKey"],
                 "is_coinbase": False, "covenant_id": None}
        outputs.append({"index": index, **entry, "utxo": dict(entry)})
    return {"transaction_id": body["id"], "accepted_body": body,
            "accepted_body_sha256": body_hash(body), "trust": LOCAL,
            "classification": "OFFLINE_FULL_SUPPLIED_OUTPUT_CONTEXT_NOT_CHAIN_UTXO",
            "current_outputs": outputs,
            "spent_inputs": [{"outpoint": row["previousOutpoint"], "unspent": False}
                             for row in body["inputs"]]}


def identity_check(identity, backup, archive, stage):
    require(stage in (LOCAL, NETWORK) and archive["oracle_stage"] == stage, "oracle-stage")
    require(archive["trial_id"] == identity["trial_id"], "trial-identity")
    for key in ("domain_hex32", "network_id", "genesis_hash_hex"):
        require(archive[key] == identity[key] == backup[key], "backup-archive-identity")
    domain = exact(identity["domain_hex32"], 32)
    if stage == NETWORK:
        require(identity["schema"] == "kpx2-tn10-private-trial/v1"
                and identity["classification"] == "PRIVATE_TN10_TEST_KAS_ONLY"
                and identity["secret_origin"] == "OS_RANDOM_NEW_TN10_TRIAL/v1"
                and identity["network_id"] == "testnet-10"
                and identity["genesis_hash_hex"] == GENESIS, "fresh-private-tn10-identity")
        nonce = exact(identity["domain_nonce_hex32"], 32)
        require(domain == h(b"KPX2/TN10/TRIAL/v1\0", exact(GENESIS, 32), nonce)
                and domain.hex() != OLD_DOMAIN, "fresh-domain")
    require(backup["schema"] == "kpx2-tn10-seed-backup/v1", "seed-only-backup-schema")
    require(set(backup) == {"schema", "network_id", "genesis_hash_hex", "domain_hex32", "seed_hex32"},
            "backup-not-seed-only")
    return domain, exact(backup["seed_hex32"], 32)


def time_value(raw):
    require(type(raw) is str, "observation-time")
    parsed = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "observation-timezone")
    return parsed


def freshness(current_view, stage):
    if stage != NETWORK:
        return
    checkpoint = current_view["checkpoint"]
    require(checkpoint["network"] == "testnet-10" and checkpoint["expected_genesis"] == GENESIS,
            "current-checkpoint-network")
    exact(checkpoint["start_hash"], 32)
    exact(checkpoint["reference_sink"], 32)
    timestamp = time_value(checkpoint["observed_at"])
    for record in current_view["observations"]:
        require(time_value(record["observed_at"]) >= timestamp, "stale-current-observation")
    # Different later sinks are normal on a rapidly advancing DAG. The caller
    # must actually obtain the checkpoint/observations from the selected node;
    # timestamps/JSON labels cannot authenticate a dishonest archive provider.


def evaluate(identity, backup, archive, current_view, bodies, old_observations, crypto, label, stage):
    require(archive["schema"] == "kpx2-tn10-accepted-archive/v1", "archive-schema")
    domain, seed = identity_check(identity, backup, archive, stage)
    require(label in ("bob", "charlie"), "recipient-label")
    operations = archive["operations"]
    require([x["kind"] for x in operations] == list(KINDS[:len(operations)])
            and len(bodies) == len(operations) == len(old_observations), "finite-operation-order")
    for index, (operation, body, old_observation) in enumerate(zip(operations, bodies, old_observations)):
        require(operation["txid_raw_hex"] == body["id"], "operation-transaction-id")
        observation(old_observation, body, stage)
    snapshot, reserve, payouts, before = finite_trace(bodies, archive["snapshots"], domain)
    head = archive["head"]
    require(head["accepted_operation_index"] == len(bodies) - 1
            and head["state_hex112"] == state(snapshot, domain).hex()
            and amount(head["reserve_sompi"]) == reserve
            and head["outpoint"] == (point(bodies[-1], 0) if reserve else None), "archive-head")
    require(current_view["schema"] == "kpx2-tn10-current-view/v1"
            and current_view["trial_id"] == identity["trial_id"]
            and current_view["oracle_stage"] == stage, "current-view-identity")
    freshness(current_view, stage)
    fresh = current_view["observations"]
    by_id = {row["transaction_id"]: row for row in fresh}
    require(len(by_id) == len(fresh), "duplicate-current-observation")
    required = [(len(bodies) - 1, {"outpoint": point(bodies[-1], 0), "amount_sompi": reserve,
                 "script_public_key": bodies[-1]["outputs"][0]["scriptPublicKey"]})] if reserve else [
                 (p["operation_index"], p) for p in payouts]
    require(reserve > 0 or len(bodies) == 6 and len(payouts) == 2, "terminal-two-payouts")
    for index, expected in required:
        body = bodies[index]
        require(body["id"] in by_id, "missing-refreshed-observation")
        observed = by_id[body["id"]]
        observation(observed, body, stage)
        current_output(observed, expected)
        if index >= 4:
            consumed = body["inputs"][0]["previousOutpoint"]
            matching = [r for r in observed["spent_inputs"] if r["outpoint"] == consumed]
            require(len(matching) == 1 and matching[0]["unspent"] is False,
                    "final-reserve-input-still-unspent")
            if stage == NETWORK:
                require(matching[0]["queried"] is True
                        and matching[0]["script_public_key"]
                            == bodies[index - 1]["outputs"][0]["scriptPublicKey"],
                        "final-reserve-absence-not-queried")
    restored = Receiver(seed, domain, crypto)
    result = recover(restored, snapshot.pin(domain), snapshot)
    recipient_position = 2 if label == "bob" else 3
    matched = [claim for claim in result.owned if claim.position == recipient_position]
    expected_payment = amount(archive["expected_payments_sompi"][label])
    require(expected_payment >= 60_000_000 and len(matched) == 1
            and matched[0].receipt.value_sompi == expected_payment,
            "backup-does-not-recover-pilot-recipient")
    witness_count = 0
    for claim in result.owned:
        if claim.owner_action_available:
            exit_witness(restored, claim, snapshot.pin(domain), snapshot)
            witness_count += 1
    # At terminal, verify the selected receiver owned exactly the note opened
    # by its ordered reveal, using its earlier accepted snapshot and old backup.
    if reserve == 0:
        index = 4 if label == "bob" else 5
        previous = before[index]
        received = recover(restored, previous.pin(domain), previous)
        payout = next(p for p in payouts if p["operation_index"] == index)
        owned = [c for c in received.owned if c.position == payout["position"] and not c.spent]
        require(len(owned) == 1 and owned[0].receipt.commitment().hex() == payout["cm"]
                and (b"\0\0\x20" + owned[0].receipt.native_pk + b"\xac").hex()
                    == payout["script_public_key"],
                "payout-not-owned-by-backup")
        require(result.all_owned_unspent_sompi == 0, "owned-terminal-liability-survived")
    return {"schema": "kpx2-tn10-recovery-verdict/v1", "passed": True, "trial_id": identity["trial_id"],
            "label": label, "oracle_stage": stage, "operations_checked": len(bodies),
            "actual_received_note_sompi": expected_payment,
            "owned_unspent_sompi": result.all_owned_unspent_sompi,
            "current_witnesses_constructible": witness_count, "reserve_sompi": reserve,
            "terminal_zero": reserve == 0,
            "both_payout_outputs_checked": len(payouts) == 2 and reserve == 0,
            "both_payout_utxos_reobserved": stage == NETWORK and len(payouts) == 2 and reserve == 0,
            "confirmed_with_trusted_node": stage == NETWORK,
            "trusted_node_archive_assumption": True, "independent_network_recovery_proved": False,
            "prover_or_payer_secret_read": False}


def check_request(request):
    stage = request["oracle_stage"]
    backup_path = Path(request["backup_path"])
    if stage == NETWORK:
        backup_path = backup_path.absolute()
        require(not any(p.is_symlink() for p in (backup_path, *backup_path.parents))
                and ROOT not in backup_path.resolve().parents
                and stat.S_IMODE(backup_path.stat().st_mode) == 0o600,
                "private-backup-permissions")
    identity = json.loads(Path(request["identity_path"]).read_bytes())
    require("secrets" not in identity, "identity-must-be-public-not-payer-profile")
    backup = json.loads(backup_path.read_bytes())
    archive_path = Path(request["archive_path"])
    archive = json.loads(archive_path.read_bytes())
    current = (json.loads(Path(request["current_observations_path"]).read_bytes())
               if request.get("current_observations_path") else None)
    bridge = Path(request["crypto_path"])
    if stage == NETWORK:
        require(request["crypto_sha256"] == identity["runtime_pins"]["bridge_sha256"],
                "identity-crypto-bridge-pin")
    require(hashlib.sha256(bridge.read_bytes()).hexdigest() == request["crypto_sha256"],
            "crypto-bridge-pin")
    bodies, observations = [], []
    for operation in archive["operations"]:
        body = canonical(pinned_json(archive_path.parent, operation["accepted_body_path"],
                                     operation["accepted_body_sha256"]))
        bodies.append(body)
        if stage == LOCAL and "observation_path" not in operation:
            native = pinned_json(archive_path.parent, operation["native_validation_path"],
                                 operation["native_validation_sha256"])
            checked = pinned_json(archive_path.parent, operation["local_check_path"],
                                  operation["local_check_sha256"])
            observations.append(local_full_observation(body, native, checked,
                                                       operation["accepted_body_sha256"]))
        else:
            observations.append(pinned_json(archive_path.parent, operation["observation_path"],
                                           operation["observation_sha256"]))
    if current is None:
        require(stage == LOCAL, "network-needs-refreshed-observations")
        current = {"schema": "kpx2-tn10-current-view/v1", "oracle_stage": LOCAL,
                   "trial_id": archive["trial_id"], "checkpoint": {"classification": LOCAL},
                   "observations": observations[-2:] if len(bodies) == 6 else observations[-1:]}
    return evaluate(identity, backup, archive, current, bodies, observations,
                    Crypto(Path(request["crypto_path"])), request["label"], stage)


if __name__ == "__main__":
    try:
        print(json.dumps(check_request(json.load(sys.stdin)), sort_keys=True))
    except Invalid as error:
        print(json.dumps({"passed": False, "error": str(error)}))
        sys.exit(1)
    except (ValueError, KeyError, TypeError, OSError, IndexError):
        # Deliberately do not print malformed documents, seeds or exception
        # messages from dependencies. The diagnostic result contains no secret.
        print(json.dumps({"passed": False, "error": "RECOVERY_CHECK_REJECTED"}))
        sys.exit(1)
