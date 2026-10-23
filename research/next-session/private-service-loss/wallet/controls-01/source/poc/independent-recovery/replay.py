"""Public KPX2 lineage/state replay without operator snapshots or private keys.

This replays public predicates. Unless an independently selected native validator
is supplied, signatures and Groth16 validity retain the explicit selected-node
acceptance premise. It does not establish independent consensus or durable DA.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys

from policy_template import approved_policy

GENESIS = "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370"
MAX = 2_870_000_000_000_000_000
NOTE_FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
ZERO = bytes(32)
CM_NODE = b"KPX1CMN\0"
NF_NODE = b"KPX1NFN\0"
NF_LEAF = b"KPX1NFL\0"
CM_EMPTY = hashlib.sha256(b"KPX1CME\0").digest()
NF_EMPTY = hashlib.sha256(b"KPX1NFE\0").digest()
DESCRIPTOR_FIELDS = {"schema", "network_id", "genesis_hash_hex", "domain_hex32",
    "founding_outpoint", "birth_start_hash", "initial_redeem_hex", "vk_hex328",
    "immutable_policy_sha256"}


class Invalid(ValueError):
    """Stable public validation category; no secret or input document in errors."""


class Incomplete(Invalid):
    """Required accepted history/current data is unavailable or inconsistent."""


def need(condition, reason, *, incomplete=False):
    if not condition:
        raise (Incomplete if incomplete else Invalid)(reason)


def hx(value, size=None):
    need(type(value) is str and re.fullmatch(r"(?:[0-9a-f]{2})*", value) is not None,
         "canonical-hex")
    result = bytes.fromhex(value)
    need(size is None or len(result) == size, "hex-width")
    return result


def integer(value, maximum=MAX):
    need(type(value) is int or type(value) is str and re.fullmatch(r"0|[1-9][0-9]*", value),
         "canonical-integer")
    result = int(value)
    need(0 <= result <= maximum, "integer-range")
    return result


def u32(value):
    return integer(value, (1 << 32) - 1).to_bytes(4, "little")


def h(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode()).hexdigest()


def point(value):
    need(type(value) is dict and set(value) == {"transactionId", "index"}, "outpoint-fields")
    hx(value["transactionId"], 32)
    return value["transactionId"], integer(value["index"], (1 << 32) - 1)


def outpoint(tx, index=0):
    return {"transactionId": tx["id"], "index": index}


def spk(value):
    raw = hx(value)
    need(len(raw) >= 3 and raw[:2] == b"\0\0", "script-public-key-version")
    return raw


def p2sh(raw):
    return (b"\0\0\xaa\x20" + hashlib.blake2b(raw, digest_size=32).digest() + b"\x87").hex()


def p2pk(raw):
    need(len(raw) == 32, "payout-key-width")
    return (b"\0\0\x20" + raw + b"\xac").hex()


def timestamp(value):
    need(type(value) is str, "observation-time")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Invalid("observation-time") from None
    need(parsed.tzinfo is not None, "observation-timezone")
    return parsed


class SparseTree:
    """Sparse fixed-depth tree; each update copies no full ledger structures."""
    def __init__(self, depth, tag, empty):
        self.depth, self.tag = depth, tag
        self.defaults = [empty]
        for _ in range(depth):
            self.defaults.append(h(tag, self.defaults[-1], self.defaults[-1]))
        self.levels = [{} for _ in range(depth + 1)]

    @property
    def root(self):
        return self.levels[-1].get(0, self.defaults[-1])

    def leaf(self, index):
        return self.levels[0].get(index, self.defaults[0])

    def path(self, index):
        need(type(index) is int and 0 <= index < 1 << self.depth, "tree-index")
        return b"".join(self.levels[level].get((index >> level) ^ 1, self.defaults[level])
                        for level in range(self.depth))

    def set(self, index, value):
        need(type(index) is int and 0 <= index < 1 << self.depth and len(value) == 32,
             "tree-update")
        self.levels[0][index] = value
        for level in range(self.depth):
            at = index >> (level + 1)
            lower = self.levels[level]
            self.levels[level + 1][at] = h(self.tag,
                lower.get(2 * at, self.defaults[level]),
                lower.get(2 * at + 1, self.defaults[level]))


def nf_leaf(entry):
    return h(NF_LEAF, entry["value"], entry["next_value"], u32(entry["next_index"]))


class State:
    def __init__(self, domain, note, cipher):
        self.domain = domain
        self.cm = SparseTree(16, CM_NODE, CM_EMPTY)
        self.nf = SparseTree(17, NF_NODE, NF_EMPTY)
        commitment = h(b"KPX1NOT\0", domain, note)
        self.deliveries = [{"position": 0, "cm": commitment.hex(), "ciphertext": cipher.hex()}]
        self.entries = [{"value": ZERO, "next_value": ZERO, "next_index": 0}]
        self.nf_positions = {ZERO: 0}
        self.cm.set(0, commitment)
        self.nf.set(0, nf_leaf(self.entries[0]))

    def encoded(self):
        return (b"KPX2ST01" + self.domain + self.cm.root + u32(len(self.deliveries))
                + self.nf.root + u32(len(self.entries)))

    def counts(self):
        n, m = len(self.deliveries), len(self.entries)
        need(1 <= n <= 65_535 and 1 <= m <= 2 * n + 1 <= 131_071, "state-counts")

    def insert(self, value, witness):
        need(len(value) == 32 and value != ZERO and value not in self.nf_positions,
             "double-spend-or-zero-nf")
        need(len(witness) == 1160, "nf-witness-width")
        at = int.from_bytes(witness[:4], "little")
        need(at < len(self.entries), "nf-predecessor-index")
        entry = self.entries[at]
        need(witness[4:72] == entry["value"] + entry["next_value"] + u32(entry["next_index"]),
             "nf-predecessor-record")
        need(witness[72:616] == self.nf.path(at), "nf-current-path")
        order = int.from_bytes(value, "little")
        need(int.from_bytes(entry["value"], "little") < order
             and (entry["next_value"] == ZERO or order < int.from_bytes(entry["next_value"], "little")),
             "nf-strict-absence")
        new_index = len(self.entries)
        replacement = {"value": entry["value"], "next_value": value, "next_index": new_index}
        self.nf.set(at, nf_leaf(replacement))
        intermediate = self.nf.root
        need(witness[616:] == self.nf.path(new_index), "nf-intermediate-append-path")
        need(self.nf.leaf(new_index) == NF_EMPTY, "nf-append-not-empty")
        appended = {"value": value, "next_value": entry["next_value"], "next_index": entry["next_index"]}
        self.entries[at] = replacement
        self.entries.append(appended)
        self.nf_positions[value] = new_index
        self.nf.set(new_index, nf_leaf(appended))
        return intermediate

    def append(self, cm, cipher, witness):
        index = len(self.deliveries)
        need(index < 65_535 and len(cm) == 32 and len(cipher) == 264, "cm-append-width-capacity")
        need(witness == self.cm.path(index) and self.cm.leaf(index) == CM_EMPTY, "cm-append-path")
        self.cm.set(index, cm)
        self.deliveries.append({"position": index, "cm": cm.hex(), "ciphertext": cipher.hex()})


def canonical(tx):
    need(type(tx) is dict and set(tx) == {"version", "id", "inputs", "outputs", "lockTime",
        "subnetworkId", "gas", "payload", "storageMass"}, "transaction-fields")
    need(type(tx["version"]) is int and tx["version"] == 1, "transaction-version")
    hx(tx["id"], 32)
    hx(tx["payload"])
    need(integer(tx["lockTime"], (1 << 64) - 1) == 0 and integer(tx["gas"], (1 << 64) - 1) == 0
         and tx["subnetworkId"] == "00" * 20, "transaction-defaults")
    integer(tx["storageMass"], (1 << 64) - 1)
    need(type(tx["inputs"]) is list and tx["inputs"] and type(tx["outputs"]) is list and tx["outputs"],
         "transaction-arity")
    for item in tx["inputs"]:
        need(type(item) is dict and set(item) == {"previousOutpoint", "signatureScript", "sequence", "computeBudget"},
             "input-fields")
        point(item["previousOutpoint"])
        hx(item["signatureScript"])
        need(integer(item["sequence"], (1 << 64) - 1) == (1 << 64) - 1, "input-sequence")
        need(integer(item["computeBudget"], 65535) > 0, "input-compute-budget")
    for item in tx["outputs"]:
        need(type(item) is dict and set(item) == {"value", "scriptPublicKey", "covenant"}
             and item["covenant"] is None, "output-fields")
        need(integer(item["value"]) > 0, "zero-native-output")
        spk(item["scriptPublicKey"])
    need(sum(integer(o["value"]) for o in tx["outputs"]) <= MAX, "output-sum")
    return tx


def context_entries(tx, row, *, synthetic=False):
    entries = row["input_contexts" if synthetic else "accepted_input_contexts"]
    need(type(entries) is list and len(entries) == len(tx["inputs"]), "input-context-arity")
    for input_, entry in zip(tx["inputs"], entries):
        need(point(entry["outpoint"]) == point(input_["previousOutpoint"]), "input-context-outpoint")
        need(integer(entry["amount_sompi"]) > 0, "input-context-amount")
        spk(entry["script_public_key"])
        need(entry["is_coinbase"] is False and entry["covenant_id"] is None, "input-context-metadata")
        integer(entry["block_daa_score"], (1 << 64) - 1)
    total_in = sum(integer(e["amount_sompi"]) for e in entries)
    total_out = sum(integer(o["value"]) for o in tx["outputs"])
    need(total_in <= MAX and 0 < total_in - total_out <= MAX, "native-fee-conservation")
    return entries, total_in - total_out


def confirmation(row):
    need(row["network_id"] == "testnet-10" and row["genesis_hash_hex"] == GENESIS, "accepted-network")
    header, policy = row["accepting_block_header"], row["confirmation_policy"]
    hx(header["hash"], 32)
    minimum = integer(policy["min_confirmation_count"], (1 << 64) - 1)
    accepted = integer(policy["accepting_blue_score"], (1 << 64) - 1)
    sink = integer(policy["sink_blue_score"], (1 << 64) - 1)
    need(minimum >= 20 and policy["passes"] is True and sink >= accepted
         and sink - accepted > minimum
         and integer(policy["actual_blue_score_distance"], (1 << 64) - 1) == sink - accepted
         and integer(header["blueScore"], (1 << 64) - 1) == accepted, "accepted-confirmation")


def descriptor_check(descriptor):
    need(type(descriptor) is dict and set(descriptor) == DESCRIPTOR_FIELDS, "descriptor-fields")
    need(descriptor["schema"] == "kpx2-recovery-descriptor/v1"
         and descriptor["network_id"] == "testnet-10"
         and descriptor["genesis_hash_hex"] == GENESIS, "descriptor-network-profile")
    domain, vk = hx(descriptor["domain_hex32"], 32), hx(descriptor["vk_hex328"], 328)
    hx(descriptor["birth_start_hash"], 32)
    need(point(descriptor["founding_outpoint"])[1] == 0, "founding-output-index")
    raw = hx(descriptor["initial_redeem_hex"])
    need(len(raw) >= 114 and raw[:10] == b"\x4c\x70KPX2ST01" and raw[10:42] == domain,
         "initial-state-frame-domain")
    need(raw[114:] == approved_policy(domain, vk), "unapproved-policy-semantics")
    need(h(raw[114:]).hex() == descriptor["immutable_policy_sha256"], "immutable-policy-hash")
    return domain, vk, raw


def pool_witness(tx):
    raw = hx(tx["inputs"][0]["signatureScript"])
    need(len(raw) >= 199 and raw[0] == 65 and raw[66:68] == b"\x4c\x80"
         and raw[196] == 77 and int.from_bytes(raw[197:199], "little") == len(raw) - 199,
         "pool-witness-frame")
    return raw[1:66], raw[68:196], raw[199:]


def funding_signature(input_, entry):
    key = spk(entry["script_public_key"])
    signature = hx(input_["signatureScript"])
    need(len(key) == 36 and key[2] == 32 and key[-1] == 172,
         "funding-input-p2pk")
    need(len(signature) == 66 and signature[0] == 65 and signature[-1] == 1
         and signature[1:65] != bytes(64), "funding-all-signature-frame")


def public_note(payload, domain, magic):
    need(payload[:8] == magic and payload[8:40] == domain, "public-note-domain")
    note, cm, cipher = payload[40:208], payload[208:240], payload[240:504]
    need(h(b"KPX1NOT\0", domain, note) == cm and h(cipher) == payload[504:536],
         "public-note-cipher-binding")
    value = int.from_bytes(note[64:72], "little")
    need(NOTE_FLOOR <= value <= MAX, "public-note-value")
    return note, cm, cipher, value


def same_entry(actual, expected):
    need(actual is not None and point(actual["outpoint"]) == point(expected["outpoint"])
         and integer(actual["amount_sompi"]) == expected["amount_sompi"]
         and actual["script_public_key"] == expected["script_public_key"]
         and actual["is_coinbase"] is False and actual["covenant_id"] is None,
         "current-utxo-mismatch", incomplete=True)
    integer(actual["block_daa_score"], (1 << 64) - 1)


def checked_network_coverage(descriptor, bundle):
    # A faithful installed fetcher must obtain this coverage from the selected
    # node. JSON metadata cannot prove that a dishonest provider really queried it.
    coverage = bundle["coverage"]
    need(coverage["start_hash"] == descriptor["birth_start_hash"] and coverage["complete"] is True
         and coverage["frontier_seen"] is True and not coverage["removed_chain_block_hashes"]
         and not coverage["missing"] and coverage["pruned"] is False,
         "incomplete-or-reorganized-history", incomplete=True)
    frontier = coverage["frontier"]
    hx(frontier["hash"], 32)
    frontier_score = integer(frontier["blueScore"], (1 << 64) - 1)
    anchor_score = integer(coverage["anchor_header"]["blueScore"], (1 << 64) - 1)
    fixed_sink = coverage["initial_sink"]
    hx(fixed_sink["hash"], 32)
    fixed_sink_score = integer(fixed_sink["blueScore"], (1 << 64) - 1)
    minimum = integer(coverage["min_confirmation_count"], (1 << 64) - 1)
    need(coverage["end_cursor"] == frontier["hash"]
         and coverage["anchor_header"]["hash"] == descriptor["birth_start_hash"]
         and anchor_score < frontier_score and minimum >= 20
         and fixed_sink_score >= frontier_score and fixed_sink_score - frontier_score > minimum,
         "scan-anchor-frontier", incomplete=True)
    view = bundle["current_view"]
    need(view["post_query_delta"]["removed_chain_block_hashes"] == []
         and view["post_query_delta"]["related_transactions"] == []
         and view["post_query_delta"]["start_hash"] == frontier["hash"]
         and view["post_query_delta"]["completed"] is True
         and integer(view["post_query_delta"]["frontier"]["blueScore"], (1 << 64) - 1) >= frontier_score,
         "reorganized-or-stale-frontier", incomplete=True)
    need(view["checkpoint"]["network"] == "testnet-10"
         and view["checkpoint"]["expected_genesis"] == GENESIS, "current-view-network")
    need(timestamp(view["observed_at"]) >= timestamp(view["checkpoint"]["observed_at"]),
         "stale-current-view", incomplete=True)
    need(timestamp(view["post_query_delta"]["checked_at"]) >= timestamp(view["observed_at"]),
         "current-view-not-reconciled-after-query", incomplete=True)
    return coverage, frontier, anchor_score, frontier_score, fixed_sink_score, minimum, view


def _replay(descriptor: dict, bundle: dict, native_validator=None, *, context="NETWORK_FETCH") -> dict:
    need(context in ("NETWORK_FETCH", "UNPROVED_SYNTHETIC"), "unsupported-replay-context")
    synthetic = context == "UNPROVED_SYNTHETIC"
    domain, vk, initial_redeem = descriptor_check(descriptor)
    need(bundle["schema"] == ("kpx2-unproved-synthetic/v1" if synthetic else "kpx2-network-fetch/v1")
         and bundle["network_id"] == "testnet-10" and bundle["genesis_hash_hex"] == GENESIS
         and bundle["descriptor_sha256"] == digest(descriptor), "fetch-descriptor-binding")
    if synthetic:
        need(bundle["context"] == "UNPROVED_SYNTHETIC" and native_validator is None,
             "synthetic-context-not-network-validation")
        coverage = {"start_hash": descriptor["birth_start_hash"]}
        frontier = None
        view = bundle["declared_view"]
    else:
        coverage, frontier, anchor_score, frontier_score, fixed_sink_score, minimum, view = checked_network_coverage(descriptor, bundle)
    rows, spends = {}, {}
    for row in bundle["transactions"]:
        tx = canonical(row["transaction"])
        need(tx["id"] not in rows, "duplicate-accepted-transaction")
        if not synthetic:
            confirmation(row)
            need(row.get("sdk_transaction_id_recomputed") is True, "sdk-transaction-id-validation-missing")
            accepted_score = integer(row["accepting_block_header"]["blueScore"], (1 << 64) - 1)
            need(anchor_score < accepted_score <= frontier_score
                 and integer(row["confirmation_policy"]["sink_blue_score"], (1 << 64) - 1) == fixed_sink_score
                 and integer(row["confirmation_policy"]["min_confirmation_count"], (1 << 64) - 1) == minimum,
                 "transaction-after-scan-frontier", incomplete=True)
        context_entries(tx, row, synthetic=synthetic)
        rows[tx["id"]] = row
        for index, item in enumerate(tx["inputs"]):
            spends.setdefault(point(item["previousOutpoint"]), []).append((tx["id"], index))
    founding_key = point(descriptor["founding_outpoint"])
    need(founding_key[0] in rows, "missing-founding-history", incomplete=True)
    founding = rows[founding_key[0]]
    tx = founding["transaction"]
    entries, founding_fee = context_entries(tx, founding, synthetic=synthetic)
    payload = hx(tx["payload"], 536)
    need(len(tx["inputs"]) == 1 and len(tx["outputs"]) in (1, 2), "founding-arity")
    funding_signature(tx["inputs"][0], entries[0])
    genesis_note, _, cipher, reserve = public_note(payload, domain, b"KPX2GN01")
    state = State(domain, genesis_note, cipher)
    need(initial_redeem[2:114] == state.encoded(), "incoherent-founding-state")
    need(integer(tx["outputs"][0]["value"]) == reserve
         and tx["outputs"][0]["scriptPublicKey"] == p2sh(initial_redeem), "founding-reserve")
    if len(tx["outputs"]) == 2:
        need(tx["outputs"][1]["scriptPublicKey"] == entries[0]["script_public_key"], "founding-change")
    if native_validator is not None:
        need(native_validator(tx, entries) is True, "local-native-validation")
    operations = [{"kind": "FOUNDING", "transaction_id": tx["id"], "fee_sompi": founding_fee,
                   "reserve_sompi": reserve, "state_hex112": state.encoded().hex()}]
    payouts, consumed, seen = [], {point(item["previousOutpoint"]) for item in tx["inputs"]}, {tx["id"]}
    consumed_contexts = {point(entry["outpoint"]): entry for entry in entries}
    current_redeem = initial_redeem
    current_point = outpoint(tx)
    last_consumed = None
    while reserve:
        children = spends.get(point(current_point), [])
        need(len(children) <= 1, "competing-accepted-reserve-spends")
        if not children:
            break
        child_id, input_index = children[0]
        need(input_index == 0 and child_id not in seen, "reserve-input-index-or-cycle")
        row = rows[child_id]
        tx = row["transaction"]
        entries, actual_fee = context_entries(tx, row, synthetic=synthetic)
        expected = {"outpoint": current_point, "amount_sompi": reserve,
                    "script_public_key": p2sh(current_redeem)}
        same_entry(entries[0], expected)
        for input_ in tx["inputs"]:
            key = point(input_["previousOutpoint"])
            need(key not in consumed, "duplicate-accepted-spend")
            consumed.add(key)
        consumed_contexts.update((point(entry["outpoint"]), entry) for entry in entries)
        sig, proof, raw_redeem = pool_witness(tx)
        need(raw_redeem == current_redeem and raw_redeem[2:114] == state.encoded(),
             "current-policy-state")
        old_reserve = reserve
        payload = hx(tx["payload"])
        magic = payload[:8]
        if magic == b"KPX2AD01":
            need(len(payload) == 1344 and len(tx["inputs"]) == 2
                 and sig == bytes(65) and proof == bytes(128), "admit-frame")
            note, cm, cipher, value = public_note(payload, domain, magic)
            if len(state.deliveries) == len(state.entries) == 1:
                need(payload[1176:] == genesis_note, "admit-genesis-opening")
            else:
                need(payload[1176:] == bytes(168), "admit-later-genesis-zero")
            fee, change = (int.from_bytes(payload[at:at + 8], "little") for at in (1160, 1168))
            need(0 < fee <= MAX and change <= MAX and old_reserve + integer(entries[1]["amount_sompi"]) <= MAX,
                 "admit-amount-range")
            need(integer(entries[1]["amount_sompi"]) == value + fee + change and actual_fee == fee,
                 "admit-external-conservation")
            funding_signature(tx["inputs"][1], entries[1])
            need(len(tx["outputs"]) == (2 if change else 1), "admit-change-arity")
            if change:
                need(integer(tx["outputs"][1]["value"]) == change
                     and tx["outputs"][1]["scriptPublicKey"] == entries[1]["script_public_key"],
                     "admit-change-output")
            state.append(cm, cipher, payload[536:1048])
            reserve += value
            need(reserve <= MAX and payload[1048:1160] == state.encoded(), "admit-next-state")
            kind = "ADMIT"
        elif magic == b"KPX2AU01":
            need(len(payload) == 4356 and len(tx["inputs"]) == len(tx["outputs"]) == 1
                 and sig == bytes(65) and proof != bytes(128), "private-frame")
            need(payload[8:40] == domain and payload[40:76] == hx(current_point["transactionId"], 32)
                 + u32(current_point["index"]) and payload[76:188] == state.encoded(), "private-auth-context")
            fee = int.from_bytes(payload[196:204], "little")
            need(int.from_bytes(payload[188:196], "little") == reserve and actual_fee == fee
                 and 0 < fee < reserve and reserve - fee >= NOTE_FLOOR, "private-reserve-fee")
            need(h(payload[484:1012]) == payload[332:364], "private-ciphertext-binding")
            need(payload[204:236] != payload[236:268] and payload[268:300] != payload[300:332],
                 "private-distinct-nfs-cms")
            for slot in range(2):
                state.insert(payload[204 + slot * 32:236 + slot * 32],
                             payload[1012 + slot * 1160:2172 + slot * 1160])
            for slot in range(2):
                state.append(payload[268 + slot * 32:300 + slot * 32],
                             payload[484 + slot * 264:748 + slot * 264],
                             payload[3332 + slot * 512:3844 + slot * 512])
            reserve -= fee
            need(payload[364:476] == state.encoded()
                 and int.from_bytes(payload[476:484], "little") == reserve, "private-next-state")
            kind = "PRIVATE"
        elif magic == b"KPX2RV01":
            need(len(payload) == 2029 and payload[8] == 1 and len(tx["inputs"]) == 1
                 and proof == bytes(128) and sig[-1] == 1 and sig[:64] != bytes(64), "reveal-frame")
            position = int.from_bytes(payload[177:181], "little")
            need(position < len(state.deliveries), "reveal-position")
            note = payload[9:113] + payload[181:213] + payload[145:177]
            cm = h(b"KPX1NOT\0", domain, note)
            need(cm.hex() == state.deliveries[position]["cm"] and cm == payload[213:245], "reveal-cm")
            key = payload[113:145]
            need(h(b"KPX1KEY\0", domain, key) == payload[181:213], "reveal-key")
            need(payload[245:757] == state.cm.path(position), "reveal-current-cm-path")
            nf = hmac.digest(key, b"KPX1NF\0\0" + domain + cm + u32(position), "sha256")
            need(nf == payload[1917:1949], "reveal-original-nf")
            intermediate = state.insert(nf, payload[757:1917])
            need(intermediate == payload[1949:1981] and state.nf.root == payload[1981:2013], "reveal-next-nf")
            value = int.from_bytes(note[64:72], "little")
            fee, paid = (int.from_bytes(payload[at:at + 8], "little") for at in (2013, 2021))
            need(NOTE_FLOOR <= value <= reserve and 0 < fee <= MAX and paid >= PAYOUT_FLOOR
                 and value == fee + paid and actual_fee == fee, "reveal-conservation")
            reserve -= value
            payout_index = 1 if reserve else 0
            need(len(tx["outputs"]) == (2 if reserve else 1), "reveal-output-count")
            output = tx["outputs"][payout_index]
            need(integer(output["value"]) == paid and output["scriptPublicKey"] == p2pk(payload[145:177]),
                 "reveal-native-payout")
            payouts.append({"transaction_id": tx["id"], "outpoint": outpoint(tx, payout_index),
                "amount_sompi": paid, "script_public_key": output["scriptPublicKey"], "cm": cm.hex(),
                "position": position, "note_hex168": note.hex()})
            kind = "REVEAL"
        else:
            raise Invalid("unsupported-pool-operation")
        state.counts()
        if reserve:
            need(reserve >= NOTE_FLOOR and integer(tx["outputs"][0]["value"]) == reserve,
                 "continuing-reserve-floor-value")
            next_redeem = b"\x4c\x70" + state.encoded() + initial_redeem[114:]
            need(tx["outputs"][0]["scriptPublicKey"] == p2sh(next_redeem), "immutable-successor")
        else:
            next_redeem = None
        if native_validator is not None:
            need(native_validator(tx, entries) is True, "local-native-validation")
        operations.append({"kind": kind, "transaction_id": tx["id"], "prior_outpoint": current_point,
            "prior_reserve_sompi": old_reserve, "reserve_sompi": reserve, "fee_sompi": actual_fee,
            "state_hex112": state.encoded().hex()})
        seen.add(tx["id"])
        last_consumed = current_point
        current_point = outpoint(tx) if reserve else None
        current_redeem = next_redeem
    query_map = {}
    for query in view["queries"]:
        key = point(query["outpoint"])
        need(key not in query_map and query["queried"] is True, "duplicate-or-unqueried-current-point")
        spk(query["script_public_key"])
        query_map[key] = query
    for key, expected in consumed_contexts.items():
        query = query_map.get(key)
        need(query is not None and query["script_public_key"] == expected["script_public_key"]
             and integer(query["amount_sompi"]) == integer(expected["amount_sompi"])
             and query["entry"] is None, "consumed-input-current-query", incomplete=True)
    if reserve:
        query = query_map.get(point(current_point))
        need(query is not None and query["script_public_key"] == p2sh(current_redeem)
             and integer(query["amount_sompi"]) == reserve,
             "current-head-not-queried", incomplete=True)
        same_entry(query["entry"], {"outpoint": current_point, "amount_sompi": reserve,
                                    "script_public_key": p2sh(current_redeem)})
        current_utxo = query["entry"]
    else:
        need(last_consumed is not None, "terminal-without-consumption")
        query = query_map.get(point(last_consumed))
        need(query is not None and query["entry"] is None,
             "terminal-reserve-not-observed-spent", incomplete=True)
        current_utxo = None
    for payout in payouts:
        query = query_map.get(point(payout["outpoint"]))
        need(query is not None and query["script_public_key"] == payout["script_public_key"],
             "payout-not-queried", incomplete=True)
        need(integer(query["amount_sompi"]) == payout["amount_sompi"],
             "payout-query-amount", incomplete=True)
        if query["entry"] is not None:
            same_entry(query["entry"], payout)
        payout.update(queried=True, current_utxo=query["entry"])
    return {"schema": "kpx2-independent-replay/v1", "descriptor_sha256": digest(descriptor),
        "network_id": "testnet-10", "genesis_hash_hex": GENESIS, "domain_hex32": domain.hex(),
        "immutable_policy_sha256": descriptor["immutable_policy_sha256"],
        "deliveries": state.deliveries,
        "nullifiers": [{"value": e["value"].hex(), "next_value": e["next_value"].hex(),
                        "next_index": e["next_index"]} for e in state.entries],
        "head": {"outpoint": current_point, "state_hex112": state.encoded().hex(),
            "reserve_sompi": reserve, "current_redeem_hex": None if current_redeem is None else current_redeem.hex(),
            "current_utxo": current_utxo, "observation_checkpoint": None if synthetic else view["checkpoint"],
            "accepting_block_header": None if synthetic else rows[operations[-1]["transaction_id"]]["accepting_block_header"]},
        "operations": operations, "payouts": payouts,
        "context": context,
        "completeness": {"complete": not synthetic, "public_replay_complete": True, "terminal": reserve == 0,
            "acceptance_trust": "UNPROVED_SYNTHETIC" if synthetic else "SELECTED_VALIDATING_NODE", "scan_anchor": coverage["start_hash"],
            "frontier": frontier, "view_is_atomic": False, "independent_consensus": False,
            "durable_data_availability_proved": False, "orphan_disclosure_history_complete": False},
        "local_native_validation": native_validator is not None,
        "groth16_and_signatures": "UNCHECKED_SYNTHETIC" if synthetic else "LOCALLY_EXECUTED_NATIVE" if native_validator is not None else "TRUSTED_VALIDATING_NODE",
        "sdk_transaction_id_validation": not synthetic and all(rows[item["transaction_id"]].get("sdk_transaction_id_recomputed") is True
                                             for item in operations)}


def replay(descriptor: dict, bundle: dict, native_validator=None, *, context="NETWORK_FETCH") -> dict:
    """Replay only; callers must obtain fresh honest-node records separately."""
    try:
        return _replay(descriptor, bundle, native_validator, context=context)
    except Invalid:
        raise
    except (KeyError, TypeError, ValueError, IndexError, OverflowError):
        raise Invalid("public-replay-schema") from None


if __name__ == "__main__":
    try:
        request = json.load(sys.stdin)
        result = replay(request["descriptor"], request["fetched"])
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    except Incomplete as error:
        print(json.dumps({"status": "INCOMPLETE", "reason": str(error)}))
        raise SystemExit(2)
    except (Invalid, KeyError, TypeError, ValueError, IndexError):
        print(json.dumps({"status": "REJECTED", "reason": "PUBLIC_REPLAY_REJECTED"}))
        raise SystemExit(1)
