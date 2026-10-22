#!/usr/bin/env python3
"""Public v6 observation with independently regenerated settlement witnesses.

Only public descriptor fields, a public VK, native transaction bodies and their
selected funding parents enter this module. It never imports a wallet, model,
observer, setup, proving key or experiment. SHA-256 trees implement the existing
public relation in src/two_input/tree.rs; this is not a proof/VM verifier.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

SCHEMA = "kpi-public-native-observation-v1"
MAX_SOMPI = 2_900_000_000_000_000_000
ZERO = bytes(32)
GENESIS = "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370"
HERE = Path(__file__).resolve().parent
FIXTURE_BASE = "evidence/2026-10-20-two-input-tn10"
FIXTURE_PINS = {
    "descriptor": (FIXTURE_BASE + "/rehearsal/descriptor.json", "795eebdefb3eabea6446b3b1a9bd8c80e7f262fe32f7dfcf39efccbe7bbc07ac"),
    "receipt": (FIXTURE_BASE + "/rehearsal/chain-confirmed.json", "75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8"),
    "vk": (FIXTURE_BASE + "/verification-key.json", "4fd7dc563e4a1f843c99d5517485ba7664a7dcb69057784ca2fac066b20cddaf"),
}


class ObservationError(ValueError):
    """A malformed, inconsistent or unsupported public input."""


def require(condition, reason):
    if not condition:
        raise ObservationError(reason)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names.split()), label + ": fields")


def integer(value, maximum, label):
    require(type(value) is int and 0 <= value <= maximum, label + ": integer/range")
    return value


def decimal(value, maximum, label):
    require(type(value) is str and value.isascii() and value.isdecimal()
            and str(int(value)) == value, label + ": canonical decimal string")
    return integer(int(value), maximum, label)


@dataclass(frozen=True)
class Sompi:
    """Individual native amount; floats, bools and implicit unit conversion fail."""
    value: int

    def __post_init__(self):
        integer(self.value, MAX_SOMPI, "sompi")

    @classmethod
    def parse(cls, value):
        return cls(decimal(value, MAX_SOMPI, "sompi"))

    @classmethod
    def little_endian(cls, value):
        require(type(value) is bytes and len(value) == 8, "sompi: eight bytes")
        return cls(int.from_bytes(value, "little"))

    def __str__(self):
        return str(self.value)


def unhex(value, size=None, label="hex"):
    require(type(value) is str, label + ": string")
    try:
        data = bytes.fromhex(value)
    except ValueError as error:
        raise ObservationError(label + ": invalid hex") from error
    require(data.hex() == value and (size is None or len(data) == size), label + ": canonical hex/length")
    return data


def hash_array(value, label):
    require(type(value) is list and len(value) == 32, label + ": hash array")
    return bytes(integer(x, 255, label) for x in value)


def sha(data):
    return hashlib.sha256(data).digest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def unique_json(data):
    """Ordinary json.loads silently keeps the last duplicate object key."""
    def pairs(entries):
        result = {}
        for key, value in entries:
            require(key not in result, "JSON duplicate key: " + key)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def point(value):
    fields(value, "transactionId index", "outpoint")
    unhex(value["transactionId"], 32, "transaction ID")
    return value["transactionId"], integer(value["index"], 2**32 - 1, "outpoint index")


def native_shape(tx):
    fields(tx, "version id inputs outputs lockTime subnetworkId gas payload storageMass", "native transaction")
    require(type(tx["version"]) is int and tx["version"] == 1, "native version")
    unhex(tx["id"], 32, "transaction ID")
    require(tx["lockTime"] == tx["gas"] == "0" and tx["subnetworkId"] == "0" * 40, "native envelope")
    decimal(tx["storageMass"], 2**64 - 1, "storage mass")
    unhex(tx["payload"])
    require(type(tx["inputs"]) is list and tx["inputs"]
            and type(tx["outputs"]) is list and tx["outputs"], "native input/output lists")
    used = set()
    for entry in tx["inputs"]:
        fields(entry, "previousOutpoint signatureScript sequence sigOpCount computeBudget", "native input")
        outpoint = point(entry["previousOutpoint"])
        require(outpoint not in used, "duplicate transaction input")
        used.add(outpoint)
        unhex(entry["signatureScript"])
        decimal(entry["sequence"], 2**64 - 1, "sequence")
        require(type(entry["sigOpCount"]) is int and entry["sigOpCount"] == 0, "sigop encoding")
        integer(entry["computeBudget"], 65535, "compute budget")
    for output in tx["outputs"]:
        fields(output, "value scriptPublicKey covenant", "native output")
        require(Sompi.parse(output["value"]).value > 0 and output["covenant"] is None, "ordinary positive output")
        require(len(unhex(output["scriptPublicKey"])) >= 2, "script public key version")


def node(left, right):
    return sha(b"\x01" + left + right)


class PublicTree:
    """The existing depth-16/17 tree, including an all-zero empty leaf."""
    def __init__(self, leaves, depth):
        require(depth in (16, 17) and len(leaves) <= 1 << depth, "public tree capacity/depth")
        self.depth = depth
        self.empty = [ZERO]
        for _ in range(1, depth):
            self.empty.append(node(self.empty[-1], self.empty[-1]))
        self.levels = [list(leaves)]
        for level in range(depth):
            current = self.levels[-1]
            self.levels.append([node(current[i], current[i + 1] if i + 1 < len(current) else self.empty[level])
                                for i in range(0, len(current), 2)])

    def root(self):
        return self.levels[-1][0] if self.levels[-1] else node(self.empty[-1], self.empty[-1])

    def path(self, index):
        integer(index, (1 << self.depth) - 1, "Merkle position")
        return b"".join(self.levels[level][sibling] if sibling < len(self.levels[level]) else self.empty[level]
                        for level in range(self.depth) for sibling in [((index >> level) ^ 1)])


class PublicState:
    """Only commitments, public indexed nullifiers and anchor-root history."""
    def __init__(self, commitment):
        self.commitments = [commitment]
        self.nullifiers = [(ZERO, 0, ZERO)]
        self.roots = [self.cm_tree().root()]

    def cm_tree(self):
        return PublicTree([sha(b"\x00" + c) for c in self.commitments], 16)

    @staticmethod
    def nf_bytes(leaf):
        value, index, following = leaf
        return value + index.to_bytes(4, "little") + following

    def nf_tree(self):
        return PublicTree([sha(b"\x02" + self.nf_bytes(leaf)) for leaf in self.nullifiers], 17)

    def history_tree(self):
        return PublicTree([sha(b"\x03" + (2 * i + 1).to_bytes(4, "little") + root)
                           for i, root in enumerate(self.roots)], 16)

    def compact(self):
        cm, nf = len(self.commitments), len(self.nullifiers) - 1
        require(0 < cm < 65536 and cm % 2 == 1 and nf <= 2 * cm and nf % 2 == 0, "public state counts")
        require(len(self.roots) == (cm + 1) // 2 and self.roots[-1] == self.cm_tree().root(), "public root history")
        return (b"\x06" + cm.to_bytes(4, "little") + nf.to_bytes(4, "little")
                + self.cm_tree().root() + self.nf_tree().root() + self.history_tree().root())

    def advance(self, authorization):
        """Regenerate every witness byte, never use supplied witness siblings."""
        old = self
        next_state = copy.deepcopy(self)
        witness = bytearray(4368)
        mode = authorization[204]
        if mode == 0:
            require(len(self.nullifiers) > 1, "admission before bootstrap")
        else:
            count = int.from_bytes(authorization[40:44], "little")
            anchor = authorization[44:76]
            require(count > 0 and count % 2 == 1 and count <= len(self.commitments)
                    and self.roots[(count - 1) // 2] == anchor, "historical anchor")
            witness[:512] = self.history_tree().path((count - 1) // 2)
            for slot in range(2):
                nf = authorization[76 + slot * 32:108 + slot * 32]
                require(nf != ZERO and all(leaf[0] != nf for leaf in next_state.nullifiers), "nullifier spent/zero")
                key = int.from_bytes(nf, "little")
                predecessors = [i for i, (value, _, following) in enumerate(next_state.nullifiers)
                                if int.from_bytes(value, "little") < key
                                and (following == ZERO or key < int.from_bytes(following, "little"))]
                require(len(predecessors) == 1, "unique nullifier predecessor")
                pred = predecessors[0]
                previous = next_state.nullifiers[pred]
                index = len(next_state.nullifiers)
                base = 512 + slot * 1160
                witness[base:base + 4] = pred.to_bytes(4, "little")
                witness[base + 4:base + 72] = self.nf_bytes(previous)
                witness[base + 72:base + 616] = next_state.nf_tree().path(pred)
                next_state.nullifiers[pred] = (previous[0], index, nf)
                witness[base + 616:base + 1160] = next_state.nf_tree().path(index)
                next_state.nullifiers.append((nf, previous[1], previous[2]))
        outputs = [authorization[140:172], authorization[172:204]]
        if mode != 2:
            require(len(next_state.commitments) + 2 < 65536 and ZERO not in outputs
                    and outputs[0] != outputs[1], "commitment capacity/output")
            for i, commitment in enumerate(outputs):
                witness[2832 + i * 512:3344 + i * 512] = next_state.cm_tree().path(len(next_state.commitments))
                next_state.commitments.append(commitment)
            witness[3856:] = old.history_tree().path(len(old.roots))
            next_state.roots.append(next_state.cm_tree().root())
        else:
            require(outputs == [ZERO, ZERO], "DRAIN commitment padding")
        next_state.compact()
        return next_state, bytes(witness)


def p2sh(redeem):
    return (b"\0\0\xaa\x20" + hashlib.blake2b(redeem, digest_size=32).digest() + b"\x87").hex()


def region(pointer, start, end, data):
    return dict(pointer=pointer, byte_start=start, byte_end_exclusive=end,
                bytes=end - start, sha256=sha(data[start:end]).hex())


def descriptor_fields(raw):
    fields(raw, "format network genesis domain initial_commitment initial_value_sompi vk_sha256 funding_txid funding_full_hash", "descriptor")
    require(raw["format"] == "kpi-v6-public-replay-v1" and raw["network"] == "testnet-10"
            and raw["genesis"] == GENESIS, "descriptor identity")
    for key in ("vk_sha256", "funding_txid", "funding_full_hash"):
        unhex(raw[key], 32, "descriptor " + key)
    initial = Sompi.parse(raw["initial_value_sompi"])
    require(initial.value >= 60_000_000, "initial reserve floor")
    return hash_array(raw["domain"], "domain"), hash_array(raw["initial_commitment"], "initial commitment"), initial


def select_prefix(raw, prefix_operations):
    """Select the observation cut before examining any later transaction body.

    Unselected parents and later lineage bytes cannot affect the result. Parent
    transaction bodies are public when their selected output is consumed. Their
    other outputs are therefore retained; their *input* ancestry is not assumed.
    """
    fields(raw, "descriptor vk_hex lineage parents", "public input")
    require(type(raw["lineage"]) is list and raw["lineage"], "nonempty lineage")
    integer(prefix_operations, len(raw["lineage"]) - 1, "prefix operations")
    require(type(raw["parents"]) is list, "funding parent list")
    lineage = copy.deepcopy(raw["lineage"][:prefix_operations + 1])
    selected_ids = set()
    for ordinal, tx in enumerate(lineage):
        native_shape(tx)
        if ordinal == 0:
            require(len(tx["inputs"]) == 1, "founding input count")
            selected_ids.add(point(tx["inputs"][0]["previousOutpoint"])[0])
        else:
            payload = unhex(tx["payload"], 5228)
            if payload[212] == 0:
                require(len(tx["inputs"]) == 2, "ADMIT input count")
                selected_ids.add(point(tx["inputs"][1]["previousOutpoint"])[0])
    parents = []
    found = set()
    for parent in raw["parents"]:
        # No validation or hash of future/unselected bodies. The ID is only the
        # lookup key here; native hashing remains a separately reported check.
        if type(parent) is dict and type(parent.get("id")) is str and parent["id"] in selected_ids:
            require(parent["id"] not in found, "duplicate selected funding parent body")
            found.add(parent["id"])
            parents.append(copy.deepcopy(parent))
    require(found == selected_ids, "missing selected funding parent body")
    parents.sort(key=lambda tx: tx["id"])
    return dict(descriptor=copy.deepcopy(raw["descriptor"]), vk_hex=raw["vk_hex"], lineage=lineage, parents=parents)


def extract(raw, prefix_operations, expected_descriptor_sha256):
    """Extract under a caller-supplied pool expectation, never a self-pin.

    The caller must obtain that digest from an independently trusted source.
    Matching it checks identity; it cannot authenticate the caller's source.
    """
    selected = select_prefix(raw, prefix_operations)
    descriptor = selected["descriptor"]
    unhex(expected_descriptor_sha256, 32, "expected descriptor digest")
    require(sha(canonical(descriptor)).hex() == expected_descriptor_sha256,
            "descriptor differs from trusted expectation")
    domain, initial_commitment, initial = descriptor_fields(descriptor)
    vk = unhex(selected["vk_hex"], 328, "verification key")
    require(sha(vk).hex() == descriptor["vk_sha256"], "VK identity")
    parents = {parent["id"]: parent for parent in selected["parents"]}
    lineage = selected["lineage"]
    for parent in parents.values():
        native_shape(parent)
        require(parent["payload"] == "", "ordinary funding parent payload")
    identities = list(parents) + [tx["id"] for tx in lineage]
    require(len(identities) == len(set(identities)), "duplicate native transaction identity")
    used_inputs = set()
    for tx in list(parents.values()) + lineage:
        for entry in tx["inputs"]:
            outpoint = point(entry["previousOutpoint"])
            require(outpoint not in used_inputs, "native input reused across public graph")
            used_inputs.add(outpoint)
    consumed = set()
    funding_records = []

    def funding(outpoint, consumer):
        txid, index = point(outpoint)
        require((txid, index) not in consumed, "selected funding outpoint reused")
        require(txid in parents and index < len(parents[txid]["outputs"]), "missing funding output")
        output = parents[txid]["outputs"][index]
        script = unhex(output["scriptPublicKey"], 36, "selected funding script")
        require(script[:3] == b"\0\0\x20" and script[-1] == 0xac, "selected funding P2PK")
        value = Sompi.parse(output["value"])
        consumed.add((txid, index))
        record = dict(transaction_id=txid, output_index=index, value_sompi=str(value),
                      script_public_key=script.hex(), consumer=consumer,
                      source_pointer=f"/parents/{list(parents).index(txid)}/outputs/{index}")
        funding_records.append(record)
        return value

    founding = lineage[0]
    require(founding["id"] == descriptor["funding_txid"] and len(founding["outputs"]) == 2
            and founding["payload"] == "" and founding["inputs"][0]["sequence"] == str(2**64 - 1), "founding shape/ID")
    require(Sompi.parse(founding["outputs"][0]["value"]) == initial, "initial reserve value")
    founding_source = funding(founding["inputs"][0]["previousOutpoint"], "/lineage/0/inputs/0")
    change = Sompi.parse(founding["outputs"][1]["value"])
    founding_fee = Sompi(founding_source.value - initial.value - change.value)
    public_state = PublicState(initial_commitment)
    balance = initial.value
    expected_point = (founding["id"], 0)
    expected_spk = founding["outputs"][0]["scriptPublicKey"]
    code_suffix = code_prefix = None
    records = []
    admitted = paid = fees = 0
    for ordinal, tx in enumerate(lineage[1:]):
        require(balance > 0, "history after terminal")
        payload = unhex(tx["payload"], 5228, "payload")
        require(payload[:8] == b"KPICR06\0", "payload framing")
        auth, ciphertexts, successor, supplied_witness = payload[8:385], payload[385:755], payload[755:860], payload[860:]
        require(auth[:8] == b"KPICU06\0" and auth[8:40] == domain, "authorization domain")
        require(sha(ciphertexts) == auth[345:377], "ciphertext binding")
        mode = auth[204]
        require(mode in (0, 1, 2) and len(tx["inputs"]) == (2 if mode == 0 else 1), "mode/input shape")
        reserve_input = tx["inputs"][0]
        require(point(reserve_input["previousOutpoint"]) == expected_point
                and reserve_input["sequence"] == str(2**64 - 1)
                and reserve_input["computeBudget"] == 3000, "reserve ancestry/input metadata")
        signature = unhex(reserve_input["signatureScript"], 24709, "reserve signature")
        require(signature[:2] == b"\x4c\x80" and signature[130:133] == b"\x4d\x00\x60", "proof/redeem framing")
        proof, redeem = signature[2:130], signature[133:]
        require(redeem[:1] == b"\x20" and redeem[1:33] == domain and redeem[33:36] == b"\x75\x4c\x69"
                and redeem[141] == 0x75, "redeem domain/state framing")
        require(redeem[36:141] == public_state.compact(), "recomputed old public state mismatch")
        require(p2sh(redeem) == expected_spk, "reserve script binding")
        if code_suffix is None:
            code_prefix, code_suffix = redeem[:36], redeem[141:]
        require(redeem[:36] == code_prefix and redeem[141:] == code_suffix, "covenant code continuity")
        payout, fee, deposit, bootstrap = [Sompi.little_endian(auth[start:start + 8]) for start in (205, 213, 257, 337)]
        require(fee.value > 0 and bootstrap.value == (initial.value if ordinal == 0 else 0), "fee/bootstrap")
        require(payout.value > 0 or auth[221:257] == bytes(36), "zero payout script")
        funding_pointer = None
        if mode == 0:
            require(auth[40:140] == bytes(100) and payout.value == 0, "ADMIT public fields")
            extra = tx["inputs"][1]
            require(extra["sequence"] == str(2**64 - 1) and extra["computeBudget"] == 10, "funding input metadata")
            require(len(unhex(extra["signatureScript"])) == 66, "funding signature length")
            actual = funding(extra["previousOutpoint"], f"/lineage/{ordinal + 1}/inputs/1")
            txid, index = point(extra["previousOutpoint"])
            source = parents[txid]["outputs"][index]
            require(bytes.fromhex(txid) + index.to_bytes(4, "little") == auth[265:301]
                    and source["scriptPublicKey"] == auth[301:337].hex() and actual == deposit, "actual funding binding")
            funding_pointer = funding_records[-1]["source_pointer"]
        else:
            require(auth[257:337] == bytes(80), "SPEND/DRAIN funding fields")
        if mode == 2:
            require(ciphertexts == bytes(370) and payout.value > 0, "DRAIN ciphertext padding/payout")
        next_state, expected_witness = public_state.advance(auth)
        require(supplied_witness == expected_witness, "recomputed public settlement witness mismatch")
        total_input = Sompi(balance + deposit.value)
        remaining = Sompi(total_input.value - payout.value - fee.value)
        require(remaining.value > 0 or mode == 2, "terminal requires DRAIN")
        require(len(tx["outputs"]) == int(remaining.value > 0) + int(payout.value > 0), "native output count")
        require(sum(Sompi.parse(o["value"]).value for o in tx["outputs"]) == remaining.value + payout.value, "native output accounting")
        if payout.value:
            require(tx["outputs"][-1]["value"] == str(payout)
                    and tx["outputs"][-1]["scriptPublicKey"] == auth[221:257].hex(), "native payout binding")
        if remaining.value:
            require(successor == next_state.compact(), "recomputed successor public state mismatch")
            require(tx["outputs"][0]["value"] == str(remaining)
                    and tx["outputs"][0]["scriptPublicKey"] == p2sh(code_prefix + successor + code_suffix), "successor reserve/script binding")
            expected_spk = tx["outputs"][0]["scriptPublicKey"]
        else:
            require(successor == bytes(105), "terminal successor padding")
        before_count = len(public_state.commitments)
        source_prefix = f"/lineage/{ordinal + 1}"
        digest = sha(auth)
        records.append(dict(
            ordinal=ordinal, transaction_id=tx["id"], mode=mode,
            order_source="reserve dependency ordinal", timestamp=None, request_minute=None, owner=None,
            reserve_before_sompi=str(Sompi(balance)), deposit_sompi=str(deposit), payout_sompi=str(payout),
            fee_sompi=str(fee), reserve_after_sompi=str(remaining), bootstrap_sompi=str(bootstrap),
            funding_source_pointer=funding_pointer, payout_script=auth[221:257].hex() if payout.value else None,
            anchor_count=int.from_bytes(auth[40:44], "little"), anchor_root=auth[44:76].hex(),
            commitment_count_before=before_count,
            appended_commitment_positions=list(range(before_count, len(next_state.commitments))),
            commitment_slots=[auth[140:172].hex(), auth[172:204].hex()],
            nullifier_slots=[auth[76:108].hex(), auth[108:140].hex()],
            authorization_sha256=digest.hex(), proof_sha256=sha(proof).hex(),
            ciphertext_sha256=sha(ciphertexts).hex(), ciphertexts=[ciphertexts[:185].hex(), ciphertexts[185:].hex()],
            groth16_public_input_decimal=[str(int.from_bytes(digest[i:i + 16], "little")) for i in (0, 16)],
            old_public_state_hex=public_state.compact().hex(), next_public_state_hex=next_state.compact().hex(),
            settlement_witness=dict(supplied_sha256=sha(supplied_witness).hex(),
                                    independently_regenerated_sha256=sha(expected_witness).hex(), exact_match=True,
                                    source="earlier selected public commitments, indexed nullifiers and root history only"),
            source_regions=[region(source_prefix + "/payload", start, end, payload)
                            for start, end in [(0, 8), (8, 385), (385, 755), (755, 860), (860, 5228)]]
                           + [region(source_prefix + "/inputs/0/signatureScript", 2, 130, signature),
                              region(source_prefix + "/inputs/0/signatureScript", 133, 24709, signature)],
        ))
        admitted += deposit.value
        paid += payout.value
        fees += fee.value
        require(initial.value + admitted == paid + fees + remaining.value, "cumulative backing accounting")
        balance = remaining.value
        expected_point = (tx["id"], 0)
        public_state = next_state
    all_known = {tx["id"]: tx for tx in list(parents.values()) + lineage}
    unresolved, known_parent_inputs = [], []
    lineage_positions = {tx["id"]: i for i, tx in enumerate(lineage)}
    parent_consumers = {}
    for record in funding_records:
        consumer_ordinal = int(record["consumer"].split("/")[2])
        parent_consumers.setdefault(record["transaction_id"], []).append(consumer_ordinal)
    for i, parent in enumerate(selected["parents"]):
        for j, entry in enumerate(parent["inputs"]):
            txid, index = point(entry["previousOutpoint"])
            pointer = f"/parents/{i}/inputs/{j}/previousOutpoint"
            if txid not in all_known:
                # Never fill unknown ancestry with a synthetic UTXO.
                unresolved.append(dict(transaction_id=txid, output_index=index,
                                       source_pointer=pointer, status="input UTXO body/value/script absent"))
                continue
            require(txid in lineage_positions, "parent-to-parent ancestry unsupported; supply a separately validated graph")
            require(lineage_positions[txid] < min(parent_consumers[parent["id"]]),
                    "funding parent references a future pool transaction")
            referenced = all_known[txid]
            require(index < len(referenced["outputs"]), "parent source output index")
            output = referenced["outputs"][index]
            known_parent_inputs.append(dict(parent_transaction_id=parent["id"], input_index=j,
                                            source_pointer=pointer,
                                            referenced_output_pointer=f"/lineage/{lineage_positions[txid]}/outputs/{index}",
                                            value_sompi=output["value"], script_public_key=output["scriptPublicKey"],
                                            meaning="exact public dependency only; no owner or segregated value-flow attribution"))
    return dict(
        schema=SCHEMA, prefix_operations=prefix_operations,
        provenance=dict(selected_public_input_sha256=sha(canonical(selected)).hex(),
                        selected_public_input_bytes=len(canonical(selected)),
                        descriptor_sha256=sha(canonical(descriptor)).hex(),
                        expected_descriptor_sha256=expected_descriptor_sha256,
                        descriptor_matches_caller_expectation=True,
                        expected_identity_source="caller must authenticate this digest independently",
                        vk_sha256=sha(vk).hex(),
                        transaction_source_pointers=[f"/lineage/{i}" for i in range(len(lineage))],
                        source_scope="selected prefix and exact consumed public funding parents; later bytes excluded"),
        validation=dict(public_settlement_witness_recomputed=True, public_state_roots_recomputed=True,
                        public_settlement_witnesses_checked=len(records),
                        public_native_accounting_checked=True, covenant_script_continuity_checked=bool(records),
                        transaction_id_recomputed=False, native_vm_verified=False, groth16_verified=False,
                        funding_parent_spends_verified=False, chain_acceptance_verified=False,
                        canonical_covenant_code_verified=False),
        initial=dict(transaction_id=founding["id"], commitment=initial_commitment.hex(), commitment_count=1,
                     reserve_sompi=str(initial), funding_input_sompi=str(founding_source),
                     founding_change_sompi=str(change), founding_fee_sompi=str(founding_fee)),
        accounting=dict(admitted_sompi=str(admitted), paid_sompi=str(paid), pool_fees_sompi=str(fees),
                        remaining_reserve_sompi=str(Sompi(balance)), cumulative_amount_type="unbounded integer sompi; individual amounts range checked"),
        final_public_state_hex=public_state.compact().hex(), records=records, funding_outputs=funding_records,
        known_funding_parent_inputs=known_parent_inputs,
        omissions=dict(funding_parent_input_ancestry=unresolved,
                       timing="no request/first-seen time; historical header times intentionally not relabeled",
                       identities="no ownership directory or participant channel",
                       private_data="no note openings, private membership paths, keys or delivery/decryption result",
                       native_validation="proof/VM/transaction identity and canonical covenant code require the pinned Rust replay",
                       chain_view="descriptor authentication, acceptance, current spendability and complete prefix are external"),
    )


def validate_observation(value, raw, expected_descriptor_sha256):
    """Rebuild a claimed output from the declared public input and exact cut."""
    require(type(value) is dict and value.get("schema") == SCHEMA
            and type(value.get("prefix_operations")) is int, "observation schema/prefix")
    expected = extract(raw, value["prefix_operations"], expected_descriptor_sha256)
    try:
        observed_bytes = canonical(value)
    except (TypeError, ValueError) as error:
        raise ObservationError("observation is not canonical JSON") from error
    # Python object equality conflates True/1 and 0/0.0. Exact JSON bytes retain
    # the type contract as well as every source-derived value.
    require(observed_bytes == canonical(expected),
            "observation differs from regenerated public bytes")


def load_public_rehearsal(base=HERE):
    """One allowlisted retained fixture; never walk an evidence directory."""
    values = {}
    for label, (relative, expected) in FIXTURE_PINS.items():
        path = base / relative
        require(path.is_file() and not path.is_symlink(), "missing/nonregular allowlisted public fixture: " + relative)
        data = path.read_bytes()
        require(sha(data).hex() == expected, "public fixture pin mismatch: " + relative)
        values[label] = unique_json(data)
    old, receipt = values["descriptor"], values["receipt"]
    require(type(receipt.get("transactions")) is list
            and type(receipt.get("exactBodies")) is int
            and receipt["exactBodies"] == len(receipt["transactions"]), "public receipt framing")
    rows = receipt["transactions"]
    descriptor = {key: old[key] for key in ("network", "genesis", "domain", "initial_commitment", "vk_sha256")}
    descriptor.update(format="kpi-v6-public-replay-v1", initial_value_sompi=str(old["initial_value"]),
                      funding_txid=rows[1]["transaction"]["id"], funding_full_hash=rows[1]["fullHash"])
    # Explicitly exclude the legacy descriptor's roster and receipt headers.
    return dict(descriptor=descriptor, vk_hex=values["vk"]["hex"],
                lineage=[row["transaction"] for row in rows[1:]], parents=[rows[0]["transaction"]])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix-operations", type=int, required=True)
    parser.add_argument("--expected-descriptor-sha256", required=True,
                        help="independently trusted canonical public descriptor digest; not derived from this run's input")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = extract(load_public_rehearsal(), args.prefix_operations, args.expected_descriptor_sha256)
    with args.output.open("x") as target:
        json.dump(result, target, indent=2)
        target.write("\n")


if __name__ == "__main__":
    try:
        main()
    except (ObservationError, OSError, KeyError, json.JSONDecodeError) as error:
        print("public native observation: " + str(error), file=sys.stderr)
        sys.exit(1)
