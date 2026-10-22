#!/usr/bin/env python3
"""Review-only public witness path closure and typed-output regression checks.

Uses only the adapter's three hash-pinned public rehearsal fixtures. Does not
invoke Rust, a VM, a prover, a privacy observer, a network or private evidence.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys

SOURCE = Path(__file__).resolve().parents[2] / "native/poc/shared-pool"
sys.path.insert(0, str(SOURCE))
import public_native_observation as observation

EXPECTED_DESCRIPTOR = "d02c36cd87db7bfd43f6f85a425539a90f8f39224a20ac5ef860ae0f54be3a8b"
ZERO = bytes(32)
checks = 0


def require(condition, reason):
    global checks
    checks += 1
    if not condition:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).digest()


def root(leaf, index, path):
    if len(path) not in (512, 544):
        raise ValueError("wrong path dimension")
    for level in range(len(path) // 32):
        sibling = path[level * 32:(level + 1) * 32]
        pair = sibling + leaf if (index >> level) & 1 else leaf + sibling
        leaf = sha(b"\x01" + pair)
    return leaf


raw = observation.load_public_rehearsal()
decoded = observation.extract(raw, 13, EXPECTED_DESCRIPTOR)
paths = 0
for i, record in enumerate(decoded["records"], 1):
    tx = raw["lineage"][i]
    payload = bytes.fromhex(tx["payload"])
    signature = bytes.fromhex(tx["inputs"][0]["signatureScript"])
    old = signature[169:274]
    new = bytes.fromhex(record["next_public_state_hex"])
    auth, witness = payload[8:385], payload[860:]
    mode = auth[204]
    nf_root = old[41:73]
    if mode != 0:
        count = int.from_bytes(auth[40:44], "little")
        history_leaf = sha(b"\x03" + auth[40:76])
        require(root(history_leaf, (count - 1) // 2, witness[:512]) == old[73:105], "historical anchor path")
        paths += 1
        for slot in range(2):
            base = 512 + slot * 1160
            pred = int.from_bytes(witness[base:base + 4], "little")
            leaf = witness[base + 4:base + 72]
            pred_path = witness[base + 72:base + 616]
            append_path = witness[base + 616:base + 1160]
            nf = auth[76 + slot * 32:108 + slot * 32]
            index = int.from_bytes(old[5:9], "little") + slot + 1
            require(root(sha(b"\x02" + leaf), pred, pred_path) == nf_root, "indexed predecessor path")
            changed = leaf[:32] + index.to_bytes(4, "little") + nf
            intermediate = root(sha(b"\x02" + changed), pred, pred_path)
            require(root(ZERO, index, append_path) == intermediate, "empty indexed append path")
            nf_root = root(sha(b"\x02" + nf + leaf[32:]), index, append_path)
            paths += 4
    require(nf_root == new[41:73], "sequential nullifier root")
    if mode != 2:
        count = int.from_bytes(old[1:5], "little")
        cm_root = old[9:41]
        for slot in range(2):
            path = witness[2832 + slot * 512:3344 + slot * 512]
            require(root(ZERO, count + slot, path) == cm_root, "empty commitment append path")
            cm_root = root(sha(b"\x00" + auth[140 + slot * 32:172 + slot * 32]), count + slot, path)
            paths += 2
        require(cm_root == new[9:41], "sequential commitment root")
        index = (count + 1) // 2
        require(root(ZERO, index, witness[3856:]) == old[73:105], "empty history append path")
        leaf = sha(b"\x03" + (count + 2).to_bytes(4, "little") + cm_root)
        require(root(leaf, index, witness[3856:]) == new[73:105], "new history root")
        paths += 2

typed_rejections = 0
for field, value in (("mode", True), ("ordinal", False), ("ordinal", 0.0)):
    bad = copy.deepcopy(decoded)
    bad["records"][0][field] = value
    try:
        observation.validate_observation(bad, raw, EXPECTED_DESCRIPTOR)
    except observation.ObservationError:
        typed_rejections += 1
    else:
        raise ValueError("typed output injection accepted")

print(json.dumps(dict(passed=True, operations=len(decoded["records"]),
                     independently_folded_paths=paths, root_equalities=checks,
                     typed_output_rejections=typed_rejections,
                     scope="public path closure and typed projection only; no native/proof verification")))
