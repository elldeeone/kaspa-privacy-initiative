#!/usr/bin/env python3
"""Review public synthetic state fixtures without importing either implementation.

Checks bytes, SHA256 paths and roots only. No Groth16/zkVM/native verification,
proving material, wallet secrets, accepted history or backing assertion.
"""
import hashlib
import json
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "poc/two-v6-state/public-fixtures"
PAIR_SHA = "7771a2e610d37fdb12b1d668b8e229bd3cd1e5fe83c5993847daa0fef8c93b36"
MANIFEST_SHA = "3dec202e797fd714547de6ef77e76489c557188f4e4e38b2d01c0618c495f9c6"
SOURCE_PINS = {
    "poc/shared-pool/src/two_input/tree.rs": "9fc004721ae2a22c6faa26f2a046eefd7bb707e3c83077be01a7913b464891ed",
    "poc/shared-pool/src/compact/tree.rs": "4ac46cb3e514e58181d0a4e2195e882f22d1df83d8dc6ea926fac47102ea0dc6",
    "poc/two-v6-state/public_state_oracle.py": "77788cb3cb15a497ad02b6c9fd08c659fe2909e691823b855243be69afd8372e",
}
ZERO = bytes(32)
COUNTS = {"path_folds": 0, "full_tree_roots": 0, "checks": 0}


def check(condition, reason):
    COUNTS["checks"] += 1
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).digest()


def uint(raw):
    return int.from_bytes(raw, "little")


def u32(number):
    return number.to_bytes(4, "little")


def node(left, right):
    return sha(b"\x01" + left + right)


def fold(leaf, position, wire):
    check(len(wire) in (512, 544), "path dimension")
    check(0 <= position < (1 << (len(wire) // 32)), "path position")
    COUNTS["path_folds"] += 1
    for offset in range(0, len(wire), 32):
        sibling = wire[offset:offset + 32]
        leaf = node(sibling, leaf) if position & 1 else node(leaf, sibling)
        position >>= 1
    return leaf


def full_root(leaves, depth):
    """Recursive interval tree, independent of the producer's levels/path code."""
    COUNTS["full_tree_roots"] += 1
    zeros = [ZERO]
    for _ in range(depth):
        zeros.append(node(zeros[-1], zeros[-1]))

    def subtree(start, height):
        if start >= len(leaves):
            return zeros[height]
        if height == 0:
            return leaves[start]
        return node(subtree(start, height - 1),
                    subtree(start + (1 << (height - 1)), height - 1))

    return subtree(0, depth)


def cm_leaf(commitment):
    return sha(b"\x00" + commitment)


def history_leaf(count, root):
    return sha(b"\x03" + u32(count) + root)


def state(cm_count, nf_count, cm_root, nf_root, history_root):
    return b"\x07" + u32(cm_count) + u32(nf_count) + cm_root + nf_root + history_root


def inspect(entry):
    name = entry["context"]
    folder = FIXTURES / name
    files = {}
    for filename, pin in entry["files"].items():
        files[filename] = (folder / filename).read_bytes()
        check(len(files[filename]) == pin["bytes"], "file size")
        check(sha(files[filename]).hex() == pin["sha256"], "file digest")
    wire = files["input.bin"]
    check(len(wire) == 11_219 and sha(wire[:2846]).hex() == PAIR_SHA, "unchanged pair")
    p = wire[:1088]
    nfs = [p[92 + 32 * i:124 + 32 * i] for i in range(4)]
    records = [p[220 + 217 * i:437 + 217 * i] for i in range(4)]
    check(nfs == sorted(nfs) and len(set(nfs)) == 4, "public NF sort/uniqueness")
    check(nfs != sorted(nfs, key=uint), "fixture exercises comparator disagreement")
    check(records == sorted(records), "complete output record sort")
    prior = wire[2882:2987]
    check(prior == files["expected-prior-state.bin"], "prior bytes")
    check(prior[0] == 7, "separate state version")
    n, m = uint(prior[1:5]), uint(prior[5:9])
    check(n in (3, 5) and m == 2, "declared synthetic counts")
    cms = [bytes.fromhex(x) for x in entry["prior_commitments"]]
    leaves = [bytes.fromhex(x) for x in entry["prior_nullifier_leaves"]]
    prefixes = [bytes.fromhex(x) for x in entry["prior_odd_commitment_prefix_roots"]]
    check(len(cms) == n and len(leaves) == m + 1 and len(prefixes) == (n + 1) // 2,
          "complete public initial leaves")
    cm_root = full_root([cm_leaf(x) for x in cms], 16)
    nf_root = full_root([sha(b"\x02" + x) for x in leaves], 17)
    history = [history_leaf(2 * i + 1, x) for i, x in enumerate(prefixes)]
    hr = full_root(history, 16)
    check(prior == state(n, m, cm_root, nf_root, hr), "independent complete prior roots")
    auth0, auth1 = wire[1088:1465], wire[1963:2340]
    check(auth0[40:76] == auth1[40:76], "both actual authorization anchors")
    a, anchor = uint(auth0[40:44]), auth0[44:76]
    check(a == 3 and 1 <= a <= n and a % 2 == 1, "historical count range")
    check((anchor == cm_root) == (name == "current-anchor"), "historical-only control")
    check(fold(history_leaf(a, anchor), (a - 1) // 2, wire[2995:3507]) == hr,
          "actual inner anchor under supplied history")
    for i, value in enumerate(nfs):
        start = 3507 + 1160 * i
        w = wire[start:start + 1160]
        index, old = uint(w[:4]), w[4:72]
        old_path, append_path = w[72:616], w[616:1160]
        append_index = m + i + 1
        check(index < append_index < 131072 and old == leaves[index], "NF predecessor identity")
        check(uint(old[:32]) < uint(value), "numeric predecessor lower bound")
        check(old[36:] == ZERO or uint(value) < uint(old[36:]), "numeric successor upper bound")
        check((uint(old[32:36]) == 0) if old[36:] == ZERO else (0 < uint(old[32:36]) < append_index),
              "NF successor pointer range")
        check(fold(sha(b"\x02" + old), index, old_path) == nf_root, "current NF predecessor path")
        leaves[index] = old[:32] + u32(append_index) + value
        middle = fold(sha(b"\x02" + leaves[index]), index, old_path)
        check(middle == full_root([sha(b"\x02" + x) for x in leaves], 17), "full predecessor update")
        check(fold(ZERO, append_index, append_path) == middle, "empty current NF slot")
        leaves.append(value + old[32:])
        nf_root = fold(sha(b"\x02" + leaves[-1]), append_index, append_path)
        check(nf_root == full_root([sha(b"\x02" + x) for x in leaves], 17), "full sequential NF root")
    new_prefixes = []
    for i, record in enumerate(records):
        path = wire[8147 + 512 * i:8659 + 512 * i]
        check(fold(ZERO, n + i, path) == cm_root, "empty sequential CM slot")
        cms.append(record[:32])
        cm_root = fold(cm_leaf(record[:32]), n + i, path)
        check(cm_root == full_root([cm_leaf(x) for x in cms], 16), "full sequential CM root")
        if i in (1, 3):
            new_prefixes.append(cm_root)
    for i, prefix in enumerate(new_prefixes):
        position, count = (n + 1) // 2 + i, n + 2 + 2 * i
        path = wire[10195 + 512 * i:10707 + 512 * i]
        check(fold(ZERO, position, path) == hr, "empty sequential history slot")
        history.append(history_leaf(count, prefix))
        hr = fold(history[-1], position, path)
        check(hr == full_root(history, 16), "full prefix history root")
    after = state(n + 4, m + 4, cm_root, nf_root, hr)
    check(after == files["expected-next-state.bin"], "complete independently derived next state")
    reserve, fee = uint(wire[2987:2995]), uint(p[76:92])
    check(fee == 80_000_000 < reserve == 1_700_000_000, "declared reserve and exact fee")
    journal = (b"KPI2V6S1\x01\x00" + sha(p)
               + sha(b"KPI/public-two-v6-state/DO-NOT-FUND/v1") + wire[2846:2882]
               + prior + after + reserve.to_bytes(8, "little")
               + (reserve - fee).to_bytes(8, "little"))
    check(len(journal) == 336 and journal == files["expected-journal.bin"], "complete J336")
    return {"context": name, "prior_cm_count": n, "next_cm_count": n + 4,
            "journal_sha256": sha(journal).hex(), "input_sha256": sha(wire).hex()}


for relative, digest in SOURCE_PINS.items():
    check(sha((REPO / relative).read_bytes()).hex() == digest, "source pin " + relative)
manifest_raw = (FIXTURES / "manifest.json").read_bytes()
check(sha(manifest_raw).hex() == MANIFEST_SHA, "frozen fixture manifest")
manifest = json.loads(manifest_raw)
results = [inspect(entry) for entry in manifest["contexts"]]
print(json.dumps({"passed": True, "scope": "public synthetic byte/tree/J336 conformance only",
                  "source_pins": SOURCE_PINS, "fixture_manifest_sha256": MANIFEST_SHA,
                  "contexts": results, "counts": COUNTS,
                  "inner_cryptographic_verification": False,
                  "native_or_accepted_predecessor_authentication": False,
                  "backing_genesis_or_owner_exit_qualification": False}, indent=2, sort_keys=True))
