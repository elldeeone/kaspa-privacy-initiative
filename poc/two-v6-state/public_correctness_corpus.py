#!/usr/bin/env python3
"""Frozen deterministic PUBLIC correctness corpus for NONFUNDABLE S7 assertions.

No privacy evaluation, private inputs, Rust invocation, setup, proof or network.
All predecessors are supplied synthetic contexts, not accepted/reachable/backed
states. Existing two-fixture bytes are read only. Freeze --plan before --generate.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("independent_public_oracle", HERE / "public_state_oracle.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
ZERO = bytes(32)
SEED = b"KPI/public-two-v6-state/correctness-corpus/v1"
SHAPES = ("sentinel", "tail", "bracket-first", "bracket-last", "bracket-all", "hashed", "numeric-neighbors", "dense-capacity")
COUNTS = (3, 5, 17, 65531)
MAX = base.MAX_SOMPI
FEE = 80_000_000
OFF = {"state": 2882, "reserve": 2987, "anchor": 2995, "nf": 3507, "cm": 8147, "history": 10195}


def sha(raw):
    return hashlib.sha256(raw).digest()


def number(raw):
    return int.from_bytes(raw, "little")


def le256(value):
    return value.to_bytes(32, "little")


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


class Tree:
    """Independent mutable fixed-depth public Merkle tree with O(depth) updates."""

    def __init__(self, leaves, depth):
        self.depth = depth
        self.empty = [ZERO]
        for _ in range(depth):
            self.empty.append(base.node(self.empty[-1], self.empty[-1]))
        self.levels = [list(leaves)]
        for level in range(depth):
            previous = self.levels[-1]
            self.levels.append([base.node(previous[i], previous[i + 1] if i + 1 < len(previous) else self.empty[level])
                                for i in range(0, len(previous), 2)])

    def root(self):
        return self.levels[-1][0] if self.levels[-1] else self.empty[-1]

    def path(self, index):
        assert 0 <= index < 1 << self.depth
        return [self.levels[level][sibling] if sibling < len(self.levels[level]) else self.empty[level]
                for level in range(self.depth) for sibling in [(index >> level) ^ 1]]

    def set(self, index, value):
        assert 0 <= index <= len(self.levels[0]) and index < 1 << self.depth
        for level in range(self.depth + 1):
            if index == len(self.levels[level]):
                self.levels[level].append(value)
            else:
                self.levels[level][index] = value
            if level < self.depth:
                sibling = self.levels[level][index ^ 1] if (index ^ 1) < len(self.levels[level]) else self.empty[level]
                value = base.node(sibling, value) if index & 1 else base.node(value, sibling)
                index >>= 1


def make_plan():
    cases = []
    for n in COUNTS:
        for shape in SHAPES:
            for layout in ("numeric", "permuted"):
                for reserve in (FEE + 1, MAX):
                    ordinal = len(cases)
                    m = min({"sentinel": 2, "tail": 2, "bracket-first": 4, "bracket-last": 6,
                             "bracket-all": 8, "hashed": 16, "numeric-neighbors": 128,
                             "dense-capacity": max(2, 2 * n - 2)}[shape], 2 * n)
                    cases.append({"id": f"valid-{ordinal:03d}", "cm_count": n, "nf_count": m,
                                  "shape": shape, "physical_layout": layout, "reserve_sompi": str(reserve),
                                  "expected": "AcceptWithExactIndependentJournal"})
    negatives = [
        ("state-version", "StateVersion", "semantic"),
        ("cm-zero", "StateCounts", "semantic"), ("cm-even", "StateCounts", "semantic"),
        ("nf-odd", "StateCounts", "semantic"), ("nf-excess", "StateCounts", "semantic"),
        ("nf-zero-uninitialized", "Uninitialized", "semantic"),
        ("cm-capacity", "Capacity", "semantic"), ("cm-u32-max", "StateCounts", "semantic"),
        ("nf-u32-max", "StateCounts", "semantic"), ("anchor-count-above-prior", "HistoricalCount", "semantic"),
        ("anchor-path", "HistoricalRoot", "semantic"), ("history-root", "HistoricalRoot", "semantic"),
        ("current-cm-root", "CurrentAnchor", "semantic"), ("nf-stale-root", "NullifierRoot(0)", "semantic"),
        ("nf-index", "NullifierIndex(0)", "semantic"), ("nf-sentinel-link", "NullifierLink(0)", "semantic"),
        ("nf-equality-wire", "NullifierOrder(0)", "semantic"), ("nf-next-link", "NullifierLink(0)", "semantic"),
        ("nf-predecessor-path", "NullifierRoot(0)", "semantic"), ("nf-append-path", "NullifierOccupied(0)", "semantic"),
        ("cm-path-0", "CommitmentOccupied(0)", "semantic"), ("cm-path-3", "CommitmentOccupied(3)", "semantic"),
        ("history-path-0", "HistoryOccupied(0)", "semantic"), ("history-path-1", "HistoryOccupied(1)", "semantic"),
        ("reserve-zero", "Reserve", "semantic"), ("reserve-equals-fee", "Reserve", "semantic"),
        ("reserve-above-max", "Reserve", "semantic"), ("reserve-u64-max", "Reserve", "semantic"),
        ("public-fee-u128-overflow-native", "Binding", "semantic-binding"),
        ("public-fee-mismatch", "Binding", "semantic-binding"), ("public-duplicate-nf", "Binding", "semantic-binding"),
        ("bundle-anchor-substitution", "Binding", "semantic-binding"),
        ("nf-authenticated-replay", "NullifierOrder(0)", "semantic"),
        ("input-truncated", "Length", "framing"), ("input-trailing", "Length", "framing"),
    ]
    return {"format": "kpi-public-s7-correctness-plan-v1", "public_deterministic_seed_ascii": SEED.decode(),
            "seed_sha256": sha(SEED).hex(), "generator_sha256": sha(Path(__file__).read_bytes()).hex(),
            "base_oracle_sha256": sha((HERE / "public_state_oracle.py").read_bytes()).hex(),
            "pair_input_sha256": base.PAIR_SHA, "public_projection_sha256": base.P_SHA,
            "positive_count": 128, "cases": cases,
            "negative_cases": [{"id": name, "expected_error_family": error, "class": kind}
                               for name, error, kind in negatives],
            "scope": "Supplied synthetic context/path validity only; no genesis/backing/reachability/exit/chain/privacy claim.",
            "stop_rule": "Freeze all expected bytes before Rust. Retain every mismatch; never remove/tune a case after differential results.",
            "resource_errors": "Resource/process failures do not count as semantic rejection.",
            "fee_error_boundary": "Unchanged genuine P fixes fee80M. Mutating P fee can only test Binding; direct StateError::Fee cannot be reached with these unchanged proofs."}


def public_nf_values(case, real_nfs):
    count, shape = case["nf_count"], case["shape"]
    ns = sorted(number(nf) for nf in real_nfs)
    values = []
    if shape == "sentinel":
        values = [ns[-1] + 1, ns[-1] + 2]
    elif shape == "tail":
        values = [1, 2]
    elif shape in ("bracket-first", "bracket-last"):
        target = ns[0] if shape == "bracket-first" else ns[-1]
        values = [target - 1, target + 1]
    elif shape in ("bracket-all", "numeric-neighbors"):
        values = [value + delta for value in ns for delta in (-1, 1)]
        values = values[:count]
    seen = set(values)
    assert all(0 < value < 1 << 256 and value not in ns for value in values)
    i = 0
    label = f"{case['cm_count']}/{shape}".encode()
    while len(values) < count:
        value = number(sha(SEED + b"/nf/" + label + struct.pack("<Q", i)))
        i += 1
        if value and value not in ns and value not in seen:
            seen.add(value)
            values.append(value)
    assert len(values) == len(set(values)) == count
    values.sort()
    if case["physical_layout"] == "permuted":
        values.sort(key=lambda value: sha(SEED + b"/physical/" + label + le256(value)))
        if values == sorted(values):
            values.reverse()
    return [le256(value) for value in values]


def linked_leaves(values):
    physical = {value: i + 1 for i, value in enumerate(values)}
    ordered = sorted(values, key=number)
    assert len(physical) == len(values) and ZERO not in physical
    leaves = [(ZERO, physical[ordered[0]], ordered[0])] + [None] * len(values)
    for i, value in enumerate(ordered):
        successor = ordered[i + 1] if i + 1 < len(ordered) else ZERO
        leaves[physical[value]] = (value, physical[successor] if successor != ZERO else 0, successor)
    return leaves


def insert(leaves, tree, nf):
    matches = [i for i, leaf in enumerate(leaves)
               if number(leaf[0]) < number(nf) and (leaf[2] == ZERO or number(nf) < number(leaf[2]))]
    assert len(matches) == 1 and all(leaf[0] != nf for leaf in leaves)
    pred, index = matches[0], len(leaves)
    old = leaves[pred]
    path = tree.path(pred)
    before = tree.root()
    assert base.fold_path(base.nf_leaf(old), pred, path) == before
    changed = (old[0], index, nf)
    tree.set(pred, base.nf_leaf(changed))
    assert base.fold_path(base.nf_leaf(changed), pred, path) == tree.root()
    mid = tree.root()
    empty = tree.path(index)
    assert base.fold_path(ZERO, index, empty) == mid
    added = (nf, old[1], old[2])
    leaves[pred] = changed
    leaves.append(added)
    tree.set(index, base.nf_leaf(added))
    assert base.fold_path(base.nf_leaf(added), index, empty) == tree.root()
    return base.u32(pred) + base.leaf_bytes(old) + b"".join(path) + b"".join(empty), {
        "pred_index": pred, "append_index": index, "sentinel": pred == 0, "tail": old[2] == ZERO,
        "prior_root": before.hex(), "intermediate_root": mid.hex(), "after_root": tree.root().hex()}


def make_cm_bases(initial):
    tree, roots, bases = Tree([], 16), [], {}
    for position in range(max(COUNTS)):
        cm = initial[position] if position < 3 else sha(SEED + b"/cm/" + struct.pack("<I", position))
        tree.set(position, base.cm_leaf(cm))
        if position % 2 == 0:
            roots.append(tree.root())
        count = position + 1
        if count in COUNTS:
            bases[count] = (copy.deepcopy(tree), list(roots))
    return bases


def derive(case, pair, nfs, records, context, cm_bases):
    n, m = case["cm_count"], case["nf_count"]
    cm, roots = copy.deepcopy(cm_bases[n])
    history = Tree([base.history_leaf(2 * i + 1, root) for i, root in enumerate(roots)], 16)
    leaves = linked_leaves(public_nf_values(case, nfs))
    nf = Tree([base.nf_leaf(leaf) for leaf in leaves], 17)
    prior = b"\x07" + base.u32(n) + base.u32(m) + cm.root() + nf.root() + history.root()
    anchor_count, anchor = context
    anchor_path = history.path((anchor_count - 1) // 2)
    assert base.fold_path(base.history_leaf(anchor_count, anchor), (anchor_count - 1) // 2, anchor_path) == history.root()
    nf_wires, nf_steps = [], []
    for value in nfs:
        wire, step = insert(leaves, nf, value)
        nf_wires.append(wire)
        nf_steps.append(step)
    cm_paths, cm_roots, prefixes = [], [], []
    for i, record in enumerate(records):
        path = cm.path(n + i)
        assert base.fold_path(ZERO, n + i, path) == cm.root()
        cm.set(n + i, base.cm_leaf(record[:32]))
        assert base.fold_path(base.cm_leaf(record[:32]), n + i, path) == cm.root()
        cm_paths.append(b"".join(path))
        cm_roots.append(cm.root().hex())
        if i in (1, 3):
            prefixes.append((n + i + 1, cm.root()))
    history_paths, history_roots = [], []
    for i, (count, root) in enumerate(prefixes):
        index = (n + 1) // 2 + i
        path = history.path(index)
        assert base.fold_path(ZERO, index, path) == history.root()
        history.set(index, base.history_leaf(count, root))
        assert base.fold_path(base.history_leaf(count, root), index, path) == history.root()
        history_paths.append(b"".join(path))
        history_roots.append(history.root().hex())
    successor = b"\x07" + base.u32(n + 4) + base.u32(m + 4) + cm.root() + nf.root() + history.root()
    reserve = int(case["reserve_sompi"])
    outpoint = sha(SEED + b"/outpoint/" + case["id"].encode()) + base.u32(int(case["id"][-3:]))
    wire = pair + outpoint + prior + base.u64(reserve) + b"".join(anchor_path) + b"".join(nf_wires) + b"".join(cm_paths) + b"".join(history_paths)
    journal = b"KPI2V6S1\x01\x00" + sha(pair[:1088]) + sha(base.POOL_LABEL) + outpoint + prior + successor + base.u64(reserve) + base.u64(reserve - FEE)
    assert len(wire) == 11219 and len(journal) == 336 and 0 < reserve - FEE <= MAX
    return wire, journal, {"prior_state": prior.hex(), "next_state": successor.hex(), "nf_steps": nf_steps,
                           "intermediate_cm_roots": cm_roots, "intermediate_history_roots": history_roots}


def negative(name, original, nfs):
    raw = bytearray(original)
    def put(offset, value):
        raw[offset:offset + len(value)] = value
    def flip(offset):
        raw[offset] ^= 1
    state = OFF["state"]
    nf = OFF["nf"]
    mutations = {
        "state-version": (state, b"\x06"), "cm-zero": (state + 1, base.u32(0)),
        "cm-even": (state + 1, base.u32(4)), "nf-odd": (state + 5, base.u32(3)),
        "nf-excess": (state + 5, base.u32(8)), "nf-zero-uninitialized": (state + 5, base.u32(0)),
        "cm-capacity": (state + 1, base.u32(65533)), "cm-u32-max": (state + 1, base.u32(2**32 - 1)),
        "nf-u32-max": (state + 5, base.u32(2**32 - 1)), "anchor-count-above-prior": (state + 1, base.u32(1)),
        "nf-index": (nf, base.u32(3)), "nf-sentinel-link": (nf, base.u32(1)),
        "nf-equality-wire": (nf + 4, nfs[0]), "nf-next-link": (nf + 36, base.u32(0)),
        "reserve-zero": (OFF["reserve"], base.u64(0)), "reserve-equals-fee": (OFF["reserve"], base.u64(FEE)),
        "reserve-above-max": (OFF["reserve"], base.u64(MAX + 1)), "reserve-u64-max": (OFF["reserve"], base.u64(2**64 - 1)),
        "public-fee-u128-overflow-native": (84, b"\x01"), "public-fee-mismatch": (76, (FEE + 1).to_bytes(16, "little")),
        "public-duplicate-nf": (124, raw[92:124]), "bundle-anchor-substitution": (1088 + 44, bytes([raw[1088 + 44] ^ 1])),
    }
    flips = {"anchor-path": OFF["anchor"], "history-root": state + 73, "current-cm-root": state + 9,
             "nf-stale-root": state + 41, "nf-predecessor-path": nf + 72, "nf-append-path": nf + 616,
             "cm-path-0": OFF["cm"], "cm-path-3": OFF["cm"] + 3 * 512,
             "history-path-0": OFF["history"], "history-path-1": OFF["history"] + 512}
    if name in mutations:
        put(*mutations[name])
    elif name in flips:
        flip(flips[name])
    elif name == "input-truncated":
        raw = raw[:-1]
    elif name == "input-trailing":
        raw += b"\x00"
    elif name == "nf-authenticated-replay":
        leaves = linked_leaves([le256(1), nfs[0]])
        tree = Tree([base.nf_leaf(leaf) for leaf in leaves], 17)
        index = next(i for i, leaf in enumerate(leaves) if leaf[0] == nfs[0])
        path = tree.path(index)
        assert base.fold_path(base.nf_leaf(leaves[index]), index, path) == tree.root()
        put(state + 41, tree.root())
        put(nf, base.u32(index) + base.leaf_bytes(leaves[index]) + b"".join(path))
        # Strict equality rejects before an insertion/appended-slot path is used.
    else:
        raise AssertionError(name)
    return bytes(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", type=Path)
    mode.add_argument("--generate", type=Path, help="Previously frozen plan path")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    plan = make_plan()
    if args.plan:
        with args.plan.open("xb") as stream:
            stream.write(json_bytes(plan))
        print(json.dumps({"plan_sha256": sha(json_bytes(plan)).hex(), "cases": 128, "negatives": len(plan["negative_cases"])}))
        return
    assert args.output and json.loads(args.generate.read_text()) == plan
    args.output.mkdir(parents=True, exist_ok=False)
    pair = (base.PUBLIC / "expected-input.bin").read_bytes()
    p, nfs, records, context = base.validate_pair_input(pair)
    fixture_manifest = json.loads((base.PUBLIC / "manifest.json").read_text())
    cms = [bytes.fromhex(cm) for cm in fixture_manifest["common_membership_context"]["commitments"]]
    cm_bases = make_cm_bases(cms)
    manifest = {"format": "kpi-public-s7-correctness-corpus-v1", "plan_sha256": sha(args.generate.read_bytes()).hex(),
                "generator_sha256": sha(Path(__file__).read_bytes()).hex(), "scope": plan["scope"],
                "proof_verification": False, "rust_differential_run": False, "positives": [], "negatives": []}
    first = None
    for case in plan["cases"]:
        wire, journal, detail = derive(case, pair, nfs, records, context, cm_bases)
        if first is None:
            first = wire
        directory = args.output / case["id"]
        directory.mkdir()
        (directory / "input.bin").write_bytes(wire)
        (directory / "expected-journal.bin").write_bytes(journal)
        detail.update(case)
        detail.update({"input_sha256": sha(wire).hex(), "journal_sha256": sha(journal).hex()})
        manifest["positives"].append(detail)
        print(json.dumps({"case": case["id"], "input_sha256": sha(wire).hex(), "journal_sha256": sha(journal).hex()}), flush=True)
    for case in plan["negative_cases"]:
        wire = negative(case["id"], first, nfs)
        directory = args.output / "negative" / case["id"]
        directory.mkdir(parents=True)
        (directory / "input.bin").write_bytes(wire)
        manifest["negatives"].append({**case, "input_bytes": len(wire), "input_sha256": sha(wire).hex(),
                                      "base_case": "valid-000", "new_proof_or_setup": False})
    assert len(manifest["positives"]) == 128 and len(manifest["negatives"]) == 35
    (args.output / "manifest.json").write_bytes(json_bytes(manifest))
    print(json.dumps({"completed": True, "positive_count": 128, "negative_count": 35,
                      "manifest_sha256": sha(json_bytes(manifest)).hex()}), flush=True)


if __name__ == "__main__":
    main()
