#!/usr/bin/env python3
"""Independent stdlib initial-four-proof fixture/root/P/J MATH oracle.

No ledger parser/replayer, wallet or owner CLI, DRAIN workflow, Gate/Rust/SDK,
proving, key/opening file or native execution. Named PUBLIC producer artifacts
only. Groth16 validity is deliberately not verified by this byte/math checker.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ZERO = bytes(32)
LABEL = b"KPI/s7-offline-owner-lifecycle/DO-NOT-FUND/v1/"
MAX = 2_900_000_000_000_000_000
PAIR_FEE = 80_000_000
NAMES = ("bootstrap", "admit", "bundle-0", "bundle-1")


def sha(raw):
    return hashlib.sha256(raw).digest()


def u32(n):
    return struct.pack("<I", n)


def u64(n):
    return struct.pack("<Q", n)


def number(raw):
    return int.from_bytes(raw, "little")


def document(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def hex_bytes(value, length, label):
    assert isinstance(value, str), label
    raw = bytes.fromhex(value)
    assert len(raw) == length and raw.hex() == value, label
    return raw


def hash_array(value):
    assert isinstance(value, list) and len(value) == 32
    assert all(type(n) is int and 0 <= n <= 255 for n in value)
    return bytes(value)


def decimal(value):
    assert isinstance(value, str) and str(int(value)) == value and int(value) >= 0
    return int(value)


def node(left, right):
    return sha(b"\x01" + left + right)


def cm_leaf(cm):
    return sha(b"\x00" + cm)


def hist_leaf(count, root):
    return sha(b"\x03" + u32(count) + root)


class Tree:
    def __init__(self, leaves, depth):
        assert depth in (16, 17) and len(leaves) <= 1 << depth
        self.depth = depth
        self.empty = [ZERO]
        for _ in range(depth):
            self.empty.append(node(self.empty[-1], self.empty[-1]))
        self.levels = [list(leaves)]
        for level in range(depth):
            previous = self.levels[-1]
            self.levels.append([node(previous[i], previous[i+1] if i+1 < len(previous) else self.empty[level])
                                for i in range(0, len(previous), 2)])

    def root(self):
        return self.levels[-1][0] if self.levels[-1] else self.empty[-1]

    def path(self, index):
        assert 0 <= index < 1 << self.depth
        return [self.levels[level][sibling] if sibling < len(self.levels[level]) else self.empty[level]
                for level in range(self.depth) for sibling in [(index >> level) ^ 1]]


def fold(leaf, index, path):
    assert 0 <= index < 1 << len(path)
    for level, sibling in enumerate(path):
        leaf = node(sibling, leaf) if (index >> level) & 1 else node(leaf, sibling)
    return leaf


def leaf_bytes(leaf):
    value, next_index, next_value = leaf
    return value + u32(next_index) + next_value


def nf_digest(leaf):
    return sha(b"\x02" + leaf_bytes(leaf))


def linked_leaves(values):
    """Rebuild links from physical insertion order and independent numeric sort."""
    assert ZERO not in values and len(set(values)) == len(values)
    if not values:
        return [(ZERO, 0, ZERO)]
    physical = {value: i+1 for i, value in enumerate(values)}
    ordered = sorted(values, key=number)
    leaves = [(ZERO, physical[ordered[0]], ordered[0])] + [None]*len(values)
    for i, value in enumerate(ordered):
        successor = ordered[i+1] if i+1 < len(ordered) else ZERO
        leaves[physical[value]] = (value, physical[successor] if successor != ZERO else 0, successor)
    return leaves


def nf_tree(values):
    return Tree([nf_digest(leaf) for leaf in linked_leaves(values)], 17)


def cm_tree(cms):
    return Tree([cm_leaf(cm) for cm in cms], 16)


def history_tree(roots):
    return Tree([hist_leaf(2*i+1, root) for i, root in enumerate(roots)], 16)


def state(cms, values, roots):
    n, m = len(cms), len(values)
    assert 0 < n < 65536 and n % 2 == 1 and m % 2 == 0 and m <= 2*n
    assert len(roots) == (n+1)//2 and roots[-1] == cm_tree(cms).root()
    return b"\x07" + u32(n) + u32(m) + cm_tree(cms).root() + nf_tree(values).root() + history_tree(roots).root()


def insertion_witness(values, nf):
    """Only paired-assertion public math, not an owner/withdrawal witness API."""
    assert nf != ZERO and nf not in values
    old_leaves = linked_leaves(values)
    less = [value for value in values if number(value) < number(nf)]
    predecessor = max(less, key=number) if less else ZERO
    pred_index = values.index(predecessor)+1 if less else 0
    old = old_leaves[pred_index]
    assert number(old[0]) < number(nf) and (old[2] == ZERO or number(nf) < number(old[2]))
    index = len(values)+1
    tree = nf_tree(values)
    path = tree.path(pred_index)
    assert fold(nf_digest(old), pred_index, path) == tree.root()
    mid_leaves = list(old_leaves)
    mid_leaves[pred_index] = (old[0], index, nf)
    mid = Tree([nf_digest(leaf) for leaf in mid_leaves], 17)
    assert fold(nf_digest(mid_leaves[pred_index]), pred_index, path) == mid.root()
    empty = mid.path(index)
    assert fold(ZERO, index, empty) == mid.root()
    inserted = (nf, old[1], old[2])
    next_values = values + [nf]
    after = nf_tree(next_values).root()
    assert fold(nf_digest(inserted), index, empty) == after
    wire = u32(pred_index) + leaf_bytes(old) + b"".join(path) + b"".join(empty)
    assert len(wire) == 1160
    return wire, next_values, {"pred_index": pred_index, "append_index": index,
                               "prior_root": tree.root().hex(), "mid_root": mid.root().hex(), "next_root": after.hex()}


def self_checks():
    one, two_fifty_six = (1).to_bytes(32, "little"), (256).to_bytes(32, "little")
    assert sorted([one, two_fifty_six]) != sorted([one, two_fifty_six], key=number)
    leaves = linked_leaves([two_fifty_six, one])
    assert leaves[0] == (ZERO, 2, one) and leaves[2] == (one, 1, two_fifty_six)
    _, inserted, _ = insertion_witness([two_fifty_six, one], (2).to_bytes(32, "little"))
    assert len(inserted) == 3
    records = [sha(b"duplicate-cm")+bytes(185), sha(b"duplicate-cm")+bytes(185),
               sha(b"other-cm-0")+bytes(185), sha(b"other-cm-1")+bytes(185)]
    ordered = sorted(enumerate(records), key=lambda pair: (pair[1], pair[0]))
    assert len(ordered) == 4 and len(set(record for _, record in ordered)) == 3
    cms = [sha(b"initial-math-cm")]
    for _, record in ordered:
        before = cm_tree(cms)
        path = before.path(len(cms))
        assert fold(ZERO, len(cms), path) == before.root()
        cms.append(record[:32])
        assert fold(cm_leaf(record[:32]), len(cms)-1, path) == cm_tree(cms).root()
    assert len(cms) == 5


class PublicFiles:
    """Closed leaf-name allowlist. No directory walks or producer/wallet reads."""
    allowed = {"constants.json", "verification-profile.json", "verification-key.bin", "profile.json",
               "prepare-manifest.json", "initial-state.json", "pre-pair-state.json", "initial-proofs-manifest.json"}
    allowed |= {name+suffix for name in NAMES for suffix in (".json", ".bin")}

    def __init__(self, root):
        self.root, self.opened = root.resolve(), {}
        assert self.root.name == "public", "Use only the producer's named public directory"

    def read(self, leaf):
        assert leaf in self.allowed and "/" not in leaf
        path = self.root/leaf
        assert not path.is_symlink() and path.resolve().parent == self.root
        raw = path.read_bytes()
        self.opened[leaf] = {"bytes": len(raw), "sha256": sha(raw).hex()}
        return raw

    def json(self, leaf):
        return json.loads(self.read(leaf))


def profile_check(files):
    constants = files.json("constants.json")
    descriptor = files.json("verification-profile.json")
    vk = files.read("verification-key.bin")
    domain, pool_id = sha(LABEL+b"domain"), sha(LABEL+b"pool-id")
    assert hex_bytes(constants["domain"], 32, "domain") == hex_bytes(descriptor["domain"], 32, "domain") == domain
    assert hex_bytes(constants["pool_id"], 32, "pool") == hex_bytes(descriptor["pool_id"], 32, "pool") == pool_id
    assert len(vk) == 328 and hex_bytes(descriptor["vk_sha256"], 32, "vk") == sha(vk)
    initial_cm = hex_bytes(constants["initial_commitment"], 32, "initial CM")
    for key, expected in {"initial_value_sompi": 800_000_000, "admit_sompi": 940_000_000,
                          "pre_pair_reserve_sompi": 1_660_000_000, "post_pair_reserve_sompi": 1_580_000_000,
                          "aggregate_pair_fee_sompi": PAIR_FEE, "pool_fees_through_pair_sompi": 160_000_000}.items():
        assert decimal(constants[key]) == expected, key
    assert constants["owner_workflow_implemented"] is False and constants["chain_acceptance_verified"] is False
    return domain, pool_id, vk, initial_cm


def bundle(files, name, domain):
    value = files.json(name+".json")
    assert set(value) == {"authorization", "proof", "ciphertexts"}
    a = hex_bytes(value["authorization"], 377, name+" A")
    proof = hex_bytes(value["proof"], 128, name+" Q")
    assert isinstance(value["ciphertexts"], list) and len(value["ciphertexts"]) == 2
    c = [hex_bytes(value["ciphertexts"][i], 185, name+" C") for i in range(2)]
    raw = a+proof+b"".join(c)
    assert files.read(name+".bin") == raw
    assert a[:8] == b"KPICU06\0" and a[8:40] == domain
    assert a[345:377] == sha(b"".join(c))
    assert number(a[213:221]) == 40_000_000 and a[205:213] == bytes(8)
    assert a[221:257] == bytes(36)
    cms = [a[140:172], a[172:204]]
    assert ZERO not in cms and cms[0] != cms[1]
    return {"a": a, "raw": raw, "nfs": [a[76:108], a[108:140]], "cms": cms,
            "records": [cms[i]+c[i] for i in range(2)]}


def compare_public_state(value, cms, values, roots):
    assert set(value) == {"commitments", "nullifiers", "roots"}
    assert [hash_array(cm) for cm in value["commitments"]] == cms
    assert [hash_array(root) for root in value["roots"]] == roots
    leaves = []
    for leaf in value["nullifiers"]:
        assert set(leaf) == {"value", "next_index", "next_value"}
        assert type(leaf["next_index"]) is int and 0 <= leaf["next_index"] < 131072
        leaves.append((hash_array(leaf["value"]), leaf["next_index"], hash_array(leaf["next_value"])))
    assert leaves == linked_leaves(values)


def derive_initial(files):
    domain, pool_id, vk, initial_cm = profile_check(files)
    b = {name: bundle(files, name, domain) for name in NAMES}
    profile = files.json("profile.json")
    assert profile["domain"] == domain.hex() and profile["pool_id"] == pool_id.hex()
    assert profile["initial_commitment"] == initial_cm.hex() and profile["vk_sha256"] == sha(vk).hex()
    assert decimal(profile["initial_value_sompi"]) == 800_000_000
    manifest = files.json("initial-proofs-manifest.json")
    assert manifest["proof_count"] == 4 and manifest["owner_drain_proof_count"] == 0
    assert manifest["native_pool_transactions"] == 0 and manifest["owner_lifecycle_complete"] is False
    rows = manifest["proofs"]
    assert [row["label"] for row in rows] == list(NAMES)
    for row, expected_real, amounts in zip(rows, [1, 0, 2, 2], [[400_000_000, 360_000_000],
        [450_000_000, 450_000_000], [400_000_000, 320_000_000], [500_000_000, 360_000_000]]):
        assert row["sha256"] == sha(b[row["label"]]["raw"]).hex()
        assert row["constraints"] == 4_372_824 and row["real_inputs"] == expected_real
        assert [decimal(value) for value in row["output_values_sompi"]] == amounts
    # These are producer assertions, not cryptographic verification by this oracle.
    cms, values = [initial_cm], []
    roots = [cm_tree(cms).root()]
    compare_public_state(files.json("initial-state.json"), cms, values, roots)
    genesis = state(cms, values, roots)
    boot = b["bootstrap"]
    assert boot["a"][204] == 1 and number(boot["a"][40:44]) == 1 and boot["a"][44:76] == roots[0]
    assert number(boot["a"][337:345]) == 800_000_000 and boot["a"][257:337] == bytes(80)
    assert ZERO not in boot["nfs"] and len(set(boot["nfs"])) == 2
    values += boot["nfs"]
    cms += boot["cms"]
    roots.append(cm_tree(cms).root())
    after_boot = state(cms, values, roots)
    admit = b["admit"]
    assert admit["a"][204] == 0 and admit["a"][40:140] == bytes(100)
    assert number(admit["a"][257:265]) == 940_000_000 and admit["a"][337:345] == bytes(8)
    assert admit["a"][301:304] == b"\x00\x00\x20" and admit["a"][336] == 0xac
    cms += admit["cms"]
    roots.append(cm_tree(cms).root())
    compare_public_state(files.json("pre-pair-state.json"), cms, values, roots)
    prior = state(cms, values, roots)
    for name in ("bundle-0", "bundle-1"):
        a = b[name]["a"]
        assert a[204] == 1 and number(a[40:44]) == 5 and a[44:76] == roots[-1]
        assert a[257:345] == bytes(88)
    actual_nfs = b["bundle-0"]["nfs"]+b["bundle-1"]["nfs"]
    actual_records = b["bundle-0"]["records"]+b["bundle-1"]["records"]
    assert ZERO not in actual_nfs and len(set(actual_nfs)) == 4 and set(actual_nfs).isdisjoint(values)
    ordered_nfs = sorted(enumerate(actual_nfs), key=lambda item: (item[1], item[0]))
    ordered_records = sorted(enumerate(actual_records), key=lambda item: (item[1], item[0]))
    p_nf, p_record = [None]*4, [None]*4
    for i, (original, _) in enumerate(ordered_nfs):
        p_nf[original] = i
    for i, (original, _) in enumerate(ordered_records):
        p_record[original] = i
    public_nfs = [value for _, value in ordered_nfs]
    records = [value for _, value in ordered_records]
    p = b"KPI2V6P1\x01\x00\x02\x00"+domain+sha(vk)+PAIR_FEE.to_bytes(16, "little")+b"".join(public_nfs)+b"".join(records)
    pair = p+b["bundle-0"]["raw"]+b["bundle-1"]["raw"]+bytes(p_nf)+bytes(p_record)
    assert len(p) == 1088 and len(pair) == 2846
    anchor_path = history_tree(roots).path(2)
    assert fold(hist_leaf(5, roots[-1]), 2, anchor_path) == prior[73:105]
    nf_wires, nf_steps = [], []
    for value in public_nfs:
        wire, values, step = insertion_witness(values, value)
        nf_wires.append(wire)
        nf_steps.append(step)
    cm_paths, cm_steps, prefix_roots = [], [], []
    for i, record in enumerate(records):
        tree = cm_tree(cms)
        path = tree.path(len(cms))
        assert fold(ZERO, len(cms), path) == tree.root()
        cms.append(record[:32])
        assert fold(cm_leaf(record[:32]), len(cms)-1, path) == cm_tree(cms).root()
        cm_paths.append(b"".join(path))
        cm_steps.append({"position": len(cms)-1, "original_bundle_slot": ordered_records[i][0],
                         "record_sha256": sha(record).hex(), "root": cm_tree(cms).root().hex()})
        if i in (1, 3):
            prefix_roots.append((len(cms), cm_tree(cms).root()))
    history_paths = []
    for count, root in prefix_roots:
        tree = history_tree(roots)
        path = tree.path(len(roots))
        assert fold(ZERO, len(roots), path) == tree.root()
        roots.append(root)
        assert fold(hist_leaf(count, root), len(roots)-1, path) == history_tree(roots).root()
        history_paths.append(b"".join(path))
    successor = state(cms, values, roots)
    prefix7 = history_tree(roots).path(3)
    assert fold(hist_leaf(7, prefix_roots[0][1]), 3, prefix7) == successor[73:105]
    files_out = {"expected-public.bin": p, "expected-pair-input.bin": pair, "expected-genesis-state.bin": genesis,
                 "expected-post-bootstrap-state.bin": after_boot, "expected-prior-state.bin": prior,
                 "expected-next-state.bin": successor}
    report = {"domain": domain.hex(), "pool_id": pool_id.hex(), "vk_sha256": sha(vk).hex(),
              "prior_state": prior.hex(), "next_state": successor.hex(), "nf_permutation": p_nf,
              "record_permutation": p_record, "nf_steps": nf_steps, "cm_steps": cm_steps,
              "history_prefixes": [{"count": count, "root": root.hex()} for count, root in prefix_roots],
              "historical_count7_membership_checked": True, "count7_standalone_native_state": False,
              "rawlex_nf_order_differs_from_numeric": public_nfs != sorted(public_nfs, key=number),
              "producer_real_input_assertions": [1, 0, 2, 2], "oracle_verified_private_openings": False,
              "oracle_verified_groth16": False, "native_or_ledger_validation": False,
              "owner_workflow_parked": True, "full_lifecycle_claim": False}
    math = {"pair": pair, "prior": prior, "next": successor, "pool": pool_id,
            "tail": b"".join(anchor_path)+b"".join(nf_wires)+b"".join(cm_paths)+b"".join(history_paths)}
    return files_out, report, math


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--profile-only", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--pair-context", type=Path, help="PUBLIC tuple only: prior_outpoint_hex36, reserve_sompi; never a ledger")
    args = parser.parse_args()
    self_checks()
    if args.self_check:
        assert not args.public_dir and not args.pair_context
        print(json.dumps({"math_self_checks": True, "new_proofs_setup_native_wallet_or_ledger_work": False}))
        return
    assert args.public_dir and args.output
    files = PublicFiles(args.public_dir)
    if args.profile_only:
        assert args.pair_context is None
        domain, pool_id, vk, initial = profile_check(files)
        outputs = {}
        report = {"domain": domain.hex(), "pool_id": pool_id.hex(), "vk_sha256": sha(vk).hex(),
                  "vk_bytes": len(vk), "initial_commitment": initial.hex(), "key_curve_validation": False,
                  "scope": "PUBLIC identity/hash/length check only; canonical subgroup checks belong to independent host preflight"}
    else:
        outputs, report, math = derive_initial(files)
        if args.pair_context:
            raw_context = args.pair_context.read_bytes()
            context = json.loads(raw_context)
            assert set(context) == {"prior_outpoint_hex", "reserve_sompi"}
            outpoint = hex_bytes(context["prior_outpoint_hex"], 36, "public outpoint tuple")
            reserve = decimal(context["reserve_sompi"])
            assert reserve == 1_660_000_000 and reserve <= MAX
            remaining = reserve-PAIR_FEE
            journal = b"KPI2V6S1\x01\x00"+sha(math["pair"][:1088])+math["pool"]+outpoint+math["prior"]+math["next"]+u64(reserve)+u64(remaining)
            guest = math["pair"]+outpoint+math["prior"]+u64(reserve)+math["tail"]
            assert len(journal) == 336 and len(guest) == 11219
            outputs.update({"expected-journal.bin": journal, "expected-state-input.bin": guest})
            report["supplied_public_pair_context"] = {"sha256": sha(raw_context).hex(), "prior_outpoint": outpoint.hex(),
                                                      "reserve_sompi": str(reserve), "remaining_sompi": str(remaining),
                                                      "native_context_authenticated_by_oracle": False}
    report["opened_public_files"] = files.opened
    report["oracle_source_sha256"] = sha(Path(__file__).read_bytes()).hex()
    report["outputs"] = {name: {"bytes": len(raw), "sha256": sha(raw).hex()} for name, raw in outputs.items()}
    outputs["oracle-result.json"] = document(report)
    args.output.mkdir(parents=True, exist_ok=False)
    for name, raw in outputs.items():
        with (args.output/name).open("xb") as stream:
            stream.write(raw)
    print(json.dumps({"result_sha256": sha(outputs["oracle-result.json"]).hex(), "outputs": report["outputs"]}, indent=2))


if __name__ == "__main__":
    main()
