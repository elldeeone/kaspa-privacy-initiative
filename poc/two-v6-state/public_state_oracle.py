#!/usr/bin/env python3
"""Independent stdlib-only public oracle for a NONFUNDABLE state assertion.

Reuses frozen public bundle bytes. Does not verify Groth16, construct a native
transaction, reconstruct an accepted predecessor, or handle proving material.
Tree/hash encodings are independently transcribed from ec6aa15 two_input/tree.rs
and compact/tree.rs. New S7/input/J336 framing is agreed with the state-core
owner, not an encoding accepted by the existing v6 covenant.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "artifacts/public-v6-fixture-production-20261022T124051Z/public"
ZERO = bytes(32)
POOL_LABEL = b"KPI/public-two-v6-state/DO-NOT-FUND/v1"
MAX_SOMPI = 2_900_000_000_000_000_000
PAIR_SHA = "7771a2e610d37fdb12b1d668b8e229bd3cd1e5fe83c5993847daa0fef8c93b36"
P_SHA = "9ac720aa55e7bd6eaec674788d418aa3314bc7af1010b7c9f09a493d9aa76ce9"
BUNDLE_SHAS = [
    "3f8f0a13f4ce7a73b61fd093c5aad01fc2cb2ea0ca3db65ed4f0d44de72019a9",
    "1cc3094a335dfa94897929fde258d05da2a3270314738919b972838e61e2d7b8",
]
VK_SHA = "2a9acd1639fb7b454384c65fb317a139695f5a2cbb3ebd941dd13b5f6045a2f4"
SOURCES = {
    "poc/shared-pool/src/two_input/tree.rs": "9fc004721ae2a22c6faa26f2a046eefd7bb707e3c83077be01a7913b464891ed",
    "poc/shared-pool/src/compact/tree.rs": "4ac46cb3e514e58181d0a4e2195e882f22d1df83d8dc6ea926fac47102ea0dc6",
}


def sha(raw):
    return hashlib.sha256(raw).digest()


def u32(value):
    return struct.pack("<I", value)


def u64(value):
    return struct.pack("<Q", value)


def node(left, right):
    return sha(b"\x01" + left + right)


def cm_leaf(cm):
    return sha(b"\x00" + cm)


def history_leaf(count, root):
    return sha(b"\x03" + u32(count) + root)


def leaf_bytes(leaf):
    value, next_index, next_value = leaf
    return value + u32(next_index) + next_value


def nf_leaf(leaf):
    return sha(b"\x02" + leaf_bytes(leaf))


def little_number(raw):
    return int.from_bytes(raw, "little")


class PublicTree:
    """Bottom-up sparse levels, with raw-zero absent leaves, not H(tag||0)."""

    def __init__(self, leaves, depth):
        assert depth in (16, 17) and len(leaves) <= 1 << depth
        self.depth = depth
        self.empty = [ZERO]
        for _ in range(depth):
            self.empty.append(node(self.empty[-1], self.empty[-1]))
        self.levels = [list(leaves)]
        for level in range(depth):
            previous = self.levels[-1]
            self.levels.append([
                node(previous[i], previous[i + 1] if i + 1 < len(previous) else self.empty[level])
                for i in range(0, len(previous), 2)
            ])

    def root(self):
        return self.levels[-1][0] if self.levels[-1] else self.empty[self.depth]

    def path(self, index):
        assert 0 <= index < 1 << self.depth
        return [
            self.levels[level][sibling] if sibling < len(self.levels[level]) else self.empty[level]
            for level in range(self.depth)
            for sibling in [(index >> level) ^ 1]
        ]


def fold_path(leaf, index, siblings):
    assert 0 <= index < 1 << len(siblings)
    for level, sibling in enumerate(siblings):
        leaf = node(sibling, leaf) if (index >> level) & 1 else node(leaf, sibling)
    return leaf


def cm_tree(cms):
    return PublicTree([cm_leaf(cm) for cm in cms], 16)


def nf_tree(nfs):
    return PublicTree([nf_leaf(leaf) for leaf in nfs], 17)


def history_tree(roots):
    return PublicTree([history_leaf(2 * i + 1, root) for i, root in enumerate(roots)], 16)


def state(cms, nfs, roots):
    n, m = len(cms), len(nfs) - 1
    assert 0 < n < 65536 and n % 2 == 1 and m % 2 == 0 and m <= 2 * n
    assert len(roots) == (n + 1) // 2 and roots[-1] == cm_tree(cms).root()
    return b"\x07" + u32(n) + u32(m) + cm_tree(cms).root() + nf_tree(nfs).root() + history_tree(roots).root()


def insert_nf(nfs, value):
    """Construct paths from full public leaves, independently fold every update."""
    assert value != ZERO and all(leaf[0] != value for leaf in nfs)
    number = little_number(value)
    matches = [i for i, leaf in enumerate(nfs)
               if little_number(leaf[0]) < number
               and (leaf[2] == ZERO or number < little_number(leaf[2]))]
    assert len(matches) == 1
    pred_index = matches[0]
    old = nfs[pred_index]
    append_index = len(nfs)
    assert pred_index < append_index < 131072
    assert (old[1] == 0) if old[2] == ZERO else (1 <= old[1] < append_index)
    before_root = nf_tree(nfs).root()
    pred_path = nf_tree(nfs).path(pred_index)
    assert fold_path(nf_leaf(old), pred_index, pred_path) == before_root
    changed = (old[0], append_index, value)
    nfs[pred_index] = changed
    intermediate = nf_tree(nfs).root()
    assert fold_path(nf_leaf(changed), pred_index, pred_path) == intermediate
    append_path = nf_tree(nfs).path(append_index)
    assert fold_path(ZERO, append_index, append_path) == intermediate
    added = (value, old[1], old[2])
    nfs.append(added)
    after_root = nf_tree(nfs).root()
    assert fold_path(nf_leaf(added), append_index, append_path) == after_root
    wire = u32(pred_index) + leaf_bytes(old) + b"".join(pred_path) + b"".join(append_path)
    assert len(wire) == 1160
    return wire, {
        "value": value.hex(), "pred_index": pred_index, "append_index": append_index,
        "old_leaf": leaf_bytes(old).hex(), "prior_root": before_root.hex(),
        "after_predecessor_root": intermediate.hex(), "after_insert_root": after_root.hex(),
    }


def validate_pair_input(raw):
    assert len(raw) == 2846 and sha(raw).hex() == PAIR_SHA
    p = raw[:1088]
    assert sha(p).hex() == P_SHA and p[:12] == b"KPI2V6P1\x01\x00\x02\x00"
    assert p[44:76].hex() == VK_SHA
    public_nfs = [p[92 + 32 * i:124 + 32 * i] for i in range(4)]
    records = [p[220 + 217 * i:437 + 217 * i] for i in range(4)]
    assert public_nfs == sorted(public_nfs) and len(set(public_nfs)) == 4
    assert records == sorted(records)  # Non-strict: record multiplicity is retained.
    assert all(nf != ZERO for nf in public_nfs)
    original_nfs, original_records, contexts, fees = [], [], [], []
    for index in range(2):
        bundle = raw[1088 + 875 * index:1088 + 875 * (index + 1)]
        assert sha(bundle).hex() == BUNDLE_SHAS[index]
        a, c = bundle[:377], bundle[505:]
        assert a[:8] == b"KPICU06\0" and a[8:40] == p[12:44]
        assert a[204] == 1 and a[205:213] == bytes(8) and a[221:345] == bytes(124)
        assert a[345:377] == sha(c)
        fees.append(little_number(a[213:221]))
        assert 1 <= fees[-1] <= MAX_SOMPI
        contexts.append((little_number(a[40:44]), a[44:76]))
        for slot in range(2):
            original_nfs.append(a[76 + 32 * slot:108 + 32 * slot])
            original_records.append(a[140 + 32 * slot:172 + 32 * slot] + c[185 * slot:185 * (slot + 1)])
    p_nf, p_record = raw[-8:-4], raw[-4:]
    assert sorted(p_nf) == sorted(p_record) == list(range(4))
    for i in range(4):
        assert public_nfs[p_nf[i]] == original_nfs[i]
        assert records[p_record[i]] == original_records[i]
    assert contexts[0] == contexts[1]
    assert sum(fees) == little_number(p[76:92]) == 80_000_000
    assert sorted(public_nfs, key=little_number) != public_nfs
    # Encoding-only multiplicity control, not another accepted proof fixture.
    duplicate_example = [records[0], records[0], records[2], records[3]]
    assert len(sorted(duplicate_example)) == 4 and sorted(duplicate_example).count(records[0]) == 2
    return p, public_nfs, records, contexts[0]


def derive(name, pair, initial_cms, public_nfs, records, anchor_context):
    cms = list(initial_cms)
    if name == "historical-anchor":
        cms += [sha(b"KPI/public-two-v6-state/DO-NOT-FUND/extra-cm/" + bytes([48 + i])) for i in range(2)]
        outpoint = bytes([0x55]) * 32 + u32(2)
    else:
        assert name == "current-anchor"
        outpoint = bytes([0x33]) * 32 + u32(1)
    prior_cms = list(cms)
    roots = [cm_tree(cms[:count]).root() for count in range(1, len(cms) + 1, 2)]
    prior_roots = list(roots)
    nfs = [(ZERO, 0, ZERO)]
    insert_nf(nfs, (1).to_bytes(32, "little"))
    insert_nf(nfs, (2).to_bytes(32, "little"))
    prior_nfs = list(nfs)
    prior = state(cms, nfs, roots)
    anchor_count, anchor = anchor_context
    anchor_index = (anchor_count - 1) // 2
    assert 1 <= anchor_count <= len(cms) and anchor_count % 2 == 1
    assert roots[anchor_index] == anchor
    anchor_path = history_tree(roots).path(anchor_index)
    assert fold_path(history_leaf(anchor_count, anchor), anchor_index, anchor_path) == prior[73:105]
    nf_wires, nf_steps = [], []
    for value in public_nfs:
        wire, step = insert_nf(nfs, value)
        nf_wires.append(wire)
        nf_steps.append(step)
    cm_paths, cm_steps, prefixes = [], [], []
    n = len(cms)
    assert n + 4 < 65536
    for index, record in enumerate(records):
        position = len(cms)
        before = cm_tree(cms)
        path = before.path(position)
        assert fold_path(ZERO, position, path) == before.root()
        cms.append(record[:32])
        after = cm_tree(cms).root()
        assert fold_path(cm_leaf(record[:32]), position, path) == after
        cm_paths.append(b"".join(path))
        cm_steps.append({"position": position, "record_sha256": sha(record).hex(),
                         "commitment": record[:32].hex(), "prior_root": before.root().hex(),
                         "after_append_root": after.hex()})
        if index in (1, 3):
            prefixes.append((len(cms), after))
    history_paths, history_steps = [], []
    for count, root in prefixes:
        index = len(roots)
        before = history_tree(roots)
        path = before.path(index)
        assert fold_path(ZERO, index, path) == before.root()
        roots.append(root)
        after = history_tree(roots).root()
        assert fold_path(history_leaf(count, root), index, path) == after
        history_paths.append(b"".join(path))
        history_steps.append({"index": index, "count": count, "commitment_prefix_root": root.hex(),
                              "prior_history_root": before.root().hex(), "next_history_root": after.hex()})
    successor = state(cms, nfs, roots)
    reserve, fee = 1_700_000_000, little_number(pair[76:92])
    assert 0 < fee < reserve <= MAX_SOMPI
    remaining = reserve - fee
    wire = pair + outpoint + prior + u64(reserve) + b"".join(anchor_path) + b"".join(nf_wires) + b"".join(cm_paths) + b"".join(history_paths)
    journal = b"KPI2V6S1" + struct.pack("<H", 1) + sha(pair[:1088]) + sha(POOL_LABEL) + outpoint + prior + successor + u64(reserve) + u64(remaining)
    assert len(wire) == 11219 and len(journal) == 336
    assert successor[1:5] == u32(n + 4) and successor[5:9] == u32(6)
    metadata = {
        "context": name, "do_not_fund": True, "native_predecessor_authenticated": False,
        "backing_or_genesis_reconstructed": False, "owner_exit_qualified": False,
        "cryptographic_verification_by_oracle": False,
        "scope": "Public synthetic state-path and journal oracle only; unchanged inner proofs must be independently verified by the state core.",
        "pool_id": sha(POOL_LABEL).hex(), "pool_id_ascii": POOL_LABEL.decode(),
        "prior_outpoint": outpoint.hex(), "prior_state": prior.hex(), "next_state": successor.hex(),
        "prior_cm_count": n, "next_cm_count": n + 4, "prior_nf_count": 2, "next_nf_count": 6,
        "reserve_sompi": str(reserve), "aggregate_fee_sompi": str(fee), "successor_reserve_sompi": str(remaining),
        "anchor_count": anchor_count, "anchor": anchor.hex(), "anchor_history_index": anchor_index,
        "prior_commitments": [cm.hex() for cm in prior_cms],
        "prior_nullifier_leaves": [leaf_bytes(leaf).hex() for leaf in prior_nfs],
        "prior_odd_commitment_prefix_roots": [root.hex() for root in prior_roots],
        "nf_steps": nf_steps, "cm_steps": cm_steps, "history_steps": history_steps,
        "raw_lex_nf_order": [nf.hex() for nf in public_nfs],
        "little_numeric_nf_order": [nf.hex() for nf in sorted(public_nfs, key=little_number)],
        "duplicate_record_control": "Encoding-only multiplicity check passed; no new genuine duplicate-record proof asserted.",
    }
    return {"input.bin": wire, "expected-journal.bin": journal,
            "expected-prior-state.bin": prior, "expected-next-state.bin": successor}, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New public output directory; existing files are never overwritten")
    parser.add_argument("--check", action="store_true", help="Recompute and compare every frozen byte without writing")
    args = parser.parse_args()
    for path, expected in SOURCES.items():
        assert sha((ROOT / path).read_bytes()).hex() == expected, path
    assert sha((PUBLIC / "verification-key.bin").read_bytes()).hex() == VK_SHA
    pair = (PUBLIC / "expected-input.bin").read_bytes()
    p, nfs, records, context = validate_pair_input(pair)
    manifest = json.loads((PUBLIC / "manifest.json").read_text())
    cms = [bytes.fromhex(cm) for cm in manifest["common_membership_context"]["commitments"]]
    assert len(cms) == 3 and cm_tree(cms).root() == context[1]
    files, contexts = {}, []
    for name in ("current-anchor", "historical-anchor"):
        case_files, metadata = derive(name, pair, cms, nfs, records, context)
        metadata["files"] = {file: {"bytes": len(raw), "sha256": sha(raw).hex()} for file, raw in case_files.items()}
        files.update({f"{name}/{file}": raw for file, raw in case_files.items()})
        contexts.append(metadata)
    metadata = {"format": "kpi-public-two-v6-state-independent-oracle-v1", "state_version": 7,
                "source_commit": "ec6aa15d586bcc8a90f7232b433fd48d8c73d509", "source_sha256": SOURCES,
                "oracle_sha256": sha(Path(__file__).read_bytes()).hex(), "pair_input_sha256": PAIR_SHA,
                "public_projection_sha256": P_SHA, "public_bundle_sha256": BUNDLE_SHAS, "vk_sha256": VK_SHA,
                "input_bytes": 11219, "journal_bytes": 336,
                "input_offsets": {"pair": 0, "prior_outpoint": 2846, "prior_state": 2882, "reserve": 2987,
                                  "anchor_path": 2995, "nf_witnesses": 3507, "cm_paths": 8147, "history_paths": 10195},
                "contexts": contexts}
    files["manifest.json"] = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode()
    for name, raw in files.items():
        target = args.output / name
        if args.check:
            assert target.read_bytes() == raw, f"Frozen byte mismatch: {target}"
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(raw)
    print(json.dumps({"checked_only": args.check, "manifest_sha256": sha(files["manifest.json"]).hex(),
                      "contexts": [{"name": case["context"], "files": case["files"]} for case in contexts]}, indent=2))


if __name__ == "__main__":
    main()
