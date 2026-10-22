#!/usr/bin/env python3
"""Finite prepared-public-state math only, before the fresh verification key."""
import argparse
import json
from pathlib import Path

import initial_four_public_oracle as oracle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    files = oracle.PublicFiles(args.public_dir)
    constants = files.json("constants.json")
    manifest = files.json("prepare-manifest.json")
    domain = oracle.sha(oracle.LABEL+b"domain")
    pool = oracle.sha(oracle.LABEL+b"pool-id")
    assert constants["domain"] == domain.hex() and constants["pool_id"] == pool.hex()
    assert constants["owner_workflow_implemented"] is False
    assert constants["chain_acceptance_verified"] is False
    initial_cm = oracle.hex_bytes(constants["initial_commitment"], 32, "initial CM")
    for key, value in {"initial_value_sompi": 800_000_000, "admit_sompi": 940_000_000,
                       "pre_pair_reserve_sompi": 1_660_000_000, "post_pair_reserve_sompi": 1_580_000_000,
                       "aggregate_pair_fee_sompi": 80_000_000, "pool_fees_through_pair_sompi": 160_000_000}.items():
        assert oracle.decimal(constants[key]) == value, key
    expected_rows = [
        {"label": "bootstrap", "inputs": ["Alice800000000"], "outputs": ["Alice400000000", "Alice360000000"], "fee": "40000000"},
        {"label": "admit", "deposit": "940000000", "outputs": ["Bob450000000", "Bob450000000"], "fee": "40000000"},
        {"label": "bundle-0", "inputs": ["Alice400000000", "Alice360000000"], "outputs": ["Bob400000000", "Alice320000000"], "fee": "40000000"},
        {"label": "bundle-1", "inputs": ["Bob450000000", "Bob450000000"], "outputs": ["Alice500000000", "Bob360000000"], "fee": "40000000"},
    ]
    assert manifest["ownership"] == expected_rows
    assert manifest["statements"] == 4 and manifest["owner_proofs"] == 0 and manifest["native_pool_transactions"] == 0
    equations = [(800_000_000, 400_000_000+360_000_000+40_000_000),
                 (940_000_000, 450_000_000+450_000_000+40_000_000),
                 (760_000_000, 400_000_000+320_000_000+40_000_000),
                 (900_000_000, 500_000_000+360_000_000+40_000_000)]
    assert all(left == right for left, right in equations)
    genesis_public = files.json("initial-state.json")
    genesis_roots = [oracle.cm_tree([initial_cm]).root()]
    oracle.compare_public_state(genesis_public, [initial_cm], [], genesis_roots)
    genesis = oracle.state([initial_cm], [], genesis_roots)
    prepared = files.json("pre-pair-state.json")
    cms = [oracle.hash_array(cm) for cm in prepared["commitments"]]
    assert len(cms) == 5 and cms[0] == initial_cm
    values = [oracle.hash_array(leaf["value"]) for leaf in prepared["nullifiers"][1:]]
    assert len(values) == 2
    roots = [oracle.cm_tree(cms[:count]).root() for count in (1, 3, 5)]
    oracle.compare_public_state(prepared, cms, values, roots)
    prior = oracle.state(cms, values, roots)
    outputs = {"expected-genesis-state.bin": genesis, "expected-prior-state.bin": prior}
    report = {"scope": "Declared prepared public-context math only; no key/proof/native/ledger/owner verification",
              "domain": domain.hex(), "pool_id": pool.hex(), "prepared_counts": [5, 2],
              "history_counts": [1, 3, 5], "history_commitment_roots": [root.hex() for root in roots],
              "four_scalar_conservation_equalities": equations,
              "opened_public_files": files.opened,
              "source_sha256": oracle.sha(Path(__file__).read_bytes()).hex(),
              "tree_oracle_source_sha256": oracle.sha(Path(oracle.__file__).read_bytes()).hex(),
              "outputs": {name: {"bytes": len(raw), "sha256": oracle.sha(raw).hex()} for name, raw in outputs.items()},
              "verification_key_checked": False, "groth16_verified": False,
              "native_or_ledger_validation": False, "accepted_lineage_or_backing": False,
              "owner_workflow_parked": True, "full_lifecycle_claim": False}
    outputs["report.json"] = oracle.document(report)
    args.output.mkdir(parents=True, exist_ok=False)
    for name, raw in outputs.items():
        with (args.output/name).open("xb") as stream:
            stream.write(raw)
    print(json.dumps({"report_sha256": oracle.sha(outputs["report.json"]).hex(), "outputs": report["outputs"]}, indent=2))


if __name__ == "__main__":
    main()
