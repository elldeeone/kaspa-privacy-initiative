#!/usr/bin/env python3
"""Freeze parameter-independent arithmetic cases for the initial-four-proof test.

This has no wallet, ledger parser/replayer, proving, native execution or network.
The two planned exit rows are arithmetic only; their workflow is parked and no
completion is claimed. Actual VK/image/outpoint-dependent bytes are a later stage.
"""
import argparse
import hashlib
import json
from pathlib import Path

M = 1_000_000


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rows = [
        {"id": "founding", "cm_count": 1, "nf_count": 0, "reserve": 800*M,
         "private_liability": 800*M, "admitted": 0, "paid": 0, "pool_fee": 0,
         "positive_notes": {"alice-initial": 800*M}, "status": "initial-ordinary-UTXO assumption; bootstrap pending"},
        {"id": "bootstrap", "cm_count": 3, "nf_count": 2, "reserve": 760*M,
         "private_liability": 760*M, "admitted": 0, "paid": 0, "pool_fee": 40*M,
         "positive_notes": {"alice-bootstrap-0": 400*M, "alice-bootstrap-1": 360*M}, "status": "initial-four-proof target only"},
        {"id": "admit", "cm_count": 5, "nf_count": 2, "reserve": 1660*M,
         "private_liability": 1660*M, "admitted": 940*M, "paid": 0, "pool_fee": 40*M,
         "positive_notes": {"alice-bootstrap-0": 400*M, "alice-bootstrap-1": 360*M,
                            "bob-admit-0": 450*M, "bob-admit-1": 450*M}, "status": "initial-four-proof target only"},
        {"id": "paired-assertion", "cm_count": 9, "nf_count": 6, "reserve": 1580*M,
         "private_liability": 1580*M, "admitted": 0, "paid": 0, "pool_fee": 80*M,
         "positive_notes": {"pair-0-bob": 400*M, "pair-0-alice": 320*M,
                            "pair-1-alice": 500*M, "pair-1-bob": 360*M}, "status": "initial-four-proof/math target only"},
        {"id": "planned-alice-exit-arithmetic", "cm_count": 9, "nf_count": 8, "reserve": 760*M,
         "private_liability": 760*M, "admitted": 0, "paid": 780*M, "pool_fee": 40*M,
         "positive_notes": {"pair-0-bob": 400*M, "pair-1-bob": 360*M}, "status": "ARITHMETIC ONLY; owner workflow parked"},
        {"id": "planned-bob-terminal-arithmetic", "cm_count": 9, "nf_count": 10, "reserve": 0,
         "private_liability": 0, "admitted": 0, "paid": 720*M, "pool_fee": 40*M,
         "positive_notes": {}, "status": "ARITHMETIC ONLY; owner workflow parked"},
    ]
    prior_reserve = rows[0]["reserve"]
    for row in rows:
        assert row["private_liability"] == sum(row["positive_notes"].values()) == row["reserve"]
        assert row["cm_count"] % 2 == 1 and row["nf_count"] % 2 == 0
        assert row["nf_count"] <= 2*row["cm_count"]
        if row is not rows[0]:
            assert prior_reserve + row["admitted"] - row["paid"] - row["pool_fee"] == row["reserve"]
        prior_reserve = row["reserve"]
    assert 800*M + sum(row["admitted"] for row in rows) == 1740*M
    assert sum(row["paid"] for row in rows) == 1500*M
    assert sum(row["pool_fee"] for row in rows) == 240*M
    assert 1740*M == 1500*M + 240*M
    # Public toy values, not keys, actual fixture NFs, privacy seeds or proofs.
    one, two_fifty_six = (1).to_bytes(32, "little"), (256).to_bytes(32, "little")
    raw = sorted([one, two_fifty_six])
    numeric = sorted([one, two_fifty_six], key=lambda value: int.from_bytes(value, "little"))
    assert raw != numeric
    repeated = [(b"a"*217, 0), (b"a"*217, 1), (b"b"*217, 2), (b"c"*217, 3)]
    positions = [(5+i, original) for i, (_, original) in enumerate(sorted(repeated))]
    assert len(positions) == 4 and positions[:2] == [(5, 0), (6, 1)]
    cases = [
        {"id": "exact-pool-equation", "expected": "1740000000=1500000000+240000000"},
        {"id": "initial-four-proof-counts", "expected": [[1, 0], [3, 2], [5, 2], [9, 6]]},
        {"id": "planned-exit-counts-arithmetic-only", "expected": [[9, 8], [9, 10]], "workflow": "parked"},
        {"id": "pair-two-real-note-value-sums", "expected": [[760*M, 720*M, 40*M], [900*M, 860*M, 40*M]]},
        {"id": "pair-record-global-positions", "expected": [5, 6, 7, 8], "assignment": "stable complete-record raw-byte order, never hidden group order"},
        {"id": "history-prefix-counts", "expected": [1, 3, 5, 7, 9], "indexes": [0, 1, 2, 3, 4]},
        {"id": "count7-is-prefix-only", "expected": "history_leaf(7, root_after_two) at index3 under final history; no standalone UTXO"},
        {"id": "rawlex-versus-LE-numeric", "expected_raw": [value.hex() for value in raw], "expected_numeric": [value.hex() for value in numeric]},
        {"id": "duplicate-complete-records", "expected_positions_and_occurrences": positions, "cryptographic_fixture": False},
        {"id": "wrong-pair-fee-40M", "expected": "reject scalar reserve/accounting mismatch; actual aggregate target is80M"},
        {"id": "wrong-admit-fee-39M", "expected": "reject scalar reserve/accounting mismatch; target is1660M"},
        {"id": "missing-count7-history-leaf", "expected": "reject implicit odd-prefix length/count relation"},
        {"id": "deduplicated-record-list", "expected": "reject four-record multiplicity/count equation"},
        {"id": "repeated-pair-NF", "expected": "reject four-distinct-nonzero active NF relation"},
    ]
    plan = {"format": "s7-initial-four-public-math-plan-v1", "public_case_label": "KPI/S7/INITIAL4/MATH-ORACLE/2026-10-22/v1",
            "scope": "Independent finite arithmetic and named public initial-four-proof fixture/root/P/J checks only.",
            "excluded": ["public ledger parser or replayer", "owner CLI", "DRAIN proving or withdrawal workflow",
                         "wallet/opening/trapdoor/private input files", "Gate/Rust import", "native execution", "new proofs or setup"],
            "do_not_fund": True, "owner_workflow_parked": True, "full_lifecycle_claim": False,
            "source_baseline": "ec6aa15d586bcc8a90f7232b433fd48d8c73d509",
            "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "before_setup": "Freeze this plan and parameter-independent vectors. VK/image/native outpoint-dependent bytes cannot yet be frozen.",
            "later_stage": "Independently derive exact public roots/P/J/input after fresh public VK/profile and explicit native pair-context tuple exist, before the corresponding paired proof.",
            "stop_rule": "Keep every mismatch, collision and unavailable artifact explicit; do not retune seeds/cases or manufacture completion.",
            "cases": cases}
    vectors = {"format": "s7-parameter-independent-accounting-v1", "integer_unit": "sompi", "rows": rows,
               "pool_inputs": 1740*M, "planned_payouts_arithmetic_only": 1500*M, "pool_fees": 240*M,
               "founding_ordinary_fees": "additional; not included in pool equation", "initial_inner_proofs": 4,
               "future_owner_proofs": "parked; not generated or implemented", "history_prefix_counts": [1, 3, 5, 7, 9]}
    files = {"parameter-independent-plan.json": encoded(plan), "parameter-independent-vectors.json": encoded(vectors)}
    if not args.check:
        args.output.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        if args.check:
            assert (args.output/name).read_bytes() == content, name
        else:
            with (args.output/name).open("xb") as stream:
                stream.write(content)
    print(json.dumps({"checked_only": args.check, "cases": len(cases), "files": {
        name: {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()} for name, content in files.items()}}, indent=2))


if __name__ == "__main__":
    main()
