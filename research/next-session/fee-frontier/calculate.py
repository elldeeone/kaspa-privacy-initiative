#!/usr/bin/env python3
"""Source-pinned necessary fees; no transactions, proving, wallet or RPC."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
from fractions import Fraction

REV = "01b532e8b553523216471682649693af92f0fd16"
parser = argparse.ArgumentParser()
parser.add_argument("native_source", type=pathlib.Path)
parser.add_argument("output", type=pathlib.Path)
args = parser.parse_args()
assert subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=args.native_source, text=True
).strip() == REV
paths = [
    "crypto/txscript/src/zk_precompiles/tags.rs",
    "crypto/txscript/src/zk_precompiles/groth16/mod.rs",
    "consensus/core/src/mass/units.rs",
]
data = {p: (args.native_source / p).read_bytes() for p in paths}
for p, contents in data.items():
    assert contents == subprocess.check_output(
        ["git", "show", f"{REV}:{p}"], cwd=args.native_source
    ), f"source differs from selected commit: {p}"
tags, groth, units = [data[p].decode() for p in paths]
m = re.search(r"ZkTag::Groth16\s*=>\s*Gram\((\d+)\s*\*\s*(\d+)\)", tags)
base_grams = int(m[1]) * int(m[2])
per_ic = int(re.search(
    r"GROTH16_GAMMA_ABC_G1_ELEMENT_SCRIPT_UNITS: u64 = ([\d_]+)", groth
)[1].replace("_", ""))
assert "public_input_count as u64 + 1 != gamma_abc_element_count" in groth
assert "meter.consume_script_units(gamma_abc_cost)" in groth
assert "GRAMS_PER_COMPUTE_BUDGET_UNIT: u64 = 100;" in units
assert "SCRIPT_UNITS_PER_GRAM: u64 = 100;" in units
assert "SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT.saturating_sub(1)" in units
used = base_grams * 100 + 3 * per_ic
budget = (used - 9_999 + 9_999) // 10_000
mass = budget * 100
assert (used, budget, mass) == (14_750_000, 1475, 147_500)
rows = []
for rate in (100, 200, 500):
    fee = mass * rate
    for amount in (1_000_000_000, 10_000_000_000, 100_000_000_000):
        rows.append({
            "rate_sompi_per_mass": rate,
            "principal_sompi": amount,
            "single_verifier_necessary_fee_sompi": fee,
            "single_verifier_ordinary_one_percent_necessary_gate": 100 * fee <= amount,
            "two_verifier_lifecycle_necessary_fee_sompi": 2 * fee,
            "two_verifier_lifecycle_two_percent_necessary_gate": 100 * (2 * fee) <= 2 * amount,
            "two_verifier_fee_principal_ratio": str(Fraction(2 * fee, amount)),
        })
result = {
    "format": "kpi-conditional-fee-frontier-v1",
    "native_revision": REV,
    "kind": "source-derived necessary lower bounds; no observed transaction quote",
    "source": [{"path": p, "sha256": hashlib.sha256(b).hexdigest()} for p, b in data.items()],
    "two_public_input_verifier": {"script_units": used, "necessary_budget": budget, "necessary_mass": mass},
    "rows": rows,
    "reference_two_verifier_minimum_principal_for_two_percent_sompi": 50 * (2 * mass * 100),
    "singleton_500": {
        "claim_sompi": 60_000_000,
        "payout_floor_sompi": 10_000_000,
        "maximum_exit_fee_sompi": 50_000_000,
        "necessary_verification_fee_sompi": mass * 500,
        "necessary_gate": mass * 500 <= 50_000_000,
    },
    "limits": [
        "Two-verifier lifecycle assumes one attributable unamortized ADMIT and one fresh direct exit proof.",
        "Exclude receiver-only histories and legitimately shared/amortized admission from that bound.",
        "No alternative architecture impossibility, measured gas quote, proof validity, privacy or acceptance claim.",
        "Transaction overhead, private payment, service costs and retries are omitted lower-bound costs, never free actual costs.",
    ],
}
with args.output.open("x") as f:
    json.dump(result, f, indent=2)
    f.write("\n")
print(json.dumps({"verification_mass_floor": mass, "reference_two_verifier_fee": 2 * mass * 100,
                  "reference_two_percent_minimum_principal": result["reference_two_verifier_minimum_principal_for_two_percent_sompi"]}))
