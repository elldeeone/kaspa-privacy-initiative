#!/usr/bin/env python3
"""Exact rational all-values KIP9 envelope, independent of model iteration."""
import hashlib
import json
import os
import pathlib
import resource
from fractions import Fraction

resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
p = pathlib.Path(__file__).with_name("arithmetic-03.json")
raw = p.read_bytes()
assert hashlib.sha256(raw).hexdigest() == "0d38996e7adc7e0ca10acf94a3b24bba8f269780d092ba3e2efe4c57b3af8c59"
data = json.loads(raw)
K, V0 = 10**12, 60_000_000
rows = []
for profile in data["small_claim_all_rates"]:
    for mode in ("terminal", "minimum_other_liability"):
        q = profile[mode]
        f = q["fee_sompi"]
        # For fixedf, continuous K/(V-f)+K/r-K/(V+r) decreases with
        # V>=V0 and r>=V0. floor(a)+floor(b)-floor(c)<=ceil(a+b-c).
        # Thus these rational ceilings cover all positive integer V/r,
        # including floor discontinuities missed by a monotonicity shortcut.
        expr = (Fraction(K, V0 - f) - Fraction(K, V0) if mode == "terminal"
                else Fraction(K, V0 - f) + Fraction(K, V0) - Fraction(K, 2 * V0))
        ceiling = (expr.numerator + expr.denominator - 1) // expr.denominator
        mass = q["metrics"]["normalized_mining_mass"]
        covered = q["passes"] and mass >= ceiling
        rows.append({"redeem_bytes": profile["redeem_bytes"], "rate": profile["rate"],
                     "mode": mode, "declared_context_least_fee_sompi": f,
                     "exact_continuous_upper_fraction": str(expr),
                     "integer_storage_mass_ceiling_for_all_supported_values": ceiling,
                     "charged_mass": mass, "global_storage_covered_at_same_fee": covered,
                     "declared_context_pass": q["passes"]})
        if profile["redeem_bytes"] in (16384, 24576, 32768):
            assert covered
out = pathlib.Path(__file__).with_name("storage-bound.json")
if out.exists():
    raise SystemExit("refusing existing output")
result = {"format": "candidate-C-universal-fee-storage-envelope-v1",
          "input_sha256": hashlib.sha256(raw).hexdigest(),
          "calculator_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
          "assumptions": ["one input,standardp1outputs,no covenantID", "exact completebacking",
                          "V>=60M and remainingreserve0or>=60M", "whole-note fee fromclaim",
                          "same selectedsize/budget as prospectiveprofile"],
          "result": "16/24/32KiB conditionalprofiles cover all supportedamounts/remainders at100/200/500",
          "historical5979_profile_is_not_newunion_or_universal500_qualification": True,
          "rows": rows}
out.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"output": str(out), "bytes": out.stat().st_size,
                  "sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
                  "native_or_proving_executed": False}))
