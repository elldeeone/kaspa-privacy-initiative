# Selected real/dummy HMAC synthesis

**First frozen full synthesis passed:** 3,199,529 constraints, 3,164,457
witness variables, three instance variables including one, satisfied=true.
The FFT domain remains2^22. This removes298,364 constraints (8.53%) from the
closed Ch/Maj candidate and1,451,004 (31.20%) from the original4,650,533.

The implementation computes one exact selected HMAC per input. Its standard
IV, three-block padded inner message, differing real/dummy marker and length,
outer HMAC, Boolean selector and all ownership/value/canonical constraints
were independently source-reviewed. The retained cheap-test build passes14
checks, including reference HMAC/padding/selector negatives and inherited
Boolean/SHA checks. Full synthesis takes30.516s at2CPU,876,348KiB RSS,swap0.

The server restart occurred after completion. RESULT.json and recovered
cleanup were derived from the retained byte-identical run log and current
inactive/dead/PID0 unit; no synthesis was repeated. The original snapshots,
source ACKs, plan, freeze, start record and log remain unchanged.

No setup/key/proof/native check or active-trial change belongs to this sizing
packet. The original17 full-transfer R1CS negative controls have not run on
this candidate. A separate fresh-key genuine proof is required for resource
measurement; no cryptographic correctness, security, p95 or adoption claim
follows from SAT or source equivalence checks.
