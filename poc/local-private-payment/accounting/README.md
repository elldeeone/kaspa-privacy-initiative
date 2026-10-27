# Independent public final accounting

Run `final.py` only after the actual final `HANDOFF.json` confirms all fifteen
private actions and nine native payouts. It accepts only externally pinned
public handoffs, the frozen runtime source closure, the separately pinned
`--checker-selection`/`--checker-selection-sha256` for this new checker, and
retained Full pages. Both source closures are recorded in the result.

The extractor independently finds the three accepted ordinary consolidation
transactions in those pages, including their full witnesses, budgets and
populated coinbase contexts. The checker re-executes native Full on these three
cases and all sixteen pool cases, validates genuine genesis outputs, verifies
the complete public proof/history chain, and derives native fees from integer
inputs minus outputs.

It requires six payments followed by nine direct Exit152 actions, unique action
IDs and original NFs, CM15/NF16, zero terminal reserve, and nine exact observed
payout outpoints/amounts/scripts. The pool equation is:

`60 KAS = private-payment fees + direct-exit fees + nine native payouts`.

All-in fees equal the final accepted pool prefix fees (including the 676,100-sompi
GEN3 fee once) plus the 3,762,200-sompi ordinary consolidation fees once. The
21-KAS denominator remains the frozen owner-directed workload; public accounting
does not decrypt or independently prove confidential transfer amounts. It does
not establish original-seed/download provenance, off-host cold recovery,
independent consensus, general privacy, or cryptographic correctness.

The structural unit tests deliberately accept no cryptographic or native claim.
The preparation fixture extracts actual ordinary+GEN3 bodies only and cannot
produce a terminal trial pass.
