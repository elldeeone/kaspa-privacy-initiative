# C-only actual-chain disclosure observer

The selected known-pilot run reconstructs public Note168 commitments and
positioned original nullifiers, then links the two private output positions to
their revealing native payouts. It does not load private records, verify
consensus/proofs, infer people or qualify privacy. The prospective contract,
cancelled zero-run first freeze, corrected freeze and one result are under
[`research/next-session/privacy-recovery/observer`](../../research/next-session/privacy-recovery/observer/RESULTS.md).

`export_pilot.py` exports only canonical public chain bodies, public populated
input contexts and headers under ordinal names. Source filename provenance is
kept in a separate map which is not mounted in the evaluator. `pilot_observer.py`
consumes the resulting public-chain.json and requires a fresh output path.

Cheap controls: `python3 -B -m unittest -v test_pilot_observer` from this directory.
All unit inputs are synthetic shape controls with placeholder native/proof data;
they make no native acceptance claim. The selected actual evaluation has already
run once; do not rerun it as qualification or quietly replace its result.
