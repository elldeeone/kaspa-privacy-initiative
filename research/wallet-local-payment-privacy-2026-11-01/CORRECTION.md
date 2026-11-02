# Correction to the first wallet-local privacy assessment

**Date:** 2026-11-01

The first version of `analyze.py` did not measure candidate sets. It decoded real
public artifacts, but then inserted the expected Alice/Bob/400,000,000-sompi
assignment and candidate counts as constants. The candidate table in the first
`ASSESSMENT.md` was therefore a case reconstruction from already-known truth,
not a blinded observer result and not a general privacy measurement.

This does not make the published role labels, deterministic source order,
singleton history, public exit amount, timing or operator-custody declaration
disappear. It means their combined attribution must be reproduced by an attack
program that consumes admitted observer evidence, seals predictions, and only
then receives separately held truth.

The correction is:

1. preserve the original `SELECTION.md`, evidence and note;
2. replace hard-coded candidate output with evidence-derived enumeration;
3. require a leaking-baseline control to recover the known published case;
4. run a separately frozen fresh experiment with owner-local truth and sealed
   predictions before scoring;
5. report exact remaining limitations without treating ideal cryptographic
   opacity as an empirical cryptographic result.

No prior candidate count should be cited as a measured general privacy result.

