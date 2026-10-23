# Constructive SAT search and independent scoring review

**ACK for another root-released PUBLIC development probe, not heldout work.**
Both original fixed public development fixtures reached baseline UNKNOWN at
120 seconds; that failure is retained, not privacy evidence. No hidden corpus
had been generated. Source-only review by the main reviewer and a fresh
countermodel reviewer found no mathematical counterexample to the declared
terminal lemmas, symmetry lifting, UNKNOWN or NONE rules. No jobs, hidden data,
PKs, backups, native/proof runtime or network were used by the reviewers.

Reviewed 2026-10-23 UTC snapshot:

| File | SHA256 |
| --- | --- |
| `construct.py` | `150a6a232658ca8f33f1690a7bd75876043b206ba4d50939dc307a702f5cede4` |
| `model.py` | `e80fd8e3a1ed9ad1703bab6bf78bf3a80cbc3a9730941ed2e29e46707b368b07` |
| `score.py` | `397efd15b686f31bf294f2d0ba9986269565e9adb8d17e6222f4704818dfb301` |
| `run.py` | `e1e917737600104fb1ae18fcda143e2a4c248659c309c8a1898347d5b529fde1` |

The new search uses only public ledger facts and deterministic public two-chain/
wide templates to propose full integer assignments. Its exact cardinality subset
DP uses public payout-plus-fee values and ingress totals. This intentionally
restricted template is incomplete for the original arithmetic model. Failure,
unsupported topology or exhausted search returns None and falls back to the
same exact SMT/UNKNOWN path; it never establishes UNSAT or forcedness. It does
not constrain ownership, original lineage or solver worlds to its template.

Every successful assignment passes the existing independent, sequential,
unsimplified certificate checker. The Model adapter also checks the exact typed
requested predicate: baseline, selected input, original source, alternative Note
value, alternative native input value or no direct native use. Reusing a globally
valid certificate that fails the requested query is rejected. All UNSAT results
remain solver results. SAT remains arithmetic possibility under the declared
one-real/full-native policy, not cryptographic realizability or probability.

The independent reviewer found a resource bug before the next probe: shifting a
DP bitset by a legal weight far above target could allocate an enormous integer
before masking, despite the reduced target bound. The implementation now skips
weights above target (nonnegative and impossible in a solution) and still records
each unchanged history row, preserving exact indexing/backtracking. It keeps
explicit target/history search bounds, which return None rather than UNSAT.

The independent reviewer also found that the scorer trusted COMPLETE without
checking exhaustive query tables. A malformed source row containing SAT and
UNKNOWN could therefore have been counted as forced, although the frozen
observer did not emit that combination. The corrected scorer requires exact,
unique event/Note/guess/input/source/outgoing candidate sets, SAT/UNSAT-only
statuses, consistent projected rows and recomputed forced summaries. Existing
content-addressed original SAT certificate and query-target checks remain.
Public malformed-prediction controls are required before the heldout freeze.

The runner now flushes/fsyncs every prediction and fsyncs its prediction directory
before sealing the fsynced global96-prediction barrier; all scoring remains after
that barrier. This closes the earlier durability wording gap. Final source/plan/
dependency manifest and public controls/probe outcomes still need binding before
any heldout seed draw. This development ACK does not grant that release or erase
the retained old amount-prior qualification failure.
