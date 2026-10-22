# Pre-Rust source-discovered expectation erratum

Recorded2026-10-22 at13:31:43UTC, before this lane received any Rust corpus
outcomes. The independent source reviewer identified the issue; the corpus
owner and core engineer agreed before differential execution.

Frozen plan SHA256:
`08183d20e6c15fa4591ebd903d5e133d4e3afaf5fa035e465f6f2d956deefe96`.
Frozen corpus manifest SHA256:
`19fc246c682a9545da41bec205535a6c76b6207dd05fdbf98ccf2fe1c9a74e6f`.
Neither file, generator source nor input bytes are changed by this erratum.

The semantic negative `nf-equality-wire` has input SHA256
`69c8e1ca8e2e381d9d8f1cd31cac6b951e1886bf3c39e3a66d14d74914245484`.
Its frozen expected family is `NullifierOrder(0)`. The wire mutation changes
the first witness's predecessor value from ZERO to the target NF, while
leaving the predecessor index at0. The core intentionally checks
`(pred_index == 0) == (value == ZERO)` before comparing numeric ordering.
Consequently source predicts **NullifierLink(0)**, not the frozen family.
The exact reviewed core SHA256 is
`562c6c80cd92b622f3421a1f9798d5ba3e6bddb91c0d8f7d25544eeabc73222f`.

This is an error in the independent generator's expected label, not evidence
of a state-core defect. Execute and retain the original case, original
expectation and actual result; report the mismatch explicitly. Do not prune
the case, relabel the frozen plan, tune source, or count a resource/decoding
failure as a semantic rejection.

The distinct `nf-authenticated-replay` input rebuilds the current tree with the
actual first P nullifier already present, uses that leaf's nonzero physical
index, and authenticates its correct predecessor path against the declared
root. It passes the sentinel equivalence rule and is independently expected
to fail strict equality as `NullifierOrder(0)`. Its SHA256 is
`0b8a4cb2adc1301eb176f48773c0db27a8c68bcdb345c316e5e24c04468345ca`.
