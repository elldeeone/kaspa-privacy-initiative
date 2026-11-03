# Compose two owner predicates for an offline correspondence experiment

**Status: accepted for offline research implementation, 2026-10-26.**
ADR number is unassigned. Existing repository ADR inventory ended at 0067 when
checked; Root will place/number this decision with the final documentation.
Root authorized this bounded implementation after predicate CPP02 matched all
49 actual R1CS checks. Compiler/build/check execution still needs the separate
source/run selection. This is not a native protocol architecture decision.

The question is whether a minimal aggregate can verify two genuine owner
authorizations while exposing independently ordered NF and complete-tuple
arrays. Independent predicate checks do not establish their aggregate
correspondence. Public owner slots or per-owner digest outputs would preserve
the grouping that a later private construction needs to hide.

Implement the exact two-owner [plan](../TWO-OWNER-AGGREGATE-EXPERIMENT-PLAN-01.md)
`458451f62e00bade1a7207b312ded0081ae05ac526c9c46318d54f6c5ddb2bc1`:
an exact extraction of the existing authority templates, two child predicates,
private Boolean bijections, within-batch NF/CM distinctness and an exact
65-bit sum of two uint64 fees. Reuse the original public handoff/signatures;
keep all 35 child outputs internal. No new secret, cryptographic primitive,
package family, setup, proving key, Groth16 proof or MPC is selected.

The selected fixture and its constructor know the full map; tuple bytes even
encode owner/slot information. This decision supports mechanical relation and
projection checks only. Its 2,091 debug public fields are not a native proof
ABI. CV equations, ciphertext/output-proof validity, native state/effects,
historical replay handling, recipient/change recovery and private proving
remain absent. Identical eligible-state replay is expected to accept.

Consequently current native 1NF→2CM grouping, active-retry failures, availability
and fee limits remain unchanged. Before adopting a protocol successor, resolve
its open RFC questions and record a separate native architecture decision with
synchronized architecture/threat-model and invariant review. No old note,
profile, KDF, proof, recovery software or financial runtime is reinterpreted.
