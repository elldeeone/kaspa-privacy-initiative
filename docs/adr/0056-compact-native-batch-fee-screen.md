# ADR-0056: Whole-program screen for compact native batch payments

**Status:** Accepted for bounded native-only feasibility work. No funded profile,
circuit, setup or production architecture is selected.
**Date:** 2026-10-23 UTC. Baseline `a8392f11` plus ADR-0055 work in progress.

## Problem and evidence

The current two-output route fails the adopted 2% complete-fee target for
10-KAS useful payments even before other costs. Faster proving does not reduce
the native Groth16 charge. Simply widening the existing per-leaf unroller also
fails the prior source lower bound. Native 2.1 has no general loop/call/eval
facility to turn the existing witness into a compact executable subroutine.

The separate public `compact-cm-append` experiment checks the same aligned
Merkle transition in two encodings. At N32, redeem bytes fall from 50,385 to
1,862, payload from 17,488 to 1,456 and observed units from 392,747 to 19,003.
Eight positive and 48 typed negative cases pass. These are component results,
not a financial policy or fee qualification. An independently reviewed source
composition suggests a route below 2%, conditional on real code/dispatch fitting
its allowances. An actual whole-program emitter is the next decisive test.

## Decision

Prototype a **new, unfunded profile** in a separate package. Keep the current
ADR-0055 Auth528 program, parameters, wallet and completed trials unchanged.

1. Compare one payer's already demanded simultaneous 32-recipient batch with
   32 independently owned compact two-output exits. Do not pool owner witnesses,
   count change as useful payments, manufacture extra users or require future
   participation. Retain all entry, ordinary change, terminal and exit costs.
2. Preserve common public state/outpoint/payout/fee/NF fields in an Auth528-sized
   envelope. Replace the old CM pair with a CM-array digest and canonical
   mode/range metadata. Keep the two native NF insertion paths at fixed offsets
   immediately after Auth across modes. Select the wide or compact VK explicitly;
   a future circuit must constrain that exact digest, arity and all outputs.
3. Authenticate a power-of-two output subtree and its old-empty/new-root boundary
   path. Check alignment, next index/count, array digest, ciphertext digest and
   complete code/state continuation. Canonical empty gaps rely on an explicit
   initial-state/transition induction; account for consumed capacity. Never
   present an arbitrary malformed prior tree as covered by that induction.
4. Canonically omit inactive terminal ciphertext/CM-path material. Require the
   corresponding canonical zero digest/metadata, carried CM root/count, both NF
   updates, payout/conservation and future circuit zero-output constraints.
   Omission changes serialization, not permission to leave fields unconstrained.
5. Emit the **entire** common program, including retained admission/revealing
   fallback branches, both VK literals, dispatch, range/digest guards and framing.
   Measure actual lengths and calculate normalized compute/relay/KIP9 mass with
   exact integer amount/fee fixed points. Keep the 1600 exit budget; also stress
   a 2200 payer budget. No smaller budget is credited without a conservative
   all-valid-path bound.

First runtime controls use only public synthetic DO_NOT_FUND data and valid
public placeholder VKs with zero proofs. Valid public cases must fail at the
expected final G16 seam after all public checks; malformed cases must fail their
earlier checks. This does not prove private conservation, produce a financial
positive or authorize funding. No new circuit/PK/setup follows automatically.

## Exit capacity and privacy boundary

The bounded batch reaches at most CM126/NF67 and can price existing continuing
two-output exits. It does not solve private exit availability at full CM capacity.
A future proof-constrained no-append full-exit mode may preserve CM state while
inserting both NFs and proving all private outputs zero even with reserve left.
That requires explicit new circuit gates and discloses full-versus-change mode;
it cannot be implemented by deleting checks or reusing the current parameters.
Keep this an open design question, with the potential inductive capacity
invariant `m + 2 * positive_unspent_notes <= 2*n + 1` reviewed separately.

All source bounds are conditional until the actual emitter fits and its source,
meter and native rejection cases are independently checked. If the complete
lower bound fails the target, stop before cryptographic implementation. A
passing native-only screen warrants a separately reviewed circuit/proof/native
lifecycle experiment and privacy/recovery evaluation; it does not qualify fees,
financial privacy, setup honesty, data availability or production safety.

Primary references and rejected alternatives are retained in the new
[source refresh](../../research/next-session/private-change/SOURCES.md) and
[fee proposal](../../research/next-session/private-change/fees/COMPACT-APPEND-PROPOSAL-01.md).
