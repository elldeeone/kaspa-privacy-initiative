# ADR-0022: Two-note deposits into a new compact pool

**Status:** Accepted for the bounded experiment; not protocol adoption.
**Date:** 2026-10-19.
**Related RFC:** [RFC-0010](../rfc/0010-compact-independent-deposits.md).

## Context and decision

The compact prototype accepts one initial funding contribution. H9 supports
fresh exit authorization as a privacy mechanism in small synthetic fixtures,
but those fixtures cannot test independently funded participants. Add that
missing capability before the population study, while retaining independent
exit fallbacks and all security invariants.

Use a new immutable application version that reuses the exact current private
circuit and VK. An ordinary signed native input funds two new private notes;
the existing transfer relation proves their total equals the deposit less its
fee. In this distinct native branch the proof's input/root/nullifier are virtual
value witnesses, not a real pool spend. Append only the two output commitments
and resulting accepted root. Preserve the actual nullifier tree unchanged and
require the reserve to grow by exactly the credited value.

This avoids a second private proof, new setup, operator, token or identified L1
change. Preserve the existing verified first-depositor bootstrap and independently
validated public descriptor/lineage. The depositor signs the intended monetary
transaction/payload with canonical SIGHASH_ALL. The proposal is grounded in
[current primary sources](../../research/compact-deposits-source-review-2026-10-19.md);
its bounded offline composition and native cost are now measured in the
[report](../../poc/shared-pool/DEPOSITS.md). Complete TN10 rehearsal and a fresh
measured trial also passed, with all four wallets paid and both pools drained.

The old pool cannot acquire new code in place. Keep v4 code/evidence/proofs intact;
do not transplant its domain-bound claims. In the new pool, proofs prepared
before later deposits must remain byte-identical and usable through public-only
settlement. A fixed fee remains a fixed fee; this does not solve repricing.

## Alternatives and tradeoffs

| Alternative | Reason not selected for this bounded scope |
| --- | --- |
| Dedicated one-note admission circuit | Lower minimum and one exit per depositor, but a new relation/verifier/setup and separate proof review. Revisit if two-note cost or the reused relation's composition is unacceptable. |
| Add a deposit mode to the current private relation | Changes that relation/VK and increases compatibility work without being necessary for two-output value conservation. |
| Port the earlier array-state deposit unchanged | Demonstrates useful atomic funding checks, but its full-state proof loses the compact historical-authorization property. Reuse its accounting lesson. |
| Publish a note opening or insert an unchecked commitment | Publishing changes confidentiality; unchecked credit can exceed backing. Neither satisfies the question. |
| Empty reserve, subsidized dummy claim, operator credit or new L1 rules | Adds a separate mechanism or trust assumption. Zero-valued outputs fail native consensus; ordinary first-depositor bootstrap already provides a bounded start. |

Each deposit creates two claims of at least 60,000,000 sompi. Minimum funding is
120,000,000 sompi plus its fee, and draining both requires two full exits. Added
covenant code can increase every transaction's fee. This is the smallest change
to the existing proof machinery, not a claim of minimum user cost.

## Security, privacy and reconsideration

The native branch must bind real input backing, output value and exact state;
its virtual input must never create a pool claim or modify spentness. Normal
spends retain real membership/nullifier checks. Fresh backing can legitimately
reuse an admission proof at different positions; the same spent funding input
cannot be replayed. Existing positioned nullifiers distinguish those claims.
Funding signatures, canonical framing and valid genesis/lineage are mandatory;
an operator assertion or `nf_count >= 1` alone is insufficient.

All four wallets must scan their own notes and later exit with their original
bundles, the prover stopped, public data only and no other wallet's help. Test
every wallet's terminal role and complete drainage. Correct-node, public-history,
setup and fixed-fee assumptions remain explicit. No invariant is relaxed.

Native funding amounts/ancestry and the two-note creation event are public.
Old proof anchors retain their privacy restriction. Independent deposits are a
workload prerequisite, not evidence that useful privacy exists; Stage 2 remains
open and RPC/network observation remains separate.

Reconsider if a safety control fails, any old claim loses its exit path, the
unchanged note floor cannot pay the measured worst exit fee plus payout floor,
two-note cost misses the use case, or a new proof relation/L1 change is needed.
Stop mechanical expansion after the bounded prerequisite and assess inference.

## Outcome

The owner authorized implementation/offline validation and conditional TN10
execution on 2026-10-20 (Australia/Sydney). Preserve the scope, invariants and
stop conditions. The offline gate passed with four drain orders, unchanged
saved proof bytes, exact backing and adversarial controls. Complete TN10
rehearsal and a fresh measured trial confirmed all 14 transactions each, paid all
eight notes using unchanged saved proofs and drained both reserves. Measured
fees were 2.656933 tKAS including ordinary allocation/genesis; the admission
minimum is 1.420052 tKAS and each note exit costs 0.219344 tKAS.

Retain this admission candidate for the later population study. Its two-note
cost and old-anchor privacy limits remain reasons to reconsider it. This does
not select a production architecture or complete Stage 2.

The preceding scoping step recorded the 13-transaction main fixture, required
regressions, controls and cost gates in RFC-0010. It changed no code, experiment,
chain state, setup or existing evidence; implementation was authorized afterward.
