# Early privacy test: public-surface and amount-inference calibration

Date: 2026-10-20. Candidate: `bf4505c16bd3f55ee6e4b534b14fece4281c963a`;
work order: `6dff59dfa16917170a2bebf4b6f4d29aca9146a7`.
This specification precedes execution of the new analysis. Save its bytes/hash
with execution inputs before running; preserve failed attempts and any correction.

## Question and limit

What does the actual current-v6 transcript expose, and can a correctly scoped
observer recover or narrow private output values using public conservation,
anchor counts and documented wallet shape alone?

This first slice audits and calibrates an analysis method on an already published
three-wallet integration history. Its truth has been published. It is **not** a
blinded held-out trial, a 32-role qualification, an owner-anonymity measurement or
a privacy pass. It can establish deterministic deductions on this trace and
identify invalid assumptions before the larger evaluation.

The [early gate](../../docs/SHARED-POOL-PLAN.md#early-privacy-gate--before-milestone-3)
and [RFC-0012 targets](../../docs/rfc/0012-useful-privacy-requirements.md#adopted-privacy-targets)
are unchanged. Any claim of failure of the supported primary use case must show
that the counterexample instantiates that use case; singleton calibration alone
cannot do so. No funds, broadcasts, new setup or new cryptographic proofs.

## Inputs and observer boundary

Use only `evidence/2026-10-20-wallet-lifecycle/positive/`:
`descriptor.json`, `vk.bin`, `lineage.json`, and `parents.json`.
Pin each file and the native replay executable by SHA-256. Native replay validates
the genuine existing proofs, funding contexts and complete transaction lineage;
the parents' ancestry and expected acceptance remain synthetic/offline assumptions.
Native validation is not a new accepted-chain result.

Retain the exact native records and parent bodies. Derive a public projection
from their payload bytes, not hand-entered event values or the experiment report.
Expose all raw public bytes for future attacks; the arithmetic attack uses only
its declared reduction. No experiment narrative, process/role labels, backups,
note openings, action files, scans, receive envelopes or proof timings enter it.
Shared receive data and infrastructure observations need separate declared views.

Decode native mode, fee, deposit, payout/destination, real funding outpoints,
reserve movement, anchor count/root, commitment/nullifier bytes, ciphertexts,
proof identity, successor state and public settlement witness. Classify every
payload region. Preserve equal commitments at different positions; commitment
uniqueness is not a v6 invariant. Under the declared binding assumption, equal
commitments constrain their values equal without merging their positions/spends.
Resolve initial funding grouping from the actual
founding input's parent transaction, not the newly created founding transaction.

Order is an ordinal. No block times or artificial wallet delays are supplied.
If an internal adapter uses the old H14 `minute` key, set it to the constant zero
and explicitly declare it unused; it is not a measured or synthetic time series.
Public equality/shape checks report zero padding separately from nonzero
commitments, nullifiers, ciphertexts and ephemeral encryption prefixes. Compare
funding and payout scripts for reuse; fresh native addresses are not assumed.

## Two arithmetic profiles

Reuse the existing independently encoded H14 integer CP-SAT and Z3 conservation
relations, not the H15/H16 policy subclasses. The latter require one real input
for every DRAIN, while the current wallet supports one or two.

1. **Relation:** one or two real unspent inputs before the public anchor;
   zero-or-at-least-floor outputs; explicit fees/payouts/deposits; one spend per
   note position; reserve conservation at each prefix and terminal drainage.
   Do not assume hidden owners, recipient labels or the research schedule.
2. **Current-wallet shape:** additionally ADMIT output 0 is deposit minus fee
   and output 1 is zero; SPEND has no native payout, positive output 0 and
   zero-or-positive change in output 1; non-ADMIT authorizations use the current
   anchor. DRAIN still permits one or two inputs. These are client rules, not
   consensus rules. Input common ownership is not modeled in this slice;
   the profile is a relaxation of the full wallet, not its complete semantics.

Cryptographic identifiers are treated as hiding/unlinkable except for publicly
observable equality, format and state structure. This is an explicit assumption,
not a tested cryptographic result. Omitting restrictions can widen feasible sets;
an unjustified extra restriction can falsely create a unique deduction.

## Predeclared measurements

For every created output position, query exact integer minimum and maximum at
creation, at each subsequent DRAIN, and at final history. Include ADMIT/bootstrap
and padding as labeled diagnostics, not secret-payment successes. For ordinary
SPEND output 0, a wallet-conditioned positive value corresponds to the payment
amount, but its owner is not inferred by this measurement.

Use no truth in inference. Report both profiles, each horizon, integer bounds,
whether zero is feasible, and whether a single value is logically forced.
Minimum/maximum describe extrema, not a contiguous set or probability. For each
endpoint require a satisfying witness; require UNSAT below the minimum and above
the maximum, or exact OPTIMAL certificates. Cross-check both solver encodings.
Unknown, timeout, disagreement, inconsistency or missing query is incomplete;
none increases anonymity. No guessing accuracy, confidence or owner count is
inferred from these few observations.

Report public repeated-value/equality patterns and field exposure separately.
Nullifier insertion/history/append witnesses are not private note membership
paths; check their derivation from public state and authorization before claiming
they expose consumed-note positions.

## Required controls and execution

Before inferring the real trace, check:

- Tiny known-answer ledgers against independent exhaustive enumeration, including
  ambiguous amount splitting and a value forced only after a later withdrawal.
- A valid two-real-input DRAIN retained by both profiles; a one-input-only
  mutation must reject that control or change its feasible set.
- Admission padding is a wallet condition, not a protocol restriction; preserve
  both profiles and demonstrate the difference on a tiny control.
- Distinct commitment positions are preserved even when commitment bytes match
  in a decoder-level control. This is not a new genuine proof/history.
- A missing interior native transaction, authorization/ciphertext corruption and
  wrong funding parent fail native replay before analysis. Removing only a tail
  can leave a valid prefix; native replay alone must not be said to reject it.
  Input hashes and the separately recorded complete endpoint/count identify the
  intended complete calibration history.
- Observer input schema rejects role/truth/participant metadata; a poisoned
  diagnostic/report is never substituted for the byte-derived projection.

Pin scripts, dependencies, specification and inputs in a fresh output directory
before inference. The runner may be given this public source set but must not
read private directories. Execute the observer in a restricted process with only
its code/dependencies and public input, no network or private wallet material.
Record actual isolation limits; this is author-side analysis, not an independent
audit or adversary.

**Method passes calibration** only if all declared controls and complete
cross-checked queries finish. Preserve any discovered forced/narrow values as
findings, not a privacy success. If calibration fails, repair the method and
retain the failed run. The overall early privacy gate stays open regardless.
Next freeze the 32-role/eight-adversary held-out workload and explicit C/P/A,
owner/amount, baseline and statistical details using the audited surface.
