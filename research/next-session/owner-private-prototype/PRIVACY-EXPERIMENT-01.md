# Frozen first integrated privacy experiment

2026-10-24. ADR0063, unfunded research only. This contract is recorded before
owner initialization, genuine proving or a private MPC run. It is a bounded
functional privacy experiment, not a general anonymity qualification. Existing
privacy failures and thresholds remain unchanged.

## Question and observer

Does the implemented protocol remove the action/output subset certificate and
keep the three creators' two-output partitions out of the coordinator's view?
Use three fresh owner workers and six complete genuine Output tuples, followed
by three genuine Spend proofs authorizing one common native financial body.

The coordinator receives the full actual public IPC, session/roster and source
identities, public input NF/CV skeletons, fixed contribution counts, public phase
scheduling, the agreed final mixed pool/Delta, all final Spend proofs and the
complete public body. Public endpoints and scheduling are not declared secret.
One colluder additionally knows everything its own participant knows, including
its two contributed tuples, beta, local randomness and legitimately decrypted
incoming notes. Exclude knowledge the colluder legitimately already has from
the unknown mapping target. At least two eligible honest participants are an
explicit premise; all-but-one collusion remains a negative boundary.

The trusted same-host supervisor and Docker daemon are outside this observer.
The untrusted coordinator must actually run separately without their socket,
owner paths, private logs, host home or an execution-request interface. If the
implementation gives it those capabilities, this boundary fails; a label does
not make the capability disappear. This does not establish privacy against
malicious host administration or anonymous network transport.

## Truth separation and output

Create all private material inside individual owner namespaces. Whole party
parents protect both wallet state and MPC inputs/scratch. No controller reads,
hashes or copies private inputs or owner-to-tuple maps. Fixed-width transport
must have the same length for every legal pair/scalar. Public readiness exports
contain no tuple identifiers, hashes, beta, per-output timing or private path.

Keep any scoring oracle owner-local. Seal the observer's strategy/predictions
before a separate owner-local scorer compares them with its own records.
Export only bounded count results, never seeds, private contributions, tuple
ownership, matched locations or a public map. Do not expose honest truth to
the coordinator to make a test convenient. A missing truth oracle or unavailable
permitted colluder view is INCOMPLETE, never an anonymity pass.

## Decisive gates

1. Produce all nine genuine proofs from owner-local witnesses, execute the new
   guest and require the actual new Native predicate. Keep host checks, guest
   execution, genuine outer proof and Native acceptance separately identified.
2. Require every complete tuple exactly once, all three owners' required
   output/delivery checks, one identical EffectsDigest, exact original NFs,
   authentic current root transitions and exact native reserve/fee effects.
3. Exercise the coordinator's real namespace: protected roots/socket are
   unavailable; trusted host reads of untrusted results reject aliases before
   reading; no private record reaches the actual public IPC before mixing.
4. Examine public Spend/Output/body schemas for an owner-specific output digest,
   per-owner beta/point, creator tag, distinguishable proof key, input ordering
   certificate, variable-length transport or unnecessary per-party timing.
   Retain the demonstrated old grouped-record/blinding certificate as a
   separate public synthetic calibration, never as the new hidden truth.
5. Run the frozen correctness/failure cases below on actual integrated artifacts.
   No native authorization or privacy conclusion follows from a shuffle alone.

## Fixed failure cases

Reject changed domain, session, roster, profile or prior context; malformed or
wrong-key component proofs; wrong CV, noncanonical coordinates/scalars, torsion
or individual identity CVs, r>=q and out-of-range values; changed Delta; missing,
duplicated, substituted or modified tuples/ciphertexts; duplicate/spent original
NFs; stale CM/NF paths and wrong previous point; altered reserve, fee, successor
or an extra native payout; and missing or mismatched final Spend authorization.

Exercise loss before inputs, after inputs/mixing and after authorization. There
must be no reduced-membership sum or map-reveal response. Retry uses fresh
session/MPC keys, input blindings and complete output material while preserving
the input note's authority and original NF. Keep any old authorized body in the
test state: timeout cannot revoke it, it may settle once, and uncertainty must
remain INCOMPLETE. Public error paths must not disclose private fields.

A different valid Spend proof for the same statement is allowed witness
malleability. A changed financial effect under an old authorization is failure.

## Interpretation and stop rules

Any concrete recovery of a previously unknown honest grouping from the allowed
view, any honest premix tuple/map disclosure, unauthorized effects, double
spend or accepted invalid financial body fails the candidate. Record the exact
source and view that exposed it. Do not repair the observer or exclude that
view after seeing the outcome.

Successful gates establish only this implemented boundary and finite cases.
They do not prove indistinguishability, fix amount/timing/ancestry priors or
establish safe composition under adaptive corruption. One small six-output
sample cannot support a statistical privacy score. Larger held-out experiments
must use independently generated realizable worlds and the existing frozen
qualification criteria; relabeling one fixed commitment set is insufficient.

Operational interruptions produce INCOMPLETE with retained evidence. Strict
financial and privacy checks remain unchanged. No testnet readiness, real
funding, production security, independent operators or long-term retention is
claimed by this unfunded experiment.
