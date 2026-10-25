# ADR-0066: Independent-wallet native KAS payment research

Date: 2026-10-25

Status: Accepted for research implementation and a separately identified testnet
rehearsal. This selects a candidate to evaluate, not a production design or a
finding that its privacy is stronger than ADR-0065.

## Context

[RFC-0029](../rfc/0029-local-native-kas-private-transfer.md) and the
[source-grounded options review](../../research/next-session/sender-private-lifecycle/review/RETRY-PRIVACY-OPTIONS.md)
compare local spending, fair MPC, anonymous admission and reservations. The
external synthetic-wire MPC diagnostic reported changed-cohort aborted-retry
ownership matches of 3/3, versus 0/2 in its same-cohort control; it did not test
financial authorization or payouts. Valid proofs and fair output alone do not
ensure settlement when another exit consumes the reserve head first.

## Decision

Implement local one-input/two-output payments under the exact
[SPEC](../../poc/local-private-payment/SPEC.json). It selects fresh domain
`b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c`, new KPXA
framing and statement tags, and independent guest/native/profile identities.
Retain established KPX1 note/key/tree algorithms, CV generators and strict curve
codecs. Refresh Spend, Output and Exit parameters because D is circuit-bound.
Do not migrate old pools, notes or backups or modify the running frozen study.

One wallet validates its accepted head, exact consent, recipient invoice,
recoverable change, integer conservation, fee, state paths and actual native
effects before authorizing. No other live owner or MPC party is required.
Secretly permute the two output tuples. Output commitments are distinct and each
differs from ZERO32 and the established CM_EMPTY leaf. Adapt the outer guest first;
a direct combined Groth16 relation is a separate later comparison. Preserve a
full-note direct Exit152 path independent of the outer prover and other owners.
Preserve every SECURITY-INVARIANTS.md requirement. No new primitive, token,
privileged withdrawal, real funds or mainnet path is authorized.

Use established Tor transport, remote DNS, isolated sessions and TLS for public
requests/submission, with no direct fallback. Keep witnesses, scan indices and
view keys local. Authenticate the exact invoice out of band; sealed encryption
does not authenticate it. Reconcile stale/reorganized history and rebuild proofs
without weakening state binding or imposing permanent private note locks.

## Limits and validation

Bootstrap uses three explicitly transparent 20-KAS deposits. Each genesis
Output520 carries a genuine Output proof and CV(value=20 KAS, blinding=0), checked
against the deterministic commitment and the actual 60-KAS reserve. Initial
plaintext notes are not exported. Funders approve this exact state before their
ordinary SIGHASH_ALL signatures; accepted-history replay repeats all checks.
Subsequent Spend CVs use fresh blindings and do not inherit this opening.

Commitment identity includes its occupied position. A historical CM repeated at
a different position is not an additional consensus rejection: the native
predicate proves empty append slots and within-action distinctness, not global
CM nonmembership. Recovery retains distinct (CM, position) claims and positioned
nullifiers; fresh commitment generation remains wallet policy. This avoids an
invented history-replay rule stranding valid accepted state.

The ledger visibly groups one NF with two outputs and reveals fees, reserve
movement, timing and transparent exits. This cannot pass the old six-output
metric by changing its definition. Identifiable ingress reveals the submitter's
NF; Tor does not establish global traffic anonymity. Invoice/counterparty and
compromised-host linkage remain explicit limits. The target is bounded ledger
confidentiality plus removal of compulsory identifiable live-owner cohorts.

Freeze new observers, criteria, fixtures and disclosure boundaries before
measurement. Retain the old 21-KAS workload and failed 2% fee verdict. First
require independent canonical-byte agreement, genuine component/outer/native
verification, replay/conflict/reorg negatives and original-seed received/change
recovery and spending on public fixtures. Then perform a fresh testnet-only
deposit-to-repeat-payment-to-independent-exit rehearsal with actual terminal
payouts, zero reserve and complete sompi accounting. Retry failed trials using
fresh identities; never retransmit a used trial submission.

Keep source controls, assumption-based confidentiality, supplied-context tests,
testnet confirmation, actual off-host recovery and independent retention as
separate evidence. Passing tests do not prove cryptographic correctness or
production safety. Setup trust, shared-head contention and proof latency remain
research risks; this decision supplies no privacy or cost pass in advance.
