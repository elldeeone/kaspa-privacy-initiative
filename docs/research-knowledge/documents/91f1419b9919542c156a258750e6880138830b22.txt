# ADR-0019: opt-in depth-four multi-user TN10 trial

Status: Accepted for one bounded Testnet-10 experiment, 2026-11-01. This is not
a production parameter choice, mainnet design, security review, privacy proof or
authorization for paid compute. It implements the trial profile proposed in
[RFC-0003](../rfc/0003-depth-four-multi-user-tn10-profile.md).

## Problem

The executed multi-user wallet lifecycle used ADR-0018's explicit
`LOCAL-NO-FUNDING` domain. Its proofs and verifier cannot authorize native TN10
settlement. The retained recovery-native guest and TN10 tooling support safe
partial and exact-reserve exits, but pin the older depth-two wallet verifier and
cannot verify the new operations.

## Decision

Add a compile-time-isolated `tn10-full-drainage-depth-4` wallet profile with:

- Merkle depth four and domain
  `SHA256("KPI/TN10/native-KAS/full-drainage-depth4-v1")`;
- a fresh experimental Groth16 setup and verifier;
- separate private-note-chain VK pins and a separately identified recovery
  guest image; and
- the existing recovery-native/TN10 state, covenant, permission and payout
  semantics, extended only to the selected two-deposit, three-payment,
  five-exit workload.

The default, historical TN10 and ADR-0018 local profiles remain unchanged and
mutually incompatible. Existing live evidence remains regression evidence only.

Use seven ordered outer settlements if CPU calibration confirms the 160M cycle
limit: three early wallet operations; two payments plus exit 1; four
payout-plus-next-exit batches; final payout reconciliation. A measured overflow
must split a batch. Operational limits may not silently weaken a value/root,
nullifier, authorization, reserve or payout check.

Every exit is authorized by its owner proof, pins one sufficient tracked reserve
and is paid before the next exit is admitted. Exact-reserve terminal payouts
must not create a zero-value reserve output. Final success requires zero reserve,
private liability, pending deposits, unpaid exits and outstanding permission
rent, with state rent accounted separately.

## Alternatives rejected

- Relabel or reuse local-depth-four proofs: wrong economic domain.
- Reuse historical depth-two receipts: wrong verifier, state and journal.
- Add merge, MPC, locks, delays, privileged withdrawal or new service
  infrastructure: unnecessary for the selected research question.
- Combine reserves for one exit or admit several pending exits: changes the
  reviewed native policy and expands the theft/accounting surface.

## Security and privacy implications

Cross-profile proofs, states and receipts must fail. Native settlement must bind
the exact accepted lane interval, old/new roots and tips, nullifiers, exit
destination/value, reserve outpoint, permission and payout. A host success flag
cannot move state or discharge value. Failed native consumption must halt rather
than commit stale backing.

Seven public settlements, deposits, payout keys, amounts, fees, UTXO structure,
timing, RPC metadata and owner knowledge remain observer surfaces. A confirmed
payout proves only that the tested path settled; it does not establish anonymity,
cryptographic correctness or independent administration. Same-owner logical
users remain an explicit limitation.

## Evidence and reconsideration

The selected workload and observer rules are frozen in
`research/full-drainage-executed-lifecycle-2026-11-01/SELECTION.md` and the
scoped TN10 threat model beside it. ADR-0017 and the retained six-stage live
recovery trial establish reusable native semantics, not compatibility with this
new profile.

Reconsider if seven batches exceed the frozen cycle limit, cross-profile
material verifies, any owner cannot recover and exit from public authenticated
history plus its backup, a payout can divert/underpay/replay, final accounting
is nonzero, or the trial needs a new authority or weakening of a security
invariant.

## Local implementation status

The separate profile now pins verifier
`97ef3a85e5d03956150f9802d42697a8dcbb338a32a30efc811d1b3898157e32`
and guest image
`b80aa1fa8b9553b2021be9987647046ff8c15aa77206a4db858f13bf9c9a8688`.
Fresh two-world wallet execution, seven linked local native batches, all exact
CPU targets and cross-profile/native mutation controls passed. All seven batches
now have genuine independently verified Succinct receipts. Batches 1-6 used the
pinned prover's supported po2-19 segmentation resource control on the local
8-GiB RTX 3070; the guest, exact journal, program image, JOIN control, verifier,
witness and native checks were unchanged. The original po2-20 OOM is retained.

The receipt-backed rehearsal rebuilt all seven settlements, matched every frozen
transaction ID, executed every issuance/payout script and reached zero terminal
principal liabilities. The isolated TN10 builder also passed both 100M-sompi
deposit layouts and all five genuine-receipt permission/payout layouts.

On 2026-11-02 a fresh TN10 identity completed the bounded trial over a verified
TLS route, with a second independently operated synchronized route corroborating
relevant UTXOs and terminal outputs. Two deposits, three private transfers,
five owner-authorized exits, five native payouts and seven receipt-backed
settlements confirmed. Terminal reserve principal, private liability, pending
deposits, unpaid exits and permission rent are zero; state rent remains separate.

The final hour-long proof interval exceeded Node's single-string capture limit
after settlement acceptance. No transaction was retried. Read-only recovery
retained both complete native response passes, compacted only non-lane-only
transaction bodies while retaining every header and all transactions in each
lane-active block, and passed the unchanged pinned validator and its omission
and substitution controls. Reordering was inapplicable because the interval had
one KPI-lane transaction. This recovery representation is evidence plumbing;
it does not change covenant, guest, receipt, state or payout authorization.

The result remains bounded implementation evidence, not cryptographic
correctness, production safety, independent custody, general privacy, audit
proof or mainnet readiness. Exact preparation evidence and the retained OOM are
under `research/full-drainage-executed-lifecycle-2026-11-01/`; the live private
run and its audited allowlisted result bundle remain outside Git.
