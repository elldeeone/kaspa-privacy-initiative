# ADR-0064: Integrate owner-private payments with native backing and independent exits

**Status:** Accepted for the owner-authorized research implementation and local
rehearsal. Funding requires the complete genuine local path; testnet readiness
requires confirmed terminal payouts. This is not a security or privacy approval.
**Date:** 2026-10-24 UTC. **Baseline:**
`760d27491b3a7ab28a14712ee41e107ebdc76b76`.
**Origin:** [RFC-0027](../rfc/0027-owner-private-native-kas-lifecycle.md).

**Execution checkpoint:** the dated
[result index](../../research/next-session/owner-private-lifecycle/RESULTS.md)
records actual TN10 GN3/both batches, fresh-seed payment/change spending,
nine confirmed payouts, zero reserve and three further fresh terminal seed
reconciliations. Complete fees are 2.156935 KAS / frozen 21 KAS = 10.2711190476%,
failing 2%. Public CI's final HTTPS/native replay remains pending publication.
Privacy, setup, host, consensus and availability assumptions are unchanged.

## Problem and scope

The ADR-0063 prototype removes an explicit output-grouping certificate, verifies
genuine independent Spend/Output proofs, and passes local native validation. It
has supplied backing, zero payout, and no independent exit. Earlier funded
profiles demonstrate payments, change recovery and native payouts under
different relations. Their properties cannot be combined into a claim that one
complete privacy-preserving lifecycle works.

The owner selected execution steps 1, 2, 3 and 5: one coherent financial profile,
repeated payments and original-backup recovery, recovery after the original
coordinator/prover disappear, and a complete TN10 run with confirmed payouts and
integer accounting. The expanded privacy study in step 4 is not selected.
Required financial correctness checks and adversarial implementation review
remain part of this work. No invariant in `SECURITY-INVARIANTS.md` is changed.

## Alternatives

1. Fund ADR-0063 unchanged. Reject: its deliberately unfunded domain and P0 policy
   neither authenticate admission nor permit withdrawals.
2. Present older funded exits alongside the new constructor. Reject: different
   domains, relations, keys, statements and policies do not establish composition.
3. Require another three-party mix or the shared outer prover for every exit.
   Reject: loss or refusal of either would defeat the independent-exit question.
4. Select one new profile with GN3 admission, the existing three-spend/six-output
   construction, and a direct one-owner full-note exit. Select this smallest
   coherent experiment; no new cryptographic primitive or runtime is introduced.

## Decision

The root-selected [interfaces](../../research/next-session/owner-private-lifecycle/INTERFACES-01.md)
are normative shared identities and role shapes. Implementation belongs under
`poc/owner-private-lifecycle`; evidence belongs under
`research/next-session/owner-private-lifecycle`. Old profiles, programs, setups,
original backups and evidence remain unchanged.

1. **Select a fresh testnet-only identity.** D is SHA256 of exact ASCII, without
   newline, `KPX8 owner-private native KAS lifecycle v1 / TN10 RESEARCH ONLY`:
   `be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480`.
   Use the selected KPX8 statement/state/body/effects/journal tags. Fresh
   Spend/Output/Exit development setups use their own role manifests and keys;
   the retained transparent Pedersen parameters are not secret setup entropy.
   A component profile binds roles and primitives before the guest is compiled.
   The final externally selected profile binds guest/image/native tail and
   executable identities without hashing itself or a future trial into the guest.
2. **Admit three independently authorized initial claims.** Adapt the reviewed
   GN2 structure to GN3: exactly three distinct ordinary P2PK funding sources and
   three Note168/CM32/CF264/CFH32 initial records, in a 1,576-byte frame.
   Initial CM count is 3 and indexed NF count is 1. Both note/receipt derivation
   and the exact initial reserve/state/policy are checked before each owner
   signs its own input. Native ALL signatures cover the whole transaction;
   explicit body checks still bind v1 compute budgets. Allocate the total entry
   fee as `[F//3, F//3, F-2*(F//3)]`; each source equals its admitted value,
   source-owned ordinary change and fee share exactly. No coordinator-controlled
   output, admin key or unbacked initial state is permitted.
   Initial Note168 records, including rho, owner/incoming fields and amounts,
   are public transparent-deposit data; no initial-claim privacy is asserted.
3. **Retain genuine three-owner rounds.** Each round consumes three genuine
   notes and creates six positive complete Output tuples through the existing
   selected malicious MPC engine. Reuse separate Spend200/Output168 roles with
   the new domain/tags, fresh input blindings, complete-effect authorization,
   current NF insertion, append-only CM updates and the direct global
   commitment conservation equation. Each owner verifies complete effects and
   required payment/change delivery before authorizing. The shared outer proof
   verifies all nine genuine component proofs under pinned keys.
4. **Add direct full-note exits.** A separate Exit152 statement is
   `KPX8EX01|D32|anchorCMroot32|NF32|effects32|payout_u64LE8|fee_u64LE8`.
   The hidden witness proves current CM membership, ownership, the same original
   positioned NF and exact bounded integer `note_value = payout + fee`.
   There is no output note, saved creator blinding or MPC requirement. Native
   policy verifies the genuine Exit proof under its fixed VK, one current indexed
   NF absence/insertion, unchanged CM root/count, actual prior reserve point and
   full state, exact payout destination/value, fee and remaining reserve.
   Positive remaining reserve continues under the identical policy; zero reserve
   has no continuing reserve output. A native payout is at least 10,000,000 sompi,
   the fee is positive, and note value remains in the existing bounded range.
   A proof cannot authorize a host-selected state or output by assertion.
5. **Recover with owner secrets and authenticated public material.** Immutable
   original backups are owner-local. Public history contains admission and
   accepted output ciphertexts, current CM/NF history, actual physical reserve
   points and native context. Owners reconstruct/decrypt locally and keep
   recovered note CMs/positions and output maps private. Public READY exports
   participant/session/NF/CVin only. Missing or conflicting history is INCOMPLETE,
   not an empty wallet. Scan recognition requires public verification material,
   not proving keys; proving authenticates the complete selected key before
   taking a private witness.

The ordinary funding key is recoverable from the same original seed through
the existing derivation at reserved index `0xffffffff`. That index is excluded
from payment/invoice/exit use. For an exit, calculate the first eight bytes of
`SHA256(KPX8EP01|D32|actual_reserve_point36|original_NF32|counter_u32LE)` as an
unsigned64 little-endian index. Start counter at0 and choose the first index
outside `{0,0xffffffff}` and all known own invoice indices, including the
consumed note's original index. Obtain its native key with the existing
`Receiver.keys(index)` derivation. Counter exhaustion refuses rather than
reusing a key. Original seed plus authenticated accepted history suffice to
rederive the payout key; no private payout map or new KDF is introduced. The
complete effects bind its actual P2PK script.

Unsettled mixed authorization must not disable independent exit. A new mixed
retry may conservatively refuse while an old authorization can still settle;
an owner may nevertheless exit its still-current unspent original NF using
latest authenticated state. Keep the old disclosure barrier and maps closed.
The original reserve outpoint and original NF arbitrate old mixed body versus
direct exit: at most one can be accepted. Creating the exit does not revoke or
erase the old valid authorization. Required regressions cover this distinction
and payout-key separation from funding/initial/consumed invoice keys.

No full wire layout may be inferred from a prose count. The native author's
canonical body/projection offsets and SPK encodings must match every independent
producer and consumer before proof/setup execution is released.

## Capacity and conservation argument

Let n be appended CM count, m indexed NF count including the sentinel, and U
the semantic number of outstanding positive notes. GN3 starts `(n,m,U)=(3,1,3)`.
Each selected round consumes 3 notes, creates 6 and inserts 3 NFs, changing
`(n,m,U)` by `(6,3,3)`. Each full-note exit changes them by `(0,1,-1)`.
Therefore every valid selected history preserves `m + U = n + 1`.

If a note remains, `U >= 1`, so `m + 1 <= n + 1 <= 65,537`, within the 17-level
NF tree even at the 65,536-leaf CM limit. A full-note exit needs no CM append.
This argument assumes valid GN3 and every branch preserving the selected rules;
an arbitrary supplied root does not establish reachability or valid backing.

All amounts are checked integer sompi. GN3 initializes reserve to the admitted
liability. A batch decreases reserve and total note value by its exact fee. An
exit decreases each by `payout + fee`. No accepted exit liability is discharged
before its actual native payout is accepted. Root/profile/state/proof checks
remain mandatory for stale, duplicate, cross-domain and competing spends.

## Existing work and trust assumptions

The [source refresh](../../research/next-session/owner-private-lifecycle/SOURCE-REFRESH-01.md)
rechecks current Kaspa/Toccata/vProgs and existing implementation dependencies,
and records mature-protocol mechanisms reused, adapted or rejected. Reuse
Sapling-style separation of Spend/Output responsibility, ValueShuffle-style
confidential construction and checks-before-authorization, established
Pedersen/Groth16 primitives, the existing malicious MPC engine, and the earlier
no-append exit/current-NF/native-effect obligations. This composition does not
inherit any other protocol's security proof.

Same-host administration, selected software/compiler, development setup,
discrete-log/proof assumptions and non-atomic validating RPC observations remain
explicit premises. Namespaces do not establish independent operators. The
coordinator-plus-one-participant privacy target requires two eligible honest
participants; endpoints, participation, timing, native entry/exit amounts,
invoice knowledge and sparse ancestry remain visible. Recipient delivery checks
remain necessary because Output proofs bind ciphertext hashes, not encryption
correctness. Timeout cannot revoke already valid owner authorization.

The frozen equal-value workload and deterministic integer fee remainders also
leave a potential arithmetic linkage channel at transparent exits: the actual
19,914,100-sompi mixed fee has shares 6,638,033/6,638,033/6,638,034, so change can
retain a one-sompi distinction. This source/arithmetic finding is not an attack
measurement or a private ownership-map observation. It does not justify changing
the frozen workload or claiming resistance to amount inference.

The testnet acquisition marker additionally publishes domain/trial/participant
pseudonym. That participant ID enters the public session roster and the same
input order is retained through NF/CV serialization. The inherited grouping
experiment permits visible input-owner labels; this source finding makes the
funding-to-pseudonym-to-mixed-input channel explicit. It does not itself map
shuffled outputs, receivers or terminal payout owners. Hiding that channel and
coordinator READY-admission pairing is an open design question, not a change to
the selected financial decision or current trial.

Public recovery objects require authenticated complete bytes and actual
availability. Two locations under one administrator, personal Drive or a local
loss fixture do not establish independent administration or indefinite retention.
No new privileged recovery/upgrade/withdrawal path is selected. A missing
participant may stop a new mixed round but must not be required for an accepted
note's full exit.

## Execution and completion

Inspect/review source and circuit/native seams before expensive setup/proving.
Complete genuine local GN3, successive mixed rounds, seed-only payment/change
recovery, separate direct exits and exact native validation before live funding.
Use only free TN10 KAS and fresh routine trial identities. Never rebroadcast a
used trial intent; ambiguous results require read-only reconciliation.

Then confirm actual GN3 and batch settlements from accepted history, remove
access to the original coordinator/shared prover, restore public software/history
and parameters, and produce owner-local direct exits on replacement
infrastructure. Confirm every native payout, final reserve and outstanding
liabilities, and the complete acquisition/admission/payment/recovery/exit fee
ledger. Preserve the 2% fee target as its own verdict. Functional success does
not change earlier privacy or fee failures, and does not establish anonymity,
independent consensus, production security or long-term data availability.

Reconsider this selection if any branch mints value, changes an original NF,
accepts a stale or foreign state, redirects reserve, makes an accepted note's
exit depend on another participant, or reveals recovered note identity to the
coordinator. Execution evidence and unresolved limitations are recorded
separately from this implementation decision.
