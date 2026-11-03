# Shielded KAS recovery test design

Status: **Proposed test design, 2026-10-18.** The
[offline prototype](../poc/shielded-design/RECOVERY.md) now implements a model-level
R01–R04 slice with 18 recovery tests. The [R05/R06 extension](../poc/shielded-design/TRANSITIONS.md)
adds 14 tests for restored spentness and pending credit/refund-request races.
Both use a separately trusted model checkpoint, not L1/proof authentication.
The [R07 extension](../poc/shielded-design/PAYOUTS.md) adds 10 tests for paid
claims, duplicate payouts after restore and terminal reserve drain. Unknown-sender
wrong-key delivery remains unqualified. The [R08–R16 offline programme](../poc/shielded-design/PROGRAMME.md)
adds 14 tests, bringing the suite to 80. Every full proof/native gate remains
open; R13 has model controls only and R16 an offline rehearsal only.
This is the concrete follow-up to the
[specification-to-code review](shielded-spec-code-review-2026-10-18.md), supporting
[P09/#9](https://github.com/olafweller/kaspa-privacy-initiative/issues/9),
[P10/#10](https://github.com/olafweller/kaspa-privacy-initiative/issues/10) and
[P12/#12](https://github.com/olafweller/kaspa-privacy-initiative/issues/12).

**First build target:** fresh-process reconstruction from a specified public
record set and one user's documented backup, with authenticated completeness,
current spentness and explicit missing-data results. Start offline; do not
represent model recovery as the later real-proof TN10 shutdown/exit gate.

This design selects no note construction, tree, serialization, archive service,
proof system or fee mechanism. Resolve those interfaces in RFC-0002; record
architecture choices in an ADR when decided. All existing invariants remain.

## Boundaries to specify before writing the harness

| Boundary | Inputs | Observable result and independent check |
| --- | --- | --- |
| Public reconstruction | Protocol descriptor, accepted ordered records, authenticated checkpoint/lineage, native reserve/permission/payout observations | Canonical public commitments, spentness, deposit/exit/fee records and completeness horizon; compare with independent fixtures and L1-bound commitments. No reconstruction of users' hidden amounts/ownership or input wallet balance cache. |
| Wallet restoration | One user's documented private backup and authenticated public state/delivery records | Discovered notes, accepted notes, currently spendable notes, pending deposits/exits and missing dependencies as distinct results. No sender or operator secrets. |
| Spend/exit construction | User-held spend authority, allowed anchor, current state, pinned artifacts and explicit fee/rent source | Valid proof/operation/exit claim bound to recipient and principal; view-only material cannot authorize. |
| Native completion | Accepted settlement and permission, reserve inputs and payout outputs, canonicality observations | Exact native principal/rent paid once, backing reconciled and no unpaid liability forgotten. Mempool admission is insufficient. |

Suggested test-facing operations are conceptual: `reconstruct`, `restore_wallet`,
`prepare_exit`, `observe_payout`. They are not existing APIs or a frozen module
layout. Tests should target their public outcomes, not pickle a Pool object or
inspect a prover's internal database.

## Required input inventory

The field names below describe required meanings, not final wire keys. Amounts
are integer sompi everywhere. A transport string must decode once with strict
range/canonical checks; do not compare strings to numbers.

| Data class | Required contents | Authentication / omission question |
| --- | --- | --- |
| Protocol descriptor | Actual network/genesis, pool/lane/covenant, supported statement/encoding versions, exact verifier/image/key identities and initial state | How is this descriptor bound to the reserve? A caller-selected descriptor or self-hashed manifest is insufficient. |
| Accepted ordered activity | Native transaction/payload IDs, accepting-chain contexts/order, complete operation bytes, outcomes and prior/successor state references | Reconstruct the interval through a declared end anchor. Omission, duplication or reordering must fail; submission order is not acceptance order. |
| Commitments, nullifiers and anchors | Ordered note commitments, current spentness, allowed membership roots, insertion positions/witness reconstruction data | Authenticate roots and full updates, including a competing spend from an old allowed root. One membership proof does not prove unspentness. |
| Delivery records | Complete ciphertexts, ephemeral/encryption/discovery fields and their commitment/operation association | What independently committed count/digest/position detects missing records? A valid note root alone may not commit ciphertexts; a list of available files cannot prove completeness. |
| Deposits | Native outpoint, exact amount/script/covenant, descriptor/recovery authority, accepted pending/credited/refunded transitions | Authenticate the event and current single-consumption state. Decide behavior for an invalid inner proof and malformed unsolicited transfer. |
| Exits, fees and rent | Authorized claim identity/recipient/principal, unpaid/paid transitions, permission tree evidence, separate rent/refund and fee ledger | Native payout observations need canonical lineage and exact consumed permission/output bindings. Claim creation is not payment. |
| Snapshots and suffix history | Economic state, commitment/spentness/claim data, snapshot height/anchor, authenticated coverage and full suffix | Define validation back to the descriptor/settled state. An operator signature cannot replace required proof/chain authentication. Snapshots are optional if complete replay works. |
| Public proving/verifying artifacts | Required parameters, program bytes, key/image/control identities, reproducible software and version dependencies | Integrity and independent availability are separate. A key hash cannot recreate missing proving parameters. No trusted-setup or destruction claim is added. |
| Private user backup | Spending authority, incoming/view/discovery material, required owned-note metadata, pool/restore locator and any derivation/discovery counters selected by the design | Exact minimal backup is unresolved. Prove which fields are seed-derived; do not promise seed-only restore. Keep every other user's secrets inaccessible. |
| Native current and historical context | Validating-node/chain source, current UTXOs plus historical contexts needed to validate reserve lineage | State the source trust and pruning coverage. Current UTXOs, matching endpoint URLs or retained headers alone do not recreate full accepted history. |

A qualified input inventory must name which independent source already retains
each public item before shutdown, how it is retrieved and what retention is
assumed. An archive may be required; it must not depend on a privileged original
operator. Finite availability at inclusion does not prove later retrievability.
See the [primary-source review](../research/recovery-source-review-2026-10-18.md).

## Worked three-user workload

**Synthetic expected accounting only.** No deposit below was broadcast. N=3 is
a proposed minimal workload to expose transfers, pending exits and uncredited
deposits; it is not an anonymity measurement or a general-scale claim.

1. Alice deposits `1_000_000_000`, Bob `700_000_000`, Carol `300_000_000` sompi.
   Credit Alice and Bob; leave Carol's valid deposit pending after rejected
   credit so its owner-recovery path must work.
2. Alice spends her note to give Bob `400_000_000` and herself `600_000_000`.
3. Bob spends his original `700_000_000` into a `200_000_000` pending native
   exit, `499_999_000` change and `1_000` authorized unpaid fee. His received
   `400_000_000` note remains unspent. Fund the existing exit's `50_000_000`
   permission rent externally and record it separately.
4. Shut down producer services at this checkpoint for the later real gate.
   Attempt a duplicate Alice spend from its old allowed root in a subsequent
   batch/restart; reject it without changing economic state.
5. Independently restore each user. Alice exits `600_000_000`; Bob collects his
   existing `200_000_000` claim and exits `899_999_000`; Carol recovers her pending
   `300_000_000`. Resolve the `1_000` fee claim separately. Do not assume refund
   permissions, combined payouts or future rent funding are already implemented.

| Shutdown checkpoint, sompi | Expected |
| --- | ---: |
| Native principal reserve | 2_000_000_000 |
| Spendable private liabilities | 1_499_999_000 |
| Funded uncredited deposit liability | 300_000_000 |
| Unpaid exit principal | 200_000_000 |
| Unpaid authorized fee | 1_000 |
| Separately locked permission rent | 50_000_000 |

Principal liabilities sum to exactly `2_000_000_000`; rent is not counted twice
as principal. At completion user principal payouts total `1_999_999_000` and the
fee payout is `1_000`, leaving zero principal reserve and liabilities. Refund
existing rent exactly once. Additional exit/refund permissions must have a
declared, separately funded and reconciled rent source; their exact count and
refund rules depend on the chosen native path. Native fees and state rent stay
outside user principal. An unfunded rent requirement is a liveness failure,
not permission to debit user backing silently.

Also use a **fee-free one-note variant**: a valid user's exit consumes exactly
the remaining reserve. This directly tests the current trial helper's
`delegate amount > payout amount` restriction. A new terminal output shape needs
native validation; do not remove the restriction and assume the scripts agree.

## Case inventory

R01–R07 have bounded model coverage linked above; the rows below retain the
full intended requirements, including still-open proof/native and recipient
acceptance obligations. R06 creates an unpaid refund claim, not a native refund
payout; R07 models payment effects, not native acceptance. Unsolicited native
deposits remain unspecified. R08–R16 now have the bounded offline controls
linked above; the full requirements in these rows are unchanged. R13 does not
have real-proof classification and R16 does not have confirmed native payouts.
Required evidence levels:
**M** = offline fixture/model behavior; **P** = real proof and state relation;
**L** = actual native validation/acceptance and payout. An M result never passes
the P/L gate. Existing A1 tests are control examples, not implementations of
these shielded cases.

| Case | Setup / fault | Required result | Level / gap |
| --- | --- | --- | --- |
| **R01: fresh recovery** | Separate producer and recovery processes/directories; give each restorer only its backup, declared public data/artifacts and independent authentication input | Exact worked checkpoint, correct user's notes/claims, rebuilt witnesses and identical canonical state across independent reconstruction paths; no hidden oracle registry or producer object. Later prove/spend/pay every user. | M then P/L; G4/G5 |
| **R02: omission and false completeness** | Remove a middle operation, commitment or relevant ciphertext; truncate a suffix while retaining the externally declared end anchor; give only roots/current UTXOs | Detect incomplete/tampered coverage, preserve prior trusted state and name missing dependencies. Never return complete zero balance. Redundant independent data may repair the run. A root-only negative is safely incomplete, not successful recovery. | M/P; G4 |
| **R03: substituted or stale archive** | Valid but wrong pool/network/version/checkpoint; duplicate/reordered records; self-consistent replacement snapshot and manifest | Reject wrong descriptor/lineage/coverage; changes to supplied files and their manifest cannot replace the independent trust anchor. A legitimate older wallet backup must instead catch up with complete authenticated suffix data. | M/P; G2/G4 |
| **R04: receiver acceptance and spentness** | Valid decryptable but never accepted record; same record twice; previously spent note; wrong commitment/ciphertext/receiver key; sender creates bound but unusable delivery | Unaccepted/duplicate/spent records add no spendable balance. Reject or clearly mark undeliverable outputs before payment acceptance under the selected receiver protocol. Correct recipient can independently prove its next spend. | M then P; G1/G5 |
| **R05: restart and competing spend** | Two individually valid spends of one note using the same old allowed anchor, separated by batch, process restart and archive restore; also within one batch | Exactly one economic consumption; current nullifier state survives restore, second operation has deterministic no-op, unrelated later valid operation succeeds. Altering intent/proof serialization cannot create a new spend right. | M then P/L; G1/G2 |
| **R06: pending credit versus refund** | Shutdown before credit; invalid inner proof; owner recovery with current state; race credit/refund in either accepted order; wrong owner/outpoint/amount | Preserve liability until exactly one credit/refund path consumes it. Invalid credit does not strand supported deposit. No signature-only bypass; actual refund payout must bind exact principal/destination. Specify unsolicited malformed transfers separately. | M then P/L; G3 |
| **R07: unpaid exit and terminal drain** | Shutdown after exit creation but before payout; restart after payout; final user/fee claim consumes remaining backing | Unpaid claim remains backed; consumed permission cannot pay twice. Exact native principal/rent/refund/change and final reserve reconcile, including zero-reserve terminal shape. | M then P/L; G3/G7 |
| **R08: removed state/payout** | Remove a formerly observed transfer, settlement or payout from canonical history; replay an alternate accepted suffix; deep reorg crosses retained checkpoint | Roll back dependent notes/nullifiers/claims/paid observations atomically and reconcile actual UTXOs. Restore unpaid liabilities when an unpaid claim survives but its payout is removed. If claim itself is removed, derive alternate canonical note/claim state. Reject/mark incomplete when required pre-checkpoint history is unavailable. | M then P/L; G6 |
| **R09: crash atomicity** | Interrupt before/after persisting record, checkpoint, private scan cursor and payout observation; unknown submission outcome | Restart yields previous committed or fully verified new state, never mixed state/cursor or double credit. Inspect saved financial intent and canonical acceptance; no blind rebroadcast. Recover missing records from independent retained data. | M then P/L; G4/G6 |
| **R10: pruning and archive replacement** | Original node prunes the interval; original archive is inaccessible; another independently retained archive supplies full data, then a variant where no source has required ciphertext/history | Complete replacement path restores every user. No-source variant reports recovery failure without inventing data or using the original operator's private files. State which retention assumption failed. | M then independent L; G4 |
| **R11: backup/authority separation** | Restore spending backup, view-only backup, wrong key, missing discovery metadata, stale backup and missing prover artifact | Spending backup succeeds under documented requirements. View-only cannot spend. Distinguish missing keys/artifacts/history from zero funds; report scope of scanning/spentness possible with view-only material. No export of another user's secrets. | M then P; G1/G4/G5 |
| **R12: independent fees/rent** | Remove normal sponsor/relayer, vary fee demand, offer fee inputs or reordered/substituted inputs/outputs; try redirecting rent/change or taking fees from principal | Under declared fee-demand conditions, an independent route can prove/settle/pay without normal sponsor authority. All exact payout/backing checks hold; report payer linkage and external funding assumptions. Above supported conditions, report failed liveness. | M/P then L; G7 |
| **R13: adversarial ordered operations** | Valid / malformed or cryptographically invalid / valid; wrong-root/owner, repeated nullifier and range/overflow vectors; late-failing proof | Every accepted lane operation gets the forced outcome; rejection leaves economic state unchanged and later valid work continues. Full receipt binds actual accepted interval and image/journal; time/resource failure is not an invalidity result. | P/L; G1/G2 |
| **R14: witness and query exposure** | Capture permitted executor/prover/RPC inputs, journals, diagnostic logs and scan requests using synthetic secrets as canaries | No raw notes/spend/view secrets or selected membership witness outside user wallet. Report query/timing/fee/operation-shape linkage; passing canary checks does not prove zero knowledge or anonymity. | M/P; G5 |
| **R15: unsupported/legacy version** | Change version/image/key or present already consumed old claim on another route | Initially reject unsupported versions. Before enabling migration, prove one shared consumption or one-way migration and recover dormant users with legacy artifacts; no admin rescue. | M then P/L if enabled; G8 |
| **R16: full shutdown gate** | N=3 workload with all normal application operators, provers, executors, hosted state and original archive services unavailable; independent retained data/artifacts and per-user backups only | Independently reconstruct, locally prove private wallet relations, settle via replaceable infrastructure and confirm each user's exact native payout. No privileged files/cooperation. Every user's result and all remaining liabilities reported; partial completion is a failed gate. | Independent P/L; G1–G7 |

## Implement the tests in this order

1. Review the input/output contract; implement **R01–R04** as the first offline
   vertical slice. Work from known accepted fixtures with explicitly labelled
   authentication assumptions. Include discovery's unfunded/duplicate/spent
   controls from the review and a separate expected ledger; do not snapshot the
   same implementation as the oracle.
2. R05–R09 now have their bounded offline slice at the public
   reconstruction/restore boundaries. Continue to inject
   faults into one dependency at a time, keeping unrelated bytes valid so a
   parser error cannot masquerade as a proof/nullifier/payout rejection.
3. R10–R14 have offline controls; qualify their full retained-data, process,
   fee and real-proof integration requirements as those become available. Reuse the established A1 pagination and public native-output
   controls where their assumptions match; do not transplant the fixed-claim
   manifest/setup or same-owner checkpoint as a private-pool recovery solution.
4. Keep **R15** version rejection active; defer migration-specific implementation
   until selected. The R16 offline rehearsal is implemented; attempt the actual
   **R16 native gate** only after the complete real lifecycle and
   actual terminal payout have succeeded in a fresh testnet rehearsal.

Do not require a new service network for offline tests. Use separate fresh
processes and explicit data permissions first. The later independence test must
add genuinely separate infrastructure/control and independently retained data;
separate directories or endpoint names alone do not establish that independence.

## Result and evidence contract

Each future run should retain the evidence below with **public and protected
wallet outputs separated**. Public artifacts contain aggregate backing and
native payout outcomes plus declared public/synthetic fixture values. Hidden
per-user balances, discovered-note identities/linkage, view-derived history,
private scan state and sensitive query traces stay in that user's protected
output. An explicitly public synthetic oracle supplies the worked workload's
per-user expected balances; the public reconstructor does not learn hidden note
contents. Keep aggregate test verdicts useful without publishing wallet secrets
or derived private history.

Evidence inventory:

- source/toolchain/program/verifier identities, fixture hashes, case and fault;
- actual network/pool, canonical start/end anchors, accepted operation coverage,
  independent sources and named trust/retention assumptions;
- backup *field inventory* and process access boundaries, never private backup
  contents in public evidence; synthetic public fixture values labelled as such;
- per-user discovered/accepted/spendable principal, pending deposits/exits,
  missing dependencies, and proof/settlement/payout states separately;
- reserve, unpaid principal/fee/rent liabilities, actual output/permission IDs,
  recipient amounts, change, fees, rent and refunds at each canonical stage;
- actual proof verification/rejecting layer and negative-control result, plus
  restore/proof/settlement times, peak resources and observed linkage limits.

Distinguish **complete at declared horizon**, **incomplete data**, **rejected
unverifiable input**, **proof unavailable**, **payout unconfirmed** and **all
payouts confirmed**. These are proposed result meanings, not new protocol error
codes. Completeness at a historical horizon is not current spendability.

Operational budgets should be generous and based on measured work. A timeout,
resource limit or missing telemetry yields an incomplete experiment, never proof
of invalidity or a successful exit. A new live trial identity must be creatable
unfunded with one command in minutes; fix that if the later harness cannot do it.
Never rebroadcast within a consumed identity. These test-design requirements do
not authorize a live run, rental, machine shutdown or use of old trial keys.

The all-users gate passes only when **every supported user entitlement is
resolved into confirmed native payouts**, with any remaining fee/rent liabilities
explicitly backed/reconciled. Missing required data, a safe halt, a valid proof
without settlement, or a zero balance inferred from an empty archive does not
pass. Passing the gate would still not prove cryptographic correctness,
production safety or anonymity.
