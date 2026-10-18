# Next focus: shielded native KAS and financial privacy

**Current execution, 2026-10-18:** the owner authorizes P1–P5 work, local proving
and eventual qualified testnet trials against `10.0.3.26`, with no mainnet or
real funds. [ADR-0018](adr/0018-private-payment-implementation-package.md) and
[RFC-0004](rfc/0004-private-payment-suite-and-encoding.md) add a concrete suite,
interoperable public intent bytes and established-library vectors. The
[P1 package](../poc/private-payment/README.md) keeps primitive VM compatibility
separate from the subsequent full offline wallet relation. The owner-selected
[separate-agent review](../poc/private-payment/REVIEW-RESULTS.md) found four
design blockers; fixes passed focused re-review. Unfunded offline P2 may now
proceed with synthetic fixtures under
[ADR-0019](adr/0019-separate-agent-prototype-review.md). External audit, proved outer transitions
and native bindings remain open. No test wallet top-up is needed yet.
Its [measured primitive result](../poc/private-payment/RESULTS.md) is a real
Orchard API receipt in 6m53s on the 3070, reverified from saved bytes on CPU.
This measures one public key/note/nullifier workload, not the full private
payment relation. The node's Full history RPC works; its lane-proof RPC fails,
so private native settlement qualification remains open.
The later [recovery-authority supplement](../poc/private-payment/RECOVERY-AUTH-RESULTS.md)
adds native signature/encoding interoperability, exact proposed private witness
bytes and a source-grounded deposit-binding gap analysis. Its original scope is P1 preparation; the later full wallet evidence below
adds proof enforcement without closing outer/native or external-review gates.

The [full offline wallet prototype](../poc/private-payment/WALLET.md), under
[ADR-0020](adr/0020-offline-wallet-relation.md), now implements the reviewed
relation. [All four genuine receipts](../poc/private-payment/WALLET-RESULTS.md)
passed GPU proving and saved CPU verification, including a spend reconstructed
from own-backup restore. Eight isolated restore runs passed; duplicate spends
and exits reject. The adapter uses trusted synthetic backing/history and is
not the proved outer or native payout path. No new native funding is needed.

The [2026-10-18 specification-to-code review](shielded-spec-code-review-2026-10-18.md)
maps eight concrete work gaps and recommends the authenticated recovery-record
and wallet backup/restore contract first, alongside existing proof diagnostics.
The [recovery test design](shielded-recovery-test-design.md) supplies 16 proposed
cases, including a worked three-user ledger and final-reserve payout. These are
review/design artifacts, not implemented recovery or a change of architecture.

The subsequent [offline prototype](../poc/shielded-design/RECOVERY.md), under
[ADR-0011](adr/0011-offline-model-recovery.md), implements model backup/restore
and R01–R04 controls. The [R05/R06 extension](../poc/shielded-design/TRANSITIONS.md)
adds restored double-spend prevention and both pending credit/refund-request
orders. [R07](../poc/shielded-design/PAYOUTS.md) now retains paid claims and
drains the model reserve in fee-last and user-last orders. The
[R08–R16 programme](../poc/shielded-design/PROGRAMME.md) now adds bounded offline
rollback, process-crash, replacement-data, authority and shutdown controls.
All rely on a separately trusted model checkpoint;
actual L1/proof authentication, native recovery and unknown-sender delivery
remain open.

**Owner-authorized parallel work, 2026-10-18:** qualify the GPU proof path and
complete the private-payment specification, with no mainnet or real funds.
[RFC-0003](rfc/0003-private-payment-proof-and-settlement.md) now states the full
proposed semantics. Its gate order is P1 exact suite/composition review, P2 full
wallet implementation, P3 real R13 outer proof, P4 native integration/rehearsal,
then P5 independent R16. The local RTX 3070 experiment is separate from the
prepared remote L40S path. Its [measured result](../poc/remote-cuda/LOCAL-RESULTS.md)
finds segment proving exceeds 8GB, while two GPU lifts and their join complete
with independently verified receipts. The five-phase GPU gate remains failed;
the remote L40S path has not run. GPU performance cannot close private relation/
native gates.

The owner's subsequent instruction to use the existing 3070 leads to
[ADR-0017](adr/0017-rtx3070-smaller-segments.md) and a successful
[smaller-segment full proxy proof](../poc/gpu-segments/RESULTS.md): 7m36s,
6096MiB sampled peak prover VRAM, exact original image/input/journal and
independent original CPU verification. The unchanged po2=20 benchmark remains
failed; po2=19 proves the whole proxy workload on current hardware. Next review
P1, then implement/measure the full private relation; R13/R16 stay open.

**Resumed by the owner, 2026-10-17:** the
[bounded phase diagnostics](../poc/proof-phase-diagnostics/PLAN.md) follow merged
PR #39 and its preserved [pause handoff](../poc/outer-proof-128m/STATUS-HANDOFF.md).
Only that local unfunded diagnostic package is resumed; broader private-note
implementation and TN10 integration remain deferred.
The [diagnostic result](../poc/proof-phase-diagnostics/RESULTS.md) now retains five
verified partial receipts. Before another full job, qualify the same assets on
the official CUDA proving path. The later local experiment above supplies only
recursion qualification for the original segments; the subsequent po2=19
experiment now supplies the complete proxy receipt with new segmentation.

Owner-directed priority, 2026-10-17, after the scoped
[Based App feasibility milestone](based-app-feasibility-2026-10-17.md).
The next deliverable is a reviewable private-payment specification and executable
model, followed by a minimal TN10 privacy experiment. No production architecture
or proof system is selected here; [RFC-0001](rfc/0001-state-architecture.md) remains
Open. Native KAS is the sole backing asset; there is no new privacy token.

## Local work-package checkpoint, 2026-10-17

The first [local package](../poc/shielded-design/README.md) now supplies
[RFC-0002](rfc/0002-shielded-payment.md), a visibility contract, executable model,
adversarial tests, source/reuse review and real bounded wallet-to-batch proof
composition. No funded privacy trial was run. The current recursive syscall does
not prove an invalid-operation no-op; that classifier, complete private relation,
noncircular proof-carrying payload and authenticated deposit recovery require
review before the [conditional TN10 proposal](../poc/shielded-design/TN10-PROPOSAL.md).
The model/proxy proof do not establish financial privacy or close the issues below.

The [classification follow-up](../poc/proof-classification/RESULTS.md) executes
the correct valid-invalid-valid sequence using ordinary verification of real
wallet proof bytes. It costs 870,829,938 user cycles / 880 segments; no outer
classification proof was produced. A complete proxy native operation already
uses 89.7% of the pinned block transient capacity. Compare the previously named
specialized proof route before building the full private relation around this
path. Keep real accepted-lane integration, private economics and funding gated.

The [Groth16 follow-up](../poc/groth16-comparison/RESULTS.md) produces actual
specialized 128-byte wallet proofs with the same small predicate, but the outer
classifier exceeds its 32-million-cycle budget. Next resolve the maintained
BN254 backend/budget question and produce one complete outer receipt before
expanding to the private note circuit. No new funded TN10 experiment is ready.

The [bounded accelerated backend](../poc/accelerated-bn254/RESULTS.md) now completes
the real-proof sequence at 117.47M cycles (121 segments) in its separate calibration.
It is compatible with the existing pinned VM but does not meet the 32M practical
cap; no outer proof ran. The next concrete budget decision is a declared 128M
practical experiment, retaining full adversarial controls and the one-hour proof
limit, before connecting private notes or actual native settlement.

The [approved 128M proof attempt](../poc/outer-proof-128m/RESULTS.md) completes all
24 required execution cases, then reaches the one-hour proof-job stop without a
receipt. No budget is automatically increased. Next profile actual segment
proving/recursive compression and memory behavior; the compact wallet candidate
and execution qualification remain useful. That phase's evidence is preserved;
the later po2=19 experiment above now closes the proxy outer-receipt gap.
The full private-note/native-integration gates remain open.

## First work package: define the private payment statement

Work through existing issues rather than inventing a second backlog:

| Priority | Existing issues | Concrete deliverable and completion condition |
| --- | --- | --- |
| 1: privacy and spendable notes | [P04/#4](https://github.com/olafweller/kaspa-privacy-initiative/issues/4), [P13/#13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13) | Specify which values/owners/links are hidden from chain observers, executors, provers and RPC providers. Compare established note/ownership/encryption designs, recipient spendability and delivery requirements. Include an explicit public/private data table and linkability risks at entry/exit. |
| 2: conservation and spentness | [P05/#5](https://github.com/olafweller/kaspa-privacy-initiative/issues/5), [P06/#6](https://github.com/olafweller/kaspa-privacy-initiative/issues/6) | State exact integer-sompi ranges, deposits, hidden transfers, nullifiers, pending exits, completed payouts, rent and fees. Bind proof version/domain, accepted note anchors, current spentness and actual native reserve/payout. Executable adversarial vectors must reject inflation, overflow, wrong ownership, duplicate spends within/across batches and replay across domains. |
| 3: native entry and exits | [P07/#7](https://github.com/olafweller/kaspa-privacy-initiative/issues/7), [P08/#8](https://github.com/olafweller/kaspa-privacy-initiative/issues/8), [#23](https://github.com/olafweller/kaspa-privacy-initiative/issues/23) | Map a native deposit to one private claim and an authorized spent claim to an exactly bound native payout. Keep unpaid liabilities counted. Specify user-accessible fee handling and exit data; no operator withdrawal signature or privileged rescue path. |
| 4: witness privacy, delivery and retained data | [P10/#10](https://github.com/olafweller/kaspa-privacy-initiative/issues/10), [P11/#11](https://github.com/olafweller/kaspa-privacy-initiative/issues/11), [P12/#12](https://github.com/olafweller/kaspa-privacy-initiative/issues/12), [P09/#9](https://github.com/olafweller/kaspa-privacy-initiative/issues/9) | Define how private proofs are generated without exposing another user's secrets to an executor or hosted prover. Inventory commitments, spentness, ciphertexts, accepted updates, witnesses and user backups. Specify complete discovery and safe handling of missing/corrupt data; identify a falsifiable later independent recovery test. |

These are coupled requirements, not four isolated implementations. Public-account
balances cannot be made into a private payment protocol merely by encrypting a
JSON file or putting their existing execution inside a ZK VM. Public payloads,
resource identifiers, fee inputs, timing and note retrieval can still reveal the
payment graph. A service that receives plaintext witnesses is within the privacy
threat model even if the resulting on-chain proof reveals less.

## Reuse and comparison before implementation

The [Phase 1 comparison](../research/phase1-source-review-2026-10-08.md) and its
[Orchard](../research/zcash-orchard.md), [Aztec](../research/aztec.md),
[RAILGUN](../research/railgun.md), [Monero](../research/monero.md) and
[MWEB](../research/litecoin-mweb.md) notes are the starting point. Refresh exact
upstream state and the [existing Kaspa privacy inventory](../research/existing-kaspa-privacy.md)
before selecting constructions; the prior source reviews are dated evidence.
Record reused components, required adaptations, rejected alternatives, license
constraints and assumptions. Do not invent new cryptographic primitives.

Use the tested Based App ordering, recursive proof and native bridge path as a
candidate backend. Keep Candidate A as a comparison for cost, native bindings
and witness/recovery needs. A single logical privacy domain is the initial
comparison workload; add sharding, a full runtime or operator network only when
measurements or an explicit requirement justify it. A note/nullifier or settlement
design decision requires RFC review and an ADR before substantial cryptographic
implementation, with [all invariants](../SECURITY-INVARIANTS.md) preserved.

## Next experiment's falsifiable target

After reviewing that statement/model, the minimal experiment should demonstrate:

```text
native test-KAS deposit
-> recipient-spendable private claim
-> private value-conserving transfer to another user
-> deterministic duplicate-spend rejection
-> authorized exit claim with backing preserved
-> confirmed native test-KAS payout
```

It must use real proofs with pinned identities and disabled development mode.
Report the exact number of users/notes, public observations, hidden witnesses,
proof time/memory/fees and every unpaid liability. Include unauthorized spend,
wrong-root, overflow/inflation, same-note duplicate, cross-domain replay,
recipient substitution, malformed proof and underpaid/diverted payout controls.
Neither encrypted transport nor a hidden amount alone establishes payment
unlinkability; report residual timing/amount/network/service correlations.

This work package does not require building an independent operator network now.
It does require specifying the data and user secrets needed to replace services.
The [N-user shutdown and exit gate](ROADMAP.md#early-exit-and-recovery-gate) stays
mandatory before treating an architecture as credible. Same-node replay does
not satisfy it, and private transfers do not excuse an unavailable exit.

## What counts as progress now

The immediate artifact is the reviewed statement, threat/data table, reuse map
and adversarial model linked to P04/P05/P06/P07/P08/P10/P12/P13. Only then build
the smallest testnet private lifecycle that can falsify those requirements.
Further public-account runtime expansion is secondary to a demonstrated private
protocol requirement. Existing issues remain open until their own acceptance
criteria are met; completing the Based App milestone closes none by implication.
