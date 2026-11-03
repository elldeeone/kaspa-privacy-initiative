# RFC-0029: Local one-input, two-output native KAS private transfer

**Status:** [ADR-0066](../adr/0066-local-native-kas-payment-prototype.md) completed the bounded TN 10 financial lifecycle; the 2% fee target failed and financial privacy/external availability remain unqualified.
**Date:** 2026-10-25 UTC.
**Reference:** [RFC-0028](0028-sender-private-native-kas.md) and
[ADR-0065](../adr/0065-sender-private-admission.md), baseline
`2e56d8a10fde5c998dde3bac3c7070c9d36f6827`.

Implementation uses a separate fresh domain/profile under ADR-0066. Existing
funded pools and the frozen benchmark remain unchanged. All
[security invariants](../../SECURITY-INVARIANTS.md) remain in force. Native KAS
is the asset; research/testnet only, no real funds or privileged withdrawal path.

## Question and evidence

Can one wallet create a complete private payment from one owned note, without
recruiting other live owners, while retaining verifiable native backing,
received-note/change recovery and an independent exit?

The existing three-owner construction exposes stable NFs before authorization.
The external bounded MPC wire diagnostic found changed-cohort ownership
intersection; it did not establish financial acceptance or confirmed payouts.
The source-only [options review](../../research/next-session/sender-private-lifecycle/review/RETRY-PRIVACY-OPTIONS.md)
is the immediate input, SHA256
`0317207eada187eac12cc6d90900f649f4db270d3d47152a04f5788282f38846`.
It explains why valid proofs and fair MPC output still do not ensure settlement:
a competing independent exit can consume the shared reserve outpoint first,
leaving disclosed honest NFs unspent. No new active experiment is proposed here.

The proposal removes mandatory multi-owner admission/authorization from an
ordinary payment. It does **not** hide a submission endpoint or eliminate shared
reserve contention. A public transaction still groups one NF with two outputs.

The [actual result](../checkpoints/2026-10-27.md)
answers the functional lifecycle question withsix payments, nine payouts, zero reserve and three cold scans and 19-case Native
accounting. It does not remove the grouping or constructor privacy limits.

## Existing work and alternatives

The [source review](../../research/next-session/sender-private-lifecycle/SOURCES.md)
records current Kaspa/Toccata/vProgs/research and Orchard, Aztec, RAILGUN, Monero
and MWEB. This proposal reuses their separation of hidden ownership, public
single-spend markers, recipient discovery and exact authorization; it imports no
new primitive or runtime. No demonstrated requirement for vProgs follows yet.

| Candidate | Reuse and decisive limitation |
| --- | --- |
| **Local 1-input/2-output payment** | Keep established note, NF, commitment, encryption and per-note proof semantics; change aggregate shape, guest/profile and native policy. No other live owner is required. Shared-head retries, network origin and proving cost remain. |
| Local 3-input/6-output self-spend | Could retain current aggregate shape and component keys if D stays fixed. Requires three eligible notes owned by that wallet; one initial note does not suffice. It does not create three-party anonymity. |
| Hidden construction plus valid-proof gate and fair MPC | Might retain current financial statements, but needs secret indexed-tree/hash computation, authenticated owner consent and genuine proof validation before opening. Fair delivery alone does not resolve competing exits or reorgs. |
| Fixed cohort/no retry | Can restrict a particular overlap channel under explicit membership assumptions. Sybils, peer loss and seed-only recovery remain; permanent note locks or mandatory transparent exits are not a free privacy remedy. |

The pinned [Orchard builder](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L901)
provides an established local-builder comparison: owned notes, recipient
addresses and membership paths suffice without other live spending owners.
Its historical anchors and chain-wide NF rules do not remove this prototype's
additional exact reserve-outpoint binding. The pinned
[WabiSabi protocol](https://github.com/WalletWasabi/WabiSabi/blob/1e6deb989f58bc6edce91bc300252d2bed18db30/protocol.md#attacks-on-privacy)
explicitly leaves targeted denial/intersection mitigation outside its admission
protocol. [MP-SPDZ's security model](https://mp-spdz.readthedocs.io/en/latest/readme.html#protocols)
does not itself promise fair output or chain settlement.

## Proposed validator and owner-consent contract

The following is a contract to review, not permission to reinterpret old bytes.
Use a separately versioned codec/profile. Old 3/6 payloads, sessions and policy
must fail under the candidate parser, and candidate payloads under the old one.

| Boundary | Required candidate behavior and current reference |
| --- | --- |
| Body shape | Exactly **one NF32/CV64**, **two complete Output520 tuples**, **one indexed-NF insertion witness1160**, **two CM append paths512**, and **one Spend proof128**. No zero/dummy input or output. Current fixed 3/6 framing: [wire.py:168](../../poc/owner-private-lifecycle/verification/wire.py#L168). |
| Public context | Fresh action ID, selected D/profile, current accepted reserve outpoint, old/new CM and NF roots/counts, reserve amounts, explicit fee, zero native payout, aggregate blinding Delta. No participant roster, owner label or MPC session is needed. |
| Native effects | Consume the actual selected current reserve UTXO; create exactly one same-policy continuing reserve output. Require `new_reserve + fee == old_reserve`, bounded positive fee and reserve, and zero public payout. Check actual whole transaction/context, including witness and budget, not merely txid or a host flag. Current branch: [policy.rs:267](../../poc/owner-private-lifecycle/verification/native/src/policy.rs#L267). |
| State | One distinct nonzero original NF, absent from accepted NF state; indexed predecessor replacement plus empty append; `NF_count += 1`. Two distinct nonempty output CMs, empty-slot append paths; `CM_count += 2`. Preserve tree capacities and accepted occupied-prefix invariant. Current insertion: [wire.py:65](../../poc/owner-private-lifecycle/verification/wire.py#L65). |
| Component proofs | Verify one genuine Spend200 and two genuine Output168 statements using externally selected matching VKs, strict point/scalar/proof codecs and subgroup checks. Spend binds D, prior CM root, own NF/CV and the complete effects digest. Output binds D, CM, CV and exact CF hash. Current [statements](../../poc/owner-private-lifecycle/relation/src/statements.rs#L15) and [circuit](../../poc/owner-private-lifecycle/relation/src/circuit.rs#L129). |
| Conservation | Integer sompi only. `v_in = v_payment + v_change + fee`; both output values obey the existing positive note range. Check `CV_in - CV_payment - CV_change - fee*V == Delta*R` with canonical subgroup scalar Delta. Native reserve fees and private-value fees must be the same amount. |
| Effects/proof binding | Hash the canonical complete native prefix and body core, including both full output tuples/proofs, roots, paths, fee and policy. Exclude only the final Spend proof bytes to avoid self-reference. Reconstruct this digest independently in the verifier. Existing pattern: [effects_digest](../../poc/owner-private-lifecycle/verification/wire.py#L219). |
| Final authority | An adapted outer guest verifies all components, state transitions and balance, and emits a profile/domain/projection-bound journal. Native policy verifies the selected new image/proof and actual consumed effects. Component success alone is not accepted native backing or settlement. |

For sizing review only, retaining the current 436-byte fixed header footprint,
with the old roster field **reserved zero under the new codec**, yields a
3,756-byte core and 3,884-byte body. This is serialization arithmetic, not an
implemented format or fee estimate. The action ID replaces round coordination;
no old MPC session is accepted as a candidate authorization context. Exact
version tags/header choice remain an ADR question.

Before generating its Spend proof, the wallet must independently reconstruct
the accepted head, identify its exact unspent note/position, and validate the
selected immutable successor policy and fee. It creates and locally checks both
complete output tuples, authenticates the requested recipient invoice, checks
its change receipt/keys, integer conservation, state paths and exact effects.
The recipient output and change must each occur exactly once. A remote prover
may receive public components only; any private-witness delegation needs a
separate explicit trust decision. Current safety checks at
[worker.py:411–454](../../poc/sender-private-lifecycle/wallet/worker.py#L411)
are obligations to preserve, not checks to remove with MPC.

The two-output minimum means `v_in >= 2*NOTE_FLOOR + fee`. An exact full-note
cashout uses the independent exit path. This proposal does not assume zero
change, a dummy note or smaller note floors under the existing component keys.

## Domain, proof identity and recovery compatibility

ADR-66 implemented the fresh domain/profile, refreshed Spend/Output/Exit keys,
KPXA 1/2 codec, outer guest and direct-exit policy. The
[current terminal/public evidence](../checkpoints/2026-10-27.md)
records its selected identity and accepted history; old funded notes/backups
were not migrated. D remains a compiled constant in the
[selected relation](../../poc/local-private-payment/relation/src/lib.rs). A future
D/predicate change requires corresponding circuit/key/manifest review; changing
JSON alone is invalid and per-note key reuse is never inferred silently.

Keep the established Receipt216/Note168 and sealed-box adapter. The
[receiver](../../poc/future-recipient/v2/recipient.py#L202) derives indexed owner/NF
keys and a domain-stable delivery key from the original seed. Receipt216 carries
its index inside CF264, so [open](../../poc/future-recipient/v2/recipient.py#L231)
can recover the descriptor before deriving indexed spend keys. The receiver
need not be online when the sender uses an already authenticated public invoice.
Sealed encryption is neither invoice authentication nor proof of accepted backing.

Scan complete authenticated public output history locally, decrypt with the
original seed, check descriptor/domain, CM, Output proof, accepted position and
spent-NF status, then derive ordinary Spend/Exit authority. Received payment and
change must both be recoverable/spendable without a roster, live peer, private
coordinator map, attempt journal or saved invoice-index lookahead. A convenience
"change" label must not determine spendability; the label/index convention is
open. Never send scan indices or view keys to a remote server. The stable delivery
PK in invoices can link invoices to a party that sees them; confidential invoice
handling and authenticated recipient selection remain explicit assumptions.

Retain a direct full-note Exit152 proof path consuming the **candidate** current
head, updating NF state and binding exact payout/fee/destination. It must not
require MPC, another owner or the shared outer prover. New policy/domain/exit VK
and original-seed recovery software must agree; old cold adapters are not assumed
compatible. Preserve terminal zero reserve and no owner-indexed public recovery
records. Public software/parameters/history availability remains necessary;
separately administered retention and actual off-host recovery remain unproven.

## Privacy, retries and proving cost

Ledger target: hide which existing note commitment a valid NF consumes and hide
note values/recipient descriptors under established proof/encryption assumptions.
The transaction exposes one NF, two complete output tuples, state changes, fees,
reserve movement and timing. It explicitly links those two outputs to that
transaction. Removing three-owner input admissions does not remove this grouping.
There are only **two output candidates**, compared with the present joint six;
this proposal cannot claim a better NF-to-payment-CM score under the frozen
experiment. Its promising difference is removal of a compulsory identifiable
live-owner cohort, combined with note-CM-to-NF unlinkability and a separately
specified anonymous ingress. These are different privacy surfaces. Any future
measurement needs prospectively selected observers/criteria; it must not rewrite
the old metric or turn its result into a pass for this architecture.

No other honest spending owner is required for this wallet's proof. However,
an authenticated coordinator that sees the origin of a local request knows the
owner of its single NF. Anonymous ingress, timing/counterparty correlation and
malicious prover observations require a separate observer model and design; this
RFC claims no network-origin anonymity or complete financial privacy.

An unrelated payment/exit can move the shared head during proving. Reject the
stale case, replay accepted state, reconcile its NF and rebuild effects/proofs
when the note remains unspent. A reorg requires the same reconciliation against
the new accepted history; a dropped successor is not a confirmed payment. An
exposed NF can remain unspent after conflict. Local construction removes the
need to change a multi-owner cohort, but it does not prove that repeated
submission is unlinkable, guarantee inclusion or make cached authorizations
valid for a new outpoint. Do not solve this with a permanent private note lock
or a privileged delay of independent exits.

The source-only [current alternatives](../../research/next-session/local-private-payment/privacy-next/direct-native-composition-01/SOURCE-ASSESSMENT-01.md)
retain signature-gadget/MPC/authority gaps and choose no architecture.

Two proving options remain open: first adapt the existing outer guest for
reuse/equivalence; later compare one established Groth16 relation expressing
Spend+two Outputs+state update+balance directly, avoiding in-guest component-proof
verification. The latter is a new circuit/setup/review and financial-identity
decision, not a new cryptographic primitive or a selected optimization. The
existing 3/6 baseline used 514,472,398 user cycles and about 33 minutes of GPU
proving; [component evidence](../../research/next-session/sender-private-lifecycle/components/COMPONENT-WORLD-01.json)
and [unfunded native qualification](../../research/next-session/sender-private-lifecycle/components/MIXED-NATIVE-01.json)
do not measure 1/2 performance. No speed or fee reduction is assumed.

The frozen 21-KAS workload's **2% all-in fee target remains FAIL**. Do not replace
its denominator, count change as demand or convert a quote into paid savings.
A matched comparison needs the same useful payments, deposits, repeated spends
and nine exits; six singleton payments can require more native proofs than two
three-owner batches. The native Groth16 verification cost floor remains even if
proving is faster. Fee feasibility and privacy feasibility are separate verdicts.

## Original prospective experiment and stop criteria

Before implementation, resolve domain/profile, exact codec, consent and exit
compatibility in review/ADR. Then prospectively freeze **public synthetic
fixtures only**, exact sources/expected bytes and the following decisions:

1. Independently construct one local 1/2 projection from a public occupied CM/NF
   state. Require byte-exact agreement between independent codec/reference/native
   reconstructions of state, effects, conservation and journal. Compare per-note
   statement semantics with the existing predicate; never compare unequal 3/6
   and 1/2 transactions as identical native effects.
2. Require genuine selected component/outer proofs and Native Full/all-input
   checks before claiming execution. Include malformed/truncated/extra records,
   bool/float/overflow amounts, floor/capacity boundaries, duplicate/zero NFs/CMs,
   bad subgroup/proof/scalar encodings, wrong paths/roots/D/profile/guest/tail,
   substituted payment/change/CF/fee/outpoint and cross-state/pool replay.
   At the model/reference boundary, include two otherwise valid conflicting
   current-head transitions and a supplied reorg history: at most one successor
   is accepted, the losing authorization is stale and reconciliation preserves
   unspent claims. This is not an active deanonymization reproduction.
3. Restore an original **public fixture seed** using only authenticated public
   history/software, discover received and change notes, spend each without live
   other owners, then independently exit and reconcile zero terminal reserve.
   Keep supplied-context results distinct from actual testnet confirmations.
   Record cycles, wall time, RAM/VRAM, proof bytes and native mass/paid fee without
   projecting a new cost claim from the old 3/6 result.

Stop and retain the negative result if any safety/control mismatch appears,
spendability depends on a roster/private journal, or the honest path requires
another owner's secret/online authorization. Resource exhaustion means incomplete
execution, never a privacy pass. Do not tune failed fixtures, weaken checks,
fund/broadcast, or launch an active retry experiment under this proposal. An
accepted public-fixture implementation would justify a separate testnet plan;
it would not qualify privacy or authorize mainnet use.

## Open decisions

1. Is this local transaction's explicit 1-to-2 public grouping acceptable under
   the required ledger observer, and which anonymous submission assumptions are
   realistically supportable?
2. The implemented ADR-66 profile uses its selected freshD/keys/codec/exit
   policy. A successor or migration requires its own reviewed identity decision.
3. Can shared-head contention and proof latency support useful repeated payments
   without weakening current-state binding or independent recovery? Compare the
   adapted outer guest against a reviewed direct relation before making a cost
   claim; reusable intents/historical anchors need their own authorization RFC.

**Outcome:** ADR-0066 selects the bounded candidate for research implementation.
Current native settlement/recovery and fee outcomes are linked below. Privacy
and successor cost/authority decisions remain open; selection alone resolves none.


### Actual operational outcome (2026-10-27)

[ADR-0067](../adr/0067-authenticated-local-prefix-reuse.md) cached/full comparison
and [ADR-0073](../adr/0073-shared-baseline-peer-acquisition.md) shared-baseline
acquisition succeeded through the final exact CASE 15 confirmation. One prepared
common prefix and lawful boundary clipping/recompression preserve the 13 financial
sources and full import/reorg/current-UTXO/native checks. The seven-source
sidecar grants no reserve-release or external cache authority.

The [current result](../checkpoints/2026-10-27.md)
contains six payments, nine confirmed native exits, zero reserve/null outpoint,
three Original cold scans and 19-case independent Native Full accounting. All-in
fees are 264,166,000 sompi on 2,100,000,000 useful sompi (about 12.5793%);2% FAIL remains.
Even free payments leave 148,795,600 sompi for exits/GEN3/prefunding, so payment
proof savings alone cannot meet the 42,000,000 sompi lifecycle budget.

The same frozen public ledger/policies yield 68,040 exact-economic forests/24
partitions,6480 known-workload forests/24, and 72 source-policy schedules/3 actor
masks with conditional exits 4/5 predictions. Neither economic comparator adds a
forced ancestry relation. There is no owner-truth accuracy, posterior or privacy
PASS; honest selected-source execution/input-order is an assumption. The old
singleton-GEN3 adapter failure is preserved before the reviewed 21-control fix.

### Bounded successor work and publication (2026-10-27)

49/29 consent/aggregate checks,42 canonical-encoding controls and 15 one-Output
matrix controls preserve their narrow scopes. The matrix gate checks one actual
NativeOutput relation plus two digest links, not multiple-circuit aggregation,
setup/proofs, MPC, native batch acceptance or cheaper/private payments.
The [recursive qualification contract](../../research/next-session/local-private-payment/privacy-next/native-batch-exception-contract-01/ONE-OUTPUT-QUALIFICATION-CONTRACT-01.md)
and [direct Native alternative](../../research/next-session/local-private-payment/privacy-next/direct-native-composition-01/SOURCE-ASSESSMENT-01.md)
select no architecture. Keep signature-gadget/full-witness/authority and delivery
gaps explicit; do not weaken funds checks through secret-sharing substitutions.

The old offline RPC qualification is historical; later actual terminal evidence
is separate. The JSON fallback remains held. FinalDATA all 9 Original canaries,
global supplemental completion and public Tor readback remain pending at this
source freeze. Same-host recovery and one-admin hosting do not establish off-host
seed recovery, independent retention or a second public origin.
