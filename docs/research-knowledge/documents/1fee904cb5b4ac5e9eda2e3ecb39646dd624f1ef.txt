# Asynchronous payments without public owner partitions

**Proposed RFC/design memo, 2026-10-26. Research only; no architecture selected.**

**Answer:** the smallest plausible established construction is owner-local
restricted-intent proofs, private inputs to a fixed threshold MPC service, and a
public zero-knowledge proof of the **hidden partition** of all batch inputs and
outputs. Ordinary aggregation exposes the partition to its constructor. Fixed
MPC servers can replace simultaneous wallet attendance, but do **not** solve
active known-cohort abort/retry intersection or guarantee chain inclusion.
Under that stronger adversary, the complete requirement remains unresolved.
Resolve that failure in a finite information-flow model before new cryptography.

This memo changes no selected protocol, observer, keys, circuits or live files.
It reads no original seed, private state, owner log or world truth. It makes no
current lifecycle-completion claim. Current KPXA 1×2 is not qualified privacy;
neither old passive results nor the separate MASCOT component study qualify this
native design. The changed-cohort finding remains bounded synthetic evidence.

## Scope and observer

Native KAS remains the asset. Preserve [I-1–I-16](../../../../SECURITY-INVARIANTS.md),
original-seed independent direct exits, noninteractive receiving, and current
native authorization. No new token, admin escape or resident-balance policy.
This is a proposed successor to [RFC-0029](../../../../docs/rfc/0029-local-native-kas-private-transfer.md)
and [ADR-0066](../../../../docs/adr/0066-local-native-kas-payment-prototype.md),
not an extension interpreted into their existing proof bytes.

Freeze two distinct observers:

* **O-ledger:** complete public transaction/mempool and accepted/reorg history,
  output ciphertexts, NFs, CVs, fees, shapes, timing and transparent exits.
* **O-active:** O-ledger plus the dispatcher, one corrupted server of a proposed
  three-server honest-majority service, one colluding wallet, and known ingress
  owner/cohort/session metadata. It can delay proposals, withhold its messages,
  inject invalid intents and race its own independent exit. It cannot break
  cryptography or read honest owners/servers. Traffic observation outside those
  endpoints, two corrupted servers, compromised wallets, recipient disclosure,
  and amount/counterparty auxiliary information are separate stronger models.

“Hide the map” means both (a) no public per-payment `NF → {CM0, CM1}` partition
and (b) no such map available to the allowed coordinator/server coalition.
Hiding the historical consumed CM behind an NF is a different property.
A batch still publicly groups its entire NF set with its entire output set.
At least two honest unknown payers are necessary after colluder subtraction;
batch size alone cannot establish that condition against Sybils.

## Three candidates

| Candidate | Wallet attendance and coordinator knowledge | Verdict |
| --- | --- | --- |
| Ordinary asynchronous proof/intention queue | Owners export once. Batcher sees each NF, its exact two output tuples and individual balance data. | Useful cost/liveness comparison; fails coordinator-map privacy even if the ledger sees one large batch. |
| **Fixed threshold private-intent service plus hidden-partition proof** | Each owner finishes its own input submission, then may leave. Servers jointly process persistent secret shares; no allowed coalition reconstructs the map. | Smallest conditional candidate for these two structural leaks. New consent, hidden-statement proving and retry contract; no end-to-end qualification. |
| Owner-interactive hidden construction and final whole-effects authorization | Owners participate again when final head/membership changes; construction/proving must also hide private maps. | Can retain whole-effects authorization semantics, but fails the no-simultaneous-wallet-dependency requirement for ordinary settlement/retry. |

The [existing batching memo](../proving/ASYNCHRONOUS-BATCHING-01.md) already
identifies ordinary queue map leakage and the new durable-intent requirement.
The [direct-proof memo](../proving/DIRECT-GROTH16-FEASIBILITY-01.md) is a proving
comparison, not a hidden batch constructor. The
[outbox memo](../proving/OUTBOX-EXIT-FEASIBILITY-01.md) distinguishes accepted
liabilities from proposed messages; an unaccepted queue is not an outbox claim.

## Conditional threshold candidate: exact boundaries

Use three separately administered servers, privacy against at most one corrupt
server, authenticated encrypted channels, and an established malicious-security
MPC composition. This is a proposed trust threshold, not existing deployment.
Two servers can reconstruct a 2-of-3 sharing: **privacy then fails**, including
archived submissions unless a separately justified erasure/refresh model applies.
Proof soundness/native policy, not the server threshold, must still prevent
theft when all servers collude. No server signature releases reserve KAS.

The owner keeps seed, NF/spend keys, note opening and private Merkle witness
local. It authenticates the invoice, constructs both encrypted output tuples,
validates recipient value and recoverable change, then proves a new restricted
intent. Its immutable authorization binds:

1. chain/genesis, authenticated pool lineage, fresh profile/domain/role and
   selected immutable successor/exit policy;
2. historical membership anchor/root/count, original positioned NF and CVin;
3. exactly two complete approved output tuples, their exact descriptors/value
   commitments/ciphertexts, a unique intent nonce, and exact integer `fee_i`;
4. private per-intent conservation and canonical `Delta_i`, explicit permitted
   anchor/head evolution, and validity/cancellation semantics.

The proof must establish the same note ownership/membership/NF and bounded
integer-value predicates as the selected design, plus restricted consent and
per-intent conservation. A hash of arbitrary tuples or a global balanced sum is
insufficient. The owner authorizes the exact payment/change set, but explicitly
allows the batch to permute those complete tuples globally. The current local
wallet's exact two-row ordering rule cannot silently be reinterpreted this way.

For the minimum durable-intent comparison, fees are exact and there is no
batcher tip/refund/output discretion. Require, with checked sompi sums:

```text
for every intent: v_in_i = v_pay_i + v_change_i + fee_i
actual native fee = sum(fee_i)
new reserve + actual native fee = old reserve; native payout = 0
```

The final relation privately verifies each genuine owner proof and its hidden
statement, proves a bijection between approved intent fields and the public NF
and output multisets, enforces each output exactly once, and checks distinct
unspent NFs, state updates and capacities against actual accepted current state.
It binds full native effects, current reserve outpoint and selected policy.
Historical anchors need authenticated accepted-prefix consistency or a reviewed
anchor-history state rule. A coordinator's root/genesis label supplies neither.

**Public output:** independently ordered `(NF, CVin)` rows and complete output
tuples, genuine per-output proofs if retained, aggregate fee, optional aggregate
Delta, state/update data and one final proof. No pair index, owner/intent ID,
per-intent proof/statement digest, fee-to-NF allocation, `Delta_i`, or upload
handle may accompany the public rows. All output encryption metadata must be
included in the same field audit. Only total Delta may be public: publishing
individual Delta allows observers to test candidate output pairs against each
input CV balance equation and recover the very partition being hidden.

**Prover privacy is mandatory:** shuffling through MPC and then giving the
per-intent witnesses to a normal outer prover leaks the map. The final proof
must be collaboratively generated over shared witnesses, or use another reviewed
established private-proving construction. Current public R0 aggregation does not
provide this. Verifying hidden inner Groth16 statements inside another circuit,
and privately producing that outer proof, can be expensive; no speed claim is
made. Output proofs alone do not prove the hidden input/output correspondence.

MP-SPDZ has established external-client private input and honest-majority
protocols, but its [current client](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/ExternalIO/client.py#L43-L129)
connects to all servers, receives masks/triples and identifies a TLS client.
That is evidence for owners submitting at different times, **not** an existing
one-message durable encrypted mailbox or anonymous ingress. Asynchronous
storage, share consistency/authentication and later MPC input admission need a
selected established protocol. No post-submission owner consent may be needed
merely to choose peers or refresh a permitted head. Requiring servers online
during each owner's short input session is a distinct availability assumption.

### Collaborative-proof source gate

Ozdemir–Boneh, [USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/ozdemir),
pp.4291–4308, establishes collaborative proof generation over distributed
witnesses; its abstract is the inspected evidence here, not a performance model.

Garg, Goel, Jain, Roberts and Sekar,
[**Malicious Security in Collaborative zk-SNARKs: More than Meets the Eye**](https://eprint.iacr.org/2025/1026),
CRYPTO 2025, publisher pp.396–428, provides a required caution. Inspected primary
ePrint indexed excerpts: §4.1.1, ePrint pp.18–19, requires extended-witness
validity before collaborative Groth16 proving, even with honest majority;
§4.1.2 p.20 concerns consistency between witness extension and proof generation;
§4.2 p.21 concerns releases during reactive computation. §5 begins p.22 and
presupposes a valid combined witness and mitigation of the first pitfall.
Select and map the exact construction, sharing model, corruption threshold and
every intermediate release/check before implementation. Direct PDF fetch was
403; publisher abstract/metadata and primary indexed excerpts were available.
**This is not full-paper verification, a claim that every compiler is broken,
or a finding against current MASCOT.** No mitigation is treated as implemented.

## Who sees what, and when

| Boundary | NF and output mapping | Recipient/value | Network/session linkage |
| --- | --- | --- | --- |
| Owner before submission | Own NF, both tuples and relation | Own input/payment/change and authenticated invoice | Its own connections |
| One server/dispatcher before release | Opaque shares; no NF/CM/individual-Delta plaintext under the selected input protocol | No plaintext invoice/value; lengths must have one fixed format | Client endpoint/certificate, upload handle, arrival time and queue membership may be known |
| Threshold collective, kept inside MPC | Computes with secret-shared NF, tuples, authorization and partition | Opens no value, key or descriptor | Honest parties must reject metadata/row tagging; no public handle-to-row output |
| Final proof/transaction egress, **before confirmation** | Stable NF set and complete CM/CF set become public, without intended per-payment partition | Ciphertexts, CVs and total fee; parties know their own receipts | Observer can associate released set with known queue/cohort/timing |
| Accepted history and seed-only recovery | Public state/NFs/outputs; owner locally finds its receipts and positioned spend authority | Owner decrypts locally; transparent direct Exit exposes its native payout | Remote scan indices/view keys are never required; traffic correlation remains |

The public release is transaction **egress**, not acceptance. A proof gate checks
validity; it does not make release and accepted settlement atomic. Size padding,
Tor/TLS and random handles do not erase known cohort/timing information.

## Decisive abort/retry limitation

Consider a batch with honest queued intents A and B and colluder C. Its complete
valid proof/transaction leaves MPC and reveals stable NFs. C independently
exits its own input first against the current head. The batch is stale or now
contains a spent NF. Native checks correctly reject it. A and B remain unspent.
The dispatcher next proposes batches containing surviving honest intents but
different known owner cohorts. Intersections of their released NF sets can
identify an honest owner. Fixed **server** membership does not fix these owner
cohorts. Fair MPC output delivery does not undo the disclosure or settle a
transaction whose reserve input/NF has lost a race. Reorgs add another case.

A persistent honest-majority queue can refuse coordinator-chosen omissions and
retry the same complete released NF/output set after harmless head movement.
That is useful only while every input remains eligible. Once C spends, the
original complete batch cannot settle. No safe check permits retaining C's
spent input. Removing it, admitting replacements or moving A/B to another
service creates a new cohort and needs fresh analysis.

There is **no claimed resolution** under O-active. The available tradeoffs are:

* constrain cohort/admission observations and adversarial scheduling, and state
  a conditional privacy claim with persistent honest covering demand;
* design a separately reviewed **accepted** reservation/continuation state that
  consumes authority and preserves recoverable liabilities before later work;
  specify its own disclosure race, cancellation, native exits, fees and reorgs;
* accept lost private-payment progress or this retry leakage after disclosure.

A local never-retry flag, fixed aliases, always-online-wallet requirement,
operator freeze of direct exits, or an unaccepted “reservation” is not a remedy.
No bound on private settlement latency can coexist with guaranteed multi-owner
mixing when only one honest owner has demand or adversarial Sybils supply every
other input. This memo does not establish a general cryptographic impossibility
theorem; it identifies a concrete counterexample to the proposed composition.

## Independent exit, recovery and service loss

The queue is not a debit, note lock or accepted payment. Until accepted NF
consumption, the original owner can take the direct Exit path. With competing
valid intents/Exit, first accepted consumption wins; there is no local
revocation flag. The minimum intent has no implicit wall-clock expiry. Any
expiry needs authenticated enforceable consensus context and a new rule.

After acceptance, original seed plus complete authenticated public history,
public software/parameters and output ciphertexts must recover received/change
notes, their positions, witnesses and direct Exit authority. Keep Receipt216's
encrypted index/local scan pattern. Individual output proofs may remain public
because they bind only an output; otherwise recovery must verify the retained
complete batch seal. Neither scan needs the hidden partition, pending-intent
journal, another owner's key or MPC shares. A fresh domain requires matching
Output/Intent/Exit parameters and profile identities; current proof bytes are
not silently compatible and no old notes are migrated.

If all servers vanish before acceptance, direct exits retain their existing
costs and current-state reconstruction requirements. After acceptance, missing
CF/history/tree data cannot be repaired by a root alone. Acceptance must bind
the complete recoverable public data; separately administered retention remains
an availability assumption, not a fact established here. Servers may censor or
abort private batching; they must not obtain withdrawal authority or make direct
exits depend on them. Seed recovery restores funds authority, not forgotten
off-chain disclosure history or automatic private retry anonymity.

## Reuse and primary-source refresh

Local source inspection: worktree `research/shielded-kas-feasibility`, HEAD
`62dea77f44da44820971ded88d674f0243df8913`; these current files may include
uncommitted work. Guarded reads verified
[Spend200](../../../../poc/local-private-payment/relation/src/statements.rs#L15-L64),
[exact wallet consent](../../../../poc/local-private-payment/wallet/payment.py#L114-L175),
[whole-effects verification](../../../../poc/local-private-payment/verification/common/src/lib.rs#L222-L252),
and [seed/index recovery](../../../../poc/future-recipient/v2/recipient.py#L202-L249).
Reuse their established predicates/codecs and adversarial obligations;
**Spend200 binds actual complete effects and cannot be repacked unchanged.**
New work includes intent statement/circuit/setup, historical-anchor/lineage
rules, private input/queue protocol, hidden-partition relation/private prover,
aggregate/native policy and recovery/profile review. None is implemented here.

Exact guarded SHA256 identities for those four inspected public files, in the
same order: `bcd3f5f947904fe6fecc4e747b93e0f85a5c611390d0331651e3a1884004e123`,
`5ff0774fd1bb67ebc5ed5ec246ce2434082bfc4ce82dad9e58047b34232d2bda`,
`949452a43d9db837067a818e09f9660bf5f6ff9a3adac82094120e532aca6d5d`,
`93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2`.

Official default heads were refreshed read-only on 2026-10-26. The following
specific source contracts were inspected; commits are source pins, not claims
about deployed/audited versions:

| Primary source | Reuse / rejected inference |
| --- | --- |
| [Orchard builder](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L1320-L1514) and [Action](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/action.rs#L15-L37); Zcash specification head `2bdf39494320e5e04057ac93b1794031ebfb00b5` | Local construction and spend/output randomization are established. The complete constructor still knows its supplied inputs/outputs; Action formatting is not coordinator-map hiding. No Orchard circuit/key port. |
| [Aztec TxEffect](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/noir-projects/fnd/noir-protocol-circuits/crates/types/src/blob_data/tx_effect.nr#L21-L33) and [private effect builder](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/noir-projects/fnd/noir-protocol-circuits/crates/rollup-lib/src/tx_base/components/private_tx_effect_builder.nr#L73-L99) | Proven private execution still emits transaction-scoped note hashes/nullifiers/logs. Aggregating those transactions does not automatically hide their partitions. No whole rollup/runtime import. |
| [RAILGUN validation and accumulation](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol#L420-L535) | Reuse historical-root checking, proof-bound effects and current nullification. Public per-Transaction arrays remain identifiable inside a submitted batch; no relayer-map anonymity inference or admin model import. |
| [Monero verification](https://github.com/monero-project/monero/blob/3fd0f88c20f559839cafb20911cb13cb45eba7bd/src/cryptonote_core/tx_verification_utils.cpp#L56-L151) | Linkable spend markers must agree with verified input signatures/commitments. Hidden historical input selection is distinct from hiding an entire transaction's output grouping. No ring-signature redesign. |
| [MWEB LIP-4](https://github.com/litecoin-project/lips/blob/73cb2a6cea05b3891e7986ca215e7ccf4a49cb41/lip-0004.mediawiki#L138-L168) and [local light-client scanning](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md) | Noninteractive receiving and public aggregation are relevant analogues. A merger that receives pre-merge transactions can retain their map; view-key filtering reveals owned outputs/value. No Mimblewimble consensus or horizon assumptions imported. |
| [Kaspa inline ZK](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx#L25-L70), [KIP-20](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0020.md), rusty-kaspa `4edcbbccb449f84832afb1ca157904b35f37d006` | Exact program/VK/state and actual successor effects remain mandatory; no native primitive alone supplies private construction, atomic egress or inclusion. No proof-format modification is assumed. |
| [vProgs prototype](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md#L5-L7), [research architecture](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex#L120-L137) and [state-layout guide](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx#L114-L157) | Shared-state batching may motivate a based-app runtime. The sources do not establish necessity or dispensability for this minimum candidate, nor supply anonymous private intent admission. |
| [MP-SPDZ protocol models](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/README.md#L822-L941) | Established three-party malicious honest-majority processing is available as a building-block family. Encrypted channels and exact corruption assumptions matter; no fair-output/settlement or private-proof composition claim follows. Its README explicitly disclaims having undergone production security review. |

Read-only upstream downloads were inspected through the unchanged guarded
reader; temporary public caches live under `/var/tmp/kpi-async-design-20261026/`.
No external chat content was used. No original/world files were read or hashed.

## Frozen smallest next falsification — NOT EXECUTED

**Gate:** independent source/design review of this memo first. This freeze
authorizes no execution; a later task must explicitly select the model/run.
Use public fictional records only, no wallet, prover, MPC binary, GPU, network
experiment, funding or broadcast. Cryptographic opacity/proof validity is an
explicit ideal-functionality boundary, not something this test proves.

Use two initially honest queued intents A/B, one colluder C, and two additional
honest wallets D/E for alternate known cohorts. Freeze each synthetic input at
2,000,000,000 sompi, payment at 100,000,000, change at 1,890,000,000 and fee at
10,000,000; use distinct NFs and fresh blinds. This equal-value control isolates
structural mapping and does not test unequal-value auxiliary inference. Owners
submit at different times and are absent before settlement.
Freeze both O-ledger and O-active views, the entire finite schedule below and
the equality/ownership queries before constructing any fixture. Enumerate all
owner/partition assignments consistent with each view rather than scoring one
hand-picked guessing strategy. No old 1/6 or passive-128 metric is inherited.

1. **Single accepted-batch information flow.** Hide the two honest owners' NF
   assignments and output partitions after subtracting C's known material.
   Require at least two indistinguishable honest ownership assignments and no
   deterministic per-intent partition under the declared opaque-field model.
   Ordinary plain-intent aggregation is an expected negative control. Explicit
   pair IDs and per-intent Delta publication must also fail.
2. **Offline consent/current-state controls.** Model fixed recipient/change/fee,
   separate per-intent conservation, one current reserve and a historic anchor.
   Reject tuple/CF/fee substitutions, fee redistribution hidden by a correct
   global sum, duplicate NF/intent, invalid proof, bad anchor/pool/profile,
   stale final point, a second accepted successor and replay after rollback.
   Advancing only the head may rebuild permitted public state without owners;
   it must not grant new financial discretion.
3. **Mandatory forced-abort counterexample.** Release ABC's valid final
   transaction/proof before confirmation; C wins an independent Exit race.
   A/B remain unspent. Offer the dispatcher retries in different known owner
   cohorts, including `A+D+E`, retaining each honest note's stable NF. Compute
   intersections across all disclosed attempts and include a same-cohort
   control. Also model a reorg after apparent inclusion. A fixed server roster
   alone is **expected to fail** O-active; retain that result. Any proposed
   prevention must show the exact enforceable transition that rejects subset
   reuse while still permitting original-seed exits and service loss. If it
   simply refuses new private progress, record a liveness failure.
4. **Availability boundary.** Remove all servers before and after modeled
   acceptance. Public-data-plus-seed recovery must require no private partition
   or pending journal; model direct Exit's NF race and exact remaining backing.
   Withhold accepted CF/tree data as an expected availability failure. This
   symbolic control is not actual seed restoration/native payout evidence.

Stop on any authorization/backing/state mismatch, visible partition tag,
threshold overclaim or undocumented privacy/liveness assumption. Do not tune
the schedule to save a candidate. A passing ideal information-flow test is
only permission to consider a separately reviewed implementation plan; it is
not a cryptographic, native-settlement, network-anonymity or recovery pass.

**Fees remain unmeasured.** Include owner proving, collaborative proving,
storage, deposits, every retry and nine original independent exits in any later
matched workload. The frozen 21-KAS, 2% all-in target and existing FAIL remain
unchanged. No hidden server subsidy, extra unrelated volume or outbox promise
can convert this structural design study into a fee pass.

Before implementation: resolve the retry/admission contract and private-prover
construction, then write a new RFC/ADR and synchronize architecture/threat-model
documentation. The smallest next action is review and the frozen finite model,
not a new subsystem.
