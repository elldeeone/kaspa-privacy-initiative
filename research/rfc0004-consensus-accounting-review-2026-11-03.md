# RFC-0004 consensus, recovery and accounting review

**Date:** 2026-11-03. **Baseline:** `e00e47427a96e134069e796ac504d945ba22f1a5`.
**Scope:** internal AI technical review of Q5–Q8 and Q10, with an adversarial
second pass. This is not independent human consensus/cryptography approval.
No native implementation, proof, setup, funded trial or deployment was run.
Companion reviews resolve [Q1's information limits](rfc0004-privacy-feasibility-review-2026-11-03.md)
and [Q2–Q4/Q9's cryptographic reference](rfc0004-cryptographic-profile-review-2026-11-03.md).

## Dispositions

| Question | Concrete research answer | Remaining implementation or qualification gap |
| --- | --- | --- |
| Q5 | Apply native state in canonical accepted order; all-slot nullifier conflicts, pool checks, append order and complete undo are stateful. Parallelize context-independent cryptography only. | Exact native state commitment/codec, header activation, storage transactions, cache isolation, body rules and actual conflicting-DAG/reorg integration. |
| Q6 | Use full retained history as the conservative reference; distinguish validator replay from wallet recovery. Authenticate new native state explicitly. | No complete native header/state commitment, replay/bootstrap implementation, independent retention arrangement or measured storage budget. Existing pruning proofs do not supply these by implication. |
| Q7 | Owner rebuilds and re-authorizes a complete transaction at a chosen explicit fee; owned shielded value or authorized ordinary contribution can pay. | Native mass/fee policy, replacement handling and practical inclusion/affordability measurements. No arbitrary future fee or inclusion guarantee. |
| Q8 | Boundary equation and stock accounting below; complete-construction/zero-genesis induction for the smaller native monetary limit. | Explicitly reviewed I-2 boundary wording and I-1 reserve interpretation, plus native enforcement. The invariant file remains unchanged. |
| Q10 | Unqualified. Preserve all old negative results and define one complete prospective profile before measuring it. | Compatible privacy qualification claim/population, complete fees, native performance and all-normal-service-loss recovery evidence do not yet exist. |

These are usable answers and engineering obligations. They are not ten claims
that passing a source review has qualified an implementation.

## Q5: accepted state, conflicts and undo

### What the current source actually does

Kaspa derives past UTXO state from the selected parent and its ordered mergeset,
checks the header's UTXO/accepted-ID commitments, and checks the current block
against that past state. Validation of transactions within a block uses parallel
paths whose comments explicitly rely on block-body validation having made those
transactions independent. Those body checks inspect ordinary input outpoints
and prohibit ordinary intra-block chaining. They do not know the proposed pool's
nullifiers, balance or accumulator. [K-ORDER][K-HEADER-CHECK][K-PARALLEL][K-BODY]

A note spend without an ordinary outpoint does not inherit that independence.
Likewise the existing UTXO MuHash and accepted-ID/sequence commitment do not
automatically commit to the contents of a new native state. Current headers and
virtual-state records need deliberate extension. [K-HEADER][K-VIRTUAL]

### Reference semantics

Use one state view for ordinary UTXOs and native `(B,C,n,N,A,D,P)` and one atomic
diff/undo boundary. Define the following algorithm before any optimization:

1. Parse canonical bytes, identify the immutable pool and allowed exact profile,
   and verify complete proof/signature/effects bindings. Cache only this exact
   context-independent result, including the selected circuit/key identity.
2. Visit candidate transactions in Kaspa's consensus accepted order and original
   transaction index. For each, check ordinary inputs, allowed anchors, **all**
   slot markers against current `N`, within-bundle uniqueness, current `B`,
   capacity and public fee/balance. Recheck state even after a proof-cache hit.
3. Stage every effect, including ordinary spends/creates, pool balance, both
   markers, both output commitments and discovery records, accepted-anchor
   bookkeeping, fees and acceptance identity. Commit the whole diff or none.
4. Undo the entire diff on virtual-state changes; reapply the alternative order
   against its restored predecessor. Wallet pending balances do not override
   consensus acceptance. Returning to a predecessor restores its eligibility
   rules, markers, positions, discovery records and fees together.

The reference allows anchors from authenticated completed predecessor states;
it does not make an intermediate same-block append a spendable anchor. Publish
the exact eligible-anchor set/window in the final codec/state specification.
This is a research restriction on witness eligibility, not an added withdrawal
timelock or a claim about current Kaspa rules. Retain all anchor records in the
conservative storage reference; eligibility is distinct from archival retention.

For a current block, preserve the distinction between full block qualification
and later mergeset acceptance. Reject duplicate native markers within a block
under its new body rules. A current block failing its contextual qualification
must not be accepted by quietly dropping its invalid transactions. For mergeset
conflicts, only the first valid effect in the specified accepted order commits;
the later conflict has no native/ordinary/fee effects. Purely parallel checks
against the same initial `N` are insufficient. Current Kaspa's exact contextual
block checks remain the implementation authority until an explicit new rule is
specified. [K-HEADER-CHECK][K-PARALLEL]

Propose a **new versioned native-state header commitment**, rather than silently
redefining UTXO MuHash or KIP-21's accepted-ID root. Its state point must match
the header's authenticated past-state point, with deterministic roots for all
consensus-relevant native components. Exact field allocation, root encoding,
nullifier authenticated structure, hashing domain, proof-of-work/header hashing,
activation and pruning-proof coverage remain consensus design work. This review
does not allocate bytes or assert that a chosen hash of a server file is enough.

### Required conflict traces

The companion [review checker](../scripts/check_rfc0004_review.py) executes
abstract traces: duplicate slots, two transactions with no shared ordinary
outpoint but one shared marker, a stale anchor after cached proof validity,
current pool underflow, a second verifier version reusing spentness, rejection
without partial mutation, and undo/reapply with all modeled components restored.
They exercise the specification's state obligations, not Kaspa DAG processing,
real note openings, authenticated roots or cryptographic validity.

## Q6: recoverable data and authenticated bootstrap

Choose full retention for the first reference; defer optional snapshot-based
pruning. This removes an unreviewed snapshot shortcut, not the storage cost or
availability assumption. Existing pruning-proof application and UTXO bootstrap
do not authenticate an unspecified new native state. [K-PRUNING][K-HEADER]

Two different tasks require different data:

| Task | Necessary authenticated inputs |
| --- | --- |
| Full validator independently revalidates every native credit | Agreed activation state including ordinary UTXO context, sufficient Kaspa headers/DAG bodies and ordinary transaction context to check each funding spend, all native bundles/proofs/signatures, accepted order, complete native state and exact profile artifacts. A list of shielded ciphertexts alone cannot validate deposits. |
| Wallet discovers, proves ownership and spends on an already consensus-validated chain | Correct network/pool/profile and authenticated current native state, position-complete note/delivery history, current spentness, eligible anchor/path or sufficient log to construct it, exact software/artifacts and the owner's original keys/backup. A wallet need not pretend to revalidate all ordinary history. |

Do not conflate these with a signature from an indexer or an unverified archive
hash. A snapshot optimization needs a consensus-authenticated complete native
state and count/root coverage at an exact accepted point. Its absence cannot be
filled by a caller-supplied predecessor, invented genesis or old valid proof.

Retain exact accepted Action order and positions, both complete delivery records
per bundle, nullifiers, frontier/count and branch/undo context. The data service
must expose omissions/truncation against authenticated counts/roots. Retain the
full ciphertexts, not just hashes. Recipient trial decryption and commitment/key
consistency checks precede credit; delivery is not proved correct by the unchanged
Orchard circuit. An incoming viewing key is not the entire outgoing/spentness
backup. Use the chosen profile's scope/key rules. The exact old position-based
claim identity must not override Orchard's position-independent nullifier.

Current Orchard derives public proof keys from its selected circuit/constants;
do not repeat the historical missing circuit-specific Groth16 parameter failure
as a claim that this reference needs that same ceremony. Retain exact reproducible
source, dependencies, key/profile fingerprints and portable artifacts anyway.
The [crypto review](rfc0004-cryptographic-profile-review-2026-11-03.md)
identifies that distinction and the per-version rules.

The explicit availability assumption is at least one reachable independent
source of authenticated required data/artifacts, or a sufficiently complete
owner-held copy plus independent settlement connectivity. All normal hosted
services may disappear; every copy of public recovery data cannot disappear
while the requirement still promises seed-only recovery. Consensus cannot force
machines to serve bytes forever. No automatic ciphertext/nullifier deletion is
justified by ordinary pruning or an unrelated public spent marker.

Qualification must cold-start an owner with only the declared backup, remove all
normal application services, authenticate and retrieve the required data from
independent sources, construct a fresh authorized spend, and settle it. Include
missing/truncated/corrupt data, wrong profile, obsolete anchors and reorg recovery.
None of this complete native-profile test has run.

## Q7: owner-controlled fees and replacement

Use explicit public `F` and authorize the complete effects. The default way to
reprice is to rebuild and re-authorize the transaction, choosing a smaller
shielded change or ordinary payout, or adding authorized fee input. A contributor
is optional; no named service holds exit authority. A relay only transports the
finished bytes. Changing `F`, payout, change, input ordering or other signed
effects requires the relevant new signatures. If public proof inputs or witness
relations change, regenerate the proof too; some signature-only changes need not.

For replacements consuming the same note, preserve the same actual note
nullifier. Mempool replacement is a policy decision; whichever conflicting
version consensus accepts consumes it once. A new verifier identifier is not a
new spend identity. Separate change in pending wallets from confirmed state.
Additional padding markers/output commitments are checked normally, not treated
as permission to duplicate the real note's claim.

This resolves the fixed precommitted branch-fee design trap at specification
level. It does not resolve affordability, mempool relay policy, censorship or
guaranteed inclusion. A tiny claim can be economically uneconomic to spend.
Never promise arbitrary-future-fee liveness without additional value, disguise
a fee as lost principal or introduce an admin rescue. Document contributor
linkage and public fee/timing channels. Existing fee validation distinguishes
contextual consensus balance from mempool fee policy. [K-FEE]

Native Halo2/ciphertext/nullifier/log work still has no accepted compute/storage
mass schedule. Price the complete new permanent state, invalid-verification
work, bytes and witness access before qualification. A 7,264-byte proof is not a
7,264-byte transaction, complete mass quote or a measured cost pass.

## Q8: backing, conservation and the proposed invariant change

For the direct no-queue reference, the reviewed candidate equations are:

```text
b = S_in - S_out
T_in + b = T_out + F
B_next = B - b
delta(ordinary UTXO stock + B) = -F
```

Count native value once: `B` is protocol-reserved native supply, not also an
ordinary reserve UTXO. Hidden outstanding note value is a liability against it,
not an additional asset. Coinbase remains on the current path; feed each
accepted `F` into Kaspa's accepted-fee/reward accounting exactly once. Rewards
follow mergeset rules, not an invented immediate same-block repayment. [K-REWARD]

Complete repaired Orchard plus unique creations/spentness, nonnegative `u64`
notes, exact bounded public `b`, authentic zero genesis and integer lifting of
the binding equation give the proposed **induction**: total outstanding note
value equals `B`; hence each live note and all distinct consumed-note totals are
at most `MAX_SOMPI`. The local circuit does not itself prove that smaller bound.
Two Actions bound each arithmetic side below `2^65`, far below the scalar order;
preserve binding soundness and the exact integer argument. This is a design
argument awaiting specialist validation, not a newly proved soundness theorem.
An unauthorized migration/credit or duplicated claim would break its premises.

An explicit proposed wording for I-2 is:

> For a valid native boundary transition, private inputs plus actual ordinary
> native inputs equal private outputs plus actual ordinary native outputs plus
> explicit allowed network fees. With no ordinary crossing, this reduces to
> the private-transition conservation equation. Every input/output is counted
> once in its domain; no payout principal is classified as a fee.

I-1's inequality remains. Its explicit proposed native-pool interpretation is:
consensus-reserved `B` is backing controlled by protocol rules, counted once;
outstanding liabilities include **all** spendable claims and unpaid authorized
exits. For this direct atomic profile, there is no separate pending-exit queue.
A later queue/migration must conserve the whole old liability until actual
payment/authorized replacement. State rent, treasury and service fees are
separate; none supplies reserve backing by relabeling.

**These are proposals, not edits to SECURITY-INVARIANTS.md.** Its review rule
requires explicit independent security review before implementing a changed
invariant. [ADR-0101](../docs/adr/0101-native-shielded-research-reference.md)
records research-reference choices and this unresolved adoption gate. It does
not approve the wording or activate new native supply rules.

## Q10: qualification and an actionable engineering boundary

There is no runnable complete native profile to benchmark. The retained 12.5793%
matched lifecycle fee failure, approximately 1.85% different offline layout,
constructor-limited MPC evidence and corrected privacy failures do not combine
into a native-pool pass. The [Q1 review](rfc0004-privacy-feasibility-review-2026-11-03.md)
also demonstrates a prior-only 21.10% lower bound against a 20% ceiling for the
retained common-price population. Keep it unqualified; do not retune old truth,
labels, workload or thresholds to make a future run pass.

The next implementable **bounded study**, if requested, is an unfunded local
codec/verifier interoperability specification using upstream V2 vectors and
fixed complete-effect test cases. It can extract/fingerprint exact keys, parse
both Action roles, validate complete proof/signature bundles and reject changed
effects. This need not claim privacy qualification or activate a KAS pool. It
does not depend on modifying the invariant file or restarting MPC/Testnet work.

Before a native consensus prototype: settle the exact header/state/transaction
codec and authenticated bootstrap; review the induction and proposed invariant
wording; implement state/body/cache/reward/undo integration. Independent crypto
and Kaspa consensus reviewers must evaluate the actual final specification and
implementation, not just a status table. Network/governance activation is a
separate downstream decision, not a substitute for missing engineering.

Before a qualification claim, freeze one compatible privacy claim/population,
observer/legitimate information, prior baseline, metric and thresholds; then run
the complete matched deposit/transfer/change/exit/recovery lifecycle with all
fees, retained-state costs, native verification memory/throughput and independent
service-loss recovery. Include low activity, isolated owners and optional later
transparentization. No campaign or funding is authorized by this review.

## Adversarial second pass

| Attack or failure | Required outcome / remaining limit |
| --- | --- |
| Pool counter funded, but counterfeit hidden note | Reject through full proof/binding/authority plus valid creation history; a counter alone proves no entitlement. |
| Duplicate ordinary deposit or dummy marker | Real ordinary input consumed once; every published marker unique; atomic state changes. |
| Two concurrent spends with disjoint outpoints | Current native marker conflict rejects the second accepted effect; body/mergeset rules cannot assume ordinary independence. |
| Old valid proof after another accepted spend | Cache hit never replaces current `N`, anchor, `B` or exact-effects checks. |
| Version change makes old note look unspent | Immutable note-origin spentness shared across accepting verifier versions; no root import/reset shortcut. |
| Rejected payout partially burns a note or inserts a marker | No ordinary/native/discovery/fee/acceptance changes survive rejection; full undo on reorg. |
| Archive signs a convincing wrong snapshot | Reject without consensus-authenticated new native-state coverage and exact point. |
| Normal services disappear or ciphertexts are missing | Independent retained data/artifacts or owner copy needed; fail safely without claiming successful recovery. |
| Fee sponsor disappears or raises fee | Owner can build a new complete authorized spend if value/software/data are available; no affordability/inclusion guarantee. |
| Malicious ciphertext or prover sees witnesses | Recipient checks before credit; local proving protects witness custody. Circuit validity alone is not delivery/privacy. |
| Legacy curve assumptions break | No PQ promise; preserve exact authorized migration/recovery obligations. |

## Pinned primary-source references

The Kaspa source pin below was rechecked against official HEAD during this
review. Source inspection is not a network-activation claim. Companion source
manifests retain exact file identities; no historical binary/proof pin changed.

[K-ORDER]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/pipeline/virtual_processor/utxo_validation.rs#L110-L175
[K-HEADER-CHECK]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/pipeline/virtual_processor/utxo_validation.rs#L180-L265
[K-PARALLEL]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/pipeline/virtual_processor/utxo_validation.rs#L297-L350
[K-BODY]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/pipeline/body_processor/body_validation_in_isolation.rs#L126-L151
[K-HEADER]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/header.rs#L158-L190
[K-VIRTUAL]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/model/stores/virtual_state.rs
[K-PRUNING]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/pruning_proof/apply.rs
[K-FEE]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs#L30-L165
[K-REWARD]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/coinbase.rs#L80-L181
