# Candidate Architecture

## Independent-wallet payment candidate

[ADR-0066](adr/0066-local-native-kas-payment-prototype.md) implements the
[RFC-0029](rfc/0029-local-native-kas-private-transfer.md) fresh domain 1/2 payment
profile: a recipient note and recoverable change without other live owners,
with local consent/effects checks and a direct full-note exit independent of
the outer prover. Existing pools and prior profiles remain separate.

The [current TN 10 result](checkpoints/2026-10-27.md)
completed six payments, nine independent payouts, zero reserve/null outpoint
and three Original terminal cold scans using downloaded finite recovery software.
Independent accounting passed 19 Native Full cases (16 pool/3 ordinary), 15 commitments/16 nullifiers.
Paid fees 264,166,000 sompi/21 useful KAS fail the unchanged 2% target.

The ledger still groups one NF with two outputs and the ordinary constructor
sees its witness/map. Tor/TLS, selected-node financial success and bounded
observer/component results do not establish general privacy or production safety.
Shared-head conflicts, invoice/origin linkage and independent public-data
retention remain explicit limits. No successor architecture is selected.

## Earlier sender-privacy experiment

[ADR-0065](adr/0065-sender-private-admission.md) and
[RFC-0028](rfc/0028-sender-private-native-kas.md) select a new off-chain client
protocol under the existing financial domain, keys, guest and native policy.
Fresh pools, seeds and sessions keep the completed experiment unchanged.
Existing complete-effects authorization binds the actual reserve outpoint,
session, state, inputs, outputs and fees; changing input order requires new
authorization, not a weaker financial predicate.

The candidate privately mixes input NF/CV rows and output tuples independently,
then privately mixes complete Spend authorization rows after owners validate
the exact effects. Public assembly receives only the mixed lists and performs
a strict input/authorization bijection. Fresh round aliases replace persistent
wallet labels, and seed-only recovery scans every public candidate invoice slot.
Implementation, genuine execution and privacy measurements are pending.

This targets direct input attribution under passive observation and honest
scheduling with at least two honest owners. An active coordinator can still
abort overlapping cohorts and intersect their exposed stable nullifiers.
That known failure must be measured. Host-administrator access, traffic,
amount/timing correlation and independent recovery-data custody remain separate.

## Completed financial baseline

**Status:** the integrated owner-private profile completed actual TN10 GN3,
both genuine private-payment rounds, nine independent native payouts and three
further fresh original-seed terminal scans. Reserve and owned claims reconcile
to zero. Financial privacy remains unqualified and production architecture
remains unselected. See the [result index](../research/next-session/owner-private-lifecycle/RESULTS.md).

[ADR-0064](adr/0064-owner-private-native-kas-lifecycle.md) selects one new
TN10-only profile combining three-owner GN3 backing, repeated 3-spend/6-output
rounds, original-seed payment/change recovery and direct no-append Exit152.
The [contract](../research/next-session/owner-private-lifecycle/CONTRACT.md)
binds the new domain, Spend/Output/Exit keys, current state/NF insertion and exact
native effects. GN3's initial note records are public deposit-boundary data;
funding index `0xffffffff` is excluded from payment/exit keys.

The complete supplied-context route passed before live funding. The actual
run then confirmed twelve pool transactions and 57.888496 KAS in nine payouts,
including spending recovered payments/change in R2. Original coordinator/MPC,
shared R0 and writer processes quiesced; replacement clients used authenticated
downloaded software/history/keys and direct proofs with original paths absent.
Three further fresh backups replayed final history, required every owned claim
spent and rederived historical payout keys. This is same-host isolated execution,
not independent custody. Initial complete 64-object HTTPS recovery passed;
after terminal publication, [fresh hosted public CI](https://github.com/elldeeone/kaspa-privacy-initiative/actions/runs/40163954168)
passed HTTPS retrieval and unchanged twelve-case native replay at source
`a4578ae994105620a62becdb5cef802fc43f49ae`. This verifies public evidence on
another machine; it does not establish off-host seed recovery or independent
administration, retention, consensus or anonymity.

Complete actual fees are 2.156935 KAS / frozen 21 KAS = 10.2711190476%, failing 2%.
The [fee audit](../research/next-session/owner-private-lifecycle/fees/FEE-RATE-FINDING-01.md)
finds a rate of 100 consistent with observed estimates/pinned standard policy, while
remote admission configuration is unknown. [Confirmed proof cases](../research/next-session/owner-private-lifecycle/fees/CONFIRMED-ENGINE-BUDGET-01.json)
already use roughly 82–87% of B1800's allowance; trimming headroom alone offers
limited savings. No lowered-budget/rate candidate or workload retuning occurred.

The source-established funding-marker→pseudonym→ordered mixed NF/CV channel
leaves sender anonymity unresolved; coordinator READY-admission pairing is a
separate problem. This does not itself map shuffled outputs/change/receivers or
terminal payout owners. Deterministic fee remainders can leave one-sompi change
fingerprints; amounts, timing, endpoints, ancestry and trusted-host/setup limits
also remain. Excluding additional private recovery association artifacts does
not remove public protocol identifiers or existing chain linkage. No new
privacy-study step4 was run; earlier failures and invariants are unchanged.
Separately administered storage and durable retention remain unconfigured.

[ADR-0063](adr/0063-owner-private-payments-prototype.md) selects a **new,
unfunded** three-owner/six-output design under a distinct domain, setup and
verification profile. Its [contract](../research/next-session/owner-private-prototype/CONTRACT.md)
separates Spend200 from Output168 proofs: each owner proves its own hidden
input value/authority and creates two independently proved complete output
tuples. No public action/output subset, individual blinding contribution
`beta_i` or `beta_i*R` is published. Input NF/CV records may still identify
input owners. Stock malicious MASCOT over the BabyJubjub scalar field privately
sorts the six complete tuples with secret random keys using its Batcher
network; on success it reveals the mixed tuples and aggregate Delta.
Collision/abort status is public; collisions abort before tuple opening. The selected
[Source04 boundary](../poc/owner-private-payments/construction/BOUNDARY-04.md)
supersedes the earlier stock-shuffle selection and retains its source-level
counterexample.

After independently checking every output proof, its own payment/change
inclusion, state transition and global group balance, each owner authorizes
the same recomputed financial EffectsDigest through its Spend proof. Effects
include complete Output tuples and their proof bytes, but omit Spend proofs;
valid same-statement Spend-proof malleability is explicitly allowed. The new
[verifier/native contract](../poc/owner-private-payments/verification/DESIGN.md)
requires all nine proofs, current NF/CM updates, direct commitment balance and
an outer journal binding the complete prototype body, component-proof bytes
and defined native financial projection. P0 has
one reserve input, one immutable continuation, exact fee and **zero payout**.
Six genuine Output proofs, actual Source04 stock-sort MPC, all three postmix
Spend authorizations, independent nine-proof verification and the new CPU guest
have passed. Genuine outer proving/compression, separate receipt verification
and local Native Full validation have also passed, with all twelve same-proof
native mutations rejected. These are unfunded supplied-context results, not
accepted backing or a live payment rehearsal. The earlier KPX2 and four-wallet
results do not qualify this new relation's privacy or lifecycle.

The [new result](../research/next-session/owner-private-prototype/RESULTS.md)
also records sixteen fresh genuine financial worlds. A frozen colluder strategy
guessed both unknown groups in four; no excess success was detected against
its explicit idealized chance model. This is a bounded strategy comparison,
not a privacy qualification or a substitute for a composition review.

The prototype trusts its same-host launcher, daemon and selected software;
they are excluded from the coordinator adversary. Isolated workers do not
establish independent operators. Its intended coordinator-plus-one-participant
model requires at least two eligible honest owners and still exposes endpoints,
counts, timing and final public components. Recipient decryption and Output-proof
checks remain necessary: a ciphertext hash does not prove correct encryption.
No new-domain receiver recovery/repeated spending, independent exit, accepted
chain/currentness, durable availability or financial-privacy qualification is
established. Existing amount/prior, funding-ancestry and entry/exit limitations
and all adopted targets remain unchanged.

The new [four-wallet result](../research/next-session/four-wallet-testnet/RESULTS.md)
now completes the actual accepted TN10 two-sender/two-recipient lifecycle:
genuine combined proof, four independent original-backup private withdrawals,
four confirmed native payouts, final recovery scans and zero reserve. One exit
uses restored software and a complete copied proving key with original paths
absent. Complete fees including acquisition are 4.521645% of 20 useful net KAS,
failing the unchanged 2% target. The earlier supplied-context result remains
separate at 4.35123%. Separately controlled recovery storage still needs an
external destination and access.
[ADR-0062](adr/0062-existing-engine-private-field-sum.md) now has four actual
exact-field sums, wrong-field rejection, two participant-loss runs and a real
RedJubjub binding consumer. These establish a bounded component API; full
owner-private financial acceptance remains open in the separate ADR-0063
prototype above.

[ADR-0060](adr/0060-four-wallet-gn2-testnet-rehearsal.md) now selects a fresh
four-wallet TN10 rehearsal: two ordinary funding inputs create strictly checked
GN2 liabilities, A pays B and C pays D, accepted physical W history drives four
independent original-backup exits, and every payout must confirm with zero
reserve. The new financial profile is acyclic and distinct from the public
benchmark. Initial ciphertexts are signed GN2 data; State112 has CM/NF roots,
not a separate CF root. Profile/setup is separate from routine one-command
fresh trial identity. Implementation and execution gates are recorded in the
[new plan](../research/next-session/four-wallet-testnet/PLAN.md). The bounded
accepted lifecycle is now complete; the privacy-construction and independently
controlled storage questions remain open without changing old failures.

[RFC-0024](rfc/0024-independent-private-payment-settlement-and-recovery.md)
now coordinates independent-sender settlement fees, the demonstrated financial
privacy leaks, cold/independently distributed recovery and private exits at
state capacity. A public two-action checker must verify actual owner proofs and
complete native effects before selecting aggregation. It does not itself reduce
L1 verifier calls. [ADR-0058](adr/0058-private-full-note-exits-without-commitment-appends.md)
selects a separate unfunded experiment: full-note private cashout may omit CMs
while preserving another user's reserve. Terminality depends on remaining
reserve, independently of append mode; every original ownership, nullifier,
membership and payout constraint remains. Fresh domain/role parameters and
independent code/CS review are required. No old instance changes. Prototype and
validation results are tracked in the
[new execution packet](../research/next-session/independent-payments/PLAN.md);
the four product gates are not yet closed. The
[capacity result](../research/next-session/independent-payments/exits/RESULTS.md)
now completes three genuine proofs, two native full-note exits at CM65535 and
NF131071, zero terminal reserve and a fresh current occupied-NF rejection.
The public research release also supplies exact software/parameters over HTTPS;
a clean owner restores them and generates a genuine local terminal withdrawal
from its original known-public canary backup. These are supplied-context
experiments, not accepted-chain or separately administered retention evidence.
[ADR-0059](adr/0059-scheduled-private-actions-with-public-settlement-proofs.md)
now has a genuine two-owner public-settlement receipt, same-claim Groth16
compression and actual immutable W native Full/all-engine acceptance. The
18,508,000-sompi outer fee is exactly allocated between the two owner-local
proofs; continuation reserve is 3,981,492,000 sompi. Genuine bytes and coherent
body rejection controls preserve the acyclic financial binding. Current
private-prover source also cold-rebuilds exactly from all 19 current files and
148 locked dependency packages. Both original backups now recover their
incoming payment and change on the same W, generate two genuine two-real-input private exits using HTTPS-restored
software/parameters and drain all 3,981,492,000 remaining sompi. Total outer plus
exit fees are 52,512,100 sompi, or 2.625605% of two declared 10-KAS synthetic
payments before entry costs. Financial privacy, low-demand fees, accepted-head reconciliation and independent retention remain
open; public synthetic state is not live readiness.

[ADR-0057](adr/0057-matched-batch-proofs-and-portable-recovery.md) selects
separate fixed compact2/wide32 Groth16 relations for the measured compact native
program, with fresh parameters and unchanged shared real nullifiers. Compact
owners need only compact parameters. New sparse public recovery capsules retain
physical positions and independent static authority; fresh chain/current-UTXO
reconciliation remains mandatory before spending. The unfunded
[matched rehearsal](../research/next-session/compact-batch/RESULTS.md) now passes
33 genuine proofs and 34 native Full transactions through all 32 independent
withdrawals, ending with zero reserve. Complete supplied-context fees are
1.9486784375% for 32 useful 10-KAS payments. All original backups recover their
spent receipts and per-claim payout keys; the first withdrawal uses the real
compact PK fetched through a fallback with the original source/cache absent.
These are local supplied-context results, not new accepted-chain payouts,
financial privacy or durable independent-provider availability. The frozen
global linkage study completes all 96 views (61 complete, 35 incomplete), with
no financial-privacy qualification. Legitimate invoice facts let the fixed
heuristic label other same-batch payer roles in the modeled workload; staggered
withdrawals also force some funding ancestry. These are separate from human
identity and exact note-to-payout links. Individual payment plus independent exit has
a source-derived verification-only floor of 2.95% for 10 KAS at reference rate 100; the
batch result does not solve that case. Existing failures and old instances stand.
Optional fixed 1 GiB chunks now reconstruct both exact public role PKs with
original paths absent. Four transport entry points preserve exclusion iterables
across all reads after an independently reproduced alias-guard bug; historical
executed source is archived separately from corrected current source. These
changes affect public byte transport, not financial authority or capsule format.

[ADR-0055](adr/0055-recoverable-private-change-and-repeated-spending.md) extends
the owner wallet to requested partial cashout, seed-recoverable private change,
private payment from that change and complete exit. It preserves Auth528 and
the existing cryptographic/native relation. Exact-spend private payments use a
separate zero-proof public sizing quote followed by a legal actual candidate
and exact re-quote before witness submission. Random-u64 receive indices and
private input/output shuffling add no saved issuance-map requirement; unknown
pending/orphan reuse remains an explicit freshness boundary. This new
[workload](../research/next-session/private-change/RESULTS.md) now completes a
smaller confirmed TN10 route with two original-backup change recoveries and
three native payouts, ending with zero reserve. It does not replace the earlier
completed trial evidence or qualify financial privacy/fees.

[ADR-0056](adr/0056-compact-native-batch-fee-screen.md) separately selects a
native-only whole-program fee screen: authenticated subtree appends, a shared
NF path layout, compact/wide verification-key dispatch and canonical omission
of inactive terminal bytes. It must retain all financial/state checks and price
every branch and independent exit. The complete23575-byte emitter passed
55 expected native outcomes and its all-valid-path source bound fits the1600
budget. Complete32-recipient fee projection is1.9491%; separate-time payments
remain above target. These are native binding/cost results without matched
circuits or financial positives; no new funded/circuit profile is selected. Capacity-full private exit behavior remains an explicit open question
in [RFC-0023](rfc/0023-compact-native-private-payment-fees.md).

[RFC-0022](rfc/0022-private-cashout-and-independent-recovery.md) now targets the
remaining privacy and recovery blockers. [ADR-0049](adr/0049-receiver-driven-network-recovery.md)
selects independently fetched accepted records, an authenticated public pool
descriptor, local replay and seed-only ownership/witness reconstruction.
[ADR-0050](adr/0050-proof-private-native-cashout.md) selects a separate unified
private action with exact public native payout, hidden input notes and private
change. Its terminal form inserts NFs without appending CMs. A fresh Auth528
instance now has both owner-local proof-private withdrawals confirmed on TN10,
separate from the older revealing-exit program. The revealing-exit channel is measured; validating-node/data
availability and receiver delivery remain assumptions, and direct verification
fees prevent this unamortized route meeting the10-KAS2% lifecycle target.

The [fresh service-loss result](../research/next-session/privacy-recovery/RESULTS.md)
now confirms old-program fallback recovery from independently fetched public
data and one backup per owner: Bob receives 55,026,200 and Charlie 55,036,800 sompi.
The prover is stopped, neither client receives an operator archive or saved
exit, and a final fresh public replay verifies zero reserve and both payouts
unspent. These explicitly consented revealing exits validate liveness under
selected-node/retained-data assumptions; they do not validate financial privacy.

[ADR-0052](adr/0052-separate-public-replay-for-private-cashouts.md) now adds a
separate public Auth528 replay adapter for supplied contexts. It verifies the
whole approved program and terminal updates, reusing exact previously validated
native bodies. Its original offline compatibility evidence retains `complete:false`.
The new outer network client separately requires fresh acquisition, complete
finite coverage, exact queries/post-query checks, SDK hashes and fresh native
Full validation before an owner reads a seed.

[ADR-0053](adr/0053-private-network-recovery-and-local-owner-proving.md) now selects
a fresh research rehearsal integrating those two boundaries: authenticated
public parameters, descriptor-based network reconstruction and one local prover
per seed-only owner, followed by confirmed proof-private native payouts. The
[fresh result](../research/next-session/private-service-loss/RESULTS.md) confirms
41,000,100 and 41,042,400 sompi payouts with terminal reserve zero, after the
operator prover stopped. Initial cold exits require the authenticated public PK
and an owner-local prover; no operator archive, amount map or saved exit is used.
This does not change previous privacy/fee failures or establish durable public
parameter/history availability, independent consensus or setup honesty.
[ADR-0054](adr/0054-trusted-read-only-executable-releases.md) chooses ordinary
hash-checked, read-only executable releases under explicit host trust for this
rehearsal; it changes no private proof or native state/authorization check.

[RFC-0021](rfc/0021-confirmed-native-private-payment-rehearsal.md) and
[ADR-0046](adr/0046-fresh-private-testnet-rehearsal.md) now record a
[complete fresh-domain TN10 rehearsal](../research/next-session/testnet-rehearsal/RESULTS.md):
all six native transactions accepted, both seed-backup recipients paid
95,026,200 / 95,036,800 sompi, terminal reserve and positive liabilities zero.
The two 100M-sompi notes form a liveness pilot with 36,954,400 total native fees;
it does not qualify fee or privacy targets. A selected validating node and
retained complete public archive remain trusted. Separate one-owner exit
sandboxes exclude payer/other-recipient secrets, PK and prover.
[ADR-0045](adr/0045-authenticated-uncompressed-development-key-cache.md) reduces
observed parameter-loading cost; [ADR-0047](adr/0047-sha-circuit-cost-experiment.md)
and [ADR-0048](adr/0048-selected-real-dummy-hmac-circuit.md) separately measure
equivalent SHA/HMAC circuit implementations without changing this funded trial.
The final isolated HMAC candidate has 3,199,529 constraints and one genuine
four-worker proof at 10.495 seconds / 3.82531 GiB. It remains a separate fresh
setup: only the proof-process memory screen is below target in that observation;
warm latency, aggregate-wallet and p95 qualification remain open.

[RFC-0020](rfc/0020-private-proof-and-native-exit-integration.md) and
[ADR-0041](adr/0041-new-format-private-native-integration.md) now select a
separate offline implementation of the genuine private relation and actual
private/admission/reveal native union. The
[complete offline lifecycle](../research/next-session/private-integration/RESULTS.md)
now passes six linked native Full operations with a genuine private proof,
pre-payment-backup recovery and both native owner payouts without the prover.
Every positive liability and the reserve end at zero. This uses supplied UTXOs,
current-head and archive oracles; it is not an accepted-chain lifecycle. New State112
and Auth484 bind two private input/output slots, two real/dummy NF insertions
and exact reserve/fee context; native reveal consumes the same original NF
without a new proof. Sentinel-inclusive capacity has no old parity rule.

[ADR-0042](adr/0042-separate-delivery-and-note-receive-fields.md) selects a
208-byte one-time invoice separating stable delivery encryption from
the per-index opaque note incoming field. The selected recipient/reference suite
passes27 checks while preserving V1's25-check result. This removes one deterministic
fresh-note equality channel; participant invoice linkage, emergency disclosure
and the existing privacy-prior failure remain. Both backup recovery and current
witness reconstruction use an explicit synthetic accepted-state/archive oracle.

[ADR-0043](adr/0043-native-public-admission-experiment.md) selects native public
admission as a fee experiment: a signed external P2PK input funds a positive note,
its fee and same-owner change; existing reserve/NFs remain intact. Public ingress
is not a private spend. The clean two-recipient pilot consumes both same-payer
founding/admitted notes and cashes out both resulting liabilities. It must count
all founding/admission/tail costs; generic recipient-plus-change remains a
different, currently uneconomic direct-verifier case. Actual native fees in the
two-recipient no-change pilot are 1.85177% and 1.85071% per 10-KAS payment,
including both exits. The primary proof's 198.12 seconds and 5.41 GiB peak do not
qualify wallet resources. [ADR-0044](adr/0044-selected-development-key-loading.md)
scopes a separately pinned development-key loading experiment without changing
the circuit, verification policy or baseline. No new production format,
migration, funded deployment or financial-privacy qualification is adopted.

[RFC-0019](rfc/0019-fees-and-independent-exit-obligations.md) and
[ADR-0039](adr/0039-exit-liability-and-native-claim-experiments.md) now target
complete-lifecycle fees and independent exits. They select an exhaustive
abstract liability/service-loss model and an existing upstream native terminal
permission-claim cost probe under public synthetic UTXOs. An accepted unpaid
claim is a different state from an unconsumed private note: cheap redemption
after earlier authorization does not supply the latter's independent exit.
No new note format, revealing branch or production reserve authority is adopted.

[ADR-0040](adr/0040-public-revealing-exit-feasibility.md) additionally selects a
separate public synthetic revealing-exit probe. Its new candidate relation
separates undisclosed private ownership from a revealed note-local NF credential
and CM-bound native signature authority. It can test current-state exclusion
and full native costs; it has no implemented private-proof branch, accepted
funding, wallet recovery or migration. Future combined-script cost remains
conditional on an explicit byte-size envelope. Existing v6/S7 formats and
requirements are unchanged.

The [closed exit-feasibility checkpoint](../research/next-session/exit-fee/RESULTS.md)
now records60 native positive bodies and39 exact rejection controls in that
separate public prototype. A60M claim can self-fund at500 and retain44,631,000
sompi in the minimal continuing60M-remainder context; the32KiB size envelope
also passes, while49KiB and20M/10M remainder fee profiles fail. No private
branch is implemented. Exact backing plus a60M positive-note floor is an
inductive future-profile condition, not an inference from supplied native roots
or permission to discard the boundary failures. Current S7/private fees remain
unchanged; complete lifecycle fee allocation and accepted owner recovery remain open.

[ADR-0038](adr/0038-bounded-cost-and-proving-qualification.md) scoped the previous
work on ordinary-budget qualification, unchanged-claim proving performance and
self-consistent circuit boundaries. The [decision review](../research/next-session/ARCHITECTURE-DECISION-REVIEW.md)
keeps accepted backing, financial privacy and independent exits open. A
[new conditional lower bound](../research/next-session/fee-frontier/README.md)
also excludes the unamortized ADMIT-plus-fresh-exit route from the 10-tKAS
reference lifecycle target before payment costs. [Established alternatives](../research/next-session/native-kas-singleton-fee-alternatives-2026-10-22.md)
relocate authorization cost, change its payer or require native protocol support;
none is adopted here. GPU scheduling and operational-budget changes do not
change the value relation, reserve authority or the failed price-prior result.

The [ordinary1600 qualification](../research/next-session/ordinary-budget/REPORT.md)
now passes four genuine and28 synthetic supplied-context cases, with45 typed
reserve rejection controls and a separate mass-cap rejection. The unchanged40M
fee covers rate200 for these cases; rate500 still fails. This is an independently
reviewed candidate qualification, not default adoption: S7 factories remain1700,
paired remains1700 and fresh DRAIN remains unexecuted.

[ADR-0034](adr/0034-public-proof-composition-experiment.md) scopes a local,
nonsettling [two-v6 composition package](../poc/two-v6-binding/README.md).
Its shared checked host/guest relation binds two genuine private authorizations
to exact public P[1,088]/J[42] bytes. A real Succinct receipt passes independent
software verification and the [bare Kaspa native predicate](../poc/public-receipt-native-check/README.md),
including rejection controls; the [results register](../research/intensive-2026-10-22/RESULTS.md)
retains each source, image and artifact identity. This uses a separately named,
unreviewed single-party development setup; no compatible original-rehearsal
pair is established. The receipt authenticates neither a separately supplied
anchor nor accepted state, current spentness, native backing or reserve release.
The collector sees the complete source bundles and grouping. No architecture,
exit mechanism or privacy benefit is adopted.

The additive [public-native observation adapter](../poc/shared-pool/PUBLIC-NATIVE-OBSERVATION.md)
independently reconstructs public prefixes, roots and witnesses, cross-checked
against native replay under supplied UTXOs. Descriptor trust, missing funding
ancestry and accepted-chain/current-head authentication remain separate.
The [budget-1,600 screen](../poc/shared-pool/PUBLIC-NATIVE-BUDGET.md) qualifies
13 genuine fixed public cases. [ADR-0036](adr/0036-v6-native-budget-1600.md)
subsequently adopts the 1,600 v6 factory default after 13 actual factory-built
cases, compatible historical/current replay and 48 synthetic boundary cases.
The emitted covenant and actual fee remain unchanged; broader exits and fee
qualification remain open. Historical 3,000-budget artifacts are preserved.
[RFC-0018](rfc/0018-paired-native-settlement-experiment.md) leaves a complete
atomic native transition with independent owner exits open for design review.
The J42 receipt alone cannot supply that transition. Accepted-chain settlement
and a continuing owner-exitable pool remain unqualified; a funded trial remains
outside this local experiment.
[ADR-0035](adr/0035-synthetic-state-aware-assertion.md) now confines a follow-on
to a **NONFUNDABLE synthetic state assertion**. Its
[public oracle](../poc/two-v6-state/public_state_oracle.py) and
[frozen current/historical-anchor vectors](../poc/two-v6-state/public-fixtures/manifest.json)
and [state core](../poc/two-v6-state/common/README.md) now exist. Host/corpus
checks preserve one original typed-label discrepancy. The
[new guest and receipts](../poc/two-v6-state/README.md) pass their fixed
execution/software checks, and the compressed historical-context receipt passes
a [23-case native input-script diagnostic](../poc/public-state-native-check/evidence/historical-state-native-01/report.json).
Its J336 binds the supplied predecessor, complete state updates and exact R-F.
The native policy is one-shot: its fixed outpoint guard deliberately prevents
the successor continuing as a pool. A separate
[official Full-validator check](../poc/public-state-consensus-check/evidence/historical-state-consensus-01/report.json)
now accepts the same body under supplied UTXO/DAA context, with ten typed
negative cases. Its four policy cases use source-adapted predicates, not actual
Mempool admission. Synthetic context, absent owner exits and unqualified
relay/chain/backing remain explicit; neither
lower measured mass nor the unchanged 80m fee qualifies the payment-fee target.

[ADR-0037](adr/0037-offline-continuing-s7-owner-lifecycle.md) permits a separate
offline continuing experiment, with a [fresh instance's state core](../poc/s7-owner-lifecycle/state/src/lib.rs).
Its [first four genuine proofs](../artifacts/initial-four-public-fixture-20261022T1415/public/initial-proofs-manifest.json)
cover bootstrap, ADMIT and a pair at common count 5. A genuine state receipt and
paired native Full check subsequently pass in this separate profile. Its public
replay/owner CLI job remains parked following automatic safety rejection;
independent owner exits remain unexecuted. This does not select a fundable
privacy architecture.
Separate official Full checks now cover the supplied-seed founding/funding,
bootstrap/ADMIT prefix and two alternative ordinary SPEND forks. Those forks
consume the same predecessor and cannot be combined; the new guest/receipt and paired native Full checks now also pass. Accepted
chain/backing/owner qualification remains separate; no DRAIN was executed.

[RFC-0017](rfc/0017-price-priors-and-transaction-leakage.md) and
[ADR-0033](adr/0033-price-baseline-evaluation.md) record the
[completed price-baseline test](../poc/shared-pool/PRICE-LEAKAGE.md): 512 ledgers,
all 1,024 predictions sealed before truth, and both recounts passed. Observed
public/pooled `split_tail` accuracy was 13.53%/14.47% against the price prior's
20.88%. All three comparisons support below-five-point mean advantage; none
establishes positive advantage. Improve attack calibration/native observation
mapping before selecting another mitigation. No proof, note, reserve, exit or
runtime changes; the common-price workload remains unqualified.

The [sparse-case diagnosis](../poc/shared-pool/WORKING-BALANCE-SPARSE-DIAGNOSIS.md)
explains the failed partial-policy score without selecting a new architecture.
Eight of eleven successful partial-pooled guesses use unrelated payout supports;
three have ancestry without a closed value path. [ADR-0032](adr/0032-sparse-diagnosis-and-privacy-evaluation.md)
retains direct-L1 mechanics and stops general cashout-policy tuning. Next audit
public information, price priors and behavior assumptions before selecting a
mitigation. Wrong support does not prove no predictive signal; current privacy
requirements and unilateral-exit constraints remain unchanged.

[RFC-0016](rfc/0016-working-balance-withdrawals.md) and
[ADR-0031](adr/0031-arithmetic-working-balance-screen.md) scope an arithmetic
comparison of whole-note cashouts with requested partial payouts and retained
private change. This tests wallet behavior on the existing relation before
adding a wallet command. It introduces no protocol, circuit, setup, operator
or exit-authority change. Both arms retain immediate complete exit, account
for outside cash and re-entry, and eventually drain every private remainder.
The [completed screen](../poc/shared-pool/WORKING-BALANCE-PRIVACY.md) fails its
frozen continuation gate: overlapping independent demand improves, but sparse
pooled final amount accuracy does not; receipt-correlated partials worsen
guessing. The conditional native continuation is stopped. Existing partial-
payout mechanics remain available for research; no new wallet policy is adopted.

[RFC-0013](rfc/0013-coherent-v6-lifecycle.md) records the completed bounded offline
current-version integration. [ADR-0028](adr/0028-public-funding-replay.md) scopes an additive offline
public replay path whose descriptor identifies the pool rather than its users.
Actual funding-parent bodies supply native input context; proof declarations alone
do not establish backing. Authenticated accepted-chain/current-head selection
remains external to this component. Strict parent-format and retained-history
limits are explicit; the existing v6 relation and historical runners stay unchanged.
This replay component supplies the public-state foundation for the wallet below.

[ADR-0029](adr/0029-own-key-admission-and-recovery.md) now scopes an offline
own-key wallet around that replay interface. Backups pin pool and exact parameter
identities; receipt scanning covers ADMIT and SPEND with position-bound
nullifiers. The wallet derives native exits from its own key and generates fresh
proofs after restoration. [Source/reuse review](../research/shielded-kas-admission-recovery-2026-10-20.md)
records the existing primitives and older-recovery incompatibilities. The
[complete local trace](../poc/shared-pool/WALLET-LIFECYCLE.md) passes admission,
two original-backup restores, payment/change and fresh terminal exit.
Synthetic ancestry, offline expected heads and same-host isolation remain;
new chain acceptance and general recovery remain open.

The [native script-reuse diagnostic](../poc/shared-pool/ADDRESS-REUSE.md) confirms
that caller-selected funding indices can collide with this wallet's exit
derivation. A sparse, known-startup history then exposes an internal payment
through the repeated native script. That experiment changes no architecture,
derivation, backup format or invariant; its conditional disclosure is not a
32-role verdict. The subsequent [ADR-0030](adr/0030-separate-funding-and-exit-keys.md)
adopts separate funding keys for fresh v2 backups, with unchanged exit keys and
explicit legacy v1 interpretation. No migration or fallback is introduced.
Legacy backups retain the known reuse risk. The
[new candidate's offline retest](../poc/shared-pool/ADDRESS-KEY-SEPARATION.md)
passes ten genuine proofs and original-backup recovery/payout spending for both
profiles. Fresh v2 removes the tested script-equality inference; legacy v1 keeps
the positive control. Proofs, pool identity and recovery requirements are unchanged.
Broader payment privacy remains unqualified.

[ADR-0027](adr/0027-shielded-payment-targets.md) adopts the
[RFC-0012 requirements](rfc/0012-useful-privacy-requirements.md) and closes
milestone 1. These targets constrain future architecture choices; they do not
select a proof system/runtime, qualify v6 or change deployed pool rules.
Milestone 2 closes only bounded offline integration of the candidate's lifecycle
and native funding/recovery interfaces. The small-payment fee target is a known challenge
for individually verified transitions under the pinned relay policy.

[ADR-0026](adr/0026-scheduled-common-payout-screen.md) records H18's completed
optional local-withdrawal comparison on unchanged v6. Its short-delay policy
fits the fee/delay limits but does not reduce the strongest tested attack's
success, so it is not adopted and the conditional TN10 step is stopped.
The timing assumptions remain experimental wallet behavior, not protocol
restrictions. Keep private change and independent saved exits; no coordinator,
operator role, new relation or setup is introduced. [Result](../poc/shared-pool/SCHEDULED-PAYOUT.md).

[RFC-0011](rfc/0011-two-input-private-payments.md) defines a new compact pool
relation for two private inputs, two padded outputs, private payment change and
partial withdrawals. [ADR-0024](adr/0024-two-input-private-payment-scope.md)
records the scope and subsequent implementation. H13 passes its bounded
[offline](../poc/shared-pool/TWO-INPUT.md) and
[TN10](../poc/shared-pool/TWO-INPUT-TN10.md) trace: private change, partial
withdrawal, four wallets paid through six unchanged saved proofs, and zero
reserve. The live clients discover and validate accepted history themselves,
without the stopped prover or controller state. They share one host/RPC and
pin four known funding sources; this is not general wallet recovery.
Retain historical private authorization and current native covenant settlement,
with a no-append full-exit fallback, exact claim-funded fees and no privileged
withdrawal key. Padding requires new nullifier/capacity rules; terminal release
depends on authorized native value conservation, not note counts. Existing
v4/v5 pools and proofs do not migrate. The
[observer review](../poc/shared-pool/TWO-INPUT-PRIVACY-REVIEW.md) distinguishes
hidden private change from still-visible deposits, payouts, timing and anchors.
The new single-party setup and costs are measured but unreviewed. Independent
review, broader exit qualification, network acceptance and useful privacy remain open.

[H16's participant-disclosure study](../poc/shared-pool/PARTICIPANT-PRIVACY.md)
keeps this implementation unchanged. Its strict screen fails on two startup
payment links; fresh normal proofs retain more alternatives and fewer forced
withdrawal links than saved exits. Retain the compact settlement/fallback
candidate, with strong privacy still open. That result motivated the
withdrawal-amount comparison using existing partial withdrawals/private change.
[H17](../poc/shared-pool/COMMON-PAYOUT.md) now implements that bounded offline
comparison under [ADR-0025](adr/0025-common-payout-offline-screen.md). Its privacy
screen passes: separate participant views force 4/28 original cashout sources
after full drain, down from 7/28, with no new payment links. All four wallets'
independent exits pass with seven saved proofs unchanged. The protocol and
setup remain byte-identical; optional shaping never replaces the full exit.
All tails and fees count. The fixed schedule fails the unchanged delay target,
so keep optional shaping as a research candidate without adopting the schedule
or claiming strong privacy.

[H12's bounded funding-policy comparison](../poc/shared-pool/NORMALIZED-DEPOSITS.md)
adds equal net credits to H11's fresh-proof/private-fallback candidate. Its
offline screen leaves four funding deposits possible after full drain when all
four equalized deposits precede payments. [ADR-0023](adr/0023-equal-net-deposit-policy.md)
records the assumptions: this is a wallet policy on the unchanged v5 covenant
and v4 private relation, not an enforced denomination, a consensus change or a
production-privacy decision. Independent exits remain permitted when privacy
is weak. TN10 adapter validation is recorded separately in the report.

[RFC-0010](rfc/0010-compact-independent-deposits.md) and
[ADR-0022](adr/0022-compact-two-note-deposits.md) define a new immutable compact
pool version accepting independent native deposits. A signed ordinary input
funds two notes under the existing private relation/VK; the covenant adds exact
backing and commitment/history entries while leaving nullifier state unchanged.
The proof's virtual admission input is not a pool claim. Keep verified bootstrap
and independent public genesis/lineage validation. Earlier proofs **within the
new pool** must survive later deposits; deployed v4 proofs do not migrate.
The v5 implementation passed the bounded offline gate, including all eight saved
exits in four withdrawal orders. Complete TN10 rehearsal and a fresh measured
trial also passed: all eight original proofs settled, all four wallets were paid,
and both pools drained. The private
circuit/setup and L1 rules are unchanged. See the [measured report](../poc/shared-pool/DEPOSITS.md)
and [source review](../research/compact-deposits-source-review-2026-10-19.md).
The four-source harness list is not a native admission allowlist. Useful privacy
and population policy remain separate decisions.

[Stage 2's compact privacy audit](../poc/shared-pool/PRIVACY.md) reached its
redesign condition: an old count-three proof identifies the withdrawal's source
transaction even after 100 payments. [ADR-0021](adr/0021-separate-exit-fallback-and-privacy-policy.md)
retains reusable proofs for independent exits. [H9's offline comparison](../poc/shared-pool/FRESH-PROOF.md)
now supports fresh local authorization as a candidate normal path: target source
candidates grow to 3/5 with two/four later payments, and only one of the two proofs
can spend. [RFC-0009](rfc/0009-compact-anchor-privacy.md) remains open for population
policy; these three fixtures do not establish usable privacy. No circuit, covenant
or L1 change was made. Keep unused fallback authorizations
private, since old/new versions share a nullifier and expose the old restriction
if both are published. Full-exit amounts and single-deposit ancestry remain public.

[ADR-0020](adr/0020-independent-wallet-recovery.md) adds independent restoration
tooling for the compact variant. A wallet keeps its three existing private keys
and an authenticated pool-descriptor hash; the initial depositor additionally
keeps the initial note opening. Replaceable public copies supply parameters and
transaction history, while a separate synchronized node supplies accepted-chain
state. Recovery reconstructs witnesses and scans ciphertexts locally, without
the original experiment manifest or receiver list. The proof relation and
covenant are unchanged. [RFC-0008](rfc/0008-independent-wallet-recovery.md) and the
[recovery report](../poc/shared-pool/RECOVERY.md) distinguish offline validation,
independent-host TN10 evidence and remaining availability assumptions.
That bounded gate passed: all three wallets recovered and exited in a complete
rehearsal and fresh measured trial, with the original services stopped. Retain
this recovery path for the candidate; useful privacy and broader failure
conditions remain open, and the result does not select a production architecture.

[ADR-0019](adr/0019-compact-public-settlement.md) replaces the bounded arrays in
a separate experimental variant with note, indexed-nullifier and root-history
Merkle trees. The covenant checks public updates; the private proof retains its
historical anchor. [RFC-0007](rfc/0007-compact-state.md) requires 100 intervening
payments, Bob's unchanged proof, current spentness and complete drain before a
TN10 trial. The offline gate, complete short TN10 rehearsal and fresh 100-payment
trial passed: Bob reused his original proof, all 204 native transactions were
confirmed and every claim drained. Public history still grows and
the configured depth remains finite; compact state is not a privacy guarantee.

[ADR-0018](adr/0018-reusable-private-authorization.md) tests historical private
authorization plus current native covenant settlement. It preserves the earlier
experiments and requires current spentness, complete state retention and native
value conservation. [RFC-0006](rfc/0006-reusable-private-authorization.md) records
the offline/live gates and unresolved questions. The bounded
[offline and funded TN10 test](../poc/shared-pool/ANCHORED.md) passed: Bob's exact
private proof survived Alice's payment with a roughly 21-ms public-only rebuild.
Retain this separation for further direct-L1 research; larger-state privacy,
general liveness and cryptographic review remain open. The larger covenant costs
more per exit than v3.

[ADR-0017](adr/0017-note-floor-and-independent-exit-retry.md) adds a bounded
version-3 protocol note floor and an autonomous stale-proof exit retry test.
Its fee-rate and node-availability assumptions are explicit; results are tracked
in the [research journal](RESEARCH-JOURNAL.md).

The [four-wallet comparison](adr/0016-four-wallet-shared-pool-trial.md) extends
the direct trial with deposits, repeat private spends and private withdrawal
change. It measures chain-only inference before and after complete drain;
[RFC-0004](rfc/0004-four-wallet-shared-pool.md) scopes its limits.
Both funded arms completed on TN10; the
[result](../poc/shared-pool/README.md) records four separately authorized exits,
the partial-withdrawal comparison and its version-2 dust/contention limitations.
The separate [version-3 follow-up](../poc/shared-pool/CONTENTION.md) addresses
below-floor claims and one competing spend under explicit fee/availability
assumptions. It does not establish general adversarial liveness.

The bounded [direct self-funded TN10 trial](adr/0015-direct-self-funded-tn10-trial.md)
tests Candidate A with one reserve and native miner fees charged to private
entitlements. It does not adopt a production architecture; its open questions are
tracked in [RFC-0003](rfc/0003-direct-self-funded-trial.md).

The open comparison is in [RFC-0001](rfc/0001-state-architecture.md), pending review.

The [A0 feasibility experiment](poc-a0.md) investigates direct Groth16 proof
authorization and native payout constraints for one terminal claim. Its local
consensus-code evidence must be distinguished from funded TN10 acceptance and
the broader private-state/recovery requirements. This experiment does not select
Candidate A or accept RFC-0001. A0.5 now records a terminal TN10 release and
spent-input replay rejection through a retained-key/native-RPC test adapter
under [ADR-0002](adr/0002-a0-reserve-release-experiment.md), with no change to
the terminal proof statement or the candidate architecture.

The purpose of this document is to compare candidate ways to create optional privacy for native KAS without prematurely locking the project into one implementation.

## Initial asset scope

**Initial scope: native KAS only.** KCC20/private token transfers and trading are explicitly out of scope for the initial protocol and PoCs.

Where reasonably possible, the architecture should avoid design decisions that would unnecessarily prevent future support for KCC20 or other Kaspa-native assets. This is a future extensibility consideration, not a requirement for the initial protocol. It must not outweigh security, simplicity, native-KAS privacy, or other primary design requirements.

This is a reversible early-stage scope/design constraint, not a commitment to a long-term protocol feature or a selection of any candidate architecture. Future KCC20 or other asset support would require separate research and an explicit later design decision recorded in an ADR.

## 1. Common economic model

Regardless of implementation, the intended model is:

```text
native KAS enters
      |
      v
protocol-controlled reserve
      |
      +---- public commitments / state roots
      |
      v
private claims / notes
      |
private transfers change claim ownership
      |
      v
valid exit proof
      |
      v
native KAS leaves
```

A private note is best understood as a cryptographic claim on backing, not as a separate cryptocurrency.

The proof-statement specification must define separate integer accounting equations for deposits, private transfers, withdrawal requests, pending exits, completed payouts, and explicit fees. An unpaid exit remains a user liability after its private note is consumed. Reserve rent and externally sponsored fees must be distinguished from spendable user backing. Every actual reserve output and payout must be bound to the verified transition. See [proposal P06](INITIAL-ISSUES.md#p06--define-value-conservation-proof-statement) and [I-1, I-2, I-7, and I-12](../SECURITY-INVARIANTS.md).

If a user shields 10,000 KAS and privately pays 5,000 KAS, the public Kaspa ledger does **not** necessarily need to show a 5,000 KAS UTXO moving. The reserve can remain locked while private state changes which keys can later prove claims on that reserve.

## 2. Common private-state building blocks

A note-based design would likely need concepts such as:

### Notes

Private records containing at least some combination of:

- value;
- recipient/owner information;
- randomness;
- protocol/domain identifiers;
- metadata required for secure nullification and encryption.

Exact construction is undecided.

### Commitments

Public cryptographic commitments to private notes. Observers can verify inclusion without seeing note contents.

### Nullifiers

Public one-time values proving that a private resource has been consumed without necessarily revealing which commitment was spent.

Nullifier design is security-critical and should draw from mature systems rather than being improvised.

### Commitment/state tree

An append-only or otherwise verifiable structure tracking public commitments/state.

### Proofs

A spender proves the required facts without exposing private note contents, for example:

- valid ownership/authorization;
- input existence;
- authenticated spent-state checks and updates;
- value conservation;
- valid output commitments;
- correct prior state binding.

Note inclusion alone does not establish that an input is unspent. The design must specify how proof-verified spent-state updates and settlement duplicate-nullifier checks work together. A historical note inclusion anchor, if explicitly permitted, must not allow stale settlement/nullifier-state replay.

### Encrypted note delivery / discovery

Recipients must learn enough private data to recognize and later spend notes without revealing ownership to untrusted infrastructure.

## 3. Publicly observable boundaries

A likely shielded system cannot hide everything on the public L1.

Depending on design, observers may still see:

- native KAS entering the reserve;
- native KAS leaving the reserve;
- public commitments/nullifiers/state roots;
- Kaspa fees;
- timing;
- network-level behavior.

The privacy claim must therefore be scoped carefully.

Proof confidentiality against public observers does not automatically hide private witnesses from the prover. Specify local proving or disclose what a hosted prover learns. A based app must also explain confidential execution and what its public payloads and resource-access patterns reveal.

## 4. Candidate A: Minimal L1 covenant + ZK pool

Candidate A is the current experimental baseline: the smallest falsifiable use of current L1 primitives. It is not the accepted production architecture. [RFC-0001](rfc/0001-state-architecture.md) remains open. A0/A1 evidence informs its comparison; notes, nullifiers and private transfers may require major redesign or a different candidate.

### Sketch

```text
Deposit KAS
   |
   v
Covenant-controlled reserve/state UTXO
   |
private transition proof
   |
   v
Updated covenant/state UTXO
```

### Why it is attractive

- smallest candidate scope for a testnet settlement experiment;
- uses current Kaspa primitives directly;
- direct relationship between state progression and settlement;
- may demonstrate ZK verification and value conservation without a full application runtime, subject to verifier, budget, and recovery validation.

### Main concern: contention

If one state-carrying UTXO must be spent for every update, concurrent users may compete to consume the same state object.

This may be acceptable for a PoC but unattractive for a large privacy system.

### Research questions

- Can commitments/nullifiers be split across multiple UTXOs safely?
- Can batching reduce contention?
- Can state be sharded without fragmenting privacy or complicating exits?

## 5. Candidate B: Sharded/native covenant UTXO architecture

Instead of one state object, state could be partitioned across multiple covenant-controlled UTXOs or resources.

### Potential benefits

- greater concurrency using native UTXO parallelism;
- less dependence on an external shared-state runtime.

### Potential costs

- harder cross-shard/private-note semantics;
- more complex wallet behavior;
- fragmented state may reduce anonymity or complicate note selection;
- exit and rebalance paths may become difficult;
- proving across multiple state objects may be expensive.

This route should be evaluated rather than assumed to be superior merely because Kaspa is a UTXO system.

## 6. Candidate C: Based app / vProgs shared state

Kaspa's based-app model uses L1 for ordering/commitment while application execution and proving can happen in an application runtime, followed by proof-based settlement to an L1 covenant.

Simplified flow:

```text
Kaspa L1 lane activity
        |
        v
execute private app transactions
        |
        v
update shielded application state
        |
        v
prove receipts / batches / aggregate
        |
        v
settle proof to L1 covenant
        |
        v
new accepted application state
```

This pattern may amortize settlement across many operations. Whether that makes it suitable for a large shared shielded state requires benchmarks and a reviewed privacy/recovery model. Executed, proved, settled, and withdrawable states are distinct; asynchronous execution does not make an unproved exit withdrawable.

### Potential benefits

- batching may reduce L1 updates per user operation; settlement UTXOs still serialize updates;
- asynchronous proving/aggregation;
- potential throughput improvement that remains to be measured;
- application-level execution and storage tooling.

### Current limitation

The `kaspanet/vprogs` repository describes itself as early development / prototype. Kaspa's builder documentation describes full vProgs as the future direction for composition between independent apps, with the runtime still evolving rather than a stable external API or production dependency.

Therefore:

> Investigate which based-app/vProgs components, if any, this application needs. Neither vProgs nor sharding is preselected as the scaling path.

## 7. Safety and liveness separation

The architecture must explicitly distinguish:

### Safety

Can funds be stolen, inflated, or spent without authorization?

### Liveness

Can valid users make progress promptly?

A preferred design allows infrastructure to fail or be replaced without compromising safety.

A state root authenticates data; it does not supply commitment history, nullifiers, encrypted note delivery, or Merkle witnesses. Specify which data comes from retained Kaspa history, replicated archives, user backups, and independent software. Pruning and reorg handling must be explicit. Safely halting under I-9 does not satisfy recoverability under I-10 by itself.

For example, if prover A disappears, the desirable failure mode is:

```text
transactions temporarily stop
-> prover B reconstructs state
-> proving resumes
```

not:

```text
prover A disappears
-> user funds cannot ever be recovered
```

## 8. Exit architecture

**Open production blocker: fixed-fee exit liveness.** A1 precommits branch fees. Headroom helps only under bounded future conditions; higher relay/inclusion costs can prevent practical exits. Extraordinary miner cooperation is not an acceptable production exit design. A reviewed sponsorship or other mechanism must preserve reserve, accounting, authorization and output invariants. [Issue #23](https://github.com/olafweller/kaspa-privacy-initiative/issues/23) tracks this question; no mechanism is selected here.

A viable architecture must explain how a user can recover native KAS without cooperation from a privileged operator. A candidate must pass the [early exit and recovery gate](ROADMAP.md#early-exit-and-recovery-gate) before it is treated as credible.

Each candidate must specify:

- the exact proof or protocol condition authorizing native KAS to leave the reserve;
- the component that verifies that condition;
- the L1 covenant/script/state transition that releases the KAS;
- the public inputs bound to the proof and how they bind authorization to the corresponding native KAS payout;
- the required user-held material, including keys/secrets, note data, or backups;
- the required public or independently reconstructable state and history;
- whether an independent prover can reproduce the required exit artifact;
- the recovery and exit behavior when all default operators, provers, and executors disappear.

Open questions also include whether an emergency/escape path is needed and how exits remain safe during upgrades.

## 9. Candidate proof technology

No production proof system has been selected. A0/A1 use BN254/Groth16 because the current verifier makes it useful for the experiment. It is not post-quantum. A1's per-instance/fixed-context setups are not the intended scalable private-pool architecture; single-party setup provenance remains trusted.

Toccata provides native L1 ZK verification through `OpZkPrecompile`, including Groth16 and RISC Zero Succinct verification paths; see the [pinned verifier sources](../research/kaspa-toccata-vprogs.md#exact-verifier-surface). This capability does not require full vProgs. Other privacy systems provide lessons from Halo 2 and specialized circuits.

Selection should follow architecture and benchmarking, not branding.

### Proving topology

The architecture should evaluate both local and delegated proving. No proving topology has been selected.

Local proving has privacy and trust-minimization advantages because witnesses do not need to be exposed to external infrastructure. However, proving latency, RAM usage, and hardware requirements may make it impractical on some devices, especially mobile. The protocol should not assume that every user device can efficiently generate proofs locally.

If delegated proving is needed, the preferred direction is permissionless and provider-replaceable. A prover should provide computation, not custody or authorization over user funds. Failure or disappearance of a prover may affect liveness; it must not compromise fund safety.

Architecture comparisons should benchmark:

- proving latency;
- peak memory;
- hardware requirements;
- proof size;
- L1 verification cost;
- opportunities for batching or aggregation.

## 10. Architecture decision process

The next step is not to choose based on intuition.

Review the proposed [RFC-0001](rfc/0001-state-architecture.md), which compares:

1. minimal L1 covenant pool;
2. sharded/native covenant state;
3. based-app/vProgs shared state.

Evaluate each against:

- security invariants;
- exit safety;
- current Kaspa capability;
- implementation complexity;
- throughput/concurrency;
- state availability;
- wallet complexity;
- privacy/anonymity implications;
- proving cost;
- upgrade risk.

## Primary sources

- [Kaspa builder overview](https://kaspa.org/build)
- [Kaspa based-app documentation](https://github.com/kaspanet/docs/blob/main/content/docs/toccata/based-apps.mdx)
- [vProgs repository](https://github.com/kaspanet/vprogs)

## Public based-app native-value integration experiment

[ADR-0004](adr/0004-public-based-app-native-value.md) scopes the authorized
[public native-value PoC](../poc/native-value/MAPPING.md) following PR31. It combines
existing vProgs account Deposit/Withdraw actions and delegate/permission scripts
with the demonstrated monolithic lane proof. Public balances are temporary test
state, not private notes or a new asset. User backing excludes state-covenant
rent and sponsor fees; an unpaid permission claim remains a liability until L1
consumes it into a payout. Full runtime composition, privacy, mandatory processing
progress and independent recovery remain open. RFC-0001 remains Open.

## Recursive public-account research follow-up

[ADR-0005](adr/0005-long-gap-recursive-takeover.md) and the
[recursive adapter](../poc/takeover/README.md) replace the monolithic proof route
for an isolated experiment: the complete public account state is one SMT
resource, transaction journals feed reference batch verification and batch
receipts feed reference aggregation. This deliberately serial state model is not
a production scheduler or privacy design. The source-pinned local review checks
historical public inputs. A separate [fresh TN10 rehearsal](../poc/takeover/LIVE-REHEARSAL.md)
now confirms a deposit, clean public reconstruction after a 175-blue-score stop
gap, recursive settlement and native payout, with reserve matching the remaining
account balance. This used the same owner/node and retained public archive.
Native expiry is rejected inside the batch guest; unavailable public history
can halt recovery. No privileged withdrawal path is introduced.

## Feasibility checkpoint and private-protocol focus

The [five-criterion assessment](based-app-feasibility-2026-10-17.md) concludes the
public Based App integration milestone from PRs #31–#33. Ordering completeness
within a claimed interval, correct public execution and native settlement are
established for those experiments; privacy, mandatory progress and independent
recovery are not. The next [shielded-KAS work package](shielded-kas-next.md) must
specify confidential ownership/value, spentness, retained data and exact native
backing before implementation. A/B/C remain comparison candidates, not accepted
production designs. No new primitive or admin path is selected by this checkpoint.

## Protocol evolution and privacy-preserving migration

**Status: design requirement and open research, not a selected upgrade mechanism.** See [principle 25](../PRINCIPLES.md#25-privacy-preserving-protocol-evolution), [RFC-0001](rfc/0001-state-architecture.md#privacy-preserving-version-migration-research), and existing [issue #19](https://github.com/olafweller/kaspa-privacy-initiative/issues/19) on cryptographic/PQ migration.

Before defining the first production shielded pool, evaluate how future versions could be deployed without giving an administrator the power to rewrite existing verification rules or seize reserve assets. Favor independently verifiable version identities and voluntary user authorization; immutable parallel versions are a candidate, not an accepted decision.

A user should not be forced to make a transparent withdrawal and fresh deposit merely to adopt improved privacy rules. Investigate a proof-authorized, value-conserving shielded-to-shielded migration path with authenticated old/new pool identities, spentness across versions, exact reserve/exit accounting, and no privileged bypass. A direct mechanism may require additional covenant capabilities and does not automatically conceal timing, amounts, origin/destination links, fees, or network metadata.

A user who never upgrades must not be silently stranded by project policy or a discontinued website. Specify how valid legacy claims remain independently spendable or recoverable when executors, provers and maintainers disappear, which old verifier/programs and public histories must remain accessible, and what user-held notes/witnesses/backups are required. Unchangeable contracts alone cannot guarantee availability if data, consensus support, fee access, or cryptographic security are lost.

Any proposed migration mechanism must be tested for unauthorized movement, reserve conservation, double claims across versions, replay/downgrades, partially completed migration and unpaid exits. Compare privacy leakage under low activity and long dormant periods, and include old-version users in the multi-user recovery/shutdown test. Do not implement or approve a migration path solely on these requirements; select it only after a separate reviewed RFC/ADR and scoped test evidence.

## Proposed private-payment statement and local compatibility

[RFC-0002](rfc/0002-shielded-payment.md) proposes the hidden ownership/value,
current nullifier, delivery, deposit recovery and unpaid-exit interfaces. The
[local work package](../poc/shielded-design/README.md) exercises an ideal economic
model and real representative wallet -> transaction -> reference batch/aggregate
composition with local native script verification. It selects no production
note/encryption construction or funded deployment. Missing/wrong recursive
assumptions abort; a cryptographically enforced invalid-operation no-op remains
unimplemented. Intent must exclude proof bytes to avoid a circular native-ID
binding. PR34's shared economic single-consumption and voluntary migration/legacy
requirements remain open. [ADR-0006](adr/0006-shielded-design-local-work-package.md)
records the bounded local research decision only.

The [local classification follow-up](../poc/proof-classification/RESULTS.md),
under [ADR-0007](adr/0007-local-proof-classification.md), executes ordinary
receipt verification on canonical proof bytes and obtains valid-invalid-valid
outcomes. Its full run requires 870,829,938 user cycles and 880 proof segments;
no outer receipt was generated. The native-ID sequence is a fixed local fixture,
not an accepted TN10 endpoint. Affordable proved classification and real-lane
integration remain blockers; this result does not qualify the privacy circuit.

The [specialized Groth16 comparison](../poc/groth16-comparison/RESULTS.md), under
[ADR-0008](adr/0008-specialized-groth16-comparison.md), retains the same small
SHA-256/u64 statement and reduces complete proxy operations to 702 bytes.
Its ordinary in-guest verifier does not finish the agreed 32-million-cycle run,
so no outer receipt is produced. Circuit-specific setup and immutable prepared
parameter pins are explicit new assumptions. Compact wallet proofs are promising
for publication, but affordable proved classification and actual private/native
integration remain open.

The [accelerated BN254 qualification](../poc/accelerated-bn254/RESULTS.md), under
[ADR-0009](adr/0009-accelerated-bn254-qualification.md), reuses those exact proofs
and finishes the full correct sequence in a separately bounded calibration:
117,473,222 cycles, 121 segments. Actual pinned-VM/precompile compatibility is
demonstrated. This still fails the predeclared 32M practical cap; no outer proof
is attempted. A new classifier identity is pinned before execution. An explicit
larger practical-budget decision and full-sequence adversarial qualification
must precede any one-hour outer-proof attempt or private-note expansion.

The owner-approved [128M proof experiment](../poc/outer-proof-128m/RESULTS.md),
under [ADR-0010](adr/0010-approved-128m-outer-proof.md), completes all 24 full/narrow
adversarial execution cases with the same classifier image. Its one real
succinct-proof attempt is stopped at the one-hour whole-job limit without a
receipt, using four logical CPUs and 9.19 GiB peak sampled summed RSS. This closes
the missing replay/continuation execution checks, not the outer-receipt milestone.
Profiling actual proof production/compression remains necessary before expanding
to private notes; no new setup, accepted L1 endpoint or native funding is added.

The [bounded phase diagnostics](../poc/proof-phase-diagnostics/RESULTS.md) retain
two segment proofs, two lifts and an actual adjacent join, all independently
reverified. Segment proving dominates the measured costs; the original guest,
wallet relation and proving architecture are unchanged. These middle-segment
receipts are not a complete classifier proof. The next proposed qualification
is the official pinned CUDA proving path on the same retained assets.

## Local private-note experiment checkpoint — 2026-10-18

The [complete classifier receipt](../poc/remote-cuda/FULL-RESULTS.md) closes the
older test-model outer-proof blocker. [ADR-0011](adr/0011-local-private-note-wallet.md)
records a new experimental wallet circuit and local application kernel: hidden
SHA256 Merkle membership, rightful HMAC economic nullifiers, bounded conservation,
version/domain/verifier and output/delivery binding, independent recipient
validation, current spentness and deposit/exit liabilities. The first tree has
four slots and zero app fees, chosen only for the Alice/Bob research lifecycle.
This is not selection of a production commitment/encryption construction.

The new kernel's native inputs/payout confirmations are explicitly test fixtures;
its transitions are not yet proved in an outer guest. The next chain must bind
new transaction/batch/aggregate program identities to the existing native
Succinct verification ABI. A wallet receipt or the old 167-byte classifier
journal cannot substitute for that native aggregate statement. User witnesses
remain local; external executors/provers receive only public operations/state.


## Private-state integration calibration — 2026-10-18

[ADR-0012](adr/0012-private-note-state-integration.md) fixes a distinct unfunded
TN10 economic domain before a new wallet setup/image. The monolithic
[calibration guest](../poc/private-note-chain/README.md) binds a previous private
resource/config, actual v1 preimage IDs and computed native lane endpoints,
checks deposit value/script/owner references, verifies ordinary wallet proofs
and emits the existing 352-byte aggregate ABI plus permission commitments.
Reference per-transaction journals are decoded but no separate recursive
transaction/batch/aggregate proof is produced. Completed journals match the
independent native reference; the full three-proof execution hits 128M.

The new [binding map](../poc/private-note-chain/BINDINGS.md) distinguishes these
checks from canonical native acceptance, actual permission consumption/payout,
fee/rent handling and independent recovery. A permission commitment does not
confirm a payout or release reserve. No host fixture may bypass these gates.


The [separately approved 160M calibration](../poc/private-note-chain/calibration-160m/RESULTS.md)
completes that identical monolithic execution at 139,763,284 user cycles and 143
segments. Its exact 352-byte journal preserves the same program/VK identities;
only host/runner selection changed. It still starts after synthetic deposit
registration and contains no exit/payout. The
[next proof manifest](../poc/private-note-chain/calibration-160m/next-proof-target.json)
records exact program, state, lane and journal identities, explicitly distinguishing
relation-domain slots from absent recursive transaction/batch image identities.

The [fixed proof package](../poc/private-note-proof/README.md), recorded in
[ADR-0013](adr/0013-private-note-proof-package.md), now prepares that unchanged
claim for a genuine Succinct receipt. Its native variant explicitly pins
`join.zkr`; earlier assumption-composing fixtures retain `resolve.zkr`. Producer,
independent CPU verification and actual native fixture checks share independently
compiled image/control/journal expectations. Archived PR43 verification qualifies
only join/precompile compatibility. The new private receipt/native positive is
subsequently completed by the owner-reviewed and released
[single L40S run](../poc/private-note-proof/gpu-2026-10-18/RESULTS.md): a genuine
139,763,284-user-cycle Succinct receipt in 243.088 seconds, independent CPU
verification and local native positive/fifteen-negative checks. The correct
352-byte journal and 1,000,000,000-sompi fixture backing are enforced. Provider
stop and deletion were confirmed after external preservation. No runtime,
privacy relation or backing rule changed; canonical deposit lineage, Bob's exit
and actual native payout remain open.

## Local private/native lifecycle preparation — 2026-10-18

[ADR-0014](adr/0014-private-native-lifecycle.md) and the
[local package](../poc/private-native/README.md) connect zero-liability deposit
registration, real private credit/payment, Bob's independent exit proof and
native permission/delegate payout reconciliation. State-covenant rent 100M is
separate from the user delegate reserve 1,000M and sponsored permission rent 50M;
Bob's 400M exit remains an unpaid liability until the accepted native permission/
reserve spend and at least 450M recipient output (including 50M rent refund) justify
discharge. The remaining delegate principal/private liability is 600M.

The separate guest carries full state, reserve/permission outpoints and active
lane continuity beyond the old short fixture's 100-score cap. Four connected
batches and 17 additional cases ran in the zkVM; actual local native payout scripts
accepted/rejected their targeted variants. The sponsor builder supports the
private lane before signing. These are synthetic accepted-lane/UTXO fixtures,
not native chain acceptance. Genuine new lifecycle receipts, native permission
issuance and terminal TN10 confirmation remain future gates under the
[proposed rehearsal plan](../poc/private-native/TN10-PLAN.md). No new GPU rental,
funding, broadcast or general architecture selection follows from preparation.

The [PR49 review correction](../poc/private-native/REVIEW-FIX.md) enforces the
private lane in both the state covenant and issued permission, preserves these
restrictions in continuation, and pins a sufficient reserve per admitted exit.
Other registered deposits remain tracked. Partial consumption and additional
sponsor inputs/outputs are excluded by native rules; recipient top-ups are
accounted correctly. The builder checks the supplied restricted permission bytes against the actual
UTXO hash; live construction still must use the restricted state adapter.

The [fixed four-batch GPU package](../poc/private-native-proof/README.md) reuses
these reviewed identities without changing the guest or native relation. A single
externally watched process group covers all four proofs, compression and local
CPU/native checks. B independently re-verifies returned data using trusted local
executables. A new immutable image identifies this workload separately from PR47.
Software preparation does not establish new receipt or TN10 acceptance evidence.


### Authenticated local history reuse (2026-10-26)

[ADR-0073](adr/0073-shared-baseline-peer-acquisition.md) also completed actual
shared-baseline acquisition: one prepared prefix, lawful boundary recompression,
seven-source binding and 13 financial sources unchanged. These ordinary host bytes do
not grant external cache authority or qualify independent retention.

[ADR-0067](adr/0067-authenticated-local-prefix-reuse.md) selects a bounded cache experiment after the first ADR-0066 payment was confirmed on TN10. A controller may reuse only its own admitted, byte-identical verified prefix, fetch a fresh fixed-frontier delta, verify all new headers/edges, and replay every selected pool transaction with native Full and the existing financial rules. Local admission is a performance/evidence assumption; public receipt fields are not authority. External imports require full verification, and reorg/current-UTXO checks remain mandatory. The native domain, keys, policy, amounts, fees and once-only submission rules are unchanged. Activation still requires independent controls and an actual cached/full comparison.

The actual second-payment cached/full comparison passed. The bounded extension
in the same ADR stages host-guard-admitted public bytes into an immutable,
offline namespace for the original replay and preflight code. A genuine full
replay produced all five financial/SDK files byte-identically twice; measured
warm replay took about 76–80 seconds after separate admission work. New wrappers
require an explicit outer source profile and their own qualification. Tor
acquisition, live queries, private intent journals and single submission remain
outside that public worker. No new key, native domain or release authority is
introduced. The six-payment/nine-payout rehearsal is now complete; final DATA
publication verification remains separate.


### Owner-consent, proving components and RPC acquisition (2026-10-27)

[ADR-0068](adr/0068-offline-owner-consent-aggregation.md) retains 49 authority and 29
aggregate actual R1CS checks. The 42 canonical field-encoding controls do not
verify a complete 128-byte proof/curve/subgroup relation. The qualified one-Output
matrix gate matched 15 controls (2 SAT,6 residual UNSAT,4 assignment and 3 matrix
refusals), preserving one actual NativeOutput matrix plus two digest equalities.
Multiple circuits, setup/proofs, malicious MPC, native batch and fee/privacy
qualification remain unbuilt. 119 MB of raw matrix/assignment outputs stays local.

The [one-Output contract](../research/next-session/local-private-payment/privacy-next/native-batch-exception-contract-01/ONE-OUTPUT-QUALIFICATION-CONTRACT-01.md)
and [direct Native Arkworks 0.6 assessment](../research/next-session/local-private-payment/privacy-next/direct-native-composition-01/SOURCE-ASSESSMENT-01.md)
compare source options without selecting architecture. Required gnark commitment/
PoK checks cannot be dropped; signature-gadget, full-witness private-prover,
delivery and authority gaps remain explicit. Same-state synthetic replay and a
plaintext constructor do not supply privacy. New note/KDF/Spend/Exit, complete
validity, state/replay and recovery rules need their own review.

[ADR-0069](adr/0069-separate-read-only-rpc-client.md) and the shared-prefix family
successfully acquired the final confirmed history. The seven-source sidecar
remains separate from unchanged financial SDK/runtime/admission/submission
checks. The [19-case/three-observer result](checkpoints/2026-10-27.md)
is bounded validating-node/public-model evidence. FinalDATA 9-Original audits
and Tor readback remain pending at this source freeze; independent administration,
off-host recovery and long-term retention remain unproven.
