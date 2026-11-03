# Open Research Questions

The initiative should treat these as questions to answer, not conclusions to defend.

[RFC-0021](docs/rfc/0021-confirmed-native-private-payment-rehearsal.md) now
closes the bounded confirmed-TN10 lifecycle: six accepted native bodies, two
seed-backup recipient payouts and zero remaining reserve/liabilities. How can
clients replace its selected-node/archive trust with independent discovery,
durable data and reorg recovery? How can the same asset/authority model meet
strong financial privacy and general per-user fee targets? Separate exact-SHA
optimization halves the FFT domain, but its first four-worker proof still misses
10 seconds and 4 GiB at 11.17 seconds / 4.009258 GiB. The next equivalent HMAC
candidate reaches 10.495 seconds / 3.82531 GiB in one fresh four-worker proof,
clearing the isolated memory screen while still missing warm latency. Can the
complete wallet meet both targets across a declared workload and p95? Further
work must retain those failures and leave funded instances intact.

[RFC-0020](docs/rfc/0020-private-proof-and-native-exit-integration.md) now
records a [passing complete offline lifecycle](research/next-session/private-integration/RESULTS.md)
joining the actual private circuit, native public admission and self-funded
reveal. The same payer's two useful 10-KAS payments amortize one verifier at
1.85177% and 1.85071% complete native fees, counting founding, admission and both
cashouts. How can fresh testnet identities authenticate accepted ancestry,
current state and available public data through confirmed payout? How can the
198.12-second, 5.41-GiB primary proof meet wallet resource targets? What composition
can support generic recipient-plus-change or independent owners without pooling
their private witnesses? Source floors and historical aggregation latency remain
failures, not measurements of a new affordable route.

The selected [receive-V2 separation](research/next-session/private-integration/INVOICE-V2-CONTRACT.md)
removes one shared-note incoming equality while retaining directory linkage and
selected-note reveal disclosure. Can real accepted public data support old-backup
discovery and witness refresh without a trusted archive/current-head oracle,
including orphaned disclosure history? A passing recipient reference or genuine
proof does not close that recovery or financial-privacy question.

[RFC-0019](docs/rfc/0019-fees-and-independent-exit-obligations.md) separates an
unconsumed private note from an already accepted unpaid exit entitlement. Can
either complete path meet the unchanged minimum-claim and per-user lifecycle
targets without another user's arrival, hidden sponsorship or discarded
liability? The [selected offline experiments](docs/adr/0039-exit-liability-and-native-claim-experiments.md)
test liability/service-loss counterexamples and the full fee contract of an
existing native terminal claim. A hypothetical revealing future note additionally
needs destination binding, an identical current NF and private-spend authority
that remains secret after revelation; current v6 notes do not supply that branch.
[ADR-0040](docs/adr/0040-public-revealing-exit-feasibility.md) now selects only a
public feasibility checker for that new relation. Can the complete native body,
including current-state proofs, signature, future-code byte allowance and KIP9
storage, fit100,000 mining mass at the60M claim endpoint? Even if it can, what
genuine private relation, recipient descriptor and admitted funding would make
the same claim safely available before any exit request is accepted?
The [new native probe](research/next-session/exit-fee/RESULTS.md) now passes its
frozen current-state/authorization cases and self-funded60M rate500 screen for
minimal/32KiB layouts with terminal or60M-remainder contexts. Larger layouts
and small tails still fail. Can a genuine combined private relation preserve
the exact-backing/floor condition, account for padded NF identities and fit that
byte envelope without changing any existing supported claim or privacy target?

[ADR-0038](docs/adr/0038-bounded-cost-and-proving-qualification.md) prioritizes
cost and proving qualification before larger batches. Which architecture can
avoid the [conditional admission-plus-exit fee floor](research/next-session/fee-frontier/README.md)
without hiding a payer, requiring another user's arrival or changing supported
claims retrospectively? The [current primary-source comparison](research/next-session/native-kas-singleton-fee-alternatives-2026-10-22.md)
distinguishes a cheap claim after earlier settlement from the full unsettled
singleton exit. The existing workload's price-prior limit remains independent
of either cost optimization. No new architecture or requirement is selected.
The [ordinary1600 candidate](research/next-session/ordinary-budget/REPORT.md)
now closes the measured rate200 gap under unchanged fees, while S7 defaults
remain1700. How should a separately reviewed adoption preserve historical
operational budgets and qualify every intended mode without promoting
source-only DRAIN coverage into executed exit evidence?

[ADR-0034](docs/adr/0034-public-proof-composition-experiment.md)'s
[two-v6 experiment](poc/two-v6-binding/README.md) now has genuine compatible
development proofs, a pinned paired guest, an independently verified Succinct
receipt and a passing [bare native opcode check](poc/public-receipt-native-check/README.md).
These close the scoped proof-composition predicate gate, using a separate test
setup; they do not close transaction acceptance or the original-instance gap.
[RFC-0018](docs/rfc/0018-paired-native-settlement-experiment.md) asks what a new
native transition must additionally bind: authenticated accepted history,
current nullifiers, complete successor state, exact reserve/fee accounting and
owner exits independent of another user or outer prover. The existing J42 does
not expose/bind an externally supplied count/anchor. Which minimal reviewed
extension can meet those obligations without weakening an invariant?
[ADR-0035](docs/adr/0035-synthetic-state-aware-assertion.md) scopes the next
NONFUNDABLE assertion experiment; its
[two independent synthetic contexts](poc/two-v6-state/public-fixtures/manifest.json)
are frozen. The [state core](poc/two-v6-state/common/README.md) reproduces both
exact J336 results and passes 14 host groups. The independent corpus agrees on
128 positive/35 negative decisions, retaining one expected-label discrepancy.
The [new guest/receipts](poc/two-v6-state/README.md) and one-shot native
input-script diagnostic now pass their fixed cases. A separate
[official Full-validator check](poc/public-state-consensus-check/evidence/historical-state-consensus-01/report.json)
accepts that same body under supplied UTXO/DAA context; actual Mempool/chain
admission remains untested. What additional design can provide accepted
lineage/backing and genuine independent owner exits
without reusing this deliberately noncontinuing successor as a live pool?
The separate [ADR-0037](docs/adr/0037-offline-continuing-s7-owner-lifecycle.md)
experiment now has four genuine initialization/SPEND proofs, a new guest
receipt/compression and actual paired native Full checks. Those do not
establish accepted lineage or independent exits; the
owner/replay job is parked for this run after automatic safety rejection.

The [public-native adapter](poc/shared-pool/PUBLIC-NATIVE-OBSERVATION.md) now
reconstructs all retained public witnesses and agrees with supplied-context
native validation. How should a client authenticate descriptor, parent ancestry
and the current accepted endpoint independently? The separate
[budget screen](poc/shared-pool/PUBLIC-NATIVE-BUDGET.md) fits 13 genuine cases at
1,600 while retaining their 40m fee. [ADR-0036](docs/adr/0036-v6-native-budget-1600.md)
now adopts that v6 factory default after genuine factory/historical-replay and
boundary qualification. What complete transaction/exit envelope,
including high fees and minimum notes, can satisfy the unchanged requirements?
Keep those questions distinct from source-only bounds, receipt compression and
the [completed price-baseline result](poc/shared-pool/PRICE-LEAKAGE.md).
Existing privacy qualification limits and rejected withdrawal policies remain.

[Milestone 1's accepted requirements](docs/rfc/0012-useful-privacy-requirements.md)
now fix the repeated-payment use case and quantitative privacy/operating targets.
Which current-L1 architecture can meet them, especially the small-payment fee
endpoint? How can one current-version client authenticate live admission, receipt
acceptance and recovery without fixture metadata? Milestone 2's bounded offline
integration now passes; the live/data-survival questions remain. The
[decision](docs/adr/0027-shielded-payment-targets.md)
closes requirements only; exact experiment manifests remain prospective.

[RFC-0013](docs/rfc/0013-coherent-v6-lifecycle.md) now maps the coherent lifecycle
and invariant obligations. Its first slice resolves funding from actual public
parent bodies rather than a participant list. How will a general client obtain
authenticated parents older than its discovery window, identify the current
accepted reserve, and preserve everything needed for v6 backup recovery?
Offline receipt recovery now passes; the component does not resolve independent
availability or accepted-head authentication.

[ADR-0029](docs/adr/0029-own-key-admission-and-recovery.md)'s
[bounded trace passes](poc/shared-pool/WALLET-LIFECYCLE.md): a new own-key participant
admits, restores admission/payment notes from a prior backup, spends recovered
value/change, and freshly exits through drainage on unchanged v6 parameters.
How will live clients authenticate a fresh endpoint, discover native payout coins
and recover from surviving independent public sources? The local synthetic trace
does not answer those questions or establish useful privacy.

[H18's completed comparison](poc/shared-pool/SCHEDULED-PAYOUT.md) rejects the
tested short-delay common-payout policy: the strongest attack's success is
unchanged on new workloads in both regimes/profiles. Fees and delay fit the
limits, but all sparse common payouts can be paired with their remainder
under the declared normal-policy timing assumptions. No conditional TN10 run
follows. What cashout behavior can realistically retain overlap with other
activity while preserving immediate independent exit? Decide the acceptable
privacy/latency tradeoff before another implementation, rather than tuning
these frozen workloads or claiming all current-L1 designs are excluded.

[RFC-0011](docs/rfc/0011-two-input-private-payments.md) now has a bounded
[offline result](poc/shared-pool/TWO-INPUT.md) and
[TN10 result](poc/shared-pool/TWO-INPUT-TN10.md): two-input payments, spendable
private change, partial withdrawal and all four wallets paid through six
unchanged saved proofs. The selected fee is 0.4 tKAS per pool operation;
the new circuit takes about 20–22 seconds per warm proof and roughly 3.4 minutes
to cold-load parameters in the recorded runs. Can review validate its constrained
padding, backing induction and no-append exit capacity beyond the tested trace
and constructed boundary state? Can the costly native budget be reduced safely?
Can varied, interleaved payments retain useful ambiguity after full drainage
under an observer that permits merging and padding? Exact fees, public-data
availability, experimental setup, contention and reorg assumptions remain.
The [scope ADR](docs/adr/0024-two-input-private-payment-scope.md) and
[observer review](poc/shared-pool/TWO-INPUT-PRIVACY-REVIEW.md) leave general
privacy and broader qualification open. Live clients reconstruct accepted state
from one RPC without the original prover; general recovery, arbitrary new
depositors and adversarial availability remain untested for this adapter.

[H17](poc/shared-pool/COMMON-PAYOUT.md) answers its narrow common-payout question
positively: one frozen 2-tKAS partial cashout per wallet reduces original-source
links from 7/28 to 4/28 across separate participant views after all remainders exit.
Original payment links stay unchanged, and all four wallets independently
exit with saved proofs. Four extra operations add 1.6 tKAS to the fixture;
its forty added synthetic minutes exceed the unchanged thirty-minute target.
H18 tests one practical schedule within that target and fails its privacy
requirement on new workloads. Neither tested schedule is adopted. Startup
inference, broader workloads and real-world privacy remain unresolved; no L1
change is selected.

[H12](poc/shared-pool/NORMALIZED-DEPOSITS.md) answers the narrow equal-net question
positively in its all-deposits-first workload: four deposit candidates remain
for every withdrawal through drainage on the existing relation. What survives
when deposits, payments and withdrawals interleave, amounts differ, or one
payout becomes externally attributable? Equal gross amounts still expose the
112,000-sompi bootstrap/admission fee difference. Equal net credit is a candidate
wallet policy, not covenant-enforced behavior or a guarantee of compatible users.
Synthetic results and testnet acceptance establish neither real-world anonymity
nor RPC/network protection.

[Stage 2's compact audit](poc/shared-pool/PRIVACY.md) reached its old-anchor
redesign gate. [H9's bounded offline test](poc/shared-pool/FRESH-PROOF.md) now
supports fresh authorization plus a private independent fallback: 3/5 target
source candidates after two/four payments, with either winner preventing the
other spend. Which common-anchor/withdrawal policy improves inference success
across independent ledgers at acceptable proving cost and delay? How much
remains inferable from full-exit amounts and one-input split structure?
[RFC-0009](docs/rfc/0009-compact-anchor-privacy.md) keeps that population question
open. Independent admission has a v5 candidate; partial exits remain absent
from that older compact variant and are now tested separately in v6 offline.

[RFC-0010](docs/rfc/0010-compact-independent-deposits.md) records the deposit
prerequisite: can a distinct native branch reuse the existing two-output proof
to add exactly backed claims without modifying spentness or invalidating earlier
exit proofs in the same new pool? Can four separately funded wallets drain all
eight notes with their provers stopped? The [offline gate](poc/shared-pool/DEPOSITS.md)
and complete TN10 rehearsal/measured trial passed with all wallets paid. Its
two-note minimum, extra full exits and added covenant fees may make a dedicated
one-note admission relation preferable later. No deployed v4 migration is implied,
and this result does not answer the population privacy question.

[Stage 1 recovery](docs/rfc/0008-independent-wallet-recovery.md) tests the compact
candidate using pre-payment private backups, independently retained public data
and a separate node; its bounded offline/rehearsal/measured trial passed. The
initial depositor's note opening is an additional
backup requirement; recipient keys do not eliminate the need for public history.
After this bounded test, what retention, pruning and reorg model would preserve
recovery for long-offline users? Does the compact transaction layout provide
useful chain-only privacy before we expand wallet features? Track the measured
scope in [RECOVERY.md](poc/shared-pool/RECOVERY.md) and the
[branch plan](docs/SHARED-POOL-PLAN.md).

The [local receipt-classification follow-up](poc/proof-classification/RESULTS.md)
executes valid-invalid-valid processing, but needs 880 proof segments; no outer
receipt or actual accepted-lane integration is demonstrated. Affordable proved
classification, full private note rules and complete native budgets remain open.

The [specialized comparison](poc/groth16-comparison/RESULTS.md) demonstrates small
real wallet proofs, while in-guest verification exceeds its agreed 32-million-cycle
cap. Which maintained verifier backend and declared practical budget can produce
the complete outer classification receipt without weakening the statement?

The [concrete accelerated backend](poc/accelerated-bn254/RESULTS.md) is compatible
and completes the same sequence in 117.47M cycles, measured under a separate 128M
calibration cap. Should a new practical 128M experiment qualify full adversarial
execution and attempt one real outer proof within the unchanged one-hour cap?
The original 32M result and absence of any outer receipt remain unchanged.

That [128M phase has now run](poc/outer-proof-128m/RESULTS.md): all 24 full/narrow
execution cases pass, but one real proof job reaches its one-hour stop without
returning a receipt. Which segment-proving/compression work and memory/cache
behavior dominate the bounded prover cost? The complete cost remains unknown;
do not infer total proving throughput from execution time or claim a receipt.

The [bounded phase diagnostics](poc/proof-phase-diagnostics/RESULTS.md) now retain
five real partial receipts, independently reverified: two full segments cost
415-421 seconds each, lift 33-34 seconds and join 36 seconds. Can the official
pinned CUDA prover qualify these same assets at a suitable cost before another
full attempt? Full-session proof costs and GPU compatibility remain unmeasured.

The [A0.5 terminal reserve experiment](docs/poc-a0.md) and its retained-key/native-RPC
adapter test one narrow proof-authorized payout. They do not answer the open
private-state, independent-recovery or anonymity questions. [Draft A1 PR #22](https://github.com/olafweller/kaspa-privacy-initiative/pull/22) adds local/native-synthetic successor-liability evidence and qualification repairs; full G5 and live G6 remain unclosed/unexecuted respectively. Fixed-fee exit liveness is tracked in [issue #23](https://github.com/olafweller/kaspa-privacy-initiative/issues/23).
Live outcome and remaining validation gaps belong to that evidence report.

## 1. Minimal Kaspa architecture

- What can be implemented today using current Toccata primitives?
- What requires covenants?
- What requires on-chain ZK verification?
- What requires sequence commitments / based-app infrastructure?
- Which functions, if any, truly require full vProgs?
- Can a minimal privacy proof-of-concept be built before vProgs stabilizes?

Primary question:

> **What is the minimal architecture for shielded native KAS using current Toccata primitives, and which parts actually require a based-app/vProgs architecture?**

## 2. Existing Kaspa work

- Has a usable TN10 shielded-pool implementation already been built?
- Which public repository, branch, or commit contains it?
- What are its trust assumptions?
- Which privacy properties are already proven and which are only claimed?
- Can we collaborate with or extend existing work rather than duplicate it?

## 3. State model

- Should private value use a note-based UTXO model?
- How are note commitments structured?
- How are nullifiers derived?
- How is the commitment tree maintained?
- Which state is public, encrypted, local to wallets, or reconstructable?
- Can a new independent node reconstruct everything required to verify the system?

## 4. Fund safety

- Can a malicious prover ever violate fund safety, or only delay progress?
- Can an executor alter balances without producing an accepted proof?
- Can any invalid transition cause the pool to become undercollateralized?
- How is overflow, rounding, or value-conservation handled?
- What exact integer equations cover deposits, transfer fees, withdrawal requests, pending exits, completed payouts, reserve rent, and externally sponsored fees?
- How does consuming a note into an unpaid exit preserve the outstanding user liability?
- How are malformed or duplicate nullifiers rejected?
- How do note inclusion, authenticated spent-state updates, and settlement duplicate rejection fit together?

## 5. Exits

- Can users exit without cooperation from a privileged operator?
- What exact Kaspa L1 covenant/script verifies or consumes the result of an unshield proof?
- What exact public inputs must be bound to that proof?
- How does a valid proof cryptographically authorize the corresponding native KAS payout?
- What information must a user retain to prove ownership later?
- Can the same exit be independently constructed after every normal operator/prover has disappeared?
- What data must come from L1, what may come from independently reconstructable protocol history, and what must the user retain privately?
- Is an emergency exit path required?
- How can any escape path preserve the same authorization, conservation, and single-spend requirements?
- Can an exit path itself create a privacy leak or theft vector?

## 6. ZK system

Candidate technologies may include:

- Groth16;
- Halo 2-style circuits;
- RISC Zero / zkVM-based proving;
- recursive or aggregated proofs;
- another construction supported efficiently by Kaspa.

Evaluation criteria:

- soundness assumptions;
- trusted setup requirements;
- proof size;
- verification cost on Kaspa;
- proving time;
- memory use;
- mobile feasibility;
- aggregation/recursion;
- audit maturity;
- implementation complexity.

Also specify whether proving is local or outsourced, what private data a prover receives, and how a confidential application avoids exposing spend material to an executor.

## 7. Privacy properties

Which properties are targets?

- sender privacy;
- recipient privacy;
- amount privacy;
- balance privacy;
- note ownership privacy;
- transaction-graph unlinkability;
- private change;
- wallet note-discovery privacy.

What remains observable?

- shielding events;
- unshielding events;
- timing;
- public fees;
- public network metadata;
- possibly unique deposit/withdrawal values.

## 8. Metadata and network privacy

- What can an RPC provider learn?
- Can a wallet discover notes without revealing which notes it owns?
- Should a recommended wallet support Tor/I2P or other relays?
- Is transaction broadcast itself identifying?
- How do mobile/light clients avoid leaking their private state to a server?

## 9. Scaling and concurrency

- Does a simple covenant pool create one-UTXO contention?
- Can state be safely sharded without damaging privacy?
- Which bottlenecks would batching reduce, and which remain at serialized covenant settlement?
- What distinguishes executed, proved, settled, and withdrawable balances?
- How often must L1 settlement occur?
- Can proofs be aggregated asynchronously so proving is not on the user critical path?

## 10. State availability and recovery

- What data must remain available forever?
- What data may be pruned?
- Which data must a user back up?
- What happens if all common state servers disappear?
- Can anyone rebuild the required state from Kaspa plus public protocol data?
- What history must be archived after Kaspa pruning, and who can independently retrieve it?
- How are witness/state updates rolled back or rebuilt on a reorg?

## 11. Wallet design

- How are private notes discovered and decrypted?
- How is change handled?
- Can the wallet warn users about dangerous unshield patterns?
- How should privacy quality/anonymity-set information be presented?
- Can hardware wallets safely support spending?

## 12. Economics

- What costs exist for L1 transactions, proving, storage, execution, relays, audits, and maintenance?
- Should shielding/unshielding carry a development fee?
- Should proving be a permissionless market?
- Could fees create central control or harmful incentives?
- How do we fund independent audits and long-term maintenance?

See [ECONOMICS.md](ECONOMICS.md).

## 13. Governance and upgrades

- How can upgrades occur without giving maintainers control over user funds?
- Can old versions continue independently?
- What changes are merely implementation changes versus protocol changes?
- Which security invariants may never be relaxed through ordinary governance?

## 14. Legal and operational questions

- Which roles could be treated as operating a service rather than publishing software?
- How do custody, frontend operation, fee collection, treasury management, and hosted proving change the analysis?
- What legal review is needed before mainnet or receiving protocol revenue?

See [research/legal-operational-questions.md](research/legal-operational-questions.md).

## 15. AI development

- Which tasks can be safely accelerated by AI?
- Which security-critical decisions require specialist human review?
- How do we prevent AI-generated assumptions from silently becoming protocol design?
- Which invariants can be machine-tested, model-checked, fuzzed, or formally verified?

## Public based-app native-value integration follow-up

The [2026-10-17 source map](poc/native-value/MAPPING.md) identifies existing
Deposit/Withdraw actions, delegate reserve scripts and permission claims. The
bounded experiment is [ADR-0004](docs/adr/0004-public-based-app-native-value.md).
Outstanding questions remain: scalable proof composition beyond the fixed
monolithic circuit, data availability and takeover after pruning/reorg, a stated
progress policy (no mandatory latest checkpoint was found), private authorization
and confidential execution. Passing the public cycle would not resolve them.

The [recursive adapter review](poc/takeover/README.md) now isolates composition
from those open questions. A coarse public state resource can exercise the
reference recursive interface locally; it does not establish scalable private
state, true native expiry, missing-history recovery or guaranteed exits. A fresh
long-gap TN10 rehearsal has now [completed through native payout](poc/takeover/LIVE-REHEARSAL.md)
after a 175-blue-score stop gap. This narrows that empirical question for the
tested same-owner/node public replay; it leaves the above recovery and privacy
questions open.

## After the public Based App feasibility milestone

The [five-criterion integration question](docs/based-app-feasibility-2026-10-17.md)
is answered positively for the recorded public TN10 experiments. It does not
close P01-P03 in full or private note/nullifier, financial-privacy, discovery,
exit-fee and recovery questions. The [next work package](docs/shielded-kas-next.md)
prioritizes these private-protocol requirements against the existing issues;
new public runtime/operator infrastructure needs a demonstrated purpose.

## Questions exposed by the first shielded local package

The [proposed private statement](docs/rfc/0002-shielded-payment.md) asks how to
prove invalid-proof rejection without an executor skip flag or whole-batch-only
halt; how to bind a wallet intent without circularly including its own proof's
native transaction ID; how to retain proof/ciphertext availability within native
mass limits; and how every supported funded deposit gets an authenticated credit
or recovery path. The ideal model and real small composition test are different
evidence layers. Complete note/ownership/nullifier/encryption constraints,
permissionless fees, migration and independent recovery remain open.
