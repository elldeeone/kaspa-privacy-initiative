# Threat Model

[RFC-0019](docs/rfc/0019-fees-and-independent-exit-obligations.md) and
[ADR-0039](docs/adr/0039-exit-liability-and-native-claim-experiments.md) add an
offline liability/service-loss model and native terminal-claim cost diagnostic.
Ideal model authority/membership predicates are explicit assumptions, not
cryptographic verification. Consuming a note into an unpaid claim must atomically
consume its NF and preserve all backing; a separate stable claim ID is safe only
after that consumption. Roots extending or regrouping claims must not create
another economic identity. Stale current spent state and orphaned authorization
must not release reserve. Reorgs do not erase already disclosed secrets or
restore an unavailable service or data copy.

A revealing future-format branch must not disclose the credential sufficient
for a competing private SPEND. A native signature protecting only the revealing
branch cannot stop that race. Current v6's reusable ownership/NF secret and
uncommitted native payout key are not silently reinterpreted. No new branch is
adopted. Native probes must separate principal, permission rent and external fee
funding; a zero-fee script pass is not a claim-funded exit. A cheap terminal claim
also does not solve service loss before its authorization was accepted.

The separate [ADR-0040 public probe](docs/adr/0040-public-revealing-exit-feasibility.md)
tests a new candidate whose private reference requires independent s+k and whose
native exit reveals only k plus a signature under a CM-bound native key. No
actual private circuit or secret-delivery/descriptor scheme is implemented.
Supplied synthetic CM/NF roots and native backing are assumptions; matching a
hash or passing Full is not accepted lineage. A size-padded reveal script does
not implement the missing private branch. Sender-selected unusable exit keys,
credential reuse, published-but-unaccepted disclosure and future-union code
size remain explicit review boundaries. The old single-secret relation and
immutable instances gain no new exit path.

The [closed public probe](research/next-session/exit-fee/future-exit/REPORT.md)
passes60 native positives and39 exact negatives. That source's real-NF count
bound cannot be assumed compatible with an old private relation inserting two
NFs for padded inputs. Future union size, padding semantics and privacy must be
reviewed jointly. The fee/storage fixed-point failures remain failures even
when the body is consensus-valid. Excluding small positive reserve tails needs
complete exact backing and a preserved floor on every remaining obligation;
I-1 alone does not imply either condition. No pending/refundable liability may
be omitted to force that profile.

[ADR-0038](docs/adr/0038-bounded-cost-and-proving-qualification.md) adds bounded
offline resource and constraint checks. It adds no withdrawal authority or
production trust assumption. A native operational budget is excluded from the
pinned version1 transaction ID and SIG_HASH_ALL but changes the full hash and
metered/mass behavior; qualification must preserve proof-authorized fields and
exercise actual native checks. This is not evidence of relay or inclusion
liveness. A multi-worker GPU measurement must account for every worker, reject
development/unresolved receipts and independently verify the exact original
claim. Faster proving supplies no financial-privacy or independent-exit claim.
The [fee-frontier analysis](research/next-session/fee-frontier/README.md) retains
all liabilities when a fee scenario fails; a stranded claim cannot be removed
from backing accounting or repaired by an undisclosed sponsor.

[ADR-0034](docs/adr/0034-public-proof-composition-experiment.md)'s
[two-v6 package](poc/two-v6-binding/README.md) is a nonsettling proof-composition
experiment. Its genuine development receipt passes independent software and
[bare native predicate verification](poc/public-receipt-native-check/README.md).
The collector receives both public bundles and their grouping; a short journal
does not establish privacy. A separate single-party test setup remains an
unreviewed soundness assumption and cannot qualify the retained original key.
Immutable compiled parameters require checked host preparation and independent
source/key/program/image pins; a prover-selected key, image or adjacent metadata
file is not a trust anchor. Submitted proof points retain checked decoding.

P/J binds an existential partition into two valid authorizations, but does not
publish their common count/anchor. A host-supplied anchor/history path beside
the old receipt is therefore unauthenticated by that receipt. Neither native
opcode success nor the collector's declarations establish accepted history,
current nullifier nonmembership, successor state, reserve backing or an
authorized payout. [RFC-0018](docs/rfc/0018-paired-native-settlement-experiment.md)
keeps those obligations and independent owner exits open; it grants no weaker
settlement or privileged rescue path.
[ADR-0035](docs/adr/0035-synthetic-state-aware-assertion.md)'s separate
[public vectors](poc/two-v6-state/public-fixtures/manifest.json) declare synthetic
predecessor roots and reserve amounts. The generated state-aware receipt and
[one-shot native script](poc/public-state-native-check/evidence/historical-state-native-01/report.json)
now establish the tested assertion from that supplied context; they cannot establish the
context's accepted genesis, backing or owner-exit capability. The experiment
remains NONFUNDABLE, and its new image/J336 cannot replace or reinterpret J42.
The fixed predecessor guard intentionally makes its successor noncontinuing;
there is no DRAIN branch. A separate
[official Full-validator check](poc/public-state-consensus-check/evidence/historical-state-consensus-01/report.json)
now accepts the same saved body with declared UTXO/DAA context, without skipped
script/mass checks. Source-adapted policy cases remain distinct from actual
Mempool/relay/chain acceptance. The 80m actual
fee is unchanged and does not cover the measured rate-500 scenario.

The separate [ADR-0037](docs/adr/0037-offline-continuing-s7-owner-lifecycle.md)
instance uses a fresh single-party **UNTRUSTED TEST** setup, fixed new
domain/pool/key and intentionally public wallet seeds. Its retained public PK
has a stream-integrity check, not full-key restoration or owner-exit evidence.
Four initial proofs, the new guest receipt and paired native Full checks
cannot replace accepted lineage,
accepted backing or independent exits. No secure-erasure or privacy claim
follows; the public replay/owner CLI job remains parked for this run.

The [public-native reconstruction](poc/shared-pool/PUBLIC-NATIVE-OBSERVATION.md)
uses a caller-trusted descriptor and checks a selected prefix under supplied
funding UTXOs. Separate flags retain missing funding-parent input ancestry and
chain acceptance as false even after native proof/VM checks pass. Reconstructed
bodies, matching transaction IDs and a valid prefix cannot establish acceptance
or currentness. The [budget screen](poc/shared-pool/PUBLIC-NATIVE-BUDGET.md)
retains v1's distinction: budget-only changes preserve IDs and SIG_HASH_ALL,
but change full hashes. Its fixed-case execution evidence changes no default,
authorized fee, privacy target or general exit-liveness assumption.
[ADR-0036](docs/adr/0036-v6-native-budget-1600.md) subsequently adopts the v6-only
factory budget of 1,600 with compatible replay of supplied typed budgets.
Exact body reconstruction, native metering/validation, protocol mass caps and
authorized fee/accounting remain mandatory. The actual 40m fee, emitted
covenant, privacy targets and known high-fee minimum-note failure are unchanged.

The [price-baseline test](poc/shared-pool/PRICE-LEAKAGE-SPEC.md) separates public
arithmetic observations plus the declared directory from additional pooled
colluder records. It compares a preselected heuristic with marginal price-only
actions, not an optimal full-transcript posterior. Independent seeded ledgers
are the inference units; honest truth enters only after all predictions seal.
Ideal hiding, modeled demand and finite attacks remain limitations. No new
settlement trust, privileged exit path or privacy qualification is introduced.

Its [completed result](poc/shared-pool/PRICE-LEAKAGE.md) does not establish
incremental prediction benefit for the selected heuristic: observed public and
pooled accuracy were below the optimal marginal price action. All three frozen
comparisons support mean advantage below five points, but this is no bound on
stronger, selective, earlier-prefix or native-byte attacks. Public/new-hit
turnover and legitimate participant knowledge remain distinct from a causal
account of each success. No threat or absolute requirement is removed.

The [sparse diagnosis](poc/shared-pool/WORKING-BALANCE-SPARSE-DIAGNOSIS.md)
separates correct numeric guesses from matching actual paths. In the partial
pooled final view, eight successful guesses use unrelated selected payouts and
three touch ancestry without closed accounting flow. All still count in the
unchanged failed score. False explanations do not prove zero transaction signal,
and structural ancestry does not allocate economic value after mixing. The
known-price prior can itself exceed an absolute cap. These distinctions guide
[the next research direction](docs/adr/0032-sparse-diagnosis-and-privacy-evaluation.md)
without changing any threat, privacy target, protocol or exit dependency.

The [working-balance comparison](poc/shared-pool/WORKING-BALANCE-PRIVACY-SPEC.md)
adds a bounded arithmetic screen for withdrawal amount leakage. It compares
public-plus-initial-directory and pooled eight-participant observers, preserving
the public strategy under collusion. Public payouts, fees, re-entry ancestry
and modeled order remain visible; private change is only an idealized hidden
value in this model. Tail sums, known co-input subtraction, receipt-correlated
requests and fixed earlier-prefix guesses attack the proposed behavior.
All predictions precede truth scoring. No result of this screen establishes
proof confidentiality, native recovery, network anonymity or actual user
behavior. Sparse activity, correlated cash needs and urgent complete exits
remain explicit cases, not exceptions hidden from the score.
The [completed result](poc/shared-pool/WORKING-BALANCE-PRIVACY.md) rejects the
tested policy under its frozen gate. Retained change helps one independent-
demand case but does not reduce the sparse pooled amount-guessing score. Known
half-receipt cashouts become more guessable with partial payouts. Some identity
count regressions already exist in arm-specific creation priors; report them
without claiming a new causal identity leak. No threat or qualification target
is relaxed by this result.

[RFC-0012](docs/rfc/0012-useful-privacy-requirements.md) is the accepted
requirements profile for broader shielded-KAS research. It separates chain,
participant/collusion, active, infrastructure and endpoint observers; internal
payments, ingress/egress and urgent recovery; and cryptographic confidentiality
from user-level inference. Its numerical gates and observation horizons are
adopted, not demonstrated. [ADR-0027](docs/adr/0027-shielded-payment-targets.md)
closes milestone 1 without changing a mechanism, invariant or historical result.
Network anonymity and endpoint-compromise claims require separate qualification.

[RFC-0013](docs/rfc/0013-coherent-v6-lifecycle.md) separates actual native funding
evidence from the proof's deposit declaration and from a participant roster.
The first offline replay component checks parent identity/output context and
funding single-use while retaining full native validation. It assumes an externally
authenticated accepted-chain view; matching bytes alone establish neither chain
acceptance nor current spendability. Unsupported parent formats and missing older
parents fail explicitly. No private witness or privileged role is introduced.

[ADR-0029](docs/adr/0029-own-key-admission-and-recovery.md) adds a local recovery
boundary: the backup authenticates pool and exact proving parameters, and the
caller independently supplies the expected history endpoint. A hostile provider
can withhold data; a valid prefix cannot satisfy a different expected endpoint.
The endpoint's acceptance/currentness still requires external evidence.
Decryptability alone never credits a note: ownership, commitment, position,
v6 value bounds and current spentness must also pass. A backup predating receipts
must recover them without a saved proof or controller-supplied plaintext.
Malformed delivery in a valid public transition must not block scanning or exit
of unrelated valid notes. Private selection positions and derived payout-key
indices stay out of public transaction wrappers.
The offline test isolates recovery from original wallet/controller files, but
does not claim endpoint compromise, independent-host or network privacy protection.

The [native address-reuse test](poc/shared-pool/ADDRESS-REUSE.md) demonstrates
that keeping derivation indices out of wrappers does not prevent native script
reuse. Funding and exits share a key namespace; an allowed matching index
repeats the native spending condition. With declared funding-owner associations
and self-bootstrap/current-wallet policies, the tested sparse final history
then exposes a previously ambiguous sender, recipient and amount. Removing
self-bootstrap removes the sender-uniqueness conclusion. The report separates
a narrower analytic recipient deduction from that measured stronger model.
These ownership bindings are assumptions, not general v6 circuit guarantees.
Neither the different-index control nor this diagnostic qualifies the 32-role
privacy promise. No key or backup interpretation changes in that test.
[ADR-0030](docs/adr/0030-separate-funding-and-exit-keys.md) subsequently separates
funding/exit purposes for fresh v2 wallets. Exact v1 metadata preserves historical
derivation and its reuse risk; mismatched profiles reject rather than guessing.
Relabeling an old backup cannot remove historical links. Native index discovery,
amount/timing inference, compromised endpoints and history availability remain
separate risks. The [offline retest](poc/shared-pool/ADDRESS-KEY-SEPARATION.md)
passes original-backup recovery, exit and native payout spending for both
profiles without a new secret or mutable sidecar. The unchanged observer no
longer forces the payment in either fresh-v2 case; it still forces all three
fields in the legacy final linked control under the same declared assumptions.
This removes the demonstrated alias, not general financial inference.

[H18](poc/shared-pool/SCHEDULED-PAYOUT.md) gives the chain observer
the declared remainder-delay distribution and service/queue assumptions, in
addition to the existing amount and wallet rules. Each participant disclosure
remains separate; RPC/network access is excluded. Timing compatibility and
maximum-score guesses are conditional models, not calibrated posterior
probabilities. Immediate fallback remains a supported, potentially revealing
choice. No new private protocol or trust authority is introduced.
The completed comparison fails its privacy gate: attack-family success stays
unchanged under both policies, despite acceptable modeled fees/delay. In sparse
activity all 48 common payouts have a sole time-compatible actual remainder,
restoring the ordinary full-exit source alternatives under these assumptions.
This does not identify every source or demonstrate general deanonymization.
The inherited untimed model also retains the same unique-claim totals; do not
attribute the entire negative result to timestamps. Immediate post-partial
exit remains valid outside the normal-timer model, as a separate arithmetic
control checks. No precise acceptance-time field, RPC/network observer or new
native validation is implied. Reject the tested scheduling policy; preserve
the existing private-change and independent-exit mechanisms.

The experimental [two-input relation](docs/rfc/0011-two-input-private-payments.md)
adds zero-value padding, merged private inputs and partial withdrawals with
private change. Its [bounded offline trace](poc/shared-pool/TWO-INPUT.md) and
[TN10 continuation](poc/shared-pool/TWO-INPUT-TN10.md) pass with four wallets
paid through six unchanged saved proofs;
earlier variants and evidence remain unchanged. Critical obligations are constrained dummy-nullifier derivation,
sequential current NF insertions, all-path value/range checks, native funding
and payout binding, and termination by authorized reserve debit rather than
entry counts. A wider NF tree and no-append full-exit path are intended to leave
room for every remaining positive note to exit at commitment capacity. A
constructed capacity-boundary state supports a genuine saved terminal proof,
but is not a replayed valid full-capacity history. New costs are measured;
independent review of the composition and broader qualification remain open.

The original offline adapter supplies current public state/UTXOs to isolated
workers. The live adapter instead downloads accepted history and checks native
funding/lineage in each client's namespace; it supplies no current controller
state. Clients have their own saved capabilities and pinned descriptor/VK,
with no wallet keys or PK. The generating controller still knows the fixture's
secrets. All four clients share one host and one correct RPC view, and the
descriptor restricts discovery to four known depositors. This does not test
malicious RPCs, pruning, rollback or contention; the RPC also sees client access.
The new experimental single-party
setup remains a soundness assumption. The 0.6-tKAS floor and 0.4-tKAS selected
fee cover the declared local envelope, not arbitrary future fee markets.

The candidate retains fresh normal proofs and private saved fallbacks, exact
fee authorization, independent genesis/lineage validation and locally recoverable
witnesses from authenticated public data. A fallback may reveal its old anchor
and whole-input value; publication alongside another proof links their shared
real NF. Padding does not hide native payouts, funding ancestry, operation
timing or logically forced note choices. The old single-parent observer is not
valid after merging. The [dedicated review](poc/shared-pool/TWO-INPUT-PRIVACY-REVIEW.md)
separates chain data from RPC/network/recipient knowledge, and lists inflation,
double-spend, capacity, service-loss and fee-limit obligations. No security
invariant is weakened and no strong-privacy claim is added.

[H16](poc/shared-pool/PARTICIPANT-PRIVACY.md) tests chain observation plus one
complete, honest participant record, separately for each wallet. The record
reveals own receipts, authored inputs/output values and local receive-address
equality; it does not reveal an incoming sender, another wallet's future spends,
other records or network access. The primary observer additionally assumes this
client's single-author inputs and fixed change ownership, not protocol-enforced
ownership rules. Unknown authorities are not bounded to four.

Excluding already-known participant targets, two new fresh payment-source links
are forced at startup. Separate participant views also force 7/28 distinct
fresh full-exit sources versus 28/28 saved; this does not mean one observer
links every target or establish an anonymity percentage. Records alone force
six fresh full exits and two partials; the ownership assumptions add one of
each. Source alternatives are not owner-identity or hidden-amount guarantees.
Fresh proofs/private fallbacks remain candidates; strong privacy is open.
[H17](poc/shared-pool/COMMON-PAYOUT.md) tests a common partial-payout policy,
without adopting it as a defense. Its additional observer assumption is that
a visible 2-tKAS partial uses one input and keeps positive change; v6 itself
permits two inputs. Each Q-change inherits its input's original source in the
inferred graph. Final odd-sized remainders can retain amount information despite
equal early payouts. In the four frozen cases, participant original-source links
decline from 7/28 to 4/28 after complete drainage, with no new payment links.
All remaining links concern unsplit claims; source alternatives do not imply
hidden amounts, owner anonymity or protection from RPC/network observation.
The genuine full/partial alternatives exclude each other and saved change
exits remain independently usable. The fixed schedule fails the delay target.
Retain optional shaping as a research candidate, not an established defense
for arbitrary workloads or saved-proof publication.

H16's second pass found that the inherited H14/H15 sandbox exposed host case/arm
labels through process/mount metadata, though the observers did not read them.
H16 was fully repeated without `/proc` or a supervisor, with dropped capabilities
and denied nested user namespaces. All 64 probes pass and all 30 completed
earlier predictions agree. The older numerical evidence remains intact; its
isolation receipts do not demonstrate resistance to arbitrary metadata inspection.
None of this changes the protocol's setup, backing, recovery or liveness model.

[H12](poc/shared-pool/NORMALIZED-DEPOSITS.md) finds a bounded mitigation for
funding-origin reconstruction: equal net private credits, with fresh proofs and
all four deposits before payments, leave four feasible deposit labels through
drainage. This relies on workload symmetry, not a cryptographic guarantee about
users. The covenant permits unequal deposits; interleaving, early exits, fallback
publication and off-chain attribution can reduce that ambiguity. Shared test
funding still gives one observable funding cluster. Private proving in a test
controller and chain-only observation do not establish hosted-prover or network
privacy. Permissionless exits must remain usable when those assumptions fail.

[H11](poc/shared-pool/PRIVACY-STUDY.md) shows that fresh historical membership
proofs reduce source-transaction guessing in the frozen synthetic workloads,
while complete-drain value constraints still uniquely recover most funding
deposits. An observer needs neither RPC logs nor private wallet data for this
attack. Keep unused fallback proofs private; report funding ancestry separately
from the creating transaction and from owner identity. The population model
assumes opaque cryptographic bytes and favorable independent funding roots;
two genuine native calibrations do not establish real-world anonymity. No
protocol invariant, setup, fee-repricing or data-availability assumption changes.

The experimental [independent-deposit extension](docs/rfc/0010-compact-independent-deposits.md)
introduces a native funding input and a distinct admission branch, not a new
trusted actor. Critical checks are actual funding authorization/value, exact
reserve credit, disjoint deposit/spend semantics, unchanged NF state and
independently validated genesis/accepted lineage. The virtual proof input must
never become a pool claim or authorize omitting real spend checks. SIGHASH_ALL
binds monetary intent and the nonempty payload, but excludes signature scripts
and v1 compute budgets; do not assume every field is signed. Native execution,
canonical construction and relay checks have separate roles.

The candidate keeps setup, correct-node, public-history and fixed-fee assumptions.
Its ciphertext digest does not prove correct delivery; each wallet checks its
own notes. Repeating a proof with fresh signed backing can create valid separate
positions, while reusing a spent funding input must fail. Old deployed pools
remain immutable and their proofs cannot cross domains. All four wallets' saved
proofs in the new pool must survive later deposits and settle without privileged
help. The offline gate passed with all four terminal roles, native adversarial
controls and independent public accounting. Complete TN10 rehearsal and a fresh
measured trial also passed, with all eight saved proofs and zero remaining reserve.
Client namespaces test access to own saved bundles plus public data, not
protection from a malicious host. Public deposit pair totals, ancestry and old
anchors remain visible; no privacy result or invariant relaxation is added.
See [results and limits](poc/shared-pool/DEPOSITS.md).

[H8's chain-only audit](poc/shared-pool/PRIVACY.md) shows a deterministic source
transaction link for the first H6 exit, even though its two possible note positions
remain indistinguishable under the modeled public constraints. The count-three
anchor cannot include later notes; the initial note was already spent. This
does not identify an owner or person, or prove every other exit anonymous. Full
exits expose consumed value as payout plus fee, and one-deposit pools expose a
single funding ancestor. [H9's actual fresh-proof comparison](poc/shared-pool/FRESH-PROOF.md)
removes this singleton ceiling in two small fixtures through full drain; the
no-activity control stays linked. Both proofs independently authorize the same
exit before spending; current spentness rejects the loser in either order. This
is bounded offline evidence, not a privacy guarantee. If old and fresh authorizations are both visible,
their shared nullifier exposes the old restriction; a proposed fallback must stay
private. Public research bundles/labels, RPC access and network metadata are
separate observation surfaces. No protocol assumption or invariant was relaxed.

The [H7 recovery tooling](docs/adr/0020-independent-wallet-recovery.md) treats
public mirrors as replaceable data sources. A private backup pins the pool
descriptor, which pins parameters and funding identity; native replay validates
every transition. A synchronized node still authenticates accepted history and
current UTXOs: native replay alone cannot establish freshness. Losing every copy
of required history or parameters can prevent an exit. A terminal root does not
recover missing ciphertexts, and a pinned setup does not remove setup trust.
The initial depositor needs the original note opening until that claim is spent.
Each restored client gets only its own backup and public bytes, with no original
receiver list, future note export or prepared authorization. Live clients use
ordinary RPC, so connection metadata remains visible; this is not network
privacy or a chain-only anonymity experiment. General reorg, pruning and
concurrent recovery remain outside this bounded test. See [results](poc/shared-pool/RECOVERY.md).
The offline gate, full TN10 rehearsal and fresh trial passed with all three
claims paid and complete drain. An initial RPC interruption was recovered through
ordinary wallet exits. These observations support only the declared backup,
public-data and correct-node model; no invariant or setup assumption is weakened.

The compact-state experiment in [ADR-0019](docs/adr/0019-compact-public-settlement.md)
adds authenticated public Merkle update witnesses. An untrusted witness provider
may lie about a predecessor, empty leaf, historical root or spentness; every path,
strict unsigned nullifier gap and exact successor must be checked by native
script against the consumed UTXO. Bootstrap fixes canonical sentinel/history
state. Positioned-note nullifiers bind the private membership index, so repeated
commitment bytes cannot erase or merge separately funded claims. Wrong index,
cross-domain and duplicate-spend controls are required. A missing public history
source may stop reconstruction; it must not authorize accepting unverifiable
state. Depth, history availability, setup, serial contention, fee repricing and
reorg assumptions remain explicit. Public predecessor indices concern nullifiers,
not the privately selected note, but anchor horizon and timing still leak.
The bounded offline and TN10 100-payment tests passed with both original provers
stopped before Bob's exit and complete drain afterward. This tests the recorded
sequence and retained-data assumptions, not arbitrary service loss, reorgs,
contention fairness or real-world anonymity. See [evidence](poc/shared-pool/COMPACT.md).

[ADR-0018](docs/adr/0018-reusable-private-authorization.md) separates authorization
against an authenticated earlier commitment prefix from current native settlement.
Current nullifiers must never be rolled back; every accepted successor retains
all prior state. The covenant binds recipient, value, fee, ciphertext and rules
while checking the exact consumed UTXO. An old private authorization is not an
old full-state proof. Public prefix/count choice reveals the membership horizon;
it can narrow candidate notes. Fixed fees, finite capacity, setup, public-data
availability and a correct chain view remain assumptions. The
[bounded TN10 result](poc/shared-pool/ANCHORED.md) confirms exact authorization/proof
reuse after one unrelated payment, with Bob's prover stopped; current-spentness
and state-retention mutations reject offline. It does not establish arbitrary
reorg recovery, ongoing-contention fairness or real-world anonymity.

The version-3 experiment in
[ADR-0017](docs/adr/0017-note-floor-and-independent-exit-retry.md) implements a
proof-enforced minimum on every real note and withdrawal payout to prevent
tiny outstanding claims from obstructing native exits at the configured fee
rate. It uses fresh parameters rather than upgrading a live pool. Independent
retry requires public accepted history, retained parameters, a correct full-node
view and an opportunity after the competing winner stops. It does not establish
fairness against continuous contention or recovery from arbitrary reorgs.
The [funded report](poc/shared-pool/CONTENTION.md) distinguishes local boundary
checks, actual confirmed exits and these remaining assumptions. The fixed floor
also narrows feasible hidden amounts; it must enter future chain-observer models.

The [four-wallet trial](docs/adr/0016-four-wallet-shared-pool-trial.md) treats
funding ancestry, reserve lineage, fees, mode/counts, timing and public payouts
as observer inputs. Partial withdrawal hides change value cryptographically but
may reveal it through later exits. Synthetic wallets sharing one funding source
are not independent anonymity participants. Setup and public artifact retention
remain assumptions. RPC/network metadata is excluded from the chain-only attack,
not claimed private. Deposits require a proved bootstrap and cannot debit prior
holders; partial withdrawals must preserve the remaining private liability.
Wallet quarantine prevents accepting dust as payment but does not erase its
reserve liability. That version-2 circuit permits tiny positive notes: a malicious
claim can make a later reserve output fail native storage-mass limits. The
trial therefore demonstrates independent exits for its accepted-note workload,
not general adversarial exit liveness. Competing reserve spends and reorgs remain
separate tests.

The [direct self-funded TN10 trial](docs/adr/0015-direct-self-funded-tn10-trial.md)
adds experimental single-party Groth16 setup and retained public-parameter/data
assumptions. It has no operator withdrawal authority. Its complete old/new state,
native predecessor, output scripts, values and miner fee must be proof/covenant
bound. Four commitment slots and public deposit/exit boundaries provide no claim
of real-world anonymity. RPC/network exposure remains separate from chain data.

**Status:** initial research draft. This document should become more precise as architecture choices are made.

## Assets to protect

1. Native KAS backing the shielded system.
2. The integrity of the shielded supply.
3. User authorization and spend rights.
4. Sender privacy.
5. Recipient privacy.
6. Amount privacy.
7. Balance privacy.
8. Transaction-graph unlinkability.
9. Availability of valid exits.
10. The ability to reconstruct and independently verify protocol state.

## Primary security goals

An attacker must not be able to:

- create unbacked shielded KAS;
- spend the same private value twice;
- withdraw another user's funds;
- alter a valid state transition without detection;
- make an invalid proof accepted;
- make a valid user's funds dependent on one trusted operator;
- silently change the protocol rules through a privileged key.

## Adversaries

The system should consider:

- malicious users;
- blockchain analytics companies;
- large passive observers;
- malicious or compromised provers;
- malicious executors/sequencers;
- compromised RPC/state servers;
- compromised wallet software;
- colluding infrastructure operators;
- attackers seeking denial of service;
- attackers exploiting implementation bugs;
- governance or treasury capture;
- adversaries with exchange/KYC information;
- long-term observers correlating deposits and withdrawals.

## Attack classes

### 1. Inflation

A bug in the circuit, arithmetic, commitment scheme, proof verifier, or state transition allows more shielded value to exist than native KAS locked by the protocol.

**Severity:** catastrophic.

### 2. Double spending

The same note/value can be consumed more than once because nullifiers are not unique, not correctly bound, or not consistently checked.

**Severity:** catastrophic.

### 3. Unauthorized withdrawal

An attacker convinces the settlement mechanism to release native KAS without owning a valid shielded claim.

**Severity:** catastrophic.

### 4. Malicious prover

A prover submits a forged, stale, incomplete, or wrongly-bound transition proof.

Desired property: an invalid proof cannot threaten safety. Loss of a prover may threaten liveness only.

A hosted prover may also learn private notes, amounts, and other witnesses supplied to it. A zero-knowledge proof does not hide those inputs from the prover that handles them. Record local/outsourced proving assumptions and keep spend secrets out of untrusted execution infrastructure.

### 5. Malicious executor/sequencer

An executor censors, reorders, withholds, or selectively includes operations.

Questions:

- Can another executor take over?
- Can censorship be detected?
- Can users still exit safely?
- How long does failover to an independent executor/prover take?
- Can a censored valid operation or exit be resubmitted through independent infrastructure?
- Can censorship and failover be observed and measured externally?

### 6. State availability failure

A server or group disappears with data needed to generate future proofs or withdrawals.

Desired property: critical state is public/reconstructable, replicated, or user-held such that disappearance of common infrastructure does not destroy funds.

Roots alone cannot reconstruct state or witnesses. Recovery must account for L1 pruning, retained public history, encrypted note delivery, wallet backups, and independent proving. A safe halt is not evidence of recoverability.

### 7. Witness corruption

Wallets or provers receive incorrect Merkle paths, state roots, note metadata, or encrypted payloads.

The system should verify rather than trust witness providers wherever practical.

### 8. Timing correlation

A user shields a distinctive amount and soon unshields a similar amount. Even perfect ZK may not prevent a strong statistical link.

Low-activity periods require particular attention, because batching provides less timing anonymity when very few users are active.

### 9. Amount correlation

Unique public deposit/withdrawal values may reduce the practical anonymity set.

### 10. Network metadata

RPC requests, note scanning, transaction submission, IP addresses, and peer connections may reveal relationships that the ledger itself hides.

### 11. Wallet fingerprinting

Wallet-specific transaction construction, timing, fee behavior, note selection, or relay patterns may identify a user or software version.

### 12. Viewing-key leakage

A compromised viewing key may reveal incoming activity or other metadata depending on the final key model.

### 13. Cryptographic failure

A primitive, curve, proof system, hash, PRF, or implementation assumption becomes insecure.

Cryptographic agility must be balanced against upgrade risk.

### 14. Circuit/spec mismatch

The implementation proves a subtly different rule set than the written specification.

Independent test vectors and cross-implementation testing should reduce this risk.

### 15. Upgrade capture

A governance process, multisig, or maintainer group gains the ability to replace the settlement logic with rules that can confiscate or redirect funds.

### 16. Treasury capture

A development funding mechanism becomes technically or socially entangled with user reserves.

The two must remain separate.

### 17. Denial of service

Attackers spam commitments, nullifiers, proofs, or state requests to make proving or verification too expensive.

### 18. Reorg / finality assumptions

An application acts on a Kaspa state transition before the required finality assumptions are satisfied, leading to inconsistent state or invalid settlement.

Define rollback/replay behavior and distinguish executed, proved, settled, and withdrawable state. Historical note anchors must not authorize replay against stale settlement or spent-state roots.

### 19. Unpaid exit liability

A private claim is consumed into an exit entitlement, but the reserve accounting drops that entitlement before the user receives an authorized payout. All pending exits remain user liabilities; proofs and settlement must bind the amount, destination, reserve continuation, and any fees.

### 20. Fee-payment correlation

A private operation may cause a publicly observable Kaspa L1 transaction whose fee is paid by a known or linkable transparent wallet. Even if the private state transition hides sender, recipient, and amount, an observer may correlate the payer, timing, and privacy-system activity.

Desired property: private operations should not require a publicly linkable fee payment from the user's transparent wallet.

Testnet analysis should measure whether a passive observer can correlate a known transparent wallet's L1 fee payment with a specific private operation.

## Initial out of scope for the first cryptographic PoC

The first PoC may not fully solve:

- IP/network privacy;
- mobile light-client privacy;
- economic spam resistance;
- production-grade prover decentralization;
- polished recovery flows;
- legal/operational deployment.

These are not out of scope for the eventual protocol. They are only deferred so the first experiment remains falsifiable and small.

## Principle

**A privacy protocol is not secure merely because transaction contents are encrypted or hidden in a proof.**

The entire path — deposits, state availability, proving, note discovery, transaction broadcast, exits, wallet behavior, and upgrades — belongs in the threat model.

## A0.5 experiment-specific operational boundary

The [A0.5 adapter](docs/poc-a0-tn10-runbook.md) assumes an uncompromised local
host and correct pinned SDK/node binaries. Persisted claim/proving material and
recipient keys are required for liveness; a same-host restricted backup is not
independent recovery. A substituted key cannot spend the original P2SH reserve,
but lost material can strand the test claim. No admin recovery path is added.

The adapter checks exact fields after serialization and accepted-block readback.
A blue-score distance greater than 20 plus a later UTXO recheck are bounded observations,
not a finality guarantee. On uncertain submission/acceptance, stop and inspect
saved IDs; do not automatically refund/rebroadcast. Transparent source, reserve,
recipient, amounts, proof and timing are public and linkable. A0.5 demonstrates
no anonymity or general state availability. Setup remains single-party Groth16
with no independent audit, ceremony or proof of toxic-waste destruction.

During A0.5, the own node can validate network headers while its full UTXO import
is incomplete. Two explicit synchronized native RPC endpoints may then supply
UTXO/acceptance observations after matching locally validated headers and the
independently established TN10 genesis. Their responses remain a trust assumption;
two endpoint URLs do not prove operator independence. Corroborate the accepted
block/body and payout/spentness, fail closed on disagreement, and never describe
this route as local validation of the entire live UTXO set. The original local
full transaction validator and on-chain covenant remain the authorization path.

## Public native-value based-app experiment boundary

The [ADR-0004](docs/adr/0004-public-based-app-native-value.md) experiment exposes
all account balances, public keys, requests, recipients, deposits and payouts.
The prover receives public state only; random signing keys stay on the VPS.
New attack surfaces under test are fabricated/repeated credit, failed-command
side effects, recipient redirection, omission at a fixed authentic lane anchor,
permission replay and reserve/change diversion. Imported runtime actions and
permission scripts enforce different parts of that boundary; see the
[enforcement map](poc/native-value/MAPPING.md). Host checks alone are not proof
of theft prevention. Missing public witnesses can halt progress; there is no
admin bypass or new reserve key. Independent recovery remains untested.

## Recursive public-account adapter boundary

The [recursive follow-up](poc/takeover/README.md) adds a transaction journal and
one coarse SMT resource around the existing public account rules. Its review
must bind the full prior account state, native v1 transaction ID, global merge
index, block context, batch/aggregate images, lane and covenant continuity.
Wrong/missing inner receipts must fail at execution; a changed journal must fail
SDK/native cryptographic verification. Host preparation alone does not establish
these properties. The local script accessor must also be checked against the
fixed captured commitment, since accepting a prover-derived anchor alone cannot
show omission resistance. Lane expiry/reset remains unsupported and rejected in
the batch guest. The experiment retains one owner's historical node/archive
trust and public balances; no independent-operator, pruning-recovery or privacy
claim is added. The [fresh TN10 rehearsal](poc/takeover/LIVE-REHEARSAL.md)
separately confirms actual payout after clean public replay and a 175-score stop
gap; native omission, bridge-diversion and spent-input controls were rejected.
A canonical-chain observation does not establish general reorg recovery; the
runner halts on a detected reorg and never automatically retries broadcasts.

## Privacy work after the Based App checkpoint

The [feasibility conclusion](docs/based-app-feasibility-2026-10-17.md) covers public
ordering/execution/settlement. The next [shielded-KAS specification](docs/shielded-kas-next.md)
must explicitly cover chain observers, executors, hosted provers, RPC providers
and recipient discovery. A prover receiving plaintext witnesses is a privacy
trust dependency; lane payloads, resource access, fee funding, ciphertext retrieval
and timing can leak relationships despite a ZK execution proof. No privacy
requirement is satisfied by the public-account result. Existing fund-safety,
recovery and independent-review requirements remain unchanged.

## Local private-payment model boundary

The [first package](poc/shielded-design/README.md) uses an explicitly ideal proof
registry and reproducible test keys. Its SHA/HMAC IDs and sealed-box demonstration
are not selected production cryptography. A server validity flag cannot replace
a proved predicate. Two valid wallet proofs using one old anchor still need a
current shared nullifier check. Failed operations must change no economic state,
and a funded rejected deposit must retain a proved credit/owner-recovery path.
Uncommitted rent sponsor funds are not backing; the model requires an explicit
funding step before creating an exit rent entitlement. Missing recursive evidence
currently aborts, so deterministic invalidity/no-op handling remains a real
liveness/completeness design blocker. See the [adversarial review](poc/shielded-design/ADVERSARIAL-REVIEW.md).

The [ordinary-verifier experiment](poc/proof-classification/RESULTS.md) checks
canonical submitted proof bytes and reduced field/path encodings in the guest;
local omission/substitution against a fixed expected endpoint aborts. Correct
sequence outcomes were executed, not proved in an outer receipt. Verification
cost and almost-block-sized receipts expose a resource/availability concern:
an invalid seal can fail late and consume nearly the full verification work.
No fee-based denial-of-service protection, arbitrary accepted-lane totality,
real L1 authentication, complete private statement or production safety follows.

The [specialized wallet comparison](poc/groth16-comparison/RESULTS.md) retains
full checked decoding of untrusted curve/subgroup points while loading immutable
prepared constants already checked against the selected VK. Both exact parameter
bytes and program identity must be pinned. Circuit-specific setup introduces a
soundness trust assumption; fresh one-party research entropy is not a production
ceremony. Small real proofs do not establish completed in-guest classification:
that execution still exceeds its 32-million-cycle research cap.

The [accelerated backend experiment](poc/accelerated-bn254/RESULTS.md) subsequently
completes the same full sequence at 117.47M cycles in its labelled 128M calibration,
retaining checked submitted-point decoding before coordinate conversion into
existing library arithmetic. This introduces a pinned backend implementation and
a new expected classifier image, not new host validity authority or setup.
The 32M practical cap still fails; no outer receipt, general replay qualification
at a larger budget, L1 endpoint or production stability claim follows.

The [subsequent approved 128M attempt](poc/outer-proof-128m/RESULTS.md) qualifies
all existing full replay/continuation and malformed/authentication cases. One
actual succinct-proof call is stopped at its one-hour process-group ceiling
without a receipt. No negative control relies on that timeout. Separate real
receipt verification and its wrong-image/journal checks are implemented but
unexecuted without the missing artifact. The fixed synthetic relation, local
ordering source, setup and private-note/native backing limitations remain.

The [follow-up phase diagnostics](poc/proof-phase-diagnostics/RESULTS.md) verify
actual middle-segment, lift and join receipts, including altered seal/claim
rejection in a separate process. Workload association uses the trusted pinned
SDK export and asset hashes. These partial transition proofs do not establish
a cryptographically composed path from the initial image to the full journal;
they cannot replace the full-receipt identity/journal checks or native settlement.

The [remote CUDA preparation](poc/remote-cuda/README.md) sends only these existing
public research fixtures to a candidate rental. An independent CPU comparison
pins all five PR #40 claims; a remote report or transport hash is not enough.
The provider can deny service or falsify telemetry and billing, but cannot make
a different sealed claim pass those checks. The independent watchdog's host,
credentials and provider stop API are availability/cost assumptions, not protocol
authorities. Live CUDA, stop and persistence behavior remain unqualified. Never
send private wallet witnesses through this public-fixture interface without a
separate privacy design. This changes no protocol, circuit or settlement rule.

The disabled [B-host guard](poc/remote-cuda/B-GUARD.md) is installed separately
from the TN10 management gateway. After later activation it keeps its lease,
timer, backups and provider credential on B; Cloud/gateway/laptop availability
is not required by that loop. B-root administrators remain trusted and can read
files or alter the service. The management SSH restrictions and file permissions
do not protect against a malicious administrator. Guard qualification tests use
simulated provider responses. The operator's later successful read-only provider
GET does not establish stop/write permission or live rental/stop qualification.

## Local private-note research boundary (2026-10-18)

The ADR-0011 experiment keeps spend/view keys, note plaintexts and selected
Merkle paths inside the local wallet/proof process. Public payloads contain
commitments, nullifiers, historical anchors, ciphertexts and proofs, not input
notes or paths. The Groth16 setup is one-party experimental; no production
ceremony or toxic-waste guarantee is claimed. SHA/HMAC note composition is a
new experimental protocol adaptation, not a new primitive or inherited Orchard
security result. Native facts are test fixtures, not a trusted rescue authority.

The proof binds ciphertext bytes; it does not prove encryption correctness.
Recipients must decrypt, reconstruct the commitment, verify the expected
owner/incoming key and find the note in accepted data before counting a payment.
Malformed delivery can burn a malicious sender's own output and is never counted
as recipient receipt. Public deposit/exit amounts, timing, tiny tree/low activity,
fixed operation shapes and service/network observation remain linkability risks.
The full state guest, native accepted data/payout verification and independent
service-disappearance recovery are still required before a funded privacy trial.


The subsequent ADR-0012 calibration commits the covenant/config together with
private state and checks deposit fields from native preimages. Its lane anchors
are synthetic until matched by actual canonical native settlement. Untrusted
host balances, locally invented outputs and the mere existence of a proof over
a fixture cannot establish backing. Pending exit permissions remain liabilities;
actual native consumption and exact payout confirmation are still unimplemented.
The 128M full-sequence limit failed; no full receipt or GPU job follows from the
successful single-operation and rejection executions. New test-domain wallet
backups are local-only 0600 files; public parameter retention/loading and local
separate-process recovery do not establish durable independent availability.


A separately owner-approved 160M execution now completes the identical private
sequence and exact aggregate journal. Completion alone is not a genuine receipt,
canonical native deposit acceptance or payout. In the restore path, only the
independently expected VK is enforced; the full parameter-file SHA256 is recorded
but not compared to an independently expected value. Future parameter distribution
must supply/enforce that trusted whole-file hash before use.

The [fixed private-note proof package](poc/private-note-proof/README.md) adds an
explicit join-control binding for the monolithic route while retaining the old
resolve fixtures. A valid allowed control alone is insufficient: the decoded
seal control must equal the independently expected join and the receipt metadata.
The verifier uses the official STARK callback and allowed root in addition to
successful image/journal verification. Native fixture checks cannot establish
canonical initial funding or payouts. Public frozen inputs only reach the GPU;
the owner-local wallet secrets/setup are not packaged. Image/binary hashes bind
the reviewed artifacts, not compiler correctness. Owner Chat review and any paid
rental release remain separate from this software preparation.

The subsequently reviewed/released [single private-note GPU run](poc/private-note-proof/gpu-2026-10-18/RESULTS.md)
produced the genuine receipt with independently verified image/control/exact
journal. Actual local native execution accepted the backed fixture and rejected
all fifteen mutations; B and Cloud preserved and verified the receipt before
confirmed provider stop/deletion. This closes this fixed proof/ABI integration
gate without establishing canonical funding, exit/payout or a proved omitted
sequence. Remote GPU input remains public-only. B root, trusted local verifiers
and compiler provenance remain trust assumptions; the run adds no new authority
over protocol funds and does not establish practical anonymity.

## Private/native lifecycle preparation boundary

The [local lifecycle package](poc/private-native/README.md) tracks individual
native reserve/permission outpoints and retains unpaid-exit liabilities until
ID-bound accepted payout bytes consume the expected permission/reserve and bind
principal, destination, refund and change. Tracked native spending is recognized
before interpreting deposit payloads, including third-party payouts without
honest tags. State-covenant rent is separate from user backing and never drawn
down. The real sponsor builder signs only after choosing the private lane/payload.

Native endpoint acceptance remains load-bearing: arbitrary preimages or caller-
asserted covenant metadata cannot establish L1 funding/payment. Local native
payout scripts and a fixture UTXO set are tested; genuine new receipt/native
permission issuance and canonical chain spentness are not claimed. Current
nullifiers, exact prior root/tip/last-touch and native final seqcommit binding
remain required. Long active gaps are supported; true expiry, general reserve
aggregation and permission concurrency are outside this narrow package.
See the [second-pass review](poc/private-native/ADVERSARIAL-REVIEW.md).

PR49 review correction: [native/accounting alignment](poc/private-native/REVIEW-FIX.md)
adds actual state/permission lane enforcement, pins the selected reserve and
rejects unsupported partial/expanded native spends before funds move. Sponsor
top-ups are reconciled without minting liability; additional deposits remain
tracked. An unreconciled tracked native spend aborts, never commits stale backing
as an ordinary rejected wallet request. The old generic lane-selecting builder
is not evidence of these restrictions: the actual permission UTXO binds the
restricted redeem bytes, which the updated builder must supply and hash-check.
New live receipts and the complete terminal rehearsal remain required.

The [four-batch proof package](poc/private-native-proof/ADVERSARIAL-REVIEW.md)
retains independent expected identities and excludes GPU-supplied executables from
CPU/B verification. Its aggregate external process watchdog survives service loss;
partial outputs cannot become full qualification. Existing B-root trust, lease,
backup, confirmed-stop and storage-preservation boundaries remain unchanged.
