# Threat Model

The [wallet round-agreement follow-up](research/round-agreement-2026-11-07/RESULT.md)
blocks the prior different-round tag before a payout key leaves any wallet.
It does **not** stop an active issuer from holding valid common-round blind
signatures and releasing them one at a time, waiting for each redemption. That
service saw the genuine issue and next payout messages and linked all 3/3
claimants without wallet backups or owner truth. The unchanged offline kernel
still accepted the fully approved payouts. A service-supplied transcript proves
claim validity, not simultaneous delivery; this availability/timing control is
an explicit threat assumption under [ADR-0115](docs/adr/0115-service-release-timing-limits-blind-withdrawals.md).
Costs remain gated on privacy. Completed runs used one physical host; no
two-machine or chain-acceptance result is claimed.

The [separated-wallet/service comparison](research/separated-withdrawal-2026-11-07/RESULT.md)
finds an active configuration-tagging leak: one issuer supplies different round
IDs, derives all three claimant/payout-key links, and still obtains genuine
whole-set approvals accepted by the unchanged economic kernel. No wallet files
or controller truth were available to its observer. Common configuration is an
existing requirement whose client enforcement was missing in that run. Under
[ADR-0114](docs/adr/0114-round-agreement-before-payout-disclosure.md), verify
agreement before key disclosure; an approval-time check alone is too late.
The honest arm's order guess also matched all three once, without statistical
timing qualification. Separate same-host containers are not independent machines,
host-root isolation or global-traffic anonymity. No conditional cost work starts.

The [7 November verification-cache experiment](docs/adr/0113-cached-wallet-proof-verification.md)
reuses only static proof validity. A new settlement image pins the authorization
image, complete packet/domain/pool/key commitment and actual Proven Succinct
receipt. Current accepted anchors, spent notes, deposits, conservation, fee caps
and exact native effects remain freshly checked. Missing cache availability
permits recreation from the public packet or direct full verification; it permits
no unchecked fallback. A Claim-only/conditional receipt is not spending authority.
The final native claim must be successful, complete and unconditional. This
requires a new bank and upgrades no old bank. Dedicated TN10 experimental
one-party parameters are distinct from the old offline profile and remain
unqualified for production. The cache improves no anonymity by itself.
The combined run keeps wallet blinding state and payout secrets in each actor;
service logs, private controller instructions and later owner-disclosure controls
are separate observer facts. Same-host actors, labelled request order, participant
knowledge, collusion and transparent amounts remain explicit limitations.

The fresh TN10 rehearsal now verifies unchanged approvals after an actual accepted
private update, complete terminal principal payout and five accepted restored-key
spends, with independent synchronized UTXO corroboration. This remains one-host
custody and latest-full-backup recovery. The actual Claim-only negative is refused
by SDK 3.0.3 before receipt generation; native conditional-proof execution is not
claimed. Complete privacy, independent recovery and production setup remain open.

Current qualifications and corrected privacy findings are in
[project status](docs/PROJECT-STATUS.md). Legitimate payout-owner knowledge and
full transparent drainage remain in scope; confidential on-domain state does not
remove their conservation-based disclosures. This consolidation changes no
security invariant or spending rule.
The local [privacy guide](docs/research-knowledge/privacy.md) and
[recovery guide](docs/research-knowledge/recovery.md) carry earlier observer,
availability and failure-model lessons into future reviews.

The [6 November batched comparison](research/batched-payment-costs-2026-11-06/RESULT.md)
retains complete public state/prover inputs and actual native fee refunds. Its
six payout-key assignments assume blind registration, fresh independent keys,
protected logical redemption and a suitable honest cohort. Real eligibility
proofs still disclose the identified claimants' withdrawal amounts. Prior known
destinations, origins and all-but-one collusion collapse the benefit. The native
adapter binds exact current effects/old-new state/operation payload and preserves
NFs after paid-record normalization. Outpoint-bound approvals can become stale;
active-pool races, fee top-ups, later admission and independent data/parameter
availability are not qualified. Pricing local work at a reference tariff does
not establish an invoice, idle utilization or a fully priced anonymous service.
No privileged recovery or withdrawal key is introduced.

The subsequent [requester test](research/withdrawal-request-and-busy-pool-2026-11-06/RESULT.md)
uses an actual onion service and removes human identifiers from the eligibility
API itself. Its service-only view has six owner assignments; measured labelled
client activity or later ownership disclosures collapse them. Known NF owners
still expose exact eligible amounts, and distinct known entitlements map public
payout values. These are local-client counterfactuals, not a global-network,
independent-user, Sybil or timing-anonymity qualification. Combining the published
direct control with its shared candidate keys also identifies them. Fixed-key
loading applies only to fully checked immutable program points; submitted proof
checks and the native program/effects bindings stay intact. Actual Tor-registered
keys and eligibility notes now match a complete native Full-validated payout;
restored native-key spending passes. Approval transport remains local/unqualified.
A genuine unrelated payment invalidates outstanding approvals despite untouched
cohort notes; fresh retry and restored independent exits recover all principal.
This safe collision test does not establish liveness under sustained contention.

The [optional reusable intent](research/reusable-withdrawal-approvals-2026-11-06/RESULT.md)
separates fixed owner consent from exact current-state settlement. Pool/config,
reference anchor, complete claim/payout sets, nonce and aggregate fee cap remain
bound; current spentness and fresh native effects/receipt cannot be cached away.
Actual old-receipt/payload replay and changed successor controls refuse. The
selected wallet reapproval failure is fixed across three unrelated updates;
backend serialization/proving races are not. Released complete consent can be
executed by any holder while its conditions remain true, without wall-clock
expiry or final timing confirmation. Accepted note spending revokes it; off-chain
cancellation does not. Timing/known-owner privacy and independent users remain
unqualified, and combining the public solo counterfactual identifies shared keys.

The [busy-payment follow-up](research/busy-pool-payment-flow-2026-11-06/RESULT.md)
adds cooperating queue age preservation and measured stale-worker cancellation.
Neither is an L1 lock or spending authority. Pending requests alone do not stale
a receipt; a genuine accepted bank change does. A live watcher must authenticate
the winning state rather than let arbitrary request messages force cancellation.
The supplementary timer-controlled process test reuses a retained actual race,
not a new chain event. Incoming-payment delays worsen under the measured batch;
independent operators can still repeatedly win the current-bank race. Actual
identified entitlement replies disclose NFT-to-payout links. The complete IPC
trace also contains research-controller client instructions, which must not be
mislabelled as automatic service knowledge. No stronger privacy, production
wallet interface, unlimited-load or independent-user qualification follows.

**Status:** initial research draft. This document should become more precise as architecture choices are made.

**Active scope, 5 November:** unchanged Kaspa consensus under
[ADR-0105](docs/adr/0105-maximize-privacy-without-consensus-changes.md).
Compare public-chain, known-owner/counterparty and service/network adversaries
separately across the complete lifecycle. A cooperative output protocol may
reduce attribution only with an adequate honest cohort and protected registration/
transport; coordinator transcripts, collusion, unequal amounts/change, aborts and
immediate independent fallback exits remain attacks. No cover participants,
unknown owner mappings, persistent balances or forced batching are assumed into
existence. Preserve the corrected conservation attacks and prior-only floor.
The native-consensus prototypes below remain historical local evidence only.

The [joint-withdrawal audit](research/joint-withdrawal-feasibility-2026-11-05/RESULT.md)
derives request-to-payout links from already public recipient keys/scripts;
human ownership still requires explicit auxiliary information. Removing labels
or shuffling outputs cannot erase an earlier public link. Mixing after the
original payout retains all previously disclosed facts. A replacement protocol
must account for what the registration service actually receives, not assume
an anonymous-registration oracle. This gate adopts no new protocol or trust role.

The subsequent [finite common-set experiment](research/common-set-withdrawal-2026-11-05/RESULT.md)
uses real blind registration with one pinned issuer mode/key and a round-wide
issuance barrier. Client randomizers/blinding factors must remain absent from
identified issuance; origin/randomizer leakage, externally mapped payouts and
all-but-one collusion remove the measured ownership ambiguity. Native spending
requires owner proofs over the whole actual transaction; issuer signatures are
coordination only. Solo exits retain the same reserve/spentness protection.
Experimental setup, supplied unconfirmed state, disclosed input claim identities,
same-host roles and unmeasured network/timing/Sybil attacks remain explicit trust
limits. The prototype does not establish complete financial privacy or recovery.

The [actual-wallet extension](research/payment-set-withdrawal-2026-11-05/RESULT.md)
retains the complete original relation while exposing a SHA256 digest of all
canonical statement bytes as two 128-bit public limbs. Native predicates must
reconstruct those bytes, including actual full-effects context, current root,
economic nullifier, VK/domain and amounts; a host-provided hash is insufficient.
Public Operation delivery binding and current kernel NF checks remain mandatory.
The finite predecessor is supplied at the locally executed kernel's root; it
does not authenticate accepted native ancestry or upgrade the old guest/parser.
Direct-route fee floors cannot be applied to the separately batched architecture.

The [native-draft authorization package](poc/native-tx-validation/README.md)
adds local proof/signature rejection evidence under
[ADR-0104](docs/adr/0104-unfunded-native-draft-authorization.md). Its entire UTXO/
anchor/spentness/balance view is synthetic. A forged server could supply a
self-consistent view; valid signatures under it establish no native backing or
accepted history. The package cannot mutate consensus state. Signed mass is not
validated pricing, and a fixed key-constructor diagnostic is not a portable key
importer. The [second-pass review](poc/native-tx-validation/REVIEW.md) records
the executed attacks and remaining independent-review/consensus/recovery gates.

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

## Staged TN10 input and bootstrap boundary (2026-10-19)

The [TN10 preparation](poc/private-native-tn10/README.md) must not reuse a local
fixture receipt for real chain data, trust GPU-supplied expectations, skip lane
activity during a proof wait, or treat a submit-success flag as native acceptance.
Its native validator is pinned independently, complete journals are frozen on the
trusted controller, and a checkpoint preserves accepted lineage plus the next
capture start. Historical acceptance still requires fresh live UTXO/selected-chain
checks before spending. An orphan/stale receipt cannot be repaired by editing its
endpoint or accounting; halt and retain it for diagnosis.

The new [rent-only initializer](docs/adr/0015-tn10-private-native-preparation.md)
addresses a previously unexercised genesis ID/state-root circularity. It exposes
no withdrawal authority and cannot touch a deposit, but its canonical state
serialization, exact successor reconstruction and native bindings are new code
requiring review. Do not deposit until initialization is actually accepted.

The native broad signing helper resets all input compute budgets; the adapter
uses the existing single-input sponsor signer after fixing measured budgets and
checks every input again on the fully signed layout. Fees are paid from sponsor
change, with user principal/state rent/permission rent accounted separately.

Separate 0600 local role files do not protect Bob against the host administrator.
The operator must establish Bob's actual custody before release. No RunPod key,
wallet backup or witness enters a public proof bundle. Existing B credentials,
lease deadline, backup and provider stop remain separate from chain execution;
the gateway is only a management route. New staged GPU transport/image binding
and a live full terminal rehearsal remain unqualified in this preparation.

## Staged GPU service preparation (2026-10-19)

The [staged service](poc/staged-tn10-service/README.md) authenticates uploads and
requires a target hash approved independently on trusted B. GPU-returned metadata
cannot set receipt expectations. Only four public assets are accepted; uploaded
executables cannot replace the image host or pinned guest. Archive traversal,
links, duplicates and altered assets are rejected before execution. No wallet
secrets or provider credentials belong in this interface/image.

The service token, trusted B installation and B root remain operator trust
assumptions. This is not isolation from a malicious administrator. A missing
controller or stale heartbeat blocks a new stage; an interrupted active service
consumes the attempt rather than resuming or repeating it. An exclusive volume
lock prevents another mutating service process. The unchanged external B guard
retains the absolute rental stop even if service/backup I/O fails. Synthetic
provider responses do not qualify actual provider stop or account permissions.

These transport changes cannot authorize native withdrawals or alter monetary
state: the unchanged guest/native scripts and independent exact receipt checks
remain necessary. Reorg, stale anchor and accepted-chain checkpoints remain the
reviewed PR52 controller duties; a mismatch requires stopping the trial. This
preparation adds no claim of production privacy or live TN10 rehearsal success.

The PR53 correction bounds all gzip expansion before tar parsing, including
hidden PAX/GNU metadata and padding; returned evidence also has a compressed-read
and logical-member cap. Interrupted recovery repeats identity-checked process
cleanup even after an earlier recovery died between durable gate closure and
the kill. Neither fix changes proof/native policy or extends the deadlines.

## Local user recovery / exact-reserve experiment — 2026-10-19

The [user-held recovery package](poc/user-recovery/README.md) requires an
independently accepted root, not a root supplied by the snapshot provider.
Roots authenticate retained data but cannot restore missing ciphertexts/history
or establish freshness. User native keys/backups never belong in outer proving
jobs. Separate processes on an operator-owned host do not protect against that
operator; independent custody requires separately administered hardware/software.
The additive terminal policy is a host-only fixture, not an upgrade or new exit
right for the existing live reserve. A later guest must bind its policy under a
new identity and enforce genuine permission issuance before live use. No rescue
key, operator withdrawal privilege, or weakening of current spentness is added.

## Integrated recovery guest boundary

The [new guest](poc/recovery-native/README.md) has its own state/program namespace,
covering positive-change and exact-reserve native payout shapes without a host
payout-success oracle. It retains unpaid exit liabilities through permission
issuance. Old/fake receipts are rejected under independent compiled expectations.
CPU execution and synthetic native payout contexts do not establish new receipt
soundness/issuance acceptance or canonical TN10 backing. New-root wallet handling
retains user-held secrets and independent-root checks. No old funded pool is
upgraded; a fresh native instance and actual chain proofs are required. Data
availability, current anchors, independent custody and shutdown liveness remain
open qualifications, with no rescue-key fallback.


## Proposed native shielded-value domain — 3 November 2026

The [RFC-0004 extension](docs/rfc/0004-native-kas-private-payment-boundary.md#reviewable-native-shielded-value-proposal)
is a consensus research proposal with a completed internal AI technical review.
[ADR-0101](docs/adr/0101-native-shielded-research-reference.md) chooses complete
repaired Orchard V2/native verification as the research reference. It does not
deploy a pool, amend an invariant or establish privacy/security qualification.
The current covenant experiments keep their own scopes. A native pool would
need separate exact validity, state, supply and data-availability arguments.

| Threat / failure | Required design obligation | Current review limit |
| --- | --- | --- |
| Hidden inflation or reserve double counting | Complete `u64` note/binding construction, authentic zero genesis and explicit native-backing induction; count KAS once, reject underflow/overflow and route fees once. | Upstream circuit does not prove `MAX_SOMPI`; induction and proposed I-1/I-2 interpretation await independent review/adoption and native enforcement. |
| Replay/double spending across DAG blocks or versions | One current spent set/domain across mutually accepting profiles; deterministic atomic accepted-order effects and complete undo. | Cached/parallel proof checks cannot establish current marker absence; implementation is absent. |
| Payout, fee or delivery substitution | Authorization binds actual native effects, ordered encrypted outputs, amounts/fees and domains; every old transaction format retains its old rules. | Exact signing/profile encodings and fee-contribution design require review. |
| Valid-looking but unspendable delivery | Standard Orchard recipient validates plaintext/commitment/key consistency before credit. All-slot uniqueness and Action-linked freshness prevent duplicate spend identities. | Unchanged proof does not prove correct encryption. Native delivery binding/recipient integration remain; old position-derived nullifiers cannot be reused. |
| Public totals, isolated activity and counterparty disclosures | Preserve the legitimate observer, public b/B, boundary amounts and fee/query/network metadata in privacy analysis. | Hidden note fields do not guarantee hidden inferred balances or relationships; later ordinary payouts remain public. |
| Pruned or withheld history/parameters | Independently retained authenticated discovery/spentness data, exact public artifacts and compatible owner backups. | A root or server-signed snapshot does not recover missing bytes; at least one sufficient independent data source remains an availability assumption. |
| Fixed-fee lockup, service loss or ciphertext-dependent recovery | Wallet-owned authority and usable fee/repricing path; no required sponsor/admin rescue; distinguish validity, affordability, relay acceptance and inclusion. | Complete service-loss and future fee conditions remain unqualified; no free-exit or guaranteed inclusion claim. |
| Upgrade, setup or quantum failure | Explicit classical Halo2/RedPallas/ECDH assumptions, immutable claim identity/common spentness and exact authorized migration. | Native verifier remains unimplemented; Proposed ZIP 2005 prepares future recovery and supplies no current end-to-end PQ guarantee. |

Safety under unverifiable state still requires rejection/halting. That is not
sufficient for I-10: the full recovery contract must show that every valid user
can obtain and use the declared public data independently. The
[agent source/spec self-review](research/native-kas-shielded-value-review-2026-11-03.md)
records two corrected wording/compatibility issues; it is not specialist approval
or an audit. Frozen historical failures and corrected scores remain unchanged.

The completed [Q1 privacy review](research/rfc0004-privacy-feasibility-review-2026-11-03.md)
also proves a prior-only lower bound above the retained population's absolute
cap. It blocks that population's qualification, not every diagnostic study.
The [crypto](research/rfc0004-cryptographic-profile-review-2026-11-03.md) and
[consensus/accounting review](research/rfc0004-consensus-accounting-review-2026-11-03.md)
record exact current assumptions, header/bootstrap gaps and an adversarial second
pass. Twelve symbolic traces exercise model obligations only; they validate no
cryptographic soundness, actual DAG/store undo or independent data availability.
Independent human cryptography/consensus approval remains outstanding.

## Unfunded complete-Orchard codec/verifier — 4 November 2026

The [ADR-0102 package](poc/orchard-interop/README.md) checks genuine full Halo2
and both signature roles for an experimental complete modeled-effects digest.
Untrusted packet fields cannot select another verifier/version. Canonical
role/length parsing, bounded allocation, signed delivery/economic fields,
duplicate supplied outpoints, all-slot spentness and stale supplied-context
checks have explicit negative coverage. Its [adversarial review](poc/orchard-interop/REVIEW.md)
records the attack paths and remaining boundaries.

Ordinary input amounts/authorization, roots, predecessor and spentness are
supplied inputs, not authenticated native state. No UTXO/script execution,
durable acceptance/undo, archive availability, native mint/release or funded
payment is implemented. Reusing old supplied context is not stateful double-
spend prevention. Public fixture keys/seeds belong only to synthetic unfunded
vectors. The diagnostic Rust Debug key fingerprint is not a portable consensus
key format. Passing this package does not qualify privacy, complete costs,
recovery, cryptographic soundness or production safety; invariants remain intact.

## Native consensus draft — 4 November 2026

[ADR-0103](docs/adr/0103-native-shielded-consensus-specification.md) records the
[native draft](docs/spec/native-shielded/README.md), whose
[adversarial review](docs/spec/native-shielded/CONFORMANCE.md) separates proposed
mitigations from actual implementation. Standard key-controlled native funding
and new complete actual-input/effects signing avoid silently applying new
shielded-balance rules to arbitrary old contracts. Forest rollover retains old
anchors and one global spent set; a full depth-32 tree must not strand exits.
Current block qualification and mergeset conflict filtering remain distinct,
with atomic ordinary/native/log/fee undo and no proof-cache absence shortcut.

Header3 commits native state at the actual past-state point and in its PoW
prehash. Replay requires ordinary funding/DAG context as well as retained native
events. The proposed snapshot is restricted to an already independently qualified
point; it supplies no new fresh-node trust shortcut. The portable mathematical
VK capsule pins the actual compatibility scalar; substituting a new hash into
the proof transcript is forbidden. Scalar provenance still records the upstream
Debug derivation, and a native key importer/backend remains absent.

All these are draft rules with hash/model conformance, not tested native guards
or a soundness proof. No invariant amendment, network allocation/activation,
approved mass prices, full recovery guarantee or privacy pass is adopted. New
tree/anchor/fee metadata and later transparentization remain observer inputs.
