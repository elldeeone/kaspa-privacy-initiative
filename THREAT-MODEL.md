# Threat Model

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

## Offline model recovery boundary

The [R01–R04 prototype](poc/shielded-design/RECOVERY.md) assumes authenticity of a
separately retained model checkpoint and ideal-model acceptance of the committed
public effects. A malicious checkpoint/producer can assert invalid hidden
transitions; an archive hash is not a proof or Kaspa acceptance evidence. An
old trusted horizon also cannot establish current spendability. This module
creates no reserve withdrawal authority and never marks a native payout paid.

Backups contain unencrypted synthetic spending/incoming secrets; derived wallet
reports contain private note data and selected positions. Both use new mode-0600
files and must remain private. Stdout is a bounded verdict. Known expected
receipt metadata can detect wrong-key delivery; with no such metadata, unrelated
ciphertexts and malicious unknown-sender wrong-key delivery are indistinguishable.
The success report therefore explicitly declines that delivery guarantee.
Fresh processes/directories do not establish independent operators or sandboxed
file access. Reorg recovery, crash durability and native exit success remain open.

The [R05/R06 continuation](poc/shielded-design/TRANSITIONS.md) reconstructs the
current public nullifier/deposit state before accepting new ideal-model proofs.
A valid proof against an old allowed root does not override current spentness.
Credit and a signed refund request consume the same pending deposit; only the
first accepted transition succeeds. The signature binds owner, domain, deposit,
principal and destination. A refund request preserves principal reserve as an
unpaid claim and locks separately funded rent; it grants no native withdrawal
authority. Backup v2 retains private pending-note metadata for credit retry;
spending keys alone cannot reconstruct an unpublished note. Fresh-process race
tests exercise ordered model transitions, not distributed concurrency, actual
refund payout, reorg rollback or paid-state recovery. The new model checkpoint
remains a trusted harness output, not independent chain authentication.

The [R07 model extension](poc/shielded-design/PAYOUTS.md) retains paid claims
and fees instead of resetting them during restore. Payment must match the
existing unpaid claim's destination/principal/rent and exact remaining reserve;
principal-plus-rent output overflow rejects before consumption. Rent returned
is retained separately from principal reserve and unpaid liabilities. A refunded
deposit stays consumed. These are synthetic payment effects, not native payout
observations or reserve authority. Omitted effects fail against the retained
later checkpoint, but an older internally valid horizon can hide later payments;
this model cannot prevent payment on separate stale/forked histories. Native
lineage, general rollback and crash-safe submission recovery remain open.

The [R08–R16 offline programme](poc/shielded-design/PROGRAMME.md) rebuilds a
replacement model history before publishing it, and preserves complete public/
private generations under a local file lock and revision check. Actual process
kills and competing writers are tested; hardware power loss, cross-host races
and native reorg authentication are not. Unknown payment intent cannot become an
automatic retry; missing observations leave it unresolved. A malicious local
host can replace the stored model checkpoint, so private-file modes and hashes
are not authority against that attacker. View-only inspection has no spending
seed or nullifier method and reports unknown spentness. Canary and Python socket
audit results are bounded to the exercised code; they establish neither an OS
sandbox nor anonymity. Per-user fresh-process recovery uses one backup each,
but independent hosts, real private proofs and confirmed native payouts are
absent. R13 and R16 full acceptance gates remain open.

The proposed [full private-payment relation](docs/rfc/0003-private-payment-proof-and-settlement.md)
adds explicit checks against tree-count overflow, full-tree exit lockup,
zero-real-input CREDIT authorization confusion, unconstrained encryption and
reuse of one native output for multiple claims. Proposed `exit_only` retains
ownership/nullifiers and zero-output constraints while appending no leaves;
zero outputs never become received entitlements. Strict per-deposit recovery
authorization is shared by credit/refund and remains gated by current state.
Incoming-only keys lack authoritative spentness; Orchard full-viewing material
may derive own-note nullifiers with complete authenticated history, but neither
viewing role authorizes spending. Exact primitive/version/parameter composition,
native descriptor enforcement and all real proof/payout paths remain unreviewed
implementation gates; Orchard source reuse does not transfer its audit assurance.

The [P1 candidate tools](poc/private-payment/README.md) add structural public
codecs and existing-library primitive checks only. Their public test-vector
keys must never be funded. A valid primitive receipt is tagged with its own
program/journal identity and establishes no ownership/balance/current-state
payment statement. Structural codec acceptance does not check curve points,
deposit authority or spentness. No production verifier may accept a placeholder
or this diagnostic program as a wallet. Node capability observations come from
one owner-operated RPC endpoint; raw responses are not independent consensus
authentication. Socket isolation prevents an unknown RPC closing a connection
from being misreported as failure of subsequent known-good methods.

The candidate recovery signature checker adds canonical point recompression,
prime-order/non-small-order checks and canonical signature scalars before the
established strict Ed25519 verification call. Public test vectors and separate
library interoperability exercise these APIs on the native host; they do not
qualify an actual wallet/outer proof. A shared delegate-entry output does not
alone authenticate a recovery key. Later host-supplied metadata, a self-referential
funding descriptor, a different private signature from the public operation
envelope, or a guest's claimed self image must not become authority. Native
funding recognition, mutually exclusive pending consumption and actual payout
enforcement are still unimplemented for this private profile.

The separate-agent AI review route in ADR-0019 supplies limited design evidence,
not external audit assurance. Its fixes bind the actual public CREDIT
authorization bytes through a journal digest, assign all immutable-policy and
actual-image admission checks to proved outer execution, initialize the genesis
allowed anchor, and clarify native boundary conservation explicitly. These are
reviewed design requirements and public format checks; real guest/outer/state
enforcement still needs implementation and adversarial proof evidence. A generic
wallet receipt alone cannot authenticate native funds or choose its economic D.

### Offline wallet prototype boundary

The [wallet harness](poc/private-payment/WALLET.md) uses actual Orchard V2
relation code and RISC Zero receipt checks, but its initial deposit/policy and
complete history origin are trusted synthetic inputs. A host-computed checkpoint
is not native consensus authentication. The caller must retain/trust the latest
synthetic history pin separately; a self-supplied pin cannot authenticate data.
Full history bytes and all receipts are checked before decryption; duplicate
backup keys cannot count the same note twice. Missing data halts recovery.
Plaintext research backups/raw witness memory require a confidential local
machine and are not production key storage. Runtime/profiling metadata can leak
workload differences. Native recognition/ordering/payout, a total proved outer
classifier and external audit assurance remain separate open requirements.
