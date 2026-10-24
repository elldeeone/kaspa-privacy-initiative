# ADR-0060: Four-wallet GN2 testnet rehearsal

## Execution result

The [actual TN10 rehearsal](../../research/next-session/four-wallet-testnet/RESULTS.md)
completed: accepted GN2, two genuine payments, a genuine combined proof, four
original-backup exits and four confirmed native payouts, ending at zero
reserve. All four final no-PK recovery scans passed. Complete transaction fees
including acquisition are 4.521645% of 20 useful net KAS; the 2% target fails.
This is bounded lifecycle evidence. Financial privacy, independent consensus
and separately administered retention remain unqualified.

## Ordinary testnet funding route

Normal faucets were unavailable. Read-only current TN10 probes and a pinned
SDK PoW benchmark support acquiring free test KAS through ordinary mining.
Use only the selected TN10 2.1 endpoints and fresh public funding address A.
Check the template's future miner reward script, preserve its full body and
recheck found work/header identity before one attempt per unique block hash.
Ambiguous responses permit queries, not rebroadcast. This trusts the selected
validating node/template; it is no independent consensus proof.

Mining reads no wallet key and has no pool/admin withdrawal path. After actual
reward UTXOs reach the consensus maturity of 1,000 DAA, a separately reviewed
one-original-owner signer may consolidate its ordinary A-owned coinbase inputs
into 21 KAS for A, 21 KAS for C and source-A-only change. Use exact integer
sompi, fresh fee quotes and current-source checks. Count its acquisition fee
separately and in the complete fee total; mined rewards/refunds are not useful
payments. Strict GN2 still requires noncoinbase sources. No real funds,
mainnet, new daemon, new privacy token or changed financial profile is used.

**Status:** Accepted for bounded implementation; independent design review must
release code generation/setup before execution. No live readiness claim.
**Date:** 2026-10-24 UTC.
**Origin:** [RFC-0025](../rfc/0025-four-wallet-testnet-funding-and-accepted-recovery.md).

## Context and alternatives

The owner authorizes A pays B, C pays D and all four original-backup exits on
free TN10 KAS. The old public benchmark cannot be funded. Reusing GN1 omits
independent contributions; adding a W entry branch is unnecessary because the
funding transaction executes its two ordinary inputs. Select strict GN2 and a
new accepted-W adapter around the reviewed ADR0058/0059 relations. Preserve
every old selected source, profile, study and evidence packet.

## Financial profile and identity

Use the once-selected public identity/domains in
`research/next-session/four-wallet-testnet/PROFILE-IDENTITY.json`.
The exact classification is `TESTNET_REHEARSAL_ONLY_ADR0060`; mainnet is refused.
Generate a fresh compact2 setup and selected private prover, virtual child tail,
child profile, R0 guest/image and actual W/native codec. Wide remains unselected
and rejected. Retain all ownership, conservation, current original NF absence,
membership, native payout/continuation and exact allocated-fee predicates.
Corrected strict SDK-coordinate conversion is retained. No new primitive or
private relation is introduced; changed constant identities still require fresh
source/matrix/build/parameter pins and independent review.

Select the final public `kpx6-four-wallet-financial-profile/v1` by an external
whole-file SHA. It includes profile ID, exact classification/network/genesis,
child/wrapper domains; compact VK/manifest/whole PK/build identity; child-profile
and virtual-tail identities; guest program/image; actual immutable W tail;
reviewed private/aggregate budgets; and exact five generic/current executable
basenames, sizes and hashes. It contains no trial, starting state, funding
point, currentness or funding assertion. Select the software inventory digest
separately: that inventory may contain the financial profile. Never compile the
final profile SHA into the guest that helps determine that SHA.

Reuse authenticated generic validator077, Node d1, crypto6f and fixed SDK bytes
as bytes only. The complete-input bound must be recalculated for the new actual
W tail before selecting private B1500; aggregate B1600 remains conditional on
actual genuine native Full. Quotes/Auths/witnesses come after selected budgets.

## Owner backups and fresh trials

The one-command constructor launches four isolated owner-init processes. Each
creates its own random shielded seed and separate random ordinary funding key,
writing one owner-held `kpx6-four-wallet-backup/v1` original backup containing
network/genesis/child domain/trial UUID and those two private scalar values.
The coordinator receives public invoices, ordinary public keys/addresses and
public initial records only. It never reads either owner's private key. This
adapts the already used separate random funding-key practice, with no new KDF.
Only A/C contribute ordinary inputs; B/D are distinct recipients. Original
backup recovery can also identify the owner's ordinary change via its separate
funding key. Private payout derivation keeps the existing seed/physical-position
recipe and excludes consumed note keys. No private backup hash is published.

Profile setup is one time. Routine fresh identities take minutes without setup
or proving and reuse the selected financial profile. A failed trial gets fresh
keys/outpoints/UUID, not weaker checks or duplicate submissions. Public unsafe
local-control identities are distinct from a subsequently fundable live trial.

## Exact GN2 entry contract

Payload is1080 bytes: `KPX5GN02`(8), final financial-profile SHA(32), child
domain(32), trial UUID bytes(16), then two ordered496-byte initial records:
Note168, CM32, CF264 and CF SHA256(32). A is row0/input0; C is row1/input1.
Require exactly two distinct ordinary P2PK sources, canonical headers, no
covenants and ordinary ALL signatures. New proposals/signing use budgets10/10;
accepted history follows the distinction below. Entry output0 is exactly
selected W(S0) at reserve R0; optional positive source-owned ordinary change
outputs follow A then C. No foreign or unexplained output is accepted.

Both note values satisfy60,000,000 <= v <=2,870,000,000,000,000,000 sompi;
checked R0=vA+vC is within that same maximum. Recompute CMs, CF hashes, ordered
CM placement, cursor n2, exact empty NF sentinel m1 and State112. **State112
does not contain a CF root**: signed GN2 payload binds the initial ciphertexts.
W is reconstructed from push112+State112+selected immutable tail, not a
host-supplied arbitrary output. Use the generic validator/official SDK to
normalize and quote two-input funding; the W codec's one-input normalizer is
not a GN2 oracle.

Compute actual required entry fee F at the selected reference quote. Allocate
F_A=F//2, F_C=F-F_A. Every owner re-quotes and checks its own integer equation:
input_i=noteValue_i+ordinaryChange_i+F_i. Both independently match their exact
immutable owner-init initial record and decrypt/rederive it from their original
backup before signing. Merely decrypting a host-chosen substitute is insufficient.

Each export contains only its own complete input signature, index, own receipt
approval and the digest of the exact unsigned canonical body+both contexts+
profile/trial. Exclude signatures alone from that digest; retain budgets,
headers, all ordered outputs and payload. ALL/sighash and txid do not commit v1
budgets, so explicit body/quote/budget checks are independently mandatory. The
combiner accepts two matching exports, never keys, and rechecks both signatures,
exact fees/body and native Full/all engines before one submission.

## Accepted history, proving and exits

Anchor a retained recent accepted prefix before funding. Reconstruct accepted
GN2 and each actual W successor from official Full accepted-chain data, including
removed/added blocks, physical outpoints and real native UTXO/DAA contexts.
Derive CM/CF delivery history, positioned original NFs and exact reserve after
each operation. State roots/deliveries are not authoritative merely because an
operator exports them. Query current W/payout UTXOs and perform a post-query
race/reorg scan. Pruning, missing pages/bodies/ciphers, wrong entry, conflicting
successors or stale heads fail INCOMPLETE. Trusted non-atomic RPC observations
remain an explicit premise; two URLs are not independent consensus.

Proof-generation processes authenticate whole selected PK/VK/software/profile
and exact READY before the first backup byte; their witness pipe stays empty
until the actual candidate's fee/body quotation. Recognition and GN2 ordinary
approval need no PK or proof-generation worker, but still need selected public
verification software. Mount one original backup per owner; never gather private
witnesses at the coordinator. Four separate one-real-input private exits consume
the two sender changes and two receiver claims, using current actual heads.
No public REVEAL substitute or hidden operator withdrawal key is selected.

## Review, execution and completion

Independent review first releases these designs. Source/code review precedes
setup/proof execution and funding. Serialize CPU/RAM-heavy setup/proofs on the
14-core/24-GiB host; genuine R0 GPU proving is explicitly scheduled. Use existing
authenticated official assets and no paid compute. Complete the local genuine
four-wallet path before the first live trial; the first live run itself is a
rehearsal, never called ready before all payouts confirm.

Success requires actual accepted funding and settlement, coordinator/proving
service loss, all four independent original-backup recoveries, every native
payout confirmed and zero reserve. Close sources=ordinary change+entry fee+
outer fee+all four exit fees+all native payouts in integer sompi. Preserve failures
and uncertain state. Lost coordination may reduce liveness, never authorize
theft or inflation. A failed experiment does not remove the protocol's original
owner-controlled fallback or create a privileged rescue path.

The positive-change four-owner case is expected to exceed2% and must be measured
honestly. Financial privacy still fails the old observer; a confirmed rehearsal
does not repair public partitions or price/sparse-ancestry leakage. This trusted
host development setup is no multiparty ceremony or proof of toxic-waste erasure.
Independent public retention requires real separate administration, access and
loss/retrieval evidence; it is not established by the storage harness.

## Source-review clarifications before execution

The old virtual-child emitter requires distinct compact/wide operands and the
guest requires the compact VK to occur exactly once. Use an explicit all-zero
328-byte `UNUSED_WIDE_VIRTUAL_ONLY` sentinel in the dormant virtual wide slot;
assert both operand occurrences exactly once. Guest permits only compact mode2,
actual W permits only its selected compact private modes/outer route, and GN2
requires actual W rather than a virtual SPK. The zero operand is never an active
financial verification key. No old wide key or wide setup is inherited.

Generic accepted history permits any canonical native u16 budget for both
actual aggregate and direct transactions, validated by fresh native Full and
all financial/proof/body checks. W does not whitelist the actual budget and
its financial projection omits it. Our new campaign quotes remain selected
aggregate1600/private1500 after the exact bound; virtual child templates remain
exact1600. A pricing preference cannot become history/ownership authority.

The same distinction applies to accepted GN2 entry. A calibrated native control
changed input0 budget10→11 while preserving both ALL signatures, txid, all note/
output/payload effects and the actual fee; Native Full accepted it. Rejecting
that accepted entry solely for budget11 would hide valid backed claims.
Separate strict proposal/sign/combine validation (10/10, exact quote and unsigned
body digest) from accepted-GN2 financial validation (canonical u16, fresh native
Full, all signatures/contexts/notes/CF/roots/ranges/output/fee-allocation checks).
Accepted history does not require fee=reference100 times the changed budget's
mass. Actual fee and deterministic allocation/conservation remain unchanged;
this is no waiver of a financial invariant or own preparation price policy.

A once-submitted exact intent remains immutable and is never resubmitted.
Recovery may reconcile a same-txid native-valid budget/witness variant after
complete accepted-page-to-actual-case byte binding and financial-effect checks.
Record both public body digests, actual mass/fee and the byte difference; do not
erase the original intent or confuse its full byte digest with spend authority.
Trusted non-atomic RPC and a fresh pre-submit UTXO check remain necessary.

Cold owner emission may reconstruct the canonical State112 push plus the exact
selected immutable W tail without executing the codec. Enforce selected domain,
state/cursor/range bounds and tail/metadata hashes; public replay and Native Full
remain mandatory. The codec remains selected build/reproduction material,
not an unnecessary dependency for an independent exit.

B/D locally decrypt/rederive the proposed actual recipient notes before the
outer proof/submission, using only their own original backups. This preflight
retains no public ownership map/hash and grants no extra native authority;
pending virtual receipts are not settled. It is deterministic recipient wallet
detection/consent, not a proof of encryption correctness inside the circuit.
Accepted-history recovery still repeats after actual settlement.

## Reconsider on

Failed per-owner entry authorization/recoverability, an asset/body hash cycle,
wrong/stale accepted heads, inconsistent backing/fees, inability to make an
independent private exit, or incompatible verified consensus rules. No invariant
or privacy threshold is relaxed by this decision.
