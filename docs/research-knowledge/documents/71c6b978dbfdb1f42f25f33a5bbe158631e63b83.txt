# Recovery without the preferred operator archive

**Status:** prospective public-fetch/replay/receiver contract, 2026-10-23.
The first positive target is a fresh network reconstruction of the already
completed KPX2 TN10 trace, not a new payout or recovery of an unspent claim.

## Selected bootstrap and trust tiers

The receiver has one seed-only backup (seed, network/genesis/D and derivation
profile) and a **user-authenticated public pool descriptor**. Saving a public
descriptor hash/genesis locator is ordinary wallet configuration; it is not a
private operator export or precomputed exit. A supplied current root, arbitrary
descriptor hash, shared D or coherent bytecode cannot choose the canonical pool
among separately funded copies. The user must pin the intended founding
outpoint/descriptor at wallet setup, before accepting the payment.

The current descriptor schema is `kpx2-recovery-descriptor/v1`, exactly these
nine JSON fields:

```text
schema, network_id, genesis_hash_hex, domain_hex32,
founding_outpoint{transactionId,index}, birth_start_hash,
initial_redeem_hex, immutable_policy_sha256, vk_hex328
```

Index is0; network is testnet-10 and genesis is source-pinned. The descriptor
digest uses SHA256 of UTF-8 sorted-key compact JSON. It has no later transaction
IDs, actor/stage labels, intended amounts, snapshots, archive paths or secrets.
The initial redeem contains coherent singleton State112 and the selected
immutable policy/VK. An application-bundled source-pinned policy template must
recognize the whole state-free bytecode: parse canonical pushes, substitute only
the expected D32/VK328 constants with checked multiplicity and compare the entire
tail. An arbitrary descriptor-selected script is not a verified KPX2 program.

| Tier | Demonstrates | Still assumed |
| --- | --- | --- |
| Previous finite checker | Seed-only ownership against supplied accepted snapshots/records | Preferred complete archive and validating node |
| Selected R1 | Independently fetched raw public history, locally rebuilt roots/receipts/witnesses; no operator snapshots/amount map | User-pinned genesis/descriptor, an honest validating node and retained complete data |
| Multiple-node R1 | Failover/corroboration and explicit disagreement handling | Availability/retention and node honesty; endpoint count is not consensus proof |
| Independent consensus | Not selected/established by this prototype | Requires a verified local consensus view or a separately justified authenticated light-client construction |

An R1 success is **operator-independent data recovery**, not independent
consensus, anonymity, durable DA or proof that every public service can vanish.

## Fetch public data, then derive ownership locally

The fetcher sees only the descriptor and public pool graph. It sends no seed,
viewing key, invoice index, recipient label or note-ownership filter to RPC.
Fetch Full accepted history from the pinned birth anchor without jumping
cursors. Retain raw pages plus source/cursor/hash records, accepting headers,
strictly greater than20 blue-score depth and removal/reorg observations. Native
u64 values remain lossless integer sompi; SPK version is0, transaction version1.
The remote node's network/version assertion is trusted, not binary attestation.

Do not supply the six known operation IDs or former stage labels to discovery.
Find the chosen founding transaction, then follow actual consumed reserve
outpoints. Derive the singleton from its 536-byte public genesis payload,
including D/Note/CM/cipher hash. Fetch and verify every successor, its actual
populated input contexts and complete delivery/update data. Query the exact
derived current head and relevant public payout outpoints, then reconcile a
post-query chain delta. These views are not atomic or permanently final.

A second endpoint may restart a complete scan from the same retained anchor.
Never silently splice a stale prefix from one source into a different suffix.
Conflicts, incomplete pages, absent middle links, unknown policy/payload,
missing founding, pruned anchors, removed blocks or a missing unspent head
without a verified terminal transition are explicit INCOMPLETE/INVALID results,
**not recovered zero balance**. A safe halt is a recovery failure, not I-10.

## Deterministic public replay

Replay rebuilds sparse CM/NF trees and physical indexed-NF records from bound
payloads, checks unsigned-LE256 ordering, predecessor/append/intermediate roots,
counts, original positioned NFs, integer backing effects, complete immutable
successors and native payouts. Distinct positions are never collapsed because
their CM bytes happen to match. Preserve all positive liabilities, including
unusable/quarantined deliveries. No operator's declared current root/snapshot,
local-check boolean or expected-payment amount substitutes for reconstruction.

Accepted proof/signature validity retains the explicitly honest validating-node
premise unless a separately selected generic native validator executes actual
Full/ScriptEngine against the recovered public contexts. Such validation needs
no PK/prover or private profile; record its code/binary identity and exact scope.
Public hash replay alone is not Groth16/Schnorr verification or consensus proof.

The receiver process mounts only its own backup, public descriptor/replay output,
approved public source and pinned crypto bridge. It derives the V2 stable
delivery key locally, decrypts each receipt, rederives arbitrary u64 invoice
indices/authority, verifies CM/position/value and computes its original NFs.
It then reconstructs fresh current witnesses for all recognized correctly
encoded owned positions, without an intended-amount map. Failed decryption or
unusable delivery is an explicit foreign/undeliverable residual, not evidence
that every accepted output belongs to someone else or that undiscovered owned
value is zero. Correct encryption/delivery is not proved by the sender circuit;
this availability/acceptance limitation remains a blocker. A later invoice duplicate may flag
privacy contamination; it must not freeze earlier legitimate value.

## Exit and remaining obligations

The current recovered native REVEAL route requires explicit privacy-loss
consent before creating a revealing payload/signature. No automatic fallback,
operator signature or precomputed exit is permitted. Ordinary PRIVATE_EXIT is
a separately versioned proof experiment; it requires public proving material
and a fresh owner-selected destination distinct from Note.nativePK. Such a
destination must be covered by the receiver's own native wallet backup; any
new seed-derived default role needs an explicit reviewed derivation decision.

The historical positive can verify previously paid owned outputs and terminal
zero but cannot prove a newly constructed exit from a still-unspent liability.
That needs a fresh identity, local complete terminal rehearsal and actual
authorized test-KAS payout after the operator archive/prover are unavailable.

The 10,000-operation/20-Mbit/s/15-minute requirement remains unchanged. A
synthetic replay/resource run must label unproved history and cannot establish
live availability, privacy, accepted history or reference-device p95. Pruned or
withheld ciphertexts cannot be recovered from a seed/root: surviving public
replication is an architectural requirement. Orphan-only invoice/disclosure
knowledge also cannot be reconstructed from canonical chain history alone.
