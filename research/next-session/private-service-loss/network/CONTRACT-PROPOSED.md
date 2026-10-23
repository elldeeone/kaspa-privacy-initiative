# Auth528 descriptor-only network recovery contract

Status: proposal for ADR0053/source review. No new network client or replay code
has been executed. Existing frozen KPX2 fetch/replay/wallet and KPX3 offline
adapter remain unchanged.

## Purpose and source basis

Acquire a new Auth528 pool from only a user-authenticated public descriptor and
birth anchor, then reconstruct its state before a separate one-owner cold
client reads a backup. Native KAS stays the sole reserve. No seed, key, proving
key, prover, expected payment map, private fixture, operator tree/archive or
precomputed exit is an input to this module.

Reuse the finite FullV2/expanded-header codec and exact populated contexts from
ADR0049's pinned fetcher. Reuse ADR0052's frozen `public_adapter` for Auth528
semantics, including both NF insertions, continuing CM appends and terminal
CM-root/count preservation. The source-derived approved union is exactly
24,417 bytes (State112 prefix 114; immutable tail 24,303), with exactly ten
canonical D32 pushes and one canonical VK328 push. Entire code identity is
checked; a caller-selected policy self hash cannot select arbitrary bytecode.

The 2026-10-23 comparison in `privacy-recovery/SOURCES.md` remains the primary
Kaspa/Toccata/vProgs and Orchard/Aztec/RAILGUN/Monero/MWEB source basis. This
integration adds no note, nullifier, signature or proof primitive. It reuses
public-event reconstruction and keeps local ownership separate from RPC data.

## Descriptor proposal

Strict schema name and tenth-field spelling await ADR0053. Proposed schema is
`kpx3-private-network-descriptor/v1`; proposed exact fields are:

```text
schema, network_id, genesis_hash_hex, domain_hex32,
founding_outpoint, birth_start_hash, initial_redeem_hex, vk_hex328,
immutable_policy_sha256, public_params_manifest_sha256
```

Amounts remain canonical integer sompi at every boundary. Canonical descriptor
SHA256 is recursive sorted-key compact UTF-8 JSON, consistent across JS/Python.
The public parameter manifest is separately authenticated and source-approved;
its hash identifies retained proving software/parameters, not ownership or
honest consensus. The descriptor never selects a local executable or secret
path. A wrong manifest/VK/policy relationship must fail before a backup read.
Exact manifest schema and availability policy await the proof/ADR owner.

The complete descriptor is authenticated by the user/caller. Pool identity is
its founding outpoint and birth anchor; matching a domain in chain data does not
select a canonical instance. No action IDs, current root/head, stage names,
expected counts, snapshots or payment map appear in the descriptor.

## New acquisition API

Proposed files: `poc/private-network-recovery/fetch.mjs` and
`poc/private-network-recovery/network_replay.py`.

```text
node fetch.mjs PUBLIC_DESCRIPTOR NEW_OUTPUT [--rpc WSS ...]
NEW_OUTPUT/fetch.json: kpx3-private-network-fetch/v1
```

Keep the earlier canonical `transactions`, `coverage`, `current_view`, `pages`
and endpoint-attempt shapes. Each selected row contains the full canonical SDK
body, exact `accepted_input_contexts`, expanded accepting header, confirmation
policy and SDK-recomputed ID evidence. The descriptor and canonical digest bind
the complete acquisition. Failed sources retain isolated attempts; never splice
a partial first-source prefix into another source.

Freeze the first sink and a finite selected-chain frontier with more than twenty
blue-score depth. Scan from the retained birth anchor to that exact frontier.
Reject missing/pruned anchor/history, premature empty page, cycle, mismatched
header, removals, malformed contexts and conflicting accepted head spends.
Recompute header identities from actual fields after clearing cached hashes;
preserve expanded parents, hexadecimal blue work and all u64 values.

Discover every reserve transition from the founding output/input0 graph, without
actor/stage labels or desired counts. New Auth528 payloads have magic KPX3AU01,
length 4400 and declared remaining reserve at bytes476..484. A terminal candidate
requires the declared zero remainder and native payout-only topology. The
adapter, then fresh native verification, authenticates the complete terminal
fields; the fetcher does not infer zero from an absent address. Existing ADMIT
and explicitly consented REVEAL fallback encodings remain supported by the
approved new policy.

Query every selected input/output exact outpoint/script/value, covering the
derived current reserve and every public payout. A nonterminal reserve must be
unspent. Perform a second finite catch-up after current queries. New confirmed
spends of any queried currently unspent point, including payouts, invalidate
this snapshot; removals or a missing frontier also fail incomplete. This improves
current-view reconciliation but does not make multiple RPC calls atomic.

## New public replay composition

The frozen adapter only accepts `kpx3-supplied-context/v1` and a strict nine-field
`kpx3-recovery-descriptor/v1`. It intentionally returns `complete:false` and
`accepted_chain_backing:false`. Preserve those inner provenance fields.

The new wrapper explicitly validates the network descriptor/manifest, projects
only the nine approved semantic fields with the adapter's schema, and constructs
its supplied-context rows from fetched full bodies/contexts. It invokes the
frozen semantic adapter without the finite `ExistingNativeResults` cache. No old
module global is patched. It separately performs:

1. Full descriptor binding, finite coverage, fixed-sink confirmation and every
   accepting-header/frontier consistency check.
2. Exact current-query reconciliation for all consumed inputs, the derived
   current head and every public payout, plus post-query catch-up evidence.
3. Fresh generic `NativeValidator` checks on every selected complete body and
   every populated input context using an installed, hash-pinned executable.

Only that independently established composition produces a new outer
`kpx3-private-network-replay/v1` with a complete observed network view. It does
not edit the adapter's `complete:false` result into network evidence. Retain its
semantic result/provenance separately; label fresh public native verification
as fresh, not exact offline cache reuse.

Return deliveries, physical NF records, ordered operations, actual public
payouts, exact current outpoint/state/redeem/current UTXO and observation anchor.
An open head absent from current exact queries is INCOMPLETE. A terminal result
requires a valid terminal transition and observed consumption, never merely an
empty query. A later ordinary-spent payout remains received history with a
queried-null current UTXO, not a missing query or proof of an empty wallet.

## Trust, limitations and acceptance controls

An authenticated descriptor selects the pool and development VK/setup. The
selected validating RPC supplies accepted-chain membership, honest current state
and surviving history. SDK/body/header hashes and local native Groth16/signature
checks do not independently prove PoW/GHOSTDAG, accepted-ID inclusion or durable
data availability. Distinct endpoints alone do not establish independent
operators or consensus. No orphan-disclosure completeness is claimed.

Use source/fixture controls for wrong profile/manifest/policy, decimal/u64 loss,
changed witness/context/destination, wrong/stale state, competing spends,
terminal inactive bytes/no-CM-append, missing history, truncated frontier, bad
header, reorg, head-query absence/substitution and missing payout queries. Mock
transport controls must remain separate from genuine native/chain evidence.

First actual rehearsal captures an open prefix, then a new cold-created owner
exit and its fresh successor, and finally the terminal body/payouts. It does not
qualify sustained active-pool catch-up, all-source pruning or a 10k-operation/
20Mbit/s/15-minute target. No recovery failure silently authorizes a revealing
fallback. No funding or broadcast API is added to this package.
