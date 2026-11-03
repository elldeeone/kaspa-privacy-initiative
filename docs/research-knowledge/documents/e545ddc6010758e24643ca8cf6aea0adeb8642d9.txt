# ADR-0078: Public continuation after private egress

Date: 2026-10-28 UTC.

Status: Accepted bounded research design. Implementation, source selection and
actual financial execution still require their own evidence. This changes no
financial relation, proof key, profile ID, native policy or withdrawal authority.

## Problem

The implemented financial gate exits after durable EGRESS. Its authenticated
assignment, MAC context and one-use prepared ticket cease to exist. The genuine
R0 receipt and complete native CASE are produced later. Consequently the first
`EgressRelease::bind_final_candidate` interface, which requires that old context,
cannot complete ADR-0077's later public phase.

Keeping private shares alive throughout public GPU proving is unnecessary.
Restoring them, serializing an old capability or accepting a caller's success
flag would introduce the wrong authority. The required continuation concerns
already-public, durably bound bytes.

## Decision

Keep ADR-0077's EGRESS, FINAL-CANDIDATE and SETTLED barriers distinct. Add a
separate public-only finalization path:

1. Reopen each fixed registered server journal and trusted latest anchor.
   Require the exact unresolved EGRESS, attempt/binding, effects, core,
   aggregate-proof and projection hashes. Require all three authenticated
   participants to agree that same public history and registration.
2. Directly execute a fixed source-qualified offline verifier against the
   actual whole CASE. Check canonical SDK encoding and all supplied contexts,
   exact core/projection, selected proof-role manifest, genuine R0 receipt,
   image/journal and real NativeFull/ScriptEngine obligations. Every required
   proof/state check remains in the mandatory accepted composition; a host
   `accepted` field is insufficient.
3. Only that fresh direct execution may mint a private one-use
   `VerifiedFinalCandidate`. Bind the request nonce, source/tool selection,
   journal checkpoint, registration, attempt, exact EGRESS and complete
   candidate. No public constructor, deserialization or report-import path
   may mint it.
4. In a fresh authenticated public-only context, consume that capability and
   append the same FINAL-CANDIDATE at all three servers. File/anchor durability
   and all-three acknowledgements precede submission. Do not overwrite an
   existing different candidate.
5. Settlement remains a separate fresh accepted-chain acquisition/replay path
   under its explicit selected-node assumptions. Only its separate qualified
   private capability can append SETTLED and permit later disjoint private work.

The public finalization capability cannot settle, unlock, authorize a reserve
decrease or bypass a native proof. It cannot admit owner inputs. No old MAC key,
share, private witness or process-local prepared ticket is restored. Fresh TLS
or process identities never select a new history or discard its tombstones.

The fixed known-unfunded fixture uses a distinct derived, unregistered
qualification history and cannot be promoted into live registered history or
claimed to have settled on chain.

Registered certificate identity is SHA256 of canonical X.509 DER. Keep separate
whole-PEM-file hashes for source/file admission. Retain CA and hostname checks,
and pin the actual TLS peer DER on both streams and every OT/setup `fresh_fork`
before creating the context. Echoed certificate metadata is not authentication.
Use fresh ephemeral preprocessing directories with only the individually bound
public certificates/CA and own TLS key; never restore an old whole Player-Data
directory or persisted MAC/OT state. Existing qualification identities are not
changed or relabelled by this convention.

## Why this preserves the existing barriers

The raw core was already opened under a durable unresolved lock. Its released
NFs are permanently tombstoned. Future public processing cannot change those
bytes because the reopened EGRESS fixes their hashes and exact binding. A crash
or failed verifier leaves the same unresolved history. Missing/rolled-back
journals, anchors, role identities, evidence or acknowledgements refuse progress.

Successful offline finalization establishes a candidate only. Rejection,
orphaning, Exit, a changed head or reorg does not resolve it. Genuine settlement
never removes released-NF history. Direct owner Exit remains independent of
every private-service capability.

## Source and research boundary

This implements the already selected public proof composition in
[RFC-0030](../rfc/0030-private-batch-construction.md) and the phased history in
[ADR-0077](0077-durable-private-attempt-history.md). It reuses established
authenticated agreement, SHA256, pinned SDK/NativeFull/R0 verification and
durable journals. It adds no cryptographic primitive or consensus rule.

The same [mature-protocol/source refresh](../../research/next-session/local-private-payment/privacy-next/PRIVATE-BATCH-SOURCE-REFRESH-2026-10-28.md)
supports separating private authorization, public verification and accepted state.
Existing local confirmation/replay code is a reuse point; its old profile is
not automatically evidence for the new codec. Source tests, offline successes
and trusted-node observations must keep their distinct scopes.

Required acceptance evidence includes changed EGRESS/CASE/source/registration
refusals, replayed/fabricated verifier output refusal, inherited-FD closure,
one-use and partial-peer durability behavior, independent Exit, and actual
whole-CASE settlement before a second real private round. No such complete
live result is claimed by this decision.
