# ADR-0046: Fresh private TN10 rehearsal

**Status:** Accepted for implementation and test-KAS rehearsal.
**Date:** 2026-10-23 UTC.

## Context

The completed offline six-body lifecycle and genuine competing-spend controls
use public synthetic DO_NOT_FUND secrets, a fixed compiled domain, supplied
UTXOs and an archive/current-head oracle. They must never be funded. The owner
now requests the prover bottleneck work and a complete testnet rehearsal with
confirmed payouts. Existing generic SDK/wRPC serialization and accepted-history
primitives can be adapted; old S7 owner/replay workflows and keys stay parked.

## Decision

Build a separate finite TN10-only constructor, lifecycle orchestrator and chain
adapter. Preserve closed offline source/evidence. `new` creates an unfunded
private identity in one command, in minutes: fresh OS randomness, payer and
recipient seed-only backups, native funding/payout keys and a trial nonce. Store
private material outside Git under restrictive permissions and exclude it from
arguments, public logs and publication packets. Reject existing destinations.
No mainnet switch, real funds, token or privileged reserve release is introduced.

Choose a fresh per-trial domain bound to the fixed TN10 genesis and trial nonce.
The current relation constrains its domain at compile time; therefore produce
matching isolated source copies, binaries and a fresh development setup/VK.
An identity UUID does not substitute for this binding. Preparing those matching
artifacts is automated and separately measured; do not silently substitute the
old fixture key or a shared domain to shorten creation. A retry always has a new
identity and no used-trial rebroadcast.

Reuse the finite six-body shape: actual funded source preparation, coherent
founding, public admission, one genuine two-recipient payment and both owner
reveals. Use integer sompi throughout. Before any funding/broadcast, rehearse the
complete local terminal path with the exact new suite and SDK serialization;
verify TN10 genesis, node activation/sync/index and actual fee/body compatibility.
Then use test KAS only, bind real accepted outpoints/amounts/SPKs and record each
submission once. Reconcile ambiguous submission read-only. Authenticate each
accepted full body/current output before constructing its successor and retain
public receipts/update data. A changed fee/context requires its actual new proof.

Restore recipients from pre-payment backups and supplied authenticated public
data. Remove prover/PK/preferred-service access before exit authorization. Real
terminal broadcast and confirmed native payouts for both recipients, with final
reserve and every positive liability zero, are required for rehearsal completion.
An acknowledgement, offline pass or partial chain is not readiness.

## Trust and open questions

This bounded rehearsal may trust a selected validating node and retained complete
archive; accepted-body evidence must expose that assumption. It is not independent
network recovery, durable data availability, privacy qualification or production
safety. Reorg/confirmation policy and node/relay compatibility must be explicit.
Existing privacy failures, generic fee limits and wallet resource requirements
remain. Development setup honesty/trapdoor erasure remain unreviewed. No
mainnet deployment, real funds, paid infrastructure or old rejected workflow is
authorized by this decision.
