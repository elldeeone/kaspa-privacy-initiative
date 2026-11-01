# Registered financial driver authority bridge

Status: **UNQUALIFIED SOURCE ONLY — `CONFIGURED=0` — NO LAUNCH**.

`registered_driver_bridge.*` implements the public-identity authority seam from
ADR-0083. It does not implement a registered financial main.

The outer authority owns objects in this order:

1. the durable identity `Registry`;
2. the permission-separated Docker anchor client; and
3. the three-party `Supervisor`.

Destruction is reverse-order, so the supervisor cannot outlive the registry or
anchor. `OuterSupervisorAuthority` exposes only proposal submission, readiness
and approval. It exposes no registry/anchor path, descriptor, Docker socket or
secret capability to a party.

For a party attempt, the bridge consumes:

- one role/session-bound `PartyApproval`;
- a direct accepted-head commitment;
- one compiled driver selection; and
- one capture plan binding round, canonical UUIDs, run/attempt/cohort,
  capture source/build/launcher and fixed descriptors 20 through 29.

Registered construction now preserves this exact order: heavy public preflight,
one fresh direct head used by both the supervisor recheck and selected compiler,
durable LOCK, a second fresh direct head, durable-lock capability minted from
that actual `LockedAttempt`, and permit consumption inside its owner-intake
claim. Construction owns the authorized attempt and capture session through
proof verification and registered release; callers cannot inject a capture
session, owner port or multiplication batch.

After exact LOCK-bound durable EGRESS and projection observation, one party may
emit only a move-only `PartyDriverCompletionAuthority`. It binds role, round,
lineage plus attempt/authorization identities, all owner contracts,
proposal/selection, both head observations, LOCK, capture plan and
effects/core/proof/projection. It deliberately has no producer or global
capture-complete field. Per [ADR-0085](../../../../docs/adr/0085-staged-registered-payment-capture-authority.md),
an absent outer supervisor must join all six party capabilities with genuine
END/EOF/exit observations for ten streams. Plain JSON cannot mint either
authority.

`baseline_public_effects_collector.*` is a separate source-only positive-control
slice. Capture classification enters the capture-plan identity and party EGRESS
receipt. Only `ExplicitOwnerPublicEffectsBaseline` can form a nonforgeable
verified-effects plan derived from the live registered construction and its
matching durable `EgressRelease`; `HiddenCandidate` is rejected before
collection. Three
authenticated owner capabilities must exactly partition the source-derived
three public NFs and six public tuple hashes. The final typed receipt preserves
each owner's contract -> NF -> two-tuples mapping. No private owner body, host
fixture, JSON or caller digest is accepted. These driver/baseline authority
constructors friend only concrete classes defined in their own headers;
redefining their former forward-only friend names cannot mint them.

## Current hard stops

The source status deliberately reports these incomplete:

- authenticated supervisor-to-party IPC delivery and acknowledgement;
- the selected configuration producer for compiled fresh-lineage authority;
- the authenticated per-role supervisor/party delivery and acknowledgement;
- a configured outer driver that invokes the compile-tested source path;
- the outer six-party/two-round plus ten-stream capture supervisor;
- a parent-owned durable R1/R2 completion record; and
- a nonforgeable owner-private-effects source that binds each authenticated
  owner to its actual NF and created tuple pair, authenticated owner IPC and
  parent disclosure dispatch;
- downstream activation, accepted payment terminal, settlement and later
  terminal-Exit privacy integration.

The party capture session starts before head recheck/LOCK and observes the real
owner cohort and verified EGRESS projection. It intentionally cannot emit
global capture completion because it does not own the producer or other
roles/round. The party completion constructor is private and has no production
metadata/JSON mint.

## Evidence boundary

Compiled controls cover authority/config mismatch, stale pre- and post-LOCK
heads, changed owner contracts, invalid capture UUID/round, replay, premature
completion, cross-attempt EGRESS mixing, projection mismatch, duplicate party
completion, hostile forward-friend redefinition, production interface
non-forgeability and the full heavy translation-unit/order closure. These
controls are source evidence only. They are not an MPC proof, global capture,
privacy result, Testnet trial, native
settlement or cryptographic review.
