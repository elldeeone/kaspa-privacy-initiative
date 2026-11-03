# ADR-0079: Source-generated programs for registered accepted heads

Date: 2026-10-28 UTC.

Status: Accepted bounded research design after independent design review.
Implementation, actual head admission and funded execution remain unqualified.
The fixed known-unfunded constructor and its immutable active run stay separate.

## Problem

The first financial gate deliberately accepts only the nonexistent fixture
reserve point. It cannot accept a real GEN3 or subsequent accepted payment head.
Replacing a context constant or allowing a caller's trace hash would not solve
this safely: public history changes state construction, scratch operations and
assertion counts. The same financial relation may need a different complete
assignment program.

The existing public-only Rust exporter already accepts Context/PublicHistory,
checks roots/counts and emits the complete header-first IR, layout and prefix
recipe. Its caller-provided source label is not authentication that the selected
exporter actually ran. Real head admission is also absent from that interface.

## Decision

Implement a closed registered selection factory, reusing the current exporter,
IR and checked financial proving path. Add no cryptographic primitive, opcode
or consensus rule.

1. `RegisteredService` comes only from fixed server-owned configuration. It
   binds the persistent service epoch, actual authenticated certificate roster,
   exact journal/anchor paths, native/model/key identities and exporter/tool/
   source authority. A job cannot choose a new path, registration or epoch.
2. `AcceptedFinancialHead` has a private constructor. Only direct fresh execution
   of the selected acquisition/replay verifier may mint it, under explicit node
   assumptions. It binds the actual accepted reserve outpoint, script, integer
   sompi amount, State112 and chain/pool/profile/domain/service. Caller hashes,
   transaction IDs, offline Full results and imported settlement reports cannot
   supply this authority.
3. Each honest server checks complete public history against that admitted
   head. The factory directly runs the pinned assignment-free exporter in a
   closed public namespace. Authenticate its actual consumed source/tool
   closure; do not accept its source-label argument as provenance.
4. Seal and fully admit the resulting graph/layout/recipe. Check canonical and
   container hashes/counts, complete model-column assignment, every assertion,
   source binding and digest-prefix independence before intake. Owners supply
   no combined witness, private shuffle keys, replacement program or prefix.
5. The privately constructed immutable `RegisteredFinancialSelection` binds all
   these artifacts and exact head/policy to the context generation/MAC epoch.
   All three servers agree, obtain the real durable one-use LOCK, then receive
   owners and execute that selected graph themselves. Full validation uses its
   actual assertion counts, history comparisons, ONE and prefix checks.

The existing validated-assignment, fresh coin, PREPARED, proof/MAC, independent
verification and EGRESS barriers remain mandatory. Missing registration, head
authority, source evidence or history refuses progress. The registered path
never calls the qualification initializer or reinterprets its derived epoch.

## Acyclic registration and configuration identities

The acquisition specification contains the stable registered-service identity:
`SHA256("KPB_REGISTERED_FINANCIAL_SERVICE_ID_V1\n" || encode(EpochKey) || registrationDigest)`.
The registration exists before, and excludes, the acquisition/exporter
specifications and their source closures. This prevents a hash cycle in which
the specification would contain an identity that also hashes that specification.

`identity()` remains the full authenticated configuration/source identity.
Only the acquisition request, specification and returned summary use
`registered_identity()`. The private accepted-head capability, all-server
agreement, context checks and job dependencies retain the full identity. The
stable label cannot authorize a replacement source, tool or configuration.

Complete program/layout agreement and expensive tool admission precede the
final fresh head acquisition. Only the small head agreement, one-use claim and
durable LOCK follow that acquisition before owner intake.

## Exact key reuse

Changing public history does not authorize a new financial relation. Reuse the
stock PK/VK only when independently synthesized finalized rows, physical variable
mapping and domain match the admitted matrix exactly. For this first profile
the fingerprint is
`c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab`.
A changed program/layout/recipe/model identity needs an explicit new selection;
a changed matrix needs a separate architecture/key decision. No fallback,
relabelled zero prefix or per-head hand edit may silently reuse an incompatible
key.

Public-only admitted model/query storage may be retained across attempts when
the exact immutable bytes and authority remain intact. Private contexts,
capabilities, randomness, shares and preprocessing remain fresh and one-use.
A serialized `already_admitted` Boolean or an imported PASS is not a cache
capability. This efficiency work must preserve the complete initial point and
row admission before owner intake.

## Reuse, alternatives and evidence boundary

Reuse `export_financial_trace.rs`, `joint_trace.rs`, `state_trace.rs` and
`joined_source.rs`; preserve internal shared randomness and every actual row.
This follows [RFC-0030](../rfc/0030-private-batch-construction.md),
[ADR-0077](0077-durable-private-attempt-history.md),
[ADR-0078](0078-public-continuation-after-private-egress.md) and the existing
[source refresh](../../research/next-session/local-private-payment/privacy-next/PRIVATE-BATCH-SOURCE-REFRESH-2026-10-28.md).

Recompiling hardcoded head pins for each transaction is rejected as the normal
interface. New public-context IR opcodes are deferred: public-history-dependent
work would still change, and the existing complete exporter suffices.

Required evidence includes fresh/stale/wrong head, history, registry, source,
tool, program and recipe refusals; exact row/key reuse; actual accepted GEN3
selection; full exporter/constructor validation; Original-only spending; and a
complete native broadcast/confirmation rehearsal. Independent source review and
public controls must precede registered private intake. No funded readiness,
privacy, production safety or completed live result is claimed here.
