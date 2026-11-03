# Registered EdDSA/financial relation admission: CONFIGURED0 blocker

## Outcome

No production admission capability can be minted from the current checkout.
The exact public relation candidate is identifiable, but the immutable selected
exporter specification and the live owner-input handoff do not exist. Adding a
constructor around hashes, JSON, counts, or caller-supplied identities would be
forgeable, so this change deliberately adds no authority type and enables no
execution.

The machine-readable record is
`REGISTERED-RELATION-ADMISSION-BLOCKER.json`. Its controls are
`controls/test_registered_relation_admission_blocker.py`.

## Exact public candidate

The joined public source evidence agrees on this candidate:

- relation model: `f3ca3c18...60ba28ff`
- complete source table: `3ff31adf...380d829`
- finalized matrix: `c02320f8...6c756ab`
- trace graph: `5bda570c...5a64297`
- trace: `4c3dec7c...604808e`
- canonical owner layout: `9a3ee5f5...4617e1e`
- prefix recipe: `ef6279fa...d0e0edb`
- EdDSA matrix: `b573a68b...f17d11`
- EdDSA mapping: `dfff3a6a...290712`
- three owners, each with `2,635,409` ordered input columns

Each owner partition is exactly 66 native-edge columns, 2,625,295 local
auxiliary columns, and 10,048 columns from its selected EdDSA component (all
component variables except constant ONE). The selected matrix has 67 instances,
10,049 variables, and 10,065 constraints, and is copied exactly three times.

This is public structural evidence only. It contains no owner body, checked
private execution, aggregate proof, financial acceptance, launch, or network
result.

## Current-source matrix equivalence

The 48-file current public source table
`04adfd77...137a9d7` regenerated all 13,093,029 relation rows.  Its complete
A/B/C matrices are byte-identical to the matrices behind the selected
`c02320f8...6c756ab` fingerprint.  The retained machine-readable evidence is
`current-matrix-equivalence-2026-10-29.json`.

This removes source-to-matrix drift as a matrix/key-rebuild blocker only.  The
selected relation source identity remains `3ff31adf...380d829`; the current
table is not selected and mints no authority.  It adds no trusted-setup or
toxic-waste provenance, private-execution, proof, financial-acceptance,
privacy, configuration, or launch evidence.

## The owner-map identity already exists

Do not add a second caller-provided `owner_map_hash`.

The raw canonical layout SHA-256 `9a3ee5f5...4617e1e` is the exact owner-column
map identity. `trace/trace_witness.cpp` authenticates those canonical bytes,
then enforces exact role order, strictly increasing and disjoint in-range
columns, exact EOF, and the expected model shape before it returns a
`TraceProgram`. Counts are only a secondary shape check; they are not the map
authority.

The additive owner transport may continue carrying the existing trace and
layout identities. What it lacks is a live capability proving that those values
came from the same immutable selected EdDSA/financial relation.

## Why current selection is insufficient

The source design has useful pieces:

1. `RegisteredService` authenticates fixed exporter executable, source closure,
   specification, runtime, namespace tool, paths, and hashes into its live
   identity.
2. `export_registered_program.py` requires an exact EdDSA matrix record and
   mapping SHA-256 while generating the public trace.
3. `RegisteredFinancialSelection` authenticates the final relation, trace,
   canonical layout, recipe, roles, and owner counts under the live service.

The production chain is still open:

1. `KPI_REGISTERED_FINANCIAL_CONFIGURED` is `0`.
2. `/srv/kpi/registered-financial/v1/compiler/{SPEC.json,SOURCE.json,SIGNATURE-MATRIX.json}`
   and the selected registration were absent at review time.
3. `REGISTERED-EXPORT.txt` drops both the EdDSA matrix and mapping identities.
   Its C++ descriptor therefore cannot compare or retain them explicitly.
4. No private move-only relation capability crosses from the live registered
   selection into additive owner-input admission. Strings, counts, digests,
   JSON receipts, and a locally preserved matrix cannot fill that role.

The ephemeral matrix was copied without overwrite to
`.local/registered-financial-relation-candidate-20261029/` and verified
byte-for-byte at SHA-256 `b573a68b...f17d11`. Its `PROVENANCE.json` marks the
copy `PUBLIC_CANDIDATE_PRESERVED_NOT_AUTHORITY`. The ignored local copy is not
installed under `/srv`, selected, or usable as authority.

## Required future seam

A reviewed implementation should expose one deep seam, tentatively
`SelectedRelationAdmissionAuthority`:

1. Mint only inside the live selected parent from the same
   `RegisteredFinancialSelection`, its authenticated immutable exporter SPEC,
   and its fully parsed `TraceProgram`.
2. Bind the live service/selection, model, complete source closure, graph,
   finalized matrix, exact EdDSA matrix and mapping, trace, canonical layout,
   recipe, exact parsed owner columns, build/runtime, process, context
   generation, and failure epoch.
3. Make the token private-constructor, move-only, and single-consume. Consume it
   before any owner listener or masked input.
4. Poison on replay, wrong role/run/relation/matrix/mapping/layout, cross-context
   use, or parent restart.
5. Never mint or restore it from JSON, a digest, a Boolean, a public receipt, or
   the candidate matrix by itself.

Before implementation, materialize and review the complete root-owned
selection, extend the registered export/selection handoff to retain the EdDSA
matrix and mapping identities, and freeze the parent call site. Until then the
honest state is CONFIGURED0 and no ADR decision beyond the existing registered
selection design is claimed here.
