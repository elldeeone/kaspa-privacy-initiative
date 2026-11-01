# ADR-0095: Pre-setup-only bounded CRS plan

Date: 2026-10-29 UTC.

Status: Accepted source architecture, `CONFIGURED0`. No production plan
selector exists, no full setup has run, and no S4, S12, Testnet or funds path
is selected.

## Problem

Groth16 setup for the exact Output and aggregate circuit closures must finish
before either circuit can produce a proof. The measurement `RunBinding` is a
later completion binding, not a safe CRS input:

- `projections[2]` are hashes of actual released projection bodies. The
  registered capture session computes the hash only after verified EGRESS,
  and the retained parent route receives it only after the body is delivered.
- each `round_capture_plans` identity commits model, query-store and capture
  manifest preimages. No production pre-setup capture-plan minter exists, and
  the current schema does not prove these preimages independent of generated
  keys.
- the finite manifest commits 60 selected-parent artifacts. All 60 production
  rows are currently missing. In particular, the generic
  `canonical-assets-archive` field does not yet exclude CRS-, proof-,
  projection- or observer-derived content.
- the parent recomputation identity is created only after selected-child
  verification and inherits the unresolved 60-artifact dependency.
- `comparison_selection` and `run_selection` are opaque selection-artifact
  hashes with no production pre-setup authority. Their current schemas do not
  prove that they exclude setup outputs.

Binding any of these values into the CRS setup request either creates a direct
chronology cycle or treats an unproved dependency as precommitted.

The word "attempt" is also overloaded. A fresh-owner round carries an attempt
nonce before owner intake. The registered attempt-history row identity is a
different value that commits its ordinal, predecessor, projection and route;
the final history identity additionally commits process and outcome evidence.
Only the fresh-owner nonce can belong in a pre-setup plan.

## Decision

1. `FrozenSetupPlanBinding` is a pre-setup-only lifecycle skeleton. It carries
   exactly one trial identity, two financial-run identities, two fresh-owner
   round attempt nonces and two cohort identities.
2. The trial identity is the precommit root. The other six identities are
   fixed SHA-256 children of
   `KPB_BOUNDED_SETUP_PRECOMMIT_V1\n || trial || kind || round`, where kind is
   financial run, round attempt or cohort and round is 1 or 2. Controller and
   worker independently recompute them. All seven identities must also be
   nonzero and globally distinct. This rule prevents an arbitrary generated
   CRS, PK, VK or later evidence digest from occupying a lifecycle slot.
   These six values are bounded-setup precommit labels, not evidence that the
   current financial `RunBinding` already has a production pre-setup minter.
   A future typed selector must choose the trial root before setup and later
   join these exact labels to the financial lineage. It may not accept a raw
   caller root, setup-artifact hash or post-run receipt as that root.
3. The plan wire then carries the exact Output and aggregate source, matrix
   and geometry closures. A closure means reviewed source identity, recomputed
   matrix identity, constraint/variable counts and expected serialization
   lengths. Static worker, build/source closure and aggregate input identities
   are separately selected before execution. Generated PK/VK bytes and their
   hashes are outputs measured only after setup; no expected output identity
   is a plan field. The sealed plan hash is returned by both dedicated
   one-shot setup workers.
4. Measurement selections, capture-plan identities, projections and both
   finite-manifest identities are forbidden in the setup wire. Test fixtures
   cannot reintroduce them through an unused or caller-authored field.
5. A future production selector must source-own and linearly consume the
   pre-setup skeleton before CRS generation. Existing structural validators,
   test fixtures, diagnostic selection hashes and post-run authorities cannot
   mint it. Until that selector and its callsite exist, the launcher exposes
   preflight only and full setup remains blocked.
6. After setup, a separate authority must join the setup receipt and exact
   PK/VK identities to the richer capture and measurement plan before any
   proof production. Later post-EGRESS evidence, including projection and
   observer outputs, joins only after it actually exists. This ADR does not
   implement or authorize those consumers.
7. The 60-row selected-parent table may enter a later pre-setup selector only
   after every admitted artifact kind explicitly excludes setup and run
   outputs, or after the table is split into a proven pre-setup build closure
   and a separate post-setup execution manifest. A complete table by count
   alone is insufficient.
8. The future typed chronology seam is fixed in
   `bounded_setup_chronology_contract.hpp`. A registered counterfactual source
   owner must mint a move-only `W1PreSetupTrialAuthority` from a new pre-key
   trial reservation after consuming exact relation/profile/build selection,
   both round labels and fixed W0-to-W1 policy, and the accepted starting-head
   lineage. The reservation contains no owner contract or PK/VK-derived
   metadata. The current fresh-owner trial issuance is ineligible: its owner
   contracts already bind proving- and verifying-key identities and therefore
   cannot precede setup. `freeze(W1PreSetupTrialAuthority&&)` burns the new
   reservation and atomically
   retains the frozen plan plus an opaque same-trial
   `W1SetupBindingContinuationAuthority`. There is no digest/root overload.
9. Setup completion does not itself authorize W1 or capture. A distinct
   post-setup join must consume both the genuine `SetupCompletionAuthority`
   and its matching continuation, independently measure the exact four PK/VK
   byte streams, and mint an opaque `W1PostSetupReceiptAuthority`. That receipt
   binds the pre-setup plan, relation/profile/build/worker closures and the
   measured artifact sizes and hashes. A later FullW1/capture/Close bridge must
   consume it with its live lineage authority; the measured-key receipt must
   also precede fresh owner-contract/trial issuance. Proof bytes, projections,
   observer outputs and post-run values are not pre-setup inputs.

## Rejected alternatives

- **Bind the full measurement `RunBinding`.** Rejected because projections are
  post-proof outputs and the other excluded fields are not proven
  setup-independent.
- **Use zeroes, placeholders or predicted projection hashes.** Rejected
  because they do not identify the eventual evidence and make later matching
  caller-controlled.
- **Generate setup first and retroactively label it with a plan.** Rejected
  because the one-shot authorization would not have constrained execution.
- **Treat an attempt-history identity as the predeclared attempt.** Rejected
  because the row identity commits projection and route data, while final
  history additionally commits process and outcome data that do not exist
  before the run.
- **Admit all 60 artifact rows once paths exist.** Rejected until their
  contents and artifact kinds are proved independent of the CRS and later
  observations.

## Security and privacy consequences

The split removes a real circularity and makes the setup request falsifiably
pre-setup-only. It does not make local setup honest: the worker may still know
toxic waste, erasure remains best effort, and a malicious kernel or host can
observe memory. The CRS is not accepted for proof production merely because
the setup receipt exists.

The narrower plan deliberately binds less than a completed measurement run.
Safety therefore depends on the future post-setup joins refusing wrong CRS,
plan, artifact, capture and projection identities. Those joins are absent, so
S4/S12/configuration flags remain false.

## Evidence and current limit

- `bounded_setup_authority.hpp` exposes only the pre-setup fields.
- `bounded_setup_wire.hpp` fixes the 424-byte wire and excludes every
  post-setup offset.
- `bounded_setup_authority.cpp` and the static Rust worker independently
  require all seven lifecycle identities to be nonzero and distinct and bind
  both circuit closures.
- `bounded_setup_plan_blocker.json` records the exact excluded fields, all 60
  missing parent rows, the absent production selector and every unimplemented
  typed chronology transition.
- `privacy_registered_measurement_capture_bridge.cpp`,
  `registered_capture_session.cpp`, `registered_projection_route.cpp`,
  `registered_driver_bridge.cpp`, `registered_trial_attempt_history.cpp` and
  `privacy_measurement_parent_manifest.cpp` establish the chronology above.
- `fresh_owner_trial_issuance.hpp/.cpp` currently carries run, trial, attempt
  and cohort only after joining owner contracts, whose metadata includes
  proving- and verifying-key identities. `registered_proposal_bridge.cpp`
  consumes that later lineage. Neither path is the missing pre-setup selector.

The current Rust FullW1 verifier pins historical Output and aggregate VK
hashes. Those keys remain feasibility-only. A fresh randomized setup will
produce different key identities, so it cannot feed that verifier until a
source-owned bridge consumes `W1PostSetupReceiptAuthority`, binds the newly
measured key bytes and relation identity, and replaces the hardcoded VK check
without weakening the existing relation/source/matrix pins.

Focused controller controls cover malformed, missing, reused and cross-field
aliased pre-setup identities, including insertion of an actual post-setup test
PK hash into each individual lifecycle slot, plus the existing
worker/process/output hostile cases. These are
source and OS-boundary tests, not proof of cryptographic correctness, privacy,
setup honesty or erasure.

## Reconsideration

Revisit only after a source-owned pre-setup selector exists; each admitted
field has a documented creation point before CRS generation; the selected
parent artifacts explicitly exclude setup/run outputs; and a separate
post-setup join binds the exact generated keys to every later capture and
measurement authority. A fresh full setup remains unsafe before those gates
and the resource guard are independently green.
