# ADR-0093: Phase-scope pre-network private coverage

**Status:** Accepted fail-closed phase partition; immutable Observer-v3 open
inventory and linear sealed-output join implemented, authorization absent

**Date:** 2026-10-29

**Related ADRs:** [ADR-0084](0084-two-phase-testnet-trial-authorization.md),
[ADR-0091](0091-sealed-measurement-data-planes.md)

## Problem

The private public-projection blocker matrix has 21 family types per round.
Two of those types require accepted-chain state and outpoint history:

- `context.accepted_chain_outpoint_and_external_history_linkage`; and
- `state.accepted_chain_state_and_outpoint_continuity`.

Across the fixed R1/R2 workload these are four open occurrences. The private
completion gate previously required all open occurrences to be closed before
it could issue the prediction capability. That is circular: Step 2 must pass
before the first network action, while genuine accepted-chain history can only
exist in Step 3 after that action. Treating these rows as covered in Step 2
would be false, and requiring them in Step 2 makes the first trial impossible.

## Constraints

- Step 2 remains pre-network and may not consume caller-authored accepted-head,
  state, outpoint, transaction or history claims.
- The two Step-3 family types remain `unmodeled`, with
  `coverage_relabel_allowed=false`, under the exact existing evidence
  requirement
  `STEP3_ACCEPTED_CHAIN_STATE_AND_OUTPOINT_HISTORY_AUTHORITY`.
- Step 2 must still recompute the exact ten typed leaves, four fixed views,
  exhaustive lattice and every non-deferred coverage row.
- No count, Boolean, summary, digest, JSON object or parsed FD40 section is a
  phase authority.
- Importable Python constructor sentinels and mutable live-object registries
  are not capabilities. The selected FD40 Python path therefore cannot close
  the two structural-continuity rows; those remain Step-2 blockers until a
  native, non-importable one-shot authority enters the isolated child.
- The native deferred authority may be lost or replayed only at the cost of
  liveness; neither case may permit terminal completion.
- This change does not select an assumption, qualify privacy, enable a network
  adapter or change `CONFIGURED0`.

## Options considered

### Require accepted-chain history in Step 2

Rejected. The evidence cannot exist before Step 2 authorizes the network
phase, so this preserves the circularity identified in ADR-0084.

### Mark the four occurrences covered or remove them from the ledger

Rejected. Step 2 has no evidence for them. Renaming, deleting or setting their
coverage status would turn a phase distinction into a false privacy claim.

### Defer an exact row-bound residual

Accepted. The model continues to report the four occurrences as open. A
separate phase partition identifies whether every other Step-2 row is closed
and retains the exact four-row definition for a future native Step-3 join. A
Python object is not accepted as that future authority.

## Decision

1. The model's private internal phase partition recomputes the existing
   four-view summary. For each view it returns the exact still-open Step-2 rows
   and the exact deferred Step-3 rows. It returns no public authority or
   authorizing receipt.
2. `require_step2_private_coverage` recomputes that partition and validates the
   exact ten leaves and exhaustive lattice; no artifact is missing; every
   Step-2 row is closed; and all four views contain exactly the same four
   deferred R1/R2 public-projection rows named above. Even when all of those
   conditions hold, it fails with `phase-scope-native-authority-required`.
   It never returns an authority, residual, digest, summary or Boolean.
3. The original summary must remain `completion_ready=false`, every view must
   remain `all_candidate_edges_covered=false`, and every view must report four
   unmodeled rows. This is deliberate retained evidence that Step 3 is not
   covered.
4. The Python module defines no constructor sentinel, `_live` authority,
   mutable live registry, prediction consume function or deferred residual
   type. Importing exact old names, manufacturing an object with
   `object.__new__`, and inserting it into a caller-owned registry yields no
   consume path.
5. The native boundary consumes one authenticated, sealed Observer FD62 v3
   completion and one opaque native empirical-result residual. Its complete
   header-defined bridge burns both caller capabilities before validation;
   exact-matches their `RunBinding`; rechecks Observer role, ABI
   identity/version, size, seals, process completion, the exact 144-byte
   deferred Step-3 section and the full 256-byte Step-2 section; and retains
   the sole FD62 and both private evidence values in one move-only
   `ObservationOutputJoinAuthority`. It exposes no fd, body, hash, count,
   receipt or digest-based constructor.
6. Observer ABI v3 is explicitly nonauthorizing. Its exact per-view totals are
   `[42,56,108,122]`, all 26 family rows retain their open dispositions and its
   empirical mask is `0x03ff`. The join therefore mints no prediction, phase,
   Step-2, barrier, FD41 or Step-3 permit. Zero-count, invented `CLOSED`, mask,
   registry/model identity and v2-downgrade substitutions all refuse.
7. Any source-derived closure must use a later immutable ABI/model identity;
   v3 may not be reinterpreted. A later ADR must separately define the genuine
   accepted-chain producer and atomic post-network Step-3 join. Until those
   sources exist, capsule prediction authorization and Step-3 completion are
   impossible.

The selected callsite remains absent and launch remains disabled. The C++
`RunBinding` carries digest trial/attempt identities while the Python capsule
ABI requires the trial UUID and attempt ASCII preimages; this boundary does
not infer those preimages.

The selected-FD40 parser remains useful as non-authorizing evidence, but its
former nominal Python capability is forgeable by importing its constructor
sentinel and mutating its live registry. The model now burns any such object
and refuses with `selected-fd40-native-structural-authority-required`; a
forged structural context refuses identically. The phase module does not
import or consume that FD40 type. Consequently its genuine fixture remains
RED with the two structural rows, and other unresolved rows, explicitly
Step-2-open.

## Security and privacy consequences

- The phase design no longer requires future network evidence in Step 2. The
  native join is executable only with the sealed output and opaque empirical
  residual, but the v3 inventory is open and cannot authorize a barrier,
  prediction or privacy-pass authority.
- Accepted-chain continuity is not silently promoted into measured coverage.
- Extra open Step-2 rows, a missing/extra/relabelled deferred row, wrong round,
  wrong artifact kind, stale inputs, public substitutes and replay all refuse.
- Forged Python FD40 objects, structural contexts/models, raw v3 counts and
  serialized empirical summaries cannot authorize Step-2 prediction.
- The retained deferred evidence may prove only phase partitioning. It must
  not prove an
  accepted transaction, current head, native validity, backing, outpoint
  ownership, state continuity, anonymity or terminal privacy.
- The Python observer runtime remains inside the private measurement TCB.
  Source-level opacity is not protection against a malicious interpreter,
  debugger, kernel or host-memory reader.

## Evidence and current limit

- `poc/local-private-payment/private_batch_trial/privacy_phase_scope_authority.py`
- `poc/local-private-payment/private_batch_trial/test_privacy_phase_scope_authority.py`
- `poc/local-private-payment/private_batch_trial/privacy_capture_model.py`
- `poc/local-private-payment/private_batch_trial/privacy_native_phase_scope_bridge_contract.hpp`
- `poc/local-private-payment/private_batch_trial/privacy_native_phase_scope_authority.hpp`
- `poc/local-private-payment/private_batch_trial/privacy_native_phase_scope_authority.cpp`
- `poc/local-private-payment/private_batch_trial/privacy_native_phase_scope_authority_control.cpp`
- `poc/local-private-payment/private_batch_trial/test_privacy_native_phase_scope_authority.py`

The focused controls retain the old all-rows completion gate, exercise the
phase partition against genuine model fixtures, and reject public substitutes,
repeat/cross-input attempts, coverage relabelling,
missing/extra/wrong deferred rows, exact-name sentinel/registry/object-new
manufacture and the importable-sentinel/registry FD40 forgery. Native controls
exercise the sealed v3-plus-empirical join, replay, cross-binding and
wrong-role refusal, v2 downgrade, phase/Step2 mutation, forged zero/CLOSED
inventory, move-only opacity, hostile exact-name bridge redefinition and
receipt/body substitution. The selected runtime callsite and every
authorization consumer remain absent. This evidence establishes only
the bounded fail-closed source invariant. It is not a privacy result or a
Testnet/production readiness claim.

## Revisit if

- the user sequence permits accepted-chain observation before the private
  gate;
- a reviewed design can produce genuine accepted history without any network
  action; or
- the fixed projection ledger changes either accepted-chain family, in which
  case the exact-row controls and this decision must be updated together.
