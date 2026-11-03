# ADR-0094: Source-owned selected-parent artifact table

Date: 2026-10-29 UTC.

Status: Accepted source architecture, `CONFIGURED0`. The production table has
zero admitted entries and the machine report lists all 60 entries as missing.
The diagnostic launcher is non-authorizing and does not qualify privacy,
production readiness or Testnet activation.

## Problem

`ParentManifestRecomputationAuthority` is intended to prove that the same exact
finite artifacts were selected, executed and recomputed by the parent. A
public selector that accepts arbitrary sealed descriptors cannot prove that:
an arbitrary caller can author 60 blobs, hash them, and obtain a manifest that
is self-consistent but unrelated to any selected program. Hashing
`/proc/self/exe` of the selector proves the selector image, not the child image
that consumed the artifacts.

The repository also does not yet contain final selected images and complete
runtime closures for all ten manifest components. Diagnostic hashes, test
workers, partial static builds, capture-plan receipts and source-only ABI
schemas cannot fill those gaps.

## Decision

1. The production input is one immutable ordered table with exactly ten
   components matching `ManifestComponent` and six artifact fields per
   component: canonical source archive, reproducible build receipt, transitive
   runtime closure, canonical assets archive, final pinned executable and
   source-owned launch plan.
2. Every one of the 60 rows must bind an absolute normalized path beneath one
   selected snapshot root, exact SHA-256, an allowlisted component-owned build
   contract and that contract's exact SHA-256. The pinned-executable row must
   be the finalized selected child image; another ABI, executable receipt or
   runtime digest cannot substitute.
3. A partial table never generates a C++ production table. Selection,
   callsite and configured flags remain false while any row is missing. After
   the table is complete, an independent review is still required before any
   flag changes.
4. The source-owned launcher has no production path, descriptor or digest-list
   overload. Its future compiled table is internal. It opens each fixed path
   with `openat2` and no-symlink/no-magic-link resolution, verifies the pinned
   hash before and after copying, and retains one unique sealed read-only
   object per row.
5. The launcher executes the selected child from the retained pinned
   executable descriptor with `execveat`. The child independently reads,
   hashes and `fstat`s all 60 inherited sealed descriptors and returns one
   fixed authenticated packet. The parent requires exact credentials, packet,
   kernel EOF and zero `waitpid` exit, then recomputes the manifest from
   descriptors referring to those same sealed inodes. The selected child
   image, session, PID and clean-exit identity enter the recomputation; the
   selector's `/proc/self/exe` does not.
6. The committed diagnostic table mechanism is deliberately macro-gated. Its
   compiled fixture proves descriptor and race behavior only. It is not a
   source of production rows.

## Current all-missing gate

`privacy_measurement_selected_parent_artifact_contract.json` defines the exact
cross-product and component owners. The deterministic
`privacy_measurement_selected_parent_artifact_missing.json` report binds that
contract and records `missing_count=60`.

- FinancialCore, P1Capture, C1Supervisor, TerminalCapture, Dispatcher and
  Producer have no source-owned selected output for any of the six fields.
- Observer v3 now has a read-only six-artifact reproducibility candidate at
  `artifacts/observer-selected-v3-20261029-r2`, bound by candidate manifest
  `fe54e03b71a2cc7b0112bb2aefcd358f38e86ab9a9590e78b5e5295ecfd488e4`.
  It includes two-build-equal source/build/runtime/assets/ELF/launch-plan
  artifacts and a static ELF with no `PT_INTERP` or `DT_NEEDED`. It is still
  not an admitted production pin: ABI v3 is intentionally open-only and
  nonauthorizing, so the final Observer row must be rebuilt under the future
  feasibility-aware v4 semantics after independent review.
- OwnerScore has a fixed output ABI, not a source-closed worker build, so all
  six fields remain missing.
- Aggregate and OwnerComparison also have no selected complete build/runtime
  closure or final executable.

No row may be inferred from a diagnostic fixture, public receipt, partial
build, caller path or digest.

## Rejected alternatives

- **Public arbitrary-FD selection.** It lets a caller create a self-authored
  internally consistent manifest without selected execution.
- **Use the selector's executable hash.** It does not bind the launched child.
- **Fill rows from source or ABI hashes.** Source identity, output schema,
  runtime closure, final executable and launch plan are distinct artifacts.
- **Enable after the first complete component.** The authority binds the exact
  ten-component cross-product; a partial manifest can authorize no capture.
- **Trust paths after open.** Path replacement is harmless only because the
  opened inode and expected content digest are pinned and the child consumes
  the sealed derivative. A later open of the replacement must refuse.

## Evidence and limitations

The diagnostic control covers no-symlink opening, exact expected hashes,
unique sealed read-only objects, retained-FD `execveat`, child-side independent
hash/stat of all 60 descriptors, kernel credentials, exact EOF, clean exit,
same-inode recomputation, path replacement after open, abnormal child exit,
and absence of production caller path/FD methods. The existing exact
self-authored-60-blob production compile control remains negative.

These controls establish source and Linux descriptor mechanics only. The
fixture is dynamically linked, does not represent the final ten programs, and
does not establish cryptographic correctness, anonymity, selected execution,
Testnet readiness or production safety.

## Reconsideration

Revisit `CONFIGURED0` only after every owner emits a reviewed final artifact
set, all 60 rows pass content and build-origin validation, every selected child
consumes the compiled table descriptors, and an independent adversarial review
confirms that no receipt-, path-, digest- or fixture-only construction route
remains.
