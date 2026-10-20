# ADR-0028: Begin lifecycle integration with public funding replay

**Status:** Accepted — bounded local implementation scope, not protocol adoption.

**Date:** 2026-10-20

**Related RFC:** [RFC-0013](../rfc/0013-coherent-v6-lifecycle.md)

## Context and decision

The owner directed starting milestone 2 after closing and pushing milestone 1.
The v6 relation admits ordinary independently signed native funding, but its live
adapter pins the four experiment sources in its descriptor. This makes later
participation depend on researcher preparation.

Start with an additive offline public replay component whose pool descriptor
contains no participant roster. Resolve funding from actual public parent bodies,
retain native validation and track consumed outpoints. Reuse retained genuine v6
transactions for a bounded positive/negative integration test.

This changes public transport metadata and client integration only. Existing pool
instances, circuit/covenant bytes, VK/setup, legacy descriptors/saved exits and
historical evidence remain unchanged. No new proof or native broadcast is needed
for the first slice.

## Alternatives and rationale

Another fixture-specific participant would not remove the dependency. Starting
with a complete wallet would combine receipt, backup, proof and transport changes
before the backing evidence boundary is clear. Importing upstream recovery code
wholesale would mix proof/state namespaces. Public replay is the smallest useful
shared component for admission, scanning and recovery.

The accepted small-payment cost target still challenges this direct design.
This slice is useful integration/evidence infrastructure, not a decision to expand
the direct architecture indefinitely or defer batching research until wallet polish.

## Security and privacy implications

The public proof statement's claimed deposit value is not backing evidence.
Canonical parent identities, output indices, native value/script and supported
metadata must be checked before constructing UTXO context. Native script and
funding-signature validation remain mandatory. Track funding single-use, including
the founding input, independently of a roster.

Authenticated chain acceptance/currentness is still supplied outside this offline
component. Parent bytes alone do not prove acceptance or present spendability.
Missing parents fail closed; supported parent formats and retained-history
requirements are explicit. No private witness, key or new trust authority is added.
Additional admissible funding sources do not establish anonymity.

## Evidence and revisit conditions

[RFC-0013](../rfc/0013-coherent-v6-lifecycle.md) defines the interface/invariant map
and controls. The [source review](../../research/shielded-kas-lifecycle-integration-2026-10-20.md)
records upstream/local reuse and remaining gaps.

Revisit if actual-funding checks cannot be preserved, bootstrap assumptions change,
the public format requires private controller data, or the implementation starts
depending on another relation/runtime. A new depositor's proof and live acceptance,
general wallet recovery and broader parent/pruning coverage remain later work.
