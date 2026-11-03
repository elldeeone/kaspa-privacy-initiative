# ADR-0041: New-format private/native integration experiment

**Status:** Accepted for bounded offline implementation and measurement only.
**Date:** 2026-10-23 UTC.

## Context

The candidate-C public reveal checker passes its frozen native controls, but the
private predicate is a host reference. Recipient-owned delivery, a genuine proof,
the actual union script and complete lifecycle costs remain missing. The owner
requested execution of all five integration workstreams on available local
resources. [RFC-0020](../rfc/0020-private-proof-and-native-exit-integration.md)
states the scope, evidence gates and open decisions.

## Decision

Implement separate new-format recipient, pure Arkworks0.6 private-proof and native
union packages. Reuse established SHA256/HMAC, sealed-box encryption, secp256k1
Schnorr, tagged Merkle/indexed-NF structures and Groth16. Independently review the
canonical note/state/authorization contract before freezing setup/proof inputs.
Do not import old owner/replay/DRAIN workflows, restore their PK or alter old
notes, covenants, parameter identities or frozen evidence.

Use receiver-issued one-time invoices with explicit interaction, descriptor
reuse and delivery-key disclosure limitations. A recipient's old backup must
derive its ownership/nullifier/native signing material; sender output proofs
must not require those secrets. Duplicate delivery cannot revoke earlier owned
claims or remove their backing. Both spend paths consume the same original NF.

Measure fixed two-input/two-output constraints and actual combined native bytes.
Select fresh development parameters only after review of exact source and actual
resource measurements. Use CPU parallelism; installed Arkworks has no built-in
CUDA backend. GPU use requires an applicable existing backend and cannot stand
in for the adopted CPU-only wallet qualification.

Investigate complete fee allocation and native public admission in parallel.
These remain research candidates until separately specified and reviewed. A
single-proof integration success does not override the known one-payment fee
floor, all-tail accounting or existing privacy failure.

## Consequences and limits

New development setup integrity is an explicit trust assumption; hashes do not
prove trapdoor erasure. Synthetic supplied state and an authenticated-record
oracle do not prove accepted chain lineage, complete backing or independent
chain recovery. Actual cryptographic proof/native validation is stronger than a
host predicate, but neither is a security or privacy audit. No production format,
migration, mainnet deployment, real funds, admin exit or requirement relaxation
is selected. Testnet readiness requires the complete confirmed-payout rehearsal.
