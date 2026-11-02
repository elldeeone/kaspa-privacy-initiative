# Proposed private note merge

**Status:** Proposed research architecture; not approved or implemented  
**Scope:** optional wallet operation for the private-note PoC  
**Decision driver:** reduce note-level public disclosure when an owner fully
withdraws several independently received notes

## Minimal operation

Add a private `MERGE` operation with:

- exactly two positive input notes owned by the same spending authority;
- one Merkle membership path per input against the same accepted anchor;
- exactly two distinct economic nullifiers, both atomically checked and marked;
- one positive private output note back to the owner; and
- exact integer conservation: `input_1 + input_2 = output`, with checked `u64`
  range semantics and no public fee in the first experiment.

Keep payment transfers unchanged. Do not add batching, aggregation services,
delays, cover traffic, MPC, coordinator custody or privileged recovery.

## Why this is the smallest candidate

The current transfer already demonstrates the bounded possibility result. The
missing capability is narrower: an owner cannot consolidate two independently
received notes before withdrawing. A two-input/one-output operation directly
removes that terminal note split without changing recipients or payment policy.

The model projection preserves both candidate gross histories while changing
M's exits from `30,000,000 + 20,000,000` to `50,000,000` sompi. This is an
information-shape improvement, not a general privacy guarantee.

## Security requirements before implementation

1. Bind both memberships to the intended domain, verifier, operation kind and
   one accepted state root; reject stale/wrong-root and cross-domain witnesses.
2. Derive two input-specific nullifiers and require them to be nonzero, distinct
   from each other and absent from ledger state before an atomic state update.
3. Prove authorization for both notes. Do not infer common ownership merely from
   wallet possession or ciphertext decryption.
4. Prove exact value conservation with explicit range/overflow behavior. Reject
   zero-value inputs/outputs and malformed inactive fields.
5. Bind the output commitment and delivery ciphertext to the public statement;
   test replay, output substitution and cross-state/cross-lane reuse.
6. Define reorg and concurrent-spend behavior. A dependency failure may halt the
   merge but must not accept unverifiable state or release reserve KAS.
7. Measure metadata leakage from the distinctive two-nullifier operation. A
   merge can itself signal that one owner controlled two prior notes.

## Required design work

Before code, update the protocol RFC/ADR, architecture, threat model and security
invariants as needed. Compare the operation with current Orchard multi-note spend
semantics and current Kaspa/Toccata/based-application state. Then write negative
tests for duplicate inputs, partial nullifier insertion, wrong roots, replay,
overflow, unauthorized mixed-owner inputs and malformed statements.

## Non-goals and stop condition

This proposal does not claim that merge is consensus-required, sufficient for
ordinary-user privacy, or safe. Do not implement it until the architecture
review decides where multi-nullifier atomicity and state anchoring live. The
sparse one-transfer/full-drainage control remains uniquely recoverable even if a
merge operation exists.
