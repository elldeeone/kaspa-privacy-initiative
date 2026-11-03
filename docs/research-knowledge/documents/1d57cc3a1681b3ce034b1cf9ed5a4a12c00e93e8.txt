# Current wallet capability audit

**Source baseline:** repository commit
`7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`, plus the visible uncommitted
depth-four experiment already present in this checkout.

## What the current private operation supports

- The circuit witness contains exactly one input note, one Merkle path and two
  output notes (`poc/private-note-wallet/src/circuit.rs:14-19`).
- A wallet witness constructor accepts the same one input, one path and two
  outputs (`poc/private-note-wallet/src/wallet.rs:61-73`).
- A transfer publishes one nullifier and two output commitments
  (`poc/private-note-wallet/src/protocol.rs:126-140,196-203`).
- The circuit enforces conservation from the one input value to the two output
  values and any public exit/fee limbs (`poc/private-note-wallet/src/circuit.rs:201-205`).
- The ledger rejects a zero or previously seen transfer/exit nullifier, then
  inserts that single nullifier (`poc/private-note-wallet/src/ledger.rs:146-150`).

Therefore, an ordinary payment can consume one note and create a recipient note
plus sender change. Repeated receipts can leave one owner holding several
independent notes. The current operation cannot privately combine two of those
notes into one.

## Consequence at complete withdrawal

The candidate histories need no new operation: three ordinary one-input payments
produce the same fully drained public evidence under the declared opacity
assumptions. But owner M must withdraw its two notes separately, publicly exposing
the terminal note values `30,000,000` and `20,000,000` sompi.

A two-input private merge would change that terminal disclosure to one
`50,000,000`-sompi exit in this workload. It would reduce note-level withdrawal
granularity; it would not hide M's net withdrawn amount, make the two candidate
histories equally likely, or rescue the sparse failure control.

## Evidence boundary

This is static source inspection plus a public constraint model. No circuit,
prover, wallet, runtime, network or funded trial was changed or run. The model
assumes commitment/ciphertext/nullifier opacity; it does not prove those
cryptographic properties.
