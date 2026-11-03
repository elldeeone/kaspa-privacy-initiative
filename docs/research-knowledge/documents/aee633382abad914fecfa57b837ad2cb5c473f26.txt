# ADR-0018: depth-four local continued-private-spend profile

Status: Accepted for one unfunded local privacy experiment, 2026-11-01. This is
not a production tree-capacity decision, migration, TN10 release or cryptographic
security claim. ADR-0011 and all security invariants remain unchanged.

## Problem

The retained private-note circuit has a depth-two append-only tree. Two credits
plus one two-output transfer consume all four leaves, so the recipient cannot
execute a second private transfer. No compatible larger-capacity wallet-local
path exists in the repository. The continued-private-spending study cannot be
answered honestly with modeled operations or by relabelling independent ledgers.

## Decision

Add an opt-in `privacy-experiment-depth-4` Cargo feature to the existing
`kpi-private-note-wallet` crate. It changes only:

- Merkle depth from two to four (capacity 16); and
- the economic domain to
  `SHA256("KPI/LOCAL-NO-FUNDING/native-KAS/private-note-experiment-depth4-v1")`.

The profile uses a fresh experimental Groth16 setup and verifier identity. It is
incompatible at compile time with `tn10-rehearsal`. Default builds retain depth
two and their original local domain, parameters, source behavior and evidence.

Note commitment, ownership, nullifier derivation, encryption, u64 conservation,
one-input/two-output transfer shape, anchor checks, current-nullifier spentness,
deposit authorization and whole-note exit semantics are unchanged. Wallet
witnesses remain local and the processing boundary remains public-only.

## Alternatives rejected

- **Model a larger pool:** cannot establish executable recipient re-spending,
  recovery, replay rejection or exit authority.
- **Use several independent depth-two ledgers as one pool:** invents cross-ledger
  privacy and state semantics that the code does not provide.
- **Copy the wallet/circuit into a research-only implementation:** creates a
  second subsystem and risks semantic drift.
- **Resume MPC or an outer prover rewrite:** does not solve tree capacity and is
  outside the bounded wallet-local question.
- **Select production depth/cryptography now:** unsupported by this small local
  experiment and current review evidence.

## Security and privacy implications

Depth changes membership paths and the verifier, so cross-profile proofs/state
must fail through the distinct domain and fresh VK. Increasing capacity does not
itself create an anonymity guarantee. Timing, contact knowledge, public entries,
eventual exits and sparse activity remain observer surfaces. Fresh setup toxic
waste remains an experimental trust boundary. Passing proofs demonstrate only
the executed relation, not cryptographic correctness or production safety.

The experiment must test wrong-domain/root rejection, replay/double-spend
rejection, exact conservation, backup-based recipient/change recovery and an
independently authorized exit for every remaining note. Owner-local keys and
truth remain outside public artifacts and Git.

## Evidence and reconsideration

The frozen workload and observer model are in
`research/wallet-local-private-spend-2026-11-01/SELECTION.md`. Reconsider this
profile if it changes any semantic rule beyond depth/domain, default-profile
regressions fail, cross-profile operations are accepted, or the finite workload
cannot reach zero final liability through owner-authorized exits.

This ADR does not update the repository threat model because it adds no deployed
actor, authority or network surface. The experiment report must retain the
same-host, offline-fixture and assumed-cryptography limitations.
