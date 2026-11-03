# Durable private-attempt history

ADR0077 keeps one unresolved attempt per pool/service epoch and retains every
released NF, including orphaned transactions. ADR0078 supplies public processing
after the private MPC process exits. This is research implementation; genuine
registered-service and accepted-chain execution remain unqualified.

The boundaries are:

| Source | Authority |
| --- | --- |
| `epoch_journal` | Local journal/anchor durability and replay; its public receipts alone authorize no private intake, proof or settlement. |
| `epoch_ticket` | Authenticated all-three LOCK/PREPARED/EGRESS barriers, immutable construction bindings and one-use proof/release capabilities. |
| `settlement_capability` | Separate private `VerifiedFinalCandidate` and `VerifiedSettlement` types, minted only by direct selected verification. |
| `final_candidate/` | Offline exact CASE, seven component proofs, selected R0 receipt and NativeFull verification; can support FINAL only. |
| `settlement/` | Fresh selected SDK accepted-prefix/current-UTXO acquisition and complete replay of the exact FINAL candidate. |

The financial validity bridge joins actual immutable NF256 wires against the
permanent public tombstones before any reactive proof opening. Unknown exposure,
abort, crash, Exit, changed head and reorg leave the attempt unresolved. Only
independent exact accepted settlement can return the history to Ready. SETTLED
retains every released NF and all prior events; the next lock commits the full
checkpoint and seen-set identity.

`VerifiedFinalCandidate::acquire_fresh` reopens fixed registered EGRESS, executes
the pinned offline verifier, checks its fresh request and all computed candidate
fields, and requires all-three agreement. Its one-use `bind` appends FINAL and
requires all-three durable acknowledgements. It restores no old private shares,
MAC context or process-local prepared ticket.

`VerifiedSettlement::acquire_fresh` separately verifies exact fresh chain
acceptance, CASE/witness, policy, projection and R0 identities. Its one-use
`resolve` rechecks the current checkpoint, appends SETTLED with journal/anchor
fsync, and requires all-three durable agreement. An offline result, imported
JSON, txid, timeout or accepted Boolean cannot construct either capability.
Different local observation nonces/evidence do not enter the common checkpoint;
all parties agree the same exact candidate and accepting-block identity.

Both factories default to refusal. Trusted builds must pin the interpreter,
correct distinct launcher/selection, registered history identity, each party's
fixed journal/anchor paths and mandatory private-root lists. Callers may add
exclusions but cannot remove the fixed roots. Public byte admissions precede
execution; a sealed, rewound source memfd preserves the fixed source filename,
and every inherited private/TLS/journal descriptor closes before exec.

The trusted fresh TLS driver must authenticate actual registered peer DER on
both transport directions and every fork before creating `MascotContext`.
Certificate labels in a request are insufficient. New live configuration pins
canonical X.509 DER identities and separate PEM file hashes, with distinct
subject public keys. Fresh preprocessing storage contains no old MAC/OT files;
only the selected public certificates and the role's own TLS key are exposed.
The driver/launcher is being qualified separately and has no initialization or
reset route. Missing stores/anchors halt; they never trigger initialization.

`qualification_bootstrap.py` creates only a distinct **UNREGISTERED** namespace
for the fixed nonexistent-head fixture. It cannot initialize a live service or
resolve its lock. Its intrinsic derived epoch prevents relabelling an old live
Ready journal. See `QUALIFICATION-BOOTSTRAP.md` for the narrow setup boundary.

Public component controls cover real write/crash boundaries, restart, races,
rollback/path aliases, NF ordering, persistent tombstones, sequential locks,
strict direct-result substitutions and inherited-FD closure. They do not prove
cryptographic correctness, chain acceptance, backing, financial privacy or
production safety. Live registration, accepted GEN3/history admission and the
complete R1 → R2 → independent-exit rehearsal remain required.
