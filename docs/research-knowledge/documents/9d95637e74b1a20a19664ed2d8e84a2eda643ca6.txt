The constructor creates a private, unfunded TN10 identity. The separate finite
orchestrator builds matching domain-specific source, performs a fresh setup,
retains the PK for the actual authorization, and rehearses six native bodies.
No command in this orchestrator broadcasts.

1. Run `trial.py new --network testnet-10 PRIVATE_DIRECTORY`.
2. Import an explicitly supplied observed source with `orchestrate.py source`.
   Its P2PK key is separate from the new profile and stays outside Git.
3. Run `orchestrate.py rehearse PRIVATE_DIRECTORY --source SOURCE_JSON`.
   This automatically builds, sets up, prices, proves and validates the complete
   terminal path. Every output is private; the resident prover stops before exits.
4. The separate reviewed chain adapter/driver may submit the unchanged six bodies
   only after its testnet release. It must confirm each accepted full body and
   both payouts. `LOCAL-COMPLETE.json` alone makes no chain-acceptance claim.

The current scarce-source liveness pilot uses two 100,000,000-sompi notes. It is
separate from the sealed offline two-10-KAS experiment and fails fee qualification
at this scale. Note minimums, ownership, value conservation, nullifier ordering,
current-root checks and terminal zero remain unchanged.

`local-archive.json` contains the ordered exact bodies, local-check receipts and
public snapshots. `public/recovery-identity.json` adds the selected crypto bridge
hash without changing the original constructor identity used by the release.
Each exit process receives only its own seed backup and public current records;
the other recipient, payer profile, PK and prover are absent from its filesystem.
Validating-node and complete-public-archive trust remain explicit for live checks.
