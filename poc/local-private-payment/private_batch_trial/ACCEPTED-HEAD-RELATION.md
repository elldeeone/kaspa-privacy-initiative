# GEN3-to-head relation seam

`accepted_head_relation.replay_relation` supplies plain public tree data to the
ADR-0079 fresh accepted-head producer. It has no filesystem, wallet, Original,
network, submission, registration or financial-capability API. It does not
change `wallet_history.load_supplied` or its `UNFUNDED_SUPPLIED_CONTEXT` boundary.

```python
head_data = replay_relation(
    genesis_case, selected_genesis_parameters, trial_uuid,
    independently_quoted_genesis_fee_sompi,
    [{"kind": "payment", "case": whole_case}, ...],
    verify_case,
)
```

`selected_genesis_parameters` is the existing
`genesis.Selection.from_component(component_bytes, component_sha, tail, verifier)`.
Inside the admitted public namespace, construct
`NamespaceGenesisVerifier(profile, binary, binary_sha, output_manifest,
output_manifest_sha, read_public=admitted_stable_read)`. It verifies the actual
three Output proofs and independently derives `Commit(2_000_000_000, 0)` through
the established native value-commitment operation. Neither operation mounts a
proving key or reads an Original.

The seam calls the existing strict `genesis.validate_case(..., signed=True)`:
new1648-byte GEN3 payload and exact selected identity; three distinct genuine
Output notes with that known-value CV; three distinct ordinary P2PK funding
sources and ALL signature frames; exact60-KAS reserve and state policy; own
ordered change only; exact integer contributions and deterministic fee shares;
and the independently supplied exact native fee quote. Actual ordinary signature
execution and SDK/accepted-chain verification remain the producer's obligation.

For each following whole CASE it derives the canonical native projection,
checks the actual fixed128-byte witness proof and exact old-state/policy redeem,
replays payment Output/NF/CM or Exit NF updates, checks integer reserve effects,
and derives the successor at output0 from that CASE's transaction ID. It retains
physical CM/NF insertion order. The finite projection framing adapts
`rehearsal_gate.case_projection` without importing its operational funding
drivers. Transaction IDs are frozen before external callbacks; callback mutation
of the serialized CASE refuses.

The required trusted-code callback has this contract:

```python
verify_case(kind, whole_case, projection_or_none, actual_native_proof_or_none)
```

It returns exactly `True` only after actual selected checks succeed. GEN3 passes
`None, None`; payment passes its projection and actual R0 witness; Exit passes
its projection and actual AuthExit witness. The producer must directly run the
pinned SDK, Native Full/all input engines, aggregate/six Output/R0 checks for
payments, and actual AuthExit verification for exits. A loaded JSON verdict or
acceptance Boolean cannot substitute for that source-pinned callback. The seam
does not independently implement these verifier runtimes.

The exact exporter-compatible result is:

```json
{
  "context_hex": "276 canonical bytes as lowercase hex",
  "commitments_hex32": ["one lowercase hex32 CM per physical position"],
  "nullifiers": [
    {"value_hex32": "hex32", "successor_hex32": "hex32", "successor_index": 0}
  ]
}
```

Nullifiers include the zero sentinel at position0, followed by physical
insertion order. Successor links use the established numeric little-endian NF
ordering, not lexicographic bytes. A zero-reserve terminal payout has no live
financial head and cannot export a fake Context/outpoint.

The returned JSON has **no acceptance authority**. Only the independently
selected direct producer may join it to fresh complete SDK/chain acquisition,
the exact GEN3 origin and ordered accepted CASE prefix, current UTXO/reorg/race
checks and the registered service's one-use sealing path. Omitting a final
transition can produce an earlier structurally valid head; the producer must
reject it against its fresh current UTXO observation. An imported copy of this
JSON cannot mint `AcceptedFinancialHead`.

Nine public model controls pass. They cover strict GEN3 liabilities/funding,
complete ordered tree/context export, mandatory non-Boolean verifier callbacks,
CASE mutation and detached-alias substitution, stale/reordered/cross-lane
transitions, exact witness/proof/policy/effects, integer aliases and terminal
refusal. Independent source review found the detached-alias issue before source
freeze; the immutable-ID fix and regression control are retained. These controls
use dummy financial proofs and model callbacks. They establish no real native,
chain, funding, lifecycle readiness or privacy result.
