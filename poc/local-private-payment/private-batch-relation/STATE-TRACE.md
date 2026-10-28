# Private state-witness construction

`src/state_trace.rs` constructs three indexed-nullifier witnesses, six CM append
paths, and the new roots without opening the new NF/CM values. It reuses the
exact tree tags, indexed-list semantics and little-endian ordering from
`poc/owner-private-lifecycle/wallet/trees.py` and the corresponding proved public
path consumer. SHA-256 uses the shared trace implementation, not a new primitive.

The caller supplies an authenticated accepted public history and its selected
`Context`. The module rebuilds the old roots and validates the complete indexed
NF list. This binds supplied leaves to those roots/counts; it does not establish
consensus, currentness or data availability by itself.

New inputs are `SecretBytes`: canonical byte order, eight little-endian bit LCs
per byte. The three final NF rows must be privately sorted; the six CM rows
must already have the selected private output order. No loop, host branch or
memory address depends on their values.

1. Compare every possible indexed-NF predecessor privately. Require exactly
   one valid interval, then select its value, successor, physical index and
   Merkle path with secret Boolean flags.
2. Update all possible predecessor records obliviously, construct the append
   witness at the public append index, and hash the successor tree. Repeat for
   all three inputs.
3. Maintain the CM frontier at public append indices. Construct each empty-slot
   path, check it against the current root and append the corresponding secret
   CM. Reject repeated/default CMs before disclosure.

All bitness, order, uniqueness, interval and path assertions must enter the
same authenticated pre-opening validity boundary as the aggregate relation.
The interpreter must not open individual assertions or raw residuals. Internal
tree/hash scratch registers are outside the SNARK assignment prefix and must
not become public output. The resulting LC bytes belong at these canonical
effect-core offsets:

| Field | Byte offsets |
| --- | --- |
| New CM root | 284 to 316 |
| New NF root | 316 to 348 |
| New CM/NF counts | 348 to 356 |
| Three NF witnesses | 3812 to 7292 |
| Six CM paths | 7292 to 10364 |

The constructor checks full little-endian 256-bit NF order, not a reduction into
the SNARK field. Counts obey the existing depth-17 NF/depth-16 CM capacities.
Its fixed scans grow with the public history; no scalability measurement is
claimed.

The five initial controls compared every resulting witness byte and root with
the retained independent Python constructor, including nontrivial physical NF
ordering, stale/malformed histories, replay, empty/reused resources and capacity
refusals. Those controls used public constants. The separate full variable-input
control uses the actual generated operations and two changed public synthetic
assignments; it requires the same complete operation-stream hash and independent
constructor agreement for both. That control passed on October 28: each graph
had 17,929,974 logical wires and 11,607,920 operations, with graph hash
`2bbf41f6f9376a77f8f0825d7d9f5a90cc25a571efd3a57ce9a1808ed8331b0c`.
The two parallel public fixtures completed in 24.98 seconds with a measured
1,491,779,584-byte scope memory peak. These are reference-execution measurements,
not authenticated MPC measurements. Local source/results are retained under
`.local/private-state-trace-dynamic-20261028-01`. Run it explicitly:

```sh
cargo test --release --locked --manifest-path poc/local-private-payment/private-batch-relation/Cargo.toml --lib state_trace
cargo test --release --locked --manifest-path poc/local-private-payment/private-batch-relation/Cargo.toml --lib full_variable_state_trace_matches_oracle_with_identical_ir_across_values -- --ignored --nocapture
```

The bounded-memory `new_public_fixture` mode is only a public differential oracle.
It is not an MPC input route, cannot emit a retained production trace body, and
must never receive a real owner witness. Actual authenticated state execution,
full-model column assignment and the release barrier remain integration work.
The mandatory R0 public verification, native effect binding, independent exits
and known abort/retry privacy failures remain unchanged.
