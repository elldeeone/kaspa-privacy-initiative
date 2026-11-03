# Successor financial round selection

`successor_round_selection.py` closes the public selection seam between a
completed first financial round and a distinct successor-head round. It does
not launch a party, contact a node, read owner input, execute MPC, or create an
accepted-head capability.

The compiler accepts only a canonical selection that binds:

- a verified aggregate-plus-six-Output handoff;
- a genuine R0/native successor receipt and its exact outpoint, state,
  reserve, and reserve script;
- a fresh registered trial and three pinned server certificates;
- a configured, linked registered driver build;
- the dynamic registered-service, accepted-head, selection, construction,
  and journal source closure;
- fresh trial, run, attempt, cohort, accepted-head, and owner-contract
  identities.

Its result is always `SOURCE_SELECTION_READY_EXECUTION_NOT_RUN` with
`launch_authorized: false`. A JSON receipt is never accepted-head authority.
The selected C++ driver must directly acquire the current head and re-acquire
the identical one-use capability immediately before durable lock.

After execution, `validate_completed_pair` rejects reuse of the prior run ID,
projection, or accepted-head identity. This check is pair-binding evidence,
not proof or privacy evidence.

## Why Source05 cannot supply Round 2

Source05 pins its old point, state, reserve, reserve script, public context,
genesis-head path/hash, owner-input paths, and qualification source at build or
runtime-source level. It has no safe public parameter seam. Re-running it would
reuse the same fixed-head profile rather than consume the first round's
successor.

The intended reusable implementation is already in the registered path:

- `AcceptedFinancialHead::acquire_fresh` creates non-serializable authority;
- `RegisteredFinancialSelection::admit` consumes it with the selected public
  compiler;
- `RegisteredFinancialSelection::attempt_binding` supplies dynamic old point,
  state, reserve, and script values;
- `consume_for_lock` re-acquires the same head before the durable lock.

## Remaining execution prerequisites

1. Round 1 must finish its public cryptographic handoff and genuine R0/native
   successor validation. The current public qualifier intentionally reports
   those native fields as false.
2. A root-selected configured registered-service header and full configured
   build must bind the accepted-head acquisition/exporter programs, node SDK,
   native parameters/tail, model/query transport, trial-03 roster, and stores.
3. Round 2 needs fresh owner inputs/contracts and fresh run, attempt, and cohort
   identities.
4. Each party must directly acquire and agree on the successor head, then
   refresh it before lock. A saved head JSON or this selection receipt cannot
   replace that check.
5. The completed pair still requires the frozen observer measurement. Passing
   this selection does not establish privacy, native settlement, or lifecycle
   readiness.

Controls:

```bash
python3 -B -m unittest -v controls/test_successor_round_selection.py
```

The seven controls cover wrong successor linkage, fixed-genesis fallback,
stale/serialized head authority, identity reuse, mutable/hardlinked/drifted
source, unconfigured or Source05 builds, and duplicate completed run,
projection, or head identities.
