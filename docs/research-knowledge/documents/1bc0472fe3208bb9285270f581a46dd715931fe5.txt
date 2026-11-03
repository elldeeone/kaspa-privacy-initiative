# Actual four-view capture and bundle bridge

Status: frozen source-only bridge; actual private execution is deliberately
`UNQUALIFIED`. Synthetic fixtures are rejection controls, not evidence.

## Pre-truth selection

Root must create one canonical 0400
`kpb-privacy-comparison-selection/v2` before either run has private input. It
names exactly two canonical 0400 `kpb-privacy-actual-run-selection/v2` records in
this order:

1. `ACTUAL_TRANSPARENT_BASELINE`
2. `ACTUAL_HIDDEN_MAPPING_CANDIDATE`

Both runs pin the same method, measurement freeze, workload, exact transitive
source closures, runtime identity, observer/capture/bundle/owner-comparison
sources, coverage policy, capture-producer authority and financial release
contract. They use different trial IDs, attempts, diagnostic selections,
capture identities, financial runs/projections and fixed public roots.
Classification cannot be supplied later.

The fixed public root is:

```text
/var/tmp/kpi-private-batch-bootstrap-20261028/TRIAL-LABEL/privacy-diagnostics
```

## Required receipt chain

For each run, the isolated capture/observer/scorer path must create:

```text
capture-producer/PUBLIC.json
capture/PUBLIC.json
capture/CONSTRUCTION.json
capture/LAUNCH.json
observe/PUBLIC.json
observe/BARRIER.json
observe/LAUNCH.json
score-owner-0/PUBLIC.json + LAUNCH.json
score-owner-1/PUBLIC.json + LAUNCH.json
score-owner-2/PUBLIC.json + LAUNCH.json
aggregate/PUBLIC.json + LAUNCH.json
<comparison-sha>/owner-comparison/PUBLIC.json + LAUNCH.json
```

The schemas are respectively:

- `kpb-capture-producer-receipt/v1` (future actual authority; absent today)
- `kpb-privacy-actual-capture-receipt/v2`
- `kpb-financial-construction-classification/v1`
- `kpb-actual-capture-launch/v2`
- `kpb-direct-observation-receipt/v2`
- `kpb-direct-prediction-barrier/v2`
- `kpb-private-score-completed/v2`
- `kpb-public-all-view-direct-counts/v2`
- `kpb-privacy-owner-nonregression/v1`

The producer receipt must bind the exact selected source/build/role-launch
closure, both financial rounds, all ten append-only streams, their counts and
closed roots. The capture receipt binds that producer receipt, a salted private
manifest seal, exact per-round category counts and closed capture roots.
Observation binds that receipt and
the same manifest, freezes four distinct capsules, derives the exact union and
commits the complete two-round/terminal candidate sets. The barrier binds all
of those values before truth. Score receipts bind the barrier; aggregate binds
the capture and barrier and emits only count/commitment/boolean results.
The closed owner-comparison role authenticates both fresh runs and all eight
capsules, reads only the six private score bundles, and exports no owner count.
It must report non-regression for both honest owners and at least one strict
honest-owner gain across input/output/joint/full-workload truth masks. The
graph predicate is not an all-output relabel: colluder-known edges stay
fixed while the two honest NFs exchange input labels and each maps to a
different created pair in one common terminal-consistent alternative.

## Public production commands

After the complete actual chain exists, produce both bundles without passing a
classification or provenance value:

```bash
python3 -B privacy_capture_bundle.py \
  --comparison /ABSOLUTE/COMPARISON.json \
  --comparison-sha256 FROZEN_SHA256 \
  --run-index 0 \
  --output /ABSOLUTE/BASELINE-BUNDLE.json

python3 -B privacy_capture_bundle.py \
  --comparison /ABSOLUTE/COMPARISON.json \
  --comparison-sha256 FROZEN_SHA256 \
  --run-index 1 \
  --output /ABSOLUTE/CANDIDATE-BUNDLE.json

python3 -B privacy_acceptance.py \
  --baseline /ABSOLUTE/BASELINE-BUNDLE.json \
  --candidate /ABSOLUTE/CANDIDATE-BUNDLE.json \
  --output /ABSOLUTE/PRIVACY-ACCEPTANCE.json
```

All inputs and outputs are owned, regular, single-link canonical JSON0400
leaves. Outputs use create-new semantics. The v2 acceptance result binds the
exact bundle hashes, comparison/run/diagnostic selections and both trial IDs so
a lifecycle gate cannot reuse a PASS from another trial.

## Future actual closure manifest

The nine `kpb-transitive-source-closure/v1` role maps are Python-worker drift
controls only. They are not an actual producer/build/runtime closure.

Future activation requires an outer-supervisor-selected
`kpb-selected-multilanguage-source-build-runtime-closure/v1` manifest. It
lists, hashes, and byte-counts every Python, C/C++, JavaScript, asset, build
product, build receipt, interpreter, namespace tool, loader, shared library,
root guard, and kernel identity. Its finite dependency graph includes static
imports/includes plus explicit asset reads, subprocesses, compile/link edges,
and runtime dependencies. `privacy_source_closure.validate_actual_closure`
re-reads every member from three supervisor-supplied roots, independently
rediscovers local Python/C/C++/JavaScript dependencies, verifies graph
transitivity, recomputes source/build/runtime/whole-closure identities, and
requires the independently selected manifest digest.

The parent must also consume one
`kpb-selected-capture-role-closure/v2`. Its ten fixed-FD rows reference
manifest member IDs—not caller-supplied source/build/launch hashes—for the
two-round financial-release, terminal-controller, private-dispatcher,
server-P1, and owner-C1 call sites. It also binds five distinct authority
build entrypoints—outer supervisor, capture producer, actual-capture worker,
diagnostic launcher, and owner-comparison launcher—to five distinct selected
source members through direct `compiled-from`/`generated-from` edges. The role
identity is recomputed from those exact members and the full-manifest digest.

These formats are necessary but not sufficient execution authority. Current
source does not make launch consume the same parent-sealed file descriptors,
instrument dynamic imports/asset reads/exec/dlopen, prove a structured build
recipe/flags/output relation, resolve the selected ELF/interpreter runtime
graph, or attest the running kernel. `actual_closure_source_status()` records
all six as false. Activation requires the parent-owned sealed snapshot and
those runtime/build checks; a canonical manifest alone remains forgeable
evidence, not a capability.

No such selected manifest or build receipt exists today;
`require_selected_actual_closure()` hard-refuses. A canonical manifest is
evidence, not authority: the future outer supervisor must supply its selection
and one-shot completion capability.

## Current blockers

No actual bundle is currently producible:

- `privacy_capture_producer.py` is pinned source-only and emits
  `kpb-capture-producer-source-only/v1`; its role-hook, inherited-FD, launcher,
  launch-authorized and actual-receipt flags are all false;
- the bridge requires a future selected `kpb-capture-producer-receipt/v1` and
  refuses before run intake while that authority is absent;
- legacy observation/barrier/score/aggregate receipts are v1 and rejected;
- there is no actual transparent full-financial control or actual hidden-mapping
  aggregate under the common comparison selection;
- the complete fixed-root private capture manifest/receipt has not run;
- public projection, dispatcher, corrupt-server-plus-wallet and terminal
  adapters must cover every frozen category without broad or opaque modeling;
- full-workload truth/alternate-graph masks and the private owner-comparison
  still require selected one-shot launch authority; they may not be asserted
  by the host;
- batch-terminal privacy does not measure nine-exit/service-loss linkability.
  Step 3 requires its separate exit-privacy receipt.

Until these exist, status is `UNQUALIFIED`; do not fund or advance to Testnet.
