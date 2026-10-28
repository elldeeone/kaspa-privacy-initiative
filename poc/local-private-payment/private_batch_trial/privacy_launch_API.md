# Trusted diagnostic launcher

`privacy_launch.py` adds the finite launcher seam to the previously frozen
privacy core. The eight qualified core/source-review files remain unchanged.
Implementation and tests use public model fixtures only. Actual private
payments, observation, truth scoring and final execution selection remain held.

```text
python3 -B privacy_launch.py observe|score|aggregate
  --selection PUBLIC_SELECTION --selection-sha256 SHA
  [--owner-component 0|1|2] [--execute]
```

Default validates public inputs and returns a plan without reading private
bodies or running a diagnostic. `--execute` launches the selected role in a
network-off namespace. `score` requires exactly one owner; the other operations
reject an owner option. There is no caller-supplied private root or output path.

## Public selection

Schema: `kpb-private-diagnostic-launch-selection/v1`. Exact fields:

- `binding`: unchanged method/run-selection/trial/phase/attempt binding.
- `run_selection`: `{path,sha256}`; SHA must equal `binding.selection_sha256`.
  The method digest must equal the actual frozen method in the repository.
- `bootstrap_trial`: `{path,sha256}` selecting the actual new-profile `TRIAL.json`.
  Domain, profile, trial, public route and private Original parent must agree.
- `source_members`: ordered `{name,sha256}` for `privacy_codec.py`,
  `privacy_observer.py`, `privacy_owner.py`, `privacy_roles.py`, `privacy_launch.py`.
  The first four must match their already qualified immutable source identities.
- `rounds`: exactly rounds1 and2, each with `round`, `invoice_result`, `pay_result`,
  `projection`, `dispatcher_artifacts`. Public selections are `{path,sha256}`.
- `corrupt_server_view`: null, or `{owner_component:1,root,relative_leaves}`.

The launcher validates actual typed invoice/pay controller results and the
owner public receipts they reference. It derives the three original truth and
public commitment routes from those owner records. It automatically includes
the actual route sidecars and public invoice/pay metadata in the dispatcher
view. The target, operation identities and exact private invoice leaf must agree
with the actual selected invoice operation and fixed round schedule.

`dispatcher_artifacts` entries are `{kind,path,sha256,route_owner}`. Additional
public `invoice-route` records use actual public hashes, retain failed attempts,
and must belong to this trial's invoice path. Private `dispatcher-metadata` or
`terminal-raw` captures require `sha256:null` and must be original leaves under:

```text
ORIGINAL_TRIAL/diagnostics/private-batch-privacy/dispatcher-capture/round-1/
ORIGINAL_TRIAL/diagnostics/private-batch-privacy/dispatcher-capture/round-2/
```

The optional corrupt-server capture must use this exact root:

```text
ORIGINAL_TRIAL/diagnostics/private-batch-privacy/corrupt-server-1/
```

Trusted runtime capture must write the original declared files directly; the
controller does not copy, read or hash them. The launcher checks only owned,
regular, single-link0600 metadata and nonsymlink routes. These fixed capture
roots prevent a selected artifact from aliasing an honest truth or Original.
Declared server1 capture is a routing assumption, not proof of complete capture.
Present full raw material remains unmodeled; absent material stays missing.

## Fixed roles and state

The admitted bootstrap receipt must select the exact private parent derived
from its label beneath the established new-Original root. Only the diagnostic
subdirectory is mounted; no role mounts an Original or an entire trial.

| Role | Persistent private state | Private read mounts |
| --- | --- | --- |
| Observe | `TRIAL/diagnostics/private-batch-privacy/observe` | The two actual colluder1 constraint leaves, selected dispatcher captures and at most one server1 capture |
| Score owner i | `TRIAL/owner-i/diagnostics/private-batch-privacy` | That owner's two truth leaves; four original prediction capsules |
| Aggregate | `TRIAL/diagnostics/private-batch-privacy/aggregate` | Three original count leaves; four original prediction capsules |

An exclusive `LAUNCH-CLOSED` file consumes the fixed operation state. Core roles
also reserve their existing `OBSERVATION-CLOSED` and `SCORING-CLOSED` markers.
Files and parent directories are fsynced. A new attempt label, selection path or
controller output directory cannot create a new scoring oracle for an Original.
Interrupted or refused actual queries are retained, never reset.
Public observation/barrier/completion checks precede score-slot consumption;
an early call with no public barrier reads no private content and consumes no
score slot. The persistent consume still precedes every private content read.

Observer completion checks public capsule seals and private capsule metadata,
then writes an exclusive0400 `BARRIER.json` before scoring can mount any truth.
Scoring binds the exact barrier/observation hashes, all four capsules and its two
original public commitments. Aggregation receives count/capsule leaves only.
Private configs, command plans and FD-only logs remain excluded; the controller
never reopens or hashes their bodies.

All namespaces use selected public source copies, `python3 -B -S`, unshared
network, `/proc`, `/dev`, temporary storage and the exact role mounts. There are
no host home, TLS certificate/private directories, wallet, PK or Original mounts.
Public input admission uses unchanged guard09. Private leaf admission is metadata
only; actual content reads and commitment verification stay in the role worker.

## Public outputs and remaining integration

Public outputs derive from `BOOTSTRAP_PUBLIC/LABEL/privacy-diagnostics`:
`observe/PUBLIC.json`, `observe/BARRIER.json`, `score-owner-i/PUBLIC.json`,
`aggregate/PUBLIC.json`, and per-role `LAUNCH.json`. Launch schema is
`kpb-private-diagnostic-launch-result/v1`, binding operation/selection, public
result path/hash, fixed-query consumption and no-private-read/network flags.
It never exports truth, per-owner scores, capsule bodies or membership masks.

The owner1 hook must still create each original0600 `COLLUDER-CONSTRAINTS.json`
inside its actual pay operation directory, after the actual projection and all
actual invoice routes are available. It must call the frozen `colluder_facts`
adapter with its own actual receiver/record. A missing hook is recorded as
missing coverage; the launcher does not synthesize facts or known routes.

Actual trusted capture, root execution/source pins and complete-view provenance
remain pending. Unknown dispatcher metadata, full corrupt-server transcripts
and terminal economic constraints remain **UNQUALIFIED** under the unchanged
strategy. Legitimate incoming creator knowledge retains the pre-execution
strict-H1 failure counterexample. No successful launcher control can become
financial readiness, complete-view privacy evidence or a terminal privacy pass.
