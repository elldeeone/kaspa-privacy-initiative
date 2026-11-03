# Terminal Exit-privacy freeze contract

Status: **SOURCE-ONLY / UNEXECUTED / REHEARSAL AUTHORIZATION FALSE**.

`terminal_exit_privacy.py` defines a separate privacy experiment for the nine
independent Exits after financial-service loss and through the final cold scan.
It does not inherit, substitute or reinterpret a private-batch payment result.
No trial identity, private body, capture, service-loss operation, Exit, scan,
network contact, funding or broadcast was created for this contract.

## Pre-execution freeze

The Root-owned selection must exist before the terminal workload starts. It
binds:

- distinct transparent-baseline and hidden-mapping-candidate capture identities;
- the fixed trial, method, workload, observer model, coverage policy, one
  colluding owner and immutable thresholds;
- the exact current transitive source closure and selected runtime closure;
- both exact registered payment-release records already accepted as lifecycle
  inputs;
- nine ordered opaque Exit operation identities, salted private owner-receipt
  seals and distinct preselected output roots; owner labels are not public;
- preselected service-loss and terminal-scan operation identities/output roots;
- `execution_started:false`, no private truth/body export and
  `rehearsal_authorized:false`.

Future result hashes are forbidden in this freeze. The capture must later
reopen the actual service-loss, Exit lifecycle/release/CASE and scan records
under the preselected roots. This avoids a post-result “freeze.” A capture
cannot supply its own source closure: the validator recomputes the finite
current closure, verifies its repo-local Python import closure is complete, and
reopens every selected source, runtime and registered record by exact path,
SHA256 and byte count. Source-owned empty-root markers and one durable barrier
are consumed once before either arm may write results.

## Complete union observation

Each arm retains all nine clear payout amounts, distinct fresh payout scripts,
transaction identities, native order and monotonic timing. It also retains the
actual owner-origin route/contact/cohort facts and every attempt, including
retries, rejections, orphaned candidates and reorged candidates. Empty event
classes remain covered categories; they are not omitted.

The service must be observed absent after the loss barrier, before every Exit
and after the cold scans. Any process, listener, mounted private service state
or Exit dependency reappearance refuses. All three scans occur after Exit 9,
report zero reserve and export no payout script or Exit identifier.

The union side-information model includes positive invoice, contact, amount,
script, order, timing, route, cohort, retry and colluder-receipt mappings. The
candidate relation is the intersection of every matching observed fact. Thus a
fresh payout script does not compensate for an owner-labelled route, unique
order, timing or contact edge. Accepted and failed attempt route, timing,
contact, cohort and transaction identities are scored. A complete pairwise
constraint graph plus selected full nine-Exit assignment vectors represents
cross-Exit amount-sum and retry/intersection constraints; unary candidate sets
alone are insufficient.

## Frozen scoring and stop rule

The transparent control must resolve exactly one truthful three-by-three Exit
assignment. The candidate is enumerated over the same nine Exit identities
with exactly three Exits per owner. With one colluding owner fixed, both honest
owners must retain at least two candidate Exit sets, every one of the six
honest Exits must retain at least two eligible owners, the truthful joint
assignment must remain, the joint set must contain at least two assignments,
neither honest owner may regress, and both must improve strictly over the
transparent control. Colluder receipts must identify exactly the selected
colluder's three true Exits and cannot be omitted or broadened.

The public score exports only aggregate counts and a source-model status. It never
exports Exit IDs, owner labels, assignments, Originals or private bodies.
Missing, relabelled or reordered Exit evidence; duplicate/previous scripts;
wrong lifecycle references; result paths outside frozen roots; incomplete
coverage; truth relabelling; route/order uniqueness; late service loss; service
reappearance; early scans; or private exports refuse or produce a privacy fail.

## Authorization boundary

Raw observer bundles and private truth remain inside the future isolated
capture/scorer. `terminal_exit_privacy_acceptance.py` receives only their exact
seals and the count-only public score, and currently emits:

```text
privacy_status = UNQUALIFIED_SOURCE_ONLY
actual_capture_and_private_score_executed = false
rehearsal_authorized = false
```

An actual isolated capture/private-score producer and direct lifecycle bridge
join do not exist yet. A synthetic fixture, a caller PASS Boolean, the payment
privacy gate, or a self-authored receipt cannot cross this boundary. The
complete rehearsal bridge must keep its terminal-privacy hard stop until a
future actual producer executes this frozen contract and a separately reviewed
acceptance path directly validates its receipts.
