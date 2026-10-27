# Finite information-flow model freeze 01

**Freeze-time status: source prepared; NOT EXECUTED. Root source review is required before
the first model import, compilation or run.** No cryptography, actual wallet,
MPC binary, GPU, network experiment, native verifier or ledger is used.

Design authority is
[ASYNC-HIDDEN-PARTITION-DESIGN-01.md](../ASYNC-HIDDEN-PARTITION-DESIGN-01.md),
SHA256 `5825670bd730a4ff65c39e40068d1f6676c93a0a8a370d535f44cf9eede6fe2e`.
This implements only that memo's four finite-model arms. No architecture,
cryptographic construction, RFC/ADR or existing observer/policy is selected.

## What is actually being modeled

Inputs are five fictional intent records. Every input is 2,000,000,000 sompi;
payment 100,000,000; change 1,890,000,000; exact fee 10,000,000. Each has one NF
and two real positive complete output tuples. All token strings are fixed
uninterpreted literals; no token is derived from an owner name, actual key,
actual note or real hash. Public tuple rows have only tuple/CM/CV/CF/proof tokens.
NF, tuple, CF and CV equality across retries is preserved. Owner permission to
rerandomize a durable output is **absent**; substitution is a rejection control.
Distinct tuple symbols across the five intents are a frozen fixture fact, not
a new global-CM-nonmembership rule. The existing protocol's accepted repeated
historical CM at another position is outside this finite fixture; no selected
protocol rule is changed by the model.

The research fixture itself is completely public. The finite solver's observer
is explicitly granted only `make_view()`'s projection. It does not receive the
fixture's assignment, receiver/value openings or future-NF descriptor. A person
who reads the complete fixture already knows its assignment. Multiplicity here
is a property of the stipulated ideal view, **not secrecy of the public fixture
or evidence that deployed cryptography produces indistinguishable views**.

Explicit ideal oracles supply:

* opaque secret shares against at most one of three servers; two servers are
  allowed to reconstruct and are tested as outside that assumption;
* genuine owner consent/proof validity, commitment confidentiality, accepted
  historical-anchor consistency and exact selected current-state enforcement;
* public individual-Delta equality queries with a unique matching output pair
  in that negative control; no group arithmetic/collision claim is tested;
* original fictional backup-to-key derivation, ciphertext decryption and
  authenticated public-position recovery; these are tables, not algorithms;
* no transcript/traffic information beyond explicitly granted session/cohort
  fields. Every wallet stops after its own asynchronous upload. Availability of
  fixed servers for that individual input session is assumed.

The owner universe is the union represented in each scenario: ABC for the
single/same-cohort arms; ABCDE for changed-cohort arms. Even O-ledger is granted
that finite universe, but no named owner cohorts or ingress assignment.
O-active also receives the named cohorts, upload sessions and C's own NF and
two output tuples. It controls dispatcher subsets and one server; C is its only
colluding wallet. D/E are additional honest wallets, not extra colluders.
Public Exit events include their NF, payout and an opaque destination. The
enumerated owner maps cover the queued-intent NF universe; D's unrelated Exit
in the same-cohort control is explicitly outside that queued universe. No named
Exit identity is granted to O-ledger through an event label.

## Frozen enumeration and metrics

For each view, exhaust all NF-to-owner bijections. For each bijection, exhaust
all disjoint two-output partitions covering every output. Reject a candidate
only using constraints in that view: named-cohort membership, colluder/plain/
threshold disclosures, explicit pair/Delta links, and complete appearance
signatures across all releases. A durable intent's NF and both output tuples
must appear in exactly the same released batches. This last constraint exposes
the output-set intersection channel to O-ledger as well as O-active.

Retain **every** consistent joint assignment in compact indexed form, plus
its enumeration digest. Report all candidate sets for NF→owner, owner→NF,
NF→output-pair, owner→output-pair and output→owner. There is no guessing
algorithm, accuracy score, inherited 1/6 baseline or passive-128 result.
Primary queries are A/B's NF ownership and output partitions; all owner/row
candidate sets remain available so a global count cannot obscure a unique A.

| Scenario / disclosure | O-ledger joint assignments | O-active joint assignments |
| --- | ---: | ---: |
| One accepted ABC, hidden partition | 540 | 12 |
| One accepted ABC, ordinary plaintext per-intent framing | 6 | 1 |
| One accepted ABC, explicit NF/output pair ID | 6 | 2 |
| One accepted ABC, individual-Delta equality oracle | 6 | 2 |
| Same ABC set/tuples after unrelated D Exit advances head | 540 | 12 |
| ABC egress, C Exit wins, then known ADE egress | 4,320 | 12 |
| ABC apparently accepted, reorg, C Exit wins, then ADE | 4,320 | 12 |

An additional O-active hidden-partition cell grants two server shares: exactly
one assignment is expected. All 15 cells together retain 9,792 assignments.
These combinatorial expectations are frozen before executing the enumerator.

In single hidden ABC, A has two NF candidates and six output-pair candidates
after C is removed. Explicit pair/Delta controls must uniquely link each NF to
its pair, even when owner labels remain ambiguous. After ABC→ADE, O-active
must uniquely identify A's NF **and** exact stable output pair. O-ledger must
uniquely link the intersecting NF to the intersecting two complete outputs even
without knowing that owner's name. The same-cohort control must preserve its
initial multiplicity. Reorg must not erase observer knowledge.

The forced-race schedule is deliberately allowed by **fixed servers alone**.
A future persistent queue might reject B's omission, but no such protocol is
assumed implemented. The model records refusal of every changed cohort as
private-payment liveness loss: the original batch cannot settle after C spends.
It preserves an independent direct Exit; no private local flag becomes a lock.

## Frozen safety and availability controls

The separate accounting model begins with five original fictional notes and
10,000,000,000 reserve sompi. Every accepted transition must satisfy:

```text
reserve = exact sum of all live note liabilities
reserve + all native payouts + all fees = initial reserve
no consumed NF remains a live note
```

Accepted model paths: exact ABC with owners offline; unrelated D Exit followed
by ABC rebuilt at the actual new head with unchanged intents/outputs; C Exit
followed by a now-stale/invalid ABC and a consent-valid ADE; original-backup
recovery and direct Exit with all servers absent before/after ABC acceptance.
The accepted-ADE case is a **privacy counterexample**, not an architecture pass.

Expected rejections: wrong pool/profile, stale final point, invalid ideal proof,
coordinator native payout, tuple/CF/recipient/fee/anchor/count substitution,
unapproved output rerandomization, bool/overflow fee, globally balanced fee
redistribution, duplicate intent/NF, second successor, consumed colluder NF,
orphaned output Exit, orphaned successor replay, operator Exit key, changed Exit
destination, invalid Exit proof, double Exit and withheld accepted CF/tree data.
Exact approved-intent comparison is an explicit ideal authorization oracle;
these controls do not test a cryptographic circuit's enforcement of it.

After rollback, a successor bound to the orphaned new head must reject.
Re-accepting the same exact consent against the restored actual prior head is
allowed when its NF is again unspent; this is fork reconciliation, not a second
spend on one accepted history. Orphaned output receipts confer no accepted
authority. Observer disclosures remain retained in the information-flow arm.

Missing CF or tree history is an expected **availability failure**. A valid
backup is no substitute for unavailable accepted data/current witnesses.
Server loss may stop private batching; it must not give the service withdrawal
authority. Recovery is an ideal backup/public-history/decryption control and
must receive no coordinator partition or pending-intent journal.

## Stop rules and review/run boundary

Stop on the first unexpected assignment count, unexpected unique baseline
mapping, vanished expected NF/output intersection, accepted negative control,
backing/accounting mismatch, inconsistent public tuple reuse, use of owner
labels inside opaque identifiers, or undeclared oracle. Preserve the failure;
do not retune symbols, schedules, observers or expectations. Expected privacy,
availability and liveness failures are reported as failures of those modeled
properties, not hidden by an overall expectation-check outcome.

`run_model.py` performs no I/O, network access, file discovery or automatic
execution. After Root approves exact `SOURCE-MANIFEST-01.json` pins, the runner
must use the unchanged `/var/tmp/kpi-root-guard-helper-09.py` to read/check model
source and input bytes, then call `run_model(data)`. The returned `summary` and
`enumerated_assignments` may be saved separately inside this model directory.
Retain exception details as failure evidence if execution stops. No real funds,
native verifier, signer, wallet restore, MPC engine, GPU or service is involved.

The sole successful top-level label is `frozen_model_expectations_met`. Every
report must state the ideal finite-model boundary. Fees remain unmeasured and
the frozen 21-KAS 2% all-in FAIL remains unchanged. No result qualifies native
privacy, cryptographic security, real recovery, network anonymity or production.
