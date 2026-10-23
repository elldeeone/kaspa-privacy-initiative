# Finite exit-liability experiment

**Closed, 2026-10-23 UTC.** Both frozen searches exhausted their complete128
initial configurations without a modeled accounting/authorization violation.
The model retained concrete liveness failures and detected every deliberately
broken rule. It does **not** establish a native exit, safe revealing format,
cryptographic correctness or complete payment lifecycle.

[ADR-0039](../../../../docs/adr/0039-exit-liability-and-native-claim-experiments.md)
authorized this isolated stdlib experiment. [Source/model details](../../../../poc/exit-liability-model/README.md),
[primary-source comparison and seams](../IMPLEMENTATION-SEAM.md),
[exact totals](SUMMARY.json).

## What completed

| Separate search | Initial configs | Financial states | Exact environment-product states |
| --- | ---: | ---: | ---: |
| Base; existing-format reveal unresolved/disabled |128|9,397,840|75,182,720|
| Hypothetical reveal with ideal future authority/exact-NF oracle |128|13,051,392|104,411,136|

Each configuration covers three origin notes with ownerA/B and value2/3,
including one bounded private-transfer hop, batches of1..3 resources, two
entitlement locations, quote1/2 and all eight service/data/witness products.
There was no depth, sampling, state-count or time truncation. The environment
product is exact because availability losses only disable financial actions;
all financial states and every loss product were enumerated. Pilot base127 was
reused exactly once. The two searches must not be combined into an unconditional
revealing-exit result.

An independent per-origin Ghost ledger audits native reserve, delivered native
outputs, unpaid claims, authorized fees and bound recipients. It also supplies
the unpaid-claim set for liveness checks. Candidate guards never read it.
All selected source/config before/after hashes and snapshots matched. A second
agent independently recounted exact000–127 coverage, pilot reuse, totals and
all retained mutant witnesses without rerunning exploration.

## Useful result and retained failures

Accepted shared-root entitlements can be modeled with service-independent final
claims **only when** original private NFs were consumed atomically, liabilities
remain backed, claim identity is stable across roots, current paid state is
checked, keys/data remain available and the claim can pay its fee. Native P2PK
tickets instead deliver owner-controlled native value at batch acceptance;
the later ordinary spend is not a second protocol exit or a free operation.

The base search retains these failures, not success labels:

- Fee-exhausted backed entitlements occur in all128 initial configurations.
  Abstract units/quotes are not sompi or measured native fee bounds.
- Missing shared-claim data/witnesses blocks recovery in all64 shared-root
  configurations. Native-output visibility and retained owner keys are separate
  ideal premises; this is no scanner or data-availability qualification.
- Shutdown before private acceptance strands an unaccepted note in all128 base
  configurations. Moving authorization earlier does not solve that user's path.

The conditional search assumes the unresolved revealing-authority relation; it
checks exclusion/accounting under that premise only. No existing v6 note or
immutable covenant gained a new branch.

## Actual counterexamples, not only positive checks

All11 deliberately broken variants produced retained counterexamples:
omitted original NF, missing backing, missing paid marker, root-local claim ID,
historical paid state, service-dependent claim, redirected recipient, amount
substitution, fee-exhausted payout, retiring pending liabilities and an omitted
entitlement with backing left intact.

The [directed root/index trace](raw/controls-03/result/controls.json) uses two
**accepted** cumulative roots28672→28679. The same NF5 moves leaf index0→1.
A broken root-local ID pays its principal3 twice: native payouts total4 plus
fees2. Correct stable-ID rules reject that second claim. A different negative
publishes a reusable private credential **without an accepted reveal**, retains
that knowledge across chain rollback, then accepts an attacker private-spend
redirect in the unsafe model. Independent owner-consent accounting rejects it;
same-NF exclusion alone does not prevent theft by the first spender.

Final controls also check64 environment/knowledge/quote rollback products,
9 same-original-NF competitors outside generator filtering, authentic old-root
claim usability, current/historical-paid replay rejection and atomic duplicate
batch rejection. These are symbolic controls, not native transactions.

## Evidence identities and preserved correction

The full graphs use [freeze02](source-freeze-02.json), SHA256
`3d72f799914df77a59bda810b939850bd1f7283f36cf0984d072fd1d19967dd6`.
Unused freeze01/source snapshot remains retained: pre-runtime review found that
candidate-only claim iteration could hide an omitted entitlement. Freeze02
fixed independent Ghost coverage and added that mutation control before search.

A later directed-helper issue was reproduced against freeze02: raised quote2
rolled back to1. Its [FALSE result and raw exit1](reorg-quote-regression-freeze02.json)
are preserved. The old32 checkpoint products qualify quote1 only. Financial BFS
never calls that helper and already explores quotes1/2.

[Controls-only freeze03](source-freeze-03-controls.json), SHA256
`412d758552bc17f09cab138a0549b73f3f10479bd0fd5bb006886e73aeadab9c`,
corrects quote persistence and adds the directed race checks. Only controls.py
and README changed; [the model/oracle/search/runner/config stayed byte-identical](source-relationship-02-03.json).
No financial graph was repeated. Final controls result SHA256 is
`d9c2b4977a40cf585c95f1e490ceaeea994d48c840dfbf455ff1f58438633721`.

## Resources and limits

| Owned job | Wall seconds | Cgroup CPU seconds | Peak bytes |
| --- | ---: | ---: | ---: |
| Pilot base127, counted once |50.57|50.59|394,735,616|
| Remaining base + all conditional + original controls |574.25|4,138.26|2,164,690,944|
| Final controls-only correction |0.55|0.58|25,731,072|

The full job used at most8 CPU/12GiB/zero swap, with network and all unrelated
repo/private inputs unmounted. All owned units stopped with PID0 and empty
cgroups. Resource records use owned cgroups; worker CPU/RSS fields are explicitly
cumulative and must not be summed as per-case costs.

Proof/hash/signature verification, canonical predecessor identities and
sufficient current witnesses are ideal predicates. Concrete native scripts,
Merkle encoding/capacity, consensus/reorg/DAA, transaction mass, paid fees,
privacy, arbitrary transfers and unbounded liveness remain outside this finite
model. No wallet, owner CLI, ledger replay, DRAIN/proof workflow, PK restore,
setup, GPU job, funding or broadcast ran. No architecture was adopted here.
