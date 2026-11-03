# Cost and correctness checkpoint

Status: experiments and independent publication checks complete, with failures
retained. All owned CPU/GPU jobs have stopped. The combined source baseline
is `0fcd409`. This is offline research with public test data, not a fundable
private-payment system or a completed exit lifecycle.

| Work | Current result | Evidence |
| --- | --- | --- |
| Publication and consolidation | Both original snapshots pushed; combined branch pushed. Missing standalone fresh binding/state locks added. Initial missing-lock failure retained, followed by63 passing source checks. | [Merge checks](merge-checks/SOURCE-CHECKS.json), [publication guide](../../PUBLICATION.md) |
| Ordinary native budget | Candidate1600 passes4 genuine cases and28 synthetic boundary contexts, with45 exact typed reserve rejections plus a separate mass-cap rejection. Paired1700 unchanged. | [Closed report](ordinary-budget/REPORT.md), [manifest](ordinary-budget/MANIFEST.json) |
| Cost implication | At unchanged40M fees, ordinary rate200 now fits; rate500 fails. Factory remains1700. No fresh DRAIN was executed. | [Independent review](ADVERSARIAL-REVIEW.md) |
| Complete-lifecycle floor | Under the unamortized ADMIT-plus-fresh-exit route, necessary verification fees are29.5M at reference100, exceeding the20M lifecycle budget for10 tKAS before private payment costs. | [Conditional frontier](fee-frontier/README.md), [exact results](fee-frontier/results.json) |
| Fresh state boundaries | Seven-group run passes; a separately frozen eighth group passes genuine-proof17-bit predecessor/append paths and rejects authentic low16-bit aliases. Earlier helpers are byte-identical. Synthetic state is not accepted/backed history. | [Closed boundary report](boundary-correctness/REPORT.md), [test module](../../poc/s7-owner-lifecycle/state/src/tests.rs) |
| Full-circuit arithmetic | All30 frozen outcomes match:28 complete4,372,824-constraint systems (11 satisfied/17 unsatisfied) and2 expected partial-synthesis shape errors. Amount cases rebuild commitments, anchors and nullifiers. No acceptance bug found. | [Closed report](boundary-correctness/REPORT.md), [manifest](boundary-correctness/MANIFEST.json) |
| GPU scheduling | Both saved receipts independently verify the original claim. IPC18 takes505.118s startup+response versus historical IPC19's302.926s. Separate actor18 emits its valid candidate after about449s, but the monitor aborts during worker shutdown; exact client timing fields are unavailable. Operational failure and original6656MiB admission failure remain retained. | [Proof performance results](../../poc/s7-proof-performance/RESULTS.md), [original plan](AGGREGATE-COST-DESIGN.md), [separate8GiB profile](actor18-8gib/SPEC.md) |

The native candidate changes only the operational budget, preserving all other
body fields, ID, signatures, proof-authorized fees, storage mass and script
units. Its full hash changes. The actual Full-validator results and separate
source-adapted policy predicates are labeled independently. The native sampler
captured the outer bwrap mount namespace rather than the checker namespace;
that observation is explicitly unqualified, not silently repaired by a rerun.
The circuit lane used about2.68CPU hours and1.05GB cgroup peak memory across
the pilot and suite. Its wrapper-only per-case CPU/RSS files are retained but
unusable for those metrics. Constraint checking is not wallet-proof generation
or CPU-only wallet qualification.

The actor candidate was saved before the guard fired and passes the original
independent verifier, including negative controls. Its sampled5532MiB peak is
an observation, not completed memory qualification. SDK shutdown warnings
precede the monitor event and are not attributed to it. A separate future
monitor helper has9 CPU-only regression cases, including a real Linux zombie;
it was not used in either GPU experiment. Neither GPU configuration qualifies
the60s payment diagnostic, CPU-only wallet requirements or end-to-end acceptance.

The [source comparison](native-kas-singleton-fee-alternatives-2026-10-22.md)
checks current official Kaspa and established privacy designs. Smaller arity
does not remove the native Groth16 base charge; prior-settled terminal claims
relocate earlier authorization cost. No alternative is adopted. The
[architecture review](ARCHITECTURE-DECISION-REVIEW.md) keeps per-user economics,
CPU-only wallet targets, accepted backing and independent exits separate.

The adopted privacy requirements and failed common-price workload remain
unchanged: the21.0977% public-prior floor exceeds the20% absolute amount cap.
Passing implementation tests do not establish cryptographic correctness or
financial privacy. The previously rejected owner/replay/DRAIN workflow remains
parked; this checkpoint does not complete it.
