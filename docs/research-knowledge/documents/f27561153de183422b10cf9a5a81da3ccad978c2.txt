# V6 relation control validation — 2026-10-22

**Complete: all 16 finite controls returned their preregistered expected outcomes.** Twelve exercised the complete unchanged v6 constraint generator; four invoked its exact private `bounds` helper. There were six satisfiable and ten unsatisfiable cases. No unexpected acceptance or rejection was observed. This is constraint-satisfaction evidence, not generated-proof, native-validation, chain-execution, formal-assurance or privacy evidence.

## Identity and reproducibility

- Source pin: `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`.
- Exclusive worktree: `/home/luke/projects/kpi-orchestration/2026-10-22/workload-review/relation-controls-v1/worktree`.
- Test-only commit: `2251864a7f89065a526641c3782506f27b39c59f`, detached, not pushed. Four added files under `poc/relation-controls/`; no core source or original lockfile changes.
- Raw evidence: `/home/luke/projects/kpi-orchestration/2026-10-22/workload-review/relation-controls-v1/results/`. `summary.json` contains every outcome, first unsatisfied constraint, time and RSS; individual JSON/stderr/time files, unit properties, cleanup, source manifest and failed preflight logs remain there.
- Build target: `/home/luke/projects/kpi-orchestration/2026-10-22/workload-review/relation-controls-v1/target`.

The adapter compiles the pinned `two_input/circuit.rs` unchanged except removal of its leading documentation comment for Rust `include!` syntax. A byte comparison verified that transformation. `protocol.rs` is included directly; Authorization serialization, constants, Merkle helpers and positioned/dummy nullifiers are exact source spans extracted by the adapter's `build.rs`. It does not compile or substitute a new proof system. All 158 dependency identities in the adapter lock match name/version/source/checksum entries in the original lock; build used `--release --locked --offline -j2`.

Fixtures instantiate the existing public `harness.rs` fixture/control shapes and amounts, with explicitly disclosed deterministic development wallet/rho bytes and synthetic public trees. No saved private witness, evaluation seed, truth, real funds or network was used. These are synthetic relation witnesses, not claims of replayed transaction histories.

## Results and discriminating value

References below are lines in pinned `poc/shared-pool/src/two_input/circuit.rs`. Each complete-circuit case constructed **4,372,824 constraints**. Every selected case preserves integer input/output conservation in the test constructor; cases intended to fail another guard compensate amounts and rebuild affected commitments, paths or nullifiers where needed. Numeric failure IDs are diagnostic first-unsatisfied R1CS indices, not formal attribution proofs.

| Control | Expected/observed | First failing R1CS index | Guard or unresolved assertion addressed |
|---|---|---:|---|
| Mixed owners, reversed input slots | Satisfied | — | Both owners and positioned NFs valid, despite reversed slots; lines 136–137, 180–218. Baseline. |
| Wrong second owner, public NF repaired for changed secret | Unsatisfied | 2,127,358 | Ownership, lines 136–137; membership, note commitment, balance and NF relation remain consistent. Removes the old owner/NF coupling. |
| Slot 1 is the only real input | Satisfied | — | Slot 0 canonical padding; real-input OR and slot-specific dummy NF, lines 139–212. |
| Same commitment at two different positions | Satisfied | — | Distinct positioned NFs and positions, lines 180–218. Extends prior unproved scanner-fixture evidence to the actual relation. |
| Two individually valid inputs total exactly MAX | Satisfied | — | Inclusive aggregate cap and conservation, lines 255–270. |
| Two individually valid inputs total MAX+1 | Unsatisfied | 4,094,876 | Aggregate cap, lines 255–267; outputs, fee and individual amounts remain in range and the transaction balances. |
| Zero fee with compensated output | Unsatisfied | 4,094,455 | Fee minimum, line 245. |
| Fee consumes all value; no payout or positive output | Unsatisfied | 4,094,591 | Nonempty useful result, line 249; fee is in range and conservation holds. |
| DRAIN with positive hidden output and compensated payout | Unsatisfied | 3,973,488 | DRAIN requires zero output value, line 227; public output commitments are zero, payout/SPK valid for this circuit. |
| Positive payout one below floor, compensated change | Unsatisfied | 4,094,325 | Payout floor, line 244. |
| Padding value 60m, output increased 60m | Unsatisfied | 2,127,617 | Padding value zero, line 142; dummy NF unchanged and balance repaired. |
| Nonzero padding secret | Unsatisfied | 2,127,584 | Padding secret zero, lines 139–140; dummy NF and balance unchanged. |
| Exact bounds helper: MAX | Satisfied | — | Inclusive upper bound, lines 62–72. |
| Exact bounds helper: MAX+1 | Unsatisfied | 194 | Isolates the individual upper guard from aggregate conservation. |
| Exact bounds helper: u64::MAX | Unsatisfied | 194 | Saturating witness construction does not accept this out-of-range value. |
| Exact bounds helper: inactive MAX+1 | Satisfied | — | Confirms conditional guard semantics only; complete-circuit padding still requires zero. |

`MAX = 2,900,000,000,000,000,000` sompi. Complete-circuit times were 2.73–3.50 seconds each; helper times rounded to zero milliseconds. No old settled negative control was repeated wholesale. The baseline adds mixed ownership and reversed ordering.

## Resource enforcement and cleanup

The initial 4-CPU/1.5-GiB allocation was not used for a workload. Root subsequently authorized a ceiling of **6 vCPU, 3 GiB aggregate RAM, no swap**, with the original finite 20-minute wall limit. The execution gate sampled five seconds: memory PSI some/full deltas zero, swap-out delta zero, and 21.227 GiB available. Conservatively subtracting all 15.5 GiB of reserved lane caps left 5.727 GiB headroom.

Owned units:

1. `kpi-relation-controls-v1-20261022.service`: isolated build and one baseline, then stopped at the decision boundary. Build took 30.63 seconds; baseline 3.45 seconds and 1,014,228 KiB maximum RSS. Unit peak including build/controller/cache was 1,554,710,528 bytes; memory event counters showed no max/OOM events and swap peak was zero.
2. `kpi-relation-controls-cases-v1-20261022.service`: remaining 15 cases, two workers selected from measured RSS. Peak aggregate memory 2,078,519,296 bytes; swap peak zero; 35.69 CPU-seconds; exit status zero. Three simultaneous complete circuits were not justified by the 3-GiB cap.

Both used `MemoryMax=3221225472`, `MemorySwapMax=0`, `CPUQuota=600%`, inherited `taskset` affinity 0–13, `KillMode=control-group`, `OOMPolicy=stop` and bounded `RuntimeMaxSec`. User cgroups did not delegate cpuset, so affinity was enforced through inherited process affinity rather than falsely claiming a cgroup cpuset limit. No GPU calls occurred. Later units retained the first launch's absolute deadline, 09:36:16 UTC; all controls and cleanup completed by 09:21:07 UTC. Both units are inactive/dead with MainPID 0 and no ControlGroup. No workers remain.

Three cheap pre-build stops are preserved: missing Cargo in user-systemd PATH, fresh lock resolution selecting newer dependencies, and unfiltered offline metadata requesting an uncached Android dependency. They were fixed through an absolute Cargo PATH, retention of the original lock entries and Linux-filtered metadata. No compile or test ran during those stops; there was no OOM retry, installation, global controller change or budget increase by this lane.

## Remaining limits and decision

The new evidence narrows U1–U3 in `V6-RELATION-INVARIANTS.md`; it does not replace earlier failures or expand privacy claims.

1. Identical real inputs necessarily couple same-position and same-NF checks without a hash-preimage/collision construction. ADMIT-with-real and active-with-no-real similarly conflict with other required equations. Their earlier coupled controls/source evidence remain labelled as such; this lane does not manufacture independent witnesses or claim exhaustive branch coverage.
2. The bounds helper establishes its own guard, not every amount-field/mode integration. Zero-fee, aggregate, payout, DRAIN and padding integration are tested above; all possible boundary combinations are not.
3. Genuine proof/native qualification of a minimum v6 note exit, native backing, replay/spentness and independent recovery remain outside this lane. Native KAS backing and permissionless independent exits remain invariants, not relaxed acceptance criteria. No new architecture or proof relation is proposed.

**Recommended action:** accept these results as targeted relation regression evidence and retain the test-only commit. Do not spend more CPU repeating this finite matrix. The next material assurance step belongs to the separately scoped native/exit work; any generated-proof minimum-exit test needs separate authorization and allocation. Passing this matrix is not cryptographic assurance.

## Evidence hashes

- Pinned circuit: `59071901c3abc25daab68c982ef065f8755c09abbb2ce30e6010d821813dd2a7`.
- Unchanged original Cargo.lock: `13007a446f0d9561d50b18897b52a98c951584b2e6c7c721c95580287f5edc64`.
- Tested executable: `d0e84f954fc4de3356e762ed581b30f144aa1cb6d92f6e93a28b1be0398268cc`.
- Raw `summary.json`: `00df9032c6cae1571ee760edce8c160a74c4f47c0a8813256fdffb162c60c07c`.
- Raw `provenance.json`: `82091bf7528220640d22f830eb620c8407b36a28b8c13c2d6a93cc3affa8bfaf`.
- Raw `tested-main.rs`: `3ced137428418f2153d4c5edb2f3b4ae95c4a17b60eb09c78f70862049d4cd8e`.

One diagnostic source-line label for padding value was corrected from 143 to 142 after execution. This changes no test construction or constraint logic; the exact executed source and binary remain in raw evidence. The table above uses the corrected source line. Evidence-lineage owns staging/commit of this canonical report; executable code and raw runtime data are not imported into the documentation repository.
