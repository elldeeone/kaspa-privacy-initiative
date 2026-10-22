# Production tree capacity controls — 22 October 2026

All **six selected boundary controls passed**, together with two initial-state baselines. At both production depths, the actual incremental `Tree::append` reached exact capacity and refused one additional leaf with the complete stored state unchanged. This closes the specific unexecuted boundary gap identified in the frozen `UNIT-COVERAGE-PROPOSAL.md`; it does not change that proposal's historical recommendation about existing tests.

| Depth / capacity | Initial baseline | Penultimate append | Exact-full append | One additional append |
|---|---|---|---|---|
| 16 / 65,536 | 65,534 leaves; pass | 65,535 leaves; pass | 65,536 leaves; pass | `Merkle capacity`; complete state unchanged |
| 17 / 131,072 | 131,070 leaves; pass | 131,071 leaves; pass | 131,072 leaves; pass | `Merkle capacity`; complete state unchanged |

The new isolated adapter compiles byte-identical spans containing the production `Tree` and hash function, with whole-file SHA-256 assertions before extraction. It constructs each starting tree with the public deterministic fixture `SHA256("KPI/public-tree-capacity-control/v1\0" || depthLE32 || indexLE32)`, then performs exactly two successful incremental appends and one refusal. A separately allocated dense reference pads the entire leaf array and hashes it bottom-up without using production `Tree::new`, `append`, `root`, `path` or `node` for its expected values. Every stored level, empty-subtree value and depth is compared, as are the root and selected boundary paths. Refusal compares all those fields plus every vector's pointer, length and capacity before/after; public state digests intentionally omit addresses. Both refusal digests match exactly.

This is ordinary data-structure correctness evidence. It generated no Groth16 setup/proofs and used no circuit, replay, recovery, native verification, chain, private evaluation or network workload. Generic tree fullness is not proof that a pool state at that count satisfies separate count/parity or admission rules. Native KAS backing, independent permissionless exits and all existing privacy requirements remain invariants; this lane neither exercises nor relaxes them. Second-pass source review confirmed that only the new adapter was added and that the expected-state reference does not call the implementation under test. Passing these finite controls is not formal cryptographic assurance.

The isolated source commit is **`67793fa4b849e12555a13dfe10016cad7299d040`**, branch `test/tree-capacity-controls-20261022`, parent `2251864a7f89065a526641c3782506f27b39c59f`. It adds only four files under `poc/tree-capacity-controls/`; no push was made. The whole `poc/shared-pool/src/` directory and its Cargo files are unchanged from **`9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`**. The earlier relation-control package and its 16-case evidence remain unchanged.

| Pinned evidence | SHA-256 |
|---|---|
| Production `two_input/tree.rs` | `9fc004721ae2a22c6faa26f2a046eefd7bb707e3c83077be01a7913b464891ed` |
| Production `protocol.rs` | `5243cab1b36e0d9cae8bf13e81b7fcdb033c8dc1bc7405daa401c69334cc4ec4` |
| Tested adapter `src/main.rs` | `bce79ab04c28f5511f3d1fc07e541cf21896dfef18893f537bae0d2829ec90c5` |
| Exact executed binary | `1ba6c95638a2077bf78fbbc4779cd1a4e5acdd1e82555e72f1d02d3f245f0ab0` |
| `results/summary.json` | `ba7fb1f50f9931a767ec1f221b6e91cfe06db62ca20ee997dc52c8821ea3aea8` |
| `results/source-provenance.json` | `226160e64b2f67999ebddbe644b55ac13a257222c89fdc2383a19bffd3ab57c7` |
| `results/raw-evidence-manifest.json` | `202b7cc6a9a9c13df10896d2b5dab34881d115284f07d0189c7455acf8afd52f` |

All paths below are on Forge. The exclusive lane is `/home/luke/projects/kpi-orchestration/2026-10-22/workload-review/tree-capacity-v1`; source is in `worktree/`, the isolated build in `target/`, and public raw evidence in `results/`. The provenance file records every source/dependency lock identity, the extracted-span hashes, exact command, compiler and binary. All 22 dependency identities match the pinned original lock; the build ran offline with the adapter's own lock and target.

The owned unit was `kpi-tree-capacity-v1-20261022.service`, invocation `088e5fda59fb44b6872c0da628bcaba7`. Actual limits were CPU quota 1,200%, inherited `taskset` affinity 2–13, hard RAM 4 GiB, swap 0, 256 PIDs, 1,200-second absolute runtime, `KillMode=control-group`, and `OOMPolicy=stop`. The host lacks delegated cpuset control, so CPU placement was process affinity, not a cpuset guarantee. Cargo used four jobs: `cargo build --release --locked --offline -j4`. Runtime used at most two workers, one per depth, after the measured first baseline justified the second.

Build time was 2.99 seconds (8.98 CPU-seconds). The first baseline passed in 20 ms with `/proc` HWM 16,812 KiB; the second in 41 ms with HWM 31,032 KiB. Final worker HWM was 25,048 / 47,576 KiB. Total unit CPU was 9.847 seconds and peak aggregate charged memory **309,567,488 bytes (295.2 MiB)**. The unit ran 09:41:36–09:44:29 UTC; about 169 seconds was the first worker's footprint-decision barrier, not computation. This was finite useful coverage, not a sustained-load benchmark. The launch sample measured host busy 37.03% across 14 cores (5.18 cores), lane use 3.43 cores, summed process RSS 514.8 MiB and cgroup charged memory 217.6 MiB; RSS sums include shared pages and are not aggregate physical usage.

Two earlier, overly strict preflights stopped on isolated microsecond PSI increments before any build/runtime; both receipts are preserved. Under root's clarified allocation policy, the launch gate had 0.00148% full stall over 10 seconds, no swap-out growth and 12.14 GiB conservative headroom after all reservations. The second-worker gate had 0.0675% full stall, no swap-out growth, 12.32 GiB headroom and zero memory max/OOM events. No test criteria changed. The unit and both workers exited successfully; GNU time recorded zero swaps. At **09:45:02 UTC**, cleanup verified inactive/dead, MainPID 0, empty ControlGroup, absent former cgroup and no matching executable PIDs. The entire reservation was released. The GPU owner received unit/phase and completion notices so its overlapping development timing remains appropriately qualified.
