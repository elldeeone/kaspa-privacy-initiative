# Aggregate cost screen and fixed-claim GPU experiment

Status: prospective plan under ADR0038. No new guest, circuit, setup, input,
native policy, owner CLI/replayer/DRAIN or recovery workflow. Source base is
merged `0fcd409`, preserving `85e3939` and `68d7b03`. Root releases execution
only after independent source/identity review. Historical packets are immutable.

## Selected next experiment: IPC18, then conditionally actor18

The existing B2 proof took302.926s with170segments at po2=19 and sampled matching
GPU peak6096MiB. Raising B to12 would mostly buy another~30min proof while the
existing60s payment-latency diagnostic already fails. Instead change the host
segmentation/scheduling around the **same exact successful claim**.

1. **IPC18:** one complete genuine proof with the retained CUDA worker and
   `ExecutorEnvBuilder::segment_limit_po2(18)`. Hypothesis: smaller FFT/working
   sets reduce memory and may improve segment time; more segment lifts/joins
   can instead increase total latency. Stage timing determines which dominates.
   SDK3.0.3 documents approximately linear segment memory and explicitly permits
   tuning either direction (`host/client/env.rs:179–193`).
2. **Conditional actor18:** at most one full proof, only after IPC18 succeeds,
   independent receipt verification passes, and measured memory permits the
   supported existing actor pipeline. The actor manager uses separate primary
   segment and secondary lift/join GPU processes, allowing CPU preflight and
   stages to overlap. This is the scheduling hypothesis, not a cryptographic
   change. The IPC18/actor18 pair is the matched scheduling comparison; the old
   IPC19 run is historical context, not a statistical baseline.

**No actor19 or higher-po2 trial.** Two processes do not share the CUDA singleton
mutex. A6096MiB segment allocation plus recursion can overrun the selected card.
There is no inspected SDK hard VRAM-quota or resource-aware cross-process
arbitration knob. More Rayon/Tokio threads alone do not parallelize the serial
IPC segment loop.

### Exact immutable identities

| Item | Selected identity |
| --- | --- |
| Guest image | `e21ab79e3aebdaba0355680d6a17bf0142bf0b3b5bbb687a6f2726499282a0d3` |
| Wrapped program SHA256 | `7f853b7cbdf0044a061057eac9e0ddc826b949969db06c31adf6bdf1215c805f` |
| Public input11219 SHA256 | `eab451e4701d2fa65c5a5a2cf23a0d1c9483723951c0382989c8e0e9decfaa39` |
| J336 SHA256 | `699697f07565d28faad6e45b9e6daa0a09dbcea3f475d51880a75289f7e49b57` |
| Successful claim | `88f54f54030b2fc884c777a872262679fa15bffca8e613a0f6d40f7d90e92aaa` |
| Official decoded JOIN | `7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e` |
| CUDA worker SHA256 | `3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7` |
| Historical Succinct receipt SHA256 | `345568d0dd58de73f384aa616b5698a7d535c7aaa5335ff74c7a0a94a1b583ce` |
| Historical frozen verification host | `f00ce3545c326758de12768043617b26f799134ff247a90df5121dbdfaa9e40e` |

Files are retained under sibling `lifecycle-outer-target`: `programs-stage00/`,
`publication/input.bin`, `selected-host/`, `fresh-pair-proof/`. Worker is sibling
`proof-target/tools/r0vm-cuda`. A fresh performance client in
`poc/s7-proof-performance` depends on the unchanged selected host library. It
permits only18 and the explicitly selected IPC/actor backend, checks worker SHA
and original input/image/J/claim, saves+fsyncs every candidate before verification,
and runs the same SDK plus official decoded-control/allowed-root checks. Original
source, pins, program and historical executables are never edited.

Before execution, root/reviewer freeze this plan, new client/lock/binary/runner
hashes, original dependency/tool identities and the full exact command. Outputs
must use new, previously nonexistent `performance-target/ipc18/` and,
conditionally, `performance-target/actor18/`. No compressed receipt is needed;
do not repeat compression for this latency question.

### Operational command contract

Use the already installed Rust1.95 and a private task target/cache. Build only
the new host client after source review. Its invocation is:

```text
kpi-s7-proof-performance ipc PROGRAMS INPUT NEW_OUTPUT
kpi-s7-proof-performance actor PROGRAMS INPUT NEW_OUTPUT  # conditional only
```

Both use `RISC0_PROVER` equal to the selected argument, absolute
`RISC0_SERVER_PATH` naming the hashed worker, `CUDA_VISIBLE_DEVICES=0`,
`RAYON_NUM_THREADS=6`, `OMP_NUM_THREADS=6`, writable task-local work/cache/tmp,
empty `GITHUB_TOKEN`, original HOME and absent `RISC0_DEV_MODE`.
Actor additionally requires `RISC0_DEFAULT_PROVER_NUM_GPUS=1` and
`TOKIO_WORKER_THREADS=6`. No backend/SDK source changes or global installations.

Use one owned cgroup per candidate:6CPU,8GiB host RAM,swap0,one RTX3070,
generous60min absolute wall limit. The60s product diagnostic is a score, not an
abort timer. Root coordinates this with the8CPU/10GiB constraint lane. Retain
CPU throttling counters;6CPU differs from the historical8CPU cap, so throttled
results cannot isolate segmentation speedup against that historical run.

Network stays isolated but namespace-local IPC/TCP is permitted. Actor uses
inherited Unix sockets plus an ephemeral private TCP listener and writable
temporary configuration. Its default client does not forward ProverOpts,
VerifierContext or the session cycle limit; exact independent verification and
external limits remain mandatory. Actor output must be genuine Succinct,
successful, same exact claim/image/J, with no assumptions and development mode
disabled. Actor compression is unimplemented; any future compression must use
the existing IPC compressor under a separate decision.

### Frozen measurement, condition and outcomes

- Enable bounded module-specific stage tracing:
  `RUST_LOG=info,risc0_zkvm::host::server::prove=debug,risc0_zkvm::host::recursion::prove=debug`
  and `RISC0_INFO=1`. Do not add guest pprof overhead to timed proving. Record
  execution, segment preflight/core, lift, join, final verification and cleanup
  separately. Actor's task/JobDone logs supply its overlap chronology. Its child
  telemetry startup/shutdown can add loopback errors: retain them and distinguish
  proof-response time from complete owned-process cleanup wall time.
  The client binds the prover explicitly, captures startup/API-response before
  its Drop, fsyncs the candidate, then measures backend cleanup separately.
  Actor stats' paging/reserved-cycle zero fields mean unavailable, not zero work.
- Sample the **sum** of all matching cgroup GPU-PID allocations, their PID/start
  identities and cgroup RAM/swap at0.1s, with GPU clocks/power/temperature/load.
  Record cache state, compiler time separately, and whether another workload
  used GPU. Keep host/build/CPU verification outside the proving timer. This is
  one diagnostic per configuration, not p95 or an end-to-end wallet measurement.
- Actor18 opens only if IPC18 logs reliably separate primary and recursion
  stages, and `measured primary peak + measured recursion peak +512MiB <=6656MiB`.
  Require reviewer/root acknowledgement of that gate before launching. This is
  a conservative measured admission rule, not a proven allocation bound. Stop
  all owned processes if summed matching GPU use exceeds6656MiB; the sampler is
  detection rather than a hard CUDA quota. Preserve any failure/overshoot.
- Verify every saved candidate in a separate process using the frozen original
  verification host, expected source hashes/image/J/claim/JOIN, no assumptions
  and development mode disabled. Retain SDK/context/seal/control negatives.
  No cache, Fake receipt, unresolved assumption, executor-only result or returned
  image can replace a genuine full proof. Preserve slower/failing candidates;
  do not choose another setting after seeing a result within this experiment.
- Report signed latency/memory differences and full phase timings, with an
  explicit below/above60s diagnostic. A GPU/service result does not qualify R8's
  CPU-only4-core/16GB reference device,4GiB aggregate wallet,10s warm p95,
 60s payment p95, cold startup, independent recognition or complete user costs.

Source basis: pinned SDK3.0.3 `host/server/prove/prover_impl.rs:89–100` serial
segments, `host/client/prove/{mod.rs,default.rs}` actor selection/argument limits,
and official worker source at `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6`:
`risc0/r0vm/src/actors/{mod.rs:180–251,worker.rs:277–280,job.rs:355–415}`.
`risc0/zkp/src/hal/cuda.rs:46–49` is the process-local mutex. The retained image
source was inspected read-only; no build/proof/GPU was run for this source pass.

## Prospective B2/4/8/12 screen; no heavy aggregate release

Let B count independently useful payments/inner2in2out authorizations, not2B
recipient/change outputs. The current source has fixed arrays and a hardcoded
B=2 header; the following are verified **generalization formulas**, not current
arbitrary-B acceptance:

`P_B=92 +2B*32 +2B*(32+185)=92+498B`.

`pair_input_B=P_B +875B +2*(2B)=92+1377B`, only while byte indices cover2B
slots (all proposed cases fit; do not generalize beyond128 without new framing).

Full state input adds one36-byte outpoint, S105, R8, a common512-byte historical
path,2B indexed-NF witnesses of1160bytes,2B CM paths of512bytes, and B odd-prefix
history paths of512bytes: `state_input_B=753+5233B`. The NF witness includes72
metadata bytes and two17-level paths. CM/history trees remain16-level. A J336
can retain the same field lengths because it commits SHA256(P), but any new-B
profile needs separately frozen count/version/image/native framing; old J/images
must not be reinterpreted.

| B | P | Pair input | Full state input | Native payload (11+P+105) | Linear GPU context only |
| --- | ---: | ---: | ---: | ---: | ---: |
|2|1088|2846|11219|1204|~5min measured|
|4|2084|5600|21685|2200|~10min projection|
|8|4076|11108|42617|4192|~20min projection|
|12|6068|16616|63549|6184|~30min projection|

State counts must use checked `n'=n+2B<65536`, odd n, and
`m'=m+2B<131071`, even m>=2, preserving `m<=2n`; history appends retain every
intermediate odd prefix, not just the final root. Keep all2B NF uniqueness,
sequential current-root absence/inserts, record multiplicity/cipher binding,
two complete bijections, common anchor/count and per-proof checked canonical
verification. Sum fees in checkedu128, then reject aggregate fee>MAX_SOMPI and
require positive R'=R-fee; a larger sum fittingu128 is not a valid reserve debit.

With the SAME24KiB redeem,1700budget, one input/one output and existing P2SH
shape, native estimated bytes are conditionally`25118+498B`, compute mass
`195488+498B`, transient mass`4*(25118+498B)`. These reproduce observed B2
26114/196484/104456. New code emission/padding, actual script units, standardness,
Full validation and contextual storage must establish that those constants still
apply. Script charges newly pushed bytes1:1 and SHA256 input bytes1:1; hashing a
larger P adds work even with one fixed native Groth16 verification. Do not inherit
the1700 budget from the small fixture without a new emitted-source bound.

At10KAS, the1% reference cap is10M sompi per payment. Current B2 native quote at
100 is9.8242M/payment before extra costs, but its actual fixed fee is40M/payment
and the actual public recipient values are4/5KAS. Repricing those proofs is
invalid. Larger-B native quotes can screen amortization, but do not measure an
all-in user fee, service subsidy, batch-fill wait, owner exit or10KAS lifecycle.
The existing60M singleton claim versus73.75M verification floor at500 and the
privacy-prior failure remain unchanged. Thus B12 is not the minimal decisive
next experiment; revisit it only after a separate operating-point decision.

Aggregate source basis: `poc/two-v6-binding/common/src/lib.rs:18–25,197–355`;
`poc/two-v6-state/common/src/lib.rs:10–29,91–124,149–241,314–367`;
`poc/shared-pool/src/s7_lifecycle/native.rs:14–24,395–454,457–487,551–649`;
native `01b532e` mass `mod.rs:335–369` and script charging `lib.rs:591–595`,
`opcodes/mod.rs:55–71`. RFC0012 R8 and architecture review retain their gates.
