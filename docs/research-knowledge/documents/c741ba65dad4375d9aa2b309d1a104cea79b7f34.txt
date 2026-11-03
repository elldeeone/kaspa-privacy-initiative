> Imported documentation snapshot. [Canonical status and ownership](../../README.md). Original artifact hashes inside this document refer to its source artifacts; [PROVENANCE.json](../../PROVENANCE.json) records the imported bytes. Commands and paths retained from experiments are historical documentation, not execution approval or a runnable package here.

# Compute feasibility and next-run GPU recommendation

2026-10-22. Analysis and standalone preparation only; no benchmark, profile, dependency installation, compilation, GPU execution, funded trial, commit or push.

## Decision

**Current frozen run: leave the GPU idle. Next privacy run: fund one bounded development benchmark, not a wholesale GPU rewrite.** A GPU integer eligibility filter is plausible, but no executable GPU observer or measured function profile is available. Do not promise acceleration until it beats both the unchanged observer and a sensible packed-array CPU implementation, with exactly identical complete predictions. The package in this directory is queued behind the active 12-worker run.

This recommendation concerns privacy inference. It is separate from v6 wallet proving and historical RISC Zero work.

## Current machine and execution readiness

Read-only SSH to alias forge resolved to luke@10.0.3.141. Forge exposes 14 vCPUs (KVM; CPU model string Ryzen 7 5800X), about 25 GiB total RAM / 18.6 GiB available at inspection, and an idle RTX 3070 with 8,192 MiB VRAM, driver 595.99.02. A VM topology is not proof of four physical laptop cores.

Available: /usr/bin/python3.14; /home/luke/.local/bin/uv; an existing Python 3.12.13 runtime; NVIDIA driver library and device nodes. System package metadata reports NumPy 2.3.5, but no CuPy, PyTorch, Numba, JAX or SciPy. nvcc is absent from PATH and /usr/local/cuda/bin; libnvrtc/libcudart were not listed by ldconfig. No current GPU backend was found in the inspected project paths. The historical expected /opt/kpi/bin/r0vm-cuda and /opt/cuda-target/release/r0vm are absent.

No installation or GPU qualification was attempted. A future isolated environment must establish package and device compatibility. CuPy's official documentation supports installing CUDA component wheels into a virtual environment, without installing a system CUDA Toolkit: https://docs.cupy.dev/en/stable/install.html

## What the current privacy observer actually computes

The active source checkout is /home/luke/projects/kaspa-privacy-shared-pool, HEAD 9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02, with current price-test documentation/code uncommitted. Sources were read, never changed; active evaluation data was not opened.

price_leakage_trial.py launches working_balance_observer.observe() in isolated subprocesses, through a 12-worker controller. The observer uses Python integers, dictionaries, sets, bisect, itertools and Fraction. It has no neural inference, matrix library, solver, beam-search implementation or GPU invocation on this path.

Static hotspots to measure:
- make_sums(), lines 302–351: enumerate payout pairs/triples, reject incompatible owners, subtract eligible known co-inputs within merged amount intervals.
- eligible(), lines 353–363: repeated target/anchor/spent/amount/owner checks.
- books()/split(), lines 383–528: per-target filters, grouped support sets, exact deterministic rankings and first-eight support selection.
- observe(), lines 554–575: pooled view also evaluates the public-only engine.
- price_leakage_score.e_value(), lines 194–219: exact rational inference after predictions are sealed. Keep this on CPU unchanged.

This is predominantly irregular combinatorial Python work by source structure. **Wall time does not establish which function dominates.** The benchmark must profile before choosing the proposed eligibility kernel. It must not alter the attack, candidate cap, support identity, tie-breaking, scalar integer ranges or exact rational score.

A packed CPU control and optional GPU kernel can evaluate independent candidate/target predicates using exact int64 values after checked conversion. Keep enumeration, support deduplication, ranking, SHA-based role choice and final prediction assembly in the unchanged CPU reference. This narrow candidate is deliberately falsifiable: conversion, dispatch, mask transfers and remaining Python loops may erase any GPU gain.

NVIDIA recommends measuring hotspots and minimizing host/device transfers, particularly many small transfers. CuPy requires synchronized GPU timing, and context creation/JIT are real one-time costs. Sources:
- https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/index.html
- https://docs.cupy.dev/en/stable/user_guide/performance.html
- https://docs.cupy.dev/en/stable/reference/generated/cupy.RawKernel.html

## Fixed development evidence and proposed single benchmark

Use the already published historical archive:
 /home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/evidence/2026-10-21-working-balance/public-evidence.tar.gz

Archive SHA-256: 05b3d80d080aa51ec48fed387caecd0197ca64efe141eb18dfa33af5830a5950.
Observer SHA-256: b492d5a2e63836751f51f5151c002c3ec6492c224b518846c45eca23f3ea7495.
This is byte-identical to the current observer and its published rehearsal source pin.

Select the pre-existing final sparse-correlated / partial pair, inputs/observe-1504 and inputs/observe-1505: public C+D and pooled respectively. Both have 173 events, 258 commitments, 76 payout events and 64 targets. There are C(76,2)+C(76,3)=73,150 base pair/triple subsets before co-input expansion. The pooled known-position upper bound is 118; an intentionally loose maximum is 8,704,850 candidate records. At 64 packed bytes each that is about 531 MiB, not a measured Python object footprint. Three maximum public payouts plus fees fit in 39 bits for this fixture; every actual conversion still needs a checked int64 bound.

Retained process receipts show 38.758253 s (C+D), 74.226321 s (pooled); these are historical wall times under contention, not isolated performance claims. Across 1,506 old observer jobs the median was 0.05957 s and maximum 74.226321 s; most small prefixes are poor GPU targets. Old generation/scoring receipts were 0.182/3.542 s. There is no per-function profile or observer peak-RSS measurement in the inspected receipts.

Run one benchmark with three backends, identical fixture bytes and full 13/26 variant outputs:
1. Unchanged reference CPU, including a separate cProfile measurement.
2. Packed-array CPU eligibility control.
3. Optional GPU eligibility filter only if profiling shows eligible() is material.

Require canonical full-prediction equality against retained published outputs and fresh reference outputs, not matching only accuracy totals. Preserve unknown/zero values, partial tails, co-input conflicts, exact support dedup and all rank fields. Keep score code unchanged: identical complete predictions imply identical scores for any fixed truth; this development benchmark does not mount or re-score truth.

Adoption gate: exact equivalence first; then at least 20% lower whole-observer median warm time than BOTH controls for each selected view, and disclose cold-start break-even. No claim of a 512-ledger speedup follows from this one fixture. The GPU gets no adoption credit merely for being occupied.

Resources: sequential workers, at most two assigned vCPUs, 4 GiB sampled process-group RSS stop, 2 GiB GPU pool limit / 3 GiB observed total GPU stop, 300 s per worker and 30 minutes overall after setup. These are development containment budgets, not measured expected peaks. Materialize only two candidate masks per current target rather than a cross-ledger tensor; never share observer inputs across ledgers. Stop on mismatch, overflow, resource breach, unsupported runtime, inability to preserve isolation, absent hotspot or insufficient end-to-end gain. Do not optimize against current held-out outcomes.

CuPy's pool does not include all CUDA context allocations; record total device memory separately. Its default compiler cache is shared, so redirect it and the CUDA cache into this exclusive directory. Source: https://docs.cupy.dev/en/stable/user_guide/memory.html

## v6 wallet proving: separate, currently CPU-only

Current Cargo.toml pins ark-bn254 / ark-groth16 / ark-ff / ark-ec-family 0.6.0 and Rusty Kaspa 01b532e8b553523216471682649693af92f0fd16. harness::prove() calls Groth16::create_random_proof_with_reduction and verifies the result on CPU. Cargo.lock has Rayon and no CUDA/icicle/cudarc/ec-gpu dependency. ldd of the retained wallet executable lists ordinary C/C++ libraries, no CUDA library. This is evidence about this build, not a claim that GPU Groth16 implementations cannot exist.

Already executable under poc/shared-pool/target/release:
- kpi-two-input-wallet: SHA-256 1ee3835b1b0ed3e4c4ca0ce4f5ee1cd6f85b79d19b2cef10a7402ece42e298a3
- kpi-two-input-lifecycle: 67d54d203f5e101deae92c388e0e961132a5896e871215d5e43444343d2382bd
- kpi-two-input-replay: 4e9f84bd1f94aed744690d600227311500d0e8b72d359a4a184914e7c93eb584

Cached crates exist under /home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/{ark-groth16,ark-bn254,ark-ec,ark-poly}-0.6.0. Public SDK/source caches are /home/luke/.cache/kpi-sdk/v2.1.0 and /home/luke/.cache/kpi-source/rusty-kaspa-90dbf074275d60c1fe74a3491883196f110970c0; that latter snapshot is not the pinned validator revision above and is not a substitute.

RFC-0012 and WALLET-LIFECYCLE.md retain material unmet targets:
| Requirement | Target | Relevant retained evidence |
|---|---|---|
| Warm local witness + verified proof | p95 <=10 s | 38.132–39.315 s preparation plus 20.495–21.486 s proof, about 59–60 s |
| Cold ready-to-prove startup | p95 <=60 s | 202.939–205.838 s parameter loads |
| Aggregate wallet peak | <=4 GiB, CPU laptop/16 GB | Earlier same v6 TN10 preflight peak 6.44 GiB; not a complete current wallet peak measurement |
| Ordinary / lifecycle fees | <=1% / <=2% of payment | 0.4 tKAS operation fee is already 4% at 10 tKAS; earlier full workload 5.216205 tKAS |
| Payment / exit / recovery | <=60 s / <=120 s / <=15 min over 10,000 ops | Not qualified on the adopted reference device/workload |

The 4,372,824-constraint relation uses a 962,197,520-byte experimental PK (SHA-256 6f95db952f84420717b3b677e1368bc85776791eb1ccf409cb390a4e4fb39593) and VK 9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef. Runtime checks both hashes, compressed points and embedded VK. No PK was read, copied or loaded here. No wallet benchmark is additionally selected: CPU resources remain reserved for the privacy run and the single proposed observer benchmark.

## Historical Orchard / RISC Zero distinction

The Orchard research note is a design comparison; it explicitly records no code imported or executed. It is not the current v6 proving backend.

The retained RISC Zero outer private-note receipt used an L40S with 46,068 MiB, four CPU threads, 143 segments / 139,763,284 user cycles, 243.088 s, and 13,706 MiB sampled peak GPU memory. It passed separately built CPU verification and native controls. Its measured GPU memory already exceeds Forge's 8 GiB. That exact run proves a different historical statement and cannot benchmark v6 or the current privacy observer.

Its preparation record pins RISC Zero 3.0.3 source 14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6, CUDA 12.8 and sm_89. The original repository is /home/luke/projects/kaspa-privacy-initiative at 7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1. Its AGENTS.md and SECURITY-INVARIANTS.md match those in the shared-pool checkout. Historical build scripts install software and mutate build caches: do not run them as a shortcut. Keep the GPU idle until the isolated observer lane is ready and the resource gate opens.

## Prepared package and dispatch status

**BLOCKED for execution; preparation complete.** BENCHMARK.md is the frozen development specification; benchmark.py is the gated controller; capsule/adapter.py contains the packed CPU and optional CUDA predicate; capsule/worker.py runs one isolated view. manifest.json pins all 18 source/spec/fixture/expected-output files. The public fixture/source capsule is under 1 MiB. No prototype source has been imported, syntax-compiled, tested, profiled or benchmarked during preparation.

Static review checked the predicate against the original owner/anchor/spent/co-input rules, kept all arithmetic/ranking/dedup in the reference, and added canonical whole-output equality against independent published CPU results. This is not runtime validation. The benchmark uses a profile gate before adapter selection, separately measures GPU context/JIT setup, and rejects cold-process regression as well as requiring 20% warm gain against both controls. Expected prediction files are not mounted inside workers.

Prerequisites: parent resource release, a fresh isolated wheel-only environment from SETUP.sh, successful unchanged Bubblewrap/device access, and source/fixture hash verification. No system Python, global environment, active cache, driver or service changes are permitted. Exact future commands and budgets are in BENCHMARK.md. All benchmark outputs are fresh directories inside this exclusive lane. If profiling, compatibility or end-to-end benefit fails, retain that result and leave the GPU idle.
