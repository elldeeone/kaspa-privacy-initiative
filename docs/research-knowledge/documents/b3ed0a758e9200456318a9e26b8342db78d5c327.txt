# Upstream four-batch reproduction on an RTX 3070

Local research, 2026-10-19 Australia/Sydney. Source is upstream
[PR51 at `2525d804`](https://github.com/olafweller/kaspa-privacy-initiative/tree/2525d804bbd34e8b0f4e6c38153d060f30af617c),
which was open when selected. This branch does not merge PR51 or `offline-wallet`.

**All four fresh outer receipts passed on the RTX 3070 8GB.** The complete local
suite, including separate per-batch CPU verification and native checks, took
**627.3 seconds (10m27s)**. Peak sampled matching-process VRAM was **6,096 MiB**;
peak sampled summed process-group RSS was **622.8 MiB**.

| Batch | Observed wall seconds | po2 | User cycles | Segments | Peak sampled VRAM MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| deposit | 27.7 | 16 | 551,028 | 34 | 2,926 |
| credit-transfer | 361.5 | 19 | 93,105,559 | 202 | 6,096 |
| exit | 172.6 | 19 | 43,964,526 | 96 | 6,096 |
| reconcile | 63.7 | 16 | 1,486,804 | 79 | 2,926 |

All four receipts passed the unchanged upstream CPU verifier and 60 cryptographic
negative controls in total. The actual new exit receipt passed local native
issuance and payout checks. Receipt hashes and exact commands are retained in
[evidence/result.json](evidence/result.json) and the individual batch directories.

## Workload and adaptation

This reproduces the four **outer** RISC Zero Succinct statements from upstream:
deposit, credit-transfer, exit and reconciliation. It reuses the frozen public
inputs, including existing inner specialized Groth16 wallet proofs. It does not
generate new inner wallet proofs or private wallet witnesses. Earlier Orchard
wallet timings measure a different workload and are not compared here.

The unchanged upstream producer completed deposit and reconciliation at po2=16.
Credit-transfer at po2=20 failed with a CUDA out-of-memory error while allocating
1,728,053,248 additional bytes (`risc0/zkp/src/hal/cuda.rs:246`). It produced no
receipt; one-second samples missed its short GPU allocation, so they establish
no peak VRAM for that failure. See
[the original error](evidence/original-credit-transfer/stderr.log).

The [one-line host patch](segment19.patch) caps segmentation at
`min(original_po2, 19)`: credit-transfer and exit use 19; deposit and reconciliation
retain 16. The CUDA prover is the retained official SDK3.0.3 source build for
`sm_86`, rather than upstream's `sm_89` L40S build (see [CUDA diff](cuda-sm86.patch)). Its source/build report and
binary hash are retained. The historical build report's
`gpuExecutionQualified=false` is a build-time label; current matching-process GPU
observations and verified receipts are recorded separately.

Guest bytes, image, public inputs, inner wallet proof bytes/VK, complete expected
journals, join control, 160M cycle limit, proof verification and native policy
are unchanged. The host is rebuilt from pinned source with its original lockfile
and Rust 1.95.0. No verifier check is removed to fit the GPU.

- Guest image: `794cfff4cfa509799ec1f6750678d3fe4bc8623522aa647cc65e6b53955c4bc9`.
- Guest bytes SHA256: `213ed12a0f0b514443fcab9608de5d42e0961fc6704fd51d49326106ead1e375`.
- Join control: `7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e`.
- Upstream public archive: `f28dfcea27c8c357cece022b7036f013895d907a48b151c4e45d9700f3c2e5a0`.
- CPU verifier: `d9ee19513d2ba2b4296e0e9c4199c175ba2d0948b0f130d3df53a5e875415109`.
- Local CUDA prover: `3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7`.

## Verification and measurement

Before proving, upstream's CPU audit checked 76 retained files and reverified its
four real receipts, exact journals, cryptographic negative controls and local
native exit. The [audit log](evidence/upstream-cpu-audit.log) and
[retained-receipt reports](evidence/retained-cpu/verification.json) are preserved.

Fresh receipts are checked in separate CPU processes by the unchanged upstream
executable. Each check authenticates the exact program, complete 352-byte journal,
join control and empty assumptions with development mode disabled. It runs 15
negative controls per receipt: wrong image, 11 journal-field mutations, corrupt
seal, corrupt inclusion proof and wrong expected control. The new exit receipt
also passes the existing local native issuance/restricted-payout path.

The adapted host's retained test accepts all four fixed targets and rejects fake
receipts. Separate package mutations of guest bytes, input bytes and expected
journal bytes fail before proving. See [host tests](evidence/segment19-host-test.log)
and [package controls](evidence/package-negative-controls.log).

The local harness uses four CPU cores/compute threads and samples process-group
RSS plus matching-process VRAM approximately once per second. Samples can miss
peaks; summed RSS can count shared pages twice. Time includes startup and polling
granularity. Initial small-batch exploration and part of the adapted deposit
overlapped local Rust compilation. CPU affinity does not isolate the whole host.
These are local feasibility measurements, not a controlled performance comparison
with the L40S.

The suite passes each batch the remainder of one 3,600-second allowance. GNU
`timeout` supervises each active proof group; CPU rechecks follow separately.
This local command-line harness does not reproduce the remote worker, provider
guard, image/container environment or rental orchestration. There is no provider
interaction. [Provenance](evidence/provenance.json) records exact dependencies,
source/binary hashes and hardware; [result](evidence/result.json) records receipts.

## Repeat CPU verification

Obtain `poc/private-native-proof/evidence/public-package.tar.gz` from the pinned
upstream source above, then run:

```bash
python3 poc/upstream-reproduction/check_evidence.py \
  poc/private-native-proof/evidence/public-package.tar.gz
```

The checker authenticates the archive and verifier hashes, checks retained file
hashes, then runs only the pinned CPU verifier. It generates no proof and uses no
GPU, network, wallet backup or private witness. The verifier is an upstream
prebuilt artifact: separate processes do not provide an independent cryptographic
implementation, and this exercise does not independently rebuild the guest.

## Repeat fresh proving

1. Check out upstream commit `2525d804bbd34e8b0f4e6c38153d060f30af617c`
   in a separate directory. Before applying the patch, run its
   `poc/remote-cuda/lifecycle_package.py restore NEW_PACKAGE` to authenticate and
   restore the fixed public inputs and original CPU verifier.
2. Build RISC Zero from commit `14b5d588dd01cf4f7ba804d8bb0a61264e6ae2c6`
   with `cuda,disable-dev-mode` and `NVCC_APPEND_FLAGS=-arch=sm_86`.
   [The retained build script](evidence/cuda-build-sm86.sh) documents the original
   disposable-container build; it installs packages and is not a host setup command.
3. Apply `segment19.patch` in the pinned checkout. Build with its unchanged lock:

```bash
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=NEW_TARGET \
  cargo build --locked --release --manifest-path poc/private-native/Cargo.toml \
  --features proof --bin kpi-private-native-proof
```

Use absolute paths for `NEW_PACKAGE`, the CUDA prover and the rebuilt host.
From this reproduction branch run the following for `deposit`, `credit-transfer`,
`exit`, then `reconcile`, using a fresh output directory for each:

```bash
python3 poc/upstream-reproduction/run_batch.py NEW_PACKAGE R0VM_CUDA CASE NEW_OUTPUT \
  --producer NEW_TARGET/release/kpi-private-native-proof --seconds REMAINING_SECONDS
```

For a complete suite, pass the remaining shared hour rather than resetting its
allowance between cases. [The stored suite log](evidence/adapted-suite.log) and
per-batch `invocation.json` files retain the actual commands. Output directories
must not already exist. Failure and candidate receipts remain available; there
is no automatic retry. Both producer and independent CPU verification reject
development mode. The upstream fixed package and reviewed source, not returned
GPU metadata, supply verifier expectations.

## Limits and adversarial second pass

The source change alters segmentation in the host; it does not alter guest
authorization, value conservation, spentness, state/lane binding or withdrawal
rules. The unchanged verifier checks new receipts, including cryptographic
mutations. Missing/failed proving yields no accepted receipt. No new service,
operator privilege, withdrawal key or reserve path is introduced.

The native check uses synthetic UTXOs, anchor and spentness fixtures. Its parent
invocation verifies the actual new exit receipt; its nested payout helper still
has upstream's standalone synthetic-issuance label and does not verify another
receipt. The fixture pays 400,000,000 sompi principal plus 50,000,000 permission
rent refund, retains 600,000,000 reserve change and excludes 100,000,000 state rent.
Underpayment, diversion and wrong-recipient controls reject locally.

This establishes neither canonical Kaspa history nor consensus transaction
acceptance, funded deposit/issuance, actual native payout, independent recovery,
privacy against timing/network observers, cryptographic correctness or production
safety. Reorg/stale-state behavior and service-loss recovery are not exercised
beyond existing fixed checks. Fixture origins, upstream binaries, verifier SDK
and setup/VK remain trust dependencies. GPU proving receives public fixtures,
so this run does not establish confidential proving for private user witnesses.

No mainnet use, real funds, funding, broadcast, rental, commit, push, merge or
upstream posting is included. This report is AI-assisted reproduction evidence,
not independent expert security review.
