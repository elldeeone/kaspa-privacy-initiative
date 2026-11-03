# Fixed-claim B2 proving performance

This host-only diagnostic reuses the reviewed public S7 initial-pair guest,
input and successful claim. It selects segment18 with the existing RISC Zero
SDK3.0.3 IPC or actor backend. It changes no circuit, setup, state rules or
native transaction. See [the experiment plan](../../research/next-session/AGGREGATE-COST-DESIGN.md)
and [the separate 8 GiB actor profile](../../research/next-session/actor18-8gib/SPEC.md).

Build with Rust1.95 and the locked existing source/dependencies:

```sh
cargo build --locked --release --manifest-path poc/s7-proof-performance/Cargo.toml
```

With the dependency cache present, add `--offline`. The qualified experiments
used a private target/cache, isolated networking, an immutable selected client,
read-only public input/program/tool mounts and bounded owned process groups.
Generated executables and runtime caches are local artifacts, not Git data.
Rebuilding the original guest/program requires the pinned official guest
compiler and original guest source recipe; see the repository reproduction and
omitted-artifact records. An arbitrary co-located program/image pair is not a
trusted substitute for the selected image.

The binary interface is:

```text
kpi-s7-proof-performance ipc PROGRAMS INPUT NEW_OUTPUT
kpi-s7-proof-performance actor PROGRAMS INPUT NEW_OUTPUT
```

It requires an explicit matching `RISC0_PROVER`, the exact qualified worker at
absolute `RISC0_SERVER_PATH`, and no development mode. Actor additionally
requires `RISC0_DEFAULT_PROVER_NUM_GPUS=1`. The input, wrapped program, expected
image, J336 and successful claim are checked against the selected original
profile. Every candidate is fsynced before backend shutdown and checked with
the SDK and official decoded control root; an independent process must verify
the retained receipt afterward.

Actor does not forward the SDK ProverOpts/VerifierContext/session limit. Its
paging/reserved-cycle fields are unavailable placeholders. These limitations
are explicit, while final genuine Succinct receipt/claim/journal/control and
no-assumptions checks remain mandatory. Startup, API response and backend
cleanup are reported separately; IPC API time may contain its own worker
startup/cleanup. Stage markers describe host/prover intervals, not isolated
CUDA kernel timings.

The original6656 MiB actor admission failure stays immutable. The separately
selected actor18-8gib profile uses a7680 MiB sampled guard on an8192 MiB card;
measured memory fit is an empirical outcome, not a static allocation proof.
A single GPU diagnostic does not qualify R8's CPU-only wallet, p95 payment
latency, all-in fees or financial privacy. No funding, broadcast, owner/replay
workflow, withdrawal or recovery operation is included.
