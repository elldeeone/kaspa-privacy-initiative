# Private payment P1 preparation

This package fixes a reviewable candidate suite and public intent bytes,
compares established Orchard APIs with published vectors, measures a public
primitive in the actual proving VM, and probes the owner's testnet node without
signing or submitting transactions. The subsequent [offline wallet prototype](WALLET.md)
implements the full relation; [GPU proof and restore results](WALLET-RESULTS.md)
are recorded separately. Native R13/R16 remain open.

See [RFC-0004](../../docs/rfc/0004-private-payment-suite-and-encoding.md),
[ADR-0018](../../docs/adr/0018-private-payment-implementation-package.md),
[candidate manifest](suite-candidate.json), [results](RESULTS.md),
[review handoff](REVIEW-PACKAGE.md) and [adversarial self-review](ADVERSARIAL-REVIEW.md).
The owner-selected [separate-agent review](REVIEW-RESULTS.md) found four design
blockers, fixed and re-reviewed under
[ADR-0019](../../docs/adr/0019-separate-agent-prototype-review.md). Unfunded
offline wallet implementation may now proceed using synthetic fixtures.
The full offline wallet now has four genuine GPU receipts and own-backup
restore evidence. External audit, proved outer transitions and native
qualification remain open.

The later [recovery-auth supplement](RECOVERY-AUTH-RESULTS.md) adds exact
candidate signature checks, CREDIT tuple interoperability and proposed private
witness/journal bytes. Its native-binding source analysis identifies why a
shared deposit address alone cannot identify the recovery authority. It does
not implement the full wallet/native path; the first evidence archive remains
unchanged.

See the [full offline wallet prototype](WALLET.md) for the subsequent guest,
real-receipt and restore work. Primitive measurements below retain their original
scope and identities.

## Reproduce the interoperability checks

Use the checked-in Cargo locks; no development receipts or funded keys.

```bash
cargo build --locked --release --manifest-path poc/private-payment/primitive-vectors/Cargo.toml
poc/private-payment/primitive-vectors/target/release/kpi-private-primitive-vectors \
  poc/private-payment/vectors/upstream-orchard.json \
  poc/private-payment/vectors/depth32-reference.json NEW_PRIMITIVE_REPORT.json
python3 poc/private-payment/check_wire.py \
  poc/private-payment/primitive-vectors/target/release/intent_codec \
  poc/private-payment/vectors/upstream-orchard.json NEW_WIRE_RESULTS
```

Nine structural public intents must match Python/Rust encoders, round-trip the
Python decoder and equal the retained golden corpus. They include absent/zero/
maximum expiry, maximum u64 amounts, both exit modes and malformed cases. Their
unrelated published crypto fields and synthetic IDs are **not valid payments**.
The scripts do not enforce actual proof authority, current spentness, native
script policy or economic conservation.

`extract_vectors.py ORCHARD_CHECKOUT NEW_JSON` re-extracts public vectors from
the exact clean pinned source files. `make_depth32_vectors.py
ZCASH_TEST_VECTORS_CHECKOUT UPSTREAM_JSON NEW_JSON` uses the separately pinned
upstream Python reference to recompute three full-depth paths. Both published
encryption corpora are checked, even where their input rho differs. The
resulting fixture files include source hashes and scope labels.

## Public primitive VM experiment

`primitive-probe-guest` reads 115 runtime bytes from a published upstream vector,
derives the full key/address relationship, constructs one V2 note and computes
its commitment/nullifier. It commits a distinct diagnostic tag and those two
outputs. It has **no** payment intent, balance equation, membership, delivery,
spentness or native authorization. Do not accept its image as a wallet verifier.

Build with the locally pinned RISC Zero Rust toolchain used by
`poc/lane-completeness/bootstrap.sh`: release `r0.1.97.0`, archive SHA-256
`100b597d605b706bec94e1d32bfaaf5851df8d75173f986d4b56a3e90916be53`.
Download/extract into a task directory and set `RUSTC` to that binary; do not
replace the host toolchain. The measured native client uses host Rust 1.95.0.

```bash
CARGO_BUILD_JOBS=4 \
CARGO_TARGET_DIR=TASK_GUEST_TARGET \
RUSTC=TASK_TOOLCHAIN/bin/rustc \
RISC0_FEATURE_bigint2=1 \
RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"' \
cargo build --locked --release --target riscv32im-risc0-zkvm-elf \
  --manifest-path poc/private-payment/primitive-probe-guest/Cargo.toml

python3 poc/private-payment/prepare_probe.py \
  TASK_GUEST_TARGET/riscv32im-risc0-zkvm-elf/release/kpi-orchard-primitive-probe \
  PINNED_PUBLIC_PACKAGE/bin/kpi-takeover-host NEW_PUBLIC_CASE
python3 poc/private-payment/run_probe.py \
  PINNED_PUBLIC_PACKAGE QUALIFIED_CUDA_BUILD \
  poc/private-payment/primitive-vectors/target/release/probe_host \
  NEW_PUBLIC_CASE NEW_VM_RESULTS
```

The wrapper identity is checked against the original pinned public CPU host.
The measured guest/client locks align RISC Zero transitive versions with that
tested host; an initial unexecuted guest build with newer transitive patches is
retained separately. The unchanged [qualified sm86 CUDA binary](../remote-cuda/LOCAL.md)
performs IPC proving at po2=19, four compute threads and a generous two-hour
proof limit. Sampled RSS limit is 20GiB. Require a genuine succinct receipt,
exact predeclared image/journal, successful exit, no unresolved assumptions,
mutation rejection and positive matching-prover GPU SM activity. A distinct CPU
process reloads the saved receipt; it shares the pinned SDK and is not an
independent cryptographic audit or second verifier implementation.

To verify retained evidence without running the GPU or contacting the node,
extract the archive linked in [results](RESULTS.md), then run:

```bash
poc/private-payment/primitive-vectors/target/release/probe_host verify \
  EXTRACTED/measurements/primitive-case-aligned \
  EXTRACTED/measurements/primitive-vm/proof/candidate-receipt.bin NEW_CPU_VERIFICATION
```

It must match the exact retained case/image/journal, not an expectation copied
out of the receipt. Development mode must be absent.

## Read-only testnet preflight

Requires Node with built-in WebSocket support (measured with Node 24).

```bash
node poc/private-payment/probe_node.mjs ws://10.0.3.26:18210 NEW_NODE_RESULTS
```

The allowlisted methods only read public node state. Each gets a fresh socket,
so an unknown RPC closing a connection cannot contaminate the next result.
Require synced/indexed Testnet-10 before probing. Full history is sampled after
a short chain-advance interval; counts are observations, not authenticated lane
or settlement proofs. No SSH, node configuration change or broadcast occurs.
No private trial wallet or funding request is created before the reviewed
cryptographic/native path and actual fee budget exist.

## Rights and evidence

Orchard and Zcash test vectors are dual MIT/Apache-2.0; this package selects MIT
for the derived public vector material. Their copyright/permission notices are
in `licenses/`. No RAILGUN circuit source is copied. Source pins, dependency
locks, source refresh, public inputs/expected outputs, raw reports and retained
primitive receipt are indexed by the evidence manifest linked from results.
The public wrapped guest program is retained so its image can be recomputed.
Host executables, toolchain archives and funded/private wallet keys are not
part of the public evidence archive.
