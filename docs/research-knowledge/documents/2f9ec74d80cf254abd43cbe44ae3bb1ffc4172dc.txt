# One public v6 proof inside a RISC Zero guest

This is a **nonsettling compatibility diagnostic** for one already public
rehearsal proof. It does not implement the two-bundle contract, hide the source
grouping, authenticate accepted state, establish current spentness, release KAS,
or generate a receipt. The existing pool and its setup are unchanged.

The isolated common module compiles the exact 328-byte public verification key,
checks its digest and canonical curve/subgroup decoding, and constructs the
existing accelerated verifier only after those checks. The guest receives
exactly `authorization[377] || proof[128] || ciphertext0[185] || ciphertext1[185]`.
It checks the narrow mode-1, zero-payout profile, bounded integer fee, active
nullifier/commitment shape and original ciphertext order. It derives the two
little-endian 128-bit authorization-digest limbs and runs the existing checked
Arkworks 0.5/substrate-bn Groth16 verification equation.

The diagnostic journal is exactly `KPI1V6J1 || SHA256(the 875-byte bundle)`:
**40 bytes**, deliberately different from the proposed two-bundle 42-byte
`KPI2V6J1` journal. Hashing this already public source bundle supplies no privacy
benefit and would expose grouping if reused on otherwise unpublished bundles.

Only these source fixture files are read, under their original exact SHA-256
pins: `rehearsal/descriptor.json`, `verification-key.json`, and
`rehearsal/chain-confirmed.json` in the retained
`poc/shared-pool/evidence/2026-10-20-two-input-tn10/` directory. The selected
transaction is fixed at `/transactions/6/transaction`. Its source-supplied ID is
an identity check; this diagnostic does not recompute consensus identity or
recheck historical chain acceptance.

## Reproduce

The existing source contract and its boundary cross-review were inspected before
implementation. No new primitive, setup, wallet secret or recovery job is used.
The dependency locks explicitly retain SDK 3.0.3, binfmt/zkp 3.0.4 and recursion
4.0.4. The established accelerated helper remains at substrate-bn commit
`22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509` and Arkworks 0.5.0.

Use the separately retained, hash-verified official tools. No global Rust
toolchain link or installation is required:

```sh
export CARGO_TARGET_DIR=/absolute/task-target
cargo +1.95.0 test --offline --locked --release --jobs 6 \
  --manifest-path poc/v6-guest-compat/Cargo.toml

RUSTC=/absolute/tools/risc0-rust/bin/rustc \
RISC0_FEATURE_bigint2=1 \
RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"' \
  /absolute/tools/risc0-rust/bin/cargo build --offline --locked --release \
  --jobs 6 --target riscv32im-risc0-zkvm-elf \
  --manifest-path poc/v6-guest-compat/guest/Cargo.toml

/absolute/task-target/release/kpi-v6-guest-compat-host prepare /new/public-fixture
/absolute/task-target/release/kpi-v6-guest-compat-host wrap \
  /absolute/task-target/riscv32im-risc0-zkvm-elf/release/kpi-v6-guest-compat-guest \
  /new/programs
```

Before executing a changed build, independently review and freeze its source,
locks, tool hashes, raw ELF, wrapped program and expected image. The execution
host contains the reviewed expected image as a compiled constant, independently
of the supplied program directory. Changing both a program and its adjacent
`expected-image.txt` cannot satisfy that constant. Merely generating the text
file is not independent image authentication.

```sh
RISC0_PROVER=ipc RISC0_SERVER_PATH=/absolute/tools/r0vm \
  /absolute/task-target/release/kpi-v6-guest-compat-host execute \
  /reviewed/programs /new/execution valid
```

Execution cases are `valid`, `trailing`, `truncated`, `wrong-domain`,
`wrong-ciphertext`, and `changed-count`. Rejection controls require the exact
guest rejection marker and expected error class; resource/IPC errors fail the
qualification. Development mode must be absent. Use an enclosing process-group
or systemd resource limit for every guest run. The host's 160-million-cycle limit
is a generous diagnostic ceiling, not a new production budget.

The local campaign is capped at six CPUs, 8 GiB RAM, no swap, with a separate
wall deadline. There is no proof command or GPU path in this diagnostic.

## Evidence

`evidence/build-freeze.json` records the first exact source/build identity before
execution. Large public artifacts, official tools and logs remain in the
separate task target directory; their absolute paths and hashes are recorded.
The native tests check the retained proof, a changed first public input reaching
actual pairing rejection, identity A/B/C, malformed proof bytes, wrong arity,
strict framing/profile/range rules and ordered ciphertext binding.

Passing those tests is evidence about these tested inputs and implementations,
not a cryptographic audit or general Arkworks acceptance-equivalence proof.
