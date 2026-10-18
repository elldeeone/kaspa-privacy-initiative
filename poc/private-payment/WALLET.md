# Full offline wallet prototype

Implementation of the reviewed two-slot Orchard V2 relation, under
[ADR-0020](../../docs/adr/0020-offline-wallet-relation.md) and the
[acceptance plan](WALLET-PLAN.md). [Four real proofs and restore results](WALLET-RESULTS.md)
are recorded separately. No mainnet, testnet broadcasts or real funds.

## Boundaries

`wallet-core` implements exact public/witness decoding, full spending-key and
scope derivation, depth-32 hidden membership for positive inputs, dependent
nullifiers, V2 output commitments and complete incoming encryption, checked
u128 balance and the kind/mode restrictions. `wallet-guest` proves this exact
code and commits only the 229 reviewed journal bytes. It has no embedded pool
policy or own-image constant.

`wallet-host` prepares fresh unfunded fixtures, proves/verifies succinct
receipts, exercises the native relation, admits receipts against explicit
synthetic immutable policy, and rebuilds/scans complete pinned synthetic
history. All eight context fields and the actual verified image are checked
before current spentness. Initial allowed roots contain exactly the Orchard
empty root. Credits consume pending principal without adding reserve twice;
exits create unpaid backed claims. Rejections preserve economic state and
advance the synthetic cursor. An old allowed root does not reset nullifiers.

The adapter and history origin are locally trusted **host code**, not a proved
outer classifier or authenticated Kaspa history. Malformed receipt envelopes
and unavailable data may halt this harness; it does not satisfy total R13.
Native descriptor recognition, bootstrap, credit/refund and payout scripts,
confirmed native reserve release and independently operated R16 remain open.

## Build

Use the pinned guest toolchain and sm86 CUDA setup described in
[the primitive build instructions](README.md#public-primitive-vm-experiment).
Build new crates with their own checked-in locks; existing evidence locks and
qualified CUDA binaries are unchanged.

```bash
cargo build --locked --release --manifest-path poc/private-payment/wallet-host/Cargo.toml
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR=NEW_GUEST_TARGET \
RUSTC=PINNED_GUEST_TOOLCHAIN/bin/rustc RISC0_FEATURE_bigint2=1 \
RUSTFLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"' \
cargo build --locked --release --target riscv32im-risc0-zkvm-elf \
  --manifest-path poc/private-payment/wallet-guest/Cargo.toml
```

Wrap the resulting guest ELF with the unchanged pinned CPU wrapper's `wrap`
command. The wallet image is computed after build and inserted into synthetic
policy/intents; never substitute the primitive probe image. Record exact source,
locks, toolchain, wrapped bytes, host and CUDA identities with results.

## Run with fresh local directories

Use a private task directory. `prepare` generates unfunded secrets from the OS
CSPRNG, rejection-samples through established constructors and fails on entropy
errors. It creates a CREDIT of 1000 synthetic sompi, a two-real-input TRANSFER
of 600 to Bob plus 400 internal change to Alice, and Bob's no-change EXIT.
Both dummy outputs are still constrained in `exit_only` mode.

```bash
wallet-host prepare WRAPPED_WALLET_PROGRAM NEW_CASES
wallet-host check-native NEW_CASES NEW_NATIVE_REPORT.json
python3 poc/private-payment/run_wallet_negatives.py WALLET_HOST CUDA_BUILD \
  NEW_CASES/negative-vm NEW_NEGATIVE_VM_RESULTS
python3 poc/private-payment/run_wallet.py PUBLIC_PACKAGE CUDA_BUILD WALLET_HOST \
  NEW_CASES/credit NEW_PROOFS/credit
```

Run the same proof command for `transfer` and `exit`, sequentially. Each run
executes the guest, proves on the 3070 with po2=19, requires matching process GPU
activity and re-verifies saved receipt bytes in a separate CPU process.
Development mode, non-succinct receipts, wrong image/journal, noncanonical
bincode receipt envelopes and unresolved assumptions reject. A shared decoder
requires deserialize/serialize byte equality; trailing bytes or a concatenated
second receipt cannot alias one canonical receipt. Defaults pin the existing RISC Zero 3.0.3 verifier parameter
set; the measured parameter digest is retained with each proof. CPU verification
uses the same pinned SDK and is not independent cryptographic assurance.

After those three receipts exist:

```bash
wallet-host exercise NEW_CASES NEW_PROOFS NEW_RESTORE_RESULTS
python3 poc/private-payment/run_wallet.py PUBLIC_PACKAGE CUDA_BUILD WALLET_HOST \
  NEW_CASES/restored-exit NEW_PROOFS/restored-exit
wallet-host finalize NEW_CASES NEW_PROOFS NEW_FINAL_RESULTS
```

`exercise` verifies every full operation/receipt before scanning, checks double
spends and duplicate exits after restore, wrong contexts, two distinct valid
CREDIT signatures on the same intent, expiry/cursor/capacity boundaries, changed
ciphertexts and incomplete history. Duplicate backup keys are rejected by decoded
key bytes, including hex aliases. A deliberately false receipt between valid
operations is classified by the host verifier and replayed as a no-op; this is
not an outer invalidity proof. The altered Ed25519 nonce-prefix API exists only
in that adversarial control; honest signing always uses the standard signer.

Alice's restored internal change is reconstructed from her own backup and
verified public ciphertext history, then used to prepare `restored-exit`.
`finalize` checks that proof and repeats current-spentness replay controls. All
1000 synthetic sompi then remain unpaid exit liabilities; no native payout or
reserve drain is asserted.

## Restore without original witnesses

```bash
wallet-host restore HISTORY.json EXTERNALLY_TRUSTED_HISTORY_SHA256 NEW_PROOFS \
  OWN_BACKUP.json NEW_RESTORE_REPORT.json
```

The expected latest history digest must come from the caller's trusted synthetic
checkpoint, not the received history itself. The pin binds the full policy,
order, intent, ciphertext, authorization and receipt identities. Replay verifies
every receipt and rebuilds current state before local decryption in both scopes.
Missing/truncated/changed/foreign history is unavailable, never zero balance.
The command does not read original private witnesses or another user's keys.

Alice/Bob have distinct backups. Required inventory is Orchard spending key(s),
profile/context and every independently sampled pending-deposit Ed25519 seed
with full reference/principal metadata. Orchard keys alone do not recover an
uncredited deposit. Outgoing audit history is not recovered by this incoming-only
profile. A joint backup remains only a private lab fixture.

These research backups are plaintext 0600 files inside a private task directory;
this is not a production encrypted backup, hardened secret-memory or secure
storage implementation. Never archive or publish backups or witness inputs.
Only public intents, authorization, receipts, source identities and bounded
reports belong in evidence. Receipt/profiling timing and execution cost can
reveal workload differences; no constant-time or anonymity claim is made.

## Verify retained public evidence without secrets

```bash
wallet-host verify-history PUBLIC_HISTORY.json TRUSTED_MANIFEST_HISTORY_SHA256 \
  PUBLIC_PROOFS NEW_PUBLIC_VERIFICATION.json
```

This command verifies every retained receipt/full public operation, current
spentness and aggregate synthetic state. It reads no backup or original witness.
The published artifact manifest supplies the expected synthetic history digest;
it does not authenticate native Kaspa history. The fixture-specific `verify`
command additionally reads the original local witness to check preparation hashes
and is not needed to verify the public archive.

## Known typed-helper limitation

`Intent::journal()` expects a shape-validated typed intent and can panic if a
local caller directly constructs malformed ID widths. Wire decode, guest
validation and host admission shape-check before using it. The separate code
review found no untrusted-input acceptance bypass from that helper precondition;
it remains an API hardening item. Exact proved core/guest sources are frozen
with the receipt evidence rather than silently changing an image mid-run.
