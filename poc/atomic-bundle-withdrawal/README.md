# Offline atomic-bundle withdrawal test

This experimental runner tests the [frozen question](../../research/atomic-bundle-withdrawal-2026-11-07/SELECTION.md)
with real private wallet payments, blind credentials, separate wallet/service
containers and the unchanged economic kernel. A local read-only directory and
atomic file rename **simulate** an accepted Kaspa payload; no chain connection,
broadcast, funds or consensus change occurs. See the [result](../../research/atomic-bundle-withdrawal-2026-11-07/RESULT.md).

```sh
CARGO_TARGET_DIR="$PWD/.local/ci-target" cargo +1.97.1 build --locked \
  --release --offline --no-default-features --features testnet,round-agreement \
  --manifest-path poc/separated-withdrawal/host/Cargo.toml
python3 poc/atomic-bundle-withdrawal/run.py .local/atomic-bundle/NEW-PRIVATE-RUN
python3 poc/atomic-bundle-withdrawal/export.py \
  .local/atomic-bundle/NEW-PRIVATE-RUN research/atomic-bundle-withdrawal-2026-11-07/NEW-PUBLIC-RUN
```

The runner requires the existing ignored local Testnet-profile parameters,
settlement program, Docker and Tor binary used by the prior round-agreement
test. A failed run keeps its private directory; choose a new name for a retry.
Wallet backups, blinding secrets, issuer key, Tor state and owner truth stay in
`.local` and are excluded by the export allowlist.

Replay the committed public evidence without those secrets:

```sh
python3 poc/atomic-bundle-withdrawal/check.py \
  research/atomic-bundle-withdrawal-2026-11-07/run \
  research/cached-approval-verification-2026-11-07/run/programs/settlement.bin
```

`board-public-check` verifies every blinded RSA reply against its blinded
request using the pinned RFC9474 implementation's public key. Wallets also
verify their own unblinded credential and every proof-backed claim. This
experiment does not assert that a real accepted transaction was published or
that independent users saw it at the same time.
