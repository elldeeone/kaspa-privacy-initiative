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

## Testnet-10 continuation

The [fresh live result](../../research/atomic-bundle-withdrawal-2026-11-07/TESTNET-RESULT.md)
publishes one complete bundle through an ordinary TN10 transaction and runs
the full private-payment, withdrawal and restored-key path. It uses the same
host and two public RPC operators; it is not an independent-user or production
privacy result. The [frozen selection](../../research/atomic-bundle-withdrawal-2026-11-07/TESTNET-SELECTION.md)
specifies the integer-sompi fixture and stop rules.

Build the cached-payment host with the experimental board check, create a
fresh **unfunded** identity in one command, and prepare an ordinary test-coin
source envelope plus private `CONFIG.json` as described in the
[cached-payment trial guide](../cached-approval-verification/README.md):

```sh
CARGO_TARGET_DIR="$PWD/.local/ci-target" cargo +1.97.1 build --locked --offline \
  --release --no-default-features --features testnet,round-agreement \
  --manifest-path poc/cached-approval-verification/host/Cargo.toml
.local/ci-target/release/kpi-cached-approval-verification \
  fresh-board-trial SETTLEMENT_PROGRAM PRIVATE_PARAMETERS NEW_PRIVATE_TRIAL
python3 poc/atomic-bundle-withdrawal/testnet.py NEW_PRIVATE_TRIAL/CONFIG.json
python3 poc/atomic-bundle-withdrawal/export-testnet.py \
  NEW_PRIVATE_TRIAL NEW_PUBLIC_OUTPUT
python3 poc/atomic-bundle-withdrawal/check-testnet.py NEW_PUBLIC_OUTPUT
```

`testnet.py` checks onion reachability before funding, makes three issue
requests concurrently, requires the exact accepted bundle at each wallet,
then checks final native payouts and five restored-key spends. A failed trial
keeps all evidence and requires a new identity. Wallet backups, issuer key,
source key, onion state and proving parameters must stay under ignored `.local`.
The public checker replays the accepted payload, service-only observer,
three reader receipts, linked fees and exact payout-spend links; the first
funding input and bundle fee source are not independently fetched. It does not
prove independent chain header validation or global anonymity.
