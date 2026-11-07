# Wallet round-agreement and reply-timing test

This local-only experiment uses the actual private-payment wallet, blind
registration and unchanged whole-set withdrawal checks. It requires no real
funds or consensus changes. Read the [selection](../../research/round-agreement-2026-11-07/SELECTION.md)
and [result](../../research/round-agreement-2026-11-07/RESULT.md).

Build with the Testnet-profile parameters already present locally:

```sh
CARGO_TARGET_DIR="$PWD/.local/ci-target" cargo +1.97.1 build --locked \
  --release --offline --no-default-features --features testnet,round-agreement \
  --manifest-path poc/separated-withdrawal/host/Cargo.toml
python3 poc/round-agreement/run.py .local/round-agreement/NEW-PRIVATE-RUN
```

The runner makes new local wallet/service containers for honest, tagged and
staggered-service arms. It has no remote-host code. It needs the existing local
parameters/settlement program and Docker/Tor assets referenced by the prior
separated-withdrawal experiment. Wallet backups, issuer keys, blinding state and
owner scoring truth remain under `.local`.

Public evidence is exported by a reviewed allowlist. Replay it with:

```sh
python3 poc/round-agreement/check.py \
  research/round-agreement-2026-11-07/run \
  research/cached-approval-verification-2026-11-07/run/programs/settlement.bin
```

The read-only `agreement-check` command validates a wallet's own saved public
issue response and a supplied redemption configuration without redeeming or
using the network. `guard-controls.py` runs ten genuine/mutated cases against a
private wallet copy; its summary contains no wallet secrets.
