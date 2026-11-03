# Fresh KPX2 TN10 rehearsal identity

From the repository root, one network-free command creates an **unfunded**
private trial outside Git:

```sh
python3 -B poc/future-testnet/trial.py new --network testnet-10 /absolute/new/private-trial
```

The destination parent must exist. Existing destinations, symlinks, Git worktrees
(including ignored subdirectories), other networks and a changed SDK are rejected.
Defaults use the existing task-local recipient bridge and cached official2.1.0
SDK; `--bridge` / `--sdk` permit explicit paths. No install, RPC, funding,
broadcast, build or setup occurs. Only public keys enter the SDK address adapter;
secrets enter the established RustCrypto/libsecp bridge on stdin.

`profile.json` and seed-only `backups/{alice,bob,charlie}.json` are0600 below a
0700 directory. Backups are saved before invoice generation. `public/identity.json`
contains addresses and V2 invoices, no secrets. The immutable profile starts with
no selected VK, suite or funding UTXO. Publish only deliberately selected public
evidence; never copy the profile, backups, private vectors or proving key to Git.

The fresh note/NF/circuit domain is exactly
`SHA256(b"KPX2/TN10/TRIAL/v1\\0" || TN10genesis32 || nonce32)`, where the quoted
tag denotes a single terminating NUL byte and nonce32 is fresh OS randomness.
Fixed TN10 genesis is
`f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370`.
Tags and wire formats remain KPX2; a trial UUID alone is not domain isolation.

```sh
python3 -B poc/future-testnet/trial.py materialize /absolute/new/private-trial
```

This creates an isolated source workspace. Its explicit allowlist copies only
current pure/native source+locks, the separate private-trial proof runner,
compile-time public known answers, and the V2 recipient module. It replaces
exactly the two compiled DOMAIN arrays, validating
their previous bytes, and records every original/generated SHA256. No fixture,
PK, VK or selected-development key pin is copied. Old known-answer tests remain
unchanged and use their original domain; they are provenance, not fresh-domain
test qualification. The materialized packages need matching **fresh setup and
VK** before use. Build/setup and finite lifecycle orchestration are separately
implemented in this directory; they never reuse the public DO_NOT_FUND instance.

```sh
cd poc/future-testnet
python3 -B -m unittest -v test_trial.py
```

The finite tests create/remove private trials in OS temporary directories outside
Git. They exercise freshness, permissions, exact address/SPK generation, secret
exclusion, rejected networks/paths/genesis/domain/SDK, and exact source
substitution. They do not establish chain acceptance or confirmed payouts.

Source reuse: official native pin01b532e/TN10 genesis, official cached SDK2.1.0
(JS/WASM/package SHA pins in `trial.py`), and the existing reviewed recipientV2
and Rust bridge. [ADR0046](../../docs/adr/0046-fresh-private-testnet-rehearsal.md)
defines the bounded rehearsal and remaining trusted node/archive assumptions.
The old S7 workflow remains parked.
