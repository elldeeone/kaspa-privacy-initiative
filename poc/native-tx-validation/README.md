# Unfunded native-draft authorization

Real local signatures and complete Halo2 verification for the
[proposed native transaction](../../docs/spec/native-shielded/transactions.md).
Scope: [ADR-0104](../../docs/adr/0104-unfunded-native-draft-authorization.md).

```sh
bash poc/native-tx-validation/check.sh
```

The three **public synthetic** examples use newly generated proofs/signatures:

1. Deposit: two fake ordinary UTXOs (70 Schnorr + 42 ECDSA), 11 ordinary change,
   100 shielded value and fee 1, all integer sompi.
2. Private spend: Alice's real 100 note to Bob 60 and Alice change 39, fee 1.
3. Withdrawal: Bob's real 60 note to an ordinary ECDSA output 59, fee 1.

All keys and the RNG seed are public. Never use them for live funds. No network
is activated, contacted or funded. Ordinary outpoints are invented. Pool state
and funding records are explicitly supplied synthetic context. Both ordinary
signatures and the two RedPallas roles authorize the draft's actual `S`; its
complete repaired Orchard V2 proof uses the fixed upstream research key.

The Rust codec checks bounded native-v2 framing and role-specific encodings.
Python independently reconstructs Q, ordered input context, IDs and signature
preimages and checks the earlier frozen specification comparator. Rust tests
exercise actual proof/signature rejection separately from contextual failures.
The [adversarial review](REVIEW.md) records the evidence boundary.
The [verification receipt](VERIFICATION.json) binds exact artifacts, dependency
identities, prior-file preservation and executed checks.
Twenty integration tests pass, including all 9,641 strict prefixes of the
deposit packet, 96 deterministic bit flips and a distinct valid Schnorr
authorization with unchanged economic ID and changed full hash.

Regenerate into a separate ignored folder and compare the 10 files:

```sh
export CARGO_TARGET_DIR="$PWD/.local/orchard-interop/target"
cargo +1.95.0 run --release --locked --manifest-path poc/native-tx-validation/Cargo.toml -- generate .local/native-authorization-reproduction
diff -r poc/native-tx-validation/vectors .local/native-authorization-reproduction
cargo +1.95.0 run --release --locked --manifest-path poc/native-tx-validation/Cargo.toml -- check-fixtures poc/native-tx-validation/vectors
```

`python3 poc/native-tx-validation/reproduce.py` performs generation, exact
comparison, independent parsing and fresh-process verification in a unique
ignored directory. CI runs the checks and this complete reproduction.

`check-fixtures` uses the fixed public synthetic funding map. Its roots and
balance are test inputs; it does not replay or authenticate the history. A local
success report is not a spend permit or a native transaction acceptance result.
The APIs never mutate context or apply a state transition. Conditional locks and
coinbase inputs are refused because their chain context is unimplemented.

The capsule SHA-256 and upstream key-constructor diagnostic fail closed on drift.
This backend **does not import the portable key capsule**. It retains the same
locked Halo2 transcript compatibility as the earlier copied-source export.
The old [interoperability package](../orchard-interop/README.md) stays unchanged.

Still required: independent cryptography/Kaspa/accounting review and invariant
decision; portable key import; real UTXO/DAA/sequence/mass checks; node/DAG/state/
header/undo integration; qualified bootstrap and service-loss recovery; approved
activation and pricing; complete privacy/cost/performance qualification. A
storage-mass placeholder is signed here, not validated. No passing test proves
cryptographic soundness or native backing.
