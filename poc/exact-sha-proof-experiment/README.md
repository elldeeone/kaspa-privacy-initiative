# Fresh exact-SHA proof performance experiment

ADR0047, synthetic DO_NOT_FUND only. This run-only CLI depends on the frozen
`kpi-exact-sha-cost-probe` candidate. It never loads a proving key or matrix.
It authenticates the exact primary public fixture, creates a new OsRng
Groth16 setup, retains that PK for one genuine proof and the original fully
checked verification, then saves/fsyncs/hashes official uncompressed
parameters outside Git. Old PKs/VKs and active testnet policy are untouched.

The circuit source hashes are compiled pins. Its independently measured
3,497,893 constraints and actual new query lengths/domain identify the fresh
matrix construction. A source/fixture fingerprint is recorded; it is not
misrepresented as a raw matrix digest. The fresh VK must differ from the
old parameter VK. No claim of setup-ceremony safety or cryptographic review.

```sh
CARGO_TARGET_DIR=/absolute/private/exact-sha-proof-target \
 cargo +1.95.0 build --release --locked --offline --jobs 4 \
 --manifest-path poc/exact-sha-proof-experiment/Cargo.toml
CARGO_TARGET_DIR=/absolute/private/exact-sha-proof-target \
 cargo +1.95.0 test --release --locked --offline --jobs 4 \
 --manifest-path poc/exact-sha-proof-experiment/Cargo.toml
```

Runtime, after source/fixture/binary freeze and independent ACK:

```text
kpi-exact-sha-proof-experiment PRIMARY_PUBLIC_FIXTURE NEW_OUTSIDE_GIT_OUTPUT
```

The prospective allocation is four CPU equivalents, 16 GiB RAM, zero swap,
network isolated and a generous one-hour limit. The 4 GiB wallet and 10s
warm proof targets remain unchanged measurement thresholds, not kill limits.
External whole-process CPU/RSS/swap and separate setup/proof/serialization
timers are retained. `/proc/self/status` snapshots report current and
cumulative high-water RSS, not independently isolated phase peaks.

The primary public fixture is semantic performance evidence, not a new
native or chain result. The one proof observation cannot establish p95,
whole-wallet readiness or privacy. A fresh VK/native policy would need
separate qualification before any adoption. Larger parameter files and
compiled software remain local and are excluded from Git.
