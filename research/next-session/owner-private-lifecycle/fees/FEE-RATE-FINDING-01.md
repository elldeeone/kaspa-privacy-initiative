# Fee rate and native mass: read-only finding

The measured fees are primarily a native compute-mass cost. The frozen rate of
100 sompi per mass unit matches both the pinned source's standard relay floor
and every fee-estimate bucket returned by the two selected TN10 endpoints. The
evidence does not support describing it as an arbitrary 100-fold fee premium.

## What each number means

| Item | Finding | Evidence boundary |
| --- | --- | --- |
| Chosen experiment rate | 100 sompi per mass unit | Financial profile `69a7adc4…`; unchanged |
| Standard node relay floor in pinned code | 100,000 sompi/kg = 100 sompi/gram | Applies to `max(compute_mass, normalized_transient_mass)`; storage is excluded from this floor |
| Stock daemon policy | Standard checks enabled | The examined official daemon passes `false` for `relay_non_std_transactions` |
| Generic consensus minimum | No universal 100-rate requirement in the examined consensus validator | It checks input/output conservation, mass commitments, scripts and other rules; its optional feerate threshold is explicitly a mempool/RBF rule |
| Current advisory estimate | 100 in every priority, normal and low bucket | Both selected endpoints, observed 2026-10-25 at 00:23:45.970 UTC |
| Actual remote admission configuration | Unknown | RPC reports version 2.1.0/TN10/synced/indexed, not an authenticated binary commit or operator configuration |

The fee source distinguishes a standard mempool admission policy from consensus.
In the pinned code, `accept_non_standard` bypasses the standard checks, while the
estimator still clamps its buckets to the configured minimum standard rate.
Therefore an RPC estimate of 100 alone does **not** establish an exact deployed
admission floor. We did not test admission below 100. The endpoint names also do
not establish separate administration.

## Why the mixed payment currently costs 0.199141 KAS

The actual R2 Native Full metrics give this decomposition:

| Charged compute mass | Mass units | Fee contribution at the frozen rate |
| --- | ---: | ---: |
| Committed budget: 1800 × 100 | 180,000 | 18,000,000 sompi |
| Estimated transaction bytes | 18,771 | 1,877,100 sompi |
| Output script public key weight | 370 | 37,000 sompi |
| **Total** | **199,141** | **19,914,100 sompi** |

The committed native compute budget is **90.3882%** of the mass and fee. This
budget covers the whole native verification/policy script and includes execution
headroom; it is not a measurement of proof-generation CPU/GPU time. Transient
mass is 75,084, storage mass is zero, and compute dominates both the reported
relay and mining mass. Thus, for this case, the chosen fee also equals the
examined stock standard relay formula exactly.

The current failure to fit the 2% target cannot be dismissed as a demonstrated
rate markup. The evidence points to reducing verified compute mass and the cost
of the withdrawal architecture as the substantive fee work. This read-only
comparison does not select a new budget, rate or candidate, and does not replace
the actual rate-100 fee ledger or its eventual complete-lifecycle verdict.

## Source and observation identities

The actual remote version is advertised as `2.1.0`; its deployed commit and
configuration remain unauthenticated. The examined local native-verifier source
is the clean tracked dependency commit
`01b532e8b553523216471682649693af92f0fd16`. Separately, a fresh read-only
`git ls-remote` returned official `master` at
`4edcbbccb449f84832afb1ca157904b35f37d006`; its relay default, standard fee
calculation and stock daemon setup were also checked.

Primary source pointers:

- [Relay units and default](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/mempool/config.rs#L17-L20), [relay mass and integer fee formula](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/mempool/check_transaction_standard.rs#L67-L104).
- [Conditional standard-policy checks](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/mempool/validate_and_insert_transaction.rs#L157-L168), [consensus versus optional mempool/RBF threshold](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs#L37-L66).
- [Budget conversion](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L4-L7), [charged compute-mass calculation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L340-L369).
- [Estimate floor](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/manager.rs#L220-L224), [bucket construction](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/feerate/mod.rs#L140-L161), [current stock daemon's standard-policy selection](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/kaspad/src/daemon.rs#L677-L685).

Retained evidence in this directory:

- `SOURCE-EVIDENCE-01.json`: source/blob hashes, exact source ranges and arithmetic; SHA256 `47a3a33536a0614646bb04fd704c944579b3582263cfbe656f5509b4643288fd`.
- `NODE-FEE-PROBE-01.json`: original read-only node responses; SHA256 `ad086f2db75432ad6b30aeae53550c930b5b5d8b47de4cf6e721b492254e7f82`.
- `CONFIRMED-R2-NATIVE-METRICS-01.json`: actual retained native metrics; SHA256 `f7f1e46fac9fca4252658a7ca3fa67d88c315ffd3990b4d2b28bb7ce9dac9a9a`.

The experimental fee RPC request failed with `missing field verbose` on both
nodes; those failures are retained. The normal fee RPC succeeded. No new service,
proof, lowered-fee candidate, trial, private wallet read or broadcast was used.
