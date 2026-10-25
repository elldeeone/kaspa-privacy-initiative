# Current fee floor: 100 sompi/gram

**2026-10-25 UTC. The checked official default and both fresh TN10 fee estimates
are 100 sompi per mass gram. The evidence does not support a 1-sompi rate or a
100-fold research surcharge.** This note changes no rate, budget, proof case,
old 21-KAS workload or failed 2% verdict.

The selected `v2.1.0` revision is
`01b532e8b553523216471682649693af92f0fd16`; current official HEAD observed today
is `4edcbbccb449f84832afb1ca157904b35f37d006`. Their checked relay configuration,
standardness calculation and fee-estimator files are byte-identical. The
configuration stores `100_000u64` **sompi/kilogram**; dividing by 1,000 gives
**100 sompi/gram**. RPC bucket `feerate` is already an `f64` in sompi/gram and
must not be divided by 1,000 again. [Official default](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/mining/src/mempool/config.rs#L17-L20),
[conversion](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/mining/src/mempool/config.rs#L137-L141),
[RPC units](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/rpc/core/src/model/feerate_estimate.rs#L5-L34).

There are two mass denominators:

| Purpose | Normalized mass |
| --- | --- |
| Default standard relay floor | Maximum of compute and transient; excludes storage |
| Mining/template ranking and inclusion estimates | Maximum of compute, transient and storage |

TN10 transient mass is scaled by 0.5 and rounded upward. The relay calculation
uses saturating `u64` multiplication by configured sompi/kg, integer division by
1,000, its zero-result fallback and MAX_SOMPI cap. At the default and these
ordinary valid masses, the result is exactly `100 × relay_mass`. A full-mass
inclusion quote can exceed the bare relay floor when storage dominates; storage
cannot simply be discarded from inclusion pricing. [Exact relay calculation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/mining/src/mempool/check_transaction_standard.rs#L67-L104),
[normalization](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L176-L188),
[ranking mass](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/mining/src/mempool/model/frontier/feerate_key.rs#L87-L100).

The generic VM public source calculates
`source_adapted_default_relay_fee = fee >= relay_mass * 100` in
[`native.rs`](../../../../poc/private-exit-native/src/native.rs#L261).
“Adapted” labels a copied policy check; it does not establish a different rate.
Its separate Native Full execution is a consensus/script check, rather than an
actual remote mempool admission test. The new codec quotes full normalized mass,
and the selected wrapper compares the authorized fee with that quote.
Exact guarded source and selected executable hashes are retained in
[`LOCAL-SOURCE-IDENTITIES-01.json`](LOCAL-SOURCE-IDENTITIES-01.json); this research
does not claim a new rebuild or source-to-binary attestation.

A separate public-only calibration confirms that distinction: a genuine new
direct Exit with a fee of 100,000 sompi passed Native Full and its input script, while
`source_adapted_default_relay_fee` was **false** and the quote at 100 was
16,044,400 sompi. The selected wrapper still refuses that underfee fixture.
This establishes supplied-context VM behavior, rather than public-node admission
or a viable lower-fee candidate. The unchanged fixture's result is retained as
[`NATIVE-UNDERFEE-CALIBRATION-01.json`](NATIVE-UNDERFEE-CALIBRATION-01.json), SHA256
`db4fcedd99dcbe4d58f03dacfa7ffa82647d14f858121a45134cde5e5a9b47f0`.

For the retained new candidate quotes, **compute dominates every dimension**, so
the relay and inclusion denominators agree:

| Case | Compute | Raw transient | Storage | Fee at 100, sompi |
| --- | ---: | ---: | ---: | ---: |
| Payment, budget 1800 | 192,284 | 47,656 | 0 | 19,228,400 |
| Continuing exit, budget 1500 | 160,444 | 38,856 | 5,015 | 16,044,400 |
| Terminal exit, budget 1500 | 160,021 | 38,644 | 0 | 16,002,100 |

The payment's committed budget contributes 180,000 mass, or 93.6115% of its
compute mass. It covers native execution and headroom, rather than proof-generation
CPU time. No lower budget or rate is selected here. The exact original quote
hash is `95f96de465c74190fe2fbbcd096c3e2c03ff2a49da4224cd88bcf30f9ac375c4`.
[Budget conversion](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L4-L7),
[charged compute mass](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L340-L369).

Fresh Tor+TLS+Borsh `getFeeEstimate({})` reads returned **100 in every bucket**:

| Public peer | UTC observation | Network |
| --- | --- | --- |
| vector-10.kaspa.green | 20:53:24.117 | testnet-10 |
| electron-10.kaspa.blue | 20:53:27.616 | testnet-10 |

The complete public responses and hashes are retained in
[`TOR-OBSERVATIONS-01.json`](TOR-OBSERVATIONS-01.json). The estimator clamps
recommendations to its supplied configured minimum. Consequently these responses
corroborate the advised rate, rather than independently proving remote policy.
Remote commits/configuration and separate administration are unauthenticated;
estimated seconds are model outputs, not measured confirmation latency.
[Estimator minimum](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/mining/src/manager.rs#L220-L241),
[bucket bounds](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/mining/src/feerate/mod.rs#L140-L162).

**Boundary:** 100 is the checked standard relay default and current observed
advisory rate, rather than a universal consensus fee rule. No remote lower-fee admission
probe, funding, mining or broadcast occurred. Actual admission and confirmation
remain later evidence. A 1-sompi comparison would require a separately identified
candidate and would fall below the checked default standard relay floor.
See [`OFFICIAL-CURRENT-RELAY.md`](OFFICIAL-CURRENT-RELAY.md) for the pinned primary
source details.
