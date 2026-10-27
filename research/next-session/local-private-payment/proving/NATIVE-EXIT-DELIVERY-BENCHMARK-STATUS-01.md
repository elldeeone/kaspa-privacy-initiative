# Native exit-delivery benchmark: incomplete

2026-10-26 UTC. **No benchmark measurements or native claim results exist.**
The implementation worker stopped after an automated cybersecurity filter
flagged its turn. No specific rejection reason beyond possible cybersecurity
risk was supplied. The blocked work has not been retried or reassigned.

The [frozen proposed plan](NATIVE-EXIT-DELIVERY-BENCHMARK-PLAN-01.md), SHA256
`5984eaa71e36db9e031037da1f18ca7c7b49b0191ea464fbb0fc7597a292317b`,
retains the hypothesis, ideal funded-checkpoint assumption, three output layouts,
six supplied-context claim paths, fixed amounts/budget/rate, proposed controls
and stop rules. It selects no new native architecture or financial profile.

Two partial, unvalidated files remain in the local checkout, outside the finite
publication selection:

| Local partial file | Bytes | SHA256 |
| --- | ---: | --- |
| `poc/native-exit-delivery-cost/benchmark.mjs` | 21626 | `ea85f1e760890add67c7df0ca4c12e0ba2879c025a1864166a101336539cd18b` |
| `poc/native-exit-delivery-cost/control.py` | 16209 | `e6f9ce74788016bd56d3da50810a01b72fe1f4a5d6255a5b9d9c33895007aaa7` |

The worker reported that its attempted parse-only check failed before starting
Node because `/usr/bin/node` was absent. Later checks in that command were not
reached. This separate tooling observation is **not** the filter's stated
reason. No benchmark SDK/Native process, fixture preparation, source freeze,
build, setup or proving job ran. Source and driver construction was underway.

A premeasurement source calculation remains a conditional warning: for the
plan's 120M-sompi shared input, 59M payout and 60M successor, the selected
storage formula gives 25,282 mass grams. At 100 sompi/gram that dimension alone
would imply a 2,528,200-sompi full-mass quote, exceeding the fixed 1M fixture
fee. This is arithmetic from the [selected storage source](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/mass/mod.rs#L410-L484),
not a measured transaction, remote relay rejection or complete fee comparison.
The relay floor and mining/ranking mass use different dimensions, as recorded
in [the existing fee research](../fees/OFFICIAL-CURRENT-RELAY.md).

The separate [finite liability model](../exit-liability-model/REPORT-01.md)
remains completed and unchanged. Its ideal accounting evidence does not supply
the missing native benchmark. Genuine checkpoint creation, authority, recovery,
availability and system cost remain open. The running payment rehearsal and
its fee policy were not changed; the existing 2% failure is unchanged.
