# Mining delivery fix and activation04 review

2026-10-25 UTC. Source and public-module regressions only. Reviewer performed no
network, mining, broadcast, trial01-runtime or protected-original access.

GO for the reviewed activation04 source selection. This does not establish that
a live block is accepted or that a mining reward is observed.

The public old preimage `3e58b6b875e46aa207347cb7afdecc77e9ec6966a23d849f87f1aabea1add868`
refreshed the active template before draining worker messages. A nonce produced
while awaiting a slow RPC could therefore be compared with a different job and
discarded. New miner `178f4ae6e481c7e5bfb3ab7a26b84aa3cfb86cfaa2a2516bfac03425c9520333`
retains public jobs by identity and passes the corresponding original template
to the nonce consumer. Queues drain before and after awaited template/reward
requests. Repeated templates cannot reset an already consumed job.

Independent SDK nonce verification, full raw-body identity, own reward-script
checks, durable per-block intent and the one submit RPC remain unchanged. The
new public observations are aggregate work/submission/acknowledgment/query/job
counts; they disclose no nonce or private wallet material. Acknowledgments stay
separate from actual reward observation.

All three public regressions passed independently with the exact pinned Node
runtime. See `MINING-DELIVERY-FIX-REGRESSIONS-01.json`. These controls cover work
queued during a delayed RPC, work pending before refresh and duplicate/consumed
job identity. They perform no SDK/network/mining call.

`ACTIVATION-04-CORRESPONDENCE-01.json` records the exact 57-file source selection,
profile and financial selection bindings. Current queue/miner/test/operator/
launcher bytes match those pins. The operator now accepts a canonical fresh
label plus exact trial SHA and UUID, retaining the new-private-prefix and
once-only attempt protections. Trial01 remains stopped and untouched; this
review authorizes no retry within its consumed identity.
