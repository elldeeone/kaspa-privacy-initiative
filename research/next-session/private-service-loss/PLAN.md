# Private owner recovery rehearsal

Prior checkpoint `2ee3e0850a277f2d4a2f512da67683540be01958` is committed/pushed.
This new work integrates the previously separate Auth528 private action and
independently fetched recovery. Earlier closed packets remain unchanged.

Authority is ADR-0053 and the immutable common `CONTRACT.md` in this directory.
ADR-0054 and `EXECUTION-CONTRACT.md` supersede only the initial executable-launch
mechanism, selecting ordinary trusted read-only releases without host-policy
changes. The earlier launch probes remain historical.
New proof/native/network/wallet/trial packages have separate owners and two
independent reviewers. Prover build may use8CPU/12GiB; native build4CPU/4GiB;
serialize selected setup/proof work at14CPU after builds. No GPU backend is added.

Fresh unfunded trial: `6b2b461a-f34d-41b2-a288-fbadc37a0b9a`.
Domain: `caf85e3b34cd9b426559f57bb1ab647835c5dfaf255d17bf3d1291c0f7408470`.
Private directory outside Git:
`/home/luke/projects/kpi-intensive-2026-10-22/private-service-loss-tn10-01`.
Constructor completes in0.146s and produces backups before invoices. This is
identity-only evidence; no pool funding/setup or chain readiness follows.

Four existing ordinary test-KAS UTXOs were freshly queried:229,498,500 sompi.
The signed but **unbroadcast** ordinary merge has ID
`98580676726abeb9057de82f6a5e3c3077cd865aa8c8acad205b210d09fcdb7f`;
output0 is228,999,900 sompi to the new trial's funding key after498,600 fees.
All four native input engines and Full pass. Its private directory is
`/home/luke/.local/share/kpi-kpx2-recovery-trials/20261023-ordinary-merge-03`.
That separate identity is ordinary funding transport only, never a pool.

1. Finish and independently review new source/strict APIs and tiny public controls.
2. Clone only selected source with the fresh domain; build, then create one new
   setup/public parameter manifest. Keep all old/AA/S7 keys unmounted.
3. Bind the four-body local rehearsal to the exact planned merge output; quote
   all fees, generate three genuine proofs, validate native/SDK/links and zero
   terminal accounting. Stop the operator prover.
4. Root confirms the ordinary merge and publishes only founding plus P0 once.
   Refresh only actual blockDAA metadata and revalidate each newly available
   context; signed bodies/Auth/proofs remain exact.
5. Bob and Charlie separately fetch fresh history, authenticate public parameters
   before seed access and run their own local private prover. Confirm each newly
   built native private payout before the next owner's fresh fetch.
6. Independently refetch terminal history, verify zero reserve and both payout
   UTXOs, seal a public-only evidence packet, commit and push.

The current relation is not fee/privacy qualified. This is a small liveness
rehearsal with selected-node/data/public-parameter/setup assumptions. No mainnet,
real funds, admin path, private-witness pooling, automatic REVEAL or extra payer.
