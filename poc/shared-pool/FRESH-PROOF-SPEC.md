# H9: genuine fresh proof and private exit fallback

Frozen before proof generation/evaluation, 2026-10-19. Baseline `49e5262`.
Owner authorization: build and run offline; retain code/journal on the
`shared-pool-four-wallet` branch. No TN10 broadcast in this experiment.
[RFC-0009](../../docs/rfc/0009-compact-anchor-privacy.md) and
[ADR-0021](../../docs/adr/0021-separate-exit-fallback-and-privacy-policy.md) govern
the unchanged compact relation. No new setup, circuit, covenant or token.

## Prediction and scope

A newly generated proof for the same note, exact payout script/value and fee,
using a later accepted commitment root, removes H8's singleton source link in
the two non-singleton fixtures. Its old authorization remains independently
settleable using current public state, without new proving. Only one may spend
the note: both winner orders must reject the other against current spentness.
The singleton control must remain one possible source.

This is a bounded mechanism comparison, not completion of the population-policy
study. One independently randomized ledger per fixture is too small for paired
population confidence intervals. The branch's 25% inference/25% fee/30-minute
screening thresholds are not revised or claimed passed. No live users,
independent later deposits, partial exits, RPC/IP arm or mainnet conclusion.

## Matched workloads and assumptions

Each fixture has one synthetic 10-tKAS initial reserve and three independently
generated wallet key sets. Alice transfers 4 tKAS to Bob, who privately prepares
an exit at count three. Alice then spends her change into payments to Carol.
Bob's target is always that first received note; owner labels and actual note
values/openings are kept outside the observer process. These are three wallets,
not three independently funded users or an anonymity set.

| Fixture | Intervening payments | Scheduled minutes after Bob receives | Target exit minute | Amount seed |
| --- | ---: | --- | ---: | ---: |
| Singleton | 0 | none | 5 | 19001 |
| Low activity A | 2 | 5, 20 | 25 | 19002 |
| Low activity B | 4 | 30, 90, 150, 210 | 240 | 19003 |

All monetary values are integer sompi. Payment amounts are generated once per
fixture from the seed with `state = (1664525*state + 1013904223) mod 2^32`,
then `60,000,000 + state mod 40,000,001`; neither arm redraws. This is workload
generation, not cryptography. Wallet keys, note randomness and proof randomness
use the existing OS RNG, never the public workload seed. Target and remaining
claims exit fully; Carol's notes exit in creation order, then Alice's change.
Cleanup times are one-minute increments after the target. Funding/bootstrap
precede the scheduled activity. These clocks are explicit simulation inputs,
not mined block timestamps, and execution does not sleep for them.

Old/fresh arms share exactly the same funding, private ledger, prior transaction
bytes, target destination/amount/fee and withdrawal order. Only the chosen target
authorization/proof and resulting reserve outpoints differ. Cleanup proofs may
be reused across these exclusive worlds when their public authorization/state
matches; no transaction is broadcast. The fresh proof is generated even in the
singleton control, where the anchor cannot grow.

## Required checks

1. Validate all positive transactions with the pinned native Full validator and
   default relay-policy checks; round-trip native JSON. Reconcile payouts, fees,
   notes/spends and final zero reserve in both arms. These use explicit synthetic
   UTXO contexts and do not prove live relay or chain acceptance.
2. Keep the fallback bundle in a private directory. Generate a genuinely fresh
   proof with identical domain, nullifier, payout/script, fee and other bound
   fields; only anchor count/root may change. Record proof time and cold setup
   loading separately. Do not substitute a changed public input for a new proof.
3. Independently rebuild each candidate using only its bundle and current public
   state/UTXO/VK, with no wallet, proving key or network access. Both must validate
   before either spends. For the fallback, preserve exact proof/auth bytes.
4. After either winner, reject the loser through both the normal builder and a
   hostile native transaction with the original genuine losing proof, freshly
   computed duplicate-insertion paths and consistent successor roots. Also
   reject mismatched old/new proof+authorization, stale witnesses, wrong pool,
   malformed proof and unauthorized payout/fee mutations. Exact old-outpoint
   replay is separately rejected by the synthetic UTXO ledger; do not confuse
   supplied-context native validation with chain UTXO lookup.
5. Run the public-field observer separately for each exclusive arm, mounting only
   its transaction projection, simulation clock and observer software. Never
   give it both alternatives, pending bundles, truth, seeds, wallet labels or
   note openings. Query all exits at withdrawal and full drain, with joint value,
   floor, anchor and single-spend constraints. Separate scorer checks true
   creation transactions and reports precision/coverage, abstention, candidate
   counts, recency and uniform-public-candidate baselines. No owner inference.

Native fee increase must be zero at the same shape/rate for this narrow check.
Extra proof work must be recorded; no subjective usability target is invented
after results. Amount/time priors from these chosen small fixtures cannot be
used to claim real-world anonymity or a 25% population improvement.

## Evidence and stop rules

Retain all raw files privately outside Git. Export only the fresh arm's serialized
transactions and public validation context, summaries, software/parameter hashes,
isolation receipts and control results. Keep the entire old arm, both pending
bundles, rejected transactions, wallet files, private truth and initial opening
out of Git. Scan exports for exact unused fallback proof bytes, distinct old
authorization bytes and all known wallet secrets. In the singleton control the
old/fresh authorization is necessarily identical because the root never changes;
its fresh public transaction may contain those shared authorization bytes, while
the unused old proof and bundle still stay private. This encoding clarification
was recorded before running any fixture. Aggregate old-arm results do not publish note/nullifier
identifiers or old source assignments. Published synthetic workload descriptions
are not part of the observer input; this is an explicit experiment boundary.

Stop on any accepted double spend, changed recipient/backing, missing claim or
need for new proof/operator help to use the fallback. A privacy null result
completes the bounded test and triggers further design work. Do not extend to
larger traffic counts or TN10 merely to seek a better result. Keep useful privacy,
fee repricing, public-data availability, setup trust and independent review open.
