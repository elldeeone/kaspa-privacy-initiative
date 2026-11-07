# One public bundle removes the tested issuer reply-timing link, offline

**Decision:** keep an atomic accepted-payload bundle as a candidate for one
more current-L1 validation gate. It passed the selected **local service-only**
timing test, but it has not established real chain delivery, network anonymity,
complete financial privacy, a usable fee, or independent exit. No consensus
rule changed. The prior service-controlled protocol still fails
[ADR-0115](../../docs/adr/0115-service-release-timing-limits-blind-withdrawals.md).

## What changed and what ran

Kaspa's [payload guide](https://docs.kaspa.org/integrate/transaction-payload)
permits application data in ordinary transactions under a roughly 25 KB
practical standard-mempool ceiling. Its
[accepted-transaction guide](https://docs.kaspa.org/integrate/accepted-transactions)
describes independent payload retrieval, confirmation buffering and reorg
rollback. We tested the [preselected design](SELECTION.md): one *simulated*
accepted payload containing three real proof-backed blind requests and all
three blinded signatures, published by one atomic local file rename. The
issuer's individual network acknowledgements contain no usable signature.
Each separate wallet container reads the same read-only board, checks all three
blinded RSA reply relations and genuine common-round eligibility proofs, then
unblinds its own reply. This is experimental feature-gated wallet code.

Four real wallet actors repeated the 40 KAS supplied-deposit history: A->B 20,
B->C 10, A->D 10. A/B/C each requested one equal 10 KAS exit. The same onion
issuer logged issue and redemption messages. The genuine approvals and
unchanged offline kernel accepted 30 KAS of payouts, leaving 10 KAS liability
and principal. No new native receipt, Full validation, accepted payout or chain
broadcast was run.

| Selected check | Observed result |
| --- | --- |
| No public bundle, or only one reply | All three wallet checks refused before payout-key disclosure. |
| Complete bundle with one invalid blinded reply | All three refused. A corrective check made the invalid reply belong to a *different* claimant for each wallet; all three still refused. |
| Genuine complete bundle | All three wallets redeemed and approved; unchanged kernel accepted exactly 30 KAS. |
| Active issuer's service-only ownership view | **0 exact claim-to-payout links**, six compatible assignments; the fixed order guess matched **1/3** in this one run. |

The actual compact payload was **9,256 bytes**. This is below the documented
payload-dominant ceiling with room for ordinary transaction fields, but is
**not** an accepted native transaction or a paid fee quote. All completed
roles ran in separate unprivileged containers on **one physical host**. The
service never mounted wallet backups. The observer saw only the service/public
view; its prediction hash was sealed before private owner truth was read.

## Why this is narrow

The old attack worked because the issuer delivered one usable blind reply and
waited for that client's payout key before delivering the next. Here all three
usable replies become visible in one common object, and a wallet refuses a
partial or broken object. The issuer may withhold the object and stop the
optional group; it cannot turn a *single* accepted complete object into three
different reply times under the modeled independent-reader assumption.

That assumption is not yet established on real L1. A wallet using the issuer's
RPC/relay can still be selectively delayed or observed. A live reader must
authenticate accepted payloads, handle reorgs and retain data needed after
pruning; the local atomic file did none of that. A service with two known or
Sybil claimants trivially identifies the third owner. One legitimate known
owner leaves two mappings; two leave one. Public exit amounts, distinctive
values, fee funding, later participant disclosures and full drainage remain
adverse. Six structural mappings and one failed order guess are not a
statistical anonymity guarantee.

The local checks do not prove RSA blindness, a globally private transport,
independent machines or production security. They reuse the pinned RFC9474
implementation and existing proof/kernel relations. The public
[evidence](run/RESULT.json) includes a finite [manifest](run/MANIFEST.json),
bundle, proof-backed payments, service messages, sealed observer prediction,
guard summaries and kernel replay, without wallet backup, issuer key, blinding
state, owner truth or proving parameters. Replay with the
[checker](../../poc/atomic-bundle-withdrawal/check.py). The corrective
other-claimant controls and public replay were additive after the original
run; the original source hash remains frozen in the private run.

For cost triage, the retained matched 47-useful-KAS workload already quoted
**0.992104 KAS** in native fees (2.11%) before any bundle publication. If
this candidate adds a separate positive-fee L1 payload transaction to that
otherwise unchanged workload, it cannot meet the retained 2% **all-in** target.
The new payload has no measured accepted fee or full service cost, and larger
payments or a safely shared existing transaction could change the percentage.
This is a conditional floor, not a completed cost comparison or a rejection of
every workload.

## Next decision

Do **one Testnet-only end-to-end gate** with an actual accepted payload and
independent wallet chain readers, including reorg/withholding and issuer-hosted
RPC controls. Require the complete payout and restored-key spend in rehearsal
under the repository trial rules. If controlled delivery or known-owner
effects leave no useful conditional privacy, stop this option and carry the
result into Olaf's [P13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13)
work. If it survives, then measure the added payload transaction and complete
first-payment/service costs against the retained same-workload baseline. No
mainnet experiment, real funds or consensus change is proposed.
