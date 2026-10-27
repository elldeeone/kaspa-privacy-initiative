# Next-trial wallet-policy counterfactuals

**All three counterfactuals remove the scripted actor-1 exception in this source model. None establishes withdrawal-group unlinkability.** Private random eligible-note choice can recreate a distinctive amount pair belonging to one unnamed wallet. This research read public source and generated public synthetic examples only; it did not read actual payouts, plans, state, owner files or truth, or change the current trial/runtime.

The current public generator uses `any` for round one and `change` for actor 1 versus `received-preferred` for the other actors in round two (`integration/campaign_cached.py:74-75,99-100`, SHA `586a8852…655bd8`). The wallet first filters for `value >= payment + exact fee + 60m sompi`, then selects by kind and greatest value (`wallet/payment.py:77-80`, SHA `5ff0774f…2d2bda`; `recovery/history.py:159-173`, SHA `3e637e52…ab542`). Its received/change labels are derived locally from authenticated history, not public role tags. The existing source-policy finding and funding-order bridge limitations remain unchanged.

For the prescribed synthetic 20 KAS initial notes, 5 KAS then 2 KAS payments, and qualified exact fees `f,g` in `(0,0.5] KAS`, each actor's descending withdrawal-note queue is one of:

- Received-first: `R = [15−f, 3−g, 2] KAS`.
- Change-first: `C = [13−f−g, 5, 2] KAS`.

Both original round-two candidates are eligible throughout these bounds; newly received 2 KAS notes are ineligible because the next payment also needs its fee and minimum change. These are gross note values; the source observer reconstructs a gross as native payout plus that exit's exact fee once. Common owner does not mean common funding-root ancestry.

| Policy | Removes the fixed actor-1 signature? | Amount-grouping limitation |
| --- | --- | --- |
| Current actor-1 exception | No: actor 1 alone has `C` | Unique 5 KAS and 12–13 KAS notes identify its common-owner pair conditionally on the source model. |
| Uniform received-first | Yes: every actor has `R` | Known amounts plus greatest-note-first exits can still group withdrawals. |
| Uniform change-first | Yes: every actor has `C`; the 5 KAS note is no longer unique | Same grouping problem; shared policy does not hide amounts. |
| Privately random eligible-note choice | Yes, if the same algorithm applies to every actor without an identity-dependent fallback | Supports all eight `R/C` combinations. One `C` among two `R` wallets still exposes a distinctive common-owner pair, without a stable actor label. |

“Removes” here means actor-label permutation symmetry in the counterfactual model, not a real funding-input association result. Linking the original actor-1 finding to funding input 1 remains conditional on the original selected-source/input-order bridge; no new activation-argv or ownership evidence was acquired.

The controls were frozen before execution in `WALLET-POLICY-COUNTERFACTUAL-SOURCE-01.json` (SHA `99bb0c24…ae8b70`), binding the exact script/spec. They retain three public fee vectors: 1–6m sompi, one sompi each, and the 50m cap. All 216 baseline schedules matched wire's independently frozen forward model and queue formulas. The new owner-partition matcher matched an independent enumeration of 1,680 exit interleavings in its baseline control; duplicate models added no evidence. The equal-queue matcher sanity fixture admitted 280 unlabeled partitions/84 actor-1 masks with no forced pair; it is a matcher fixture, not a wallet-generated state. Invalid fee types, over-cap fees and impossible withdrawal chronology are retained as rejected/zero-model controls, without vacuous ownership predictions.

For the predeclared 1–6m fee vector and round-robin exits:

| Model | Compatible unlabeled owner partitions | Actor-1 masks | Forced actor-1 exits | Forced common-owner pair |
| --- | ---: | ---: | --- | --- |
| Current | 12 | 3 | 1,4 | 1,4 |
| Uniform received-first | 36 | 27 | None | None |
| Uniform change-first | 36 | 27 | None | None |
| Random support; one `C` outcome | 12 | 15 | None | 1,4 |

All 60 counterfactual observations had no forced actor-1 exit. However, **all 30 predeclared frontloaded counterfactual observations uniquely grouped the nine withdrawals into three owner triples**, while leaving the actor labels ambiguous. With greatest-note-first exits, a wallet that withdraws a medium/small note before another high note appears must already have consumed its own high note. Thus removing the identity-coded branch does not remove this source-policy/amount/chronology channel. Model counts are deduplicated possibilities, not probabilities, posteriors or privacy scores. All 66 observations and failures are retained in `WALLET-POLICY-COUNTERFACTUAL-RESULT-01.json`, SHA `695b4e36…df8cfd0`.

Wire independently sanity-checked the conceptual separation between label symmetry, unnamed co-ownership and asset-root ancestry. That review did not independently rerun/read these counterfactual artifacts or any actual data; it is not independent numerical replication.

The smallest next-trial correction for this specific source bug is one common round-two rule: received-first already has a selector mode and needs no random selector. Uniform strict `change` also matches the tested workload because eligible change exists for every actor; a general change-first fallback is a separate explicit design choice. Private random eligible selection needs a new local selector and frozen private draw/retry semantics; it is not a demonstrated privacy repair. Relevant future files are `integration/campaign_cached.py` and, if adding a mode, `recovery/history.py`; eligibility, owner fee consent and proof/range checks must stay intact.

Any real policy change requires a **fresh frozen trial** and separately frozen observer assumptions. The current six-payment/nine-exit target, fees, prior failures and financial criteria remain unchanged. No mandatory resident balance, delayed/forbidden exit, new cryptography, new asset, privacy PASS, posterior or owner-verified accuracy is proposed or claimed.
