# Withdrawal amounts: diagnosis and candidate mitigations

Reviewed 2026-10-21, against local commit
`2c036c0fe01b11ee68306c90ca8cfd56d7e0235f`. This is a post-result investigation,
not a new frozen experiment or an adopted wallet policy. No private truth,
wallet backups or seeds were accessed for the source review. The separate
exploratory trace below reads hash-bound truth only after verifying all original
prediction seals; it publishes aggregates, not individual hidden records.
No protocol, wallet, parameters or funds were changed.

**Recommendation:** test a wallet that keeps a working shielded balance and
withdraws only the native liquidity requested, retaining private change for
later payments. The existing v6 relation already supports this. Keep immediate
whole-note exits available. Whether this improves privacy after all remaining
value eventually exits is unresolved; a short delay or common denomination by
itself has already failed a relevant earlier test.

## What the result establishes

The [completed native-usage screen](../poc/shared-pool/NATIVE-USAGE-PRIVACY.md)
reported C+D amount guesses within 10% on 12/36 primary payments after the next
public withdrawal, versus 7/36 for its prior. Exact hits were 6/36. These are
successful guesses in one dependent history, not 12 proven amount disclosures.
The next withdrawal is selected from public order; it need not be the target
recipient's withdrawal. An analysis of the successful guesses must distinguish
the actual target note from an unrelated, similarly sized withdrawal.

The subsequent [exploratory trace](../poc/shared-pool/artifacts/native-usage-withdrawal-diagnosis-20261021.json)
reproduced all 864 selected original guesses
exactly (36 primary payments, two profiles, three horizons, four variants).
At the next public withdrawal, C+D's 12 within-10% hits comprise six exact hits
supported by withdrawal of the actual target receipt alone, five approximate
matches to other receipts, and one successful fallback to the prior. Against
the prior's seven hits, there are eight gains and three losses. The pooled
heuristic's ten hits comprise the same six actual-receipt exact hits and four
prior fallback hits (three gains, no losses). The approximate matches remain
valid accuracy hits under the frozen metric; they are not evidence that those
other withdrawals spent the target receipt.

At that horizon native-graph and residual guesses have identical amounts for
all 36 targets in both profiles, with no selected graph-based ownership tier.
The key-separation fix therefore does not address this measured arithmetic
mechanism. Extra colluder information changes heuristic selection; its lower
score is not a protection against a stronger attacker, who can ignore it.

At final drainage the residual attack has ten approximate hits and no exact
hits for either profile; its selected supports all point to other receipts.
The split/native-graph attack has five exact hits for each profile, but C+D's
selected supports do not spend those target receipts; the pooled split has one
true-receipt-supported exact hit and four exact matches using other receipts.
Matching a common invoice amount is therefore not the same as identifying the
direct receipt withdrawal. This classification tests consumption of the original
receipt note, not every possible later descendant or allocation of its value.
These accuracy hits still count in the retained score.

The [diagnostic code](../poc/shared-pool/native_usage_withdrawal_diagnosis.py)
passed twelve public controls and a source review. Classification rules were
hashed before execution; every replayed guess must match the sealed original.
An initial final-drainage phase label was corrected to use the declared
60-minute phase boundary, preserving the
[initial aggregate artifact](../poc/shared-pool/artifacts/native-usage-withdrawal-diagnosis-20261021-initial-label-version.json).
All non-phase aggregates remained identical. Neither version changes the
original experiment, attacks, eligibility, scores or thresholds. No masking
ablation or mitigation trial was performed.

The [frozen observer][observer] forms `withdrawal + fee` and, when it has a
candidate known input value, subtracts that value. These quantities are plausible
one-note values or residual values of a two-note exit. It filters by permitted
ancestry/spentness, then ranks candidate explanations using ownership knowledge,
support and recency. Split explanations also compare private payment and change
against publicly known input values. This is heuristic ranking, not exhaustive
proof that only one amount or owner is possible.

The tested [wallet][wallet] exposes whole-selected-note EXIT: one or two owned
notes become `payout = input total - fee`. Thus promptly cashing out a received
note can publish its exact value after adding the public fee. Two inputs hide
their individual split only to the extent that the other input is unknown.
Persistent private spending changes those arithmetic relationships; merely
waiting with the same note does not. These are consequences of the relation
and wallet policy, not evidence that proof encryption has failed.

For example, at the frozen 0.4-tKAS fee, withdrawing a whole 40-tKAS receipt
pays 39.6 publicly: adding the fee gives 40. A 20-tKAS partial instead leaves
19.6 privately. But a linkable subsequent 19.2-tKAS tail restores the same
equation: `20 + 19.2 + 0.4 + 0.4 = 40`. Partial withdrawal helps only if its
connection to that receipt and later value cannot be reliably reconstructed.

## The boundary cannot be encrypted away

Current [Kaspa transaction outputs][kaspa-tx] contain a public integer value and
locking script. The candidate's [native transaction builder][native-builder]
emits the payout as an ordinary native output; reserve movements and fees also
expose value leaving the pool. A different proof system, fresh payout address,
or executor cannot make this same native output confidential.

The useful target is to prevent a public cashout from identifying a particular
internal payment or remaining balance. Hiding the actual amount of an ordinary
native output would require a different base-layer representation; that is not
the next experiment. A recipient who insists on promptly withdrawing one whole
received note retains an inherent amount-linkage risk under this wallet policy.

This distinction appears in mature designs too. [ZIP-315][zip315] identifies
public value balances, transparent outputs, fee/shape metadata and receipt-driven
activity as separate leakage surfaces; it remains Draft guidance, not a security
proof. [MWEB peg-outs][mweb] explicitly carry amounts and native scripts even
though amounts inside the domain use a different representation. The empirical
[Zcash study][kappos], §§6.3–7, motivates testing distinctive values, short
round trips and intervening private activity. Its historical success rates do
not predict this experiment's accuracy.

## Existing capability versus wallet limitation

Do not confuse the current wallet command with the proof relation.
[RFC-0011](../docs/rfc/0011-two-input-private-payments.md) and the
[circuit][circuit] permit ordinary SPEND with both a public payout and private
change:

```text
private inputs = private outputs + native payout + public fee
```

The [native harness][harness] already withdraws 211,000,000 sompi, retains a
480,000,000-sompi private note, decrypts that note and spends it later. The
[H13 TN10 report](../poc/shared-pool/TWO-INPUT-TN10.md) and
[H17 report](../poc/shared-pool/COMMON-PAYOUT.md) retain bounded mechanical
evidence. They do not qualify arbitrary current-wallet recovery or privacy.

The current `Action::Pay` has zero public payout; `Action::Exit` has no private
outputs. Adding an explicit partial withdrawal to that wallet can reuse the
existing relation, setup and covenant, subject to integration and recovery
tests. A preparatory self-PAY followed by EXIT is possible in principle because
PAY does not prohibit the sender as recipient, but incurs another operation;
it is not the minimal path when native partial withdrawal already exists.

Partial withdrawal consumes its input notes. Old fallback exits for those notes
must lose to the accepted partial, and the new change must remain recoverable
and independently withdrawable. Keep deterministic payout-key recovery, reject
double spends, respect note/payout floors, and count every change-management fee.
No operator may be required to release the remainder.

## Which ideas merit testing

| Candidate | Why it could help | Cost, limitation and decision |
| --- | --- | --- |
| Keep received value shielded and spend it privately | Breaks the direct receipt-to-whole-note-cashout relationship; makes retained value useful. | Requires counterparties accepting private payments and users willing to keep a balance. Sparse activity and eventual drainage can undo gains. Strongest direction to test. |
| Withdraw requested liquidity, retaining private change | Public payout need not equal the selected receipt; existing v6 SPEND supports it in one operation. | Distinctive requests can still identify a user. Later tails may reveal the original amount. Test with genuinely independent liquidity needs and later spending. |
| Common-size optional payouts | Many equal public outputs can reduce value uniqueness. | Public policy, denomination counts, residual tails and fee arithmetic remain attack inputs. Small denominations fragment balances and multiply fees. Test only with complete tails; do not assume a new size fixes H18. |
| Aggregate two receipts in one withdrawal | Publishes their sum rather than each separately; current EXIT supports two inputs. | Known/tagged co-inputs reveal the other value; few plausible pairs may identify both. More than two inputs needs extra merging or a relation change. |
| Delay, batch or decouple withdrawal scheduling | Can weaken simple receipt-to-next-exit timing when independent activity actually overlaps. | Quiet time creates no other users. Mandatory rounds, operator approval or expiry cannot gate escape. Cross-user multi-payout atomic batches are not an existing v6 wallet feature. |
| Private self-PAY/merge/split before exit | Can alter note composition without transparent re-entry. | Added fee/proof time; deterministic immediate reshape-and-exit can remain recognizable. Never call additional commitments additional people. |
| Fresh purpose-separated addresses and network privacy | Reduce script equality and provider/network identity signals. | Neither removes on-chain values, fees or spend edges. Keep key separation, but it is not an amount-privacy fix. Network observers need their own experiment. |

The [H17 common-payout screen](../poc/shared-pool/COMMON-PAYOUT.md) reduced
forced original-source links from 7/28 to 4/28 in its small modeled cases, but
failed its delay limit. [H18](../poc/shared-pool/SCHEDULED-PAYOUT.md) then found
**zero improvement** for its strongest frozen attacks with 2-tKAS payouts and
5–15-minute tails. All 48 sparse-case partials paired with their unique
time-compatible tails under the declared policy, reconstructing original values
with fees. Even its broader no-scheduling/no-re-splitting ablation did not restore
the earlier benefit. Preserve both outcomes; do not relabel tuned H18 as success.

The pinned fee is 40,000,000 sompi per pool operation: a single operation costs
4% of a 10-tKAS payment. Extra reshaping cannot meet the adopted 1% ordinary-
payment target at that size on this profile. The 2% complete-lifecycle target
also includes funding, admission, all exits and tails. Privacy benefit alone
cannot qualify the current cost profile. See
[RFC-0012](../docs/rfc/0012-useful-privacy-requirements.md).

## Smallest decisive next comparison

Proposed feature-ablation follow-up, not executed by this source review: use
the completed public history for diagnosis by removing declared feature
families from an analysis view and compare the frozen predictions. Masking only
the payout field is insufficient if reserve differences, native outputs or fees
still reconstruct it. Separately test order/clock, directory, native bridge and
whole-note residual information; preserve all original data and scores. Such
ablations show what an attack used. They are not valid alternative transactions
or evidence that a wallet mitigation works.

Then freeze one candidate comparison before sampling fresh histories:

1. **Matched demands:** the same 32 roles/eight adversaries, private invoice
   obligations, external liquidity requests and starting capital in each arm.
   Baseline uses whole-selected-note withdrawals. Candidate pays requested native
   liquidity through existing partial SPEND and retains/spends change. Requests
   are sampled independently of a particular received invoice in the working-
   balance scenario; retain a receipt-correlated cash-demand stress scenario
   too. Independence is a workload assumption, not something a wallet can
   force on users. Do not invent extra honest transfers merely to improve the
   candidate's activity. Match
   actual payouts where feasible; otherwise disclose whole-note over-withdrawal
   explicitly. Never credit the candidate for paying less than requested or
   missing the request deadline. This tests a change in cashout behavior, not
   a cryptographic guarantee for identical public amounts. Count overshoot,
   all tails, any required re-entry fees and unmet requests in both arms.
2. **Coverage:** one overlapping and one sparse paired history is a small
   falsification screen, not a population estimate. Freeze selector, request
   sizes/times, tail handling and failures. Include prompt full-exit overrides,
   tagged co-inputs, receive-only users and eventual full drainage in both arms.
   Compare the same original economic obligations, not the growing note count.
3. **Attacks:** freeze a policy-aware price prior, residual/split attacks adapted
   to partial payouts, amount/fee conservation, receipt recency, partial-tail
   matching, subset-sum reconstruction and colluder tagging. Each stronger
   observer can retain the public-only strategy: pooled collusion must not
   appear protective merely because one heuristic uses its extra information
   badly. Include carrying earlier-prefix predictions forward as a fixed
   strategy: declining final accuracy from reranking does not erase information
   already observed. Do not select correct guesses per target using truth.
   Seal predictions before truth.
4. **Decision:** reject this candidate policy if the strongest frozen amount
   attack fails to improve over whole-note withdrawal in either activity regime
   through complete drainage, if advantage over its proper prior remains above
   five percentage points, or if new relationship leakage or failed exits
   defeat the declared requirement. Report incremental fee/latency changes
   separately from the already-failed 1%/2% cost targets. A directional privacy
   result cannot relabel that known cost failure or qualify the system.

Generate and validate each arm's actual proofs, native amounts, state transitions
and withdrawals before claiming a native counterfactual. Replaying the old proofs
with edited amounts or changing payout labels is not a valid arm. An arithmetic
screen can reject a policy cheaply first, but must be labeled as such.

The existing honest-price prior already has expected within-10% accuracy
`21103/100025 ≈ 21.10%`, above the unchanged 20% absolute target, although its
realized result here was 7/36. Separately report withdrawal-derived advantage and
absolute accuracy. No wallet can erase an observer's legitimate price prior;
the workload/absolute-target tension needs explicit requirements review, not a
post-result threshold or distribution change. Any claim of qualification remains
open even if a candidate reduces the additional withdrawal signal.

## Design records and source scope

Keeping a balance, choosing inputs and scheduling optional actions are wallet
policy experiments. Exposing the already-supported partial SPEND needs an RFC
update and a recorded decision on recovery, fees and policy; it does not itself
require new cryptography, setup or L1 rules. [ADR-0025](../docs/adr/0025-common-payout-offline-screen.md)
is precedent, not approval of a new policy. A multi-owner batch, changed note
arity, new operator dependency, altered proof relation or changed exit invariant
needs a new ADR and synchronized architecture/threat-model review before work.

Official GitHub head requests on this date reconfirmed Rusty Kaspa `4edcbbcc`,
docs `0ac77d04`, vProgs `f9b84a86`, research `c923faca`, and ZIPs `d167dd39`.
Exact source links below identify the full commits. The experiment still pins
Rusty Kaspa `01b532e8b553523216471682649693af92f0fd16`; current source is not a
claim about deployed nodes. [Toccata covenant state][toccata], the
[vProgs README][vprogs] and [Kaspa research index][kaspa-research] supply context;
the existing partial-withdrawal implementation gives no demonstrated reason to
introduce a new runtime here. The prior
[Orchard/Aztec/RAILGUN/Monero/MWEB review](shielded-kas-privacy-requirements-2026-10-20.md)
remains the broader design inventory; this focused review does not claim to
reaudit those implementations.

[observer]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/2c036c0fe01b11ee68306c90ca8cfd56d7e0235f/poc/shared-pool/native_usage_observer.py#L243-L382
[wallet]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/2c036c0fe01b11ee68306c90ca8cfd56d7e0235f/poc/shared-pool/src/two_input/wallet.rs#L466-L526
[circuit]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/2c036c0fe01b11ee68306c90ca8cfd56d7e0235f/poc/shared-pool/src/two_input/circuit.rs#L220-L273
[harness]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/2c036c0fe01b11ee68306c90ca8cfd56d7e0235f/poc/shared-pool/src/two_input/harness.rs#L453-L500
[native-builder]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/2c036c0fe01b11ee68306c90ca8cfd56d7e0235f/poc/shared-pool/src/two_input/mod.rs#L194-L214
[kaspa-tx]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/tx.rs#L178-L185
[zip315]: https://github.com/zcash/zips/blob/d167dd3994e40790971f8f00b0b330885d2c9fe5/zips/zip-0315.rst
[mweb]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md#L31-L33
[kappos]: https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-kappos.pdf
[toccata]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/covenant-state.mdx
[vprogs]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[kaspa-research]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/README.md
