# Continue the candidate: the fee floor is not the total price

Date: 6 November 2026, Australia/Sydney. Owner asked whether the previous
recommendation stopped too early and whether roughly 3% could be acceptable.

**Revised engineering judgement:** continue a bounded complete-cost investigation.
Failing the old 2% benchmark at one payment size does not establish that the
ownership mechanism is unusable or not worth its cost. The previous recommendation
against adoption was justified; treating the direct route as a dead end was too
categorical. No production adoption, revised qualification threshold or general
prover programme follows from this review.

## What 3.075% actually means

The [frozen actual-wallet experiment](../payment-set-withdrawal-2026-11-05/RESULT.md)
had 30 KAS of useful payments. Its native withdrawal pays 0.48 synthetic KAS and
three other proof checks have a 0.4425-KAS verification-only floor at 100
sompi/mass. Their sum is **at least 0.9225 KAS**, or **3.075%**.

That number is not a measured total or an upper bound. Missing items include
other transaction bytes/guards and funding/admission/settlement transactions,
proof-generation resources, service charges, aborted/retried rounds and recovery.
Refundable or recoverable locked state/permission capital must be shown separately
from money permanently spent. We cannot currently say the actual total is 3%,
4%, 5% or any other completed price. There is no finite measured upper bound yet.

## A useful reason to keep pushing

The cost depends heavily on how much computation is needed, rather than rising
directly with every extra KAS paid. Keeping exactly the same work and fee floor
gives this **arithmetic sensitivity**, not fresh executed payments:

| Useful payment value | Same-work fee floor | Floor as percentage | Room for other costs within 2% |
| --- | ---: | ---: | ---: |
| 30 KAS | 0.9225 KAS | 3.075% | Already exceeds the target |
| 60 KAS | 0.9225 KAS | 1.5375% | 0.2775 KAS |
| 75 KAS | 0.9225 KAS | 1.2300% | 0.5775 KAS |
| 100 KAS | 0.9225 KAS | 0.9225% | 1.0775 KAS |
| 300 KAS | 0.9225 KAS | 0.3075% | 5.0775 KAS |

Amounts affect some native storage/script costs; actual new policies/proofs must
be constructed and priced before these become quotes. Larger denominations can
also reduce available honest peers. A lower fee percentage cannot be counted as
a privacy improvement or assumed to preserve cohort availability.

The same balance may fund several private payments before withdrawal, which can
spread boundary costs over more useful payment activity. Every extra private
payment still incurs its own work. This is a workload to measure, not free or
unlimited amortization.

## Fee-rate correction

The benchmark price is not merely arbitrary historical congestion pricing.
The pinned official Kaspa source sets `DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE`
to **100,000 sompi per kilogram**, equal to **100 sompi per mass unit**. The
standard-admission code checks the required fee against normalized transaction
mass. The current official `master` config was also read during this review and
had the same default. This is source/policy evidence, not actual relay admission
or live inclusion.

Consequently the prior 1/10-sompi sensitivities are mathematical cases, not a
usable default-relay optimisation. Do not get a favourable result by lowering
node checks or assuming a miner will accept a nonstandard fee. No consensus or
policy change is proposed.

Sources: [default fee configuration](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/mining/src/mempool/config.rs),
[standard admission](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/mining/src/mempool/check_transaction_standard.rs).
The [machine-readable assessment](assessment.json) binds the source identities
and original execution and reproduces the arithmetic.

## Batching and the next decisive test

The shared implementation has already produced real outer proofs over public
wallet proofs. Reusing it to bundle many checks into one is a real mechanism to
investigate, not a consensus feature we need to invent. It is still **not** an
implemented or priced common-set withdrawal path. Its old destination parser and
permission checks need an explicitly verified replacement; old receipts cannot
prove changed code. Preserve the [prior batching screen](../payment-set-withdrawal-2026-11-05/BATCHING.md)
and do not count a hypothetical receipt reduction as a saving already earned.

The useful acceptance experiment is a source-bound full transaction/cost ledger:
deposit and funding, genuine private payments, joint withdrawal, independent solo
withdrawal, and an aborted round/retry. Show every actual transaction mass/fee,
proving/service expense, locked-but-refundable capital and final unpaid balance.
Measure the original 30-KAS example and at least one larger same-work workload.
Report direct and shared-batched variants only at their actually executed layers.

Privacy must remain part of that decision: the existing result hides payout
assignment in a declared logical transcript with three synthetic wallets. It
does not yet demonstrate internet anonymity, honest cohort availability or
complete payment privacy. A usable all-in fee near 3% could be worth exploring;
neither that price nor that stronger privacy has been established.

The frozen 2% test remains a failure. This review changes the forward research
judgement, not old results, observer knowledge, consensus, safety invariants or
the owner's fee acceptance criteria. No funds, RPCs, broadcasts or provider
allocations occurred.
