# ADR-0023: Test equal net credits as the next wallet funding policy

Research decision, 2026-10-20 (Australia/Sydney). Applies to the shared-pool
candidate only. No consensus, covenant, proof relation, setup or invariant
change; no production adoption or upstream approval is implied.

## Problem and evidence

[H11](../../poc/shared-pool/PRIVACY-STUDY.md) retained fresh proofs, but public
amounts and complete drainage still recovered most funding origins. Equal gross
contributions left different private balances: the first bootstrap's fee is
112,000 sompi below the later admission fee. The smallest candidate change was
to equalize the private credit after that fee.

[H12](../../poc/shared-pool/NORMALIZED-DEPOSITS.md), preregistered at `a522e59`,
compares varied, equal gross and equal net policies with equal total funding
and common payment/exit topology. In 32 paired ledgers per regime, unique funding
reconstruction after drain falls from 91.875% / 84.115% under varied funding
and 24.063% / 22.656% under equal gross funding to zero under equal net funding.
All four deposits remain feasible; fixed deposit rankings guess about 25–27%
correctly. This passes the frozen screen, not an anonymity standard. Genuine
native calibration matches both workloads and drains both saved/fresh alternatives.

## Decision

Keep equal net credit as a **candidate wallet policy for compatible deposits**,
alongside fresh normal-path proofs and private saved exit fallbacks. A wallet
adds its actual admission fee to the intended private denomination. No new
transaction, fee subsidy, privileged signer or waiting lock is required by the
policy. The existing covenant remains amount-flexible; nonmatching deposits are
valid and can reduce privacy. Do not silently enforce a pool admission whitelist.

The unchanged payment and independent-exit mechanics passed a complete TN10
rehearsal and fresh measured trial: four wallets, two private payments, ten
unchanged-proof exits and zero reserve in each. The report records actual chain
outcomes/costs and the earlier recorder failure separately from synthetic
inference. This validates the tested mechanism, not anonymity. Preserve
individual exits even when leaving early reveals origin.

## Assumptions and rejected expansions

The favorable study has four equalized deposits before any private payment,
all exiting with fresh proofs. This gives a deposit-label permutation symmetry;
it does not establish that four unknown people are equally likely sources.
Actual test funding is publicly shared. Interleaving, mixed denominations,
external knowledge, fallback use and network observations remain open.

Do not claim that the policy conceals all payment relationships or that zero
unique assignments means complete privacy. Do not infer arbitrary-amount support
or a practical waiting-time guarantee. Test the effect of interleaved arrivals
before generalizing beyond the closed workload. Existing fee-change, history,
reorg, setup and contention assumptions continue to apply.

Partial withdrawals and multi-input aggregation would change the private
relation and require separate decisions. H12 does not establish a need for
either, a new token, vProgs, or a consensus change to obtain this bounded benefit.
