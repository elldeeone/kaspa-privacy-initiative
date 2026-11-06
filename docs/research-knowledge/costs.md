# Cost and performance lessons

[Knowledge guide](README.md) · [Proof evidence](proofs.md)

## Keep profiles and denominators together

| Retained result | What it says | What it does not say |
| --- | --- | --- |
| [Actual-wallet common-set integration](../../research/payment-set-withdrawal-2026-11-05/RESULT.md) | Full-statement digest packing reduces verification floor 177,500 to 147,500 mass; three withdrawals fit at 457,671 quoted compute mass. The selected route still has an optimistic 3.075% floor at 100 sompi/mass against 2%. | No complete-route/paid fee pass, general cohort scaling, or lower bound on the separate outer-proof batching architecture. |
| [matched lifecycle checkpoint](documents/fdfd544f40bd93450cab30c7bda64dcab3ec69fa.txt) | Six payments/nine payouts paid 264,166,000 sompi on 2,100,000,000 useful sompi: 12.5793%, failing 2%. | Faster payment proving alone cannot repair the measured fee gap: other costs alone remain 148,795,600 sompi, above 42,000,000. |
| [two-recipient offline layout](documents/e26b3bf00641382ebabf9b4b577cc31ee1c27d7d.txt) | The separate offline supplied-UTXO layout with two useful 10-KAS recipients calculated approximately 1.85% per payment. | It was not broadcast, is not the same benchmark, and one useful recipient plus change failed. |
| [authenticated cache measurement](documents/90a8571364109e2cb5f360b33e966fedd0ca7308.txt) | Parameter loading fell from 156.38 seconds to roughly six seconds; one genuine load/prove/verify run took 30.87 seconds. | About 5.39 GiB and missed warm-proof/memory targets remain; cache/CPU conditions prevent a universal speedup claim. |
| [selected HMAC sizing](documents/7eb487100c8e69f48abe417e7bcd98c681b24e3b.txt) | The selected synthesis reduced constraints by 31.20%. | That sizing packet did not complete setup, proving, native validation and the full negative suite. |
| [independent RTX 3070 reproduction](documents/b3ed0a758e9200456318a9e26b8342db78d5c327.txt) | Four retained outer receipts completed in 627.3 seconds on RTX 3070 under the documented adaptation. | Do not extrapolate another curve, proof profile or GPU from that timing. |
| [compression qualification note](documents/4b69b4e8de333d2e96ec10eb2ddc82474a7e4ee6.txt) | A selected compression run measured sampled VRAM and process memory separately. | A setup file's size is not a VRAM formula; sampling may miss peaks, and an upstream benchmark row with RAM=0 means unmeasured. |

Compute mass, storage mass, transient/overall mass, committed script budget,
units consumed and paid transaction fees are different quantities. Use final
SDK-decoded transaction bytes and the actually selected policy for quotes;
separate quotes, local Full validation, relay policy and paid chain evidence.
A cheaper bare verifier is not a cheaper complete lifecycle.

## Carry into the next measurement

The [6 November cost review](../../research/payment-set-withdrawal-2026-11-06-cost-review/RESULT.md)
corrects an overly categorical stop recommendation: 3.075% was a lower bound at
one workload, not a measured total or product impossibility. Keep the old 2%
failure. The pinned default relay minimum is 100 sompi/mass; earlier 1/10-price
sensitivities are not default-relay savings. Larger same-work payment amounts
and existing batching remain opportunities to measure with complete costs.

Use integer sompi end to end. Include deposits, funding, private transfers,
change, all exits, rent, pool/sponsor fees and useful-recipient value under the
same declared accounting scope. Report remaining principal, liabilities and
state rent independently. The successful depth-four attempt's zero user
principal does not recover earlier halted attempts' retained test-KAS reserves.

Current tool/process repairs improve reproducibility; they establish no new
GPU benchmark, cryptographic performance result or paid-fee result. A useful
optimization is a candidate to assess when its component is needed, not a reason
to restart an unrelated proving campaign.

## 6 November measured batching follow-up

The [actual-wallet batched comparison](../../research/batched-payment-costs-2026-11-06/RESULT.md)
uses genuine compressed outer proofs and native Full validation. Complete native
quotes fall from 3.2716% to 1.1118% for 30 useful KAS; named and common-set batches
have identical native fees. At 75 useful KAS the native share is 0.4447%. Proving
still takes about 17.7 minutes; the conditional reference valuation including
network/prover/active disk is about 5.87% at 30 KAS and 2.34% at 75 KAS. Keep
hypothetical/reference pricing separate from actual invoices, GPU-only energy
from whole-host cost, refunded allowance from fees, and the quiet fixture from
active-pool/cohort delays. The original 2% complete-cost target remains open.


## Requester and pinned-key follow-up

The [subsequent complete quiet path](../../research/withdrawal-request-and-busy-pool-2026-11-06/RESULT.md)
uses actual onion-registered keys, genuine complete receipts and native Full
validation. Existing program-key pinning reduces proving 17.73 to 14.35 minutes
(19.11%); the exact-input control separately saves 20.73% wall time and 19.93%
total cycles. Native fees stay 0.333552 KAS. Holding earlier tariff/valuation and
non-outer overhead constant gives a 5.04% warm subtotal at 30 KAS, or 2.02% when
extrapolating unchanged work to 75 KAS. The new 75-KAS case was not executed;
Tor/operator/availability remain unpriced. No two-percent complete-cost pass.
An unrelated accepted update wastes 18.465 seconds of two owner approvals, with
no stale-transaction fee. The 0.821538-KAS stress-route quote also includes an
extra self-payment and two solo exits: do not attribute all of it to contention.
