# Busy payments: fewer fees, a real latency tradeoff, and safe cancellation

**Decision:** keep the optional privacy mechanism and reusable approvals. Stop
obsolete proving when an authenticated bank advance is learned, and preserve the
original request's queue age. Keep batching optional: the measured batch saves
fees but makes incoming payments wait substantially longer. Slow proof generation
remains the next practical blocker. No consensus change or competing production
architecture is selected.

Both complete offline histories finish with **40 KAS of principal paid and zero
reserve/liability**. The source UTXO is synthetic; no funds, broadcast or accepted
chain settlement are claimed. No new financial-privacy qualification follows.

## Complete, matched comparison

The [selection](SELECTION.md) preceded execution. Four wallet processes generate
real encrypted notes, recipient re-spends and complete wallet proofs using the
unchanged depth-four circuit/setup. Alice pays Bob 20, Bob pays Carol 10, Alice
pays Dave 10; Dave then pays 2, 1, 3 and 1. Useful private payments total **47 KAS**.
Alice/Bob/Carol approve a 10-KAS common-set withdrawal once. Later cashouts pay
the remaining five notes. Four processes on one machine are not independent users.

A genuine competing receipt is prepared beforehand on the single GPU, charged
to both arms, and accepted 30 seconds into actual withdrawal proving. Actual
wallet requests arrive during proving. The obsolete proof deliberately finishes
as a rejection control. The reference and candidate then extend the identical
accepted prefix, sequentially on the same GPU, using the same original requests
and approval bytes. Neither policy is asserted to describe a production service.

| Measurement | Admission-first, individual payments | Preserve withdrawal age, batch payments |
| --- | ---: | ---: |
| Successful settlement receipts, excluding funding | 7 | 5 |
| Whole-route native fee quote | 1.154101 KAS | 0.830131 KAS |
| Native quote / 47 useful KAS | 2.4555% | 1.7662% |
| Group wait from first proof start | 22.31 min | 14.63 min |
| Incoming payment proof readiness waits | 8.19 / 6.73 / 5.29 min | 20.36 / 16.37 / 12.35 min |
| Charged complete proving, including obsolete work | 46.43 min | 46.15 min |
| New cohort approvals after bank advance | 0 | 0 |

The candidate saves **0.323970 KAS (28.07%)** in native quotes and reduces this
withdrawal wait **34.43%**. Incoming-payment waits are worse. They measure request
to complete-proof readiness using original same-host timestamps; native Full
validation follows. They are not chain-confirmation times. This is one observed
pair, with colocated wallet processes and reused common-prefix work charged to
both arms, not a sustained-load or independent-client performance qualification.

## Cancellation follow-up

The [additive selection](CANCELLATION-SELECTION.md) keeps the original failed-work
evidence intact. After the full campaign, a real CUDA proof of that obsolete work
item is interrupted after **30.398 seconds**. Both owned processes stop; cleanup
takes **0.135 seconds**. A fresh replacement proof takes **437.249 seconds**.
Full public replay finishes **468.210 seconds (7.80 minutes)** from control start,
using the same original approvals.

This replays the retained post-advance state with a declared detection timer;
it does not observe another bank advance or make another live payout. Only the
native proof witness is replaced in a temporary history copy. Exact input,
journal, transaction body/IDs, descendants and all eight payout spends still
validate. Original records are untouched.

This is a measured worker-control improvement, **not a repeated complete arrival
comparison**. Earlier completion can change how many payments are waiting when a
batch starts. Do not combine its timing with the first table as one measured
fully optimized route or promise the same two-transaction saving under every load.

## Accounting and costs

Integer-sompi [accounting](run/ACCOUNTING.json) reconciles both 43-KAS sources:

- Candidate: 40 principal + 0.996322 ordinary change + 1.173547 allowance refund
  + 0.830131 native fees.
- Reference: 40 principal + 0.996322 ordinary change + 0.849577 allowance refund
  + 1.154101 native fees.
- Eight restored-key self-spend controls quote another **0.021008 KAS**; their
  recipient outputs retain 39.978992 KAS. These ordinary subsequent spends are
  reported separately from settlement fees. No reserve/rent remains in this bank.

There are eleven complete proving executions in the comparison and one fresh
complete execution in the cancellation check, plus its interrupted partial job.
The comparison also generates sixteen genuine wallet proofs; wallet calls,
including cold parameter checks, take 363.832 seconds. Retaining fully checked
parameters in each wallet avoids repeating roughly 65-second cold calls for each
operation; later individual proof calls take about 8.5 seconds.

The frozen hypothetical $0.13/hour and KAS/USD 0.02987 valuation gives native plus
complete-proof-only subtotals of **8.89%** (candidate) and **9.62%** (reference),
including deliberately completed obsolete work. These are not current offers,
provider-speed qualifications, invoices or complete service prices. Wallet CPU,
cold loading, optional protected-registration work, operators/transport,
availability, whole-host electricity and depreciation remain unpriced. Actual
provider charges are zero. The unchanged **2% complete-cost target is unqualified**;
this does not establish a universal cost floor or reject larger-value payments.

The paired local campaign takes 78.93 minutes, samples 182.26 Wh of device-wide
GPU energy, peaks at 6,096 MiB of owned CUDA memory and 17.07 GB of summed process
RSS including wallets. Sampling can miss peaks/double-count shared memory;
GPU power includes display/idle and excludes whole-host energy.

## Privacy and evidence limits

The [observer views](run/OBSERVER-VIEWS.json) show three actual identified
entitlement responses containing each claim nullifier and its payout together:
**one** ownership assignment. This test does not repeat protected registration;
the earlier conditional origin benefit remains separate. `SERVICE.json` is the
research controller's complete IPC trace, including private client instructions.
Those instructions are not automatically withdrawal-service knowledge; the
identified mapping above needs only the actual registration responses.

With the separately supplied contact graph and frozen ordinary-change workload,
four active notes, three identified 10-KAS claims and Dave's remaining note
reconstruct the original 20/10/10 payments. The two later Dave-to-Alice payments
are not individually recovered from their sum alone. No hidden note labels or
private instruction amounts are used as observer facts for that control.

Historical-anchor/current-nullifier, fee-cap and exact effects checks remain.
The old native transaction fails current-outpoint admission; transplanting its
genuine proof into the replacement fails `ZkIntegrity("Groth16 verification failed")`.
Six guard controls and queued child-before-parent/double-spend controls refuse.
Independent public replay verifies both complete histories, original approval
byte equality, real payout ancestors and eight restored-key spends; it also
verifies the fresh cancellation witness in the unchanged history.

The experiment uses fifteen of sixteen leaves and one external advance. It
cannot qualify unlimited traffic, hostile competing operators, reorg recovery,
all-service-loss availability or production wallet security. The local signing
helper is driven by a trusted research controller. No funded testnet readiness
or trial is claimed. The next work should reduce/qualify proving latency and
complete costs within the shared direction, preserving optional privacy rather
than adding more transport or queue machinery.

Sources, exact pins, retained failed preflights and adversarial review:
[sources](SOURCES.md), [shared-upstream refresh](UPSTREAM-REFRESH.md),
[attempts](ATTEMPTS.md), [review](REVIEW.md), [public manifest](run/MANIFEST.json).
