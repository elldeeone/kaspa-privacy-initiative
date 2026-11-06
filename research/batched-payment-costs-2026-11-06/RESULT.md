# Batched payment costs and payout ownership

**Decision: keep the optional common-set withdrawal mechanism within the shared
batching direction. Its extra privacy is inexpensive. This is not a reason to
replace Olaf's architecture, and it does not solve the complete financial-privacy
goal.** Small payments still have a material proving cost and delay.

The actual private-note wallet credited Alice, privately paid Bob, and had Bob
decrypt and spend that received note to pay Carol. All three then withdrew their
full balances through real current-rule native transactions and genuine compressed
RISC Zero proofs. The supplied initial funding UTXO is synthetic: these are
**offline Full validation and default-relay quotes**, not paid fees or accepted
chain evidence. No consensus changes, new asset, real funds or provider allocation.

## Complete successful paths

At 100 sompi/mass, the verified default minimum relay policy:

| Path | Useful payments | Native transactions | Total native fees | Fee share | Outer proving |
| --- | ---: | ---: | ---: | ---: | ---: |
| Individual named withdrawals | 30 KAS | 7 | 0.981488 KAS | 3.2716% | 24m 59s |
| Batched named withdrawals | 30 KAS | 3 | 0.333552 KAS | 1.1118% | 17m 42s |
| Batched common-set withdrawals | 30 KAS | 3 | 0.333552 KAS | 1.1118% | 17m 44s |
| Batched common-set withdrawals | 75 KAS | 3 | 0.333552 KAS | 0.4447% | 17m 42s |

Each successful path ends with zero reserve principal, private liability, unpaid
exits and active bank UTXOs. The batch's native fees comprise 0.003678 KAS for
deposit, 0.164787 for the credit/payment batch, and 0.165087 for withdrawal.
The initial 2 KAS prepaid allowance is **not** a 2 KAS fee: 1.670126 KAS returns
unused. Ordinary funding change is another 0.996322 KAS. Principal, refunds,
change and consumed fees reconcile exactly to the synthetic source value.
Useful payments count Bob's received payment and Carol's subsequent payment;
deposit, change and withdrawal are not counted again as useful value.

Hiding payout ownership adds **zero native fee** over matched named batching.
The 30-KAS privacy path uses 25.80 seconds for real blind registration/eligibility
proofs. Including observed timing variation, its measured sequential work is
27.24 seconds longer than named batching: 1,157.41 versus 1,130.17 seconds.
This is one same-host measurement, not a universal timing estimate.

## Computer work and economic interpretation

The local machine has no provider invoice. Its work still consumes hardware and
electricity. A retained [Kraken snapshot](https://api.kraken.com/0/public/Ticker?pair=KASUSD)
values KAS at $0.02987. The retained public Runpod catalogue references $0.13/hour
for RTX 3070, with **null live price/stock fields**. This is a sensitivity rate,
not an executable offer or measured remote performance. The exact requests are
in [valuation assumptions](VALUATION-ASSUMPTIONS.json) and
[provider reference](PROVIDER-REFERENCE.json).

Valuing **local measured work** at that reference and adding an assumed active
20-GB disk gives:

| Path | Network + proof work + active disk | Share of useful payment value |
| --- | ---: | ---: |
| Named, separate, 30 KAS | $0.08712 | 9.7224% |
| Named, batched, 30 KAS | $0.05163 | 5.7622% |
| Common-set, batched, 30 KAS | $0.05264 | 5.8743% |
| Common-set, batched, 75 KAS | $0.05252 | 2.3444% |

The privacy difference in the matched 30-KAS model is about **$0.001**, or 0.1121
percentage points. Most cost belongs to the payment/proof engine regardless of
whether destinations remain individually named. Larger value amortizes that
mostly fixed cost; this does not improve privacy by itself.

These are conditional warm-work models. Cold startup, independently available
parameters/history, idle worker utilization, actual cohort waits, active-pool
races/reproving, operator margin, anonymous transport and retained storage are
not fully priced. GPU energy is device-wide, including display/idle, and excludes
unknown CPU/whole-host energy and depreciation. Retain measured physical usage
and multiple tariff sensitivities separately. **The original 2% complete-cost
target is not qualified.** A modeled 2.34% at 75 KAS is compatible with the owner's
willingness to consider about 3%, subject to the unpriced items.

## What privacy changed

With all public native transactions, fee refunds, wallet operations, canonical
state, coordinator messages and public prover inputs retained:

- Both named paths identify all three payout-key owners: one assignment.
- Common-set paths retain six assignments; each key can belong to three owners.
- One participant knowing its own key leaves two assignments.
- All-but-one knowledge, known old destinations, leaked redemption origin or
  identified issuance randomizers reduce the score to one.

The real issuance proofs still identify each participant's withdrawn amount:
10 KAS each, or 25 KAS each in the larger case. **Six key assignments are not six
private payment histories.** Amount fields remain transparent. This is a narrow
address-ownership benefit under the declared cryptographic/logical-interface
assumptions. Three local wallets do not establish independent people, anonymous
network transport, malicious cohort resistance or later spending privacy.

Baseline and candidate are separate counterfactual worlds sharing a fixture.
Publishing a prior individual destination map to a real candidate observer defeats
the benefit; that is a retained failure control. No privacy is claimed for the
research fixture against someone with its combined truth/artifacts.

## Evidence and decision limits

The four complete core worlds have passed a new-process replay using public files
only: all 12 complete receipts, original wallet proofs, native Full checks,
current NF/state lineage and real blind credentials. Predictions were sealed
before reading separate private truth; label/display-order controls and refusal
of unknown fields pass. Critical guest, wallet relation and native policy sources
still match the completed run's frozen hashes.

The completed recovery/failure campaign has a separate public replay:

- Withholding the third approval rejects in the actual guest, retaining the exact
  state/outpoint with zero principal loss and zero native fee. Six generated
  wallet proofs consume 53.36 seconds; about $0.00193 at the reference rate.
- A fresh round/key registration and genuine retry withdraw all principal. Its
  0.165087 KAS fee is the successful withdrawal fee, not an extra abort charge.
  Registration, owner proofs and the complete outer proof take 581.99 seconds.
- All three owners restore their wallet backups and choose fresh native keys.
  Each exits without issuer/peer approval. Solo fees are 0.163022, 0.163022 and
  0.163011 KAS. The complete deposit/payment/three-solo route is 0.657520 KAS
  (2.1917% of 30 KAS) before computer costs. Every genuine old-NF replay rejects
  after paid-record normalization, even at an accepted historical anchor.
- The pending-deposit owner refunds all 30 KAS; wrong-owner and replay attempts
  reject. Deposit plus refund native fees total 0.166689 KAS.
- Twenty-four adversarial controls cover actual input/root/effects/payload,
  modified payouts, duplicate/current NFs, partial groups, range/overflow,
  principal/fee separation, successor policy and strict image/journal binding.

All 17 distinct complete receipts across core and recovery paths have been
verified again from public files, with independent wallet verification and native
Full validation. Sampled proof-phase GPU memory peaks at 6,096 MiB. The privacy
batch uses about 43.69 Wh of device GPU energy at 30 KAS and 43.59 Wh at 75 KAS;
that is not whole-host energy. Peak sampled summed process RSS reaches about
5.71 GiB in the larger core proof intervals; sampling may miss peaks and can
count shared memory twice. Checked parameter loading/restoration/public replay
before the failure experiment takes another 55.37 seconds in its measured setup
phase. Do not hide that recovery work in a claim that a seed alone suffices.

The retained attempt ledger distinguishes one host serialization bug, a manually
stopped successful preflight, and one backend segment-verification failure from
the completed campaigns. The failed input later passes unchanged; the root cause
and production failure rate remain unqualified. Every earlier run remains intact.
These research overheads are separate from one successful payment's recurring
model, and no invalid/partial receipt counts as a positive result.

The initial source, finite admission and fee allowance are explicit. There is no
test of arbitrary later deposits, fee top-ups, live reorganization/finality,
service-loss availability or active-pool contention. Approvals bind an exact bank
outpoint, so accepted state changes can make them stale. The bank adapter is an
isolated experiment, not a production upgrade or a selected architecture.

The [second-pass review](REVIEW.md), [source reuse](SOURCES.md),
[frozen selection](SELECTION.md) and [ADR-0109](../../docs/adr/0109-complete-cost-and-batched-payout-test.md)
record the assumptions. An existing checked-before-pinning parameter path is a
specific next proving-cost optimization to assess; its savings have not been
measured here. Keep the privacy mechanism, contribute within the shared batching
work, and test actual cohort/network behavior and state contention before a live
product claim. No change to consensus is required for the demonstrated behavior.

## Retained packet and checks

The [public evidence packet](run/MANIFEST.json) retains a finite allowlist of
inputs, receipts, native transactions, observations, seals and source/resource
snapshots. Private wallet/native secrets and proving-parameter files are excluded.
The [full accounting](run/costs/COSTS.json), [ownership controls](run/scores/VALIDATION.json),
[core public replay](run/replay/public-replay.json),
[recovery public replay](run/extra-replay/extra-public-replay.json) and
[attempt ledger](run/ATTEMPTS.json) are separate source-bound records.

Run `bash poc/batched-payment-costs/check.sh` for hash/accounting/observer checks
and a new-process public proof/native replay. The original payment-set checks,
full relation boundaries/malformed-proof tests and historical public replay
still pass. Documentation/research-knowledge checks do not qualify cryptography,
network privacy, paid fees or accepted chain history.
