# Frozen complete-cost and batching selection

Authority: owner's explicit request on 6 November 2026 Australia/Sydney.
Decision: ADR-0109. Source baseline: 9dd72bbb plus retained uncommitted isolated
wallet/common-set work. Freeze exact source/tool/dependency identities per run.

## Workloads and accounting

Three fresh synthetic wallets. Alice credits 3D, pays Bob 2D with D change; Bob
decrypts and spends that received note, paying Carol D with D change. All finish
with D. Execute D=10 KAS (30 useful KAS) and D=25 KAS (75 useful KAS). Count the
two real private payments once; deposit, change, refund and withdrawal are not
additional useful value. Integer sompi throughout.

The source funding UTXO is synthetic and unfunded. Sign and validate the initial
deposit transaction, every continuing state transaction and every terminal
payout. Include all native transaction bytes, script/compute/storage/transient
mass and actual input-output fee differences. Apply pinned default standard
relay fee 100 sompi/mass; never lower policy to create a pass. Record refunded
prepaid fees and locked-but-recoverable capital separately from consumed fees.

## Comparison

For the 30-KAS workload, compare the same wallet relation, keys, notes, deliveries,
value and native bank adapter:

1. Named direct exits, one wallet operation per complete outer proof/settlement.
2. Named direct exits with credit/payments batched and the three explicitly
   named authorizations batched. Each still binds its own public output.
3. Common-set exits, credit and both private payments in one complete outer
   proof, then three approved exits in a second complete outer proof.

Every receipt must be genuine, assumption-free and checked against the new guest
image and exact independent journal. Use existing RISC Zero Groth16 compression
and native verification; never substitute an old receipt or placeholder seal.
For the larger workload execute the batched path. Show exact per-transaction
fees and the marginal role of batching versus public-input packing. Retain any
native/cryptographic failure and its intended layer; fix ordinary bugs without
changing financial/privacy targets.

## Safety, failure and recovery

Preserve complete wallet constraints and current kernel NF checks. Bind full
actual effects and state changes; require all original authorization, backing,
principal, successor and program checks. Reject stale/wrong root/outpoint,
modified payout/payload/new root, duplicate/spent NF, malformed/old/fake proof,
fee/principal diversion, wrong successor and replay. Exercise u64/range behavior
where modified and preserve the existing complete-relation boundary tests.

One owner must restore its backup and withdraw without issuer/peers. A pending
deposit must be refundable only by its owner. An aborted joint round consumes
no principal and cannot apply a partial batch: show unchanged state/outpoint and
count spent proof/registration work. Retry is a fresh round; include its work.
No native fee is charged to a round with no submitted native transaction.

## Privacy

Keep all public wallet operations, actual native transactions, refunds, before/
after state, coordinator messages, receipts and public prover inputs. No private
truth or note opening enters the public prover. Blind registration must actually
run and eligibility must use genuine current wallet proofs. Seal each observer's
prediction before consulting separate synthetic truth.

For three known eligible input owners, count actual payout-key assignments:
named baseline must have one; candidate should retain more than one, including
one participant knowing its own payout. All-but-one/known owners, leaked origin,
leaked issuance randomizer and old public destinations must collapse ambiguity.
All native fee refunds remain visible and cannot count as extra honest peers.
Unknown fields refuse. Preserve hidden-label/order invariance and full truth.
RSA blindness, Groth16/receipt zero knowledge and encryption are assumptions;
no network anonymity, independent people or whole-payment privacy qualification.

## Cost and decision

Keep the old 2% complete-cost target unchanged and separately report exact fee
ratios and measured proving resources. No general product rejection follows from
one ratio. Compare actual matched attribution, fee premium/saving, latency,
cohort dependence, solo costs and abort costs to make an engineering judgement.
Local hardware has no provider invoice: report measured usage and tariff/rental
sensitivity, not a false all-in fiat price. If a cost is unmeasured, name it.

Current primitives only. No real funds, broadcasts, node RPCs, new asset,
privileged withdrawal authority, paid provider or paused MPC. No general runtime
or cryptographic invention. Keep failed receipts/attempts in fresh ignored runs.

Additive fairness control, frozen before any completed priced lifecycle: the
matched named-batch path uses the same guest/image and native adapter as the
common-set batch. Retain the original separate-transactions baseline too.
The first image allowing only single named withdrawals is a retained preflight,
not evidence about the matched batched comparison.

Interpretation guard, recorded before the first completed batch: also report
identified eligible owners' withdrawal amounts directly from the real issuance
proofs. Hiding the key assignment must not be called hiding those amounts, or
counted as six complete private-payment histories. This is a limitation to
measure alongside the selected key-ownership score, not a relaxed privacy target.
