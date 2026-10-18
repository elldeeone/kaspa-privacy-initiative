# Offline paid-claim recovery: R07

**R07 has model coverage.** The subsequent [R08–R16 programme](PROGRAMME.md)
adds bounded offline fork/crash and shutdown controls, with 80 tests total. This
page retains the original 66-test R07 results and scope.

Paid exits, refunds and fees stay consumed after restore. The worked three-user
ledger drains to zero in both fee-last and
user-last orders, and a fee-free one-note exit consumes the exact final reserve.

These are **synthetic payment effects**, not native KAS transactions or payment
proofs. All runs are offline. Historical ideal-proof acceptance and the separately
trusted model checkpoint remain assumptions. Single payment is enforced on the
supplied ordered history; a stale/forked checkpoint cannot establish that no
later payment occurred. [ADR-0013](../../docs/adr/0013-offline-paid-claim-recovery.md)
records the bounded extension to [R05/R06](TRANSITIONS.md).

## Reproduce

Use the existing [dependency setup](RECOVERY.md#run-it) before going offline.
From the repository root, choose a new suffix rather than reusing any directory:

```bash
export PYTHONPATH=.local/shielded-design/python
python3 -O poc/shielded-design/recovery_fixture.py .local/r07-base-NEW
python3 -O poc/shielded-design/recovery_payout_trials.py prepare .local/r07-base-NEW .local/r07-ready-NEW
python3 -O poc/shielded-design/recovery_payout_trials.py pay-next .local/r07-ready-NEW .local/r07-paid1-NEW
python3 -O poc/shielded-design/recovery_payout_trials.py pay-next .local/r07-paid1-NEW .local/r07-paid2-NEW
python3 -O poc/shielded-design/recovery_payout_trials.py pay-next .local/r07-paid2-NEW .local/r07-paid3-NEW
python3 -O poc/shielded-design/recovery_payout_trials.py pay-next .local/r07-paid3-NEW .local/r07-paid4-NEW
python3 -O poc/shielded-design/recovery_payout_trials.py pay-next .local/r07-paid4-NEW .local/r07-paid5-NEW
python3 -O poc/shielded-design/recovery_payout_trials.py audit .local/r07-paid5-NEW .local/r07-audit-NEW
python3 -m unittest discover -s poc/shielded-design -p 'test_*.py' -v
```

The default is fee-last. Repeat in new directories with `--last user` on each
stage to pay the fee first and finish with a user payout. Each invocation starts
a new process from the previous public archive, separately supplied model
checkpoint and declared synthetic user backups. Before continuing, it retries
already paid claims and checks that economic state remains unchanged. The final
audit is another restore after the zero-reserve payment.

Wallet/executor roles coexist in this harness; this is not independent-operator
or enforced confidential-witness recovery. Directories are 0700 and copied
backups/private results are 0600, with overwrite refused. Keep those files
private. Stdout gives only stage/scope and the no-chain/no-native-payout status.

## Version 3 model effects

Archive `kpi-model-records/v3` requires checkpoint `kpi-model-checkpoint/v3`.
Existing v1/v2 archives remain readable; their claims begin unpaid. Backups,
note/nullifier derivation, statement version and economic domain are unchanged.
v3 also accepts prior refund requests; adding one after payment preserves v3.

| Event | Exact fields after `seq`, `kind` | Checks and effect |
| --- | --- | --- |
| `payout` | `claim`, `recipient`, `principal`, `rent`, `remaining_reserve` | Existing unpaid exit/refund claim; exact destination/principal/rent; exact reserve subtraction; checked u64 principal-plus-rent output. Mark claim paid, decrease reserve by principal, move locked rent to paid rent. A refund deposit becomes `refunded`. |
| `fee_payment` | `claim`, `recipient`, `amount`, `remaining_reserve` | Existing unpaid fee claim, exact recipient/amount/residual. Mark fee paid and decrease principal reserve; do not touch rent. |

Both execution and public replay check these rules. Paid claims and consumed
operation identities remain in reconstructed state; restoration never resets
their paid flags. Invalid attempts append a rejection no-op without changing
economic state. No payment event carries a host validity flag, operator
withdrawal signature, native transaction ID or fabricated chain receipt.

At every event:

```text
reserve = private liabilities + pending deposits + unpaid claims + unpaid fees
locked rent = rent attached to unpaid exit/refund claims
funded rent = available sponsor rent + locked rent + rent already returned
```

Wallet reports exclude paid claims from unpaid exit/refund amounts. Any unused
sponsor rent remains separate even when principal reserve reaches zero; no
sponsor withdrawal mechanism is invented here.

## Results and evidence

[offline-payouts.json](evidence/offline-payouts.json) retains source/artifact hashes
and results for one producer plus **14 fresh continuation/audit processes**,
all with Python `-O`, covering both orders. Public final histories/checkpoints
and a fee-free terminal example are retained. No private backups or raw wallet
reports are published. Prior 42-test and 56-test reports remain historical
evidence for their original source hashes.

The starting reserve is 2,000,000,000 sompi. Preparation converts the remaining
private notes and Carol's pending deposit into unpaid claims, preserving all
principal. Three additional permissions need 150,000,000 external rent sompi;
with the existing 50,000,000, total rent is 200,000,000.

| Terminal accounting | Sompi |
| --- | ---: |
| Alice paid principal | 600,000,000 |
| Bob paid principal, including original exit | 1,099,999,000 |
| Carol paid refund principal | 300,000,000 |
| Authorized fee paid separately | 1,000 |
| Remaining principal reserve and outstanding liabilities | 0 |
| Rent returned separately | 200,000,000 |
| Remaining available/locked rent in this fixture | 0 |

Each order has four user payments and one fee payment. Fee-last finishes from
1,000 sompi to zero; user-last finishes from 899,999,000 sompi to zero. The
fee-free retained example pays a 1,000,000,000-sompi principal plus separately
funded 50,000,000 rent and leaves zero reserve. No actual miner/network fee is
modeled; the 1,000-sompi amount is the existing authorized model fee liability.

**66 tests passed in this report:** 24 original model, 18 R01–R04, 14 R05/R06 and 10 R07 tests.
R07 covers fresh-process payment/restoration, exact terms, unknown/duplicate
claims, exit/fee confusion, paid refunds rejecting later credit, matching format
versions, omitted/reordered/forged public effects, and malformed integer values.
Forty seeded terminal vectors exercise both payment orders over 20 principals
while preserving an unused 21-sompi sponsor balance. Separate fee-free boundary
cases include 1 sompi, u64-max minus rent, and output overflow at larger values.
Overflow keeps the claim unpaid and backed; it is a modeled liveness limitation,
not permission to truncate rent or principal. Native output capacity is unproved.

## Adversarial second pass and remaining limits

- **Inflation/double payout:** claims remain recorded as paid, and current-state
  checks precede mutations. Restoring public history preserves the same consumed
  identities. Altered terms/repeated payments fail without economic changes.
- **Reserve release:** the exact existing claim determines payment terms. No
  operator/admin withdrawal authority or native release condition is added.
  Terminal equality is modeled, not evidence that the current native builder or
  permission scripts accept the required final output shape.
- **Privacy:** public histories contain intentionally synthetic payment terms;
  secrets and derived wallet reports remain private. This proves no anonymity,
  query privacy, cryptographic soundness or protection between co-located roles.
- **Dependency loss/stale state:** a missing payout under the retained later
  checkpoint fails completeness. Replacing that checkpoint with an older valid
  one can hide later payments; no offline digest establishes chain freshness.
- **Reorg/crash:** monotonic effects only. No rollback of orphan payments,
  crash-safe journal, unknown submission handling or distributed writer control.
  Later R08/R09 controls cover local model forks and process crashes only;
  native rollback, hardware power loss and network submissions remain open.

R07's model slice is complete. Real-proof/native R01–R07 acceptance requirements
remain open, together with the full R08–R16 requirements; the later offline
programme does not qualify a funded experiment or production use.
