# Kaspa mempool replacement source audit

Checked: 2026-11-09 (Australia/Sydney)

Official `kaspanet/rusty-kaspa` `master` resolved read-only to
[`4863866fce8439d0305b410fc4d802e7261d54d0`](https://github.com/kaspanet/rusty-kaspa/commit/4863866fce8439d0305b410fc4d802e7261d54d0).

## Verdict

Current `rusty-kaspa` source supports mempool replace-by-fee (RBF) for the
proposed payout shape. A higher-fee payout that spends the same permission and
reserve inputs but uses a different sponsor input can replace the lower-fee
candidate **while the lower-fee candidate is still in that node's mempool**,
provided:

1. the replacement is submitted through the dedicated replacement RPC (or
   reaches peer relay under the allowed policy);
2. every conflicting input is owned by exactly one mempool transaction;
3. the replacement's fee per contextual mass is strictly greater;
4. the different sponsor input is independently spendable; and
5. the replacement passes all ordinary transaction, script, mass and standardness
   validation.

This is not replacement after confirmation. Once either payout is accepted in a
block, the node removes its mempool double spends and the shared permission and
reserve outputs are spent. The alternate candidate is then an invalid double
spend, not an RBF candidate.

## Primary-source findings

### Dedicated RPC and policy

- Ordinary RPC submission uses `RbfPolicy::Forbidden`, so resubmitting the
  higher-fee candidate through the ordinary submit call is expected to fail as a
  mempool double spend. The dedicated replacement path uses
  `Orphan::Forbidden` and `RbfPolicy::Mandatory`, broadcasts the accepted
  replacement and returns the removed transaction. See
  [`flow_context.rs` lines 675–721](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/protocol/flows/src/flow_context.rs#L675-L721)
  and the public RPC handler in
  [`service.rs` lines 683–724](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/rpc/service/src/service.rs#L683-L724).
- `Mandatory` RBF requires at least one double spend, requires all double spends
  to belong to one mempool transaction, and requires a higher fee/mass ratio.
  `Allowed` RBF can insert a non-conflicting transaction or replace conflicts.
  See the policy definition in
  [`mempool/mod.rs` lines 189–233](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/mining/src/mempool/mod.rs#L189-L233).

### Exact replacement rule

- Mandatory replacement rejects zero conflict owners and more than one conflict
  owner. On one owner it validates, removes that transaction and inserts the
  replacement. See
  [`replace_by_fee.rs` lines 43–54 and 118–133](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/mining/src/mempool/replace_by_fee.rs#L43-L54).
- The comparison is strictly `replacement_feerate > original_feerate`; equality
  fails. See
  [`replace_by_fee.rs` lines 150–168](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/mining/src/mempool/replace_by_fee.rs#L150-L168).
- The error is explicitly a mempool rule rather than consensus:
  [`TxRuleError::FeerateTooLow`](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/consensus/core/src/errors/tx.rs#L99-L102).
- All isolation, consensus-context, mass and standardness checks run before the
  conflicting transaction is removed. See
  [`validate_and_insert_transaction.rs` lines 20–82](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/mining/src/mempool/validate_and_insert_transaction.rs#L20-L82).

### Different sponsor input is compatible

The rule is based on overlapping spent outpoints and fee/mass, not identical
input sets or transaction shape. The official test suite includes a successful
mandatory replacement where only part of the input set overlaps, as well as
successful higher-fee two-input replacements. See
[`manager_tests.rs` lines 530–577](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/mining/src/manager_tests.rs#L530-L577).

**Inference for this repository:** candidates `(permission, reserve, sponsor A)`
and `(permission, reserve, sponsor B)` have two conflicts, but both conflicts are
owned by the same lower-fee payout transaction. They therefore satisfy the
single-conflict-owner shape. Sponsor B still has to be a valid unspent input, and
the resulting signed transaction must have a strictly higher fee/mass ratio.

### Confirmation boundary

When a block is accepted, the mempool removes the accepted transaction and all
mempool transactions that double-spend its inputs, then records the accepted ID.
See
[`handle_new_block_transactions.rs` lines 27–52 and 82–91](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/mining/src/mempool/handle_new_block_transactions.rs#L27-L52).
The official tests explicitly verify removal of block-accepted transactions and
their mempool double spends:
[`manager_tests.rs` lines 595–680](https://github.com/kaspanet/rusty-kaspa/blob/4863866fce8439d0305b410fc4d802e7261d54d0/mining/src/manager_tests.rs#L595-L680).

## Repository-specific execution

The follow-on regression executes the fully signed Bob partial-exit and Alice
terminal-exit candidates through `kaspa-mining` at the repository's locked
revision `01b532e8b553523216471682649693af92f0fd16`:

1. the low-fee payout enters the pool;
2. a different-sponsor equal-fee conflict rejects and leaves the low-fee payout;
3. ordinary submission of the higher-fee conflict also rejects and leaves the
   low-fee payout;
4. mandatory replacement by the higher-fee conflict succeeds;
5. the returned removed transaction is the low-fee payout; and
6. the low-fee ID is absent while the higher-fee ID is present.

The official generic `test_replace_by_fee_in_mempool` also passes at audited
upstream commit `4863866fce8439d0305b410fc4d802e7261d54d0`.

A same-node public Testnet RPC/broadcast remains unexecuted. A fast block may
confirm the first candidate before replacement; that would test the confirmation
boundary, not disprove RBF.

## Evidence boundary

The source audit and transaction-specific engine test establish current official
implementation semantics and local pre-confirmation replacement. They do not
establish that every public Testnet RPC endpoint runs that commit, exposes
transaction replacement, retains the first candidate long enough to replace it,
or will mine the replacement. Those are deployment and live-network facts
requiring separate observation.
