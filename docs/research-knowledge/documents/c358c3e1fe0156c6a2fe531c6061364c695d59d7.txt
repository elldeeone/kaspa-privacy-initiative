# Native compute-budget evidence: independent review

Result: no material correctness or evidence-identity gap found in the new fixed
public budget screen. All 13 original transactions and their budget-1600
candidates retain genuine proof/authorization/ciphertext/output/signature bytes
and the original 40,000,000-sompi fee. This is isolated offline native validation,
not a default protocol change or newly accepted chain history.

Reviewed source:
`native/poc/shared-pool/src/bin/kpi-native-budget-screen.rs`, SHA-256
`5349970463afbb9957165331d1a282fcf0a9e4c5009517856eb11b9f2f641d7e`.
Reviewed retained evidence:
`native/poc/shared-pool/evidence/2026-10-22-public-native-budget/attempt-03/`.
Input SHA-256:
`7fd8bd70774872a1748fb52d32754556e578f8abf89c76100e28e1fd315b02a1`.
Native dependency:
`01b532e8b553523216471682649693af92f0fd16`.
No rebuild or additional native execution was performed by this reviewer.

## Source checks

`candidate` clones each original transaction, changes reserve input 0's
`ComputeBudget`, finalizes and recalculates derived storage mass. It compares
the complete candidate transport against the original with only that budget
and derived mass field permitted to differ. It separately compares every input's
`SIG_HASH_ALL` digest, canonical parser roundtrip, stable V1 ID and changed full
transaction hash. Each candidate uses the original legitimate parent outputs
as UTXO context; mutated descendants are not substituted.

The pinned source supports these semantics directly:

- `consensus/core/src/hashing/tx.rs` constructs V1 IDs from payload and rest
  digests. The rest preimage excludes signature scripts and mass commitments,
  including V1 compute budgets. The full transaction hash includes the budget
  and storage mass instead.
- `consensus/core/src/hashing/sighash.rs` excludes legacy sigop commitments for
  V1 and never substitutes the new compute budget into `SIG_HASH_ALL`. Fresh
  reused-value caches are created; equality is not inherited from a stale cache.
- `ComputeCommit::allowed_script_units` adds the pinned free 9,999 units to
  `budget * 10,000`. Thus minimum covering budget is floor division by 10,000,
  not an ordinary ceiling that forgets the free allowance.
- Full validation runs `TxValidationFlags::Full` through the consensus validator.
  Isolated reserve validation also supplies the actual committed unit limit.
  Valid cases must retain baseline per-input measured units and fee.

The focused underbudget classifier first fixes the concrete outer enum by
downcast, then matches the complete variant/payload and canonical used/limit
amounts. It handles the real native Groth16 adapter's serialized meter cause
inside `ZkIntegrity`, without accepting a generic integrity error. Wrong limit,
same-display wrong type, and unrelated damaged-proof controls reject. The full
native error contains the isolated reserve error; failure is not inferred from
generic nonzero exit status.

## Independent byte/hash and arithmetic recount

`native_budget_recount.py` imports none of the producer's validators. Using only
stdlib keyed BLAKE2b and serializers derived directly from pinned native source,
it independently reproduces all 35 original/candidate full transaction hashes.
For every case it also checks unchanged V1 rest preimages, independently
computed `SIG_HASH_ALL` digests, storage mass, transaction size and transient
mass. The resulting compute mass changes by exactly 100 grams per reserve
budget unit; relay/mining maxima and all 105 fee quotes match.

The case count is 31 successful validations plus four expected underbudget
rejections. Quotes attached to failed budget variants are arithmetic stress
quotes, not successful native transactions. The decisive budget-1600 set has
13 successful genuine-proof cases.

| Quantity | Independently recounted value |
|---|---:|
| Maximum budget-1600 mining mass | 191,628 |
| At 200 sompi/gram | 38,325,600 sompi |
| Margin below original 40,000,000 fee | 1,674,400 sompi |
| At 500 sompi/gram | 95,814,000 sompi |
| Claim needed for that fee plus 10,000,000 payout floor | 105,814,000 sompi |

Results are retained in `native-budget-independent-recount.json`.
All 22 named source, saved-output, executable and previous-baseline identities
were also independently rehashed against the manifest; all match. That evidence
is retained in `native-budget-identities-rechecked.json`.

## Limits preserved

Attempts 01/02 retain their classifier-failure stderr and selected input. Their
status records honestly state that exact old source/binaries were not retained;
those failed attempts cannot be independently rebuilt from their snapshots.
They do not invalidate attempt 03's separate exact source/input/binary manifest.
The frozen focused matrix was not changed to evade a failed protocol check.

Budget 1600 is qualified only on these 13 genuine public cases. It is not a
general worst-case path proof or a changed default. Higher-rate fee numbers are
quotes; original proof-bound fees/payouts were not rewritten or re-proved.
The 60,000,000-sompi note floor does not cover the worst 5x fee. Funding ancestry,
accepted-chain state, wallet fee repricing and broad operational qualification
remain outside this result.
