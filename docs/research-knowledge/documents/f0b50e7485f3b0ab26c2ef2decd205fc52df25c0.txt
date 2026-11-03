# Public generator facts excluded from the frozen economic models

This is a source-only record made before final payout inputs were available.
No generated private PLAN/state, original wallet, owner log, hidden truth or
actual final ledger was read. Neither frozen observer/policy is changed or
refitted. The facts below are material limits of those bounded models.

## GEN3 funding identity and CM slot order

The selected builder preserves payload-record order and funding-input order.
`gn3_entry.prepare_genesis` puts `records` into `encode_payload` (lines33–41),
iterates `sources` directly for inputs/entries (63–67), and uses the same index
for source/change accounting (57–62). `gn3.validate_genesis` explicitly allocates
input amount i to note row i plus its change and fee (174–178).

The owner signer makes this more than an arbitrary builder convention:
`sign_worker.py` finds its own encrypted row's unique payload slot (55–59), derives
its funding key, and requires that the corresponding **same input index** has
that key's script before signing (82–86). `new_trial.py` retains initialization
order0,1,2 through `pool.map(..., range(3))` and reads records in that order
(71–78). There is no GEN3 record/input permutation hiding this correspondence.

Under the selected builder/signer execution assumption, a source-aware observer
can associate a public funding-input index/key with the same GEN3 CM slot. This
does not reveal a later cryptographic NF-to-CM preimage by itself. It also is not
a protocol-wide rule that every future implementation must use this builder.

## What the campaign generator randomizes and advertises

Both `campaign.py` and `campaign_cached.py`, lines62–79, use default
`random.SystemRandom()`. They choose a private cycle direction1 or2, independently
shuffle the three actors within each payment round, and shuffle the nine exit
actors. `prepare` calls `make_plan` without a supplied RNG. The actual actor/action
and exit order cannot be recovered merely by reading these generator functions.

However, the source fixes more than the global amount multiset:

- Payments1–3 are5KAS each; payments4–6 are2KAS each (68–75; validation90–104).
- Every actor pays once per round, using the same directed recipient cycle.
- In round two, actor index1 selects `change`; the other two select
  `received-preferred` (74–75 and99–104).
- Exactly three exits per actor are scheduled, although their order is shuffled
  (76–78 and105–109).

The public selection implementation in `recovery/history.py` prefers available
received notes for `received-preferred`, otherwise change (164–166), and selects
the largest eligible note with position tie-breaking (173). These are additional
source-derived structural constraints, not observations of any generated plan.
`wallet/payment.py` still randomly reverses its two output tuples (91–93), so a
public CM slot is not assigned a payment/change role by this source.

## Interpretation of the frozen results

The chain-only arm omits campaign/source schedule knowledge. The amount-known
arm adds only the global multiset of three2-KAS and three5-KAS outgoing notes; it
still omits the round-to-amount mapping, fixed-cycle/actor constraints, asymmetric
selection policy and funding-key/CM-slot correspondence above. A source-aware
observer could use these additional constraints. Its feasible set is unmeasured.

Consequently, the reported3! root-label permutations and absence of a named root
owner are properties of the **modeled observer sets**. They are not a
protocol-wide anonymity size or a finding that funder identity is hidden from
all public-source observers. Asset ancestry also does not establish common
ownership after transfers. Report the two frozen arms as bounded metrics with
this excluded stronger observer assumption; do not describe either as general
financial privacy or a privacy PASS.

## Exact inspected public source identities

| Repository path | SHA256 |
| --- | --- |
| `poc/local-private-payment/bootstrap/new_trial.py` | `91b8c17e0b1ceb6cf8d72064e34ab30042551f7f050b01913e8fee473e82f8b7` |
| `poc/local-private-payment/bootstrap/gn3.py` | `ca401e890ae3b328999d745c26205fb17cfe6dcafb7fdd4253f7315ff347d5d9` |
| `poc/local-private-payment/bootstrap/gn3_entry.py` | `820e01eea25be190fea11e50c94d93ebb1d7b8d2353d40f21c7312fd3540ec54` |
| `poc/local-private-payment/bootstrap/sign_worker.py` | `fa0d41303fde2a95cbea497a93718b2e6ef676a44190bb8b02081126cf6811f4` |
| `poc/local-private-payment/integration/campaign.py` | `1af6c2ccd34839e36dba724781bff1801d5505fb5b973c09d39d09fe7108080e` |
| `poc/local-private-payment/integration/campaign_cached.py` | `586a8852bff9b5dbfce13d0f16a70546d9f94d39553d9a4bc1df85d6ce655bd8` |
| `poc/local-private-payment/recovery/history.py` | `3e637e52ff598ef875b9b50c129e5b8da2057726458af631c788b13cacbab542` |
| `poc/local-private-payment/wallet/payment.py` | `5ff0774fd1bb67ebc5ed5ec246ce2434082bfc4ce82dad9e58047b34232d2bda` |
