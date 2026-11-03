# Individual private-payment fee floor review

**ACK for the conditional lower bound and counterfactual arithmetic. No material
error found.** Target: [NEXT-FEE-BLOCKER-01.md](../fees/NEXT-FEE-BLOCKER-01.md),
SHA256 `4be13bf3b2994793052a715bc8444defeed5e3b2e37e9d7973e7ccfd40522d65`.
Read-only source/report review and exact integer/Fraction arithmetic only; no
code, workload, budget, circuit, proof, native execution or old evidence changed.

## Pinned tariff and allowance

The local Cargo checkout is exactly rusty-kaspa
`01b532e8b553523216471682649693af92f0fd16`. `git show` at that commit reproduced
all six rusty-kaspa blob IDs listed in the note. This review did not substitute
the current master branch.

- `OpZkPrecompile` consumes the tag cost before verification. Groth16 charges
  140000 grams times100 SU/gram, plus250000 SU for each gamma-ABC entry.
  The exact two-LE128 public-input relation has three entries: **14750000 SU**.
- One committed budget unit is100 grams/10000 SU. The per-input allowance is
  **9999 SU**, added by `ComputeCommit::allowed_script_units`. Therefore
  B1474 permits14749999 SU and fails even the verifier; B1475 is the necessary
  verifier-only minimum. Native work may require more.
- Version1 compute mass includes100 times the committed budgets, plus byte
  and output-SPK costs. `NonContextualMasses::normalized_max` takes the maximum
  of compute and normalized transient mass; `Mass::normalized_max` also includes
  storage. Neither other dimension can reduce compute mass.

Thus two separately settled selected-profile calls require at least
`2*1475*100*100 = 29500000` sompi at reference rate100: **0.295 KAS, or2.95% of
10 KAS**, before other costs. The verification-only2% principal threshold is
14.75 KAS. This is a conditional lower bound for two calls under the pinned
tariff/reference rate, not an achievable full-body quote, consensus minimum fee
or impossibility result for architectures with fewer calls.

## Budget and batch counterfactuals

The retained [old whole-policy report](../../private-change/fees/RESULTS.md)
(SHA256 `772a063bf0352b1d4bf5038d256c2d7b014ea218ba35251d1a55d866ff6afb27`)
states its exact emitter's conservative15008331-SU private-path bound. B1500
allows15009999 SU, leaving1668 SU; B1501 allows15019999. The arithmetic is
correct. This review did not reprove that old abstract bound or transfer it to
every matched-program branch. The note correctly leaves any lower budget
unselected pending a scoped review; sampled successful executions are insufficient.

B1600→1501 removes99 committed units: at most990000 sompi per private transaction
when compute dominates. B1600→1500 would remove100 units/1000000 sompi.

Using the [recorded32-payment ledger](../lifecycle/main-synthetic-01/FINANCIAL-CLOSURE.json)
fees and149500 terminal credit refund gives the stated N-dependent totals:

| Counterfactual | Last failing N; excess over2% | First passing N; headroom below2% |
| --- | ---: | ---: |
| B1600:18867700*N+19810700 |17;561600 sompi|18;570700 sompi|
| B1500:17867700*N+18810700 |8;1752300 sompi|9;380000 sompi|

These thresholds are **unimplemented conditional arithmetic**. The actual wallet
entrypoint requires32 distinct positive recipient invoices and preparation
funds32 gross claims. Changed reserve-dependent storage, blinded zero outputs,
fee credits and the full changed route still require implementation and evidence.
Dummies and exit-credit refunds never increase useful demand. Equal budget
reductions on continuing/terminal exits preserve the149500 refund difference.

## Privacy and independent-exit boundary

The note preserves the distinction between the bounded supplied-context32-owner
lifecycle and future aggregation/shared settlement. It does not qualify market
demand, arbitrary individual-payment fees, accepted-chain payouts, financial
privacy or general independent exits. SnarkPack, recursive wrapping and Based
Apps are design candidates, with role/setup compatibility, exact state/NF/payout
binding, inclusion, data availability, bounded delay and unilateral fallback
explicitly unresolved. A cooperative average cannot replace a priced unilateral
exit. No future aggregation or privacy property is established by this fee note.
