# Smaller native budget: fixed genuine-transaction qualification

**Result:** all thirteen retained public v6 operations pass full native
validation with reserve-input budget **1600** and the original proofs,
authorizations, ciphertexts, outputs, signatures and **40,000,000-sompi fee**.
This demonstrates a smaller valid budget for this trace. The protocol/wallet
default remains **3000**; no transaction was broadcast.

The largest measured mining mass falls from 331,628 to **191,628 grams**. At
the declared 200-sompi/gram stress rate, the worst necessary fee is
**38,325,600 sompi**, covered by the original 40,000,000 fee. At 500 sompi/gram,
the worst fee is **95,814,000 sompi**, exceeding the 60,000,000 minimum note.
A payout of at least 10,000,000 then needs a claim of **105,814,000 sompi**.
The five-times minimum-note limitation remains.

## Exact scope and changes

The input is byte-identical to the successfully validated
[public observation baseline](evidence/2026-10-22-public-native-observation/attempt-01/MANIFEST.json):
the pinned TN10 rehearsal's founding transaction, 13 operations and one public
funding parent. Each candidate is validated independently against its original
legitimate public UTXO context. No changed transaction is used to construct a
descendant context, and no key, seed, private opening or proving parameter enters
the experiment.

Only reserve input zero's compute-budget field changes. The candidate is
finalized, its storage mass recomputed and its canonical parser round trip
checked. Exact JSON comparison confirms every other input/output/payload field
is preserved. V1 transaction IDs and every input's `SIG_HASH_ALL` hash are
**unchanged**; full transaction hashes change. The exact upstream implementation
at rusty-kaspa `01b532e8b553523216471682649693af92f0fd16` deliberately excludes
compute budget from both V1 transaction ID and signature hashing. The original
ADMIT funding signatures therefore remain valid; no resigning is needed.

## Measured results

All 13 originals pass at 3000, and all 13 candidates pass at 1600. Per-input
script-unit counts match exactly. The table shows mining-mass ranges:

| Operation | Count | Budget 3000 | Budget 1600 |
| --- | ---: | ---: | ---: |
| ADMIT | 3 | 331,628 | 191,628 |
| SPEND | 4 | 330,508–330,920 | 190,508–190,920 |
| DRAIN | 6 | 330,497–330,920 | 190,497–190,920 |

Nine focused native boundary cases also pass their expected outcomes:

| Exact public operation | Pass budgets | Reject budgets | Measured completed reserve units |
| --- | --- | --- | ---: |
| Bootstrap SPEND, ordinal 0 | 1500, 1497 | 1496, 1474 | 14,972,613 |
| First ordinary SPEND, ordinal 4 | 1500, 1497, 1496 | 1495, 1474 | 14,969,899 |

Allowed units are `10,000 * budget + 9,999`. The successful ordinary 1496 case
has only 100 units of headroom; it is boundary evidence, not a default proposal.
These exact counts belong to this rehearsal, not another retained trace.

The [successful third attempt](evidence/2026-10-22-public-native-budget/attempt-03/validation.json)
contains **35 native cases**, four classifier controls and **105 independently
recounted fee quotes**. Quotes use conservative mining mass and retain separate
relay-only values at 100, 200 and 500 sompi/gram. No modified-fee authorization
or proof is executed: the actual native fee remains 40,000,000 throughout.

## Failure history and precise error attribution

[Attempt 01](evidence/2026-10-22-public-native-budget/attempt-01/STATUS.json) and
[attempt 02](evidence/2026-10-22-public-native-budget/attempt-02/STATUS.json)
remain failed runs. Their initial classifier expected a direct typed
`ExceededCommittedScriptUnits` error. The actual Groth16 adapter converts that
meter error to `Groth16Error::FromTxScript`, then serializes it into typed
`TxScriptError::ZkIntegrity(String)`. Diagnostic attempt 02 exposed, for example:

```text
ZK Integrity: Kaspa txscript error: script units exceeded the amount committed in the input: used=14972612, limit=14969999
```

The corrected classifier requires the concrete outer enum type, its complete
derived Debug value and full canonical Display, plus an inner message identical
to a freshly constructed typed meter error at the known budget limit. It reports
the outer typed `ZkIntegrity` and serialized inner cause separately. An arbitrary
proof-integrity failure cannot count as a budget failure. Controls reject a
wrong limit, an identical-display error of another type and a genuine unrelated
bad-proof error. Budget values and expected native outcomes did not change.

Attempt 03 took 0.580 seconds for the complete cgroup-controlled job, 0.667 CPU
seconds and 47.3 MiB peak memory, with zero swap. The source, public input,
executable, observation-baseline identity and output artifacts are pinned in
its [manifest](evidence/2026-10-22-public-native-budget/attempt-03/MANIFEST.json).
The prior observation executable and all baseline artifacts were rehashed
unchanged before and after this phase.

## Remaining limits and review

- This qualifies a fixed public trace and specific byte/path shapes. It is not
  a worst-case qualification across tree capacity, nullifier insertion positions,
  history lengths, monetary encodings or future dependency versions.
- No wallet/covenant default or fee changes. The default-3000 implementation has
  its earlier cost limits until a separately reviewed adoption decision.
- Fee-rate stresses are arithmetic quotes against declared rates, not current
  network pricing, chain acceptance or executions with increased proof-bound fees.
- The 500-sompi/gram singleton minimum-note exit remains unsupported by these
  costs. This result changes no accepted privacy or financial targets.
- Native proof checks provide finite implementation evidence, not cryptographic
  assurance, anonymous payments, receipt delivery or production safety.
- Descriptor/accepted-chain authentication, current spendability, funding-parent
  input ancestry and public-data availability remain external assumptions.

The new executable is [kpi-native-budget-screen.rs](src/bin/kpi-native-budget-screen.rs);
the independently checked arithmetic/manifest wrapper is
[verify_native_budget_screen.py](verify_native_budget_screen.py). No inherited
protocol source, frozen observer, setup or wallet file changed.
