# Next fee blocker 01: individual small private payments

**Finding:** under the selected two-public-input Groth16 profile and reference rate **100 sompi per normalized mass**, an individually settled private payment followed by a separately settled independent private exit has a **verification-only lower bound of 29,500,000 sompi = 0.295 KAS = 2.95% of 10 KAS**. Bytes, native checks, storage, entry and payer-change recovery only add costs. Byte cleanup or B1600→1501 cannot reach the 2% complete-fee target for that lifecycle.

Source-only analysis, 2026-10-23 UTC; workspace base `a6fcdf1edd904dbe1bb395285230649b6c40d44c`. No benchmark, budget, proof, profile, frozen workload or old result changed. Current matched circuits remain unreviewed research in the cryptographic/security sense; genuine proofs and implementation reviews are not soundness or privacy qualification.

## Exact source-to-fee chain

Execution stays **rusty-kaspa 2.1.0 at `01b532e8b553523216471682649693af92f0fd16`**; master is not substituted. The following links pin that exact source:

1. [OpZkPrecompile](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L759-L767) consumes the selected tag charge before verification. [Tag pricing](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L25-L35) sets Groth16 to 140,000 grams. [Unit conversion](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs#L4-L7) is 100 script units (SU) per gram: **14,000,000 SU**.
2. [VK deserialization](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L16-L49) requires gamma-ABC count = public-input count+1 and charges **250,000 SU per entry**. The selected relation binds SHA256(Auth528) as two exact LE128 field inputs, hence three entries: **14,750,000 SU per verification**. “Two inputs” here means public field inputs, not the private note count.
3. A compute-budget unit is **100 grams = 10,000 SU**. Each input additionally receives **9,999 free SU**; [allowed_script_units](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/tx.rs#L99-L103) adds that allowance. The smallest verifier-only budget is therefore `ceil((14,750,000−9,999)/10,000)=1475`. B1474 allows only 14,749,999 SU and cannot cover even the verifier. Upstream calls this `ComputeBudget`; “budget per unit” must not be confused with a one-gram or one-SU charge.
4. [Consensus compute mass](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L340-L369) adds transaction-byte mass, output-SPK mass and **100×sum(committed budgets)**. [Normalized mass](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L298-L305) is at least compute mass; a larger transient/storage dimension cannot reduce it. Thus each verification requires at least **147,500 mass** before other costs.

At the stipulated reference rate:

```text
two verifications: 2 × 147,500 = 295,000 compute mass
fee lower bound:   295,000 × 100 = 29,500,000 sompi
10-KAS principal:  1,000,000,000 sompi
fee percentage:    29,500,000 / 1,000,000,000 × 100 = 2.95%
```

This is a lower bound, not an achievable minimum-body quote. Even the fixed 140,000-gram base alone would give 2.80% for two calls. It is conditional on **two separately settled verifications at rate100**, not an impossibility theorem for every native-KAS architecture or every future market rate. Reference100 is an experiment assumption, not a claimed consensus minimum fee.

The verification-only principal threshold for 2% is **14.75 KAS**; real overhead pushes it higher. Reducing public-input count is a relation/security change: the present full 256-bit SHA binding cannot be replaced by one field reduction silently.

## Why budget and byte shaving are secondary

The retained [whole-policy result](../../private-change/fees/RESULTS.md) reports a 15,008,331-SU conservative private-path source upper bound for that exact emitter and preserves B1600. Accounting for the free allowance, that old bound already fits **B1500**, whose allowance is **15,009,999 SU**; naive rounding without the free allowance would suggest B1501. B1501 allows **15,019,999 SU**. A smaller budget remains a future scoped review against the exact matched program, bound assumptions and every valid branch; sampled successful paths alone do not establish a universal bound. This note selects no lower budget and launches no experiment.

If compute remains the fee bottleneck, B1600→1501 saves at most:

```text
99 units × 100 grams/unit × 100 sompi/gram = 990,000 sompi
= 0.0099 KAS per affected spend
= 0.0198 KAS for the payment/exit pair
```

If another mass dimension dominates, savings are smaller or zero. Code-byte savings reduce byte/embedding/native-work costs, but cannot erase either Groth16 call. Faster CPU/GPU proving improves prover cost/latency, not these native tariff constants.

The selected [matched32 closure review](../review/NATIVE-ECONOMICS-REVIEW-01.md) records **1.9486784375%** complete fees, including entry, 32 independent exits and terminal surplus refund, for supplied synthetic contexts at rate100. It is conditional integration evidence, not accepted-chain backing, market demand or small-payment qualification. One payer's 32 genuine simultaneous requests amortize a payment verification; fabricated identities, padding and change cannot supply the useful-payment denominator.

Budget shaving can still reduce the *genuine batch-demand threshold*. A separate counterfactual keeps the32-slot wire shape, uses N actual10-KAS requests and32−N properly blinded zero-value outputs, then N full compact exits. From the recorded entry258,500, wide19,701,700, continuing18,867,700 and terminal-refund149,500 sompi, its B1600 arithmetic would be `18,867,700×N + 19,810,700`; it first falls strictly below `20,000,000×N` at **N18**. If B1500 were validated and compute remained dominant for every shape, each private transaction would save1,000,000 sompi: `17,867,700×N + 18,810,700`, first below2% at **N9**. Adjacent N17/N8 still fail. The terminal refund stays unchanged because both exit shapes lose the same budget charge.

These are **unimplemented counterfactuals**, not new results. The current [wide wallet entrypoint](../../../../poc/compact-batch-lifecycle/actions.py) requires32 distinct positive recipient invoices; [preparation](../../../../poc/compact-batch-lifecycle/prepare.py) funds32 gross notes. Native storage must be repriced at the changed reserves/payouts, fixed-size blinded dummies and fee credits must remain relation-valid, and the complete changed route needs fresh evidence. No dummy counts toward N, no current workload is retuned, and neither threshold solves an isolated payment. Thus budget work can help a useful intermediate batching product while remaining secondary to the individual two-verification blocker.

## Next largest lever: fewer L1 verifications per useful payment

| Candidate | What it changes | Required boundary |
| --- | --- | --- |
| Genuine native payer batch | Amortizes one transfer proof across that payer's real simultaneous demands; leaves each recipient's independent exit. Already demonstrated in the bounded32 case. | Does not solve a lone payment or unrelated later demand; do not expand the denominator or require future cooperation. |
| Aggregate independently produced proofs, settle one transition | Can amortize a verifier across independent users without requesting their private witnesses. [SnarkPack](https://eprint.iacr.org/2021/529) is an established Groth16 aggregation design, not a new primitive proposal. | Its aggregate is not an ordinary proof accepted by the current G16 verifier. Current tags expose Groth16 and R0Succinct only. Establish two-role/separate-setup compatibility, exact ordered state/NF/payout binding, inclusion, bounded delay, data recovery and unilateral fallback before choosing an adapter or recursive wrapper. |
| Established recursion with an outer proof | [RISC Zero composition](https://dev.risczero.com/proof-system/) aggregates receipts and can reduce a session to Groth16. This is a candidate route to amortized settlement. | No measured cost, witness-privacy or compatible native pipeline is claimed here. Native R0Succinct's fixed **250,000-gram** tag is not automatically cheaper; at rate100 one such call alone is0.25 KAS. Wrapping/recursion does not remove the outer charge. |
| Based App/shared settlement | Official [agent brief](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/agent-brief.mdx#L69-L85) separates L1 user-operation payloads from proof-settled state. Can place multiple actions under one settlement proof. | Neither assume it is required nor unnecessary. [Based Apps](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/programmability/based-apps.mdx) remains in construction and warns about custom/privacy-first execution. Price native backing, lane inclusion/ordering, currentness, DA, operator failure and genuinely unilateral private exits; built-in public accounts are not the desired privacy model. |
| Different tariff/fee rate | Changes the fixed economics directly. | A separate upstream/policy or market premise, not a source optimization. Do not credit hypothetical repricing or lower live quotes against the frozen rate100 target. |

For intuition only, one transfer verification amortized over N useful payments plus one independent verification per exit has verifier-only percentage `1.475%×(1+1/N)`: N1=2.95%, N2=2.2125%, N3≈1.9667%, N32=1.52109375%. N3 barely clears 2% **before all overhead**, so this is not a passing three-payment profile or an old-workload retune.

**Recommended next design question:** can established public-proof aggregation/shared settlement reduce the verification count for independently initiated small payments while every recipient can recover and exit without another user's witness, cooperation or future arrival? Compare a minimal native settlement extension with a Based App on the same workload, complete costs, latency, DA and noncooperative-exit threat model. Preserve a priced unilateral fallback; cheaper cooperative averages cannot substitute for it. Resolve that architecture question before another large implementation or native microbenchmark.

## New exact source pins

Git blob IDs below were fetched from the official repositories; full commit refs are in the links above. Existing [SOURCE-PINS.json](../SOURCE-PINS.json) remains unchanged.

| Repository/ref | File | Git blob SHA |
| --- | --- | --- |
| rusty-kaspa `01b532e8…` | consensus/core/src/mass/units.rs | `cc0fafb1c03254b1b1132e645bd64ff23ac26049` |
| same | consensus/core/src/mass/mod.rs | `61816a77efb28c59655ceb238d02a3770a4ab961` |
| same | consensus/core/src/tx.rs | `8e383daccf03a94f6592d0d17672a9bd61db05be` |
| same | crypto/txscript/src/opcodes/mod.rs | `3e5e2133a457c17b14ec7904dc8dd7aced892ef8` |
| same | crypto/txscript/src/zk_precompiles/tags.rs | `803bb3211b737855176b1aa58b027af57669b90b` |
| same | crypto/txscript/src/zk_precompiles/groth16/mod.rs | `19e930972c5ac1bec53c8b356010c73fec54f7db` |
| kaspanet/docs `0ac77d04…` | content/docs/toccata/agent-brief.mdx | `f3ee68edab91f01d9ee981a46371fd02cf2efa16` |
| same | content/docs/programmability/based-apps.mdx | `190b28e034dcc38db5a7a870df6eacb0434c10ee` |

