# Existing-proof aggregation compatibility 01

**Finding:** the existing compact2/wide32 public proofs can be verified without their owners' private witnesses, but there is **no drop-in aggregation path that reduces L1 calls while preserving the current settlement policy unchanged**. A proof wrapper establishes its specified computation; it does not automatically turn several exact, possibly competing transitions into one authorized native-KAS settlement. This is a source-based compatibility finding, not an impossibility claim for aggregation, native extensions or Based Apps.

Source-only analysis, 2026-10-23 UTC, workspace base `a6fcdf1edd904dbe1bb395285230649b6c40d44c`. No code, proof, native validation, benchmark, architecture selection or hidden-study access. Existing sources, parameters and closed evidence remain unchanged.

## Supported facts about the current statements

| Binding | Exact current behavior |
| --- | --- |
| Public proof statement | Two LE128 field inputs encode the complete SHA256(Auth528). Both installed roles check this binding; the verifier selects a trusted role/VK. [A:252–311,437–458; B:486–491] |
| Current pool and money | Auth includes the exact previous outpoint, prior CM/NF roots and counts, reserve, exact fee, successor state/reserve, payout amount and payout SPK. Native compares them against the consumed pool input and actual outputs. [A:232–272; C:355–394] |
| Private recipients | The relation binds the ordered physical output-commitment digest, including blinded zero outputs; each commitment covers the note's receive fields/value. Auth separately binds the delivery-ciphertext digest, which native checks against published bytes. It does not prove correct encryption or availability. [A:123–133,380–389; B:431–485; C:329–351] |
| Settlement shape | Native requires exactly one input, exactly two sequential NF insertions, a role-sized CM append for continuing modes, one continuing pool output and at most one payout output. Terminal mode appends no CM, preserves the CM root/count and omits the pool successor. It then invokes one ordinary G16 verification under the selected role VK. [C:355–399] |
| NF absence and public updates | Private proofs establish ownership/CM membership, NF derivation and conservation; native authenticates strict predecessor intervals and empty append slots, derives the exact NF/CM updates and matches successor roots. These checks are outside G16. [B:358–430,472–491; C:193–259,329–351,385–391] |

The public control already demonstrates the seam: a fresh proof on the actual supplied post-REVEAL state is privately valid, yet native rejects its occupied NF before G16. [F] Rechecking only the private proof cannot replace that rejection.

There is a **public-body dependency**, not a proof-randomness dependency. A successor Auth binds its predecessor transaction ID/output index. Version1 IDs hash the payload plus the remaining body, excluding signature scripts and mass/compute commitments. Thus predecessor state, payload, reserve, payout and exact fee effects must be fixed before constructing a successor statement; randomized proof bytes in signatureScript need not be ready. Proof generation may overlap once those exact bodies are fixed. History advances to `body.id:0`. [D:84–95,248–259; E:175–183; U:99–134,207–235]

## Inferences and unresolved choices

1. **Same-current-state proofs are alternatives.** Even with disjoint private claims, each authorizes its own successor state/reserve from the same pool UTXO. Their separate CM/NF deltas and payouts do not become one combined transition by verifying both proofs. With identical NFs they also conflict directly. The unchanged one-input/one-action policy has no aggregate branch. [A–C]
2. **An ordered proof chain is different from one settlement.** It can be checked as a chain of public bodies, but settling every intermediate UTXO retains the native call per action. Interpreting intermediate outpoints as virtual transactions inside one outer settlement would require a new specified policy: exact ordering, current-state NF absence, CM appends, outputs, replay protection and authorization for omitting intermediate settlements. Old Auths are not automatically reusable intents after another action changes the point/state/reserve. [C–E,U]
3. **Exact fees cannot silently become savings.** Inner conservation debits each exact fee from both note value and reserve. A cheaper outer transaction needs an authorized equation for aggregate native fee, owner charges, reserve backing and any rebate/surplus. Replacing the inner fee or changing its payout/destination/output notes changes the proof statement; retaining all old native effects does not establish lower fees. [A:252–272,329–345; B:340–351,472–491; D:261–292]

[SnarkPack](https://eprint.iacr.org/2021/529) is established Groth16 proof aggregation. Its paper does not establish compatibility of this pair of independently generated role setups, nor this settlement semantics. Raw SnarkPack aggregates are not the ordinary BN254 Groth16 proof parsed by the current native tag. [V] [RISC Zero's documented composition](https://dev.risczero.com/proof-system/) combines receipts and can produce an outer Groth16 receipt; verifying these existing BN254 statements inside such a program, pinning the role VKs/image/journal and binding a complete settlement remain work. A receipt-verification wrapper and a correct settlement program are separate obligations. The native tags expose G16 and R0Succinct, not a free aggregation operation; the latter's 250,000-gram base is not automatically a fee improvement. [V; existing fee note]

Native shared settlement and a Based App remain candidates, not selected requirements. Neither established aggregation nor recursion supplies transaction inclusion, canonical ordering, currentness, delivery data or permissionless exits by itself.

## Smallest decisive next experiment and acceptance requirements

**First specify and check a two-action public settlement transcript, before building an aggregator.** Reuse the existing public wide-canary → compact-successor chain as the ordered positive, the same-current-point compact/wide alternatives as a conflict, and the fresh post-REVEAL privately valid proof as an occupied-NF negative. Consume only public Auth/proofs, trusted VKs, bodies and authenticated public update witnesses; do not gather owners' note witnesses. A small future semantic harness should state exactly which public checks an outer proof would have to prove. It is not a new L1 qualification or a claimed fee saving.

Proceed to a matched outer-proof/native prototype only if that specification can bind: (a) the externally current starting pool and complete ordered transitions, including cross-action NF uniqueness and current NF absence; (b) role/domain/VKs, CM placement, exact recipient/payout effects and the authorized fee/reserve equation; and (c) one actual final L1 body. Decide explicitly whether existing Auths retain exact-transition semantics or a newly reviewed intent relation/policy is needed. Do not relax the outpoint binding as an implementation shortcut.

The comparison must price complete entry/payment/exit costs, outer verifier and native checks, bytes/storage, aggregation/proving work, delay, inclusion failure and every fallback. A recipient must retain a **private unilateral exit** from their own backup plus authenticated current public history/parameters, without another owner's witness, cooperation or future arrival. REVEAL is an explicitly consented disclosure/liveness alternative; its cheaper cost cannot qualify the complete private lifecycle. Include operator disappearance, withheld/invalid data, missing delivery records, parameter retention and stale/reorg recovery. A DA commitment alone is not retrievable data. Cooperative amortization cannot erase the separately priced private fallback or the isolated-payment lower bound in [NEXT-FEE-BLOCKER-01.md](NEXT-FEE-BLOCKER-01.md).

## Exact source anchors

Ranges above are source-file lines. SHA256 pins below identify the bytes inspected; upstream runtime remains rusty-kaspa `01b532e8b553523216471682649693af92f0fd16` (2.1.0), not master.

| ID | File | SHA256 |
| --- | --- | --- |
| A | [prover lib.rs](../../../../poc/compact-batch-prover/src/lib.rs) | `10db2eb372df40e814b8ab85921898e7d3cac44eab2b6fe803a7dfbc5a455153` |
| B | [prover circuit.rs](../../../../poc/compact-batch-prover/src/circuit.rs) | `34baa165b45dce138777971cbdb229403d7c770d86a6cddadf6bd01f35a95edb` |
| C | [native policy.rs](../../../../poc/compact-batch-lifecycle/native/src/policy.rs) | `7e61c6060291f500fc0faa49ff3b467a9f9d6d8d1bff4d6fc52e8b87a94ba714` |
| D | [native_runtime.py](../../../../poc/compact-batch-lifecycle/native_runtime.py) | `dac6d42987a9419864c967773677a033c143028053f33f5f6ad506739ef005af` |
| E | [history.py](../../../../poc/compact-batch-lifecycle/history.py) | `b24f5712d16b75e5d1c33e6021e7f3e06e3bf180926af00f5ee01a09e1060202` |
| F | [public fresh-NF result](../lifecycle/competition-01/finish-01/RESULTS.json) | `1d8c17905d9e899d29965080a2e5ce21432f4b1c109c9aab63aa56f03341974f` |
| U | [upstream hashing/tx.rs](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/tx.rs#L207-L235) | `965772f8daf6a941625c1c3b4601c1ee2dc4031d402bae98339064113c0ac5f1` |
| V | [upstream tags.rs:8–32](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L8-L32); [groth16/mod.rs:64–108](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L64-L108) | `b3288d447e0ea09447e6564c921389bd6d5668d6d302c8d409ded7895919ef03`; `cb9fa14115d445c727cb8639ba384bde37d9a01f6c6f7fd1c92f77861f8a388d` |

The existing fee note inspected has SHA256 `4be13bf3b2994793052a715bc8444defeed5e3b2e37e9d7973e7ccfd40522d65`. External primary sources were re-read on 2026-10-23: SnarkPack ePrint2021/529 metadata (latest revision2021-09-06; PDF fetch returned403), and RISC Zero's Proof System Overview, “Types of Receipts.” These establish candidate capabilities only; no implementation compatibility or performance result is inferred from their published numbers.
