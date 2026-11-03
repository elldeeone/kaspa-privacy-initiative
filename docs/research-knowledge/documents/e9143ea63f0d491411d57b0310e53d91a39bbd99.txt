# Actual W private fallback: independent static source review

**Source ACK for the exact selected W private path; no blocking counterexample found.** This is review of the abstract calculation and pinned execution rules. I did not run the calculator, controls, VM, proof/native jobs, read PK/backup material, or select a budget.

## Reviewed identities

- `fees/private-fallback-budget/abstract_meter.py`: `30ef579e00ed9327011cce7a6f94ffc7fd16090f63ab71bfa8f7d0f3e5b1b8d6`.
- `fees/private-fallback-budget/bound.py`: `9387692867bd2614f22e01519679eee911c08add96860078ff32a0b00343abf8`.
- `test_bound.py`: `b2ff0ece322944cd2e08f0f1d5516905c4b0f2e95c493b4b4fb2f0ca8c5d1710`.
- `INPUTS.json`: `15d082226362b67c0b1730a9e053759d54ff0a9523efd762d772213f1cc0522a`.
- Actual redeem: `c03345e8e9bbd1df7cba8940e9578724c3dd2e127ad73ee6a974d0c182875f3e`, length 16,202; immutable tail after state112: `5c9e15357f07f092e25f272ea40bb92f1c0335574e37e0e4e687297db4e56559`.
- Gas model: official rusty-kaspa commit `01b532e8b553523216471682649693af92f0fd16`, as pinned by INPUTS. Review compared the relevant versioned primary source logic; the source owner's eight-file byte-authentication result is separate retained evidence.

## Abstract execution and scope

The calculator selects the final W ELSE/private arm, retaining the common prefix. It visits both alternatives of every private conditional, including forbidden wide-mode code, takes maximum branch cost, merges maximum element widths, and rejects incompatible stack/alt-stack shapes. It does not use sampled amounts, roots, index bits, or a one-real-input assumption to prune work. Unknown operations or dynamic substring/NUM2BIN widths refuse instead of receiving zero cost.

The transfer rules account for newly pushed bytes, concatenation and bounded substrings, numeric outputs, comparisons, stack copies, hash preimages/results and the fixed verifier. Unknown arithmetic/context integers use nine bytes. Successful BIN2NUM output cannot exceed its source-byte bound. Literal pushes and alt-stack transfers are conservatively charged despite their upstream exemptions.

An earlier generality caveat is now closed defensively: Item lengths are ordinarily upper bounds, so converting their length into an exact OP_SIZE number was unsafe for arbitrary code. `exact_length` now defaults false; OP_SIZE refuses an inexact width. The adapter additionally requires exactly two common-prefix OP_SIZE sites and none in the private arm. The two executed sites inspect the initial 128/65-byte items. The other emitter OP_SIZE, in `split_claim`, belongs to the unselected aggregate arm.

The initial stack is enforced by this W program, rather than assumed from normal wallet behavior. `poc/shared-settlement-native/src/policy.rs:970` checks depth2; lines 971/973 check widths128/65. Lines 1003–1012 require signatureScript length199+L and exact push markers at offsets0,66,196. Those markers and total length partition the complete unlock into the 65-byte, 128-byte and L-byte literal pushes. There is no padding-opcode space. The official engine also requires an input signatureScript to be push-only. Native P2SH restoration leaves precisely the two modeled items before W execution.

For successful private executions, the queried continuation SPK must equal the constructed 37-byte value and any payout SPK the 36-byte Auth field. This justifies the 37-byte context-SPK upper bound. It is not a bound on all malformed executions before rejection. All mode0/mode2 terminal/continuing and positive/zero payout branches remain covered; the private real-input count does not change the fixed two-NF paths or two-public-input verifier.

## Complete-input cost and primary rules

The proposed 14,957,286-unit result includes the 52,364-unit prelude overcharge: `3*16202 + 258 + 3500`. This covers witness literals, the outer P2SH BLAKE2b preimage and result/comparison, and a full standard-SPK byte overcharge. P2SH saved-stack restoration and final success checks add no further metered pushes.

The pinned [engine](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs) and [stack](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/data_stack.rs) meter new pushed bytes. [Opcode rules](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs) price SHA256/BLAKE2b preimages at one/two units per byte plus pushed results; equality-verify operations introduce no hidden boolean push. The [Groth16 tag](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs) costs14M and its [three gamma-ABC elements](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs) add750k; the successful result byte is included. No executed private signature opcode was omitted.

Under the pinned [unit conversion](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/units.rs) and [input allowance](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/tx.rs), budget1500 permits15,009,999 units. The stated bound leaves52,713. This review did not independently execute/recompute the complete abstract total.

This ACK is conditional on the exact W tail, canonical frame and pinned schedule. It is not a general-purpose abstract-VM proof, cryptographic correctness result, actual fee quote, lifecycle qualification or budget selection. A future selected private budget needs fresh complete-body quoting, Auth/witness/proof and native validation. Existing child/aggregate fees and authorizations cannot be retargeted.
