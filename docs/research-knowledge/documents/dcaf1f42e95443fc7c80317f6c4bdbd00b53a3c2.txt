# Native receipt predicate harness: independent review

Result: the inspected harness genuinely invokes the pinned Kaspa native script
engine and its `0x21`/`0x20` precompiles. No material encoding or statement-binding
gap remains after the negative-control classifier correction below. This source
review does not establish fresh-pair receipt acceptance; that requires the
actual saved receipt.

Owned harness, read only:
`/home/luke/projects/kpi-intensive-2026-10-22/research/poc/public-receipt-native-check/`.
Reviewed source SHA-256 after correction:
`b1a30955a144bb895692fe5279e5c33375c62a87bdb27564edecf838f112c353`.
Manifest SHA-256:
`0ef226aab52732ec038744301a4f73da19a317d7549242c62a1afd03159f0a92`.
Lock SHA-256:
`1b0a8c9e037568c509bc7e7944695f96caf7e4ab2ae47f043170da659dab604c`.
No rebuild, proof generation or edits to the harness occurred in this review.

The owner then froze reporting-only updates as source SHA-256
`e7aed53557362d59d1354dae4b92cb93b0b58872f1a25dd6611818520586baa9`, recorded
in `evidence/harness-freeze.json` before a paired invocation. These add checker
identity and separate rounded script-unit grams from minimum committed budget.
The floor conversion is correct for this pin: `allowed_script_units` includes
9,999 free per-input units, so the smallest covering budget is `units / 10,000`.
Neither the witness nor expected-error/verification logic changed.

## Actual engine and fixed statement

`native_case` constructs
`TxScriptEngine::<PopulatedTransaction<'_>, _>::from_script` and calls
`vm.execute()`. Its scripts end with `OpZkPrecompile, OpVerify, OpTrue`.
The `OpTrue` cannot bypass precompile failure: native opcode execution propagates
failure before reaching it. These are actual pinned native calls, not SDK
verification relabeled as native execution.

The native source HEAD was checked as
`01b532e8b553523216471682649693af92f0fd16`. Relevant primary source hashes:

| Pinned native source | SHA-256 |
|---|---|
| `crypto/txscript/src/lib.rs` | `f8011e2f992172f4ecfc0e5d30a89b78e07c1a3b1d0b981065bcfd0518593b53` |
| `crypto/txscript/src/zk_precompiles/risc0/mod.rs` | `7d67128ac18975fcddf8f85167e81b962b0a42732f7db3bedbcaf19c43b19ba8` |
| `crypto/txscript/src/zk_precompiles/groth16/mod.rs` | `cb9fa14115d445c727cb8639ba384bde37d9a01f6c6f7fd1c92f77861f8a388d` |

The new pair's independently selected image is
`50ceec8ebb91edd01028c4aec9b495e7d77eb9e3b39e065910c0600f7693d832`.
Its expected program SHA-256 matches the frozen proof host:
`fa367c2d887a1a86ce23919f664af46dc418db0a2c79c2c62040c1526e8354cf`.
The harness's compiled 42-byte J is byte/hash bound to
`5d667b709f35191c6fc98e6aa0b79bd934e39a40ef4edfea582fcef3b06d4ac7`.
This is `SHA256(J)`, not `SHA256(P)`.

## `0x21` succinct path

Bottom-to-top stack matches pinned native `verify_zk` and upstream vProgs witness
extraction: claim digest, four-byte LE control index, concatenated inclusion
digests, LE u32 seal words, journal digest, fixed image, fixed JOIN control,
Poseidon2 byte `1`, then tag `0x21`.

The JOIN control is independently fixed as
`7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e`.
Receipt control/hash metadata is reported but does not select the expected
native image/control/hash function. Native code authenticates decoded seal
control equality and official allowed-root inclusion, then binds the verified
claim to `Halted(0)`, fixed image, the actual J digest, a zero claim-input digest
and zero unresolved assumptions. The guest still consumes its 2,846-byte witness.

## `0x20` Groth16-wrapped path

G1 coordinate reversal and G2 component order match
`kaspanet/vprogs` commit `f9b84a863a7c7c20586a9cf947550475e894f72e`
`zk/backend/risc0/api/src/witness.rs`. The harness adds fallible exact coordinate
shape checks and checked Arkworks point decoding.

The fixed official RISC Zero VK is obtained from its trusted serde envelope,
checked with complete uncompressed decoding and byte-identical re-encoding,
then compressed to 424 bytes with six IC points. The five native Fr inputs are
`[control_root_0, control_root_1, claim_0, claim_1, bn254_control_id]` in pop
order. Digest halves occupy the first 16 bytes of exact 32-byte LE scalars.
This matches the official `risc0-groth16 3.0.4` verifier and vProgs build/script
source. No whole-digest modular reduction is substituted. The claim is rebuilt
from fixed image/J, rather than trusted from receipt metadata.

This route verifies an outer RISC Zero Groth16 wrapper using its official setup
key. It is not the unchanged v6 covenant's 328-byte inner VK/two-input statement.
It inherits that wrapper setup's trust assumptions. Runtime acceptance remains
conditional on producing the matching wrapped receipt.

## Addressed finding: exact error and layer matching

The initial classifier treated any `TxScriptError::ZkIntegrity(_)` as a passing
negative, despite claiming resource failures could not pass. Native
`Groth16Error::FromTxScript` can wrap `ExceededCommittedScriptUnits` inside
`ZkIntegrity`. With a future finite meter budget between the fixed tag cost and
the gamma-ABC charge, that infrastructure rejection could have been mislabeled
as proof rejection. The present `from_script` uses an unlimited u64 meter, so
this was a classifier robustness gap, not an observed false result.

The reviewer requested exact source-derived errors and separate layer labels.
The updated `native_case` compares actual `TxScriptError` with the exact expected
variant/string. Meter/setup/panic/build errors cannot satisfy those expected
proof/framing errors. Framing cases are separately labeled, and the 0x20 bad
proof now negates A with the established Arkworks group API, retaining canonical
valid point encoding and requiring actual `Groth16Error::VerificationFailed`.

The retained historical qualification report was inspected: one valid historical
succinct receipt accepts and all eight single mutations reject with their exact
expected errors. Image/J changes reach expected-successful-claim verification;
control/path/index changes reach control authentication; truncated inclusion
reaches native digest-list framing; changed claim reaches seal/claim digest
binding. This qualifies the harness against that exact historical receipt and
its Lift20 control, not the new pair/Join image.

## Scope boundary

The report correctly states bare native opcode predicate execution with no
transaction, UTXO, reserve, state/nullifier transition, covenant, withdrawal,
network or chain acceptance. `from_script` uses a u64-max script-unit limit;
reported script units and their gram floor are not a valid transaction's
compute/transient/storage mass or fee qualification. Native precompile success
cannot authorize reserve movement without the separate application composition.
