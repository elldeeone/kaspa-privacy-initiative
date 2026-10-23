# Independent six-negative artifact review

All six once-run mutations rejected. The original frozen error-name prediction
matched four cases and failed two; that 4/6 result and failed process return
remain unchanged. The two mismatches are a prediction error, not accepted
transactions. No native case or proof was rerun.

The reviewed final source selection is
`d89f1d12940eda137b7fb47b9ee15e32ca178f9083b8467556b6e084f964451a`,
pinning runner `7d5dbf12b276ed1442b2f0366698c4594d6ab74fd5a691a5afc533156a080f28`.
Before execution, source review required whole normalized-mutant equality,
allowing only official ID/storage-mass recomputation, and exact native-case
context entries. The owner added these guards before the sole run.

The reviewer checked the actual private public-type artifacts read-only. Every
case retains the original successful transaction's complete signature/proof
frame. Official normalization changes only ID and storage mass; actual native
case entries match the intended supplied contexts. Every report has isolation
PASS, rejected Full, rejected individual engine and consistent aggregate status.

| Mutation | Observed rejection boundary |
| --- | --- |
| Native destination differs from Auth | Early Full `SignatureInvalid(VerifyError)` / engine `VerifyError` |
| Auth and actual destination consistently rebound | Full `SignatureInvalid(ZkIntegrity("Groth16 verification failed"))` / corresponding engine `ZkIntegrity` |
| Payout and reserve consistently rebound by one sompi | Same Groth16 verification failure |
| Extra native output on P0 with reduced pool output | Early `VerifyError` |
| Original NF update chunks swapped, original Auth/proof retained | Early `VerifyError` |
| Old payment body evaluated against its successful successor's context | Early Full `SignatureInvalid(EvalFalse)` / engine `EvalFalse` |

Both coherent Auth changes reach the Groth16 tariff and stay within the
committed budget. Their original proofs deserialize but fail for the changed
public statement. The other four fail before that tariff. Actual per-case
units, transaction variants, Auth/NF data and candidate digests remain private.

The pinned `01b532e8b553523216471682649693af92f0fd16` implementation returns
`Groth16Error::VerificationFailed` when the checked pairing fails
(`crypto/txscript/src/zk_precompiles/groth16/mod.rs`). Its display text is
`Groth16 verification failed` (`groth16/error.rs`), and
`zk_precompiles/mod.rs` maps that error to `TxScriptError::ZkIntegrity`.
The frozen prediction incorrectly expected `VerifyError` for those two cases.
The independent reviewer also missed that mapping during the source pass;
the additive interpretation corrects it without changing the frozen result.

This is supplied-context rejection evidence. It includes no fresh chain query,
newly rebased genuine proof against an occupied NF, or broad authorization,
privacy, fee or production qualification. The materializer's two original/change
spent-recognition refusals remain separate local controls. No backup, seed,
profile, private witness or PK was read by this review; no raw competing main
statement is exported here.
