# New union native controls: prospective plan

Status: prepared before the first new-union native VM/Full run. Source and exact
signed bodies receive a separate final freeze and independent review. Unit
construction, official mass calculation and cryptographic signing are preparation,
not native acceptance. All credentials and values are public synthetic DO_NOT_FUND.

The executing covenant is the actual three-branch immutable private Groth16 /
public admission / revealing exit union. No padded envelope, NOP proof branch,
old-format owner workflow, old proving key, node or broadcast is used. The
six-operation lifecycle is owned by `poc/future-lifecycle`; this lane adds only
finite signed semantic controls and reports every failure unchanged.

## Positives and authority boundaries

1. One ordinary supplied 4B P2PK input creates the 120M founding coin, the exact
   admission funding coin and optional positive change to the same source key.
2. Ordinary founding creates a coherent Alice60M singleton reserve and returns
   owner change. Its public Note168 excludes Invoice208/stable deliveryPK.
3. ADMIT uses both current pool input0 and the actual funding input1. Exact ALL
   validates under the funding key; entry principal and entry fee come from
   input1, old NF is unchanged and the same immutable policy receives R+V.
4. One genuine private proof consumes BOTH Alice notes and creates Bob1B and
   Charlie1B, with no change output counted as a payment.
5. Recovered Bob and Charlie each authorize an actual revealing exit from the
   evolved current state, in both exit orders. The final R=V transaction has one
   positive payout and no zero reserve output. Its complete-liability conclusion
   is conditional on the explicit coherent prior lineage/backing oracle.

Actual native-computed output IDs and SPKs link each body to the next UTXO;
constructing a self-consistent Auth does not supply accepted chain backing.
An extra supplied-source/snapshot counterfixture is never reported as accepted
initialization. Receiver seed-only backups and availability evidence remain the
separate lifecycle/recovery responsibility.

## Typed negative families

Every instantiated case will name its exact parent body, mutations, final signed
body hash and expected input-engine result BEFORE execution. The table fixes the
permitted expectation families; a generic failure does not satisfy a semantic
expectation. Controls that need altered public state retain an explicit
`supplied_context_only` classification. Fresh proof generation is not required for
an early native guard, and a reused proof is never called valid for changed Auth.

| Family | Frozen mutation and intended guard | Required result |
| --- | --- | --- |
| Funding exact ALL | Sign the ACTUAL NONE2 digest, rather than append byte2 to an ALL signature | Pool input0 `VerifyError`; funding input1 ACCEPTS its cryptographically valid NONE signature; Full REJECTS |
| Funding signature | Flip a Schnorr signature data byte, retaining canonical push/type | Pool input0 ACCEPTS; funding input1 `NullFail`; Full REJECTS |
| Funding wrong key | Re-sign with a different valid public development secret, retaining the original actual funding SPK | Pool input0 ACCEPTS; funding input1 `NullFail`; Full REJECTS |
| Admission amount conservation | Change declared fee/change or R+V output by one sompi, then correctly re-sign input1 | Pool input0 `VerifyError`; funding input1 ACCEPTS; Full REJECTS |
| Admission change destination | Positive declared change paid to a different valid P2PK key, correctly signed by original funder | Pool input0 `VerifyError`; funding input1 ACCEPTS; Full REJECTS |
| Admission Note/CM | Change Note168 rho or committed nativePK while retaining CM; correctly re-sign input1 | Pool input0 `VerifyError`; funding input1 ACCEPTS; Full REJECTS |
| Admission ciphertext | Change one ciphertext byte with old ciphertext hash; correctly re-sign input1 | Pool input0 `VerifyError`; funding input1 ACCEPTS; Full REJECTS |
| Admission CM append | Corrupt current empty-append path or proposed CM successor; correctly re-sign input1 | Pool input0 `VerifyError`; funding input1 ACCEPTS; Full REJECTS |
| Admission NF isolation | Change proposed next NFroot/m while retaining current NF; correctly re-sign input1 | Pool input0 `VerifyError`; funding input1 ACCEPTS; Full REJECTS |
| Singleton G | First n=1,m=1 admission with missing/wrong G, wrong G amount or wrong sentinel/current singleton root | Pool input0 `VerifyError`; funding input1 ACCEPTS; Full REJECTS |
| Later G zero | A coherent later-admission positive uses G=0; companion reuses a nonzero old G | Positive all inputs/Full ACCEPT; nonzero-G pool `VerifyError` and valid funding ACCEPT |
| Native ranges | Actual R=MAX+1, V=0/floor−1/MAX+1, fee=0, change=MAX+1, combined R+E>MAX; prepare signed bytes before evaluation | Pool input0 `VerifyError` or, ONLY for a separately declared consensus-range fixture, explicit isolation range error; no resource/storage failure credited |
| Count capacity | Current n=0/65536, m=0/131072, m>2n+1; admission n=65535; private n=65534; reveal m+1>2n+1 | Pool input0 `VerifyError` before CM/NF/proof operations; invalid contexts labeled supplied-only |
| Private current context | Change actual input outpoint/R or prior Auth state independently, with fixed genuine proof bytes | Pool `VerifyError` at native context binding, before Groth16 |
| Private public NF witness | Corrupt current predecessor path/index, predecessor interval or SAME intermediate empty-append path | Pool `VerifyError` before Groth16; no ZK parse/budget error credited |
| Private public CM witness | Corrupt empty CM append path or proposed CM successor | Pool `VerifyError` before Groth16 |
| Private ciphertext | Alter one ciphertext byte while preserving Auth hash | Pool `VerifyError` before Groth16 |
| Immutable policy/VK successor | Pay correct reserve to a policy whose VK or code suffix differs while leaving executing original policy/input/proof unchanged | Pool `VerifyError` before Groth16; no alternate VK parsing needed |
| Genuine proof rejection | Preserve valid Auth/native public witnesses and negate a genuine proof's A point through official Arkworks serialization | Pool exact `ZkIntegrity("Groth16 verification failed")`; Full REJECTS; valid-curve proof shape retained |
| Reveal exact ALL | ACTUAL valid NONE2 native signature with unchanged CM-bound key/payout | Pool `VerifyError` at exact-ALL guard, before signature verification |
| Reveal key/payout | Valid signature from different key retaining original committed PK, or correct signature with redirected payout | Wrong signer `NullFail`; wrong payout `VerifyError`; Full REJECTS |
| Reveal full principal/fee | Declared P+fee differs from V, actual payout differs from P, or continuing remainder below60M | Pool `VerifyError`; correct re-sign removes signature confound |
| Cross-branch spentness | Private→reveal and reveal→private losing attempts retain the ORIGINAL positioned CM and NF and current CM membership. Supply CURRENT authenticated spent-NF equality, rather than only the stale old predecessor path | Pool `VerifyError` at strict authenticated NF ordering before signature/Groth16; old stale-root rejection reported separately |
| Cross-branch path | Companion to spent-NF equality has the correct current predecessor leaf/index but a corrupted CURRENT predecessor path | Pool `VerifyError` at current root authentication, before strict order |
| Header/domain/isolation | New payload wrong version/domain/length or current state header/domain altered in supplied context | Pool `VerifyError` or construction/schema rejection explicitly recorded; never substitute a stale proof failure |

`NullFail`, `VerifyError` and Groth16 verification text are pinned to the official
native source at `01b532e8…`. Both actual input engines are run even when Full
stops at input0. Full must reject every semantic negative. A Full-only failure,
undefined storage mass, insufficient budget, malformed curve point, invalid
unrelated signature or wrong earlier root does not qualify the intended check.

## Preparation, freeze and one execution

`*-freeze` and `control-resign-freeze` write exact Transaction/UtxoEntry serde,
supplied context, official full dimension masses, actual fees, raw txid and all
outputs. The re-sign helper uses only an explicitly supplied public development
secret and the actual requested sighash, keeps the recorded entry SPK, and has
no coin selection, network or wallet state. `validate-transaction` is the single
raw-case native execution path. Malformed input/context dimensions reject as a
fixture schema error before indexing.

After lifecycle materializes the genuine positive bodies, freeze source, binary,
actual VK/proof, all exact raw positive/negative cases, expected outcomes and
producer source in one manifest. Root and independent adversary review this
freeze before the single native run. Any necessary defect correction receives a
new source/preparation/run identity and retains the old one. Record the actual
six-body outcomes, typed controls, per-input units and compute/transient/storage/
mining masses. Quote100/200/500 separately from fee affordability; keep failed
economic targets even when consensus passes. No subsequent tuning is an earlier
trial success.

Heavy compilation is complete; short cached unit changes use at most8CPU/8GiB,
swap0. Native execution needs no GPU or fresh setup. Yield RAM/CPU to the sole
fresh lifecycle proving process; record unit cleanup. No funding or broadcast.
