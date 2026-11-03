# Selected-profile local native rehearsal

2026-10-24 UTC. **Both genuine mixed rounds and all nine direct withdrawals
passed actual Native Full validation and every input script under one selected
profile.** These are local supplied UTXO contexts, not funded testnet acceptance,
confirmed payouts, independent consensus, a privacy qualification or an audit.

The new profile is `69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f`.
Both mixed rounds used the selected image
`d4b2d4e2c195533457bbb34a80cca286e489f9bb3624c5767d53ccc525db7784`.

The attachment helper verified each externally selected native128 proof and
retained the original transaction ID, current point, payload, outputs, input
context, storage mass, B1800 compute budget, exact fee, projection and journal.
Only the original zero 128-byte outer-proof witness slot changed. Separate CPU
verification of each compressed receipt matched the external image and journal
with development mode and unresolved assumptions absent.

Nine independently rechecked direct Exit cases then followed the genuine second
round's physical transaction ID. Every head/state/reserve/script link agreed;
nine distinct original nullifiers were inserted. Direct withdrawals used no
MPC or shared RISC Zero prover. Final public state has CM count 15, NF count 16
and reserve 0. Backup-restoration provenance and final private wallet scans are
separate integration evidence, not findings inferred by this native validator.

| Consecutive native checks | Result |
| --- | --- |
| Genuine mixed rounds | 2 Full/script positives |
| Genuine independent full-note withdrawals | 9 Full/script positives |
| Changed mixed cases with the same genuine R1 proof | 16 native rejections |
| Maximum observed mixed script units | 15,583,199 of 18,009,999 |
| Maximum observed direct Exit script units | 14,830,060 of 18,009,999 |

Eight coherent changed effects/root/commitment/proof cases reached
`ZkIntegrity`; eight state/header/amount/output/covenant controls rejected with
`VerifyError`. No financial rule, authorization or core source was changed.

Integer reserve accounting across the two mixed rounds and nine withdrawals:

```text
6,000,000,000 initial supplied reserve
= 5,788,849,600 native payouts
+ 211,150,400 mixed-round and withdrawal fees
+ 0 final reserve
```

This fee subtotal excludes ordinary funding acquisition and GN3 founding; it
must not be presented as the complete lifecycle fee result or a fee-target pass.

The [finite evidence packet](native/selected-local-result-01/MANIFEST.json)
contains 140 payload files totaling 1,052,012 bytes: exact final cases, projections,
journals, native128 proofs, compressed receipts, separate CPU verification,
actual Full/script reports, consecutive-state summary and same-proof controls.
No original private backups, note openings or ownership maps were read or hashed.
Actual testnet funding, accepted backing, confirmations and separately
administered recovery availability remain separate required gates.
