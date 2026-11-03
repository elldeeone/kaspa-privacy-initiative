# Independent-deposit adversarial self-review

Reviewed 2026-10-20 (Australia/Sydney). This is the implementing agent's second
pass, not an independent audit or proof of cryptographic correctness. The
[specification](../../docs/rfc/0010-compact-independent-deposits.md) and unchanged
security invariants govern the experiment. [Results](DEPOSITS.md).

| Attack or failure | Binding / evidence | Remaining boundary |
| --- | --- | --- |
| Inflate credit or dilute prior claims | Existing range/conservation relation binds D and both output notes; native input amount equals D; successor is R+D-fee. Re-signed altered credit/fee/reserve mutations fail. | Single-party setup and unaudited relation/composition. |
| Treat a deposit as a free real-note spend | Distinct two-input/magic/mode/count branch; virtual input never enters pool CM/NF/history. NF root/count unchanged. Normal branch retains real anchor and strict NF insertion. | Requires authenticated canonical genesis/lineage; nf_count alone is insufficient. |
| Spend another person's ordinary funding | Input 1 is exact P2PK with canonical SIGHASH_ALL; native validation checks its real signature/context. Wrong-key/weak-type/context controls fail. | SIGHASH_ALL excludes signature scripts and compute budgets. |
| Spend a claim twice | Positioned NF, authenticated predecessor, strict unsigned gap, exact successor. Actual old/fresh proofs tested against the winner's successor in both orders. | Full-node accepted-history/current-UTXO view remains trusted. |
| Replay admission | The same funding outpoint is single-use in accepted ledger. Fresh backing may deliberately reuse proof/CM bytes at new positions; both positions spend independently. | Repeated bytes are a public link; normal wallets generate fresh notes. |
| Delete history / spentness | Native append paths preserve prior CMs/history; deposit NF bytes remain exact. Wrong roots, paths, count and unused padding fail. Python reconstruction agrees. | Data availability is not implied by root authentication. |
| Cross-pool/version spend | Immutable script retains domain/VK/code; saved descriptor hash and native proof check bind context. Wrong domain/VK/framing controls fail. | No v4-to-v5 migration. |
| Redirect payout / replace proof | Proof binds payout script/value/fee; settlement compares saved bytes and builds only current public paths. Native altered output checks fail. | Saved authorizations are sensitive; unused alternatives remain private. |
| Corrupt note delivery | Depositor decrypts/verifies intended outputs before signing and scans accepted ciphertexts before saving exits. Negative delivery control fails. | Circuit proves ciphertext digest, not correct encryption. |
| Exhaust tree capacity / strand small claims | Last-fitting admission and old-proof exit native boundary fixtures pass; overflow admission fails. Genuine minimum-note exits and unchanged floor/fee inequality pass. | Constructed capacity state is not a full accepted-history stress test; future fee increases remain open. |
| Prover/operator disappears | All four prover processes exit before drainage. Separate client namespaces expose only own saved bundles and authenticated public data; live clients obtain history through their own RPC. | Same host schedules clients; no adversarial-host or independent-hardware claim. |
| Data source lies / becomes unavailable | Descriptor/VK pinning, native lineage replay, missing/corrupt controls and fallback source. Valid stale prefix needs a separate current UTXO check. | All-history loss, reorg and pruning recovery are not demonstrated. |
| Leak payment relationships | No privacy improvement is inferred from four keys/eight notes. Old anchor ceiling, public amounts/ancestry/timing and repeated-CM linkage remain. | Stage 2 population inference and network/RPC privacy remain open. |

The harness's four admitted funding outpoints are a fixture restriction. The
covenant has no funding-key list or privileged admission signer. The native
validator supplied with arbitrary populated UTXOs proves script/transaction
validity, not real unspentness. Live accepted-parent/UTXO checks and final exact
accepted bodies/full hashes address that distinction for the measured run.

The ordinary funding helper correction searches earlier payout derivation indices
but requires exact script equality before signing. It does not grant access to
unknown keys or add a withdrawal path. Its first failed plan never broadcast.

No invariant was relaxed. This review supports proceeding through the bounded
testnet result, not public adoption. Offline, complete TN10 rehearsal and a
fresh measured trial passed; their actual accepted bodies/full hashes and
independent accounting are retained. Stop expanding mechanics after H10; assess
privacy policy and costs before the next implementation decision.
