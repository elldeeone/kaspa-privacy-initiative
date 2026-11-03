# Private-payment source review — 2026-10-18

**Recommendation:** investigate an Orchard-derived note/action relation, locally
proved by the wallet, with a total ordinary verifier inside the existing ordered
application transition. Prove delivery correctness as well as commitment creation.
This is a proposed integration, not reuse of Orchard's security result.

The [file manifest](private-payment-source-review-2026-10-18.json) records selected
primary files freshly fetched, byte lengths and SHA-256 digests. All listed files
were read at relevant definitions; this is not an exhaustive audit. Default-branch
heads for Kaspa docs, Rusty Kaspa, vProgs, Research, Orchard, Aztec, RAILGUN engine,
Monero and Litecoin were refreshed through GitHub on this date and match the
previous review. The `Railgun-Privacy/contract`, `circuits-v2` and existing Kaspa
membership experiment heads were also refreshed and match their prior pins.

## Facts and their implications

| Primary source / exact pin | Observed fact | Implication for the proposal |
| --- | --- | --- |
| [Kaspa Based Apps](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/based-apps.mdx) | L1 ordering, application execution and settlement have distinct responsibilities. | A locally valid wallet proof is insufficient without actual ordered-input and native settlement binding. |
| [vProgs batch verifier](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/abi/src/batch_processor/verifier.rs) | Batch verification folds operation identity/activity and checks resources/journals. | Adapt the demonstrated ordered backend; do not introduce another operator runtime or infer private-note enforcement. |
| [Research draft](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex) | Sovereign synchronization, availability and pruning require explicit treatment. | Native exit feasibility does not imply a complete archive or permissionless recovery implementation. |
| [Orchard notes](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note.rs), [nullifiers](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/nullifier.rs) | Notes bind recipient, u64 value, rho and seed; nullifiers are derived from the committed note and nullifier authority. New action output rho follows that action's old nullifier. Zero-valued dummy notes have specific semantics. | Preserve the complete dependent relation; do not replace it with a public commitment preimage or independent caller-selected spend marker. |
| [Orchard circuit](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/circuit.rs) | Source distinguishes insecure historical pre-NU6.2, repaired post-NU6.2, and post-NU6.3 circuit variants. The latter additionally constrains a cross-address flag. | A source commit alone is insufficient: pin the selected semantics, flags and verifying key. Prohibit the historical insecure variant and mismatched unsupported flags. |
| [Orchard note encryption](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs), [keys](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs), [tree](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/tree.rs) | Key roles, note reconstruction/validation and depth-32 ordered membership have separate APIs. Current source also distinguishes note versions. | Reuse role separation and exact decoding obligations. A valid low-level note constructor alone does not establish received-note validation or spend authority. |
| [Aztec constrained delivery](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/docs/docs-developers/docs/aztec-nr/framework-description/note_delivery.md) | Unconstrained on-chain logs may contain bad encryption/tagging; constrained delivery proves those computations. | Require proof-constrained encryption for completed payments. A ciphertext hash binds bytes, not their correctness. This is a **dated v5.2 source**, not current-head API evidence. |
| [RAILGUN commitments](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol), [note](https://github.com/Railgun-Community/engine/blob/6e2614d53a106dd62abad91e7ce03ee4a3956138/src/note/transact-note.ts) | Commitment/root accounting and encrypted-note reconstruction are distinct from current nullifier rejection. | Adapt these obligations; reject transplanting an entire account/runtime or copying restricted circuit code. Existing [rights limits](../poc/shielded-design/SOURCES.md) remain. |
| [Monero RingCT verification](https://github.com/monero-project/monero/blob/f8aba51d2d50ebe7c96a0f4d1f2d6e88add61710/src/ringct/rctSigs.cpp) | Range/conservation, spend authorization and key-image handling are distinct. | Compare privacy tradeoffs; do not substitute ring membership or imply Kaspa verifies RingCT. |
| [MWEB light clients](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md) | Server-assisted viewing and local compact scanning have different disclosure/availability properties. | Prefer full local scanning initially; do not export viewing keys to simplify recovery. This document is a design discussion, not universal deployed-wallet proof. |
| [Existing Kaspa membership circuit](https://github.com/mrzeku2000XTTT/kaspa-xmss-covenants/blob/6713eb0115722d5193718dfe4dbe716bdc9b3d09/covenants/privacy_pool/withdraw.circom) | The inspected experiment supplies bounded membership/nullifier constraints. | Study rather than reimplement that narrow experiment; it does not supply this full monetary relation, delivery, current-state replay or all-users recovery. No deployment was reproduced. |

## Candidate comparison and decision boundary

1. **Leading note family: Orchard-derived actions.** Hidden membership, nullifiers,
   separated keys and note encryption are available to study together. A new KPI
   wallet guest/circuit must prove all dependent predicates, checked integer
   balance and exact public intent. Reusing primitive definitions is not copying
   Halo2 verifier compatibility or the security result of its deployed circuit.
2. **RAILGUN-derived notes** are a meaningful comparison, but current rights limits
   and integration review make copying its circuits inappropriate. The proposal
   retains its scan-and-compare and current-spentness lessons.
3. **Aztec** informs delivery constraints; deploying its runtime is unnecessary to
   ask this research question. **Monero/MWEB** illuminate leakage and recovery but
   are not selected hidden-membership backends for native KAS.

The two existing proving routes remain RISC Zero wallet composition and the
specialized BN254 wallet-proof comparison. Ordinary verification must classify
bad proofs inside the proved outer computation. The latter requires reviewed
circuit-specific setup; the current one-party proxy setup is not appropriate
for real liabilities. GPU qualification measures computation only, independently
of whether the note relation is correct.

The [new proposed specification](../docs/rfc/0003-private-payment-proof-and-settlement.md)
names the full relation and integration conditions. The bounded
[ADR](../docs/adr/0015-private-payment-proof-boundary.md) accepts only separation
of the research tracks and the specification's review boundary. Primitive suite,
exact parameter/key material, production construction and native funding remain
unapproved. No third-party code, proof, pool or native transaction was executed
in this source-review track.
