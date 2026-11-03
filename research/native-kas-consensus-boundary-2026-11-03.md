# Native-KAS shielded-value consensus boundary: source refresh

**Reviewed:** 2026-11-03. **Scope:** primary-source evidence for open
[RFC-0004](../docs/rfc/0004-native-kas-private-payment-boundary.md).
No consensus architecture is adopted and no node, proof, wallet or trial was run.
The [source manifest](native-kas-consensus-sources-2026-11-03.json) records exact
commits, Git blobs and SHA-256 for 21 inspected files. Official HEADs match the
3 November consolidation refresh; a repository head is not proof of network
activation. The older RFC's rusty-kaspa identity is updated to the inspected head.

## What the current source actually enforces

| Boundary | Source fact | Consequence for a new native value domain |
| --- | --- | --- |
| Representation | Ordinary outputs expose `value: u64`, script and optional covenant; the transaction has version, inputs/outputs, subnetwork, gas and payload. [transaction types](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/tx.rs) | A payload alone does not change native value accounting. A consensus-recognized bundle/output representation and all serializers must be specified. |
| Isolation | Ordinary outputs are positive and bounded; output sums are checked. Unknown transaction versions and non-coinbase transactions with no ordinary inputs are rejected. [isolation rules](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs) | A pure shielded spend cannot silently use the current no-input transaction rules. Empty/dummy bundles must not gain minting authority. |
| Balance/fees | The contextual validator checks ordinary input/output amounts and returns their difference as a fee. It separately checks mass, sequence constraints and scripts; fee-rate threshold is identified as mempool policy. [contextual validation](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs) | A new public shielded balance must enter conservation and exactly-once fee accounting, without relaxing old transaction validation or conflating consensus validity and relay policy. |
| Hash/authentication | Transaction-ID encoding excludes signature-script/mass fields according to its flags; full hashing and signature hashing have their own exact effects. Payload and ordinary output effects are included through their respective paths. [transaction hashing](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/hashing/tx.rs), [signature hashing](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/hashing/sighash.rs) | Specify an effect digest without a proof/signature fixed point and update each hash/signature path deliberately. Never infer a new field is authenticated because a proof verifies. |
| State/order | The virtual processor composes selected-parent state and consensus-ordered mergeset effects, records accepted transactions and fees, and can parallelize validation. [accepted transaction processing](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/pipeline/virtual_processor/utxo_validation.rs), [virtual-state updates](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/pipeline/virtual_processor/processor.rs) | Global shielded nullifiers, note positions and pool balance need matching deterministic acceptance, conflict resolution, atomic updates and undo; independent successful proof checks are insufficient. |
| Rewards | Coinbase construction uses mergeset reward data including subsidy and transaction fees. [coinbase reward construction](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/coinbase.rs) | Do not invent a same-block emission identity or separately mint shielded fee rewards. Integrate the calculated fee with the existing delayed/DAG reward path. |
| Mass/state | Serialized-size, compute/transient and persistent UTXO storage accounting are distinct. [mass accounting](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/mass/mod.rs) | New note/nullifier/ciphertext state needs reviewed pricing and bounds; a verifier's base cost is not a complete fee quote. |
| Bootstrap | Pruning-proof application imports existing consensus structures and virtual state. [pruning-proof application](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/src/processes/pruning_proof/apply.rs) | It authenticates no proposed shielded snapshot by assertion. Add an authenticated bootstrap rule or replay the retained shielded history from activation. |
| Cryptography | Current dispatch accepts Groth16 and RISC Zero Succinct tags; `MAX_SOMPI` is `29_000_000_000 * SOMPI_PER_KASPA`. [verifier dispatch](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/crypto/txscript/src/zk_precompiles/tags.rs), [monetary bound](https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/consensus/core/src/constants.rs) | Orchard/Pasta/Halo2 proofs are not a drop-in ABI. Carry explicit bounded sompi arithmetic across any reviewed adaptation. |

The proposal inference is narrow: the reviewed ordinary native value fields
and conservation rule do not supply confidential native output amounts. This
is not a claim that no application on Kaspa can hide its internal state.

## Current covenants and Based Apps remain distinct

[Inline ZK](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx) binds a proven
transition to the actual successor; [the decision guide](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx)
uses state layout/shared-state requirements to choose infrastructure.
[KIP-21](https://github.com/kaspanet/kips/blob/d832dbd89347dcb16d3d83bf6755b081714cbcb2/kip-0021.md) supplies ordering/sequence commitments,
not confidential value conservation. These are useful current primitives and
must not be relabelled a native shielded serialization change.

The inspected vProgs [README](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md) remains prototype
infrastructure. Its [withdraw action](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/runtime-processor/src/action/withdraw.rs)
takes public amount/destination data and its
[permission path](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/permission_script.rs)
binds ordinary payout effects. The [research reference](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex)
describes historical state/witness dependencies with pruning details deferred.
A future based app may amortize shared execution, but none of these source facts
removes the ordinary transparent boundary or proves independent recovery after
all required ciphertexts/parameters are gone.

## Design review consequences

The following are proposed requirements, not current capabilities:

1. Keep transparent inputs/outputs and the new consensus pool in one native-KAS
   conservation equation. Never count pool balance twice as an ordinary reserve
   UTXO and shielded backing; never call withdrawal principal a fee.
2. Process public pool balance, nullifiers, commitment append positions and
   ordinary UTXO effects atomically in accepted DAG order, including undo.
   Rechecking current spentness cannot be skipped with a cached proof verdict.
3. Specify exact bounded encodings, signing effects, program/key identity,
   network/pool scope and version-migration nullifier rules. Reserve unfamiliar
   transaction/profile values for review rather than assign a deployed constant.
4. Retain authenticated discovery records and exact public proving artifacts.
   Existing UTXO/pruning commitments are not automatically commitments to a new
   pool or its recovery log. Retention/serving is an explicit liveness assumption.
5. Keep transparentization visible. Confidential native ownership could remove
   the measured terminal-public-value input while the holder stays shielded;
   converting later into ordinary KAS reveals that later boundary again.

These points are read together with the
[mature-protocol source review](native-kas-shielded-value-sources-2026-11-03.md)
and the [local prior-knowledge guide](../docs/research-knowledge/README.md).
Existing invariant I-2 and the global/native-domain accounting interpretation
require explicit review; SECURITY-INVARIANTS.md is unchanged.
