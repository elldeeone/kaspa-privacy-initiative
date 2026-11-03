# Adversarial second pass: P1 preparation

Scope: candidate formats, established-library vector checker, public primitive
VM probe and read-only node observations. This is an author self-review, not
the independent cryptographic composition review required by P1.

| Failure | Control and remaining limit |
| --- | --- |
| Mint or spend from a fixture | The tools have no native signing/submission path and implement no accepted wallet relation. Public structural intents deliberately use synthetic artifact/descriptor IDs. Do not register the primitive image as a payment verifier. |
| Accept a different program or output | Freeze case hashes and image before execution; compare the full VM journal with independently published commitment/nullifier bytes; verify the saved succinct receipt, successful claim and empty assumptions in a separate CPU process. Reject seal, image and journal mutations. This shares the pinned SDK; it is not a second verifier implementation or audit. |
| Wrong amounts or ambiguous bytes | Exact unsigned integer semantics, canonical hex, fixed two-slot lengths, strict kind fields, distinct optional absence/present-zero, bounded script lengths, complete decoder consumption and Python/Rust byte comparison. Malformed inputs and every truncation of all golden examples reject. This is a structural codec, not conservation or native policy verification. |
| Hide incorrect primitives with generated expectations | Orchard outputs are checked against published vectors, not freshly self-generated outputs. Depth-32 expectations come from the separately pinned upstream Python reference and match published empty roots/shorter-path corpora. Different Rust/Python encryption corpora are retained and checked separately. |
| Claim the old proxy or development receipt is private proof | Distinct primitive tag/image and explicit non-payment labels throughout; development mode forbidden and succinct receipt type required. The preexisting proxy receipt and original failed large-segment attempt stay unchanged. |
| Leak a user's key | Only already-public upstream keys enter this experiment. No user seed/witness, funded wallet or remote proving service is used. This does not establish privacy of future proving, logging, network access or ciphertext discovery. |
| Accept stale state or double-pay | No native state is accepted and no payout is implemented. The codec does not verify current anchors/nullifiers/deposit consumption. R05/R06/R07 model results still need real proof and native enforcement. |
| Misdiagnose a node from a failed RPC | Each read-only method gets a separate WebSocket. An unknown operation closing one socket cannot make the next known-good method appear absent. Retain server/network observations before and after. Successful Full history and failed lane proof are separate observations, not a blanket claim about consensus support. |
| Overwrite an earlier result | New output directories and create-new writes; the GPU runner rejects an existing output before writing failure markers. Original historical evidence is retained. Operational resource caps are generous and cannot turn an incomplete attempt into an accepted proof. |
| Dependency disappears | Source commits, Cargo locks, public vectors, build hashes, raw observations and receipt bytes must be retained. Missing program/proof/history means unavailable, not acceptance. These archives do not yet comprise a complete independent private recovery bundle. |

Remaining trust: selected upstream implementations and toolchains, local host
integrity, the RISC Zero verifier and its cryptographic assumptions, and the
owner's single RPC server for its reported state. Reusing Orchard APIs does not
inherit the soundness of its separate Halo2 circuit. The new composition,
recovery authorization/native binding, complete wallet relation, real R13 and
independent confirmed R16 remain open.
