# Private-batch source refresh — 2026-10-28

Source review only. No compiler, prover, wallet, RPC experiment or financial
trial was run. This note refreshes the existing-work comparison for private
owner consent, hidden witness routing and public-marker disclosure. It selects
no production architecture and changes no invariant.

## Sources inspected and what can be reused

| Source | Verified source fact | Reuse or adaptation boundary |
| --- | --- | --- |
| Kaspa Toccata | The official guide maps KIP-16 to native Groth16/RISC Zero verification, KIP-20 to covenant/output bindings and KIP-21 to sequencing. The current Groth16 implementation uses BN254, checks the verification-key input dimension and rejects trailing key bytes. [Guide](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/references.mdx), [verifier](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/groth16/mod.rs). | Reuse the actual native verifier/encoding and exact native-effect bindings. These interfaces do not supply private input admission, owner consent or witness confidentiality. |
| `kaspanet/vprogs` | The inspected default-branch README explicitly identifies early/prototype infrastructure and describes the runtime/framework. [README](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md). | Study the existing based-app settlement/runtime option. Do not infer that a different runtime is required, or expand operator infrastructure to solve the present private-construction gap. This was a default-branch check, not a survey of all feature branches. |
| `kaspanet/research` | The inspected index links the vProgs protocol specification as a v0.0.1 draft. [Research index](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/README.md). | Retain the draft as an architecture reference. The inspected index is not an implementation of private owner authorization or MPC proving. |
| Zcash Orchard | ZIP-244 sets the signature hash type to `SIGHASH_ALL` for an Orchard Action and includes the Orchard effects digest. Orchard separately derives its binding validating key from action value commitments and the public value balance. [ZIP-244](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/zips/zip-0244.rst#signature-digest), [bundle](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle.rs#L763-L779). | Reuse separation of spend authorization, hidden witness and value binding. An established signature alone does not replace the complete-effects message contract or provide private multi-owner consent. |
| Aztec | The current official v6.0.0 PXE documentation says private execution/proving is client-side and private inputs remain there. It explicitly identifies node-query interest leakage. State documentation separates note commitments from nullifiers and permits on-chain encrypted or off-chain note delivery. [PXE](https://docs.aztec.network/developers/docs/foundational-topics/pxe), [state](https://docs.aztec.network/developers/docs/foundational-topics/state_management), [nullifiers](https://docs.aztec.network/aztec-nr-api/mainnet/noir_aztec/nullifier/). | Reuse the distinction between keys, private execution, public effects, discovery and retained recovery data. Off-chain delivery and public roots alone cannot meet KPI's seed-plus-public-data recovery requirement. Outsourcing a witness introduces a different trust boundary. |
| RAILGUN | The inspected join-split circuit hashes the Merkle root, `boundParamsHash`, all input nullifiers and all output commitments into the signed message; signature validity, input membership, output ranges and balance are separate constraints. [Circuit](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom#L8-L81). | Reuse explicit signed-effect binding and separate constraints. A new owner-intent format must preserve every authorized effect through a constrained correspondence; a server-provided digest is insufficient. |
| Monero | Current RingCT code checks CLSAG signature scalars and rejects an identity key image; semantic balance/range verification and signature verification are distinct functions. [RingCT](https://github.com/monero-project/monero/blob/3fd0f88c20f559839cafb20911cb13cb45eba7bd/src/ringct/rctSigs.cpp#L889-L904), [semantic verification](https://github.com/monero-project/monero/blob/3fd0f88c20f559839cafb20911cb13cb45eba7bd/src/ringct/rctSigs.cpp#L1358-L1498). | Reuse the separation of authorization, deterministic spent markers and confidential conservation. Monero's native-asset/ring model does not supply a Kaspa reserve exit or demonstrate KPI's known-cohort MPC privacy. |
| Litecoin MWEB | The pinned consensus document defines explicit inputs, outputs, kernels and signatures. MWEB's light-client document states that private-view-key server filtering exposes owned outputs and amounts, and describes client-side retrieval of verifiably unspent outputs. [Consensus](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md), [light clients](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md), [aggregation specification](https://github.com/litecoin-project/lips/blob/master/lip-0004.mediawiki#9-transaction-aggregation). | Study aggregation and independently verifiable recovery data. Final aggregate structure does not erase transactions already observed before aggregation. Do not move scan secrets to an untrusted coordinator for convenience. |

## Direct implications for the pending design

**Facts from the retained KPI source:** the current authority seam has an owner
reconstruct and sign the complete packet. The proposed MPC backend explicitly
does not supply generic private NativeAuth witness generation. Client IDs,
register offsets and a clear public-input prefix may reveal ownership before
the final proof. See the retained [implementation plan](../source-checkpoint-2026-10-27/groth16-integration/INTEGRATION-IMPLEMENTATION-PLAN-03.md)
and [private-instance boundary](../source-checkpoint-2026-10-27/groth16-integration/PRIVATE-INSTANCE-AND-WITNESS-BOUNDARY-01.md).

**Design inference:** hiding unrelated owners' effects from each signer while
retaining authorization requires an explicit new message contract. One
candidate is an owner-signed intent containing that owner's exact allowed
effects, fee and context, with an aggregate relation proving a bijection from
all authorized inputs and outputs into the final public effects. It must prove
per-owner conservation, current-state validity, uniqueness and exact tuple
contents. This is a changed relation requiring RFC/ADR review and new profile
qualification; it is not compatible merely because the signature primitive
and native Groth16 tag already exist.

**Observer-model inference:** if a stable deterministic spend marker is
released to a coordinator or colluding server, and that observer knows the
cohort in each attempt, later known-cohort intersections can reveal ownership.
A valid zero-knowledge proof cannot revoke that earlier observation. Public
release timing, owner admission/routing and retry behavior therefore belong to
the protocol and observer experiment. This inference does not assert a break
of the mature protocols above. Preserve KPI's measured changed-cohort failure;
neither a successful toy proof nor fresh transport masks close it.

**Exit constraint:** a cohort or coordinator cannot acquire the ability to
freeze an otherwise valid independent exit as a privacy repair. Delaying
private batch progress may be a liveness tradeoff; removing independent exits
would violate I-8/I-9/I-10. Accepted payments must remain recoverable from the
specified wallet secret and complete authenticated public data, without a
private pending-intent journal.

## Refresh identity and limits

GitHub's default-branch commit API was queried on 2026-10-28. The pinned source
heads above were returned for Kaspa docs, rusty-kaspa, vprogs, research,
Orchard, ZIPs, RAILGUN circuits, Monero and Litecoin. RAILGUN contract head was
also resolved to `36bcf5ed7cf94bfafb6e1a303e1832c769c16780`; the join-split
circuit was the specific consent source inspected here. This is a bounded
file review, not a complete upstream audit.

Aztec's monorepo default head resolved to
`cc60215b4d4a88f85b41f83351f1b5d112e06b3f`, but the older reviewed documentation
and `aztec-nr` paths are absent there. The official live v6.0.0 documentation
was inspected instead; its edit/source links point at reorganized repositories.
No code compatibility with the old v5.2.0 pin is inferred. The MWEB LIP link is
moving `master`; its aggregation description is used only as a design source,
while consensus/light-client code-document links are pinned above.

Existing detailed comparisons remain in `research/zcash-orchard.md`,
`research/aztec.md`, `research/railgun.md`, `research/monero.md` and
`research/litecoin-mweb.md`. Those October 8 notes are historical reviews;
their measured or compatibility claims were not newly reproduced here.
