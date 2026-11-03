# Compact-state source review, 2026-10-19

Current official heads rechecked: rusty-kaspa
`f7d7877363fb97c2ec6871be0e8cbc351d44df10`, vProgs
`f9b84a863a7c7c20586a9cf947550475e894f72e`, research
`c923faca11a49148fa7d912d27ce00197a5c5a4a`, KIPs
`e4ae2332117b5cb68bd6188e065ef885b6d17939`; initiative upstream
`cde2b88de3a16af401a2046bd90a124aa105418a` (fixed four-batch proof package).
Keep the preceding experiment's native/SDK pin
`01b532e8b553523216471682649693af92f0fd16`; report the live node separately.

Read [KIP-17](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md)
and pinned native `crypto/txscript/src/{lib.rs,opcodes/mod.rs,data_stack.rs}`:
SHA256, concatenation, substring, integer arithmetic and introspection support
the proposed unrolled public path checks. The native script element/combined
script bounds are 1,000,000 bytes; practical transaction mass is a separate gate.
This source reading is not relay acceptance.

Re-read [Orchard commitment trees](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/commitment-tree.md):
adapt fixed-depth append-only membership; do not import Sinsemilla or block-root
semantics. [Zcash specification section 4.14](https://zips.z.cash/protocol/sapling.pdf)
describes positioned-note nullifiers; adapt the position binding using the
experiment's existing HMAC-SHA256, with a new tag. Do not claim compatibility.

Read [Aztec indexed nullifier trees](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree):
reuse authenticated predecessor/gap checking and append insertion. Keep public
predecessor computation untrusted; the covenant verifies it. Re-read
[Aztec state management](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/docs/docs-developers/docs/foundational-topics/state_management.md)
and [historic proofs](https://docs.aztec.network/developers/docs/aztec-nr/framework-description/advanced/how_to_prove_history):
adapt an archive of accepted roots, not their sequencer or runtime.

Re-read [RAILGUN commitments](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol):
retain historical membership/current spentness separation, not EVM mappings or
administration. Re-read [Monero RingCT](https://github.com/monero-project/monero/blob/7778a369afdb788af245ba5ac4d5b17d5a2cc4c5/src/ringct/rctSigs.cpp)
and [MWEB kernels](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md):
retain explicit fee conservation; reject importing their consensus/proof systems.

Re-read [vProgs covenant](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs)
and [research draft](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex):
retain immutable suffix propagation and explicit state binding. The proposed
application experiment does not settle the broader runtime question.
