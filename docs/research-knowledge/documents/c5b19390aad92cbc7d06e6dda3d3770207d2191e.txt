# Reusable authorization: source check, 2026-10-19

GitHub heads rechecked before implementation: Rusty Kaspa
`f7d7877363fb97c2ec6871be0e8cbc351d44df10`, vProgs
`f9b84a863a7c7c20586a9cf947550475e894f72e`, research
`c923faca11a49148fa7d912d27ce00197a5c5a4a`, KIPs
`e4ae2332117b5cb68bd6188e065ef885b6d17939`. They match the preceding
[review](shared-pool-four-wallet-source-review-2026-10-19.md). Keep native/SDK pin
`01b532e8b553523216471682649693af92f0fd16`; node version is separately observed.

Read the pinned native `crypto/txscript/src/opcodes/mod.rs`: input/output/payload
introspection, concatenation, substring, integer arithmetic, NUM2BIN/BIN2NUM and
Groth16 `OpZkPrecompile` provide the candidate checks. Current Toccata/KIP and
mass/policy context is recorded in the earlier review. Native execution and
relay/resource validation, not this source interpretation, decide feasibility.

Re-read [Orchard commitment-tree design](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/commitment-tree.md)
and [ZIP 225](https://zips.z.cash/zip-0225): membership anchors can refer to past
commitment state; nullifiers are separate spend identifiers. Re-read
[RAILGUN Commitments.sol](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol):
root history and nullifiers are separate storage. Adapt that separation, using
authenticated array prefixes because this experiment already retains all notes.
Do not claim this array/circuit is Orchard or RAILGUN cryptography.

Re-read [Aztec state management](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/docs/docs-developers/docs/foundational-topics/state_management.md):
reuse append-only private records plus unlinkable spent markers, not its
sequencer/runtime. Re-read [Monero RingCT](https://github.com/monero-project/monero/blob/7778a369afdb788af245ba5ac4d5b17d5a2cc4c5/src/ringct/rctSigs.cpp)
and [MWEB kernels](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md):
retain explicit fees in conservation; reject importing ring signatures or
extension-block consensus merely to fix application proof invalidation.

Re-read [vProgs covenant](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs)
for immutable suffix propagation, and [Kaspa research draft](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex)
for historical-state anchors. Reuse the suffix technique already adapted in our
pool. The broader runtime is neither required nor ruled out by this bounded test.

Privacy tradeoff: public anchor count bounds the possible consumed commitments
to an older prefix. It can reduce candidates compared with the full current
set. Exposing a snapshot and economic nullifier is intentional; exposing the
selected note or private amount is not. Compare privacy separately from latency.
