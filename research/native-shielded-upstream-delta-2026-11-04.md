# Kaspa source refresh during native specification finalization

**Date:** 4 November 2026 (Australia/Sydney). **Scope:** source review only;
no node, RPC, index build, funds or native experiment was run.

Official Rusty Kaspa HEAD moved during this task from reviewed base
`b85380d16514e65136001530e7c717eef304e654` to
`af6ff23a0b3e8271407da3203ce4017dd188d7ec`. One new commit adds a covenant-ID
UTXO index and paginated RPC. The full 47-path delta inventory and 25 byte-equal
protocol-file hashes are retained in the
[source receipt](../docs/spec/native-shielded/artifacts/upstream-delta.json).
Kaspa docs/KIPs and Orchard HEADs remained at their reviewed pins.

## Verified new capability

`get_utxos_by_covenant_ids` returns ordinary covenant UTXOs with optional DAA
range/script filters, cursor and bounded database-work budget. The node must
enable both `--utxoindex --covenant-index`; the new config flag defaults false.
Returned entries contain public outpoint, amount, script, DAA/coinbase and
covenant metadata. The new gRPC conversions wrap those entries; they do not
change the ordinary transaction codec. Sources:
[API](https://github.com/kaspanet/rusty-kaspa/blob/af6ff23a0b3e8271407da3203ce4017dd188d7ec/rpc/core/src/api/rpc.rs#L406-L432),
[configuration](https://github.com/kaspanet/rusty-kaspa/blob/af6ff23a0b3e8271407da3203ce4017dd188d7ec/consensus/core/src/config/mod.rs#L44-L51),
[entries/conversion](https://github.com/kaspanet/rusty-kaspa/blob/af6ff23a0b3e8271407da3203ce4017dd188d7ec/rpc/core/src/convert/utxo.rs).

## Consequence for this draft

This is useful reusable discovery tooling for future covenant-backed research;
do not recreate it or infer its presence from `--utxoindex` alone. It is not an
authenticated native shielded snapshot, missing ciphertext/parameter recovery,
confidential output type or a privacy pass. First-profile native funding here
uses plain key scripts without covenants, so the optional index is not a
prerequisite. Old paused covenant experiments were not resumed.

The actual ordinary output/value type, compute/covenant widths, ID/signature
hashes, header2/PoW hash, mass formulas, accepted-order/parallel/body checks,
virtual-state/pruning rules, coinbase rewards and Groth16/RISC0 tag dispatch
relevant to the draft are byte-identical at the refreshed HEAD. Retain their
exact baseline citations rather than silently rewriting historical receipts.
The current-source claim now records both the reviewed base and refreshed HEAD.
No spec rule changed because of this source delta; no upstream build or new RPC
runtime qualification is claimed.
