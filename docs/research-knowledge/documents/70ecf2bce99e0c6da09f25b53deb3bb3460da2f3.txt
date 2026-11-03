# Toccata activation in official v2.1.0

**No Toccata DAA threshold or opt-in feature flag exists in the selected official
v2.1.0 source.** At the supplied live TN10 DAA score of about 603,995,000, there
is no additional Toccata activation score to wait for. This is a source result;
this review did not query or attest the remote node.

Pinned source: `kaspanet/rusty-kaspa` tag `v2.1.0`, commit
`01b532e8b553523216471682649693af92f0fd16`.

| Component | Exact selected behavior |
| --- | --- |
| Transaction version | `TX_VERSION_TOCCATA = 1`; isolation validation rejects versions greater than 1 and does not check DAA for version 1. |
| Version-specific fields | Version 1 inputs use compute budgets; legacy sig-op commitments are rejected. Output covenant bindings are allowed for version 1 and rejected for version 0. Native/system subnetworks require gas zero. |
| Covenant validation | `check_covenant_info` calls `CovenantsContext::from_tx`; its `block_daa_score` argument is unused. |
| Script validation | `check_scripts` also ignores `block_daa_score`. `EngineFlags` contains only signature-operation resource cost, with no KIP-10/Toccata/Groth16 enable flag. |
| Introspection | Transaction introspection opcodes directly access transaction/input/output context. They are not in the disabled-opcode list and have no activation branch. |
| Groth16 | `OpZkPrecompile` (0xa6) directly dispatches parsed tag 0x20 to Groth16 after charging its resource cost; no network/DAA/activation branch. |
| Params | `Params` and `OverrideParams` have no `toccata_activation` field. An explicit regression test verifies that field is rejected as unknown. |
| Historical TN10 fork | `TESTNET_PARAMS.crescendo_activation = 88_657_000`, far below the supplied live score. This is not a Toccata activation. |

The older `kip10_enabled` parameter text remaining in two engine doc comments
is stale: it does not exist in the actual function signature or `EngineFlags`.

Sources: [transaction version/field checks](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs#L124-L213),
[covenant/script validation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs#L162-L179),
[engine flags](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/lib.rs#L122-L130),
[opcode definitions](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L759-L769),
[Groth16 dispatch](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/mod.rs#L34-L39),
[TN10 params](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/config/params.rs#L651-L705),
[removed-field regression](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/config/params.rs#L794-L799).

For the adapter, retain `getServerInfo` fields `serverVersion`, `networkId`,
`hasUtxoIndex`, `isSynced`, `virtualDaaScore`, and RPC API version/revision.
Require `networkId == "testnet-10"`; `getCurrentNetwork` reports only network
type and cannot establish the testnet suffix. Cross-check
`getBlockDagInfo.network` and retain its sink, pruning point and DAA score.
There is no dedicated activation-capability or consensus-params RPC in this
release's API. The returned version/network fields are remote assertions,
not proof that an unmodified official binary is running.
[RPC response definitions](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/rpc/core/src/model/message.rs#L2390-L2400).

This removes a speculative activation wait. It does not replace local Full
validation, actual relay/acceptance testing, or confirmed payout evidence.
Preserve transaction version 1 **and SPK version 0** as separate exact checks;
unknown SPK versions bypass script execution in the selected engine.
