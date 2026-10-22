# Offline Full transaction validation of the saved one-shot body

Status: **actual official isolation and Full validation passed**.
The unchanged positive, all ten typed native rejection controls and all four
separate policy cases matched. See [report](evidence/historical-state-consensus-01/report.json)
and [runtime metadata](evidence/historical-state-consensus-01/run-metadata.json).
This SDK-free sibling preserves the closed `public-state-native-check` source,
lock, binary and 23-case report. It consumes that diagnostic's exact saved
2,910-byte native Borsh transaction, 336-byte journal and 1,383-byte predecessor
redeem, each checked against compiled SHA256 pins before deserialization.
No proof, policy, output, fee or state is regenerated. The source-only build
passed two structural tests; failed PATH/mount-wrapper launch attempts are
retained separately from the successful build and actual runtime.

The official validator returned the unchanged fee 80,000,000 sompi. Native
masses exactly matched the original script diagnostic: compute/mining/relay
163,290; transient 11,680; storage/commitment 29; estimated bytes 2,920.
Default source-adapted policy passed. At 500 sompi per gram the necessary
81,645,000 fee exceeds the fixed fee by 1,645,000; that negative is retained.
No short-runtime resource event was emitted, so memory peak is unknown;
immediate launch caps were observed at 2 CPUs/3 GiB/zero swap.
The build consumed 702.409 CPU seconds over 132.872 seconds wall time,
4,418,777,088 bytes peak memory and zero swap under 6-CPU/6-GiB caps.

The positive runs the official Kaspa `01b532e` `validate_tx_in_isolation`, then
`validate_populated_transaction_and_get_fee` with `TxValidationFlags::Full`.
It uses `TransactionValidator::new` and `TESTNET_PARAMS`, with neither mass nor
script checks skipped. A finalized clone independently checks cached identity;
the original consumed Borsh bytes are preserved unchanged.

The explicitly supplied synthetic UTXO is 1.7B sompi, P2SH of the exact retained
predecessor redeem, block DAA 0, noncoinbase, no covenant ID. The caller declares
POV DAA 1,000,000,000 and block DAA 2,000,000,000,000. These are input context,
not a queried accepted chain view. The exact output remains 1.62B, fee 80M,
budget 1,600, fixed historical state/image and genuine embedded proof unchanged.

Ten typed controls distinguish isolation rejection (missing/duplicate inputs,
zero/overrange outputs) from Full UTXO rejection (outputs exceeding inputs,
overrange input, wrong storage commitment, changed P at actual pairing,
immature coinbase metadata and an unmet relative sequence lock). Exact
`TxRuleError` variant and stage must match; generic resource failures cannot
close a semantic gate.

Four separately labeled policy cases use source-adapted public script class,
P2SH sigop scanner and native normalized mass/relay-fee predicates: unchanged
default policy, maximum-budget block-mass rejection, nonstandard output
rejection, and the preserved fixed-80M failure of the 500-sompi scenario.
Official Mempool standardness methods are crate-private; this helper does not
claim to invoke them or enter an actual mempool. Native block dimension policy
is also separate from Full validation's storage-mass commitment check.

Independent [source review](evidence/independent-review/STATE-CONSENSUS-HELPER-SOURCE-REVIEW.md)
and [result observation](evidence/independent-review/STATE-CONSENSUS-HELPER-RESULT-OBSERVATION.md)
are copied unchanged with independent byte/mass recount evidence. The reviewer
did not execute the helper or generate a proof.

The closed packet includes the single frozen `evidence/frozen-checker` and
three read-only inputs in `evidence/frozen-inputs/`; no target/cache is included.
To repeat in a separately selected offline sandbox, run
`./evidence/frozen-checker verify evidence/frozen-inputs fresh-output`.
A repeat is a new observation and must use a fresh output identity.

Source references, all at `01b532e8b553523216471682649693af92f0fd16`:

- `consensus/src/processes/transaction_validator/{mod.rs,tx_validation_in_isolation.rs,tx_validation_in_utxo_context.rs}`
- `consensus/core/src/{errors/tx.rs,mass/mod.rs,config/params.rs}`
- `mining/src/mempool/{check_transaction_standard.rs,config.rs}`

Builds use an isolated copy of the completed native cache and offline Cargo;
no shared target lock or source tree is mutated. This imports no `risc0-zkvm`,
prover, wallet or shared-pool crate. Native verifier dependencies transitively
include the existing RISC0 verification components.

This remains **NONFUNDABLE**. The literal predecessor guard deliberately stops
successor continuation. Full validation trusts supplied UTXO/DAA context and
does not prove predecessor existence, accepted ancestry, unspentness, genesis,
backing, owner exit or privacy. Private header/block activation/finality APIs,
selected-chain validation, live conflict/RBF/mempool admission and P2P relay are
not invoked. The unchanged baseline locktime is zero with max sequence.
No network, funding, broadcast, setup or proving is part of this helper.
