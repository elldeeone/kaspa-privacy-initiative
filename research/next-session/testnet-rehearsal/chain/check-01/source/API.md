# Finite TN10 adapter

Run `node poc/future-native-chain/adapter.mjs` with one JSON object on stdin.
The adapter contains no wallet or private signing keys. All amounts/64-bit
integers in its returned transaction representation are decimal strings.

Common request: `op`, `sdk_path` (optional pinned SDK kaspa.js or directory),
`rpc_url` (except roundtrip). Primary:
`wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh`.
Only TN10, synced/indexed official-version2.1.0 nodes are accepted for execution.
The remote network/version assertions remain trusted, not binary attestation.
Genesis may be pruned; the expected network genesis is source-pinned.

- `network`: read-only network/capability/fee report.
- `checkpoint`: read-only `start_hash`, `header`, `reference_sink`, time.
- `utxos`: request `scripts` (full version-prefixed hex); returns unordered exact
  `entries` plus network/time/sink. This alone establishes no acceptance depth.
- `roundtrip`: request `body_path` (native transaction.json), optional `context_path`
  (default sibling supplied-context.json; required populated native context). Returns `transaction`
  (safe canonical representation), `SDK_PINS`, `lossless_native_roundtrip:true`.
- `observe`: parameters below. No submission, no observation deadline.
- `submit-once`: parameters below; requires exact root release and durable markers.

## Identity and local checks

`profile_path` points to `<trial>/public/identity.json`, never secret profile.json.
Constructor schema `kpx2-tn10-private-trial/v1`, `network_id`,
`genesis_hash_hex`, `domain_hex32`, `domain_nonce_hex32`, trial classification
`PRIVATE_TN10_TEST_KAS_ONLY`. Domain derivation is independently checked and the
old public DO_NOT_FUND domain is rejected.

Both observe/submit require `stage` from this finite list:
`fundingprep`, `founding`, `admit`, `private`, `bob-reveal`, `charlie-reveal`;
`body_path`, `local_check_path`, `profile_path`, `start_hash`.
The local check JSON is produced after actual native Full and every input engine:

```json
{
  "body_sha256":"sha256 of raw native transaction.json bytes",
  "transaction_id":"native raw txid hex",
  "profile_sha256":"sha256 of public/identity.json bytes",
  "native_full_accepted":true,
  "all_input_engines_accepted":true,
  "native_binary_sha256":"selected immutable native ELF hash",
  "inputs":[{
    "outpoint":{"transactionId":"raw hex","index":0},
    "amount_sompi":"306866100",
    "script_public_key":"0000 plus exact script hex",
    "block_daa_score":"0",
    "is_coinbase":false,
    "covenant_id":null
  }]
}
```

For founding ONLY add `output0_redeem_hex`: actual entire successor redeem
(the subsequent ADMIT input signatureScript bytes from offset199 onward).
Its fresh domain and exact version0 P2SH match are checked. Founding payload has
Note168 immediately after its magic, so it contains no standalone domain field.

## Observation

Additional request fields: `expected_unspent_output_indices` (default all),
`min_confirmations` (default20, must≥20), `poll_ms` (default1500).
Use `[]` when rechecking acceptance of an already consumed intermediate body.
Observe compares all accepted body fields AND Full populated input UTXO context
against the local check. Exact SPK version0, amounts, no covenant and noncoinbase
are mandatory; all input SPKs are queried before any spentness claim.
`block_daa_score` in a precomputed local context can be zero for future outputs;
it is not part of the signed transaction or these policies. The actual accepted
input block score is retained separately and is not claimed to equal a prediction.

Returned fields:

```text
transaction_id, accepted_body, accepted_body_sha256,
accepted_input_contexts[], accepting_block_header,
observed_sink, virtual_daa_score, start_hash, final_cursor,
confirmation_policy{min_confirmation_count,comparison,accepting_blue_score,
 sink_blue_score,actual_blue_score_distance,passes:true,immutable_finality:false},
current_outputs[{index,outpoint,amount_sompi,script_public_key,utxo}],
spent_inputs[{outpoint,script_public_key,queried:true,unspent:false}],
chain_delta_removed:[], pages[{start_hash,response:<raw FullV2>}],
utxo_query_started_at, observed_at, network, expected_genesis,
trust:"VALIDATING_NODE_AND_PUBLIC_ARCHIVE_ORACLE", server
```

`utxo` and `accepted_input_contexts` entries:
`{outpoint,amount_sompi,script_public_key,block_daa_score,is_coinbase,covenant_id}`.
`accepted_body_sha256=SHA256(JSON.stringify(accepted_body))` with the emitted
canonical field order. Save the accepted body in that order; archive outer
pretty-printing does not alter this canonical inner hash.

Policy means **sinkBlueScore−acceptingHeader.blueScore >20**, at least21;
it is not elapsed time, DAA depth or permanent finality. The accepting header
must equal its FullV2 added hash and currently be a chain block. A second delta
is checked after the UTXO view; any removed hashes invalidate the observation.
Successive observations may have different advancing sink hashes. These RPC
views are not atomic. Terminal refresh must observe both exact payouts and
prove terminal input absent; absence of a reserve address balance alone is not
terminal accounting.

## Once-only submission

Extra request: `trial_dir`, `release_path`, `release_sha256`.
Release JSON (root explicitly supplies it only after all six local validations):

```text
authorization:"TN10_FRESH_TRIAL_REHEARSAL",
profile_sha256, network:"testnet-10", genesis, rpc_url,
allowed_stages:[the six stages], adapter_sha256, native_safe_sha256,
native_binary_sha256,
bodies:{stage:{transaction_id,body_sha256,local_check_sha256}, ...}
```

The release binds exact unchanged six bodies/receipts, adapter/helper/ELF,
public identity and endpoint. Live exact input outpoints/amounts/SPKs are checked
before sending. Exclusive per-stage and per-txid intent files are fsynced before
the only submission. They survive process failure and prevent rebroadcast under
a different stage. `RPC_ACK_ONLY` is admission, not payout confirmation.
`RECONCILE_READ_ONLY` means an ambiguous result: continue observe, never submit
again within that trial. A new trial has a fresh identity, not weaker checks.
