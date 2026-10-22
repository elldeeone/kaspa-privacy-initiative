# Public receipt native predicate check

This offline harness passes a public RISC0 receipt through the actual Kaspa
`TxScriptEngine` and `OpZkPrecompile`. It does not invoke `Receipt::verify` or a
RISC0 SDK verifier as a substitute for native verification.

The paired statement is compiled into the binary:

- Guest image: `50ceec8ebb91edd01028c4aec9b495e7d77eb9e3b39e065910c0600f7693d832`.
- Exact 42-byte journal: `pins/expected-journal.bin`, SHA256
  `5d667b709f35191c6fc98e6aa0b79bd934e39a40ef4edfea582fcef3b06d4ac7`.
- Wrapped program SHA256:
  `fa367c2d887a1a86ce23919f664af46dc418db0a2c79c2c62040c1526e8354cf`.
- Native Kaspa revision: `01b532e8b553523216471682649693af92f0fd16`.
- `0x21`: expected JOIN control
  `7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e`.
- `0x20`: the official SDK 3.0.3 default Groth16 wrapper key, control root,
  and BN254 control ID; five public inputs. These are fixed source parameters,
  never a key or expected claim supplied by the receipt.

For `0x21`, the native journal argument is SHA256 of the complete J42 above.
The inner hash contained inside J42 is a different value. For `0x20`, the
official `ReceiptClaim::ok` creates the successful, assumption-free claim from
the expected image and complete J42; the native precompile verifies the proof
against the fixed key and corresponding five scalar inputs.

## Run

Use a private target directory and a resource-limited shell or service. Dependencies
are isolated to this crate; the lockfile records the graph. Proving, client, CUDA,
network, and transaction-broadcast features are absent.

```sh
CARGO_TARGET_DIR=/tmp/public-receipt-native-check-target cargo build --locked --manifest-path poc/public-receipt-native-check/Cargo.toml
/tmp/public-receipt-native-check-target/debug/kpi-public-receipt-native-check verify-succinct PUBLIC_RECEIPT NEW_OUTPUT_DIR
/tmp/public-receipt-native-check-target/debug/kpi-public-receipt-native-check verify-groth16 PUBLIC_GROTH16_RECEIPT NEW_OUTPUT_DIR
```

The output directory must not already exist. Results preserve the input receipt
hash, checker binary hash, immutable expectations, native script bytes/hash, script-unit use, elapsed
time, and exact native errors. A failed expectation exits nonzero and preserves
the report. Groth16 output also preserves the checked 128-byte compressed proof,
424-byte fixed key, and five 32-byte little-endian scalar inputs.

Each mode executes a genuine positive first, followed by changed expected image,
journal, and control plus seal/proof integrity and encoding controls. Succinct
also checks altered inclusion path/index and claim. Groth16 checks trailing
proof/key bytes. Resource/setup errors do not qualify as negative evidence.

`qualify-historical-succinct` accepts only the exact retained public native-value
receipt SHA256
`3097795146ed147c2b4c3710b6ad4bcb52291a4ec65c473bdb92aaae0480ab2a`.
Its separate compiled 352-byte journal, image `52c214c2…dcc6cf0`, and official
`lift_rv32im_v2_20.zkr` control qualify the harness. That mode cannot establish
anything about the new paired guest or receipt.

## Reused sources and limits

Witness extraction, checked point conversion, fixed-key conversion, scalar order,
and script stack mapping follow existing sources:

- [vProgs witness extraction](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/api/src/witness.rs)
  and [covenant parameters](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/build.rs),
  adapted with fallible checked decoding; see `NOTICE`.
- [Existing covenant statement mapping](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/script.rs).
- Native [RISC0 predicate](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/risc0/mod.rs)
  and [Groth16 predicate](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs).

The SDK parses the receipt and supplies the official claim/parameter definitions.
Native `0x21` independently verifies the seal and successful expected claim;
native `0x20` independently verifies the Arkworks proof. Groth16 retains the
official RISC0 setup trust. There is no new cryptographic construction.

This is a **bare opcode predicate**, with an unlimited standalone script-unit
meter, rather than a transaction or reserve covenant. It does not establish KAS
backing, authorization, nullifiers, replay prevention, exit policy, settlement
admissibility, relay fees, or privacy. Script bytes, script units rounded to grams,
and the minimum committed budget covering this bare predicate are reported
separately. The budget bound uses the native rule `limit = budget*10000 + 9999`;
none of these is complete transaction mass. No UTXO, selected chain, node,
testnet, real funds, or network is involved.
Passing these controls is implementation evidence, not an audit or a proof of
cryptographic correctness.

## Retained local result

The new paired receipt SHA256
`51a2f69e9986179696141ef106401109a3c7bf58fe87c8b0a645e29c49c4a3ec`
passed actual native `0x21` plus all eight declared negative controls. See
`evidence/paired-succinct/report.json`, its service log, and `run-metadata.json`.
Positive: 223,075 script bytes, 222,668 seal bytes, 25,000,001 script units;
bare covering budget 2,500. The 42-byte journal and compiled expected image/control
were fixed before invocation, as recorded in `evidence/harness-freeze.json`.

The same claim's 581-byte compressed receipt SHA256
`7ace0642e77fadacf9bc704e7500a97f2c8ea6a0b81a043ae5049eefbd1b97ff`
also passed actual native `0x20` and all seven declared negatives; see
`evidence/paired-groth16/`. Checked point conversion produced a 128-byte native
proof under the fixed 424-byte key. Positive: 728 script bytes and 15,500,001
script units, with bare covering budget 1,550. The checker binary and expected
statement are identical between both modes. The official setup trust remains.

The separately labeled `evidence/historical-final/` passes the older exact
public fixture. These results establish native predicate compatibility;
transaction settlement and anonymity remain untested.

`scripts/compare-native-costs.py SUCCINCT_REPORT GROTH16_REPORT DIRECT_1600_REPORT NEW_JSON`
checks the retained reports and artifact hashes and computes bounded resource
deltas. `evidence/native-cost-comparison.json` compares these actual predicates
with the separately measured direct budget-1,600 matrix. It includes compute
bytes when modeling a literal flat-script embedding, and leaves complete
aggregate mass and fee savings unknown. Its 2/4/8/16-operation ranges are
arithmetic sensitivities, not executed aggregate transactions.

Service metadata distinguishes verified launch caps, actual journal events,
and unavailable post-GC properties. The short `0x20` service emitted no peak
resource event; its peak memory is unknown. Native case timings are single
observations from a debug build, not stable performance benchmarks.
