# Native predecessor byte order

Source baseline: rusty-kaspa
`01b532e8b553523216471682649693af92f0fd16`. This is a source check, not a
new native execution or an authentication of a supplied predecessor tuple.

The J336 predecessor must be exactly
`transaction_id.as_bytes()[32] || index.to_le_bytes()[4]`.

1. `crypto/txscript/src/opcodes/mod.rs:1046–1052` implements
   `OpOutpointTxId` by pushing `input.previous_outpoint.transaction_id.as_bytes()`
   directly. `OpOutpointIndex` pushes the numeric index; a journal's fixed
   four-byte index encoding is a separate explicit u32 little-endian encoding.
2. `crypto/hashes/src/lib.rs:78–79` returns the inner array from `as_bytes`.
   `Display` at line142 hex-encodes that same array; `FromStr` at line157
   hex-decodes directly. No reversal occurs between these native forms.
3. `consensus/core/src/hashing/tx.rs:118–119` writes an outpoint as raw hash
   bytes followed by `index.to_le_bytes()`.
4. V1 transaction ID derivation at lines207–217 uses the domain-separated
   keyed-BLAKE3 `PayloadDigest`, `TransactionRest` and `TransactionV1Id`
   hashers. It is not SHA-256 of Borsh bytes or the complete transaction hash.
   `transaction_v1_rest_preimage` excludes payload, signatures and mass; the
   payload digest is separately bound. `crypto/hashes/src/hashers.rs:120–149`
   defines the zero-padded ASCII keyed-BLAKE3 domains.

| Pinned upstream source | SHA-256 |
| --- | --- |
| `crypto/hashes/src/lib.rs` | `c24b8a276edd0defcf6c22f46a7bae289bb59c9639eee6dde4fe46657484b5d3` |
| `crypto/hashes/src/hashers.rs` | `752f6e6353b1316732e3141c8ac8a92094be70314e47ea83bb6dd68d5ca951c5` |
| `crypto/txscript/src/opcodes/mod.rs` | `201d69b5a8de3db27b94b3e850a7ee62c4920532886c1d19544baed7fd163731` |
| `consensus/core/src/hashing/tx.rs` | `965772f8daf6a941625c1c3b4601c1ee2dc4031d402bae98339064113c0ac5f1` |

The previous repeated-0x55 synthetic ID could not expose a reversal. The fresh
ADMIT ID must be nonpalindromic and the supplied raw36 tuple must match the
actual selected ADMIT body/ID/output. Independent native Full validation is
the source of the native-validity claim; this math oracle does not parse or
replay a ledger. Actual tuple/body comparison was pending at the initial source
freeze; the later public-artifact check follows below. No new parser, owner
workflow or hash substitute is introduced.

## Actual fixed public ADMIT ID recheck

The later `blake3-id-check-02/report.json`, SHA-256
`d2b167ae6665fb4022ddc3977b70687c877258570645519477f58aa978ff7ea1`,
independently reconstructs the **single fixed ADMIT JSON** rest preimage from
its public fields using the pinned source encoding. Its 220 bytes match the
official finalizer's supplied rest preimage. The public payload is 5,231 bytes.
Official portable C BLAKE3 recomputes the payload/rest/final ID digests and
matches the published raw32, display ID and exact raw36 tuple:

```text
ID:       c2fb1044efc0afd7c5d5c820813f67234b2734e497196424f9995876ecf6f0d7
outpoint: c2fb1044efc0afd7c5d5c820813f67234b2734e497196424f9995876ecf6f0d700000000
```

The ID differs from its byte reversal. The public JSON-body SHA-256 is
`41e155971863ef0475d6f2360efdaa545217a0318b14105c668cc5c632e012d1`;
this is explicitly the native JSON body file, not Borsh bytes or a transaction
full hash. The check hashes named public files only and authenticates no chain
context. Official Full validation remains separate evidence.

The C implementation is extracted only from cached official `blake3-1.8.7.crate`,
whose archive SHA-256 matches the existing lockfile checksum
`6d9e454fc11f76977dc803893aff6304ed33d6a26efae8696573bea74baa27ae`.
The report pins five C/header source hashes, compiler binary/version/flags,
wrapper and compiled-library hashes. It first checks the pinned upstream
`ZERO_PAYLOAD_DIGEST` known vector. Attempt 1 stopped before reading the ADMIT
files because my copied known-vector literal had a `cc`/`cd` transcription
typo. Its original source, log and expectation erratum are preserved under
`blake3-id-check/`; attempt 2 corrects only that literal to the exact upstream
constant. No public input or expected transaction ID was retuned.

The owned network-isolated unit used one CPU, 1 GiB hard RAM, zero swap and a
60-second deadline; it finished in displayed 719ms with 101.2M displayed peak
memory. Exact run metadata and journal are retained. Its process ID was not
captured before terminal unit collection; no PID identity claim is made.
