# Settlement adapter source qualification, 2026-10-28

This records source inspection and public controls, not a successful live
financial observation. The actual outer profile remains `selected:false`.
No node acquisition, funding, broadcast or journal resolution was performed
for this qualification. Historical control manifests are retained unchanged.

The implemented financial path is transition-relative: the immutable locked
ticket must already bind an independently admitted head and backing. Native
Full on a GEN3 producer alone does not establish genuine Output proofs,
contributions or commitment/value admission. The wallet's actual GEN3 verifier
and accepted-history admission remain required before financial intake.

## Actual checks traced through maintained source

1. `launch.py` authenticates the fixed adapter selection, source/tool closure,
   selected component manifest, outer image, native parameters and request.
   Private exclusions are metadata-only; the readonly public namespace contains
   no original private filesystem. Only acquisition shares network access.
2. `protocol.py` version2 binds the complete CASE, including witness, budget,
   storage mass and all supplied entries. It joins actual split state, old
   outpoint/reserve/script, full NF256 values, core/proof/projection hashes,
   immutable tail and final image/journal/native-proof identities. Native
   parameter selection means the raw parameter artifact hash, never a host flag.
3. `acquire.mjs` uses generic current chain APIs, with no old financial profile
   or old GN3 decoder. It obtains a fresh finite confirmed accepted prefix and
   the accepted locked-head producer, then follows the exact new payment/Exit
   graph. Producer and transition accepting blocks cannot move backward;
   dependent transactions may share one accepting block.
4. `chain/wire.mjs` rebuilds every complete header with cached hash cleared and
   invokes the pinned official SDK `Header.finalize`. It reconstructs each Full
   transaction with all populated input contexts, invokes `Transaction.finalize`
   and compares the entire canonical body. JS wide integers remain decimal
   strings until conversion to exact Python integers for native CASE replay.
5. `private-batch-public/native/src/main.rs::body` constructs the actual selected
   redeem and P2SH script. It checks split old/new state, exact consumed point,
   reserve, integer fee/conservation, output layout, state counts, immutable
   successor, computed storage mass and recomputed ID. It emits the real
   projection/journal; this codec does not confer proof acceptance.
6. `private-batch-public/host` runs `evaluate` and independent Arkworks
   `evaluate_reference`: aggregate plus six genuine Output Groth16 proofs,
   state transition and commitment balance. These are directly spawned selected
   executable calls, not imported reports.
7. Host `native-proof` forbids development mode, verifies the selected image
   with `VerifierContext.dev_mode(false)`, exact104-byte journal and empty
   assumptions, requires a genuine Groth16 receipt and emits canonical128 bytes.
   The adapter explicitly checks its image/journal/proof report and emitted
   journal, then matches the full128 bytes to the accepted CASE witness and
   durable final-candidate digest.
8. The selected generic native runner actually calls `TransactionValidator`
   with `TxValidationFlags::Full` and executes every input `TxScriptEngine`.
   The adapter checks those immediately generated results for the producer and
   every accepted successor. The payment fee must equal the real codec result.
9. Retained Full pages are independently rebuilt and checked for missing or
   duplicate pages/blocks, removals, missing predecessor/frontier/producer,
   changed complete header, SDK transaction/body mismatch and graph conflict.
   Exact current UTXO queries, consumed-input absence, a confirmed post-query
   delta, selected-chain anchor checks and an identical second query bound race
   and reorg observation. They do not claim atomic or continuous currentness.
10. Only the outer direct preflight/acquire/verify sequence can write final
    `SETTLEMENT.json` and emit `KPB_SETTLEMENT_VERIFIED_V1`. Offline/inner paths
    export evidence only. Selected original bytes are reauthenticated, all fresh
    public evidence files/directories and parent directory are synchronized,
    and traversal/write/sync uncertainty refuses export. The history owner must
    consume the fresh fixed line directly; it cannot import a result Boolean.

## Primary source identities inspected

Paths below are relative to `continuation/poc/` unless otherwise stated. These
pins identify the inspected source; the fixed selector must separately select
the corresponding qualified executable and complete runtime/source closure.

| Source | SHA256 |
| --- | --- |
| `local-private-payment/chain/wire.mjs` | `0dbcf847cbf3e7ef16ca2d6b3428eac227fe09023d95aa795ac18e98b399277c` |
| `local-private-payment/private-batch-public/native/src/main.rs` | `1c941a3fb529465549eab5ab16286098a216ed91db0e6a223b73557d51fa5939` |
| `local-private-payment/private-batch-public/native/src/policy.rs` | `920dfe2aa42faf78bdf6a16b11077a37d0b6ce4d6b201ec0e2ca63a444d94592` |
| `local-private-payment/private-batch-public/common/src/lib.rs` | `f49548358d4cd02949843f5c3677074773a9a427a49dc8c24953cd6afa90674c` |
| `local-private-payment/private-batch-public/host/src/main.rs` | `39cb542861fa585bee15d0b19fbcc711c7b33e814dd7a521679bc475f07cc743` |
| `local-private-payment/private-batch-public/host/src/receipt_checks.rs` | `0af26ef2d5f2815f43fde882ec6729a8a863a2f4771381c9edc8b6cdfa1ce7bb` |
| `local-private-payment/private-batch-public/host/src/native_proof.rs` | `53da4c819fa0a1801c0f00ef76e0a15acf98dc6ec348c16ea4cab889dcc0ce7b` |
| `private-exit-native/src/main.rs` | `73196654305d6c755232a583561df71fb46700db15e7c3fca642f49ea649bb13` |
| `private-exit-native/src/native.rs` | `0a5a535b6baaa86e719d0becacf611129da7a825e3190f632baa9b0cf58f7857` |

The official SDK is
`/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa`:
`kaspa.js` SHA `6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf`,
`kaspa_bg.wasm` SHA `c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5`.
The inspected JS `Header.finalize` and `Transaction.finalize` call the actual
WASM finalizers; these are not locally invented hash codecs.

The independent reviewer traced actual Full accepted-prefix semantics in the
retained upstream checkout
`/home/luke/projects/kpi-intensive-2026-10-22/native-claim-target/cargo-home/git/checkouts/rusty-kaspa-410e06d1fde91a92/01b532e`:

| Upstream source | SHA256 |
| --- | --- |
| `rpc/service/src/service.rs` | `1bd23aedce198ce3f7d4731c37008e98ad7d7ef7119361a25572b94c157ac33d` |
| `rpc/service/src/converter/consensus.rs` | `41a57123b5c616dc2cf724a6c2316a07ad5582a5351f675fb7f6bd6e39fcadbe` |
| `rpc/core/src/convert/verbosity.rs` | `857fa8b698634f0661701b44868df3645b47360fb9a9a0f7451c08f305c3f055` |
| `consensus/src/pipeline/virtual_processor/utxo_inquirer.rs` | `42182c9c8799a95a7f1ef7e730adb882416cfcd9be5e3d7c71bf9c5979a6d690` |

The service obtains the actual selected chain path, applies strict accepting
blue-score distance greater than20, and reads consensus acceptance data. Full
conversion includes populated UTXO contexts. Dependencies can be created and
spent within one accepting block, which is why raw transaction-index order is
not required by the adapter.

## Independent review and controls

Independent reviewer `accepted_prefix_review` inspected acquisition, upstream
RPC/SDK semantics, whole launcher/protocol, actual host/receipt/native source,
direct provenance and filesystem/descriptor boundary. Findings about accepting
block chronology and fail-closed complete evidence synchronization were fixed.
Final v2 policy-pin review is recorded in the accompanying qualification
manifest with exact candidate source hashes.

Public controls:17 Python encoding/policy/version/namespace/durability controls
and10 retained-page controls with the pinned official SDK header hash. Dummy
proofs and synthetic non-PoW headers are deliberate; these controls are not
genuine financial or accepted-chain observations.

The C++ launcher contract uses admitted source bytes in a sealed memfd and the
admitted interpreter descriptor. It compiles those bytes with the frozen
canonical original source path and explicit `__file__`, preserving selected
relative imports. Stdin is `/dev/null`; only stdout/stderr, source and interpreter
descriptors survive. All inherited private/MPC/journal descriptors are closed.
The request is internally constructed from immutable durable history records,
not supplied by a caller. All three servers independently acquire and replay
the selected path before durable settlement agreement. C++ capability/journal
implementation and its source review belong to the history owner.

## Remaining actual integration

- Freeze and independently register the complete selected adapter/tool/runtime
  closure; current outer selection stays false until authorized qualification.
- Qualify the exact selected profile with genuine aggregate/Output/R0 witness
  and actual accepted whole CASE through this fresh live path.
- Exercise actual C++ direct-launch/capability/all-three agreement and guarded
  journal settlement, then the second disjoint private round.
- Independently admit GEN3 backing and the complete accepted wallet history.

Trust remains a selected honest validating-node finite-prefix observation.
The adapter does not independently prove PoW, GHOSTDAG or accepted-ID inclusion;
a dishonest selected node can fabricate acceptance under a stronger adversary.
Later reorgs remain possible, and permanent NF tombstones survive them.
No source review or passing control proves cryptographic correctness, unrestricted
privacy, financial readiness, mainnet safety or a completed native payment trial.
