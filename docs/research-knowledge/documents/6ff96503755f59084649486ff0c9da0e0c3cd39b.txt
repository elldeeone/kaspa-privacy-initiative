# Integrated owner-private verification and native exit

ADR0064 selects a new TN10 research domain. Existing ADR0063 P0 and earlier
funded profiles are unchanged. The selected component profile pins fresh Spend,
Output and Exit verification keys before guest compilation. The final native
policy pins that component hash, the resulting RISC Zero image and the Exit VK.
A valid host report never substitutes for a proof or native validation.

## Mixed rounds

The fixed mixed frame retains three Spend proofs and six complete 520-byte
Output tuples, without creator/output partitions or individual balance
blindings. Its 10,780-byte body and 193-byte native projection prefix use KPX8
tags and the selected new domain. Current CM membership, indexed-NF insertion,
CM appends, value ranges, public fee and the global commitment balance remain
mandatory. The real guest verifies every component proof before committing the
104-byte journal. Native policy reconstructs the actual complete projection
and accepts a genuine RISC Zero proof for its pinned image/journal only.

## Independent full-note exit

Direct Exit uses a distinct fixed 1,632-byte body and one genuine 128-byte
Groth16 proof in the input witness. It needs no MPC or shared RISC Zero prover.
The owner still needs authenticated public history, software and the complete
selected Exit proving key, and may produce the proof using replacement
infrastructure. This is an availability requirement, not an administrator path.

| Body offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 16 | `KPX8XB01`, u16LE version 1 / spends 1 / outputs 0 / mode 1 |
| 16 | 32 | Selected domain |
| 48 | 32 | Nonzero fresh session |
| 80 | 32 | Reserved zero; no public owner roster |
| 112 | 36 | Actual previous transaction/outpoint |
| 148 | 112 | Complete old state |
| 260 | 8 | Actual input reserve, integer sompi |
| 268 | 112 | Complete next state |
| 380 | 8 | Remaining reserve |
| 388 | 8 | Exact native fee |
| 396 | 8 | Payout |
| 404 | 36 | Exact canonical native P2PK payout script |
| 440 | 32 | Original positioned note nullifier |
| 472 | 1,160 | Authenticated indexed-NF insertion witness |

Payout SPK is `0000 | 20 | x-only-key32 | ac`, exactly 36 bytes. Positive remaining
reserve has exactly two outputs: a same-tail state successor then the payout.
Zero remaining reserve has exactly one payout and no reserve successor.
Output covenant metadata must be absent; input covenant identity must be null.
All header, input context, predecessor state/point, amounts and output layouts
are checked by the native script. CM root/count remain unchanged, NF count
increments once and the script computes the exact new NF root from the current
root through the established predecessor-replacement/empty-append algorithm.

The exact native projection prefix is 240 bytes for a continuing exit and 192
bytes for a terminal exit. `effects=SHA256(KPX8EF01|prefix|completeExitBody)`.
Exit152 is `KPX8EX01|D32|oldCMroot32|NF32|effects32|payoutLE8|feeLE8`.
Its proof establishes hidden note membership/ownership, the stable original NF,
range bounds and exact unsigned `note.value=payout+fee`. Native reconstruction
binds those effects to the actual transaction; no note opening, note position,
native authority key or per-owner balance opening is published.

## Implementations and evidence

`wire.py` and Rust `common/src/wire.rs` independently parse the public frames
and compute authenticated root updates. The Python helpers do not verify a
financial proof. `host exit-check` verifies direct Exit with the accelerated
standard pairing equation and an independent Arkworks reference. Actual
`Native Full` and individual input-script validation are separate checks.

The public native codec emits bytes and canonicalizes legitimate body shapes;
it performs no proof verification, RPC, funding or broadcast. The test-only
control codec uses pinned upstream Transaction methods to canonicalize malformed
fixtures without weakening the production codec. The native engine uses the
same exact upstream revision as the previous selected evidence.

Early direct-Exit fixtures deliberately use publicly known test keys and
supplied UTXO contexts. They demonstrate the native branch and strict rejection
of changed effects/state/metadata, not actual backing or accepted currentness.
They use declared synthetic image/component identities, distinct from the
selected lifecycle tail. The complete selected-tail local rehearsal and actual
TN10 confirmation remain separate required integration gates.
