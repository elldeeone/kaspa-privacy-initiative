# NONFUNDABLE one-shot native state diagnostic

This separate local diagnostic tests the native transaction context around a
**new** state-aware outer claim. The successful J42 predicate remains unchanged
in `../public-receipt-native-check/` and cannot authorize this assertion.

Current status: **actual native input-script/context verification passed**.
The selected historical compressed receipt passed the positive and all 22
exact-error rejection controls. The [report](evidence/historical-state-native-01/report.json)
and [claim preimages/scalar mapping](evidence/historical-state-native-01/claim-boundary.json)
are retained separately from the earlier source-only evidence.
The coordinator independently selected image
`e9d7bd51e12b253c5cb7839d6854cf30d387dea95aff4e853feb47eb6d0edcf9`,
wrapped-program SHA256
`d1336290bd4b8555edea9c5d7dd56aa4883f1d185b0a4aca9b08105b0537097a`,
and the historical-anchor J336 SHA256
`457a9c09edd5840a978f8b785e165af3656c77f579b43ff322a9b3548a88c3f3`.
This is the n=5 to9 context with the genuine count3 anchor, literal synthetic
predecessor `55…55`/index2 and R1.7B to1.62B sompi. The genuine 1,169-byte compressed receipt SHA256 is
`e01de2650193181f96f40a985f6d321bc21bae7eb01805194b40fb022b983a3b`;
its fixed claim is `2450e2c7e083e367887ec53f3449cd4d5d62b1575b94119479997cec8ff5aaf4`.

The prior None-image/zero-journal source and source-only binary are retained
separately in `evidence/source-only/archive-manifest.json`; they never supplied
a proof or native-positive result. `verify` rejects incomplete selections before
receipt I/O. `design-info` reports the current selection state.

This work follows the accepted synthetic scope in
[ADR-0035](/home/luke/projects/kpi-intensive-2026-10-22/integration/docs/adr/0035-synthetic-state-aware-assertion.md)
and [RFC-0018](/home/luke/projects/kpi-intensive-2026-10-22/integration/docs/rfc/0018-paired-native-settlement-experiment.md).
It creates no live pool, accepted predecessor, owner exit, fundable policy,
network connection or broadcast command.

## Exact boundary

- Journal: `KPI2V6S1 || u16le(1) || SHA256(P)[32] || poolID[32] || priorOutpoint[36] || S7prev[105] || S7next[105] || u64le(R) || u64le(R')`, exactly 336 bytes.
- Public payload: `KPI2V6T1 || u16le(1) || P[1088] || S7next[105]`, exactly 1,203 bytes. All four complete CM/ciphertext records remain available in P; no ciphertext is replaced by a digest.
- The pool ID is SHA256 of the exact ASCII `KPI/public-two-v6-state/DO-NOT-FUND/v1`, selected independently of any transaction containing the script.
- Previous redeem prefix: `<poolID32> DROP <S7prev105> DROP`, exactly 142 bytes; state starts at byte 36. Input witness: canonical 128-byte proof push (130 bytes), then canonical `PUSHDATA2 || u16le(redeemLength) || redeem`; redeem starts at byte 133. No witness selector or alternate branch exists.

The native engine first authenticates that redeem preimage against the supplied
input UTXO's P2SH locking script. Thus extracting S7prev from that exact executed
preimage is authenticated by the native input script, rather than by a host
success flag. The supplied UTXO itself remains synthetic, not chain evidence.

The immutable suffix requires the exact independently frozen synthetic predecessor
outpoint. It reconstructs the successor's P2SH hash using the same prefix/header,
payload S7next, and identical executed suffix. The successor therefore retains
the old one-shot outpoint guard: its real transaction ID differs from that guard
and it deliberately cannot continue as a reserve. No DRAIN or live continuation
is implemented. This is not an ownerless deployable pool.

## Native assertions

1. Exactly one input and output, current input 0, native version 1, zero subnet,
   gas and locktime, max sequence, noncoinbase input, no input covenant ID and
   no output authorizing-input metadata. Require canonical witness/payload/state
   framing and state discriminator 7.
2. Enforce the designated synthetic outpoint and reconstruct the exact successor
   P2SH script from the current authenticated immutable body, not host-selected
   policy or an output prefix alone.
3. Require P's u128 fee high eight bytes zero; canonicalize the lower eight
   bytes with native ScriptNum decoding/reencoding, require `0 < F <= MAX_SOMPI`,
   `0 < R,R' <= MAX_SOMPI`, and exact native amount difference `R-R'=F`.
   All values are integer sompi. The present public pair's fee stays 80,000,000.
4. Reconstruct J336 **on the native stack** from actual input outpoint, current
   authenticated prior state, complete actual P, proposed successor state,
   actual input UTXO amount and output amount. Reuse vProgs' official successful,
   assumption-free RISC0 receipt-claim mapping on that hash. Verify the new fixed
   image under the fixed official 424-byte outer Groth16 key and five public
   inputs through actual `OpZkPrecompile 0x20`.

SPK introspection is `version:u16be || script`, not transaction-wire LE. Native
outpoint IDs are raw 32-byte hash arrays. Native outpoint indices are ScriptNums;
eight-byte `NUM2BIN` followed by the first four bytes gives canonical u32 LE,
including high-bit indices. Amount introspection returns signed i64; the
MAX_SOMPI range fits i64, and checked positive values serialize to raw u64 LE
through eight-byte `NUM2BIN`. Negative-zero fee encodings cannot pass.

## Evidence contract

Runtime was released after the coordinator independently froze the new
image, J336, fixture, genuine compressed receipt and exact checker binary. There is no fake receipt,
skipped precompile or host-only positive mode. Expected image/J are compiled
pins, never selected by receipt metadata or CLI input. Proving features are off.

The declared controls cover outpoint/index, sequence/gas, extra input/output,
changed successor policy, coherently changed prior state/next state/amounts,
P bytes, unequal fee, u128 upper bytes, zero/overrange amounts, zero/negative-zero/
overrange fees, trailing payload and a canonical negated proof point. Native
errors must equal exact expected variants: generic integrity or resource errors
cannot pass. Coherent state/amount changes must reach the native pairing check.
No failed operational run or parser error closes a semantic gate.

The full native transaction is finalized, native-Borsh round-tripped and saved.
That serialization includes the cached native ID and is explicitly **not** a
P2P/RPC wire-size claim. Resource results use the actual native
`transaction_estimated_serialized_size` and `MassCalculator` contextual and
noncontextual APIs, including all witness/payload/output bytes and storage.
The native engine checks the input script and its transaction introspection;
`TransactionValidator`, relay policy, selected-chain membership, UTXO ancestry
and maturity are not tested by this diagnostic.
The frozen committed budget 1,600 covered the measured 15,514,686 units
(limit 16,009,999). The actual redeem length is 1,383 bytes; signature script
1,516; payload 1,203; native estimated whole transaction 2,920 bytes (native
Borsh artifact 2,910). Compute/mining/relay mass is 163,290, transient 11,680
and storage 29. All measured dimensions fit the pinned empty-block limits.
At scenario rates 100/200/500 sompi per gram the necessary quotes are
16,329,000 / 32,658,000 / 81,645,000 sompi. The unchanged 80M fee covers the
first two and **fails** the 500 scenario by 1,645,000. No fee was repriced.
The positive took 0.03986 seconds in one debug-build observation, not a
throughput benchmark. Launch caps were observed at 2 CPUs/2 GiB/zero swap;
no short-service resource event was retained, so peak memory is unknown.
The one-shot successor must differ from the pinned predecessor transaction ID.

Report the transaction's exact unchanged 80M-sompi fee separately from
rate-dependent necessary-fee scenarios. Lower mass cannot demonstrate an actual
fee reduction: the old authorizations cannot be repriced and their PK is gone.
It also does not qualify the 1% target for the retained 4/5-KAS payments or a
hypothetical pair of 10-KAS payments. Bare J42 cost bounds remain separate from
this full-context result and its data/publication assumptions.

## Source and limitations

`script.rs` adapts the established v6 P2SH successor construction and vProgs
`f9b84a8` claim/scalar mapping. `receipt.rs` reuses the already qualified checked
256-byte SDK-seal to 128-byte native-proof conversion and official fixed key.
See `NOTICE`. Native dependencies are fixed at Kaspa `01b532e`, SDK 3.0.3,
binfmt/zkp/Groth16 3.0.4 and recursion 4.0.4. No Merkle, privacy proof, hash or
claim primitive is invented here; state-transition validity belongs to the
independently reviewed new guest.

The initial reserve/nullifiers/history are declared synthetic context. This
does not establish genesis, accepted lineage, private liabilities, KAS backing,
chain acceptance, owner recovery, parameter availability, privacy or production
safety. The official outer setup and single-party inner development setup remain
trust assumptions. This diagnostic is **NONFUNDABLE even if every check passes**.
