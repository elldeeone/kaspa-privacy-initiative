# Native public admission extension

**Status:** proposed bounded extension for root and independent adversarial
review; no admission runtime, setup or proof is authorized by this file.
Baseline `0c2f4c788a4274b381c4838e05cce5e9c32e8536` and
[ADR-0041](../../../docs/adr/0041-new-format-private-native-integration.md).
The [core contract](NOTE-STATE-CONTRACT.md) and selected
[Invoice V2 supplement](INVOICE-V2-CONTRACT.md) remain separate. All credentials
and UTXOs in this offline experiment are public synthetic DO_NOT_FUND material.

## 1. Selected minimal operation to review

One signed ordinary funding input creates **one positive public-ingress note**
and its encrypted delivery record in the existing new-format reserve. No
Groth16 verification, private input, private payout, pool-key signature or
operator permission is used. The pool input is not a free source of fees.

```text
input0: current reserve R under the exact immutable union/state
input1: ordinary P2PK funding E, signed by its owner with exact SIG_HASH_ALL
output0: same immutable union, one appended CM, value R' = R + V
output1: optional change C, same exact SPK as input1
E = V + f + C; native transaction fee = f
```

Funding ownership and note ownership may differ. The receiver's native PK in
Note168 need not equal the funding PK. Sending public descriptor fields does
not reveal receiver s/k/native secret. Only the funding owner can authorize
the particular public note, delivery bytes, fee and change through input1's
signature. Existing reserve principal and its current NF state are preserved.

All integers use canonical unsigned little endian. Enforce:

```text
60M <= R <= MAX; 60M <= V <= MAX; 1 <= f <= MAX; 0 <= C <= MAX
1 <= E <= MAX; R + E <= MAX
E = V + f + C; R' = R + V <= MAX
```

Use the core profile MAX=2,870,000,000,000,000,000 sompi. Check each bound and
sum before narrowing; no overflow/wrap/saturating-subtraction interpretation.
C=0 means **exactly one output**, no zero-valued change. C>0 means exactly two
outputs with change value C. There is no silent change minimum: tiny positive
native change remains an actual cost/storage boundary, not a discarded credit.

## 2. Canonical payload and witnesses

ADMIT payload is exactly 1,344 bytes. Its distinct eight-byte magic selects
this branch; there is no caller-selectable bootstrap flag.

| Field | Offset / size |
| --- | --- |
| exact `b"KPX2AD01"` | 0 / 8 |
| selected D | 8 / 32 |
| public Note168 | 40 / 168 |
| CM | 208 / 32 |
| sealed receipt264 | 240 / 264 |
| SHA256(receipt264) | 504 / 32 |
| empty CM append path, depth16 | 536 / 512 |
| exact next State112 | 1048 / 112 |
| fee f | 1160 / 8 |
| change C | 1168 / 8 |
| genesis opening G, Note168 | 1176 / 168 |

Keep the common three-item pool witness and redeem offset199: sig65 and
proof128 are both exactly zero on input0, followed by the actual full union
redeem. No fake proof acceptance or proof API call is involved. Input1 uses
the ordinary canonical 66-byte scriptSig `push65 || Schnorr64 || 0x01`.

Native checks exact transaction version1, input0 index0, two inputs, subnet/
locktime/gas defaults, canonical lengths and no trailing payload. Both inputs
have sequence u64::MAX, are noncoinbase and have no covenant ID. Input1 SPK
encoding is exactly version0 P2PK: `00 00 || OpData32 || key32 || OpCheckSig`
(36 bytes including SPK version). Input1 scriptSig has the exact push/length
and ALL byte; **official native validation of input1** verifies the Schnorr
signature. Inspecting its last byte alone is not signature validation.

Every output has ordinary metadata with no authorizing-input/covenant shortcut.
Output0 must hash to the complete current immutable union body with **only**
the allowed next state substituted. Preserve D, private VK, all branch bytes,
profile/version and policy constants exactly; do not trust a supplied new SPK.
If C>0, output1 has exactly input1's SPK. No extra receiver/fee/refund output,
arbitrary change destination or privileged reserve withdrawal is allowed.

The input1 ALL signature binds native outpoints, amounts, outputs and payload
according to the pinned native API. V1 compute budget is excluded from that
signature: actual compute/storage/transient/mass checks and fee quotes remain
mandatory. A budget change does not authorize a larger fee or different output.

## 3. Commitment, delivery and state update

Recompute CM from the public Note168 using the unchanged exact core tag/D/
field order. V must be positive and at least60M; hash-only hidden-value ingress
is **not** this operation. Native code checks fixed field widths and exact
ciphertext length/hash; it does not decrypt or validate hidden receipt framing.
Receiver/library checks validate its rederived native key and receipt encoding.
Receiver acceptance still rederives the invoice from its
pre-payment backup; native hashing does not prove that a recipient owns K/PK
or that a sealed ciphertext correctly encrypts this note.

Invoice V2's note incoming is opaque per-invoice bytes. Do not interpret it as
the delivery key. Publish only Note168 and the sealed receipt; never publish
the full Invoice208 or its stable deliveryPK in ADMIT or genesis data.
Receipt216 contains the invoice index and Note168 and is sealed to the separate
deliveryPK. Hashing authenticates the exact 264 bytes; successful local
decryption/rederivation/CM comparison remains a separate I-14 acceptance gate.

From the executing input0 redeem, authenticate State112/D and current n/m/roots.
Require `1 <= n <= 65,534`, `1 <= m <= 2n+1`. The supplied depth16 path must
authenticate the **empty CM leaf** at index n against the old CM root. Reuse
that same index/path with the new **raw CM** leaf to derive the new root.
No independent new-root path is accepted. Next State112 is exactly:

```text
same b"KPX2ST01", same D, CMroot=new root, n'=n+1,
NFroot'=old NFroot, m'=old m
```

No NF insertion, marker clearing, history-root namespace or old even-count rule
is introduced. D is unchanged:
`9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c`.
All nonempty current roots/counts must belong to the selected authenticated
lineage; a supplied root is not self-authenticating protocol history.

## 4. Initialization and evidence boundary

The minimal public test trace is **funding → coherent singleton founding →
first native ADMIT → initialized two-note state**. It uses no old S7 artifacts
and implements no ledger-replay/owner/withdrawal workflow.

1. Select a public genesis note G0 under this D, value R0>=60M, with an owned
   receiver-issued descriptor/receipt. Independently derive its raw-CM singleton
   root (leaf0; all other leaves empty) and sentinel-only NF root. Set n=m=1.
2. An ordinary ALL-signed P2PK funding transaction creates output0 value R0 at
   that exact union State112/SPK, with any separately funded ordinary change.
   Retain its complete body, actual raw output outpoint, public input context,
   G0 and bound encrypted receipt. Validate the funding signature/native body
   using official Full; independently compare output amount/state/script to G0.
   Output creation does not execute its new covenant or prove this comparison.
3. First ADMIT spends that output as input0 and a separate signed funding input1.
   If the **executing old state has n=1 and m=1**, native ADMIT requires G in its
   payload to be a valid positive Note168, G.V==actual R, and recomputes the exact
   singleton root against old CMroot plus the fixed sentinel-only NFroot. No
   arbitrary supplied sibling path is used for the singleton check. This
   establishes local exact initial note backing before accepting this append.
4. For every other old n/m, all168 G bytes must be zero. The previous initialized
   lineage supplies the inductive premise; merely setting a payload flag cannot
   request bootstrap treatment. The first ADMIT gives n=2,m=1 and reserve
   R0+V, exactly the two positive note liabilities. Subsequent core private/
   reveal operations retain their own separately reviewed contracts.

**Canonical genesis and accepted current head remain external inputs.** Multiple
separately funded outputs may share D/script fields; hash coherence cannot
identify which one is the protocol's founding outpoint. The experiment must pin
the chosen genesis outpoint and ordered current lineage via an explicitly
authenticated-record/accepted-state oracle. Real chain acceptance, resolved
funding ancestry, confirmation/reorg and durable publication are not established
by supplied UTXO Full validation. A fake later root may satisfy local script
checks but is rejected by that lineage oracle, not magically detected by native
hashing. A standalone test beginning at n>1 is labeled **declared synthetic
input**, never an initialized/accepted backing result.

The first-ADMIT coherence guard does not retroactively qualify an earlier direct
private/reveal spend of an arbitrary supplied initial context. The integrated
trace requires its selected coherent funding/founding prefix. No general native
creation-validation primitive, ancestry proof or fundable genesis is claimed.

## 5. Backing, capacity, cost and required controls

Under complete prior `R=L`, ADMIT adds V to both reserve and note liability;
the external funding owner alone pays f/change. There is no rent, pending claim,
refundable pool credit or donation merge. The capacity ghost counts C/U both
increase by one, m stays fixed, n grows, so the core `m+2U<=2n+1` proof remains.
This does not remove an old supported credit or excuse a malformed delivery
from liability accounting.

Before runtime, freeze at least coherent initial ADMIT and later initialized
ADMIT, C=0/C>0, distinct funding/receiver keys and an n-capacity boundary. Require
exact semantic rejections for:

- wrong D/header/length, recomputed-CM mismatch, ciphertext/hash mismatch,
  append index/sibling/nonempty slot;
- changed NFroot/m, count overflow, wrong state/version/VK/policy/output SPK;
- V=0/floor−1/MAX+1, f=0, wrong E or output amount, subtraction/addition overflow;
- extra/zero-valued/misdirected change, wrong input count/type/metadata;
- genuinely valid weak-type signature, corrupt funding signature and wrong key;
- missing/wrong singleton G, nonempty initial NFroot, G.V!=R, or nonzero G later;
- copied-state/noncanonical genesis under the **separate lineage oracle**.

Malformed receipt encryption may pass the native byte/hash checks but must fail
strict receiver credit. Retain that explicit distinction and all positive
liabilities. Native authorization, receiver usability and accepted lineage are
different verdict layers.

Measure the actual full union including this inactive branch on PRIVATE and
REVEAL as well as ADMIT. Include both input witnesses/budgets, optional change,
all payload bytes, output metadata and KIP9 storage. Freeze actual signed fees
and quote at100/200/500; same-owner change is not a subsidy. Tiny change may
fail economic/storage screens. No result inherits the prior32KiB NOP allowance.

Removing the admission verifier is a fee opportunity, not complete R8 success.
One direct Groth16 ordinary transfer still has its147,500-mass verifier floor.
Two genuinely useful recipient payments with no change are a distinct favorable
case; ordinary recipient-plus-change is one payment. Count funding/founding,
admission, every payment/change/exit, retries and per-user shares separately.

## Source reuse

The funding SPK/scriptSig/ALL/amount checks adapt existing public
[`two_input/covenant.rs`](../../../poc/shared-pool/src/two_input/covenant.rs)
admission guards; its Groth16 ADMIT relation is **not** imported as a fee.
[`native.rs`](../../../poc/shared-pool/src/native.rs) supplies the existing
ordinary funding/signature/mass seam. Commitment/Merkle semantics come from
the frozen public [candidate-C source](../../../poc/future-exit-feasibility/src/main.rs)
and new core contract; do not substitute old v6 CM-leaf framing. Pinned native
`01b532e8b553523216471682649693af92f0fd16` supplies actual transaction
introspection, SHA256, Schnorr and signature hashing.
[Primary-source gate](PRIMARY-SOURCES.md),
[complete backing limits](../exit-fee/BACKING-AND-TAILS.md).

This is a simple native composition of existing primitives, not audited code,
accepted backing, privacy qualification, funded deployment or a new primitive.
Root plus one independent adversarial review selects this extension before
implementation/source/runtime freeze. No ADMIT setup or private proof is needed.
