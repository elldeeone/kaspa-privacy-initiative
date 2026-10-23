# Independent selected-HMAC design review

Status: **design ACK, subject to source review and measurement**. Static
review only; no source modification, synthesis, setup, key loading, proof,
native validation or trial was performed by this reviewer.

The proposed single selected HMAC is algebraically equivalent to the two
conditionally checked HMACs for a Boolean real/dummy selector. The manual
inner SHA-256 padding described below is correct. Keep this experiment in a
new package; the closed Ch/Maj experiment and active trial remain unchanged.

## Exact construction

For input slot `i` in `{0,1}`, let `r` be the existing constrained Boolean
real-input flag. Select through Boolean gadget operations:

```text
key  = r ? k       : dummy_key       # 32 bytes
tag  = r ? NF_TAG  : DUMMY_TAG       # 8 bytes
data = r ? CM     : dummy_seed      # 32 bytes
```

Keep the same constrained 32-byte domain `D`. Select the key before creating
its 64-byte zero-padded ipad and opad blocks. Both keys are exactly 32 bytes;
there is no long-key hashing branch and no change to RFC 2104 HMAC semantics.

The real message has 76 bytes:
`NF_TAG8 || D32 || CM32 || positionLE4`.
The dummy message has 73 bytes:
`DUMMY_TAG8 || D32 || dummy_seed32 || slotU8`.

Including the 64-byte ipad block, the inner SHA inputs are respectively 140
and 137 bytes. Their bit lengths are **1120 (`0x0460`)** and
**1096 (`0x0448`)**, encoded as eight-byte big-endian integers. Both require
exactly three 64-byte compression blocks after standard SHA padding.

| Inner padded block | Offsets within block | Bytes |
| --- | --- | --- |
| 0 | 0-63 | `(selected_key || zero32) XOR ipad64` |
| 1 | 0-7, 8-39, 40-63 | selected tag, domain, selected data first 24 bytes |
| 2 | 0-7 | selected data final 8 bytes |
| 2 | 8-11 | real: `positionLE4`; dummy: `[slot, 0x80, 0, 0]` |
| 2 | 12 | real: `0x80`; dummy: `0` |
| 2 | 13-55 | 43 constant zero bytes |
| 2 | 56-63 | real: `0000000000000460`; dummy: `0000000000000448` |

Thus the real final block is
`dataTail8 || positionLE4 || 80 || zero43 || bitLength8`, and the dummy final
block is `dataTail8 || slot || 80 || zero46 || bitLength8`. The proposed
offsets contain neither a missing byte nor an extra padding byte.

Initialize the standard SHA-256 IV, compress those three blocks through the
unchanged pinned compression function and serialize the resulting eight
state words in standard big-endian order. **Do not call `finalize` afterward**:
that would append a second SHA padding suffix and compute a different hash.
Then hash the ordinary 96-byte outer message
`(selected_key || zero32) XOR opad64 || innerDigest32` using standard SHA
finalization. The outer length is always 768 bits and needs two compressions.

Prefer a private or crate-private function with a fixed three-block input
type. A generic helper must reject empty/non-multiple-of-64 input and must
remain an internal compression interface; callers must not confuse it with
standard hashing of unpadded messages. Padding and bit lengths are derived
constants/Boolean selections, never caller-supplied witness bytes.

## Why the relation is preserved

The old relation requires `target == HMAC(k, real_message)` when `r = 1`,
and `target == HMAC(dummy_key, dummy_message)` when `r = 0`. Because `r` is
Boolean, selecting every key/message/padding component with the same `r`
then enforcing `target == selected_HMAC` unconditionally has exactly those
two cases. The unused old HMAC output had no independent relation obligation.
This removes five compressions per input, ten total across the fixed pair.
Selection constraints reduce the net saving; measure the actual count.

All other obligations must remain:

- The real selector is allocated with `Boolean::new_witness`; at least one
  input is real. Never choose circuit structure through a Rust branch on the
  selector witness value.
- Real inputs still prove ownership, note membership, positioned nullifier
  secret commitment and position bounds. Dummy note, path, owner/nullifier
  secrets and position retain their canonical zero rules.
- `dummy_key` and `dummy_seed` remain zero for real inputs. Slot is the
  loop's constant `0` or `1`, distinct from the note position.
- Each NF is nonzero, the two NFs differ, and every existing input/output
  count, range, value-conservation and transcript binding check stays intact.
- The same original `D`, `k`, `CM`, position and dummy fields feed the
  selected computation; do not introduce replacement unconstrained witnesses.

## Main implementation risks

1. **Mixed branch bytes:** choosing the tag or data with a different flag,
   selecting ipad but not opad key, or treating the dummy slot as four bytes
   changes the nullifier relation. Build every component from the same
   constrained `r`.
2. **Padding length error:** encoding the message length without the 64-byte
   ipad prefix gives incorrect HMAC. Length is 140/137 bytes before padding.
   SHA length is big-endian; note position remains little-endian.
3. **Second finalization:** the 192-byte inner stream already includes full
   padding. Compress and read state, rather than ordinary hashing that stream.
4. **Free padding witnesses:** accepting witness-supplied suffix/length bytes
   would prove an arbitrary compression preimage instead of the specified
   HMAC. Construct bytes with constant/Boolean gadgets only.
5. **Inactive-field or selector weakening:** preserve old canonicalization and
   `Boolean` allocation even though the inactive HMAC is no longer evaluated.
   Do not use an unconstrained field element as a selector.

No changed asset, public format, ownership secret, primitive or privacy
assumption is required by this transformation. It changes R1CS matrices and
therefore requires a fresh matching setup before any later proving or native
experiment. Existing proving keys cannot be reused.

## Prospective byte and constraint checks

Before full synthesis, freeze these checks and review the actual source:

1. For both slots and both selector values, read every generated byte and
   compare the 192-byte stream with independently constructed ordinary
   SHA-256 padding of `ipad64 || exact_selected_message`. Check complete
   buffers, not just the last eight length bytes. Use nonzero patterned key,
   CM and seed, and distinguish all four position bytes in the isolated
   helper test. Include zero and `0xffffffff` helper positions; legal transfer
   bounds remain the circuit's separate obligation.
2. Compare the resulting HMAC output with the existing ordinary RFC 2104
   implementation for both slots/branches. Include zero and all-`ff` keys,
   patterned fields, and several legal positions. Change each selected field
   and confirm equality remains only to the appropriate reference output.
3. Allocate the selector as a witness, constrain it to each Boolean value and
   check satisfaction and equal circuit shape. Cover relevant
   constant/witness operand modes. Explicitly retain Boolean allocation in
   source review; a host-language `bool` test alone does not check Booleanity.
   If testing an adversarial field assignment of `2`, mutate a constrained
   selector assignment in an isolated test and require UNSAT; never bypass
   Boolean allocation in production to make this test possible.
4. Compare a single altered inner stream against the correct reference for
   each of: padding marker offset, bit length, dummy slot, real position byte,
   key, tag, domain and data. An incorrect supplied NF must fail the equality
   constraint. These checks must not give callers control of padding bytes.
5. Run one frozen complete SAT sizing witness and later the existing full
   authority, inactive-field, domain, wrong-NF, replay and integer controls.
   A helper digest match is necessary but does not establish transfer-relation
   equivalence. Retain any unexpected failure without silently changing the
   frozen specification.

This design ACK supports an isolated prototype and measured synthesis. It
does not establish proof speed, wallet memory, privacy, cryptographic
correctness, native acceptance or testnet readiness.
