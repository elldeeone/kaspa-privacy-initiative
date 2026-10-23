# Independent selected-HMAC source ACK

**ACK for the isolated build and frozen synthesis experiment.** This is a
read-only source review; this reviewer ran no tests, synthesis, setup, key
loading, proof, native validation or trial. The design remains as specified
in [INDEPENDENT-DESIGN.md](INDEPENDENT-DESIGN.md).

## What was checked

A mechanical text comparison against the closed `poc/exact-sha-cost-probe`
found:

- The transfer relation from `fn slack` through the CM membership/root check
  is byte-identical. Thus real Boolean allocation, real-note zero padding,
  owner/key commitments, position bounds, integer constraints and membership
  authorization checks are retained.
- The `dummy_key`/`dummy_seed` witness allocation and conditional zero checks
  are byte-identical. Both remain constrained to zero for real inputs.
- From the per-slot NF nonzero check through the end of the transfer relation,
  the source is byte-identical. This retains the at-least-one-real rule,
  double-real position distinction, cross-slot NF distinction, output checks,
  range/conservation and authorization digest/public-input binding.
- The SHA source is byte-identical except for the added crate-private
  `digest_padded_hmac_inner` helper. Existing compression, Ch/Maj expressions,
  schedule, padding, ordinary digest and inherited tests are unchanged.

The new helper rejects every length except 192, creates `Self::default()`
with the standard IV, processes all three full blocks through unchanged
`update`, and reads eight state words in big-endian order. There is no extra
finalization or caller-supplied initial state.

## New nullifier calculation

`selected_hmac_g` selects key (`k`/`dk`) and data (`CM`/`ds`) with the same
existing Boolean `real`. `selected_inner_bytes` uses that flag for tag and
the complete trailer selection. Domain is the original constrained domain
slice. No new witness is allocated for padding, SHA length, tag or selector.
The inner prefix is exactly 136 bytes; both selected trailers are 56 bytes.
The real stream contains the four original little-endian position bytes and
140-byte bit length; the dummy stream contains exactly one slot byte and
137-byte bit length. This matches the reviewed 192-byte construction.

The selected key is reused for the outer opad block, padded with the original
32 zero key bytes. The ordinary outer digest processes exactly 96 bytes.
The two conditional NF equalities are replaced with one unconditional
equality to this selected HMAC, preserving the Boolean two-case relation.
Input-dependent Rust branching is absent from the synthesizing functions.
Host `if real` branches are confined to independent test reference values.

The copied library changes only the frozen synthesis pass assertions: remain
within the `2^22` domain and use fewer than the closed 3,497,893 constraints.
No public format, domain, proving API or transfer invariant was changed.

## Test-source coverage

Four added tests cover:

1. Eight full 192-byte comparisons against independently padded host inputs
   and ordinary RFC 2104 HMAC outputs: both slots, one dummy branch and real
   positions `0`, `0x3412cdab`, `0xffffffff`. Selector and source bytes are
   witness variables. The four position bytes differ in the middle case.
   The tests compare constraint/witness counts across selector values.
2. Four malformed-inner cases: padding marker and bit-length corruption for
   each real/dummy branch, requiring UNSAT against the unchanged reference NF.
   Only the test mutates the constructed padding vector; production callers
   supply no free padding witnesses.
3. A Boolean selector's underlying field assignment changed to numeric `2`
   after allocation, for both starting flag values, requiring UNSAT. The
   Booleanity constraint remains present; the test does not replace the
   production selector with an unconstrained field variable.
4. Rejection of six incorrect padded-inner lengths, including empty, partial,
   two-block and four-block inputs.

The inherited 64 Boolean value/allocation cases and 15 SHA length checks are
unchanged. These coverage statements describe source, not executed results.
The eight HMAC cases use patterned keys; they do not claim exhaustive keys,
full-transfer negative controls or cryptographic correctness.

## Reviewed candidate pins

```text
src/circuit.rs       4ac571ff98d422d76caf2f420a08b68b53fd62781a495735e0b7d0ecff656d40
src/exact_sha256.rs  24c7bb2e8c830261a1d000f96a0add5c19d7b992c1d7fcd0021ab272b0c0e9b8
src/lib.rs           82c920e55f676e0d4c37ca877e4ca128cac822eea61415b7cb2fbbe6b8a347a5
Cargo.toml           a2a7bb7e9161554441034023df6c5d9a6b9d7e6bd6726e70474abf8ac2c2d0ed
Cargo.lock           3080b1f57581f4b8c2f9a11a34c206b0d888bf940f7bf2c68ef7ae15264cc8e4
```

The reviewed change removes ten SHA compression blocks across two inputs,
with additional selection constraints. Actual size, satisfaction, timing and
RAM remain measurement questions. The matrix changes require a new matching
setup and VK for any future proof/native experiment; this ACK does not
authorize changing existing selected keys or trial policy.
