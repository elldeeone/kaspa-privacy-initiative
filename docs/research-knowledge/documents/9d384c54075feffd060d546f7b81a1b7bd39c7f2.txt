# SDK-coordinate to native-proof conversion correction

This supplements the host-only conversion review in
`R0-PRE-PROOF-REVIEW-02.md`. The first actual native128 conversion safely
rejected the already genuinely verified compressed receipt at
`native G2 canonical nonidentity encoding`. It emitted no native financial
acceptance. The original executed source and failure must remain retained.

The reviewer had ACKed the added affine canonical roundtrip without inspecting
Ark0.6 SWFlags handling. Exact library source explains the incompatibility:
`ark-ec-0.6.0/src/models/short_weierstrass/mod.rs` serializes an uncompressed
affine point as x followed by y **with** `point.to_flags()`. Its negative-y
metadata can set0x80. SDK seals carry the two field coordinates without that
affine metadata. Checked uncompressed deserialization validates the supplied
coordinates, but its affine reserialization need not reproduce metadata-free
coordinate bytes.

The corrected source keeps checked affine deserialization, subgroup checking,
nonidentity rejection and exact coordinate order. It retrieves the point's x/y
fields and serializes those **fields** canonically, comparing the exact bytes
to the SDK-coordinate input. It does not mask arbitrary input bits or remove
coordinate canonicality. Final compressed128-byte Ark proof encoding and the
standard sign convention remain unchanged; there is no A negation.

Reviewed corrected source:

- `poc/shared-settlement-proof/host/src/native_proof.rs`:
  `53da4c819fa0a1801c0f00ef76e0a15acf98dc6ec348c16ea4cab889dcc0ce7b`.
- `poc/shared-settlement-proof/host/Cargo.toml`:
  `3f3886a9bf5cc71796c42f8f1d79b6cf46c4fa41482a1b2097501481cc73e3aa`.

The new controls exercise G1/G2 generator points with both y signs, injected
affine flags, wrong endianness/extension-field order, malformed width, off-curve,
noncanonical field coordinates and identity. This is a source ACK for the
specific correction; executed control results and successful native conversion
remain separate evidence.

The host still requires genuine selected-image SDK Groth16 verification,
exact424-byte journal and empty assumptions **before** conversion. The rebuilt
host must be independently selected; prior successful proving/compression
records retain their original host selection. No guest, child relation,
profile, image, journal or cryptographic proof regeneration is required. Only
actual Native Full verification can establish that the resulting native proof
matches the selected W financial program.
