# Independent state compression source review

Reviewed additive historical-state tools only; no compression/runtime invocation.
Source identities:

- `compress_state_retained.rs` SHA256
  `9bbfb314810be5cc9fb1177403aa61cdecf673e29c8b3deebcf6b1d10ed2a5da`.
- `verify_state_compressed.rs` SHA256
  `3793c622a2dbc3ac89f8862b5039072325aaff464510ef0fafa600e96d9360a3`.

No source blocker found. The compressor fixes historical-anchor context rather
than accepting a runtime context selector. It requires an externally frozen
source receipt SHA, exact parsed Succinct profile, selected new state image,
J336, official JOIN/no-assumptions check, and the independently constructed
successful `ReceiptClaim::ok(image,J336)` digest before compression. Old J42 or
the current-anchor J cannot satisfy these conditions.

The only proving API call is `default_prover().compress(...,&source)`. There is
no executor/ELF/guest replay or prove_with_opts path. Candidate bytes are fsynced
before post-checks. Output must be Groth16, retain the source's complete claim
digest and exact journal, pass the SDK with dev mode disabled and have no
unresolved assumptions. Actual source runtime identity/frozen assets remain
coordinator obligations; the reported archive SHA is not an in-code asset hash
check. The externally verified official output key protects acceptance.

The separate verification-only tool has no prover import/call. It checks fixed
historical image, exact expected successful claim/J336, Groth16 profile,
no assumptions and publication consistency. Actual SDK negatives cover wrong
image,11 field-specific journal bytes, seal corruption; fake receipt is a
separate application profile rejection. It does not claim fake rejection occurs
at the pairing layer.

Build/source hashes and immutable executable copies rechecked against compression
build freeze SHA256
`0b94b30a54ce3caa52efc301c7b10755cb9c9d1866750aec227680d489ed67bc`;
identities retained in `state-compression-source-identities.json`. This source
review permits no claim that compression, native settlement or exits occurred.
The official Groth16 wrapper retains its established setup trust assumption.
