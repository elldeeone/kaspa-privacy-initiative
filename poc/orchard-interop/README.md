# Complete Orchard V2 interoperability

Unfunded local interoperability package for [RFC-0004](../../docs/rfc/0004-native-kas-private-payment-boundary.md)
and [ADR-0102](../../docs/adr/0102-unfunded-orchard-interoperability.md).
Implementation/verification results will be recorded here as the package is completed.
This format does not authorize native KAS or authenticate supplied chain state.

## Format v1

All integers are fixed-width little endian; no compact integers, JSON numbers
or ignored suffixes. The envelope is effects prefix followed by authorization:

1. Magic `4b50494f56320001` (8), profile identifier (32), experimental transaction
   version `1` (`u16`), network/genesis/pool/accepted-context identifiers (32 each).
2. Lock time (`u64`), subnetwork (20), gas/storage-mass/fee (`u64` each).
3. Input count (`u16`, at most 16); each input is txid (32), index (`u32`),
   **supplied** value (`u64`), sequence (`u64`), compute tag (`u8`: 0 sigops,
   1 budget), compute value (`u64`; sigops at most 255). Ordinary signatures are
   outside this package; outpoint/value consistency is not authenticated.
4. Output count (`u16`, at most 16); each output is value (`u64`), script version
   (`u16`), script (`u32` length plus at most 4096 bytes), covenant-present tag
   (`u8`: 0/1), optional authorizing-input index (`u32`) and covenant ID (32).
5. Payload (`u32` length, at most 4096 bytes), Orchard flags (`u8`, exact V2
   default), public balance (`i64`, bounded to native maximum), anchor (32),
   Action count (`u8`, exactly 2).
6. Each Action: `cv_net`, nullifier, randomized authorization key, `cmx`, `epk`
   (32 each), recipient ciphertext (580), outgoing ciphertext (80).
7. Authorization: proof length (`u32`, exactly 7264), proof (7264), two ordered
   spend signatures (64 each), binding signature (64). No trailing bytes.

The effects digest is standard BLAKE2b-256, personalization
`KPIInteropEffV1!`, of exactly items 1–6. The profile ID is BLAKE2b-256 with
personalization `KPIInteropPrfV1!` over the UTF-8 string
`orchard:616a669df8c9a59c33d47064d3ce04b25d026b2e:FixedPostNu6_2:NoteV2:2-actions:codec-v1`.
Both personalizations are exactly 16 bytes. The envelope is capped at 160,000
bytes before parsing; lengths/counts are bounded before allocation. Unknown
profiles, flags, tags, counts, malformed role encodings and suffixes reject.
`cv_net` permits identity where upstream permits it; `rk`/`epk` do not.

`Verifier::verify_crypto` checks the complete proof, both spend signatures and
the aggregate binding signature against that digest. It deliberately does not
check ancestry or ordinary funding. `Verifier::verify` additionally validates
public equations/ranges, expected domains, allowed anchors, all-slot nullifiers
and pool range against explicitly **supplied** context, without mutating it.
Neither API is native transaction acceptance. No hidden-value `MAX_SOMPI`
constraint is added to the upstream `u64` circuit.
