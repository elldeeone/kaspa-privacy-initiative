# Complete Orchard V2 interoperability

Unfunded local interoperability package for [RFC-0004](../../docs/rfc/0004-native-kas-private-payment-boundary.md)
and [ADR-0102](../../docs/adr/0102-unfunded-orchard-interoperability.md).
**Result, 4 November 2026 (Australia/Sydney):** three genuine two-Action Halo2
bundles (deposit, real-spend transfer, real-spend withdrawal) serialize, parse and
verify with individual spend/binding signatures. Fifteen integration tests pass,
including actual changed-input/wrong-key/proof rejection, signed economic-effect
mutations, role-specific malformed encodings, recipient checks, stale/spent
supplied context and 96 deterministic bit flips. Python independently checks
framing and digests. Ten generated files reproduce byte for byte; separate
processes reconstruct the same verifier and verify all three bundles.

This format does not authorize native KAS or authenticate supplied chain state.
All keys, values and random seeds in these fixtures are public synthetic test
data, never imported from a wallet or funded instance. The
[verification receipt](VERIFICATION.json) records exact identities and scope.

## Run

Requires Rust 1.95.0 with rustfmt/clippy, Python 3 and initial Cargo dependency
access (or the exact cached dependencies). From the repository root:

```sh
bash poc/orchard-interop/check.sh
```

This parses/cross-checks the public vectors, checks format/lints and verifies
the full cryptography and negatives. It makes no RPC requests. Default build
artifacts go under ignored `.local/orchard-interop/target`.

Verify a packet in a fresh process:

```sh
cargo +1.95.0 run --release --locked --manifest-path poc/orchard-interop/Cargo.toml -- verify poc/orchard-interop/vectors/transfer.bin poc/orchard-interop/vectors/transfer.context.json
```

Construct independent public keys/proofs/bytes in a new local output folder:

```sh
cargo +1.95.0 run --release --locked --manifest-path poc/orchard-interop/Cargo.toml -- generate .local/orchard-interop/reproduced-vectors
```

The fixed synthetic RNG/keys are in `fixtures.rs` and the manifest. The generator
derives the proving/verifying keys from the selected upstream circuit, creates
three real proofs, checks decryption and complete bundle verification, and writes
only public vectors. It does not use a ceremony coordinator or any old setup.
`fingerprint` prints the independently constructed verifier's diagnostic identity.
The dedicated [CI workflow](../../.github/workflows/orchard-interop.yml) runs
the verifier/negative checks without proof generation or RPCs.

## Evidence and limits

| Evidence | What it establishes / limitation |
| --- | --- |
| Three genuine complete bundles | Full upstream Halo2, two spend signatures and binding signature under one fixed V2 key. Supplied inputs are not real UTXOs or authorized funding. |
| Known-answer key/note vector | Public first vector extracted from pinned upstream `src/test_vectors/keys.rs`, with exact source hash. It tests key/address/commitment/NF compatibility, not received-note validation or Kaspa's smaller monetary limit. |
| Changed public inputs | Canonical cv/NF/rk/cmx/anchor changes and a wrong circuit key reject in the actual Halo2 verifier, rather than only failing a fixture hash. |
| Changed economic/delivery effects | Original proof remains valid for non-circuit effects, but actual spend signatures reject the changed digest. Binding-signature corruption rejects separately. |
| Supplied context | Current all-slot spentness, anchor/domain, ordinary arithmetic and pool range checks; no authenticated chain ancestry, real UTXO lookup or durable state update. Reusing the same supplied context is not a stateful double-spend prevention service. |
| Reproduction and Python parser | Exact local bytes/digests/key identity across new processes; not independent-host recovery or an audit. |

Key fingerprint: `eafbdf6694e6da29789e105a15ce9509b957dd9f5ca3a1fa4c468bb6546686af`.
This is SHA-256 of the constructed **public upstream Rust Debug** representation
under the locked dependency/toolchain profile. It is diagnostic, not a portable
serialized verification key or allocated consensus identifier. The verifier API
fixes its key/version; no packet can choose a different key. A future portable
native codec must define a reviewed identity independent of Rust Debug output.

This is not a wallet, native transaction, UTXO/script validator, DAG database,
reorg implementation, archive/bootstrap/recovery system, mass schedule, privacy
pass or cryptographic soundness proof. Scripts/covenants and ordinary input
authorization are not executed. The native invariant/accounting decision remains
open. No smaller hidden-value range gadget is added. The unchanged price-prior
qualification failure remains. See the [adversarial review](REVIEW.md).

The upstream vector excerpt is attributed to Zcash's Orchard repository at the
pinned revision and distributed under its [MIT license](UPSTREAM-LICENSE-MIT).

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
