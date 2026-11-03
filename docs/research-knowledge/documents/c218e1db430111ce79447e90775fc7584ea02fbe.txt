# Public projection raw-lane and history-linkage evidence

Date: 2026-10-29  
Repository baseline: `b58de1a182347c4223ebe84f92bb0bdd6c88d003`  
Status: source audit only; no assumption, runtime, or ledger selection

## Decision

The selected 10,685-byte public projection is not adequately described by a generic `projection.raw_bytes` row.

1. The public state observer can deterministically link accepted rounds as one pool-state history. Old/new roots, counts, reserve value, reserve script, and accepted outpoint lineage make that explicit. This is expected pool-operation linkage; it is not an owner-spend edge.
2. Public NF insertion witnesses add exact predecessor/successor values, historical insertion indices, and paths. They create a public numeric-neighborhood/history graph. Under an honest-key HMAC-PRF assumption that graph should be independent of owner identity, but the graph is real and must be modeled.
3. Public CM append paths assign every output row an exact global CM position. They expose batch/order/state continuity, but do not by themselves link a later NF to the CM it spends.
4. The nine public CVs plus public total fee and aggregate delta do not select an owner grouping. The aggregate equation is invariant under every permutation/partition of the same three inputs and six outputs. Candidate-specific testing requires an individual fee/delta/opening or a blinding/reuse failure.
5. Honest ciphertext confidentiality is conditional on the exact pinned sealed-box implementation, fresh ephemeral randomness, a valid honest recipient key, and secret delivery key. Recipient/output unlinkability is an additional key-privacy claim. The circuit proves **no encryption-correctness relation**, so a malicious output creator can publish a tagged 264-byte field while still proving the CM/CV and ciphertext hash.
6. Honest NF pseudorandomness hides the source CM/position only conditionally. NF equality deliberately links a retried/replayed spend of the same note and position.

## Exact lane map

The grammar is pinned by `poc/local-private-payment/private-batch-public/common/src/wire.rs:1-215` and selected aggregate `private-batch-relation/src/wire.rs:5-127`. Body-relative offset `B` begins at absolute projection offset 193.

| Absolute bytes | Body bytes | Public lane |
|---:|---:|---|
| `0..193` | — | native effects prefix |
| `193..201` | `B[0..8]` | `KPBAEF01` |
| `201..361` | `B[8..168]` | chain genesis, pool lineage, profile, domain, service policy (five 32-byte values) |
| `361..397` | `B[168..204]` | current reserve outpoint/point |
| `397..477` | `B[204..284]` | old CM root, old NF root, both counts, old reserve |
| `477..565` | `B[284..372]` | new CM root, new NF root, both counts, new reserve, total fee |
| `565..597` | `B[372..404]` | canonical aggregate CV delta scalar |
| `597..885` | `B[404..692]` | three sorted rows `NF32 || input-CV64` |
| `885..4005` | `B[692..3812]` | six output rows, 520 bytes each |
| `4005..7485` | `B[3812..7292]` | three indexed-NF insertion witnesses, 1,160 bytes each |
| `7485..10557` | `B[7292..10364]` | six CM append paths, 512 bytes each |
| `10557..10685` | `B[10364..10492]` | aggregate Groth16 proof |

Each input row at `B[404 + 96*i]` is:

```text
NF[0..32] || CV[32..96]
```

Each output row at `B[692 + 520*j]` is:

```text
CM[0..32] || CV[32..96] || ciphertext[96..360] ||
SHA256(ciphertext)[360..392] || OutputGroth16Proof[392..520]
```

These are the exact parser slices at `private-batch-public/common/src/wire.rs:122-170`.

The prefix contains the current reserve point, old reserve amount/script, new reserve amount/script, and framing. It binds `prefix[12..48]` to `B[168..204]`, `prefix[56..64]` to `B[276..284]`, and `prefix[105..113]` to `B[356..364]` (`common/src/wire.rs:179-208`). The 37-byte old/new reserve scripts commit the 112-byte state and immutable policy tail with BLAKE2b-256 (`private_batch_trial/exit_wire.py:106-109`; construction at `wallet_history.py:116-121`).

## Accepted-history linkage

For consecutive accepted rounds, the public transition requires:

```text
R1 B[284..316] == R2 B[204..236]   new CM root == old CM root
R1 B[316..348] == R2 B[236..268]   new NF root == old NF root
R1 B[348..352] == R2 B[268..272]   new CM count == old CM count
R1 B[352..356] == R2 B[272..276]   new NF count == old NF count
R1 B[356..364] == R2 B[276..284]   new reserve == old reserve
R1 prefix[115..152] == R2 prefix[66..103]  successor state script
```

The R2 reserve point also references the accepted R1 reserve output through the native transaction history. `wallet_history.payment` reconstructs and checks the exact successor state, roots, counts, prefix, and rows at `wallet_history.py:80-122`.

Therefore “round unlinkability” is not a valid public-state claim. The intended privacy question is whether the linked operations reveal the hidden owner/input/output mapping.

A typed observer-admission continuity authority must come from the genuine accepted public transition/history source. The fresh-owner successor authority currently authenticates head/history identities and three private lineage digests only; it has no authenticated raw roots/counts/projections. Minting public continuity from caller-supplied owner-adapter fields would create false authority.

## Indexed-NF witness linkage

For input `i`, let `W = B[3812 + 1160*i .. 3812 + 1160*(i+1)]`. Its public layout is defined at selected `private-batch-relation/src/wire.rs:55-76`:

| Witness bytes | Field |
|---:|---|
| `W[0..4]` | predecessor insertion index |
| `W[4..36]` | predecessor NF value |
| `W[36..68]` | successor NF value |
| `W[68..72]` | successor insertion index |
| `W[72..616]` | 17-node predecessor path |
| `W[616..1160]` | 17-node append path |

The public verifier checks the predecessor leaf in the old NF root, rewrites its successor to the new NF at append index `old_nf_count+i`, proves the empty append leaf, and appends the new `(NF, successor, successor_index)` leaf (`wire.rs:171-229,293-304`). Inputs are inserted in public sorted-NF order (`:261-268`).

Consequences:

- a later witness can repeat an earlier round's NF as its predecessor or successor;
- predecessor/successor insertion indices expose the age/position of those neighbors;
- paths bind each insertion to an exact old/intermediate/new NF root;
- same-round witnesses can reference an NF inserted earlier in the same batch.

This is an explicit cross-history graph. If honest NFs are pseudorandom, numeric adjacency and historical indices should not carry owner semantics, but that conclusion requires the NF PRF assumption below. It cannot be replaced by a distinct-NF count.

## CM append-path linkage

For output `j`, `B[7292 + 512*j .. 7292 + 512*(j+1)]` is its 16-node path. The verifier first folds the empty leaf at exact position `old_cm_count+j` to the current intermediate root, then folds the public CM into that position (`selected wire.rs:305-319`).

This exposes:

- each output's exact global CM position;
- all six public append-order edges and intermediate roots;
- exact batch boundaries and cross-round state continuity.

The later spend membership path and note CM are private. CM append paths alone do not identify which old CM produced a later public NF. If an NF key is compromised, however, the public CM archive and exact positions make exhaustive NF matching immediate.

## CV grouping algebra

The exact public equation is checked at `native-relation/src/cv.rs:160-177` and selected `private-batch-relation/src/wire.rs:282-291`:

```text
sum(input CV[0..3]) - sum(output CV[0..6]) - total_fee * V
    = public_delta * R
```

For private owner `i`, the selected circuit enforces:

```text
input_value_i = output_value_i0 + output_value_i1 + fee_i
delta_i = input_blind_i - output_blind_i0 - output_blind_i1  (mod q)
input_CV_i - output_CV_i0 - output_CV_i1
    = fee_i * V + delta_i * R
```

The private `fee_i` sum is constrained to public total fee and the three private deltas sum modulo `q` to public delta (`private-batch-relation/src/circuit.rs:174-216,240-268` and `src/gadgets.rs:86-109`, selected commit `b58de1a...`). Private input/output rows are routed to the public arrays through hidden permutation matrices (`circuit.rs:262-293`).

For any candidate partition that uses all three input CVs and all six output CVs exactly once, summing its three candidate equations yields the same public equation. Reassigning outputs therefore cannot change the aggregate test. For any single candidate group and proposed fee, the residual is a prime-subgroup point and hence some unknown scalar multiple of nonzero `R`; without its individual delta or a discrete-log break, existence of that scalar is no discriminator.

A corrupt C1 can remove its known input, two outputs, fee, and private delta. The remaining two-input/four-output equation is still symmetric and partition-invariant. A passive corrupt P1 has authenticated shares/MACs rather than the honest owners' reconstructed deltas under the pinned fresh-mask assumption. Candidate-specific testing becomes possible if an individual delta/opening/fee mapping leaks, a blind is zero/reused, or retry randomness is reused. The companion detailed analysis is `research/public-cv-joint-leakage-analysis-2026-10-29.md`.

## Output ciphertext construction and limits

### Exact honest construction

The selected owner code encrypts a fixed 216-byte receipt:

```text
"KPBREC01" || domain32 || invoice_index_u64_le || Note168
```

`wallet_profile.py:154-178` defines the receipt; `output_producer.py:105-125` creates a fresh `rho`, commits the note, and calls `crypto.seal(invoice.delivery_pk, receipt.encode())`.

The delivery secret is:

```text
HMAC-SHA256(owner_seed,
  "KPBKDF01" || profile_id || domain || "DELIVERY" || u64_le(0))
```

and is deliberately stable across invoices in the same owner/profile/domain (`wallet_profile.py:65-69,191-217,227-233`). The public invoice contains the corresponding 32-byte X25519 public key. It is not included as a field in the public output row.

`wallet_profile.py:32-33,88-95` pins the executable to SHA-256 `6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff`. At repository commit `b58de1a...`, its bridge sources hash to:

| Source | SHA-256 |
|---|---|
| `poc/future-recipient/bridge/Cargo.toml` | `285e32cfb7a2c394eb65b907937ff26390308334c59a707b7706161c0a443b4c` |
| `poc/future-recipient/bridge/Cargo.lock` | `2d6cd25389016adc7eaaaa3e9af4121e9708f2355102f51bf7cedc89a0825d98` |
| `poc/future-recipient/bridge/src/main.rs` | `5fe1f3b9d678086dc7b4a7681642b90841395135b0135a4f07f876f740ee5829` |
| `poc/local-private-payment/private_batch_trial/wallet_profile.py` | `4991baef65d13a91a7944f21bc7750b77c5776dc6f7c4d2c6844ca5b8f39e289` |
| `poc/local-private-payment/private_batch_trial/output_producer.py` | `e074f3a1f3cf68381c5809cc343c796810e3139c6b0e35ab8e683968712677e6` |

The bridge uses RustCrypto `crypto_box = 0.9.1` with the `seal` feature (`bridge/Cargo.toml:10-14`, Cargo checksum `16182b4f...0f009`). Its upstream source is commit [`91078b60...`](https://github.com/RustCrypto/nacl-compat/tree/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box). Exact sealed-box construction:

1. generate a fresh ephemeral X25519 secret with `OsRng`;
2. prepend its 32-byte public key;
3. derive the 24-byte nonce as `BLAKE2b-192(ephemeral_pk || recipient_pk)`;
4. encrypt/authenticate with `SalsaBox` (`crypto_secretbox`, XSalsa20-Poly1305);
5. prepend the 16-byte authentication tag to the 216 encrypted receipt bytes.

See [`public_key.rs:45-67`](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/src/public_key.rs#L45-L67) and [`lib.rs:195-255,310-317`](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/src/lib.rs#L195-L255). Thus `32 + 216 + 16 = 264` bytes.
The exact inner layout is therefore
`ephemeral_pk32 || Poly1305_tag16 || encrypted_receipt216`; tag prepending is
implemented by pinned `crypto_secretbox = 0.1.1` at
[`crypto_secretbox/src/lib.rs:241-304`](https://github.com/RustCrypto/nacl-compat/blob/0324a1ed7ef3fdf5d53f35b6cae6f7ff2429e27a/crypto_secretbox/src/lib.rs#L241-L304)
(local source SHA-256
`e8335a00dbe2ccf5497d5cb66db725ab3fe14c74e796cd3331d55ff1fd86c488`).

A no-funds synthetic control also exercised the admitted executable itself.
The selected binary with SHA-256 `6f65ec20...3143ff` sealed a fixed 216-byte
test plaintext under a fixed test recipient secret. Recomputing
`BLAKE2b-192(ephemeral_pk || recipient_pk)` and passing the 232 bytes after the
ephemeral key directly to libsodium 1.0.18 `crypto_box_open_easy` returned
success and the exact plaintext. Moving the final 16 bytes to the front as a
postfix-tag interpretation returned authentication failure. This confirms the
prefix-tag serialization of the selected binary; it does not by itself prove
that the binary was reproducibly built from the reviewed source closure.

The retained control and reproduction commands are:

```bash
python3 -B poc/local-private-payment/private_batch_trial/test_selected_crypto_box_layout_control.py
python3 -B poc/local-private-payment/private_batch_trial/selected_crypto_box_layout_control.py
```

`selected_crypto_box_layout_control.py` pins the selected binary hash, the
synthetic key hash `ae216c2e...a612c9`, plaintext hash
`4b6bdc1d...578ad`, recipient public key, libsodium 1.0.18, and one exact
264-byte retained vector with SHA-256
`49bdb288a0d09f8e1ab044f486c8209fa7f2f9f70885256323af7303e13059c6`.
It also generates a fresh randomized vector on every run and applies the same
direct-open/reordered-tag checks. The fresh vector hash is intentionally not a
fixed expectation. The receipt explicitly records
`production_secret_material_used=false` and `privacy_claim=false`.

### Narrow confidentiality statement

> For outputs created by the exact honest producer above, receipt plaintext confidentiality and integrity are assumed under the pinned X25519/SalsaBox/BLAKE2b construction, a valid honestly generated recipient public key, fresh unpredictable `OsRng` ephemeral secrets for every seal, and a secret uncompromised delivery key. Hiding which candidate recipient key was used requires an additional recipient-key-privacy assumption in the complete auxiliary view; ordinary plaintext confidentiality alone is not that claim.

Limits and counterexamples:

- The selected executable hash and repository source hashes do not by themselves
  prove executable/source correspondence. A genuine registered build/admission
  authority must bind the exact binary to this source/dependency closure before
  the construction-specific assumption applies.
- The stable delivery public key links the owner's invoices to directory observers and participating senders. The projection alone omits it, but the joint auxiliary view may not.
- A recipient can trial-decrypt and identify all of its own outputs. A participating sender already knows the exact row it created. These are modeled auxiliary facts, not encryption failures.
- Reused ephemeral randomness repeats the visible first 32 bytes and reuses key/nonce material.
- Delivery-secret compromise decrypts and links all ciphertexts for that owner/profile/domain.
- A low-order or otherwise adversarial recipient key needs explicit refusal/provenance; `PublicKey::from` alone is not evidence of an honestly generated key.
- The Output circuit constrains CM and CV and binds only the **hash** of the caller-selected ciphertext (`auth_exit/src/circuit.rs:111-123`). Public validation checks `SHA256(ciphertext) == cfh`; it does not prove encryption correctness. A malicious output creator can put an owner tag in the 264 bytes and still produce an otherwise valid Output proof. Privacy applicability therefore requires the admitted honest owner-output program, not merely proof validity.

## Honest NF construction and limits

The selected construction is:

```text
k_i = HMAC-SHA256(owner_seed,
      "KPBKDF01" || profile_id || domain || "NULKEY01" || u64_le(invoice_i))

NF = HMAC-SHA256(k_i,
     "KPX1NF\0\0" || domain || CM || u32_le(global_CM_position))

K = SHA256("KPX1KEY\0" || domain || k_i)
```

The KDF and owner key selection are at `wallet_profile.py:65-69,196-216`; NF derivation is at `:235-240`. The Rust relation uses the identical HMAC message at `native-relation/src/lib.rs:76-84`, and the selected aggregate circuit proves the private `k_i`, CM, position, key commitment, and public NF relation at `private-batch-relation/src/circuit.rs:154-176` (selected commit `b58de1a...`). HMAC is the standard construction in [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104).

### Narrow pseudorandomness/unlinkability statement

> For an honest owner's NF, the public value is assumed pseudorandom and computationally unlinkable to its source CM/position/owner under HMAC-SHA256 multi-user PRF security, domain-separated HMAC key derivation from a secret high-entropy owner seed, SHA-256 one-wayness for the exposed key commitment, and absence of the NF secret from the complete observer/colluder view. This claim hides no equality: the same `(k, domain, CM, position)` always produces the same NF.

Applicability conditions and failures:

- A retry or replay of the same note at the same position publishes the exact same NF and is directly linkable. Fresh attempt/cohort identifiers do not change that.
- NF-key or owner-seed compromise lets an observer enumerate the public CM archive and exact positions and match the NF.
- Participating invoice holders may know `K`, CM, value, and other note fields. The assumption must cover that auxiliary input; SHA collision resistance alone is irrelevant to NF pseudorandomness.
- Role/index/domain separation and distinct honest owner seeds are mandatory. Cross-arm owner/seed reuse violates the condition.
- The predecessor/successor witness graph and sorted row order remain visible even when NF values are pseudorandom.
- The claim does not cover a malicious owner choosing keys or input lineage to create tags.

## Model disposition and remaining gaps

The current uncommitted model now has an exact frozen partition of all 10,685
projection bytes: 102 contiguous, non-overlapping lanes with manifest SHA-256
`1bf69a2f0df24e494e5ad212ebf4770ee98e2c40f1186b912f9a9ae898e305ea`.
Its focused controls pass 30/30. The geometry-only manifest over each ordered
`(name, start, end)` row is
`bbbf077037ec84bc8ddd87dfd7de472f04fde074bbd711f95ac559bf0596b2e1`.
The prior full manifest
`df6560fd742b2388ade6ecefb89d0773023173754fc53943f2ac4b55702ff0d1`
is reproduced by changing only the two script-lane `field_path` values back to
`context.cross_round_or_external_identity_linkage`. The current manifest binds
both `[66,103)` and `[115,152)` instead to
`context.two_round_structural_profile_script_binding`; names, categories,
offsets, order, and all ciphertext/witness boundaries are unchanged. It
separately inventories:

1. stable profile/pool/service identifiers and native reserve outpoint/script lineage;
2. old/new CM/NF roots, counts, and cross-round equality edges;
3. NF predecessor/successor values, indices, and both witness paths;
4. CM append indices and paths;
5. three input CVs, six output CVs, total fee, aggregate delta, and the partition-invariant equation;
6. six ciphertexts, six ciphertext hashes, honest-encryption provenance, plaintext confidentiality, and recipient-key privacy;
7. honest-NF PRF/source unlinkability, with deterministic retry equality explicitly excluded;
8. six Output proofs and one aggregate proof under their two distinct CRSs;
9. row order, batch shape, timing/history, and every auxiliary invoice/colluder fact.

There is no `projection.raw_bytes` leakage row. The exact lane manifest, ledger,
CV equation, ciphertext subfields, and witness-edge fields provide the direct
inventory instead. Honest-encryption provenance/malicious tagging,
ciphertext confidentiality and key privacy, CM hiding, NF pseudorandomness,
deterministic retry equality, state paths/history edges, cross-round
continuity, cross-attempt byte equality, proof ZK, CV candidate residuals, and
blind freshness remain fail-closed `unmodeled` rows.

Two implementation gaps remain material:

1. Retry/replay NF equality is named and correctly left unmodeled, but the
   single-projection adapter has no authenticated multi-attempt comparator or
   equal-NF retry mutation control. It must not be described as measured yet.
2. NF predecessor/append paths are retained as whole-path SHA-256 values in
   the derived inventory. Raw path bytes remain exactly named and unmodeled,
   so this is not a privacy overclaim, but per-node overlap and candidate
   effects are not yet computed.

The model's lane-offset control uses synthetic ciphertext bytes, but the
tag-prefix layout is independently established by both the pinned Rust source
and the selected-binary control above. Reproducible executable/source admission
remains an applicability condition. `SELECTED_SOURCE_ASSUMPTIONS` must remain
empty until each source assumption is pinned and its complete auxiliary-view
conditions are admitted.
