# Combined P1+C1+public finite source-assumption ledger

Date: 2026-10-29  
Repository baseline: `b58de1a182347c4223ebe84f92bb0bdd6c88d003`  
Status: proposal only; no assumption selected

## Decision

The bounded observer needs twelve base candidate assumption families, one
V3-specific replacement family, and one explicitly non-selectable research
hypothesis. None is selected by this note:

1. `S1-CM-SHA256` -- note/tree binding and conditional salted hiding;
2. `S2-CV-JOINT-HIDING` -- joint Pedersen hiding conditional on the public
   aggregate equation;
3. `S3-CV-BINDING` -- Pedersen binding and generator independence;
4. `S4-OUTPUT-GROTH16` -- the six owner-local Output proofs;
5. `S5-CRYPTOBOX-CONFIDENTIALITY` -- honest sealed-box plaintext security;
6. `S6-CRYPTOBOX-RECIPIENT-PRIVACY` -- recipient/output key privacy;
6a. `S6A-V3-HIDDEN-DELIVERY-PRF` -- the bounded V3 replacement: one-use
    delivery-key pseudorandomness plus source-proved absence from the admitted
    observer view;
7. `S7-NF-HMAC-PRF` -- honest nullifier pseudorandomness and source
   unlinkability;
8. `S8-MASCOT-OT` -- the exact pinned MP-SPDZ/MASCOT/OT stack;
9. `S9-DDNNT-5N` -- the five-value external-owner input protocol;
10. `S10-AUTHENTICATED-GROUPS` -- custom authenticated G1/G2 linear state and
    checked openings;
11. `S11-MIXED-SCALAR-GROUP` -- the two scalar/G1 Beaver products;
12. `S12-AGGREGATE-GROTH16` -- collaborative Appendix-E proof completion; and
13. `S13-JOINT-AUXILIARY-COMPOSITION` -- **non-selectable research
    hypothesis:** the target joint cryptographic payload distribution in the
    combined P1+C1+public auxiliary view.

The dependency graph is:

```text
S8 <- S9
S8 <- S10 <- S11
S8 + S10 + S11 <- S12
S1..S5 + S7..S12 + (S6 or S6A) -- concrete hybrids/direct facts --> S13 target
```

`S2` is hiding; `S3` is binding. `S5` is plaintext confidentiality and
outsider ciphertext integrity; `S6` is recipient-key privacy. `S4` and `S12`
use different relations, CRSs, setup records, and randomizer sources. Combining
any of these pairs into a generic “commitment,” “encryption,” or “Groth16”
assumption would hide a real applicability failure.

`S6` and `S6A` are alternatives, not cumulative labels. The current V2 or any
profile exposing candidate recipient keys still needs `S6`, which remains
unsupported. The bounded V3 experiment may use `S6A` instead only after native
source authority proves that every honest one-use key, key hash, private index,
and directory identifier is absent from the complete view while all corrupt
sender/C1 invoice facts remain direct constraints.

The following never consume an assumption digest:

- literal public bytes, canonical decoding, paths, positions, row order,
  counts, root continuity, proof verification, hashes, and the public CV
  aggregate equation;
- C1's authenticated contacts, invoices, original amounts, created-output
  amounts, successfully decrypted receipt fields, and retry values;
- C03 framing, source/build/role binding, typed lane grammar, scalar call-site
  IDs, repeated-stage equality, and equations directly recomputed from the
  captured share/MAC lanes; and
- timing, length, order, direction, peer, fork, abort, retry, and partial-tail
  signals. These are direct observations whose mapping effect must be measured
  in the actual trace, not declared harmless by a cryptographic citation.

`SELECTED_SOURCE_ASSUMPTIONS` remains `{}`. A future selection must use one
canonical machine-readable preimage per family and must not replace actual
candidate filtering by a label or digest.

## Corruption and claim boundary

The empirical object is the complete admitted view of the exact pinned,
instrumented, protocol-following P1 process plus passive owner C1 and the
public projection. It is not the view of an arbitrary modified binary or
physical host.

All candidate statements below require:

- P1 and owner C1 are statically corrupt; P0 and P2 and their owner programs
  follow the selected honest source; at least P0 or P2 remains an honest MPC
  computing party for the entire attempt;
- both compared mappings have identical public projection, corrupt-party/C1
  input and auxiliary information, dimensions, call schedule, declared public
  outputs, and admitted success/abort class;
- every owner blind, note salt, sealed-box ephemeral key, Output proof
  randomizer, MASCOT tuple/triple, DDNNT tuple, mixed triple, aggregate proof
  randomizer, MAC lifecycle, and retry context is fresh and one-use as required
  below;
- authenticated role-bound channels, canonical field/point parsing, subgroup
  checks, secure randomness, source/build/launch correspondence, and every
  sacrifice/MAC/broadcast/proof check execute exactly as pinned; and
- failed attempts are never resumed. Abort stage, retry count, partial bytes,
  and all already-sent messages remain explicit leakage.

Internal OT/PRNG random tape, uninstrumented process objects, arbitrary host
memory/log/swap/cache/page/scheduler/CPU/GPU state, and covert or network-stack
channels remain outside the bounded empirical view and unqualified for a
general active-host claim. No candidate assumption silently turns those
boundaries into captured facts.

## Candidate source and build preimage

### Upstream protocol pins

The exact MPC dependency authority is
[`DEPENDENCIES.json`](../poc/local-private-payment/mpc-prover/DEPENDENCIES.json),
currently SHA-256
`46ff3f41db8e1cb3cac0c9702a62cd9473ed0e059cbb02117b033a77c9cf9ece`.

| Component | Exact pin | Candidate families |
|---|---|---|
| MP-SPDZ | [`113c4e47dd94bca9ecab029d2f0abe649bea5c52`](https://github.com/data61/MP-SPDZ/tree/113c4e47dd94bca9ecab029d2f0abe649bea5c52) | `S8`--`S12` |
| SimplestOT_C | [`7ef7666909e493a18c99efe56f97cc4d13723005`](https://github.com/mkskeller/SimplestOT_C/tree/7ef7666909e493a18c99efe56f97cc4d13723005) | unresolved base-OT part of `S8` |
| libOTe | [`fe6b2ff82a976a5332b3a2efe325831588b1324a`](https://github.com/mkskeller/libOTe/tree/fe6b2ff82a976a5332b3a2efe325831588b1324a) | malicious SoftSpoken part of `S8` |
| cryptoTools | [`f70175e0cbd36b808475c0c1bbf585304e43d3d0`](https://github.com/mkskeller/cryptotools/tree/f70175e0cbd36b808475c0c1bbf585304e43d3d0) | transitive `S8` dependency |
| mcl | [`9f49ba06593e2d426ab6fb9b0e17bc125a6f720c`](https://github.com/herumi/mcl/tree/9f49ba06593e2d426ab6fb9b0e17bc125a6f720c) | BN254 Fr/G1/G2 implementation for `S8`--`S12` |
| RustCrypto `crypto_box` | 0.9.1, crates.io checksum `16182b4f39a82ec8a6851155cc4c0cda3065bb1db33651726a29e1951de0f009`, upstream [`91078b60b1cacf674885c1dc86bd00b97adaf828`](https://github.com/RustCrypto/nacl-compat/tree/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box) | `S5`, evidence boundary for `S6` |
| RustCrypto HMAC / SHA-2 | 0.12.1 / 0.10.9, checksums `6c49c37c09c17a53d937dfbb742eb3a961d65a994e6bcdcf37e7399d0cc8ab5e` / `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` | `S1`, `S6A`, `S7` |
| Arkworks Groth16 | 0.6.0, checksum `a293328aa422e65527e285614ce5d1dceb0bd7b8b18d18b1b63191ee1f74cb41`, upstream [`0bb3e604c534bd118ed477eaf1231f591d6fc40f`](https://github.com/arkworks-rs/groth16/tree/0bb3e604c534bd118ed477eaf1231f591d6fc40f) | `S4`, `S12` |
| Arkworks Pedersen / Baby-Jubjub | `ark-crypto-primitives` 0.6.0 checksum `31b3409b1846fe459d19c95df039481575ac6d5842ae63858ad75cc31219bfc1`; `ark-ed-on-bn254` 0.6.0 checksum `a4585ccc828ac1a1c0973a6d859b8cd9ae6055a0ee943139c8e254dfd87d6f38` | `S2`, `S3` |

Primary protocol sources are MASCOT [ePrint 2016/505](https://eprint.iacr.org/2016/505),
SoftSpokenOT [ePrint 2022/192](https://eprint.iacr.org/2022/192), the revised
SimplestOT report [ePrint 2015/267](https://eprint.iacr.org/2015/267), DDNNT
[ePrint 2015/1006](https://eprint.iacr.org/2015/1006), Smart--Talibi Alaoui
[ePrint 2019/768](https://eprint.iacr.org/2019/768), Ozdemir--Boneh
[ePrint 2021/1530](https://eprint.iacr.org/2021/1530), Groth
[ePrint 2016/260](https://eprint.iacr.org/2016/260), HMAC
[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104), and SHA-256
[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

### Local source snapshot, not a selection

The following hashes identify the mutable candidate source inspected for this
proposal. A future assumption preimage must replace this table with a complete
transitive manifest and an actual build/launch receipt.

| Source | SHA-256 |
|---|---|
| `mpc-prover/p1_capture_stream.cpp` | `05b24699db96d49b1be81b64ff28bc33079aa33507cccd981879b2fc7cd58f44` |
| `mpc-prover/p1_capture_seams.cpp` | `b4a560a5e887a501260dca23940f8c89aac121ab0b6e6fbfb191a02573d1139f` |
| `mpc-prover/p1_capturing_player.cpp` | `331645c02bc3c719d5ea3218f07ac7a17704adf66b8847c6fddac06ed2b4ea79` |
| `mpc-prover/p1_scalar_capture_manifest.hpp` | `1fa2e6c168804187b98d35a7d91bd3231fa506f6f23dc9a210ae9fe6c60dc7e8` |
| `mpc-prover/financial/query_msm_correspondence.hpp` | `ab59818aa9363030ef7d47adfe731e203348868155cd7c26f098a510a6dbb5f2` |
| `mpc-prover/auth_field.cpp` | `d4403dc830c4dd251e3cb0422bd58d37adff4fd53f3fb2a22df1c812dfa2ea2c` |
| `mpc-prover/owner_input_ddnnt.cpp` | `837f859356a674c0c38cb40ac313b0565a04d24f437db26df6b4ee44bcffb0cf` |
| `mpc-prover/owner_inputs_active.cpp` | `31808e2fb748ccee33bdb308451e0081b7c814dd45aa5d6ba0571fb56ee8d69d` |
| `mpc-prover/auth_groups.cpp` | `b6c4a9960c87ec4b46c4651623a9efb5b891315477d6f55bc0f6797417212400` |
| `mpc-prover/auth_groth16.cpp` | `a2909b32339dbb61a92155884b6d42dc944a2ad322b638a28043f9076e257a06` |
| `mpc-prover/financial/packed_groth16.cpp` | `17fc3d65f9a0685b047c7205189902b574e5d7826e04e4a4c0aef07c4677aa8f` |
| `mpc-prover/financial/financial_prover.cpp` | `846ee1ff701ef6f8c0ca028b9dcf62ea9b1ae356c5cb87d55042ba4b725a4073` |
| `private_batch_trial/privacy_capture_producer.py` | `7b2f50cb70e211202e2a788d11e05b045e592050fcd4defc5eea25833135de76` |
| `private_batch_trial/privacy_capture_model.py` | `26c135012ccff8b3ddeb66fda4c8d3dda7ccaa6e9e32d5351ac2af45fe3d01bf` |
| `private_batch_trial/c1_contact_value_authority.hpp` | `f683db1e226600a87148c2e8b4e2db087e1f12173f3f89f0ac47f7743c21b947` |
| `private_batch_trial/c1_contact_value_authority.cpp` | `8c19844215db9872c0adbf0a214ddf469637a757c5727d20becdd8ec7545e360` |
| `private_batch_trial/c1_capture_supervisor.py` | `0721fd59ccda4fa0de961f9b02a96075288d66b23b29dd4c931383346882f529` |
| `private_batch_trial/privacy_measurement_observer_capture_bridge.cpp` | `03e4618b8212b2a04576b11bab579898749c65f894e22ead0c8ab0c103d14dca` |
| `private_batch_trial/wallet_profile.py` | `4991baef65d13a91a7944f21bc7750b77c5776dc6f7c4d2c6844ca5b8f39e289` |
| `private_batch_trial/output_producer.py` | `e074f3a1f3cf68381c5809cc343c796810e3139c6b0e35ab8e683968712677e6` |
| `future-recipient/bridge/{Cargo.toml,Cargo.lock,src/main.rs}` | `285e32cfb7a2c394eb65b907937ff26390308334c59a707b7706161c0a443b4c`, `2d6cd25389016adc7eaaaa3e9af4121e9708f2355102f51bf7cedc89a0825d98`, `5fe1f3b9d678086dc7b4a7681642b90841395135b0135a4f07f876f740ee5829` |
| `relation/src/lib.rs` | `f93c2593444acd3936595e4e0d07cc680ff8ada05ce9f9c7dd5a47a387245b9e` |
| `private-batch-relation/src/gadgets.rs` | `a395e49d1d16860bcc1d874e344b4a381de2ed0b51ded6ff232c7830a6b9d978` |

The C03 source currently declares v9/17 semantics, a 496-byte footer,
instrumented mask `0x1ffff`, scalar-site bitmap `0x3fffff`, scalar manifest
`5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b`,
and query/MSM manifest
`7cd5956c8a30da0d9bf2e040b1d67b83ffd516a211aba8d08985c6ecdae13ace`.
These constants are direct correspondence inputs, not security assumptions.

There is no qualifying build receipt for this combined source. Retained
`.local/mpc-prover-build-16/BUILD-RESULT.json` has SHA-256
`8e9c60daaf76699e38f8bff83d6b69b75a851b759d92988e8e10e4252205cc61`
but binds the earlier capture source, not the current v9 closure. It is
ineligible for selection.

The selected aggregate setup source table has identity
`3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829`.
Its selected `circuit.rs` hash is
`a5e8f2d0332f342b4406d99c0a4b7f893933d2ddca8a5218907f3c27fa01e12b`,
whereas the mutable worktree file inspected now hashes to
`bae649e1c80fa82f5f1a22446197be7bfaa3b367ea21875e2a6384b98567c022`.
Current source table
`04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7`
now has a complete reproducible matrix receipt: all 13,093,029 rows and all
three compressed axes are byte-identical to the selected setup matrices. The
existing PK/VK therefore still cover the same mathematical relation. Their
setup provenance and toxic-waste handling remain insufficient for selection.

## Candidate assumptions

### S1-CM-SHA256

**Exact statement.** For
`CM = SHA256("KPX1NOT\\0" || domain || Note168)` and domain-separated SHA-256
tree nodes, binding is assumed under SHA-256 collision resistance. Hiding is
assumed only when the note's `rho` is independent uniform 256-bit randomness,
unknown conditional on the complete P1+C1+public auxiliary view, and SHA-256
acts as a hiding random-salt commitment for this fixed encoding.

**Applicability.** Exact fixed-width encoding, fresh non-reused `rho`, honest
owner producer, matching circuit/source closure, and no salt/key disclosure.
Collision resistance alone does not imply hiding.

**Direct/empirical remainder.** CM bytes, equality, append positions, paths,
roots, counts, history continuity, and repeated CM/NF relationships remain
direct. Low-entropy values become dictionary-testable if `rho` leaks.

### S2-CV-JOINT-HIDING

Let `CV(v,b)=vV+bR`. For owner `i`, the circuit enforces

```text
I_i - O_i0 - O_i1 = fee_i V + delta_i R
delta_i = b_i - r_i0 - r_i1 mod q.
```

The projection exposes nine CVs, total fee `F`, and
`Delta=sum(delta_i)`. **Exact statement:** conditional on independently uniform
honest blinds and the one public linear relation, the joint nine-CV
distribution is information-theoretically independent of which honest
value/owner partition is used among alternatives satisfying the same public
value-balance equation. After removing C1's known row, the remaining two-owner
equation stays partition-invariant.

This hiding statement does not require a computational discrete-log
assumption. It does require every honest blind to be uniform, secret, fresh,
and non-reused, including on retry. If individual honest `delta_i` plus its fee
mapping leaks, the observer can test

```text
I_a - O_b - O_c - fee_i V == delta_i R
```

and must use positive matches to prune candidates. Public canonical point
decode, the aggregate equation, and its zero pruning effect are direct.

### S3-CV-BINDING

**Exact statement.** The exact Baby-Jubjub prime-subgroup Pedersen commitment
is computationally binding under discrete-log hardness and absence of a known
scalar relation between the deterministic bases `V` and `R`.

**Applicability.** Exact Arkworks 0.6.0 generator transcript and subgroup,
canonical point decoding, nonzero prime-order bases, and proof soundness for
the exact circuits. The deterministic seed does not prove that no party knows
`log_R(V)`.

**Remainder.** This is a value-integrity assumption, not CV hiding and not a
claim that public CVs are independently harmless.

### S4-OUTPUT-GROTH16

The six Output proofs use Arkworks Groth16 0.6.0/BN254 and a statement binding
`domain || CM || CV || SHA256(ciphertext)`. The manifest pins source identity
`ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e`,
matrix `d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31`,
PK `1c2d02992ae89810b8a95ede7bf38aefd503f4984e7b82b27db452141752339a`,
and VK `8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119`.

**Exact statement.** The joint six-proof distribution reveals no witness
information beyond those six public statements and the complete frozen
auxiliary view, under Groth16 zero knowledge, soundness, an honestly generated
circuit-specific CRS whose toxic waste is unavailable, canonical subgroup
encodings, and fresh independent `OsRng` prover randomizers for every proof.

**Status/blocker.** `PRIVATE_OS_RNG_NOT_RETAINED` is not evidence of an honest
ceremony or toxic-waste erasure. Correlated multi-proof auxiliary-input ZK is
also an explicit applicability condition. This family is not selectable from
the present setup record.

**Remainder.** Proof bytes, positions, statements, verification outcomes,
CM/CV/ciphertext hashes, failure, and timing are direct. The circuit binds only
the ciphertext hash; it proves no encryption correctness.

### S5-CRYPTOBOX-CONFIDENTIALITY

The exact honest bridge emits
`ephemeral_X25519_pk32 || XSalsa20-Poly1305(ciphertext+tag)` using
RustCrypto `crypto_box` 0.9.1 sealed boxes. The 24-byte nonce is
`BLAKE2b-192(ephemeral_pk || recipient_pk)` and a fresh `OsRng` ephemeral
secret is sampled for each 216-byte receipt, yielding 264 bytes.

**Exact statement.** Honest receipt plaintext confidentiality and outsider
ciphertext integrity are assumed for this exact X25519/SalsaBox/BLAKE2b
construction with a valid honestly generated recipient public key, fresh
unpredictable non-reused ephemeral secret, secret uncompromised delivery key,
and no decryption side channel. This gives no sender authentication.

**Applicability.** Exact executable SHA-256
`6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff`,
the bridge source hashes above, admitted honest output-producer source, valid
X25519 key provenance, and no low-order/adversarial-key acceptance.

**Remainder.** C1's successful decryptions are direct knowledge. Ciphertext
bytes, hash, length, row, repeat/ephemeral-prefix equality, and failures remain
direct. A malicious producer can publish a tagged 264-byte string and still
prove the hash; `S5` applies only to the admitted honest producer.

### S6-CRYPTOBOX-RECIPIENT-PRIVACY

**Exact statement.** In the complete frozen auxiliary view, ciphertexts made
by the honest producer do not reveal which of the candidate honest recipient
public keys was used, beyond directory/contact/sender/C1 facts already modeled.

This is deliberately separate from `S5`: ordinary plaintext confidentiality
does not establish key privacy. The inspected RustCrypto source defines the
construction but supplies no reviewed theorem for this exact multi-key,
auxiliary-input claim. Stable delivery keys can be linked by a directory or
participating sender even though the projection omits them. Therefore `S6`
stays **unsupported/unselected** until a primary-source theorem or a narrower
protocol redesign removes the need for it.

### S6A-V3-HIDDEN-DELIVERY-PRF

This is a bounded V3 alternative to `S6`, never evidence for the V2 sealed-box
construction or for known-candidate-key anonymity. For a unique private invoice
index `i`, V3 derives

```text
delivery_secret_i = HMAC-SHA256(
    owner_seed,
    "KPBKDF01" || profile_id || domain || "DELIVERY" || u64le(i))
delivery_public_i = X25519-Public(delivery_secret_i).
```

**Exact statement.** Under multi-output HMAC-SHA256 PRF security with an
independent high-entropy honest owner seed and unique domain-separated indices,
the honest V3 delivery secrets may be replaced by independent uniform samples.
If native source authority additionally proves that their indices, public keys,
key hashes, directory identifiers, and ledger positions are absent from the
complete P1+C1+public view, then swapping the two honest-owner labels is an
exact renaming of hidden independent delivery-key samples. C1's and every
corrupt sender's genuinely issued/received invoice facts are fixed direct
auxiliary input and are never replaced.

**Applicability.** The authenticated owner ledger allocates every index once;
aborts and retries poison the old entry; the honest output producer accepts
only an opaque authenticated invoice authority; key derivation and X25519
public-key generation use the pinned source; and the actual two-round sealed
capture negatively inventories every forbidden key/index identifier. The
absence result must come from the source-owned native FD40-to-FD62 boundary,
not a caller list, Python object, count, or synthetic fixture.

**Remainder.** This family says nothing about ciphertext message security,
known-key recipient privacy, malicious producers, senders that saw the invoice,
directory/network privacy, timing, order, retry metadata, or recovery. `S5`
still covers honest-message confidentiality. Public ciphertext bytes and all
direct metadata remain in the finite candidate filters. The complete private
ledger is required for V3 recovery.

### S7-NF-HMAC-PRF

The exact construction is:

```text
k_i = HMAC-SHA256(owner_seed,
      "KPBKDF01" || profile_id || domain || "NULKEY01" || u64le(index))
NF  = HMAC-SHA256(k_i,
      "KPX1NF\\0\\0" || domain || CM || u32le(global_position))
K   = SHA256("KPX1KEY\\0" || domain || k_i).
```

**Exact statement.** For an honest owner, NF is pseudorandom and
computationally unlinkable to its source CM, position, and owner under
multi-user HMAC-SHA256 PRF security, domain-separated HMAC key derivation from
a secret high-entropy owner seed, SHA-256 preimage resistance for exposed `K`,
and absence of `k_i`/seed from the complete observer view.

**Applicability.** Distinct honest seeds, exact role/profile/domain/index
separation, exact Rust/Python/circuit message equality, and no key compromise.
The exact selected circuit must prove the private key/CM/position/public-NF
relation.

**Remainder.** NF equality is intentionally visible. Reusing the same
`(k,domain,CM,position)` on retry gives the same NF. Sorted order,
predecessor/successor values and insertion indices, paths, and the entire NF
history graph remain direct. C1's NF key and own rows are auxiliary input.

### S8-MASCOT-OT

**Exact statement.** The pinned SimplestOT_C `ref10` -> malicious libOTe
SoftSpoken/VOLE -> MP-SPDZ MASCOT stack securely realizes the ROT/VOLE and
authenticated-arithmetic hybrids needed by MASCOT for the selected
three-party BN254-Fr configuration, against one static corrupt computing party
with abort.

This is an admitted composition assumption, not a theorem conclusion. MASCOT
Theorems 2--5 cover the arithmetic protocol in their hybrids. SoftSpoken
Theorem 5.1 covers its protocol in its malicious-VOLE-pre hybrid. Revised
SimplestOT expressly withdrew its former UC claim. No inspected primary source
proves this exact base-OT -> extension -> MP-SPDZ composition.

**Applicability.** Exact commits/configuration (`USE_KOS=0`,
`USE_LIBOTE2=1`, `NO_AVX_OT`), fresh one-use preprocessing, correct field and
security parameters, authenticated channels, correlation/sacrifice/MAC/
broadcast checks, fresh MAC lifecycle, and no retry-state resumption.

**Coverage.** Joint recognized scalar shares/MACs, alpha share, MASCOT
randoms/input tuples/triples, stock masked openings, MAC-check state, and
precisely attributed OT/preprocessing/field traffic. It does not cover custom
owner/group logic, metadata, internal random-tape capture, or unknown peer
frames.

### S9-DDNNT-5N

**Exact statement.** For each field, servers give the owner additive shares of
fresh `(s,r,w,v,u)` with `w=s*r` and `u=v*r`; the owner checks both equations,
sends common `d=x-s`, servers agree on identical canonical `d`, and derive
`[x]=[s]+d`. Conditional on `S8`, DDNNT Section 3.1/Figures 1--2/Lemma 1 gives
input security with undetected alteration probability at most `1/p` and
explicit abort.

**Applicability.** One independent tuple per field; exact field-major
`s,r,w,v,u` order; value shares only to owners; exact `5N`/`N` framing; both
checks before `d`; authenticated role-bound TLS; common-byte agreement before
decode; and poisoning/fresh attempt on malformed, partial, replayed,
disagreeing, or failed exchange.

**Remainder.** C1's own tuple shares, chosen input, `d`, decisions, and aborts
are explicit auxiliary input. The removed three-value adapter and unselected
stock-additive proposal receive no coverage.

### S10-AUTHENTICATED-GROUPS

**Exact statement.** The pinned custom `AuthG1`/`AuthG2` representation,
linear operations, `Direct_MC`-style group MAC check, agreement/broadcast, and
checked opening correctly realize authenticated prime-order group sharing
under the same secret scalar MAC key used by the admitted SPDZ field state,
with abort against one static corrupt computing party.

This is a source-grounded assumption. MP-SPDZ's scalar theorem does not
automatically cover the custom group implementation. Smart--Talibi Alaoui's
SPDZ-offline group functionality supports the design, but exact G2 linear
state, local encoding, and opener correspondence remain part of the local
source preimage.

**Applicability.** Canonical on-curve subgroup-checked BN254 points, Fr equal
to the group order, exact share/MAC algebra, fresh context/generation/epoch,
all pending scalar and group checks, and no untyped generic final opener when
capture is attached.

**Remainder.** Typed BASE/MIXED/PRODUCTS/FINAL state and direct share/MAC
equations can be recomputed. Worker/MSM residue and physical copies are not
thereby captured or harmless.

### S11-MIXED-SCALAR-GROUP

For each `x*Q`, the implementation takes a fresh field triple `(a,b,c=ab)`,
sets `U=aG`, `V=cG`, opens `D=Q-U` and `e=x-b`, then derives
`V+eU+bD+eD=xQ`. Two independent triples compute `s*A` and `r*B1_base`.

**Exact statement.** Conditional on `S8` and `S10`, the two products realize
the Smart--Talibi Alaoui Figure-9 scalar/group multiplication functionality
and their masked scalar/G1 openings disclose no more than the functionality
and abort, under Theorem 2's prime-order/SPDZ-offline conditions.

**Applicability.** Two fresh independent one-use triples, exact local label
mapping, canonical points/scalars, checked scalar and group openings, and
context poisoning on failure. Direct equations `D=Q-U` and the captured
Beaver/product relations are correspondence checks, not substitutes for
triple validity or protocol security.

### S12-AGGREGATE-GROTH16

The selected candidate pins aggregate source identity
`3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829`,
matrix `c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab`,
canonical PK `170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945`,
compressed PK `4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff`,
VK `2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102`,
and independent verifier
`c1805cfe7ae9b2db7d58fd58727b57e92a0fec866506cd720fbd59242359131f`.

**Exact statement.** Conditional on `S8`, `S10`, and `S11`, the exact
Ozdemir--Boneh Appendix-E decomposition constructs only the standard
three-element Groth16 proof `(A,B2,C)` with fresh authenticated `r,s`; its
joint distribution reveals no witness information beyond the exact public
statement and frozen auxiliary view under Groth16 ZK, soundness, and an honest
CRS whose toxic waste is unavailable. Raw auxiliary `B1` is never opened.

**Status/blocker.** The aggregate setup calls itself a fresh local research
setup, not a ceremony; `role_manifest_selected=false`; registered selection is
`UNCONFIGURED_BLOCKED`. Current source table
`04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7`
regenerated all 13,093,029 rows and complete A/B/C artifacts byte-identical to
the setup matrix, so source drift is no longer a rebuild blocker. Setup
integrity/toxic-waste handling and runtime selection remain unresolved. This
family is not selectable.

**Remainder.** Literal `A,B2,C` equality, independent verification, and the
captured equations are direct. Query/MSM source correspondence must be exact;
local callback timing and uncaptured process residue stay empirical or outside
scope.

### S13-JOINT-AUXILIARY-COMPOSITION

**Status: NON-SELECTABLE RESEARCH HYPOTHESIS.**

**Exact statement.** Conditional on every actually used family among
`S1`--`S5` and `S7`--`S12`, plus exactly one of `S6` or `S6A`, the joint nonliteral
cryptographic payload distribution of the
exact public projection, C1 auxiliary view, and admitted P1 application-level
capture is indistinguishable between two fresh, source-valid executions of the
fixed `W0` and rewired `W1` workloads, with the same noncryptographic workload,
corrupt-input/C1 semantics, source schedule, dimensions and direct leakage
class, except for the explicit direct and empirically measured leakage ledger.
The concrete public cryptographic statements and descendant bytes need not be
identical and normally are not.

No inspected primary source proves this exact composition of correlated note
commitments/CVs/ciphertexts/NFs, seven correlated Groth16 proofs, DDNNT,
MASCOT, authenticated groups, mixed products, aborts, and the C1 auxiliary
view. The statement is effectively the target privacy claim. Selecting its
digest would be circular and is forbidden.

The only admissible route to this conclusion is a concrete hybrid/composition
argument. It must replace the real joint distribution one step at a time,
reduce every step to a selected member of `S1`--`S5`, `S7`--`S12`, and the
selected `S6`/`S6A` path, recompute and track every affected public descendant,
keep C1 semantics fixed or expose differences as direct leakage, and separately
retain the actual metadata candidate tests. Any uncovered transition remains an
unmodeled blocker; it cannot be discharged by naming `S13`.

### Concrete bounded-V3 hybrid schedule

The former `H0`--`H20` label-swap schedule is **invalid**. Its `H11` changed
owner names but did not establish the acceptance gate's required change to the
honest NF-to-physical-created-pair graph. It also treated `M1` as a second
witness/opening of the realized `M0` cryptographic bytes. Commitment,
nullifier, CV, ciphertext and proof binding generally makes that impossible.

The repaired target compares two freshly sampled world distributions. `W0` is
the frozen real workload. For each round write its three private input notes as
`I0,I1,I2`, and its creator-indexed payment/change outputs as
`P0,C0,P1,C1,P2,C2`. The real relation is
`I0->{P0,C0}`, `I1->{P1,C1}`, `I2->{P2,C2}`. `W1` is fixed before observation:
swap the honest input associations `I0<->I2` and independently swap only the
honest change associations `C0<->C2`; do not swap `P0/P2`, and leave every
owner-1 association fixed. Relative to the original public slots its relation
is therefore `I0->{P2,C0}`, `I1->{P1,C1}`, `I2->{P0,C2}`. Thus both honest NF
edges reach a different physical created pair while the colluder-created and
colluder-received payment edges remain fixed. This is a graph rewire, not a
label permutation.

`W1` is only eligible if a private pre-observation commitment fixes the exact
source, workload, relation, matrix, leakage class and coupling rule, and a
post-barrier source-owned check proves a valid closed witness for that fixed
choice without releasing it. In the present workload
the two honest inputs and payments are equal within each round
(`2,000,000,000` and `500,000,000` sompi in round 1; `500,000,000` and
`200,000,000` sompi in round 2), fees are common, and changes are consequently
equal. Round 2 must also prove the two honest inputs select their received
outputs, while owner 1's fixed input selects its change. Every owner must still
satisfy `input = payment + change + fee`, all ranges, source constraints and
the complete relation. Structural candidate survival is not witness
feasibility and cannot substitute for this check.

The isolated authority added with this schedule deliberately stops short of
that claim. It precommits the exact identities and fixed transform, then checks
two-round arithmetic/selection shape and four-view different-pair survival.
Those checks mint only `CounterfactualArithmeticShapeAuthority`. A production
`CounterfactualFeasibilityAuthority` additionally requires a move-only
`CounterfactualJointClosureAuthority`. It can only follow the linear sequence
`LiveCounterfactualSourceInstanceAuthority ->
FullW1WithCloseResidualAuthority -> CounterfactualJointClosureAuthority`: the
first transition consumes one source-owned instance containing the selected W0
truth, authenticated C1 facts, accepted history, complete W1 witness and the
sole runtime-`Close` residual; the second checks all exact descendants and
retains both closures. Independent arms with matching caller bytes are not an
eligible join. The isolated C++ controls now exercise that one-shot sequence,
binding mismatches and replays, but no production source minter, Rust-to-C++
adapter, runtime-`Close` provider, selected callsite or complete retained W1
fixture exists. Configuration therefore remains false, and source hashes,
manifests, enums or booleans cannot replace those authorities.

The Rust side now has a separately pinned typed bridge whose only accepted
input is `FullW1SourceInstanceAuthority` and whose only successful output is a
non-cloneable `FullW1WitnessClosure`; byte strings, paths, manifests, digests
and caller booleans have no constructor or overload. This closes the API-shape
problem only. No live source minter has produced that input, no complete fixture
has exercised the 13,093,029-row verifier, and no C++ bridge consumes the Rust
closure. Those two status fields remain false. The exact next callsite is the
future atomic W0+C1+accepted-lineage owner, which must move the typed Rust
closure into the same linear residual that carries the sole runtime-`Close`
source. The current C++ control token is not that callsite or evidence.

For any hidden-object replacement, `Close(X)` means reconstruct **every**
dependent descendant from `X`: both rounds' CM/NF trees, sorted NF rows and
paths; CM rows and paths; CVs and public delta; ciphertexts and hashes; all
affected Output statements/proofs; `Effects10364`, its digest and aggregate
statement/proof; the round-2 context; both C03 `FINAL` copies; and all
projection, dispatcher, terminal, archive and capture hashes. A hybrid may not
retain a descendant byte from the previous world after changing an ancestor.
In particular, simulated Output and aggregate proofs are recomputed whenever a
later CM, CV, NF, ciphertext or context hybrid changes their statements.

Subject to that rule, the exact proof obligation is:

1. `G0 = Real(W0)`.
2. `G1` jointly simulates both rounds' complete admitted corrupt-P1 MPC view
   and aggregate proofs for the current statements, while preserving all
   explicit C1 semantics, declared metadata and abort outcome. This is one
   joint transition, not independently swappable protocol fragments.
3. `G2` simulates the eight honest-creator Output proofs across the two rounds
   under `S4`; the four owner-1-created proofs remain real.
4. `G3` is one multi-domain HMAC PRF game over the shared hidden seed, with the
   exact nullifier and delivery-key domain separators and all adaptive queries
   in one transcript. It jointly idealizes the outputs used by `S7` and `S6A`;
   citing those two statements separately is not a joint reduction.
5. `G4` replaces only honest-hidden Note commitments with canonical
   equal-value dummy commitments under `S1`; owner-1-known/direct notes remain
   real. Apply `Close`.
6. `G5` replaces the honest CV blind vector by the `S2` affine-space
   distribution conditioned on the exact aggregate equation and owner-1
   subtraction. Apply `Close`.
7. `G6` replaces only C1-unknown honest `Receipt216` plaintexts with a fixed
   equal-length dummy under `S5`, using fresh producer ephemerals. C1-created or
   C1-decrypted receipts remain real. Apply `Close`.
8. `G7` applies the fixed input-and-change graph rewire above to the remaining
   ideal honest objects. The public ordered ideal samples may be coupled
   unchanged at this midpoint, but the private relation edges must change and
   the complete closed witness must remain source-valid.
9. `G8` restores the honest receipt/ciphertext distribution under `W1` (`S5`),
   then applies `Close`.
10. `G9` restores the joint honest CV distribution under `W1` (`S2`), then
    applies `Close`.
11. `G10` restores honest Note commitments under `W1` (`S1`), then applies
    `Close`.
12. `G11` restores the joint honest HMAC-derived NF/delivery-key distribution
    under `W1` (`S7` plus `S6A`), then applies `Close`.
13. `G12` restores the eight honest-creator Output proofs under `W1` (`S4`).
14. `G13` restores the joint two-round corrupt-P1 MPC view and aggregate proofs,
    yielding `Real(W1)`.

The endpoints are distributions of two fresh executions. They share the exact
noncryptographic workload, source program, dimensions, public format and direct
leakage class, but their concrete CMs, NFs, CVs, ciphertexts, proof statements,
proofs and descendant hashes normally differ. Actual candidate survival is
separate empirical evidence; it is not proof that `W1` opens the realized
`W0` bytes.

The comparison is over the full joint distributions, including aborts. Any
conditional claim must name a prospectively frozen, efficiently recognizable
event having non-negligible probability in **both** worlds and account for its
probability loss. Conditioning on an exact nanosecond trace, exact full
projection, successful candidate survival observed after the run, or any
negligible realized transcript is forbidden.

The source sorts six output keys sampled from 128-bit domains per round. The
probability of any output-sort collision is at most `C(6,2)/2^128 = 15/2^128`
per round and `30/2^128` over two rounds. The fixed original-index minor key
still makes the implementation's total order unique; this bound is the loss in
any coupling that treats the random 128-bit major keys as distinct, not a retry
event. NF sorting is a deterministic close descendant and must be regenerated,
not held fixed. Any additional collision or rejection event needs its own bound
and conditioning treatment.

`S1`, `S2`, `S5`, `S7`, `S6A`, `S4` and `S12` do not by themselves justify
`G1/G13`: DDNNT, MASCOT, authenticated groups, mixed products, correlations,
aborts and aggregate-proof randomizers share state. The ledger must either
strengthen `S8`--`S11` with a reviewed sequential-composition reduction for
this exact two-round program and then apply exact `S12` to the resulting
aggregate statements, or state one narrow, noncircular, non-selectable
`S14-KPB-MPC-JOINT-REALIZATION` assumption. The minimal `S14` says only that the
exact frozen DDNNT/MASCOT/AuthG1/AuthG2/mixed implementation realizes the
value-valid batch ideal functionality against static corrupt P1 plus passive
C1, exposing only the public effect, C1 semantics, declared metadata and abort;
`S12` is still separately required for aggregate-proof simulation. If `S14`
also covers Appendix-E proof generation, its statement must explicitly include
the exact `S12` CRS, auxiliary-input and randomizer conditions and the joint
proof distribution. In either form `S14` must not assert target mapping privacy
or candidate survival. No assumption is selected here, so the chain currently
stops at `G1`.

It cannot cover:

- timing, size, sequence, direction, peer, fork, abort/retry or partial-tail
  effects;
- C1-known contact/value/decryption relationships or participating-sender
  knowledge;
- public row/history/path/order/equality relationships;
- malformed or adversarial honest-output-source violations; or
- uncaptured random tape, arbitrary-host state, or covert/network-stack
  channels.

## Direct and empirical admission ledger

| View family | Required non-assumption treatment | Fail-closed condition |
|---|---|---|
| Public fixed fields and history | Direct parse/equality/algebra constraints; recompute all four candidate lattices | Any omitted lane, noncanonical point/scalar, or missing continuity source |
| Public CVs | Direct nine-point parse, total fee/delta, aggregate equation, corrupt-C1 subtraction; individual-delta candidate test if such data exists | Treating nine CVs independently or calling the aggregate equation mapping evidence |
| Public CM/NF paths | Direct positions, paths, roots, counts, sorted NF graph and cross-round edges | Collapsing to a generic commitment count |
| Public ciphertexts | Direct bytes/hash/row/length/repeat checks; `S5` plus the selected `S6` or `S6A` path only for their stated nonliteral claims | Honest producer/key provenance absent; V3 key-absence authority missing; encryption correctness inferred from Output proof |
| Public proofs | Direct statement/position/byte/verification checks | CRS/source/matrix/key mismatch or unverified proof |
| C1 v2 | Consume both move-only postcapture residuals plus producer closure; apply contacts and amounts to candidate filtering | Legacy v1, caller JSON, missing live authority, or a known value relabeled harmless |
| C03 v9 literal view | Exact 17-lane/HELLO/footer/scalar/query/group/source/role grammar and directly recomputed equations | Unknown site/frame, missing footer byte, unmatched typed lane, or stale build receipt |
| C03 metadata | Frozen actual-run structural joins and symmetric timing-distance/rank/length/peer/fork/retry/partial-tail tests | Missing field/clock domain/coverage, zero or ambiguous joins called positive evidence, synthetic calibration used for admission |
| Cross-view lattice | Derive candidates independently from ten typed leaves, use positive authenticated joins to prune, retain ambiguity, require zero missing/unmodeled categories | Caller-supplied candidates/events/truth, self-join/copied P1 event, or incomplete four-view bridge |

Cryptographic assumption selection never closes a mapping-dependent direct
row. For example, qualified C1 values close only when they actually filter the
candidate lattice and the surviving privacy result is measured.

## Selection preimage and stop rules

Each future selected entry must contain:

1. exact family ID/version and canonical statement digest;
2. paper/spec revision and exact theorem/figure/section, or the explicit words
   `ADMITTED_COMPOSITION_ASSUMPTION_NOT_A_THEOREM`;
3. upstream commits/crate checksums and every transitive local source hash;
4. compiler flags, linked objects/libraries, binary/build digest, sealed
   runtime/launcher/assets/role identities, and actual two-round receipt;
5. exact covered ledger paths and dependencies, never a generic category;
6. corruption, auxiliary-input, freshness, channel, check, abort, retry, CRS,
   key, and randomness conditions;
7. explicit exclusions and direct/empirical rows that remain; and
8. a one-shot authority binding the assumption preimage to the exact sealed
   model/query/projection artifacts before truth is available.

Selection must stop if any of these holds:

- the selected profile still needs unsupported `S6`, or V3's `S6A` PRF,
  one-use ledger, honest-producer, and native key-absence conditions are not
  all closed;
- Output or aggregate CRS provenance/toxic-waste conditions are unresolved;
- the aggregate circuit/matrix/PK/VK/source hashes do not form one exact
  reproducible closure;
- the SimplestOT_C -> SoftSpoken -> MASCOT composition is neither explicitly
  admitted as `S8` nor replaced by a source-closed proven stack;
- C1 v2 authority is absent, a C03 v9 field lacks a direct/empirical rule, or
  actual candidate pruning has incomplete coverage;
- retry freshness or honest-output producer provenance is not authenticated;
  or
- any family is selected merely because a unit test, proof verification, or
  synthetic classifier passed.

`S13` is never an assumption-selection candidate. It remains a research
hypothesis until the concrete reduction above exists.

## Actionable blocker classes

| Blocker class | Families/rows | Required action | Selection effect |
|---|---|---|---|
| Exact runtime freshness and source closure | `S1`, `S2`, `S3`, `S5`, `S7`, `S8`, `S9`, `S10`, `S11` | Freeze a complete transitive source/build/runtime/launch preimage; authenticate honest producer and randomness provenance; prove fresh, independent, one-use salts/blinds/ephemerals/tuples/triples/contexts across both trials and every retry; close C03 v9 and C1 v2 authorities | Potentially selectable only after exact applicability controls pass. `S8` must still say explicitly that base-OT composition is an admitted assumption, not a theorem. |
| CRS provenance or reviewed ceremony | `S4` Output Groth16; `S12` aggregate Groth16 | Produce circuit-specific source->matrix->PK/VK receipts, reviewed setup/ceremony and toxic-waste-handling evidence. `S12` current-source matrix equivalence is complete; bind that closure plus collaborative randomizer provenance to a newly eligible setup | Not selectable from the current `PRIVATE_OS_RNG_NOT_RETAINED` or research-only setup records |
| Primary theorem or protocol redesign | `S6` recipient-key privacy | Either supply a reviewed primary-source key-privacy result matching the exact multi-key construction and auxiliary view, or redesign output encryption/routing around an established recipient-anonymous/key-private construction while directly modeling sender/directory facts | Non-selectable today |
| Bounded hidden-key replacement | `S6A` V3 delivery-key PRF | Bind the exact HMAC derivation and one-use ledger source, honest producer, retry poisoning, and native negative inventory of every key/index/hash/directory identifier; keep C1/corrupt-sender facts direct | Potentially selectable only for the exact ADR-0092 bounded observer; never a known-key or production anonymity claim |
| Circular target claim | `S13` | Write and review a concrete hybrid argument reducing every transition to selected `S1`--`S12` plus exact direct auxiliary facts; retain metadata empirical tests outside the hybrids | `S13` itself is never selectable; a missing hybrid leaves the final privacy result unqualified |
| Direct or empirical leakage | Public/C1/C03 literal constraints; timing/length/order/peer/fork/abort/retry/partial tails | Complete the four-view candidate lattice and actual-run positive joins; missing or ambiguous evidence retains candidates or unqualifies | Never selectable as a cryptographic assumption |

Under the present evidence, `S4`, the applicable `S6`/`S6A` path, the joint
multi-domain HMAC reduction, `S8`--`S12`, and either the exact composition proof
or narrowly scoped `S14` remain unresolved. The repaired `G0`--`G13` proof plan
and an isolated control-only counterfactual arithmetic-shape authority now
exist, but full W1 relation/descendant closure, a selected assumption preimage,
and a production callsite do not. No edge may be skipped. The honest conclusion
is therefore a source-closed proposal
for a **conditional bounded observer**, not a privacy qualification or
production-security claim.

## Companion evidence

- [Corrupt-P1 finite source-assumption ledger](corrupt-p1-finite-source-assumption-ledger-2026-10-29.md)
- [Public CV joint-leakage analysis](public-cv-joint-leakage-analysis-2026-10-29.md)
- [Public projection raw-lane/history evidence](public-projection-raw-lane-linkage-evidence-2026-10-29.md)
- [Public commitment/Groth16 assumption evidence](public-view-commitment-groth16-assumption-evidence-2026-10-29.md)
- [ADR-0088 passive pinned-P1 observer scope](../docs/adr/0088-passive-pinned-p1-empirical-observer-scope.md)
- [ADR-0089 authenticated C1 contact/value capture](../docs/adr/0089-authenticated-c1-contact-value-capture.md)

