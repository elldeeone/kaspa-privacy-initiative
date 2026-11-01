# S4/S12 CRS and S6 recipient-key privacy remediation decision

- Date: 2026-10-29
- Repository baseline: `b58de1a182347c4223ebe84f92bb0bdd6c88d003`
- Status: primary-source design decision; **no source assumption is selected**

## Decision

1. **S4/S12, bounded Testnet observer:** a fresh, source-closed, one-party
   Groth16 setup may be admitted only under the explicit assumption that the
   dedicated setup process honestly follows `Setup`, samples uncompromised
   randomness, never exposes it to the frozen passive P1+C1 observer, and
   erases it. This is a selectable *trusted-setup assumption* for the exact
   bounded experiment after the exact current matrices are reproduced and the
   setup receipt is complete. It is not ceremony evidence, trust minimization, or a
   production claim. The current local setups remain ineligible.
2. **S4/S12, production:** keep Groth16, but replace local research setup with
   two separately verified circuit-specific Phase-2 MPC ceremonies rooted in
   one verified BN254 Phase-1 transcript. Freeze and reproduce the exact Output
   and aggregate matrices first. The smallest credible implementation path is
   pinned `snarkjs` plus strict Arkworks/mcl conversion controls; gnark is an
   independent implementation candidate, not a second ceremony requirement.
3. **S6, bounded observer:** choose the one-use hidden-invoice-key design for
   the next bounded experiment. Replace the domain-stable delivery key with a
   different one-use key for every output invoice, keep every honest key and key
   identifier inside the authenticated private invoice/backup plane, and model
   C1's own invoice, contact, accepted payment, and decryption facts directly.
   This removes the *known candidate public key* question from the exact bounded
   P1+C1+public view. It requires an authenticated private recovery ledger and
   does not prove general recipient anonymity.
4. **S6, same-width recoverable candidate:** prefer a versioned 264-byte
   DHAES-shaped profile for the product direction: fresh X25519 ephemeral key,
   `BLAKE2b-256(shared_secret || epk)` with a profile-specific personalization,
   and IETF ChaCha20-Poly1305 with empty AD and the all-zero nonce. This preserves
   the current stable private delivery key and seed-only trial decryption. It is
   structurally aligned with Zcash, but **not selectable yet**: the inspected
   anonymity theorem does not directly cover X25519's group/encoding, the
   `epk`-indexed KDF, or a single-key AEAD in place of DHIES's separate
   encryption and strongly unforgeable MAC.
5. **S6, exact established fallback:** if that proof obligation cannot be
   closed, use the larger Sapling/Orchard pattern: an incoming viewing key,
   diversified addresses, fresh ephemeral key agreement, trial decryption, and
   commitment-consistency checks. That is a new wallet/note/wire/circuit
   profile, not a label for the current NaCl sealed box.

Current `crypto_box` therefore **does not map rigorously** to the Zcash
recipient-key-privacy requirement. It may remain the exact S5
message-confidentiality component in the bounded one-use-key experiment, but it
must not be cited for S6. The DHAES-shaped replacement narrows the proof gap; it
does not by itself close it.

## Exact evidence snapshot

The finite assumption proposal is
[the combined P1+C1+public ledger](combined-p1-c1-public-finite-assumption-ledger-2026-10-29.md).
Its SHA-256 at this review point is
`8f033672ec35072a2b968ea938b3896b1e7b72caddbf92c34366990d56a836d4`.
`SELECTED_SOURCE_ASSUMPTIONS` remains empty.

### Current Groth16 artifacts

| Family | Circuit/matrix closure | Key closure | Setup evidence |
|---|---|---|---|
| S4 Output | source `ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e`; matrix `d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31`; 217,807 constraints | PK `1c2d02992ae89810b8a95ede7bf38aefd503f4984e7b82b27db452141752339a`; VK `8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119` | `PRIVATE_OS_RNG_NOT_RETAINED` |
| S12 aggregate | selected source table `3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829`; current source table `04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7`; both produce matrix `c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab`; 13,093,029 constraints | PK `170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945`; VK `2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102` | Complete current A/B/C matrices are byte-identical to the setup matrices; `FRESH_LOCAL_RESEARCH_SETUP_NOT_CEREMONY_OR_FINANCIAL_ACCEPTANCE`; role manifest unselected |

The changed aggregate source is now fully reconciled. A fresh synthesis from
the 48-entry current source table regenerated all 13,093,029 rows; its complete
A/B/C gzip artifacts are byte-for-byte identical to the setup matrices and
retain fingerprint
`c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab`.
See `current-matrix-equivalence-2026-10-29.json`. This removes matrix/key
invalidation due solely to those source edits. It does not improve setup
integrity or toxic-waste evidence, and registration remains
`UNCONFIGURED_BLOCKED`.

### Current delivery construction

The selected bridge is RustCrypto `crypto_box` 0.9.1 at upstream commit
[`91078b60b1cacf674885c1dc86bd00b97adaf828`](https://github.com/RustCrypto/nacl-compat/tree/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box),
crate checksum
`16182b4f39a82ec8a6851155cc4c0cda3065bb1db33651726a29e1951de0f009`.
Its sealed-box path generates an ephemeral X25519 key, prefixes the ephemeral
public key, derives a 24-byte BLAKE2b nonce from
`ephemeral_pk || recipient_pk`, and encrypts with `SalsaBox`
([`public_key.rs`](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/src/public_key.rs#L47-L68),
[`lib.rs`](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/src/lib.rs#L235-L318)).
The selected bridge's exact 264-byte layout is
`ephemeral_pk32 || poly1305_tag16 || encrypted_receipt216`; RustCrypto's
`SecretBox::encrypt_in_place` prepends the tag. This order matters when
versioning the replacement profile.
The pinned local bridge executable is
`6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff`.

The stable key is explicit in both implementations:

```text
poc/future-recipient/v2/recipient.py:206
    delivery = derive(seed, domain, "DELIVERY", 0)

poc/local-private-payment/private_batch_trial/wallet_profile.py:204
    delivery = derive(seed, profile, "DELIVERY", 0)
```

The current scanner relies on that stability: it decrypts first, learns the
private random invoice index from the plaintext, and only then reconstructs the
invoice (`wallet_profile.py:227-233`, `recovery/history.py:126-147`).

## S6: what the primary sources prove

### Bellare et al. does not prove the current sealed box

Bellare, Boldyreva, Desai, and Pointcheval define IK-CPA/IK-CCA key privacy as
an adversary receiving two known public keys and a challenge ciphertext, then
guessing which key encrypted it
([Definition 1](https://www.di.ens.fr/users/pointche/Documents/Papers/2001_asiacryptC.pdf#page=6)).
They explicitly warn that even IND-CCA message privacy does not imply key
privacy because a ciphertext can reveal its public key. Their Theorem 4 proves
IK-CPA for prime-order-group ElGamal under DDH; their Cramer-Shoup result covers
IK-CCA under its own construction and assumptions
([paper, Sections 1.3 and 3.1](https://www.di.ens.fr/users/pointche/Documents/Papers/2001_asiacryptC.pdf#page=3)).

The current scheme is neither of those schemes. It is X25519 plus
SalsaBox/XSalsa20-Poly1305 and a recipient-key-dependent nonce. The inspected
RustCrypto source supplies an implementation, not a reduction from its
sealed-box construction to BBDP's IK game. Consequently:

- S5 confidentiality cannot be relabelled S6 key privacy;
- the library description “anonymously send messages” is not a theorem; and
- no BBDP theorem applies merely because the construction uses Diffie-Hellman.

### Zcash is the relevant established design, but not the current design

The current Zcash Protocol Specification is revision
[`2bdf39494320e5e04057ac93b1794031ebfb00b5`](https://github.com/zcash/zips/tree/2bdf39494320e5e04057ac93b1794031ebfb00b5),
identified in the PDF as `v2026.7.0-344-g2bdf39`. It requires the composed
Sapling/Orchard key-agreement, KDF, and authenticated-encryption scheme to be
both IND-CCA2-secure and key-private in the BBDP sense
([§4.1.6](https://zips.z.cash/protocol/protocol.pdf#abstractkdf)).

Its exact recipient path differs materially from the KPB path:

- each output uses a fresh ephemeral secret/public key;
- encryption uses `sharedSecret = KA.Agree(esk, pk_d)` and a KDF of the shared
  secret plus the encoded ephemeral key;
- an incoming viewing key trial-decrypts every public ephemeral key;
- the decrypted diversified address and note must agree with the public note
  commitment; and
- the transmitted note ciphertext has an outgoing-ciphertext component as well
  as `epk` and the recipient ciphertext
  ([§4.20.1-4.20.3](https://zips.z.cash/protocol/protocol.pdf#saplingandorchardencrypt)).

Section 8.7 is directly cautionary for this review. It says generic ECIES has
many variants, key privacy can fail for unsuitable curve/key distributions,
and passing a recipient public key into a KDF can in principle compromise key
privacy even when confidentiality remains intact
([§8.7](https://zips.z.cash/protocol/protocol.pdf#inbandrationale)). It also
ties resistance to partitioning-oracle attacks to checking the decrypted note
against the note commitment.

The reviewed implementation pins are:

| Source | Pin | Relevant surface |
|---|---|---|
| Zcash Orchard | [`616a669df8c9a59c33d47064d3ce04b25d026b2e`](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs) | `OrchardDomain`, diversified key agreement, plaintext/commitment validation, trial decryption |
| `zcash_note_encryption` | 0.5.1, commit [`b646773328bf97cbbeeb92f7affaeb91541119ea`](https://github.com/zcash/zcash_note_encryption/blob/b646773328bf97cbbeeb92f7affaeb91541119ea/src/lib.rs), crate checksum `4812d133908ebf1a1c91d2411a109f63a863a152633db1fc7fbb0f774edeae30` | generic `Domain`, one-note ephemeral-key discipline, ChaCha20-Poly1305, full and batched trial decryption |

Implementing the generic `Domain` trait with KPB-specific curves, note fields,
or validation would reuse code but would not automatically inherit the Zcash
security requirement. Exact applicability requires either the exact
Sapling/Orchard domain or a reviewed reduction for every changed component.

### What the DHIES anonymity theorem actually covers

Abdalla, Bellare, and Neven's *Robust Encryption* proves recipient anonymity
for one exact DHIES family
([ePrint 2008/440, Figure 18 and Theorem 6.2](https://eprint.iacr.org/2008/440)).
The theorem uses a prime-order group `G`, `H : G -> {0,1}^(kSE+kM)`, a separate
symmetric encryption key, and a separate strongly unforgeable MAC key. Under
the double Oracle Diffie-Hellman assumption (reduced there to ODH) and MAC
strong unforgeability, the DHIES ciphertext `(R, gamma, tag)` is ANO-CCA for
the equal-message recipient-key game. The older Abdalla--Bellare--Rogaway
[DHIES analysis](https://www.cs.ucdavis.edu/~rogaway/papers/dhies.html) proves
message privacy, not recipient anonymity; it also assumes a prime-order group
and says that, for a non-prime-order group, the ephemeral group element should
be included in the hash input.

This is real evidence for the architecture, but not a proof of the proposed
KPB instantiation. The remaining gaps are exact and finite:

| Proposed component | Primary-source match | Unclosed proof obligation |
|---|---|---|
| X25519 shared secret | Same DH pattern; [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) defines clamped scalar multiplication | The theorem's `G` is prime-order with group elements. X25519 exposes Montgomery `u` encodings over a cofactor curve, accepts non-canonical inputs, and has equivalent/small-order cases. A representation/subgroup reduction is missing. |
| `BLAKE2b-256(shared || epk)` | Sapling and Orchard use personalized BLAKE2b-256 over exactly the encoded shared secret followed by `epk`; Zcash says `epk` is sufficient for the DHAES properties | Theorem 6.2 uses `H(shared)`. The `epk`-indexed hash family needs the corresponding ODH/ODH2 game and assumption for this exact encoding and BLAKE2b profile. |
| ChaCha20-Poly1305 | Zcash uses IETF ChaCha20-Poly1305 with empty AD, all-zero 96-bit nonce, and a 256-bit key | The theorem uses independently derived `SE` and strongly unforgeable `MAC` keys. A single-key AEAD is not that syntax; an ANO-CCA adaptation to AEAD security is required. |
| Known candidate recipients | Theorem 6.2 is an equal-message known-key anonymity game and extends to the PKE multi-user setting described by the paper | The complete P1+C1+public auxiliary view, honest-producer authority, decryption failures, timing, retries, and sender/C1 facts must still be modeled directly. |

Therefore the sources support an ADR and a focused reduction/review effort for
the 264-byte design. They do **not** support selecting S6 now.

### Preferred recoverable proposal: versioned `KPB-DHAES-264`

The proposed profile is:

```text
esk  <- fresh uniform 32 bytes for this output and this attempt
epk  = X25519(esk, basepoint9)
ss   = X25519(esk, recipient_delivery_pk)
K    = BLAKE2b-256(personalization = fixed KPB profile,
                   input = ss32 || epk32)
(C,T)= ChaCha20-Poly1305(K, nonce = 0^96, AD = empty,
                        plaintext = Receipt216)
wire = epk32 || C216 || T16                         # 264 bytes
```

A bare, unpersonalized BLAKE2b call is not admissible; the ADR must freeze a
unique 16-byte BLAKE2b personalization and the exact byte order. Sender and
receiver must reject an all-zero `ss`; [RFC 9180, Section 7.1.4](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.4)
makes that check mandatory for X25519 DHKEM. Honest recipient keys and `epk`
must come from the profile's canonical generator. The profile must either
reject non-canonical encodings before X25519 or supply the missing proof for
RFC 7748's required non-canonical-input acceptance; it must not silently treat
the two behaviours as equivalent.

The fixed nonce is safe only conditionally on a fresh, non-reused derived `K`
for every output. A retry, abandoned attempt, or repeated recipient therefore
needs a fresh `esk`; repeated `epk` is a hard failure. Decryption must collapse
all public-key, shared-secret, AEAD, receipt, descriptor, and commitment errors
to one externally indistinguishable failure path. After AEAD success, the
receiver must keep the current checks that `Receipt216` matches the expected
private invoice descriptor and that `receipt.commitment()` equals the public
`CM`. Zcash's rationale makes this commitment-consistency check part of its
partitioning-oracle defense, not optional parsing hygiene.

This profile preserves the current private stable delivery key, so recovery
can continue to derive one secret from the seed and trial-decrypt public
ciphertexts. It needs no per-output private key ledger. It also changes the
current lane order from `epk || tag || encrypted_receipt` to
`epk || encrypted_receipt || tag`; a new profile/version and observer grammar
are mandatory even though the total remains 264 bytes. Because the Output
circuit currently binds only `SHA256(ciphertext)` and its width, the redesign
need not change its mathematical relation *if* a source-to-matrix comparison
proves it unchanged. That comparison now proves the current aggregate relation
is matrix-identical to the retained setup. The setup itself remains ineligible
because its trust/erasure record is insufficient; same width alone would not
have been permission to reuse old keys.

## Smallest non-circular S6 change

### Bounded passive-P1+C1 experiment: select one-use hidden invoice keys

Create a separately versioned recipient profile with these rules:

1. Every logical output gets a unique delivery secret. A deterministic
   `HMAC-SHA256(seed, profile || domain || "DELIVERY" || index)` is acceptable
   only under an explicit multi-output PRF assumption and an authenticated
   one-use index ledger. Sampling a random 32-byte secret instead requires that
   secret to be present in the private recovery backup.
2. The public key exists only inside the exact authenticated private invoice.
   It, its hash, its index, and any directory identifier must be absent from the
   public projection, P1 capture, honest-owner logs, launcher receipts, and
   observer export.
3. One key encrypts one immutable output exactly once. Retransmitting the same
   sealed artifact may repeat bytes and is direct metadata; re-encrypting or
   encrypting another plaintext under the key is forbidden. A fresh trial or
   abandoned attempt uses fresh output keys.
4. A corrupt C1's issued/accepted invoice, contact, value, delivery key, and
   successful/failed decryptions remain direct candidate constraints. If C1 is
   the sender or recipient, its counterparty knowledge is not hidden.
5. The selected honest output producer must authenticate valid generated keys.
   RustCrypto's byte constructor accepts a 32-byte Montgomery encoding without
   proving honest key provenance; arbitrary caller bytes cannot qualify an
   honest-key hybrid.

This removes S6 only through a concrete hybrid, not a new assumption named
“one-time keys are anonymous”:

1. Under the domain-separated HMAC PRF condition, replace each honest one-use
   delivery secret with an independent uniform secret.
2. Under S5 for the exact admitted honest producer, replace each equal-length
   honest receipt plaintext with a fixed dummy plaintext. C1 decryptions and
   sender/contact facts are not changed by this step; they are direct.
3. The remaining honest-recipient key/plaintext/ephemeral tuples are independent
   identically distributed hidden samples. Swapping the two honest recipient
   labels is then an exact renaming of hidden samples, not a BBDP known-key
   challenge.
4. Restore the real plaintexts and PRF-derived keys in reverse.

This reduction is finite and non-circular. It still depends on S5, the PRF
condition, honest-producer provenance, equal fixed widths, and direct/empirical
coverage of all metadata. It says nothing about a directory observer that has
the honest public keys, a malicious host, a modified binary, or a corrupt
sender's remembered invoice.

### Recovery consequence: the current seed-only claim must be withdrawn

The present random 64-bit invoice index is learned only after decryption. With
a different delivery key at every unknown index, a restored seed cannot know
which key to try. Therefore the bounded redesign must choose one of these
honest statements:

- restore a private authenticated append-only invoice/key ledger and state that
  recovery needs `seed + ledger + public history`; or
- keep the bounded one-use-key experiment separate, then implement the proposed
  `KPB-DHAES-264` profile after its exact anonymity proof obligation is closed;
  its stable private delivery key preserves seed-only trial decryption; or
- implement the exact Orchard-style incoming-viewing-key, diversified-address,
  and public-ephemeral-key trial-decryption design.

The first is the smallest experiment, but it changes the current public status
fields `seed_only: true` and `private_maps_imported: false`. Losing the ledger
must safely halt; it cannot report successful empty recovery. The DHAES-shaped
option is the smallest same-width path that retains seed-only scanning, but it
remains unselected pending the proof gaps above. Exact Orchard is the strongest
established fallback, with a larger profile change. Either needs new CRS
material if note/circuit fields change. The current aggregate edits do not:
complete matrix regeneration proved byte identity.

### Why an Orchard-style product profile is larger

The current 264-byte ciphertext is exactly
`ephemeral_pk32 || tag16 || encrypted_receipt216`. The exact Orchard
transmitted-note form also commits to a diversified recipient address and
includes an outgoing ciphertext; its standard note plaintext and commitment
grammar do not match KPB `Note168` or SHA-256 `CM`. The current Output circuit
only proves
`domain || CM || CV || SHA256(ciphertext)` and proves no encryption
correctness.

A production adaptation must therefore be versioned as a new note/wire/circuit
profile. It must bind the diversified transmission key/address into the note
commitment, use the exact validated ephemeral-key and trial-decryption rules,
decide whether and how sender recovery uses the outgoing ciphertext, and
rebuild both Groth16 circuit closures. A custom KPB `Domain` with a 216-byte
plaintext is feasible at the API level, but is **not** exact Orchard and remains
unqualified until its cryptographic mapping is reviewed.

## Exact S6 implementation impact

Do not mutate the retained V2 evidence. A bounded V3 one-use-key experiment
requires at least:

| Path/surface | Required change |
|---|---|
| `poc/future-recipient/v3/` (new) | Version invoice/profile; derive delivery key at the unique invoice index or load a random per-invoice secret; refuse index/key reuse; add explicit-key decryption |
| `private_batch_trial/wallet_profile.py` | New V3 `Keys`, invoice issuance, `open(ciphertext, admitted_invoice_key)`, one-shot key registry, and no fallback to `DELIVERY/0` |
| `wallet/worker.py` | Persist the private issuance/key ledger; bind invoice export to one issuance; restore it privately; stop claiming seed-only/no-private-map recovery for V3 |
| `wallet/payment.py` | Consume the exact authenticated recipient invoice once; retain the private change invoice/key; poison abandoned/replayed issuance; keep 264-byte width only for the bounded NaCl profile |
| `recovery/history.py` and `wallet_profile.recover_openings` | Trial the finite admitted private key set; reject duplicate key/index, missing ledger, ambiguous multi-decrypt, and successful decrypt with wrong CM/descriptor |
| `private_batch_trial/{output_producer.py,lifecycle_worker.py,prepare_unfunded_batch.py}` | Carry one-use authority and retry freshness through the genuine source path; never synthesize a key from public labels |
| C1 v2 capture/model | Authenticate C1's exact invoice key/contact/operation/value and decrypted output; apply them as candidate constraints rather than relabelling ledger rows |
| P1/public observer | Negative scan for honest invoice key, key hash, index, or directory identifier; retain ciphertext bytes/hash/position/repeat and timing as direct leakage |
| backup/recovery controls | Missing, reordered, duplicated, cross-round, cross-owner, reused, and partially committed key-ledger negatives; seed-only recovery must explicitly refuse |

The proposal-only `KPB-DHAES-264` path has a smaller state diff but a larger
cryptographic review obligation: add a pinned X25519/BLAKE2b/ChaCha20-Poly1305
bridge, version the invoice/profile and 264-byte lane grammar, keep
`DELIVERY/0`, enforce fresh one-shot `esk` across retries, reject invalid
shared secrets/encodings, and update the scanner and observer for
`epk || C || tag`. If source-to-matrix comparison confirms that the circuit
still treats the lane only as 264 opaque bytes plus its SHA-256 digest, the
circuit need not change for this redesign alone. S6 nevertheless remains
unselected until the anonymity mapping is independently reviewed.

An Orchard production profile additionally changes the recipient bridge
dependencies, note/address encoding, output row width, wire parser, Output
statement/circuit, aggregate circuit, setup manifests, recovery scanner, and
independent verifier. It must use pinned `zcash_note_encryption`/Orchard source
rather than restating their algorithms from scratch.

ADR impact:

- add a new ADR selecting bounded V3 ledger-backed recovery for the exact
  passive-observer experiment; keep `KPB-DHAES-264` proposal-only in that ADR;
- supersede the stable-delivery-key part of ADR-0042, without rewriting its
  retained V2 result;
- update `docs/ARCHITECTURE.md`, `THREAT-MODEL.md`, RFC-0030, the recovery
  contract, and the finite assumption ledger;
- record the new private-ledger availability/trust requirement or the new
  incoming-viewing-key assumptions; and
- regenerate Groth16 parameters if any note, wire, statement, or constraint
  changes.

## S4/S12: theorem and ceremony mapping

Groth's original construction is the preprocessing SNARK in
[Groth 2016, ePrint 2016/260](https://eprint.iacr.org/2016/260). Its Theorem 2
states perfect completeness and perfect zero knowledge, and statistical
knowledge soundness only against adversaries making polynomially many generic
bilinear-group operations, for the stated setup/prove/verify protocol and its
generated CRS. It does not prove that this repository's local `OsRng` setup was
honest, that toxic waste was erased, or that a converter produced exactly that
CRS.

Bowe, Gabizon, and Miers give a scalable two-round MPC for an extended Groth
CRS in the random-beacon model
([ePrint 2017/1050](https://eprint.iacr.org/2017/1050)). The exact mapping is:
Theorem 5.1 covers the layered MPC when the random oracle is available, the
beacon is `u`-co-resistant, and there is an honest player in **each** phase;
Section 6 shows that the extra extended-CRS terms do not enlarge the proof
adversary's usable basis and reduces knowledge soundness back to Groth;
Sections 7.1 and 7.3 instantiate the two phases as powers of tau and the
circuit-specific delta/query transformation. Thus one honest Phase-1
contributor and one honest contributor in each circuit's Phase 2 must introduce
and delete unknown secret randomness. A public beacon randomizes and finalizes
the transcript under the theorem's limited-influence condition; it does not
turn an entirely colluding phase into an honest setup.

This is also a curve boundary. The paper's Section 8 warns that the historical
254-bit BN construction no longer meets its original concrete 128-bit estimate
and proposes BLS12-381. The pinned KPB verifier, query store, and `snarkjs`
candidate use BN254. The generic-group theorem can describe their algebraic
protocol, but it is not a new concrete-security proof for BN254. A production
decision to keep BN254 must record the selected concrete-security target; a
move to BLS12-381 changes the verifier, every key/query encoding, and both
ceremonies.

### Bounded Testnet exception: explicit trusted local setup

The theory does not forbid a bounded claim based on one honest setup party.
Groth's theorem is stated for the CRS output by its `Setup` algorithm; an MPC
ceremony is a way to distribute that trust, not a prerequisite of the theorem.
For the frozen passive P1+C1 Testnet observer, the following may therefore be
added as a **candidate selectable assumption**, never as measured fact:

> `A-CRS-LOCAL-BOUNDED-V1`: For each exact frozen circuit, the dedicated
> source-closed setup process honestly executed the pinned Groth16 `Setup`
> algorithm with fresh randomness from an uncompromised OS CSPRNG. The setup
> party and its random tape are outside the admitted passive P1+C1+public view;
> only the exact CRS left the process. No trapdoor, seed, core image, log, swap,
> or derivative state was retained or disclosed, the process erased its
> transient secrets and terminated, and the party never colludes with the
> observer. The resulting CRS is used only for the two predeclared,
> hypothesis-symmetric trials of this bounded Testnet experiment.

That statement is deliberately an operational trust assumption. Isolation and
erasure receipts can detect violations; they cannot cryptographically prove
that entropy was honest or toxic waste was forgotten. Selection requires all
of these gates before either trial starts:

1. Reproduce and freeze the current Output and aggregate source, R1CS/matrix,
   field, instance/witness order, and query counts. Complete aggregate
   reproduction is now byte-identical to the retained setup matrix; this does
   not admit the retained setup or replace the required setup receipt.
2. Pin the setup executable and complete transitive source/compiler/library/OS
   closure. Refuse a caller-provided deterministic seed.
3. Run each setup in a dedicated one-shot process outside every P1/C1 capture,
   with private inherited output descriptors, no network, no debugger, no
   stdout/stderr secret logging, core dumps disabled, swap excluded, and
   private temporary storage. Only canonical PK/VK/query artifacts may leave.
4. Best-effort zeroize setup memory, close temporary descriptors, destroy the
   process namespace, and record start/exit, isolation policy, exact input and
   output hashes, and absence of unexpected outputs. Never record the random
   tape or a derivative that helps recover it.
5. Independently validate the PK/VK/query conversion, subgroup encodings,
   counts/order, fixed proof fixtures, and exact binding to the sealed two-run
   plan. Do not regenerate after observing truth or a trial outcome.
6. Make the final result say `conditional_on_A-CRS-LOCAL-BOUNDED-V1`. Missing
   receipt fields, setup-process reuse outside the plan, circuit drift, or any
   observer/setup contact keeps S4/S12 unqualified.

The existing records `PRIVATE_OS_RNG_NOT_RETAINED` and
`FRESH_LOCAL_RESEARCH_SETUP_NOT_CEREMONY_OR_FINANCIAL_ACCEPTANCE` do not satisfy
these gates and cannot be grandfathered in. This exception covers only witness
privacy in the exact protocol-following passive observer experiment. It does
not cover a malicious setup party, active/malicious hosts, proof soundness
against a party that knows toxic waste, production funds, or permissionless
trust. Production still requires the independently verifiable Phase-1 and
circuit-specific Phase-2 ceremonies below.

The chosen implementation candidate is official `snarkjs` v0.7.6, commit
[`9a8f1c0083d18b9b5e18f526cfd729e7259423be`](https://github.com/iden3/snarkjs/tree/9a8f1c0083d18b9b5e18f526cfd729e7259423be).
Its official guide specifies:

- verified Phase-1 contribution chains and a final future beacon;
- a circuit-specific Groth16 Phase 2;
- refusal to use the zero-contribution initial `zkey`;
- contribution-chain, circuit, and final-beacon verification; and
- a published BN128 power-24 Phase-1 file for up to 16,777,216 constraints,
  BLAKE2b digest
  `fa404d140d5819d39984833ca5ec3632cd4995f81e82db402371a4de7c2eae8687c62bc632a95b0c6aadba3fb02680a94e09174b7233ccd26d78baca2647c733`
  ([guide, Phase 1](https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/README.md#7-prepare-phase-2),
  [guide, Groth16 Phase 2](https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/README.md#15-setup)).

Power 24 covers the selected 13,093,029-constraint aggregate circuit and can
root both ceremonies. Phase 2 remains separate for Output and aggregate because
Groth16 setup is circuit-specific.

Official gnark v0.16.4 at
[`e974abb44722dd201a7f1949baeabca0fef5866e`](https://github.com/Consensys/gnark/tree/e974abb44722dd201a7f1949baeabca0fef5866e/backend/groth16/bn254/mpcsetup)
also implements BN254 Phase1/Phase2 contribution, verification, sealing, and
beacon APIs. Its reviewed package hashes are:

```text
phase1.go  a5fe610f60a3ca0c183fbb532d20243ac977bf50d59eb102e96f794b68058b46
phase2.go  01bb7be08a4525acb95cf9e49d5d94e7f0b78d68a7a2c2e27d6bb3b8c8ef820e
setup.go   f82f422ec778f65828bf726a4bd9751f0545ed188ba32731526cb043bc73ff23
marshal.go 5409d2bf89d8ec79a109a9b480835df6fd1f38d41bd0cc3ab7707a217b74cc38
```

It is a useful differential verifier or alternative ceremony stack. Choosing it
instead does not remove the Arkworks-matrix conversion and contributor
governance requirements.

## Smallest S4/S12 implementation plan

### Offline work that is safe to implement now

1. **Freeze two exact R1CS artifacts.** Export the Arkworks matrices, field
   modulus, instance/witness ordering, row counts, and canonical coefficient
   encodings into a deterministic standard R1CS file. Round-trip every row back
   into Arkworks and evaluate both forms on identical valid and invalid
   witnesses.
2. **Reconcile aggregate drift first -- complete.** Current source table
   `04adfd77...a9d7` reproduces the selected geometry, fingerprint, and every
   compressed A/B/C byte. Any later source change must repeat this comparison;
   a mismatch invalidates the PK/VK/query-store closure before any ceremony.
3. **Pin the ceremony stack.** Vendor or immutably bind snarkjs v0.7.6, Node,
   the verified power-24 Phase-1 file, and all transitive source/build hashes.
   Independently recompute the published BLAKE2b digest and run Phase-1
   verification.
4. **Build conversion without ceremony claims.** Implement deterministic
   `zkey -> Arkworks BN254 PK/VK -> mcl query-store` conversion with canonical
   field encodings, curve/subgroup checks, exact query counts/order, and
   round-trip pairings. No conversion may reorder public/private IC or H/L/A/B
   queries.
5. **Rehearse only with disposable keys.** Exercise contribution, verification,
   wrong-circuit, missing/reordered contribution, altered beacon, malformed
   point, cross-key, and transcript-truncation controls. Mark every rehearsal
   key `DO_NOT_SELECT_LOCAL_REHEARSAL`.
6. **Cross-prove.** For each frozen circuit, prove and verify fixed fixtures in
   snarkjs and the selected Arkworks/mcl verifier after conversion. Require
   equal public inputs and acceptance, not byte-identical randomized proofs.

These steps can falsify adapters and artifact mismatches. They cannot establish
an honest contributor, entropy, non-collusion, erasure, or an actual ceremony.

### Actual ceremony needed before selection

For each frozen circuit:

1. publish the exact R1CS and its source/matrix manifest before contributions;
2. start from the independently verified power-24 Phase-1 transcript;
3. obtain multiple operationally independent Phase-2 contributions, with at
   least one contributor assumed honest and able to erase its secret;
4. bind a future, public, precommitted beacon unavailable during contributions;
5. verify the complete contribution chain, beacon, exact R1CS match, final
   PK/VK, conversion, query-store, and independent proof verification;
6. publish immutable transcript and contributor attestations without claiming
   that attestations cryptographically prove erasure; and
7. bind the final keys into the exact selected build/runtime/launch receipt.

The aggregate ceremony must also bind the collaborative MASCOT proof-randomizer
path. An honest CRS does not prove fresh `r,s`, and fresh `r,s` does not repair a
bad CRS.

## Bounded test versus production boundary

| Evidence | Bounded privacy gate | Production/general claim |
|---|---|---|
| Current or unattested local single-process setup | May run functional tests; cannot close S4/S12 | Ineligible |
| Fresh source-closed honest local setup satisfying `A-CRS-LOCAL-BOUNDED-V1` | May make S4/S12 conditional for the exact two-trial passive P1+C1 Testnet observer after exact matrix reproduction, isolation/erasure receipt, and runtime binding | Ineligible; explicitly trusted, not ceremony evidence or trust minimization |
| Disposable MPC ceremony rehearsal | Adapter/control evidence only | Ineligible |
| Verified actual Phase-2 ceremonies, exact frozen circuits, one honest contributor in Phase 1 and in each Phase 2 | May make S4/S12 explicitly conditional on those assumptions after runtime/freshness closure | Still needs independent review, durable public transcript, contributor governance, and unchanged audited circuits |
| One-use hidden NaCl invoice keys + private ledger | Can remove S6 from the exact bounded passive-view ledger after genuine two-round capture proves non-disclosure and C1 direct constraints are applied | No general directory, malicious-host, corrupt-sender, or seed-only-recovery claim |
| Proposed `KPB-DHAES-264` | Same-width, seed-recoverable design candidate; S6 remains unselected until the X25519/KDF/AEAD anonymity proof mapping is reviewed | No production claim from structural similarity to Zcash |
| Exact reviewed Orchard-style profile | Candidate production recipient-privacy/recovery design | Still conditional on exact Zcash applicability, its cryptographic assumptions, metadata/network analysis, and independent review |

Any circuit change after a ceremony invalidates that circuit's Phase 2. Any
delivery redesign that changes `Note168`, ciphertext width/hash statement, or
Output constraints therefore forces new Output and aggregate matrices and new
Phase-2 ceremonies.

## Actionable blocker disposition

| Item | Smallest next action | Selection status |
|---|---|---|
| Bounded S4/S12 | Use the reproduced exact current matrices; generate fresh keys in the isolated source-closed setup; bind the `A-CRS-LOCAL-BOUNDED-V1` receipt to the two-run plan | Selectable only as an explicit trusted-setup condition for the bounded passive experiment |
| Production S4/S12 | Complete verified Phase 1 plus separate Output and aggregate Phase-2 ceremonies and conversions | Needs real ceremonies; local setup is never a substitute |
| Bounded S6 | Implement V3 one-use hidden invoice keys, authenticated private ledger, retry poisoning, C1 direct constraints, and actual key-absence capture | Potentially selectable after runtime/source/recovery closure under S5+PRF+honest-producer conditions |
| Recoverable same-width S6 | Specify and independently review `KPB-DHAES-264`, including the X25519/KDF/AEAD anonymity reduction | Proposal only; not selectable from present sources |
| Exact mature S6 fallback | Adopt the complete Orchard recipient-encryption and recovery profile | Protocol redesign plus exact applicability review |
| “The joint view is private” | Replace it with concrete hybrids over the finite ledger plus direct auxiliary facts | Inherently circular as an assumption; never selectable |

## Admission and stop rules

- Do not select S4 or S12 while setup evidence says
  `PRIVATE_OS_RNG_NOT_RETAINED` or
  `FRESH_LOCAL_RESEARCH_SETUP_NOT_CEREMONY_OR_FINANCIAL_ACCEPTANCE`.
- A bounded S4/S12 selection must use the distinct
  `A-CRS-LOCAL-BOUNDED-V1` preimage and say that it is conditional on an honest
  isolated setup party. Process attestations do not turn that condition into a
  proven erasure or a production ceremony.
- Do not select S6 for the current NaCl construction.
- Do not select S6 for `KPB-DHAES-264` merely because its byte layout resembles
  Zcash. Close or explicitly review the X25519 group/encoding, `epk`-indexed
  ODH, AEAD-composition, multi-user auxiliary-view, and failure-channel gaps.
- Do not close S6 merely because honest key bytes are absent in a unit fixture.
  The actual sealed P1+C1+public capture and launcher/log inventory must prove
  their absence, and C1's own facts must actually filter the candidate lattice.
- Do not call a custom `zcash_note_encryption::Domain` Orchard-equivalent
  without a reviewed mapping for its curve, diversifier, KDF, plaintext,
  commitment, validation, and auxiliary view.
- Do not launch the one-use-key experiment while recovery still reports
  `seed_only: true` without admitting and testing the private key ledger.
- The earlier C1 v2 incomplete-friend vulnerability is now closed: hostile
  redefinitions of both complete friend classes fail, and the focused C1
  authority suite is 7/7 green. This is source-control evidence only. The
  source-status receipt still leaves controller stage/route integration,
  selected-launcher consumption, observer join, and actual launch false, so no
  C1-dependent privacy admission is available yet.
- Passing proof verification, ciphertext decryption, or ceremony-rehearsal tests
  is not proof of zero knowledge, key privacy, toxic-waste erasure, or
  production privacy.

The immediate actionable sequence is therefore: (1) select the bounded V3
one-use-key plus authenticated-ledger contract in a new ADR; (2) freeze the
reproduced exact circuits and implement the source-closed local-setup receipt; (3)
complete the genuine C1 stage/route/launcher/observer integration; (4) run the
predeclared capture and apply key/contact/value facts to the candidate lattice;
and (5) pursue the `KPB-DHAES-264` reduction independently, without consuming
it in acceptance. Actual Phase-2 ceremonies remain mandatory before any
production or trust-minimized claim. Until the bounded gates and explicit
assumptions are complete, S4, S6, and S12 remain unselected and the privacy gate
remains unqualified.
