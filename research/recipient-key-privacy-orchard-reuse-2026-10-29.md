# Recipient-key privacy: RustCrypto gap and exact Orchard reuse

**Date:** 2026-10-29

**Repository baseline:** `b58de1a182347c4223ebe84f92bb0bdd6c88d003`

**Status:** primary-source design research; no implementation or privacy qualification

**Scope:** native-KAS private-output encryption only; no token, mainnet deployment,
real funds, or new cryptographic primitive

## Answer

1. **No qualifying recipient/key-privacy theorem was found for the pinned
   RustCrypto `crypto_box` 0.9.1 sealed-box construction.** The crate and its
   official libsodium construction source say that sealed boxes let an
   unidentified sender encrypt to a recipient. They do not state or prove the
   Bellare--Boldyreva--Desai--Pointcheval (BBDP) property that a ciphertext
   hides *which of multiple candidate recipient public keys* was used. This is
   an evidence gap, not evidence of an attack.
2. **V3's one-use hidden invoice keys solve a narrower problem.** Under the
   bounded observer model, hiding fresh honest delivery keys can reduce stable
   key-reuse linkage and make an honest-output swap a relabelling of hidden
   samples. It does not show ciphertext recipient anonymity when candidate
   public keys are known, and it cannot hide the recipient from the sender who
   received the private invoice.
3. **The smallest mature reuse with an explicit primary-spec key-privacy
   statement is the exact Zcash Orchard note-encryption domain.** Reuse the
   released `orchard`/`zcash_note_encryption` implementation and its exact
   receiver, key agreement, KDF, AEAD, note-commitment check, and fixed wire
   formats. Put the existing `Receipt216` in Orchard's fixed 512-byte memo;
   do not design a KPB-specific ECIES variant.
4. **This still does not close the existing `S6` gate by theorem.** The Zcash
   protocol specification expressly *requires* Orchard note encryption to be
   key-private and cites BBDP, but it does not provide a reduction for KPB's
   complete `P1 + C1 + public` multi-output auxiliary view. `S6` must remain
   unselected until that composition, including commitments, positions,
   retries, timing, sender knowledge, and other direct facts, is reviewed.

## Exact question and baseline

The relevant BBDP game gives an adversary two public keys, encrypts a challenge
under one of them, and asks which key was used. Its CCA form also provides the
corresponding decryption oracles subject to the challenge restriction. BBDP
also makes the essential separation explicit: ordinary message privacy does
not imply key privacy, because a message-secure ciphertext can still identify
the public key.

KPB asks for more than that two-key game. `S6-CRYPTOBOX-RECIPIENT-PRIVACY` in
the [finite assumption ledger](combined-p1-c1-public-finite-assumption-ledger-2026-10-29.md)
must survive multiple outputs and candidate recipients together with the
frozen public transcript and auxiliary facts. A usable result therefore needs:

- a matching per-ciphertext recipient/key-privacy property;
- a justified multi-user/multi-ciphertext hybrid; and
- explicit treatment of every correlated auxiliary field and of facts already
  known to a corrupt sender (`C1`).

The inspected local inputs were:

| Input | SHA-256 |
|---|---|
| `research/combined-p1-c1-public-finite-assumption-ledger-2026-10-29.md` | `8f033672ec35072a2b968ea938b3896b1e7b72caddbf92c34366990d56a836d4` |
| `poc/future-recipient/v3/recipient.py` | `ffa32eeed08788e818178e7429f346edf49041e68aa18a61bdc7b662e9c56183` |
| `poc/future-recipient/v3/README.md` | `2924a3013e618b18035d56a633aa3cbf686b3c3070d11129fd62cdb2b8917e18` |
| `docs/adr/0092-v3-one-use-hidden-invoice-keys.md` | `a5257ee348101739e26ef9afa430ffccf897bc2aaa38632cf90d8bac1d781044` |

## Finding 1: the pinned sealed box has no matching primary theorem

The current bridge pins `crypto_box = 0.9.1`, crates.io checksum
`16182b4f39a82ec8a6851155cc4c0cda3065bb1db33651726a29e1951de0f009`.
The reviewed upstream source is commit
[`91078b60b1cacf674885c1dc86bd00b97adaf828`](https://github.com/RustCrypto/nacl-compat/tree/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box).

Its exact sealed-box source:

1. generates a fresh X25519 ephemeral key pair;
2. derives the nonce as BLAKE2b of `ephemeral_pk || recipient_pk`;
3. uses `SalsaBox`/XSalsa20-Poly1305 for the payload; and
4. transmits `ephemeral_pk || payload_ciphertext`.

See [`PublicKey::seal`](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/src/public_key.rs#L45-L66)
and the [nonce derivation](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/src/lib.rs#L311-L317).
The RustCrypto comment says the feature sends anonymously to a recipient, but
links to libsodium rather than to a security game or proof.

The official libsodium description at commit
[`585a35518bab02f0a356b792a78a6a9487182866`](https://github.com/jedisct1/libsodium-doc/tree/585a35518bab02f0a356b792a78a6a9487182866)
defines the same [wire algorithm](https://github.com/jedisct1/libsodium-doc/blob/585a35518bab02f0a356b792a78a6a9487182866/public-key_cryptography/sealed_boxes.md#L67-L72).
Its stated anonymity is about the *sender*: the recipient cannot authenticate
who created the ciphertext. It does not say that an observer holding candidate
recipient public keys cannot identify the encryption key.

A finite audit of the pinned crate's README, changelog, source, and tests found
no BBDP, IK-CPA, IK-CCA, anonymous-PKE, or equivalent theorem/reference. The
README's Cure53 audit applies to version 0.7.1
([README lines 43--47](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/README.md#L43-L47));
sealed boxes were added later in 0.8.2
([changelog lines 51--55](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/CHANGELOG.md#L51-L55)).
That audit cannot be promoted into a sealed-box key-privacy result.

The closest formal baseline is BBDP's
[*Key-Privacy in Public-Key Encryption*](https://www.di.ens.fr/users/pointche/Documents/Papers/2001_asiacryptC.pdf),
especially Definition 1 and the warning before it that data privacy and key
privacy are distinct. Its positive results cover specified schemes and
assumptions; they do not cover this exact X25519/XSalsa20-Poly1305 construction,
its recipient-key-dependent deterministic nonce, or the KPB auxiliary view.

**Decision:** do not cite RustCrypto's word "anonymously" as `S6` evidence.

## Finding 2: what V3 one-use keys do and do not establish

V3 replaces the reused index-zero delivery key with an HMAC-derived key at the
private invoice index. Its private ledger prevents reuse and requires a new key
after a failed/poisoned attempt. This is useful independently of an encryption
theorem:

- it removes a stable public-key/ciphertext handle across honest invoices;
- when honest candidate keys are absent from the bounded observer's view, a
  swap can reduce to renaming independent hidden key samples, subject to the
  PRF, honest-producer, route, and metadata assumptions already frozen; and
- it limits the effect of later disclosure of one invoice key.

It does **not** imply:

- BBDP key privacy when both candidate public keys are known;
- privacy from the sender, directory, or invoice-delivery service that directly
  saw the selected invoice;
- privacy if retry timing, positions, values, output commitments, or other
  fields identify the recipient; or
- a multi-output theorem for the whole `P1 + C1 + public` view.

The distinction is therefore:

```text
one-use hidden key
  -> removes key-reuse linkage in the frozen bounded view

key-private ciphertext
  -> hides which known candidate recipient key encrypted the challenge
```

They are complementary properties, not interchangeable claims.

## Finding 3: Orchard is the smallest established reuse candidate

The current Zcash protocol source was pinned at
[`2bdf39494320e5e04057ac93b1794031ebfb00b5`](https://github.com/zcash/zips/tree/2bdf39494320e5e04057ac93b1794031ebfb00b5/protocol)
(`v2026.7.0-344-g2bdf39 [NU6.2]`). Section 4.1.6 states that the
public-key encryption scheme used for note encryption is required to be both
IND-CCA2 secure and key-private, and points to the BBDP definition. This is the
explicit primary-spec statement missing from `crypto_box`.

The exact Orchard instantiation uses:

- Orchard diversified transmission keys and Pallas prime-order Diffie--Hellman;
- validated encodings for the relevant curve points;
- BLAKE2b-256 with personalization `Zcash_OrchardKDF` over the shared secret
  and ephemeral public key;
- IETF ChaCha20-Poly1305 with an all-zero 96-bit nonce and empty associated
  data, safe here because each Diffie--Hellman exchange derives a fresh key;
- a fresh ephemeral key and an exact note-commitment check after decryption;
  and
- fixed `epk32 || encCiphertext580 || outCiphertext80` output bytes.

Primary protocol locations:

- [PKE security requirement, protocol source](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/protocol/protocol.tex#L4828-L4839)
- [note-encryption algorithm](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/protocol/protocol.tex#L8418-L8550)
- [symmetric encryption](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/protocol/protocol.tex#L10319-L10339)
- [Orchard key agreement and KDF](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/protocol/protocol.tex#L10507-L10557)
- [ECIES/key-privacy rationale and commitment checks](https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/protocol/protocol.tex#L15596-L15716)
- [rendered protocol specification](https://zips.z.cash/protocol/protocol.pdf),
  Sections 4.1.6, 4.20, 5.4.5.5, and 8.7

Section 8.7 is material: it explains why generic ECIES key privacy need not
survive arbitrary group/key distributions, then records Orchard's prime-order
and point-validation choices. It also says that existing DHAES reasoning can be
adapted. That rationale is stronger and more directly relevant than the sealed
box documentation, but it is still not a published reduction for KPB's full
view. The underlying
[*DHAES* paper](https://eprint.iacr.org/1999/007) proves message-privacy
properties for its specified construction; it is not an Orchard
recipient-anonymity theorem.

### Exact released implementation to reuse

Do not copy the algorithm into Python or create a new `Domain` implementation.
Pin and call the released implementation:

| Component | Exact release evidence | Relevant source |
|---|---|---|
| `orchard` 0.16.0 | commit `8190e4d9b7e9c0140964e88b71f95276d2b50470`; crates.io checksum `4ae7ceb7b5387bd76cf3c0712f57708795c925cecf097036cedb60b5c3706e8f` | [ZIP32 key derivation](https://github.com/zcash/orchard/blob/8190e4d9b7e9c0140964e88b71f95276d2b50470/src/keys.rs#L80-L146), [IVK/address derivation](https://github.com/zcash/orchard/blob/8190e4d9b7e9c0140964e88b71f95276d2b50470/src/keys.rs#L699-L757), [`Address` raw 43-byte receiver](https://github.com/zcash/orchard/blob/8190e4d9b7e9c0140964e88b71f95276d2b50470/src/address.rs#L19-L78), [`OrchardDomain` and note formats](https://github.com/zcash/orchard/blob/8190e4d9b7e9c0140964e88b71f95276d2b50470/src/note_encryption.rs#L26-L42), [`Domain` implementation](https://github.com/zcash/orchard/blob/8190e4d9b7e9c0140964e88b71f95276d2b50470/src/note_encryption.rs#L213-L337), [`OrchardNoteEncryption`](https://github.com/zcash/orchard/blob/8190e4d9b7e9c0140964e88b71f95276d2b50470/src/note_encryption.rs#L507-L516) |
| `zcash_note_encryption` 0.5.1 | commit `b646773328bf97cbbeeb92f7affaeb91541119ea`; crates.io checksum `4812d133908ebf1a1c91d2411a109f63a863a152633db1fc7fbb0f774edeae30` | [fresh-ephemeral encryption API](https://github.com/zcash/zcash_note_encryption/blob/b646773328bf97cbbeeb92f7affaeb91541119ea/src/lib.rs#L480-L568), [trial decryption and consistency checks](https://github.com/zcash/zcash_note_encryption/blob/b646773328bf97cbbeeb92f7affaeb91541119ea/src/lib.rs#L594-L688) |

The Orchard ciphertext is 692 bytes: 32-byte ephemeral key, 580-byte encrypted
note plaintext, and 80-byte outgoing ciphertext. The public `cmx` commitment
and the Orchard `rho` context are separate from those 692 bytes.

## Recommended minimal adaptation

Create a new, versioned profile; retain V3 and its evidence unchanged.

1. **Receiver.** Use Orchard's exact ZIP32 key derivation, then derive its
   `FullViewingKey` and stable `IncomingViewingKey`; freeze a dedicated KPB
   path/account in the ADR. Derive one-use diversified addresses at the private
   invoice index. A raw receiver is `diversifier11 || pk_d32` (43 bytes).
   Replace V3's `delivery_pk32`; do not invent an HMAC-to-Pallas conversion or
   wrap Orchard inside `crypto_box`.
2. **Invoice.** Prefer a new fixed `Invoice219`: V3's 208 bytes with the
   32-byte delivery key replaced by the 43-byte raw Orchard receiver. Give it a
   new magic/profile identifier. Keep private one-shot delivery and durable
   invoice-state rules.
3. **Payload.** Put the exact existing `Receipt216` at the start of Orchard's
   512-byte memo and zero-pad the remaining 296 bytes. Use the same integer
   `value_sompi` as the Orchard note value and reject any post-decryption
   mismatch. There is no second denomination or floating-point conversion.
4. **Envelope randomness.** Use a fresh private Orchard `rseed` and a distinct
   canonical public `orchard_rho` for the encryption envelope. Do not expose or
   reinterpret KPB's encrypted `Receipt216.rho`; the two fields have different
   roles. Parse/reject noncanonical Pallas encodings through the Orchard API.
5. **Outgoing recovery.** Initially pass no outgoing viewing key (`ovk =
   bottom` in the protocol algorithm), which produces fixed-size random
   `outCiphertext`. Keep KPB's authenticated private invoice ledger for sender
   recovery. This avoids inventing a KPB mapping for Orchard value commitments
   and outgoing-view keys.
6. **Public output.** Publish the version, canonical `orchard_rho`, `cmx`, and
   the exact 692-byte Orchard note ciphertext at fixed positions. Retain the
   current KPB public note commitment/descriptor needed for the native-KAS
   claim.
7. **Recipient acceptance.** Scan with the stable Orchard incoming viewing key.
   Accept only if exact Orchard trial decryption validates `epk` and `cmx`, the
   recovered raw receiver reconstructs the private invoice, the padded memo is
   canonical, and `Receipt216` matches the current KPB domain/index/descriptor,
   public note commitment, and integer sompi value.

This reuses the complete Orchard encryption surface. It does **not** import an
Orchard asset, token, consensus system, or withdrawal path; `Receipt216` and
the existing proof-bound native-KAS claim remain the asset semantics.

## Exact source and evidence changes required before implementation

| Area | Required change |
|---|---|
| `poc/future-recipient/bridge/Cargo.toml`, `Cargo.lock`, `src/main.rs` | Leave the existing V2/V3 bridge pin intact. Add a separately versioned Rust bridge/profile pinned to the two releases above. Expose exact raw-address derivation, note encryption, and trial-decryption operations; remove `derive-delivery`, `seal`, and `unseal` from the new profile. No Python reimplementation. |
| New `poc/future-recipient/v4/` sibling, including a separately pinned Rust bridge | Add the new magic/profile, dedicated Orchard ZIP32 path/account, `Invoice219`, fixed Orchard fields, canonical memo, private ledger transitions, stable-IVK scanning, fresh `rseed`/`orchard_rho`, and dual Orchard/KPB acceptance checks. Preserve V3 as retained negative/bounded evidence. The path name is a recommendation subject to the required ADR. |
| `poc/local-private-payment/private_batch_trial/wallet_profile_v3.py` and tests | Preserve this adapter. Add `wallet_profile_v4.py` and `test_wallet_profile_v4.py`, using the stable IVK rather than finite X25519 secret-key trials. Test wrong IVK, invalid `epk`, wrong `cmx`, altered/padded memo, receiver/descriptor/commitment/value mismatch, duplicate output, poisoned retry, and all fixed widths. |
| `poc/local-private-payment/private_batch_trial/output_producer.py`, `wallet_profile.py`, and `poc/local-private-payment/recovery/history.py` | Construct and persist the new receiver/envelope state, use integer sompi end to end, bind every retry to fresh envelope randomness, and require both Orchard and KPB checks during recovery. |
| `poc/local-private-payment/private-batch-relation/src/{wire.rs,row_transport.rs,circuit.rs}` and the registered financial program | Version the output ABI for `orchard_rho32 + cmx32 + ciphertext692` instead of `ciphertext264`. Bind the accepted decrypted receipt to the same proof-bound native-KAS note commitment and sompi amount. Re-export matrices and rebuild every proving/verifying/registration artifact; old layout hashes and CRS artifacts are not reusable. If encryption correctness remains an honest-producer assumption rather than a circuit statement, record that explicitly and do not claim malicious-producer safety. |
| `poc/local-private-payment/private_batch_trial/{privacy_capture_model.py,privacy_fd40_archive.py,selected_crypto_box_layout_control.py,privacy_observer_static_entrypoint.py,native_terminal_mapping_source.cpp,native_terminal_projection_intake.cpp}`, `privacy_observer_runtime_build/observer_output_abi_v2.json`, and their tests | Version the capture grammar and observer ABI; parse Orchard fields and fixed offsets; remove XSalsa/tag-layout assumptions; preserve equality, position, timing, retry, corruption, and sender/directory facts in the observer view. |
| `docs/ARCHITECTURE.md`, `THREAT-MODEL.md`, the governing RFC, and a new ADR superseding only ADR-0092's encryption choice | Record exact upstream pins, receiver lifecycle, sender knowledge, public `orchard_rho`/`cmx`, recovery/dependency behavior, and the fact that a spec requirement is not a theorem for `S6`. Update the finite assumption ledger only after review. |

Any implementation is architecture-significant and must follow the repository's
research-first and ADR process before source changes begin.

## Claim boundary and acceptance gates

The Orchard reuse may be described as:

> Exact reuse of a mature note-encryption implementation whose primary protocol
> specification explicitly requires BBDP key privacy.

It may not yet be described as:

> Proven recipient anonymity for the KPB multi-output public and auxiliary
> view.

Before `S6` can be selected, require all of the following:

1. a reviewed mapping from the Orchard/BBDP per-ciphertext statement to the
   frozen multi-output experiment;
2. direct accounting for public `cmx`, public `orchard_rho`, KPB commitments,
   output position, values, retries, timing, and corrupt-sender invoice
   knowledge;
3. exact released-library vectors plus malformed-input and wrong-key tests;
4. a differential check against the released Orchard implementation, not a
   second handwritten implementation;
5. adversarial review for value mismatch, duplicate/replayed outputs, stale
   roots/state, recovery ambiguity, partitioning-oracle behavior, service loss,
   and hidden trust; and
6. synthetic/offline evidence first, followed only by authorized testnet work
   with test KAS. Passing tests remain implementation evidence, not a
   cryptographic proof.

If the gate continues to demand a *formal theorem matching the whole auxiliary
view*, Orchard's specification statement alone is insufficient. The correct
result is to leave `S6` unsupported, not to weaken the gate.

## Alternatives

- **Abdalla--Bellare--Neven DHIES:**
  [*Robust Encryption*, Figure 18 and Theorem 6.2](https://eprint.iacr.org/2008/440)
  supplies an ANO-CCA result for its exact prime-order DHIES construction with
  separately derived symmetric-encryption and strongly unforgeable MAC keys.
  It does not match X25519/XSalsa20-Poly1305, the sealed-box nonce derivation,
  or Orchard's single-key AEAD syntax. Adapting it would create a new KPB
  construction and new proof obligations, so it is not the smallest reuse.
- **Custom DHAES/ECIES variant:** rejected. Even a paper theorem would require
  proving that the exact curve, key distribution, hashes, AEAD/MAC split,
  validation, and auxiliary view meet its premises. That would create a new
  KPB cryptographic construction instead of reusing an established one.
- **HPKE (RFC 9180):** not a replacement for this property. The RFC specifies
  message-security modes, while recipient key selection/key identifiers are an
  application concern; it does not state BBDP recipient-key privacy for this
  view. See [RFC 9180 Sections 5.1 and 7](https://www.rfc-editor.org/rfc/rfc9180.html).
- **RAILGUN/Aztec:** not evaluated further. Orchard already satisfies the
  instructed first-choice requirement: mature deployed protocol design, exact
  open implementation, and an explicit primary-spec key-privacy statement.
  Adding another protocol would not close the missing KPB composition theorem.

## Primary sources

1. Mihir Bellare, Alexandra Boldyreva, Anand Desai, David Pointcheval,
   [*Key-Privacy in Public-Key Encryption*](https://www.di.ens.fr/users/pointche/Documents/Papers/2001_asiacryptC.pdf),
   ASIACRYPT 2001.
2. Zcash Protocol Specification at
   [`2bdf39494320e5e04057ac93b1794031ebfb00b5`](https://github.com/zcash/zips/tree/2bdf39494320e5e04057ac93b1794031ebfb00b5/protocol),
   Sections 4.1.6, 4.20, 5.4.5.5, and 8.7.
3. Zcash [`orchard` 0.16.0 source](https://github.com/zcash/orchard/tree/8190e4d9b7e9c0140964e88b71f95276d2b50470)
   and [`zcash_note_encryption` 0.5.1 source](https://github.com/zcash/zcash_note_encryption/tree/b646773328bf97cbbeeb92f7affaeb91541119ea).
4. RustCrypto [`crypto_box` 0.9.1 source pin](https://github.com/RustCrypto/nacl-compat/tree/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box).
5. libsodium [sealed-box construction source](https://github.com/jedisct1/libsodium-doc/blob/585a35518bab02f0a356b792a78a6a9487182866/public-key_cryptography/sealed_boxes.md).
6. Michel Abdalla, Mihir Bellare, Phillip Rogaway,
   [*DHAES: An Encryption Scheme Based on the Diffie-Hellman Problem*](https://eprint.iacr.org/1999/007),
   1999.
7. Michel Abdalla, Mihir Bellare, Gregory Neven,
   [*Robust Encryption*](https://eprint.iacr.org/2008/440), Figure 18 and
   Theorem 6.2.
8. RFC 9180, [*Hybrid Public Key Encryption*](https://www.rfc-editor.org/rfc/rfc9180.html).
