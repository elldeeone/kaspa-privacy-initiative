# Recipient construction source inspection

This lane implements only a new offline recipient reference. It does not import
old owner CLI, S7, public replay, DRAIN or restored proving-key workflows.
Primary-source refresh is coordinated with [the shared source review](../PRIMARY-SOURCES.md).

1. Existing [`Wallet::local_backup`, `restore_local`, `discover`, `Note::deliver`](../../../../poc/private-note-wallet/src/wallet.rs)
   separates receiver authority from sealed-box incoming discovery and checks
   owner/incoming/commitment/current spentness. Adapt that acceptance discipline;
   do not inherit its old owner/nullifier/native-key relation or execution code.
2. The frozen [candidate C source](../../../../poc/future-exit-feasibility/src/main.rs)
   supplies exact SHA/HMAC note fields, little-endian positioned NF, native key,
   tagged raw-leaf trees and authenticated predecessor/append ordering. Adapt
   those bytes into the separately reviewed [new contract](../NOTE-STATE-CONTRACT.md).
3. [RustCrypto crypto_box 0.9.1 `PublicKey::seal`](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/src/public_key.rs#L44-L72)
   creates a fresh ephemeral SalsaBox; [`SecretKey::unseal`](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/src/secret_key.rs#L100-L116)
   derives its nonce and decrypts. Reuse this exact existing dependency, checksum
   `16182b4f39a82ec8a6851155cc4c0cda3065bb1db33651726a29e1951de0f009`.
   [Libsodium sealed-box documentation](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)
   states that integrity verification does not authenticate the sender. Keep
   ownership, current accepted state and ciphertext binding as separate checks.
4. [Orchard key derivation](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L537-L550),
   [note encryption](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs)
   and the existing [Orchard comparison](../../../../research/zcash-orchard.md)
   motivate separate discovery/spend authority and commitment reconstruction.
   Reject direct reuse of Orchard curve/PRF/circuit bytes as native SHA primitives.
5. [MWEB receiver reconstruction](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md#L78-L105)
   recomputes commitment/key-exchange data after decryption; adapt that independent
   reconstruction requirement, not its reusable curve address format.
6. Existing primary-source [Monero](../../../../research/monero.md),
   [Aztec](../../../../research/aztec.md), [RAILGUN](../../../../research/railgun.md)
   and [Kaspa/Toccata/vProgs](../../../../research/kaspa-toccata-vprogs.md) comparisons
   require explicit view/spend roles, archived accepted data and acceptance roots.
   None supplies native KAS backing or sender-independent recovery by analogy.
7. [RFC2104](https://www.rfc-editor.org/rfc/rfc2104) and
   [RFC4231](https://www.rfc-editor.org/rfc/rfc4231) define HMAC and known-answer
   vectors. Role/domain/index-separated HMAC is adapted; no new primitive is
   introduced. Native scalar rejection calls pinned libsecp256k1 via Rust
   secp256k1 0.29.1, never Python elliptic-curve arithmetic or modulo reduction.

## Independent pre-run review and correction

The independent reviewer found four witness-builder boundary omissions before
the first test run: wrong expected domain was ignored; claim position could
raise a host indexing error; a zero NF had no explicit guard; successor count
could exceed `2*n+1` in an inconsistent supplied oracle context. Root confirmed
the findings. All four checks were added before source freeze, with tests23–25.
No failing runtime result is claimed: these were source-review findings.

Invoice reuse was corrected at design review before execution: later unsolicited
reuse cannot revoke prior owner authority. Preserve all owned positions and
ledger liabilities, while withholding automatic new credit and marking the
privacy contamination. Orphan-only disclosures and issuance counter reuse are
not reconstructible from a seed plus accepted history; no clean-privacy recovery
claim follows from the reference checks.
