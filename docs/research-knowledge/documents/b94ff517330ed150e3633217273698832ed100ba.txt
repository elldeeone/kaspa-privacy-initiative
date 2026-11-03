# Private/native integration: primary-source and receive-contract review

Reviewed 2026-10-23, refs checked by 01:12 UTC. Worktree base
`0c2f4c788a4274b381c4838e05cce5e9c32e8536`. Source inspection only: no setup,
proving, wallet creation, transaction execution, funding or broadcast occurred in
this research lane. This extends the [previous source review](../exit-fee/PRIMARY-SOURCE-OPTIONS.md)
for the proposed new private/native integration; it does not certify that design.

**Actionable conclusion:** a receiver-issued, one-time descriptor can give the
sender public `O`, `incoming`, `K` and `native_PK` while keeping the nullifier
secret `k`, private spending preimage `s` and native signing secret unknown to
the sender. Recovery from a backup predating payment requires deterministic,
separately tagged derivation and delivery of the derivation index in the
encrypted receipt. This is a bounded invoice construction to specify and test,
not a reusable stateless shielded address or an adoption of Orchard/Monero
cryptography. Revealing `k` makes reuse of that invoice a privacy hazard.

## Ref refresh and changes since the previous checkpoint

Official GitHub branch/PR endpoints were read through the connected GitHub
tools. Rows below identify source, not chain activation or deployed behavior.

| Source | Current observed commit | Relevant change |
|---|---|---|
| [Kaspa master](https://github.com/kaspanet/rusty-kaspa/tree/4edcbbccb449f84832afb1ca157904b35f37d006) | `4edcbbccb449f84832afb1ca157904b35f37d006` | Unchanged. Retained native execution pin remains `01b532e8b553523216471682649693af92f0fd16`; do not relabel it as execution of master. |
| [Toccata docs](https://github.com/kaspanet/docs/tree/0ac77d043a802fc8196abfd5812ac2afbd97a2b9) | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` | Unchanged. |
| [KIPs](https://github.com/kaspanet/kips/tree/e4ae2332117b5cb68bd6188e065ef885b6d17939) | `e4ae2332117b5cb68bd6188e065ef885b6d17939` | Unchanged. |
| [vProgs master](https://github.com/kaspanet/vprogs/tree/f9b84a863a7c7c20586a9cf947550475e894f72e) | `f9b84a863a7c7c20586a9cf947550475e894f72e` | Unchanged; still early/prototype infrastructure. |
| [Kaspa research](https://github.com/kaspanet/research/tree/c923faca11a49148fa7d912d27ce00197a5c5a4a) | `c923faca11a49148fa7d912d27ce00197a5c5a4a` | Unchanged. |
| [Initiative upstream main](https://github.com/olafweller/kaspa-privacy-initiative/tree/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1) | `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1` | Unchanged; separate recovery/reference work remains source to compare, not proof of this new integration. |
| [Orchard main](https://github.com/zcash/orchard/tree/616a669df8c9a59c33d47064d3ce04b25d026b2e) | `616a669df8c9a59c33d47064d3ce04b25d026b2e` | Unchanged. |
| [RAILGUN contract](https://github.com/Railgun-Privacy/contract/tree/36bcf5ed7cf94bfafb6e1a303e1832c769c16780) / [circuits](https://github.com/Railgun-Privacy/circuits-v2/tree/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb) | `36bcf5ed7cf94bfafb6e1a303e1832c769c16780` / `0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb` | Both unchanged. |
| [Monero master](https://github.com/monero-project/monero/tree/8340be5e920d881edc006e0896d6074cd06dfb2e) | `8340be5e920d881edc006e0896d6074cd06dfb2e` | Unchanged. |
| [Litecoin master](https://github.com/litecoin-project/litecoin/tree/ec1b6489a900d09cf5991e220dce089c77a232a2) | `ec1b6489a900d09cf5991e220dce089c77a232a2` | Unchanged. |
| [Aztec next](https://github.com/AztecProtocol/aztec-packages/tree/e63137d734ef3d0d4d7c031ded0370b5168df800) | `e63137d734ef3d0d4d7c031ded0370b5168df800` | Two commits after previous `47e78169a047e1aebe97b3bc3ae0aab2d03bd221`; only four `labs-patches` files changed, concerning supertest/Playwright patch rebasing. No note/key/rollup source delta in that comparison. |

The [exact Aztec comparison](https://github.com/AztecProtocol/aztec-packages/compare/47e78169a047e1aebe97b3bc3ae0aab2d03bd221...e63137d734ef3d0d4d7c031ded0370b5168df800)
does not justify replacing the prior release-based protocol comparison. The
receiver example below stays pinned to release commit
`49a592109ec4f18d79212b43d621891aaf36f7b6`.

vProgs [PR138](https://github.com/kaspanet/vprogs/pull/138),
[PR139](https://github.com/kaspanet/vprogs/pull/139) and
[PR146](https://github.com/kaspanet/vprogs/pull/146) were rechecked: all remain
open/unmerged, heads respectively
`1fee04f4790b161601c370c671e3163ef79bef2d`,
`5a2e855853300378f3e434a5461c69156e74a657`, and
`42353f2efe0fe577a47fe984a4006ee9661fa4eb`. The previous report's accepted
permission, external fee funding, witness delivery and reorg limitations remain
separate from the proposed unaccepted-note revealing exit. No branch was merged
or silently substituted.

## Existing-work comparison: receive, spend, recovery and exit

| Primary source fact | Adaptation for this experiment | What is not transferred |
|---|---|---|
| Toccata [inline ZK](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx#L24-L70) separates proof verification from installing the exact successor output. | Keep one native contract binding the expected verifier, current state, exact effects and output policy. Public reveal and private spend must update the same current NF state. | A proof verifier alone supplies neither backing nor availability nor a correct successor. vProgs is not assumed required. |
| Existing [v6 wallet](../../../poc/shared-pool/src/protocol.rs) already uses public receive fields, sealed-box delivery, then framing/domain/owner/value/CM checks. The [positioned NF](../../../poc/shared-pool/src/compact/mod.rs) and [private circuit](../../../poc/shared-pool/src/two_input/circuit.rs) bind reusable spending authority under the old format. | Reuse established encryption and validation structure; create an explicitly separate receive/commitment/NF format. | Revealing the old reusable spending secret is not a migration or acceptable emergency credential. Existing keys, notes, parameters and histories remain unchanged. |
| Upstream's [recovery-native wallet](https://github.com/olafweller/kaspa-privacy-initiative/blob/7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1/poc/recovery-native/host/src/bin/wallet.rs#L1-L45) has an explicit fixed relation/root namespace and no RPC/provider/broadcast path in that wallet source. | Study independent wallet state/parameter identity and recovery tests. | An upstream recovery example does not establish this candidate's receive contract, native branch or accepted chain backing. No wholesale source merge. |
| Orchard [key hierarchy](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/keys.md#L75-L100) uses hardened accounts and diversified addresses; incoming/full/spending roles differ. Its [NF](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/nullifier.rs#L1-L7) depends on the spender's NF key and is tied to the note. | The sender must not learn the recipient's NF secret. Public receive information must suffice to construct a note while backup secrets recover its authority. | Orchard's Pallas/Halo2 derivations and security argument are not a drop-in SHA256/HMAC construction. Candidate C invoice reuse does not inherit diversified-address safety. |
| Orchard's [note constructor warning](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note.rs#L265-L294) distinguishes an internally valid note from fully validated decryption. [Incoming parsing](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs#L339-L350) derives the recipient transmission key from the IVK and diversifier. | Decrypt, recompute deterministic receiver fields, verify exact CM/position/current spentness and validate accepted lineage before crediting spendable funds. | Successful AEAD decryption or a locally constructed opening alone is not payment acceptance. |
| Aztec's [CompleteAddress](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/yarn-project/stdlib/src/contract/complete_address.ts#L12-L88) carries address/public keys/partial address and recomputes their binding on creation/parsing. Its [Outbox](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/l1-contracts/src/core/messagebridge/Outbox.sol#L103-L169) consumes an already accepted message. | A receive descriptor is a structured binding to validate, not a bag of caller-provided public keys. Separate note authorization from accepted public exit claims. | Account contracts, sequencer assumptions, a new token model, or an already accepted-message claim do not solve unaccepted-note exits. |
| RAILGUN [JoinSplit](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom#L14-L100) keeps nullifying key private; its master public key binds signing key and nullifying key, and note public keys bind that master key and note randomness. [NF checking](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/nullifier-check.circom#L5-L17) binds the private key and leaf index. [Contract state](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol#L25-L58) separates historical roots from current nullifiers. | Check full ownership/NF/position relation in the proof and current spentness in native settlement. Root history is not an unspentness test. | Do not copy restricted circuit/contract code or import EVM token/admin/relayer architecture. These are design observations, not a license or compatibility claim. |
| Monero [subaddress derivation](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/device/device_default.cpp#L195-L222) uses view-secret material plus exact major/minor indices; [output secret/public derivation and key-image methods](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/device/device_default.cpp#L249-L280) remain distinct. Its [account recovery](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/cryptonote_basic/account.cpp#L175-L212) deterministically derives view/spend roles and chooses a recovery scan date. | Specify derivation indices, domains, exact backup contents and scan start. Distinguish viewing/delivery, private authority and native exit authority. | Curve-based reusable addresses/output derivations, key images and RingCT are not being reimplemented. A seed does not reconstruct missing chain data. |
| MWEB [dual-key stealth address specification](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md#L1-L5) explicitly permits repeated use to generate fresh outputs. Its [receiver checks](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md#L78-L105) reconstruct commitments/key-exchange data before spend-key recovery; [light-client guidance](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md#L13-L25) warns about handing view keys to servers. | Local receiver reconstruction and scanning; explicit public data retention. | Reusable MWEB curve addresses and its consensus extension do not make candidate invoice reuse safe or provide Kaspa history availability. |

## Candidate C receive contract: facts, inference and open obligations

The [frozen candidate formula](../../../docs/rfc/0019-fees-and-independent-exit-obligations.md#candidate-c-public-only-authorization-and-native-cost-experiment)
is:

```text
O  = SHA256(OWNER_TAG || D || s || incoming)
K  = SHA256(KEY_TAG   || D || k)
CM = SHA256(NOTE_TAG  || D || O || incoming || u64LE(V) || rho || K || native_PK)
NF = HMAC-SHA256(k, NF_TAG || D || CM || u32LE(position))
```

The public native experiment established none of the following recipient or
private-circuit properties. These are design obligations for the new work.

1. **Receiver creates the invoice.** From a prepayment backup and explicit
   invoice index, derive `k`, native signing authority and any note-local private
   ownership material with separate fixed PRF domains/encodings. Publish only
   the public descriptor fields, including `K` and the matching `native_PK`.
   A native key derivation must specify range/retry semantics rather than
   interpreting arbitrary bytes as an always-valid scalar. Do not derive `k`
   from sender-known `rho`, invoice text or public keys.
2. **Sender checks and binds the descriptor.** The descriptor must identify the
   exact protocol/domain/version and intended payment terms; delivery of the
   correct recipient descriptor needs an authenticated channel or an explicitly
   specified authenticity mechanism. Encrypt the receipt using the receiver's
   established incoming key. Never include `s`, `k` or native signing material
   in sender inputs or encrypted receipt plaintext supplied by the sender.
3. **Receiver rederives authority.** The encrypted receipt must preserve the
   invoice derivation index and canonical fields needed to reconstruct the note.
   Recompute `O`, `incoming`, `K`, `native_PK` and CM from backed-up authority,
   then check current accepted record/position/spentness. This is stronger than
   checking that `K` is a syntactically valid 32-byte value.
4. **Restore does not depend on a newer invoice database.** Backup restoration
   must discover the index from recoverable ciphertext and derive the same
   authority. Public records must retain ciphertexts and sufficient ordered CM/NF
   updates. An index appearing only in an unavailable invoice file defeats a
   prepayment-backup claim. Define whether scanning uses one retained incoming
   key or an explicit derivation lookahead; do not hide an unbounded index search.
5. **One-time use is an operational requirement to enforce and test.** If two
   notes reuse `k`, the revealing branch publishes that same key. An observer can
   compute candidate NFs for every public CM/position and match published spends,
   including earlier and later spends under the reused key. This inference
   follows directly from the candidate formula; it is not a claim about Orchard
   or Monero. Descriptor uniqueness is not magically enforced by a CM hash.
   Concurrent devices/restored invoice counters need explicit collision/reuse
   handling. Detecting a duplicate invoice must not erase a real accepted
   liability or be described as protecting the funds already sent to it.
6. **Published reveal knowledge survives reorgs.** `k` remains public knowledge
   even if the reveal transaction is removed. Possession of `k` must remain
   insufficient to redirect a private spend: that branch must also constrain
   independent private authority `s`. The native branch must constrain an exact
   signature and fixed payout under CM-bound `native_PK`. Both branches consume
   the same positioned NF with the same authenticated update rule. Invoice
   uniqueness limits disclosure; it does not by itself prove authorization.

**Inference:** these requirements permit a small interactive, one-time receive
prototype using established hashes/PRFs/encryption/signatures. They do not prove
a sound new cryptographic protocol. The actual circuit must bind every receiver
field it relies on, values/ranges, actual statement and shared spentness state;
an independently reviewed RFC/ADR must resolve the format before setup. No
reusable-address or migration claim follows from this source review.

## Reuse the existing receipt encryption, with its actual limits

The installed `crypto_box = 0.9.1` registry package records upstream source
commit `91078b60b1cacf674885c1dc86bd00b97adaf828` in `.cargo_vcs_info.json`.
The exact [seal implementation](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/src/public_key.rs#L44-L72)
generates an ephemeral key, attaches its public key and encrypts with SalsaBox;
the [unseal implementation](https://github.com/RustCrypto/nacl-compat/blob/91078b60b1cacf674885c1dc86bd00b97adaf828/crypto_box/src/secret_key.rs#L96-L116)
uses that ephemeral public key and the recipient secret. This is already selected
by [the local package](../../../poc/shared-pool/Cargo.toml) and wallet; no new
encryption primitive or handwritten construction is needed.

Official [libsodium sealed-box documentation](https://github.com/jedisct1/libsodium-doc/blob/edebe691df2e6fd8d8f658f658601cdda247ef2f/public-key_cryptography/sealed_boxes.md#L28-L36)
distinguishes message integrity from sender identity: sealed boxes do not
authenticate who sent a message. Therefore encryption must not substitute for
ledger/commitment/descriptor validation, nor prove that a payee chose an invoice.
Authenticated encryption also cannot force a malicious sender to publish a
decryptable receipt. The protocol must state that delivery limitation and test
receiver rejection; it is not solved by a successful honest fixture.

## CPU/GPU compatibility: use the implemented backend

The exact installed `ark-groth16 = 0.6.0` source commit is
`0bb3e604c534bd118ed477eaf1231f591d6fc40f`, independently matching its current
official `v0.6.0` tag and the local registry's `.cargo_vcs_info.json`.
Its [Cargo feature list](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/Cargo.toml#L49-L77)
enables CPU parallelism through Rayon and parallel arkworks algebra/polynomial
features. Its [prover](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/prover.rs#L1-L100)
uses `GeneralEvaluationDomain`, CPU iterator macros and `VariableBaseMSM`.
The inspected installed Groth16/ec/poly source contains no CUDA, GPU, ICICLE or
OpenCL references and exposes no corresponding feature.

**Engineering consequence:** ordinary use of this backend will not put the RTX
3070 to work automatically. CPU parallel proving is the supported immediate
path. A GPU MSM/FFT backend would require a separate implementation, exact
field/point/serialization compatibility and comparison against this verifier;
this review did not select or benchmark one. The existing RISC Zero CUDA worker
proves a different system and is not an accelerator switch for arkworks BN254
Groth16. Do not spend the run on GPU load unrelated to the chosen proof.

The complete native exit path still needs its own measured serialized body,
compute/storage/transient mass and fee fixed point. Faster proving cannot change
the current native verifier tariff or erase the [existing fee failures](../exit-fee/RESULTS.md).
Public parameters remain experimental trusted-setup artifacts; matching a source
pin or passing checks establishes neither trapdoor erasure nor circuit soundness.

## Scope of this evidence

Source refresh found no newly merged Kaspa/vProgs capability that removes the
private-proof/receiver/native-union obligations. The proposed receive contract
has a feasible implementation seam and explicit one-time/recovery/disclosure
limits. It still needs independently reviewed exact bytes and authority rules,
real proof and native-union conformance, adversarial/reorg controls, complete
fees, and independent backup restoration from retained authenticated public
data. Those are experiment outputs to obtain, not conclusions of this note.
