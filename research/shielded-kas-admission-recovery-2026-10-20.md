# Own-key v6 admission and backup recovery: source review

Reviewed 2026-10-20 against local commit
`fa1dcf18f786843f5dd3895cac197d7a0bd3c536`, for
[RFC-0013](../docs/rfc/0013-coherent-v6-lifecycle.md).
Scope: an offline local wallet using the existing v6 relation, public replay,
parameters and native validator. No funded test, new proof or setup was run for
this review; no private wallet or note files were read.

## Source refresh and reuse

Read-only remote-ref checks found all fourteen official heads in the
[same-day requirements review](shielded-kas-privacy-requirements-2026-10-20.md)
unchanged. Initiative main remains `52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33`;
PR59 remains `585558091cc7d326e28d10f9c04e709952c85cf5`, and PR60 remains
`f02e98d5918af3f53985b77809c7e930d888231f`. The earlier
[lifecycle source review](shielded-kas-lifecycle-integration-2026-10-20.md)
records their separate architectures and evidence limits.

| Primary source | Reuse/adapt for this slice | Reject or retain as a limit |
| --- | --- | --- |
| [Toccata inline ZK][inline] and [KIP-17][kip17] | Bind proof statements to actual native inputs, outputs and successor state. | A locally verified proof or self-declared UTXO is not accepted native backing. No new L1 feature is needed for this wrapper. |
| [Rusty Kaspa pruning][pruning] | Require retained transaction bodies, ciphertexts and funding parents, including parents older than the discovery window. | A state root or pruned node cannot supply missing historical bytes. |
| [vProgs README][vprogs] and [research index][research] | Preserve the distinction between private authorization, public reconstruction and settlement. | Do not add an executor/runtime for local scanning. The earlier unread-PDF limitation remains; no paper-specific result is newly verified. |
| [Orchard keys][keys], [note parsing][decrypt] and [note-constructor warning][note] | Separate viewing from spending authority; validate recipient, note encoding and commitment after decryption. | A decryptable or internally well-formed note is not automatically spendable. Do not import Orchard keys, curves or security claims. |
| [Orchard Merkle paths][tree] and [Aztec query privacy][queries] | Rebuild membership paths locally from public commitments and retain the correct leaf position. | Sending a leaf index to a witness service leaks which note interests the wallet. No new private-query service is needed here. |
| [Aztec auditor delivery][auditor] | Treat ownership as a separate check from successful decryption. | Import neither its discovery handshake nor a claim that viewing access authorizes spending. |
| [RAILGUN commitments][railgun] | Distinguish historical membership from current nullifier state. | Do not import EVM storage, contract administration or restricted circuit code. |
| [Monero receiving model][monero] and [MWEB light-client data][mweb] | Retain local scan material and enough public data to discover outputs after an older backup. | Do not promise seed-only reconstruction of missing ciphertexts or adopt another protocol's key derivation. |
| [Initiative wallet CLI][wallet] and [PR60 local proving][tnwallet] | Fresh own-key initialization, public-only receive data, parameter pins, expected roots, ordered replay and local proving. | Their fixed roles, amounts, state namespace and outer proof runtime do not replace the v6 wallet. |

These are validation and recovery requirements, not a new cryptographic design.
The existing experimental setup, composition and lack of independent
cryptographic review remain unchanged.

## Minimum wallet and public recovery material

The [shared `Wallet`](../poc/shared-pool/src/protocol.rs) contains independent
32-byte spending, viewing and native keys. Reuse them without inventing a mnemonic
or changing derivation. Public receiving data is only the domain-bound owner
commitment and incoming public key, wrapped in an explicit version/pool identity.
Authenticated recipient exchange remains an assumption.

| Material | Required handling |
| --- | --- |
| Three wallet secrets | Keep locally in a versioned backup; private permissions, fresh-file creation and no overwrite. Never serialize them into public evidence or prover requests. |
| Authenticated descriptor identity | Bind the backup to the intended pool/network/domain/VK and founding transaction. An arbitrary downloaded descriptor cannot authenticate itself. |
| Initial note opening, founder only | Retain the full original note, including randomness, if recovery may precede spending it. Check owner/incoming/value/commitment against the descriptor. |
| Exact public proving parameters and VK | Retain independently; verify parameter identity and the embedded VK before proving. Public parameters are not wallet secrets. |
| Public lineage, funding parents and ciphertexts | Replay and scan locally; reconstruct positions, paths and current spentness. Backups made before later receipts need no future note openings. |
| Independently authenticated accepted head | Needed for a live claim. The offline component deliberately does not establish acceptance, completeness, freshness or current spendability. |

The [H7 backup/context code](../poc/shared-pool/src/compact/recovery.rs) supplies
the closest pattern. Its descriptor includes both PK/VK hashes, while the new
[v6 replay descriptor](../poc/shared-pool/src/two_input/replay.rs) currently pins
the VK but not the PK. The wallet should explicitly bind the expected PK digest
or an authenticated public parameter manifest, while preserving existing
descriptor bytes and historical evidence. Comparing the PK's embedded VK is
also necessary; neither check establishes honest setup or trapdoor erasure.

## Retained v6 parameter availability

The existing H13 `params-1` directory was located by filenames. Only filesystem
metadata and allowlisted `setup.json` fields were inspected; its local path was
reported separately, not treated as a public distribution endpoint.

| Public identity | Retained metadata / published provenance |
| --- | --- |
| Proving key size | 962,197,520 bytes; regular non-symlink file, mode 0600. |
| Verification key size | 328 bytes; regular non-symlink file, mode 0600. |
| Constraints | 4,372,824. |
| PK SHA-256 expected from published provenance | `6f95db952f84420717b3b677e1368bc85776791eb1ccf409cb390a4e4fb39593` |
| VK SHA-256 in retained/published setup metadata | `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef` |
| Setup trust | `single_party_experimental_setup: true`. |

Sources: [H13 setup](../poc/shared-pool/evidence/2026-10-19-two-input-offline/setup.json)
and [provenance](../poc/shared-pool/evidence/2026-10-19-two-input-offline/provenance.json).
The retained TN10 descriptor uses the same VK hash. This metadata check confirms
availability and matching declared identity, not current PK byte integrity:
the large key was not rehashed or deserialized here. Verify its full expected
digest and VK equality before use. Do not generate a replacement setup merely
because the key is outside Git.

Follow-up during implementation on the same date: a read-only `sha256sum` of
both retained files matched the expected PK and VK hashes above. Runtime loading
must still check those bytes and the PK's embedded VK. Matching identities does
not establish sound setup or trapdoor erasure.

## Scanning changes that cannot be copied blindly

The [older scanner](../poc/shared-pool/src/compact/experiment.rs) handles mode-1
transfers only. A v6 scanner must consume validated `Replay.records` and:

1. Start after the founding record, with commitment position 1. ADMIT (mode 0)
   and SPEND (mode 1) each append two slots and supply two ciphertexts. DRAIN
   (mode 2) appends none. Preserve positions even for unreadable or zero padding.
2. Trial-decrypt locally with `Wallet::decrypt`, which checks plaintext
   version/domain, owner/incoming key, positive bounded value and commitment.
   Also require the v6 positive-note floor, 60,000,000 sompi, and the reconstructed
   commitment at that exact position. Never credit malformed or non-owned notes.
3. Filter spent notes using `compact::nullifier(domain, spending, commitment,
   position)` and v6 `PublicState::spent`. Do not use the older
   `protocol::nullifier`, which omits position. Build membership with the
   reconstructed v6 commitment tree and verify the intended anchor.
4. Include an authenticated founder opening at position 0 when supplied.
   Padded zero outputs are not balances; commitment/nullifier counts do not
   measure liabilities or determine v6 drainage.

Sources: [wallet validation](../poc/shared-pool/src/protocol.rs),
[positioned nullifier](../poc/shared-pool/src/compact/mod.rs),
[v6 append/spentness](../poc/shared-pool/src/two_input/tree.rs).
Scanning does not prove encryption correctness inside the circuit; the wallet
must reject unusable delivery before displaying received spendable value.

## Existing proving and settlement interface

The helpers in [v6 harness](../poc/shared-pool/src/two_input/harness.rs) already
provide the required operations, but are private to the scripted harness:

- `selected` binds an owned note, position and reconstructed membership path.
- `authorize` builds the current statement, real/padded inputs, encrypted output
  slots, positioned nullifiers and ciphertext digest. It currently selects the
  existing 40,000,000-sompi fixture fee; do not silently reprice proofs.
- `prove` uses Arkworks Groth16 `create_random_proof_with_reduction`, checks the
  generated proof locally with `verify_proof`, and serializes its 128 bytes.
- [`settle`](../poc/shared-pool/src/two_input/mod.rs) combines authorization with
  current public witnesses/reserve, then native validation checks the result.

Expose or factor that narrow interface rather than duplicating the relation.
For ADMIT, require `bootstrap_validated`, resolve the user's supported ordinary
funding output, create its private credit less the authorized fee, prove without
real private inputs, settle with the external input and sign input 1 with
[`native::sign`](../poc/shared-pool/src/native.rs) under SIGHASH_ALL. Check local
ownership of that funding input and all amount/floor arithmetic before proving.
Then replay the resulting transaction before accepting its new wallet balance.

For payment/recovery, select at most two real owned unspent notes, use existing
private change and derive the payout from the user's native key. A restored
wallet must generate its first authorization from recovered data; precomputed
exits remain optional. Parameter loading can be shared within one local process.

## Narrow outcome to establish next

Use fresh independently generated local wallets and synthetic native funding
context, clearly labelled offline. Admit a participant absent at pool creation,
receive while offline, restore a backup predating admission/payment, spend
recovered value with change and drain the supported claims through native checks.
Remove access to original wallet/controller files and saved exit capabilities.

Meaningful controls include wrong backup/pool/parameters, malformed delivery,
wrong positioned nullifier, replayed funding, stale/spent notes and missing public
data. Existing public-parent limits and external accepted-view assumptions remain;
parents outside the discovery window must be retained, never reconstructed from
self-declared authorization fields. Local success is not a funded trial,
production security, real-world anonymity or general pruning/reorg recovery.

[inline]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx
[kip17]: https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md
[pruning]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/src/pipeline/pruning_processor/processor.rs#L486-L491
[vprogs]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[research]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/README.md
[keys]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L537-L543
[decrypt]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs#L311-L320
[note]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note.rs#L265-L294
[tree]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/tree.rs#L136-L164
[queries]: https://github.com/aztec-labs-eng/aztec-node/blob/9babccfcfc083915a5bda1f378fe8bda3a6bd2b8/docs/docs-developers/docs/resources/considerations/privacy_considerations.md#L111-L125
[auditor]: https://github.com/aztec-labs-eng/aztec-node/blob/9babccfcfc083915a5bda1f378fe8bda3a6bd2b8/docs/docs-developers/docs/aztec-nr/framework-description/note_delivery.md#L219-L229
[railgun]: https://github.com/RAILGUN-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol
[monero]: https://github.com/monero-project/monero-site/blob/6ab1cb954411abffa21004d664e5c3fa755922f3/_i18n/en/resources/moneropedia/stealthaddress.md
[mweb]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md
[wallet]: https://github.com/olafweller/kaspa-privacy-initiative/blob/52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33/poc/recovery-native/host/src/bin/wallet.rs
[tnwallet]: https://github.com/olafweller/kaspa-privacy-initiative/blob/f02e98d5918af3f53985b77809c7e930d888231f/poc/recovery-tn10/src/wallet.rs
