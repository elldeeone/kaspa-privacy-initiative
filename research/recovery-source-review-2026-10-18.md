# Recovery source review — 2026-10-18

**Recommendation:** define authenticated completeness, receiver acceptance and the
minimum recovery bundle before implementing an archive or wallet scanner. A root,
successful decryption or current UTXO response alone cannot establish that a
restored wallet has recovered every spendable claim.

This is source research for the specification-to-code review and recovery test
design, not an architecture selection, security audit or executed recovery test.
Native KAS, I-1–I-16 and the later N-user shutdown/native-payout gate are unchanged.

## Source refresh and limits

Default-branch heads were resolved through the GitHub commits API on 2026-10-18.
Kaspa docs, Rusty Kaspa, vProgs, Kaspa Research, Orchard, Aztec, RAILGUN engine and
contracts, Monero and Litecoin matched the 2026-10-17 source review. No current
head is substituted for the experimentally tested Kaspa pin `01b532e8b553523216471682649693af92f0fd16`.
Current node pruning/RPC files differ from that pin; this memo cites current
`f7d7877` source for retention questions and makes no build/deployment claim.

Selected files actually fetched and read are linked below. Large implementation
files were inspected at relevant functions, not exhaustively audited. Local
requirements inspected: `AGENTS.md`, `SECURITY-INVARIANTS.md`, RFC-0002,
`docs/shielded-kas-next.md`, the prior protocol research, `SOURCES.md`,
`VISIBILITY.md`, and model discovery/missing-delivery tests.

| Primary source / exact pin | Inspected evidence and source fact |
| --- | --- |
| [Kaspa Based Apps docs](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/based-apps.mdx#L21) | L1 orders and carries operation bytes; application execution and settlement semantics are separate. Publication does not itself specify indefinite retrieval. |
| [Rusty Kaspa pruning processor](https://github.com/kaspanet/rusty-kaspa/blob/f7d7877363fb97c2ec6871be0e8cbc351d44df10/consensus/src/pipeline/pruning_processor/processor.rs#L485) | Pruning deletes block transactions, acceptance data and UTXO diffs; some retained blocks become header-only. Lines 583–595 also prune historical lane/branch SMT versions outside the retained window. |
| [Rusty Kaspa RPC service](https://github.com/kaspanet/rusty-kaspa/blob/f7d7877363fb97c2ec6871be0e8cbc351d44df10/rpc/service/src/service.rs#L523) | Block retrieval may encounter header-only blocks. Address UTXO queries require the index (lines 821 onward); current outputs are not spent-output/ciphertext history. |
| [vProgs storage](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/storage/README.md), [bridge](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/l1/bridge/src/bridge.rs) | Storage offers persistence/read/write abstractions; the bridge follows L1 through a background worker. Neither inspected file specifies a long-term independently available shielded archive. |
| [Kaspa Research vProgs draft](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex#L510) | Code publication/synchronization and client-cache pruning remain deferred. The sovereign-path discussion acknowledges pruning edge cases (lines 540–544). Its data-availability goals are not an implemented KPI recovery guarantee. |
| [Orchard note encryption](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs#L335) | Decryption reconstructs note fields using the recipient key/context; the domain exposes the reconstructed commitment for validation. This is a note-format/validation reference, not a Kaspa-compatible circuit. |
| [Current Zcash compact schema](https://github.com/zcash/librustzcash/blob/17667fb4a33789ecb71fc8418dc320b358ce81b0/zcash_client_backend/lightwallet-protocol/walletrpc/compact_formats.proto) | The schema explicitly targets payment detection, spend detection and witness updating. Orchard actions carry nullifier, commitment, ephemeral key and 52-byte ciphertext prefix; compact data is deliberately less than a full transaction. |
| [Aztec note discovery](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/docs/docs-developers/docs/foundational-topics/advanced/storage/note_discovery.md), [delivery](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/docs/docs-developers/docs/aztec-nr/framework-description/note_delivery.md) | **Dated v5.2 baseline.** Tagging can require sender/secret/handshake information and counters; tag queries expose interest to the node. Delivery distinguishes constrained encryption/tagging from unconstrained content that a sender can corrupt. These paths are absent from the inspected current `cfdcaf175030a7e22503e62b5d18080e6501ae73` tree; latest API/layout compatibility is unresolved. |
| [RAILGUN wallet scanner](https://github.com/Railgun-Community/engine/blob/6e2614d53a106dd62abad91e7ce03ee4a3956138/src/wallet/abstract-wallet.ts#L544) | Scanner context includes tree/position and explicitly compares a decrypted note's hash with the accepted leaf commitment (lines 567–572). Decrypting successfully is insufficient. No source code is imported. |
| [Monero wallet](https://github.com/monero-project/monero/blob/f8aba51d2d50ebe7c96a0f4d1f2d6e88add61710/src/wallet/wallet2.cpp#L2677) | Scanning distinguishes whether key images are known; viewing-only recovery is not equivalent to authoritative spentness recovery. Refresh/restore height can skip earlier history (lines 4281–4283 and 5993 onward). |
| [Litecoin MWEB light clients](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md), [stealth addresses](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md) | Server filtering with private view keys reveals outputs and amounts. Client-side compact-output filtering is discussed as an alternative; treat the light-client document as a design proposal, not proof of universal wallet support. |

The current librustzcash head differs from the older research pin `b0ebed292204377ada53905add1c4b425965c280`;
the current schema was inspected directly. Aztec's dated baseline is an explicit
source limitation, not silently refreshed evidence. No third-party software,
wallet, prover, RPC or funded transaction was run. Existing source-rights limits
in [SOURCES.md](../poc/shielded-design/SOURCES.md) remain applicable.

## Reuse, adaptation and exclusions

These are proposed research choices, not new protocol decisions.

| Pattern | Reuse / adapt / reject for this work |
| --- | --- |
| Orchard/RAILGUN scan, reconstruct, compare commitment | Reuse the validation obligation. Adapt to the eventual note/address/cipher format and authenticated Kaspa acceptance; do not copy a circuit or inherit its security result. |
| Aztec discovery metadata and constrained delivery distinction | Adapt into the backup inventory and receiver-spendability decision. Reject a seed-only claim until every extra dependency is derived or explicitly backed up. |
| Monero view/spend separation | Reuse the role distinction and restore-height failure case. Do not treat incoming discovery as proof a note is currently unspent. |
| MWEB local compact-data scan | Reuse local discovery as the privacy baseline. Reject sending view keys to an untrusted recovery service. Compacting is permitted only after proving the omitted fields unnecessary for the stated recovery goal. |
| vProgs storage/bridge | Study interfaces when needed; reject treating a local database or catch-up worker as evidence of independent archive availability. No new operator network is required by this design review. |
| Kaspa live UTXOs/seqcommit roots | Reuse authenticated chain bindings. Reject root-only or current-UTXO-only restoration of private history. |

## Concrete gaps and first work

**Interpretation:** RFC-0002 and `VISIBILITY.md` correctly name the data categories
but do not yet define a canonical recovery encoding, completeness proof, trusted
checkpoint/bootstrap rule, snapshot validation or rollback algorithm. The model
scans a caller-supplied list: both an empty list and a truncated archive can
produce an empty receive set. That is safe against minting but does not prove
complete recovery. The existing missing-delivery test detects inability to spend;
it does not authenticate that every accepted delivery was returned.

**First tackle:** a minimal retained-data contract and adversarial vectors, before
archive infrastructure. Specify:

1. The immutable network/pool/version identity; authenticated genesis/checkpoint,
   accepted ordered range and canonical terminal state. State whether recovery
   reexecutes all operations or verifies a proven snapshot plus a complete suffix.
2. The exact records needed to rebuild commitments, allowed anchors, current
   nullifiers, pending deposits, unpaid exits/fees and native reserve/permission
   bindings; full delivery data and selected verifier/software artifacts.
3. Which user secrets/metadata must be backed up or can be rederived, including
   discovery counters/relationships only if the chosen construction uses them.
4. A receiver-acceptance decision: an intent-bound ciphertext digest does not
   prove encryption of the committed spendable note. Require the eventual proof
   relation or an explicit acceptance protocol to address sender-created bad
   delivery; do not count an undeliverable commitment as a completed payment.
5. Exact failure statuses: incomplete/unauthenticated history, unavailable
   artifacts, stale state and insufficient fee/rent funding must remain visible;
   none may be relabelled a complete zero-balance restore or successful payout.

## Source-informed recovery test requirements

These are test **design** requirements. No result below is claimed executed.
Use public synthetic fixtures and integer sompi initially; later funding remains
subject to the existing native-testnet rehearsal and N-user gate.

| Case | Required observable result |
| --- | --- |
| Fresh directory, only declared backup + independently retained public data | Reconstruct every expected owned unspent note, current spentness and pending claim; generate a spend without the old wallet/executor database. Compare two independent state derivations. |
| Missing/reordered/duplicated range or withheld last ciphertext | Detect incomplete or inconsistent coverage against authenticated start/end lineage. Never report a complete restore with silently reduced balance. |
| Valid root but missing leaves/ciphertexts/artifacts | Report the specific unavailable dependency; do not infer note contents, authorize a spend or substitute an unpinned verifier. A retained archive fallback must succeed when that fallback is declared sufficient. |
| Decryptable wrong commitment, wrong recipient, wrong ciphertext/tag | Reject before counting received value. Also test a malicious sender's originally accepted payload, not only post-acceptance byte corruption. |
| Historical membership root, already-consumed note, simultaneous spend | Discovery may recover history; current canonical nullifiers still reject reuse. Cross-pool/version replay must not create a second economic consumption route. |
| Corrupt snapshot, omitted spentness/claim, wrong checkpoint or foreign network | Reject unless verified against canonical commitments and required transition evidence. A checksum proves bytes, not chain authority or completeness. |
| Reorg across receive/spend/exit/payout | Roll back orphan outcomes and rebuild from accepted lineage. Do not restore a note already spent canonically or mark an unpaid exit paid. General reorg recovery is absent from the current monotonic model. |
| Viewing-only restore and overly late restore height | Explicitly mark authorization/spentness limitations; detect unsupported history coverage rather than promising full recovery. |
| Preferred prover/relay/archive gone; fee/rent shortage or fee increase | Recover using only declared replacements; account for exact unpaid principal/fees/rent. The later integration success condition is confirmed native payout, not receipt creation or exit intent. |
| Recovery privacy trace | Keep note secrets/paths out of RPC, proof journals and logs; record all archive requests and state any interest/timing leak. Full-update download avoids a selected-note query but does not prove network anonymity. |

**Unresolved:** final note/encryption construction, physical tree and snapshot
format, trust bootstrap, long-term data replication, independent proving costs,
fee availability and migration/reorg semantics. No established protocol source
eliminates those Kaspa-specific obligations. This memo supplies requirements for
the review and test plan; it does not close P09/P10/P12 or establish I-10.
