# Private change and repeated spending: primary sources

Reviewed 2026-10-23 against continuation `a8392f1127e656da59709e0b6f93ece7cf5eb9c2`.
This lane used read-only public GitHub repository, file, tree and issue calls.
No node, funding, proving, key/backup access, install or broadcast occurred.
Exact public refs and source-blob identities are in [SOURCE-PINS.json](SOURCE-PINS.json).

**Conclusion:** extend the existing Auth528 wallet policy, preserve its proof and
native invariants, and recover change by decrypting its embedded V2 invoice index.
Do not add an operator receipt map, assume seed-only global issuance uniqueness,
or label private change as measured financial privacy.

## Current upstream state

All ten heads in the [previous source refresh](../privacy-recovery/SOURCES.md)
remain unchanged: rusty-kaspa, Kaspa docs/vProgs/research, Orchard, Aztec packages,
RAILGUN contract/circuits, Monero and Litecoin. The initiative upstream remains
`7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`.
Additional inspected scanning sources are RAILGUN engine
`6e2614d53a106dd62abad91e7ce03ee4a3956138` and current librustzcash
`146a08fc779678f6b81997da5f9b7c3378ffccb9`.
The native execution selection remains official 2.1.0,
`01b532e8b553523216471682649693af92f0fd16`; current master is not substituted.

Aztec client/PXE sources have an important location boundary. Its current
[README](https://github.com/AztecProtocol/aztec-packages/blob/e63137d734ef3d0d4d7c031ded0370b5168df800/README.md#L1-L10)
and [.gitmodules](https://github.com/AztecProtocol/aztec-packages/blob/e63137d734ef3d0d4d7c031ded0370b5168df800/.gitmodules)
point to official `aztec-labs-eng/aztec-node`, pinned by the `labs` gitlink to
`ea00f1b0939d034448fce9c16d461a7ea363a992`. That repository's separately
observed main is `65da05e6558c99eed16629710a2d1d8b639dabfe`. The old
`yarn-project` path at the packages head returned 404; the comparisons below
use the explicit submodule pin, not an inferred equivalent old release.

The public issues [P04](https://github.com/olafweller/kaspa-privacy-initiative/issues/4),
[P10](https://github.com/olafweller/kaspa-privacy-initiative/issues/10),
[P11](https://github.com/olafweller/kaspa-privacy-initiative/issues/11),
[P12](https://github.com/olafweller/kaspa-privacy-initiative/issues/12),
[P13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13) and
[exit liveness](https://github.com/olafweller/kaspa-privacy-initiative/issues/23)
remain open. No issue/comment was changed. A clean rebuild must lead to a valid
exit; neither a root nor safe halt closes recovery.

## Established designs: adaptation and rejection

| Primary source fact | Use here | Boundary |
| --- | --- | --- |
| Orchard's [change builder](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L1040-L1083) validates wallet ownership. Its [generic builder](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L1480-L1513) independently shuffles spends and outputs. A separate restricted mode shuffles complete pairs. | Change is an owned private output; its role must not be a fixed public slot. Preserve exact input/output/fee conservation. | Do not copy a restricted mode's pairing rules or infer that padding establishes anonymity. |
| Orchard [plaintext parsing](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs#L75-L98) extracts diversifier/value/randomness, and [incoming parsing](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs#L339-L347) derives the recipient key locally. Its [key rationale](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/keys.md#L83-L94) does not require fresh spending keys per transaction. | V2's encrypted invoice index can similarly carry derivation information so a backup predating change discovers it without an index map. | Our revealable per-index NF credential has different reuse hazards. Orchard's diversified-address/key security is not inherited. |
| RAILGUN's [join-split relation](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom#L15-L35) separates private values/nullifying key and [checks balance](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom#L97-L119). Its [wallet](https://github.com/Railgun-Community/engine/blob/6e2614d53a106dd62abad91e7ce03ee4a3956138/src/wallet/abstract-wallet.ts#L564-L572) requires decrypted notes to rehash to accepted commitments. | Reuse hidden-input/private-change accounting and local decrypt/rederive/commitment checks; use integer sompi and the existing explicit payout/fee terms. | No EVM asset/admin design, restricted implementation code or circuit security claim is imported. Decryption alone is not accepted spendability. |
| Current Aztec [CompleteAddress](https://github.com/aztec-labs-eng/aztec-node/blob/ea00f1b0939d034448fce9c16d461a7ea363a992/yarn-project/stdlib/src/contract/complete_address.ts#L31-L38) validates its structured binding; [note discovery](https://github.com/aztec-labs-eng/aztec-node/blob/ea00f1b0939d034448fce9c16d461a7ea363a992/docs/docs-developers/docs/foundational-topics/advanced/storage/note_discovery.md#L82-L104) checks emitted note hashes and uses retained aged/finalized tag-index windows. | Validate every receive descriptor and accepted CM association; state precisely which data and indices recovery needs. | Do not copy tagged discovery: unknown-sender/handshake state, counters, and [RPC/IP leakage](https://github.com/aztec-labs-eng/aztec-node/blob/ea00f1b0939d034448fce9c16d461a7ea363a992/docs/docs-developers/docs/foundational-topics/advanced/storage/note_discovery.md#L110-L133) are distinct obligations. No sequencer or based-app requirement follows. |
| Monero [recovery](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/cryptonote_basic/account.cpp#L179-L207) separates deterministic view/spend recovery and scan start; [subaddress derivation](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/device/device_default.cpp#L195-L221) commits exact indices. | Keep root seed, viewing/delivery, note authority and native payout roles distinct; specify integer index encoding. | Curve output keys/key images and Monero's retention model are not Kaspa primitives. A seed cannot replace missing ciphertext. |
| MWEB's [receiver checks](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md#L75-L105) include a used-public-key/index map and lookahead. Its [light-client guidance](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md#L13-L21) distinguishes local filtering from sharing view keys. | Fetch public history before local ownership filtering; retain exact commitment/key verification. | Do not silently require its map/lookahead for our old-backup recovery. No scan secret goes to an RPC; MWEB UTXO/pruning assurances are not inherited. |

## Recovery and freshness decisions still required

**Verified local capability:** [V2 Receiver.open](../../../poc/future-recipient/v2/recipient.py)
decrypts the derivation index, rederives every expected invoice field and rejects
a mismatch. The [current cold wallet](../../../poc/private-cashout-wallet/private_action.py)
already reconstructs public roots and current NF state before ownership credit.
The [completed rehearsal](../private-service-loss/RESULTS.md) covers whole-claim
exits, not spending new positive change.

**Design inference:** fresh change can be recovered from seed + retained accepted
ciphertext without a saved operator index map. The ADR must still specify its
index namespace/generation, collision rejection, retry persistence, private slot
allocation, duplicate invoices and any missing pending/orphan-only history.
Randomness or a current accepted-history check does not prove that no unseen
device ever issued the same index. Do not promise global issuance uniqueness.

Reorg handling must roll back acceptance and spentness together. As an established
example, [librustzcash](https://github.com/zcash/librustzcash/blob/146a08fc779678f6b81997da5f9b7c3378ffccb9/zcash_client_sqlite/src/wallet.rs#L4459-L4516)
rewinds scanning, unmines affected transactions and truncates commitment trees.
Our bounded fresh replay may safely halt/rebuild after a changed chain; it cannot
undo disclosures or reconstruct orphan-only receipts that no longer survive.
Prove the next accepted spend from the restored change, not merely recognition.

## Native binding and fees

[Toccata inline ZK](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx#L24-L70)
keeps proof validity and exact successor binding separate.
[vProgs](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md#L5-L7)
remains prototype infrastructure; the [research index](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/README.md)
labels its protocol draft. None is assumed required or sufficient for this wallet extension.

At the selected native runtime, the [Groth16 tag](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/tags.rs#L29-L35)
costs 140,000 grams and [VK loading](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L16-L49)
charges 250,000 script units per gamma-ABC element. With two public inputs this
is 14,750,000 script units / 147,500 mass before transaction/public-check costs.
Five such verifications alone cost 73,750,000 sompi at rate100; faster proving
does not lower this native charge. [Mass calculation](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/mass/mod.rs#L332-L369)
also charges serialized bytes and committed budgets, with contextual storage
separate. A smaller program or a measured path fitting1500 is not a justified
new worst-case budget.

A compact policy is worth screening, but the current circuit explicitly leaves
NF updates/empty CM insertion/continuation to native checks (its opening comment
in [circuit.rs](../../../poc/private-cashout-prover/src/circuit.rs)).
Removing them without constraining their replacement changes safety.
The unchanged [fee screen](../privacy-recovery/fee-feasibility/FEE-FEASIBILITY-01.md)
and 2% target remain in force. No scalar/source-only bound qualifies actual
fees, and private change alone does not remove public P/fee/timing/prior attacks.
