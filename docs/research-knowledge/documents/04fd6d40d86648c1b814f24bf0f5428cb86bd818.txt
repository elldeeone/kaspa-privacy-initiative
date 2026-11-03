# Privacy and independent recovery: source refresh

Reviewed 2026-10-23 against continuation `63f49405`. This lane performed public
read-only GitHub/file/ref inspection, not a node run, funding, proving or
broadcast. All ten official HEADs below were refreshed with `git ls-remote` and
remain unchanged from the earlier
[primary review](../private-integration/PRIMARY-SOURCES.md).

| Official repository | Observed HEAD |
| --- | --- |
| kaspanet/rusty-kaspa | `4edcbbccb449f84832afb1ca157904b35f37d006` |
| kaspanet/docs | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` |
| kaspanet/vprogs | `f9b84a863a7c7c20586a9cf947550475e894f72e` |
| kaspanet/research | `c923faca11a49148fa7d912d27ce00197a5c5a4a` |
| zcash/orchard | `616a669df8c9a59c33d47064d3ce04b25d026b2e` |
| AztecProtocol/aztec-packages | `e63137d734ef3d0d4d7c031ded0370b5168df800` |
| Railgun-Privacy/contract | `36bcf5ed7cf94bfafb6e1a303e1832c769c16780` |
| Railgun-Privacy/circuits-v2 | `0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb` |
| monero-project/monero | `8340be5e920d881edc006e0896d6074cd06dfb2e` |
| litecoin-project/litecoin | `ec1b6489a900d09cf5991e220dce089c77a232a2` |

The native runtime execution pin stays official2.1.0
`01b532e8b553523216471682649693af92f0fd16`; refreshed master is not substituted.
The [Toccata inline-ZK specification](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx#L24-L70)
separates expected proof/program verification from actual successor-output
binding. The new payout must satisfy both. The
[vProgs README](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md#L5-L7)
still identifies prototype infrastructure; the
[research index](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/README.md)
lists its draft protocol. Neither is assumed required or sufficient for this
native singleton/recovery experiment.

## Existing public issue scope

Connected GitHub issue reads confirm all remain open:

- [P04/#4](https://github.com/olafweller/kaspa-privacy-initiative/issues/4):
  review mature note/ownership/nullification patterns before new cryptography.
- [P10/#10](https://github.com/olafweller/kaspa-privacy-initiative/issues/10):
  retained data, pruning, backups, reorgs and a clean rebuild **plus valid exit**.
  A root or safe halt alone does not close recovery.
- [P11/#11](https://github.com/olafweller/kaspa-privacy-initiative/issues/11):
  genuine proof/backend costs, exact setup identities and witness privacy.
- [P12/#12](https://github.com/olafweller/kaspa-privacy-initiative/issues/12):
  encrypted delivery and private local scanning.
- [P13/#13](https://github.com/olafweller/kaspa-privacy-initiative/issues/13):
  timing/value/RPC/network/wallet leakage, distinct from cryptographic secrecy.
- [Exit liveness/#23](https://github.com/olafweller/kaspa-privacy-initiative/issues/23):
  exact authorization/backing do not guarantee inclusion under unbounded fees.
  No privileged rescue or hidden principal haircut is justified.

No issue/comment was posted or changed.

## Mature designs: what transfers and what does not

| Primary source inspected | Reuse/adaptation | Rejected inference |
| --- | --- | --- |
| [Orchard bundle](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle.rs#L439-L556) and [binding construction](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle.rs#L763-L783) separate actions and public value balance. Its [incoming parser](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs#L339-L350) reconstructs recipient authority. | Public native movement is another explicit term in hidden-input/private-change conservation. Decrypt/rederive before credit. | Pallas/Halo2 security, native consensus or reusable address safety is not inherited. |
| [RAILGUN join-split](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom#L14-L100), [unshield validation](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol#L420-L465), and [wallet scanning](https://github.com/Railgun-Community/engine/blob/6e2614d53a106dd62abad91e7ce03ee4a3956138/src/wallet/abstract-wallet.ts). | Bind nullification/hidden ownership, exact public release and local reconstruction from retained encrypted events. | No EVM token, privileged upgrade, list-service authority or restricted circuit code is imported. |
| [Aztec CompleteAddress](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/yarn-project/stdlib/src/contract/complete_address.ts#L12-L88) and [Outbox recipient/chain/membership checks](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/l1-contracts/src/core/messagebridge/Outbox.sol#L118-L165). | Authenticate structured receiver descriptors; separate accepted-state identity, authorization and destination binding. | Redeeming an accepted message does not authorize an unconsumed private note; no sequencer architecture is copied. |
| [Monero recovery](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/cryptonote_basic/account.cpp#L175-L212), [key/output derivation](https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/device/device_default.cpp#L195-L280), and [wallet scan comparison](../../monero.md). | Keep seed-derived viewing/spending roles distinct and specify scan start/indices and historical spentness. | RingCT/CLSAG, reusable addresses and Monero's pruning split are not Kaspa primitives or availability guarantees. |
| [MWEB client-side filtering guidance](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md#L13-L25) and [receiver checks](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md#L78-L105). | Fetch public pool data and derive ownership locally; never send the view/seed key to an untrusted RPC. | MWEB UTXO proofs, curve commitments and consensus extensions do not solve Kaspa archive authenticity. |

The existing [Orchard](../../zcash-orchard.md), [Aztec](../../aztec.md),
[RAILGUN](../../railgun.md), [Monero](../../monero.md) and
[MWEB](../../litecoin-mweb.md) comparison reports were reread. References retained
from those comparisons remain pinned; inspecting current heads does not relabel
older source examples as execution of newer versions.

## Facts, hypotheses and limits

**Fact:** current native REVEAL publishes Note/CM/k and the CM-bound native key.
The [actual six-body result](../testnet-rehearsal/RESULTS.md) is a complete
testnet mechanics result, not privacy qualification. **Inference:** hidden-note
proof authorization plus private change removes those direct opening/equality
channels, conditional on the new relation and correct native binding. Public
P/fee/drainage and known counterparty records can still force amounts/links;
only a prospectively frozen observer evaluation can characterize the difference.

**Recovery hypothesis:** public data fetched independently from a retained
anchor and replayed locally can remove the preferred operator archive. It still
needs user-authenticated canonical pool identity, an honest validating view and
surviving data. A seed cannot supply unavailable encrypted receipts or orphan-only
disclosures. No new persistent storage infrastructure or archive deployment is
selected by this source report.
