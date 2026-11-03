# Independent wallet recovery: source refresh

Reviewed 2026-10-19 before H7 implementation. Native/SDK pin remains
`01b532e8b553523216471682649693af92f0fd16`. GitHub API current heads: Rusty Kaspa
`f7d7877363fb97c2ec6871be0e8cbc351d44df10`, vProgs
`f9b84a863a7c7c20586a9cf947550475e894f72e`, research
`c923faca11a49148fa7d912d27ce00197a5c5a4a`, KIPs
`e4ae2332117b5cb68bd6188e065ef885b6d17939`. These match the H6 review.
Initiative upstream advanced to
[`da84afb`](https://github.com/olafweller/kaspa-privacy-initiative/commit/da84afbb7daf993f805859ceb40a3fc9f0dabf15),
qualifying a staged GPU service. That is a separate architecture/measurement;
it does not establish independent recovery for this direct compact pool.

| Source inspected | Reuse / rejection for H7 |
| --- | --- |
| [KIP-17](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md), pinned native validator and existing `history`/`scan` code | Keep the accepted compact relation and native transition validation. No new L1 feature is assumed. A root authenticates supplied data, not availability. |
| [vProgs](https://github.com/kaspanet/vprogs/tree/f9b84a863a7c7c20586a9cf947550475e894f72e), [Kaspa research](https://github.com/kaspanet/research/tree/c923faca11a49148fa7d912d27ce00197a5c5a4a) | Keep public-state reconstruction separate from private authorization; no runtime/operator is added merely for recovery. |
| [Orchard note decryption](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs) | Locally discover notes with incoming viewing material and verify domain/commitment before accepting them. Preserve our existing sealed-box encoding; no Orchard security/compatibility claim. |
| [Aztec indexed trees](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree) | Reconstruct authenticated current spentness from public history; an arbitrary predecessor/path from a server is not trusted. No change to H6 trees. |
| [RAILGUN commitments](https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol) | Preserve distinction between historical membership and current nullifier state. Do not import EVM storage or upgrade authority. |
| [Monero wallet restoration](https://www.getmonero.org/resources/user-guides/restore_account.html) | Backup material plus a scan start location must recover received outputs; starting too late can miss funds. Our three independent keys are not a mnemonic seed. |
| [MWEB light clients](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md), [stealth-address recovery](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md) | Keep scanning/ownership checks local; handing viewing keys to a server exposes note ownership/value. Do not import MWEB cryptography or consensus. |

Existing experiment inspection: `PrivateWallet` stores three independent keys
and optionally the funding note. `scan` decrypts transfer ciphertexts, checks
commitments/ownership and removes spent positioned nullifiers. `Manifest`
contains all recipients and is experiment-specific. H7 replaces that recovery
input with a minimal public descriptor authenticated by the user's backup.
Retained public parameters remain essential; the previous P10 archived-instance
gap is not solved by a seed, state root or a server URL alone.
