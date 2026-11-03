# Established shielded-value mechanisms: primary-source refresh

**Reviewed:** 2026-11-03. **Scope:** design evidence for open
[RFC-0004](../docs/rfc/0004-native-kas-private-payment-boundary.md), with no
implementation or architecture selection. Repository heads were resolved through
the official GitHub API and the cited files read at those exact commits. A head
identifies source, not the code running on a particular network. No protocol,
wallet, proof, funded trial or recovery experiment was run.

## Result for the native-KAS proposal

Established designs separate five obligations: hide note contents, authorize
spending, prevent repeated spending, conserve bounded value, and deliver enough
authenticated data for the recipient to spend. Copying only a commitment or
membership proof omits the other obligations. Orchard and ordinary Monero
RingCT transfers implement confidential native value through their respective
consensus systems. MWEB implements an optional confidential native domain with
public peg-outs. Aztec and RAILGUN supply useful application-state patterns,
under different settlement/custody assumptions. Sources and limits follow below.

**Design inference:** a Kaspa proposal should reuse these obligations and review
their composition, rather than claim that one protocol's proof or encrypted
ledger changes the meaning of an ordinary KAS output. Staying in a new
consensus-recognized shielded representation and later converting into an
ordinary transparent output remain different capabilities. None of these
references establishes KPI's known-owner/full-drainage privacy requirement.

## Source identities

| Source | Exact inspected identity | Source commit date (UTC) | Scope |
| --- | --- | --- | --- |
| Zcash Orchard | [`616a669df8c9a59c33d47064d3ce04b25d026b2e`](https://github.com/zcash/orchard/commit/616a669df8c9a59c33d47064d3ce04b25d026b2e), crate 0.16.0 | 2026-09-30 | Library/design source; versions must remain explicit. |
| Zcash protocol / ZIPs | [`ff594de6e95bb9e9e7d2ace09510281531c30447`](https://github.com/zcash/zips/commit/ff594de6e95bb9e9e7d2ace09510281531c30447) | 2026-10-30 | `protocol/protocol.tex` contains upgrade-conditional text, including Ironwood; this note isolates Orchard mechanisms. |
| Zcash compact wallet format | [`a551fac8a233f54799ca1920ef78ef098cfda929`](https://github.com/zcash/librustzcash/commit/a551fac8a233f54799ca1920ef78ef098cfda929) | 2026-10-27 | Compact-block schema, not a claim about every lightwallet service. |
| Litecoin LIPs | [`73cb2a6cea05b3891e7986ca215e7ccf4a49cb41`](https://github.com/litecoin-project/lips/commit/73cb2a6cea05b3891e7986ca215e7ccf4a49cb41) | 2026-02-27 | LIP-0002/0003/0004 design context; implementation documents below determine the inspected concrete profile. |
| Litecoin Core | [`ec1b6489a900d09cf5991e220dce089c77a232a2`](https://github.com/litecoin-project/litecoin/commit/ec1b6489a900d09cf5991e220dce089c77a232a2), v0.21.5.8 | 2026-09-09 | MWEB consensus, keys, kernels, recovery and native boundary. |
| Monero | [`b14fae7bca4099cea56205e44c1005602834b7bd`](https://github.com/monero-project/monero/commit/b14fae7bca4099cea56205e44c1005602834b7bd) | 2026-11-02 | Current `master` implementation inspected, not a deployed-release assertion. |
| Aztec packages | [`3c25bee4cffc3d5f95990c95425cc9f983eb65cf`](https://github.com/AztecProtocol/aztec-packages/commit/3c25bee4cffc3d5f95990c95425cc9f983eb65cf) | 2026-11-02 | Current `next` docs and L1 contracts; development snapshot. |
| Aztec node/library submodule | [`ea00f1b0939d034448fce9c16d461a7ea363a992`](https://github.com/aztec-labs-eng/aztec-node/commit/ea00f1b0939d034448fce9c16d461a7ea363a992) | 2026-10-21 | The packages snapshot's `labs` gitlink; public source, resolved through [`.gitmodules`](https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/.gitmodules). Old monorepo paths must not silently substitute for this code. |
| RAILGUN V2 contracts | [`36bcf5ed7cf94bfafb6e1a303e1832c769c16780`](https://github.com/Railgun-Privacy/contract/commit/36bcf5ed7cf94bfafb6e1a303e1832c769c16780) | 2026-08-15 | Selected contract snapshot; deployment matching was not checked. |
| RAILGUN V2 circuits | [`0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb`](https://github.com/Railgun-Privacy/circuits-v2/commit/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb) | 2025-08-22 | V2 JoinSplit/nullifier circuits; not an assertion about V3. |
| RAILGUN engine | [`6e2614d53a106dd62abad91e7ce03ee4a3956138`](https://github.com/Railgun-Community/engine/commit/6e2614d53a106dd62abad91e7ce03ee4a3956138), 9.6.0 | 2026-06-19 | Engine supports version-specific formats; V2 is examined here. |

## Mechanism comparison

| Reference | Value and spend mechanism | Recipient / recovery mechanism | What cannot transfer directly to Kaspa |
| --- | --- | --- | --- |
| Orchard | Hidden notes; Action net-value commitments; binding signature; membership and nullifiers. [O1][O2] | Separate viewing/spending authority; encrypted notes; ordered commitments, nullifiers and witnesses. [O3][O4] | Halo2/Pasta proof format, native pool accounting, accepted roots and history retention are protocol-specific. [O5] |
| Litecoin MWEB | Pedersen commitments, bounded Bulletproofs, kernel balance; explicitly identified UTXO spends. [L1] | Scan/spend keys, view tags, encrypted value/nonce; PMMR plus current unspent set. [L2][L3] | Extension-block/HogEx consensus; visible input identifiers; public peg-outs and six-block maturity. [L1][L4] |
| Monero | RingCT commitment balance and range proofs; CLSAG ring authorization; unique key images. [M1][M2] | One-time recipient outputs; view/spend separation; amount decoding checked against commitments. [M3][M4] | Ring-member/decoy distribution, native chain state, pruning and verifier assumptions. [M2][M5] |
| Aztec | App-defined notes/nullifiers, kernel siloing; app must enforce asset conservation. [A1][A2] | Wallet/PXE, tagged messages, selectable delivery guarantees; blobs and historical archives. [A3][A4] | Account/kernel/AVM/prover/sequencer/L1 protocol and portal assumptions; generic private state is not native KAS. [A5][A6] |
| RAILGUN V2 | Same-token JoinSplit balance, signed effects, tree-scoped nullifiers; EVM token release. [R1][R2][R3] | Viewing/spending roles; encrypted events; reconstructed commitment trees. [R4][R5] | ERC-20/ERC-721 contract custody, EVM accounting, verifier/admin authority, relayer policy and public unshield boundary. [R3][R6] |

## Orchard: native shielded pool reference

**Verified source facts.** `protocol.tex` sections labelled `actions`,
`orchardbalance`, `actionstatement` and `actionencodingandconsensus` separate
membership/authorization/nullifiers from bounded-value and transaction-balance
conditions. An Action commits to spent value minus newly created value; the
binding signature connects the aggregate to the public signed `valueBalance`.
It is not sufficient to prove knowledge of a note opening. [O1][O2][O8]

The key hierarchy separates spending authority, incoming viewing and outgoing
recovery. Encryption uses the note-encryption domain, ephemeral key and
ciphertexts. `CompactOrchardAction` publishes the spend nullifier, output
commitment, ephemeral key and only a 52-byte ciphertext prefix; full memos need
additional transaction data. Ordered commitments/tree size support witness
maintenance. A compact message is a transport format whose completeness and
chain authentication must still be established. [O3][O4][O7]

**Reuse/adapt.** Wallet-local proof construction, distinct spending/viewing
roles, membership plus deterministic nullifiers, range semantics, effect-bound
authorization and explicit public pool crossing are useful established
requirements. Specify what a seed can rediscover from retained public data and
what outgoing metadata requires separate retention. [O1][O3][O4]

**Limit.** Orchard 0.16.0 uses Halo2 and Pasta curves; current reviewed Kaspa
dispatch accepts Groth16 and RISC0 succinct tags. Orchard proofs are therefore
not directly accepted by that ABI. A new verifier or an independently reviewed
adaptation/wrapper would introduce fresh correctness, cost and artifact
requirements. Neither path is implemented here. [O5][K1]

The public balancing value and ordinary transparent outputs disclose the pool
crossing; shielded fees do not erase this boundary. ZIP 317 prices logical
actions, exposing transaction shape/cost even while note values remain hidden.
No claim that a large tree alone guarantees effective anonymity follows.
[O1][O6]

## MWEB: confidential native domain with transparent peg-outs

**Verified source facts.** `consensus.md` sections **UTXO LeafSet**,
**Bulletproofs**, **Kernel Sums**, **Pegging-In && Pegging-Out** and **HogEx**
specify current unspent-output checks, `[0, 2^64)` output ranges, commitment
balance and native domain accounting. Inputs name the output being consumed;
this is not hidden membership with an Orchard-style nullifier. Peg-outs contain
an amount and script, and matching ordinary outputs are required. Peg-outs
require six blocks to mature; the first HogEx reserve output is exempt.
Kernel fees are explicit. [L1][L4]

`stealth-addresses.md` separates master scan/spend keys. Output identification
checks a view tag, recovers value/nonce and verifies the commitment and key
exchange; a matching tag alone does not establish a valid received coin.
PMMR pruning authenticates retained structure without retaining all spent
output content. [L2][L3]

`light-clients.md` explicitly warns that giving an external server the private
view key exposes belonging outputs and amounts. Its client-filtering discussion
is a proposal source; it does not establish that every wallet implements that
path. [L5]

**Reuse/adapt.** Study explicit domain totals and boundary matching, bounded
commitment conservation, separated discovery keys, and authenticated compact
unspent-state recovery. Preserve the distinction between restoring spendable
coins and reconstructing complete historical activity. [L1][L2][L3][L5]

**Cannot adopt directly.** An extension block and HogEx require consensus rules;
they are not a generic covenant application. Visible spend identifiers give a
different graph-privacy model, while public amount/script peg-outs preserve the
transparent-exit problem. MWEB's six-block maturity is also a mismatch with
RFC-0004's no-forced-delay requirement; do not silently import it. [L1][L6]

## Monero: confidential native transfers under ring assumptions

**Verified source facts.** `rctSigs.cpp::verRctSemanticsSimple` checks output
commitments plus the public fee against pseudo-output commitments and verifies
range proofs, including Bulletproofs+. `verRctNonSemanticsSimple` separately
verifies ring authorization, including CLSAG. The blockchain checks previously
used key images. These responsibilities are distinct: hiding value does not
itself prevent a second spend. [M1][M2]

Wallet scanning uses the view key/output derivation and view tags to find
one-time recipient outputs. `decodeRct` checks the decoded amount/mask against
the output commitment. View-only state cannot automatically derive all spending
information: the wallet explicitly tracks whether a key image is known and can
import cold key images. [M3][M4]

The wallet's `gamma_picker` and blockchain ring-size rules make the selected
decoy universe/distribution part of the model. Monero's pruning retains
transaction base data while distributing retained subsets of prunable signature
data; one pruned node is not a complete historical proof archive. [M2][M3][M5]

**Reuse/adapt.** Separate value balance, bounded ranges, spend authorization,
spent markers and recipient discovery. Ordinary RingCT transfers show that
native confidential transfers need not cash out to a transparent reserve output
for each payment. This describes Monero's consensus, not a Kaspa capability.
[M1][M2][M4]

**Cannot adopt directly.** Ring ambiguity depends on plausible decoys, chain
history, wallet sampling and legitimate observer knowledge. It is not anonymity
over every past output. Kaspa's selected UTXO/history model and ZK ABI do not
inherit Monero's CLSAG/Bulletproofs+ verifier or pruning rules. Re-proving those
rules in another system would be additional cryptographic work, not a drop-in
integration. Fees, timing, output/ring counts and receiver disclosures remain
observations. [M1][M2][M3][K1]

## Aztec: private execution and data delivery under a larger protocol

**Verified source facts.** Current docs describe private execution/proving in
the user's PXE, with sequencer/public execution and later Ethereum settlement.
The submodule's `NoteHash` interface separates note commitment, constrained
nullifier computation and an explicitly unconstrained helper. Kernel processing
siloes note hashes/nullifiers by contract. `UintNote` contains a `u128` value;
generic note plumbing does not enforce token conservation for every app.
[A1][A2][A5]

**Current delivery distinction.** The inspected docs offer `offchain()`,
`onchain_unconstrained()` and `onchain_constrained()`. The constrained mode
constrains correct encryption and discovery tagging and publishes the message;
the other modes have weaker delivery guarantees. The external-recipient default
uses a non-interactive handshake, which discloses recipient handshake
participation. Address-derived tagging needs a known sender; interactive
handshakes need recipient participation. Tag queries leak request interest to
the serving node. These are separate choices, not one universal seed-only
recovery guarantee. [A3][A7]

Publication in Ethereum blobs and long-term retrieval are distinct. The blob
guide identifies limited L1 retention and external file-store/archive sources
for old data. Offchain delivery requires the application to retain/transmit its
messages. The L1 Outbox accepts rollup message roots and maintains consumed
message state; this depends on the rollup's root/leaf semantics, including stable
message identifiers across partial-epoch proofs. [A4][A6][A7]

**Reuse/adapt.** Keep proof construction local; separate view/nullifier/signing
roles; domain-separate hashes; specify whether recipient delivery is proven;
retain accepted note data plus witness-update information independently. Indexed
nullifier trees are an implementation candidate with their own predecessor,
duplicate and root-consistency obligations. [A1][A2][A8][A10]

**Cannot adopt directly.** Aztec is an Ethereum L2 protocol with account,
kernel, sequencer, prover, bridge/portal and DA rules. Neither a generic app
note nor an L2-to-L1 message is a Kaspa confidential native output. Private fee
payment also has fee-payer/public-call metadata; the privacy guide identifies
transaction fingerprints and witness-query leakage. Independent Kaspa exits
must be specified separately from successful operation of Aztec's normal
services. [A5][A6][A9][A11]

## RAILGUN: shielded contract-held assets and public unshielding

**Verified source facts.** V2 `JoinSplit` verifies a signature over the root,
bound-parameter hash, nullifiers and outputs; checks input membership and output
ranges; and enforces same-token input/output equality. `NullifierCheck` derives
the marker from the nullifying key and leaf index. The contract's spent set is
indexed by tree number and nullifier, and its roots are also tree-scoped. The
tree number/context must not disappear when adapting the hash formula. [R1][R2][R11]

Contract validation binds chain ID, accepted root, transaction parameters and
the unshield preimage. `transferTokenOut` releases ERC-20/ERC-721 assets from
contract holdings; ERC-20 release and treasury fees are public, and an Unshield
event exposes recipient/token/value information. This is EVM custody/accounting,
not consensus-native confidential KAS serialization. [R3]

Engine keys distinguish viewing/nullifying roles from spending authorization.
V2 encrypted events carry tree positions and note data; successful decryption
is followed by a note-hash check against the accepted commitment. Public roots
alone cannot reconstruct missing historical encrypted events. [R4][R5]

**Service boundary.** Official unversioned broadcaster documentation, retrieved
2026-11-03, describes private-balance compensation to a broadcaster that pays
public gas. It does not establish network anonymity against every observer.
Official PPOI docs separate list/proof policy from the core contracts and
describe a self-broadcast return to the original shielding address while PPOI
is incomplete. That return has a public-address boundary; it is not evidence of
privacy-preserving exits during every service failure. [R7][R8]

**Reuse/adapt.** Explicit complete-effects binding, same-asset/range semantics,
tree-scoped spentness, validated encrypted-event scanning and fees paid from
private value are useful requirements. Native KAS reserve release, parameter
availability, independent history access and fee volatility need their own
specification. [R1][R2][R3][R5]

**Cannot adopt directly.** Contract admin powers include verifier-key setting
and proxy upgrades. They are source trust assumptions, not a KPI recovery
mechanism. Groth16 compatibility alone does not establish matching key/proof
encodings, public inputs, setup or native effects. The V2 circuit repository
explicitly grants no license: conceptual study is not permission to import its
code. [R6][R9][R10][K1]

## Requirements and open specialist questions

The following are **design inferences**, not implemented capabilities:

1. **Consensus value/accounting:** specify the native confidential/shielded
   serialization, amount ranges and binding of public entry/exit/fees to hidden
   value. State what prevents a hidden counterfeit from becoming an accepted
   liability; a public aggregate reserve total alone does not establish every
   private entitlement.
2. **Authority/state:** specify key separation, authorization of exact effects,
   canonical marker derivation, accepted roots, current spentness, replay domains
   and reorg behavior together. Choose hidden-membership notes or a different
   model explicitly; MWEB output identifiers and Monero rings are not equivalent
   to Orchard nullifiers.
3. **Recipient/recovery data:** specify whether encryption/delivery correctness
   is proven, the public record retained after pruning, witness reconstruction,
   independent archive/bootstrap authentication, exact verifier/prover artifacts
   and backup metadata. A seed and root are insufficient when required messages
   or parameters have disappeared.
4. **Boundary/liveness/privacy:** separate spending to another shielded holder
   from transparentization. Review public fees, owner disclosures, public totals,
   small activity sets, timing, query/transport metadata and complete drainage.
   A forced peg-out maturity, fixed relay policy or upgrade administrator must
   not enter the proposal silently. Confidential native outputs still require
   a complete observer-model review before claiming the target is satisfied.

No protocol code or cryptographic primitive is selected here. A specialist must
resolve proof/backend feasibility, supply soundness, migration/version domains,
availability guarantees, licensing and the complete privacy claim before any
implementation proposal is treated as reviewed.

## Exact files and sections

[O1]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L4280-L4325
[O2]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L7415-L7500
[O3]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/book/src/design/keys.md
[O4]: https://github.com/zcash/librustzcash/blob/a551fac8a233f54799ca1920ef78ef098cfda929/zcash_client_backend/lightwallet-protocol/walletrpc/compact_formats.proto#L117-L136
[O5]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/Cargo.toml#L1-L38
[O6]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/zips/zip-0317.rst#L119-L180
[O7]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs#L261-L353
[O8]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L8183-L8310
[L1]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md#L101-L192
[L2]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/stealth-addresses.md#L18-L104
[L3]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/pmmr.md
[L4]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md
[L5]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md
[L6]: https://github.com/litecoin-project/lips/blob/73cb2a6cea05b3891e7986ca215e7ccf4a49cb41/lip-0002.mediawiki#L38-L90
[M1]: https://github.com/monero-project/monero/blob/b14fae7bca4099cea56205e44c1005602834b7bd/src/ringct/rctSigs.cpp#L1358-L1540
[M2]: https://github.com/monero-project/monero/blob/b14fae7bca4099cea56205e44c1005602834b7bd/src/cryptonote_core/blockchain.cpp#L3148-L3426
[M3]: https://github.com/monero-project/monero/blob/b14fae7bca4099cea56205e44c1005602834b7bd/src/wallet/wallet2.cpp
[M4]: https://github.com/monero-project/monero/blob/b14fae7bca4099cea56205e44c1005602834b7bd/src/ringct/rctSigs.cpp#L1558-L1586
[M5]: https://www.getmonero.org/resources/moneropedia/pruning.html
[A1]: https://github.com/aztec-labs-eng/aztec-node/blob/ea00f1b0939d034448fce9c16d461a7ea363a992/noir-projects/aztec-nr/aztec/src/note/note_interface.nr
[A2]: https://github.com/aztec-labs-eng/aztec-node/blob/ea00f1b0939d034448fce9c16d461a7ea363a992/noir-projects/aztec-nr/uint-note/src/uint_note.nr#L23-L85
[A3]: https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/docs/docs-developers/docs/foundational-topics/advanced/storage/note_discovery.md
[A4]: https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/docs/docs-operate/operators/setup/blob_storage.md#L10-L48
[A5]: https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/docs/docs-developers/docs/foundational-topics/transactions.md#L23-L37
[A6]: https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/l1-contracts/src/core/messagebridge/Outbox.sol#L21-L112
[A7]: https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/docs/docs-developers/docs/aztec-nr/framework-description/note_delivery.md#L37-L183
[A8]: https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/docs/docs-developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree.mdx
[A9]: https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/docs/docs-developers/docs/resources/considerations/privacy_considerations.md#L63-L129
[A10]: https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/docs/docs-developers/docs/foundational-topics/index.md#L65-L85
[A11]: https://github.com/AztecProtocol/aztec-packages/blob/3c25bee4cffc3d5f95990c95425cc9f983eb65cf/docs/docs-developers/docs/foundational-topics/transactions.md#L117-L141
[R1]: https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom
[R2]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol#L26-L58
[R3]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol
[R4]: https://github.com/Railgun-Community/engine/blob/6e2614d53a106dd62abad91e7ce03ee4a3956138/src/wallet/abstract-wallet.ts#L405-L438
[R5]: https://github.com/Railgun-Community/engine/blob/6e2614d53a106dd62abad91e7ce03ee4a3956138/src/wallet/abstract-wallet.ts#L560-L640
[R6]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Verifier.sol#L23-L42
[R7]: https://docs.railgun.org/developer-guide/wallet/broadcasters
[R8]: https://docs.railgun.org/wiki/assurance/private-proofs-of-innocence
[R9]: https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/License.md
[R10]: https://github.com/Railgun-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/proxy/ProxyAdmin.sol#L35-L59
[R11]: https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/nullifier-check.circom
[K1]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/crypto/txscript/src/zk_precompiles/tags.rs#L5-L20
