# Sender-private lifecycle: primary-source refresh

**Observed:** 2026-10-25 UTC. **Purpose:** source/design gate for
[RFC-0028](../../../docs/rfc/0028-sender-private-native-kas.md) and
[ADR-0065](../../../docs/adr/0065-sender-private-admission.md), before a new
construction implementation. No original wallet secrets, owner maps, proofs or
transactions were inspected or produced for this source review.

## Existing KAS experiment

Baseline `2e56d8a10fde5c998dde3bac3c7070c9d36f6827` completed the bounded financial
lifecycle. Relevant source is under `poc/owner-private-lifecycle/`:

- `bootstrap/fund_worker.py:62–76` emits a participant-labelled ordinary funding
  payload. GN3 backing does not require that marker.
- `wallet/worker.py:270–272` exports participant/NF/CV READY. `integration/driver.py:84–92,169–177`
  validates the pairing and preserves roster order. Its `205–208` proof
  finalization also receives authorizations in owner-associated slots.
- `wallet/worker.py:330–334` already searches for exactly one own NF/CV in the
  projection; the financial Spend statement contains no participant index.
  `338` binds domain, prior CM root, NF/CV and whole effects.
- `integration/construction/kpx7_mix.mpc` uses stock jointly generated random
  keys and an oblivious Batcher sort over complete output tuples; it currently
  does not mix input rows or post-effects authorizations.
- `wallet/worker.py:206,224,233,285,328` depends on persistent roster identity.
  Recovery must be changed explicitly when round aliases change.
- `integration/construction/codec.py` uses canonical 31-byte limbs under exact Q,
  fixed private input widths, checked public engine parsing and complete tuples.
  Reuse those rules; do not introduce field reduction/encoding aliases.

These are source facts. The composed two-phase attribution privacy remains a
hypothesis requiring its own review and prospectively frozen measurement.

## Current Kaspa / Toccata

Exact official default-branch heads inspected:

| Repository | Commit |
| --- | --- |
| kaspanet/docs | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` |
| kaspanet/rusty-kaspa | `4edcbbccb449f84832afb1ca157904b35f37d006` |
| kaspanet/kips | `e4ae2332117b5cb68bd6188e065ef885b6d17939` |
| kaspanet/vprogs | `f9b84a863a7c7c20586a9cf947550475e894f72e` |
| kaspanet/research | `c923faca11a49148fa7d912d27ce00197a5c5a4a` |

- [KIP-16](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0016.md),
  [actual opcode](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/opcodes/mod.rs#L758)
  and [tags](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/tags.rs#L7)
  retain native Groth16/R0Succinct verification. Reuse existing selected
  verification; admission metadata changes do not replace native acceptance.
- [KIP-20](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0020.md#L29)
  and [inline ZK guide](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx#L25)
  require actual successor/policy/state binding beyond proof validity. Preserve
  complete-effects/current-UTXO checks in the new client protocol.
- [Transaction hashing implementation](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/hashing/tx.rs#L354)
  distinguishes v1 txid from whole transaction hash: txid does not commit to
  compute budget/mass. [Budget units](https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/mass/units.rs#L69)
  retain explicit checked conversions. Retain whole-case equality, not txid-only
  evidence. Current docs mention KIP-24/25, but neither corresponding file exists
  at the inspected KIPs head; they are not listed as inspected specifications.
- The [decision guide](https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx)
  starts with state layout. [vProgs README](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md#L5)
  labels the runtime early/prototype; [settlement code](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/covenant/src/settlement.rs#L1)
  binds state/lane activity, while [auth helpers](https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/zk/backend/risc0/runtime-processor/src/auth.rs#L1)
  implement P2PK/BIP340 verification, not anonymous client admission.
- [Research yellow-paper source](https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/main.tex#L122)
  discusses computation DAGs/conditional proofs/stitching; its proposed complete
  architecture is not treated as deployed consensus.

**Design inference:** the inspected off-chain admission/authorization change
does not itself require new consensus or vProgs. This is not a claim that vProgs
is unnecessary for future scaling, shared-state execution or fee architecture.

## Established privacy designs

| System and inspected primary identity | Reused or adapted | Not inferred or imported |
| --- | --- | --- |
| [Zcash protocol](https://zips.z.cash/protocol/protocol.pdf), v2026.7.0-344-g2bdf39 (2026-10-21), [revision2bdf39494320e5e04057ac93b1794031ebfb00b5](https://github.com/zcash/zips/commit/2bdf39494320e5e04057ac93b1794031ebfb00b5); [Orchard nullifiers616a669…](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/nullifier.rs) | §§3.9/4.14/4.16/4.18.4 separate hidden ownership, unique nullifiers, randomized authorization and transaction-wide binding. Preserve those requirements. | No curve/circuit/key port; no assumption that cryptographic confidentiality hides coordinator ingress. |
| [Aztec current glossary](https://docs.aztec.network/developers/docs/resources/glossary), Alpha/Testnetv6.0.0; [versioned privacy guidancev5.2.0](https://docs.aztec.network/developers/v5.2.0/docs/resources/considerations/privacy_considerations) | Commitment trees, owner-key nullifiers, encrypted discovery, client-local scanning; explicit timing/query-fingerprint limits. | No new runtime/rollup dependency; giving remote servers queried leaf indices can reveal access linkage. |
| [RAILGUN state docs](https://docs.railgun.org/developer-guide/engine-1/state-structure), explicit [Commitments.sol2afd011854daf35aad155a91d6bf2397e39ca90d](https://github.com/Railgun-Privacy/contract/blob/2afd011854daf35aad155a91d6bf2397e39ca90d/contracts/logic/Commitments.sol) | Separate verified JoinSplit effects, historical roots and nullifier accounting from hidden ownership. | The code pin is the documentation reference, not a latest-deployment claim. No Solidity upgrade/admin path or relayer-privacy claim imported. |
| [Zero to Monero2](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf), 2020 background; current inspected [verification3fd0f88c20f559839cafb20911cb13cb45eba7bd](https://github.com/monero-project/monero/blob/3fd0f88c20f559839cafb20911cb13cb45eba7bd/src/cryptonote_core/tx_verification_utils.cpp) | One-time recipients, linkable key images and confidential amounts address distinct concerns; exact signature/input binding remains essential. | No switch to ring signatures or new token. |
| [MWEB LIP4](https://github.com/litecoin-project/lips/blob/73cb2a6cea05b3891e7986ca215e7ccf4a49cb41/lip-0004.mediawiki), still labelled Draft; [light-client guidanceec1b6489a900d09cf5991e220dce089c77a232a2](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md) | Separate scan/spend keys and noninteractive receiving; retain owner-local discovery. Sharing a view key for filtering reveals outputs/amounts. | Stealth receiving does not hide this protocol's public participant/input ordering; no consensus/input-format port. |

Current-source caution: the Orchard specification §4.18.4 records a pre-NU6.2
variable-base gadget soundness correction and changed verifying key. This is a
reason to pin reviewed circuit/key versions, not an assertion about this KAS
relation. The [official MWEB postmortem](https://litecoin.com/news/litecoin-mweb-security-incident-postmortem)
(2026-04-28) describes missing full input-metadata revalidation in block
connection despite checks on other paths. Retain actual consumed-context/native
validation; a host or mempool check is insufficient.

## Admission candidates and selected reuse

[MP-SPDZ documentation](https://mp-spdz.readthedocs.io/en/latest/readme.html)
identifies `mascot-party.x` as malicious-security arithmetic MPC with dishonest
majority. Reuse the already selected engine binary
`47d9ae6f52003825946a4abb6cf9dc62f62a4e2fc2c19a5e3ee6f59a6889b07e`
and pinned installation. Current documentation is a source refresh, not a silent
engine upgrade. Extend the existing complete-row random-key Batcher construction
to independent input and post-effects authorization lists; the composition and
metadata boundary remain new review obligations. Checked MPC output and at
least two honest eligible owners are required for the selected attribution
claim; one remaining unknown owner is identifiable by elimination.

The [WabiSabi paper](https://eprint.iacr.org/2021/206.pdf), §5, uses established
anonymous credentials to separate registrations and discusses network-identity
isolation and timing/connectivity leakage. The [official paper/protocol repository](https://github.com/WalletWasabi/WabiSabi)
and its [actual protocol attack section](https://github.com/WalletWasabi/WabiSabi/blob/master/protocol.md#attacks-on-privacy)
are inspected as an alternative family, not imported implementation code. The
protocol explicitly leaves targeted denial/intersection attacks to transaction
structure. The PDF endpoint refused direct retrieval during this refresh;
[official paper source](https://github.com/WalletWasabi/WabiSabi/blob/master/main.tex)
and protocol text supplied the inspected content. Defer a new credential
issuance/presentation/anti-replay subsystem: the existing MPC can first test the
specific input/admission/proof-slot leak with fewer new components. Anonymous
transport alone cannot remove explicit participant-labelled payloads; credential
unlinkability alone does not qualify endpoint or amount/timing anonymity.

The selected first candidate also has a known active overlap/intersection
limitation: phase-one disclosure of stable nullifiers followed by abort and
different known cohort membership can expose ownership across retries. Fresh
round aliases and a private attempt lock do not close that channel under
seed-only recovery. Preserve its expected failure in the frozen study; possible
positive results are passive/honest-scheduling bounds only.

The selected adaptation is an off-chain change under unchanged financial
parameters. A fresh pool/session plus the existing complete-effects/state/
outpoint bindings separate it from old instances. Old trials and privacy/fee
failures remain immutable. No source here proves this new composition private,
secure, production-ready or independently administered.
