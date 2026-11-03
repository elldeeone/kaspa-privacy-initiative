# Early privacy audit: public surface and observer sources

Reviewed 2026-10-20 against local commit
`6dff59dfa16917170a2bebf4b6f4d29aca9146a7`.
This note supports the first public-byte audit and observer/control specification
under [RFC-0012](../docs/rfc/0012-useful-privacy-requirements.md). It proposes no
new cryptography, privacy mitigation or change to the adopted thresholds.

Reuse the pinned [requirements review](shielded-kas-privacy-requirements-2026-10-20.md)
and [wallet source review](shielded-kas-admission-recovery-2026-10-20.md).
Their fourteen upstream heads were rechecked earlier today without changes.
The additional source excerpts below were inspected at those same commits.

## Upstream issue and evidence boundary

[Issue #13, practical privacy leakage analysis][issue13], remains open with zero
comments. Read-only issue/comments API checks on 2026-10-20 returned creation
and last-update time `2026-10-02T13:58:54Z`; initiative main still resolves to
`52bb2b4e7a1e0a8f98aecb58d33933f0b03d9e33`.

The issue calls for deposit/withdrawal timing, amount, RPC, network and wallet
correlation; private-witness exposure to outsourced provers/executors; and public
lane payload/resource-access analysis. It distinguishes confidentiality from
measured anonymity. It supplies no quantified result, observer specification or
acceptance threshold. The local RFC's metrics are not an upstream endorsement.

## Relevant mature-protocol lessons

| Source inspected | Reuse/adapt for the audit | Reject or limit |
| --- | --- | --- |
| [ZIP-224 public pool boundary][zip224] | Observe native ingress/egress amounts and evaluate persistent shielded activity separately from prompt cashout. | Hidden internal notes do not hide public boundary values; a pool balance cap does not prevent forged claims stealing existing backing. |
| [Orchard builder ordering][ordering] and [shuffle implementation][shuffle] | Treat output order and change conventions as information. Orchard pads and randomizes positions to avoid identifying a note's role from its index alone. | This is motivation to test v6's actual ordering, not evidence that shuffling alone fixes v6 privacy or a decision to implement it. |
| [Aztec transaction timing][timing] | Test amounts, delays and repeated public fingerprints jointly. A sender observing a consistent later reaction can learn more than a chain-only observer. | Delayed activity is not automatically independent cover. Synthetic schedules are not observed human behavior. |
| [Aztec fingerprint inventory][fingerprints] | Include roots, operation shape, public arguments/logs and counts even when private execution is hidden. | Fixed-size ciphertexts or two output slots do not establish indistinguishable operation roles. |
| [Aztec historical roots and queries][queries] | An exposed old anchor bounds when input notes existed; leaf-index queries can identify selected notes to a provider. | Fresh anchors do not erase amount, change or counterparty linkage. A chain-only experiment cannot pass an infrastructure-privacy claim. |
| [RAILGUN public events][railgun] | Include the full published commitment/ciphertext/action record used for wallet reconstruction. | Do not supply observers only a conveniently selected commitment summary or import EVM infrastructure. |
| [Monero network boundary][monero] | Separate transaction-origin/network observations from ledger confidentiality. Wallet RPC and peer broadcasting are distinct observation points. | Neither local proving nor absence of plaintext in a transaction implies network anonymity; no Tor/I2P integration is proposed here. |
| [MWEB native boundary][mweb] and [serialized input reference][mwebinput] | Distinguish public pegging values, confidential amounts and observable spend relationships. Specify whether the observer sees intermediate activity. | Amount hiding or later aggregation cannot retroactively remove information already retained by an observer. No extension-block consensus change is proposed. |

These designs have different transaction and adversary models. Reuse their
failure patterns and validation questions, not their anonymity claims or
cryptographic assurance.

## Concrete v6 implications for the first byte audit

The [authorization and settlement encoder](../poc/shared-pool/src/two_input/mod.rs)
publishes the pool domain, anchor/count, two nullifiers, two commitments, mode,
payout, fee, payout script, funding amount/outpoint/script, bootstrap field and
ciphertext digest. The native transaction additionally exposes reserve lineage,
actual values/scripts, signatures, proof bytes, ciphertexts and public settlement
witnesses. Every field and byte range needs an observer classification; fields
not yet interpreted must remain available as raw public data.

The [current wallet](../poc/shared-pool/src/two_input/wallet.rs) constructs Pay
outputs as `[recipient, change]`. For this client policy, a positive second output
belongs to the sender. ADMIT constructs a positive owned output followed by zero
padding. These are source-visible client behaviors, not universal circuit rules.
Observers may condition on the declared policy; do not silently turn it into
knowledge that every unknown client follows it. Zero padding itself is hidden
unless other facts identify it.

A recipient can locate its own decrypted output and know its amount. An author
knows its selected inputs, both created openings and destinations it used.
Those records can combine with fixed ordering, public totals and later withdrawals
to constrain other activity. Knowing a sent note's opening does not give the
sender the recipient's spending secret or its positioned nullifier.
Do not supply recipients with sender identity or sibling plaintext unless the
declared transcript or side information actually provides them.

The earlier [participant-disclosure result](../poc/shared-pool/PARTICIPANT-PRIVACY.md)
already found extra forced source links under its bounded synthetic workload.
Reuse it as a regression/falsification clue. Its source-transaction alternatives
are neither current owner anonymity nor an amount-privacy result.

## Observer projection and falsification requirements

For the forthcoming experiment, retain these distinctions explicitly:

1. **Public chain:** derive structured fields from exact public bytes and retain
   the original records. Include transaction order, funding ancestry, reserve
   values, fee/payout arithmetic, lengths and anchor age. Include timestamps
   only when actually observed or explicitly modeled; file creation times and
   private proving logs are not chain observations.
2. **Participant:** add only that participant's available records through the
   checkpoint. Keep recipient knowledge, author knowledge and pooled collusion
   separate. Link repeated counterparties only where that participant can do so;
   never provide scorer-wide owner labels disguised as anonymous handles.
3. **Infrastructure:** name the RPC/archive/broadcast observations being added.
   Exclude them explicitly when unavailable; do not interpret exclusion as
   evidence that they are harmless.
4. **Horizon:** retain earlier information at payment, later cashouts and full
   drainage. Later disclosure can defeat a claim that held at payment time.
5. **Result:** separate logical forced disclosure, ranked inference, wrong guesses
   and abstentions. A candidate count does not assign probabilities or count
   independent honest people. Solver failure is incomplete analysis.

Controls should expose known singleton/all-other-participants-disclosed cases
and detect observer/scorer information contamination. Public amount conservation,
known fees, fixed change roles and anchor-age restrictions are concrete attack
inputs. A single reproducible unauthorized disclosure can falsify its supported
claim; finding none in a small screen cannot pass the full adopted privacy gate.

No new attack execution, privacy measurement, proof, funded transaction,
deployment or private-record inspection occurred in this source review.
Cryptographic assumptions remain conditional; actual projections and executable
controls still need review against current transaction bytes.

[issue13]: https://github.com/olafweller/kaspa-privacy-initiative/issues/13
[zip224]: https://github.com/zcash/zips/blob/a34cfc091434275120ff017c92c3b50d3cef623a/zips/zip-0224.rst#security-and-privacy-considerations
[ordering]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L786-L814
[shuffle]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L1504-L1508
[timing]: https://github.com/aztec-labs-eng/aztec-node/blob/9babccfcfc083915a5bda1f378fe8bda3a6bd2b8/docs/docs-developers/docs/resources/considerations/privacy_considerations.md#L59-L71
[fingerprints]: https://github.com/aztec-labs-eng/aztec-node/blob/9babccfcfc083915a5bda1f378fe8bda3a6bd2b8/docs/docs-developers/docs/resources/considerations/privacy_considerations.md#L73-L97
[queries]: https://github.com/aztec-labs-eng/aztec-node/blob/9babccfcfc083915a5bda1f378fe8bda3a6bd2b8/docs/docs-developers/docs/resources/considerations/privacy_considerations.md#L99-L125
[railgun]: https://github.com/RAILGUN-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunSmartWallet.sol
[monero]: https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/docs/ANONYMITY_NETWORKS.md#L1-L32
[mweb]: https://github.com/litecoin-project/lips/blob/73cb2a6cea05b3891e7986ca215e7ccf4a49cb41/lip-0003.mediawiki
[mwebinput]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/include/mw/models/tx/Input.h#L80-L98
