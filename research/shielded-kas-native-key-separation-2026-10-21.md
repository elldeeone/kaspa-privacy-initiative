# Native funding/exit key separation and recovery

Reviewed 2026-10-20 UTC (2026-10-21 Australia/Sydney), after checkpoint
`b62cfd1910d77f9962882b1088d6cc718e7df1b2` was committed and pushed.
Scope: a wallet-only correction to the demonstrated
[funding/exit script reuse](../poc/shared-pool/ADDRESS-REUSE.md), preserving
[v6 lifecycle recovery](../docs/rfc/0013-coherent-v6-lifecycle.md).
This note recommends a design; it does not report implementation or test results.
No private wallets, new proofs, funds or network transactions were accessed.

## Current sources

Fresh read-only GitHub checks refreshed the
[existing protocol source map](shielded-kas-privacy-requirements-2026-10-20.md).
Kaspa docs, KIPs, rusty-kaspa, vProgs, research, Orchard, RAILGUN contracts,
Monero/code/site, Litecoin/LIPs and Aztec's protocol repository remain at its pins.
Two heads advanced:

| Repository | Current head and UTC commit date | Relevant delta |
| --- | --- | --- |
| `zcash/zips` | `d167dd3994e40790971f8f00b0b330885d2c9fe5`, 2026-10-20 22:33:28 | The 11-commit comparison changes neither ZIP32 nor ZIP316. |
| `aztec-labs-eng/aztec-node` | `29853ddaf2a9f70441fc2f733ada555eb50dbdc0`, 2026-10-20 21:41:42 | The inspected privacy guidance is byte-identical to the previous pin. |

The additional BIP32 source is pinned to bitcoin/bips
`130b8e0fa7f30fa45532f080b87b8db27a79e46e` (2026-10-19 21:21:00 UTC).
NIST SP 800-108r1-upd1 is the February 2024 update; RFC 5869 is May 2010.
These identify source versions, not deployed software or security qualification.

## Reuse, adapt and reject

| Primary source | Reuse/adapt for this correction | Reject or retain as a limit |
| --- | --- | --- |
| [NIST PRF-based derivation][nist], §§6.4–6.6; [HKDF context guidance][hkdf], §§3.2–3.3 | Distinct purpose/context inputs, unambiguous encoding and a strong secret derivation key. | The existing direct HMAC-SHA256 layout is not HKDF or automatically NIST-conformant. These sources do not audit its composition. |
| [Kaspa address purposes][kaspa-purpose] and [legacy derivation dispatch][kaspa-legacy] | Explicit receive/change branches and deliberate legacy/current interpretation are established wallet patterns. Adapt purpose-specific APIs and version dispatch. | Do not import BIP32, xpubs or mnemonics merely to change one HMAC purpose. Local backups are not standard Kaspa-wallet backups. |
| [Toccata binding][inline], [vProgs README][vprogs], [research index][research] | Preserve actual native destination binding and the distinction between wallet behavior and consensus enforcement. | No new opcode, runtime or based-app subsystem follows from this defect. The previously unread research PDF remains unread; no theorem is claimed. |
| [ZIP32 domains and compatibility][zip32], [Orchard domains][orchard] | Adapt fixed domain labels, exact index encoding and explicitly preserved legacy bytes. | [Orchard internal viewing scope][orchard-scope] retains spending-authority components; it is not a drop-in construction for separate native signing keys. |
| [ZIP316 unsupported semantics][zip316] and [Monero restore versions][monero-version] | Interpret versioned data explicitly and reject unsupported semantics. | ZIP316 describes addresses/viewing keys, not private backup storage; do not claim compatibility. |
| [Monero subaddress derivation][monero-subaddress] | A fixed domain and encoded indices illustrate purpose/context separation. | Its output is a tweak in a different curve construction, including special legacy behavior. Do not copy that arithmetic into v6. |
| [Aztec privacy guidance][aztec] | Recheck observable wallet fingerprints and correlations after the narrow correction. | Separate keys do not erase timing, amounts, fixed output roles or counterparty knowledge. |
| [RAILGUN public events][railgun] and [MWEB recovery data][mweb] | Retain public reconstruction and the prior admission/recovery source review's data requirements. | Neither source supplies this wallet's native key profile. Do not change note discovery or assume a seed reconstructs unavailable historical data. |
| [BIP32 scalar handling and wallet branches][bip32] | Reuse the need for explicit valid-scalar handling and separate wallet purposes. | A labelled HMAC output is not BIP32-compatible; do not introduce an HD key tree for this fix. |

## Recommended narrow profile

At the checkpoint, both `Backup::funding` and EXIT call the same
[`native_key`](../poc/shared-pool/src/two_input/wallet.rs), which delegates to
[`Wallet::payout_key`](../poc/shared-pool/src/protocol.rs). That derivation uses
HMAC-SHA256 keyed by the native secret, the fixed `KPI/payout-key/v2\0` prefix,
32-byte pool domain, little-endian u32 index and little-endian u32 retry counter.
The first output accepted as a secp256k1 secret scalar is used. Equal inputs
therefore produce the same native script; this is purposeful determinism, not
a hash collision.

Recommend a new backup/profile version for fresh wallets:

| Profile | Funding derivation | Exit derivation |
| --- | --- | --- |
| Explicit existing v1 | Preserve exact `KPI/payout-key/v2\0` behavior. | Preserve exact `KPI/payout-key/v2\0` behavior. |
| Explicit new v2 | Use a funding-only prefix, proposed `KPI/funding-key/v1\0`. | Preserve exact `KPI/payout-key/v2\0` behavior. |

Retain the established HMAC implementation, pool-domain binding, fixed-width
index/counter encoding and deterministic invalid-scalar rejection. The native
master remains secret derivation material, not a published or directly reused
signing key. Security still assumes its current fresh random 32-byte generation
and HMAC/curve properties. Distinct inputs do not prove mathematically impossible
output collisions; finite vectors cannot establish a cryptographic bound.

Expose `funding_key` and `exit_key` rather than an ambiguous shared native-key
API. Route normal funding, ADMIT ownership checks and the fresh founder helper
through the funding purpose. EXIT and recovery use the exit purpose. Audit the
founder helper's direct `payout_key` call as well as the main wallet interface.
Funding metadata must describe the actual selected profile, not a global label.

This changes wallet destination selection, not the v6 proof relation, note
commitments/nullifiers, backing rules, parameter identity or native consensus.
The proof must continue binding the actual payout script exactly as before.

## Recovery compatibility is part of the correction

Accept only explicitly supported backup-format/derivation-profile pairs; reject
missing, unknown and contradictory metadata. Preserve the original v1 bytes
and evidence. Never silently relabel a backup, guess a profile after failure or
overwrite it with a migrated version. The new fresh-wallet default should be v2.

Keeping legacy exits unchanged preserves the existing recovery index rule:
an EXIT uses the minimum selected note position. A restored wallet reconstructs
owned notes and their positions/spentness from validated public history; it must
not require an unretained payout counter, action file or private sidecar. The
existing descriptor, parameter and historical-data requirements remain those in
the [admission/recovery review](shielded-kas-admission-recovery-2026-10-20.md).

Legacy v1 remains recoverable **and retains its demonstrated reuse risk**.
Merely relabelling the same old native secret as v2 cannot erase old funding
scripts matching future legacy-derived exits. Fresh v2 behavior and historical
v1 compatibility need separate claims; no automatic migration is recommended.
This does not add a general scanner for unrelated native wallet UTXOs.

## Decisive checks and limits

1. Pin independent known-answer vectors for both profiles, multiple domains,
   index zero/boundaries and exact byte encoding. Old results must remain exact.
   Compare actual P2PK scripts as well as secret-key bytes for purpose separation.
   Unknown/mismatched profiles and wrong-purpose funding must fail explicitly.
2. Restore a pre-activity v2 backup after later admission/payment/exit activity,
   reconstruct the same exit key without original request files, and retain an
   explicit v1 restoration regression. Check founder and ordinary admission
   paths separately; a passing helper-only check is insufficient.
3. Repeat the frozen offline reuse diagnostic with the same economic schedule
   and matched index choices. Require native verification, exact accounting,
   no new funding/exit script equality, and removal of the equality-derived
   inference. Preserve the original result and report other surviving inferences.

These checks can establish implementation compatibility and removal of the
tested direct equality. They cannot establish useful privacy generally, the
32-role privacy target, honest setup, cryptographic security, current chain
acceptance or production readiness. The source review introduces no new trust
party or primitive; implementation and adversarial review still remain necessary.

[nist]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
[hkdf]: https://www.rfc-editor.org/rfc/rfc5869#section-3.2
[kaspa-purpose]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/wallet/bip32/src/address_type.rs#L7-L27
[kaspa-legacy]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/wallet/core/src/derivation.rs#L204-L218
[inline]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx
[vprogs]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[research]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/README.md
[zip32]: https://github.com/zcash/zips/blob/d167dd3994e40790971f8f00b0b330885d2c9fe5/zips/zip-0032.rst#L433-L465
[orchard]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/zip32.rs#L130-L133
[orchard-scope]: https://github.com/zcash/zips/blob/d167dd3994e40790971f8f00b0b330885d2c9fe5/zips/zip-0032.rst#L503-L525
[zip316]: https://github.com/zcash/zips/blob/d167dd3994e40790971f8f00b0b330885d2c9fe5/zips/zip-0316.rst#L804-L815
[monero-version]: https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/wallet/wallet2.cpp#L583-L590
[monero-subaddress]: https://github.com/monero-project/monero/blob/8340be5e920d881edc006e0896d6074cd06dfb2e/src/device/device_default.cpp#L211-L221
[aztec]: https://github.com/aztec-labs-eng/aztec-node/blob/29853ddaf2a9f70441fc2f733ada555eb50dbdc0/docs/docs-developers/docs/resources/considerations/privacy_considerations.md
[railgun]: https://github.com/RAILGUN-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunSmartWallet.sol
[mweb]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/light-clients.md
[bip32]: https://github.com/bitcoin/bips/blob/130b8e0fa7f30fa45532f080b87b8db27a79e46e/bip-0032.mediawiki
