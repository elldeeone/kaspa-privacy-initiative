# Native bytes and usage privacy: sources for the next experiment

Reviewed 2026-10-21. The recommendation is to test the existing v2 wallet with
genuine native transactions and deliberately varied usage, especially public
exit-to-spend-to-top-up links. This needs an experiment around the current wallet,
not new cryptography or a new execution runtime. It is not a claim that the
chosen behavior represents real users.

This review read public source and retained public evidence only. No wallet
secrets, held-out truth, funds or new proofs were accessed or generated. Follow
[RFC-0012](../docs/rfc/0012-useful-privacy-requirements.md),
[RFC-0014](../docs/rfc/0014-owner-aware-privacy-evaluation.md) and the unchanged
[security invariants](../SECURITY-INVARIANTS.md).

## Current source provenance

Read-only GitHub commit requests reconfirmed these default-branch heads. Dates
are commit dates, not activation dates or observations of deployed software.

| Repository | Head | UTC date |
| --- | --- | --- |
| `kaspanet/rusty-kaspa` | `4edcbbccb449f84832afb1ca157904b35f37d006` | 2026-10-19 |
| `kaspanet/docs` | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` | 2026-07-02 |
| `kaspanet/kips` | `e4ae2332117b5cb68bd6188e065ef885b6d17939` | 2026-07-15 |
| `kaspanet/vprogs` | `f9b84a863a7c7c20586a9cf947550475e894f72e` | 2026-07-28 |
| `kaspanet/research` | `c923faca11a49148fa7d912d27ce00197a5c5a4a` | 2025-09-14 |
| `olafweller/kaspa-privacy-initiative` | `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1` | 2026-10-20 |
| `zcash/zips` | `d167dd3994e40790971f8f00b0b330885d2c9fe5` | Rechecked head; date not newly recorded |

The branch's [Cargo dependency](../poc/shared-pool/Cargo.toml) remains Rusty
Kaspa `01b532e8b553523216471682649693af92f0fd16`, distinct from current HEAD.
Both [pinned][pinned-hashing] and [current][hashing] transaction hashing files
were retrieved; their diff contains import changes only. This narrow comparison
does not establish compatibility of the entire dependency or any running node.
[Issue #13][issue13] remains open, zero comments, updated
`2026-10-02T13:58:54Z`; its scope includes timing, amounts, wallets, RPC/network
observations and public payloads, not a privacy success claim.

## What the retained work establishes

The [strong screen](../poc/shared-pool/POPULATION-PRIVACY-STRONG.md) completed
16 synthetic histories and 2,048 payments without a decisive tested break.
Its opaque identifiers, assumed input selection and scheduled activity omit
actual proof, ciphertext, signature and native-script relationships. Its wide
uncertainty and limited attacks do not qualify privacy.

The [key-separation evidence](../poc/shared-pool/ADDRESS-KEY-SEPARATION.md)
contains genuine proofs and signed native transaction objects, with offline
validation and synthetic parent UTXOs. The public v2 same-index
[lineage](../poc/shared-pool/evidence/2026-10-21-native-key-separation/native/v2-same-index/lineage.json)
has SHA256 `430c38fa93a2cccdf1e1b96fe83270f2271c407d495a9f8de1a423a1f5ab4a62`;
its [parents](../poc/shared-pool/evidence/2026-10-21-native-key-separation/native/v2-same-index/parents.json)
have SHA256 `79acc6e2d00c4f53ff794cb7d226168091952d23bc7ddb52b565dfd3a9c09b59`.
Inspection confirms five lineage records and two parent records. The four pool
transactions each carry a 5,228-byte payload and a 24,709-byte reserve signature
script. ADMIT also has a 66-byte ordinary funding signature script.

These JSON objects retain actual hex-encoded transaction fields; they are not
captured network packets or evidence of chain acceptance. Earlier public
calibration is development data, not fresh evaluation data. The combined public
exports also contain post-run scoring and must never become observer inputs.

## Observation contract

| Surface | Derive from actual transaction data | Keep separate or withhold |
| --- | --- | --- |
| Native graph | Input outpoints, parent transactions, output indices, values and scripts; reserve lineage and later spends. | Synthetic ancestry is not a historically accepted chain. A common parent is not proof of common ownership. |
| Envelope | Version, input/output order and counts, sequence, compute budgets, lock time, subnetwork, gas, storage mass, lengths and exact bytes. | Native transaction identity is not a full byte commitment. Preserve full transaction hash and artifact SHA256 too. |
| Pool authorization | Mode, anchor/count, two nullifier slots, two commitment slots, payout/fee/deposit/bootstrap values, funding outpoint and funding/payout scripts. | Private note values and spent positions cannot be supplied by the harness as public features. |
| Delivery and settlement | Actual ciphertext/proof bytes, equality and lengths; old/successor state and public settlement witnesses. | Public settlement paths are not the hidden input-note membership paths. A classifier failure is not encryption security. |
| Timing and behavior | Dependency order exists in native data. | Attach explicitly modeled request/observation times in a separate schedule. Prover duration, file modification time and worker order are not chain inclusion or human activity. |
| Counterparty knowledge | A participant's own authored payments and received records, limited to its declared view. | Do not disclose the complete contact graph, receiving envelopes, hidden owner labels, scenario labels or private actions to a chain-only observer. |

The [upstream transaction structures][tx], [V1 documentation][tx-v1] and
[hashing code][hashing] justify the envelope/graph inventory. V1 transaction IDs
exclude signature scripts and mass commitments, including compute budgets.
Pinning only txids therefore fails to bind all observer-visible bytes.
[Covenant state][covenant-state] explains why spending opens a P2SH redeem script;
[inline ZK][inline] separates proof validation from successor enforcement. Neither
mechanism makes the surrounding native graph confidential.

The local [authorization/settlement encoder](../poc/shared-pool/src/two_input/mod.rs)
and [public decoder](../poc/shared-pool/early_privacy_surface.py) supply the exact
v6 byte layout. This candidate uses ordinary P2SH outputs with null native
covenant bindings; do not invent a populated KIP-20 field in the fixture.
The decoder's existing `minute=0` means dependency order only, not measured time.

## Concrete wallet behavior to test

The [wallet](../poc/shared-pool/src/two_input/wallet.rs) accepts selected one/two
input positions from its caller. It does not implement the strong screen's
automatic least-excess selector. PAY orders recipient then change; EXIT drains
the selected notes and derives its native key from their minimum position.
Declare any automated selector as experiment policy and actually pass its
choices to the wallet. Preserve insufficient-value or fragmentation failures.

The [ordinary native helper](../poc/shared-pool/src/native.rs) uses one input and
appends change to that input's P2PK script. Reusing a v2 funding index also reuses
its funding script. Purpose-separated funding/exit keys remove the demonstrated
cross-purpose equality, but do not erase public spend edges or change reuse.
An exit spent into a later deposit can expose a relationship without breaking
encryption. Whether that identifies a private payment requires a separate
argument and the observer's legitimate knowledge. Multi-input co-spend ownership
heuristics are not implemented by this helper and must not be silently assumed.
Include genuine cross-user native payments funding another participant as a
negative control: an exact public value-flow edge does not prove one person
controls both ends.

[Note encryption](../poc/shared-pool/src/protocol.rs) uses randomized sealed
encryption and fresh note randomness; repeated recipients do not imply repeated
ciphertexts. The [harness](../poc/shared-pool/src/two_input/harness.rs) encrypts
zero change to a fresh dummy wallet, emits two nullifiers for either one or two
real inputs, and uses all-zero ciphertexts only for DRAIN. Test repeated versus
different recipients, positive versus zero change and one versus two real inputs
with genuine bytes. Equality, prefix, length or padding findings need their own
controls; source intent alone is not a privacy result.

A separate submission observer could test retries/conflicting proposals: the
same positioned note has the same real nullifier even with a fresh proof and
ciphertexts. Compare with disjoint notes from the same wallet. This may reveal a
shared spend attempt, not general wallet identity. Unaccepted submissions belong
only to a separately declared relay/provider view, never the accepted-lineage
view. Offline process arrival measurements would not establish mempool exposure.

## Reuse, adapt and reject from established work

| Primary source | Reuse/adapt | Reject or limit |
| --- | --- | --- |
| [ZIP-224][zip224] and [ZIP-315][zip315] | Public ingress/egress, fees, transaction shape, chosen-value activity and colluding-counterparty timing belong in one model. | ZIP-315 is Draft guidance; Orchard's guarantees do not transfer to this circuit/wallet. |
| [Kappos et al., USENIX Security 2018][kappos], §§6.1, 6.3, 8 | Recurring withdrawals, distinctive amounts, time windows and known prices motivate cashout and repeated-contact attacks. Account for fees and splitting/aggregation. | January 2018 Zcash behavior and success rates are not Kaspa benchmarks. Size/active-interaction ideas in §9 are future work, not measured results. |
| [Möser et al., PoPETs 2018][moser], §§3–4 | Retain later disclosures and distinguish logical elimination from age-based ranking. | Historical Monero ring-decoy mechanics and rates do not transfer. |
| [Aztec privacy guidance][aztec] | Recurring activity and receipt-triggered reactions motivate correlated schedules and contact preferences. | These are engineering examples, not an empirical model of real users. |
| [Prior Orchard/RAILGUN/Monero/MWEB inventory](shielded-kas-privacy-requirements-2026-10-20.md) | Retain confidentiality versus boundary-linkage distinctions and explicit recipient/provider knowledge. | No new subsystem or primitive is selected; no new audit of those implementations is claimed. |
| [vProgs README][vprogs] and [Kaspa research index][research] | Retain current architecture context: prototype runtime and draft research. | Neither establishes a need to move this experiment to a based app. The previously unread vProgs PDF remains unread. |

## Recommended fresh experiment

Use a small, explicit family of usage scenarios rather than calling one random
distribution realistic: repeated friends/merchants, repeated or rounded prices,
unequal spending frequency, replenishment after spending, prompt versus retained
balances, and optional later cashouts. Include overlapping activity and genuinely
low active-owner periods; merely inserting quiet gaps leaves the owner set intact.
Randomize identities/phases independently of output order and filenames. These
are plausible stress scenarios until independent usage data supports frequencies.

Start with the existing native wallet producing the full supported lifecycle,
including ordinary exit spends and later top-ups. Retaining some notes while
exiting others is supported. Arbitrarily splitting one note into several native
payouts is not: any required preparatory private PAY must actually run and incur
its fee. Keep permissionless immediate exits available in every policy.

Freeze byte-only, behavior-only and combined attacks plus a policy-aware prior.
Use creation-time and later-cashout views to isolate what later disclosure adds.
Matched views of one history are correlated; keep whole histories together in
development/evaluation splits and uncertainty. Do not infer population accuracy
from the number of correlated payments. Predeclare the precision needed for any
rate claim; a small native batch can falsify a concrete link but cannot inherit
statistical power from the previous synthetic batch.

Require valid native replay/proofs and actual truth included in the tested
model before interpreting inference. Keep observer inputs limited to public
bytes, declared modeled times and its permitted participant records. Seal all
predictions before scoring. Report all requests, failures and eligibility counts;
do not remove prompt exits, startup or easy targets after observing leakage.

**Failure:** a reproducible unauthorized disclosure or a preregistered rate
failure on eligible targets under stated knowledge. **Survival:** only the named
attacks on the completed byte/usage scenarios survived; qualification stays open
unless all relevant targets and uncertainty requirements are met. **Incomplete:**
invalid native histories, unsupported actions, missing observations, truth
exclusion, contaminated views or insufficient precision for the claimed rate.
No offline result establishes real-world anonymity, live acceptance or an
external security audit. This review changes no runtime, relation or invariant.

[tx]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/tx.rs#L119-L295
[hashing]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/hashing/tx.rs
[pinned-hashing]: https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/consensus/core/src/hashing/tx.rs
[tx-v1]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/transaction-v1.mdx
[covenant-state]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/covenant-state.mdx
[inline]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx
[issue13]: https://github.com/olafweller/kaspa-privacy-initiative/issues/13
[zip224]: https://github.com/zcash/zips/blob/d167dd3994e40790971f8f00b0b330885d2c9fe5/zips/zip-0224.rst#L235-L251
[zip315]: https://github.com/zcash/zips/blob/d167dd3994e40790971f8f00b0b330885d2c9fe5/zips/zip-0315.rst#L494-L566
[kappos]: https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-kappos.pdf
[moser]: https://petsymposium.org/2018/files/papers/issue3/popets-2018-0025.pdf
[aztec]: https://github.com/aztec-labs-eng/aztec-node/blob/29853ddaf2a9f70441fc2f733ada555eb50dbdc0/docs/docs-developers/docs/resources/considerations/privacy_considerations.md#L59-L97
[vprogs]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[research]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/README.md
