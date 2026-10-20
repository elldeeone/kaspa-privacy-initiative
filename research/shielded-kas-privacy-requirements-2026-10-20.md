# Private native KAS payment requirements source review

Reviewed 2026-10-20 for [RFC 0012](../docs/rfc/0012-useful-privacy-requirements.md).
The useful target is private payments with verifiable native-KAS backing and
independent exits. Proof confidentiality alone does not establish payment
unlinkability, recipient spendability or recovery after a service disappears.

This review reuses requirements and threat-model lessons. It does not select new
cryptographic primitives, replace the current architecture or qualify a deployed
implementation. Research and testnet only; no real funds.

## Current source identities

GitHub repository and commit GET requests returned these default-branch heads.
Dates below are commit dates in UTC, not release or activation dates. A current
source head does not identify the software running on any node.

| Repository | Verified head | Commit date |
| --- | --- | --- |
| `kaspanet/docs` | `0ac77d043a802fc8196abfd5812ac2afbd97a2b9` | 2026-07-02 |
| `kaspanet/kips` | `e4ae2332117b5cb68bd6188e065ef885b6d17939` | 2026-07-15 |
| `kaspanet/rusty-kaspa` | `4edcbbccb449f84832afb1ca157904b35f37d006` | 2026-10-19 |
| `kaspanet/vprogs` | `f9b84a863a7c7c20586a9cf947550475e894f72e` | 2026-07-28 |
| `kaspanet/research` | `c923faca11a49148fa7d912d27ce00197a5c5a4a` | 2025-09-14 |
| `zcash/orchard` | `616a669df8c9a59c33d47064d3ce04b25d026b2e` | 2026-09-30 |
| `zcash/zips` | `a34cfc091434275120ff017c92c3b50d3cef623a` | 2026-10-16 |
| `AztecProtocol/aztec-packages` | `660f5f5b51333d9616b5160931a101b23840789c` | 2026-10-19 |
| `aztec-labs-eng/aztec-node` | `9babccfcfc083915a5bda1f378fe8bda3a6bd2b8` | 2026-10-19 |
| `RAILGUN-Privacy/contract` | `36bcf5ed7cf94bfafb6e1a303e1832c769c16780` | 2026-08-15 |
| `monero-project/monero` | `8340be5e920d881edc006e0896d6074cd06dfb2e` | 2026-10-19 |
| `monero-project/monero-site` | `6ab1cb954411abffa21004d664e5c3fa755922f3` | 2026-10-16 |
| `litecoin-project/litecoin` | `ec1b6489a900d09cf5991e220dce089c77a232a2` | 2026-09-09 |
| `litecoin-project/lips` | `73cb2a6cea05b3891e7986ca215e7ccf4a49cb41` | 2026-02-27 |

## Kaspa requirements and limits

**Toccata documentation and KIPs.** [Inline ZK][inline] distinguishes a proof of
a hidden transition from enforcement of its actual successor output.
[KIPs 16][kip16], [17][kip17] and [20][kip20] provide proof verification,
transaction introspection and covenant lineage. [KIP 21][kip21] commits to
ordered lane activity. These capabilities do not hide ordinary native amounts,
transaction references or application data published alongside a proof.

Reuse explicit binding between the intended proof statement, native values,
state and destination. Adapt the public/private boundary to every field of the
actual Kaspa encoding. Reject treating covenant identity, a valid proof in
isolation or a sequencing commitment as an application privacy guarantee.

**Rusty Kaspa implementation.** The [proof dispatcher tags][tags] support
Groth16 and RISC Zero Succinct. The [pruning implementation][pruning] deletes
block transactions, acceptance data and SMT metadata outside retained history.
Reuse the distinction between authenticated state and available historical
bytes. Adapt recovery requirements to the data a wallet retains and can obtain
from independent sources. Reject assuming a pruned node can reconstruct every
historical witness or encrypted note. No deployed node was checked here.

**vProgs and research.** The [runtime README][vprogs] still identifies early
prototype infrastructure. The [research index][research] labels its
[protocol paper][yellow] v0.0.1 Draft. The [decision guide][decision] distinguishes
direct covenant state from based execution and its infrastructure obligations.
Reuse that separation when stating requirements; adapt architecture choices to
demonstrated shared-state and ordering needs. Reject requiring or dismissing
vProgs in advance, and reject treating the research design as a delivered
privacy or exit guarantee.

## Mature privacy designs

**Orchard.** [ZIP 224][orchardzip] separates the shielded pool from the public
value boundary and discusses transaction-shape hiding. Its [note model][notes]
binds recipient and value; [nullifier derivation][nullifiers] ties each spend
identifier to its note and secret key material. Exiting to a transparent
destination reveals value even though internal note amounts are confidential.

Reuse recipient-bound notes, unique spend identifiers and explicit public
boundary amounts as requirements. Adapt disclosure analysis to Kaspa reserve
accounting and the actual proof statement. Reject assuming that adopting the
word “nullifier,” using a SNARK or borrowing a construction transfers Orchard's
security analysis to this implementation. Public reserve limits also do not,
by themselves, protect each legitimate holder from counterfeit private claims.

**Aztec.** The current [protocol README][aztecroot] directs node, client and
documentation readers to `aztec-labs-eng/aztec-node`. Its [privacy guidance][aztecprivacy]
identifies public-call fingerprints, timing, historical-root age and third-party
witness queries as leakage. In particular, requesting a sibling path by leaf
index tells the server which note interests the requester.

Reuse an observer-specific inventory of transaction and query transcripts.
Adapt historical-root analysis: reusable authorization can avoid reproving
while revealing that a note existed before its exposed anchor. Measure that
restriction on the candidate population; do not infer equal candidate
probabilities. Reject the assumption that encrypted state makes public
transaction structure or retrieval private.

Aztec's [delivery modes][delivery] also distinguish absent delivery, published
but unconstrained ciphertext, and constrained encryption/discovery correctness.
Reuse the requirement that recipients establish spendability before accepting
a payment. Adapt it to either verified delivery or deterministic rejection of
missing/malformed note material. Reject importing Aztec's runtime or handshake
scheme merely to satisfy that requirement: its documented discovery choices
themselves have coordination and recipient-contact leakage tradeoffs.

**RAILGUN.** [Validation][railgunlogic] checks a historical membership root,
chain context and transaction-bound parameters; [commitment state][railgunstate]
separately tracks seen nullifiers. [Wallet events][railgunwallet] publish
commitments, ciphertext and action metadata for reconstruction.

Reuse the separation between membership in accepted history and current
double-spend prevention. Adapt public-state reconstruction and proof binding
to Kaspa's state transitions. Reject importing EVM asset handling or owner and
upgrade machinery as default requirements. Historical-root acceptance is a
liveness technique, not evidence that root age or public events are harmless.

**Monero.** The inspected official explanations distinguish [one-time recipient
addresses][stealth], [possible input signers][rings] and [confidential amounts][ringct].
Reuse these as separate privacy objectives rather than a single “private”
label; adapt the observer model to an optional Kaspa pool with public ingress
and egress. Reject importing ring decoys or treating a candidate count as
equally likely independent users. The current Monero code head was recorded,
but this requirements review used its documentation, not a code security audit.

**Litecoin MWEB.** [LIP 3][lip3] studies an optional native-asset boundary;
[LIP 4][lip4] studies one-sided delivery. The latter remains marked Draft, so
it is design context rather than an activation record. Current implementation
[outputs][mweboutput] carry commitments, range proofs and masked values, while
[inputs][mwebinput] explicitly serialize the output ID being spent.

Reuse explicit native backing, confidential-value and recipient-recovery
requirements. Adapt analysis to what an observer sees before aggregation and
after settlement. Reject treating amount hiding or cut-through as sufficient
proof of payment unlinkability: serialized spend references remain relevant
to an observer who sees them. Reject adopting extension-block consensus changes
as the default route when evaluating current Kaspa capabilities.

## Implications for RFC 0012

1. Name each observer: public-chain analyst, broadcaster/fee payer, state-data
   provider, sender, recipient, colluding participants and network observer.
   Give each only the information its role obtains; inventory combined roles.
2. Distinguish hidden values and cryptographic spend unlinkability from
   statistical inference. Include amounts, fees, timing, shapes, anchor age,
   ingress/egress, public recovery requests and later history in scope.
3. Require recipient spendability at acceptance. Ciphertext availability,
   successful decryption, commitment consistency and spending authority are
   separate conditions; confidentiality alone establishes none of the others.
4. Require authenticated public recovery data with an explicit retention model.
   A replacement service must not need another user's secret. State what is
   lost if all required historical replicas and user backups disappear.
5. Preserve backing and authorization while improving privacy. Pending exits
   remain liabilities. More candidate histories do not compensate for
   unavailable exits, unverifiable state or unauthorized reserve spending.
6. Report privacy results with their workload, observation horizon and attacker
   knowledge. Separate forced links, ranked guesses, errors and abstentions.
   Synthetic ambiguity is not evidence of real-world anonymity.

These are requirements to evaluate and implement, not claims that the branch
already meets them. Existing experiment results need their own evidence links.

## Source and evidence limits

Pinned text/code paths were fetched and inspected; the headings and dates above
are reproducible source identities. The vProgs PDF was fetched, but its text
could not be extracted with available tools in this refresh. Only its repository
index and draft status support statements here; no paper-specific theorem or
algorithm is claimed to have been revalidated.

No deployment, network acceptance, funded transaction, cryptographic audit or
new privacy experiment was performed for this note. Current upstream branches
are not necessarily release configurations. Source inspection, passing tests
and synthetic privacy results do not establish cryptographic security,
production safety or real-world anonymity.

[inline]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx
[decision]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx
[kip16]: https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0016.md
[kip17]: https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md
[kip20]: https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0020.md
[kip21]: https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0021.md
[tags]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles/tags.rs
[pruning]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/src/pipeline/pruning_processor/processor.rs#L486-L491
[vprogs]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[research]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/README.md
[yellow]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/vProgs/vProgs_yellow_paper.pdf
[orchardzip]: https://github.com/zcash/zips/blob/a34cfc091434275120ff017c92c3b50d3cef623a/zips/zip-0224.rst
[notes]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note.rs
[nullifiers]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/nullifier.rs
[aztecroot]: https://github.com/AztecProtocol/aztec-packages/blob/660f5f5b51333d9616b5160931a101b23840789c/README.md
[aztecprivacy]: https://github.com/aztec-labs-eng/aztec-node/blob/9babccfcfc083915a5bda1f378fe8bda3a6bd2b8/docs/docs-developers/docs/resources/considerations/privacy_considerations.md
[delivery]: https://github.com/aztec-labs-eng/aztec-node/blob/9babccfcfc083915a5bda1f378fe8bda3a6bd2b8/docs/docs-developers/docs/aztec-nr/framework-description/note_delivery.md
[railgunlogic]: https://github.com/RAILGUN-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunLogic.sol
[railgunstate]: https://github.com/RAILGUN-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/Commitments.sol
[railgunwallet]: https://github.com/RAILGUN-Privacy/contract/blob/36bcf5ed7cf94bfafb6e1a303e1832c769c16780/contracts/logic/RailgunSmartWallet.sol
[stealth]: https://github.com/monero-project/monero-site/blob/6ab1cb954411abffa21004d664e5c3fa755922f3/_i18n/en/resources/moneropedia/stealthaddress.md
[rings]: https://github.com/monero-project/monero-site/blob/6ab1cb954411abffa21004d664e5c3fa755922f3/_i18n/en/resources/moneropedia/ringsignatures.md
[ringct]: https://github.com/monero-project/monero-site/blob/6ab1cb954411abffa21004d664e5c3fa755922f3/_i18n/en/resources/moneropedia/ringCT.md
[lip3]: https://github.com/litecoin-project/lips/blob/73cb2a6cea05b3891e7986ca215e7ccf4a49cb41/lip-0003.mediawiki
[lip4]: https://github.com/litecoin-project/lips/blob/73cb2a6cea05b3891e7986ca215e7ccf4a49cb41/lip-0004.mediawiki
[mweboutput]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/include/mw/models/tx/Output.h
[mwebinput]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/libmw/include/mw/models/tx/Input.h
