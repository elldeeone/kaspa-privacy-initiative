# Sparse withdrawals: what would justify a design change?

Reviewed 2026-10-22 (Australia/Sydney), against research branch
`7d63e5b647d8519bf17d3ddfff97e4a3fb51e5ab`. This is a primary-source design
review alongside the exploratory sparse-attack diagnosis. It does not change
the failed experiment, adopted targets, wallet policy, proof relation or exit
rules. No private truth, backup, seed, funded trial or broadcast was used for
this source review.

**Decision:** stop general wallet cashout-policy tuning. Retain the direct-L1
payment/change and independent-exit mechanics, with persistent shielded balances
as an unqualified hypothesis. Next define a prospective research contract that
separates prior price predictability, incremental transaction signal and plausible
cash-demand behavior. The sparse diagnosis does not justify a batching or runtime
rewrite. A later structure proposal must identify a causal public disclosure
and a mechanism that removes it without weakening exits.

## What is already established

The [frozen comparison](../poc/shared-pool/WORKING-BALANCE-PRIVACY.md) rejected
the candidate: overlapping independent demand improved 13/40 to 8/40, but sparse
pooled final accuracy remained 11/37 in both arms, above the partial arm's 9/37
prior. These are successful guesses within 10%, not eleven uniquely established
payment disclosures.

The [exploratory diagnosis](../poc/shared-pool/WORKING-BALANCE-SPARSE-DIAGNOSIS.md)
now attributes the partial arm's eleven successful selected `split_tail` guesses:
eight use wholly unrelated payout constructions and three have structural
ancestry, but none closes the target receipt or change branch under the declared
classification. Across all 37 targets, none of the 1,074 unique constructions
offered by that strategy reproduces the actual target PAY input set or closes
either branch. Equal whole/partial 11/37 totals also hide substantial churn:
three shared hits, eight gains and eight losses; exact hits fall from nine to two.
These observations weaken the explanation that this strategy reconstructed
eleven actual receipt/change paths. Wrong supports do not prove zero transaction
signal, and a bounded attack search does not exhaust possible deductions. The
diagnosis cannot turn the failed gate into a pass or estimate population
anonymity from one sparse history.

The tested partial policy also changes private note evolution, native cash held
outside the pool, re-entry and which native payouts exist. Sparse and overlapping
histories were sampled separately. Their difference therefore does not isolate
timing or prove that a particular activity rate causes privacy. The
[specification](../poc/shared-pool/WORKING-BALANCE-PRIVACY-SPEC.md) is the source
for these model boundaries.

## What mature designs and current Kaspa sources tell us

| Source fact | Consequence for this research |
| --- | --- |
| Kaspa's ordinary [transaction output][kaspa-output] serializes an integer value and locking script. The [current candidate builder][builder] places the requested payout in such an output. | The amount of that output is public. Changing proof system, destination key or executor cannot make the same ordinary output confidential. The research target is its link to internal payments and balances. |
| [ZIP-315][zip315] separately inventories transparent outputs, public value balances, fees, action counts and anchor metadata. It also warns about receipt-triggered on-chain activity. It remains Draft guidance. | Retaining a balance is useful design context, not a guarantee. Public cashout behavior must be included in the threat model; encrypting note contents does not remove it. |
| [Orchard's final ZIP-224][orchard] uses Actions containing a potentially dummy spend and output, with one proof over the bundle. | Uniform action structure is an established response to spend/output-shape disclosure. It does not establish that copying this shape hides native exit amounts or supplies honest independent activity. Reuse the question, not an unreviewed transplant of the protocol. |
| Litecoin [MWEB peg-outs][mweb] explicitly carry amounts/scripts and create matching native outputs. | Even a domain with a different confidential internal representation has a visible native exit boundary. MWEB is an analogy, not a proposed Kaspa consensus change. |
| [Toccata inline ZK][inline] verifies the hidden transition while separately enforcing its real successor output. The [decision guide][decision] treats shared-state execution and batching as reasons to consider based apps, with additional operator/proving infrastructure. | A batch is an execution/representation option. Its privacy effect depends on exactly which user operations, amounts, timings and output mappings remain public. Batching is not itself amount confidentiality. |
| The current [vProgs README][vprogs] labels the runtime early/prototype; the [Kaspa research index][kaspa-research] labels its protocol specification v0.0.1 Draft. | No source here demonstrates that migrating this candidate to vProgs resolves its amount-inference problem. Runtime selection remains conditional on a measured requirement. |

This focused refresh reuses the broader
[Orchard/Aztec/RAILGUN/Monero/MWEB inventory](shielded-kas-privacy-requirements-2026-10-20.md).
It is not a new cryptographic audit of those implementations.

## Separate workload assumptions from information leakage

**Known-price prior.** The unchanged workload's optimal public price prior has
expected within-10% accuracy `21103/100025`, about 21.10%, already above the
adopted 20% absolute cap. An observer can retain that strategy without looking
at transactions. This is a workload/requirement information limit, not evidence
that a particular payout leaked a payment. An empirical finite history can score
below or above that expectation.

[RFC-0012](../docs/rfc/0012-useful-privacy-requirements.md) already says to
record such a limit rather than exclude easy targets after seeing results.
Keep the cap and old results unchanged. Report absolute success separately from
additional transcript-derived success, exact recovery and logically forced
disclosure. A structure change cannot promise to erase legitimate prior
knowledge. A future revised workload or target would need an explicit new
requirements decision; it cannot retrospectively qualify this workload.

**Cash-demand behavior.** The independent scenario gives each role one cash
request, independently choosing 10/20/25 tKAS. The correlated stress scenario
requests exactly half the preceding receipt, one modeled minute later, and
publishes that behavioral rule to the attacker. Thus doubling payouts has an
explicit inverse. Neither scenario is a measured distribution of actual user
cash needs; outside funds are earmarked liquidity, not modeled merchant
spending. Do not interpret the stress result as evidence that arbitrary partial
cashouts reveal half-invoices, or assume that ordinary users can make their
liquidity needs independent of receipts.

**Necessary distinction.** A correct common-price guess remains a scored success.
Attribution can show that the attack selected an unrelated receipt or tail, but
that does not erase accuracy or prove that the transcript supplied no useful
signal. Conversely, consuming a target's descendant establishes a structural
relationship; after merges/splits it does not uniquely allocate particular sompi
to the payment. RFC-0012 requires that distinction too.

## Compare the next directions

| Direction | Defensible use | Current limit / decision |
| --- | --- | --- |
| Another wallet-only payout schedule | A specific new mechanism, supported by plausible cash needs and a fresh prospective comparison, might reduce a demonstrated linkage. | The rejected half/partial policy and H18 short-delay policy provide no basis for another parameter sweep. Keeping funds private can remain a hypothesis; it is not a requirement users can be forced to satisfy before exiting. |
| Change public transaction structure | Study whether reducing exposed action boundaries, shape or owner-linked native ancestry removes a specifically identified attack input, while preserving conservation, recovery and immediate independent exits. | First name the field/link and opposing predictions. Existing arithmetic traces idealize commitments/nullifiers and omit byte-level fingerprints, so they cannot validate an actual new encoding. Multiple ordinary payouts still disclose their individual values; publishing each user's operation can retain linkage even inside a batch. No new subsystem is selected by this review. |
| Reassess the supported privacy claim | State where persistent internal payments, public cashouts, sparse populations and outside knowledge require separate claims and evidence. | This is needed now under I-16. It does not relax adopted targets or establish impossibility of useful native-KAS privacy. The present design remains unqualified; failed privacy is not repaired by relabeling it. |

The next investment is research design rather than another cashout schedule:

1. Define the claim, prior-only strategy and additional transcript evidence as
   separate objects. Preserve the accepted 20% absolute and five-point advantage
   limits, the old workload and its failure. Do not equate near-price accuracy,
   exact hits, correct lineage and forced disclosure.
2. State which cash-demand assumptions represent the intended use case and which
   are stress assumptions. No source reviewed here supplies real-world behavior
   measurements. Do not create favorable activity or declare independent cash
   needs realistic simply because that scenario scored better.
3. Require a named public field/link and opposing predictions before considering
   a structure change. A later causal check can remove that one disclosure on
   public development fixtures; such a check is not a deployable mitigation or
   qualification. A new candidate still needs prospective evaluation, full
   drainage, colluding/active participants, real costs and immediate exits.

This note selects no fresh histories, alternative-count exercise,
privacy-threshold change or new protocol. Any later change to proof relation, native
settlement structure, operators or exit dependencies requires synchronized
RFC/ADR, architecture and threat-model review.

## Source freshness and limits

Read-only GitHub API GETs on 2026-10-22 reconfirmed Rusty Kaspa `4edcbbcc`,
Kaspa docs `0ac77d04`, vProgs `f9b84a86`, Kaspa research `c923faca` and Litecoin
`ec1b6489` as default-branch heads. Zcash ZIPs advanced to `2bdf39494320e5e04057ac93b1794031ebfb00b5`;
ZIP-224 and ZIP-315 are byte-identical to the pins used by the previous review
(SHA-256 respectively `179c31d846b697f3c75471533576794f27610333244dd760435447313f945632`
and `638f37eefd6d60d8edad4c3d32fd98d163512ff4664a750e246c154264c61166`).
The full immutable identities appear in the links below. A current repository
head is not evidence about deployed software or activation.

No source establishes realistic user behavior, current network acceptance,
independent data availability, cryptographic soundness or production anonymity
for this prototype. No new trial or protocol implementation was performed.

[kaspa-output]: https://github.com/kaspanet/rusty-kaspa/blob/4edcbbccb449f84832afb1ca157904b35f37d006/consensus/core/src/tx.rs#L178-L186
[builder]: https://github.com/elldeeone/kaspa-privacy-initiative/blob/7d63e5b647d8519bf17d3ddfff97e4a3fb51e5ab/poc/shared-pool/src/two_input/mod.rs#L194-L214
[zip315]: https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/zips/zip-0315.rst
[orchard]: https://github.com/zcash/zips/blob/2bdf39494320e5e04057ac93b1794031ebfb00b5/zips/zip-0224.rst
[mweb]: https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md#L31-L35
[inline]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/inline-zk.mdx
[decision]: https://github.com/kaspanet/docs/blob/0ac77d043a802fc8196abfd5812ac2afbd97a2b9/content/docs/toccata/decision-guide.mdx
[vprogs]: https://github.com/kaspanet/vprogs/blob/f9b84a863a7c7c20586a9cf947550475e894f72e/README.md
[kaspa-research]: https://github.com/kaspanet/research/blob/c923faca11a49148fa7d912d27ce00197a5c5a4a/README.md
