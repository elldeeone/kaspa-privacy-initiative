# Next native-KAS privacy decision

**Do the owner-private construction and binding feasibility review next, before
another prover or holdout.** The strongest source-backed direction is separate
spend/output components with transaction-level value binding and hidden payer
assignment. It is an architecture family, not a selected or demonstrated KAS
protocol. A smaller outer-proof-only redesign deserves comparison, but cannot
silently exclude the coordinator who currently sees every component.

There is **no zero-redesign route through the current Auth528/W format** to the
original privacy qualification. More generally, no proof system can hide the
only earlier funding ancestor under the original complete-history assumptions,
or beat an amount predictor that already exceeds the target without seeing a
transaction. This is not a claim that Toccata lacks the primitives for a new
relation. Neither vProgs nor its absence is assumed necessary.

This is decision input at source commit
`ad18b65e1472d904d0528520104936592cda65b7`, written 2026-10-24. No source,
parameter, frozen observation, privacy threshold or heldout corpus changes.

**The current wrapper still publishes the association.** Its tested native
transaction contains an 8,108-byte public payload: a 12-byte header and two
ordered 4,048-byte records. Each record carries Auth528, NF update witnesses,
its exact ordered two CMs, its exact two ciphertexts, the CM boundary and its
inner proof. Within a record, CMs occupy bytes 2848:2912 and CFs 2912:3440;
their hashes match Auth bytes 268:300 and 332:364. The genuine public case
`9c94f36cfa85c1a8d5a5e0bd28e764f27f7879418cb12b5d9820be6cc80aa7bc` was
read and those two associations checked without running a proof or reading
private material. The 424-byte journal is reconstructed, rather than replacing
the records in the native body. See the pinned
[codec](../../../../poc/shared-settlement/virtual.py#L13), SHA256
`6e0fd44e27ddabd45c32cbb9a019948b831d70331c1bd5cd5213faf50182c222`,
the [29-file source capsule](../settlement/source-02/MANIFEST.json), and
[genuine native result](../settlement/genuine-native-01/RESULTS.json).
This was native acceptance in supplied constructed contexts, not accepted-chain
publication. A chain observer could parse these partitions if this body were
published; it needs no coordinator cooperation.

The [finite controls](../privacy/RESULTS-01.md) additionally establish that one
invoice plus positive sender change is the existing serial baseline, with
sibling/change-chain payer-role leakage. Payer role is distinct from original
funding ancestry and human identity. The
[old heldout study](../../compact-batch/privacy/heldout-study-01/REPORT-01.md)
and its incomplete cells remain unchanged. An outer proof and a lower fee do
not turn these observations into a privacy improvement.

**Keep three observer views separate and available to the attacker.**

| View | Facts it legitimately receives |
| --- | --- |
| Public history | All ingresses and times, accepted ordering/roots/counts, all published NFs/CMs/CFs and bytes/formats, modes including no-append, exact fees/refunds, native payout amounts/SPKs, delays and fallback events. |
| Public history plus participants | Sampled merchants/payers keep their actual invoice and counterparty labels, requested principal and receipt value, own CMs/openings/original NFs, outgoing known-recipient records, acknowledgments, own change and submission history. Known counterparty does not automatically mean original funding source. Own known links are reported separately from unknown-target attacks. |
| Construction observer | The assembler/relay keeps all component submissions, output sets, timing, network associations and any offsets/blindings it actually receives. Combining it with participant facts is an explicit stronger view. Transport anonymity, an honest relay or non-collusion must be justified, not assumed from shuffled final arrays. |

Public eligibility and predictions must cover all public positions before truth
is exposed; padding/change are not useful payments. An arithmetic alternative
is not a realizable cryptographic owner world or a probability of anonymity.

**Three directions, with their actual boundary.**

| Direction | Established part and changed protocol obligation | Observer/trust and cost consequence |
| --- | --- | --- |
| 1. Hide component records inside a new outer proof; publish only the necessary global effects | Existing child proofs and the executed zkVM wrapper are available. The proposed private-record, exact-output-permutation/coverage relation is **new**. It must reconcile child virtual roots/outpoints with the real accepted head, preserve positioned original NFs, cover each output/CF exactly once, authenticate current NF uniqueness and bind fees/native destinations and the actual final body. Deleting records or verifying their digests alone supplies none of this. | Potentially the smallest cryptographic-code change for public-history plus merchant privacy. It does not survive the construction view when the assembler receives labeled current components. A recipient acknowledgment that discloses its whole component also restores the partition. Any non-colluding-assembler claim is a new explicit privacy trust assumption. Native byte savings, prover cost, recovery format and fallback prices are unmeasured; current W costs do not transfer. |
| 2. Separate spend/output proofs, hidden assignment, transaction-level value commitments and binding | Sapling encodes independent spend/output proof vectors and a binding signature. Orchard's generic builder independently shuffles spends/outputs and balances value commitments. Reuse an established complete authorization/binding construction, with each owner proving locally and recipients generating only their own public invoices. New Note/commitment/key formats, bounded ranges, relation/setup/verifier/native state rules and migration need an ADR. | Best candidate family for the strong target **if** a concrete owner-private multiparty construction also hides unrelated assignment from the declared construction observer. Existing PCZT and a single all-knowing builder are not that result. Do not disclose individual value blindings or output mappings merely to manufacture a joint binding key. More component proofs, range constraints, signatures and coordination can raise fixed/low-demand costs; no fee estimate or secure composition is established. |
| 3. MWEB-style independently authorized confidential components and merged sets | Unmodified upstream construction, public aggregation, independent recipient recovery/spending and a separate public parent-field join actually ran. It provides a mature owner-local authorization/global-balance precedent. Upstream kernel signatures bind peg-in/out feature fields; local funding remained synthetic. | Public spent output IDs directly identify consumed parents; pre-aggregation mappings still recover all four component outputs. This regresses the current hidden-membership interface and is not the chosen privacy path. Hiding those IDs by adding a new proof is a separate hybrid relation, not an established MWEB feature. Its library units, Bulletproof costs and Litecoin peg rules are not native-KAS fee or exit evidence. |

The primary evidence for direction 2 is
[Sapling serialization](https://github.com/zcash/librustzcash/blob/146a08fc779678f6b81997da5f9b7c3378ffccb9/zcash_primitives/src/transaction/components/sapling.rs#L453-L503),
[Orchard shuffle](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L1479-L1513)
and [aggregate binding-key construction](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L1279-L1296).
The latter sums commitment trapdoors inside one builder; it is not evidence of
a witness-private distributed builder. The
[PCZT prover contract](https://github.com/zcash/librustzcash/blob/146a08fc779678f6b81997da5f9b7c3378ffccb9/pczt/src/roles/prover/mod.rs#L1-L6)
requires private information for the proved component. Orchard
[signs a common sighash](https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/builder.rs#L1698-L1719);
the [transaction digest specification](https://zips.z.cash/zip-0244) must be
examined for exact effect coverage rather than treating arbitrary caller bytes
as authorization. These pinned files were re-read on 2026-10-24; their blob
identities remain in [SOURCE-PINS](../sources/SOURCE-PINS.json).

For direction 3, MWEB's
[consensus rules](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/consensus.md#L76-L150)
explicitly reference spent output IDs, parent commitment/pubkey equality and
global kernel/stealth balance. Its
[kernel message](https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/doc/mweb/kernels.md#L52-L58)
binds documented feature fields, not this project's whole final input/output
list. See the executed [association inventory](../privacy-components/PUBLIC-ASSOCIATION-FIELDS.json),
[recipient extension](../privacy-components/recipient-extension/RESULTS.md)
and [separate parent-join correction](../privacy-components/public-parent-join-01/ADDENDUM.md).
RAILGUN is a useful negative baseline rather than a fourth candidate: its
[public signals](https://github.com/Railgun-Privacy/circuits-v2/blob/0aa2d13763a9fcfbb7b7ea9c02e004e71f1394bb/src/library/joinsplit.circom#L6-L45)
retain each transaction's nullifier/output group despite batching.

**The next falsifiable experiment is a public transcript/API feasibility gate,
not a new KAS circuit.** Freeze its source references and messages before any
new generated workload, with independent adversarial review:

1. Specify every message and role using the selected established construction:
   spend owner, output constructor, recipient, binder and assembler. Walk two
   already-due independent payments with real sender change through the exact
   upstream APIs on paper/existing public fixtures. Identify who must know each
   witness, value blinding, output opening and grouping. Missing joint binding,
   all-owner witness collection, or a labeled submission in the claimed strong
   observer is an immediate **FAIL/blocker**, not an invitation to invent MPC.
2. Supply a complete global conservation/spentness certificate and two distinct
   admissible economic assignments for a predeclared unknown public target in
   a genuinely overlapping case. Use the exact bytes/formats the API would
   disclose, all participant knowledge and ciphertext/mode/fee timing. Require
   a source-grounded account of why the two challenge distributions hide the
   distinction; do not require two different openings of the same binding CM,
   or call an opaque-label/arithmetic permutation cryptographic evidence.
3. Retain public negative cases: sole earlier funder; no second payment before
   the deadline; distinct known invoices/fee credits; later receipt/change
   spending; one/two real inputs; partial/full/no-append exits; colluders that
   exhaust all eligible unknown payers. Explain exactly which rule rejects
   duplicated/omitted outputs, reused NFs, stale roots, value/CF substitution,
   fee theft and payout-SPK changes. An unspecified rejection is a protocol gap.
4. Follow each recipient acknowledgment and original backup through immutable
   CM positions/CFs, later sender change and a unilateral exit after assembler
   loss. Account for who retains the history and software, accepted-head/reorg
   assumptions, aborts, proof latency and complete useful-payment fees. Preserve
   current no-append mode as public side information. No wait/working balance,
   operator exit key or unavailable future user may make the test pass.

Passing this gate would justify a separately reviewed specification/ADR and a
bounded existing-library composition experiment. It would not establish
security, native acceptance or a privacy bound. If direction 2 cannot name an
established compatible construction, report that as the next architecture
blocker. Direction 1 can be studied only with its narrower observer/trust claim
explicitly selected; it is not a quiet substitute for the stronger target.

**Demand is a prerequisite for specific claims, not a source of free privacy.**
The singleton argument assumes zero initial user liability, every positive
ingress represented, nonnegative conservation at every prefix and no external
subsidy inside an action. It concerns causal funding ancestry, not a human.
Before any positive target, at least two genuine earlier sources must remain
feasible for funding ancestry; this is necessary, not sufficient. After all
colluding participants' facts, a payer-role target needs at least two eligible
unknown payer roles. Actual independently due payments must overlap before
their users' deadlines. Future users, change, self-churn and padded notes count
as none of these. Sparse and deadline-expired users keep an available unilateral
exit, with its real disclosure and cost reported as an outcome.

The original 45-KAS amount guess already succeeds within the original 10%
tolerance with probability `21103/100025 = 21.0977%`, above the 20% gate.
Cryptography cannot reduce the success of a transcript-free predictor for that
unchanged workload. Broader genuine demand may change a future declared price
distribution; that requires a new explicit product/workload assumption and
measurement, while the original failure remains. More funded users alone do
not remove a concentrated price prior.

Finally, fee sharing must be measured across actual useful obligations and
complete entry/payment/change/exit costs, including failure and fallback. The
tested two-action W fee is 18,508,000 sompi; it says nothing about the cost of a
hidden-assignment relation or a user arriving alone. Joint construction can
amortize fixed work when demand exists and add delay/abort cost when it does
not. Do not force the latter user to wait to protect an average.

No new holdout is justified until the architecture and analytic gates survive.
Then reuse the [prospective power/freeze rules](../privacy/POWER-AND-FREEZE-01.md):
independent histories, matched real obligations, separate principal/exit-credit
denominators, all fallback/UNKNOWN results retained, full prediction barrier
before hidden truth, and N sized for the actual target. Repeated views are not
independent samples. Original privacy qualification remains **FAIL**.
