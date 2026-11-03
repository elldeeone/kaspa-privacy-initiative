# New private proof and native exit integration

**The complete offline lifecycle passed on its first frozen attempt.** A genuine
new private proof connects native admission to two recipient-owned notes, restored
from backups made before payment, followed by both native payouts with the prover
and proving key absent. Every positive liability and the reserve end at zero.

This is public synthetic **DO_NOT_FUND** research. All native validation uses
supplied UTXOs and an explicit archive/current-head oracle. No testnet broadcast
or confirmed payout occurred. Passing these checks does not establish
cryptographic correctness, production safety, accepted backing or privacy.

## Implemented result

The [complete trace](lifecycle/REPORT.md) contains six actual native Full
operations: ordinary source preparation, coherent singleton founding, native
public admission, a genuine private payment, a continuing owner reveal and a
terminal owner reveal. Six physical output links are checked against the actual
preceding bodies. The actual immutable covenant is **22,388 bytes**, containing
all three PRIVATE / ADMIT / REVEAL branches and the same fixed verification key.

The new private relation requires independent ownership and nullifier secrets;
revealing the latter alone does not supply private-spend authority. Both spend
paths use the same positioned original nullifier. The selected V2 invoice keeps
the stable delivery key out of native note openings. Real sealed boxes deliver
receipts to recipients whose private credentials are absent from the sender's
output witness. Exact note-only backing, integer sompi, minimum positive notes
and shared private/reveal capacity are explicit experimental profile conditions.

| Evidence | Result | Practical boundary |
| --- | --- | --- |
| Complete linked native lifecycle | 6 Full operations accepted; final reserve and liabilities zero | Supplied ancestry/head and archive |
| New genuine primary private proof | Checked host verification and actual native Groth16 accepted | Fresh local development setup |
| Recipient restoration | V1 25/25 and selected V2 27/27 checks | No independent network archive discovery |
| Full R1CS malformed/boundary controls | 17/17 frozen negatives unsatisfied | Tested relation, not a cryptographic audit |
| Native authorization/state controls | 7 accepted, 56 rejected | Exact error-label score 60/63 |
| Genuine competing spends | 3/3 additional native cases passed | Separate forks, not extra mainline payouts |
| Seventeenth-bit NF capacity | Actual terminal native reveal accepted at index 65,536 | Constructive unproved history; helper provenance gap |
| Incremental privacy diagnostic | One frozen V2 evaluation completed | Full privacy qualification remains open |

The native error-label failures are retained: three invalid signatures were
predicted to return `NullFail`; official single-signature execution returned
`EvalFalse`. All three actual Full bodies rejected. They are failed typed
predictions, not 63/63 passing expectations. The capacity fixture also references
one intermediate preparation-helper hash whose exact source copy was not
recovered. Raw history, frozen cases and actual native validation remain retained;
that does not repair the missing helper provenance. See the
[native report](native/NATIVE-RESULTS-01.md).

## Fees and proving

At 100 sompi/mass, the complete native fees are **37,024,800 sompi**. Splitting
shared preparation/founding/admission/private fees equally and adding each
recipient's own exit costs gives **1.85177%** and **1.85071%** of two actual
10-KAS payments. The private operation alone allocates **0.93757%** per payment.
These are actual native network fees for one payer, two useful recipients and
no private change. They exclude unpriced services, proving and retries; headroom
is only 1,482,300 sompi for the more expensive complete route and 624,300 sompi
for each ordinary payment. The [fee frontier](fees/FEE-FRONTIER.md) preserves
failed alternatives. One useful recipient plus change still fails the direct
verifier floor; generic batching or independent-owner aggregation is not solved.

The circuit has **4,650,533 constraints**. One new setup took 22.30 seconds;
the checked compressed-key load plus genuine primary proof took **198.12 seconds**
and **5.41 GiB** peak RSS with 14 CPU threads available. This misses the 4 GiB
wallet limit and does not qualify four-core laptop latency. Installed Arkworks
has no adopted GPU backend. The one-gigabyte proving key stays outside Git.
[ADR-0044](../../../docs/adr/0044-selected-development-key-loading.md) separately
scopes an authenticated development-key loader measurement. The completed
loader-only run takes 156.38 seconds, with 155.27 seconds in decoding; this
does not resolve the bottleneck. Both new fork proofs genuinely verify on the
host. Native Full accepts the first recipient private spend, rejects the later
reveal against its current occupied NF, and rejects a separately rebound genuine
private proof after the primary reveal. These three expectations pass exactly.
See [genuine fork results](native/GENUINE-FORK-RESULTS-01.md).

The prior **21.09772557%** privacy result remains above the unchanged **20%**
target. V2 removes one deterministic fresh-note equality channel; invoice-directory
linkage, selected-note revelation, reused credentials and orphan disclosures
remain. No privacy pass follows from this integration.

The [additive fee comparison](fees/ACTUAL-PRIMARY-COMPARISON-01.json) checks the
actual primary result against the pre-frozen complete-prefix arithmetic. All
nine comparisons match; neither the earlier arithmetic packet nor native run
was changed or repeated. The reversed-order exact fee comparison remains
arithmetic only; separate native controls accepted that order at their declared
fees.

## Evidence and next gate

- [Contracts](NOTE-STATE-CONTRACT.md), [V2 invoice](INVOICE-V2-CONTRACT.md),
  [admission](NATIVE-ADMISSION-CONTRACT.md), [primary sources](PRIMARY-SOURCES.md).
- [Independent review](ADVERSARIAL-GATES.md),
  [independent relation oracle](independent-oracle/REPORT.md),
  [recipient recovery](recovery/V2-REPORT.md), [privacy diagnostic](privacy/RESULTS.md).
- [Architecture decision](../../../docs/adr/0041-new-format-private-native-integration.md)
  and [RFC](../../../docs/rfc/0020-private-proof-and-native-exit-integration.md).

The next acceptance boundary is a fresh private testnet identity, authenticated
accepted lineage/current head and complete public data, followed by an actual
confirmed payout rehearsal. The published fixture has public synthetic secrets
and must never be funded. Recovery from independent public data, reorgs, proving
resources, broader fees and financial privacy remain open research work.
