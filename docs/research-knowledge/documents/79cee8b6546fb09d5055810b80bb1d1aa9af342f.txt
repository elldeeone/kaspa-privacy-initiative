# Hidden assignment: concrete dependencies after the negative controls

The practical one-invoice API is the existing compact serial relation with a
clearer interface. The [new controls](RESULTS-01.md) show its direct cohort scope
is smaller, but invoice/change knowledge can still disclose later payer roles.
Plain aggregation of the old public Auth/output partitions does not fix that.

## An established component family now actually ran

The separate [MWEB component experiment](../privacy-components/RESULTS.md)
executed unmodified pinned upstream builders: two owner processes constructed
signed/range-proved components, a third merged only serialized public data, and
a fresh verifier accepted global balance/signatures/proofs. The
[independent recipient extension](../privacy-components/recipient-extension/RESULTS.md)
then used recipient-created public addresses, receiver-local recovery and
actual recipient-authorized spending. No owner/receiver spend secret was
transferred to the aggregator API.

This is a useful executed precedent for local authorization plus merged value
binding. It is not the current KAS relation: public spent output IDs reveal
membership references, unlike hidden CM membership/positioned nullifiers.
Pre-aggregation observers retain all component output groups. Distinct sender
keys and final vectors without a partition field do not prove unlinkability.
No native-KAS compatibility, fee or anonymity threshold transfers.

## Candidate interfaces to specify before new cryptographic implementation

1. **Spend component:** local proof of valid Note membership, ownership,
   original NF and a commitment to the same bounded Note value. Hidden
   membership must be retained; publishing the consumed CM/output ID is a
   regression. Currentness/spentness must be checked against the actual
   accepted native head, including cross-component duplicates.
2. **Output component:** independent proof binds the same bounded value to its
   value commitment and spendable Note/CM, with exact CF/output placement and
   receiver acceptance/recovery obligations. A final set cannot contain an
   unfunded or multiply counted liability. Private outputs must not regain a
   public payer partition through their proof inputs or reused keys.
3. **Authorization/binding:** choose an established exact construction.
   Sapling/Orchard separated spend authorization uses randomized keys and a
   properly constructed transaction sighash; PCZT's prover still needs private
   data and cannot be an excuse to collect every owner's witnesses. MWEB's
   excess kernels/aggregate offsets are a different component precedent; its
   kernel message is not automatically this project's whole transaction.
   Define whether each owner authorizes a fixed complete batch or a formally
   composable exact own effect. Neither arbitrary caller-provided digests nor
   knowledge-of-owner-witness alone replaces that binding requirement.
4. **Native balance/effects:** exact aggregate integer ranges, reserve changes,
   fee allocations/refunds, payout amounts/SPKs, output coverage, NF insertion
   and stale/replayed state rejection. Select native or Based App settlement
   by these requirements. The component experiment supplies none of this KAS
   integration automatically.
5. **Construction and failure:** local owner secrets remain local; specify
   request visibility, who learns grouped output/offset metadata, abort handling,
   deadline and independently priced unilateral fallback. A coordinator that
   sees labeled components may retain grouping without possessing spend keys.

A new relation, ownership/authorization interface, possible Note/curve formats,
parameters and old-claim recovery/migration consequences require a separately
reviewed ADR. This note selects no cryptographic suite or ad hoc MPC protocol
and makes no security claim for a new composition.

Even a successful hidden-assignment design needs actual independent demand.
It cannot conceal an exit that predates every second real source, erase a
payee's own authenticated counterparty knowledge or remove an already failing
amount prior. Preserve those failures and qualify only an implemented, tested,
explicit observer target.
