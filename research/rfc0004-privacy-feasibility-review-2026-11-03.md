# RFC-0004 Q1: privacy boundary and qualification feasibility

**Status:** completed internal technical review of the stated information
limits. No external specialist approval, protocol qualification or requirement
change. Source checkpoint: `e00e47427a96e134069e796ac504d945ba22f1a5`.

## Outcome

Two different facts must remain separate:

1. A consensus-native shielded representation can avoid publishing each
   holder's payout amount/script while the holder stays shielded. It cannot
   erase an ordinary transparent payout or legitimate auxiliary information.
2. The retained common-price population cannot meet its unchanged 20% absolute
   approximate-amount cap, even with a transcript revealing nothing. This
   rejects qualification of that population; it does not make every privacy
   requirement or workload inconsistent.

This resolves what Q1's mathematics says. It does **not** accept a narrower
privacy claim, change the observer/threshold/population, or decide that retaining
user funds inside a privacy domain satisfies an unrestricted transparent exit.
Those product/qualification decisions remain explicit owner review points.

## Conditional transparent-boundary counterexample

Suppose the admitted observer knows two owners' complete public crossings and
fees, no retained positive claims and one payment from A to B. In integer sompi:

| Owner | Public deposit | Public withdrawal | Known fee |
| --- | --- | --- | --- |
| A | 100 | 59 | 1 |
| B | 0 | 39 | 1 |

Both independent balance equations force the payment to 40:

```text
p = deposit_A - withdrawal_A - fee_A = 40
p = withdrawal_B + fee_B - deposit_B = 40
```

These are public facts plus admitted assumptions. Encrypting internal note
fields, hiding a proof witness or changing the constructor cannot remove the
equations. A native shielded note can remove a forced public crossing, but an
optional later transparentization can restore it. Public aggregate pool value
can also reveal an isolated sole remaining owner's balance.

The example is an arithmetic counterexample, not a new native transaction,
observer experiment or claim that every full-drainage ledger has a unique gross
history. The retained executed example still has two complete gross histories
and separately disclosed facts. Its
[correction](../research/full-drainage-executed-lifecycle-2026-11-01/CORRECTION.md)
remains authoritative for that experiment.

## The frozen price prior already exceeds the absolute cap

The retained [target-consistency review](../docs/research-knowledge/documents/2567388310cf47d05be72d91cf06ccf70182a730.txt)
records the common-price population and the adopted within-10% success rule:
60% uniform mass on 10, 20, 25, 40 and 50 tKAS; 40% uniform mass on the
4,001 cent amounts from 10 to 50. Guessing 45 succeeds at the 50 invoice mode
and at 910 grid values, 40.91 through 50.00:

```text
P(success) = 3/25 + (2/5)*(910/4001)
           = 21103/100025
           = 21.0977255686...% > 20%.
```

Any observer can ignore the transaction transcript and make that same guess.
Therefore the population's best amount-guessing success cannot be below the
prior floor. A finite favorable sample does not remove the population bound.
The frozen requirements already treat prior-predictable cases as unqualified;
this is a limit on a qualification claim, not a reason to silently amend them.

The [completed price study](../docs/research-knowledge/documents/567b363e0c6151c6d5754b7f79296cc81507a4ba.txt)
and [frozen interpretation](../docs/research-knowledge/documents/13a65c655d15731213619f3a87565acbff4ef6ac.txt)
remain negative/scoped evidence. A weaker heuristic performing worse with extra
records is not a bound on an optimal observer's available information.

The public [arithmetic vectors](rfc0004-privacy-feasibility-vectors-2026-11-03.json)
record both derivations. Verification enumerated only the public 4,001-point
grid and used exact rational arithmetic. It accessed no private evaluation
seeds/truth and reran no old workload or scorer.

## Disposition for implementation and qualification

- A fresh, unfunded interoperability or encoding study can investigate a native
  candidate without claiming that it qualifies the retained workload.
- A protocol implementation cannot promise hidden already-public fields.
  Preserve legitimate owner/counterparty information in its exact claim.
- Passing the unchanged 20% cap on this common-price population is not an
  achievable implementation deliverable. Keep this population as retained
  unqualified evidence. Any additional qualification population or requirements
  revision must be prospective, explicit and owner-directed.
- Before claiming useful financial privacy, choose the protected facts,
  failure/observer model, applicable population, prior baseline and success
  criteria. Neither this review nor a native value encoding closes that gate.

The remaining Q2–Q10 reviews must use this outcome rather than assume that a
different prover or consensus value field supplies a privacy pass.
