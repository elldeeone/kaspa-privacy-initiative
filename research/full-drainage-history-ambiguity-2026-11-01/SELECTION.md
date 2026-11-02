# Frozen full-drainage payment-history ambiguity model

**Freeze date:** 2026-11-01  
**Model identifier:** `full-drainage-history-ambiguity-v1`  
**Repository commit:** `7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1`

This is a bounded public constraint model, not a prover run or measured user
anonymity study. It is frozen before enumeration. No random sampling or secret
truth is used; all compatible histories are exhaustively enumerated in the
declared finite amount grid.

## Question

Can two materially different private payment histories be compatible with the
same complete public deposits, operation evidence and full-withdrawal evidence,
even when payout owners are known and every claim exits?

The property is gross-payment ambiguity: who paid whom and individual payment
amounts. Hidden chain labels, commitment assignments, transaction positions and
output order do not count.

## Cryptographic-opacity assumptions

- Note commitments are binding but opaque; the model does not seek different
  openings of one commitment.
- Ciphertexts hide owner/value from the observer.
- Nullifiers reveal spentness but not the spent commitment or owner.
- Generic private TRANSFER operations reveal count and order, not input owner,
  recipient or value.
- Public deposits and exits reveal their native amounts. Known-owner views also
  receive deposit and payout-owner identities.

These are assumptions for the model, not newly proved properties.

## Candidate: ordinary multi-party activity

Use actors `A`, `B`, merchant `M` and supplier `S`.

Public initial deposits, in units of 10,000,000 sompi:

```text
A: 10
B: 10
```

Allow ordinary directed payment relationships:

```text
A -> M
B -> M
M -> S
A -> S
```

Enumerate exactly three genuine payments. Each current-wallet payment consumes
one owned note and creates a positive recipient note plus positive sender change.
Amounts are positive integer grid units. No self-payment, cycle, dummy operation,
cover transfer, batching, delay or coordinator is allowed.

Known-owner terminal exit multiset after all liabilities reach zero:

```text
A: 6
B: 8
M: 3 and 2
S: 1
```

The known view receives those owner mappings. The unmapped view receives only the
exit amount multiset `8,6,3,2,1`. Both receive two deposit operations, three
generic private transfers and five exits. Transfer positions are public but not
owner-linked under the opacity assumptions.

The model must demonstrate at least two compatible histories whose gross payment
fact multisets differ in a relationship and an amount. Histories differing only
in event order, note identity, commitment assignment or hidden labels are
deduplicated.

This finite, hand-chosen workload establishes possibility only. It is not an
ordinary-user distribution, posterior probability or anonymity-set estimate.

## Hypothetical merge projection

Without changing the three payments, model a private merge of M's two terminal
notes `3+2 -> 5`. The public terminal exits become:

```text
A: 6
B: 8
M: 5
S: 1
```

Both candidate histories must remain compatible. This projection tests the
information effect of a two-input merge; it does not claim the current circuit
implements it and does not implement a new prover.

## Failure control

Public evidence:

```text
deposit A: 10
one generic private transfer
known-owner exits A: 6, B: 4
allowed relationship A -> B only
```

The known-owner control must yield exactly one gross payment history:
`A -> B: 4`. The unmapped sensitivity view is reported separately.

## Observer views

1. **Protocol-known:** complete public operations, deposit amounts/owners and
   exit amounts/owners under the declared PoC/native boundary.
2. **Protocol-unmapped:** same public evidence without exit-owner mappings.
3. **Plausible-external-known:** protocol-known plus the full four-edge possible
   contact graph; it does not assert which edge was actually used.
4. **Strong-external/workload:** known-owner evidence plus the fact that S's
   payment came from M. This is retained as an adverse sensitivity view; it may
   eliminate the candidate alternative.

Facts from earlier experiments such as exactly two chains, one-to-one recipient
roles, target/remainder phase labels and fixed payment policies are not protocol
facts and are not silently imported into the candidate. Their effect is audited
separately.

## Metrics

For every view report:

- compatible event sequences;
- unique gross payment fact multisets after position deduplication;
- candidate sender, recipient and amount sets per material payment fact;
- whether relationship ambiguity exists;
- whether individual payment-amount ambiguity exists;
- terminal owner net balances;
- terminal per-note exit amounts; and
- whether complete drainage is satisfied.

Separate net-balance disclosure from gross-payment ambiguity. A large historical
pool, multiple event orders or opaque commitment mappings do not count.

## Stop and decision rules

- Candidate possibility passes only if the known-owner view contains at least two
  distinct gross histories with a different relationship and amount, while all
  public evidence and zero final liability are identical.
- The isolated known-owner control must remain unique.
- If only unmapped ownership, event order or note assignment creates ambiguity,
  the candidate fails.
- If current one-input operations suffice for possibility but expose note-level
  exit granularity, report that limitation. Do not call it universal privacy.
- Treat a private merge as the minimal proposed change only if current source
  authority confirms the circuit cannot consume multiple notes and the merge
  projection reduces exit granularity without erasing the failure control.
- No wallet/circuit/prover/runtime implementation, network action, funded trial,
  capacity change, MPC, commit, push or upstream post.
- Stop after this model and the source-grounded architectural decision.
