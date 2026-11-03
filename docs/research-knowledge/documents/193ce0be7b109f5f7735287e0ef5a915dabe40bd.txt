# Actual-transaction privacy result

**Date:** 2026-11-02  
**Scope:** retained successful TN10 attempt 06 and one offline counterfactual.  
**Decision:** the measured reserve fix is rejected as a direct-payment privacy fix.

## Answer

The strongest demonstrated direct-payment leak is the **known-owner,
full-drainage balance constraint**. In the correction's finite three-payment
model, public deposits and complete transparent withdrawals:

- reveal `B -> M = 20,000,000` sompi in both compatible histories; and
- constrain `A -> M` to `30,000,000` or `40,000,000` sompi.

Two complete gross histories survive, and the actual history remains one of
them. The retained chain does **not** uniquely reveal the actual gross payment
history.

This is conditional on the declared owner mappings, allowed payment edges and
three-operation model. The owner mappings are experimental auxiliary evidence,
not facts encoded by the chain.

## What the actual transactions expose

Verified native transaction facts:

- Both deposits were 100,000,000 sompi.
- Deposit A's reserve funded the 60,000,000 A exit, then the 30,000,000 M exit,
  then the 10,000,000 S exit.
- Deposit B's reserve funded the 80,000,000 B exit, then the 20,000,000 M exit.
- Each payout publicly exposed its principal through the native output amount
  after subtracting the fixed 50,000,000-sompi permission rent.
- The 100,000,000-sompi state output rolled through all seven settlements.
  Settlements 02–06 each created one 50,000,000-sompi permission output, and
  payouts 01–05 each consumed a different one exactly once.
- The reserve input and change output expose exact deposit-funding ancestry.
- One sponsor funded all 27 protocol transactions. Their total recorded fees
  were 358,209,100 sompi.
- Operation kind, order and retained payload/proof/ciphertext shapes are public
  or retained public evidence.
- Accepted timestamps and blue scores give ordering and timing evidence.

The fee/sponsor, operation-shape and timing fields were logged, but no frozen
likelihood model showed that they distinguish the two surviving payment
histories. Network/IP origin was not measured. Orchestration filenames and the
`A/B/M/S` labels are not chain facts.

## Measured observer results

| Observer view | Complete compatible gross histories |
|---|---:|
| Chain only | 72 |
| Known owner mappings and terminal balances | 2 |
| Known owner plus exact reserve ancestry | 2 |

Truthful participants received only their own terminal mapping and own payment
facts. Under the actual own facts, compatible complete histories were: A `2`, B
`18`, M `2`, S `4`. These are bounded candidate counts, not a universal
anonymity score.

The corrected false `M -> S` view remained uniquely wrong. The sparse control
remained unique. Held-back execution truth was read only after prediction seal
`2d83123dc3572c2fd686642473341ffbb8a109c984a65a17f5a6451f8206a20e`.

## One targeted mitigation

The frozen candidate was a synthetic, value-conserving consolidation of both
deposit reserves into one common 200,000,000-sompi reserve before exits. It
kept the observed exit order, allowed immediate exits and drained to zero. It
added no MPC, forced delay, withdrawal lock, privileged withdrawal signature,
cover value or retained user principal.

Measured against the same observer:

- deposit-funding-origin candidates per payout improved from `1` to `2`;
- complete direct-payment histories stayed `2 -> 2`.

Therefore consolidation addresses exact reserve-origin linkage but **does not
address the biggest demonstrated direct-payment leak**. It is an offline model,
not an implemented covenant path, protocol change or ready fix. The frozen
hypothesis that reserve ancestry selected one gross history was falsified and
retained. No RFC/ADR was opened because no architecture change was accepted.

## Exact blocker and smallest remaining step

With transparent exact withdrawal amounts, known owner mappings and every user
fully withdrawing every claim, per-owner net balances survive reserve
consolidation. A local reserve-selection rule cannot hide them.

The smallest remaining step is a design decision: either exclude this
known-owner/full-drainage observer from the privacy claim, or research an
established mechanism that hides native exit amount or ownership while keeping
permissionless immediate exits. That is a protocol-level boundary question,
not a tuning change. MPC remains paused.

## Earlier funded attempts: read-only inventory

Both queried TN10 Borsh endpoints returned the same current UTXOs. Nothing was
spent, recovered or changed.

| Attempt | Last retained checkpoint | Sponsor ordinary | Reserve principal | State rent | Permission rent | Owner payout outputs |
|---:|---|---:|---:|---:|---:|---:|
| 01 | none | 9.998305 | 0 | 0 | 0 | 0 |
| 02 | initialize | 6.905777 | 2.0 | 1.0 | 0 | 0 |
| 03 | initialize | 6.422536 | 2.0 | 1.0 | 0 | 0 |
| 04 | batch-02 | 4.447339 | 1.4 | 1.0 | 0.5 | 1.1 |
| 05 | batch-05 | 2.373212 | 0.1 | 1.0 | 0 | 3.9 |
| 06 | batch-07 | 0.917909 | 0 | 1.0 | 0 | 4.5 |

Amounts in the table are test KAS. Attempts 01–05 are independent of attempt
06. Four earlier attempts retain 5.5 test KAS of reserve principal in total.
Sponsor key presence and file mode were checked, but recovery capability was
not exercised. Owner payout outputs are outside sponsor recovery.

## Adversarial review

The observer rejects reused reserve outpoints, reused/missing permissions,
broken state lineage, non-conserving reserve change and a non-zero terminal
reserve. The candidate pays exactly the original 200,000,000 sompi and drains
to zero. It changes no authorization, proof, root, nullifier or payout check.
Missing or changed evidence fails closed. Its material hidden assumptions are
the auxiliary owner mappings, allowed payment graph and three-operation count;
none are promoted to chain facts.

## Limits

This is evidence about one retained transcript and a bounded search model. It
is not production privacy evidence, a cryptographic audit, proof correctness or
a general claim about larger pools. No new trial, broadcast, mainnet action,
paid compute, MPC work, public post, push or recovery action occurred.
