# Known owners expose two payment amounts after full withdrawal

**Decision:** the [preselected arithmetic screen](SELECTION.md) triggered its
stop rule. Keep the atomic public bundle only as the previously measured
**optional service-timing improvement**. It is not a complete payment-privacy
solution, and this result does not justify another independent-machine Testnet
trial or full cost campaign for that claim. No consensus change or new
transaction was made.

## Plain result

In the accepted [three-claim bundle trial](../atomic-bundle-withdrawal-2026-11-07/TESTNET-RESULT.md),
four private payments happened before everybody withdrew. If an observer later
knows **who owned the payouts** and the four payer-to-recipient
contacts, the public payout amounts force:

| Private payment | What this observer can work out |
| --- | --- |
| A→B | **Exactly 0.6 KAS** |
| B→C | **Exactly 0.3 KAS** |
| A→D | More than 0.24 and at most 0.3 KAS |
| D→A | More than 0 and at most 0.06 KAS |

The retained actual amounts, 0.6/0.3/0.3/0.06 KAS, remain in the feasible set.
The last two values move together: A→D minus D→A is always 0.24 KAS. There are
6,000,000 positive integer-sompi pairs for those last two transfers under this
minimal amount model. That number is **not** an anonymity-set estimate: it does
not weight likely prices, network timing, actual public proof shapes or other
auxiliary facts, all of which could narrow it.

The equations are simple. C began at zero, received only from B, withdrew 0.3
KAS and ended at zero; therefore B→C was 0.3. B received only from A, sent that
0.3 to C, withdrew 0.3 and ended at zero; therefore A→B was 0.6. D's final
0.24-KAS withdrawal fixes the difference between A→D and D→A. A's available
balance before the group withdrawal gives the remaining upper bound.

**Additive observation, outside the preselected score:** the predictor never
uses which of the three equal 0.3-KAS output *scripts* belongs to A, B or C.
If the observer knows only that those three people each withdrew once, the six
possible script-owner assignments remain, while the two exact payment amounts
above are unchanged. This is still auxiliary participant knowledge; it is not
a chain-only result or proof that a stranger can identify those three people.

The atomic bundle was **not read by the amount predictor**. Removing all bundle
and service files from a temporary evidence copy produced identical ranges.
The bundle changes when wallets receive blind replies, not the accepted payout
values. This does **not** undo its earlier narrow result: from the service-only
view it removed the tested one-by-one reply-timing ownership link. Known owners
and contact information can still expose real payment amounts.

## Evidence and limits

The [predictor](screen.py) read the committed accepted fund, withdrawal and
terminal receipts, plus the completed trial's principal. Its frozen auxiliary
observer map and stop rule are in [SELECTION.md](SELECTION.md). The
[prediction](PREDICTION.json) was written before the separate truth check;
SHA-256 `c70d5c50c0097f7171b9b7551d2c5f34b73d25dcce8aed498c775190e2b5112d`.
The [score](RESULT.json) retains the actual history and reports two exact
payment amounts. The existing public TN10 replay checker passes. Two additive
controls passed: removing bundle files left the prediction unchanged, while a
changed terminal payout or incorrect payment truth was rejected.

The owner mapping, initial private principal and contact edges are **declared
auxiliary knowledge**, not established chain-only facts for arbitrary users.
This screen asks what leaks *if* they become known; it does not prove that every
observer learns them. It scores payment amounts under known contacts, not how
an outsider would discover the contacts. It uses a subset of the accepted
record; extra observable fields cannot make an exact amount less exact. It is
one existing, truth-known fixture, not a statistical privacy trial or a
cryptographic audit.

[Olaf's refreshed upstream main](../upstream-privacy-baseline-2026-11-08.md)
has a real two-user Testnet payment and sequential withdrawals, but no matched
three-claim bundle workload or observer transcript. Both designs publish
ordinary payout amounts. This is a field-level boundary comparison, **not** a
matched code-level win or loss against upstream. The existing 47-useful-KAS
proof-and-fee illustration remains about 8.25% before unpriced service costs;
this stopped screen did not reprice it.

## What follows

Stop this bundle's escalation as a proposed full-privacy architecture under
the selected known-owner/full-drainage test. Preserve the optional timing
component and the positive functional Testnet evidence. Further work must name
a *different* current-L1 mechanism and the particular payment fact it could
protect despite public withdrawals, then pass a new bounded arithmetic screen
before more Testnet or cost work. No new token, privileged withdrawal path,
consensus change or published upstream proposal follows from this result.
