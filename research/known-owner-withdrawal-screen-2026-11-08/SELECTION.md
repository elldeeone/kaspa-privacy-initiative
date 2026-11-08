# Known-owner withdrawal screen: fixed before the arithmetic check

**Date:** 8 November 2026 (Australia/Sydney). **Source:** accepted bundle
Testnet-10 run at commit `06d16ee1`. This is an offline privacy falsification
using existing evidence. It spends no test KAS, changes no consensus rule and
does not score Olaf's different two-user workload as a matched baseline.

## Question and observer

After every participating wallet withdraws, does our atomic public bundle
keep the **amounts of the actual private payments** unknown to an observer who
learns payout owners and the four allowed contact edges? The observer sees the
accepted native output values and the public trial's 1.2-KAS principal. It is
also given the truthful auxiliary mapping: A/B/C each owns one 0.3-KAS group
payout, then A owns the 0.06-KAS terminal payout and D owns the 0.24-KAS
terminal payout. These owner labels and contacts are **not chain-only facts**.

The four contacts, in chronological order, are A→B, B→C, A→D before the group
withdrawal, then D→A before terminal withdrawal. Their values are hidden from
the amount predictor. All amounts are positive integer sompi. A alone starts
with the private 1.2 KAS; B/C/D start with zero; no undisclosed outside payment
or retained private principal is allowed. The 0.8-KAS bank fee allowance and
ordinary chain fees are kept separate from private principal.

The retained scoring truth is 0.6, 0.3, 0.3 and 0.06 KAS in that order. It is
used **only after** computing feasible intervals. Because this existing fixture
and its truth are already published, this is an auditable lower-bound leakage
check, not a blinded new privacy trial or a statistical population result.

## Fixed measures and stop rule

Read accepted fund/withdrawal/terminal receipts and the completed-trial
principal, require the specified output values and zero terminal bank value,
then solve the integer balance constraints with nonnegative balances at each
step. Report each edge's minimum and maximum feasible amount and the number
whose amount is exact. Check that the actual four amounts remain feasible.

**Stop escalation if any actual payment amount is exact under this admitted
observer.** An atomic bundle changes reply availability, not native output
amounts, so the same arithmetic applies to a no-bundle publication of this
exact cashout shape. Exact facts found from a subset of the public record cannot
be made uncertain by adding more public fields. Do not claim a matched
code-level comparison to Olaf: his current main has a different two-user run
and no three-claim bundle. This test does not measure who could discover the
contact edges, network timing, chain-only owner inference or independent users.

If the stop rule fires, retain the narrow measured service-timing benefit but
do **not** start another independent-machine Testnet run or a full cost campaign
to promote this bundle as a complete financial-privacy solution. A distinct
mechanism and matched privacy hypothesis would need a new selection first.
