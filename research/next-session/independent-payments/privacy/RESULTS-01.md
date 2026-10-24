# Independent payments: finite privacy falsification

**The stronger observer still exposes payer roles through sender change.**
The eight fixed public control groups passed their expected checks; those
checks deliberately demonstrate privacy failures. No holdout was drawn and no
old study was rescored.

## Actual observations

1. Publicly disclosed component output sets remain recoverable after an outer
   wrapper/display permutation. A genuinely hidden assignment is a different,
   unimplemented relation obligation; this does not prove all aggregation fails.
2. For the same 64 modeled invoices and complete drainage, the direct
   same-component rule labels 62/62 other economic outputs in wide32 and 0/62
   in the existing serial layout. Change/dummies are not useful payments. This
   is only a restricted metadata-scope result, not a general privacy improvement
   or a new serial protocol. Fees are explicit symbolic control amounts, not
   current native quotes or fee qualification.
3. The payee's known receipt NF is absent from a later action. The bootstrap
   was spent, leaving positive sibling change as the only input. Under the
   one-invoice sender-change policy, the later payer role is forced. This holds
   in both one- and two-input capability controls. Compact packaging does not
   remove this sparse cross-action leak.
4. A positive native payout before any second funding ingress has only the
   first source as a possible funding ancestor. The controls include splitting,
   two actual inputs, partial payouts and later genuine demand/funding. Later
   value cannot fund an earlier event. The public causal certificates below
   separate this conservation argument from a human-identity claim.
5. Payer and funding origin stay distinct: an actor can pay using value
   received from another funder. Positive extra eligibility, zero/dummy generic
   remainder, generic two-payment outputs, partial payouts, no-append shape,
   stale counts, replay, malformed values and UNKNOWN guards remain explicit.

All 11 global cases in each eight-group run completed with compatible true
integer histories. This is a finite collection of controls, not independent
population samples or a statistical privacy bound. The same-partition metadata
comparison does not pretend to run global reconstruction over its large
64-invoice trace.

## Review-found omission, retained red and corrected green

Independent review found that legitimate outgoing invoice values were used,
but outgoing position→known recipient ownership was missing from the observer
and derived-role checker. The original ec337927 source/run are preserved under
`source-01` and `controls-01`; their finite negatives remain valid, but they did
not test a later spend of an outgoing recipient note.

A new fixed calibration has Alice pay Bob, then Bob pay Carol. Alice knows her
bootstrap/change NFs and her outgoing Bob invoice. Bob's receipt is the sole
later input. The correct current payer role is Bob (1), while the original
funding source remains Alice's source (0).

- [Red](outgoing-red-01/RESULTS.json): old observer returned role=None for both
  one/two-input allowances; the correct role=1 assertion failed as intended.
- [Green](outgoing-green-02/RESULTS.json): the same fixture/addon recovered role=1
  after the missing recipient fact was added to both observer and independent
  checker. All eight affected control groups also passed under source02.

The addon is an additional privacy failure detected by a stronger attacker,
not a privacy fix. No original threshold or hidden sample changed. The observer
remains a limited, explicitly declared role-inference algorithm; exhaustive
cryptographic ownership/world inference is not claimed.

## Conservation certificate and scope

[CAUSAL-CERTIFICATES-01.json](CAUSAL-CERTIFICATES-01.json) binds three public
prefixes and feasible public integer assignments. Starting at zero reserve,
all positive value enters through explicit earlier ingresses. Each action
consumes one or two earlier positive notes and conserves value into outputs,
payouts and fees. Inductively each positive descendant can have only an earlier
funding ancestor. With a singleton source set before the target, the positive
payout's nonempty ancestry is that source. This holds for every history in the
declared model, not just the displayed feasible assignment. The assumptions
include complete public ingress history and no unaccounted external value
inside an action. Mixed-source value allocation and human identity are not
inferred by taking a union of causal dependencies.

These are symbolic controls: CM/NF/cipher labels are not cryptographic
preimages, accepted transactions or real recipients. The prospective no-append
case is a capability control, not native acceptance evidence. Current protocol
implementation, fees, private unilateral exits and provider availability have
separate evidence/gates.

The original 45-KAS prior still succeeds within 10% with probability
21103/100025 = 21.0977%, above the original 20% gate. The uniform32 and sparse
failures remain. **Original privacy qualification remains FAIL.** There is no
reason to consume a large new holdout merely to repeat that analytic outcome.

[Resources](RESOURCES-01.json): the initial eight groups took about 0.20s and
reported peak36M; the green eight-plus-addon run took about 0.31s and reported
peak42.2M under 2 CPU /
6 GiB / zero-swap limits. The red assertion failure is intentional calibration,
not a native/funding failure. No proof, parameter setup, RPC, funding or external
upload was performed by this lane.
