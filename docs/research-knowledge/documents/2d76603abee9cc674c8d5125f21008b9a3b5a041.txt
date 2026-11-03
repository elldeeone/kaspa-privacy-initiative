# Proposed exact public arithmetic observer

**Status: proposal for root selection. No observer implementation or evaluation
is authorized by this file.** Existing Z3 4.15.4.0 is available in the local
shared-pool-tools environment; [inventory](SOLVER-INVENTORY-01.json) records the
Python/library identities and an exact integer probe above2^53. No install occurred.
The old72-case corpus/source is development reference only and stays unchanged.

## Research question and limits

Does the declared wallet policy plus complete public ingress/withdrawal/reserve
history logically force a private note value or a commitment-to-payout selection?
Can hidden positive change leave multiple integer arithmetic explanations?
The singleton mechanics rehearsal is an explicit negative privacy control.

Version1 should model the **known single-real-input wallet policy**. Its two
wire NF slots do not imply two real consumed notes. No private input→CM map,
owned-note/owner map, actual change slot, key, opening, generator truth or raw
participant private view enters the observer.

Owner links are **NOT_MODELLED** in the minimal version. Public destination
identity and private note ownership are different facts. A later owner-aware
version would need separately frozen legitimate public identity priors and hidden
ownership/change constraints. Without that extension, arithmetic alternatives
must not be called authorized cryptographic alternatives or owner anonymity.

## Proposed strict API

`analyze(public, value_priors, query_plan) -> report`, plus one JSON stdin/stdout CLI.
No generator imports, filesystem discovery, network, crypto or hidden-input reader.

- Public identity: new versioned schema, classification
  `SYNTHETIC_PUBLIC_INTEGER_MODEL`, fixed minimum note/payout and maximum amounts,
  declared complete chronological coverage, globally known wallet-policy arm.
- Ingress events: public new CM and explicit backed note value; reserve rises by
  that value. Ordinary ingress fee is visible but not subtracted from liabilities
  twice.
- Private events: prior/next reserve, pool-paid fee, public payout/destination,
  exact public CM births, opaque NF labels and terminal flag. Continuing actions
  append two CM slots; terminal actions append none. Counts/labels/ordering and
  reserve deltas are strictly checked. Duplicate public CMs/NFs are rejected.
- Priors: only explicitly authorized integer value bounds or finite value support
  over public CM identifiers, with declared provenance class. No probabilities,
  floating prices, private ownership/input map or implied zero for unknown notes.
  Root chooses admissible prior classes before heldout generation.
- Query plan: all public note values and all private events' input sum, new-output
  sum and consumed-CM selection by default. Target selection must not be chosen
  using truth. A frozen public subset is allowed for resource bounds.

Whole-claim arm: every positive native cashout creates zero positive private
outputs. Change-capable arm: a positive cashout may create zero or one positive
private output; private payments may create one or two. A real private payment
must have a positive output. These are declared wallet-policy assumptions,
not universal Auth528 facts. No fixed role is assigned to either output slot.

## Exact relation

Use only Z3 `Int` and Boolean selectors, not Real relaxation or amount grids.

1. Each public CM has value0 or an integer in the adopted legal note range.
2. Each private action selects exactly one earlier positive CM. Every CM is
   selected at most once across the complete history.
3. For each private action:
   `selected value = sum(new private values) + public payout + pool fee`.
4. At every prefix, the sum of positive born but unconsumed note values equals
   the public reserve. Terminal zero reserve therefore cannot leave an unspent
   positive liability.
5. Apply only the selected arm's output-count predicates and explicitly supplied
   value priors. Every sum is mathematical integer arithmetic with explicit
   adopted bounds, not modular arithmetic.

The relation deliberately omits hash-preimage existence and private ownership.
A forced arithmetic fact is a necessary inference under these assumptions;
two arithmetic models are not proof that two authorized cryptographic witnesses
exist, nor equally likely histories.

Every SAT model/countermodel should be checked by a separate small integer
certificate checker implementing the public equations without using Z3 results
as authority. No inferred model is relabelled hidden truth.

## Decisions and result semantics

First check the whole relation. Baseline UNSAT means inconsistent public history,
policy or priors; UNKNOWN means INCOMPLETE. Neither is ambiguity.

For each amount expression, obtain one SAT integer value and ask whether a
different value is possible. UNSAT alternative means FORCED_VALUE. SAT alternative
means ARITHMETIC_ALTERNATIVE_ONLY, with two checked projections. UNKNOWN means
INCOMPLETE for that query.

For a payout, similarly block the first selected-CM set. A unique single CM is
FORCED_CM_TO_PAYOUT under the declared single-input policy. Multiple checked
selections are arithmetic alternatives, not guaranteed anonymity. A known
aggregate input sum does not identify a CM or owner. Owner links remain
NOT_MODELLED and no guesses/posteriors are fabricated.

## Required analytic controls before any heldout evaluation

1. Whole-claim cashout: input value exactlyP+fee. Shuffled real/dummy output
   positions can still leave the corresponding public CM label unresolved.
2. Singleton partial cashout: known sole prior liability and public reserve
   force consumed input and aggregate remaining change even though P+fee is
   smaller than input value. Do not report this as a privacy success.
3. Multi-ingress hidden-change trace: produce two distinct exact integer
   explanations with the same public history; assert only arithmetic multiplicity.
4. Terminal/all-but-one controls: drainage or legitimate value knowledge can
   force a residual. A terminal transition leaving a positive unspent note is
   inconsistent rather than safely zero.
5. Single-spend/causality negatives: selecting the same note twice or a future
   note must be impossible; malformed counts, duplicate NF, badP/R/fee, unsupported
   policy and extra private-map fields must reject.
6. Precision/range: values above2^53, legal minima, zero dummy, maximum adopted
   value and malformed negative/overflow amounts use exact integers.
7. Forced-backend UNKNOWN control: report INCOMPLETE, never collapse it to a
   second solution or an infeasibility proof.

Root must select source/API/policy, admissible priors, workload sizes, heldout
separation and stop rules before evaluation. A useful first bound is at most
12 born CMs and8 private actions per case with independent case workers, generous
fixed per-query timeout and an explicit INCOMPLETE outcome. No old corpus scoring,
parameter search, corpus replacement or privacy/fee qualification follows from
this proposal. If arithmetic alternatives survive, the owner-aware/circuit
feasibility gap remains an explicit next obligation.
