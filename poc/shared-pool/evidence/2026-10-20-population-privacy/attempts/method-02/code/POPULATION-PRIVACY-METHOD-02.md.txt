# Method 02: compact input selection and public solver witnesses

Date: 2026-10-21 (Australia/Sydney).
Parent: [frozen population specification](POPULATION-PRIVACY-SPEC.md).
This is a method-only refinement on the same generated histories, not a new
workload, privacy criterion or protocol. Method 01 and its logs remain intact.

## Observed problem and proposed change

Method 01 is still searching for its first full-history feasible assignment.
The 150-operation first persistent history creates one selection Boolean and
one selected-value variable for every eligible earlier note at each spend.
It has not returned any prediction or privacy result.

Replace that CP-SAT arithmetic representation with two sorted input-position
indices per spend. Zero in the second index represents the absent second input.
Use element constraints to select values and owners. Give absent second inputs
distinct out-of-range dummy identifiers in a global all-different constraint;
real inputs must remain distinct across all spends. Preserve every common-owner,
value, range, admission, output-order, disclosure and commitment-equality rule.

The equivalence argument is:

1. A valid Boolean selection contains one or two distinct earlier positions.
   Sort them to obtain exactly one canonical index tuple.
2. Each canonical index tuple maps back to those exact selected positions.
   Distinct dummy identifiers do not collide with real positions or each other.
3. Element constraints select the same values and positive-note owners.
   Conservation equations and permitted selections therefore remain unchanged.
4. At terminal reserve zero, nonnegative note values, per-transition conservation
   and no repeated spend imply that every positive note was spent. At a
   nonterminal prefix, unspent positive notes are allowed.

No integer quantization, private-history hints, additional wallet-policy
restriction or relaxed leakage budget is permitted.

## Independent checking without repeated unconstrained SAT search

A complete hypothetical assignment found by the observer's CP-SAT model can be
checked in the original independently encoded Z3 relation. Temporarily fix its
values, positive-note owners and exact input selections, then require SAT.
That proves this assignment exists in the original relation; the assignment
comes from public inputs and declared participant records, never private truth.
Do not impose an owner on a zero-valued note.

The same approach checks alternative assignments for non-forced facts. Candidate
and alternative witnesses must actually differ in the tested field. For a forced
fact, both models still need UNSAT for the unrestricted alternative proposition.
In particular, all temporary witness restrictions must be removed before asking
Z3 whether any different sender, recipient or amount is possible.

Within one exact prefix/view, a previously checked full-history assignment can
also witness an alternative for another payment field. Check that field in both
encodings' returned assignments before reusing it. Never reuse a witness from a
different prefix or participant view. This avoids repeated search; it adds no
feasible histories and removes none.

These changes preserve exact feasibility semantics. They do not turn witness
counts into probabilities, weaken dual-solver certification, or pass any privacy
threshold. Unknown, inconsistent or disagreeing results remain incomplete.

## Controls, freezing and scoring

Before held-out execution, rerun the original model/workload controls and check
the compact relation against tiny exhaustive owner/value/spend assignments and
the original encodings. Include no repeated spend, common ownership, a missing
second input, two real inputs, terminal/nonterminal histories and participant
constraints. Keep rejected/unknown cases visible.

Freeze this note, executable sources, dependencies, original specification,
source-attempt identity and exact public/view/truth file hashes before method-02
inference. Reuse the same held-out histories; do not sample new seeds.
The observer receives exactly one selected public file and one participant view,
with no access to the matched arm, private seeds or true private history.

Seal predictions before the separate scorer receives private truth. The scorer
must require the concrete generated history to satisfy both original encodings.
Eligibility, the persistent-arm stopping rule and every unexecuted obligation in
the parent specification remain unchanged.
