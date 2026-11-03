# Method 04: bounded local disclosure search

Date: 2026-10-21 (Australia/Sydney).
Parent: [population specification](POPULATION-PRIVACY-SPEC.md).
This is a new, explicitly weaker analysis relaxation. Unlike methods 02 and 03,
it does not preserve the complete feasible set. It can establish a supported
forced disclosure, but cannot establish full-model ambiguity or a privacy pass.

## Motivation and fixed selection

Full-history searches have not returned an initial feasible assignment. Do not
make that global search a prerequisite for finding an algebraically local leak.
Keep the same generated histories, public inputs, participant disclosures,
target list, horizons, eligibility and stopping rules. No private truth has been
read during attack development and no completed privacy result is being retuned.

For each ordinary target payment, retain exact input selection and conservation
equations for:

- the bootstrap;
- every disclosed authored event;
- the target payment;
- the first three subsequent DRAIN events in public order, or all of them if
  fewer than three exist.

This selection uses no private eligibility, hidden graph or amount-derived
choice. It does not assert that a selected DRAIN consumed the target's note.
Every eligible predecessor position remains available to a retained spend.

Keep the complete note-position and owner universes, original public-derived
value bounds, all admission facts, positive payment/zero padding conventions,
change ownership, equal-commitment bindings and complete participant-record
constraints. Retain one/two real inputs, anchor eligibility, common ownership
and no double spending among retained events.

Omit undisclosed, unselected events' input equations and selectors, and omit
terminal exact-consumption and reserve-coverage constraints. Do not reconstruct
a fake shortened ledger or replace an unknown boundary with one solver's chosen
assignment. Unselected events' public/disclosed facts remain present.

## What the result means

Every full-model valid history restricts to an assignment of this relaxation:
only constraints are removed, while retained facts and bounds are implied by the
full model. Therefore a proposition forced by this relaxation is also forced by
the full model, provided the full model has a valid history.

Require SAT for the proposed fact and UNSAT for any different value in separately
encoded CP-SAT and Z3 versions of the slice. Reuse method 02's checked public
witness handoff: a complete CP slice assignment is temporarily pinned in Z3 to
verify SAT, then all pins are removed. Candidate and alternative field values
must agree. Caches are local to one target slice and prefix. A CP UNSAT result
still requires Z3 UNSAT with only the proposition's negation, never a fixed input
graph. Release solver objects between targets; retain plain certificates.
Seal all predictions first. Then the
isolated scorer must verify pinned generated truth satisfies both original full
encodings, and that every claimed forced value matches that truth.

An alternative in the relaxation is **slice inconclusive**, not a feasible
full-history witness, a probability, an anonymity set, or evidence of privacy.
Inconsistency, unknown or solver disagreement is incomplete. A complete set of
slice queries with no primary disclosure does not close the original privacy
gate. Do not promote startup, direct-counterparty or prompt-arm disclosures to
a failure of the primary mature persistent-payment claim.

## Controls and preservation

Before held-out execution, verify that complete tiny full-model witness sets all
satisfy the relaxation; forced slice facts must agree with the independent
exhaustive full set. Include an omitted-equation case with spurious alternatives,
demonstrating why non-forced slice facts are inconclusive. Check distinct positions,
one/two inputs, ownership, participant completeness, prefixes and temporary solver
restrictions. Existing strict schema and original-model controls remain required.

Freeze this note, executable sources, dependencies and exact parent input hashes.
Copy reused original source bytes from the preserved parent snapshot. Use one
selected public file and one declared participant view, without sibling-arm,
private-seed or true-history access. Preserve earlier failed/incomplete attempts.
No seeds, amounts, thresholds, integer domains or protocol rules are changed.
