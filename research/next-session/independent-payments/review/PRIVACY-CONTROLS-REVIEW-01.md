# Public privacy controls second pass

Independent child reviewer checked all nine frozen public source/hash rows at
`ec33792764a959d0b0e50fc50445f733d0f4c2621efa884f7768062b80ec65e5`.
No blocker to interpreting the one-shot eight groups as finite negative
controls. No execution, hidden material, retuning or heldout drawing was done by
the reviewer.

Actual ledger/observer paths cover all earlier positive one/two-input choices,
chronology, once-only spend, partial/full/no-append accounting, exact sums/prefix
backing and own-original-NF facts. Complete per-position yes/no query coverage,
exact SAT-query predicates and global UNKNOWN forcedness clearing were checked.
The independent integer checker validates SAT witnesses/predicates and baseline
contradictions; UNSAT still relies on the exact Z3 run, not an independently
checked UNSAT proof.

A concrete attacker-strength omission remains in this frozen version. Outgoing
invoice records constrain value, but do not add outgoing position→known
recipient role to ownership propagation. A participant who sent that invoice
payment legitimately knows this role. If bootstrap is already spent and its
own change NF remains absent, a later mandatory spend of the recipient receipt
should propagate the known recipient’s payer role. The current observer/checker
omit that fact and can return unknown role instead.

This is a weaker attacker/false negative, not an improved protocol. The eight
fixed fixtures do not later spend a participant outgoing note, so their declared
negative conclusions are not invalidated by that omission. Preserve original
source/run and fix via a separately identified public addon/control before any
future heldout. Do not retrospectively retune the frozen one-shot or interpret
missing role deductions as privacy. No new privacy, crypto-realizability or
human-identity qualification follows.
