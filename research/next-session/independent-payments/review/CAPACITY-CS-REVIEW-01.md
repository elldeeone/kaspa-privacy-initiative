# Capacity constraint/setup prerequisite review

Fresh development setup prerequisite ACK, following the independent design and
source delta reviews. Reviewed actual `controls.py` and selected public result
SHA256 `379daf71ed59e8d49eb067c2bcf1061da2d0bc1d3de50afc84a57fb83b0523b6`,
plus `exits/SOURCE-FREEZE-PRE-SETUP.json`. No witness, assignment or request hash
was needed by the reviewer.

All19 direct-CS cases completed and finalized:17 actual UNSAT and two explicit
SAT native-owned obligations. In particular, coherently funded hidden change,
nonzero unused rho, no-append metadata/CM carry, NF count/overflow, original NF,
ownership/membership, reserve floor, wrong role/domain and missing payout reject.
Parser errors cannot count as UNSAT because a completed structured check result
is required. Native-owned root/outpoint mutations remain SAT rather than being
misrepresented as private-circuit security failures.

All four positive shapes are actually SAT. Compact append, continuing no-append
and terminal no-append share the exact finalized matrix:

`17fc990f38e3495f52ed3aeec5bd1c33fcea0835032c23167ffdf8c15f92d684`

with3,284,767 constraints and3,248,304 witness variables. Wide append has
7,448,842 constraints/7,361,092 witness variables and matrix
`56182775fad7001dc9e3329d50bb4203016a0d54247d58c55725d8df7709be2a`.
All reports bind new domain `d55d006a...` and build identity
`fcf6e8c757613e6fea9a5dd776727f1c2456865f1185c545ac9751ef9fb26419`.
The frozen production source hashes match the prior source review; no old
parameter file was treated as a new-domain authority.

The `NF-absence-is-native-obligation` case alters the old NF root. It demonstrates
the division of private/native obligations, not an isolated occupied-NF attempt
against an authenticated current state. A later fresh privately valid current
occupied-NF native rejection remains required. Actual setup metadata, whole-key
loader readiness, genuine sequential proofs, Full native financial outcomes,
coherent body mutations and final exact accounting remain unqualified here.
