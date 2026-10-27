# Research ADR R01: explicit native Output matrix binding

Status: proposed bounded interface experiment; source prepared, not compiled or run.

The native Output predicate already exists over BN254 Fr. Its two public SHA
limbs are allocated internally by its ConstraintSynthesizer. Before changing
that API, test a smaller interface construction using the unchanged matrices.

Synthesize only the existing public Output fixture. Preserve every original
R1CS coefficient/row and its variable order, while moving its two public digest
variables to private indices. Introduce two external public digest variables
and enforce two explicit equality constraints. This answers whether actual
native witness validity remains linked through the proposed seam, rather than
through a host-side copy of values.

The evaluator must reject any unexpected GR1CS predicate; ignoring non-R1CS
constraints is never an export. It must admit only exact-length assignments
with constant wire ONE equal to one. An all-zero vector would otherwise satisfy
homogeneous matrix equations. Assignment/source refusals are separate from
actual nonzero constraint residuals.

This changes the matrix identity and allocation, even though the admitted
external language is equivalent to the original Output relation. The original
and lifted matrices may use the same FFT domain size; that does not qualify
feeding the new matrices/witness to an old proving key. This experiment uses
no key, setup or proof and makes no VK reuse claim.

The current native crate stays unchanged. Its public source files and original
manifest remain pinned. A small owned crate depends on it and synthesizes its
existing OutputCircuit; the unused Spend structure returned by its public
fixture factory is discarded and no Spend circuit is synthesized/shared.

This is not a direct Spend-sharing decision, a signature-authority design,
native2/4 acceptance, encryption/delivery proof, private-prover implementation
or fee result. It is excluded from candidate14 and the main final-data pipeline
until separately selected. Parent architecture and financial profiles do not
change. First unexpected outcomes remain retained under a fresh run identity;
source corrections require a new prospective attempt.

