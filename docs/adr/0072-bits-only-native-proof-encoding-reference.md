# ADR 0072: a bits-only reference for native proof encoding

Status: isolated research implementation; no financial/runtime selection.
Date: 2026-10-26.

The first emulated-field encoding circuit compiled, but its first positive
assignment could not be solved: the standard committed-range-check path reached
`Bsb22CommitmentComputePlaceholder`. This was recorded as a hint/solver error,
not an encoder verdict. The initial sources and both execution attempts remain
unchanged. A random/debug commitment substitute is not an authorized repair.

Use a separate tiny encoder with four original 64-bit witness limbs per Fq.
Apply established gnark binary decomposition to each limb and compare the entire
256-bit integer against q−1 using established binary comparison. Compute the
same canonical Ark bytes, signs and nonidentity policy with Boolean/native
constraints. Use no emulated field arithmetic, committed lookup, commitment hint
or challenge substitution. Assert that each compiled reference system has no
commitments before checking assignments.

The original forty expected encoding outcomes are unchanged. This is a new
prospective implementation of that encoding predicate, with its own source and
execution identities. It does not repair or qualify the full emulated pairing
verifier. Original codec sources and full-wrapper source remain separate.

The exact prior failure, source boundary and new criteria are recorded in
`research/next-session/local-private-payment/privacy-next/native-g16-adapter-01/RUN-SPEC-02.md`.
No setup, proof generation, private owner/Original data, network trial, financial
profile, native ABI, exit route or privacy claim is selected by this decision.
