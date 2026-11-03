# ADR 0071: isolated fixed-Output Groth16 adapter experiment

Status: research experiment only; no financial architecture or runtime selected.
Date: 2026-10-26.

## Decision

Test one existing native Output168/Groth16 proof using the established gnark
BN254-in-BN254 verifier at exact commit
`0be5c2ff3dbb2caafb8d48760b6f7e3ffd511b46`. Check compiled constraints only:
no outer setup, proof generation or financial integration. Keep the selected
Output VK constant and constrain canonical Arkworks128 proof bytes to private
pairing coordinates by re-encoding those coordinates. Reuse established field,
bit/comparison, SHA256, curve and pairing gadgets; introduce no primitive.

The experiment uses an existing known-public-seed fixture, verified by the
unchanged selected native relation CLI. The frozen input manifest is
`research/next-session/local-private-payment/privacy-next/native-g16-adapter-01/FIXTURE.json`,
SHA `3902034455441a53848ec5f516ba75d796373e7bb9a648fda53fcd97e545455b`.
It contains the exact public source and executable closure. A missing/invalid
fixture or dependency remains a failure; no replacement setup or proof is
authorized. The full preimplementation criteria are in that directory's
`RUN-SPEC-01.md`.

## Reason

The source assessment established mathematical BN254 compatibility, but a host
decoder does not bind public Output proof bytes to the coordinates used inside
an outer circuit. Changing public proof bytes while retaining the old private
coordinates must fail the actual compiled constraint system. A constraint
solver run is a smaller decisive gate than a new aggregate proof/setup.

Canonical field ranges, Ark compression flags and c0/c1/sign ordering must be
constrained. In particular, modular equality or normalization must not mask a
direct noncanonical private limb assignment. Encoding-only edge controls are
separate from complete fixed-role proof checks. Interpreter/generator/parser
rejection is not a substitute for a compiled-constraint rejection.

## Limits and alternatives

This does not verify the full two-Spend/four-Output aggregate, conservation,
state transition, native reserve release, delivery or recovery. It supplies no
malicious distributed prover or mapping privacy: the ordinary constructor sees
the witness. Current 1/2 codecs, profiles, policy, keys and live trial remain
unchanged. No mainnet, real funds, new token, key setup or admin exit is involved.

The existing RISC Zero exact-byte verifier remains a differential/reference
alternative. A Circom port or coSNARK integration is not selected. Optional
build resources are bounded separately from the actual trial and may stop
without changing any financial acceptance condition. Results and first
unexpected failures will be retained before any prospective correction.
