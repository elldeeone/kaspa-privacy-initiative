# Authenticated Groth16 functional gate

This implements the bounded experiment in
[ADR-0075](../../../docs/adr/0075-authenticated-groth16-functional-experiment.md).
It uses three actively authenticated MASCOT servers and two external TLS clients
for the public synthetic fixture `x=3`, `y=5`, `z=x*y`, `t=128`.
The actual three-server/two-owner toy run produced three identical complete
proofs. Independent Arkworks accepted `128` and rejected `129`. Both actual
invalid-assignment and MAC-corruption controls refused before releasing a proof;
all twelve preinput controls passed. The exact source/build/run identities and
retained failures are in
[the bounded qualification](evidence/2026-10-28-functional-toy/QUALIFICATION.json).

The complete path retains authenticated values and MACs through external input,
cross-owner auxiliary generation, full R1CS validation, the LibSnark QAP/FFT
witness map, proof randomness, group MSMs and checked openings. It emits a
canonical 128-byte proof only after all field/group checks and independent
Arkworks verification. Auxiliary B1 remains a server-internal opening.

The same authenticated extended assignment is checked before any proof-related
opening. Exact full-field Fermat zero tests and a private AND reveal only the
aggregate validity bit. They do not open individual residuals or use a bounded
integer equality shortcut. Full NativeAuth performance is unmeasured.

## Build and run

[DEPENDENCIES.json](DEPENDENCIES.json) identifies exact MP-SPDZ, mcl,
SimplestOT_C, libOTe, cryptoTools, their transitive sources and local
development-package bytes. The selected route is upstream's standard malicious
SoftSpoken implementation (`USE_KOS=0`, `USE_LIBOTE2=1`), with assertions and all
stock security guards enabled. The mutual-TLS patch requires client certificate
presence. Build caches and binaries remain outside Git.

The earlier KOS configuration is retained as failed history. Pinned MP-SPDZ
expressly guards that optional route as insecure benchmarking; its guard was
never bypassed. It is not an admitted runtime dependency. See
[the exact standard-route build settings](SOFTSPOKEN-BUILD.md).

With the admitted local vendor tree:

```sh
python3 poc/local-private-payment/mpc-prover/build.py \
  --vendor-root .local/mpc-prover-softspoken-vendor \
  --output .local/mpc-prover-build-new --jobs 2
```

`run_toy.py` selects the compiled backend, owner client, independent verifier,
public model and their expected hashes. Every invocation creates a fresh job,
cohort, TLS material and preprocessing context. Its five isolated roles receive
only their own TLS private key and public certificates; the CA private key stays
with the launcher. Raw worker captures and private keys remain local and are
never read or hashed by the controller. Fixed public sidecars report phases,
completed results and specific assignment/MAC refusals.

The positive gate requires all three identical complete proofs, independent
verification at `128`, and rejection at `129`. Separate failure-only controls
exercise an invalid extended assignment and a corrupted MAC. Network failures,
resource exhaustion or generic nonzero exits do not receive rejection credit.
The stock per-type group MAC coordinators are set up for the proof scope and
torn down after all local checkers. The qualified runner executes one proof per
isolated role; nested or concurrent calls in one process are outside this gate.

The public model tool also accepts pinned `KPI_PUBLIC_R1CS_V1` matrices:
`export-matrices MATRICES EXPECTED_MATRIX_SHA256 TRACE_SOURCE_SHA256 NEW_DIRECTORY`.
It re-synthesizes every exact matrix row and variable count before generating
fresh Groth16 parameters. Its source identity binds the trace source label,
matrix file and exporter source/Cargo closure. The caller must authenticate
those expected identities. It accepts no witness or owner input. The independent
`verify` command accepts a comma-separated public input vector and enforces the
selected VK's exact arity.

## Boundaries

This fixture has fixed, public owner slots and a clear public instance prefix.
It does not implement hidden NF routing, a native payment relation, private
multi-owner consent, original-seed recovery, exits or fee savings. A real
financial entry requires private witness construction, a secret derived public
prefix, and the authenticated durable release barrier required by
[RFC-0030](../../../docs/rfc/0030-private-batch-construction.md).
The current protocol model is not a substitute for that implementation.

One colluding server can disclose its internal B1 transcript. Passing the
functional proof gate does not qualify augmented-transcript privacy,
abort/retry privacy, cryptographic correctness or production safety.
