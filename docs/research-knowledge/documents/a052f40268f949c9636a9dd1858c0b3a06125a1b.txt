# Encoding reference 02: original limbs and ordinary bit constraints

2026-10-26. Prospective addendum frozen before the new encoder implementation.
ADR0072 records the implementation decision. RUN-SPEC-01 SHA
`a6dcecfcc3a98f6a70936ed6b46b0f52411dbc0c11b4af2aaea266f460c6b8ba`
and exact Ark contract `b98f0164d4fc3c6f81e67ee76f27af221846086f4ef345c6365e007e4764dcae`
remain the semantic reference. All forty expected outcomes are unchanged.

## Retained failure and scope

Attempt01 stopped before compilation because Go's optional VCS stamp could not
be obtained. Its execution SHA is
`e6e68936935121cce953ce6c1582fcbf6e3d60758e32c7c5c924eb27201c52ec`.

Attempt02 used `-buildvcs=false`, built the static binary and ran it in the
closed namespace. G1 compiled to5148 R1CS constraints,208817 serialized bytes,
SHA `4da8a6ebe30a53d41936ed41ad1dcc60e73a997de00d277807ad77e404d3842b`.
The FIRST positive assignment then returned the unmodified library error:
`placeholder function: to be replaced by commitment computation`.
No negative ran and no encoder acceptance/rejection was established.

Retain attempt02 execution SHA
`c7940c6193a9a472fad29612491011645fe349417b0d8c10f8f34ccd249cef23`
and original result1013 bytes, SHA
`3b6ec6afd6d3f891072d19ac5f794384b564aaf6f66ac88fccdec786c7a463dd`.
Do not relabel that hint failure as an unsatisfied relation or retry/modify it.

The selected placeholder source is `frontend/cs/commitment.go` at gnark0be5c2,
SHA `892907423e1557255deae0e38f68cd65feb5a0a840b9f4d37b8efb43152e8b95`.
Its random/debug branch is not approved. No arbitrary challenge, omitted
deferred check, host verification bit or interpreter replaces compiled checking.

## New tiny implementation

Use new packages `adapter/codecbit` and `adapter/cmd/codecbit`. Preserve original
`codec/codec.go`82c134…, corrected `cmd/codec/main.go`121d770…, their source
history, all prior results and fixed dependencies. Do not import this repair
into the unqualified full Output wrapper silently.

Represent each original Fq witness as an explicit array of four field-valued
limbs. Constrain each ORIGINAL limb to64 Boolean bits and its exact recomposition.
Concatenate the bits little-endian to256 bits. Constrain the resulting integer
to be at most the established BN254 Fq modulus minus1 with the selected gnark
binary comparator. Never reduce it modulo Fq or pack it into one native Fr.

Use the exact same Ark compression predicate: A32 | B.c0LE32 | B.c1LE32 | C32,
sign y>(q−1)/2; Fq2 c1-first and c0 only when c1=0; flags only at31/95/127;
bit6 zero for nonidentity; c0 carries no flag. Constrain every public byte to8
bits and exact equality with its recomposed byte. Nonidentity means the full
coordinate tuple is nonzero, not that every X is nonzero.

Reuse established `std/math/bits` and `std/math/cmp` primitives. No
`emulated.NewField`, modular arithmetic, committed lookup or commitment hint is
part of this reference. Compiled-system metadata must show zero commitments;
otherwise stop before solving and retain an unexpected result.

The harness reuses the SAME40 control definitions and expected verdicts from
corrected main121d770…. Necessary representation changes are limited to the
explicit four-limb type, the new encoder import, modulus access and this new
spec identity. Do not normalize adversarial raw limbs/public bytes before
`frontend.NewWitness`. Preserve direct B.c1 byte32 mutation as well as A, c0,
flags, oversized limb, q/q+1, byte256/−1, sign and nonidentity controls.

Compile two actual G1/G2 ENCODING-ONLY R1CS shapes and use their actual solver.
Retain exact compiled-system hash/size and negative constraint IDs. Only actual
unsatisfied-constraint errors meet a required UNSATISFIED outcome; hints,
parsers, panics, bad witness shape or process failures remain distinct failures.
Stop at the first unexpected outcome. No verdict retuning or automatic retry.

## Execution boundary

Freeze new source for independent and Root review before compile. Reuse the
verified exact Go1.26.8/module sums, offline CGO0/readonly build, explicit
`./cmd/codecbit`, owned cache/output and optional worker limits. Run only the
static binary in the same closed bwrap namespace, with cleared environment,
its own PID/proc/dev, no network and no host/private/home/repository mounts.
Use fresh run/scope/binary identities. These optional limits never apply to the
actual financial trial.

A pass establishes ONLY the tested canonical encoding predicate. It supplies
no on-curve/subgroup/Groth16 verification, no actual financial acceptance and no
privacy. The genuine existing Output fixture remains separately verified by
the original native CLI. Full emulated Groth16 solving, its supported commitment
hook and outer Bsb22 proof/VK/wire compatibility remain unqualified. No new
setup, proof, key, runtime profile, campaign material or Original is authorized.
