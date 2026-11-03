# Completed encoding experiment and corrected backend assessment

2026-10-26. This addendum records completed public synthetic evidence and
supersedes two narrow earlier source assessments. It changes no financial
codec, key, trial, privacy claim or native verifier.

The completed experiment checks **canonical field-coordinate encoding**, one
necessary part of a future recursive verifier. It does not verify a complete
Groth16 proof or hide a payment's witness from its prover.

## What actually ran

The separate bits-only G1/G2 encoder passed all **42 frozen controls**:
13 accepted assignments and 29 actual typed R1CS constraint rejections.
[CODEC-04-AUDIT](native-g16-adapter-01/CODEC-04-AUDIT.json), SHA256
`3ecdac6179ae2e5e3f87d8e40ed0d53f3c7f447486800716d692bc8fec270dd8`,
records the exact sources, execution, raw results and limits.

Both compiled systems have zero commitments. G1 has 1,637 constraints and G2
has 3,287. The original forty outcomes and both serialized system identities
remained unchanged when two prospective canonical-bound controls were added.
Those new assignments use x=q and x=q+1 with matching public bytes and raw
private limbs. Both fail constraint516, the x<=q-1 assertion. The earlier
q/q+1 aliases failed first at byte equality; their narrower evidence remains
in [CODEC-03-AUDIT](native-g16-adapter-01/CODEC-03-AUDIT.json).

The first experiment's failures are retained separately. Run01 stopped at Go
VCS stamping before a binary was built. Run02 added `-buildvcs=false`, built,
and stopped on its first expected-positive solve because the selected
emulated-field path required an unimplemented commitment hook. It produced
no passing encoding verdict. The successful bits-only encoder is a separate
implementation, with its own prospective specifications and ADR0072.
No arbitrary challenge, debug/random hint or omitted check was used to make
that first experiment pass.

These controls do **not** establish the composed128-byte proof relation,
curve/subgroup membership, Groth16 verification, statement SHA binding,
outer-proof interoperability, native2/4 acceptance, lower fees, malicious MPC
or financial privacy. No setup or proof was generated. The separately authored
full Output wrapper remains unfinished and is excluded from the completed
source proposal.

## Corrections to the source assessment

The frozen [initial backend note](NATIVE-G16-AGGREGATE-BACKEND-FEASIBILITY-01.md)
and [initial gnark note](GNARK-NATIVE-G16-AGGREGATE-SOURCE-01.md) remain unchanged
as historical records. Use the following findings in place of their incomplete
candidate descriptions:

1. **The Circom candidate does contain BN254.** The previously inspected
   `yi-sun/circom-pairing` commit
   `107c316223a08ac577522c54edd81f0fc4c03130` contains
   `circuits/bn254/groth16.circom`. A README-only assessment missed it.
   [Corrected candidate assessment](STANDARD-BN254-R1CS-CANDIDATES-SOURCE-01.md),
   SHA256 `44f3c034d26842eabac23ad7835ef6fa00f037e4d80b55a5e417abacfe119fdb`,
   documents the actual template and its gaps. It needs fixed authenticated
   key/GT constants, enforced `out===1`, exact Ark byte and SHA binding, and
   resolution of exceptional arithmetic and the lost IC-MSM infinity flag.
   Its existence is a research lead, not a qualified or audited adapter.
2. **Gnark's outer commitments cannot be dropped.** Inner Ark BN254 proof
   mathematics can be compatible while an outer proof has a different
   verification protocol. At the selected gnark commit an outer proof with
   commitments also requires commitment/PoK fields, derived inputs and key
   metadata. [Outer compatibility assessment](GNARK-OUTER-COMMITMENT-COMPATIBILITY-01.md),
   SHA256 `6db9301f0214d8bb8c2168fe9e8275adce3d7bceaeab5cccc9e7bc61357c4918`,
   records those source obligations. A128-byte A/B/C projection would discard
   required checks. No complete outer circuit or compatible native profile
   was qualified.

The next useful cryptographic gate is one complete fixed-Output relation:
settle exceptional arithmetic, bind the selected key and canonical proof bytes,
compute the exact statement inputs, then check genuine and inconsistent
assignments in actual R1CS. That gate remains prospective. A complete
two-Spend/four-Output relation and distributed proving follow separately.

## Publication boundary

The additive proposal covers small public experiment sources, dependency pins,
specifications, reviews and retained execution/result records only. It does
not modify candidate13 or authorize staging, upload, final canary audits or
release. Binaries, build caches, parameters, R1CS/SYM/witness files, SDK bodies,
unfinished full-verifier source, actual wallet metadata and private recipes
are excluded. Terminal financial results and final recovery publication are
separate work and are not claimed here.
