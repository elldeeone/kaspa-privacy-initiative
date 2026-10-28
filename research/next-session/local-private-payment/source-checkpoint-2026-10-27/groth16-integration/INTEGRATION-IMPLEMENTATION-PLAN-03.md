# Implement one complete MASCOT Groth16 proof path

2026-10-27. **Source implementation plan, not an implemented backend.** No build,
setup, proof, external-client connection, private witness, Original or financial
job was run for this plan. The existing Fr scalar gate remains its own completed
bounded result. Nothing in the current 489-file publication was edited.

**Next useful implementation:** one small C++ MASCOT prover, with strict external
owner inputs, authenticated BN_SNARK1 group operations and the selected
LibSnark Groth16 formula. Finish it with one real two-owner full-proof gate,
rather than another isolated scalar test.

## Readable contract and exact files to implement

1. `OWNER-PRIVATE-INPUT-CONTRACT-02.md` specifies the mandatory client boundary.
   Implement `owner_inputs_active.hpp/.cpp`: all-three authenticated TLS,
   strict active DDNNT triple masking, pinned Fr/job/shape, fresh masks and
   retained server MACs. No real witness may enter a prover's ordinary input
   file or a clear combined-witness dealer. Upstream socket/client machinery
   exists; this strict direct-prover integration does not.
2. `bn254_values.hpp/.cpp` adapts established mcl **BN_SNARK1** G1/G2 to the
   existing MP-SPDZ authenticated group pattern. Use the exact Fr/Fq and
   explicit subgroup/canonical-codec checks. Include role-specific identity
   handling: private shares, query vectors and the one H-padding identity can
   legitimately be zero; final proof/VK roles retain their actual admission
   policy. Do not copy the ECDSA application's diagnostic key openings.
3. `public_model_export.rs` and `verify_public_proof.rs` use the existing
   Arkworks0.6 matrix/setup/verification source boundary. The public model must
   carry every actual R1CS row, counts, variable order, public prefix, key/query
   identity, exact reduction/domain/root/coset plan and fixed source pins.
   Refuse unsupported extra GR1CS predicates rather than dropping them. The
   exporter handles public research parameters; it is never a witness dealer.
4. `auth_field.hpp` and `auth_fft.hpp/.cpp` retain stock authenticated Fr shares,
   public constants tagged with each server's **private MAC-key share**, stock
   checked Beaver multiplication and fresh authenticated random proof masks.
   Apply pure linear transforms to both value and MAC lanes. The preferred
   C++ route supplies explicit Ark-derived domain roots to an adapter over
   established mcl butterflies. Unmodified mcl NTT assumes BLS12-381's root/
   two-adicity32; BN254 Fr has two-adicity28. A pure Rust linear FFT bridge on
   both lanes is the alternative if it produces a smaller reviewed surface;
   choose one implementation, do not maintain two unqualified paths.
5. `auth_groth16.hpp/.cpp` ports the selected LibSnark witness map and complete
   proof formula using the method contract. Every network/preprocessing/check
   call uses one ordered MASCOT context; only pure local math may run in
   parallel. Keep authentication through A/B/C/H, all witness values, r,s and
   every point accumulator. No half-share conversion or REP3 fallback.
6. `proof_codec.hpp/.cpp` bridges the completed public affine A/B2/C to the
   exact Native128 encoding and independent Ark verifier. Do not assume mcl,
   ETH or libff stream encodings equal Ark's byte order/sign rules. The small
   `fullproof_gate_main.cpp` joins all preceding modules and releases only a
   complete, checked proof/result, with private diagnostics retained locally.

The adjacent pinned `DRIVER-INTEGRATION-CONTRACT-01.md`, `METHOD-CONTRACT-02.json`
and `API-CONTRACT-02.hpp` give the method-by-method signatures, source locations
and type obligations. The mandatory `SERVER-TRANSCRIPT-BOUNDARY-02.md` qualifies
the early masked B1 opening and owner-approval limitation. Also read
`PRIVATE-INSTANCE-AND-WITNESS-BOUNDARY-01.md`: ordinary clear public instances
and owner-to-register routing need explicit timing/privacy treatment, and a
generic shared NativeAuth witness generator is not supplied by this backend.
These declarations and filenames are work instructions; no linkable
implementation is supplied.

## Why this is a port, not a driver-name change

co-snarks `436f63fa17f2f10ece38c6650df68da99fbc0307` provides the formula and
reductions, but generic `prove_inner` is private and public proving entries
select semi-honest REP3/Shamir. Its networking-free `local_mul_vec` returns
half shares; public-constant operations take partyID without the MAC key;
LibSnark currently schedules a local product inside Rayon. A real Rust adapter
would need a new authenticated trait/public entry, alpha context, ordered
network/results throughout reduction and proving, and safe preprocessing
lifetime/fork rules. Merely giving existing methods a MASCOT name is wrong.

The proposed C++ path keeps MP-SPDZ protocol state, MAC keys, external sockets
and checked point openings together. It reuses established arithmetic and a
small selected prover formula. It still requires a new compiled prover and
complete build/source qualification. The old stock `mascot-party.x` proved Fr
scalar compatibility; it is not already this Groth16 executable.

## Freeze this one complete functional gate before running it

Use public synthetic fixtures but the **real external private-input route**:

```text
two external clients: x=3 and y=5
three MASCOT computing servers
MPC auxiliary: z=x*y=15
public t=128
constraints: x*y=z ; (z+1)*(x+y)=t
global assignment: [ONE,t,x,y,z]
```

There are2 constraints,2 instance variables,3 private variables and domain N=4.
This exercises a nonzero H polynomial, cross-client auxiliary generation,
authenticated QAP/FFT products, r/s sampling, both groups' MSMs and checked
openings. The public verifier receives `[128]`, excluding ONE.

Require exact original H-query length N-1 and H-map length N. Append exactly
one **public group identity** to that query, then require equal-length
authenticated MSM. This makes the selected reference's intentional shorter-
slice algebra explicit; it does not assume/open a secret zero tail or allow
general truncation. Every other query/scalar dimension must match exactly.

Acceptance requires all3 providers to emit the same complete canonical proof,
all protocol/group MAC checks to succeed, and independent Ark verification
against the frozen VK and `[128]`. Wrong public t=129 must reject that completed
proof. Pre-input wrong field/curve/source/job/arity and malformed-point controls
must refuse; no unsafe import or disabled check can rescue the run. The model,
key, dimensions, domain and fixture become frozen public research artifacts
before future execution. No parameters or proof were created by this plan.

The first valid full proof is evidence about this combined toy implementation,
not a proof of cryptographic correctness or active privacy. Existing field,
group and transport source assumptions remain visible. No estimate of the
custom build's RAM/disk or full NativeAuthSpend proving cost has been measured.
Schedule build/execution after the current publication/recovery workload has
capacity; do not add a compile cache while decoded/audit data needs the space.

## Privacy and financial boundaries that survive a functional proof

- External input masking hides values under its stated model, but client IDs,
  witness offsets and public NF ordering can still reveal ownership. Carry
  the existing private permutation/canonicalization through the entire batch;
  fixed synthetic gate slots are not an anonymity result.
- The selected formula opens masked A and auxiliary B1 to computing servers.
  Check these group MACs before using them with secret r/s, and do not export
  auxiliary B1 to the public coordinator. A colluding server can nevertheless
  disclose its transcript. Whether that augmented prover transcript meets the
  required active privacy definition remains a qualification question, not an
  assumed leak or a guarantee supplied by final-verifier success.
- Current NativeAuth source is authority separation only. Its owner reconstructs
  the full4077-byte packet and200-byte statement, including3756 effects bytes.
  Multi-owner consent while concealing the other NFs until finalization is
  unimplemented. Keep complete-effects binding and owner validation; an opaque
  server hash is not a substitute. Any new private approval mechanism needs an
  ADR and independent qualification before integration.
- Preserve every native financial invariant, actual root/head checks, owner
  authorization and every-path independent Exit. The toy has no KAS, real note,
  delivered output, native transaction, withdrawal, recovery or fee claim.
  Stronger arithmetic does not erase amount/timing or abort/retry linkage.

Selecting and integrating this new trust boundary requires the project's
RFC/ADR/threat-model documentation before substantial cryptographic integration.
This source plan supplies concrete implementation contracts without changing the
accepted architecture or silently revising an invariant.
