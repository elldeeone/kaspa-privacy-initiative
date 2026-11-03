# ADR-0087: no-raw-B1 collaborative Groth16 completion

**Status:** Accepted for the isolated unfunded MASCOT research paths.
Registered financial execution, capture production, and launch remain
`CONFIGURED0`.

**Date:** 2026-10-29

**Related RFC:** [RFC-0030](../rfc/0030-private-batch-construction.md)

## Context

The earlier collaborative Groth16 path opened an auxiliary G1 point `B1` to
the computing parties before constructing `C`. `B1` is not one of Groth16's
three public proof elements. A corrupt P1 therefore received witness-dependent
group data that Groth16's ordinary zero-knowledge statement does not classify
as public output. Treating it as harmless masked traffic had no source-grounded
simulation argument.

The proving path must construct the standard proof without revealing that
auxiliary point. Ozdemir--Boneh Appendix E gives an unrolled Groth16/SPDZ
construction with exactly two secret scalar/curve products and only three
final curve-point openings. Smart--Talibi Alaoui gives the corresponding
actively secure scalar/group multiplication from ordinary SPDZ field triples.

## Constraints

- Preserve the standard Groth16 proof `(A,B2,C)` and independent Arkworks
  verification. No new proof system or cryptographic primitive is selected.
- Do not open an auxiliary raw `B1` or expose a generic secret-group opening
  API.
- Use a fresh independent authenticated field triple for each secret
  scalar/group product. Never replay or share a triple between products or
  attempts.
- Check scalar and group MAC state before an opening is returned or used as a
  successful result. A corrupt party still observes protocol messages before a
  later check; abort and partial transcripts remain in scope.
- Poison the MASCOT context on any scalar/group/opening failure. A retry needs a
  fresh attempt and preprocessing context.
- Capture masked differences separately from the final public proof. Timing,
  size, order, abort phase, retries, and host/network effects remain modeled.
- This decision must not alter value conservation, nullifiers, exits, reserve
  release, native transaction authorization, or any administrator authority.

## Options considered

### Keep the raw auxiliary `B1` opening

Rejected. It is not a public Groth16 proof element and creates an unnecessary,
witness-dependent corrupt-server observation outside the inspected proof chain.

### Put the whole prover inside a generic scalar circuit

Rejected for this research path. It duplicates established collaborative
Groth16 machinery, substantially increases the circuit and implementation
surface, and is unnecessary to remove `B1`.

### Use Appendix E plus established scalar/group Beaver multiplication

Selected. It produces the standard proof with two established mixed products,
two masked Fr openings, two masked G1 openings, and only `A,B2,C` as unmasked
group outputs.

## Decision

Use the Appendix-E decomposition

```text
A       = alpha1 + sum_i assignment_i*A_i + r*delta1
B2      = beta2  + sum_i assignment_i*B2_i + s*delta2
B1_base = beta1  + sum_i assignment_i*B1_i
C       = s*A + r*B1_base + L + H
```

`B1_base` deliberately omits `s*delta1`. This is algebraically the usual
Groth16 expression: `s*A` already supplies the one `r*s*delta1` term, so adding
`r*(B1_base+s*delta1)` and subtracting `r*s*delta1` reduces to
`r*B1_base`. Appendix E.1 identifies exactly the two secret scalar/curve
products `s*A` and `r*B1_base`, then opens only the three proof points.

Compute each product `x*Q` with a distinct fresh authenticated MASCOT field
triple `(a,b,c=a*b)`. The implementation maps it to

```text
group mask   U = a*G
scalar mask  b
product mask V = c*G
```

and opens only

```text
D = Q - U
e = x - b.
```

It derives the authenticated result locally:

```text
V + e*U + b*D + e*D = x*Q.
```

This is Smart--Talibi Alaoui Figure 9 `Multiply-G-S` with the paper's field
triple labels `a` and `b` exchanged. The exchange is valid because a fresh
SPDZ triple has independent uniform first and second components and
`c=a*b`.

The implementation admits exactly two products in one typed function. A
translation-unit-private helper opens the two masked scalar differences; a
second private helper opens the two masked G1 differences. The scalar path runs
pending checks before and after `POpen`; the group path runs its `Direct_MC`
check before returning. Network shares and masked values are necessarily sent
before those checks can finish, as in the source protocol. Typed capture is
emitted for the masked differences only after the relevant check succeeds.

After forming `C`, the only unmasked group-opening API accepts exactly
`A,B2,C`. It opens G1 `A,C` and G2 `B2`, completes both group MAC checks and
the pending scalar check, validates the points, and only then returns the
proof. The exact canonical proof bytes are agreed by all servers and must pass
independent verification before publication.

Capture schema v9 distinguishes:

- exactly two 32-byte masked Fr differences;
- exactly two 65-byte masked G1 differences;
- final G1 `A,C` and final G2 `B2`;
- the authenticated scalar share/MAC lanes for both consumed triples;
- direct P1-local authenticated G1 share-then-MAC state in canonical
  `BASE[A,B1_base,L,H]`, `MIXED[U0,V0,D0,U1,V1,D1]`,
  `PRODUCTS[sA,rB1_base]`, and `FINAL[A,C]` stages; and
- direct P1-local authenticated G2 share-then-MAC state at
  `BASE[B2]` and `FINAL[B2]`.

The grammar enforces exact stage order, object counts, widths, and full repeated
`A`/`B2` byte equality. `BASE` is a canonical algebraic serialization order,
not a claim that every prover constructs `L` before `H`.

There is no raw-`B1` semantic or generic masked-opening alias. A new opening or
wrong arity fails capture completion rather than being reclassified silently.

## Security analysis

Smart--Talibi Alaoui Theorem 2 proves its online elliptic-curve functionality
with abort in the SPDZ-offline hybrid for a prime-order group. The theorem's
simulator covers the uniformly masked field/group differences and corrupt-party
state. Applying it here is conditional on:

- correct fresh MASCOT triples and at least one honest computing party;
- exact correspondence of BN254 Fr and prime-order G1 to the paper's field and
  group, including canonical point/subgroup admission;
- correct authenticated G1/G2 share and MAC representation under the same
  secret MAC-key sharing;
- complete scalar, group, broadcast, sacrifice, and OT checks;
- authenticated channels, secure randomness, one-use preprocessing, and
  poison/fresh-retry handling; and
- correct composition of the pinned SimplestOT, SoftSpoken, MASCOT, and custom
  group code.

The last item is not established by the inspected primary sources: the revised
SimplestOT paper withdrew its original UC claim. The local source is also not a
cryptographic proof or audit. Therefore the architecture is source-grounded
but remains a conditional, not admitted, privacy assumption.

Failure safely halts proof construction. This change creates no minting,
double-spend, withdrawal, reserve-release, stale-state, or privileged-exit
path. It changes only how the already-authenticated proof is completed.

## Privacy analysis

This decision removes the concrete raw auxiliary `B1` disclosure. The corrupt
P1 still sees:

- its local scalar and group shares, MAC shares, and MAC-key share;
- two masked Fr differences and two masked G1 differences;
- MASCOT/OT/MAC-check and broadcast traffic;
- final public `A,B2,C` and the released projection; and
- success/abort plus exact implementation metadata.

Under the cited scalar/group theorem and all composition assumptions, the
recognized **joint cryptographic value view** is conditionally simulatable. No
captured field is independently harmless. The exact C++ implementation,
undecoded peer traffic, nonliteral implications of openings, timing, byte and
message counts, ordering, peers/forks, retry/failure phase, TLS packetization,
host memory, logs, cache/page behavior, and later compromise remain unqualified
or empirical.

Schema v9 directly records the named P1-local `AuthG1/AuthG2` share/MAC objects
at every application stage above. Literal scans, grammar, counts, stage order,
and repeated-value equality are direct measurements. The artifact does not by
itself establish `D=Q-U`, Beaver/product equations, `C=products+L+H`, or the
query/MSM source correspondence. Worker partials, expression/checker
temporaries, allocator copies, internal OT/PRNG state, and physical-host state
remain uncaptured or unqualified; this is named application-state closure, not
a complete corrupt-host image.

No source control or valid proof establishes sender anonymity, payment privacy,
native KAS privacy, Testnet readiness, production security, or absence of side
channels. The selected registered relation and actual capture producer remain
unavailable; `CONFIGURED0` is unchanged.

## Evidence

- Ozdemir and Boneh,
  [*Experimenting with Collaborative zk-SNARKs: Zero-Knowledge Proofs for
  Distributed Secrets*, Appendix E and E.1](https://eprint.iacr.org/2021/1530).
  The unrolled prover has exactly two secret scalar/curve products and opens
  three final curve points.
- Smart and Talibi Alaoui,
  [*Distributing any Elliptic Curve Based Protocol*, Figure 9 and Theorem
  2](https://eprint.iacr.org/2019/768). The protocol locally maps a field triple
  to a scalar/group triple and proves the online group functionality in the
  SPDZ-offline hybrid.
- Groth,
  [*On the Size of Pairing-based Non-interactive Arguments*](https://doi.org/10.1007/978-3-662-49896-5_11).
- [P1 MASCOT-view source review](../../research/mascot-p1-view-leakage-assumptions-2026-10-29.md).
- Local source:
  [`auth_groth16.cpp`](../../poc/local-private-payment/mpc-prover/auth_groth16.cpp),
  [`auth_groups.cpp`](../../poc/local-private-payment/mpc-prover/auth_groups.cpp),
  and
  [`financial_prover.cpp`](../../poc/local-private-payment/mpc-prover/financial/financial_prover.cpp).
- Focused private-completion, v9 capture, and model controls cover the exact
  staged group grammar, repeated `A/B2` equality, genuine prover callsites,
  and the private final-opening capability. This is implementation evidence
  only; the final selectable evidence is an exact build/producer/model receipt,
  not a source-test count.

## Objections / unresolved questions

- `open_final_groth16()` remains a semantically named public wrapper accepting
  authenticated G1/G2/G1 values, but that overload refuses whenever capture is
  attached. Only `FinancialValidatedAssignment` can mint the additional
  one-shot `FinalGroth16CaptureAuthority`; it is bound to the context,
  generation and failure epoch, consumed by the checked `GroupMacSetup`
  overload, and poisons if abandoned. A second private permit binds the exact
  final authenticated state around the checked open before emitting the lane.
  Static controls whitelist the two definitions and exactly three genuine
  prover callers, and require that only the selected durable financial caller
  mints/moves the authority. Keep those controls exact; any added caller or
  authority mint is a schema change and blocks admission.
- The exact scalar/group source correspondence needs an independent
  implementation review or formal reduction before it can become a frozen
  `source_assumption_covered` lane.
- Real malicious controls should corrupt each `a,b,c` share, both masked
  scalar/group differences, generator/triple relations, and replay/one-shot
  state; every case must poison without returning a proof.
- A static negative control must continue to show that raw `B1` never reaches
  any `POpen`, typed capture, proof encoding, or coordinator result.
- An integrated frozen producer/model run must prove exact lane counts and
  ordering. Schema-v9 focused source controls are green, but no configured full
  registered execution or actual receipt exists.
- The full registered financial shape and independent verification have not run
  through a configured selected driver.

## Revisit if

- an independently reviewed upstream collaborative Groth16 implementation
  provides a smaller or stronger exact interface;
- a proof closes the pinned base-OT/SoftSpoken/MASCOT composition gap; or
- adversarial or full-shape execution falsifies triple freshness, MAC
  sequencing, capture completeness, or independent proof verification.
