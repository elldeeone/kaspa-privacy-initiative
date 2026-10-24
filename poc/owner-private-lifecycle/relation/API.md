# Integrated owner-private Spend, Output and Exit relations

ADR0064 research and TN10 only. These are new-domain relations, fresh keys and
separately selected artifacts. The ADR0063 unfunded prototype and previous funded
profiles, keys and backups are not modified or selected by this package.

The crate/binary is `kpi-owner-private-lifecycle-relation`, imported in Rust as
`kpi_owner_private_lifecycle_relation`. Host proving uses default `prover`;
public-only verifiers use `default-features = false`.

## Identity and public wire

Domain SHA256, ASCII without newline:
`KPX8 owner-private native KAS lifecycle v1 / TN10 RESEARCH ONLY`.

Domain hex: `be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480`.

Every statement is SHA256-hashed **inside** its circuit. Two exact 128-bit
little-endian digest limbs are the public BN254 Fr inputs; no 256-bit field
reduction is used. Each role has a separately selected 328-byte canonical VK;
proofs are 128-byte canonical compressed Groth16.

| Role | Complete public statement |
| --- | --- |
| Spend200 | `KPX8SP01 | D32 | CMroot32 | NF32 | CVin64 | effects32` |
| Output168 | `KPX8OU01 | D32 | CM32 | CVout64 | CFhash32` |
| Exit152 | `KPX8EX01 | D32 | CMroot32 | NF32 | effects32 | payoutLE8 | feeLE8` |

Spend and Output preserve the independently proved hidden membership and value
commitment responsibilities of ADR0063. Complete mixed output tuples remain
520 bytes: `CM32|CV64|CF264|CFhash32|OutputProof128`. No creator's output subset,
individual blinding adjustment, native public key or signature is exposed.

## Direct full-note exit

`ExitStatement {domain, anchor, nf, effects_digest, payout, fee}` and
`ExitWitness {note, owner_secret, nullifier_secret, position, path}` prove:

1. The privately opened Note168 is owned by the supplied private authority and
   nullifier secret, and is a member of the supplied CM root through 16 siblings.
2. Its position is in `[0,65535]`; its original positioned HMAC-SHA256 NF is
   nonzero and equals the public NF. NF excludes attempt, effects and role, so a
   competing Spend and Exit for one note have the same NF.
3. `60,000,000 <= note.value <= 2,870,000,000,000,000,000` sompi,
   `10,000,000 <= payout <= MAX`, `1 <= fee <= MAX`, and exactly
   `note.value = payout + fee`. All are bounded unsigned 64-bit integers and the
   sum is below 2^65, so the equation cannot hide field wrap or integer overflow.
4. All complete statement bytes, including exact native financial effects, are
   bound by the two public digest limbs.

The owner may authorize a chosen payout destination through the effects digest.
The native policy reconstructs those effects from the actual transaction. It
must separately authenticate the current full prior/successor state and reserve
point, unchanged CM state, exact indexed-NF insertion, actual payout SPK, fee and
remaining reserve. A circuit proof alone is not current-state, reserve-backing,
native-acceptance or confirmation evidence.

No CV blinding, MPC engine or shared RISC Zero prover is required for Exit.
Independent public proving-key/data/software availability remains required.

## Private requests and selected parameters

`prove-spend`, `prove-output` and `prove-exit` take externally selected
`--pk`, `--pk-sha256`, `--manifest`, `--manifest-sha256` and a public
`--statement` hex value. The complete selected parameters, source identity and
executable identity are checked before private stdin is opened.

Private JSON must be an object with exact fields, no duplicates or extras and
strict lower-case fixed-width hex. Errors discard underlying private details.
Witness types do not implement Debug or Serialize.

* Spend schema `kpx8-owner-private-spend-witness/v1` has `note_hex168`, `s_hex32`,
  `k_hex32`, `position` u32, `cm_path_hex` exactly 16 siblings, `blind_hex32`.
* Output schema `kpx8-owner-private-output-witness/v1` has `note_hex168` and
  `blind_hex32`.
* Exit schema `kpx8-owner-private-exit-witness/v1` has `note_hex168`, `s_hex32`,
  `k_hex32`, `position` u32 and `cm_path_hex` exactly 16 siblings. A blinding field
  is rejected.

All requests additionally contain their exact `schema` field. Public result
schema is `kpx8-owner-private-component-proof/v1`; public setup manifest schema
is `kpx8-owner-private-parameters/v1`. Setup uses fresh private OS RNG entropy,
never the public Pedersen seed. The old stock Pedersen generator derivation is
retained, while its parameter fingerprint prefix is `KPX8CV01` for this profile.

Run `public-info`, `shape spend|output|exit`, `setup ROLE FRESH_DIRECTORY`,
`verify-spend|verify-output|verify-exit` and `prove-spend|prove-output|prove-exit`
through the documented strict CLI. Setup directories and complete keys must be
externally selected before genuine owner integration. Passing these controls is
not proof of cryptographic correctness, composed privacy or production safety.
