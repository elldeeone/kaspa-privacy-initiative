# Exact Output + aggregate CRS path: source review

- Date: 2026-10-29
- Status: design audit only; **no ceremony or setup was run**
- Scope: shortest established route from the feasibility-only historical
  BN254/Groth16 keys to a trust-minimized CRS for the exact Output and aggregate
  relations

## Answer

Keep BN254/Groth16 and use one independently verified Powers-of-Tau Phase-1
transcript to root **two separate circuit-specific Phase-2 ceremonies**, one
for Output and one for aggregate. This is the only reviewed option that keeps
the current proof system, current Kaspa verifier tag, 128-byte proof ABI, and
the exact relations.

Do not run either ceremony yet. The Arkworks-to-ceremony R1CS export and the
ceremony-to-Arkworks key/query conversion do not exist, the relation crate is
still changing, the source-owned pre-key trial root and post-setup measured-key
join are not implemented, and all 60 selected-parent artifacts remain missing.

This recommendation distributes setup trust; it does not eliminate it. It
requires at least one honest contributor in Phase 1 and at least one honest
contributor in **each** circuit's Phase 2. Public transcripts can verify the
algebraic update chain. They cannot prove that an honest contributor existed,
that its machine was uncompromised, or that it erased its secret.

## Verified current facts

### Exact local closure

| Relation | Frozen identity | Current size | Historical VK |
|---|---|---:|---|
| Output | source `ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e`; matrix `d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31` | 217,807 constraints; 215,001 variables | `8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119` |
| aggregate | source `04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7`; matrix `c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab` | 13,093,029 constraints; 12,949,821 variables | `2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102` |

The current FullW1 feasibility module hardcodes those two historical VK hashes.
ADR-0095 correctly classifies them as feasibility-only. A new CRS cannot be
used merely by producing new files; FullW1 and the capture lifecycle must
consume a typed, same-trial measured-key authority after setup.

### Kaspa verifier and key format

At Rusty Kaspa commit
[`4edcbbccb449f84832afb1ca157904b35f37d006`](https://github.com/kaspanet/rusty-kaspa/tree/4edcbbccb449f84832afb1ca157904b35f37d006),
the tag dispatcher exposes only Groth16 `0x20` and RISC Zero Succinct `0x21`.
The Groth16 verifier uses Arkworks 0.6.0 over BN254 and accepts Arkworks
canonical **compressed** values. It:

- deserializes `alpha_g1`, `beta_g2`, `gamma_g2`, `delta_g2`, then the
  `gamma_abc_g1` vector in Arkworks order;
- checks public-input arity, validates curve/subgroup membership, and rejects
  trailing key or proof bytes; and
- deserializes the standard `(A in G1, B in G2, C in G1)` proof.

For the present two-public-input relations this is a 328-byte VK and a
128-byte proof. The current closure expects 85,578,096-byte Output and
2,608,842,576-byte aggregate Arkworks proving keys. Fresh Groth16 ceremony
keys therefore need no new consensus tag or verifier algorithm, but every key
hash, owner/script binding, proving query store, and post-setup lifecycle
binding changes.

KIP-16's prose calls the VK “uncompressed,” but the pinned implementation is
the source of truth and explicitly requests `Compress::Yes`.

### Established Groth16 ceremony construction

Groth16 is a preprocessing SNARK with a circuit-specific CRS
([Groth 2016](https://eprint.iacr.org/2016/260)). Bowe, Gabizon, and Miers give
a scalable two-round MPC for an extended Groth CRS in the random-beacon model
and retain knowledge soundness in the generic-group model
([ePrint 2017/1050](https://eprint.iacr.org/2017/1050)). The practical split is:

1. a reusable, size-bounded Powers-of-Tau Phase 1; and
2. a circuit-specific Phase 2 that must be repeated for every distinct circuit.

The pinned [`snarkjs` v0.7.6](https://github.com/iden3/snarkjs/tree/9a8f1c0083d18b9b5e18f526cfd729e7259423be)
implements both phases, transcript verification, circuit-to-`zkey` binding,
Bellman-format contributions, and final beacons. Its guide explicitly says the
zero-contribution Groth16 `zkey` is unsafe and requires at least one Phase-2
contribution.

Power 24 has capacity 16,777,216 and covers the 13,093,029-constraint
aggregate relation; it can also root the smaller Output ceremony. The guide
publishes a candidate prepared BN254 power-24 artifact with BLAKE2b digest
`fa404d140d5819d39984833ca5ec3632cd4995f81e82db402371a4de7c2eae8687c62bc632a95b0c6aadba3fb02680a94e09174b7233ccd26d78baca2647c733`.
That published digest is a candidate pin, not acceptance of the transcript.
The full contribution chain still must be independently obtained and verified.

PSE's Perpetual Powers of Tau repository at
[`b077232729db7c9eb65b63c4aaaa0ac4a1b0bba2`](https://github.com/privacy-ethereum/perpetualpowersoftau/tree/b077232729db7c9eb65b63c4aaaa0ac4a1b0bba2)
is another official Phase-1 source and publishes an 18 GB prepared power-24
file from contribution 0080. Its own record says only one branch has a complete
public-key history and that the discontinued fork cannot be fully verified by
`snarkjs`; the GitHub repository is now archived. It must not be substituted
by URL or filename alone.

## Mature option comparison

| Option | Exact relations and current prover | Kaspa verifier/key impact | Setup trust | Finding |
|---|---|---|---|---|
| BN254/Groth16 plus two MPC Phase-2 ceremonies | Preserves the two R1CS relations and standard Groth16 proof equations. Requires exact R1CS export and PK/VK/query conversion. | Keeps tag `0x20`, 128-byte proof, and Arkworks VK layout. New key bytes/hashes must flow through the typed post-setup join. | One honest, erasing contributor in Phase 1 and in each Phase 2; transcript and future beacon are public but erasure is not provable. | **Shortest established path.** |
| BN254 PLONK/FFLONK using the universal Powers-of-Tau SRS | Can ingest R1CS in `snarkjs`, but changes arithmetization, prover, proof, and verification key. It does not preserve the exact Groth16 closure or collaborative Groth16 prover. | No PLONK/FFLONK Kaspa tag exists at the pinned verifier. Requires a new consensus precompile/KIP and new proof/key encoding. | Removes circuit-specific Phase 2, but **does not remove toxic waste**: the universal structured SRS still needs the one-honest-updater assumption. | Longer and adds consensus/security-review work while retaining setup trust. Reject for this objective. |
| RISC Zero Succinct STARK through tag `0x21` | Transparent STARK route, but Output and aggregate must be reimplemented as a RISC-V/recursion computation. Wrapping verification of the old Groth16 proofs would retain their compromised-CRS risk and is not a solution. | Existing tag `0x21`, but a different ABI: image ID, journal/claim, control root/inclusion proof, and STARK seal. Replaces PK/VK/query artifacts and current MPC proving path. | No application-specific Groth16 toxic waste; relies on the pinned RISC Zero STARK implementation, hash assumptions, verifier parameters/control roots, and program equivalence. | Credible future alternative, not the shortest route to an **exact Output+aggregate Groth16 CRS**. |

The STARK paper defines transparency as avoiding reliance on a trusted setup
party ([ePrint 2018/046](https://eprint.iacr.org/2018/046)). RISC Zero documents
its SuccinctReceipt as a STARK of the recursion circuit. This should not be
confused with RISC Zero's optional Groth16 compression, for which RISC Zero ran
its own trusted setup. The current Kaspa `0x21` path verifies the Succinct STARK,
not an application-specific KPB Groth16 key.

PLONK's original construction uses a universal, updatable SRS requiring only
one honest updater ([ePrint 2019/953](https://eprint.iacr.org/2019/953)); it is
therefore ceremony-reducing, not transparent.

## Required adapter boundary

The reviewed upstream Arkworks 0.6.0 API does not directly consume the public
Phase-1 transcript and emit the exact current Arkworks PK/VK/query layout.
Arkworks' official Groth16 generator instead samples the circuit-specific
trapdoors and QAP point locally. `snarkjs` consumes Circom-format R1CS and emits
a `zkey` plus JSON exports, not Arkworks canonical PK/VK bytes.

The safe boundary is therefore narrow and testable:

1. Export the exact Arkworks matrices, constant/instance/witness ordering,
   field modulus, and counts to a deterministic standard R1CS artifact.
2. Round-trip every A/B/C term and evaluate both representations on the same
   valid and invalid assignments. A matching constraint count or matrix hash
   alone is insufficient if variable order changed.
3. Run the established ceremony implementation only over that frozen artifact.
4. Convert the final `zkey` into Arkworks 0.6.0 `ProvingKey<Bn254>` and
   `VerifyingKey<Bn254>` plus the existing mcl/collaborative query order.
5. Validate every point canonically and in-subgroup; check exact A/B/H/L/IC
   lengths and order; cross-prove and cross-verify fixed fixtures in independent
   implementations.
6. Independently serialize the measured 328-byte VKs through the exact Rusty
   Kaspa path. The generated PK/VK hashes are post-setup receipts, never
   expected fields in the pre-setup plan.

Official gnark v0.16.4 at
[`e974abb44722dd201a7f1949baeabca0fef5866e`](https://github.com/Consensys/gnark/tree/e974abb44722dd201a7f1949baeabca0fef5866e/backend/groth16/bn254/mpcsetup)
provides BN254 Phase-1/Phase-2 contribution, verification, sealing, and beacon
APIs. It is a useful independent verifier or alternative ceremony engine, but
it consumes gnark's R1CS and emits gnark keys. It does not remove the same
matrix and serialization adapter obligations.

Do not write a new Arkworks-native ceremony protocol merely to avoid these
adapters. Reuse an established protocol implementation and make the converters
small, deterministic, independently checked, and non-authoritative until all
cross-controls pass.

## Toxic-waste and privacy boundary

Facts:

- If every relevant contributor colludes or a retained contribution secret is
  recovered, the CRS soundness assumption fails and forged proofs may become
  possible. For a payment system that is an inflation/unauthorized-exit risk.
- A future beacon limits participant influence and finalizes a transcript. It
  does not replace an honest secret contribution.
- Algebraic transcript verification and contributor attestations do not
  cryptographically prove secret erasure or an uncompromised host.
- An honest CRS does not prove fresh Groth16 proof randomizers `r,s`, relation
  correctness, witness-source privacy, or an unlinkable network/capture path.

Inference:

- The MPC route materially improves trust over the historical one-party setup
  because no single coordinator or contributor need be trusted, conditional on
  one honest erasing participant in each required phase.
- CRS compromise is principally a soundness/authorization failure. It should
  not be relabelled as demonstrated witness extraction without a separate
  analysis, but a privacy system with forgeable exits is still unacceptable.

## Blocking conditions before any real ceremony or fresh full setup

1. **Circuit stability:** the relation crate and full transitive build closure
   are still changing; no final source/build/worker identity may be repinned.
2. **Exact R1CS bridge:** deterministic export, row/variable-order round trip,
   and hostile substitution controls are absent.
3. **Phase-1 acceptance:** no Phase-1 transcript/file has been selected and
   independently verified from a complete public-key history.
4. **Key/query conversion:** no reviewed `zkey -> Arkworks 0.6.0 -> mcl`
   converter or independent cross-proof corpus exists.
5. **Lifecycle chronology:** there is no source-owned pre-key trial root, no
   production setup launcher, no same-trial continuation, and no post-setup
   measured-key join. FullW1 still accepts only historical VK hashes.
6. **Measurement plan:** 0 of 60 selected-parent artifacts are present, so the
   pre-setup plan is not production-mintable.
7. **Ceremony operations:** contributor independence, immutable transcript
   publication, future beacon, verification quorum, compromise response, and
   explicit best-effort-erasure language are not frozen.
8. **Resources:** neither ceremony resource qualification nor the existing
   large aggregate setup resource guard has been demonstrated green for a real
   launch.

Therefore a fresh full setup run is **not safe or ready**. S4, S12, the
production selector, and configuration must remain false.

## Pinned primary sources

- Groth, *On the Size of Pairing-based Non-interactive Arguments*, ePrint
  2016/260: <https://eprint.iacr.org/2016/260>
- Bowe, Gabizon, Miers, *Scalable Multi-party Computation for zk-SNARK
  Parameters in the Random Beacon Model*, ePrint 2017/1050:
  <https://eprint.iacr.org/2017/1050>
- `snarkjs` v0.7.6, commit
  `9a8f1c0083d18b9b5e18f526cfd729e7259423be`:
  <https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/README.md>
- PSE Perpetual Powers of Tau, commit
  `b077232729db7c9eb65b63c4aaaa0ac4a1b0bba2`:
  <https://github.com/privacy-ethereum/perpetualpowersoftau/blob/b077232729db7c9eb65b63c4aaaa0ac4a1b0bba2/README.md>
- Arkworks Groth16 0.6.0, commit
  `0bb3e604c534bd118ed477eaf1231f591d6fc40f`:
  <https://github.com/arkworks-rs/groth16/tree/0bb3e604c534bd118ed477eaf1231f591d6fc40f>
- gnark v0.16.4, commit
  `e974abb44722dd201a7f1949baeabca0fef5866e`:
  <https://github.com/Consensys/gnark/tree/e974abb44722dd201a7f1949baeabca0fef5866e/backend/groth16/bn254/mpcsetup>
- Rusty Kaspa, commit
  `4edcbbccb449f84832afb1ca157904b35f37d006`:
  <https://github.com/kaspanet/rusty-kaspa/tree/4edcbbccb449f84832afb1ca157904b35f37d006/crypto/txscript/src/zk_precompiles>
- Kaspa KIP-16, commit
  `e4ae2332117b5cb68bd6188e065ef885b6d17939`:
  <https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0016.md>
- RISC Zero, commit
  `164c64bb3a844d393bb7addc5781c705c647f2d5`:
  <https://github.com/risc0/risc0/tree/164c64bb3a844d393bb7addc5781c705c647f2d5>
- Ben-Sasson et al., *Scalable, transparent, and post-quantum secure
  computational integrity*, ePrint 2018/046:
  <https://eprint.iacr.org/2018/046>
- Gabizon, Williamson, Ciobotaru, *PLONK*, ePrint 2019/953:
  <https://eprint.iacr.org/2019/953>
- vProgs current prototype posture, commit
  `f9b84a863a7c7c20586a9cf947550475e894f72e`:
  <https://github.com/kaspanet/vprogs/tree/f9b84a863a7c7c20586a9cf947550475e894f72e>
