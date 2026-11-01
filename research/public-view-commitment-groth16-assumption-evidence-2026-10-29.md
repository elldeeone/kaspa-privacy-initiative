# Public-view commitment and Groth16 assumption evidence

Date: 2026-10-29  
Repository baseline: `b58de1a182347c4223ebe84f92bb0bdd6c88d003`  
Status: research note only; **no source assumption is selected by this note**

## Decision

1. **Do not select `PINNED_COMMITMENT_BINDING_HIDING_ASSUMPTION` as currently named.** The public view contains two materially different commitment constructions: domain-separated SHA-256 note/tree commitments and Baby-Jubjub Pedersen value commitments. Their assumptions and counterexamples differ. Merkle positions, paths, counts, and repeated roots remain explicit leakage even if the hashes are ideal.
2. **A narrow `PINNED_GROTH16_PUBLIC_PROOF_ZK_ASSUMPTION` can be written, but it is not established or selectable yet.** The selected projection has six Output proofs under one circuit-specific CRS and one aggregate proof under a different CRS. A defensible statement must cover their joint, auxiliary-input public view, both setup histories, and fresh proof randomizers. The present records do not prove toxic-waste erasure or a ceremony, and the aggregate setup explicitly says it is not a ceremony.
3. Keep `SELECTED_SOURCE_ASSUMPTIONS = {}`. The fail-closed state is explicit at `poc/local-private-payment/private_batch_trial/privacy_capture_model.py:61-65`.

## Selected public bytes

The selected grammar parses an exact 10,685-byte projection. It contains three input rows, six output rows, 3,072 bytes of commitment-tree paths, six 128-byte Output proofs, and one 128-byte aggregate proof. Each output row is:

```text
CM32 || CV64 || ciphertext264 || SHA256(ciphertext)32 || OutputProof128
```

At the start of this audit the model recorded CM/path/proof bytes but did not separately represent the nine public CVs. The current uncommitted worktree now inventories three input CVs at body offsets `404 + 96*i + 32`, six output CVs at row offsets `32..96`, canonical subgroup decoding, public delta, the exact balance equation, and all 540 candidate residual partitions (`privacy_capture_model.py:662-800,868-875,997-1005`). It correctly reports zero candidate pruning without individual openings and leaves joint hiding/blind freshness unmodeled. This closes the byte-coverage gap; it does not establish or select a hiding assumption.

The selected aggregate source closure is the table at:

`poc/local-private-payment/private-batch-relation/evidence/2026-10-28-full-financial-source/stock-setup-source-table.json:1-49`.

Its key file hashes reproduce from repository commit `b58de1a...`:

| Source | SHA-256 |
|---|---|
| `native-relation/src/lib.rs` | `f93c2593444acd3936595e4e0d07cc680ff8ada05ce9f9c7dd5a47a387245b9e` |
| `native-relation/src/cv.rs` | `350153426d8ff86905a7956a76311726812151bbe301b319ee254336b33c2f05` |
| `private-batch-relation/Cargo.toml` | `fc83da438c9d1cd2264b464eb12d92ff409eb7427be7af252b9c53b02f3d2465` |
| `private-batch-relation/Cargo.lock` | `59f0d385410c63542e72220bba778a98b852fe1bab7216ad161f369dc8d4d40d` |
| `private-batch-relation/src/circuit.rs` | `a5e8f2d0332f342b4406d99c0a4b7f893933d2ddca8a5218907f3c27fa01e12b` |
| `private-batch-relation/src/gadgets.rs` | `a395e49d1d16860bcc1d874e344b4a381de2ed0b51ded6ff232c7830a6b9d978` |
| `private-batch-relation/examples/setup_direct.rs` | `f9ca07ebd302769866b28487e3ccd38cc1e9481189b4996fa99bf3b3d3a73d10` |

The current worktree has an uncommitted aggregate-circuit layout change. Claims below therefore use `git show b58de1a...:<path>` for selected aggregate circuit line references, not the mutable worktree copy.

## Commitment construction 1: note CM and commitment tree

### Exact construction

The selected note has the fixed-width encoding at `native-relation/src/lib.rs:103-139`:

```text
Note168 = owner32 || incoming32 || value_u64_le || rho32 ||
          key_commitment32 || native_pk32
CM      = SHA256("KPX1NOT\0" || domain32 || Note168)
```

The tags and SHA-256 combiner are at `lib.rs:37-42` and `:66-71`. Tree nodes are:

```text
parent = SHA256("KPX1CMN\0" || left32 || right32)
```

at `lib.rs:86-101`. The selected aggregate circuit recomputes each private input CM and membership path at `private-batch-relation/src/circuit.rs:154-176`, recomputes each output CM at `:184-200`, and binds the public projection at `:261-293` (line numbers from commit `b58de1a...`). The Output circuit independently constrains the same note hash to the public CM at `private_batch_trial/auth_exit/src/circuit.rs:111-123`.

Owner-local output creation uses `os.urandom(32)` for `rho` at `private_batch_trial/output_producer.py:105-110`. This is implementation evidence for fresh salt generation, not proof that the salt remains unknown in every observer/colluder view.

### Narrow honest statement

The following is narrow enough to review:

> For the fixed-width, domain-separated encodings above, CM and tree-node binding are computational under SHA-256 collision resistance. Message hiding is only assumed when every relevant `rho` is independently sampled with 256 bits of entropy, remains secret conditional on the complete frozen observer/colluder auxiliary view, and SHA-256 is modeled as a hiding random-salt commitment (for example, random-oracle-like behavior). Merkle paths, positions, counts, root equality, and state continuity are public and receive no hiding claim.

Collision resistance alone does **not** imply hiding. A deterministic hash commitment with a known or low-entropy opening is dictionary-testable. A concrete counterexample is an observer that learns all note fields except a bounded `value` and `rho`: it enumerates candidate values and compares CM. Reused or disclosed `rho` similarly removes the claimed salt entropy.

## Commitment construction 2: value CV

### Exact construction

`native-relation/src/cv.rs:17-30,107-131,147-158` pins Arkworks Pedersen over `ark_ed_on_bn254::EdwardsProjective` with a 64-bit message window. The effective equation is:

```text
CV = value * V + blind * R
```

The public generator transcript is deterministically derived by ChaCha20 from:

```text
"KPI owner-private payments v1 / transparent Pedersen parameters / BN254 BabyJubjub"
```

The implementation draws the randomness base `R` before the value base `V`, validates subgroup/shape, and exposes their canonical coordinates (`cv.rs:80-131`). The native check is at `cv.rs:147-177`; the selected aggregate gadget constrains the same equation at `private-batch-relation/src/gadgets.rs:96-109` and uses it per owner/output at selected `circuit.rs:174-216`. The Output circuit constrains CV at `private_batch_trial/auth_exit/src/circuit.rs:65-75,111-123`.

The selected dependency is Arkworks 0.6.0 (`private-batch-relation/Cargo.toml:9-22` and `Cargo.lock:44-48,104-108`). Its exact source provenance is:

| Crate/source | Upstream commit | Local source SHA-256 |
|---|---|---|
| `ark-crypto-primitives` Pedersen commitment | [`ba00127b...`](https://github.com/arkworks-rs/crypto-primitives/blob/ba00127bf673d93d73a3e8bf969cb9eeced20d12/crypto-primitives/src/commitment/pedersen/mod.rs#L39-L105) | `4b7f3a0c55e26475ce2a76a46d924a06f63d13fda8206f1d8083529a7d719b77` |
| `ark-crypto-primitives` Pedersen generator creation | [`ba00127b...`](https://github.com/arkworks-rs/crypto-primitives/blob/ba00127bf673d93d73a3e8bf969cb9eeced20d12/crypto-primitives/src/crh/pedersen/mod.rs#L38-L56) | `e7d419bb6d6f21771cb8e43a41d3c8cceee0c08857c1f7b75fc067189586ef1f` |
| Ark twisted-Edwards uniform point sampler | [`bffa5271...`](https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/ec/src/models/twisted_edwards/group.rs#L80-L91) | `fd1137f2d271c71083014c01552004d671213b6f4752b78dff23e6c74e8318d4` |

The sampler chooses a random field `y`, recovers a curve point, and clears the cofactor. It does not record `V = tR` for a known scalar `t`. The unknown discrete-log relation is nevertheless a cryptographic assumption, not something the deterministic seed proves.

Owner-local generation samples each output blind with `secrets.randbelow(Q)` (`output_producer.py:105-125`) and rerandomizes each input CV with a fresh sample (`lifecycle_worker.py:136-160`).

### Narrow honest statement

> For the exact pinned Baby-Jubjub prime-subgroup encoding and generator transcript, CV is perfectly hiding with respect to `value` if `blind` is independently uniform over the full scalar field and remains secret. It is computationally binding under discrete-log hardness and the absence of a known discrete-log relation between `V` and `R`. Canonical subgroup decoding, fresh one-use blinds, and the exact generator derivation are applicability conditions.

Counterexamples are direct:

- `blind = 0` permits bounded value enumeration;
- reusing a blind exposes `CV1 - CV2 = (value1 - value2)V`;
- knowing `R = tV` permits alternative `(value, blind)` openings.

This CV statement must be separately represented in the leakage ledger. Calling only roots/paths “commitments” leaves the nine CVs uncovered.

## Groth16: two proof systems and two CRSs

The implementation pins Arkworks Groth16 0.6.0 over BN254 at `private-batch-relation/Cargo.toml:11-22`; the lock entry checksum is `a293328aa422e65527e285614ce5d1dceb0bd7b8b18d18b1b63191ee1f74cb41` (`Cargo.lock:158-162`). The crate provenance is upstream commit [`0bb3e604...`](https://github.com/arkworks-rs/groth16/tree/0bb3e604c534bd118ed477eaf1231f591d6fc40f), whose setup samples `alpha`, `beta`, `gamma`, `delta`, and group generators ([`generator.rs:14-43`](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/generator.rs#L14-L43)). Its randomized prover samples fresh `r,s`; its explicit non-ZK path sets both to zero ([`prover.rs:137-170`](https://github.com/arkworks-rs/groth16/blob/0bb3e604c534bd118ed477eaf1231f591d6fc40f/src/prover.rs#L137-L170)). Local source hashes are `e188a02698d50b9a148950bf1653423b91541f9de5805054554e4044751bf9ae` for `generator.rs` and `2747321418043a0d362b95075b14141056b327b27266232c7fdbf6de018fc3bd` for `prover.rs`.

The primary construction is Jens Groth, [“On the Size of Pairing-based Non-interactive Arguments”](https://eprint.iacr.org/2016/260), EUROCRYPT 2016. The scheme's zero-knowledge result does not establish that a particular CRS was honestly generated or that a composed implementation leaks nothing through its other public fields.

### A. Six Output proofs

`private_batch_trial/auth_exit/src/proof.rs:81-93` computes a source-closure identity. Setup calls `Groth16::<Bn254>::generate_random_parameters_with_reduction(..., OsRng)` at `:102-124`; proving checks exact manifest/PK/VK/matrix identities, calls the randomized prover with `OsRng`, and independently verifies at `:127-164`.

The selected Output manifest at `private-batch-public/evidence/2026-10-28-real-role-selection/OUTPUT-MANIFEST.json:1-15` pins:

- source identity `ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e`;
- matrix `d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31`;
- 217,807 constraints, 214,998 witnesses, three instances;
- PK `1c2d02992ae89810b8a95ede7bf38aefd503f4984e7b82b27db452141752339a`, 85,578,096 bytes;
- VK `8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119`;
- setup record `PRIVATE_OS_RNG_NOT_RETAINED`.

The selected component profile binds that manifest and VK at `private-batch-public/component-profile.json:24-27`. Each proof's public statement is `domain || CM || CV || ciphertext_hash`, reduced to two public field inputs (`auth_exit/src/lib.rs:68-86`).

### B. One aggregate proof

The aggregate setup program warns that it is local research setup, not a ceremony, then invokes the same Ark randomized setup with `OsRng` (`private-batch-relation/examples/setup_direct.rs:1-3,150-189`, selected commit `b58de1a...`). The setup record explicitly says `FRESH_LOCAL_RESEARCH_SETUP_NOT_CEREMONY_OR_FINANCIAL_ACCEPTANCE`, `no seed or trapdoor serialized`, and `role_manifest_selected: false` (`private-batch-relation/evidence/2026-10-28-full-financial-source/public-stock-setup.json:1-33`).

The registered selection remains `UNCONFIGURED_BLOCKED` and `configured: false` (`mpc-prover/financial/REGISTERED-ACTUAL-HEAD-SELECTION.json:1-7`). It pins:

- aggregate source identity `3ff31adfc6f2666ac53606ecf60336366d850951fda22a38b7445262f380d829`;
- matrix `c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab`;
- canonical PK `170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945`, 2,608,842,576 bytes;
- compressed PK container `4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff`;
- VK `2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102`;
- independent verifier `c1805cfe7ae9b2db7d58fd58727b57e92a0fec866506cd720fbd59242359131f`.

These appear at `REGISTERED-ACTUAL-HEAD-SELECTION.json:8-15,52-71`.

A 2026-10-29 full regeneration from current source table
`04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7`
produced all 13,093,029 rows and A/B/C artifacts byte-for-byte identical to
the setup matrices, with the same `c02320...56ab` fingerprint. This closes the
source-drift-to-matrix question only. It does not improve the local setup's
integrity, erasure, ceremony, selection, or zero-knowledge evidence.

The collaborative prover gets authenticated masks `r,s` from MASCOT preprocessing (`mpc-prover/financial/financial_prover.cpp:188-231`; `mpc-prover/auth_field.cpp:179-202`) and constructs the standard randomized `A,B,C` proof before independent verification (`financial_prover.cpp:253-270`). Therefore aggregate-proof ZK additionally depends on the pinned MASCOT joint-view/fresh-randomness assumption; ordinary single-prover `OsRng` evidence does not cover it.

## Narrow Groth16 statement that could be reviewed

> For the exact Arkworks Groth16 0.6.0/BN254 implementation, the exact two circuit/matrix closures, and the exact Output and aggregate PK/VK pairs above, the joint distribution of six randomized Output proofs plus one randomized aggregate proof reveals no witness information beyond their public statements and the rest of the frozen observer/colluder auxiliary view, conditional on: (a) honest circuit-specific CRS generation and unavailability of all setup toxic waste; (b) canonical subgroup-checked encodings; (c) independent fresh `r,s` for every Output proof; (d) fresh authenticated aggregate `r,s` with at least one honest MASCOT party and no retry reuse; and (e) the applicable multi-proof, auxiliary-input composition of Groth16 zero knowledge. This statement gives no hiding to CM, CV, ciphertext hashes, effects, paths, counts, timing, or any other public field.

That statement is narrow enough to be meaningful. It is **not presently established** for selection because:

1. `PRIVATE_OS_RNG_NOT_RETAINED` and “no seed or trapdoor serialized” do not prove setup integrity, toxic-waste erasure, or resistance to a malicious CRS generator.
2. The aggregate setup explicitly disclaims a ceremony, and its role manifest is not selected.
3. The current assumption key collapses two CRSs and seven correlated proofs into a generic proof-byte field.
4. The six Output witnesses and aggregate witness are correlated. A one-proof ZK citation does not by itself document the required joint auxiliary-input composition.
5. Aggregate proof randomization is a collaborative MASCOT claim. It must inherit the exact corrupt-P1/fresh-mask conditions, including abort/retry handling; public verification alone cannot establish ZK.
6. Arkworks exposes a non-ZK proof path with `r = s = 0`. Any future source drift or randomizer reuse is an applicability failure, not a harmless implementation detail.
7. Passing proof verification and wrong-statement controls establishes validity behavior only. It is not empirical or formal evidence of zero knowledge.

## Required follow-up before either selection

1. Split the commitment assumption into:
   - SHA-256 CM/tree binding plus conditional random-salt hiding;
   - Pedersen CV hiding/binding with fresh-blind and unknown-generator-relation conditions;
   - explicit non-hiding treatment of paths, positions, counts, and state links.
2. Retain the current explicit public input/output CV, delta, balance-equation, candidate-residual, and blind-freshness rows. Do not collapse them back into a generic commitment or raw-byte field.
3. Split or explicitly bundle the Output and aggregate Groth16 CRSs. Pin all seven proof positions, both statement grammars, both circuit/matrix identities, both PK/VK histories, and the aggregate MASCOT randomizer provenance.
4. Obtain reviewable evidence for CRS generation and toxic-waste handling. Current local setup records are intentionally insufficient.
5. Review the seven-proof joint auxiliary-input composition against the frozen observer model before changing `SELECTED_SOURCE_ASSUMPTIONS`.

No ledger, selection JSON, runtime configuration, or assumption map was changed by this research.
