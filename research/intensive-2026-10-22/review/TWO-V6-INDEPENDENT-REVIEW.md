# Independent two-v6 binding review

Status: initial source and independent byte-oracle review complete. No material
binding bypass found in the inspected implementation. Independent execution of the completed ordinary-host CLI passes the focused
corpus. Genuine positive acceptance of the fixed rehearsal instance remains
unqualified in this review.
This is a narrow engineering second pass, not a cryptographic audit.

## Scope and identities

- Scientific base: `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`.
- Applicable instructions: repository `AGENTS.md`, `SECURITY-INVARIANTS.md`.
- Contract: canonical `TWO-V6-BUNDLE-BINDING-CONTRACT.md`, SHA-256
  `d16ec7b288cc93473cbeffd8af0c0071a06f575552522572f6ccd64b97a03e44`.
- Native boundary review: canonical `TWO-V6-BOUNDARY-CROSS-REVIEW.md`, SHA-256
  `aa2f4dc3782433dd15af9116f07378a919dd7a0c1e75d790d9c5a6510b7e8bd9`.
- Implementation inspected in the sibling `binding` worktree:
  `poc/takeover/host/src/two_v6_binding.rs`. This file is actively changing; its
  intermediate SHA-256 was
  `0b94ffe03100e23e212978262cf8ccf5cbaaf6edd695d0944fe5a6fe4897bd5c`.
- Writes are confined to this review directory. No other agent's files were
  edited. No secrets, private wallets, evaluation inputs, seeds or truth were
  read. No proof generation, build, GPU allocation, broadcast or external write
  occurred in this initial pass.

## Actionable qualification gap: retained proofs cannot form a positive pair

The exact known public rehearsal has two eligible nonbootstrap mode-1,
zero-payout SPEND statements:

| Public transaction index | Transaction ID | Count | Anchor |
|---|---|---|---|
| 6 | `aa87d613bf36c6da5dfda60dd371360f5b4cfdf455f5ce74ce9795ec996db0e7` | 9 | `4c6661670094ebad2f8de5dd1ba1187eea213cf5bd0ff9b0cd96671a5d35fc7a` |
| 8 | `ab1f5426f5b03c29a931ade155c996ae7b33d8a3a4009dbc1130bace9b1e8083` | 13 | `afa086b963df9db5ebb8d98fcbb49f52cb957227dfa5e159eadc33e96248f85e` |

The source JSON SHA-256 is
`75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8`, matching the
contract pin. Their count/anchor pairs differ, so they must reject as a pair.
Rewriting their authorization bytes invalidates the proofs; repeating either
bundle violates global nullifier uniqueness. Neither is a valid shortcut to a
positive fixture. This conclusion only classifies public bytes; it does not
claim independent proof verification.

Action: retain this as a genuine-source negative control. Obtain genuinely
compatible same-anchor proofs for exact-instance positive qualification, or
keep that gate explicitly open. Alternate-key or toy-relation positive proofs
qualify only their separately named instance and relation.

## Addressed scope-sensitive API concern: alternate keys

An intermediate implementation added `Gate::with_trusted_key(domain, bytes,
expected_sha256)`, generalizing the named gate beyond the fixed rehearsal. The
review requested separation to prevent alternate-instance positives from being
mistaken for exact-rehearsal qualification. The implementation now uses the
distinct `ConfiguredResearchGate` type; named `Gate` and default CLI retain
fixed domain/VK. Neither constructor reads a key from witness bytes.

Keep alternate-instance evidence separately named and pin its expected key/domain
independently. This was an addressed scope/API concern, not a cryptographic
acceptance bypass in default `Gate::new()`.

## Addressed finding: assembled private witness file permissions

The original CLI shared its generic `OpenOptions::create_new` writer between
public outputs and the complete assembled witness. With a typical `022` umask,
the 2,846-byte witness would be created as `0644` in traversable project paths.
It contains the otherwise hidden grouping, original authorizations/proofs,
individual fees and anchors. Its contents must not acquire the public P/J scope
merely because assembly is an ordinary host operation.

The engineer added a private-file flag with explicit Unix `0600` creation for
assembly, retained `create_new` overwrite rejection and kept ordinary public
output behavior separate. Private creation rejects on unsupported non-Unix
platforms. The independent differential CLI runner also checks that no group or
other permission bit is set on assembled witness files. Current source fixtures
are public/synthetic; no present secret exposure is asserted.

## Checked binding argument

The gate's source matches the named contract for:

1. Exact 377/128/185-byte bundle components; 1,088-byte public projection,
   2,846-byte input and 42-byte journal; exact domain/VK; native effects and
   bootstrap zeroing; exact individual and aggregate integer fees.
2. Four distinct nonzero NFs and two private index bijections. Every public
   index is consumed once. Commitments and ciphertexts are compared together as
   217-byte records. Equal records at distinct indices retain multiplicity.
3. Original ciphertext slot order, exact SHA-256 authorization digest split into
   two unsigned little-endian 128-bit Fr inputs, and checked canonical complete
   nonidentity proof/VK decoding. Key arity is exactly three IC points.
4. Journal `H = SHA256(P)` and native boundary `SHA256(J)` are distinct fields.
   Publication consistency alone is explicitly not proof or receipt verification.

Relevant source: current binding implementation's `check_profile`,
`Projection::check`, `Witness::check_binding`, `permutation`, `public_inputs`,
`checked_key`, `checked_proof` and `Gate::verify`. In the v6 source,
`circuit.rs:275` binds all authorization bytes to the digest limbs;
`mod.rs:158` separately binds ciphertext digest/native reserve; `covenant.rs`
enforces actual historical membership/current NF insertions/native successor.

## Two invalid equivalences to preserve as explicit negative reasoning

**Inner-proof validity is not accepted historical state.** At
`poc/shared-pool/src/two_input/circuit.rs:145`, positions are limited to 16 bits,
but declared count is related to a real position only by an unsigned slack:
`position + slack + 1 = count`. For a nonbootstrap real input, increasing count
above its position and changing the slack can preserve the ownership,
membership and conservation constraints. The inner relation alone does not
prove that `(count, root)` is an accepted history entry or even enforce all
native count restrictions. The native covenant's history-leaf proof provides
that additional condition. The two-v6 gate intentionally does not.

**A fresh aggregate proof is not a fresh spend.** Reverification of otherwise
valid inner authorizations says nothing about whether their four NFs are already
present in the current native set. Global distinctness within the pair only
prevents collisions among those four declared NFs. Existing native indexed
nonmembership/insertion at `covenant.rs:380` provides current spentness.
Removing that check in future composition would violate I-4/I-6/I-7.

Neither observation is a newly discovered defect in the deliberately
NONSETTLING contract. They are concrete reasons it must not authorize native
reserve movement. Current replay additionally reconstructs exact transaction
bodies and calls native validation (`replay.rs:295`), preserving that separation.

## Independent executable controls

Run from this worktree:

```sh
python3 research/intensive-2026-10-22/review/two_v6_contract_oracle.py -v
python3 research/intensive-2026-10-22/review/two_v6_contract_oracle.py fixture-profile .
```

Ten stdlib-only controls pass. They cover exact framing/profile fields,
limb order, fee endpoints and exact sum, original ciphertext slot order,
complete-record pairing, bundle-order invariance, and all 576 index-permutation
pairs in each of a unique-record and duplicate-record fixture. The unique
fixture has exactly one accepted pair of permutations; the duplicated complete
record has exactly two, corresponding to exchange of its two distinct indices.

The oracle injects a mandatory proof checker. Its tests use an explicitly
synthetic exact-byte proof callback to isolate binding semantics; no synthetic
control is described as a valid v6 proof, receipt, settlement or privacy result.
These controls do not replace running the Rust implementation or checking actual
Arkworks compatibility. `differential_cli.py` prepares a small independent
assembly/rejection corpus for the completed Rust binary, without another build.
Differential execution completed against the existing binary, without another
build. All 36 cases passed: four byte-for-byte assembly matches (including
duplicate full records, repeated CMs with different ciphertexts and maximum
fees) and 32 rejections. Rejections include the unchanged real pair with
different counts, a repeated real proof, invalid synthetic proof bytes, malformed
length/profile/native effects, count/anchor mismatch, nullifier/commitment errors,
aggregate fee mismatch, public sort order, out-of-range/reused permutation
indices and independently cross-wired ciphertexts. Each rejected verification
left no public output directory. Every assembled full witness had no group/other
permission bits.

The initial executed binary SHA-256 is
`8006b9c6a529b41ab60878a8ece2be0a16a8deb1a09cb7e912b753a09dc4149c`.
The inspected library and CLI sources at execution had SHA-256
`4e5ea9f254681eb218d7702a1f6d6d8df7d52318d352baf4f93769ec78ab6af4`
and `08358732646a91836a81cc32e78987524186818f35d4746acb1ea6a149568510`.
Full case outcomes and binary identity are retained in
`cli-differential-report.json`. The four assembly matches are deliberately not
proof acceptance; the synthetic proofs fail `CanonicalEncoding("proof")`.

After extraction into the minimal shared crate, the exact same 36-case corpus
was rerun successfully against binary SHA-256
`42f446478c9e9a7a879ba88d70c31dd89f29549d71916d49afb4aaf02dfcf47b`.
The final shared implementation is `poc/two-v6-binding/common/src/lib.rs`, SHA-256
`0e136026571131398f195e9e9c4bf69b544082143eb574d61fd0f821472fd205`;
its manifest SHA-256 is
`002b4b2638d0890ab5e8c5e4d24880fc6f1057a3f149ae9776bf034fcac15f27`.
The host re-exports this crate rather than maintaining another implementation.
Final outcomes are retained separately in
`cli-differential-report-final-common.json`; initial outcomes are preserved.

The two retained 875-byte source fixtures were additionally re-extracted
independently from the pinned JSON. Their complete bytes match the sibling
fixtures exactly, with SHA-256 `10d201fc946f983e263277413e87c1e1bc6b7342642e13f82ec2a5814e81319e`
and `d7096ebf3468a28a5c9860c1dca07fe65acfc6c5b15bd1908e0acd639fad770c`.


Reproduce the independent CLI corpus using the already-built binary:

```sh
python3 research/intensive-2026-10-22/review/differential_cli.py \
  /home/luke/projects/kpi-intensive-2026-10-22/binding-target/x86_64-unknown-linux-gnu/release/two_v6_binding \
  /home/luke/projects/kpi-intensive-2026-10-22/binding/poc/takeover/host/fixtures/two_v6
```


A distinct `research_instance_contract` entrypoint now supports the forthcoming
separately frozen development fixture using explicitly supplied trusted domain
and VK hash. It never derives those expected identities from witness bytes.
The original `contract` remains hard-pinned to the rehearsal; the additional
control proves it rejects the otherwise well-formed alternate synthetic
instance. This prepares independent P/J recounting, not cryptographic proof
qualification.
