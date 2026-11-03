# RFC-0004 cryptographic profile review: Q2, Q3, Q4 and Q9

**Date:** 2026-11-03. **Baseline:** repository `e00e47427a96e134069e796ac504d945ba22f1a5`.
**Classification:** internal AI technical review and source/format extraction,
not external specialist review, audit signoff or implementation qualification.
No build, setup, proof, wallet, trial, funds or deployment was performed. This
note recommends a **research profile**, not activation or production adoption.

## Recommendation and question outcomes

Advance a **complete repaired Orchard V2 construction with a native Halo2
verification path** as the primary cryptographic research reference for the
proposed fresh native-KAS pool. Preserve its note/key/nullifier/tree, Action
pairing, Halo2 relation, RedPallas spend authorization and binding signature
together. Integrate native KAS boundary accounting and consensus acceptance
outside those primitives; do not call their integration already implemented.

Use `orchard` 0.16.0 at
`616a669df8c9a59c33d47064d3ce04b25d026b2e`,
`BundleVersion::orchard_v2()`, `OrchardCircuitVersion::FixedPostNu6_2`,
`NoteVersion::V2` and the version's default unrestricted cross-address flags.
For the first bounded specification profile, choose **exactly two complete
Actions**, including zero-value padding. This shape is a proposed research
limit, not an upstream capacity limit or throughput result. [O-VERSION][O-CIRCUIT]

The reason is established construction reuse and an explicit repaired circuit,
not an assertion that V2 is universally secure. Adding a native value domain
already requires consensus work. A direct Halo2 path avoids making the first
specification depend on a second proof system that must itself verify or replace
the entire original relation. Keep a full-verifier RISC0 wrapper as a secondary
engineering option, not an available drop-in artifact. [O-VERIFY][K-TAGS]

| Question | Resolution available now | Remaining concrete implementation blocker |
| --- | --- | --- |
| Q2: exact construction | Recommend complete repaired Orchard V2, standard recipient verification, two Actions and explicit native accounting. Preserve role encodings below. | No native-KAS bundle codec, complete-effects digest, authorization integration or accepted native pool state exists in the inspected reference. Upstream proof does not independently constrain note values to Kaspa's smaller monetary maximum. |
| Q3: backend | Prefer a native verifier for the complete repaired Halo2/RedPallas construction. Current Kaspa Groth16/RISC0 tags are different ABIs. Full RISC0 wrapping remains the shortlist alternative. | Native verifier integration/metering, reproducible exact key/profile fingerprints, activation rules and compatibility vectors are absent. A full-Halo2-wrapper guest/image/receipt matching current tag parameters was not found in the inspected source. |
| Q4: identity | Adopt Action-linked `rho`, position-independent Orchard nullifiers, uniqueness of **every published slot nullifier**, and shared spentness across verifier-only upgrades. | Exact native ordering/bootstrap/migration rules and conformance vectors must implement these rules. Legacy position-NF code is not compatible with this identity. |
| Q9: classical/PQ | Classify this primary profile as classical. Retain complete note/key recovery material. Treat Ironwood V3/ZIP 2005 as an explicit optional recovery-preparation research comparison. | Neither current spend authorization nor historical encryption is PQ-safe by assertion. No complete native post-quantum recovery/migration protocol is selected or implemented. |

These decisions can narrow Q2/Q3/Q4/Q9 now. They do not close the native
accounting, accepted DAG state, recovery/retention, cost or privacy gates in the
other RFC questions.

## Why V2 first, and what V3 actually changes

The source distinguishes three relevant choices:

| Library construction | Circuit / note version | Relevant behavior |
| --- | --- | --- |
| `orchard_v2()` | `FixedPostNu6_2` / note V2, plaintext lead `0x02` | Repaired variable-base multiplication, ordinary cross-address transfers supported. Primary established research reference. |
| `orchard_v3()` | `PostNu6_3` / still note V2 | Adds mandatory cross-address restriction for this pool. Do not accidentally select it by equating "latest Orchard" with a fresh general-payment pool. |
| `ironwood_v3()` | `PostNu6_3` / note V3, lead `0x03` | Cross-address transfers permitted; new note-randomness/key-binding derivations prepare the recovery design in ZIP 2005. Optional research comparison, not required to make repaired V2 support classical ordinary transfers. |

`PostNu6_3` adds constraints enforcing `disableCrossAddress` when set. Both
repaired versions use the anchored variable-base multiplication gadget. There
is no inspected source basis to claim that this extra restriction is required
for a fresh V2 pool's ordinary classical transfers. `InsecurePreNu6_2` is an
explicitly historical circuit and is excluded from new research acceptance.
[O-VERSION][O-CIRCUIT]

ZIP 2005's inspected status is **Proposed**. Its V3 note derivation binds the
randomness to note fields to support a separately checked future recovery
statement. It explicitly does not make current Zcash quantum-secure, does not
require quantum privacy, and does not require the recovery protocol to be added
to consensus now. Its source availability is useful; it is not network-activation
or external security approval evidence. [Z-2005][O-RCM]

Thus V3's recovery preparation is substantive, but optional relative to the
classical research question. If future quantum recoverability becomes a fixed
requirement, evaluate the full Ironwood construction and its recovery key/data
requirements explicitly before activation. Do not selectively add its `rcm`
formula to V2 while claiming an unchanged construction.

## Exact roles and format baseline

Lengths below come from the pinned implementation/specification. They identify
upstream cryptographic roles, **not an already allocated Kaspa transaction
format**. Native headers, signing-digest framing, resource commitments and
numeric version allocations still require one coherent consensus codec.

| Role | Bytes / canonical rule | Source and integration requirement |
| --- | --- | --- |
| Spending key | 32 opaque bytes; parse through `SpendingKey::from_bytes`, which rejects invalid derived spending/viewing keys. | Keep inside wallet; use dedicated hardened key derivation, not a public-key-derived spending secret. [O-KEYS] |
| Full viewing key | 96 = `ak[32] || nk[32] || rivk[32]`; canonical component checks and valid external/internal viewing derivations. | Sensitive spend-detection/viewing capability; not a spending key. `ak` has non-identity and sign-bit restrictions. [O-FVK] |
| Incoming viewing key | 64 = diversifier key[32] plus nonzero canonical Pallas-base incoming key[32]. | Incoming discovery is not a complete outgoing/spentness backup. [O-IVK] |
| Raw receiver | 43 = diversifier[11] plus non-identity Pallas transmission key[32]. | Do not invent a new raw address encoding; authenticated user-facing network/address presentation remains a wallet integration decision. [O-ADDR] |
| Note value | 8-byte unsigned little-endian integer. | Upstream circuit range is `u64`; this is not a proved `MAX_SOMPI` comparison. [O-VALUE] |
| Note plaintext | 564 = lead[1] + diversifier[11] + value[8] + `rseed`[32] + memo[512]. | Primary profile requires lead `0x02`; `rho` comes from the creating Action and is not independently supplied inside this plaintext. [O-PLAIN][O-RHO] |
| Recipient ciphertext | `epk`[32], `encCiphertext`[580], `outCiphertext`[80]. | Preserve standard encryption, outgoing recovery and recipient reconstruction. Bind all delivered bytes to the signed effects. [Z-ACTION][O-PLAIN] |
| Nullifier and `rho` | Each 32-byte canonical Pallas-base encoding. | `rho_new = nf_old` in the same Action; nullifier parser does not generically forbid canonical zero. Do not copy a legacy all-zero-sentinel rule without specifying its changed semantics. [O-RHO][O-NF] |
| Commitment, randomized key | `cv_net`[32] compressed Pallas point, `cmx`[32] canonical Pallas-base field; `rk`[32]. | `rk` and encryption `epk` must be non-identity. A value commitment may be identity. Role-specific parsing is mandatory. [O-ACTION][O-VALUE] |
| Signatures | SpendAuth signature[64] per Action; bundle binding signature[64]. | Verify both against the actual 32-byte native transaction effects digest. `Bundle::verify_proof` alone checks neither all signatures nor current spentness. [O-SIG][O-BATCH] |
| Anchor and membership | Anchor[32], depth-32 authentication path of 32 canonical field encodings, private `u32` position. | Position selects a path; it does not enter Orchard's nullifier formula. Count storage must represent a completely full tree (`2^32`), not wrap at `u32::MAX`. [O-TREE] |
| Halo2 proof | Exact length `2720 + 2272*nActions`; 7,264 bytes for the proposed two-Action shape. | Canonical length is checked, with the exact circuit/key fixed by consensus. This is proof size, not full transaction size or fee. [O-PROOF] |
| Action public instance | One column, ten rows: anchor, `cv.x`, `cv.y`, nullifier, `rk.x`, `rk.y`, `cmx`, enable-spends, enable-outputs, disable-cross-address. | For V2 default cross-address use, the final value is zero; do not use the V2 key to attest to an enforced restriction. [O-CIRCUIT] |

Every Action carries one spend slot and one output slot. Preserve complete zero
padding and both published nullifiers even for a deposit-only or full withdrawal
bundle; do not copy a legacy terminal mode that silently skips the output
accumulator. Require all published nullifiers to be pairwise distinct and absent
from current accepted `N`, then insert all of them atomically. The native
transaction layer additionally authenticates actual ordinary funding or a real
authorized shielded spend; a dummy bundle is not mint authority.

For recipient acceptance, choose standard Orchard trial decryption followed by
the selected domain's plaintext/commitment/ephemeral-key consistency checks.
Do not claim that the unchanged Halo2 Action circuit proves correct encryption
of all delivery bytes: it receives note/commitment witnesses, not an encryption
computation. Invalid delivery is rejected before wallet credit under I-14's
explicit alternative. Preserve both scopes in recovery and use the sender's
outgoing viewing capability when outgoing recovery is desired. [O-PLAIN][O-KEYS]

## The monetary-range mismatch and a concrete resolution

RFC baseline lines 433–438 require selected monetary ranges and proved
integer/aggregate bounds. A profile must define those ranges rather than imply
the unchanged Orchard circuit proves `value <= MAX_SOMPI`. Its own `value.rs`
explicitly says note values are constrained to unsigned 64-bit integers and that
applications must enforce smaller instantiation-specific bounds. Honest builder
amount types are not constraints on an adversarial prover. [O-VALUE]

Use the following proposed **inductive accounting argument**, subject to Q8's
explicit backing/accounting review, rather than silently adding a nonexistent
range gadget:

1. Start the fresh pool at `B=0`, with no positive notes. Count each accepted
   positive claim once. Zero-valued padding contributes no liability.
2. Sound Action proofs, correct note membership/authorization and current unique
   nullifiers remove only distinct previously backed notes. All new note values
   are nonnegative `u64`. Preserve the complete construction that provides these
   conditions; membership or range proofs alone are insufficient.
3. The binding signature enforces `b = S_in - S_out` under the construction's
   assumptions. Bound the **public bundle balance** to
   `[-MAX_SOMPI, MAX_SOMPI]` using checked signed wide arithmetic and reject the
   signed minimum before negation. Individual Action differences are signed
   magnitudes up to `u64::MAX`, represented by upstream `ValueSum` in `i128`;
   they are **not** each an `i64`-encoded public `b`. [O-VALUE][Z-BALANCE]
4. Check the actual native equation `T_in + b = T_out + F` and
   `0 <= B_next = B-b <= MAX_SOMPI` in accepted order. For two Actions,
   each private side totals at most `2*(2^64-1) < 2^65`; total-value differences
   are far below the Pallas scalar order. The implementation must preserve the
   exact group/binding construction and prove the integer lift; field equality
   by itself is not this argument.
5. Inductively, outstanding positive-note value equals the native pool value
   `B` for this direct, no-queue profile. Therefore each live note and the sum
   of distinct notes available to any spend are bounded by `B <= MAX_SOMPI`,
   even though the local Action circuit supplies a wider `u64` range.

This is a source-grounded mathematical design argument, not a formal soundness
proof or executed check. It depends on unique note creation/nullifiers, authentic
zero genesis, no unauthorized credit/migration, exact current-state processing
and no separate unpaid liability omitted from `B`. It does not repair an unsound
circuit. If those induction obligations cannot be accepted, a new explicit
hidden-value range/aggregate relation is required; that would be a changed
circuit/profile with new keys and validation obligations. The RFC must state
which route it uses. **Recommendation:** use the induction route for the
unchanged-construction research reference; do not describe builder checks as a
consensus proof of a smaller range.

## Creation identity, duplicates and version races

The essential Orchard invariant is **one new note per Action with
`rho_new = nf_old`**, where every published `nf_old`, including dummy-slot
markers, is consensus-unique. It applies to credits as well as transfers. A
deposit must still use complete dummy-spend Actions with unique markers; a
caller-chosen free `rho`, an operation number or an arbitrary public receipt
hash is not equivalent to this construction. [O-RHO][O-NF][O-CREATE]

The spend marker is derived from `nk`, the note's `rho`, `psi`, and full note
commitment. Its formula does **not** take the Merkle position. The circuit binds
that same note to membership, keys and the derived public marker. [O-NF][O-CREATE]

Consequences for Q4:

- Two witnesses for the **same note** at different positions derive the **same
  nullifier**. They do not create two independently spendable claims. Current
  uniqueness rejects the second spend.
- Replaying an identical creating Action repeats its published input marker and
  is rejected before another output can be credited. Distinct valid creations
  have distinct `rho`; constructing the same spendable opening under both is
  incompatible with that note definition, absent a broken cryptographic
  assumption. Do not treat equal raw commitment bytes as proof of two liabilities.
- A wallet preserves all accepted positions for authenticated replay/witnesses,
  but never sums two references to one spend identity as two balances. If an
  imported history duplicates a complete Action, reject its history; do not
  "repair" the chain by silently deduplicating ciphertexts or commitments.
- Old-anchor proofs still consult current `N`. Two valid proofs or DAG blocks
  spending the same note cannot both commit. Rho uniqueness and native state
  acceptance must be preserved across the same reorg undo boundary.

The legacy v6 relation instead HMACs domain, note commitment **and position**,
and has separate dummy derivation. Its semantics intentionally allow a
different resource identity. This is a concrete incompatibility, not a naming
difference. Never move its position-NF or duplicate-note tests into an Orchard
profile unchanged. [L-V6]

**Domain recommendation:** bind network/genesis, immutable original native pool,
creation profile and exact current effects in authorization/accepted state.
Preserve upstream inner cryptographic derivations for this reference; merely
prepend a new pool/version to Orchard's nullifier formula changes the relation.
Namespace spentness by the immutable note-origin domain and raw marker, not by
the currently accepting verifier version. A verifier-only upgrade accepting the
same notes must share that spentness. Migration to a different pool or note
construction must consume the old claim once and create a newly backed note,
atomically; do not re-import a root, reset `N` or re-nullify an old note under a
fresh active-version namespace. Numeric native IDs and the complete effects
digest require the parent consensus specification; no new cryptographic hash
primitive is proposed here.

## Backend alternatives and actual missing pieces

| Option | What is reused | Actual gap / decision |
| --- | --- | --- |
| Complete Orchard V2 plus native Halo2/RedPallas validation | Upstream circuit, keys, Action proof verification, standard note/encryption/tree/NF and both signatures. | **Preferred research design.** Missing native codec/effects mapping, fixed allowed profile/key identity, all consensus-state integration and metering. No native tag currently accepts it. |
| RISC0 guest verifies complete Halo2 bundle and signatures | Original construction, plus a zkVM proof of running its full verifier. | Not the retained wallet guest. Requires a guest compiled for the selected zkVM with exact upstream dependencies, fixed Halo2 key/parameters, full signature checks and native-effects journal; exact image/control parameters, source-to-image reproduction and measured resource limits are missing. This pass makes no claim that it compiles or meets costs. |
| RISC0 re-executes an Orchard-derived note relation | Existing archived code parses SK/note, derives NF, verifies depth-32 paths, checks checked-integer balance and regenerates ciphertexts. | Source exists, so there is reusable work. It does **not** reuse the complete Halo2/RedPallas proof/binding construction; its guest program is a different relation. Native credit/state/boundary integration and new soundness review remain. |
| New BN254/Groth16 wrapper verifies complete Orchard | Could preserve the original semantics inside another circuit. | No compatible full non-native Pallas/Vesta/Halo2/RedPallas verification circuit or its setup/key artifacts was located in the inspected source. A BN254 verifier tag does not supply those gadgets. Do not present this as a ready shortcut. |
| Extend legacy BN254 v6 relation directly | Existing custom SHA/HMAC/position-based R1CS and current tag family. | **Retain as transparent-exit comparator.** It is an independent construction, not Orchard. Replacing commitments/NF/tree with Orchard creates new non-native gadgets/constraints and setup. Existing PK/VK and old proof results would not carry over. |

The archived wallet core at `b4114173` pins this same Orchard source with
`default-features = false` and `std,zeroize`, excluding its Halo2 circuit feature.
Its `validate` verifies the new Rust relation and produces a wallet journal.
The archive therefore supplies concrete relation/scanning lessons, **not a
completed Halo2 verifier wrapper**. [L-WALLET][L-WALLET-CARGO]

Current tag `0x20` decodes compressed BN254 Groth16 points and checks key/input
arity and complete byte consumption. Its proof is three compressed points
(32+64+32 bytes); an exact native public-input map and an authorized circuit key
are still required. Tag `0x21` accepts only the inspected Poseidon2 succinct
RISC0 format, with 32-byte digest fields, a seal of little-endian `u32` words,
control inclusion proof and image/journal claim binding. It is not a generic
Halo2 decoder or an arbitrary SDK receipt envelope. [K-GROTH][K-RISC]

For native Halo2, upstream exposes `VerifyingKey::build(version)` and
`ProvingKey::build(version)` from fixed `K=11` parameters/circuit. This is a
reproducible source-based key construction path; do not automatically import
the old Groth16-instance missing-parameters failure as a claim that Orchard
requires a coordinator-only ceremony artifact. Exact dependency/source and
serialized/fingerprint identities still need retention and independent
reproduction. `Bundle::verify_proof` verifies the proof only; both RedPallas
signature roles and every contextual native check must also run. [O-KEYBUILD][O-BATCH]

For deterministic reference validation, prefer single-proof and individual
signature verification paths. Upstream batch verification requires randomness;
any later consensus batching optimization needs its own specified failure and
determinism argument. Do not insert an unspecified host RNG into consensus
acceptance. [O-VERIFY][O-SIG][O-BATCH]

## Per-layer classical/PQ assessment

| Layer | Primary-profile conclusion | Upgrade/recovery consequence |
| --- | --- | --- |
| Halo2/Pasta proof and Pedersen/Sinsemilla commitment machinery | Classical curve assumptions remain. Repaired circuit selection fixes a known constraint problem, not quantum attacks. | A future proof-system swap must not import forged legacy claims or reset spentness; public aggregate backing alone cannot validate entitlements after a broken circuit. |
| RedPallas spending/binding authorization and Pallas key agreement | Classical. A new outer STARK cannot make an inner classical signature/commitment secure against an adversary that breaks those assumptions. | Require user-authorized, exact-once migration before an unsafe profile is retired; no administrative spending rescue. |
| Recipient ciphertext history | Symmetric encryption does not remove the classical ECDH dependency that supplies its key. | Retained ciphertexts can face future key-recovery/privacy threats; deleting the preferred archive cannot erase copies already observed. |
| SHA/HMAC or hash-based parts | Assess their actual role and hash assumptions separately. | A hash-based NF or RISC0 label alone does not establish end-to-end PQ security or preserve spendability. |
| RISC0 succinct wrapper | Additional proof-system/image/control-parameter assumptions. | Even a future PQ outer verifier would retain classical inner Orchard assumptions if it verifies that construction unchanged. |
| BN254 Groth16 adaptation/wrapper | Classical pairing assumptions plus circuit-specific setup. | A different backend does not cure note/key/privacy assumptions; changing the relation needs new artifacts and migration domains. |
| Ironwood V3 optional comparison | Proposed recovery preparation binds additional derivations; current ownership remains classical and privacy is explicitly outside its PQ guarantee. | Requires exact backup material and a separately implemented/activated recovery statement. It is not today's production PQ escape path. |

The concrete V3 source/spec reason is recovery preparation, not recency.
Keep the original spending material and note reconstruction data needed to
derive the proposed recovery credentials; a view-only export or an obsolete
proof is not automatically equivalent. This profile makes no post-quantum
privacy or non-stranding migration promise. [O-RCM][Z-2005]

## What requires approval, versus missing engineering

No extra human permission is required to make this research recommendation or
extract these public formats within the authorized review. The absent native
codec/verifier/state integration and wrapper artifacts are **engineering gaps**,
not problems solved by requesting ceremonial approval.

Separate owner/governance decisions remain necessary before adopting an
architecture, amending I-1/I-2, allocating/activating consensus formats, changing
the strong privacy requirement or accepting a production migration policy.
Independent cryptography/consensus review is needed to establish conclusions
beyond this internal AI review; its absence is not replaced by saying source
inspection passed. Builds, setups, proof campaigns, trials, funding and
deployment are outside this assigned source-only task.

## Source identities, cache and exact citations

Official heads were refreshed during this review: Orchard
`616a669df8c9a59c33d47064d3ce04b25d026b2e`, Zcash ZIPs
`ff594de6e95bb9e9e7d2ace09510281531c30447`, and Rusty Kaspa
`b85380d16514e65136001530e7c717eef304e654` matched the prior source refresh.
These are repository identities, not statements about active network rules.
Current Orchard `Cargo.toml` declares `MIT OR Apache-2.0`; older BOSL assumptions
must not be silently carried onto this inspected revision. Dependency licenses
remain their own review scope. [O-CARGO]

Verification cache, outside Git:

- `/tmp/kpi-protocol-primary-2026-11-03/zcash/orchard/`: pinned keys, note,
  nullifier, Action, circuit, builder, bundle/batch, tree, address and value files.
- `/tmp/kpi-protocol-primary-2026-11-03/zcash/zips/`: pinned protocol source and
  `zips/zip-2005.md` (the latter is Markdown, not `.rst`).
- `/tmp/kpi-protocol-primary-2026-11-03/kaspanet/rusty-kaspa/`: current-pin
  Groth16/RISC0/tag files; earlier cache contents are not a substitute for their
  exact cited commit.
- `/tmp/kpi-rfc0004-crypto-profile-2026-11-03/`: selected historical source files
  extracted read-only with `git show`, under `b4114173...` and `4d54dc02/`.

The parent can re-extract historical files from their exact commits and compare
the cache. No old worktree was resumed and no historical source was edited.

[O-VERSION]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle.rs#L52-L186
[O-CIRCUIT]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/circuit.rs#L75-L175
[O-VERIFY]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/circuit.rs#L1353-L1380
[O-KEYBUILD]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/circuit.rs#L1079-L1160
[O-KEYS]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L45-L146
[O-FVK]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L495-L525
[O-IVK]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/keys.rs#L714-L734
[O-ADDR]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/address.rs#L68-L92
[O-PLAIN]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note_encryption.rs#L25-L98
[O-RHO]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note.rs#L32-L104
[O-RCM]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note.rs#L168-L237
[O-NF]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/note/nullifier.rs#L38-L86
[O-CREATE]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/circuit.rs#L668-L830
[O-ACTION]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/action.rs#L18-L123
[O-VALUE]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/value.rs
[O-SIG]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/primitives/redpallas.rs#L160-L194
[O-TREE]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/tree.rs#L90-L175
[O-PROOF]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/lib.rs#L142-L163
[O-BATCH]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/src/bundle/batch.rs#L50-L145
[O-CARGO]: https://github.com/zcash/orchard/blob/616a669df8c9a59c33d47064d3ce04b25d026b2e/Cargo.toml#L1-L35
[Z-ACTION]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L14371-L14439
[Z-BALANCE]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/protocol/protocol.tex#L7480-L7560
[Z-2005]: https://github.com/zcash/zips/blob/ff594de6e95bb9e9e7d2ace09510281531c30447/zips/zip-2005.md#L1-L226
[K-TAGS]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/crypto/txscript/src/zk_precompiles/tags.rs#L5-L21
[K-GROTH]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/crypto/txscript/src/zk_precompiles/groth16/mod.rs#L20-L125
[K-RISC]: https://github.com/kaspanet/rusty-kaspa/blob/b85380d16514e65136001530e7c717eef304e654/crypto/txscript/src/zk_precompiles/risc0/mod.rs#L90-L138
[L-WALLET]: https://github.com/olafweller/kaspa-privacy-initiative/blob/b41141733ed04b3ef6086ab1a98e75b00372f424/poc/private-payment/wallet-core/src/lib.rs#L18-L142
[L-WALLET-CARGO]: https://github.com/olafweller/kaspa-privacy-initiative/blob/b41141733ed04b3ef6086ab1a98e75b00372f424/poc/private-payment/wallet-core/Cargo.toml#L8-L14
[L-V6]: https://github.com/olafweller/kaspa-privacy-initiative/blob/4d54dc026098506dd56dc568b20cab269be2b447/poc/shared-pool/src/two_input/circuit.rs#L178-L215
