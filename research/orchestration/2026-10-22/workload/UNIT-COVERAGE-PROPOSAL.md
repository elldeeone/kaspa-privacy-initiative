# Ordinary unit coverage proposal — 2026-10-22

**Decision: no distinct, worthwhile unrun existing target was identified in the current shared-pool path. Do not allocate CPU merely to repeat its recorded ordinary test passes.** This was bounded source/evidence inspection, not an exhaustive claim about every historical PoC in the repository. No tests, builds, metadata execution of Cargo, proof setup/generation, replay/recovery scenario or privacy workload were run.

All identities below refer to `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. The lead checkout had advanced to `ec6aa15d586bcc8a90f7232b433fd48d8c73d509`; a diff verified no shared-pool source, manifest or lock changes. Pin-specific Git objects supplied the evidence hashes. The completed 16-case relation lane remains frozen.

## Existing targets checked

| Exact target(s) | Meaningful ordinary behavior | Existing evidence and decision |
|---|---|---|
| `two_input::tests::declared_binary_layout_has_no_field_overlap` | Authorization round trip, exact 377-byte frame, short/long rejection, witness offsets | One of the five recorded passed v6 tests; unchanged source. Repeating adds no new coverage. |
| `two_input::tests::depth_seventeen_merkle_positions_and_empty_append_are_authenticated` | Depth-16/17 root/path correctness, wrong-position rejection, empty next leaf and out-of-range path | Same five-test record. |
| `two_input::tests::nullifier_headroom_covers_one_note_exits_without_new_commitments` | Enumerates allowed odd commitment counts and boundary count arithmetic; invalid parity/count rejection | Same record. This is arithmetic, not a generated exit or recovery scenario. |
| `two_input::tests::sequential_nullifier_insertion_rejects_duplicate_and_preserves_prior_set` | 24 synthetic indexed-set updates, prior membership/history retention, duplicate refusal | Same record; no new history or ordering parameter is exposed by this target. |
| `two_input::tests::incremental_public_tree_matches_reconstruction` | 65 incremental appends at each depth versus full reconstruction, root and path equality | Same record; fixed loop, not an unrun high-capacity case. |
| Current wallet ordinary subcases: exact backup/profile decoding, noncanonical amount rejection, exclusive immutable private-file creation, malformed parameter serialization | Relevant encoding/arithmetic/storage behavior | `ADDRESS-KEY-SEPARATION.md:35–38` records all 18 wallet tests and two derivation tests passed. Current wallet-test and protocol hashes equal its exported source snapshot. Not a gap to fill. No backup/recovery target is proposed for execution. |
| `compact::tests::tree_paths_unsigned_order_and_indexed_set` and older anchored codec/capacity tests | Dense-root comparison, unsigned byte ordering and older-layout codecs | `COMPACT-REVIEW.md:31–32` records five Rust groups passed; `ANCHORED.md:50–54` records four Rust groups. Older relation coverage is not new v6 qualification. |

`TWO-INPUT.md:119–121` enumerates the five v6 tests; `TWO-INPUT-TN10.md:113` explicitly records their pass. Their sole source-history change before the pin is `bf64f3d`, so there is no later modification here requiring a regression rerun. Documentary pass records are evidence of prior execution; this inspection did not reproduce them or claim a fresh run.

The parameter-encoding unit test uses a deliberately tiny manually constructed serialization fixture, not parameter setup or proof generation. That distinction was verified from source. Conversely, a broad `cargo test --lib` would mix unrelated relation/native/replay work and is not proposed.

## Command and resource decision before any execution

**Recommended command: none. Recommended allocation: none.** No new unit, cgroup, worktree, build target or worker was created.

For exact identification only, the existing five ordinary v6 targets are selected by this command from a separately authorized, pinned worktree:

```sh
CARGO_TARGET_DIR="$OWNED_NEW_TARGET" \
cargo +1.95.0 test --release --locked --offline \
  --manifest-path "$PINNED_NEW_WORKTREE/poc/shared-pool/Cargo.toml" \
  --lib two_input::tests:: -- --test-threads=1
```

This is **not a launch request**. Source inspection suggests a single-thread, small-runtime test group, but no current RSS/time measurement was made. The full shared-pool library build may dominate resource cost; no provenance-verified test executable was established. Therefore an isolated build cannot be justified solely by an otherwise redundant rerun. Do not run the command in an active/shared target or substitute a broad filter.

## One concrete coverage gap, requiring a different task

The current incremental-tree test stops at 65 leaves. It does not directly exercise the v6 `Tree::append` final depth-16/17 carry, then refusal at full capacity with the prior root/path unchanged (`two_input/tree.rs:62–83`). The historic near-capacity native fixture is not evidence for every incremental append edge. Conversely, a full generic tree is not automatically a valid pool state: public-state limits/parity are separate requirements.

A new ordinary data-structure test could compare incremental roots to an independently built dense root at the final capacity boundary and verify nonmutation after refusal. That would be genuinely new coverage, but **no existing test target exposes that case without a source change**. It is not proposed as an unrun existing target, and no code, command or resource allocation for it is authorized by this inspection. Native KAS backing and independent-exit invariants would remain unchanged; an in-memory tree check would establish neither.

The parked proof job remains parked. This proposal neither reconstructs it nor invokes its wrappers, setup, proofs, replay, recovery or private evaluation data.

## Pin hashes

| File | SHA-256 |
|---|---|
| `src/two_input/tests.rs` | `85749c72f8043d556799cd2045c386093737caa506cb387aa52b553428f3b643` |
| `src/two_input/tree.rs` | `9fc004721ae2a22c6faa26f2a046eefd7bb707e3c83077be01a7913b464891ed` |
| `src/two_input/wallet/tests.rs` | `8375ce42bcd647060565df32992dc5dd0ed31be9c9e8fc1ce0b93d6180cfe827` |
| `src/protocol.rs` | `5243cab1b36e0d9cae8bf13e81b7fcdb033c8dc1bc7405daa401c69334cc4ec4` |
| `TWO-INPUT.md` | `14fda0799bb52bcd272fa3983a07f5e8789cd12790412529d91048d101c3c92c` |
| `TWO-INPUT-TN10.md` | `9393d365910601e44a42d3329da6c74baa72758df7272ca5667a48b01206a663` |
| `ADDRESS-KEY-SEPARATION.md` | `b02e80536f957ccffcbb837f93f2e66a12ea61d3b99d1c0b7f35a82acf26e898` |
| `COMPACT-REVIEW.md` | `59c259cd842c1102d73f04facb7b9c408264baea8ba7968eabb37b0681e49044` |
| `ANCHORED.md` | `09a48e006d68ce53c2eb07b2d266f3f19b6103796d139f4b9a0b91c0669eaf37` |

Paths in this table are relative to `poc/shared-pool/` at the pin. This is a source/evidence proposal only; evidence-lineage owns its documentation commit.
