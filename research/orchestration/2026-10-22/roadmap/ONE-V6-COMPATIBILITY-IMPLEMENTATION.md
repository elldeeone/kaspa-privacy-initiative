# One-v6 compatibility adapters: implementation handoff

**Status: source authored and root scope-reviewed; neither adapter has been
built or executed.** Root committed exactly the two additive source files in
an isolated worktree. There is no compatibility result, executable identity,
qualified effective build graph or compute release. The coordinator's later
decisive independent review and capacity gate remain **pending**.

## Ownership and immutable identities

| Item | Identity |
| --- | --- |
| Source author / documentation owner | Existing batching reviewer, `/root/next_direction_sources` |
| Actual start | 2026-10-22 11:02:02 UTC / 22:02:02 AEDT |
| Deadline | 2026-10-22 11:32:02 UTC / 22:32:02 AEDT |
| Source frozen | 2026-10-22 11:09:08 UTC / 22:09:08 AEDT; root subsequently removed one extra final newline per file before commit |
| Handoff finished | 2026-10-22 11:11:46 UTC / 22:11:46 AEDT |
| Exclusive source worktree | `/home/luke/projects/kpi-one-v6-compatibility-2026-10-22` |
| Branch | `test/one-v6-verifier-compatibility-20261022` |
| Source parent | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509` |
| Root-owned source commit | `acba8b04237e62a5bbc3eb93eb10faa1722a59ea` |
| Documentation HEAD observed for handoff | `2f65a3e574c528132ca265de7d7cdf7782e94f6d` |
| Unchanged frozen protocol | [One-v6 compatibility protocol](ONE-V6-VERIFIER-COMPATIBILITY-PROTOCOL.md), SHA-256 `b01cd6bbb4b0d9f097277e5986b0b4de7001b97896f5f74f3777d1ff50919932` |

Root staged/committed only the two isolated source paths, with no push. The
source author did not stage or commit source or documentation. Only this
handoff document was written in the canonical documentation worktree; its index
and earlier protocol were untouched by this lane.

| Source added by the commit | Final file SHA-256 |
| --- | --- |
| [Reference](/home/luke/projects/kpi-one-v6-compatibility-2026-10-22/poc/shared-pool/src/bin/one_v6_reference.rs) | `ab513355d0d8e893d3742821a16fb3001ea0e9bc8ee7d10e86c44e50c270585d` |
| [Candidate](/home/luke/projects/kpi-one-v6-compatibility-2026-10-22/poc/takeover/host/src/bin/one_v6_candidate.rs) | `75f424c68de986b4059e0caf5b392f2bda6cf91a2f120e1c21ac7de2ef80ba06` |

The exact patch from
`git show --format= --binary --full-index acba8b04237e62a5bbc3eb93eb10faa1722a59ea`
has SHA-256 `dc10fbae05e6d901c7b401d58e2f0df8d333acfd20f16983320b45d40a4c79ec`.
Root recorded 42,225 patch bytes and 779 added source lines. The author
independently rechecked the commit parent/two-path scope, final file hashes,
patch hash and clean source-worktree status after the root commit.

## Implemented behavior

Both binaries accept **no arguments** and read content from only the three
original public JSON files fixed by the protocol: rehearsal descriptor,
verification key and rehearsal chain receipt. They do not read their own
source, binary, Cargo locks, proving parameters, wallet files or private data
at runtime. Source/lock/protocol pins in their JSON are explicitly labelled
expected constants; the external coordinator must supply actual source commit,
executable, target/toolchain, feature/cfg and resource identities.

Each independently:

1. Verifies the three complete file hashes, fixed descriptor/domain/VK,
   metadata-only first-qualifying-row rule and exact transaction pointer 6.
   It checks original push framing, authorization/proof/ciphertext byte ranges
   and hashes, all fixed profile values and ordered ciphertext digest. No
   fallback row or alternate fixture is tried.
2. Checked-decodes the same 328-byte VK and 128-byte proof, requires complete
   consumption and exact canonical re-encoding, validates curve/subgroup
   membership and VK IC arity three, and rejects identity proof A/B/C.
   VK identity flags are reported under the same policy on both sides; no new
   one-sided native-key acceptance rule is introduced.
3. Derives the two little-endian 128-bit authorization-hash inputs, reports
   decimal **strings** and canonical 32-byte hex, and checked-decodes/re-encodes
   those scalar bytes. The reference additionally compares them with the
   existing `Authorization::inputs()` result.
4. Calls only the specified verification path and prints one typed JSON report
   to stdout. Reference: Arkworks 0.6 `prepare_verifying_key` and
   `Groth16::verify_proof` using the public decoded VK. Candidate: validated
   Arkworks 0.5 VK, then `from_validated_program_key` and `verify_inputs`.
   A pass is conditional on the actual verifier return; it is not hardcoded.

The candidate never calls the built-in old-key verifier, classifier or 14-input
wrapper. Neither adapter calls proving, native VM/replay, setup, RPC, a zkVM
executor or another process. They create no output/fixture files. Input,
infrastructure, canonical-decoder, statement-binding, verifier-interface and
cryptographic rejection failures remain distinct; a reference verifier error
reports `accepted: null` rather than presenting an infrastructure error as
cryptographic rejection.

## Static evidence and its limits

Root inspected the actual sources and original public JSON assumptions and
found no scope or statement-binding blocker. Nonexecuting source inspection
confirmed the APIs used: Arkworks 0.6 exposes an inherent affine `identity()`
constructor while keeping its infinity flag private; the reference uses that
constructor for equality. Arkworks 0.5 exposes the public bool used by the
candidate. Existing `From<u128>`, checked canonical deserializers and point
validation APIs were read as source only.

The committed scope is exactly two additive `100644` files. Every existing
source, fixture, manifest, lock and dependency pin remains unchanged relative
to the parent. Root's cached whitespace check passed after the final-newline
correction. This is not a compiler, formatter, executable, property-test or
cryptographic result. No Cargo, rustc, rustfmt, build script, experimental
package import, adapter, test, proof, setup, installation, download, benchmark
or GPU execution occurred. Parked jobs/wrappers were not accessed or retried.

## Prospective build selection — commands below were not run

These commands identify the intended binaries under their existing locked
workspaces. They are **not an execution release**. Run nothing until the
coordinator separately freezes and releases the actual build/toolchain/cache
identity and resource envelope. An unavailable already-installed toolchain or
dependency is a stop; no installation, fetch, lock update or route substitution
is implied. The current inherited candidate host graph includes broad
Kaspa/vProgs/zkVM dependencies and comparison features `circuit,parallel`;
source-bin size does not establish a small build.

From the isolated source worktree, the proposed offline/frozen selections are:

```bash
cargo +1.91.0 build --frozen --offline --release \
  --manifest-path poc/shared-pool/Cargo.toml \
  --bin one_v6_reference \
  --target-dir artifacts/one-v6-verifier-compatibility/reference-target \
  --message-format=json

cargo +1.91.0 build --frozen --offline --release \
  --manifest-path poc/takeover/Cargo.toml \
  --bin one_v6_candidate \
  --target-dir artifacts/one-v6-verifier-compatibility/candidate-target \
  --message-format=json
```

Rust 1.91.0 here identifies the proposed existing-toolchain selection, not a
newly verified installed toolchain or binary hash. Effective feature/cfg
resolution, full offline cache closure, compilation, linking and actual output
artifact identities remain unqualified. No build/resource ceiling is allocated
by this note; build time/RAM/CPU needs remain unknown. The prior protocol's
verification-only proposed ceiling is likewise unmeasured and unreleased.

## Remaining gate

The coordinator's decisive independent source review and capacity decision
come before any separately authorized build. A successful build would still
leave both baseline executions and report comparison unperformed. A later
compatibility pass would concern only this one retained public VK/proof/input
statement; it would not establish malformed-input equivalence, guest execution,
a two-bundle pair, image/receipt interoperability, accepted history/current
spentness, native backing, recipient delivery, recovery, independent exits,
cryptographic assurance or privacy. Those boundaries remain unchanged.
