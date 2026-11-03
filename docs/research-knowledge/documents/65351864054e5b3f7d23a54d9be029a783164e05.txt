# One retained v6 bundle: verifier compatibility protocol

**Current executable status: NO.** The exact public fixture and comparison
semantics are fixed below. The two small comparison adapters do not yet exist,
and their effective build/feature identities have not been materialized. This
is a source-only preparation, not implementation or execution permission.
Missing adapters/cache metadata are not a failed public fixture or a rejected
proof. No other fixture or backend is selected if a prerequisite fails.

## Scope and ownership

| Item | Frozen identity |
| --- | --- |
| Owner | Existing batching reviewer, `/root/next_direction_sources` |
| Actual start | 2026-10-22 10:47:23 UTC / 21:47:23 AEDT |
| Deadline | 2026-10-22 11:07:23 UTC / 22:07:23 AEDT |
| Finish | 2026-10-22 10:54:15 UTC / 21:54:15 AEDT |
| Documentation base | `0b77d3a733da3adb001521d07eb0353718934714` |
| Scientific source | `ec6aa15d586bcc8a90f7232b433fd48d8c73d509` |
| Required prior review | [Two-v6 boundary cross-review](../architecture/TWO-V6-BOUNDARY-CROSS-REVIEW.md), SHA-256 `aa2f4dc3782433dd15af9116f07378a919dd7a0c1e75d790d9c5a6510b7e8bd9`, read first and matched |

The single question is whether the **same retained public v6 VK/proof and two
exact authorization-derived inputs** round-trip canonically and verify under
both the existing Arkworks 0.6 reference and the selected generic Arkworks
0.5/substrate-bn helper. It does not evaluate a new proof, guest, two-bundle
composition, recovery, native execution, throughput or privacy.

This pass read committed public source, lockfiles, known public JSON and source
cache file metadata. Standard-library JSON/byte/hash calculations selected and
identified the fixture; no cryptographic verifier or experimental module was
executed/imported. No fixture file, adapter, build, setup, install, proof,
runtime test, benchmark, GPU allocation, private-evaluation read or system
change occurred. Parked jobs and wrappers were not accessed or reconstructed.

## Deterministic fixture selection — already fixed

Selection uses only the committed public
`poc/shared-pool/evidence/2026-10-20-two-input-tn10/rehearsal/chain-confirmed.json`
at the scientific commit above. In ascending `/transactions` array order,
select the first row satisfying all these **observable metadata** conditions:

1. Payload has exactly 5,228 decoded bytes and starts `KPICR06\0`.
2. Its 377-byte authorization starts `KPICU06\0`, has the fixed rehearsal domain
   below, mode 1 and zero public payout.
3. Authorization `[221,345)` is all zero: destination, deposit, funding,
   funding SPK and bootstrap. No verifier outcome enters selection.

The selected row is **`/transactions/6/transaction`**. Its source-supplied
transaction ID is
`aa87d613bf36c6da5dfda60dd371360f5b4cfdf455f5ce74ce9795ec996db0e7`.
That is an identifier from the receipt, not newly recomputed consensus identity
or authenticated chain acceptance. Root independently reidentified the same row
and component hashes before any verifier execution.

All byte ranges below are **half-open offsets in the hex-decoded byte string**,
not offsets in JSON text or hex characters. Hex spelling may be decoded, but
no binary component may be normalized or replaced.

| Quantity | Exact JSON pointer / decoded-byte range | Length | SHA-256 |
| --- | --- | ---: | --- |
| VK | `verification-key.json` `/hex`, `[0,328)` | 328 | `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef` |
| Authorization `A` | `/transactions/6/transaction/payload`, `[8,385)` | 377 | `04beb1a621fc1c2a96da05e9eeda47cdc0b44c1b088ccdc677b908b93987a2af` |
| Proof `Q` | `/transactions/6/transaction/inputs/0/signatureScript`, `[2,130)` | 128 | `01b2cdc52131f4a612fb354fb5f86e0ad7c5c5f4a2e4146d18484514180a6b9b` |
| Ciphertext `C0` | Same payload pointer, `[385,570)` | 185 | `9d31bd540d3d80ba16a6e9400610fbddbf64656386024dcd9c5213c403d705ff` |
| Ciphertext `C1` | Same payload pointer, `[570,755)` | 185 | `7d015f1a2f0a102aae90f0c8c11d6dd478eec58c96603b05789c2084d70808c4` |

The signature script is 24,709 bytes and begins `4c80`; that push framing
identifies the 128 proof bytes above. The payload is 5,228 bytes. These checks
locate public components only; they are not VM validation. Ordered
`SHA256(C0 || C1)` is
`0b5b7654a35d68d12ab002c375a75b89cbea67ed20db3907ad3650f6728930c3`,
equal to authorization `[345,377)`. Reversing or independently sorting the
ciphertexts is outside this protocol. The selected metadata has count 9,
anchor `4c6661670094ebad2f8de5dd1ba1187eea213cf5bd0ff9b0cd96671a5d35fc7a`,
and fee 40,000,000 sompi; the proof comparison does not authenticate that anchor.

The fixed domain is
`d36fda2e668fa858ae852484e63ea6dabb259403901fd9c88a16e9c5b17e5baa`.
It comes from the rehearsal descriptor. Do not use the trial descriptor or
let either adapter select its own VK/domain.

| Source under `poc/shared-pool/evidence/2026-10-20-two-input-tn10/` | Git blob at source commit | File SHA-256 |
| --- | --- | --- |
| `rehearsal/descriptor.json` | `219aba5aae61aa09dcfba8cceb38181e8858b596` | `795eebdefb3eabea6446b3b1a9bd8c80e7f262fe32f7dfcf39efccbe7bbc07ac` |
| `verification-key.json` | `b2d4336e5b3083386df5de911d242ef3df42a3b3` | `4fd7dc563e4a1f843c99d5517485ba7664a7dcb69057784ca2fac066b20cddaf` |
| `rehearsal/chain-confirmed.json` | `1d3af74733bd743a393d8c81cea230b3aa8f3b1d` | `75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8` |

Only these three fixture files may be inputs. Do not read the sibling result,
trial, parameter/proving-key, wallet, participant, seed, truth or prediction
files. The original sources stay unchanged. Both future adapters read the named
original public JSON and select this fixed pointer directly; no new extracted
fixture is needed.

## Independent input identity

Each future adapter independently parses all 377 authorization bytes, checks
the exact framing/domain/profile and computes `h = SHA256(A)`. Then:

```text
x0 = unsigned little-endian integer h[0:16]
x1 = unsigned little-endian integer h[16:32]
```

For the frozen component bytes:

| Input | Decimal value, encoded as a string in JSON | Canonical 32-byte little-endian scalar hex |
| --- | --- | --- |
| `x0` | `"272864832706577085329381808629324299780"` | `04beb1a621fc1c2a96da05e9eeda47cd00000000000000000000000000000000` |
| `x1` | `"233458794052009950193355542024787113152"` | `c0b44c1b088ccdc677b908b93987a2af00000000000000000000000000000000` |

The integers are 128 bits and therefore embed exactly in BN254 Fr without
changing their value. No whole-digest reduction, host-endian conversion,
96-byte old classifier journal, decimal JSON Number or 14-input wrapper is
equivalent. The independent public-byte calculation and root's recount agree
on these strings/bytes; **no field decoder or verifier was run** in this pass.
The later reference must additionally compare its independently calculated
values to the existing v6 `Authorization::inputs()` result.

## Exact comparison paths — future adapters, not existing CLIs

The [existing binding contract](TWO-V6-BUNDLE-BINDING-CONTRACT.md) and
[source-selection note](OUTER-VERIFIER-SOURCE-SELECTION.md) remain unchanged.
The following are the only two intended verification paths:

| Reference | Candidate |
| --- | --- |
| Existing `poc/shared-pool` dependency graph, Arkworks 0.6.0. Checked-decode the exact raw VK and proof; prepare the decoded VK with `ark_groth16::prepare_verifying_key`; call `Groth16::<Bn254>::verify_proof` with the two independently derived fields. | Existing `poc/takeover` host dependency graph and `kpi-accelerated-bn254` path library, Arkworks 0.5.0. Checked-decode and validate the **same** exact raw VK, require IC arity 3, then call `Verifier::from_validated_program_key(&vk, K)` followed by `verify_inputs(Q, &[x0,x1])`. |

`K` is the pinned raw VK digest above. The constructor does not check the key
or authenticate the supplied `id`; the caller must establish exact bytes,
digest, checked point validation and IC arity **before** constructing it.
Never call `Verifier::pinned()`, `classify`, the PR37 key loader or the
private-note-chain 14-input wrapper. Do not call the v6 harness's `prove`
function: only its verification expression at `harness.rs:138` is reused as
the reference pattern, with a public decoded VK rather than a proving key.
The candidate can use the existing public
`kpi_groth16_comparison::proxy::hash` helper (`protocol.rs:18–20`) for plain
SHA256, and embed each independently parsed u128 through the field's existing
integer conversion. Do not assume new direct `sha2` or `ark_ff` host
dependencies: they are not declared by the current host manifest. Any required
manifest/dependency change is a stop under this unchanged-lock proposal.

Both adapters must use checked canonical decoding with complete input
consumption, on-curve/subgroup validation and byte-identical compressed
re-encoding. Report VK IC count and point-validation outcomes; require proof
A/B/C nonidentity as the generic helper does. Do not silently add a different
key acceptance policy on one side. Any uncertainty about an additional native
VK condition stays a named limitation; this comparison establishes the selected
retained key's agreement, not equivalence on every possible key/encoding.

Expected observations are **specified, not measured**: both canonical VK
round-trips reproduce the same 328 bytes; both proof round-trips reproduce the
same 128 bytes; both scalar encodings match the table; the reference returns
`true` and the candidate returns `Ok(())` on that same bound statement. No
mutation, adversarial fixture, second bundle or alternative example is part of
this protocol. A finite baseline pass would establish this retained case only.

## Source locks, dependencies and readiness

Use the **host workspace lock** for the candidate, not the classifier-guest
lock. Two Arkworks versions occur in `poc/takeover/Cargo.lock`; occurrence of
0.6 transitively does not change the helper's directly declared 0.5.0 types.
The existing host manifest also enables `kpi-groth16-comparison` features
`circuit` and `parallel` and includes many Kaspa/vProgs/zkVM dependencies.
Adding a source bin there does not remove those inherited package dependencies
or make its build a small pairing-only build.

| Source path at the scientific commit | SHA-256 |
| --- | --- |
| `poc/shared-pool/Cargo.toml` | `cfdc8e104c93e4575b1f2cf5d9b441566674b7b801856d18fc7aeb5ba50234f3` |
| `poc/shared-pool/Cargo.lock` | `13007a446f0d9561d50b18897b52a98c951584b2e6c7c721c95580287f5edc64` |
| `poc/takeover/Cargo.toml` | `9c4fdec4e6f70b70d8d5ebf4b9f9f56fbe3db2d257b18ee865d6e2d47d3f0e6a` |
| `poc/takeover/host/Cargo.toml` | `b0d062c0ef1eb1d8db31dac19177034b4c2134ee277a04d8f391dbec47209bf7` |
| `poc/takeover/Cargo.lock` | `6e2715918e0dfb9d1a9968021513065bc6653d8ae22d4b97d9b2d5e7d993e0ea` |
| `poc/accelerated-bn254/common/Cargo.toml` | `fe44804b55e4432784f60507b079986eb2f9c71f7bdfd99744b953340cef8833` |
| `poc/accelerated-bn254/common/src/lib.rs` | `ff8ef9d2ea1ef93440cadcfaac086ebafad33b2ae505ba3880b596b34660041e` |
| `poc/shared-pool/src/two_input/harness.rs` | `1bad02792f96632892487ec6af9aa94aa4fc2f14c6ecab28602f75174286583d` |
| `poc/proof-classification/protocol.rs` | `2e6ccf9442315a342dff72cf63bff0f3c4d8ce7de85af6ff57a8327d6d303d81` |

The lockfiles fix registry source/checksums and Git resolutions. Core effective
type/version selection intended by these manifests is:

| Component | Reference | Candidate |
| --- | --- | --- |
| `ark-bn254`, `ark-ec`, `ark-ff`, `ark-groth16`, `ark-serialize` | 0.6.0 | Helper/direct host dependencies 0.5.0; 0.6.0 also appears transitively in host lock |
| Pairing implementation | Arkworks 0.6.0 | `substrate-bn` 0.6.0, Git `22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509` |
| RISC Zero package | Not used as a verifier/VM by this comparison | Host lock `risc0-zkvm 3.0.3`, checksum `3fcce11648a9ff60b8e7af2f0ce7fbf8d25275ab6d414cc91b9da69ee75bc978`; no zkVM execution |
| Other relevant locked identities | Native dependency `01b532e8b553523216471682649693af92f0fd16` | Same native resolution; vProgs `f9b84a863a7c7c20586a9cf947550475e894f72e`; `risc0-binfmt 3.0.4`, `risc0-zkos-v1compat 2.2.2`, `risc0-bigint2 1.4.14` |

The complete lock bytes above, not this abbreviated table, define all locked
package identities. The future build must retain those bytes, target/toolchain,
source snapshots and its actual feature/cfg graph; neither adapter's final
effective graph or executable hash exists yet. Do not resolve newer branches
from the host manifest's `master` names: its committed lock resolves the native
source to the exact commit above. A required lock change is a stop, not a quiet
upgrade.

Metadata-only checks found the core 0.5.0/0.6.0 registry source manifests,
`risc0-zkvm-3.0.3` and the exact `paritytech-bn` checkout manifest present on
Forge. The checked registry source root lacks a `risc0-bigint2-1.4.14` manifest.
No conclusion is drawn about whether that target-specific package is required
for this host build or whether an offline build succeeds. Full cache closure,
available compiled artifacts, toolchain and feature unification are unqualified.
No Cargo command, metadata resolution or compiler was invoked to answer them.

## Later ownership, resources and evidence contract

If separately assigned, use a new isolated checkout at the scientific commit,
reserved as `/home/luke/projects/kpi-one-v6-compatibility-2026-10-22`.
The current batching reviewer would own only two proposed source files there:

- `poc/shared-pool/src/bin/one_v6_reference.rs`;
- `poc/takeover/host/src/bin/one_v6_candidate.rs`.

These are **future files**, not existing entry points. The intended builds use
their existing respective workspace manifests/locks, frozen/offline resolution,
a separately pinned existing toolchain, and separate target directories. No
existing experimental implementation, shared target cache or active checkout
may be modified. If this requires manifest/lock/dependency changes or unavailable
sources, stop and report that prerequisite. Do not install, fetch, choose another
backend or repurpose a parked wrapper.

Reserve future outputs only under that checkout's
`artifacts/one-v6-verifier-compatibility/`, with separate reference/candidate
build targets and one new result identity. No directory/file was created here.
Root controls any later resource release; lineage alone owns canonical commits.

Build CPU/RAM/wall needs are **unknown**: the adapters are unimplemented and
the inherited host graph is broader than the pairing helper. No existing build
budget or artifact is claimed. A proposed later **verification-only** ceiling
is one CPU, 1 GiB resident/cgroup memory, no swap and five minutes per adapter,
run sequentially, at most ten minutes combined. This is a conservative proposed
operational ceiling for one public VK/proof comparison, not a measured runtime,
proof-generation estimate or current execution authorization. Resource failure
means incomplete evidence, never successful cryptographic rejection.

Each future result must contain source/lock/adapter/executable hashes, actual
target/toolchain/features/cfg, exact fixture pointer/component hashes, all
canonical round-trip hashes, IC count, point-validation flags, the two scalar
values as decimal **strings** plus fixed 32-byte hex, ordered ciphertext digest,
and the actual verification return/error. Record timing/memory and any failure;
no retained secret or private witness is needed. A separate coordinator compares
both reports against the constants above and each other without changing either
input or result. Source metadata and specified expectations must be labelled
separately from observations.

## Failure and stop rules

- Stop on any source/lock/fixture/component hash drift, missing pointer,
  unsupported framing, wrong lengths/domain/profile, changed ordered ciphertext
  digest, unavailable required dependency or unqualified build identity.
- Stop on either decoder rejection, leftover bytes, round-trip disagreement,
  wrong IC arity, point-validation failure, wrong scalar bytes, or a verification
  result other than the specified reference `true` / candidate `Ok(())`.
  Preserve the exact stage/error; do not repair bytes or select the next row.
- No retry with another fixture, changed proof/VK, setup, backend version,
  permissive decoder, old built-in key, different fields, private data, native
  execution or larger experiment follows automatically.
- A pass establishes one retained bundle's host-side canonical and verification
  compatibility. It does not establish all malformed-input acceptance rules,
  guest target compatibility, a two-bundle pair, image/receipt interoperability,
  accepted history/current spentness, native backing, delivery, recovery,
  independent exits, cryptographic assurance or useful privacy.

## Primary source anchors

All project anchors are at the scientific commit above. Existing full pins for
`mod.rs`, `circuit.rs` and `protocol.rs` are carried by the unchanged binding
contract; their hashes were not reinterpreted as execution results.

- [v6 authorization and exact input conversion](/home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/mod.rs:89), layout/parse at lines 24–112 and bundle ciphertext lengths at 119–135.
- [v6 circuit authorization binding](/home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/circuit.rs:275), two digest limbs at lines 275–278.
- [v6 reference verification expression](/home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/src/two_input/harness.rs:138); the enclosing proving function is expressly not called.
- [generic candidate constructor and verifier](/home/luke/projects/kaspa-privacy-shared-pool/poc/accelerated-bn254/common/src/lib.rs:87), caller validation precondition, checked proof/arity/canonical decoding and pairing at lines 87–140.
- [candidate's existing plain hash helper](/home/luke/projects/kaspa-privacy-shared-pool/poc/proof-classification/protocol.rs:18), re-exported by `kpi_groth16_comparison::proxy`.

The independent source review and this protocol leave build/runtime release
pending. No executable comparison or scientific result exists yet.

The actual draft received independent semantic/schema/resource/readiness
review. Root independently reidentified the retained row, component hashes and
two field inputs; the final scalar hex strings each contain exactly 64 hex
characters. These are source/metadata checks, not cryptographic execution or
qualification of the future adapters.
