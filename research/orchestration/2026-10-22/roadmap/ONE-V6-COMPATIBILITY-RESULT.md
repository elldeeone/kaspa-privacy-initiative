# One retained v6 bundle: host verifier compatibility result

**PASS for the one frozen public bundle.** The Arkworks 0.6 reference returned
`true`; the checked Arkworks 0.5/substrate-bn candidate returned `Ok(())` on the
same VK, proof and two authorization-derived public inputs. Their complete
reported fixture, canonical and scalar observations agree. Each adapter ran
once. This establishes this retained host case; guest execution, a two-bundle
relation, a native receipt and privacy remain unqualified.

Owner: `/root/next_direction_sources`. Conditional execution release began
**2026-10-22 11:41:13 UTC / 22:41:13 AEDT**. Dependency ownership was explicitly
handed off before access. Builds ran **11:46:43–11:50:33 UTC**; verification ran
**11:52:43–11:53:17 UTC**. Documentation base observed after execution was
`3eefab3dc61801cc44d505c700820779abccbf5a`. Report finished **11:57:22 UTC /
22:57:22 AEDT**. No push occurred.

## Fixed statement and observed checks

The unchanged [protocol](ONE-V6-VERIFIER-COMPATIBILITY-PROTOCOL.md), SHA-256
`b01cd6bbb4b0d9f097277e5986b0b4de7001b97896f5f74f3777d1ff50919932`, selects
`/transactions/6/transaction` from the original public rehearsal
`chain-confirmed.json`. The two adapters read only its three named original
public JSON files; no extracted fixture or alternate row was used.

| Observation | Reference and candidate |
| --- | --- |
| VK | Same 328 bytes; checked full consumption, canonical re-encoding, on-curve/subgroup checks; IC count 3 |
| Proof | Same 128 bytes; checked full consumption, canonical re-encoding, on-curve/subgroup checks; A/B/C nonidentity |
| Authorization | Same 377 bytes, fixed domain/profile and ordered ciphertext-pair digest |
| Ciphertexts | Same ordered pair of 185-byte values, with original pairing preserved |
| VK identity flags | All seven reported flags false; no extra one-sided key policy imposed |
| Existing v6 inputs | Reference independently matched `Authorization::inputs()` |
| Actual verification | Reference `true`; candidate `Ok(())`, using `from_validated_program_key` then `verify_inputs` |

Raw component SHA-256 identities are VK
`9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef`, proof
`01b2cdc52131f4a612fb354fb5f86e0ad7c5c5f4a2e4146d18484514180a6b9b`,
authorization
`04beb1a621fc1c2a96da05e9eeda47cdc0b44c1b088ccdc677b908b93987a2af`
and ordered ciphertext pair
`0b5b7654a35d68d12ab002c375a75b89cbea67ed20db3907ad3650f6728930c3`.
Exact fixture-file and individual ciphertext hashes remain in both JSON
outputs and the protocol. Canonical byte equality is supported by checked
round-trips and matching complete-byte hashes; outputs do not dump raw proofs.

| Input | Observed decimal string | Observed canonical 32-byte LE hex |
| --- | --- | --- |
| x0 | `272864832706577085329381808629324299780` | `04beb1a621fc1c2a96da05e9eeda47cd00000000000000000000000000000000` |
| x1 | `233458794052009950193355542024787113152` | `c0b44c1b088ccdc677b908b93987a2af00000000000000000000000000000000` |

Root independently checked both executable/compiler-artifact identities. The
existing diagnostic reviewer independently compared final fixture, canonical
and input objects, actual returns, stdout/stderr hashes, execution paths,
source identity, limits and cleanup: **bounded PASS, no mismatch**. These are
finite checks of this instance, not equivalence over every key or encoding.

## Actual source, dependencies and toolchain addendum

Scientific worktree:
`/home/luke/projects/kpi-one-v6-compatibility-2026-10-22`, branch
`test/one-v6-verifier-compatibility-20261022`, immutable source commit
`acba8b04237e62a5bbc3eb93eb10faa1722a59ea`, parent
`ec6aa15d586bcc8a90f7232b433fd48d8c73d509`. The source patch SHA-256 is
`dc10fbae05e6d901c7b401d58e2f0df8d333acfd20f16983320b45d40a4c79ec`.
Both adapter files, manifests, locks and three fixtures matched before and
afterward; Git status stayed clean. No source, lock, feature or fixture repair
was made during execution.

| Adapter source | SHA-256 |
| --- | --- |
| `poc/shared-pool/src/bin/one_v6_reference.rs` | `ab513355d0d8e893d3742821a16fb3001ea0e9bc8ee7d10e86c44e50c270585d` |
| `poc/takeover/host/src/bin/one_v6_candidate.rs` | `75f424c68de986b4059e0caf5b392f2bda6cf91a2f120e1c21ac7de2ef80ba06` |

**Explicit toolchain addendum:** root selected the already installed absolute
**Rust/Cargo 1.97.1**, replacing the earlier unexecuted 1.91.0 proposal. No
toolchain installation occurred. Both builds used
`/home/luke/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin/cargo` and
matching absolute `RUSTC`, explicit target `x86_64-unknown-linux-gnu`, release
optimization 3, and separate private target directories. Cargo SHA-256 is
`828980723df339d62434390e9fb8ef8831036583343ae2316b7ab5646b5c1953`;
rustc SHA-256 is
`d3a664c970a9fd8361b64194861bebc1ae37b9054e5ee3400dc1c9e691797eea`.

Both locked fetches and frozen/offline metadata closures had already passed in
the separate dependency-owner scope. Its handed-off registry/Git cache stayed
read-only, mounted into this run's exclusive Cargo home. Existing metadata
graphs were reused; no duplicate resolution/fetch was run. Reference Arkworks
is 0.6.0; candidate direct Arkworks is 0.5.0 with substrate-bn
`22108fe8c6ea1ebc1358fc4fd6854a6bf46e3509`. Existing native/vProgs source
resolutions remain `01b532e8b553523216471682649693af92f0fd16` and
`f9b84a863a7c7c20586a9cf947550475e894f72e`. Candidate RISC Zero SDK is 3.0.3,
with client/bonsai/std defaults. Normal/build reachability and actual compiler
artifact feature lists contain no `prove`, `cuda` or `setup` feature. Full
effective package/feature/profile identities are retained with Cargo JSON.

The reference inherited a RocksDB C++/bindgen build and local compression
libraries. Native tools/libclang and bundled source assets were present; the
RocksDB missing-submodule trigger and RISC Zero prove-only asset-download path
were not activated. The existing covenant and vProgs build scripts generated
local OUT_DIR constants. No guest, setup or proof was run.

## Executables, supervision and cleanup

| Exact executable | Bytes | SHA-256 |
| --- | ---: | --- |
| `reference-target/x86_64-unknown-linux-gnu/release/one_v6_reference` | 9,081,616 | `6061da1237501301618c41ec2690b460d17ae1c865db76888e2f48e50f67afa9` |
| `candidate-target/x86_64-unknown-linux-gnu/release/one_v6_candidate` | 1,675,000 | `612e33cf0e28eb3902c34148fe6743ae926f4fdfd71134f51a4059e263146cf8` |

Paths are relative to the raw receipt root below. Compiler-artifact JSON
identifies each exact executable and ordinary release profile. Builds used
only `cargo build --frozen --offline --release --target
x86_64-unknown-linux-gnu --manifest-path <existing manifest> --bin <exact bin>
-j 8 --message-format=json-render-diagnostics`. No tests or other source
binaries were executed.

| Stage / unit suffix (`kpi-one-v6-…-114236.service`) | UTC start–finish | CPU seconds | Cgroup peak bytes | Outcome |
| --- | --- | ---: | ---: | --- |
| `build-reference` | 11:46:43–11:49:16 | 1117.572642 | 5,666,672,640 | exit 0 |
| `build-candidate` | 11:49:25–11:50:33 | 500.096721 | 3,423,768,576 | exit 0 |
| `verify-reference` | 11:52:43–11:52:45 | 0.019278 | 5,578,752 | exit 0; empty stderr |
| `verify-candidate` | 11:53:15–11:53:17 | 0.017452 | 4,792,320 | exit 0; empty stderr |

Builds were sequential, each capped at **8 CPUs / 8 GiB / zero swap**, within
the single **11:46:43–12:06:43 UTC** build window. Verification was sequential,
each capped at **1 CPU / 1 GiB / zero swap / five minutes**, within the
**11:52:43–12:02:43 UTC** combined window. Bubblewrap unshared network and
cleared the environment; actual Cargo/compiler network namespace isolation
was observed. Builds mounted source/toolchain/dependency sources read-only;
only exclusive outputs and Cargo bookkeeping were writable. Each runtime
sandbox mounted the exact binary and only the three original fixture files.

All four units were stopped and audited: MainPID/ControlPID 0, empty/absent
cgroups and all **609 / 195 / 3 / 4 sampled PID/start identities** absent.
The reservations are released. Source/fixture hashes and clean status matched
at the final audit. Adapter-internal single-run elapsed times were
0.005139987 s and 0.005659156 s; these observations are not a benchmark or a
guest/proving cost estimate.

### Resource-monitor correction, with original evidence preserved

Before verification, the controller incorrectly classified any full-memory
stall growth as failure. No frozen protocol required that stricter rule.
Root confirmed the existing policy: escalate **sustained full-stall >=1% over
consecutive fresh 10-second intervals**, sustained swap-out/OOM or inadequate
headroom; isolated excursions are retained. The same samples were
10.004307189 s / 0 us and 10.004323658 s / 103 us: **0% and 0.00102955%**,
with zero swap-out/OOM growth and **21,469,011,968 bytes** conservative
unreserved headroom. They pass that policy.

The original raw false flag, correction receipt and both controller versions
are retained. No capacity resampling, adapter/source/proof/fixture change or
cryptographic criterion adjustment occurred. This was an operational
instrumentation correction before either one-time verification.

## Evidence receipt

Raw root:
`/home/luke/projects/kpi-orchestration/2026-10-22/next-direction-sources/one-v6-compatibility/attempt-20261022T114236Z`.
`receipt-manifest.json` SHA-256:
`805333d53cce1bd6beaebd108844aa4f7037ee480312306568e79fc42c8a988e`
(65 leaves; 3,740,840 bytes). Compiled target/cache trees are excluded from
that log manifest; both final executable hashes are retained separately.

| Receipt | SHA-256 |
| --- | --- |
| `verify-reference/stdout` | `4e19c3e3a1a4e6aafc2538607d730641b2230455bb5601d4242c5e9c24c7e5f5` |
| `verify-candidate/stdout` | `d1ee9dc17a5a46600aa6002c263dc8fc1f3333180f52fa92f504e3ed6a83dbd8` |
| `comparison.json` | `5dd5665759efaeebe8fdd9e0fa6578652d534847f289dad81c03dd904d22cfed` |

Primary receipts include per-stage commands, unit/cgroup/child observations,
Cargo JSON, binary identity, stdout/stderr, cleanup, full feature identities,
source-before/after records and `terminal-audit.json`. The external receipt,
not expected constants printed by the binary, supplies actual provenance.
Neither source-supplied transaction ID nor historical chain acceptance was
recomputed or authenticated.

## One next executable obligation — proposal only

**Check that the candidate rejects a changed public input for this same
proof.** The baseline acceptance now makes a single deterministic rejection
control useful before implementing the desired
[two-v6 relation](TWO-V6-BUNDLE-BINDING-CONTRACT.md) or crossing the
[native interface](../architecture/TWO-V6-BOUNDARY-CROSS-REVIEW.md).

Use the same pinned row 6, domain, canonical public VK/proof, source helper and
three original JSON files above. Preserve the original inputs as the positive
control, then call the exact same checked-key generic verifier with only
`x0 + 1 = 272864832706577085329381808629324299781`; x1 is unchanged. This
fits without reduction. Freeze expected results in advance: original
`Ok(())`; changed input rejection, with the actual error recorded. No auth,
proof, ciphertext or fixture bytes are edited, and no new proof is generated.

Smallest proposed code scope: one named test module appended to the candidate
adapter, using its existing private preflight/canonical helpers; production
behavior, manifests, locks and baseline protocol stay unchanged. Output scope:
one structured receipt recording exact original/changed scalar bytes and both
actual returns, plus source/executable/resource/cleanup provenance. The test
must not catch arbitrary infrastructure failures as successful rejection.

Proposed future limits: **2 CPUs / 4 GiB / no swap / ten minutes** for the
ordinary release test build, then **1 CPU / 1 GiB / no swap / one minute** for
one named test execution. Build fit is unqualified; reuse the installed
1.97.1 toolchain and locked public dependency cache after a fresh ownership
and capacity release. This proposal allocates no compute and authorizes no
code or execution. A rejection would qualify only that one changed input;
two-bundle guest semantics, receipt/image binding, current spentness, reserve
transitions, delivery and independent exits remain separate obligations.
