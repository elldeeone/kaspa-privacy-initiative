# One-v6 changed-input control

**PASS.** The same retained public key/proof accepted the original inputs,
then rejected **only x0 + 1**, returning the exact typed
`Err("invalid proof")` from the generic verifier's false-pairing branch.
One named test ran once; fixture, decoder, infrastructure, unexpected verifier
errors and panics could not count as successful rejection.

Owner `/root/next_direction_sources`; actual start **2026-10-22 12:00:42 UTC /
23:00:42 AEDT**, hard deadline **12:30:42 UTC / 23:30:42 AEDT**. Execution
finished **12:10:34 UTC**; evidence finalized **12:12:52 UTC**. No push.

## Frozen source and input

Exclusive worktree `/home/luke/projects/kpi-one-v6-input-binding-control-2026-10-22`,
branch `test/one-v6-input-binding-control-20261022`, source commit
`6fdc5fc61ddd9b33c254acbc47316348d7d84503`, parent
`acba8b04237e62a5bbc3eb93eb10faa1722a59ea`. Only
`poc/takeover/host/src/bin/one_v6_candidate.rs` changed: **175 append-only
lines, one `#[cfg(test)]` module**. All prior source bytes, helpers,
manifests, locks and fixtures remain unchanged. Source SHA-256
`841c845a78ab31ff2b73437ab4144a7fe823021ea9ed232331baf64f16c88b42`;
exact 11,221-byte Git patch SHA-256
`ea96db9c04cf3083a81cf5ca367f94fc7cf5e0f736d171da605f56f0c3845fc9`.
The existing focused reviewer accepted the diff before compilation.

Inputs are exactly the [previous result's](ONE-V6-COMPATIBILITY-RESULT.md)
three original public JSONs, fixed `/transactions/6/transaction`, domain and
ordered ciphertext pair. No fixture/auth/proof/ciphertext bytes were edited.
Checked canonical VK/proof decoding, full consumption/round-trips, IC3 and
proof nonidentity precede both calls to the same explicit-key verifier.

| Fixed component | SHA-256 |
| --- | --- |
| 328-byte VK | `9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef` |
| 128-byte proof | `01b2cdc52131f4a612fb354fb5f86e0ad7c5c5f4a2e4146d18484514180a6b9b` |

| Input | Exact decimal string | Canonical 32-byte LE hex |
| --- | --- | --- |
| Original x0 | `272864832706577085329381808629324299780` | `04beb1a621fc1c2a96da05e9eeda47cd00000000000000000000000000000000` |
| Changed x0 | `272864832706577085329381808629324299781` | `05beb1a621fc1c2a96da05e9eeda47cd00000000000000000000000000000000` |
| x1, both calls | `233458794052009950193355542024787113152` | `c0b44c1b088ccdc677b908b93987a2af00000000000000000000000000000000` |

The checked u128 increment and canonical scalar round-trips prevent a hidden
reduction/change of x1. Original return was `Ok(())`; changed return was
`Err("invalid proof")`, error type `&'static str`, classification
`cryptographic_rejection`. The pinned helper returns that exact string only
after the Groth16 equation fails; other errors fail this test.

## Actual execution and cleanup

Installed absolute Cargo/RUSTC **1.97.1**, native
`x86_64-unknown-linux-gnu`, existing locked host workspace and dependency
cache; no fetch/install/feature changes or target seeding. The command built
only the candidate release unit-test harness using `cargo test --frozen
--offline --release -j2 --target x86_64-unknown-linux-gnu --manifest-path
<worktree>/poc/takeover/Cargo.toml --bin one_v6_candidate --no-run
--message-format=json-render-diagnostics`. Actual compiler features contained
no `prove`, `cuda` or `setup`.

Produced harness: `target/x86_64-unknown-linux-gnu/release/deps/one_v6_candidate-2a7cd6e21be85bec`
under the receipt root; **2,231,560 bytes**, SHA-256
`bf9f71b75032c87a5b7162c751eca4f24a3b9721d805ce469f232563908247dc`.
Cargo recorded the exact executable with release optimization 3 and
`profile.test=true`.

The one execution used `--exact
changed_input_control::changed_first_public_input_is_cryptographically_rejected
--nocapture --test-threads=1`. Harness result: **1 passed, 0 failed**, exit 0,
empty stderr. Parent independently checked source scope, executable/compiler
identity, actual stdout/structured JSON, all four scalar encodings, exact
returns, fixture pins, command, limits and cleanup: **bounded PASS**.

| Unit (`kpi-one-v6-input-binding-…-120042.service`) | PID | UTC start–finish | CPU seconds | Peak bytes / cap |
| --- | ---: | --- | ---: | --- |
| `build` | 1192587 | 12:06:16–12:09:51 | 415.128414 | 2,567,946,240 / 4 GiB |
| `test` | 1206547 | 12:10:34.883–12:10:34.943 | 0.019186 | 4,800,512 / 1 GiB |

Build cap: **2 CPUs / zero swap / ten minutes**, deadline 12:16:16 UTC.
Test cap: **1 CPU / zero swap / one minute**, deadline 12:11:34 UTC.
Bubblewrap denied network externally, mounted source/dependencies read-only,
and exposed only the exact harness and three original public JSONs at runtime.
Fresh resource checks passed the existing sustained >=1% full-stall policy;
the pre-test intervals preserved **1 us then 0 us** full stall, zero swap/OOM
growth and **21,456,293,888 bytes** conservative unreserved headroom. No
resampling or zero-PSI criterion was introduced.

Both units are inactive with empty/absent cgroups; all **259 build / 4 test
sampled PID/start identities** are gone and reservations released. Source is
clean at `6fdc5fc6`. The original compatibility worktree, binaries and receipt
manifest were independently rehashed unchanged. This single host control is
not a guest/native/aggregate/state/settlement/exit/privacy qualification.

## Stable evidence

Receipt root:
`/home/luke/projects/kpi-orchestration/2026-10-22/next-direction-sources/one-v6-input-binding-control/attempt-20261022T120042Z`.
Manifest SHA-256
`a0d4318992f04f62a162f02d43867408ab8569cad81631c340687414009d3501`
(44 leaves; 2,841,667 bytes; target/cache trees excluded, harness hash retained).
Test stdout SHA-256
`56605947673cf6428b7449d6c5eb9343013e84c554f2fe23be56d607bcf8a98d`;
structured JSON SHA-256
`46ef61c7471898ca21e3ea3ce380f62a7b6183b9291eaa8c0a421f73d16f1219`.
Raw receipts retain exact toolchain/fixture/source/feature identities, commands,
resource samples, returns, scalar comparisons and terminal cleanup.

## One substantive next obligation — recommendation only

Implement an **ordinary host version of the unchanged two-v6 binding gate**
before guest integration: one additive host bin containing the relation and
one focused accepted-case test, using the same checked-key generic verifier.
It must implement the complete [binding contract](TWO-V6-BUNDLE-BINDING-CONTRACT.md)
(SHA-256 `d16ec7b288cc93473cbeffd8af0c0071a06f575552522572f6ccd64b97a03e44`):
two valid inner statements; narrow SPEND/common-anchor restrictions; four
distinct active nullifiers; hidden bijections preserving multiplicity and each
commitment/ciphertext pair; checked aggregate fee; exact 1,088-byte public
projection and 42-byte journal. The
[native boundary review](../architecture/TWO-V6-BOUNDARY-CROSS-REVIEW.md)
continues to distinguish `SHA256(journal)` from the public-projection digest.

**Accepted-case execution is not ready:** a second independently valid,
already-public ordinary zero-payout SPEND bundle with the fixed domain/VK,
**count 9 and anchor `4c6661670094ebad2f8de5dd1ba1187eea213cf5bd0ff9b0cd96671a5d35fc7a`**,
and active nullifiers disjoint from row 6 has not been identified/qualified in
this allowed input scope. Its complete auth/proof/ordered ciphertexts and the
partition witness must be frozen, with independently expected public/journal
bytes. Sequential receipt rows must not be presumed to meet that contract.
No sibling/private input was searched, replacement selected or bytes/proof
manufactured here.

Expected future observations: both inner proofs accept and the complete host
relation accepts that frozen witness, reproducing the independently fixed
public/journal encodings without per-operation public grouping handles.
Once that precise input prerequisite is resolved, proposed ordinary limits
are **2 CPUs / 4 GiB / ten minutes** for a release harness build and **1 CPU /
1 GiB / one minute** for one contract test, zero swap and network denied;
fit remains unqualified. This is a recommendation, with no further code,
compute, guest/proof generation or execution authorized by this note.
