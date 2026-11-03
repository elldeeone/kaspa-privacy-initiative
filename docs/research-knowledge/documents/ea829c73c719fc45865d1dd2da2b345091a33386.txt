# Independent chunk-transport review

Status: **closed: corrected-source, current controls and actual-roundtrip artifacts ACK**.
This is an additive review of optional public-byte transport. It changes no
capsule authority, loader, financial rule or previously closed packet. The
reviewer has not read actual PK/backup/witness bytes or run a proof, VM or
network request.

## Authority and exact source

Reviewed `poc/recovery-portability/chunk_public.py` SHA256
`8cbe9d2ce5d78297cb69e65b748b031835a1b7fd0e981f15ef73111b6d3825bc`,
using frozen `capsule.py`
`88e13b484f9fd6c867a54b58610122ddc09693544f7a9ee20a1cd071737e4f56`.
The plan/API SHA is
`1f310b4c6657c32a25f30094ffd5080f4b884bb018a568f6c9219b2f63d6b76e`;
the primary-source note SHA is
`fda8f4f25f2d53b3a80283d44bc7467300a58eec1227710b2af2617b45f1eddf`.
The source note's external research was not repeated by this code reviewer.

The first source was subsequently corrected to
`c713a4871079acd040f5c434ceed47c4d6f71885c8e5256199a86488a5f724aa`.
Its only change materializes `forbidden_paths` and `must_be_absent` once before
metadata/public access. This prevents a one-shot iterator being consumed before
the manifest guard. The full diff/hash was reviewed before fresh actual runs.

The parent checked the same defect's scope and found repeated exclusion use in
the outer capsule, pack and HTTPS APIs. Each current entry now freezes the
iterable before metadata/public access. `SOURCE-SUPERSESSION.json` maps all four
old hashes to exact retained executed archives and separately records current
hashes; every pair was independently rehashed. Historical manifests/lists and
archival source bytes remain intact. Their references to old production paths
describe those historical versions, not the new current bytes.

| Current entrypoint | Current SHA256 |
| --- | --- |
| `capsule.py` | `ba6fba072eb00e54297e47473c61ce7ef2230356183c9dfd60d0a8741cc492d2` |
| `pack_local.py` | `30bb75aef5a2dea57fdfc17b23c601c766dffe7e23f6ea4a0d336c2bbe89b218` |
| `https_mirror.py` | `be1b5046f07293d5e42cfbb975879966109080b0727c8096530d6ded394664d2` |
| `chunk_public.py` | `c713a4871079acd040f5c434ceed47c4d6f71885c8e5256199a86488a5f724aa` |

Each of the first three diffs adds exactly one tuple-freeze line. Final actual
chunk evidence must select both the current chunk tool and current capsule
helper; prior no-backup runs remain separately versioned evidence.

Both pack and restore require externally supplied positive complete length and
raw SHA256. The parsed index must equal those pins before any chunk is opened.
Its own digest is explicitly a hint, not authority. The caller must obtain those
pins from authenticated installed role selection/manifest, not the same mirror.
The adapter accepts opaque public bytes: a role/domain/VK substitution changes
the selected whole identity; actual Ark decode and VK/query checks remain the
existing cold loader's responsibility.

Each canonical index is bounded to1MiB and has exact fields. The derived sequence
requires every index, offset and length once, fixed1GiB chunks except the final
remainder, and a basename generated from the index/hash. Repeated hashes at
different positions are allowed. No archive, URL, executable or downloaded
import is introduced. All chunks may satisfy a malicious replacement index and
still fail the independently selected complete-object SHA.

## File and failure boundary

The frozen core's component-wise directory-FD walk, no-follow opens and
metadata-before-content-open inode guard protect source/index/chunk inputs.
Forbidden metadata is collected before public reads; opened metadata is checked
again before bytes. Existing restore destinations are rejected without a content
open, and output parents reject symbolic-link components. Fresh output and
exclusive temporary creation prevent replacing an existing destination or
reading an output alias as input.

Restore streams1MiB buffers, authenticates each candidate's exact bytes and
metadata, and advances the whole hasher only on success. Failed candidates seek
and truncate to the current chunk boundary; a fallback cannot retain a corrupted
prefix. It verifies final length/SHA before fsync/read-only mode and atomic
no-clobber hard-link publication. Incomplete candidates remove the owned partial
file. Pack verifies its whole source before publishing the index and removes
owned output on failure. Data buffers are bounded; index/receipt metadata grows
with the number of chunks rather than object byte length.

The trusted host/release-owner mutation assumption remains explicit. These
checks do not authenticate a hostile kernel or a writer mutating already
returned files. Existing loader authentication must run again over its owned PK
buffer before private input. Atomic publication means no partially authenticated
object at the final name, not an everlasting immutability or availability claim.

## One-shot exclusion defect and correction

The independent second pass found that the first source consumed
`forbidden_paths` while building metadata exclusions, then passed the same
iterable into `read_public` for the manifest. A generator was exhausted on that
second pass. A manifest alias to a forbidden inode could therefore be opened.
Normal CLI list inputs and the no-backup actual public-only roundtrips did not
exercise that bug; their complete-object hashes remain evidence of those bytes.

The reviewer retained a failing one-case regression against the exact frozen
first source at `iterator-guard-01`. The fixture contains canonical public JSON
and ordinary public chunk bytes, never a seed or real PK. A Linux IN_OPEN watch
was positively calibrated on the same hardlink inode. The expected failure
observed an actual content-open of the forbidden manifest alias. It used three
public source/test files in a new namespace, requested/observed1CPU/1GiB/swap0;
the test failed in0.001s with13.3M displayed peak. No private input or PK was read.
The failed test is retained as zero successful controls.

Crossed messages caused the author to retain its own old-source reproduction
before learning this independent one had completed. They reproduce **one
defect**, not two distinct controls. The four-line production correction
materializes both path iterables before any metadata/public read. The author
ran its regression with the complete17-case suite on the corrected source;
the16 earlier cases are repeats, not16 new controls. This reviewer inspected
the frozen source/result without another execution. Root also requires fresh outputs for
both actual public roundtrips under the corrected source. Earlier snapshots,
negative results and no-backup roundtrip evidence remain intact.

## Controls and actual-roundtrip review

Initial test source `6ec50f48…` defined15 public synthetic controls, including
actual production CLI use, calibrated kernel IN_OPEN alias guards, fallback,
truncation/trailing bytes, reordered positions, self-consistent substitution,
repeated hashes, unsafe paths and no-clobber/error cleanup. The independent
review requested an explicit missing-final-chunk negative. The initial15 had
already passed when that request arrived, so the author preserved that run and
ran only the added negative separately. That test-source snapshot
`2bce0c4e037c2b6d82c437e042f884f8727aa5502b8843edc300042e653888a7`
differs only by that method. There are16 distinct controls, not31 rerun passes.

Both five-file frozen source sets were independently rehashed. Logs
`137b9c82fbe1cb14f1da27e841a34dd6c71f4385943daa309f246c82d4cc5236`
and `95dbddcbac4e6228cb78a077cb06d2614e4087ad1998c33948bb0816d6ee9295`
retain15/1 passing cases in0.104s/0.002s respectively, observed4CPU/4GiB/swap0
and27.8M/17M memory displays. The namespace mounts only selected public source
and system files. Manager cleanup reports inactive/dead/not-found/PID0; direct
kernel process observations remain null. These are the author's retained
executions inspected by this reviewer; no tests were rerun here.

The corrected-source suite retained17 PASS in0.114s, displayed27.8M peak and
swap0 with observed4CPU/4GiB caps. All five snapshot pins matched. Its log SHA is
`257948b445e8e7094491b44aba4ba1f9f7e5141adc0b9891f5c57c469929bb05`;
test source is
`86a0a89d169eeb194d3d7c181e0f9bd43d2d312b977b96628ef4ffc532480758`.
The17 distinct cases include one corrected generator-exclusion category.

The reviewer additionally authored three outer-boundary regressions in
`test_outer_iterator_guards.py`, SHA256
`64a2d7eefdd1fd9ffc3c3b577b04a5c113b03d2f2224f0ed676c3a711ffd1332`.
Stage and pack use actual production APIs and calibrated hardlink-sentinel
IN_OPEN checks. HTTPS uses fake byte transport and a semantic-staging callback
to check immutable exclusions reach both recognition/spend delegates. That case
is deliberately a propagation control, not TLS, semantic or native acceptance.
The author executed these with the selected current public sources; this
reviewer did not execute them. The retained current suite passed 46 cases in
4.713s with nine exact source snapshots, 32M displayed peak and swap zero.
Its log SHA is
`52a1976376611491ff5deb2c408a93612e9ac6c24f2afef6f021026042de5b2b`.
Of those cases, 43 existed before these three added boundary controls. Earlier
executions are not summed into a new distinct-case total. Loopback HTTP cases
remain local transport tests; no external network/TLS/provider result is added.

Actual compact/wide roundtrips are allowed only under the parent's separate
4CPU/4GiB/swap0 release, using exact independent manifest PK lengths/hashes and
the production1GiB rule. Restore must have original producer paths absent and
no actual backup/main private history mounted. Successful reconstruction
establishes recovered selected bytes only: no parameter decode, proof,
currentness, accepted payout, provider independence or retention follows.

The issued controller source
`e3e7e8f8bb8f52f671af071ba66c50daebbcf3fb7aa46ccf91eb9d37d8ef2cba`
was reviewed before actual launch. Each restore namespace mounts only the two
selected transport sources, read-only public chunks, base system files and its
fresh writable output. It unshares network/clears environment and explicitly
checks that the original producer file, cache parent and repository are absent
before reading the manifest. Pack/restore share the caller's independent whole
anchor; a separate output streaming readback repeats that length/SHA check.
The complete producer path and operational command are not exported here.
The controller enforces observed4CPU/4GiB/swap0. No material issued-scope blocker
was found. This source ACK is not an observed execution result.

Small public role manifests independently observed by this reviewer bind the
prospective actual roundtrips:

| Role | Manifest SHA256 | Whole bytes | Whole SHA256 |
| --- | --- | ---: | --- |
| compact2 | `f27a806928b5c2409d4e4c5428a75deabef6ecf9601b60889667e90363f26043` |1,307,894,256 | `c8d72c6eae9d03ce22e350bb9d0c616fc8e1d2a8b4f2b0d748cc0336726b11a4` |
| wide32 | `b1f0e93bf153c423c669524318efe276917a902d4e9e6b250fba564face94149` |2,892,421,872 | `05639b54302e9f568dbdbfb68bc7e6c5760bea5d96ffe09d087b1f836447f83d` |

Only the small manifest JSON files were read by this reviewer, not PK bytes.

## Final current-source roundtrip closure

`actual-roundtrip-03` binds the current chunk tool `c713a487…`, capsule helper
`ba6fba07…` and unchanged controller `e3e7e8f8…`. Their three archived/current
source pairs were independently rehashed. Its selected anchors match the small
public manifests above. Both raw chunk indexes were independently checked for
exact whole identity, contiguous production1GiB positions/lengths and expected
two/three chunk counts. Pack, restore and separate output readback all report
the selected complete length/SHA. Each restore reports three original-file,
cache-parent and repository absence probes before manifest/chunk reads.

| Role | Chunks | Pack seconds | Restore seconds | Separate readback seconds |
| --- | ---: | ---: | ---: | ---: |
| compact2 |2 |2.296 |1.795 |0.636 |
| wide32 |3 |4.473 |11.561 |2.284 |

The complete current run took23.106s; retained aggregate systemd CPU is13.268s.
Observed caps are4CPU/4GiB/swap0. Displayed peak4G includes file cache and is not
a Python-heap measurement. Manager cleanup is inactive/dead/not-found/PID0;
direct kernel process observations remain null. No private inputs, prover,
native validation, parameter decode or upload was involved. Earlier actual01
and02 remain versioned historical no-backup observations; the current claim is
bound to actual03 and repeated positives are not new independent experiments.

Exact actual03 result SHA256:
`598728a939d84b0296f980e8180b964b6b43fd848e9390155aaf10df83dd6ce9`.
Execution receipt SHA256:
`39c82554b17932b723a2481c0bef93086715688351ad61c1fc31e0e57d2d829a`.

The final [chunk publication manifest](../../chunk-transport-01/MANIFEST.json)
SHA256 is `88018c6bddf340daef4d515c569319437c2313b86771d994dfea9c2881277edc`.
All79 regular payloads/628,301 bytes and its exact81-path list were independently
rehashed. The list SHA is
`84704c1902ee79ba6f56a0904d01ee0affd0d6d6339927ef1ab62ac43fc66e3c`.
No actual PK byte was read by this reviewer. There is no remaining material
source/result inconsistency in this scoped review. Same-host offline transport
still does not establish provider independence, retention, setup honesty,
accepted-chain/current UTXOs, permissionless exits or production safety.
