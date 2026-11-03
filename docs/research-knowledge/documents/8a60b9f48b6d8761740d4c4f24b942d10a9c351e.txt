# Fresh private cashout source review

Reviewer: `/root/private_exit_review`. Scope: new prover, keyless native helper
and owner wallet core for ADR-0053. This is source review, not a cryptographic
audit, chain result, privacy qualification or permission to fund a public fixture.
The reviewer ran no build, test, decoder, native VM, synthesis, setup, prover or
RPC, and read no actual owner seed/private witness/proving-key artifact.

**Active execution amendment:** ADR-0054
`2319c8d3cbd59f2b59b1087f947f796e852a43c02d13a09573ce0695aaaffff4`
and execution contract
`50108857334661be2ace5a8ec70d0a751cd413d90d667cd090971048285569ae`
supersede the earlier special executable-FD/loader launch plan after automated
screening stopped a parallel worker. Current work uses ordinary SHA256-selected
0500 executables in private0700 release directories, read-only mounts and a fixed
clean environment. It explicitly trusts the host/release owner not to mutate
the selected inode during an operation, and makes no malicious-host/writer
defense claim. No screening workaround or host-policy change is authorized.
Earlier launch sources/probes below are retained historical evidence, not the
active execution design. The protocol, parameter-before-witness ordering and
fixed private-output boundaries are unchanged.

Current closure: selected prover/parameters, native helper, wallet software and
the complete four-body local native rehearsal are artifact-reviewed below.
Confirmed funding, independently acquired current network state, new cold-owner
proofs and confirmed owner payouts remain separate live-trial gates.

## Authority and scope

- ADR-0053: `dd77b305df860011ae6608e312eb09396f2c6585fa17225646bdb8f181fa9b58`.
- Shared contract: `16679d12132ca437624e0878dc5fc5140889d56e5f376d4459b362bb86b9df94`.
- Earlier checkpoint: `2ee3e0850a277f2d4a2f512da67683540be01958`.

The selected route is directly funded Alice whole note → P0 two 60M claims →
one continuing full private cashout → one terminal private cashout. Actual fees,
ordinary change and public payouts must reconcile to the one source. Full local
terminal rehearsal precedes funding. Cold owners must acquire public history
again and produce new proofs from their own backup; resident rehearsal exits
are excluded from their inputs. Network acquisition, trial creation, transport,
release and publication are reviewed by the other adversary.

## Prover template source ACK

`prover/TEMPLATE-SOURCE-FREEZE-01.json` SHA256:
`b207222c4f7dda52a88e8682fed5af8eec521ac1ac678ab1077128ffee74d3ec`.
All 17 pinned files were independently rehashed against current bytes.

The circuit and exact-SHA source are byte-identical to the previously reviewed
Auth528 relation. The library diff changes only its header and exported modules;
the public template still has the old AA literal and is unselected. Trial
authority rejects before shape input/RNG or cold parameter/witness access.
Only the future private clone's D array and selected public trial identity may
change at materialization; final parameter pins are selected separately.

The new private parser enforces actual objects at root/input/output boundaries,
raw duplicate/unknown-field rejection, exact lower-case hex/widths/arity, bounded
u32 positions and a generous bounded read. Its errors discard private parser/IO
details. An intermediate Serde array-as-struct alias was identified and closed
with map-only visitors; raw duplicate validation was preserved.

The parameter authority is acyclic: approved fresh setup → canonical public
manifest → compiled cold client → trusted wallet software selection. A runtime
sidecar, caller digest or matching embedded VK cannot authorize decoding. The
client compares compiled D/core/build/lock/toolchain identity, authenticates the
entire exact owned parameter buffer before its sole trusted uncompressed decode,
requires exhaustion, drops encoded bytes, and checks the extracted VK and actual
query lengths. Manifest schema objects reject sequence aliases. Canonical compact
bytes have no newline, making raw and canonical JSON SHA256 identical.

`prove` emits one public readiness identity after these checks and before
opening/reading the inherited witness FD. One private request produces a locally
checked genuine proof, then only proof/Auth/VK and public parameter/source
diagnostics. Fixed error codes and a fixed panic hook prevent private assertion,
path, note or witness-hash output. No hosted service or setup switch is exposed
by the cold executable.

The separate fresh setup executable delegates the unchanged circuit exactly
once to the standard Arkworks 0.6 generator. It retains that exact CS reference,
reads actual finalized counts after QAP/setup, checks query dimensions and drops
the retained CS before serialization. Inspection of official generator and
reduction source found no relation change from this transparent observation.
It serializes a fresh key without overwrite, fsyncs, then independently reads
back the same newly created descriptor to compare complete length/SHA256 with
the streaming hash. Public reports omit private shape/path/hash and owner links.

The prospective controls include ten private parser tests, six parameter tests
with fresh independent tiny Arkworks keys, and eight actual-process unread-pipe
checks. Their source was reviewed; execution/results are not claimed here.
Actual fresh-domain clone/build, setup, selected manifest and genuine cold-owner
proofs remain separate evidence gates.

The actual fresh source map was subsequently checked without reading its private
profile or witnesses. `SOURCE-MANIFEST.json`
`811bf4ef97603f3f37e1d342274e42e1ba241c1590b2027440ca2bc50e4f0a62`
contains exactly the 17 reviewed members. Only the D array and seven-field public
trial selection changed; the other 15 files are byte-identical. The fresh source
library is `833f4e953493a53d6e3d6fa125e6c8b02bd44e787c99273ea15032eb243b8ef2`.
Its public trial D is
`caf85e3b34cd9b426559f57bb1ab647835c5dfaf255d17bf3d1291c0f7408470`.

Build runtime freeze
`6df075a218684563a428844b6189af1080c951ce93b635a3054d1395355de712`
was reviewed before artifact closure: all 23 public/source inputs matched before
and after. The namespace mounted only source, compiler, registry, compile cache
and output, with no owner profile, witness or PK. Requested limits were 8 CPU,
12 GiB and zero swap; network was unshared. The 22 unit tests passed, including
only tiny independent test setups/proof. Actual CLI controls passed 8/8, retaining
all 294 known public-canary bytes unread, with `parameters_unselected`, no ready
event and no proof output. CLI report:
`38e597acfea835ce59ae773bb79310bdb369793a22cf3a329d59fca8e36f39b3`.

Both selected build ELFs were independently rehashed:
setup `90d81e9feb4cf2ecda9be46629bbe5f60ba940d1f4bd514495fdfc23b3d2fce6`;
cold client `8511ab69fffd5bc56a29894a819f76a34b88a215b0c05a28ca2ae79b2730d122`.
Build result `f8b31796b6ca0c2f0766f3aaee206a46d4251a0838df62e66bc25f45561831f3`
and cleanup `ae1ef00ea7c079496e5e9b8744ecbba805839a8f978c70d322c3ed8de667d76a`
record exit zero, inactive/dead and PID0. Inner GNU time was 32.28 seconds wall,
207.97 CPU seconds and 667,852 KiB max RSS; 64 telemetry samples (63 active)
recorded 828,719,104 bytes cgroup peak and zero swap. This is build/test evidence,
not a selected full-relation setup/proof or a cold-owner performance qualification.

The subsequent selected setup runtime gate was source-reviewed at
`d937fc23d92273fe7fbc122e8fef36286bb2423a2ea81b7556a9de1e8fb2e213`,
all 14 public pins matching. The ordinary setup remains `90d81e9f...`, actual
file0500/parent0700, and expected build identity is
`b2845ba58f2a895abbfddbbb43300e06fb528811b4bc5d3d0f7e1843c6491a43`.
Its app mounts one private shape read-only and only the new output subtree
read-write, with 14 CPU/18 GiB/zero-swap requested and no network. Private
configuration, FIFO/bootstrap and raw diagnostics stay outside Git; public
allowlists contain no private witness/path/hash or owner association. No private
configuration/shape/PK was opened by this reviewer.

Two review findings were closed before that gate: host paths now receive full
original-ancestry symlink, actual-repository, owner and private permission checks
before configuration reads, shape mounting or stage creation; proof events must
have distinct Auth/proof digests and cannot exceed three. The path guard accepts
actual Git non-repositories rather than every filename `.git`: this host has
empty placeholders. The false-positive development failures and correction are
retained. Ten synthetic controls and actual metadata-only preflight are reported
by the owner, without witness reads/hashes. This paragraph is the prospective
runtime ACK; fresh setup/proof artifact results remain a later gate.

Fresh setup public artifacts were then checked: report
`d514d99f4a98bc1a0289f8a8408a6f72016dacfa038b3caa7333219003d2921f`,
VK328 `a82c94918d93008160ea9af4b709b05ce41ed5fe6e4b85d66d0fb310b02d94f5`.
The exact trial/D/core8/build identity matches the approved plan. Actual finalized
counts are 3,231,025 constraints, 3,195,131 witnesses and three instances. A/B query
lengths are 3,195,134, L is 3,195,131, H is 4,194,303. Fresh setup took
13.258944696 seconds and serialization/fsync/same-FD readback 3.368911408 seconds.
The reported new public parameter artifact is 1,290,878,896 bytes,
`de26f5d5e225ee4db790d0b6b2af8679b776c8be6b494f2d783f512c86c547e3`.
This reviewer did not open/hash that blob or private shape/configuration.

Candidate producer `export_parameters.py`
`4ad521124e7c17d2ea91b4b95fa6207376590b1a411ff80e269cfafd4afeb653`
and freeze `f1c64f58d9261660663827debf936db2b1a6416a55715f199693d01c96163c06`
were checked at all 24 public pins. It independently streams the new public PK,
checks the reviewed source/domain-only clone and setup/core/build identities,
then produces a candidate; it is explicitly not its own root of authority.
The actual 2,500-byte canonical/no-newline manifest
`008689b84cd171187cc75d32402dbf13d6d4e3ed149d3349ecfbc418bfcaad54`
matches the public setup report exactly, including setup executable/source/report
provenance. Cold source manifest
`d4c6324ece5b27e4e69016eef96e9ec9049ae352b7a22a53fd94ee785f1f23cf`
was checked at all 17 files: exactly the three public parameter/selection/VK pins
change, the other 14 files are byte-identical to preserved setup source. Embedded
manifest bytes/VK/selection fields match. Root selection and the final compiled
cold executable remain separate authority gates, avoiding a final-ELF cycle.

Root selected that manifest in
`9b32b0b40f2c27a2555ee1b30ebe28fe36ada27ebeeac06efd452ff657ef6baf`.
Cold-only build02 freeze
`80d04eb428579cee3b435b883ea37d895e2b2a3590d3b862457fe0c4d0518b70`
matched all 24 inputs after compilation. Selected cold ELF
`870e61f60d002900bfc39dfad5fbdb8e54319ec083072618b027c297d94477aa`
is 3,644,656 bytes, independently checked at file0500/parent0700. No tests,
parameter loads, setup or proofs were repeated by this compile. Exit was zero,
cleanup inactive/dead/PID0; inner compile time 7.82 seconds, 29.30 CPU seconds,
501,936 KiB RSS; telemetry peak 473,628,672 bytes and zero swap. Shared RSS and
cgroup accounting are retained separately.

Selected full-size loader controls then passed at
`a1f25ed844d77cbd737e11fa0bea4dd5036186bda339b2966fab79a5ef8344c6`:
12/12 checks, exact ELF/manifest/D/VK/build/PK identities, one full actual
parameter authentication/decode and one missing-PK negative. All 302 known public
canary bytes remained unread; the failure returned only `parameter_pk_io`, with
no readiness or proof output. Read/hash/decode-plus-checked-VK/query phases were
0.781514632/0.544875509/1.751499351 seconds. Inner total was 3.21 seconds and
2,525,704 KiB RSS; seven telemetry samples recorded 2,590,212,096 bytes peak,
zero swap. Cleanup
`7068a21a72164577cdb78da0308109618da9dfe12862149b7a24f2b4011972f1`
is exit0/inactive/dead/PID0. No private owner input or proof was used; the OS page
cache may be warm and no p95/cold-download qualification follows. The reviewer
did not read the parameter blob or rerun the controls.

The resident session closed as
`5760c830452f4023425599d4ca837ce76ed65de5039378dd2e1c6b6f2e317e61`,
one fresh setup and three distinct verified proof events. Their Auth digests
independently match exactly the three reviewed public prospective Auth528 bodies.
Events `9843569bbd7efc29d8f080c6171175915dd2bbc77acf20863c757116899686b0`
contain only the approved public identities/digests; all 14 runtime pins remain
unchanged. Cleanup
`1a5f5b71f45dc89dbb1e5d4248d4a8541dc0790ee0634f721a6bb05cbaf13934`
records exit0/inactive/dead/PID0. Session RSS was 4,147,936 KiB; cgroup peak
5,593,722,880 bytes, zero swap; CPU322.52 seconds and wall25:20.56 includes long
idle. These are whole-process measurements, not independent phase peaks. Actual
proof bytes and native body substitution/Full closure remain the lifecycle gate.

## Keyless native helper source ACK

`native/helper-source-01/SOURCE-FREEZE.json` SHA256:
`8a6afce8a46c4d48518bfc13c1804312cdc586a78103c26a58743a243564c6e7`.
All 12 pinned members matched. New Rust main:
`56aaf693b0a16b63b1e9ab7b3a9c1e26a027bd0cd62d50543d4ce40bfda78fcc`.
The six earlier native-core files are unchanged.

The public API accepts quote/verify/genesis and no owner key, witness or PK.
Root/point/UTXO must be objects; original-byte Serde validation still rejects
duplicate and unknown fields. Amount/rate strings have canonical integer form
and multiplication is checked. Runtime fresh-D genesis recomputes NoteCM,
singleton CM root, State112 and GN536 rather than calling old hardcoded-domain
constructors. The complete policy is source-regenerated and patched only at
State112, ten parsed canonical D operands and one VK328 operand.

Actions bind current outpoint/redeem/reserve/full SPK, DAA/coinbase/covenant,
Auth528 fields and native output topology. Both NF checks and terminal rules
remain enforced by the unchanged native program. The quote identity hashes the
entire official serialized case and every populated context plus fee rate,
normalizing only the active proof128. It cannot be replaced by a v1 ID.

Zero-proof quote success requires isolation PASS and the exact intended G16
decode failure in both Full and ScriptEngine after the G16 tariff. It does not
claim transaction acceptance. Verify requires the same quote identity, fee
coverage and actual Full/all-engine acceptance. Chain/current-view authority
remains with the caller. Meaningful VM controls require their actual serialized
public input packet; none was run by the reviewer.

The prospective component packet was also reviewed:
`native/component-preparation-01/PRE-RUN-FREEZE-02.json`
`832aff49b9d9c7fd591a517a9ed1baeb7ea5109bdd4553137f22b602e7e65dc1`.
All 42 public members plus five external ELF/loader/SDK pins matched. Selected
helper ELF is `f6139cea85a30f092447efe199796f62c540b0399d63e949845423678d4bdc44`.
Each of four old public AA quote/verify vectors was compared to its exact closed
mainline body, populated context, proof bytes and metrics, and its normalized
case/rate quote ID was independently recomputed. Nine helper test methods cover
the intended G16 seam, genuine Full, strict parsing, policy/current UTXO, fee,
NF/terminal and same-ID proof/context substitutions. The other adversary reviewed
the transport portion, including rejection of related post-query spends while
allowing unrelated activity. This packet is deliberately labeled old public AA
wrapper controls, not actual fresh-D proof compatibility. No component runtime
result is claimed at this source gate.

Before any component semantic run, that launch packet was superseded by ordinary
packet03
`c4bd82248403885110c74837f7a69d2d1133bf4dec4c7075205757858cc99251`.
All 47 public members plus four runtime members matched; the same selected ELF
was checked at actual file0500/parent0700. Only the active helper-test launcher
changed, to a normal fixed path with full SHA256 before each launch and a clean
environment. No special-FD/loader path remains there. The unchanged helper,
fixture/quote IDs and transport checks retain the previous source review. Earlier
01/02 prospective component freezes were not executed; their preserved snapshots
are not semantic runtime results.

Ordinary component execution was artifact-closed as a partial result:
`b604acc364ad35aaf4efc5b4c417abc0ae0aea78aa1e5e8ba85a7cbcef681e0f`.
All linked artifacts matched. The nine helper methods passed in 0.542 seconds;
the later Node command ran zero transport tests and exited127 because
`/usr/bin/node` was absent. The failure is retained; this is not a full component
pass. Actual cgroup sample confirms 2 CPU/2 GiB/zero swap; cleanup
`38dd224141a5ea3b01ff4cf27f9f0ab47f2c80ae6f3d457a737ad2a97dad4a43`
records inactive/PID0 and no captured PID/cgroup. Whole-process inner time was
0.58 seconds, 37,740 KiB RSS and zero swaps.

The SDK-only retry source/fixture gate
`8c3fa1fd2067b9135bb36a47907c649bb7d4fb980aaed0799de0fcef513a1d02`
was checked at all 17 public plus four runtime pins. It uses the reviewed ordinary
0500 Node (parent0700), a full hash check before each launch and a namespace
`--version` preflight, with unchanged adapter/tests. It must wait for root's
resource release and does not repeat the nine helper VM methods. No transport
runtime outcome is claimed here.

The SDK retry subsequently passed all 31 retained checks with actual Node24.15.0
namespace preflight. Result
`6d41346fab86c9494481828fb69334dbfd90b06004cf48b32791af5a52dd7456`
and its linked log/command/resource/active-cap/cleanup hashes match, and all 21
inputs remain unchanged after execution. Inner time is 0.30 seconds, 108,184 KiB
RSS, zero swaps; actual active cgroup caps are 2 CPU/2 GiB/zero swap. Cleanup
`04d59546198437ddea44e1fb345600cbaf3597578a18adf2e8af3220ad42dcd0`
is inactive/PID0 with no captured PID/cgroup. Aggregate
`8af968a95250c08a8f882cc33949381b44bf58240b1b11aed80501060269f3bc`
correctly combines nine helper methods with 31 SDK/transport checks, reuses the
helper passes without VM repetition and retains the initial127 failure. Neither
the mocked transport checks nor these old public AA wrapper controls establish
fresh-trial proof compatibility or accepted-chain/private-payment qualification.

## Owner and trial action review in progress

The wallet design uses exact `KPX3PAY\0 || D || founding36 || CM || positionLE ||
retryLE`, keyed by its seed. Established libsecp parsing rejects zero/invalid
scalars without reduction, and retries emergency-key equality. The seed stays
in the wallet; only a derived scalar reaches the narrow crypto bridge, and no
payout secret reaches the prover/native helper.

Selected ELF bytes are copied into fully sealed memfds and hash-checked before
execution. This host's retained direct-memfd EACCES is not hidden: the reviewed
new runtime uses a separately pinned root-owned system loader on the same sealed
FD, with fixed clean environment and explicit inherited FDs. Trusted Python,
loader/shared libraries and installed fixed modules remain explicit software
assumptions. `/proc/self/exe` can identify the loader and is not payload authority.

Preliminary wallet action review found one real plus one fresh slot1 dummy,
sequential current NF updates, actual continuing CM append paths/sealed-format
dummy padding, terminal complete zeros/carry and exact full-claim conservation.
An implementation gap in historical native-payout recognition was sent to its
owner and addressed in source: spent recognized receipts also derive default
destinations and match real public payout/current-query evidence, while keeping
the association and scalar owner-private. Final wallet source/controls and
runtime artifact closure remain pending.

Historical wallet controls01 are separately artifact-closed: freeze
`fe7fdcd1ec660f09284d17d0907132a60989e56c0e017c7c719d3fd6f1c78dfa`
matches all 11 archived source files; result
`c95607ddf5c665e274650e3de32a8b8de32547efd7e869650a2280b8ffcdf063`
matches the retained 15/15 test log. Supported sealed crypto and an independent
old public tree decoder were used, with no actual backup/PK/setup/prover/native
VM. Test time was 0.412 seconds; inner GNU time 0.48 seconds and 30,956 KiB RSS,
zero swaps. Cleanup reports collected/not-found, inactive/dead, PID0. Resource
caps are explicitly requested, not live-sampled enforcement evidence. The
namespace reports host-root loader ownership as unmapped UID65534; its full
selected hash, regular/non-writable mode and trusted installation premise remain
the authority. Direct UID0 equality is not required.

Current main is a separate, not-yet-closed revision: its exact scalar-only export
allowlists reject private associations/nested reports, and a new orchestration
control checks wrong parameter readiness before any backup read. Those source
deltas were reviewed; controls01 is not relabeled as their execution evidence.

Ordinary wallet controls02 were subsequently closed at freeze
`9d73832212a6be90c8478c0ae67b528892812eb854bd41414f69badd5ea58700`:
all 12 current/archived source/metadata pins and four ordinary release files
matched, including file0500/parent0700. Result
`c8b24641653a8f42b71efd796315903850b529e6411ecd12461aec77b3302b90`
matches 19/19 actual isolated controls, using normal direct executables only.
Inner time was 0.86 seconds, 32,888 KiB RSS, zero swaps; cleanup is collected,
inactive/dead, PID0. Limits remain labeled requested without a live cap sample.
No actual owner backup/PK/prover/native VM was involved. Parameter readiness,
metadata separation, exact exports and historical payout recovery were inspected.

After controls02, a narrow privacy projection fix removes caller-chosen
`output_dir` from both public result dictionaries and field allowlists: a path
can carry an owner label. The caller already has its own request path. That
four-location removal was source-reviewed; it changes no financial/witness
logic. The updated ordinary network selection and final actual parameter/prover
release constants remain separately authenticated stages, not execution evidence
borrowed from controls02.

The separate trial builder `action.py`
`6ee9b1066dfcccb6657518e9fb34a3f1a570b01045af715b3b02631dfc8e599f`
and test source
`ca9f717326d784b092f5bc2584689e6afccd6c10df89939baed8306634be9f15`
were peer-reviewed. Its explicit D, two positioned current NF insertions,
distinct real positions, exact payout/fee conservation, all-real emergency-key
inequality and continuing/terminal semantics match the contract. Its owner's
four public synthetic controls are not reviewer execution evidence.

The subsequent no-VM financial builder sources were read:
materialize `acb03167aafdc7541c081157e55385facec4009c144a5e02e9999aaeb2079224`,
prepare `b8494ae9e9ca9dbe4a8a781fdbef95b61ed296d613c8d62054d79fc11616d308`,
SDK `7e09cb2316dd08072fa4d29e221020215f137e68f761937d7cc0751ee1678e63`.
The direct whole-note/change fee loop, exact 66-byte ALL-signature-only funding
substitution, P0 rebinding to the final founding ID while preserving chosen
notes/ciphertexts, all three subsequent native links and exact source = change
+ two positive payouts + four fees accounting were consistent. No private
materialization was read or executed. Its then-fixed recipient order is historical:
root subsequently requires a one-time OS permutation persisted only in the private
recipe and recognition-derived exit positions. Actual preparation must use that
revised source, with no public role→CM/position mapping. Setup relation/shape need
not change. This new projection/source gate remains pending.

That revised source gate is now closed at
`6a217bc20796cef1381f752d3e1c8770f20758b860cee7673224959eb101caee`,
all eight source pins matching. Actual recipe order is sampled once with OS
randomness, saved only in the separate private actual recipe before first quote,
bound to the planned source and selected VK, and retained across failed retries.
The setup recipe remains unchanged. Each owner exit locates its receipt through
recognition, rather than a public slot/map lookup. Both permutations are covered
by the owner's reported 12 ordinary-runtime public controls. Funding SDK calls
now use the selected0500 Node with full hash/fixed clean environment; no bare
inherited-environment Node or special launch remains. Conservation, current NF,
terminal and accounting checks are unchanged. No actual private order/map or
fixture was read by the reviewer.

Actual prospective public packet
`ab618096c574f5d6c5cf8540138dbcc9afce809a76a32296019db9c5348dbfc6`
was independently checked at all 17 pins, using generic case labels only.
The exporter is an explicit body/context/metrics allowlist and reads no private
witness. Cheap public recomputation checked fresh-D genesis NoteCM/singleton
roots/GN536 cipher hash, complete source-approved program with ten D/one VK slots,
both sequential NF predecessor/empty append paths, continuing CM empty-slot
paths and terminal complete inactive zeros/root/count carry. Auth, actual full
SPKs, output topology, zero inactive signature/proof placeholders, current
contexts and three predecessor links match. Estimated size, compute and
normalized mass/fee arithmetic matches all four bodies. Source 228,999,900 sompi
= ordinary change88,630,000 + two native payouts82,042,500 + four fees58,327,400;
final CM5/NF7/R0. Proof placeholders were zero128 and not presented as validated.
Hidden ownership/HMAC/note correctness remains the genuine proof and native Full
gate; no private map/recipe/witness was opened to perform this review.

The three public proof artifacts are closed at allowlist
`57ad65c705660b6b4bc857fdfac77dae0a064d5fe7051ce49df3f29d2c747ed5`:
all 13 files match, each Auth matches the corresponding prospective body and
resident-session event, and all three distinct proof128/VK328 files match their
public reports and selected manifest. Reports contain generic modes and the
explicit public field set, without owner associations or witness paths/hashes.
The public-only final controller `run_local.py`
`03e7ac336ee6d287c3c6025fc4a2e6266063a931204cfa411609d5973d683e5d`
was source-reviewed before its one authorized execution. It checks the ordinary
founding Full result, all three strict zero-proof G16 quote seams, whole prepared
body/context equality, proof128-only substitutions, all Full input engines, four
SDK round trips, three exact predecessor links and complete source accounting.
It has no seed, private witness, profile or PK inputs. Actual native artifact
closure remains separate from this prospective source gate.

Final selected ordinary wallet release is closed at
`3c6d2329df8641a23d64ae78d7b259c07f0f1a275beb7d3ecbadd9afeb6cc703`:
all 14 current source/runtime pins match. Controls03 freeze
`cb845f304c8f4b602ad1b1a4c5015e8e1614dad99a07a5c19160128e47c28729`
matches all 16 archived source/public identity files; result
`4d1854f6f6b4b50a6c4eaa777d483740a72e690fbef45afcfacef5dd703226ea`
matches the retained 19/19 test log, 0.803 seconds, 32,868 KiB RSS, zero swap,
collected/inactive/dead/PID0. Current executable source is identical to that
archive; the README only clarifies selected software and private path exclusion.
The selected cold ELF870e61f6, native ELFf6139cea, manifest008689b8, fresh D,
VKa82c9491 and buildb2845ba5 match their prior independent artifact gates.
Resource caps are requested rather than live-sampled enforcement evidence.

The cold-runtime template separately authenticates the exact 26 public network
sources and five installed public software files, mounts only their individual
files plus the selected owner modules, one own backup, public parameters and
ordinary helpers, and uses neutral namespace names. The real request/metadata
and output remain private and must not be hashed/exported. Public wiring result
`6b0f2afa5d655ff7bc1937dceafb4d43d35d895f6bd0892d96deabfdf5e8b272`
was checked against its source and raw result hashes: the complete dependency
hash/import gate succeeds and an intentionally empty descriptor then rejects.
Backup, PK and executable helper aliases are absent in that control. No actual
owner backup metadata/bytes, PK blob, native/prover execution or owner receipt
map was read by this reviewer. Actual owner-input release is a later root and
network-adversary gate.

The final prover publication packet is closed at manifest
`6552527760df4b2431d842f1e6082ccf2cfd45a1bd87edb61f85e6aa523a1ee9`
and allowlist
`a08e00068245bb5298de5d939336d6e791f7dc7fa6c677ba8ff31ba8a727e20d`:
89 payloads totaling 1,875,457 bytes, 91 exact allowlisted paths, all hashes and
lengths matched, no symlinks. Public results and retained prospective-source
history preserve the unexecuted superseded runtime, actual selected setup/load
results and path-guard failures. Logs contain public source/cache paths and
neutral sandbox aliases, without actual private config/profile/shape/witness or
backup paths/content. No PK or ELF blob is included. The old AA prover source
and closed evidence still have an empty diff against the baseline. Single
samples, possibly warm cache, single-party setup honesty, host/release inode
immutability and unproven independent mirror availability remain explicit.

The one actual public-only four-body native rehearsal is now artifact-closed:
allowlist
`1e6c45871183659a2a7cd84597e53161f067a8760b94ef6ec90f8c9cd15bb39b`
matches all 25 files; completion
`3639f08983f3c5d2656c56d727d6f4efe06316a8efd5b3529caeb4fae3066635`
and all 12 runtime pins at
`7afddcdec9c4ec376104fd354e3f3bff61b4ad952e960558ee8ad34121df9c0d`
match. All four whole native bodies and contexts were compared with the reviewed
prospective packet. The three private actions differ only in their exact128
genuine proof bytes; each corresponds to the selected public proof artifact.
Their zero-proof quote results have isolation PASS and the exact Full/engine ARK
serialization G16 error, while all four genuine positive Full and every input
engine accept. Positive engine units are respectively 100001, 14960524, 14960862
and 14846588, each within its actual allowance. All three predecessor links and
the source reconciliation were independently recomputed from the actual bodies:
228,999,900 = ordinary change88,630,000 + native payouts82,042,500 + fees58,327,400.
Terminal state carries CM5, advances NF7 and has zero reserve. Four SDK body
round trips follow the reviewed controller's successful completion; no SDK or
native call was repeated by this reviewer. The receipt reports return0,
inactive/dead/PID0, requested2CPU/4GiB/swap0, and honestly has no retained active
cap/peak sample. All mounted inputs/outputs were public-only; there was no RPC,
funding, broadcast, cold-recovery result or production/privacy qualification.

An additional independent source-only wallet pass by
`/root/private_exit_review/wallet_final_second_pass` found no concrete blocker
in the six selected owner modules and ADR0053/0054. It separately checked
readiness-before-seed, installed software authority, current context/body/proof
binding, NF/CM construction, scalar retry, historical payout recognition and
fixed public export fields. It ran no code and read no actual private inputs.

No source ACK here qualifies setup honesty, ciphertext deliverability, population
privacy, percentage fees, durable data/parameter availability, independent
consensus, production safety or readiness before confirmed terminal payouts.
