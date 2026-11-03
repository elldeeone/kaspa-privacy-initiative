# Corrupt-P1 random-state completeness: pinned source map

Date: 2026-10-29 UTC

Status: source audit and design only. No selected recorder, launch, receipt, or
privacy qualification exists. `CONFIGURED0` remains mandatory.

## Decisive conclusion

The v9 C03 artifact is an exact application-level typed/transport transcript,
not the complete view of the pinned passive P1 process. It omits P1-known local
entropy and state in base OT, SoftSpoken/VOLE, the evolving OT cache,
`Mascot-Secrets`, MASCOT preprocessing/input caches, consumed Beaver triples,
pending MAC checks, local context failure state, TLS private/session/DRBG state,
query/MSM/checker temporaries, and abort-time partial state.

Capturing the actual unbounded peer vector `T` fixes the transport-metadata
problem. It does **not** fix this random-state problem. The complete corrupt-P1
view and every failed/partial view therefore remain `MISSING`. No MASCOT or
SoftSpoken theorem turns absent implementation state into captured evidence.

## Current corrupt-P1 coverage matrix

`DIRECT` means private typed encoding/retention code exists. `SOURCE` means an
exact production source wrapper or callsite exists in the registered build
closure. `TEST` means only an isolated/control execution has exercised it.
None of those words means an actual selected trial produced the evidence.
Every row with a partial prefix or no actual-run receipt remains `MISSING`.

| View/state family | Direct capsule/stream | Genuine registered source | Actual selected run | Current disposition |
|---|---|---|---|---|
| v9 C03 typed application + peer transcript | `DIRECT` | `SOURCE`, source-only callsites | no | `MISSING`: no selected launch/producer/receipt; random state is outside v9 |
| State archive writer + terminal disposition | `DIRECT` | source-only topology/SCM path | no | unavailable-only controls; parent replay and postrun join absent |
| `PlayerAllocation` | partial `DIRECT` adapter | source-identity-checked TLS overlay only | no | `TEST`: genuine four-lane role-1 construction reaches authenticated `UNAVAILABLE`; overlay unselected and terminal allocation state incomplete |
| `TlsChannelState` | partial `DIRECT` adapter | source-identity-checked TLS overlay only | no | `TEST`: success and hostile hostname-failure both reach terminal/ACK; provider DRBG, traffic-key epochs, record/BIO state, cache/tickets and replay absent |
| `MpSpdzPrng` | `DIRECT` `ReSeed` entropy record | `SOURCE` linker wrapper + role-1 install seam | no | `MISSING`: `SetSeed`/global seeds, consumption, caches and terminal state absent |
| `CryptoToolsPrng` | `DIRECT` `sysRandomSeed` record | `SOURCE` linker wrapper + role-1 install seam | no | `MISSING`: PRNG evolution, worker correspondence and terminal state absent |
| `MascotSecrets` | incomplete source-only `DIRECT` serializer/root-thread scope; capsule adapter not linked | prior pinned MP-SPDZ patch rejected; revised callsites and registered activation absent | no | `NEGATIVE`: rejected patch SHA-256 `96d86174ed59c2d12f296d055bb1b7a933b2c9bba8a06ad2dc9c1caafea99cd5` omitted the second selected `get_fresh()` transition and the prep-static/`Player-MAC-Keys` edge; actual-run family remains `MISSING` |
| `SimplestOtBase` | `DIRECT` `randombytes` record | `SOURCE` linker wrapper + role-1 install seam | no | `MISSING`: base choices/outputs, ephemeral scalar correspondence and terminal state absent |
| `SoftSpokenExtended` | none | none | no | `MISSING`: VOLE/PPRF/check state and thread order absent |
| `OnDemandOtMap` | none | none | no | `MISSING`: map topology, packed base state, internal PRNG and reuse relation absent |
| `TripleAndInputCache` | selected derived outputs only | selected application callsites | no | `MISSING`: generated/consumed/residual preprocessing caches absent |
| `Beaver` | selected masked application openings only | selected application callsites | no | `MISSING`: every internal consumed triple/cursor/result is not captured |
| `MacCheck` | alpha share only | v9 setup lane | no | `MISSING`: pending values/MACs, collective seed, coefficients, tau and abort state absent |
| `ContextAndRetry` | `DIRECT` complete adapter | source-only `RegisteredP1Context` overload | no | `MISSING`: genuine selected plan/caller absent; pre-context setup is a separate family |
| `ProtocolSetup` | no source serializer | none | no | `MISSING`: setup/key/MAC-check construction and failure prefixes absent |
| `QueryMsmCheckerTemporaries` | named family only | manifests bind inputs/callsites, not temporaries | no | `MISSING`: no direct serialization or exact replay-correspondence proof |
| Parent reconstruction across R1/R2 | contract only | no parser/replay/minter | no | `MISSING`: no authenticated postrun/pidfd/archive/C03/history conjunction |

This matrix is only the P1 state slice. It must be joined with the separate C1
and public-projection leakage ledgers; zero missing P1 rows is necessary but
not sufficient for a complete combined observer.

### Source-only `MascotSecrets` hook sequence (incomplete)

This is the required source sequence, not a completed capture. It is not a
selected recorder, configured launch or actual-run receipt. The earlier patch,
SHA-256
`96d86174ed59c2d12f296d055bb1b7a933b2c9bba8a06ad2dc9c1caafea99cd5`,
is retained as negative evidence: it captured the first `get_fresh()` used to
write `Mascot-Secrets` but omitted the second selected transition in
`OTTripleGenerator<T>::get_mac_key()`. At the selected prime-field
instantiation `T::bit_prep_type` aliases `T`, so that second operation updates
the same complete-key static. The omitted transition made the subsequently
recorded installed state disagree with genuine source execution.

The exact type and state path is source-pinned: local `AuthScalar` is
`Share<Fr>`; upstream [`Share.h` lines 156--176](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/Share.h#L156-L176)
defines `prep_type = Share<T::next>` and `bit_prep_type = Share`, while
[`gfp.h` lines 54--72](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Math/gfp.h#L54-L72)
makes `T::next` a distinct field-template instance. The first fresh transition,
prep-static install and Player-MAC write are in
[`MascotMacKey.hpp` lines 29--84](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/MascotMacKey.hpp#L29-L84);
the text-file lifecycle is
[`fake-stuff.hpp` lines 235--266](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/fake-stuff.hpp#L235-L266);
the second fresh transition is
[`NPartyTripleGenerator.hpp` lines 48--64](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/NPartyTripleGenerator.hpp#L48-L64);
and the separate online-static install and incomplete teardown are
[`MascotPrep.h` lines 136--148](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MascotPrep.h#L136-L148).

1. `SetupBegin` binds the pinned MP-SPDZ source identity, source-derived cache
   domain/diagnostic pathname, P1/player/setup parameters and the exact packed
   whole static complete key. An explicit source-lifecycle bit distinguishes
   initialized/static reuse from the packed default object; a zero inherited
   scalar never discards serialized `OTTripleSetup` bytes.
2. A static-key reuse branch records `StaticInstalled -> Teardown`; it does not
   fabricate cache, regeneration or write events.
3. A cache branch records `CacheOpened -> CacheLocalValidation ->
   CachePeerValidation`. The open event retains pre-open `lstat`, actual flags
   and fail-closed no-symlink `openat2` policy, coherent regular-file
   opened-descriptor `fstat` identities, full native `size_t`
   header/body/trailing bytes and reopen comparison. It accepts the exact
   pinned `Player-Data//Mascot-Secrets-...` source path while rejecting dot
   components. A valid cache then proceeds directly to `WriteCandidate`; a
   missing, locally rejected or peer-rejected cache first records
   `Regeneration` with the exact packed key.
4. `WriteCandidate -> Writeback` must retain complete-key state before/after
   `get_fresh()`, the exact candidate file, actual write count, `fsync`, stable
   post-write descriptor/reopen body, and explicit rename/unlink result/errno.
   The selected source performs neither rename nor unlink on this edge, so both
   are authenticated `NotAttempted` outcomes rather than invented events.
5. A still-missing edge then installs the distinct prep-share scalar static and
   writes/truncates
   `Player-Data/3-p-254/Player-MAC-Keys-p-P1`. The exact body is the public
   player count plus the same local scalar in text form, but the prior static
   value, overwrite lifetime, write/close result, file identity/metadata and
   timing are not captured. The second `get_fresh()` then self-updates the
   selected complete-key static and must be recorded before installation.
6. `StaticInstalled -> Teardown` must record the exact complete key, prep-share
   scalar static and online `Share<Fr>` scalar static after installation, plus
   their live pre-reset and post-reset state. Teardown resets only the complete
   generator key; both scalar statics persist and can be overwritten by the
   next round.

The prep scalar and `Player-MAC-Keys` body are deterministic given the already
captured local MAC-key share and public source constants, so they likely add no
new algebraic mapping information. That is a privacy inference, not direct
process-view evidence. The uncaptured lifetime and filesystem outcomes remain
`MISSING`; the bounded observer cannot claim an exact passive-P1 process view
until they are directly captured or covered by a separately admitted exact
replay argument.

`MascotMacKey::get_fresh()` copies the scalar and advances only the embedded
`OTTripleSetup`. A normal second-round cache hit therefore reuses the same
local MAC-key share; regeneration after a missing or rejected cache may replace
it. Neither the observer nor a source assumption may treat the two round keys
as independently sampled.

Any eventual implementation must treat omission, replay, wrong-thread use,
short read, reopen mismatch, truncation/substitution, write-before-fsync
failure, duplicate teardown or any partial/failure prefix as typed
`UNAVAILABLE`, and scrub retained temporary secret buffers.

The scope retains and scrubs the current complete key and installed scalar,
and refuses a mismatch across validation/regeneration, `get_fresh()`, static
installation and teardown. Pinned OT-correlation and MAC-check cache-unlink
edges mark the family `UNAVAILABLE` before source-owned cleanup. OT worker
exceptions are returned to the root waiter instead of calling `exit(1)`, but
the worker edge remains deliberately `MISSING` until a source-owned worker
epoch can retain it without violating the root/worker authority boundary.

The packed complete key covers the scalar and serialized `OTTripleSetup`
values. It does not claim coverage of the separate thread-local OT map or its
internal PRNG; those remain `OnDemandOtMap` work. The capsule factory/take path,
`MascotContext` lifetime installation, registered child consumption and
branch-specific selected hook inventory are still absent, so live/selected,
configured and complete-view status all remain false.

## Exact selected source

The local dependency receipt is
[`mpc-prover/DEPENDENCIES.json`](../poc/local-private-payment/mpc-prover/DEPENDENCIES.json)
(SHA-256 `46ff3f41db8e1cb3cac0c9702a62cd9473ed0e059cbb02117b033a77c9cf9ece`).
It selects:

| Component | Exact revision | Archive SHA-256 | Selected role |
|---|---|---|---|
| [MP-SPDZ](https://github.com/data61/MP-SPDZ/tree/113c4e47dd94bca9ecab029d2f0abe649bea5c52) | `113c4e47dd94bca9ecab029d2f0abe649bea5c52` | `6ee404ce90be5acc9fb8222a5c92f358b1a4f78a4a50dc8d5419824cb2d39dc6` | MASCOT, `Share<Fr>`, Beaver, MAC check, OT adapter |
| [SimplestOT_C](https://github.com/mkskeller/SimplestOT_C/tree/7ef7666909e493a18c99efe56f97cc4d13723005) | `7ef7666909e493a18c99efe56f97cc4d13723005` | `e2001b6fa78ca0f51777050642bd86103e68473c5b75e1ab5f2cccac492251ec` | ref10 base OT because `AVX_OT=0` |
| [libOTe](https://github.com/mkskeller/libOTe/tree/fe6b2ff82a976a5332b3a2efe325831588b1324a) | `fe6b2ff82a976a5332b3a2efe325831588b1324a` | `f057ae31d5a28f1946fda6d002620af996cefa1e904d3abf98e789393cd31578` | malicious SoftSpoken because `USE_KOS=0`, `USE_LIBOTE2=1` |
| [cryptoTools](https://github.com/mkskeller/cryptoTools/tree/f70175e0cbd36b808475c0c1bbf585304e43d3d0) | `f70175e0cbd36b808475c0c1bbf585304e43d3d0` | `cac991e7317db7287b924f66c3ff041b9f3533e44e11c4d1f3f02ff56863495c` | `sysRandomSeed()` and libOTe PRNG |

The selected configuration also has `MASCOT=true`, `INSECURE=false`,
`NDEBUG=false`, and `NO_MIXED_CIRCUITS=true`. The selected player is
`RegisteredRosterCryptoPlayer : CryptoPlayer`, not an ideal authenticated
channel. The selected build still applies only the mutual-TLS patch. A separate
unselected source patch,
[`mp-spdz-p1-player-tls-state-v1.patch`](../poc/local-private-payment/mpc-prover/vendor-patches/mp-spdz-p1-player-tls-state-v1.patch),
SHA-256 `dc984ecfcf8602cc7c20fda96d9798b4c08808f29756897e8b8208b2d9e4ff15`,
now records certificate and private-key DER, OpenSSL message/info/keylog
callbacks, client/server randoms, the TLS 1.2 session master key and ID,
negotiated protocol/cipher, verification result and verified-chain DER through
the private capsule adapter. Its strict patched-source syntax control passes,
but it is not in the selected build or child call path. It still omits the
OpenSSL provider DRBG, full traffic-key epochs, record sequence/BIO buffers,
session cache/tickets and abort-time opaque `SSL` state. The current host links
OpenSSL 3.5.5 `libssl.so.3` and `libcrypto.so.3`; no complete TLS replay
serializer is admitted.
The overlay removes upstream `ssl_error()`'s raw `exit(1)` so a handshake
exception can unwind through the role-1 unavailable guard. The source-only
integration control now exercises both genuine four-lane TLS construction and
a real hostile hostname-verification failure. In both cases the outer role-1
runtime sends authenticated structural-false `UNAVAILABLE`, the parent returns
the terminal ACK before process exit, and no generic party-completion packet is
accepted. The focused wrapper is independently green 2/2; its C++ control and
wrapper SHA-256 identities are respectively
`1ecc0b5e45ecb750eb9536f2e723576ecc6ffff277dd91d3713d4cfd4b1fca6d`
and `4db2ddd202c11c33e9ad910071453458e1246c881d97572c18919fb24895ed2a`.
This is failure-path/source evidence only: the overlay remains absent from the
selected registered build and actual run, and the omitted TLS process state
above keeps the complete-view row `MISSING`.

## Construction and lifetime

The source call chain is exact:

The source now separates `P1StateCapsulePrelaunchBinding` from the reserved
`P1StateCapsulePostrunBinding`. A role-1-only dispatch seam can consume the
authenticated state channel plus prelaunch plan and install the recorder before
BN initialization, roster/player construction or `ProtocolSetup`. It cannot
predict projections or exits. However, `source_owned_prelaunch_minter` and the
selected parent callsite remain false: current controls create the plan, while
no genuine activation source can mint it. Therefore the compiled child seam is
still unavailable-only source structure, not an actual selected recorder.

1. [`SelectedRegisteredRoleChildProgram::run`](../poc/local-private-payment/mpc-prover/financial/registered_role_child_program.cpp#L134)
   calls `RegisteredRosterPlayerRuntime::begin_after_fork`; the selected
   `RegisteredRosterCryptoPlayer` base constructor performs TLS setup and
   handshakes before `RegisteredP1Context` exists. A recorder first started at
   the MASCOT boundary has already missed TLS entropy/session state and initial
   player traffic.
2. [`RegisteredP1Context::begin`](../poc/local-private-payment/mpc-prover/financial/registered_p1_context.cpp#L13)
   constructs `P1CapturingPlayer` and typed seams before `MascotContext`.
3. [`MascotContext`](../poc/local-private-payment/mpc-prover/auth_field.cpp#L130)
   constructs `ProtocolSetup`, captures only the resulting local MAC-key share,
   then constructs `ProtocolSet`.
4. [`ProtocolSetup`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/ProtocolSetup.h#L46-L64)
   invokes live-preprocessing MAC-key generation and MAC-check setup.
5. [`ProtocolSet`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/ProtocolSet.h#L21-L66)
   retains the output MAC checker, live preprocessing, processor, Beaver
   protocol, and input protocol for the context lifetime.
6. [`OTPrep::set_protocol`](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MascotPrep.hpp#L33-L50)
   obtains a fresh copy of a thread-local OT setup and constructs the live
   triple generator. Preprocessing buffers remain live in `ProtocolSet`.

The selected parent design runs both round programs in the same persistent role
child. Each round can construct a new `MascotContext`, but MP-SPDZ's
`thread_local OnDemandOTTripleSetup` is process/thread state. A correct recorder
must bind and join both rounds; a per-round seed list is insufficient.

## Finite state ledger

`Direct` means the v9 schema directly records the named state. `Reconstructible`
means a future recorder could retain a smaller random tape plus enough exact
source/control-flow state to replay it; it does not mean v9 can do so today.

| Family | P1-known state and lifetime | Primary source | Reconstructibility | v9 |
|---|---|---|---|---|
| MP-SPDZ `PRNG` | Entropy seed, AES schedules, counter/state buffer, random buffer, byte cursor, cached bits, initialized flag; each instance evolves per consumption | [`random.h` lines 46--73, 83--113, 184--204](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/random.h#L46-L73), [`random.cpp` lines 38--48, 79--118, 146--188](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/random.cpp#L38-L48) | Seed plus exact domain, call order, byte/bit consumption, thread/fork identity, and terminal counter reconstructs it. None of that complete replay ledger exists. | `MISSING` |
| Thread-local OT setup | Map keyed by raw `Player*`; local base choices, sender seeds, receiver seeds, and an internal `PRNG`; cached state mutates twice on every `get_base()` | [`OTTripleSetup.h` lines 14--52, 131--147](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/OTTripleSetup.h#L14-L52), [`OTTripleSetup.cpp` lines 10--28, 44--50, 60--110](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/OTTripleSetup.cpp#L10-L28), [`BaseMachine.h` lines 31, 117--133](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Processor/BaseMachine.h#L117-L133) | `pack()` covers choices/outputs but not the internal `PRNG`, map topology, raw-pointer reuse, or call sequence. Capture pre/post packed state plus logical player/thread identity and PRNG checkpoints. Raw addresses are not authority. | `MISSING` |
| `Mascot-Secrets` and static complete key | File bytes contain MAC key plus OT setup; load/validation/regeneration branch; fresh generation; evolved state is written back; multiplier failure unlinks the file; static key persists until teardown | [`MascotMacKey.h` lines 13--46](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/MascotMacKey.h#L13-L46), [`MascotMacKey.hpp` lines 29--84](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/MascotMacKey.hpp#L29-L84), [`NPartyTripleGenerator.hpp` lines 48--64](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/NPartyTripleGenerator.hpp#L48-L64), [`OTMultiplier.hpp` lines 148--160](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/OTMultiplier.hpp#L148-L160) | Exact pre/post file bodies, metadata, branch/outcome, static in-memory pre/post packed state, and unlink result are required. The policy identity alone is not state. | Direct alpha share only; all other state `MISSING` |
| SimplestOT base OT | Sender ephemeral `y`; receiver four ephemeral `x` scalars per batch; choices; derived sender/receiver outputs; local MP-SPDZ reseed | [`BaseOT.cpp` lines 146--164, 175--320](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/BaseOT.cpp#L146-L164), [`ot_sender.c` lines 8--28](https://github.com/mkskeller/SimplestOT_C/blob/7ef7666909e493a18c99efe56f97cc4d13723005/ref10/ot_sender.c#L8-L28), [`ot_receiver.c` lines 29--47](https://github.com/mkskeller/SimplestOT_C/blob/7ef7666909e493a18c99efe56f97cc4d13723005/ref10/ot_receiver.c#L29-L47), [`sc_random.c`](https://github.com/mkskeller/SimplestOT_C/blob/7ef7666909e493a18c99efe56f97cc4d13723005/ref10/sc_random.c), [`randombytes.c` lines 36--42](https://github.com/mkskeller/SimplestOT_C/blob/7ef7666909e493a18c99efe56f97cc4d13723005/common/randombytes.c#L36-L42) | Exact randombytes returns plus transcript and chosen roles determine the ephemeral values/outputs. Transcript alone does not reveal them. Hook entropy ingress or direct state before destruction. | `MISSING` |
| cryptoTools PRNG | Four `std::random_device` words form each SoftSpoken seed; AES key, buffer, byte index, block index and capacity evolve during use | [`Defines.cpp` lines 32--38](https://github.com/mkskeller/cryptoTools/blob/f70175e0cbd36b808475c0c1bbf585304e43d3d0/cryptoTools/Common/Defines.cpp#L32-L38), [`PRNG.h` lines 13--40, 161--179](https://github.com/mkskeller/cryptoTools/blob/f70175e0cbd36b808475c0c1bbf585304e43d3d0/cryptoTools/Crypto/PRNG.h#L13-L40), [`PRNG.cpp` lines 44--108](https://github.com/mkskeller/cryptoTools/blob/f70175e0cbd36b808475c0c1bbf585304e43d3d0/cryptoTools/Crypto/PRNG.cpp#L44-L108) | Seed plus exact calls reconstructs the PRNG. Concurrent sender/receiver call ordering and terminal indices are not recorded. | `MISSING` |
| SoftSpoken malicious OT/VOLE | Per-role `sysRandomSeed`; base seeds/choices; AES stream/rekey counts; block indices; PPRF/VOLE seeds and delta; correction/send/receive buffers; malicious hash PRNG/key/use count/subtotals; challenge and check state; worker-thread/fork order | MP-SPDZ [`OTExtensionWithMatrix.cpp` lines 35--66, 112--143, 162--216, 251--280, 308--368, 402--463](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/OTExtensionWithMatrix.cpp#L308-L368); libOTe [`SoftSpokenShOtExt.h` lines 24--149, 151--236](https://github.com/mkskeller/libOTe/blob/fe6b2ff82a976a5332b3a2efe325831588b1324a/libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h#L24-L149), [`SoftSpokenMalOtExt.h` lines 113--226, 229--348](https://github.com/mkskeller/libOTe/blob/fe6b2ff82a976a5332b3a2efe325831588b1324a/libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h#L113-L226), [`SmallFieldVole.h` lines 32--104, 122--267](https://github.com/mkskeller/libOTe/blob/fe6b2ff82a976a5332b3a2efe325831588b1324a/libOTe/Vole/SoftSpokenOT/SmallFieldVole.h#L32-L104), [`SubspaceVole.h` lines 42--169, 174--336](https://github.com/mkskeller/libOTe/blob/fe6b2ff82a976a5332b3a2efe325831588b1324a/libOTe/Vole/SoftSpokenOT/SubspaceVole.h#L42-L169), [`SubspaceVoleMaliciousLeaky.h` lines 17--79, 216--363, 367--540](https://github.com/mkskeller/libOTe/blob/fe6b2ff82a976a5332b3a2efe325831588b1324a/libOTe/Vole/SoftSpokenOT/SubspaceVoleMaliciousLeaky.h#L17-L79) | Full entropy and deterministic replay may suffice, but no exact replay/correspondence proof exists for the MP-SPDZ/coproto/thread composition. Until then direct pre/post state checkpoints are required. | Peer bytes only; local state `MISSING` |
| MASCOT generator | Static complete key; `share_prg`; base choices/outputs; multiplier state; `valueBits`; plain/pre-amplified/unchecked triples; generated input tuples; collective seeds; sacrifice masks/checks; generated/consumed/residual caches | [`NPartyTripleGenerator.h` lines 50--119, 136--176](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/NPartyTripleGenerator.h#L50-L119), [`NPartyTripleGenerator.hpp` lines 121--205, 260--349, 628--680, 710--866](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/OT/NPartyTripleGenerator.hpp#L628-L680), [`MascotPrep.hpp` lines 53--75, 106--117](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MascotPrep.hpp#L53-L75), [`ReplicatedPrep.h` lines 31--58, 120--143](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/ReplicatedPrep.h#L31-L58) | High-level captured shares do not identify the source tuple, unused residual cache, or local generation tape. Snapshot generator/preprocessing buffers at generation and consumption edges, including abort. | Some derived outputs direct; source/random/cache state `MISSING` |
| Beaver online multiplication | Consumed triples; multiplicands; masked local shares; opened eps/delta; result cursor and pending results | [`Beaver.h` lines 25--46](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/Beaver.h#L25-L46), [`Beaver.hpp` lines 33--42, 53--119, 123--196](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/Beaver.hpp#L53-L119) | Capture every consumed triple and masked difference at prepare/exchange/finalize, or prove a one-to-one deterministic correspondence from a captured preprocessing cache. Current typed callsite outputs do neither for all internal multiplications. | Selected application results/openings only; full state `MISSING` |
| MAC check | Alpha share; queued secrets/open values; pending `vals`/`macs`/`popen_cnt`; opening counter and buffers; collective seed; random coefficients; local `tau`; commit nonce; reset/failure/unlink state | [`MAC_Check_Base.h` lines 22--40](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MAC_Check_Base.h#L22-L40), [`MAC_Check.h` lines 85--120, 185--207](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MAC_Check.h#L85-L120), [`MAC_Check.hpp` lines 187--289, 437--478](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Protocols/MAC_Check.hpp#L187-L289), [`Subroutines.cpp` lines 133--171](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/Subroutines.cpp#L133-L171), [`Commit.cpp` lines 6--12](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/Commit.cpp#L6-L12), [`octetStream.cpp` lines 146--149](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Tools/octetStream.cpp#L146-L149) | A successful complete peer transcript can contain later seed openings and nonces, but an abort can precede them. Pending queues and local contributions must be snapshotted before destruction/exit. | Alpha direct; pending/check tape `MISSING` |
| Local wrapper/context | Generation, failure epoch, check counter, poison bit, consumed validation-attempt set, public-stage callback/exception phase | [`auth_field.hpp`](../poc/local-private-payment/mpc-prover/auth_field.hpp), [`auth_field.cpp`](../poc/local-private-payment/mpc-prover/auth_field.cpp), [`p1_context_state_hook.hpp`](../poc/local-private-payment/mpc-prover/p1_context_state_hook.hpp) | `MascotContext` now owns a sealed `ContextAndRetry` hook through `unique_ptr`. A complete final capsule adapter maps constructed/validate/retry/poison/terminal callbacks into a shared private ledger and rejects generic recorder fabrication of this family. A source-only `RegisteredP1Context` overload consumes it, but no genuine prelaunch/hook-manifest minter or selected launch exists, so the actual-run family remains `MISSING`. Pre-context setup callbacks are separate `ProtocolSetup` work. | `MISSING` |
| `Player` | No PRNG was found; local broadcast hash context, child-fork map, locks and communication stats are retained | [`Player.h` lines 241--255](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Networking/Player.h#L241-L255), [`Player.cpp` lines 604--635](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Networking/Player.cpp#L604-L635) | Complete ordered traffic and fork records should deterministically reconstruct `ctx` and stats, but this correspondence still needs an exact replay control. There is no Player random tape to add. | Transport direct; local correspondence not yet proved |
| TLS/OpenSSL channel | P1 certificate/private-key input; OpenSSL primary/public/private DRBG entropy and reseed state; four live TLS 1.2 streams for two peers; client/server handshake randomness, master/keylog secrets, sequence numbers, cipher/record buffers, alerts and partial read/write state | MP-SPDZ [`ssl_sockets.h` lines 26--81](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Networking/ssl_sockets.h#L26-L81), [`CryptoPlayer.cpp` lines 52--108](https://github.com/data61/MP-SPDZ/blob/113c4e47dd94bca9ecab029d2f0abe649bea5c52/Networking/CryptoPlayer.cpp#L52-L108); OpenSSL 3.5 [`RAND`](https://docs.openssl.org/3.5/man7/RAND/), [`SSL_CTX_set_keylog_callback`](https://docs.openssl.org/3.5/man3/SSL_CTX_set_keylog_callback/), [`SSL_SESSION_get_master_key`](https://docs.openssl.org/3.5/man3/SSL_SESSION_get_master_key/) | The unselected v1 patch and shared-ledger adapter directly retain certificate/private-key DER, exact callbacks and listed handshake/session fields. They deliberately poison both Player/TLS families on adapter destruction because provider DRBG, traffic-key epochs, record/BIO buffers, cache/tickets and abort-time opaque state remain absent. A keylog callback alone is insufficient; selected build/caller and replay are also absent. | Partial source-only prefix; actual run `MISSING` |
| Query/MSM/checker temporaries | Per-query worker partials, point/scalar pairing, MSM accumulators, mixed-protocol intermediates, checker buffers and the public-stage callback phase | Local [`auth_groups.cpp`](../poc/local-private-payment/mpc-prover/auth_groups.cpp), [`financial_prover.cpp`](../poc/local-private-payment/mpc-prover/financial/financial_prover.cpp), [`registered_construction.cpp`](../poc/local-private-payment/mpc-prover/financial/registered_construction.cpp) | The v9 source/query/scalar manifests bind callsites but do not prove that every intermediate is a deterministic function of captured inputs. Either serialize each named live temporary, including abort state, or run an exact replay-correspondence control comparing every intermediate and peer-visible effect. | Selected inputs/outputs direct; intermediate correspondence `MISSING` |

## What v9 actually captures

[`p1_capture_stream.hpp`](../poc/local-private-payment/mpc-prover/p1_capture_stream.hpp#L20)
defines only 17 semantics: owner frames, peer transport, selected application
scalar shares/MACs/randoms, selected openings, the public projection, selected
group state, the local MAC-key share, and scalar-callsite binding.
[`p1_capture_seams.cpp`](../poc/local-private-payment/mpc-prover/p1_capture_seams.cpp#L80)
declares exactly those lanes. `random_auth_batch()` records the authenticated
value returned from preprocessing, and `multiply_batch()` records selected
application results; neither records the generator/cache/random tape that
produced them. This distinction is literal, not an inference.

## Abort-safe state capsule contract

The smallest source-correct future authority is conjunctive with the C03
transcript authority; it does not replace it.

1. A source-owned move-only recorder starts **before
   `RegisteredRosterCryptoPlayer`/`CryptoPlayer` construction**, hence before
   TLS handshakes, initial `Player` allocation/traffic and `ProtocolSetup`. It binds
   the exact `RunBinding`, round, persistent child/process/thread identities,
   selected executable and dependency pins, options/cache policy, logical
   player/fork map, and a versioned pre-opened private archive. The current
   ten-archive topology has no such private slot, so selection requires an
   explicit topology/schema version; opening a late side file is forbidden.
2. Typed hooks record every entropy ingress (`PRNG::ReSeed`, SimplestOT
   `randombytes`, cryptoTools `sysRandomSeed`, commitment nonces), domain/site,
   thread/fork/peer, sequence, requested/returned length, and returned bytes.
3. Typed pre/post checkpoints cover the `Mascot-Secrets` body and branch,
   static complete key, thread-local OT setup, per-role SoftSpoken/VOLE state,
   generator/preprocessing/input buffers, every Beaver prepare/consume/finalize,
   MAC pending/check/reset state, TLS key/DRBG/handshake/session/record state,
   query/MSM/checker temporaries, and local context transitions. If deterministic
   replay is later used instead of a full snapshot, an exact independent replay
   must compare every named state and terminal counter; a seed by itself is not
   admission evidence.
4. The selected protocol boundary catches transport and protocol exceptions
   while `MascotContext`, `ProtocolSet`, triple generator, MAC checker and OT
   objects are still alive. Before closing role FDs or exiting, it records a
   typed terminal outcome (`SUCCESS` or `ABORT`), phase and bounded exception
   class, snapshots every still-required state, then fsyncs, reopens/rechecks
   the same inode read-only, hashes, and closes the last writer.
5. Every required hook has a terminal status. Abort closure consumes a
   move-only source-owned terminal-site authority binding the finite lifecycle
   phase, bounded exception class and manifest-committed exception identity;
   raw site/class/digest arguments cannot prepare a complete abort.
   `NOT_CONSTRUCTED` is legal only for families whose first construction phase
   has not been reached. A terminal-specific manifest fixes the exact
   per-family closed/not-constructed/prefix event and transition sequences;
   alternate, truncated and overlong prefixes refuse. Every source-owned
   thread/fork epoch must be terminally
   joined in child-before-parent order. A failed/unreachable hook emits
   `MISSING` if the recorder remains writable and **always** invalidates the
   run. It must never mint completion. An exception during snapshot is not a
   reason to fall back to C03, infer zero state, or discard the partial archive.
6. A child-local C++ capsule is **not** parent evidence and cannot cross the
   process boundary. Each child must burn it into an authenticated fixed-format
   terminal disposition. The parent must then atomically join ordered R1/R2
   dispositions, the exact parent-held two-archive topology residual, and
   pidfd-bound persistent-role exit evidence. Only an independent archive
   grammar parser plus state replay may mint a parent-side capsule. A reader fd,
   hash, manifest or child status alone never mints. Round 2 must start from the
   exact round-1 terminal thread-local/static state. Replay, omitted hooks,
   duplicated hooks, wrong phase/order/count, cross-round substitution,
   cache-file rollback, or success/abort disagreement refuses.
7. No raw state bytes, hash, count, path, fd, or summary crosses to the general
   parent/public receipt. The sealed observer consumes both private descriptors.

The source-only prototype is
[`privacy_p1_corrupt_state_capsule_authority.hpp`](../poc/local-private-payment/private_batch_trial/privacy_p1_corrupt_state_capsule_authority.hpp)
plus its `.cpp`. It defines fourteen versioned families, source-owned
thread/object/player allocation epochs, phase-bound and terminal-specific abort
prefix evidence, a chained anonymous-disk archive, preallocated
close/quarantine and terminal-token storage,
explicit `MISSING`, and fail-closed inode/hash rechecks. Unavailable close
retains the exact partial descriptor rather than deleting it. Its focused
control covers
structural success, exact late-abort prefix, truncated success, wrong
phase/class/exception, alternate/overlong prefix, caller-retuned manifest,
phase-legal explicit non-construction, generic `ContextAndRetry` bypass,
wrong family operation/counter/order, duplicate fork, cross-recorder
substitution, token drop, unjoined threads, replay, FD substitution and
write/fsync/reopen/hash failure. This is
interface/state-machine evidence only. The topology-v2 writer-adoption and
authenticated child terminal channel now retain an unavailable partial inode
in focused controls. A source-only role-child callsite consumes that conjunction
and can emit typed `UNAVAILABLE`; no genuine plan minter, selected parent
callsite or launch reaches it. The complete upstream
serializers, live success/abort hooks, deterministic replay verifier, two-round
continuation, C03/history join and observer consumer all remain false.
The capsule now offers only its exact complete child bridge a private rvalue
projection into an opaque disposition residual; callers cannot obtain its fd,
hash, body, status or completion bit. This closes the in-process ownership
shape, but it is not authenticated cross-process evidence until the state
channel sends it and the parent independently joins and replays the archive.

The separate parent contract is
[`privacy_p1_corrupt_state_parent_rehydration_contract.hpp`](../poc/local-private-payment/private_batch_trial/privacy_p1_corrupt_state_parent_rehydration_contract.hpp).
Its only prospective input shape is conjunctive: two ordered authenticated
child dispositions, `FreshTrialP1StateArchiveResidual`, and
`PersistentRoleExitEvidence`. It deliberately has no implementation, raw-fd
overload, parser, replay verifier, or minter; every integration status remains
false. The topology-v2 source reserves two parent-held read descriptions and
the SCM source can carry unavailable dispositions, but selected activation and
the terminal/disposition-to-rehydration join are still absent.

The production begin overload can consume the sole topology-v2 `O_WRONLY`
writer before the first state byte while the parent retains the matching
`O_RDONLY` inode, and the SCM terminal channel has unavailable-path controls.
The selected activation/parent launch and chronology-correct plan minter are
absent, so fatal-exit completeness and actual-run retention remain false.
No passing source control substitutes for those live OS ownership edges. The
prototype now enforces exact object/event counts,
transition count/bitmap and ordered event/transition identities supplied by
its success and terminal-specific abort manifests. Its opaque abort-site token
and `ContextAndRetry` adapter are structurally nonforgeable, but the genuine
catch-site minter, genuine hook-manifest minter and authenticated serializer
identities are absent. The source status therefore keeps
`source_owned_terminal_site_minter=false`,
`source_owned_hook_manifest_minter=false` and
`success_and_abort_close=false`.

This is an evidence-capture architecture, not a cryptographic proof or a
malicious-host defense. A modified binary, arbitrary host memory acquisition,
kernel compromise, swap/cache/scheduling and covert channels remain outside the
bounded pinned-process experiment. In contrast, the named random tape and
protocol state are inside the pinned process and cannot be excluded merely to
make the observer finite.

## Admission disposition

| Claim | Disposition |
|---|---|
| v9 contains exact typed application lanes and peer bytes on a complete run | source-supported, subject to selected launch/producer evidence still absent |
| actual unbounded `T` can replace a predicted peer schedule | source-only prototype; selected topology/minter/EOF/observer joins absent |
| v9 contains the complete passive P1 view | **false** |
| transcript plus current source deterministically reconstructs all local OT/PRNG/cache/MAC state | **not established** |
| plaintext C03 plus TLS peer authentication removes TLS state from P1's view | **false** |
| the source/query manifests alone reconstruct every query/MSM/checker temporary | **false** |
| MASCOT/SoftSpoken theorem coverage excuses missing local state | **false** |
| failed/aborted run is complete without an abort-time state snapshot | **false** |
| any current privacy gate may consume this as complete P1 evidence | **no; `MISSING`, `CONFIGURED0`** |

The MASCOT, SoftSpoken and SimplestOT protocol assumptions remain separately
documented in the finite source-assumption ledger. They concern security of the
recognized protocol families under their stated assumptions; they do not prove
that this implementation observer captured a corrupted party's whole local
view.

## Critical file digests

These hashes pin the local source copy audited above. The upstream commit pins
remain the authority; local files must also match at admission.

| File | SHA-256 |
|---|---|
| `MP-SPDZ/Protocols/Share.h` | `e657f7d39b6d9bf8f5b4e07123157c0d34b02619f162104801da00b9ea136520` |
| `MP-SPDZ/Protocols/Share.hpp` | `7ce9e81184a3b31545fd137730fd3f0c35b5881fb41b981600a644aa68fd8d09` |
| `MP-SPDZ/Math/gfp.h` | `3b9af0a4a83abeda72d8e48a5c90f88b2497368d964b829d50f6ef8e0092e912` |
| `MP-SPDZ/OT/OTTripleSetup.h` | `93e71b45a31f1f5f17abde80d069ea559789bbf7d28555a2f4a44252c25f7c1b` |
| `MP-SPDZ/OT/OTTripleSetup.cpp` | `05d1988b32947701965a4e6fa891c285637c40678d2267828f7bf0ca355a61aa` |
| `MP-SPDZ/OT/MascotMacKey.h` | `4485bc99b8ec3727c1dfb95baf7d2fcfe7b85e3112631cc885162eb3c4054a55` |
| `MP-SPDZ/OT/MascotMacKey.hpp` | `155a8848fb253ce2bead8e9f03df703337ce6a94e97db18a9593c1383e5d2a0c` |
| `MP-SPDZ/OT/BaseOT.cpp` | `a5c8dde6a916ba26a65057fd965cebcddac568e18b48351cea257de0f8604f14` |
| `MP-SPDZ/OT/OTExtensionWithMatrix.cpp` | `229e22315d8e002e9ce2fb216e8318e9e447fd5908ce32d7d51986a71979ce44` |
| `MP-SPDZ/OT/NPartyTripleGenerator.hpp` | `a2bd22f3a6df91f04d2ff4c8cd54628731665068000916a46a8013775e4101a6` |
| `MP-SPDZ/Protocols/MascotPrep.h` | `579541d2ec20cdfdf44cd75e0098eb4635c8c61bf4439d20494d6e395f800d8e` |
| `MP-SPDZ/Protocols/MascotPrep.hpp` | `5b33a46627bca22393f85153d8b8dc42c9c0e3568b3c51049125a5445f309946` |
| `MP-SPDZ/Protocols/fake-stuff.hpp` | `4b3f41798f961a417d255f69ac973c309b40c2e0ff64f4767d42d15b832bf5e0` |
| `MP-SPDZ/Protocols/Beaver.hpp` | `b33e2952d239f46aa6791f5716c393b149304f2c2632e6a8205df29fab8bf4fb` |
| `MP-SPDZ/Protocols/MAC_Check.hpp` | `6aa24821e6dae6370cd89832f407523dc046d4648dcc281f36dd054d7cb723b8` |
| `MP-SPDZ/Tools/random.cpp` | `2ae51e81e57dc4f1a005d597485b9fbc8e93fa8fa799615d555402cfe5a5ced9` |
| `SimplestOT_C/ref10/ot_sender.c` | `32eae2c162ca9a4cb9f1da5fb6879479e7efb8ded9f9924df738f40020ee365d` |
| `SimplestOT_C/ref10/ot_receiver.c` | `a1ae02ed524ec886cb9467238e443f8a65ab9baabd5b146969572ad21844d5b8` |
| `libOTe/SoftSpokenShOtExt.h` | `ccf2fc05ae82ce07f504014ac12af52dfe310198f6937a954bd0261f23b79ef1` |
| `libOTe/SoftSpokenMalOtExt.h` | `acbbae5e2033331770eee742666a28b89f938796edf3f9ffb3c5582e5c630a0e` |
| `libOTe/SubspaceVoleMaliciousLeaky.h` | `da0d92cb886d8d18a85627e95f2a163f72d4c9f333c42e5a2810badbd86b338e` |
| `cryptoTools/Common/Defines.cpp` | `4028e3af0ee5008033de95014a63be2b643eb9efd32f52ed6b81cb4a8faee258` |
| `cryptoTools/Crypto/PRNG.cpp` | `1f5510a2e96a53134f67ba3c375e9a950ff9fb870c074854c2eed865432a9c95` |
| `MP-SPDZ/Networking/ssl_sockets.h` | `49c2ec7c16b79206f48e6183529f40a06e7b2eb86d689eca763e987f8943320a` |
| `MP-SPDZ/Networking/CryptoPlayer.cpp` | `919b6f44e9fa6730d3ab118c16d8eb52d1056027d64c7aa920dfbc0e8ec53bb3` |
| selected `libssl.so.3` binary | `63b47f444efa588e291e9b650a5ba2ab02f856356f2d50f13a2e477db9119e09` |
| selected `libcrypto.so.3` binary | `5385f0436ac2e284ba8c5fb1488874057c29c04be72dea32add832694f381e28` |

Passing a future recorder's controls would establish only exact capture and
replay behavior for the pinned binary. It would not prove the underlying
cryptography secure or make an active/malicious host private.
