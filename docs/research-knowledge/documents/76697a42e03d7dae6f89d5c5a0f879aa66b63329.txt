# ADR-0085: Staged registered payment-capture authority

Date: 2026-10-28 UTC.

Status: Accepted source architecture. The party EGRESS capability, parent-owned
measurement state machine and authenticated outer measurement-child transport
core are implemented. Global capture supervision, selected worker/truth
callsites, selected manifest tooling and activation remain absent.
`CONFIGURED=0`; launch is not authorized and no actual privacy pass exists.

## Problem

ADR-0083 ends at owner-intake authorization. A registered party later reaches
durable EGRESS after independent proof verification, but it cannot honestly
declare the whole payment capture complete. Roles P1 and P2 do not own capture
streams, each session covers only one party and round, and the global producer
can observe END, EOF and child exit only after all five artifact streams for
both rounds close.

Requiring a global capture capability inside each party completion creates a
circular and uncallable API. Accepting JSON, success Booleans or caller hashes
instead would let a child self-author completion. Joining post-network accepted
settlement or the later nine-Exit privacy experiment into pre-network payment
capture would also recreate the launch circularity resolved by ADR-0084.

## Decision

Use staged, nonforgeable authorities with distinct scopes:

1. Each registered party consumes its exact `VerifiedEgressAuthority` after
   durable EGRESS and emits one move-only `PartyDriverCompletionAuthority`.
   The receipt binds role, round, run/trial/attempt/cohort, proposal and
   selection identities, exact attempt and authorization identities, all owner
   contracts, pre- and post-LOCK accepted head, actual lock, capture
   plan/source/build/launcher, and exact effects/core/proof/projection. It makes
   no producer, EOF, global capture or network-acceptance claim.
2. Authenticated parent IPC must observe exactly roles 0, 1 and 2 for each of
   rounds 1 and 2. A missing, duplicate, replayed, wrong-role, wrong-round or
   mixed-binding delivery halts. Public receipt bytes cannot reconstruct a
   capability.
3. A separate outer `RegisteredCaptureSupervisor` must join those six
   parent-observed capabilities with genuine producer END, EOF and clean-exit
   observations for the ten fixed local payment streams. Only that supervisor
   may mint the source model's `TrialCaptureCompletionAuthority`, a mechanical
   pre-network payment-capture completion. The party bridge defines no producer
   or global-capture claim.
4. Pre-network payment capture remains distinct from a later
   `AcceptedPaymentTerminalAuthority`, which requires actual accepted-chain and
   durable resolution evidence. The nine-Exit/service-loss/cold-scan privacy
   experiment remains a third authority, `TerminalExitPrivacyAuthority`.
5. For each baseline or candidate run, one live parent consumes capture
   completion, sequences observer completion, consumes a one-shot typed
   `BarrierFreezeAuthority` before any owner truth is released, consumes exactly
   owner-bound score completions 0, 1 and 2, then consumes aggregate
   completion. A barrier receipt alone cannot advance the state. Wrong order,
   duplicate, replay, partial or mixed-run delivery poisons that in-memory
   authority.
6. A preselected comparison consumes one qualifying transparent baseline
   aggregate and one qualifying hidden-candidate aggregate. Only an exact
   owner-comparison non-regression pass may mint
   `BatchPrivacyPassAuthority`. Its scope is payment-batch privacy before
   network launch; it is not terminal privacy, financial safety or launch
   authority by itself.
7. Parent-owned durable receipts are evidence only. JSON, digests, success
   Booleans and rebuilt receipts cannot recreate any consumed capability.
   Parent crash loses live authority and requires a fresh trial.
8. Before MASCOT setup, the authenticated parent capture plan is burned once
   into a role-bound session residual plus an optional P1 Player-capture child.
   Only role 1 can receive that child. It decorates the selected
   `RosterPinnedPlayer`, preserves its authenticated-roster interface, and
   constructs the typed P1 seams before `MascotContext`; roles 0 and 2 receive
   no P1 child. The residual is then consumed by the ordinary driver/session
   path. The production source boundary exists, but no configured selected
   driver invokes it, so `CONFIGURED=0`, launch false and actual receipt false
   remain unchanged.
9. One outer parent, not three independently configured binaries, owns the
   supervisor and forks exactly roles 0, 1 and 2 as its first action before
   threads or MP-SPDZ state exist. Role selection never comes from argv,
   environment or a path. The parent creates inherited Unix seqpacket
   capability channels before `fork`; every offer, acknowledgment and result
   packet requires kernel `SCM_CREDENTIALS` for the exact parent or child PID.
   P0 alone inherits projection/dispatcher FDs 20/22 in round 1 or 25/27 in
   round 2, P1 alone inherits corrupt-server FD 23 or 28, and P2 inherits none.
   Terminal and C1 FDs 21/24 or 26/29 remain separate-process authorities.
   All source aliases and wrong-role fixed descriptors close before child code.
10. The authenticated role channel stays open through the child run. The child
    and parent each receive a move-only completion-endpoint authority with no
    public descriptor or packet operation. Only a fully defined domain bridge
    may consume those endpoints: its child side must first consume the genuine
    process-local result authority; its parent side checks role, round, exact
    parent/child PIDs, fork plan, offer, ACK, private channel nonce, payload
    digest, one packet, EOF and zero exit before recreating a parent-owned
    domain capability. The generic fork layer never serializes an authority or
    accepts JSON, paths, Booleans or caller bindings. Reuse or ambiguity poisons
    the join.
11. A selected role must construct MP-SPDZ through one immutable-roster
    `CryptoPlayer` adapter, not a caller-selected transport. Its role authority
    binds the exact three hosts, base port, CA, three server-certificate DER
    identities, registered selection and source/build/launcher identities. The
    adapter verifies the live TLS chain root and local/peer leaves, then
    requires all three parties to agree the same binding over those channels.
    `fresh_fork` preserves and rechecks that roster. No argv, environment,
    default constructor or public metadata factory can create the authority.
11a. Before supervisor proposals, the retained role channels execute one typed
    bootstrap. Only after the fork exists may the parent consume a typed
    fresh-owner round/history result, one parent capture plan and the exact
    three immutable compiled drivers. Each fixed offer binds the role, round,
    fork/PIDs/nonces, lineage, owner contracts, capture plan and v9
    model/query/scalar-manifest identities. All children inherit one
    parent-admitted kernel-sealed public PK snapshot and use independent
    `pread` cursors. A child receives no usable proposal seed, driver, capture
    or contract capability until an actual `PackedModel` has admitted that
    artifact and the fixed model plus composite gzip-query transport identities
    match. The artifact identity separately binds sealed device/inode,
    container, canonical PK and decoder. Bootstrap phases 0-2 precede
    supervisor phases 2-7; production completion requires phase 7.
11b. Active retry cannot select a new private cohort. R1 and R2 retain distinct
    public attempt/cohort identifiers and distinct private input lineage, and
    R2 still consumes genuine accepted-R1 successor-history authority. A
    private cross-round residual must bind the same three logical owners,
    authenticated channels, child PIDs and owner-root slots without exposing a
    roster hash. A distinct same-round retry authority must preserve only that
    round's exact input lineage. Missing owner/continuity halts rather than
    re-cohorting. Production continuity and retry minters remain deferred.
11c. The transparent baseline and hidden candidate must be separate owner
    process trees, not two labels over one private cohort. Before either arm
    may issue R1, the parent consumes one private launch authority from each
    live exact-three tree. One sealed join checks full cross-set disjointness
    for logical owners, root device/inode slots, child PIDs and sessions,
    two-round canonical contracts, and owner/server TLS certificate and SPKI
    identities. It never relies on same-role inequality: a role permutation
    that reuses any member refuses. The join scrubs all raw evidence and emits
    only two opaque, arm-bound, one-shot residuals. Baseline and candidate
    `issue_round1` each require and burn the matching residual; there is no
    overload that can skip the join. No combined raw-identifier receipt is
    public or durable. The selected paired-trial callsite remains deferred.
12. Observer, three owner-score, aggregate and owner-comparison processes use a
    separate outer measurement-child supervisor, not the three MPC-party
    endpoints. Each supervisor entry consumes the genuine typed permit and an
    executable descriptor. It copies those bytes to a new executable sealed
    memfd, requires their SHA-256 to equal the permit's pinned executable, and
    performs fixed `execveat` with no caller argv or environment. One private
    seqpacket channel binds kernel parent/child credentials, exact PIDs, random
    session, offer, ACK, role/owner, permit, worker, one typed completion, EOF
    and zero exit. Only this fully defined supervisor can mint
    `ChildCompletionEvidenceAuthority`; public receipts and digests cannot.
    Baseline owner truth remains on its separate private scorer handoff and is
    never placed in this public completion channel.

The fork topology and retained endpoint primitives have compiled real-process
controls, and the roster adapter has real three-party TLS controls. Their
production minters and selected gate callsite do not exist. The baseline domain
bridge and the six-party/two-round capture supervisor remain separate required
integrations. Therefore authenticated selected-driver IPC, registered
configuration and launch remain false.

## Finite source and process closure

Python import closure is insufficient. The selected parent must recompute and
hold a live `ParentManifestRecomputationAuthority` for one finite manifest. The
manifest fixes ten components: financial core, P1 corrupt-server capture, C1
colluder-wallet capture, terminal capture, genuine dispatcher, producer,
observer, owner scorer, aggregate and owner comparison. Each entry binds
source, build artifact, runtime, assets, pinned executable and launcher
identities.

The capture join consumes that live manifest capability exactly once and binds
the selected outer-parent process and executable lineage. Run
bindings, the producer and all ten streams must equal their corresponding
manifest entries and also carry parent-observed process and child-exit
identities. A word-valued build ID or caller-provided digest is not authority.
The selected recomputation tool and its production minter do not yet exist, so
manifest and global-capture integration, configuration, launch and actual-pass
status remain false. The standalone child transport and typed adapter flags may
be true without making a selected measurement run actual.

That outer-parent process, executable and manifest-recomputation lineage is
carried through each run aggregate and must match across the baseline,
candidate and preselected comparison. Aggregates from different parent
lifetimes cannot combine into a batch pass; parent crash requires a fresh
trial.

## Outer measurement child transport

`privacy_measurement_child_supervisor.*` implements the executable transport
core for observer, owner score, aggregate and owner comparison. The parent
copies the selected executable bytes into a mode-`0500` memfd and seals write,
growth, shrink and further seal changes before executing that same file
description. The copied-byte SHA-256 must equal the worker identity carried by
the genuine permit. Caller paths, argv, environment values, result Booleans or
serialized receipts cannot select or mint a completion.

The parent and child exchange one fixed offer, ACK and completion over a new
`SOCK_SEQPACKET` capability channel with `SCM_CREDENTIALS`. The offer binds the
role, owner scope, permit, all worker identities, outer-parent lineage, random
session and exact PIDs. The completion repeats the role/owner, permit, session
and ACK and carries only the public receipt, opaque capsule seal and typed
outcome. The parent requires the same credential PID on ACK and completion,
then exact EOF and clean `waitpid`, before the sole production evidence mint.
Wrong executable, credential, PID, nonce, role, permit, result shape, extra or
missing packet, EOF or exit fails closed and burns the attempt.

This transport does not select worker binaries or provide the private owner
truth endpoint. The baseline parent must give each one-shot
`OwnerScoreTruthAuthority` directly to its isolated scorer; acceptance receives
only public score completion and an opaque seal. Genuine capture-completion,
worker/truth callsites and registered outer-parent integration remain absent.
The runtime bridge records that its authenticated supervisor and typed adapters
exist while keeping registered integration, configuration, launch and actual
privacy pass false.

The child output data plane remains an atomic activation gate. Source now pins
the Observer-v3 and OwnerScore-v1 role-to-ABI-to-exact-size table, creates an
empty parent-owned memfd, installs its sole child writer at FD62 only for those
two roles, binds ABI identity and size into the authenticated offer, and uses
full-width seccomp checks for `pwrite64(62, _, exact_size, 0)`. Aggregate and
OwnerComparison receive no FD62 body or write permission. After authenticated
control EOF and clean `waitpid`, the parent independently parses and hashes the
exact body, seals it, reopens it read-only, and retains the move-only authority
through the runtime bridge and `RunMeasurement`. Controls reject wrong role,
owner, binding, permit, worker, ABI, size, offset, body/hash, process, exit,
credentials, EOF, replay and extra inherited descriptors. Classic seccomp does
not observe a syscall count; the authority is deliberately the final exact
canonical body, not an exactly-once-write claim.

This source slice does not activate the gate. No selected production worker
writes a canonical body, no parent selected callsite invokes the supervisor,
and the genuine raw outer measurement-attempt preimage needed to match the
Observer ABI to digest-only `RunBinding.attempt` is absent. Fanout, barrier,
configuration and launch therefore remain false; a caller-selected count,
Python receipt or opaque nonce cannot substitute for those missing
authorities.

## Activation boundary

ADR-0084 retains its two-phase Testnet policy, but immutable preflight JSON is
only durable evidence. A future selected live parent may authorize the first
Testnet RPC only by consuming both `BatchPrivacyPassAuthority` and a distinct
live `PreNetworkSafetyAuthority` bound to the same fresh trial, profile, tail,
projections and manifest. The latter must directly cover financial/native/R0
and value-conservation safety. The parent must retain ownership through launch
or use an authenticated parent service that consumes both capabilities and
owns the first RPC; Python cannot reconstruct either authority from JSON.

No such parent or safety authority exists. Activation therefore remains
`CONFIGURED=0`. Actual accepted payment terminal completion and terminal Exit
privacy are post-network completion gates, not circular prelaunch inputs.

## Transparent baseline classification

The fair positive control reuses the same value-conserving private-sort
financial proof. It is not a second relation and does not open private owner
bodies. Classification is fixed in the capture-plan identity before execution:

- `HiddenCandidate` has no owner-disclosure plan or factory.
- `ExplicitOwnerPublicEffectsBaseline` permits a post-EGRESS parent collector.
  Each authenticated owner may disclose only its own already-public NF and its
  two already-public tuple hashes, bound to that owner's canonical contract,
  round, run/attempt/cohort, capture plan and exact verified projection.

The collector consumes one nonforgeable verified-effects plan plus exactly
three one-shot authenticated owner capabilities. It requires owners 0/1/2,
three distinct sessions/contracts, and an exact disjoint partition of the
three public NFs and six public tuple hashes. Its typed
`ExplicitOwnerPublicEffectsAuthority` preserves the grouped
owner-to-NF-to-two-tuples mapping in canonical owner order. A flattened set,
host fixture, JSON report, caller hash or success Boolean cannot mint it.

The verified plan is minted only by a concrete bridge consuming a live
post-EGRESS claim from the genuine registered `FinancialConstruction` and its
matching durable `EgressRelease`. The driver/baseline authority types do not
friend undefined class names; a hostile translation unit cannot define a
lookalike friend and call their private constructors.

Authenticated transport alone does not prove that an owner-supplied NF/tuple
pair came from that owner's private construction. Three authenticated owners
could swap claims while still satisfying the global partition. The selected
registered exporter therefore emits a source/layout-bound owner-effects recipe.
After matching durable EGRESS, the baseline-only recipe bridge MAC-opens exactly
the three 256-bit owner NF columns and the 6x6 authenticated output-permutation
selectors. It requires Boolean, one-hot rows and columns, maps source rows
`2*owner` and `2*owner+1` to the six already-public EGRESS tuple hashes, and
requires exact equality with the plan's three-NF/six-tuple sets. Raw tuple
bytes, owner bodies and other witness columns never open. The bridge then mints
three move-only `OwnerPrivateEffectsAuthority` values bound to the owner
contract, lineage, capture plan, projection, plan, durable EGRESS, policy,
relation source and recipe identities. It claims the plan before opening, so a
replay or concurrent loser cannot disclose or mint a second set.

The source-only `AuthenticatedBaselineOwnerReceiver` now enforces consent
before selecting or opening any of the 804 mapping bits. After EGRESS it
re-authenticates all three owners, sends the exact 459-byte pre-disclosure
challenge, and verifies each response against a parent-issued long-lived
logical-owner roster capability. The logical identity remains private and
stable across both rounds; the TLS certificates, attempts, cohorts, capture
plans, projections, financial runs and sessions remain fresh. The verified roster is burned to
mint a one-shot pre-disclosure authority, and only then may the recipe MAC-open
the mapping wires.

The same TLS sockets remain open across that opening. Every owner must then see
the same fixed 683-byte mapping challenge from P0/P1/P2, verify all three
pinned server certificates and recompute its NF plus two full-row hashes and
commitments from its actual 520-byte rows. The 40-byte acknowledgment binds the
baseline classification, round, owner, run/trial/attempt/cohort, capture plan,
projection, context, owner contract, logical owner and roster identities,
pre-disclosure challenge, relation source, recipe, policy and consent nonce.
Wrong certificate, proof, owner, row, nonce, projection, ACK, disconnect or
replay poisons and burns the attempt.

Each child submits one fixed 1,524-byte private domain payload through its
retained role-completion endpoint. The endpoint independently authenticates
the child PID, role, round, fork plan, offer, ACK and channel nonce and requires
exactly one packet, EOF and zero exit. The parent collector requires all three
roles for both rounds, distinct plan/EGRESS/session identities, identical owner
truth per round and the same ordered private logical-owner roster across
rounds, while the ordered financial runs, attempts, cohorts, capture plans and
projections must be distinct, before releasing one one-shot truth input per isolated owner scorer.
After all three exact final acknowledgments, role 0 consumes a separate
one-shot `ExplicitOwnerPublicEffectsAuthority`. The dispatcher records one
fixed 693-byte `explicit-owner-public-effects` leaf between aggregate release
and outbound route. Its three owner-ordered rows contain only owner contract
identity, the already-public NF and two already-public tuple hashes, with exact
run/trial/attempt/cohort, capture-plan, projection and context lineage. It has
no HiddenCandidate factory and contains no logical-owner identity, raw TLS
certificate, private body, body hash or path. Private score truth still travels
only through the isolated scorer channel.

The source-only role-blind handoff now has a typed parent-fork boundary. The
parent mints the endpoint pair before intake, consumes the writer into a fork
plan bound to classification, trial, run, attempt, cohort and capture-plan
identity, and gives only the authenticated P0 child fixed FD30. Its private fork
binding includes the actual parent/P0 PIDs, fork plan, offer, ACK and channel
nonce. P1/P2 close inherited high-descriptor aliases before child code; the
parent closes its source alias after the forks. The retained parent endpoint
must match that exact route and P0 acknowledgement. The route accepts exactly
10,685 bytes, distinguishes credentialed zero-length records from kernel EOF,
and acknowledges only retained public bytes. Replay, stale round, cross-arm
substitution, wrong parent route, missing parent binding and FD mixup refuse.

The session/dispatcher bridge now consumes only the typed retained route after
the exact durable EGRESS, emits one outbound record and one END, and gates P0
party completion on that close; P1/P2 cannot receive FD30. The source-only
concrete role program orders real sealed-query/PackedModel admission, immutable
TLS roster construction, registered construction, independent proof
verification, durable release, conditional baseline disclosure, route and
party completion without a digest, path or JSON authority substitute.

The one-round parent does not collapse this evidence into a public receipt or a
native-terminal token. It retains the live route, all three move-only
parent-observed party completions, optional baseline effects and the clean
three-child wait result inside one indivisible authority. Route ACK without a
matching P0 completion, missing/duplicate role, mixed classification or
lineage, wrong build/capture plan, nonzero exit and replay all consume or refuse
the join.

The source-only persistent parent now forks exactly three children once and
keeps those PIDs and the private process-session identity across R1 and R2. R2
cannot activate until R1 has been fully deferred. The final trial join consumes
both round authorities and the persistent session, requires distinct public
round lineages plus the same opaque fresh-owner roster identity, and retains
both routes, all six party completions, conditional baseline effects and the
clean final wait. A sealed measurement bridge atomically consumes this
indivisible trial authority into the six-party `TrialCaptureJoiner`; it cannot
be reconstructed from public fields or supplied from a second process tree.

The capture plan's raw lowercase trial UUID is also source-bound now: a live
immutable roster and parent capture plan must first produce a
`RosterBoundCapturePlan`, and production bootstrap accepts only that composite.
The bridge checks the explicit domain-separated UUID-to-trial identity and
burns both inputs on every attempt.

This remains source-only. Production plan, compiled-model and roster authority
minters, selected producer archive/C03/C1/terminal admission, the selected
10-by-6 manifest, selected observer execution and a selected main are absent.
The hidden candidate still has no recipe or receiver factory. Registered
configuration and launch remain false, so no actual baseline or privacy
measurement is claimed.

## Measurement completeness and terminal joins

The parent producer core is two-phase. `start` consumes and immediately drains
all ten fixed read ends concurrently; `finish` consumes two post-EGRESS route
capabilities and the authenticated child/END/EOF result. A valid route is one
role-blind aggregate mailbox endpoint carrying exactly the 10,685-byte
projection after the full-cohort barrier, with no owner-derived socket/path and
zero per-owner ACKs. Variable per-stream counts, lengths and transcript hashes
are private join evidence. Public receipts contain only fixed lineage, closure
booleans, constant 10/10/0 aggregate counts and a fresh opaque session
capability unrelated to transcript contents. A private 0700 spool directory
capability moves directly into the fully defined observer supervisor; there is
no public fd/path/body/hash accessor or forward-declared friend. The selected
pinned Python loader/stdlib capsule and final session/dispatcher
route-completion callsite remain absent, so actual launch remains false.

Artifact presence is not leakage-model completeness. Each admitted capture
field now has one explicit status: `constraint_modeled` requires a positive
field-specific modeling count; `source_assumption_covered` requires an exact
digest from the selected source-assumption registry and is not represented as
measured evidence; `unmodeled`
forces the affected view to remain unqualified. Zero-count or default modeled
fields are rejected. P1's new `owner-input-offset` and
`owner-input-preprocessing-share` lane names are exact; the legacy masked-share
label is rejected. Opening grammar separately names the masked field/G1 Beaver
differences and final A/C/B2 proof openings; no raw B1 or generic masked-opening
lane is admitted. Only record grammar, exact public projection bytes and
literal public-ID scans are constraint modeled. Nonliteral
share/MAC/randomness/opening implications, the explicit local MAC-key share,
and wire time/length/message
order/direction/peer/fork/abort/retry remain unmodeled. C03 v9 adds canonical
local authenticated G1 state at BASE/MIXED/PRODUCTS/FINAL and authenticated G2
state at BASE/FINAL. Exact stage order, share-then-MAC layout, repeated A/B2
equality, grammar and literal public-ID scans are modeled. Nonliteral group
meaning, query/MSM capture correspondence and mixed-protocol transcript meaning
remain unmodeled. The producer preserves
C03 as opaque wire, while the isolated model bridge independently parses the
exact v9 seventeen-lane grammar and v2 raw END/kernel-EOF closure. Semantic 17
binds each scalar share/MAC pair to its finite callsite ID, kind and element
count; all 22 selected sites must appear, while a repeated site is accepted
only as another complete atomic binding/share/MAC group. The HELLO binds the
selected model preimage, query-store preimage and scalar-callsite manifest. It
joins the P1 HELLO and
receipt row to the selected exact ten-role launch-closure preimage and checks
that preimage's canonical aggregate digest. Only this
source/build/launch/role/fixed-FD provenance and literal model/query/callsite
bindings are constraint modeled;
dual substitution, JSON replacement, missing or reordered local MAC-key
capture, and closure mismatch refuse. This does not model the nonliteral
meaning of any cryptographic lane or make the source-only producer/launcher
actual authority. The complete 5N DDNNT
owner input is selected in source, while the stock-additive alternative is
deferred because P1 share substitution is not bound to owner intent. Neither
the DDNNT argument nor the conditional MASCOT/OT/TLS analysis is measured
evidence or a selected source assumption. Remaining dispatcher
route/contact/terminal channels likewise stay unmodeled.

The isolated model also derives a private per-view open-field inventory from
the exact typed leaves. Each entry binds one unmodeled category/field to its
leaf schema and records only a pending direct-constraint requirement, a pending
selected-source-assumption requirement, or a mapping-dependent measured
failure. These proposals never change ledger status. The child-internal
completion validator recomputes the fixed four views, exact ten-leaf set,
terminal-aware candidate counts and lattice; it refuses unless all four views
have zero missing and zero unmodeled fields. The detailed inventory, leaf
identities, bodies and hashes are not parent-visible.

This empirical gate is scoped to the exact pinned, instrumented passive P1
protocol process plus passive owner1 view. An arbitrary modified/malicious host
or binary and host memory/log/swap/cache/page-schedule/CPU/GPU/covert channels
are a separate out-of-scope, unqualified boundary. They are not modeled fields
and cannot be used to mint a PASS. The theoretical full-party OT/PRNG random
tape is also outside the admitted empirical P1 view. An exact boundary receipt
labels none of these channels modeled or harmless and blocks general,
active-malicious and host claims.

The frozen per-round uniqueness and six-created-pair requirements also apply
after the complete two-round terminal join. The private scorer projects the
final workload set back to eligible NF, output and NF-to-created-pair
marginals. A workload with multiple complete vectors still fails if those
vectors agree on any eligible prediction or leave either honest NF fewer than
six possible created pairs. This is a correction to threshold application, not
a threshold change.

## Security boundary

The party completion is evidence of one role's actual proof-bound durable
EGRESS and exact local projection only. It is not evidence that all parties
finished, that any producer stream closed, that local capture is complete, that
a candidate was accepted by Testnet, or that terminal Exit privacy holds.

The outer supervisor must test wrong/missing/duplicate/replayed party and round,
mixed run/head/lock/capture/projection bindings, authenticated IPC/PID failure,
missing END or EOF, nonzero child exit, and parent crash at every durable write
boundary. Ambiguity consumes the attempt and requires fresh identities; it
never weakens a join.

The measurement parent must additionally test wrong classification, truth
release before the frozen barrier, duplicate or wrong-owner scores, partial
aggregate, cross-run comparison, manifest/process mismatch and concurrent
duplicate delivery. Public receipts remain inspectable evidence beside a live
token; they are never token factories.

## Alternatives rejected

- Per-party global capture completion: rejected because the party cannot
  observe the global producer or the other round/roles.
- Self-authored serialized completion reports: rejected. A fixed binary packet
  is admissible only as the private wire format of a sealed domain bridge that
  consumes the genuine child authority and a kernel-authenticated one-shot
  endpoint, then mints a distinct parent capability after exact binding, EOF
  and exit checks. The bytes alone remain non-authoritative.
- One prelaunch authority spanning accepted Testnet settlement and terminal
  Exits: rejected as circular and as a false privacy scope.

## Evidence boundary

Current controls compile the production source surface and cover intake-before-
completion refusal, exact projection and lock binding, cross-attempt EGRESS,
stale heads, six-party/ten-stream joining, manifest and process binding,
ordering, partial completion, wrong owner/classification/run, replay, duplicate
and race poisoning, and baseline/candidate comparison. Test-only minters are
absent from the production build. These are source controls, not authenticated
production collection, an actual payment privacy result, Testnet acceptance,
terminal privacy, cryptographic review or launch authorization.

Source controls:

- `poc/local-private-payment/private_batch_trial/privacy_measurement_authority.hpp`
- `poc/local-private-payment/private_batch_trial/privacy_measurement_authority.cpp`
- `poc/local-private-payment/private_batch_trial/privacy_measurement_authority_control.cpp`
- `poc/local-private-payment/private_batch_trial/test_privacy_measurement_authority.py`

