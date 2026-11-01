# ADR-0083: Parent-owned fresh-attempt authority

Date: 2026-10-28 UTC.

Status: Accepted source architecture. Process integration, selected-build
qualification and execution remain incomplete. `CONFIGURED=0`; launch is not
authorized.

## Problem

ADR-0079 puts direct accepted-head authority inside each registered MPC party.
Fresh run, trial, attempt, cohort and owner-contract identities must be consumed
before any owner listener accepts private input. A caller-supplied
`prior_identities` list, completion JSON or successful prior report cannot prove
freshness after a crash.

One shared durable registry cannot be independently consumed by all three
parties: the first valid append would make the other two look like replays.
Conversely, three unrelated role-local registries would not provide one atomic
all-party decision and would enlarge rollback and partial-approval states. The
registry must also remain unavailable to the processes whose proposals it
judges.

## Decision

Use one outer supervisor as the sole owner of one durable identity registry and
its trusted anchor. Add a two-phase protocol before private intake:

1. Each role sends the supervisor a role- and session-bound public proposal for
   the same run, trial, attempt, cohort, direct `AcceptedFinancialHead` identity
   and three canonical owner-contract identities. The proposal also binds the
   exact registration, service, source and selected build authority.
2. The supervisor requires exactly one proposal from roles 0, 1 and 2 and exact
   agreement on every common field. Missing, duplicate, stale or disagreeing
   proposals fail before registry mutation. Caller history and completion
   reports are not protocol inputs.
3. Only after all-three agreement does the supervisor atomically append the
   eight public identities to the journal-owned registry and its trusted
   checkpoint. An aborted or ambiguous append never permits owner intake. If
   the append is durable but its acknowledgement is lost, the identities remain
   consumed and the trial is abandoned rather than retried under them.
4. The supervisor returns a distinct role/session-bound, one-shot approval to
   each party. A partial delivery does not authorize the missing roles and does
   not permit a replacement cohort under the consumed identities.
5. Each party directly rechecks the exact accepted head immediately before its
   durable LOCK. That check and its role-bound approval mint a non-forgeable,
   linear `RegisteredFreshAttempt`; serialized JSON cannot mint one.
6. After LOCK, the party burns that capability at the final seam immediately
   before `claim_owner_intake` can create an owner listener. Reuse, copying,
   wrong-role transfer and stale-head use fail closed.

The supervisor does not receive owner bodies, MPC shares, proofs or settlement
data. Proposals, registry events, approvals and public receipts contain public
identity hashes only. Registry paths and file descriptors are absent from the
child mount/descriptor closure; close-on-exec alone is necessary but not a
complete namespace boundary.

## Storage and rollback boundary

The local journal is append-only and checked against a separately trusted
checkpoint. Truncation, one-sided rollback, replacement, hard links, symbolic
links and authority drift must refuse after restart.

A same-inode, coordinated rewrite of both journal and anchor to an older
mutually consistent pair cannot be detected by an unkeyed local hash chain.
Therefore a future configured supervisor must place the anchor in a genuinely
separate monotonic or permission-separated trust domain that children and the
registry journal writer cannot roll back. Mode `0600` under the same UID is not
that boundary. Until this is implemented and adversarially tested, coordinated
anchor rollback remains outside the source-only model and blocks
`CONFIGURED=1`.

The 2026-10-28 local capability check found that the user systemd manager
explicitly refuses `DynamicUser=` for user units, so it cannot provide the
separate durable owner. The available rootful Docker daemon can run a
network-disabled service under a distinct UID with named-volume state and a
Unix socket omitted from party namespaces. That separates the anchor from MPC
children, but the Docker operator can still replace or roll back the volume.
It is therefore at most an explicit research trust boundary, not a
trust-minimized monotonic authority, and is not selected as sufficient for
configuration by this ADR.

A bounded source backend and parent-only C++ adapter now exercise that Docker
boundary with `--network=none`, a distinct non-root service UID, named-volume
state, a supervisor-only authenticated Unix socket, mutual peer credentials,
restart, stale/replay, concurrency and replacement controls. This closes the
party/child access path in the tested container topology. It does not change
the Docker-operator rollback conclusion, and the adapter is not yet in the
selected registered build or party namespace closure. The source-only
production bridge now consumes a non-forgeable compiled outer selection plus
supervisor capability, opens the registry and Docker client only in the outer
parent, and owns them for longer than the supervisor by construction. Its
returned surface exposes proposal submission, readiness and approval only: no
registry/anchor path, descriptor, capability or client getter exists.
Authenticated party IPC and selected-build activation are still absent.

`RegisteredProposalBridge` is completely declared in the supervisor authority
header shared by the supervisor and Docker adapter. Private supervisor and
anchor-client constructors no longer friend a name that an unrelated
translation unit can define. Negative compile controls redefine the former
friend name and require a class-redefinition failure; public digests still have
no capability factory.

## Trial and evidence boundary

The existing trial03 READY journals predate this authority. Retrofitting a
registry would falsely claim that it observed identities from the start, so
trial03 cannot be promoted. Integration requires a fresh unfunded trial, exact
new selected build and fresh run/trial/attempt/cohort/owner identities. The
publicly recorded aborted `a86414d108d6886768f367a3384fd24de49d4fde7475d8469d92adee29c0e6ab`
run is a mandatory tombstone and must never be reused or qualified.

Source controls must cover all-field disagreement, duplicate roles, a missing
role, concurrent proposals, crash boundaries, partial approval delivery,
approval replay, wrong role/session, stale head, registry replay and rollback.
Passing them is source evidence only. No actual supervisor/party process,
private intake, MPC, proof, funding, broadcast, settlement or privacy result is
claimed by this decision.

## Alternatives rejected

- Three role-local registries: rejected as the selected design because they do
  not create one atomic all-three freshness decision.
- Let every MPC party open the shared registry: rejected because only one can
  consume a selection and it exposes the authority to children.
- Trust caller prior-identity or completion files: rejected because they are
  mutable reports, not durable freshness authority.
- Retry after ambiguous approval delivery: rejected because private intake may
  have started; use a fresh trial identity instead.

## Reconsideration

Reconsider this decision if a simpler mechanism provides one atomic durable
all-party consume, direct-head binding, linear role approvals and a stronger
rollback boundary without giving registry access to children. Any change must
preserve ADR-0077's durable-attempt invariants and ADR-0079's direct accepted-
head authority.

