# Outer measurement child supervisor

Status: **implemented transport core; unconfigured and unqualified**.

`privacy_measurement_child_supervisor.*` is the sole production mint for
`ChildCompletionEvidenceAuthority`. It does not select a trial, create capture
completion, release owner truth, choose worker binaries, mount private inputs,
or authorize Testnet launch.

## Authority contract

The parent entry points consume genuine move-only permits and a sealed
`MeasurementWorkerCapsuleAuthority`:

- `run_observer(ObserverExecutionPermitAuthority&&, capsule&&,
  NativeEmpiricalResultAuthority&&)`;
- `run_owner_score(OwnerScoreExecutionPermitAuthority&&, capsule&&)`;
- `run_aggregate(AggregatePermitAuthority&&, capsule&&)`; and
- `run_owner_comparison(OwnerComparisonPermitAuthority&&, capsule&&)`.

There is no overload for a public receipt, digest, path, Boolean, JSON object
or caller-built completion. The Observer path moves and burns the permit,
capsule and empirical residual before any validation that can fail.

The capsule already owns independently sealed runtime, source, assets and
role-input descriptors. The supervisor exact-matches all six selected worker
identities, executes the retained runtime descriptor with `execveat`, installs
the source/assets/input descriptors at their fixed numbers, supplies one fixed
argv0, and supplies an empty environment with no caller arguments.

## Pre-exec static-runtime boundary

`privacy_measurement_preexec_sandbox.*` installs an inherited seccomp filter
after descriptor isolation and immediately before the sealed `execveat`.
It permits that exec only for the exact close-on-exec runtime descriptor, the
one read-only empty-path address and `AT_EMPTY_PATH`. Native `execve`, x32
syscall aliases, runtime-FD recreation (`memfd_create`, `dup*`, and fcntl
duplication), host path opens/mutations, namespace/privilege operations,
network creation/addressing, and process/host introspection return `EPERM`.
Only the already-authenticated fixed capability operations needed to receive
the offer, ACK it, and receive owner truth remain. After the ACK, the worker
stacks the existing role-specific Landlock/seccomp filter.

The bootstrap filter deliberately denies every `openat`, including from FD40:
a classic seccomp filter cannot prove that a caller-supplied path stays beneath
a directory. A selected static observer must therefore receive a sealed regular
capture archive (or a separately reviewed `openat2(RESOLVE_BENEATH)` design),
not the current directory-shaped observer input. This is still `CONFIGURED0`.
The static runtime remains part of the private TCB between exec and the
post-ACK role filter; seccomp filters are inherited and cannot make the
exec allowance stateful. The runtime descriptor's `CLOEXEC` plus the
descriptor-minting denies make the allowance unusable after successful exec.

FD62 is now a parent-created exact-size memfd for Observer and OwnerScore only.
The parent binds the source-owned role ABI identity and size into the offer;
the child may perform only the exact role write; and the parent recomputes the
body hash, validates the full ABI, seals/reopens it read-only, and joins exact
credentials/EOF/exit. Aggregate and Comparison have no FD62 body. Observer v3
is explicitly open-only and nonauthorizing: the sole sealed output is joined
with the opaque native empirical residual and retained through RunMeasurement,
but yields no prediction, phase, Step-2, barrier, FD41 or Step-3 permit.

## Fixed transport

The parent creates a private `AF_UNIX/SOCK_SEQPACKET` socketpair with
`SO_PASSCRED`. The selected child inherits only fixed FD 63 and the sealed
executable FD before exec. The protocol is exactly:

1. one parent offer binding role, owner scope, permit, all six worker
   identities, outer-parent lineage, random transport session and exact parent
   and child PIDs;
2. one child ACK binding the same offer and session;
3. one fixed completion binding the permit, role/owner, ACK, public receipt,
   optional owner capsule seal and typed aggregate/comparison outcome;
4. EOF; and
5. `waitpid` for the same credential-authenticated PID with exit zero and no
   signal.

Every packet has a versioned fixed binary encoding. Both sides recompute the
offer, ACK and completion identities. The parent rejects wrong credentials,
PID, nonce, role, owner, permit, worker, packet count, result shape, EOF, exit
or executable hash. Only after all checks does it mint a one-shot evidence
authority and pass it, with the original permit, into the typed runtime bridge.

## Truth boundary and remaining work

The public measurement channel never carries owner truth, mappings, raw score
capsules or JSON. The baseline parent must separately consume
`BaselineOwnerScoringLaunchAuthority` and deliver each
`OwnerScoreTruthAuthority` directly to its isolated owner scorer. The outer
acceptance path sees only the scorer's public receipt and opaque capsule seal.

The feasibility-aware Observer v4 worker, private truth endpoint, complete
empirical-history producer and registered outer-parent callsites are not
wired. The
runtime bridge therefore keeps `registered_transport_integrated=false`,
`configured=false`, `launch_enabled=false` and `actual_privacy_pass=false`.
The implemented transport core is not actual privacy evidence.

### Frozen CPython worker build closure

The static CPython closure is byte-pinned across compiler/binutils/CPython,
338 transitive headers, static libraries, runtime tool dependencies, frozen
Python modules and deterministic FD60/FD61 archives. Two independent builds
produce the same static ELF with no `PT_INTERP` or `DT_NEEDED`; forbidden
filesystem/network imports and syscalls refuse. The read-only ADR-0094 v3
candidate records the six exact source/build/runtime/assets/ELF/launch-plan
artifacts, but is explicitly ineligible for the production table because v3
reports open Step-2 rows and writes no FD62. A feasibility-aware v4 model/ABI,
genuine native closure authorities and independent review are still required.

## Controls

`test_privacy_measurement_child_supervisor.py` executes real child processes
and covers all four roles plus wrong executable hash, nonce/ACK, PID,
credential relay, role, owner, permit, duplicate completion before EOF, missing
completion, invalid result, nonzero exit and moved-permit replay. Production
build controls confirm that test transport hooks and test minters are absent.
`test_privacy_measurement_preexec_sandbox.py` additionally covers host/proc
opens, FD40 traversal, filesystem mutation, x32 aliases, runtime-FD recreation,
wrong exec FD/path/flags, network creation and process introspection before the
worker reaches `main`.
