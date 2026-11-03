# ADR-0098: Observe the actual unbounded P1 transcript

Date: 2026-10-29 UTC.

Status: Accepted for a source-only bounded-observer prototype. The genuine
prelaunch minter, selected runtime EOF callsite, observer transfer and launch
remain absent and `CONFIGURED0`. This decision makes no privacy, active-host or
production claim.

## Problem

The prior producer-reservation design requires a source-derived maximum byte
schedule before launch. Eight non-P1 streams have finite grammars. P1 does not:
the selected MASCOT path still has runtime-dependent fork and peer-transport
traffic from the accepted historical-nullifier count, `Mascot-Secrets` cache
validity/regeneration, `OnlineOptions`, SoftSpoken/KOS selection and
preprocessing state.

An operational cap or a previous run's size is not a protocol upper bound. More
importantly, the exact peer vector is part of the corrupt P1 view. Predicting it
and then rejecting a different valid vector would discard the metadata the
privacy observer is supposed to measure.

The finite source-pinned typed subtotal remains useful evidence:

```text
hidden BaseNoFork(H)     = 19,861,945,316 + 57,408*H
baseline BaseNoFork(H)   = 19,861,971,156 + 57,408*H
actual round bytes       = BaseNoFork(H) + 208*F + sum(W(payload_e), e in T)
W(p)                     = p + 112*max(1, ceil(p/65,536))
```

But `F` and ordered peer vector `T` must be observed, not guessed.

## Decision

For the bounded passive observer's **C03 transcript plane only**:

1. Before the P1 role fork, a future source-owned one-shot authority must bind
   the exact `RunBinding`, round and FD23/FD28; accepted-head identity and exact
   `H`; selected P1 source/build/runtime/assets/executable/launcher and main;
   model, query-store and scalar-manifest identities; immutable
   `OnlineOptions`; SoftSpoken or KOS profile and parameters;
   `Mascot-Secrets` fresh-regeneration or pinned-valid-cache policy; the exact
   decorated `Player` virtual surface; expected HELLO identity; and the
   source-owned archive filesystem identity. No caller-authored struct mints
   this authority.
2. The selected integration must consume the already-opened P1 archive in
   canonical topology slot 3/FD23 or slot 8/FD28 from
   `FreshTrialCaptureTopologyReservation`; it must not open a second inode.
   The source-only prototype opens its own anonymous disk-backed `O_TMPFILE`
   only because that topology join is not implemented. Neither path calls
   `fallocate`, imposes a byte ceiling, allocates a payload-sized memory buffer,
   or uses a previous trial's size. The stream is appended incrementally and
   checked with 64-bit overflow refusal only.
3. `P1CapturingPlayer` remains the sole selected `Player` passed to
   `MascotContext`, before setup. Every low-level virtual send, receive,
   broadcast, async receive and `fresh_fork` path is decorated. Fork children
   remain decorated. The static selected-source control rejects another
   production callsite to `P1CaptureStream::peer_transport`.
4. The sole capture reader tees every raw byte into the anonymous inode while
   validating the exact v9 header, sequence, logical-message/chunk order,
   payload digest, fork lineage, scalar binding/share/MAC adjacency, owner
   masks, fixed group lanes, projection seal, full semantic counters and
   completeness footer. It derives ordered peer/fork vector digests and exact
   message, chunk, payload and wire counts from those same bytes.
5. A successful C03 stream contains its END record first. Kernel EOF follows.
   Only after EOF may the runtime `fsync`, recompute the full inode hash and
   size, reopen the same device/inode read-only, recheck it and close the last
   retained writer. This writer-closure transition is the "seal"; an
   `O_TMPFILE` inode does not support a Linux `F_SEAL_WRITE` claim.
6. The move-only **transcript** completion authority retains the exact static
   plan, actual transcript statistics and sole read-only descriptor. Its production API
   exposes no fd, path, body, size, hash, transcript digest or public receipt.
   The future observer bridge must consume it privately and parse the same
   descriptor; no reconstructed event list or caller summary is admissible.
7. ENOSPC, parser refusal, missing END/EOF, abnormal exit, hash mismatch or
   writer-closure failure makes the complete measurement unqualified. The
   existing partial-C03 archive must retain whatever bytes exist. There is no
   within-trial retry, truncation acceptance, alternate path or favorable
   fallback. A retry uses a fresh trial identity.

The static finite schedule still checks all typed non-peer lanes and exposes a
regression oracle. It is not an archive reservation authority and no longer
needs to predict `T`. This decision does not make the C03 transcript the
complete corrupt-P1 process view.

## Comparison with the prior pre-fork exact schedule

| Property | Predicted peer schedule | Actual descriptor stream |
|---|---|---|
| Static `RunBinding`/`H`/options/cache bind | required | required |
| Exact prelaunch P1 bytes | unavailable without an operational cap | deliberately not required |
| Variable peer/fork metadata | prediction target | measured privacy input |
| Storage | pre-reserved maximum | streaming anonymous disk inode |
| Disk failure | prevented only if a true bound exists | typed whole-trial unqualification plus partial history |
| False privacy pass after truncation | must refuse | must refuse |
| General malicious-host protection | no | no |

This supersedes only ADR-0091's requirement that P1 slots 3 and 8 possess a
source-derived worst-case byte bound and prelaunch reservation. ADR-0091's
exact-byte continuity, anonymous inode, sole-reader tee, writer closure,
same-inode recheck, private observer handoff and partial-failure retention stay
in force. The other eight finite stream grammars are unchanged.

## Invariant and threat-boundary consequences

- I-9 is preserved: any archive or parser failure halts qualification.
- I-16 is strengthened: the observer receives the actual timing/shape/contact
  transcript instead of a source prediction.
- Finite host storage remains a liveness dependency. It is not an operational
  policy cap and cannot authorize a truncated trial.
- Same-UID `/proc/<pid>/fd` writable reopen, modified binaries, kernel/host
  compromise, physical memory, swap/cache/scheduler state and covert channels
  remain outside the bounded passive-process threat model and block any general
  or production claim.
- P1-known OT/PRNG entropy and state, `Mascot-Secrets` contents and branch,
  preprocessing/input caches, Beaver material, MAC-check pending state, and
  proof-randomizer/cache state are **inside** the pinned P1 process view. They
  are not captured by v9 and are not derivable merely from C03. Consequently
  `complete_passive_p1_view=false`, and no privacy qualification may consume
  this transcript authority as a complete-view authority.

## Source prototype and remaining gate

The source-only prototype is:

- `privacy_p1_observed_transcript_authority.hpp/.cpp`;
- `privacy_p1_observed_transcript_authority_control.cpp`;
- `test_privacy_p1_observed_transcript_authority.py`.

It exercises a multi-chunk peer event, fork lineage, exact footer/counter
recomputation, scalar binding/share/MAC adjacency, owner widths, G1/G2 stage
order and repeated A/B2 equality, projection/seal equality, compensated
payload/fork/stage/counter mutations, truncation refusal, cross-round and
cross-worker binding, moved-from replay refusal, anonymous disk backing,
writer closure, and the no-public-fd/hash/summary surface.

It deliberately cannot authorize a run. Selection additionally requires:

1. a genuine pre-fork minter from the selected driver and accepted-head
   authority, not the test constructor;
2. the selected sole-reader callsite that invokes completion only after kernel
   EOF and authenticated process exit;
3. direct reuse by the ten-stream producer rather than a second parser or copy;
4. partial-history and whole-trial invalidation joins on every failure path;
5. private consumption by the sealed observer descriptor bridge; and
6. a separate source-owned internal-random-state recorder, or a source-closed
   proof that directly captured derived state is sufficient, covering every
   P1-known OT/PRNG/cache/MAC/proof-randomizer state and both rounds of the
   persistent P1 child; and
7. a full selected build/launch receipt with all status flags still false until
   those joins pass.

The topology-v2 source now reserves two additional P1-private anonymous state
archives before trial issuance. Its parent residual retains two independent
read-only descriptions while the future activation path must transfer the sole
writers to P1 over authenticated `SCM_RIGHTS`. Production transfer, selected
child writers and completion remain false. These archives are separate from
the ten public measurement streams and are never smuggled into the v9 C03
schema.

## Separate observer-v5 process-state plane

The source-only process-state prototype is
`privacy_p1_corrupt_state_capsule_authority.hpp/.cpp`. It starts from a
predeclared plan identity rather than fabricating the later accepted head,
tracks fourteen private-state families, exact thread/object/player epochs,
phase-legal abort nonconstruction, terminal-specific exact event prefixes and
exact plan-supplied hook inventory, and
retains an unavailable partial inode on close faults. Its recorder must begin
after the child validates the exact bootstrap/capture/driver plan but before
`RegisteredRosterPlayerRuntime::begin_after_fork`, because `CryptoPlayer`
performs TLS setup before `RegisteredP1Context` exists.

A child-local C++ capsule cannot cross the process boundary. The separate
`privacy_p1_corrupt_state_parent_rehydration_contract.hpp` therefore freezes a
four-input parent join: ordered authenticated R1 and R2 child dispositions,
the exact `FreshTrialP1StateArchiveResidual`, and pidfd-bound
`PersistentRoleExitEvidence`. Only independent grammar parsing and deterministic
state replay may mint the parent result. No reader-fd, path, digest, status or
HELLO overload exists.

The closed child capsule has a bridge-private rvalue projection into an opaque
disposition residual. Only the complete authenticated state-channel bridge can
consume it; ordinary callers have no fd, hash, body, status or completion
accessor. This is an ownership seam, not cross-process admission evidence.

This is a contract, not live integration. The source-owned hook-manifest
minter, topology writer consumption, authenticated child disposition, pidfd
consumer, archive parser, replay verifier, two-round continuation and observer
consumer are all false. `MascotContext` now owns a sealed
`ContextAndRetry` hook through `unique_ptr`, and the complete final capsule
adapter records that family into shared ledger ownership while generic recorder
fabrication is refused. Complete abort preparation consumes an opaque one-shot
terminal-site authority whose site, phase, class and exception identity are
committed by the terminal manifest. The genuine catch-site minter, selected
adapter caller and source-owned hook-manifest minter remain absent; setup-time
callbacks remain separate `ProtocolSetup` work. The whole passive-P1 process
view remains `MISSING` and `CONFIGURED0`.

Passing the controls establishes source behavior only. It is not cryptographic
proof, privacy evidence, launch evidence or production safety.
