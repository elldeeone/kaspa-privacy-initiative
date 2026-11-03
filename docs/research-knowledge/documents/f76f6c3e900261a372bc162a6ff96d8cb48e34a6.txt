# ADR-0097: All-branch fresh-trial history owner

Date: 2026-10-29 UTC.

Status: Accepted source architecture, `CONFIGURED0`. The unbounded registered
ledger and its terminal validator exist, but no production recorder factory,
always-returning producer outcome, mandatory abort sink, selected-parent
callsite or final observer join exists.

The current anonymous archive is only a live-process linear quarantine. It is
not allocation-failure no-drop evidence and is not durable across parent crash
or power loss.

## Problem

Privacy acceptance must not keep only the final successful capture. Parser
refusals, partial C03 tails, nonzero exits, signals and outer exceptions may
themselves reveal which hidden execution occurred. A successful fresh trial
cannot erase those observations.

The current pieces do not yet make retention unavoidable:

- production factories for the per-trial history recorder and outer ledger
  recorder are absent;
- `ParentOwnedCaptureProducer::finish_attempt` returns typed history on its
  ordinary success/failure paths, but internal validation, wait, archive or
  inspection failures can still throw before an outcome authority exists;
- `RunningCaptureProducer` kills and reaps an abandoned child, but its
  destructor cannot export the retained history;
- a C++ destructor cannot return a sealed abort capability to the parent; and
- the producer closure identity is still supplied in the launch plan rather
  than minted as a fresh-trial-bound live authority.

Adding a Boolean failure flag, reconstructing a row from a digest, or trusting
the last successful trial would create a forgeable or incomplete history.

## Decision

1. The selected parent obtains one move-only outer-ledger recorder, reserves
   storage, precreates both actual C03 objects and pins all three pidfds before
   any fresh trial identity is issued or used. Reservation/setup refusal before
   identity use creates no trial row. Preflight is not a promise that storage
   cannot fail later: exhaustion or write failure after identity use produces
   an infrastructure-unavailable terminal and invalidates the whole run.
   The durable design must create a private source-owned `0700` spool directory
   and prelink ten `0600` files before identity use, retain the sole opaque
   directory binding, and `fsync` each file and its directory. Ordinary callers
   receive no path or descriptor getter. Unlinked `O_TMPFILE` objects are
   admissible only for the current live-process control path; they cannot
   satisfy crash or power-loss retention.
2. Each attempt is a complete fresh trial containing the same fixed two-round,
   ten-stream program. A failed trial is never retried under its identity. A
   continuation can issue only a new trial identity and rerun R1 plus R2.
3. The sole producer owner consumes the running child exactly once and returns
   an always-returning, source-owned outcome authority. Its closed variants are
   complete, complete-failed-view, or infrastructure-unavailable. Complete and
   complete-failed-view variants retain the exact two precreated C03 objects
   from slots 3 and 8, including a genuine reserved zero-byte R2 object when R2
   never began, plus full `RunBinding`, closure, parser, monotonic and typed
   pidfd-exit evidence. No caller Boolean, status integer, digest, fd or
   serialized row can construct a variant.
   Every result shell and STOP shell is allocated before consuming the running
   child. Builder-to-quarantine and outcome-to-STOP transitions are
   no-allocation moves. Until injected allocation failures at every later
   boundary preserve the exact ten inode identities and future P1 state-capsule
   descriptor, the implementation reports
   `allocation_failure_no_drop=false`.
4. The outer owner burns the outcome before validation. Only a
   complete-failed-view outcome is appended and yields a move-only fresh-trial
   continuation. A complete outcome appends once, seals the ledger and yields
   one indivisible final bundle retaining the producer completion and
   successful terminal-history authority. Infrastructure-unavailable or
   incomplete capture seals a distinct unavailable terminal, transfers it to
   the mandatory sink and stops the run: it can never retry, score or reach
   privacy acceptance. A deliberately stopped ledger containing only complete
   failed views yields the separate aborted terminal type.
5. The final successful history is accepted only after every earlier fresh
   trial is retained in order. There is no protocol retry cap. Operational
   storage admission happens before trial identity use and cannot truncate or
   silently omit a trial.
6. A mandatory parent-owned abort sink is paired with the outer owner. An
   exception or destruction after trial identity use must finish/reap through
   the always-returning producer outcome. A complete failed view is appended
   before sealing the aborted ledger; an incomplete or unavailable view is
   retained in the distinct unavailable terminal. Either terminal is
   transferred to the sink and stops. Merely killing the child, closing
   descriptors, terminating the process, or validating and then destroying the
   authority is not retention.
7. The owner and sink are move-only. Every supplied capability is move-claimed
   before a throwing check. Replay, mixed-run histories, dropped residuals,
   duplicate trials, reused inodes, flattened wait status and legacy
   `KPBEMPH1`/`KPBEMPC1` bytes fail closed.
8. Selection and configuration remain false until the genuine selected parent
   supplies pre-identity spool reservation and pidfd pinning, the recorder
   factories, fresh-trial-bound producer closure, always-returning outcome,
   typed unavailable terminal, abort sink, aggregate route authority and final
   observer archive join.

## Rejected alternatives

- **Keep only the final successful trial.** Failed attempts are part of the
  observer view and cannot be erased.
- **Retry R2 inside a used trial.** A failure invalidates the whole fresh trial;
  retry means a new identity and full R1+R2 execution.
- **Use a fixed retry limit.** The ledger is an ordered linear container, not a
  fixed-size empirical grammar. Resource admission occurs before trial use.
- **Synthesize failure rows in a catch block.** The catch site does not own the
  sole-reader bytes, parser state or authenticated child-exit evidence.
- **Retry after unavailable or incomplete capture.** Missing pidfd, write,
  fsync, inspection or disk evidence means the observer view is incomplete.
  The whole run is invalid; a new trial cannot erase that gap.
- **Let a destructor silently close the ledger.** Closing descriptors destroys
  evidence. The destructor must transfer a sealed typed abort to a retained
  sink.
- **Treat a matching closure digest as authority.** The current launch-plan
  field is caller supplied. A selected factory must mint and linearly bind a
  fresh-trial closure capability.

## Current evidence and blockers

The registered history source retains two O_TMPFILE C03 objects, full producer
binding and wait lineage per fresh trial. The terminal ledger validator accepts
an unbounded ordered ledger (a control covers 65 failed trials followed by one
success), revalidates both sealed objects and raw UUID lineage, and rejects the
legacy v1 empirical byte grammar. This is source/control evidence only.

The narrow current claim is
`live_process_linear_quarantine_owner=true`. The explicit negative status is
`allocation_failure_no_drop=false`, `process_crash_durable=false`, and
`power_loss_durable=false`. Default destruction closes the last anonymous
descriptors and is therefore evidence drop, not retention. A future mandatory
sink must consume every live STOP authority; no destructor may claim durable
retention merely because it closes resources.

An isolated diagnostic sink primitive now exercises the minimum filesystem
mechanics without joining any live authority. Under a test-only bridge it
creates a preidentity private `0700` directory, prelinks distinct `0600`
payload and commit-marker files, reserves payload blocks with
`FALLOC_FL_KEEP_SIZE`, fsyncs the parent, files and child directory, closes all
writer descriptions after commit, and reopens the exact same inodes read-only.
Controls retain a synced partial payload across `_exit`, reject a symlink or
non-private root, reject pathname/inode substitution, and prove replay refusal.
Production exposes no path, fd, body, hash or factory.
Injected fallocate, short-write, `ENOSPC`, payload-fsync, directory-fsync and
read-only-reopen failures produce an opaque typed Unavailable owner retaining
both precreated sink inodes. The commit marker remains empty for every failure
before payload durability; failures after payload fsync still cannot yield a
success authority.

An isolated transactional replay core also replaces the unsafe shape of the
legacy `void consume(span)` interface without yet joining FreshOwner. It
prepares one exact 56-identity set while allocation and refusal may still
throw, preallocates the opaque commit outcome, and then exposes one move-only
`noexcept` commit. Only the selected backend's atomic all-56
compare-and-insert result can become the private Committed arm; replay,
conflict, infrastructure failure, an ambiguous post-write result and an
unknown disposition all become the opaque Unavailable arm. Dropping a prepared
operation performs no commit, and a moved-from replay cannot call the backend
again. That arm privately retains the normalized exact registry disposition
(`ReplayOrConflict`, `InfrastructureUnavailable`, `AmbiguousAfterWrite`,
invalid backend result, or stale/missing preparation) inside the same opaque
transfer so the future composite STOP does not erase why registry acceptance
failed. The production registry factory, canonical positional construction from
the three owner lineages, final receipt/closure preallocation and composite
STOP retaining Ready plus all three verifiers remain absent.

This diagnostic primitive is not the mandatory sink. The source-owned root,
exact failed-view byte schedule, canonical serializer, outer-owner consumer and
selected filesystem/mount policy remain missing, so its status keeps
`source_owned_root=false`, `source_owned_exact_byte_schedule=false`,
`outer_owner_integration=false`, `mandatory_sink=false`, and
`configured=false`. Same-UID pathname or `/proc` access remains a corrupt-host
boundary, and the test does not establish power-loss durability for an
unselected filesystem.

The replay core likewise reports `source_owned_registry=false`,
`ready_three_owner_verifier_join=false`,
`fresh_owner_result_factory=false`,
`composite_stop_retains_all_inputs=false`, `selected_callsite=false`, and
`configured=false`. Its backend rollback and durable atomicity are contract
requirements, not facts about a selected service, until a source-owned adapter
and crash controls exist.

The Round-1 FreshOwner process now has a separate dependency-neutral consumer
contract for its move-only success-or-STOP outcome. The only reserved operation
accepts the live all-branch owner and the live Round-1 outcome together and
returns one opaque, indivisible step authority. Its future success arm must
retain that same outer owner plus the exact issued continuation; its STOP arm
must retain that same owner plus the complete process STOP storage. The
selected Round-1 bridge now immediately and without allocation claims the live
outcome together with the preowned outer ledger into that closed sum. There is
no receipt, state tag, arm extractor, digest or serialized overload. The
mandatory durable sink, Round-2 closed-sum continuation and configuration
remain false; a successful Round-1 step is not a final result and cannot bypass
Round 2.

The all-branch owner is not selectable because pre-identity reservation/pidfd
pinning, the source-owned recorder factories, always-returning outcome, typed
unavailable terminal and abort sink are still missing. Passing the existing
controls is not privacy qualification, Testnet readiness or cryptographic
proof.
