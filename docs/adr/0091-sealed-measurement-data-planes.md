# ADR-0091: Sealed measurement input and output data planes

Date: 2026-10-29 UTC.

Status: Accepted source architecture, implementation incomplete. The existing
path-backed spool and receipt-only child results are not selected production
paths. The static observer, private coverage-to-prediction function, sealed
producer archive, authenticated worker output and barrier bridge remain
`CONFIGURED0`; no privacy qualification follows from this decision.

## Problem

The ten capture streams have exactly one genuine reader: the parent-owned C++
capture-producer child. That reader parses and hashes the wire bytes, but the
current implementation discards the bytes. A separate Python process cannot
read the same pipes again. A later directory assembled from paths or caller
data is therefore neither the observed stream nor a continuation of the live
producer authority.

The measurement workers have the inverse defect. Their authenticated control
channel returns only fixed metadata and opaque identities. No private output
bytes survive as a typed capability, so a score input, aggregate input or
barrier can currently be rebuilt only from fixtures or public receipts. A
random parent nonce echoed by a child proves transport continuity, not that a
prediction or score was computed.

## Decision

### Producer-to-observer input

1. Before fork, the private producer parent creates one anonymous disk-backed
   `O_TMPFILE` object for each fixed stream FD 20 through 29 beneath a
   source-owned filesystem root. It rejects RAM-backed filesystems, symlinks,
   non-regular objects, links, wrong mode and duplicate inodes. The parent
   retains the exact writer descriptions across fork; while the sole C++ child
   reader parses each stream, it also writes every exact raw wire byte to that
   stream's inherited object. No second reader, named path, producer JSON,
   caller event object or regenerated body is authoritative.
2. After the exact child exits, the parent `fsync`s each object, recomputes its
   byte count and hash, independently reopens the same inode read-only,
   rechecks the hash and closes every retained writer. This is a typed
   writer-closure transition, not a Linux `F_SEAL` claim. On parser refusal,
   read failure or abnormal child exit, the parent performs the same transition
   for the exact partial C03 slots rather than losing the attempt history.
3. The child sends one fixed completion packet, exactly ten read-only descriptors
   and its kernel credentials over the already parent-owned
   `SOCK_SEQPACKET`. The parent rejects missing or extra descriptors,
   any extra ancillary record, `MSG_TRUNC`/`MSG_CTRUNC`, duplicate
   device/inode identities, wrong
   credentials, wrong stream order, wrong anonymous-file identity or mode,
   size or root mismatch,
   trailing records, missing kernel EOF, signal exit or nonzero exit. It
   receives with close-on-exec semantics and matches every descriptor to the
   parent-retained inode before writer closure. The successful full archive is
   accepted only after the retained parent writers close and a final
   same-inode size/hash check succeeds.
4. A move-only private writer-closed archive authority retains the ten descriptors,
   the producer closure evidence and their exact run/round/kind/FD lineage.
   It has no public fd, path, body, count or hash accessor. A public producer
   receipt, opaque closure identity or directory fingerprint cannot recreate
   it.
5. The observer-admission join consumes that authority together with the live
   C03, C1 and terminal/public-continuity authorities. It exact-matches the
   private producer evidence, then creates one canonical sealed read-only FD40
   archive. The archive includes the finite manifest and private evidence
   needed for the child to recompute every stream root, END and EOF; none of
   those fields is copied into a general-parent receipt.
6. The existing path-backed `ProducerSpoolAuthority` remains a negative and
   migration fixture. Directory mode, inode, size, link count or a claimed
   writer-closure digest is not sufficient production authority: same-inode
   mutation and an unmodeled path alias can otherwise replace bytes.

### Worker-to-parent output

7. Only `Observer` and `OwnerScore` have private fixed-size canonical binary
   output ABIs. Each body contains exactly four ordered view slots. `Aggregate`
   and `OwnerComparison` return their already-typed public outcomes and receive
   no private output body or FD62 write permission. The parent creates an empty
   `MFD_ALLOW_SEALING` object, binds its device/inode, source-owned ABI identity
   and exact size, transport session, role, owner and permit into the
   authenticated child offer, and installs its sole writable alias at fixed
   FD62. The role sandbox may permit only
   `pwrite64(FD62, ROLE_ABI_SIZE, 0)` with full-width argument checks; it denies
   `pwritev*`, `ftruncate`, `lseek` and every other FD62 mutator or data mover.
   Classic seccomp cannot enforce a syscall count, so the authority claim is
   the final exact source-pinned body after child exit, independent parent
   parse/hash validation and sealing, not an unobservable exactly-once syscall
   history.
8. Output originates only after the selected program executes. For the
   observer, the future selected serializer must accept only the one-shot
   native prediction authorization only after the sealed v3 result body proves
   every Step-2 row closed by its allowed evidence authority; the current open
   v3 body cannot authorize prediction;
   a Python token, boolean, summary, digest, caller prediction or opaque nonce
   is not an input. The selected
   worker contract will issue one full-size zero-offset write and commit the
   exact size and SHA-256 in its authenticated completion packet. The parent
   does not infer syscall history from the final memfd: authority is granted
   only for the final canonical body after authenticated EOF, clean exit,
   independent parse/hash validation and sealing.
9. The parent requires exact completion credentials, session, role, owner,
   permit and full `RunBinding`; exact control EOF; and clean `waitpid` exit.
   It independently checks FD62 device/inode, size and bytes, recomputes the
   hash, adds all four seals, reopens the object read-only and closes the
   writable alias. A move-only role-scoped output authority retains the sealed
   descriptor plus process and exit lineage. Public APIs expose neither bytes
   nor an unsalted content oracle.
10. Observer output splits exactly once into three owner-scoped FD41 input
    endpoints. Each owner-score output splits only into its fixed aggregate
    and comparison inputs (FD43 through FD51). Every split rechecks
    device/inode, read-only access, seals, size and full lineage, and reopens an
    independent close-on-exec read-only file description for every child. It
    never duplicates a shared-offset open-file description. All sibling and
    inherited aliases close before exec. No fixture endpoint or copyable
    receipt can substitute for a retained sealed output.
11. The sole production barrier-freeze bridge consumes the authenticated
    observer completion and sealed observer-output fanout. Its private barrier
    identity binds the exact output identity, size and hash plus run, trial,
    permit, worker process and clean-exit lineage plus a fresh private one-shot
    secret. Public barrier and observation correlation identities are fresh
    non-content-derived values, never unsalted hashes of the low-entropy
    prediction or score catalog. `RunMeasurement` retains the
    live private output authority through `accept_observer`; it may not discard
    it and retain only `PublicObservationCompletion`. Owner-score capsule seals
    are derived in the same way from exact retained score outputs, never from
    random nonces.

## Rejected alternatives

- **Run the Python producer after the C++ drain.** The pipes have one reader;
  replayed or reconstructed data is not the captured stream.
- **Trust a path-backed spool after stat checks.** Device, inode, size, mode
  and link count do not prove immutability while any path or writer alias can
  still modify the inode.
- **Pass raw descriptors, bodies or hashes to the controller.** This exposes
  private observer features and creates a reusable construction surface.
- **Let the child choose an opaque completion identity.** A malicious worker
  can encode private output in that identity, and an echo proves no output
  computation.
- **Accept caller-authored predictions or coverage booleans.** This bypasses
  the four-view exhaustive-lattice and zero-unmodeled private gate.
- **Use a variable-size worker output.** Its length becomes an avoidable
  privacy feature and requires a broader sandbox write rule.
- **Keep unbounded raw capture in memfd/tmpfs.** Multi-gigabyte capture can
  consume RAM and full swap, killing both the trial and its failure evidence.
  Anonymous disk-backed objects preserve the no-path capability shape without
  making trial liveness depend on available memory.

## Security and privacy consequences

- Missing bytes, an uncovered view, parser disagreement, wrong descriptor,
  replay, writable reopen, wrong lineage, missing EOF or abnormal exit halts
  the measurement. This can reduce liveness but cannot create a privacy pass.
- The producer/output parent process reads and independently hashes the raw
  stream and worker-output bytes. That process and its address space are
  explicitly inside the private measurement TCB; C++ API confinement is not
  OS/process secrecy from that parent. APIs outside the private TCB learn only
  bounded role status and the intentional aggregate or comparison outcome.
  They receive no raw bodies or unsalted content-derived receipt hash.
- Worker-output sealed memfds protect that bounded handoff from later writes
  through ordinary file descriptors. Producer input instead relies on exact
  writer closure plus read-only capability confinement. A process with the
  same UID and access to `/proc/<pid>/fd`, or a privileged host process, can
  reopen an anonymous `0600` object writable; such processes are explicitly
  inside the corrupt-host/private-measurement TCB boundary. Neither mechanism
  protects against a modified kernel,
  host memory disclosure, swap disclosure, covert channels or an unselected
  worker/runtime.
- Passing controls establish only these source and process invariants. They do
  not prove cryptographic correctness, anonymity or production safety.

## Evidence and remaining gate

The current authority, C03/C1 joins, exact worker FD map and fail-closed child
transport are implemented under
`poc/local-private-payment/private_batch_trial/`. The isolated
`privacy_capture_producer_archive` core now retains ten anonymous disk-backed
raw-stream objects, supports parent-retained recovery after child crash, and
validates exact same-inode read-only transfers. Full and C03-only sealing are
transactional: all ten originals remain owned until post-seal C03 inspection
commits, and any seal/inspection failure can move the exact objects into an
opaque quarantine authority. The runtime unavailable outcome and mandatory
abort sink that must consume that quarantine remain missing. The core
reports only `live_process_linear_quarantine_owner=true`;
`allocation_failure_no_drop`, `process_crash_durable`, and
`power_loss_durable` remain false. An unlinked `O_TMPFILE` disappears when the
last process descriptor closes. Crash-retained evidence therefore requires a
future private prelinked `0600` spool beneath a source-owned `0700` directory,
with exact opaque inode binding and file/directory `fsync`. The core deliberately
reports the
source-derived byte schedule and prelaunch disk reservation as missing. The
machine-readable
`privacy_capture_archive_reservation_blocker.json` lists all ten missing
per-slot bounds. Observed fixture sizes and arbitrary operational caps are not
admissible substitutes: the selected producer/workload grammar must first bind
exact or justified maximum record multiplicities and framing bytes, after
which the parent must reserve that space before consuming a trial identity.
Reservation refusal before identity use creates no trial. Disk, write,
finalization or inspection failure after identity use must emit a typed
run-invalidating unavailable terminal retaining the recoverable objects; it
may not disappear the attempt, score, or retry under any identity. Only a
complete failed-trial observer view may yield a fresh identity and rerun the
complete R1+R2 capture.
The output ABI table and independent Python/C++ parsers now
pin two private role bodies: Observer v3 uses 151,449 meaningful bytes padded
to 151,552 bytes with ABI identity
`1e28e13affa3c23b39cf781bb003b69827ec37154514180f012e44bc072fa16f`, and
OwnerScore uses 293,466 meaningful bytes padded to 294,912 bytes with ABI
identity `895fb9dc9ba2fb8f510620bdb6bfc2a71b9d749eae847b76f98b381a1f897d02`.
Both require exactly four ordered view slots, canonical sorted constraint
arrays and the exact 32-row category union derived from the five selected
artifact category manifests. `privacy_measurement_child_output_authority`
admits only those exact role/identity/size pairs and independently parses the
final bytes before sealing; it rejects private bodies for Aggregate and
OwnerComparison. Observer v3 retains the prior 144-byte big-endian phase
inventory: four canonical views, each with exactly the R1/F1, R1/F2, R2/F1
and R2/F2 accepted-chain deferred rows, zero Step-2-open rows and no mapping or
relabel flags within that four-row phase slice. It appends a 256-byte finite
Step-2 inventory binding the frozen
model identity, the exact 26-family registry identity, per-view totals
`[42,56,108,122]`, each family count/disposition, and the ten-row empirical
open mask. All nine source-assumption families and the empirical family remain
explicitly open and non-authorizing; these counts cannot mint a privacy or
prediction authority. Observer v1 and v2 bodies are rejected by the selected
v3 output parser.

The C++ drain/archive transport and observer snapshot path remain source-only
and `CONFIGURED0` while the selected-program byte schedule, pre-fork
reservation and final writer-closure integration are incomplete. No selected
child calls the
private four-view completion gate before prediction. The source-only child
supervisor now creates the role-scoped empty output memfd, installs FD62 only
for Observer and OwnerScore, applies the exact full-width `pwrite64` rule,
authenticates completion/EOF/clean exit, independently parses and hashes the
body, seals it, and retains the read-only authority through the runtime bridge
and `RunMeasurement`. Aggregate and OwnerComparison remain denied. This is
exercised only by synthetic controls: no production worker writes either
canonical body and no selected parent calls the supervisor. A source-only
open-v3 observer fanout retains the sole sealed observer output, derives a
secret-salted private barrier value and creates three independently reopened
read-only FD41 endpoints, but deliberately emits no `BarrierFreezeAuthority`,
score permit or authorizing Step-2 result. A separate all-three owner-score
    split preallocates an opaque success/STOP closed sum, then burns owners
    0/1/2 before validation. It requires one opaque source compact-lineage
    authority and exact-matches method, selection, raw trial UUID, outer attempt
    text, run selection and owner in each canonical body; method and run
    selection also match the live full `RunBinding`. It revalidates process/exit
    evidence, inode, size and seals, then retains the three source outputs plus
    independent aggregate and comparison reopenings for FD43 through FD51 in
    one opaque success arm. Every post-claim validation, allocation or reopen
    failure returns a STOP arm retaining all present sealed outputs and the
    lineage authority. `RunMeasurement` now accepts only that opaque closed sum
    after all three score permits. It retains success and STOP identically,
    exact-matches a success arm to its live binding, barrier and permit
    identities, and retains then poisons on post-claim or cross-run failure.
    Process-local destruction is not a STOP sink. Aggregate completion still
    does not retain the comparison residuals and no final
    aggregate-plus-comparison consumer exists. The legacy per-owner
    `RunMeasurement::accept_score` and `issue_aggregate` methods exist only in
    the authority test build; production cannot use them to bypass the
    all-three lineage-bound outcome. The registered parent now
retains a genuine raw trial
UUID: a live immutable-roster authority binds it to the capture plan's explicit
domain-separated trial digest and the same value survives both persistent
rounds and the six-party join. The separate outer measurement attempt-ASCII
preimage required by FD62 is still absent; the two per-round capture-attempt
UUIDs cannot be composed or inverted as a substitute, and caller-supplied
strings remain forbidden. The exact upstream loss point is now pinned:
`privacy_launch.py::admitted` still holds both `binding.attempt_id` and the
canonical bytes of `diagnostic.run_selection` whose SHA-256 is
`binding.selection_sha256`, but the C++ selected-prelaunch input retains only
their digests. The admitted source now encodes those exact values in the
versioned `KPBOSL01` private archive together with the selected method,
diagnostic-selection, source-closure, runtime, classification and raw trial
lineage. The C++ archive parser requires exact size, zero padding, internal
SHA-256 equality, a sealed read-only anonymous inode and an exact
source-selected expectation, then yields one opaque move-only transfer with
no fd/body/hash/text/receipt getter. Forged fields, cross-run substitutions,
replay, writable or unsealed descriptors and pre-claim allocation failure are
covered by focused controls. This archive is not authority by itself. No
selected authenticated Python receiver or selected parent callsite exists.
The implemented receiver transport core burns one private binding sub-slot,
uses `SOCK_SEQPACKET` credentials, accepts exactly one sealed read-only archive
FD, distinguishes a credentialed zero record from EOF, rejects trailing data,
and requires exact child wait-zero. Its selection and executable inputs are
sealed anonymous inodes, revalidated in the child, and copied to collision-free
temporary descriptors before FD60/61/63 installation. The Python source has
the matching fixed-FD worker entry. Controls cover fixed-FD source collision,
mutable same-UID input refusal, replay, method/run/source/runtime/trial/class
substitution, wrong body, zero record, extra FD, writable/unsealed FD, trailing
record and nonzero exit. The core remains test-selected because no genuine
prelaunch source owns the exact Python worker artifact and no source-owned
domain maps the retained raw outer attempt to `measurement_attempt`; both
`authenticated_python_receiver` and selected/configured status remain false.
No genuine prelaunch accepted-head or selected-main plan authority exists
either: the current live head and selection are acquired after TLS/MASCOT.
They cannot be moved earlier or replaced with digests, so the future atomic
producer-plus-two-round-capsule split remains mechanically absent.
`privacy_owner_score_lineage_source_authority` also reserves opaque prelaunch
and trial residual types plus complete non-forgeable bridge names.
`RegisteredSelectedProducerPrelaunchBindingFactory::compile` must eventually
split the score residual at the same commit as the producer binding, and the
sole registered measurement bridge must forward the raw trial residual. Until
the selected Python-to-C++ receiver authenticates and transfers the exact
archive, the compact-lineage minter remains mechanically absent.
`privacy_owner_score_terminal_consumer_authority` separately freezes the
mandatory downstream shape without enabling it. Before claiming the retained
RunMeasurement outcome, the future sole bridge must hold both a durable STOP
sink and an indivisible aggregate-plus-comparison success consumer. Its result
is opaque and cannot expose an arm or optional residual. All four capability
types are currently unconstructible, the bridge has no operation, and every
sink/final/configuration status remains false.

Selected-runtime, configured and launch flags therefore remain false.
Eligibility
requires adversarial controls for descriptor count and credentials, duplicate
objects, byte/root/END/EOF mismatch, wrong role/owner/run/permit, writable or
unsealed objects, short/duplicate output, trailing control records, abnormal
exit, replay, cross-owner fanout and receipt-only bypass. The isolated
owner-score split already covers mixed-run, duplicate/swapped owner, all six
compact-lineage substitutions, body mutation, writable/cross-owner reopen,
stale-first sibling retention, pre-claim allocation reuse, post-claim
allocation retention, moved-from replay, production opacity, hostile
exact-friend controls and ASan/UBSan. The source compact-lineage minter and
mandatory durable STOP/final sink remain absent, so these controls do not qualify the
missing selected/runtime/final-consumer path.

## Reconsideration

Revisit this decision if the selected environment cannot provide anonymous
disk-backed files and pre-fork reservation, if Linux memfd sealing cannot be
supported by the selected static output runtime, if a reviewed fixed output ABI cannot represent all
four exhaustive views without leaking a variable length, or if the producer
must move to another sole-reader transport. Any replacement must preserve
exact-byte continuity, private one-shot authority, independent parent
verification and fail-closed privacy acceptance.
