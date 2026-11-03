# Finite METHOD03 transport candidate — source only

This is an experimental orchestrator, not a new Exit protocol or operator
framework. No private generation, Original, capture, network, broadcast or
scoring execution is authorized by these files. Root must freeze the complete
method, sources, identity/budget, view and calibration first. The independent
direct Exit route and every passed source/evidence remain unchanged.

## API and compartments

```
selected_transport_source_pins(guard) -> exact four named hashes
open_vector(binding, selection_ref, early_controller_clock_ref,
            public_output, private_tor_state, capture_root,
            guard, emit_metadata) -> ExperimentalVectorSession
session.submit_one(arm, owner_slot, candidate_ref, history_ref,
                   tail_ref, identity_tuple) -> typed attempt
session.finish() -> typed result and compartment references
```

The Python signatures use keyword arguments for open_vector. The guard is the
already externally admitted seven-root reader/metadata guard, including the
default Original/truth exclusions. It is public read admission, not a truth,
accepted-state or clock-qualification callback. Source selection is an
externally hash-selected exact public manifest, not a runtime qualified flag.

Binding has exactly method_sha256, selection_sha256, trial_id, phase and
attempt_id. A SourceGenerator writes EARLY-CONTROLLER-CLOCK.json before any
bootstrap or private RNG: schema kpb-method03-early-controller-clock/v1, binding
and value=its actual clock_snapshot('controller'). The actual same controller
passes that public artifact reference. The driver checks PID, boot, current and
child namespace identities, raw offsets and monotonic sample continuation
against a fresh self-capture. Both records are retained; no proxy substitutes.
The frozen generator source must establish the early record's position before
private intake. The driver does not invent that fact from a caller boolean.

One vector shares the actual Tor client/service, onion endpoint, receiver and
unchanged request policy across both arms. Source slots A0..2 map to
owner/transport0..2; B0..2 to3..5. submit_one is as-ready, may be invoked
concurrently and never waits for peers, batches, shuffles, delays for privacy,
retries or silently falls back. One call consumes one slot even on failure.
finish's six-event condition describes evidence completeness, not a peer
barrier before sending. Failure/partial/possibly-arrived attempts remain.

CandidateRef has exactly path, mode(integer0600), bytes, uid, gid, nlink(1), dev,
inode, mtime_ns and ctime_ns. The controller only stats it and opens O_PATH with
NOFOLLOW; only that owner's namespace receives its handle. No candidate body
is read or hashed by the controller in either arm. The unchanged7d role runs
cafb's exact statement/head/tail and genuine930/bc41 proof verification before
encoding its frame. HistoryRef/TailRef have exactly absolute path and sha256.
The identity object has chain_hex32, pool_hex32, profile_hex32, domain_hex32 and
service_hex32. The immutable tail is the actual selected4081 artifact.

The role's selected public code/config/marker/history/tail/manifest leaves are
owned single-link0400 regular copies, O_PATH-bound individually. Actual public
runtime/leaf checks precede private candidate O_PATH admission. No host
directory FD or Original/proving-key mount is provided to an owner. Common
Tor/receiver/transport roles receive no candidate or owner-private handle.

ArmA deliberately reads the **already validated** owner frame, retains its
actual bytes and labelled source mapping in A-exposures, then forwards the
exact bytes. Partial A bytes and failures are retained. ArmB connects owner
stdout1 to transport stdin0 and closes the controller's copies; no controller
read, write, tee, cache, projection/frame/exit hash or labelled content ID is
computed for B. The same unchanged88cb/packet and inside-entry stdin duplicate
are used; FD0 remains occupied so curl's DEVNULL mapping cannot erase its
payload memfd. There is no preserve-fds dependency.

Tor state is only PRIVATE/diagnostics/method03-tor-TRIAL/{service,client}.
The unchanged037 structured receiver output is only under the separate
PRIVATE/diagnostics/method03-capture-TRIAL/observations/arrivals compartment.
Neither contains honest Original files; the capture reference contains no Tor
state/key directory. The controller never lists, reads or hashes receiver
files. It returns only the unlabelled directory reference. A separate isolated
reader preserves actual filenames, reserve/arrival_sequence1..6 and complete
malformed/failed/late records; no arm/owner or favorable arrival reorder.

**Scope limit:** 037 retains structured projections/proofs/frame hashes, not
the full4096 packet padding. No new raw capture source is selected here.
Missing declared packet semantics must remain unmodeled, PRIMARY unqualified
and gain false under the current scope. App/Popen and declared FD metadata is
not every transient internal C FD, syscall or global-host observation; that
full-view coverage remains unqualified too.

## Actual process and clock metadata

NEW selected wrappers emit actual local clock evidence before intake, then
install the finite subprocess metadata helper. OWNER uses stderr2 only;
transport/receiver use their existing public stdout. Owner frame1 is never a
status or metadata input. Service/client clocks are captured inside those
actual roles by the finite helper extension, never relabelled proxy clocks.

read_role_event reads a selected status line and immediately samples monotonic,
realtime and boottime before parsing/queueing. The actual queue consumer adds
consumed_monotonic_ns separately. All actual fixed statuses and known Tor,
curl and auth-verifier pre-Popen/actual-PID/argv/passFD/stdio/lifecycle records
remain in the journal. It never observes env, communicate input/output,
credentials, configurations, candidate/frame bytes or buffer contents.
Unknown/secret-bearing argument shapes cause explicit metadata refusal, never
silent omission or inferred qualification. Curl's inner pre-Popen timestamp
must be retained as the stronger source lower bound. A valid202 read envelope
remains evidence even if the process later exits nonzero.

Host Popen metadata and actual role-local PID/namespace/clock records are
separate facts. The frozen caller/extractor must prove their role/namespace
binding. No helper alone attests an arbitrary caller's pipe/PID wiring. Clock
comparison requires actual same-kernel namespace/offset evidence or separately
Root-frozen calibration; no offsets are silently normalized here.

Normal Tor stop is fixed STOP+EOF on each Tor role's public stdin. Its helper
terminates only the tracked known Tor child, allowing unchanged0582 to observe
the real wait/exit. Receiver stop is its qualified STOP+EOF shutdown/join/close
path. Namespace termination is reserved for incomplete cleanup; it is not a
successful drain. All actual exits and failures are retained.

Closing is an atomic admission state shared by role and public-preflight
Popen sites. No new submit/launch enters once closing starts. Abort stops and
reaps known processes, waits for every admitted call to become quiescent, then
closes shared source/runtime descriptors and the journal. Lifecycle calls use
the independent controller thread, never an active submit/status callback.
A terminal journal/consumer error notifies all waiters and fails into cleanup;
it is evidence loss, not an operational timeout or a reason to continue.

## Journal and outputs

EVENTS.ndjson records have schema kpb-method03-controller-event/v1, binding,
sequence, recorded_monotonic_ns, kind and kind-specific fields. They contain
source/runtime/public-head references and actual process/pipe/FD/argv/mount/
order facts. They contain no B body/frame/projection/exit identifier or hash.

Important kinds are controller-clock (early plus source_event_ref),
controller-clock-followup, launch (pre/returned Popen times and actual host PID,
parent PID, argv, passed setup FDs, actual stdio mapping), status (the exact
post-read observation and actual consumed time), role-exit, pipe-created,
parent-pipe-ends-closed, candidate-metadata, A-exposure (artifact path only),
submission-finished, tor-stop-control and receiver-stop-control. All other
source/runtime/public-preflight/invalid-status/EOF/cleanup facts remain.
Subprocess records are nested strict values in status observations. Do not
replace observed timestamps with later journal/queue times.

session-parameters contains exactly the six agreed public parameter fields:
transport_source_sha256, tor_binary_sha256, curl_binary_sha256, onion_endpoint,
receiver_source_sha256 and request_policy. The actual admission00a hashes,
actual emitted service hostname and unchanged88cb policy supply those values.
The same dictionary is returned as transport_parameters.A and .B; extraction
checks each named source pin, not membership in an unordered set of hashes.

Each A row has schema kpb-method03-controller-A-exposure/v1, binding, armA,
owner_slot/owner_role/transport_role, actual owner return/status, actual bounded
frame_hex and frame_sha256, framing_valid, projection_hex/projection_sha256/
proof_hex128 (nullable for partials), and packet/owner source hashes. After
shutdown the controller consolidates ONLY its in-memory A rows into
A-exposures/EXPOSURE.json: schema kpb-method03-controller-A-exposures/v1,
binding, records. Its explicit baseline_A_exposure path/hash may be read as A
baseline evidence. No B content enters this collection or the metadata journal.

finish returns kpb-method03-vector-transport-result/v1 with binding, trial_id,
COMPLETE/INCOMPLETE, attempts, receiver_summary, metadata_journal, raw_capture,
arm_a_exposures, baseline_A_exposure, actual transport_parameters.A/B,
clock_channels and false broadcast/privacy_or_financial_qualification flags.
COMPLETE means the six operational receipts/owner exits/drained records only;
it grants no privacy, Native, chain, backing or settlement authority. The
independent producer/extractor derives coverage and proof facts from actual
selected artifacts; it does not trust this status as accepted truth.

The public controls use synthetic framing, mocked OS/process side effects and
no real candidate, proof, subprocess, network or vector start. They exercise B
read/write/hash traps, owner-only private handles, A exact forwarding, retry
refusal, nonzero-after202 retention and generated wrapper syntax. They are not
cryptographic or runtime qualification. The earlier fake refusal was a missing
endpoint/socks attribute in the test fixture; no private/pipeline run occurred.
