# Source-level privacy capture hooks

Status: **SOURCE ONLY — PARTIAL GENUINE INTEGRATION — NOT ACTUAL EVIDENCE**.

`privacy_capture_hook.{hpp,cpp}` and
`privacy_capture_private_hook.{hpp,cpp}` implement all five typed stream
interfaces required by the append-only capture producer:

- the exact 10,685-byte verified public projection; and
- dispatcher listener, owner connection/upload, aggregate release and outbound
  route metadata;
- corrupt server P1's admitted owner shares, MASCOT/peer lane, authenticated
  share, MAC share, randomness, masked proof opening and public projection;
- colluder wallet C1's Original facts, issued/accepted invoices, incoming/change
  receipts and retry history; and
- terminal construction/native/close events, the unlabelled 3-NF/6-output
  group, retry/rejection/orphan/reorg history and cross-round links.

The FD, round, artifact role and dispatcher release-order policy are template
parameters. The private roles additionally require the exact fixed FD for
their round (`terminal=21/26`, `corrupt-server=23/28`,
`colluder-wallet=24/29`). None can come from argv or the environment. The
dispatcher also accepts a pre-release `RunBinding` and buffers at most seven
small metadata records until the exact released projection hash is known. It
never buffers a private owner/P1 body. Frames match `privacy_capture_producer.py`
byte-for-byte:
`HELLO`, `RAW` or `META` plus ordered `RECORD`, then one `END` and close.
Every C1 `RECORD` is exactly `{stream,source,value}`. The persistent supervisor,
not the worker, supplies stage, stage sequence, exact operation digest,
prospective contact, source-event sequence and receive-boundary monotonic time.
The separate v2 path now has typed lifecycle-stage and authenticated-route
authority inputs, but their genuine production minters are not connected.
The legacy hook still has no authenticated route authority, so every legacy
contact binding and the `CONFIGURED0` source status remain explicitly
unqualified.

The Python supervisor also has a separate capability-bound v2 source envelope
defined by [ADR-0089](../../../docs/adr/0089-authenticated-c1-contact-value-capture.md).
It binds each canonical value body and contact to a one-shot run/stage/source/
runtime/route precursor. Its C++ prelaunch bridge requires the live ten-stream
producer authority, emits only a sealed FD31 offer for Python, and retains a
move-only post-capture residual that Python cannot inspect. The legacy v1
envelope and C++ hook remain false and unmodeled. Test-only C++ authority
minters are macro-guarded. Qualified rows remain unmodeled until the observer
atomically joins both round residuals to the live producer closure and exact
C1 stream closures, then actually applies contact/value constraints to the
candidate lattice.

The writer handles interrupted and partial writes until the complete selected
frame is written. A broken pipe, invalid descriptor, invalid call order,
partial terminal write or failed close throws `CaptureRefused`; the enclosing
registered driver must poison and halt the attempt. SIGPIPE is blocked and
consumed around writes so a missing observer becomes a checked refusal, not an
unclassified signal exit.

## Integrated source call sites

The source-only registered path now does the following:

1. A typed capture-plan authority starts `RegisteredCaptureSession` before
   head recheck/LOCK. P0 alone owns dispatcher/projection FDs; P1/P2 never
   touch them.
2. The real common TLS ingress emits listener, authenticated connection and
   fixed-frame completion facts. Owner arrival order enters only the private
   dispatcher stream, never a public phase or route.
3. Durable `EgressRelease` supplies the exact 10,685 projection bytes. The
   projection channel closes, and the dispatcher emits one aggregate release.
4. Hook failures propagate through construction/release and poison the MPC
   attempt.
5. The owner lifecycle source has a C1-only Unix-seqpacket seam through the
   real bubblewrap namespace. It emits issued/accepted invoices and Original
   facts at creation/authentication, then receipts immediately after genuine
   wallet decryption. Owners 0 and 2 receive neither its mount nor capability.
   No selected launcher currently constructs this persistent supervisor.

No genuine public handoff exists yet. The source therefore emits no invented
`outbound-route` and no dispatcher `END`; the producer must fail closed.

## Remaining required integration

7. Construct `CorruptServerHook` only inside the selected P1 process. Tee each
   admitted owner-TLS masked share before discard, then every selected peer,
   authenticated-share, MAC-share, randomness, masked-proof-opening and public
   release lane in source order. The call sites must be in the reviewed P1
   transport/context and proof-release sources; reading later diagnostic files
   is not equivalent.
8. The lifecycle controller and invoice route source must mint the implemented
   move-only stage/route authorities from genuine operations and contacts. A
   typed launcher must consume the resulting sealed FD31 offer, retain the C1
   supervisor across invoice/pay/scan, and pass its late projection seal to FD
   24/29. Do not route owner 0/2 Originals or truth through this process.
9. Construct `TerminalHook` in the selected terminal/native controller before
   candidate construction. Emit direct construction, native-Full and terminal
   close transitions, the single unlabelled aggregate grouping, and every
   retry, rejection, orphan, reorg or cross-round linkage before the
   corresponding in-memory record is discarded.
10. The fixed-FD launcher must bind each write end to exactly one selected
    role, bind each read end only to the producer, close all inherited aliases,
    and require all five role-completion receipts plus the producer exit before
    it may write a launch receipt. No implemented hook enables this launcher.

P1, C1, terminal, public handoff, fixed-FD launcher and actual producer
completion remain incomplete. Therefore the all-role integration flag remains
false, no actual receipt schema is enabled, and the worker rejects source-only
or self-authored producer/launch receipts.

## Controls

`test_privacy_capture_hook.py` compiles with `-Wall -Wextra -Werror` and checks
byte-exact C++/Python framing, a complete C++-to-producer path, wrong fixed FD,
wrong role, invalid protocol order, truncation, duplicate end, post-end extra
events, unavailable consumer and deferred projection sealing. The control executable is test-only; its
scenario argv is not part of the hook library or a production interface.

`test_registered_capture_session.py` proves single-role stream ownership,
byte-exact projection hashing, one aggregate release, and the deliberate
absence of an invented route or dispatcher `END`.

`test_privacy_capture_private_hook.py` applies the same byte-exact
C++-to-producer check to P1, C1 and terminal streams. It also proves missing,
extra, reordered, early-close, wrong-role/FD, cross-round replay and literal
leak cases refuse or remain visible to the model. Retry/rejection/orphan/reorg
and cross-round records are retained. A nonempty C1 retry history preserves its
supervisor-owned stage envelope but remains explicitly `unmodeled`; unsupported
terminal retry/reorg variants still fail closed.

`test_c1_capture_supervisor.py` additionally proves real bubblewrap transport,
one-shot UID/capability binding, source-envelope ownership, per-stage timing,
invoice/pay/scan distinction, retry attribution, relabel refusal, fixed FD
24/29 output and producer rejection of the legacy `{stream,value}` shape.
`test_c1_contact_value_authority.py` proves the separate v2 authority is
one-shot and run-bound; caller contact/stage substitution refuses; every
invoice, Original, receipt and retry body is covered by the frozen event
binding; and no authority/record hash escapes the public source-status value.
`test_c1_contact_value_cpp_authority.py` additionally proves the C++ split is
move-only, production cannot mint or inspect the residual, assets and pinned
executable enter the sealed offer, cross-run/contact/operation substitution
and replay refuse, and FD31 is re-checked for type, seals, size, device and
inode immediately before child installation.
