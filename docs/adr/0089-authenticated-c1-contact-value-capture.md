# ADR-0089: Capability-bound C1 contact/value capture

**Status:** Proposed, source-only, `CONFIGURED0`

## Context

Owner C1 directly knows the invoices it issues or accepts and the values it
successfully decrypts. Those facts can reduce the honest-owner candidate set.
The legacy C1 envelope records the bodies but marks its controller-supplied
contact as unqualified. Treating that legacy label or body as measured would
allow caller truth to enter the observer.

The selected observer needs a distinct path that binds contact and canonical
value bytes to the exact pinned wallet worker, route manifest, run, stage and
one-shot capture session. This remains a bounded passive-process measurement;
it is not authentication of an arbitrary network peer or modified host.

## Decision

Keep the legacy v1 envelope unchanged and unmodeled. Add a separate v2 path
with a two-phase, one-shot C++ authority:

1. Before launch,
   `kpb::measurement::c1_capture::C1ContactValueAuthorityBridge` consumes the
   live parent ten-read-ends producer authority, a move-only lifecycle-stage
   authority and a move-only authenticated invoice-route authority. It splits
   the result into a kernel-sealed offer and a private post-capture residual.
2. The offer is installed only on fixed FD 31. The Python supervisor consumes
   and closes that descriptor; no Python constructor, token or caller JSON can
   mint the authority.
3. The residual never enters Python. After C1 `END` and EOF, the observer must
   atomically join both round residuals to the live producer closure and the
   exact colluder-wallet stream closures.
4. The selected fixed experiment has no intra-trial C1 retry. Any canonical
   event whose stream is `retry`, including a malformed retry body, durably
   creates private `WHOLE-TRIAL-INVALIDATION.json`, raises the typed
   `WholeTrialRetryInvalidated` controller signal, poisons the whole fresh
   trial, and refuses stage commit, final `END`, or continuation. Retrying
   requires a new fresh trial identity and a full R1+R2 run.

The authority pre-binds:

- round, financial run, attempt, cohort and capture identities;
- owner component 1 and fixed FD 24 or 29;
- all six pinned worker identities: source, build, runtime, assets, executable
  and launcher;
- role-launch, worker-process, stage-plan, authenticated route-manifest and
  route-source identities;
- the exact three invoice/pay/scan contacts fixed by that route; and
- the SHA-256 identities of the invoice, pay and scan operation UUID text, in
  that fixed order.

Both input authorities bind the full `RunBinding`. The lifecycle authority
also names the one expected route and route-source identity. This prevents
cross-run replay, operation substitution, and swapping in another otherwise
valid contact route. The supervisor derives operations and contacts only from
the consumed FD31 offer and rejects caller-supplied replacements. It
HMAC-authenticates the complete stage config, admits only the fixed
stage/value grammar, obtains peer credentials on the one-shot private
seqpacket endpoint, and binds the canonical value body before writing the
final channel.

The qualified metadata schema is
`kpb-colluder-wallet-observer-capture/v2`. It adds exactly
`contact_value_authority_sha256` to the v1 metadata fields. Each qualified
source row uses `kpb-c1-authenticated-contact-value-source/v1` with:

1. `observer_stage`, `stage_sequence`, `operation_id_sha256`,
   `contact_owner_component`, `source_event_sequence`, and
   `observed_monotonic_ns`;
2. `contact_binding_qualified=true` and `value_binding_qualified=true`;
3. the fixed `value_kind` enum (`ORIGINAL`, `ISSUED_INVOICE`,
   `ACCEPTED_INVOICE`, `INCOMING_RECEIPT`, or `CHANGE_RECEIPT`);
4. `value_sha256`, `stage_config_sha256`, and
   `contact_value_authority_sha256`; and
5. `source_event_binding_sha256`.

All JSON below is canonical, sorted, compact JSON with one trailing newline.
The frozen formulas are:

```text
authority_id = SHA256(
  "KPB_C1_CONTACT_VALUE_AUTHORITY_V1\n" || authority_preimage_json)

stage_config_id = SHA256(
  "KPB_C1_CONTACT_VALUE_STAGE_CONFIG_V1\n" ||
  stage_config_without_hmac_token_json)

event_id = SHA256(
  "KPB_C1_CONTACT_VALUE_EVENT_V1\n" || event_preimage_json)

precursor_id = SHA256(
  "KPB_C1_CONTACT_VALUE_PRODUCER_PRECURSOR_V1\n" ||
  precursor_without_precursor_id_json)

stage_plan_id = SHA256(
  "KPB_C1_CONTACT_VALUE_STAGE_PLAN_V1\n" ||
  round || owner || ordered_stage_operation_relation)

route_id = SHA256(
  "KPB_C1_AUTHENTICATED_INVOICE_ROUTE_V1\n" ||
  round || owner || route_source_id ||
  ordered_contact_operation_relation)
```

The event preimage contains authority ID, stage-config ID, stage, stage
sequence, operation digest, contact, source-event sequence, receive-boundary
monotonic time, stream, value kind and canonical value digest.

The qualified no-retry source schedule is exactly one invoice record, two pay
records and two scan records. Final order is Original, issued invoice,
accepted invoice, incoming receipt, change receipt. With every validated
`uint64` charged at its full 20-decimal-digit encoding, the per-record maxima
are `1202, 983, 983, 1060, 1059` bytes and the stage-spool maxima are
`983, 2185, 2119` bytes. The final FD24/FD29 event grammar has one 364-byte
HELLO, one 353-byte META, five record frames and one empty END. Including each
17-byte frame header, its source-derived `ProtocolUpperBound` is exactly
`6,140` bytes in either round. These are schema bounds, not operational caps;
valid fixed-workload records do not abort merely because of an arbitrary disk
limit.

After sealing, the supervisor exposes one-shot Python producer evidence, not
an authority and not a public receipt. Its canonical precursor contains:

```text
schema, round, financial_run_id, attempt_id, cohort_sha256,
capture_identity, owner_component, fixed_fd, source_sha256, build_sha256,
runtime_sha256, assets_sha256, pinned_executable_sha256, launcher_sha256,
route_manifest_sha256, route_source_sha256, role_launch_sha256,
process_sha256, stage_plan_sha256,
operation_id_sha256[3], contact_value_authority_sha256,
stage_config_sha256[3], precursor_sha256
```

The observer admission bridge must consume the C++ residual and independently
verify `meta_sha256`, `record_count`, `record_chain_sha256`, the exact source
closure, and the complete run/route/stage/worker/owner/FD/operation binding.
A digest embedded only in the C1 leaf, or the Python producer evidence by
itself, is never authority.

## Admission boundary

The qualified rows remain `unmodeled` unless the typed adapter receives the
completed private producer receipt, exact role-launch join and exact closure.
Only then may invoice contacts/amounts, decrypted receipt creator/tuple/CM/
amount become candidate constraints. Retry evidence never becomes a terminal
leaf; it invalidates that whole trial before a final channel exists.

The split, sealed-FD offer, typed post-capture residual, and refusal controls
exist. The upstream lifecycle controller and authenticated route do not yet
mint their move-only authorities in production, no selected launcher installs
the offer, and the observer join is still being integrated. Source flags stay
false and this decision does not qualify an actual run. The legacy C++ hook
and legacy Python v1 envelope remain false/unqualified.

The retained invalidation file is private evidence, not a Python authority.
No complete native bridge yet authenticates it together with the live C1
residual and appends it to
`RegisteredFailedTrialAttemptHistoryAuthority`; that outer-history join stays
false. The ten-stream reservation capability also stays unmintable because P1
FD23/FD28 and the schedule module's selected source/build artifacts remain
missing. Archive consumption, configuration, launch, network, funding and
broadcast remain false.

## Consequences

- Colluder-known values are measured instead of being suppressed once the
  complete authority chain exists.
- Caller labels, self-reported authority digests and legacy captures cannot
  close a privacy row.
- Source/build/runtime/route disappearance or mismatch safely halts the
  qualified path.
- A retry cannot silently enlarge the C1 stream or continue inside the same
  trial; its private evidence is retained for a future authenticated outer
  failed-trial join.
- Active malicious-host, random-tape, physical-host and covert-channel privacy
  remain unqualified.

