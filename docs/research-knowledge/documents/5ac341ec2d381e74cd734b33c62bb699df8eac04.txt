# METHOD03 actual-record extraction — unselected source only

`metadata_extract.py` is a pure function module. It never opens files, captures
traffic, generates notes, invokes Native, reads Originals or truth, or authorizes
execution. It leaves the frozen5ace matcher unchanged. Only admitted closed-role
I/O may supply these records; dictionaries and refs alone are not authority.

```python
observation = extract(plan, event_journal, receiver_index, parsed_arrivals,
                      contact_facts, baseline_A_exposure,
                      view='CONTROLLER+TERMINAL')
coverage_capsule = secondary_coverage(binding, label, slot_grammar_sha256,
                                      universe_sha256, capture_refs, limitations)
public_status = public_secondary_status(coverage_capsule)
```

All `observation`, input records, exact predictions, score masks and secondary
coverage bodies remain PRIVATE. The launcher emits only salted commitments and
typed sanitized status; raw observation/prediction hashes do not become public.

## Exact inputs

Every envelope has the same five-field binding from the frozen5ace plan.

- `event_journal`: schema `kpb-method03-controller-journal/v1`, `binding`,
  `records`. Preserve the full NDJSON record order, with each record schema
  `kpb-method03-controller-event/v1`, exact binding, consecutive `sequence`,
  actual `recorded_monotonic_ns`, kind and the driver's real kind fields.
  No input `facts`, `allowed_edges`, `complete`, `coverage` or `qualified` fields
  can replace source evidence.
- `receiver_index`: schema `kpb-method03-receiver-index/v1`, `binding`,
  `records` (all actual receiver037 records in actual file/index order),
  `public_heads`, `transport_parameters` and `native_reports`. The index's A/B
  parameters must match the actual journal's single shared-session event.
  Raw records stay protected; Root does
  not inspect their bodies, packet/projection IDs or hashes before a permitted
  release. `public_heads` rows are `{arm,context_hex276,evidence_ref}` from
  the actual admitted published heads. Their public Context hashes are the
  sole arm partition; no owner truth or private directory order is used.
- `parsed_arrivals`: schema `kpb-method03-parsed-arrivals/v1`, binding,
  records `{ordinal,arrival_id,projection_hex,proof_hex128,native}`. The closed
  role uses pinned packet/Exit helpers to decode these exact received bytes.
  `native` contains frozen5ace native fields plus `context_hex276`,
  `domain_hex32`, `profile_hex32`. The extractor cross-binds raw/parsed ordinals,
  projection/proof bytes and hashes, independently parses public Context276
  fields, and retains actual global receiver ordinals and record order.
- `contact_facts`: schema `kpb-method03-private-contact-view/v1`, binding,
  `arms.A/B`, each with `contacts`, `own_payouts`, `known_receipts`, `unmodeled`.
  Retain every actual acquired contact for both public note indexes, including
  native/delivery keys, owner, index, domain and profile. Applicability reasons
  use public plan index/domain/profile only. Exact known native-address matches
  are unioned as legitimate alternative keys; no nonmatch excludes an owner
  under fresh-key policy. Actual owner1 NF AND SPK must match the same received
  record. Known receipt fields include rho, CM, value, known-consumed flag and
  the actual invoice208/receipt216/blind32/tuple520. Opaque semantics and source
  unmodeled items explicitly remain PRIMARY missing coverage. No hidden creator
  map, fabricated receipt, honest Original or owner-truth field is accepted.
- `baseline_A_exposure`: envelope schema
  `kpb-method03-controller-A-exposures/v1`, binding, three actual artifact rows
  with schema `kpb-method03-controller-A-exposure/v1`. Exact driver rows bind
  owner/transport role, actual bounded frame bytes/hash, projection/proof,
  selected packet/owner source pins and actual return/status. The extractor
  hashes the actual A frame and matches all frame/projection/proof fields to
  one actual received A record. No equivalent B controller mapping is created.

The plan source map includes every admitted driver/metadata/packet/parser/
wallet/Native dependency plus Tor/curl binaries and public parameter pins.
It also has exact named `native_source_pins` (adapter,codec,engine,verifier,
parameters,manifest,tail) and `transport_source_pins` (transport_source_sha256,
tor_binary_sha256,curl_binary_sha256,receiver_source_sha256). A hash occurring
somewhere in the broad source map cannot substitute for its correct role.
Actual shared session parameters come from the driver's single
`session-parameters` event, not a caller equality Boolean. Both arms use that
same Tor/curl/endpoint/receiver/request policy.

## Native record contract

Each `native_reports` row has schema
`kpb-method03-received-native-check/v1` and:

```text
binding, ordinal
receiver_row_sha256
projection_sha256, proof_sha256
source_pins: adapter,codec,engine,verifier,parameters,manifest,tail
actual_native_returncode
native_full_accepted, all_scripts_passed, actual_public_proof_verified
isolation: {network:"none", input_scope:"unlabelled-public-received-exits",
            originals_mounted:false}
artifact_refs: {case,normalization,native_report,proof_result}
  each: {path: canonical relative POSIX path, sha256: exact artifact SHA256}
```

The receiver-row hash is SHA256 of receiver037's actual canonical compact sorted
JSON record plus newline. All seven source pins belong to the Root-admitted
plan closure AND equal the exact selected role map. Returncode,
Full/ScriptEngine/proof results and isolation come
from actual selected producer checks over the received CASE/proof payload,
never from caller PASS fields. The producer and the closed role must admit the
referenced real artifacts before this pure normalization step. Missing/refused
reports stay unqualified; HTTP202 is never Native or proof acceptance.
The frozen METHOD03 continuing projection is exactly1844 bytes; a terminal1796
projection cannot be relabelled continuing by a supplied head-shape field.

## Timing and completeness

Use literal outer prePopen/returned/actual PID and immediate host-reader fields
in the frozen5ace observation. Preserve all argv, FD/pipe lifetime, namespace,
status, source schedule, Tor and outcome records inside the private capsule.
`controller-clock` contains the actual early generator snapshot and its
`source_event_ref`, emitted before bootstrap/private RNG by selected source;
`controller-clock-followup` contains the later vector-open sample. Both remain
retained. PID/boot/ns/offset identity and real sample order must agree; a late
sample cannot replace the early observation or prove a false pre-intake order.

The new selected subprocess helper also records actual inner curl prePopen
and actual wait/communicate/poll observations on its role's real clock. Only
observed same-boot/current=children namespace/offset evidence permits conversion
to the controller/receiver clock domain. Exact source-produced additional
`allowed-edges` apply that stronger causal interval without rewriting or
backdating the literal reader/launch timestamps. A later typed202 from the
SAME unique curl invocation is required for the inner completion upper bound;
curlrc0 alone is insufficient. A later outer-process failure cannot delete an
already observed202. No valid receipt means possibly-arrived, unbounded tail.

Separate post-shutdown Native publication metadata stays in the PRIVATE index:
actual producer PID; before/after boot, namespace, offsets and kernel clock IDs;
actual pre-public-write and after-public-fsync clocks; exact public EXITS and
Native RESULT refs. Source emits public artifacts first and writes the private
index last without self-hash cycles. The extractor admits comparable actual
clocks and checks publication begins after recorded network-role exits. Missing,
unstable or premature publication remains PRIMARY unmodeled. It never infers
that time from a later status or fits it to truth. Public exports stay flat,
unlabelled and in actual global receiver accept order, with no owner/arm label;
original private directory enumeration is preserved separately. Both arms see
the same actual terminal/publication exposure.

Unknown event semantics, missing/ambiguous inner curl metadata and violated
candidate-body boundaries are explicit PRIMARY unmodeled facts, not omissions.
Required coverage values derive from checked source records and outcomes.

Receiver037 stores frameSHA/projection/proof and structured HTTP/clock metadata
but does NOT retain raw4096 padding. This extractor refuses an invented
`frame_hex` addition and always marks the missing full terminal packet PRIMARY
and traffic coverage incomplete. Actual opaque corrupt receipt semantics also
remain PRIMARY incomplete. Counts remain useful diagnostics; these gaps force
finite-primary completeness and bounded gain FALSE. No source or control
silently upgrades that capture or works around the separately blocked server
capture. Full-host/server and cryptographic qualification remain false.

## Secondary coverage seals

The selected labels/kinds are PRIMARY/prediction,
TERMINAL_CONTACT/coverage and GLOBAL_UNION/coverage. This module never runs the
primary attack with a secondary label or inserts primary A route facts into a
terminal-only view.

`secondary_coverage` accepts only the latter two labels. `capture_refs` is a
private string list; `limitations` is a nonempty list of strict
`{category,evidence_refs:[...]}` records. An uncaptured secondary is:

```python
secondary_coverage(binding, 'TERMINAL_CONTACT', slot_sha, universe_sha, [], [
    {'category':'COMPLETE_DECLARED_SECONDARY_VIEW_NOT_CAPTURED',
     'evidence_refs':['scope/TERMINAL_CONTACT']}
])
```

The private schema `kpb-method03-secondary-coverage/v1` binds the public slot
grammar and actual post-capture unlabelled universe hash. It has `kind=coverage`,
`status=MISSING` if no refs else `UNQUALIFIED`, `scored=false`,
`gain_claimed=false`. It contains no model/count/score field. The public status
uses `actual_unlabelled_universe_sha256` (same grammar as budget04), counts only
for private refs/limitations, and no private record hash or path. Extra model
fields, PASS statuses, changed derived status and malformed bindings refuse.

The closed launcher salts/seals PRIMARY prediction and both secondary coverage
capsules before any truth read. The actual persistent budget helper must admit
all three exact labels/kinds and real completion/seal evidence. This module
cannot create temporal provenance by filling a dictionary or Boolean marker.

All tests are invented PUBLIC fixtures. Mock wire bytes and Native reports are
not actual proofs, Tor deliveries, native acceptance or privacy evidence.
