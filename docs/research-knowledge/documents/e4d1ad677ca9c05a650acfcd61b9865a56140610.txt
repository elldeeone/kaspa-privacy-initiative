# METHOD03 metadata API — unselected source only

This is the finite primary `CONTROLLER+TERMINAL` seam for draft02
`0b4f01b0cc38963d9117248fa9ee3449928b4a36f00b0aa9e8cf4cd7d77694a6`.
No private generation, capture, network, Original, truth or broadcast authority
comes from this source or its public controls. Root must freeze the complete
method, sources, new identities and persistent budgets first. METHOD02 and the
Tor13 conditional clock diagnostic remain unchanged.

`metadata_attack.py` uses only the Python standard library and performs no I/O.
The selected caller admits its exact source before importing it. It provides:

```python
prediction = predict(plan, observation)  # PRIVATE, no truth argument
private_score = score_owner(plan, observation, prediction, owner_truth)
public_result = aggregate_owner_scores(plan, observation, prediction, three_private_scores)
digest(value)  # canonical compact sorted JSON, SHA256; inside private role only
```

The source-selected view producer is responsible for complete legitimate facts.
Nonempty evidence-reference strings are references, not independent provenance
proof. This module does not verify Groth16, parse raw financial projections,
admit native state, inspect traffic, or prove a capsule was produced by a trusted
worker. Those remain selected producer/Native/launcher responsibilities. An
imported PASS, caller Boolean or independently written fact file is not authority.

## Binding and plan

Both plan and observation have the exact five-field binding:
`method_sha256`, `selection_sha256`, canonical `trial_id`,
`phase="private-exit-route-03"`, canonical `attempt_id`.

Plan schema is `kpb-method03-metadata-plan/v1`. Required fields:

- `view="CONTROLLER+TERMINAL"`, `owners=[0,1,2]`, `corrupt_owner=1`.
- `arms.A={note_index, fresh_payout:true, origin:"controller"}` and
  `arms.B={note_index, fresh_payout:true, origin:"owner-pipe"}`. Indices differ;
  11/13 are public-fixture placeholders until Root selects the real vector.
- `common_amounts={note,fee,payout}` uses integer sompi, payout+fee=note.
- `head_shape={cm_count,nf_count,reserve,exit_mode:"continuing"}`.
- `sources` maps every selected producer/attacker/adapter dependency to its
  exact SHA256. Both arms use the same selected Tor/curl/transport/receiver.
- `required_coverage` contains every constant `REQUIRED_COVERAGE` item; it can
  add reviewed requirements but cannot remove any fixed requirement.

The study uses independent actual notes, NFs, actions, payout scripts, outpoints
and public Context hashes across arms, with equivalent common head shape.
Supplied component contexts are unfunded and not a collectively accepted chain.

## Observation

Schema `kpb-method03-metadata-observation/v1`, same binding and sources:

- `clocks`: exact eight role-local snapshots from the selected
  `controller_metadata.clock_snapshot`: controller, receiver/0, transport/0..5.
  A owner0..2 uses transport/0..2; B uses transport/3..5. These are outgoing
  source slots, not terminal-frame labels. All actual owner/namespace/process
  metadata is additionally retained by the producer even if not used as a join.
- `launches`: six records with `arm,owner,role,started_ns,post_popen_ns,pid,
  event_ref,metadata`. `started_ns` is persisted BEFORE Popen.
  `metadata` retains at least actual `argv,mounts,fd_topology,schedule` and every
  additional source disclosure. PID is the actual observed launcher handle;
  do not invent an inner curl PID. Recycled PID/FD/inode numbers alone are not
  stable cross-event identities; retain namespace, creation and lifetime facts.
- `statuses`: the actual immediate reader envelopes for transport receipt
  records, augmented with arm/owner and the later `consumed_monotonic_ns`.
  All other finite status records remain in the retained source event journal.
  The receipt upper bound is `reader_observed_monotonic_ns`, stamped AFTER
  readline and BEFORE parsing/queueing, never the queue-consumption time. A
  valid observed202 remains a fact even if final process return code is nonzero.
- `exits`: six actual `{arm,owner,role,returncode,event_ref}` outcomes. A failed
  attempt without a valid receipt has no finite arrival upper bound; it may
  have arrived. Failure, fallback, partial, duplicate and late records cannot
  be removed to produce a favorable graph. Missing/extra arrivals invalidate
  this finite six-event vector rather than granting a gain.
- `arrivals.A/B`: three actual source-admitted arrival records each. Each has
  `arrival_id` (opaque SHA256 of the exact unlabelled public projection),
  `ordinal` (actual global receiver accept-reservation number),
  `accepted_monotonic_ns,post_handler_monotonic_ns,recorded_monotonic_ns,
  http_status=202,frame_bytes=4096,event_ref,native`.
  Keep actual receiver array/order and global ordinals; do not renumber per arm,
  equate accept order with POST order, assume Tor FIFO or shuffle labels.
- `native` contains `nf_hex32,destination_spk_hex36,payout,fee,action_hex32,
  context_sha256,outpoint_hex36,head_shape`, extracted from exact received
  projection bytes inside the admitted view producer. The public Native adapter
  binds every selected frame/projection/proof; false verification is missing
  coverage, not a reason to change bytes, fees or proofs.
- `arm_partition={mechanism:"source-admitted-public-context",
  contexts:{A:[contextSHA...],B:[contextSHA...]},evidence_refs:[...]}`. Published
  head/Context sets are disjoint and exactly used. Arm membership is computed
  solely from each received public Context, never private paths, owner truth or
  convenient temporal sorting.
- `transport_parameters.A/B` must be identical actual dictionaries containing
  `transport_source_sha256,tor_binary_sha256,curl_binary_sha256,onion_endpoint,
  receiver_source_sha256,request_policy`. No private SOCKS credentials, frame
  hashes or private configs are exported. The fixed request policy retains the
  actual single attempt, HTTP/ACK behavior, redirects, timeouts and fallback.
- `facts`, `coverage`, `unmodeled` as below.

The selected clock helper records the actual local role PID, boot identity,
`CLOCK_MONOTONIC`, current and children time-namespace links/inodes, canonical
kernel monotonic/boottime offsets and clock sample bracket. All eight snapshots
must be present, same boot, current=children namespace, and one namespace cannot
have conflicting offsets. The controller snapshot precedes launch; receiver
snapshot precedes acceptance. The observed receiver-minus-controller offset is
one constant across BOTH arms, never fitted separately to truth or individual
edges. Different boots, missing evidence or ambiguous namespaces refuse this
source's clock admission. A different calibration needs a new Root source
freeze. Tor13 has no such recorded evidence and cannot be upgraded retroactively.

`post_handler_monotonic_ns` is the pre-body-read event. `recorded` is postresponse
bookkeeping and never a pre-ACK upper bound. A source-assigned process/pipe label
only labels outgoing traffic; a particular receiver-frame join requires actual
content, session, timing or another legitimate source fact.

## Facts and missing coverage

Every fact has nonempty `category` and `evidence_refs`. Fixed grammar:

```text
owner-arrival:  arm, owner, arrival_id
allowed-edges:  arm, owner, arrival_ids[]
same-owner:    left:{arm,arrival_id}, right:{arm,arrival_id}
different-owner: same endpoints
```

All IDs belong to the exact admitted six-arrival universe. Include every actual
source-known order/action/head/economic/contact/receipt/session/response/body
identifier or fallback inference. No publicly computable join is dropped merely
because one transport path no longer exports a body hash.

Three actual A facts with category `controller-labelled-release` are required to
establish the baseline exposure. Both arms require owner1's actual legitimate
own NF/SPK match with category `corrupt-own-payout`. Those constraints mean at
most two candidate honest exits remain after corrupt-owner removal; public
Tor13's three-candidate mechanism diagnostic is not this private-view baseline.

Each `coverage[name]={complete:bool,evidence_refs:[...]}` admits the selected
source's completeness claim and actual artifacts. Every required entry is
present. Any false entry blocks a bounded positive result while preserving
diagnostic counts. This must not substitute for independent source review of
the producer or full-view capture.

`unmodeled` contains strict `{scope,category,evidence_refs}` records. Scope is
the primary view string, `GLOBAL-HOST/UNION`, or `UNKNOWN`. Every primary/unknown
item blocks finite-primary completeness. Only literal external categories
`full-global-host-view` and `full-corrupt-server-view` can be outside the primary
view when explicitly scoped GLOBAL-HOST/UNION. Reclassifying an omitted primary
contact/session identifier as global does not permit a gain. Root receives only
counts of these records; raw private descriptions stay private.

## Joint model, seal and one-owner scoring

The engine enumerates at most36 full `(A permutation,B permutation)` pairs,
applies all timing and fact constraints jointly, and retains exact correlations.
Counts are distinct IDs projected from surviving JOINT pairs, not row counts,
independently constructed arm marginals or marginal edge Cartesian products.
The private prediction binds canonical plan/observation hashes, exact universe,
all joint rows, exact arm projections, counts, coverage and clock facts.

The launcher consumes each genuinely new Original's persistent global budget
before notes/views, independently of method/attempt/output labels. It exports
salted commitments only; no private prediction, salt, Contact, truth, mask or
labelled B body digest is controller-readable. The actual all-selected-seals
barrier and completed role journal precede mounting/reading any owner's truth.
A Boolean marker in this pure module cannot establish temporal order.

Each one-owner scorer receives only that owner's truth:
`{schema:"kpb-method03-one-owner-truth/v1",binding,owner,arrivals:{A:id,B:id}}`.
It recomputes the exact sealed prediction before scoring. Its PRIVATE capsule
includes compatible JOINT-model indices and own counts/ranks. Exact digest
tie positions stay PRIVATE: publishing owner-labelled rank1/2 can declassify a
matching honest frame. Public output contains counts and rank intervals only.

The closed aggregate admits all three selected one-owner score capsules and
intersects their model masks. Individually retained owner edges are insufficient:
the complete true A/B assignment must occur in one surviving joint row. Empty
intersection is `INVALID_MODEL`. No Root truth-body input is needed or allowed.

Numerical bounded gain requires every honest B count >= A, at least one strict
increase, the whole truth retained, and complete finite primary inputs. Missing
primary coverage, failed transports or an unestablished baseline prevents gain.
The public result always retains overall `UNQUALIFIED` (or `INVALID_MODEL`): this
finite source/metadata study does not prove full-host/server or cryptographic
privacy, accepted native KAS backing, chain acceptance or deployment readiness.

All controls use invented public data, with dummy native/source fields. They
test the extractor/model contracts and are not actual Tor/Native/privacy evidence.
