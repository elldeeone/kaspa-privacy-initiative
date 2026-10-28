# METHOD03 budget candidate04 — source only, UNSELECTED

No production registry or private generation/intake is authorized. The module
ships `SELECTED_IDENTITY_POLICY='UNSELECTED'` and `REGISTRY_ADMISSION=None`.
Root must select/freeze the fixed-profile identity limitation, complete sources,
new bootstrap and pre-created protected registry before any private execution.
Candidate01 remains byte-exact; this draft adds explicit worker references.

The funding SPK is KPBKDF01 profile/domain-dependent. Its hash alone is the
global directory key, but this candidate refuses every different profile/domain
and does NOT claim universal cross-profile Original identity. The three known
METHOD02 funding scripts are forbidden. No new key derivation is introduced.
Registry path is fixed outside labels/backups. Missing or replaced admitted
storage refuses. The storage operator must not roll back registry contents;
local bookkeeping cannot detect arbitrary in-place restoration by that operator.

All record/reference SHAs below are computed from the helper's known PUBLIC
metadata bytes as it writes them. `reservation_refs` and `barrier_ref` only
inspect metadata. They do not open/read/hash protected record bodies, capsules,
Originals, views, predictions or truth.

## Pre-intake spec and fresh-bootstrap facts

`validate_spec(spec, bootstrap_public_facts=None)` is pure and grants no authority.
Spec exact fields:

```
schema = kpb-method03-budget-spec/v1
binding = {method_sha256, selection_sha256, trial_id,
           phase="private-exit-route-03", attempt_id}
identity_policy = UNSELECTED | FROZEN_PROFILE_FUNDING_SPK_V1
profile_id_hex32, domain_hex32
source_sha256, slot_grammar_sha256
selected_view_labels = ["GLOBAL_UNION", "PRIMARY", "TERMINAL_CONTACT"]
bootstrap = {trial_id, trial_sha256, selection_sha256,
             generator_sha256, worker_sha256}
owners = three ordered {owner_component, funding_spk_hex36,
                       initial_public_sha256}
```

`slot_grammar_sha256` is the fixed PUBLIC slot/economic grammar, not future
notes, NFs, projection IDs, private graphs or truth. Actual unlabelled universe
hashes do not exist at reservation and are forbidden in this pre-intake schema.
The facts schema is `kpb-method03-bootstrap-budget-facts/v1` with exactly
`bootstrap, profile_id_hex32, domain_hex32, owners` plus `schema`.
Actual fresh generation/selected public-output provenance comes from the
source-frozen launcher and closed bootstrap, not imported booleans or names.

`claim = reserve(spec, facts)` fsyncs exclusive global tombstones for all three
identities before returning. Every partial failure/crash remains consumed.
No cleanup, reset, restore, resume or caller-supplied registry path exists.

## One Original record for each generation worker

`reservation_refs(claim)` returns one `{owner_component, identity_key, path,
sha256, metadata}` per owner, computed at the original writes. Each leaf has:

```
schema = kpb-method03-consumed-vector-budget/v1
identity_key, owner_component, funding_spk_hex36
profile_id_hex32, domain_hex32, binding
source_sha256, slot_grammar_sha256, bootstrap
initial_public_sha256, spec_sha256
```

The generator mounts ONLY its own record at `/budget/ORIGINAL.json`, verifies
record/config/source/binding/grammar/frozen profile before Original intake, then
derives the actual `invoice(0xffffffff).native_pk` funding SPK from its sole
Original under that frozen profile and compares before new invoice/note creation.
It must not trust caller backup profile/name fields or `reserved:true`.

## Observation permits and all-seal barrier

Before each selected private view/state/capsule mount:

```
permit_ref = claim_view_intake_once(claim, label)
```

This consumes exclusive markers in all three identities. Required labels/kinds:
`PRIMARY/prediction`, `TERMINAL_CONTACT/coverage`, `GLOBAL_UNION/coverage`.
Coverage is explicitly missing/unqualified/no-score/no-gain in its closed
capsule; it is never a relabelled PRIMARY model. Its closed producer enforces
that capsule grammar. A missing required coverage capsule cannot be accepted by
a caller boolean.

Every public budget permit has exact fields:

```
schema = kpb-method03-budget-permit/v1
operation, label, kind, owner_component
binding, source_sha256, slot_grammar_sha256, spec_sha256, reservation_keys
actual_unlabelled_universe_sha256, all_seals_sha256
```

Observe permits have `operation="observe-view"`, the exact label/kind,
`owner_component=null` and both future-data fields null. The worker must check
its expected operation/label/kind/binding/source/grammar before `/state` or any
private capsule intake. A returned ref is evidence of a stateful call; an
arbitrary imported permit JSON is not temporal authority.

The selected launcher gathers real completed roles/public seals, then calls:

```
barrier = mark_views_sealed(claim, completed_view_refs)
public_barrier_ref = barrier_ref(claim, barrier)
```

Each completion ref has exactly:

```
{label, kind, binding, source_sha256, public_plan_sha256,
 slot_grammar_sha256, actual_unlabelled_universe_sha256,
 salted_public_seal: {path, sha256}, salted_commitment_sha256,
 completion: {observed_launcher_pid, returncode: 0,
              completed_monotonic_ns, event_ref: {path, sha256}}}
```

All three kinds, exact binding, frozen source/slot grammar and the SAME actual
post-capture public unlabelled universe must match. Completions follow their
stateful view permits. The actual launcher must wait/admit the seals; hashes,
PIDs and timestamps alone cannot manufacture provenance. The private capsule
must actually include a fresh high-entropy salt. Raw private observation or
prediction hashes, models, masks, owner arrival IDs and salts are rejected.

The common barrier leaf exact fields are:

```
schema = kpb-method03-all-selected-views-sealed/v2
binding, source_sha256, slot_grammar_sha256
actual_unlabelled_universe_sha256, completed_view_refs
```

It is durably written in all three claims before the barrier ref is issued.
One can be mounted at `/public/ALL-SEALS-BARRIER.json`; its SHA covers the exact
three salted seal refs and completion metadata. Partial writes grant no barrier.

## One-owner truth and closed aggregate

Immediately before each owner's truth mount/read:

```
truth_permit_ref = claim_truth_once(claim, barrier, owner_component)
```

This writes that owner's exclusive truth marker and returns a public permit ref.
Its permit has `operation="score-owner"`, `label="PRIMARY"`, `kind="score"`,
the exact owner0/1/2 and the barrier's actual universe/all-seals SHA. The closed
worker verifies it and the actual barrier before private state/capsule/truth.
The launcher cannot replay it for another intake: it must invoke the stateful
function on each actual mount path. One-owner compatibility masks stay private.

After all three actual scores complete:

```
aggregate_ref = claim_aggregate_once(claim, barrier, completed_score_refs)
```

Score refs are ordered owner0/1/2, exact `{owner_component,binding,source_sha256,
slot_grammar_sha256,actual_unlabelled_universe_sha256,completion}`; completion
has the same public PID/returncode/monotonic/event fields and follows that
owner's truth permit. There are no private scores/masks/raw hashes in these refs.
The returned permit has `operation="aggregate"`, `label="PRIMARY"`,
`kind="aggregate"`, `owner_component=null` and actual universe/all-seals SHA.
The closed aggregate independently validates its three private inputs and
intersects the whole joint models; the helper does not read those files.

These are source-level bookkeeping controls under a selected launcher/trusted
durable-storage assumption, not cryptographic capabilities against arbitrary
same-process Python code or a malicious host/storage operator.


## Issued claim accessors (candidate03)

describe_claim(claim) requires the exact in-memory issuer-bound BudgetClaim. It returns a detached public object with exact fields schema,binding,spec_sha256,source_sha256,slot_grammar_sha256,profile_id_hex32,domain_hex32,identity_policy,selected_view_labels,bootstrap,owners,owner_record_refs; schema is kpb-method03-issued-budget-description/v1. Public owner records are strictly ordered 0,1,2.

owner_record_ref(claim, owner_component) requires the same issued claim and an integer owner 0,1,2 (booleans refuse). It returns {owner_component,identity_key,path,sha256,metadata}. Both APIs check live registry/claim/record metadata; their SHA values were calculated from public bytes at write. Neither reopens protected record bodies, handles Originals, nor grants authority via an imported description/dict.

The generator calls the accessor before assembling any owner role. The selected owner checks its own mounted public record/config before its Original load, then derives invoice0xffffffff under the exact frozen profile/domain and matches its actual funding SPK before METHOD03 invoice/note creation. Closed observation/scoring/aggregate roles never receive an Original.

The completed-view salted_commitment_sha256 is copied from the actual public SEAL's salted commitment. It is NOT a private capsule file SHA. The controller never reads/hashes the private capsule. The closed worker verifies the private capsule's fresh salt/payload against that public commitment. Raw unsalted observation/prediction hashes remain forbidden in public refs.

Reservation requires explicit bootstrap_public_facts; reserve(spec, None) refuses before any registry access. validate_spec(spec) remains pure validation and grants no reservation/intake authority. Structural fact equality is not proof of fresh bootstrap provenance.
