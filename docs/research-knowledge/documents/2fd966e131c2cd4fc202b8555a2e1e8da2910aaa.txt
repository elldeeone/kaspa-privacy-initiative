# Offline public final-candidate bridge

This isolated ADR0078 candidate supplies the missing lifetime boundary after
the private runtime exits at durable EGRESS. It verifies the later complete
public CASE and genuine R0 receipt without restoring that runtime's shares,
MAC context, prepared ticket or `EgressRelease` object.

It has no network, acquisition, submission, settlement or unlock API. Its result
can support a new narrow C++ `VerifiedFinalCandidate` only after direct selected
execution and a fresh authenticated all-three FINAL barrier. The separate live
settlement adapter retains its unchanged strict v2/eight-token contract.

Only files in this new candidate directory were added. Existing active sources,
the frozen qualification and authority selections remain unchanged. The actual
outer profile remains unselected; no genuine financial verification execution,
R0 generation, funding, broadcast or journal modification was performed here.

## Direct launch

```text
python3 -I -B finalize.py --selection FILE --selection-sha256 SHA
  --request FILE --request-sha256 SHA --output FRESH_DIRECTORY
  --exclude-private-directory WHOLE_PRIVATE_ROOT [repeat]
```

The parent C++ factory must execute admitted source bytes from its sealed memfd
using the admitted interpreter descriptor. The fixed bootstrap sets `__file__`
to this original canonical compile-pinned source path, preserving relative
source selection. Stdin is `/dev/null`; inherited private/TLS/MPC/journal file
descriptors are closed before exec. No caller-supplied source origin is allowed.

The outer launcher authenticates source/tool/input bytes with unchanged guard09
after metadata-only private exclusion inventory. It snapshots independent
readonly public files, hides the writable snapshot alias, and directly launches
one network-disabled bubblewrap role. It reauthenticates the original admitted
bytes and synchronizes all retained public evidence before its final export.

## Fixed selection

Exact schema `kpb-offline-final-selection/v1`:

```text
schema, selected, classification=RESEARCH_TESTNET_ONLY,
registered_history_sha256,
source_members:[{path,sha256}],
tools:{codec:{path,sha256},host:{path,sha256},native_validator:{path,sha256}},
component_profile:{path,sha256},outer_selection:{path,sha256},parameters:{path,sha256}
```

There is no node, SDK, endpoint, network or runtime qualification field. The
selected component and outer image must be genuine and selected. The complete
fixed public closure includes this finalizer/protocol, the actual qualified
three executables and their public runtime requirements, plus the frozen shared
sources below. Missing closure files fail inside the sparse public namespace.

Shared source is loaded only through admitted reads; no frozen source is edited:

- `poc/local-private-payment/mpc-prover/history/settlement/launch.py`
  SHA `9a9d8cb0dd978e2c9265dc187dd24a92f1696e6de668a9d2997039e56fedc4c5`:
  unchanged guard bootstrap, selected-profile joins, public namespace, direct
  tool execution, finite writes and complete evidence synchronization.
- The same directory's `protocol.py`
  SHA `cae9c1c46a425c780b5545254203251cd72a4e96188cfd8998779b3febe2c8c0`:
  strict integer/JSON/hex encoding, complete CASE, actual EGRESS/NF/state/policy
  and final image/journal/native-proof joins.

The original `load_guard` bootstrap function is copied unchanged into the new
outer entry so no shared body is read before private metadata admission.

## Request from current registered EGRESS

Strict schema `kpb-offline-final-request/v1` contains exactly:

```text
schema, nonce_hex32, history_key_hex32, registered_history_sha256,
server_certificates_hex32:[ordered3], attempt_id_hex32, locked_binding_sha256,
prepared_core_sha256,
context:{chain_hex32,pool_hex32,profile_hex32,domain_hex32,service_hex32,epoch_hex32},
head:{outpoint:{transactionId,index},state_hex112,reserve_sompi},
native_policy:{old_script_public_key_hex37,immutable_tail_sha256,native_parameters_sha256},
egress_record:{sequence,checkpoint_sha256},
egress:{core_sha256,aggregate_proof_sha256,projection_sha256,nfs_hex32:[sorted3]},
candidate:{case:{path,sha256},r0_receipt:{path,sha256}}
```

The C++ factory derives this internally from its replayed authenticated journal,
registered history configuration and a fresh random nonce. The two candidate
input digests come from guarded public-byte admission; they do not claim an
existing FINAL record. There is no prefilled `final_candidate`, accepted flag,
qualified flag, imported result or caller-selected expected proof output.

The history key is independently recomputed as SHA256 of the actual
`KPBHKEY1` encoding: chain, pool, domain, profile, service, epoch, then the three
ordered server-certificate digests. The selection must name the same registered
history. `sequence` is a positive u64 JSON integer; reserve is a canonical
decimal string at this boundary. CASE amounts remain integer sompi.

## Actual verification and output

The actual selected codec checks exact redeem/SPK, immutable tail, old head,
split state, values/fees/conservation/counts/successor, storage mass and SDK/native
transaction ID semantics. Core, aggregate proof, projection and full NF256 set
must match the durable EGRESS request. Only the private payment form is eligible.

Direct host `cross-check` verifies aggregate plus six Output Groth16 proofs,
independent Arkworks reference, state and global commitment balance. Direct
host `native-proof` requires the selected image, exact104-byte journal, genuine
Groth16 receipt, no development mode/assumptions and exact canonical128 bytes
equal to the actual CASE witness. Actual NativeFull and every input engine must
accept, with fee equal to the actual codec result. No cached report is imported.

The direct outer success line has a distinct prefix and exactly16 hex32 tokens:

```text
KPB_OFFLINE_FINAL_VERIFIED_V1 NONCE REQUEST_SHA ADAPTER_SELECTION_SHA LOCK_SHA EGRESS_CHECKPOINT_SHA PROJECTION_SHA CANDIDATE_SHA EVIDENCE_SHA RAW_CASE CANONICAL_CASE PROJECTION NATIVE_PARAMETERS IMAGE JOURNAL OUTER_RECEIPT NATIVE_PROOF
```

The final eight fields are all computed from actual admitted bytes/verifier
outputs, in the existing `FinalCandidate` encoding order. `NATIVE_PARAMETERS`
is the exact raw native parameter artifact SHA, distinct from adapter selection.
`CANDIDATE_SHA = SHA256(KPBHFIN1 || those eight32-byte fields)`. The duplicate
projection must equal durable EGRESS. The evidence hash names exact retained
`FINAL-CANDIDATE.json`; its JSON is informational, not an imported authority API.
The inner role emits only `KPB_OFFLINE_FINAL_EVIDENCE_V1` and cannot emit the
outer final-candidate prefix or the live settlement prefix.

## C++ capability and durability requirements

The factory requires current phase EGRESS and fixed registered store/anchor,
source/interpreter/offline selection and roster. It checks every direct token,
independently recomputes candidate encoding/hash, and binds the result to its
fresh context/generation/failure epoch and exact journal sequence/checkpoint.
Before append it atomically rechecks that same EGRESS/attempt/LOCK under the
journal writer lock. It consumes a private one-use `VerifiedFinalCandidate`;
there is no deserializer or public Boolean constructor.

Fresh authenticated all-three agreement binds the original registered roster,
exact EGRESS checkpoint, selected verifier and complete computed candidate.
Local FINAL journal/anchor synchronization and all-three durable acknowledgement
precede submission permission. Partial append/ack/crash or stale state halts
without overwrite, reset, unlock or reconstructed private/prover authority.
An offline final capability cannot append SETTLED; accepted-chain verification
remains a separate capability. Previously admitted backing/GEN3 head remains
an independent prerequisite, not a conclusion of supplied-context NativeFull.

## Evidence boundary

Independent source review checked this actual source path and its reused
crypto/native checks. Ten focused public controls pass: strict no-prefilled
FINAL schema, roster/key/sequence joins, EGRESS/NF256/policy changes, same txid
with changed CASE, all candidate hash fields, actual guard09 early refusal and
real offline namespace/private synthetic canary/descriptor exclusion.

These controls deliberately contain dummy proofs. Actual new-host/genuine R0/
NativeFull execution is held pending root selection and real proof availability.
The C++ factory, all-three FINAL integration, real full lifecycle and later
accepted-chain settlement still require their own review and qualification.
