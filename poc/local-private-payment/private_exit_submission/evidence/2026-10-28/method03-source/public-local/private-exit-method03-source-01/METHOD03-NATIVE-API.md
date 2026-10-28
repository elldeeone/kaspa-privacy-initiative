# METHOD03 received-byte Native producer (source candidate)

This candidate has no execution authorization or privacy qualification. It
preserves receiver037's missing raw frame padding; `fullpacket_available` is
false. It does not prove a ledger, accepted backing, relay fee adequacy or
settlement, and cannot clear history locks.

The independently selected host launches it only after all receiver/network
roles have completed and stopped. The host must first perform the existing
real seven-root/private-inode public admission. The closed role never mounts
an Original, owner input, proving key, wallet directory or broad project tree.

## Fixed namespace and invocation

Use a fresh interpreter and the host's existing selected network-off bwrap
recipe, including an isolated network namespace, readonly `/usr`, `/proc`,
private `/dev` and `/tmp`, and stdin `/dev/null`. Stdout is a blocking write
pipe carrying only the completion. Close inherited setup FDs before inputs.
The program verifies the actual FD/interface/route boundary; the selected
launcher remains responsible for the complete mount proof.

Readonly, owned, regular single-link leaves (no symlink ancestors):

- `/app/method03_native.py`: exact selected candidate.
- `/app/trial/exit_wire.py`: `fabf7361…`; `/app/verification/wire.py`: `6727e00a…`.
- `/tools/codec`: `cc498d61…`; `/tools/engine`: `077585b8…`;
  `/tools/verifier`: `930972ac…`.
- `/parameters/PARAMETERS.json`: `3f9f2f29…`;
  `/parameters/MANIFEST.json`: `bc41c97e…`;
  `/parameters/IMMUTABLE-TAIL.bin`: `4081fc4e…`.
- `/public/NATIVE-SPEC.json` and `/public/NOTES.json`: exact admitted public
  selection and public heads/rows.
- `/NO-ORIGINAL-METHOD03-NATIVE`: exact bytes
  `METHOD03_CAPTURE_ONLY_NETWORK_OFF` followed by newline.

Mount only the completed receiver-record directory readonly at
`/capture/arrivals`. Provide fresh empty owned writable parent directories at
`/native` and `/public-output`. No real private parent or metadata shadow is
needed. The only nonstdlib Python imports are the two selected pure wire
sources; this role does not execute ce/q/legacy guards or the old 30-source
wallet closure.

```text
python3 -I -B /app/method03_native.py \
  --specification /public/NATIVE-SPEC.json --specification-sha256 SHA \
  --capture /capture/arrivals --output /native/result \
  --public-output /public-output/result
```

`NATIVE-SPEC.json` has exactly:

```text
schema: kpb-method03-received-native-specification/v1
binding: {method_sha256, selection_sha256, trial_id,
          phase: private-exit-route-03, attempt_id}
source_pins: {adapter, codec, engine, verifier, parameters, manifest, tail}
public_notes: {path: /public/NOTES.json, sha256}
transport_parameters: {A: actual_single_session_parameters,
                       B: the_same_actual_single_session_parameters}
```

All source pin values are lowercase 32-byte hashes. The outer frozen plan's
`native_source_pins` must equal this map role by role. The source derives its
adapter hash from its actual bytes and enforces all six existing tool/parameter
hashes. The extractor independently joins transport dictionaries to the actual
session journal and its exact transport role pins.

`NOTES.json` is `kpb-method03-unlabelled-notes/v1` with exact `binding` and
`arms.A/B = {context_hex276, rows_hex520:[3]}`. Heads belong to the existing
fixed profile. Each received projection must match one exact public context.

## Actual checks and outputs

Read exactly all six `arrival-00000001.json` through `arrival-00000006.json`.
Validate filenames before bodies, preserve directory enumeration privately,
then use actual receiver `arrival_sequence` order 1–6. No owner/arm ordering
or positional owner inference is permitted. Hash canonical sorted compact
receiver JSON plus newline for `receiver_row_sha256`.

For each actual received continuing1844 projection/proof128, validate public
framing/NF insertion/context/policy/conservation, derive statement152, directly
invoke genuine selected AuthExit verification, reconstruct the whole CASE,
and normalize it through the selected codec. Every field must remain identical
except cached transaction ID/mass. Direct selected NativeFull then requires
its real successful isolation report, `Full.accepted`, the aggregate input
engine flag and exactly one accepted ScriptEngine. Preserve fee1 unchanged.
All six attempts run; malformed/missing results never become positive.

Private `/native/result/INDEX.json` is mode0400. Its envelope is exactly
`{schema,binding,records,transport_parameters,public_heads,native_reports,
publication_metadata}`. `public_heads` carries `{arm,context_hex276,evidence_ref}`;
the reference identifies the private artifact copy of public NOTES. Native
artifact refs are relative to `/native/result`. They identify actual generated
CASE/normalization/report/proof-result bytes, not imported pass flags.

Each strict `kpb-method03-received-native-check/v1` row has:

```text
binding, ordinal, receiver_row_sha256, projection_sha256, proof_sha256,
source_pins, actual_native_returncode, native_full_accepted,
all_scripts_passed, actual_public_proof_verified,
isolation: {network:none, input_scope:unlabelled-public-received-exits,
            originals_mounted:false},
artifact_refs: {case, normalization, native_report, proof_result}
```

Each artifact ref is exactly `{path:canonical_relative_POSIX,sha256}`. A missing
report has an explicit missing-report artifact and false outcomes. A failed
construction yields no fabricated Native row and forces incomplete checks.

Only received chain-visible fields are exported publicly:

- `/public-output/result/EXITS.json`:
  `{schema:kpb-method03-unlabelled-exits/v1,binding,records:[6]}`; each record is
  `{ordinal,projection_hex,proof_hex128,statement_hex152,exit_id}`. No arm label.
- `/public-output/result/NATIVE-RESULT.json`: typed counts, exact strict check
  rows, source pins, actual qualification flag and public EXITS aggregate ref.
  Artifact refs still describe the separately private Native artifact scope.

Public files are written and fsynced first. Private INDEX then records actual
producer PID, observed kernel boot/time namespaces/offsets before and after,
actual prewrite/post-fsync clocks and exact public artifact refs. Public refs
in this event are relative to `/public-output/result`. There is no INDEX or
status hash cycle, clock fitting, or synchronization claim.

Stdout is `kpb-method03-native-completion/v1`: fixed status, six-record/check
counts, `actual_checks_passed`, metadata-only private INDEX ref, public aggregate
EXITS/result refs, and `fullpacket_available:false`. The blind controller may
translate admitted namespace aliases and stat the private INDEX. It must never
open or hash INDEX, captures, public body exports or per-record artifacts.
Closed selected observers consume those bodies independently.

Capture/schema/tool failures return a fixed `REFUSED` completion and nonzero
exit, without a private traceback. Protected partial artifacts remain retained.

Failed runtime episodes must retain all capture files and partial private
outputs. No automatic retries, fee retuning, proof replacement, padding
reconstruction, source relabelling or promotion to privacy success is allowed.
