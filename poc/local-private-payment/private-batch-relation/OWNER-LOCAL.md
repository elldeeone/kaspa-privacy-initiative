# Owner-local witness preparation

`owner_aux` runs inside one isolated wallet process. It accepts exactly one
owner record and the authenticated public old context. It constructs the other
owner slots and unknown effect core internally from public invalid filler,
returns only the held owner's native auxiliaries, and appends that owner's
complete real normalized EdDSA assignment. It never receives another owner's
record, signing seed, signing scalar or signing nonce.

```sh
.local/private-batch-relation-target/release/owner_aux \
  REQUEST.json OWNER-PRIVATE-INPUT.txt PUBLIC-RECEIPT.json
```

The request has exactly these fields; relative paths resolve against its parent:

```json
{
  "schema": "kpi-owner-local-aux-request/v1",
  "owner_component": 0,
  "context_hex": "<276 canonical bytes, lowercase hex>",
  "owner_record_path": "OWNER-LOCAL-RECORD.json",
  "signature_matrix_path": "signature-normalized-r1cs.json",
  "signature_witness_path": "signature-normalized-witness.json",
  "expected_matrix_sha256": "<selected public matrix SHA256>",
  "expected_mapping_sha256": "<selected public adapter-map SHA256>",
  "expected_witness_sha256": "<owner-local normalized witness SHA256>"
}
```

The matrix/map pins come from the independently selected signature adapter,
not from arbitrary labels in a received JSON file. The owner-local witness pin
is checked only within that isolated worker. The CLI uses the retained strict
normalization parser, checks every actual signature row, reconstructs the full
1,460-byte restricted intent, and checks the 66 native digest/AK join edges.
The active aggregate checker must still check all full model rows; local checks
are not a proof or a financial acceptance decision.

The private record has input `note_hex168`, `nk_hex32`, `position`,
`path_hex32` (16 nodes), `cv_hex64`, `blind_hex32`, `ak_hex64`, `nf_hex32`;
top-level `fee_sompi`, `nonce_hex32`, `private_delta_hex32`, `intent_hex1460`;
two `outputs` with `tuple_hex520`, `note_hex168`, `blind_hex32`; `signature`
with `owner_key_hex64`, `R8`, `S`; and the retained `signature_inputs` exact
keyset (`digestLimbs`, `ownerKeyBytes`, `sigR8`, `sigS`, `preimageA`,
`preimageR8`). Decimal strings are canonical and field/byte bounded. Optional
top-level metadata is limited to `schema` and `owner_component`.

The private output is created with mode0600, without overwriting an existing
file. It is never printed or hashed into the public receipt:

```text
KPB_OWNER_INPUT_V1
OWNER owner0
COUNT <n>
VALUES
<canonical Fr decimal, one per line>
END
```

The order is native internal edges66, owner-native auxiliary range, signature
assignment excluding ONE. These are sorted global column IDs in the selected
joined model's hash-bound owner layout. The masked-input owner process must
check owner role/count/layout and authenticate this vector. Caller-selected
columns and arbitrary global digest/state/permutation values are not accepted.
The public receipt contains only counts, the public context hash, native range
and selected public signature matrix/map identities. Controllers may inspect
that receipt, never the private record, WTNS or private input body.

The earlier three-owner partition control compared every native auxiliary and
all join edges against changed unrelated-owner/effect filler, retaining the
same physical layout. Its exact source/results are under
`.local/private-batch-partition-20261028-01`; that evidence is scoped to the
captured source. It establishes no matrix satisfaction, MPC execution or privacy
claim by itself.
