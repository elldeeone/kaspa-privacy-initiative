# Portable public recovery material

This new ADR0057 package copies/authenticates public recovery objects. It does
not read a seed, prove ownership, run a native verifier, determine a current
balance or broadcast. Earlier frozen recovery packages remain unchanged.

`capsule.py` consumes an independently selected instance/role and a separately
selected snapshot-index SHA. A mirror's self-consistent hashes cannot replace
that selection. The exact five index objects are descriptor, historical native
records, compact public parameter manifest, compact public PK and software
inventory. Actual unbroadcast main protocol bytes remain outside Git; a public
format is not permission to publish discarded Auth/NF alternatives.

```sh
python3 pack_local.py TRUSTED_SELECTION_JSON NEW_LOCAL_CAPSULE \
  --descriptor DESCRIPTOR_JSON --history PUBLIC_FORMAT_HISTORY_JSON \
  --parameters-manifest COMPACT_MANIFEST_JSON --public-parameters COMPACT_PK \
  --software-inventory SOFTWARE_INVENTORY_JSON

python3 capsule.py CAPSULE_JSON EXPECTED_INDEX_SHA TRUSTED_SELECTION_JSON NEW_OUTPUT \
  --mirror LOCAL_CAS_ROOT --mode recognition

python3 https_mirror.py EXPECTED_INDEX_SHA TRUSTED_SELECTION_JSON NEW_OUTPUT \
  --mirror-base https://public-cas.example/root --mode spend_material
```

For an actual cold invocation, `--forbidden OWN_BACKUP_FILE` performs metadata
alias checks before any caller-controlled public file read/hash. A trusted
installed caller must authenticate the public selection file independently;
downloading both that file and its hash from the same mirror does not do so.
CLI inputs cannot select an executable/import/archive or arbitrary object path.

`recognition` stages exactly four small public objects and never opens/fetches
the PK. `spend_material` additionally stages the exact compact PK; the wide PK
is not an owner dependency. The real selected owner prover must still hash its
complete owned PK buffer, decode it fully, verify extracted VK/role/dimensions,
and emit its authenticated readiness before any backup/witness read. These
transport controls do not exercise that actual loader.

The returned `StagedCapsule` exposes owned small JSON byte buffers and read-only
copied paths. Results explicitly state `current_state_verified:false` and
`spend_authorized:false`. Read-only staging assumes the ADR0054 trusted host
does not mutate it during consumption; a verified path is not an everlasting
authorization for future reopened bytes.

Lifecycle replay must independently validate native state/roots/proofs and sparse
positions. After the initial n1→wide32 append, outputs occupy32..63 and n64;
gaps1..31 are CM_EMPTY, never receipts renumbered into a dense list. Fresh
selected-node acceptance/ancestry/UTXO/spentness/post-query evidence is required
before a current exit decision. An intact historical capsule is not a new node
observation, independent consensus or immutable finality. Missing data is not
zero balance.

The HTTPS client fetches the index itself at `objects/sha256/EXPECTED_INDEX_SHA`,
then the exact referenced objects. Four-object strict preflight precedes a PK
network request. It streams exact length/full SHA and retries the whole selected
object from another source on failure. TLS verification remains enabled;
cross-origin HTTPS redirects are allowed but downgrade/userinfo is rejected.
Initial mirror URLs cannot carry userinfo/query/fragment, and redirect/query/URL
strings are omitted from receipts/errors. Only `--allow-loopback-http` permits
literal127.0.0.1/::1 HTTP for public local tests. No GitHub asset resolver, chunk
reassembly, provider upload or retention service is implemented.

Public evidence is under
[`research/next-session/compact-batch/recovery`](../../research/next-session/compact-batch/recovery):
12 parser/transport questions, 13 independent fault questions with calibrated
kernel IN_OPEN guards, eight actual loopback-HTTP questions one isolated
CLI source/cache-loss question, and six explicit-input pack controls. Reruns are not additional independent cases.
Tiny fake public keys/structural histories deliberately do not qualify Ark
decoding, private recognition, native settlement, external TLS handshakes,
independent hosting, long-term retention, cryptographic soundness or privacy.

The initial HTTP pass retained a response-handle ResourceWarning; explicitly
closing HTTPError responses fixed it and two existing affected cases passed
without warnings. The initial CLI loss probe failed at an unsupported nested
usernamespace before client entry. Its public controller moved to an owned host
cgroup; the real retrieval client remained a single isolated namespace and
passed. Original failures/logs/source bytes remain retained, with no production
checks weakened or actual cache/backup mutated.

`pack_local.py` accepts only explicit typed source files and verifies the four
small identities/schemas before opening a large PK. Recognition-only packing
needs no PK source. Its output is explicitly unpublished; the controller must
keep raw main unbroadcast Auth/NF histories private and separately authorize
any external publication. Source keys, arbitrary directories and secret-key
backups are not package inputs.
