# Capsule staging interface

Implemented under ADR-0057 release. Initial public structural controls passed;
actual new-role PK/owner/native integration remains separately scheduled.
This fixes the transport boundary for the independent fault reviewer without
claiming that a capsule is current or authorizes an exit.

## Trusted selection

`TrustedSelection` is installed/controller-authenticated public configuration,
never loaded from a capsule or mirror. Its strict fields are:

```text
schema = kpx4-recovery-capsule-selection/v1
network_id = testnet-10
genesis_hash_hex : hex32
domain_hex32 : hex32
program_label : exact selected profile label
role = compact2
auth_magic_hex8 = hex(KPX4AU01)
descriptor_sha256 : hex32
parameters_manifest_sha256 : hex32
public_parameters_sha256 : hex32
public_parameters_bytes : positive integer
vk_sha256 : hex32
software_inventory_sha256 : hex32
```

The expected capsule manifest SHA256 is supplied separately. It identifies the
exact snapshot object index selected for an experiment; it does not supersede
the static role/instance selection. Passing a mirror's own hash does not make
its identity or freshness independently authenticated.

## Capsule index

Strict canonical sorted compact UTF-8 JSON, no trailing newline or duplicate
names. Exact top-level fields:

```text
schema = kpx4-public-recovery-capsule/v1
network_id, genesis_hash_hex, domain_hex32, program_label, role
objects = [ five {kind, sha256, bytes} records, sorted by kind ]
```

The exact kinds are `descriptor`, `history`, `parameters_manifest`,
`public_parameters`, `software_inventory`. Each kind occurs once, digests are
lowercase hex32 and byte lengths are positive integers. Storage locations are
derived only as `MIRROR_ROOT/objects/sha256/DIGEST`; a capsule cannot name a
filesystem path, URL, shell command or import.

Descriptor/parameter/PK/software digests and PK length must equal the trusted
selection. Historical digest is snapshot-specific. All JSON object bytes have
their own strict schema/domain/network checks before handoff; the `history`
body still requires lifecycle semantic/acceptance verification.

## Python API and CLI boundary

```python
stage_capsule(
    manifest_path,
    expected_capsule_sha256,
    selection,                 # TrustedSelection, not capsule-provided policy
    mirror_roots,              # Untrusted public transport roots
    new_output_directory,      # Fresh and private; no previous owner output
    forbidden_paths=(),        # Actual cold use MUST include own backup metadata
    mode='spend_material',     # Or the fixed 'recognition' subset
)
```

Return `StagedCapsule`: immutable owned small JSON byte buffers in
`owned_json[kind]`, read-only owned-copy locations in `staged_paths[kind]`, and
a safe `public_receipt()`. Full mode reports
`PUBLIC_COMPACT_SPEND_MATERIAL_VERIFIED_AT_COPY`; recognition mode reports
`PUBLIC_RECOGNITION_MATERIAL_VERIFIED_AT_COPY`, with known object identities,
selected role/domain, rejected-mirror reason categories and
`current_state_verified:false`, `spend_authorized:false`. No owner, private
input hash/path, actual unexpected file digest or callback is returned.

The staging call does not accept a validator/prover/backup parser, network
endpoint, currentness flag, expected payout or intended-amount map. Public CLI
controls use synthetic fixtures and a non-seed sentinel; an actual wallet
adapter must authenticate its installed selection and perform the own-backup
metadata alias guard before any caller-selected public read/hash.

Check all path components, source/destination regular files and own-backup
device/inode aliases. Open sources without following symlinks, stream exact
expected bytes into exclusive temporary files, check full SHA/length and close
before final read-only install. A changing source is invalid. Missing/corrupt
objects can fall back only to another source for the same selected object.
All-invalid sources leave an incomplete stage and return a fixed failure.

Consumers use owned small JSON bytes. A public-PK pathname is only a staged
transport result: the selected owner loader must authenticate its complete
owned bytes, decode/exhaustion, extracted VK and dimensions before reading a
backup/witness. ADR-0054 trusted-host integrity during use remains explicit.

## Semantic and currentness handoff

`history` is `kpx4-compact-batch-history/v1` from the lifecycle lane. Exact native
body/entry records drive sparse replay. Actual positions are preserved; after
n1→wide32, outputs are32..63 and n64, with1..31 left CM_EMPTY. An archive index
or receipt-list offset is never a real NF position.

No transport success is a current-wallet success. The owner must separately
validate a fresh selected-node accepted-history/current-UTXO observation and
post-query/reorg/pruning evidence joined to the semantic history. An old intact
capsule alone yields no exit authorization. The old verifier is not automatically
compatible with the new compact policy and sparse layout.

Foreign/dummy ciphertexts normally fail decryption. Report recognized-own
balances rather than inferring zero liabilities from lack of decryption.
Previously recognized claims whose data disappears remain unresolved. A global
zero-reserve assertion requires the valid terminal transition and fresh observed
consumption, independently of an individual wallet's recognized receipt count.

## Concrete object envelopes

The capsule index always references exactly five objects. Fixed `recognition`
mode stages descriptor, history, parameter manifest and software inventory; it
never opens, fetches or requires the PK object. `spend_material` requires all
five. Neither mode performs private recognition or authorizes a spend.

- Descriptor: exact12 fields `schema, network_id, genesis_hash_hex, domain_hex32,
  founding_outpoint, birth_start_hash, initial_redeem_hex, compact_vk_hex328,
  wide_vk_hex328, immutable_policy_sha256, compact_public_params_manifest_sha256,
  wide_public_params_manifest_sha256`; schema `kpx4-compact-batch-descriptor/v1`.
- Parameter manifest: exact19 fields `schema, role, output_arity, auth_magic_hex8,
  program_label, trial_id, network_id, genesis_hash_hex, domain_hex32, format,
  pk_bytes, pk_sha256, vk_hex328, vk_sha256, core_source_identity,
  compiled_build_identity_sha256, constraint_shape, queries, setup_provenance`.
  Schema `kpx4-public-proving-parameters/v1`; program label
  `AUTH528_COMPACT_BATCH/v1`; compact2/arity2 is selected for owner material.
- History: exact `schema, classification, descriptor_sha256, records`; each
  record is exactly `{transaction, entries}`. Native body/input/output/context
  shapes are checked structurally; actual IDs, scripts, roots, membership and
  state effects require the lifecycle/native verifier. Tests explicitly use
  `PUBLIC_STRUCTURE_ONLY_DO_NOT_FUND`, with no native acceptance claim.
- Software inventory: exact `schema, program_label, source_base_commit,
  source_freeze_sha256, components`; schema `kpx4-recovery-software-inventory/v1`,
  and components are `{component, sha256}` records. No command/import/path field
  is admitted. The selected inventory does not select installed executable code.

## HTTPS transport addition

`https_mirror.retrieve_capsule(expected_root_sha, selection, mirror_bases,
new_output, forbidden_paths=(), mode=..., allow_loopback_http=False)` fetches the
index itself and exact typed objects at `/objects/sha256/DIGEST`, verifies whole
length/SHA, then invokes the same production stager. Four small objects and
strict role/identity preflight precede any PK network request. Recognition mode
performs no PK request. Cross-origin HTTPS redirects retain verified TLS and
forbid downgrade/userinfo; URL/query text is never reported. The only HTTP
exception is explicitly enabled literal127.0.0.1/::1 for local public controls.
A loopback failover test is transport portability, not external-provider retention.
