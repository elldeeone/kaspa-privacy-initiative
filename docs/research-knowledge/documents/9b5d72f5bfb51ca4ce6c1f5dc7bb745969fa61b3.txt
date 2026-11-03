# Public parameter contract

Selected under ADR-0053; executable launch follows ADR-0054. The concrete
[canonical manifest](parameters-01/public-parameters.json) is root-selected as
SHA256 `008689b84cd171187cc75d32402dbf13d6d4e3ed149d3349ecfbc418bfcaad54`.
It contains no witness, seed, private note, recovery profile path or witness hash.
The filename retains its original prospective-stage name.

```json
{
  "schema": "kpx3-public-proving-parameters/v1",
  "trial_id": "FRESH_ID",
  "network_id": "testnet-10",
  "genesis_hash_hex": "CANONICAL_TN10_GENESIS_HEX",
  "domain_hex32": "CANONICAL_FRESH_D_HEX",
  "format": "arkworks0.6-bn254-uncompressed",
  "pk_bytes": 0,
  "pk_sha256": "FULL_SHA256",
  "vk_hex328": "CANONICAL_VK_HEX",
  "vk_sha256": "SHA256_OF_VK328",
  "core_source_identity": {
    "lib_rs_sha256": "SHA256",
    "circuit_rs_sha256": "SHA256",
    "exact_sha256_rs_sha256": "SHA256",
    "request_rs_sha256": "SHA256",
    "parameters_rs_sha256": "SHA256",
    "main_rs_sha256": "SHA256",
    "setup_rs_sha256": "SHA256",
    "build_rs_sha256": "SHA256"
  },
  "compiled_build_identity_sha256": "SHA256",
  "constraint_shape": {
    "constraints": 0,
    "witness_variables": 0,
    "instances_including_one": 3
  },
  "queries": {
    "a": 0,
    "b_g1": 0,
    "b_g2": 0,
    "l": 0,
    "h": 0,
    "instances_including_one": 3
  },
  "setup_provenance": {
    "executable_sha256": "SHA256",
    "source_freeze_sha256": "SHA256",
    "public_setup_report_sha256": "SHA256"
  }
}
```

All hex is exact-width lowercase and all byte counts/query lengths are unsigned
integers. The displayed pretty JSON is illustrative only: the exported manifest
uses recursively sorted compact JSON bytes with no trailing newline. Require
that exact canonical representation, so its raw SHA256 and canonical JSON SHA256
are identical. Every object rejects unknown and duplicate fields. The selected format,
D, complete core identity, build identity, public VK and query dimensions must
match the cold client's compiled constants. Actual decoded PK query lengths and
checked VK must match the selected manifest, rather than merely being reported.
The zero shape/query numbers above are placeholders, never selected values.
Fresh constraint shape is measured from the generator's actual finalized CS;
prior AA dimensions are reference observations and are not an acceptance rule.
Source identity covers the full
relation and loader/request/output logic. The build identity includes exact
Cargo.toml/Cargo.lock, compiler version/target, profile, features and flags.
Selection-only manifest pins are explicitly excluded from this build-identity
preimage to keep the selection acyclic; their exact bytes are bound separately.

The source freeze and public setup report precede this manifest and must not
refer back to its hash. Setup report fields are public only: fresh D, VK, PK
length/hash, dimensions, timings and software/source provenance. It never emits
the private shape, shape hash, witness path or private statement metadata.

The selected cold client embeds these exact manifest bytes and their selected
SHA256, plus the exact VK328. No runtime manifest path, expected hash or alternate
VK can replace them. The wallet/network descriptor pins the same manifest SHA256
and requires its D/VK to match the selected native program. Fetch clients may
validate this public descriptor/manifest without opening the PK or backup.

The wallet's trusted software selection separately pins the final cold-client
executable hash. That client binary is built after parameter selection and binds
the manifest; putting its hash inside this manifest would create a cycle.
Mirrors deliver the public PK only. Whole-buffer length/SHA authentication and
checked extracted VK enforce parameter identity even if a mirror is malicious.

The manifest does not prove accepted ancestry, backing, toxic-waste destruction,
software safety, soundness or independent parameter availability. The selected
fresh setup remains a single-party research/testnet assumption.
