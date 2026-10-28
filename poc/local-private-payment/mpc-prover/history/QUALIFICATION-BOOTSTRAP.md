# Fixed unfunded qualification bootstrap

This standalone setup tool creates **unregistered qualification journals** for
the first fixed, nonexistent-head functional proof. It is not a service epoch
registration, accepted head, funding operation or settlement authority. The
actual prospective pool's registered history is never an output of this tool.

Run once from the trusted host controller, before starting the three roles:

```sh
python3 poc/local-private-payment/mpc-prover/history/qualification_bootstrap.py \
  --output /absolute/new/qualification-control-01 \
  --server-certificate-sha256 <party-0-public-certificate-SHA256> \
  --server-certificate-sha256 <party-1-public-certificate-SHA256> \
  --server-certificate-sha256 <party-2-public-certificate-SHA256>
```

Only three distinct canonical nonzero public certificate digests and a fresh
output path are arguments. There are no pool, domain, head, registered/live,
reset, overwrite, accepted or settlement flags. Certificate files, private keys,
owner records, Originals and raw MPC logs are not read.

The fixed pins are:

| Field | Value |
| --- | --- |
| Scope | `PUBLIC_UNFUNDED_UNREGISTERED_QUALIFICATION_ONLY` |
| Fixture context SHA256 | `6efa0e97ae8868b12743d72d45dcd46e858214e3413a1c63c1dee1ab56aacdc0` |
| Public head SHA256 | `910c09f5ea30ece29b36b1d0428a7c04c10e3b2e7f6ab65457c248b45c6cddf9` |
| Placeholder outpoint | `255798360cfa4d4c6b51b7a2f2443d1668a7e5f87cd45d01c4d683bcd76b26e8:0` |
| Prospective pool | `d68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf` |
| Reserve | `6000000000` integer sompi, supplied context only |

D, ProfileID and service policy stay fixed to the existing descriptor. The
history epoch is a separate, intrinsically unregistered qualification identity;
the live/base service epoch remains unchanged.
The initializer reconstructs the canonical 276-byte context from those fixed
IDs, State112, point and reserve, and checks the context SHA before creating a
directory. The head digest is a pinned source identity; this helper does not
acquire or authenticate a real chain head.

The wrapper rejects either direction of output/build path overlap with
unchanged guard09's private directory exclusions before creating directories.
It admits its public source and compiler with unchanged guard09,
snapshots the four source files, and builds only `epoch_journal.cpp` plus
`qualification_init.cpp` with `KPI_HISTORY_UNFUNDED_SETUP`. It does not include
`epoch_ticket.hpp`; that header rejects this setup flag. The source/tool build
selection hash is compiled into the initializer. Compiler and initializer run
in separate network-disabled namespaces. The initializer sees its executable
readonly and an empty output parent; the build directory is a separate sibling
and has no writable alias in that namespace.

Outputs:

```text
OUTPUT/BUILD-SELECTION.json
OUTPUT/BOOTSTRAP.json
OUTPUT/qualification/REGISTRATION.json
OUTPUT/qualification/party-0/journal/journal.bin
OUTPUT/qualification/party-0/anchor/latest.bin
OUTPUT/qualification/party-0/role.spec
OUTPUT/qualification/party-1/{journal,anchor}/...
OUTPUT/qualification/party-2/{journal,anchor}/...
OUTPUT-build/{source,objects,BUILD-SELECTION.json,compile.*,initialize.*}
```

`REGISTRATION.json` is an exclusively created, synchronized, mode-0400 file.
Its `registration` object includes the fixed scope and context, public random
nonce, complete epoch key and certificate roster, exact role paths, source/tool
selection and actual initializer executable hash. It always records
`registered_financial_service:false`.

The qualification history epoch is:

```text
SHA256(ASCII("KPBH/UNREGISTERED-QUALIFICATION/EPOCH/v1") || 00
       || encode(BASE EpochKey, including ordered three certificate digests)
       || fixture_context_SHA32 || fixture_head_SHA32 || public_nonce32)
```

`encode` is the journal's canonical `KPBHKEY1` encoding. BASE uses the unchanged
service epoch `1719a11d82194639da551cd7302ad3ea94e42a0e424962ac40719f5634d38b94`.
The derived epoch must be nonzero and differ from BASE. The registration includes
both identities, the exact qualification root and all three role paths.

The journal registration digest is:

```text
SHA256(ASCII("KPBH/UNREGISTERED-QUALIFICATION/REGISTRATION/v2") || 00
       || UTF8(sorted compact JSON of the registration object, no newline))
```

The outer file adds `registration_sha256` and the shared
`initial_checkpoint_hex32`. All three stores start Ready at sequence zero with
that same checkpoint; journals and anchors remain mode 0600 inside mode-0700
directories. File and directory synchronization precedes success output. The
wrapper independently recomputes the registration commitment and checks the
actual source/tool/binary identities before emitting `BOOTSTRAP.json`.

Each party also receives an exclusively created mode-0400 `role.spec`. Its text
format is `KPBQROLE2` followed by lexicographically sorted `key<TAB>value` lines,
then `END`, with one final newline. Values may contain spaces; they contain no
TAB, CR or newline. Its exact fields are:

```text
base_service_epoch_hex32
chain_hex32
component_profile_sha256
domain_hex32
epoch_hex32
fixture_context_sha256
fixture_head_sha256
initial_checkpoint_hex32
initializer_executable_sha256
immutable_tail_sha256
local_directory
native_parameters_sha256
old_reserve_sompi
old_script_public_key_hex37
old_state_hex112
outer_image_hex32
party_id
placeholder_outpoint_hex36
pool_hex32
profile_hex32
qualification_root
registered_financial_service
registration_file
registration_file_sha256
registration_nonce_hex32
registration_sha256
scope
server_certificate_sha256_0
server_certificate_sha256_1
server_certificate_sha256_2
service_hex32
source_build_selection_sha256
trusted_anchor_directory
```

Native parameters, immutable tail, image and old SPK are hard-pinned to the
parent-admitted emission for this exact public fixture. There is no late script
or policy argument. Bootstrap stdout supplies all three role-spec file paths
and SHA256 digests. A gate must select that exact file digest before parsing,
use `qualification::admit_role_spec(bytes, expected_party)` from the shared pure
public `qualification_descriptor.hpp`. The helper rejects missing, duplicate,
extra or changed fields by regenerating the full spec, derived epoch and
registration. Its returned `Role.descriptor` exposes `key`, `registration_digest`,
`initial_checkpoint`, `context_bytes`, `registration_file`,
`registration_file_bytes` and `registration_file_sha256`; `Role` also exposes
`party_id`, `local_directory` and `trusted_anchor_directory`. The gate must read
the actual registration file and require exact equality to the regenerated
`registration_file_bytes` before calling only
`EpochJournal::open_existing(local, anchor, key, registration)`. Thus relabelling
a live Ready journal fails its intrinsic header identity. The actual
three-party lock/ticket agreement is separate; these local files alone authorize
no intake or proof.

The qualification driver must pin the exact generated registration file SHA,
fixed context/head and role paths before intake. It may then call
`EpochJournal::open_existing` and the actual lock/ticket protocol. It must not
call setup from a proof server, replace a missing store, accept arbitrary
coordinator-chosen stores, or use this unregistered document in live mode.
Every live role opens its independently registered persistent store from its
frozen trusted server configuration. No Boolean in this JSON grants that
authority. An unresolved offline qualification attempt stays unresolved.

Existing output/build roots, duplicate/noncanonical certificates and unknown
flags refuse. Partial failures are retained; the helper performs no cleanup,
truncate, retry, reset, MPC execution, network request, funding or broadcast.

The earlier controls-01 through controls-03 and their `KPBQROLE1` artifacts are
retained, superseded evidence. They used the base history epoch and must never
be used for qualification intake or live operation. Version 2 admission refuses
those files; this correction does not reset or change any live service store.
