# Public recovery closure for the integrated lifecycle

This additive adapter uses the unchanged, SHA-selected
`poc/four-wallet-storage/restore.py` and its pinned HTTPS transport. It binds a
declared lifecycle dependency graph to an externally selected financial-profile
hash. It imports only authenticated local bootstrap code; downloaded software,
parameters and history remain opaque public bytes.

The `owner-private-lifecycle-public-closure/v1` manifest has exactly:

- `domain_hex32`, `profile_reference_sha256`, `transport_selection_sha256`;
- `required_roles`, mapping every role in `closure.REQUIRED_ROLES` to a selected
  public asset ID;
- `dependencies`, mapping every selected ID to its declared child IDs;
- `schema`.

The separately selected transport manifest retains schema
`four-wallet-public-recovery-selection/v1`; there is no financial dependency on
that older profile. Its profile hash must match this closure. Every object must
be reachable from a required role, every declared dependency must exist, and
cycles and duplicate edges are rejected. The role set names software and its
inventory, native policy, Spend/Output/Exit parameter manifests and complete
keys, founding descriptor, accepted-history index and checkpoint. Different
roles may select identical bytes when the reviewed profile actually shares an
asset. All required history pages/runtime members must be declared dependencies.

**An externally reviewed dependency declaration is still necessary.** Graph
validation cannot discover omitted imports or prove that a caller assigned a
role to the right program. Root must select the profile, exact whole objects,
member inventories, history coverage and complete public upload allowlist.
The closure and its SHA must come from that independent selection, rather than
from the replica whose bytes are being authenticated. The profile role is
explicitly checked against `profile_reference_sha256`.

```sh
python3 -B poc/owner-private-lifecycle/recovery/closure.py \
  --closure /public/reviewed-closure.json \
  --closure-sha256 EXTERNALLY_SELECTED_SHA256 \
  --selection /public/reviewed-transport-selection.json \
  --exclude-provider original-issuer \
  --deny-host original-issuer.example \
  --output /outside-git/fresh-public-restore
```

At least one issuer must be excluded, and **all** hosts allowed for every
excluded provider must be denied, including redirects. The existing transport
authenticates complete lengths/SHA256, canonical regular files and final
single-link objects. The adapter reauthenticates restored whole objects before
writing mode0400 `HANDOFF.json`. Its stdout also returns that handoff's SHA256.
No payload is imported, executed, unarchived or used to prove.

Only `DECLARED_CLOSURE_RESTORED` supplies role paths. An incomplete object set
returns no role mapping for a wallet to consume. Neither result establishes
current chain acceptance, trusted setup, spend readiness, independent
administration or durable retention. A new owner worker must authenticate its
runtime and complete parameter artifacts before seed access, replay accepted
history, reconcile current native state and then scan/prove locally. Original
coordinator/prover unavailability and fresh replacement execution require their
own recorded runtime evidence.

Run the public, synthetic controls with:

```sh
python3 -B poc/owner-private-lifecycle/recovery/test_closure.py
```

Those controls exercise declared dependency coverage, wrong pins/profile,
missing/changed keys, issuer exclusion and incomplete handoffs. They use no
network, real proving key, accepted chain data, wallet backup or private map.

## Minimal replacement-client namespace

`run_restore.py` stages only the six externally selected bootstrap files in
`SOURCE_PATHS`, the public closure/selection and its own fixed entry script.
The bootstrap inventory schema is
`owner-private-lifecycle-recovery-bootstrap/v1`, with `files` entries containing
exact `path`, integer `bytes` and `sha256`. Its digest is independently supplied.
Every host-side selected file is checked against declared private directories
and their metadata-only inode history before reading. Callers must declare all
private parents, including old trials and prior attempt/controller directories.

The child has read-only OS/TLS dependencies and bootstrap inputs, plus one fresh
output directory. It has no original home, repository, cache, private owner
directory, original parameter path or inherited stdin. An absence receipt is
written before transport begins. Real mode uses the pinned HTTPS transport;
`--synthetic-fixture` instead stages exact selected public fixture objects and
disables network access. Neither mode executes restored programs or opens keys.

```sh
python3 -B poc/owner-private-lifecycle/recovery/run_restore.py \
  --bootstrap-inventory /public/reviewed-bootstrap.json \
  --bootstrap-inventory-sha256 EXTERNALLY_SELECTED_SHA256 \
  --closure /public/reviewed-closure.json \
  --closure-sha256 EXTERNALLY_SELECTED_SHA256 \
  --selection /public/reviewed-transport-selection.json \
  --exclude-private-directory /outside/all-declared-private-parents \
  --exclude-provider original-issuer --deny-host original-issuer.example \
  --absent-original-path /outside/original-proving-keys \
  --output /outside-git/fresh-public-restore-run
```

This is another process on the same trusted host. An off-host public provider
adds a retrieval failure domain, not an independent administrator. Retain exact
executed source/inputs and select only reviewed public receipts for publication;
do not blindly collect runtime trees, controller selectors or logs.

## Independent destination remains an external gate

The existing issuer GitHub release and this workstation share administrative
control. A personal Drive copy is another service but does not supply a second
administrator or retention agreement. Metadata discovery must identify an
actual project destination, its separate operator/access and retention evidence
before any independent-storage claim. Do not repurpose unrelated shared
folders or upload private owner/controller artifacts. Publication waits for
root's exact public-byte audit.
