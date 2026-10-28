# Actual one-colluder fact producer

Source and public known-seed controls only. No actual private Original, local
record, truth, server view or payment workload was used during implementation.
The frozen privacy core and qualified launcher/network bytes are unchanged.

```text
python3 -B privacy_colluder.py
  --selection PUBLIC_PRODUCER_SELECTION --selection-sha256 SHA
  --round 1|2 [--execute]
```

Default validates public selections and returns a plan. `--execute` runs one
fixed owner1 role. Both actual rounds' public invoice/pay results and projections
must exist; derive each round's capsule before launching the observer.

Producer selection schema is `kpb-colluder-view-producer-selection/v1`, with
exact fields `schema`, `diagnostic_selection:{path,sha256}`, `source_members`.
The diagnostic selection is the trusted launcher selection documented in
`privacy_launch_API.md`, with the limitations in
`privacy_launch_REVIEW-2026-10-28.md`. Root still owns its exact provenance and
prospective execution selection.

Ordered source members are `{name,sha256}` for the finite `sources()` mapping:
the producer/controller, worker, qualified launcher, codec/observer, existing
private-worker/wallet/output-producer, owner-authority script and mature recipient
module. Node, crypto binary and installed JS leaf-map identities use the existing
admitted constants. Small public sources are frozen as readonly copies; existing
heavy runtimes and public JS assets are mounted readonly without duplication.
The worker rechecks all installed JS leaves inside its namespace.

The controller derives these private paths from the actual admitted trial and
actual selected owner1 pay operation, never caller-supplied truth paths:

```text
TRIAL/owner-1/BACKUP.json
TRIAL/operations/ACTUAL_PAY_LABEL/owner-1/OWNER-LOCAL-RECORD.json
TRIAL/operations/ACTUAL_PAY_LABEL/owner-1/COLLUDER-CONSTRAINTS.json
```

Only the first two private files enter the role. No truth, count, capsule,
honest owner, financial PK or corrupt-server view is mounted. The public actual
projection and all three actual trusted route sidecars are pinned. The existing
new KDF/backup parser and direct `NamespaceAuthority` are reused inside the
outer network-off namespace; there is no nested bwrap or host authority path.

The frozen `colluder_facts` adapter joins the colluder's actual input/two created
tuples, decrypts actual incoming CFs, verifies the receipt/CM/index schedule and
derives its known incoming creator from all three actual routes. It never reads
truth or an oracle result. The private0600 envelope binds method/run/trial/phase/
attempt, round and actual public context hash. No private identifiers, amounts,
tuple hashes or constraint records enter the public result.

Fixed producer state is
`TRIAL/owner-1/diagnostics/private-batch-colluder-round-R`. Exclusive file-and-
directory-fsynced `PRODUCING-CLOSED` precedes every private content read. The
worker creates the original private fact leaf in that fixed state. The
controller uses atomic Linux `renameat2(RENAME_NOREPLACE)` to route the same
inode into the exact pay directory, checks single-link0600 metadata and fsyncs
both directories. Existing destinations, symlinks and aliases refuse. The
controller never reads, copies or hashes the private body. No refused/interrupted
producer is reset or automatically repeated.

Public output derives from `BOOTSTRAP_PUBLIC/LABEL/privacy-diagnostics/
colluder-round-R`: `PUBLIC.json`, schema `kpb-colluder-view-produced/v1`, and
`LAUNCH.json`, schema `kpb-colluder-view-producer-result/v1`. Fields bind the
round/owner/common binding and confirm actual decryption/routes with fixed
no-export flags; they contain no creator correspondence. Detailed plans and
FD-only logs stay excluded. Missing producer output remains missing coverage
in the observer, never a complete-view privacy pass.

The public fixture generator uses deliberately published fixed seeds and real
selected sealed-box/EdDSA machinery to create new CFs. Its CV/proof bytes are
explicitly dummy: this is a receiving/decryption/routing control, not an Output
or financial proof. Production source has no fixture mode. Metadata controls
exercise atomic no-clobber, symlink/alias refusal and original-inode retention.
Complete raw server and terminal models remain UNQUALIFIED, and the unchanged
strict creator-swap counterexample remains valid.
