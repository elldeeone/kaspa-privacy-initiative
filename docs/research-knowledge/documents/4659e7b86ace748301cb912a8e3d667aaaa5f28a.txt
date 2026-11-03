# Finite terminal audit recipe

`prepare_terminal_audit.py` fills the missing selector/materialization seam. It
adds no worker, network path, proof verifier, lock, daemon or Original cache.
The financial caller and reviewed producer/controller/large/prepared/private
workers remain unchanged. No actual terminal or Original operation follows
from the source controls.

The three operations are explicit: **selectors → packet → plan**. Selectors and
plan read public metadata only. Packet runs the existing fbc whole-page producer
and therefore performs bulk public archive/gzip I/O; use it only after actual
terminal accounting and the finite public publication scope/docs are frozen.
The output plan still requires Root's separate concrete release before the
existing controller's `--execute` can use any Original.

## Root request

Pin a LOCAL, unpublished JSON request with exactly these fields:

```text
schema = kpxa-terminal-public-audit-bridge-request/v1
domain_hex32 = b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c
roles = all twelve role names -> {source, path, bytes, sha256, kind}
additional_data_files = [{source, path, bytes, sha256, kind}]
publication_candidate = {path: ABS, sha256: HEX64}
publication_paths = [exact selected candidate-relative path, ...]
prior_public_files = [{source, path, bytes, sha256}]
creation_template = {path: ABS, sha256: HEX64}
canary_assets = {source: ABS, bytes: INTEGER, sha256: HEX64}
originals = [nine exact LOCAL metadata/policy routes]
decoded_budget_bytes = generous positive integer
run_label = fresh neutral [a-z0-9-]{1,20}
```

The twelve roles are `terminalhandoff,activation,history,context,currententry,
replayresults,fetch,selection,descriptor,assets,parameters,accounting`. The
fetch role's packet path is exactly `chain/fetch.json`. Each kind is
`public-metadata`, `public-source` or `public-evidence`. Supply all nineteen
native CASE files named by the selected final accounting report as explicit
`public-evidence` rows in `additional_data_files`, plus the separately reviewed
finite replay/runtime/evidence closure. The bridge checks all nineteen CASE
source/SHA joins; it neither reconstructs CASEs nor crawls a directory.

Both fetch page arrays are expanded automatically into `full-source-page`
rows beneath `chain/`, preserving every original relative page path, compressed
length and SHA. These are metadata operations; packet later authenticates every
selected compressed/decoded byte. Explicit additional page rows are refused.

The source candidate is the current externally selected finite candidate (the
schema remains `kpxa-second-source-candidate/v1` across revisions). Only
`publication_paths` are selected. There is no automatic optional/recommended
policy. Selected source rows enter BASE under `publication/<candidate path>`;
explicit prior public assets keep their supplied relative candidate paths.
The reviewed producer's path policy remains exact: a source filename ending
`.pk`, raw log or known local/private prefix is refused. Keep Root's existing
exact three setup-PK provenance exemptions; do not copy/rename a 591MB key to
work around this filter or silently add raw PKs to BASE. Those exact unchanged
PK bytes are provenance-exempt, not canary-scanned. The bridge rejects all
three known SHA256 identities regardless of alias or declared length in raw
rows, decoded-page selectors and prepared GLOBAL candidates, and raw
logical candidate targets ending `.pk`, before producer I/O. This is a precise
metadata scope guard, not generic binary-content inspection. The selected finite scanned
union and those exemptions must remain separate in final claims.

The existing exemption evidence is `recovery-release/PK-WHOLE-BYTES-VERIFIED-01.json`
SHA3a82e7d0f014b373d6d4fff10b389c63d342c89c48bfac98a5409f20d46eb301
and `review/PUBLICATION-SOURCE-REVIEW-01.md`
SHA7339664c630da4fda10cc68e32383155cf20a836ba8d7522a2eb013b06a6684f
under `research/next-session/local-private-payment/`. The exception is limited
to the selected exact Spend/Output/Exit PKs in selection713554; it grants no
canary coverage or exemption for changed, external or later keys.

## Existing context reuse

The old public 17-mount release is:

```text
/var/tmp/kpi-local-private-payment-01/publication-release/final-code-software-01/AUDIT-RELEASE.json
SHA256 7e4a9101173f0d0e0e0ad1ec858a5f00d60b30d7f0c4076bcdbf035e423c4ece
```

It supplies one reviewed NONCHAIN creation H/C containing all nine genuine
creation outputs and no transitions; it is suitable for the six older Originals.
The three actual02 Originals use the terminal H/C instead. The bridge retains
fourteen non-H/C/scope source rows, then adds twelve selected original role
mounts and the new actual02 scope. The actual template has 27 mounts; the
creation template stays unchanged at 17. Existing c465 metadata/pin/terminal
checks are reused before either template is considered prepared.

The worker portable asset manifest is separately selected:

```text
/var/tmp/kpi-local-private-payment-01/recovery-release/software-02/unpacked/WALLET-ASSETS.json
16725 bytes
SHA256 df7ec243515d19e18a3ff3d9196d0c83b969a3a56255e47773d97de20b6f1e50
```

Its relocated `/public` paths differ from the original dataset role.assets.
Every original role (including original assets) binds the Root twelve-role
selection. Portable assets are an explicit separate pin shared by all actual02
checks and positives; no byte equality or normalization is silently assumed.

Every LOCAL route is exactly `{original_id,cohort,path,device,inode,bytes,
ctime_ns,expected_second_kind}`. IDs are neutral `O01`-style labels; there are
nine distinct paths/dev+inode pairs, six `creation` and three `actual02` routes.
The actual02 policy distribution is exactly two `received` and one `change`;
creation routes use null policy. Root supplies current `ctime_ns` from its
metadata-only release check. The existing nine-original snapshot's
`path/dev/inode/size` fields alone are deliberately insufficient. The bridge
never stats, reads, hashes, copies or discovers an Original or private plan.

## Commands after actual terminal freeze

Use absolute paths and the exact external SHA selectors at every step:

```text
python3 -B prepare_terminal_audit.py selectors \
  --request ROOT_REQUEST --request-sha256 ROOT_REQUEST_SHA \
  --output FRESH_SELECTORS

python3 -B prepare_terminal_audit.py packet \
  --recipe FRESH_SELECTORS/LOCAL-RECIPE.json --recipe-sha256 RECIPE_SHA \
  --output FRESH_PACKET

python3 -B prepare_terminal_audit.py plan \
  --recipe FRESH_SELECTORS/LOCAL-RECIPE.json --recipe-sha256 RECIPE_SHA \
  --preparation FRESH_PACKET/LOCAL-COMPLETE-PREPARATION.json \
  --preparation-sha256 COMPLETE_PREPARATION_SHA --output FRESH_PLAN
```

Selectors and plan outputs are fresh direct children of the established public
`publication-release` or `publication-audits` parents. Packet uses the existing
producer's exact output policy. The exact tmpfs parent for decoded batches is
`/dev/shm/kpi-local-private-payment-publication-01`, owned by the operator,
mode0700, with no symlink ancestors. No operation runs the audit controller.

The plan operation requires the **complete** fbc API result, not just its
nested `base_verification` marker. It checks the archive/index/plan/count joins,
then calls frozen0d972 `load_plan` only. Recipe reuse rechecks the original Root
request, source code, exact dataset/page union, publication candidate subset,
metadata routes/policy/assets, and unchanged static context source closure.
Before packet or plan, it reruns the same terminal metadata, twelve-role scope,
accounting identity and nineteen-CASE coverage joins; a manually authored pinned
recipe cannot skip the selectors operation's checks. These are metadata joins,
not a VM reexecution or a public PASS marker used as financial authority.

Root then selects the concrete `LOCAL-EXECUTION-PLAN.json` and uses the existing
controller as documented in `PUBLICATION-BATCH-AUDIT.md`. Primary completion
stops before supplemental DESCRIPTORS/positives. Root externally selects the
mandatory-plus-explicit-extra metadata release to resume. No primary jobs are
rerun solely to create that selection.

## Resource and publication boundary

Workers retain their u64 byte counts and chunked scans; there is no 2GiB worker
cap. A large rawA still requires whole-file guard admission in memory and uses
trusted-host direct read-only views, not sealed storage. The fbc producer
verifies/discards all decoded pages first and materializes one serial whole-page
batch at a time. Choose the budget from actual largest-page size, available
RAM/tmpfs, source/small staging and generous headroom, after GPU work ends.
Decoded total may exceed tmpfs; simultaneous decoded retention need not.

For rawA at or above the release asset limit, use the already reviewed separate
splitter/transport recipe. Preserve the exact wholeA scan and part extent/SHA
reconstruction. Include `DATA-PARTS.json` and any newly public metadata in the
Root-selected supplemental DESCRIPTORS release. Multipart transport introduces
no replacement for full raw or decoded-page coverage.

All `LOCAL-*` recipes, scopes, requests, templates, complete API receipts and
execution plans remain unpublished operator artifacts. Publication covers only
the explicit final candidate union and supplemental metadata. The bridge
performs metadata consistency and byte-selection work, not chain/native
validation, general privacy proof, malicious-host protection or off-host proof.
