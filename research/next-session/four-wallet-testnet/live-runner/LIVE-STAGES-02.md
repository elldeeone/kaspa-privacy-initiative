# Live stage recipe: closed bootstrap and fresh software union

This additive reviewable source execution map replaces the software-selection
and bootstrap-wrapper gaps in `LIVE-STAGES-01.md`. Frozen recipe01 remains
unchanged at SHA256
`6a4ac455e9a379a235f73991e5c9f5f42147dac57714a7738e386a4c8569c7f4`.
This document records available source and exact CLI joins. Source review and
the parent's execution release remain pending; it claims no funded readiness,
genuine proof, accepted pool balance, broadcast or confirmed payout.

## 1. Select a fresh complete software tree

Keep the existing8496 software tree and old publication packets immutable.
Root must pack a **fresh** finite software union after source review:

- The selected base/combined runtime and fixed SDK3 retain their exact bytes.
- Add the eight explicitly inventoried bootstrap source members:62,834 bytes,
  additions inventory SHA256
  `4a1b10a79a4846b678fa61a9c36eee640efe134ce5eb44c72d50fbec3f7cd9d5`.
- Add these four separately selected host helper sources if invoked from the
  immutable tree: `poc/four-wallet-live/outer_accepted.py`,
  `funding_descriptor.py`, `stages.py` and `prepare_runtime.py`.

The union must retain required accepted-owner/finalizer source closure and
fixed runtime/SDK members. Resolve only exact selected duplicate paths; do not
silently replace a mismatching member. Enumerate and metadata-check all finite
members against both complete LOCAL/LIVE owner namespaces before copying any
member. No recursive private-directory discovery or source execution is needed
to pack it. Root supplies the resulting external inventory digest. The old
tree and inventories remain physically unchanged.

Every later `$TREE`, `$INV` and `$INV_SHA` below means that **new reviewed
union**, not the old8496 tree. Define private controller conveniences:

```sh
LIVE_FIXED="$TREE/runtime-source/poc/four-wallet-live"
BOOT_FIXED="$TREE/runtime-source/poc/four-wallet-bootstrap"
PROFILE=(--financial-profile "$FP" --financial-sha256 "$FP_SHA")
BPROFILE=(--profile "$FP" --profile-sha256 "$FP_SHA")
SOFTWARE=(--software-root "$TREE" --inventory "$INV" --inventory-sha256 "$INV_SHA")
EXCLUDE=(--exclude-trial-directory "$LOCAL_ROOT" --exclude-trial-directory "$LIVE_ROOT")
```

Source paths, selected digests, original backup handles and role-to-controller
mappings remain in the private controller outside Git. Keep `umask077`, no
shell tracing, and no publication of raw argv/private plans or logs. Refresh
`PROFILE`, `CHAIN` and `OBS` arrays when their values change. Public JSON never
supplies a command, executable, callback or software authority.

## 2. Use the available closed prepare/sign/combine wrappers

The public entry wrapper source is
`poc/four-wallet-bootstrap/run_closed_entry.py`, SHA256
`19aa2bc6cc6937e565c4d112ac06b170e7b212faae2cdd803ac38402f8e24397`.
It stages exact public inputs and fixed software/SDK into a closed network-off
namespace with **zero backups**. The historical SDK pathname resolves only to
selected copied SDK3 bytes. Prepare with the LIVE constructor's pinned A/C
public exports and actual ordinary funding source contexts:

```sh
python3 -B "$BOOT_FIXED/run_closed_entry.py" prepare \
  --software-root "$TREE" "${BPROFILE[@]}" --trial-id "$TRIAL_ID" \
  --owners "$PUBLIC_A" "$PUBLIC_C" --owners-sha256 "$PUBLIC_A_SHA" "$PUBLIC_C_SHA" \
  --sources "$SOURCES" --sources-sha256 "$SOURCES_SHA" \
  "${EXCLUDE[@]}" --output "$ENTRY_PREP" --execute
```

The result is `$ENTRY_PREP/client/run/proposed-case.json`, not a source UTXO
or an accepted transaction. Select its actual guarded whole-file digest.
Amounts remain integer sompi and contexts use the actual observed DAA.

The signer wrapper source is
`poc/four-wallet-bootstrap/run_closed_signer.py`, SHA256
`00d893e23d9c300b5afb86850346cc3a545000148be3567266f5948aa9b88f9c`.
It metadata-excludes all eight original backups and complete owner directories
from public ingress. The host never opens, hashes or copies an original backup.
Only the selected owner's original backup is mounted read-only inside its
closed worker. Its original public record comes from the separately pinned
constructor export; the original owner directory is never reopened for public
`owner-init.json` bytes.

Run separately for A and C, with no other owner's backup mounted:

```sh
python3 -B "$BOOT_FIXED/run_closed_signer.py" \
  --software-root "$TREE" --backup "$ONE_ORIGINAL_BACKUP" --role "$ROLE" \
  --owner-public "$ONE_PUBLIC_OWNER" --owner-public-sha256 "$ONE_PUBLIC_OWNER_SHA" \
  "${BPROFILE[@]}" --case "$PROPOSED_CASE" --case-sha256 "$PROPOSED_CASE_SHA" \
  --trial-id "$TRIAL_ID" "${EXCLUDE[@]}" --output "$ONE_SIGNER_OUT" --execute
```

Each output is `$ONE_SIGNER_OUT/client/run/APPROVAL.json`. The two approvals
are public signature exports; neither carries a private backup or proving key.
Combine only those exact pinned exports:

```sh
python3 -B "$BOOT_FIXED/run_closed_entry.py" combine \
  --software-root "$TREE" "${BPROFILE[@]}" --trial-id "$TRIAL_ID" \
  --case "$PROPOSED_CASE" --case-sha256 "$PROPOSED_CASE_SHA" \
  --approvals "$APPROVAL_A" "$APPROVAL_C" \
  --approvals-sha256 "$APPROVAL_A_SHA" "$APPROVAL_C_SHA" \
  "${EXCLUDE[@]}" --output "$ENTRY_COMBINED" --execute
```

The result is `$ENTRY_COMBINED/client/run/selected-case.json`. The fixed
reference fee rate is100. Both wrappers **stage only by default**; without
`--execute`, no ordinary approval or SDK/Native result was produced. A staged
plan or local NativeFull result never establishes chain acceptance.

## 3. Continue the same fresh LIVE lifecycle

Use the descriptor builder, `outer_accepted.py quote-payment`, `stages.py`
request/prefix/bundle operations, and `outer_accepted.py prepare` from the
new immutable `$LIVE_FIXED` tree. Continue recipe01's accepted-owner, fresh
outer R0 and accepted-finalizer/ledger sequence with their separately selected
exact sources. Do not substitute a LOCAL history, trial, sizing credit,
projection/journal, receipt or proof.

Before a frozen runner/submit reads public data, `copy-public` must have staged
every selected ordinary public input against all eight original backup/whole
directory exclusions. Retained fetch pages use the dedicated layout-preserving
operation:

```sh
python3 -B "$LIVE_FIXED/stages.py" bundle "${EXCLUDE[@]}" \
  --fetch "$RAW_FETCH" --fetch-sha256 "$RAW_FETCH_SHA" \
  --bundle-directory "$RAW_BUNDLE" --output "$STAGED_BUNDLE"
```

This operation reads only pinned fetch metadata, checks all base/post-query
page paths/inodes before the first page read, then copies each stable selected
SHA/length page mode0400 under its original relative path. It also copies the
unchanged fetch bytes mode0400. It does not decompress pages, execute SDK,
Native or replay, or establish currentness. Four public synthetic controls,
including a late post-query alias to the eighth sentinel, passed for the
helper; these are not fabricated accepted-chain pages or a live trial.

Set `$FETCH="$STAGED_BUNDLE/fetch.json"`, `$FETCH_SHA="$RAW_FETCH_SHA"` and
`$BUNDLE="$STAGED_BUNDLE"`, then rebuild `OBS`. Frozen execution paths are:

```sh
python3 -B "$LIVE_FIXED/runner.py" fetch ...
python3 -B "$LIVE_FIXED/runner.py" reconcile ...
"$NODE" --use-openssl-ca "$LIVE_FIXED/submit.mjs" ... --execute
```

The ellipses mean the complete closed argument lists in recipe01, never an
executable or argument callback supplied by public JSON. Accepted preparation
adapters independently stage all retained pages; owner workers receive all
eight explicit file and eight whole-directory exclusion flags. Every genuine
proof preparation still requires whole-PK/VK READY before reading its own
original backup, and B/D pending receipt checks still precede outer GPU work.

An immutable send intent permits one RPC attempt. Unknown response/crash means
fresh read-only acquisition and reconciliation, never another broadcast or
intent deletion. Valid accepted same-ID budget/witness variants must pass the
actual complete-byte/native/financial pipeline without changing the intent.
Four independent cold exits must advance the actual accepted physical head
serially, confirm four payouts, leave reserve0 and pass all four final backup
recoveries plus the accepted rich integer fee ledger. Until that same-trial
terminal path succeeds, no complete funded rehearsal or readiness is claimed.
