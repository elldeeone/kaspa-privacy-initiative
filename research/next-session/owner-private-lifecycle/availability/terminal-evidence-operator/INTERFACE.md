# Terminal public evidence metadata assembler

`kpi-prepare-terminal-evidence-01.py` is an outside-repository publication
operator. It performs metadata joins, not financial verification. The original
R2 assembler, 64-object snapshot, financial sources, proof parameters, rates and
wallet code remain unchanged.

## Root-selected input

The externally hashed JSON has exactly `schema`, `domain_hex32`,
`financial_profile_sha256`, `trial_id`, `files` and `cases`; schema is
`kpx8-root-terminal-evidence-inputs/v1`. Domain/profile are fixed by the code.
Each file row is exactly `{path,bytes,sha256}` with an absolute public path and
complete byte identity.

`files` has exactly ten roles:

- `handoff`: actual final 12-transaction/9-payout confirmed observer handoff.
- `sdk`: that final replay's exact `SDK-VERIFICATION.json`.
- `accounting`: reviewed neutral completed accounting, never detailed inputs.
- `terminal`: `closed_exits` aggregate `TERMINAL.json`, never individual scans.
- `outage`: exact `kpx8-observed-original-service-outage-aggregate/v1` receipt.
- `observed`: Root's actual 64-or-more release asset observations.
- `static`, `r2`: immutable initial inventories, hashes fixed by the helper.
- `top-selection`, `top-closure`: unchanged tiny complete-R2 recovery manifests,
  hashes fixed by the helper; these must be in the final audit/upload.

`cases` is exactly twelve rows in public chain order, each exactly
`{case,validation,metrics}` with file rows above. Select actual final replay
outputs `native-0000` through `native-0011`: `case.json`,
`native/native-validation.json`, `native/metrics.json`. No runtime tree search
or owner-specific candidate is accepted.

The handoff supplies the exact ten existing selectors and complete main and
post-query page enumeration. The assembler reads those selected public JSON
objects, validates source/profile/output joins and checks page metadata through
the existing Root guard. It does not open/decode/copy page payloads. New page
whole hashes and exact decoded bytes remain mandatory in Root's combined audit.

## Completion and publication checks

The helper requires actual terminal null head/current entry, zero reserve,
CM15/NF16, exactly GN3 + two mixed + nine exit cases, nine distinct payout
outpoints and exact original/final payout queries. It compares each entire
native case to the accepted RPC transaction/context using only the fixed pure
`replay.native_case` conversion. Version1 ID equality alone is insufficient:
proof witness, compute budget and populated context must also match.

All native Full/per-input results and metrics bind to the same case/order and
strict replay. Complete neutral accounting binds the actual final prefix,
all-in fees and frozen21-KAS denominator. The source aggregate terminal scan
accepts a public history path alias only when its whole history SHA matches the
final accepted history. The published aggregate omits that source path and all
client scan selectors/hashes/IDs.

The Root outage receipt uses its exact20-field allowlist and three source
receipt hashes. Same-host and administrative/retention limitations remain
explicit. Unknown owner/argv/client fields are rejected in closed schemas.

## Outputs and command

Only after every metadata check passes, a fresh output beneath the selected
public `assets` parent receives:

- `REPLAY-PACKET.json`: existing closed replay format; six explicit dynamic
  inputs, original relative page placements and exact terminal H/C hashes.
- `PAYOUTS.json`: public ledger outpoint/value/script/birth-DAA observations.
- `TERMINAL-AGGREGATE.json`: neutral three-scan/cohort/keys booleans and count.
- `INDEX.json`: whole-byte public evidence manifest, twelve chain-ordered cases
  and exact object placements/hashes/lengths/URLs; no owner association.
- `GZIP-AUDIT-MAP.json`: only new compressed-page payloads and their exact
  decoded audit hashes/lengths; no redundant decoded upload.
- `CANDIDATE-OBJECTS.json`: source pointers for finite Root audit/upload,
  explicit new-upload IDs, observed exact SHA+length reuse and required audits.

New-object URLs are deterministic declarations under the already observed
release; they are not availability evidence before Root observes actual upload
digests and the final HTTPS fetch passes. The manifest itself is one separately
hashed upload/fetch object selected by Root, avoiding a self-hash cycle.

```sh
python3 -B /var/tmp/kpi-prepare-terminal-evidence-01.py \
  --selection /public/root-selected-terminal-inputs.json \
  --selection-sha256 EXTERNALLY_SELECTED_SHA256 \
  --output /var/tmp/kpi-owner-private-lifecycle-01/assets/terminal-evidence-candidate-01
```

No actual candidate is generated before Exit09 and three fresh terminal seed
scans. No owner READY/restore/scan files, local bookkeeping, private order,
registry, raw argv or logs enter the packet. The reviewed replay bootstrap and
eight existing static verification objects are referenced explicitly; role PKs
are unnecessary for this read-only replay. The final transport separately pins
and fetches the whole manifest plus all referenced selected bytes.
