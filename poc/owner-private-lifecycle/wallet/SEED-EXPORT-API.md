# Literal seed export canary

Additive publication helper. The six selected financial runtime files, circuits,
parameters, backups and proof identities are unchanged.

The standalone worker reads exactly one original `BACKUP.json` leaf in its
closed namespace. It accepts only the four-field `kpx8-owner-seed-backup/v1`
record and this fixed domain. It performs no key derivation, receipt decryption,
map access, proving, RPC or networking. It never hashes the private file or
returns a seed, derived tag, owner ID or matched filename.

Before that one private read it authenticates every selected public candidate
against an externally hashed finite allowlist. It then scans literal raw seed32,
lowercase hex64 and uppercase hex64 across chunk boundaries. The decoded
selected relative paths and raw allowlist are also scanned. This is a literal
canary, not a claim about transformed secrets, general security or privacy.

## Launcher

```text
python3 -B run_export_seed.py
  --owner-leaf PRIVATE/local-01/party-0/owner/BACKUP.json
  --registered-trial local-01 --registered-trial live-01
  --public-root SELECTED_PUBLIC_ROOT
  --allowlist FILE --allowlist-sha256 EXTERNALLY_SELECTED_SHA
  --exclude-old-trial OLD_LOCAL --exclude-old-trial OLD_LIVE
  --exclude-new-private-parent /var/tmp/kpi-owner-private-lifecycle-01/private
  --exclude-new-private-parent EACH_OTHER_RETAINED_PRIVATE_PARENT
  --private-output PRIVATE/controller/FRESH_CANARY_RUN
  --output PUBLIC/FRESH_CANARY_RESULT [--execute]
```

Two explicitly registered trial labels select exactly six original leaves:
`PRIVATE/LABEL/party-{0,1,2}/owner/BACKUP.json`. All six are metadata-checked;
only the selected original is read inside the child. A nested/restored/dummy
backup is refused. The whole current private parent and every other retained
private parent/inode must be excluded before public reads. Private TLS symlinks
are not followed. The root supervisor is responsible for supplying the complete
retained-private exclusion list; connected observers have no invocation API.

The private staging directory contains authenticated public copies, operational
plan and raw logs. Only the count-only `PUBLIC.json` result appears in the
separate public output directory. The child has one original backup read-only,
public candidates and checker read-only, standard `/usr`/devices, empty temporary
storage and closed stdin. No original owner directory, attempts, MPC state,
foreign backups or host home is mounted.

The selected worker SHA is fixed by the launcher. The source freeze and six
public unsafe synthetic controls precede any actual audit. An actual scan is
not authorized by creating this helper; root must first select the exact finite
public manifest. The unchanged old compound-backup checker remains separate.

## Allowlist and result

Allowlist:

```json
{"schema":"kpx8-new-owner-seed-export-allowlist/v1","files":[
  {"path":"relative/public-file.bin","bytes":123,"sha256":"EXACT_PUBLIC_SHA256"}
]}
```

Result has only schema `kpx8-new-owner-seed-export-result/v1`, status `PASS|FAIL`,
candidate count/bytes, matched candidate count and the fixed scope
`LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF`. Counts include the
allowlist metadata candidate. Input, authentication or namespace errors refuse
with a generic message; they never become PASS. A completed FAIL blocks export.
