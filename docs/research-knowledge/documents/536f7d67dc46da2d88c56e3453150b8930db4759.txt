# Literal new-owner seed export canary

Separate additive source; selected financial and scoring workers are unchanged.
This checks only literal raw seed32, lower/upper hex seed64, and those literal
forms in decoded selected filenames. It does not derive keys, decrypt CFs,
inspect witnesses/maps, certify privacy/security, or replace the old8 checker.

```text
python3 -B run_export_seed.py
  --owner-leaf ORIGINAL_PARTY/owner/OWNER.json
  --public-root SELECTED_PUBLIC_ROOT
  --allowlist FILE --allowlist-sha256 EXTERNALLY_SELECTED_SHA
  --exclude-old-trial OLD_LOCAL --exclude-old-trial OLD_LIVE
  --exclude-new-private-parent PARTY0
  --exclude-new-private-parent PARTY1
  --exclude-new-private-parent PARTY2
  --exclude-new-private-parent EACH_OTHER_PRIVATE_PARTY_OR_CONTROLLER_PARENT
  --output FRESH_PRIVATE_CONTROLLER_JOB [--execute]
```

The first three private parent selectors are disjoint party directories for
the reused guard. Include ALL other new private parents across every world,
plus private controllers. The trusted supervisor, not an observer, supplies
this complete list and exact external public allowlist selection. Metadata-only
lstat/no-follow traversal records regular-file inodes without opening private
files; private TLS symlinks are never followed. All public source/allowlist/file
paths are checked against old8 plus ALL new private directories/inodes before
their content is read or hashed. Only exact `<selected parent>/owner/OWNER.json`
is accepted: nested dummy owner files cannot substitute for the original.

The allowlist has exact schema:

```json
{"schema":"kpx7-new-owner-seed-export-allowlist/v1","files":[
  {"path":"relative/public-file.json","bytes":123,"sha256":"EXACT_PUBLIC_BYTES_SHA"}
]}
```

Each relative path is canonical, unique and beneath `--public-root`. The list
is finite, externally hashed and fixed before the actual scan. The launcher
copies only authenticated public candidates and a fixed standalone checker.
Its clean namespace receives ONE original OWNER.json file read-only, those
public copies and public allowlist, `/usr`/standard devices and empty temporary
storage. No original owner directory, attempts, TRUTH, MPC, map, capsule, private
count, PK or network is mounted; stdin is closed. Default stages only.

Inside the worker, all selected public file hashes/sizes are checked before
the single private content read. The exact six-field known owner schema is
parsed to obtain its seed; the owner file is never hashed. Only that one seed
is read. Candidate files are scanned with overlap across chunk boundaries.
The public allowlist and decoded relative paths are also scanned as one extra
candidate, so filenames cannot evade the literal check.

The sole successful-job output is `FRESH_JOB/public/PUBLIC.json`, with exact
fields `schema` (`kpx7-new-owner-seed-export-result/v1`), `status` (`PASS|FAIL`),
`candidate_count`, `candidate_bytes`, `matched_candidate_count`, `scope`
(`LITERAL_SEED_CANARY_ONLY_NOT_SECURITY_OR_PRIVACY_PROOF`). Counts include the
allowlist metadata candidate as well as its listed files. Output contains no
seed/key, owner-file hash, owner-derived tag, owner ID or matched file location.
Input/namespace failures produce a generic refusal, never a PASS. A completed
FAIL blocks publication. Raw operational plans/logs remain private.

The trusted supervisor authorizes only this selected finite publication job;
there is no observer request interface or additional private query. Source and
synthetic controls plus peer review precede any actual owner seed scan. All
tests use explicitly public unsafe seed sentinels in temporary directories.
