# Working-balance arithmetic comparison: public evidence

See the [result report](../../WORKING-BALANCE-PRIVACY.md),
[frozen specification](../../WORKING-BALANCE-PRIVACY-SPEC.md) and
[prefreeze review](../../WORKING-BALANCE-PRIVACY-REVIEW.md).

The experiment is offline arithmetic with idealized opaque labels. It creates
no native transactions or cryptographic proofs. Its results do not establish
real-user anonymity, native acceptance, backup recovery or security.

## Contents

- `freeze.json`: exact fresh source/spec/runtime identities and prospective
  observer matrix. The base commit is the pushed withdrawal investigation.
- `public-development-rehearsal-audit.json`: score-free complete-path check
  using a public development seed, before fresh sampling.
- `summary.json` and `completion.json`: full aggregate scores,
  accounting summaries, frozen decision outcomes and their completion binding.
- `public-evidence.tar.gz` and `manifest.json`: the exact
  allowlisted export, including all public inputs, observer predictions, seals,
  process/isolation receipts, source snapshots and aggregate scoring. Large
  logical files are individually gzip-compressed; the manifest records both
  stored and decoded sizes and SHA-256 values.
- `package-verification.json`: verified archive membership, stored/decoded
  hashes and a repeated semantic prediction-batch check on the decoded export.

The package contains 13,621 logical files (148,195,615 decoded bytes). The
outer archive is 24,880,496 bytes and its SHA-256 is
`05b3d80d080aa51ec48fed387caecd0197ca64efe141eb18dfa33af5830a5950`.

No seed, private truth, honest wallet records or backups are exported. Pooled
participant records are included because they were permitted observer inputs.
Public metadata retains hashes and filenames referring to excluded private
artifacts; these are not the private contents.

The outer archive preserves the export's physical file layout and manifest.
It uses sorted ordinary-file members with normalized metadata and no symlinks.
`SHA256SUMS` checks the package files. Do not interpret storage
hash verification as a standalone semantic audit of prediction seals.

## Re-audit boundary

The frozen export command validates the complete prediction batch before
writing the public package. `verify_export()` checks the complete expected
logical roster and stored/decoded bytes. To repeat the public semantic check,
unpack the archive into a new directory, decode each logical file according to
the manifest into another new directory, then call the exported runner's
`verify_batch(logical_root, generation)` with its exported `generation.json`.
This requires no seed or truth. The later aggregate audit additionally checks
score arithmetic and gates; it does not recompute accuracy against hidden
per-payment truth. See the [aggregate audit receipt](../../artifacts/working-balance-result-audit-20261021.json).

The private attempt and original public export are retained outside Git under
`/home/luke/kpi-private/working-balance-privacy-20261021-01` and the sibling
`working-balance-privacy-20261021-01-public-export`. They are local operator
paths, not independent public attestations. Earlier experiments are unchanged.
