# Price-baseline experiment evidence — 2026-10-22

The [completed report](../../PRICE-LEAKAGE.md) explains the result and limits.
The original score is unchanged: 512 ledgers, 1,024 observer jobs and 18,192
eligible payments. Both independent recounts passed; privacy is unqualified.

- `evaluation-public-evidence.tar.gz` contains the complete verified export:
  8,225 allowlisted files plus its manifest, under `evaluation/`.
- `export-manifest.json` records each original logical file's SHA-256/length and
  its stored identity/gzip SHA-256/length. Decode each file using its `encoding`.
  The archive preserves those stored bytes; it does not alter prediction seals.
- `result.json` is the original full aggregate score; `cases.json.gz` holds
  aggregate ledger counts. `freeze.json` and `completion.json` pin chronology.
- `independent_recount.py` and `independent-recount.json` check aggregate
  arithmetic and exact inference. They do not independently establish targets.
- `price_leakage_target_audit.py`, its tests/design freeze, `target-audit.json`
  and `target-audit-process.json` record the separate semantic recount. It uses
  the seed-free private scoring tree only after the complete prediction barrier
  and original scoring/export. The public receipt contains no target truth.
- `rehearsal-public-evidence.tar.gz` retains the full four-public-seed rehearsal;
  the rehearsal recount receipts and source-review/generation controls are here
  separately. These controls are not evaluation samples.
- `archive-verification.json` checks every stored/decompressed member and all
  13 frozen source snapshots. `SHA256SUMS` covers the final public files and
  report; run `sha256sum -c SHA256SUMS` from this directory.

Observer inputs named `*-targets.json` contain **all public zero-payout SPEND
event IDs**, not the hidden honest eligibility mask. Pooled views contain only
the declared eight colluders' permitted records. Cost/accounting totals are
post-run validation disclosures and were not observer inputs. Raw truth, seeds,
backups, honest input mappings and truth-joined correctness vectors are excluded.
Source code and metadata can reference private filenames; no such data files
are archive members. All checks are author-operated, not external attestation.

To inspect the package, extract the archive, verify stored file hashes against
the manifest, then decompress files whose encoding is `gzip` and verify logical
hashes. The exact observer sources/spec are under `evaluation/code/`. Recounting
the public aggregate files needs only the standard library; the semantic recount
also requires the separately retained authorized truth and strict sandbox mounts.
See the target-audit source for its closed input contract.
