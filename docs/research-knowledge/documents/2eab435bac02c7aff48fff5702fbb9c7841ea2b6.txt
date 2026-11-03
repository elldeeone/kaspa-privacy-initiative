# Local commit scope for the price-baseline result

This commit persists the final scientific documentation, aggregate summaries,
verification records and required reviewed public source. It does not push or
release another experiment. Existing files, frozen sources, report and original
checksum records are included byte-for-byte without retuning or regeneration.

The final report SHA-256 remains
`ee0001d5e54f36368b75fe48ae4c55a5979e5eb637e61fa0208a4f64fec87d14`.
The frozen score SHA-256 remains
`80022f7b21018d9695863cafe31bdba8eb61e72bd22ad5016ec624bab7921556`.

## Intentionally retained outside this commit

Both archives contain public target-level predictions and are deliberately
unstaged. They remain unchanged in the original Forge worktree:
`/home/luke/projects/kaspa-privacy-shared-pool/poc/shared-pool/evidence/2026-10-22-price-leakage/`.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| evaluation-public-evidence.tar.gz | 50112632 | `64671204f17bbcd7970dc66039928ca6df2e490cfda38662361edd86f9601f8f` |
| rehearsal-public-evidence.tar.gz | 474619 | `d919e312e6cb6f2a3867b3469702bf30dfe1a32c4cc5e8a4d4201bdebffac172` |

The original complete public exports remain in the same worktree's ignored
`.local/price-leakage-evaluation-export-01/` and
`.local/price-leakage-rehearsal-export-03/`. No observation/prediction payload
from those exports is staged. Raw seeds, truth, honest target masks and joined
correctness remain in the original private attempt outside Git. No runtime,
environment, private data or canonical `research/orchestration/` document is
part of this commit.

The report and original evidence README describe the full retained package;
this scope record distinguishes that package from the smaller committed subset.
The original `SHA256SUMS` is preserved and includes the two unstaged archives.
A clone can verify the committed subset from the repository root with:

```sh
sha256sum -c poc/shared-pool/evidence/2026-10-22-price-leakage/COMMITTED-SHA256SUMS
```

Aggregate arithmetic can be checked from committed `cases.json.gz`,
`result.json` and `independent_recount.py`. Full observer replay and independent
semantic recount require the separately retained authorized inputs; committed
receipts report the completed checks and are not independent attestation.
The four new experiment source/test files are required by the frozen specification
and previously passed review/controls. Their bytes match `freeze.json`; the eight
unchanged model/observer/validator/controller sources are already present in
parent commit `9e0dca5851f80a3c9fd9e09db1cc7f340aaf8e02`. Nothing is executed by
persisting these files. No tests or experiments were rerun for this commit.

## Exact changed paths

The following 44 repository-relative paths are the explicit staging allowlist.
`COMMITTED-SHA256SUMS` hashes the other 43 files; Git identifies the checksum
file itself without a circular self-hash.

```text
THREAT-MODEL.md
docs/ARCHITECTURE.md
docs/RESEARCH-JOURNAL.md
docs/SHARED-POOL-PLAN.md
docs/adr/0033-price-baseline-evaluation.md
docs/adr/README.md
docs/rfc/0017-price-priors-and-transaction-leakage.md
docs/rfc/README.md
poc/shared-pool/PRICE-LEAKAGE-SPEC.md
poc/shared-pool/PRICE-LEAKAGE.md
poc/shared-pool/README.md
poc/shared-pool/evidence/2026-10-22-price-leakage/COMMIT-SCOPE.md
poc/shared-pool/evidence/2026-10-22-price-leakage/COMMITTED-SHA256SUMS
poc/shared-pool/evidence/2026-10-22-price-leakage/README.md
poc/shared-pool/evidence/2026-10-22-price-leakage/SHA256SUMS
poc/shared-pool/evidence/2026-10-22-price-leakage/archive-receipt.json
poc/shared-pool/evidence/2026-10-22-price-leakage/archive-verification.json
poc/shared-pool/evidence/2026-10-22-price-leakage/cases.json.gz
poc/shared-pool/evidence/2026-10-22-price-leakage/completion.json
poc/shared-pool/evidence/2026-10-22-price-leakage/export-manifest.json
poc/shared-pool/evidence/2026-10-22-price-leakage/final-freeze-verification.json
poc/shared-pool/evidence/2026-10-22-price-leakage/final-interpretation-review.json
poc/shared-pool/evidence/2026-10-22-price-leakage/freeze.json
poc/shared-pool/evidence/2026-10-22-price-leakage/independent-recount.json
poc/shared-pool/evidence/2026-10-22-price-leakage/independent_recount.py
poc/shared-pool/evidence/2026-10-22-price-leakage/prefreeze-review.json
poc/shared-pool/evidence/2026-10-22-price-leakage/price_leakage_target_audit.freeze.json
poc/shared-pool/evidence/2026-10-22-price-leakage/price_leakage_target_audit.py
poc/shared-pool/evidence/2026-10-22-price-leakage/price_leakage_target_audit_tests.py
poc/shared-pool/evidence/2026-10-22-price-leakage/public-generation-controls.json
poc/shared-pool/evidence/2026-10-22-price-leakage/rehearsal-freeze.json
poc/shared-pool/evidence/2026-10-22-price-leakage/rehearsal-independent-recount.json
poc/shared-pool/evidence/2026-10-22-price-leakage/rehearsal-target-audit-process.json
poc/shared-pool/evidence/2026-10-22-price-leakage/rehearsal-target-audit.json
poc/shared-pool/evidence/2026-10-22-price-leakage/result.json
poc/shared-pool/evidence/2026-10-22-price-leakage/target-audit-process.json
poc/shared-pool/evidence/2026-10-22-price-leakage/target-audit.json
poc/shared-pool/evidence/2026-10-22-price-leakage/terminal-resources.json
poc/shared-pool/price_leakage_score.py
poc/shared-pool/price_leakage_score_tests.py
poc/shared-pool/price_leakage_trial.py
poc/shared-pool/price_leakage_trial_tests.py
research/README.md
research/shielded-kas-price-baseline-test-2026-10-22.md
```
